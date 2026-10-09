"""
GASHA Telemetry Delivery Client
Thread-safe, non-blocking background queue with bounded local buffering,
observable saturation metrics, exponential backoff retries, and clean shutdown.
"""
import time
import threading
import queue
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import httpx

try:
    from .models import TelemetryEvent, SDKDeliveryMetrics
    from .sanitizers import sanitize_metadata
except (ImportError, ValueError):
    from models import TelemetryEvent, SDKDeliveryMetrics
    from sanitizers import sanitize_metadata

from dataclasses import dataclass

logger = logging.getLogger("gasha.telemetry.client")

@dataclass
class TelemetryClientConfig:
    """Configuration options for TelemetryClient."""
    endpoint: str = "http://localhost:4000/api/v1/telemetry/ingest"
    api_key: str = ""
    environment_id: str = "env-prod"
    service_name: str = "python-service"
    max_queue_size: int = 2000
    batch_size: int = 20
    flush_interval_seconds: float = 1.0
    http_timeout_seconds: float = 3.0
    max_retries: int = 3

class TelemetryClient:
    """
    Asynchronous telemetry delivery client.
    Enqueues events into a bounded in-memory buffer and dispatches them via background worker thread.
    Zero-blocking guarantee for the calling application thread.
    """
    def __init__(
        self,
        endpoint: str = "http://localhost:4000/api/v1/telemetry/ingest",
        api_key: str = "",
        environment_id: str = "env-prod",
        service_name: str = "python-service",
        max_queue_size: int = 2000,
        batch_size: int = 20,
        flush_interval_seconds: float = 1.0,
        http_timeout_seconds: float = 3.0,
        max_retries: int = 3,
        auto_start: bool = True
    ):
        self.endpoint = endpoint
        self.api_key = api_key
        self.environment_id = environment_id
        self.service_name = service_name
        self.max_queue_size = max_queue_size
        self.batch_size = batch_size
        self.flush_interval = flush_interval_seconds
        self.timeout = http_timeout_seconds
        self.max_retries = max_retries

        self._queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self._lock = threading.Lock()
        self._running = False
        self._worker_thread: Optional[threading.Thread] = None

        # Observable delivery metrics
        self._queued_count = 0
        self._transmitted_count = 0
        self._dropped_count = 0
        self._error_count = 0
        self._retry_count = 0
        self._last_flush_time: Optional[str] = None

        self.http_client = httpx.Client(timeout=self.timeout)

        if auto_start:
            self.start()

    def start(self):
        """Starts the background worker thread."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._worker_thread = threading.Thread(
                target=self._worker_loop,
                name="gasha-telemetry-worker",
                daemon=True
            )
            self._worker_thread.start()
            logger.debug(f"[GASHA SDK] Telemetry client started for {self.service_name} ({self.environment_id})")

    @property
    def queue(self) -> queue.Queue:
        """Direct access to the underlying queue."""
        return self._queue

    def get_queue_depth(self) -> int:
        """Returns the current number of events pending in the queue."""
        return self._queue.qsize()

    def enqueue(self, event: TelemetryEvent) -> bool:
        """
        Submits an event to the background queue.
        NON-BLOCKING: If the queue is saturated, drops the oldest event to make room
        for freshest security telemetry, increments dropped count, and enqueues.
        """
        # Ensure metadata is strictly sanitized prior to queue entry
        if event.payload and event.payload.metadata:
            event.payload.metadata = sanitize_metadata(event.payload.metadata)

        with self._lock:
            self._queued_count += 1

        try:
            self._queue.put_nowait(event)
            return True
        except queue.Full:
            with self._lock:
                self._dropped_count += 1
            try:
                # Drop oldest event to prioritize freshest telemetry
                self._queue.get_nowait()
                self._queue.put_nowait(event)
                logger.warning(f"[GASHA SDK] Queue saturated ({self.max_queue_size} max). Dropped oldest event.")
                return True
            except (queue.Empty, queue.Full):
                return False

    def emit(self, event: TelemetryEvent) -> bool:
        """Alias for enqueue."""
        return self.enqueue(event)

    def _worker_loop(self):
        """Worker thread continuously batching and transmitting events."""
        while self._running:
            self._drain_and_transmit()
            time.sleep(self.flush_interval)

        # Final drain upon stopping
        self._drain_and_transmit()

    def _drain_and_transmit(self):
        """Extracts available batch from queue and posts to GASHA Ingestion API."""
        batch: List[TelemetryEvent] = []
        while len(batch) < self.batch_size:
            try:
                event = self._queue.get_nowait()
                batch.append(event)
            except queue.Empty:
                break

        if not batch:
            return

        self._transmit_batch_with_retry(batch)

    def _transmit_batch_with_retry(self, batch: List[TelemetryEvent]):
        """Transmits a batch with bounded exponential backoff for transient failures."""
        payload_events = [
            e.model_dump(by_alias=True, exclude_none=True) if hasattr(e, 'model_dump') else e
            for e in batch
        ]
        request_body = {"events": payload_events}
        headers = {
            "Content-Type": "application/json",
            "X-GASHA-TELEMETRY-KEY": self.api_key,
            "Authorization": f"Bearer {self.api_key}"
        }

        attempts = 0
        backoff_delay = 0.2

        while attempts <= self.max_retries:
            attempts += 1
            try:
                resp = self.http_client.post(self.endpoint, json=request_body, headers=headers)
                # Successful or partially accepted response
                if resp.status_code in (200, 201, 202):
                    with self._lock:
                        self._transmitted_count += len(batch)
                        self._last_flush_time = datetime.now(timezone.utc).isoformat()
                    return
                elif resp.status_code in (400, 401, 403, 422):
                    # Permanent client/auth/schema rejection: DO NOT retry indefinitely
                    with self._lock:
                        self._error_count += len(batch)
                    logger.error(f"[GASHA SDK] Ingestion rejected (HTTP {resp.status_code}): {resp.text}")
                    return
                else:
                    # 5xx or transient status code
                    logger.warning(f"[GASHA SDK] Transient server error (HTTP {resp.status_code}), attempt {attempts}/{self.max_retries}")
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                logger.warning(f"[GASHA SDK] Network transmission error: {exc}, attempt {attempts}/{self.max_retries}")

            if attempts <= self.max_retries:
                with self._lock:
                    self._retry_count += 1
                time.sleep(backoff_delay)
                backoff_delay = min(backoff_delay * 2, 2.0)

        # Retries exhausted
        with self._lock:
            self._error_count += len(batch)
            self._dropped_count += len(batch)
        logger.error(f"[GASHA SDK] Failed to deliver {len(batch)} events after {self.max_retries} attempts.")

    def flush(self, timeout: float = 3.0) -> None:
        """Blocks until the queue is drained or timeout expires."""
        start = time.time()
        while not self._queue.empty() and (time.time() - start) < timeout:
            self._drain_and_transmit()
            time.sleep(0.05)

    def close(self, timeout: float = 2.0) -> None:
        """Gracefully stops the worker thread and cleans up HTTP client."""
        with self._lock:
            self._running = False
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=timeout)
        try:
            self.http_client.close()
        except Exception:
            pass

    def shutdown(self, timeout: float = 2.0, timeout_seconds: Optional[float] = None) -> None:
        """Alias for close. Flushes pending events and stops worker thread."""
        eff_timeout = timeout_seconds if timeout_seconds is not None else timeout
        self.flush(timeout=eff_timeout)
        self.close(timeout=eff_timeout)

    def get_metrics(self) -> SDKDeliveryMetrics:
        """Returns observable telemetry delivery and health metrics."""
        with self._lock:
            return SDKDeliveryMetrics(
                queued_count=self._queued_count,
                transmitted_count=self._transmitted_count,
                dropped_count=self._dropped_count,
                error_count=self._error_count,
                retry_count=self._retry_count,
                last_flush_time=self._last_flush_time,
                is_running=self._running
            )
