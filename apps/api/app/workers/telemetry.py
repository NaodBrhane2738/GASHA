"""
==============================================================================
FILE: apps/api/app/workers/telemetry.py
ROLE / OWNERSHIP: Backend & Telemetry Engineers
OBJECTIVE: Background queue consumer for continuous telemetry stream processing.
TOOLS & LIBRARIES: asyncio, logging
==============================================================================
"""

import asyncio
import logging
from typing import Optional

from app.telemetry.ingester import get_telemetry_ingester
from app.telemetry.processor import process_stream

logger = logging.getLogger("gasha.workers.telemetry")


async def run_telemetry_flusher(
    stop_event: Optional[asyncio.Event] = None,
    poll_interval: float = 0.1,
    batch_size: int = 100
) -> None:
    """
    Background worker that continuously drains the in-memory telemetry queue
    and dispatches batches to the processor.
    """
    ingester = get_telemetry_ingester()
    logger.info("Telemetry background buffer consumer started")

    while stop_event is None or not stop_event.is_set():
        try:
            batch = await ingester.dequeue_batch(max_items=batch_size)
            if batch:
                await process_stream(batch)
            else:
                await asyncio.sleep(poll_interval)
        except asyncio.CancelledError:
            logger.info("Telemetry background buffer consumer cancelled")
            break
        except Exception as e:
            logger.error(f"Error in telemetry flusher loop: {e}", exc_info=True)
            await asyncio.sleep(poll_interval)


async def flush_all_pending() -> int:
    """Synchronously/cooperatively drains all pending items currently in the buffer."""
    ingester = get_telemetry_ingester()
    total_flushed = 0
    while True:
        batch = await ingester.dequeue_batch(max_items=100)
        if not batch:
            break
        await process_stream(batch)
        total_flushed += len(batch)
    return total_flushed
