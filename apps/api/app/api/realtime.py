"""
==============================================================================
FILE: apps/api/app/api/realtime.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: Secure, environment-partitioned WebSocket streaming for live platform updates.
SECURITY: Single-use authentication tickets, JWT fallback, strict environment isolation,
          and zero cross-tenant event broadcast leakage.
==============================================================================
"""

import time
import secrets
import logging
from typing import List, Optional, Dict, Any, Set
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query, HTTPException, status
from pydantic import BaseModel

from app.core.auth import get_current_user
from app.core.security import verify_jwt_token

logger = logging.getLogger("gasha.realtime")
router = APIRouter()

import threading

# In-memory single-use ticket store: ticket_str -> {"userId": str, "environmentId": str, "expiresAt": float}
_ws_tickets: Dict[str, Dict[str, Any]] = {}
_ticket_lock = threading.Lock()


def create_websocket_ticket(user_id: str, environment_id: str, expires_seconds: int = 60) -> str:
    """Generates a high-entropy single-use ticket bound to user and environmentId."""
    ticket = f"wst_{secrets.token_urlsafe(32)}"
    with _ticket_lock:
        _ws_tickets[ticket] = {
            "userId": user_id,
            "environmentId": environment_id,
            "expiresAt": time.time() + expires_seconds
        }
    return ticket


def consume_websocket_ticket(ticket: str) -> Optional[Dict[str, Any]]:
    """
    Validates and atomically consumes a ticket under thread synchronization.
    Returns ticket context or None if invalid, expired, or already consumed.
    """
    if not ticket or not isinstance(ticket, str):
        return None
    with _ticket_lock:
        data = _ws_tickets.pop(ticket, None)
    if not data:
        return None
    if time.time() > data["expiresAt"]:
        return None
    return data


class TicketResponse(BaseModel):
    ticket: str
    expiresIn: int
    environmentId: str


@router.post("/ticket", response_model=TicketResponse, summary="Issue Short-Lived WebSocket Ticket")
async def issue_websocket_ticket(user: dict = Depends(get_current_user)):
    """
    Issues an authenticated, short-lived (60s), single-use ticket bound to caller's environment.
    Prevents exposure of long-lived access tokens in WebSocket connection URLs.
    """
    auth_env = user.get("environmentId", "env-prod")
    uid = user.get("sub", "analyst")
    ticket = create_websocket_ticket(user_id=uid, environment_id=auth_env, expires_seconds=60)
    return TicketResponse(
        ticket=ticket,
        expiresIn=60,
        environmentId=auth_env
    )


class ConnectionManager:
    """
    Manages active WebSocket connections partitioned strictly by environmentId.
    Prevents cross-tenant event broadcasts.
    """
    def __init__(self):
        # environment_id -> Set[WebSocket]
        self._connections_by_env: Dict[str, Set[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, environment_id: str):
        await websocket.accept()
        if environment_id not in self._connections_by_env:
            self._connections_by_env[environment_id] = set()
        self._connections_by_env[environment_id].add(websocket)
        logger.debug(f"Client connected to realtime stream for environment '{environment_id}'")

    def disconnect(self, websocket: WebSocket, environment_id: str):
        if environment_id in self._connections_by_env:
            self._connections_by_env[environment_id].discard(websocket)
            if not self._connections_by_env[environment_id]:
                del self._connections_by_env[environment_id]
        logger.debug(f"Client disconnected from realtime stream for environment '{environment_id}'")

    async def broadcast_to_environment(self, environment_id: str, message: dict):
        """Broadcasts only to clients authenticated for the specified environment."""
        clients = list(self._connections_by_env.get(environment_id, []))
        for connection in clients:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.debug(f"Failed to send realtime event to client: {e}")
                self.disconnect(connection, environment_id)

    def get_connection_count(self, environment_id: Optional[str] = None) -> int:
        if environment_id:
            return len(self._connections_by_env.get(environment_id, []))
        return sum(len(c) for c in self._connections_by_env.values())


manager = ConnectionManager()


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    ticket: Optional[str] = Query(None),
    token: Optional[str] = Query(None)
):
    """
    Secured WebSocket endpoint. Requires valid ticket (preferred) or token query parameter.
    Validates identity, extracts authorized environmentId, and partitions broadcast stream.
    Rejects unauthenticated or cross-tenant subscription requests with WS Policy Violation (1008).
    """
    auth_ctx = None

    # 1. Attempt single-use ticket consumption
    if ticket:
        auth_ctx = consume_websocket_ticket(ticket)

    # 2. Fallback to direct token validation if ticket not provided
    if not auth_ctx and token:
        payload = verify_jwt_token(token)
        if payload and payload.get("environmentId"):
            auth_ctx = {
                "userId": payload.get("sub", "unknown"),
                "environmentId": payload.get("environmentId")
            }

    # Reject unauthenticated connections immediately before accept
    if not auth_ctx:
        logger.warning("Unauthenticated WebSocket connection rejected")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Unauthorized: Valid ticket or token required")
        return

    authorized_env = auth_ctx["environmentId"]
    await manager.connect(websocket, environment_id=authorized_env)

    try:
        while True:
            # Client heartbeats / keep-alives
            data = await websocket.receive_text()
            if data == "ping" or "ping" in data:
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket, environment_id=authorized_env)
    except Exception as e:
        logger.debug(f"WebSocket connection terminated: {e}")
        manager.disconnect(websocket, environment_id=authorized_env)


async def broadcast_system_event(
    event_type: str,
    data: Optional[dict] = None,
    payload: Optional[dict] = None,
    environment_id: str = "env-prod",
    **kwargs
):
    """Safely broadcasts a platform state event strictly to clients of the matching environment."""
    payload_data = data if data is not None else (payload if payload is not None else kwargs)
    try:
        await manager.broadcast_to_environment(
            environment_id=environment_id,
            message={
                "type": event_type,
                "environmentId": environment_id,
                "data": payload_data,
            }
        )
    except Exception as e:
        logger.debug(f"Realtime broadcast non-critical failure: {e}")


def safe_broadcast_event(
    event_type: str,
    data: Optional[dict] = None,
    payload: Optional[dict] = None,
    environment_id: str = "env-prod",
    **kwargs
):
    """Synchronous non-blocking helper to schedule broadcast on active event loop."""
    payload_data = data if data is not None else (payload if payload is not None else kwargs)
    try:
        import asyncio
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(broadcast_system_event(
                event_type=event_type,
                data=payload_data,
                environment_id=environment_id
            ))
        except RuntimeError:
            pass
    except Exception as e:
        logger.debug(f"Sync broadcast non-critical failure: {e}")
