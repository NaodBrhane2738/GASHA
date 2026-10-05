"""
==============================================================================
FILE: apps/api/app/ai/tests/test_ollama.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Unit & integration tests for OllamaProvider, connection error handling,
           timeouts, health checks, and optional live model execution.
==============================================================================
"""

import httpx
import pytest
from unittest.mock import patch, MagicMock

from app.ai.contracts import (
    InvestigationContext,
    IncidentContext,
    EvidenceItem,
    DetectionContext,
)
from app.ai.providers.base import (
    ProviderConfig,
    AIProviderConnectionError,
    AIProviderTimeoutError,
)
from app.ai.providers.ollama import OllamaProvider
from app.ai.service import AIService


def make_test_context() -> InvestigationContext:
    """Creates standard test context fixture."""
    return InvestigationContext(
        incident=IncidentContext(
            id="INC-OLLAMA-1",
            title="Ollama Provider Test Incident",
            severity="HIGH",
            status="ACTIVE",
            primaryAffectedAssetId="asset-auth",
            createdAt="2026-09-24T00:00:00Z",
            updatedAt="2026-09-24T00:00:00Z",
        ),
        evidence=[
            EvidenceItem(
                id="EV-1",
                type="TELEMETRY_EVENT",
                source="asset-auth",
                timestamp="2026-09-24T00:00:00Z",
                summary="Auth event",
                content={},
                verified=True,
            )
        ],
        detections=[
            DetectionContext(
                id="DET-1",
                ruleId="R-1",
                ruleName="Test Rule",
                description="Desc",
                severity="HIGH",
                confidence=0.9,
                matchedEventIds=["EV-1"],
                primaryAssetId="asset-auth",
                timestamp="2026-09-24T00:00:00Z",
                evidenceSummary="Summary",
            )
        ],
    )


@pytest.mark.asyncio
async def test_2_ollama_unavailable_triggers_fallback():
    """TEST 2: Ollama connection refused -> AIService returns UNAVAILABLE fallback without crashing."""
    provider = OllamaProvider(config=ProviderConfig(base_url="http://127.0.0.1:59999"))

    async def mock_connect_error(*args, **kwargs):
        raise httpx.ConnectError("Connection refused to Ollama mock")

    with patch.object(httpx.AsyncClient, "post", side_effect=mock_connect_error):
        service = AIService(default_provider=provider)
        ctx = make_test_context()

        result = await service.investigate(ctx)
        assert result.status == "UNAVAILABLE"
        assert result.errorMessage is not None
        assert "connection" in result.errorMessage.lower() or "failed" in result.errorMessage.lower()


@pytest.mark.asyncio
async def test_3_ollama_timeout_triggers_fallback():
    """TEST 3: Ollama request times out -> AIService returns UNAVAILABLE fallback without crashing."""
    provider = OllamaProvider(config=ProviderConfig(timeout_seconds=0.01))

    async def mock_timeout_post(*args, **kwargs):
        raise httpx.ReadTimeout("Request timed out during mock test")

    with patch.object(httpx.AsyncClient, "post", side_effect=mock_timeout_post):
        service = AIService(default_provider=provider)
        ctx = make_test_context()

        result = await service.investigate(ctx)
        assert result.status == "UNAVAILABLE"
        assert "timed out" in result.errorMessage.lower()


@pytest.mark.asyncio
async def test_ollama_health_check_offline():
    """Verifies health_check returns clean AIProviderStatus when Ollama is offline."""
    config = ProviderConfig(base_url="http://127.0.0.1:59999")
    provider = OllamaProvider(config=config)

    async def mock_get_connect_error(*args, **kwargs):
        raise httpx.ConnectError("Connection refused")

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get_connect_error):
        status = await provider.health_check()
        assert status.provider == "ollama"
        assert status.available is False
        assert status.error is not None


@pytest.mark.asyncio
async def test_ollama_health_check_online_mock():
    """Verifies health_check parses models and latency when Ollama is online."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "models": [{"name": "qwen2.5-coder:7b"}, {"name": "ministral-8b:latest"}]
    }

    async def mock_get(*args, **kwargs):
        return mock_response

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        provider = OllamaProvider(config=ProviderConfig(model="qwen2.5-coder:7b"))
        status = await provider.health_check()

        assert status.available is True
        assert status.error is None
        assert status.model == "qwen2.5-coder:7b"
        assert status.latency_ms is not None


@pytest.mark.asyncio
async def test_optional_live_ollama_integration():
    """
    OPTIONAL LOCAL INTEGRATION TEST:
    If a local Ollama instance is actually running on http://localhost:11434,
    executes an end-to-end investigation against the live model.
    Otherwise skips cleanly.
    """
    provider = OllamaProvider()
    try:
        status = await provider.health_check()
    except Exception:
        pytest.skip("Local Ollama instance not reachable at http://localhost:11434. Skipping live test.")

    if not status.available:
        pytest.skip("Local Ollama instance not reachable at http://localhost:11434. Skipping live test.")

    service = AIService(default_provider=provider)
    ctx = make_test_context()

    result = await service.investigate(ctx)
    assert result.status in ("SUCCESS", "INVALID", "UNAVAILABLE", "INSUFFICIENT_EVIDENCE")
    assert result.incidentId == "INC-OLLAMA-1"
