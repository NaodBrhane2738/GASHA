"""
Integration tests for the Postgres engine and the repositories running on it.

Skipped unless GASHA_TEST_DATABASE_URL points at a database that already has the
migrations applied (python infra/scripts/apply_migrations.py). The tests DELETE
the rows in the persistence tables, so use a scratch/dev database, never the demo one.

    $env:GASHA_TEST_DATABASE_URL = "postgresql://..."
    python -m pytest tests/integration/test_postgres_engine.py -q
"""
import os

import pytest

TEST_URL = os.environ.get("GASHA_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not TEST_URL, reason="GASHA_TEST_DATABASE_URL not set")

from app.schemas.detection import DetectionEventResponse, DetectionRuleSummarySchema  # noqa: E402
from app.schemas.incident import IncidentResponse  # noqa: E402
from app.schemas.response import ResponseRecordResponse  # noqa: E402

ENV = "env-pgtest"


@pytest.fixture()
def stack():
    from app.db.postgres_engine import PostgresDatabaseEngine
    from app.db.sql_engine import (
        SQLAuditTrail,
        SQLDetectionRepository,
        SQLIncidentRepository,
        SQLResponseRepository,
    )

    engine = PostgresDatabaseEngine(TEST_URL)
    repos = {
        "engine": engine,
        "incidents": SQLIncidentRepository(engine=engine),
        "detections": SQLDetectionRepository(engine=engine),
        "responses": SQLResponseRepository(engine=engine),
        "audit": SQLAuditTrail(engine=engine),
    }
    for key in ("incidents", "detections", "responses", "audit"):
        repos[key].clear()
    yield repos
    for key in ("incidents", "detections", "responses", "audit"):
        repos[key].clear()
    engine.close()


def make_incident(incident_id="inc-1"):
    return IncidentResponse(
        id=incident_id, title="Credential stuffing", severity="HIGH", status="ACTIVE",
        primaryAffectedAssetId="asset-web", relatedAssetIds=["asset-db", "asset-api"],
        detectionEventIds=["det-1", "det-2"], attackPathId="path-1",
        createdAt="2026-10-14T12:00:00.123456Z", updatedAt="2026-10-14T12:00:00.123456Z",
        summary="Repeated failures then success", environmentId=ENV, correlationKey="ip-1.2.3.4",
    )


def make_detection(detection_id="det-1", incident_id=None):
    return DetectionEventResponse(
        id=detection_id,
        rule=DetectionRuleSummarySchema(ruleId="R-001", name="Brute force", description="d", severity="HIGH", confidence=0.85),
        matchedEventIds=["evt-1", "evt-2", "evt-3"], primaryAssetId="asset-web",
        timestamp="2026-10-14T12:00:01Z", severity="HIGH", confidence=0.85,
        evidenceSummary="5 failures in 60s", environmentId=ENV, incidentId=incident_id,
        metadata={"sourceIp": "1.2.3.4", "count": 5, "nested": {"a": [1, 2]}},
    )


def make_response(response_id="resp-1"):
    return ResponseRecordResponse(
        id=response_id, incidentId="inc-1", environmentId=ENV, actionType="BLOCK_SOURCE",
        targetType="IP_ADDRESS", targetIdentifier="1.2.3.4", status="PENDING_APPROVAL",
        reason="Brute force source", supportingEvidenceIds=["det-1", "evt-1"],
        proposedAt="2026-10-14T12:05:00Z", proposedBy="system", metadata={"note": "demo"},
    )


def test_incident_round_trip_and_upsert(stack):
    repo = stack["incidents"]
    repo.create_incident(make_incident())
    got = repo.get_incident("inc-1", ENV)
    assert got.relatedAssetIds == ["asset-db", "asset-api"]
    assert got.detectionEventIds == ["det-1", "det-2"]
    assert got.createdAt == "2026-10-14T12:00:00.123456Z"

    changed = make_incident()
    changed.title = "Renamed"
    repo.create_incident(changed)  # same id: must update, not fail
    assert repo.get_incident("inc-1", ENV).title == "Renamed"
    assert len(repo.list_incidents(environment_id=ENV)) == 1


def test_detection_round_trip_and_link(stack):
    repo = stack["detections"]
    repo.create_detection(make_detection())
    got = repo.get_detection("det-1", ENV)
    assert got.matchedEventIds == ["evt-1", "evt-2", "evt-3"]
    assert got.metadata == {"sourceIp": "1.2.3.4", "count": 5, "nested": {"a": [1, 2]}}
    assert got.confidence == pytest.approx(0.85)
    assert got.timestamp == "2026-10-14T12:00:01Z"

    repo.link_to_incident("det-1", "inc-1")
    assert repo.get_detection("det-1", ENV).incidentId == "inc-1"


def test_response_round_trip_and_status_update(stack):
    repo = stack["responses"]
    repo.save_response(make_response())
    got = repo.get_response("resp-1", ENV)
    assert got.supportingEvidenceIds == ["det-1", "evt-1"]
    assert got.metadata == {"note": "demo"}

    done = make_response()
    done.status = "SUCCEEDED"
    done.executedAt = "2026-10-14T12:06:00Z"
    repo.save_response(done)
    got = repo.get_response("resp-1", ENV)
    assert got.status == "SUCCEEDED"
    assert got.executedAt == "2026-10-14T12:06:00Z"
    assert len(repo.list_responses(ENV)) == 1


def test_audit_chain_verifies_then_detects_tampering(stack):
    audit = stack["audit"]
    for step in ("PROPOSED", "APPROVED", "EXECUTED"):
        audit.append_entry(ENV, step, "analyst", "inc-1", "resp-1", "BLOCK_SOURCE", "1.2.3.4", "OK",
                           {"step": step, "ratio": 0.5, "tags": ["a", "b"]})
    entries = audit.get_entries(ENV)
    assert [e.sequenceNumber for e in entries] == [1, 2, 3]
    assert entries[1].previousHash == entries[0].recordHash
    assert audit.verify_chain(ENV).verified is True

    with stack["engine"].get_connection() as conn:
        conn.execute("UPDATE response_audit_log SET outcome = ? WHERE environment_id = ? AND sequence_number = 2",
                     ("TAMPERED", ENV))
    assert audit.verify_chain(ENV).verified is False


def test_failed_block_rolls_back(stack):
    engine = stack["engine"]
    with pytest.raises(RuntimeError):
        with engine.get_connection() as conn:
            conn.execute("INSERT INTO detections (id, rule_id, rule_name, severity, confidence, primary_asset_id, "
                         "evidence_summary) VALUES (?, ?, ?, ?, ?, ?, ?)",
                         ("det-rollback", "R", "n", "LOW", 0.5, "a", "s"))
            raise RuntimeError("boom")
    assert stack["detections"].get_detection("det-rollback") is None


def test_unique_sequence_number_is_enforced(stack):
    import psycopg
    engine = stack["engine"]
    sql = ("INSERT INTO response_audit_log (audit_id, sequence_number, timestamp, event_type, actor, environment_id, "
           "incident_id, response_id, action_type, target_identifier, outcome, details, previous_hash, record_hash) "
           "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
    row = ("aud-x1", 1, "2026-10-14T12:00:00Z", "E", "a", ENV, "i", "r", "A", "t", "o", "{}", "p", "h")
    with engine.get_connection() as conn:
        conn.execute(sql, row)
    with pytest.raises(psycopg.errors.UniqueViolation):
        with engine.get_connection() as conn:
            conn.execute(sql, ("aud-x2",) + row[1:])