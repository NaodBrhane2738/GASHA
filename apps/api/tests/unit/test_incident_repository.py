"""
Unit tests for GASHA Incident Repository.
Validates incident CRUD, lifecycle transitions, environment boundaries,
and evidence attachments.
"""
import pytest
from app.schemas.incident import IncidentResponse
from app.db.repositories.incident_repository import IncidentRepository


def make_incident(inc_id: str, status: str = "ACTIVE", env_id: str = "env-prod", severity: str = "HIGH") -> IncidentResponse:
    return IncidentResponse(
        id=inc_id,
        title=f"Incident {inc_id}",
        severity=severity,
        status=status,
        primaryAffectedAssetId="asset-1",
        relatedAssetIds=[],
        detectionEventIds=["det-01"],
        createdAt="2026-10-09T12:00:00Z",
        updatedAt="2026-10-09T12:00:00Z",
        environmentId=env_id
    )


def test_repo_create_and_get():
    repo = IncidentRepository()
    inc = make_incident("inc-01")
    repo.create_incident(inc)

    retrieved = repo.get_incident("inc-01")
    assert retrieved is not None
    assert retrieved.id == "inc-01"
    assert retrieved.status == "ACTIVE"


def test_repo_environment_isolation():
    repo = IncidentRepository()
    repo.create_incident(make_incident("inc-prod", env_id="env-prod"))
    repo.create_incident(make_incident("inc-dev", env_id="env-dev"))

    # Listing by environment
    prod_list = repo.list_incidents(environment_id="env-prod")
    dev_list = repo.list_incidents(environment_id="env-dev")

    assert len(prod_list) == 1
    assert prod_list[0].id == "inc-prod"
    assert len(dev_list) == 1
    assert dev_list[0].id == "inc-dev"

    # Getting with mismatched environment returns None
    assert repo.get_incident("inc-prod", environment_id="env-dev") is None


def test_repo_valid_lifecycle_transitions():
    repo = IncidentRepository()
    repo.create_incident(make_incident("inc-life", status="ACTIVE"))

    # ACTIVE -> INVESTIGATING
    inc1 = repo.update_status("inc-life", "INVESTIGATING")
    assert inc1.status == "INVESTIGATING"

    # INVESTIGATING -> CONTAINED
    inc2 = repo.update_status("inc-life", "CONTAINED")
    assert inc2.status == "CONTAINED"

    # CONTAINED -> RESOLVED
    inc3 = repo.update_status("inc-life", "RESOLVED")
    assert inc3.status == "RESOLVED"


def test_repo_invalid_lifecycle_transition_raises():
    repo = IncidentRepository()
    repo.create_incident(make_incident("inc-invalid", status="CONTAINED"))

    # CONTAINED -> ACTIVE is not permitted directly (must go through INVESTIGATING)
    with pytest.raises(ValueError) as exc:
        repo.update_status("inc-invalid", "ACTIVE")
    assert "Invalid incident status transition" in str(exc.value)


def test_repo_attach_detection_and_upgrade_severity():
    repo = IncidentRepository()
    repo.create_incident(make_incident("inc-att", severity="LOW"))

    updated = repo.attach_detection(
        incident_id="inc-att",
        detection_id="det-crit",
        related_asset_id="asset-db",
        new_severity="CRITICAL"
    )

    assert "det-crit" in updated.detectionEventIds
    assert "asset-db" in updated.relatedAssetIds
    assert updated.severity == "CRITICAL"
