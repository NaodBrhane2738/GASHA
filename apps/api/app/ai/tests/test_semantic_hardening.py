import pytest
from app.ai.contracts import (
    InvestigationContext, AIInvestigationResult, AIRecommendation,
    ConfidenceAssessment, AttackProgressionItem, ObservedFact,
    IncidentContext, EvidenceItem, AssetContext
)
from app.ai.semantic_validator import (
    validate_identifier_grounding,
    validate_attack_phases,
    detect_evidence_conflicts,
    validate_recommendation_appropriateness
)
from app.ai.validation import validate_investigation_result

def create_base_context() -> InvestigationContext:
    incident = IncidentContext(id="INC-123", title="Test Incident", severity="HIGH", primaryAffectedAssetId="asset-1", status="ACTIVE", createdAt="now", updatedAt="now", relatedAssetIds=[])
    asset = AssetContext(id="asset-1", name="Test Asset", type="SERVER", ipAddress="10.0.0.1", tags=[])
    return InvestigationContext(incident=incident, assets=[asset], evidence=[], detections=[], telemetryEvents=[])

def test_ip_corruption():
    context = create_base_context()
    context.evidence.append(EvidenceItem(id="ev-1", type="TELEMETRY_EVENT", timestamp="now", source="syslog", summary="Log from 203.0.113.88", content={"ip": "203.0.113.88"}))
    result = AIInvestigationResult(
        incidentId="INC-123", status="SUCCESS", summary="Traffic from 203.0.138.88 observed.", severity="HIGH",
        confidence=ConfidenceAssessment(score=1.0, rationale="x", evidenceCompleteness="HIGH", limitations=[]),
        observedFacts=[], inferences=[], unknowns=[], attackProgression=[], affectedAssetIds=["asset-1"], citedEvidenceIds=[], recommendedActions=[]
    )
    events = validate_identifier_grounding(context, result)
    assert len(events) > 0
    assert any(e.value == "203.0.138.88" for e in events)

def test_invented_phase():
    context = create_base_context()
    context.evidence.append(EvidenceItem(id="ev-1", type="TELEMETRY_EVENT", timestamp="now", source="waf", summary="WAF block", content={"status": "403"}))
    result = AIInvestigationResult(
        incidentId="INC-123", status="SUCCESS", summary="x", severity="HIGH",
        confidence=ConfidenceAssessment(score=1.0, rationale="x", evidenceCompleteness="HIGH", limitations=[]),
        observedFacts=[], inferences=[], unknowns=[], attackProgression=[
            AttackProgressionItem(stepOrder=1, description="C2", phase="COMMAND_AND_CONTROL", evidenceIds=["ev-1"])
        ], affectedAssetIds=["asset-1"], citedEvidenceIds=["ev-1"], recommendedActions=[]
    )
    warnings, validated = validate_attack_phases(context, result)
    assert len(warnings) > 0
    assert validated.attackProgression[0].phase == "PERSISTENCE"

def test_unsupported_lateral_movement():
    context = create_base_context()
    context.evidence.append(EvidenceItem(id="ev-1", type="TELEMETRY_EVENT", timestamp="now", source="auth", summary="Login asset 1", content={}))
    context.evidence.append(EvidenceItem(id="ev-2", type="TELEMETRY_EVENT", timestamp="now", source="auth", summary="Login asset 2", content={}))
    result = AIInvestigationResult(
        incidentId="INC-123", status="SUCCESS", summary="x", severity="HIGH",
        confidence=ConfidenceAssessment(score=1.0, rationale="x", evidenceCompleteness="HIGH", limitations=[]),
        observedFacts=[], inferences=[], unknowns=[], attackProgression=[
            AttackProgressionItem(stepOrder=1, description="LM", phase="LATERAL_MOVEMENT", evidenceIds=[])
        ], affectedAssetIds=["asset-1", "asset-2"], citedEvidenceIds=[], recommendedActions=[]
    )
    warnings, validated = validate_attack_phases(context, result)
    assert len(warnings) > 0
    assert validated.attackProgression[0].phase == "RESOURCE_ACCESS"

def test_authorized_maintenance_isolate_rejected():
    context = create_base_context()
    context.evidence.append(EvidenceItem(id="ev-1", type="TELEMETRY_EVENT", timestamp="now", source="ticket", summary="Approved CHG-123", content={}))
    result = AIInvestigationResult(
        incidentId="INC-123", status="SUCCESS", summary="x", severity="HIGH", compromiseAssessment="NOT_ESTABLISHED",
        confidence=ConfidenceAssessment(score=1.0, rationale="x", evidenceCompleteness="HIGH", limitations=[]),
        observedFacts=[], inferences=[], unknowns=[], attackProgression=[], affectedAssetIds=[], citedEvidenceIds=[], 
        recommendedActions=[AIRecommendation(id="r-1", actionType="ISOLATE_RESOURCE", targetIdentifier="asset-1", targetType="ASSET_ID", rationale="x", expectedImpact="x", confidence=0.9, supportingEvidenceIds=["ev-1"])]
    )
    errors, warnings = validate_recommendation_appropriateness(context, result, result.recommendedActions)
    assert len(errors) > 0
    assert "ISOLATE_RESOURCE rejected" in errors[0]

def test_mixed_session_block_source_warning():
    context = create_base_context()
    context.evidence.append(EvidenceItem(id="ev-1", type="TELEMETRY_EVENT", timestamp="now", source="log", summary="sess-A123 logged in successfully", content={}))
    result = AIInvestigationResult(
        incidentId="INC-123", status="SUCCESS", summary="x", severity="HIGH",
        confidence=ConfidenceAssessment(score=1.0, rationale="x", evidenceCompleteness="HIGH", limitations=[]),
        observedFacts=[], inferences=[], unknowns=[], attackProgression=[], affectedAssetIds=[], citedEvidenceIds=[], 
        recommendedActions=[AIRecommendation(id="r-1", actionType="BLOCK_SOURCE", targetIdentifier="10.0.0.1", targetType="IP_ADDRESS", rationale="x", expectedImpact="x", confidence=0.9, supportingEvidenceIds=["ev-1"])]
    )
    errors, warnings = validate_recommendation_appropriateness(context, result, result.recommendedActions)
    assert len(warnings) > 0
    assert "DISABLE_SESSION may be more targeted" in warnings[0]

def test_conflicting_success_failure():
    context = create_base_context()
    context.evidence.append(EvidenceItem(id="ev-1", type="TELEMETRY_EVENT", timestamp="now", source="db", summary="Access denied", content={}))
    context.evidence.append(EvidenceItem(id="ev-2", type="TELEMETRY_EVENT", timestamp="now", source="app", summary="Access success status': 200", content={}))
    conflicts = detect_evidence_conflicts(context)
    assert len(conflicts) > 0
    assert conflicts[0].conflict_type == "SUCCESS_VS_DENIED"

def test_asset_id_in_attack_story():
    context = create_base_context()
    result = AIInvestigationResult(
        incidentId="INC-123", status="SUCCESS", summary="x", severity="HIGH",
        confidence=ConfidenceAssessment(score=1.0, rationale="x", evidenceCompleteness="HIGH", limitations=[]),
        observedFacts=[], inferences=[], unknowns=[], attackProgression=[
            AttackProgressionItem(stepOrder=1, description="Accessed web-app-03", phase="OBSERVED_ACTIVITY", evidenceIds=[])
        ], affectedAssetIds=[], citedEvidenceIds=[], recommendedActions=[]
    )
    events = validate_identifier_grounding(context, result)
    assert len(events) > 0
    assert any(e.value == "web-app-03" for e in events)

def test_identifier_in_recommendation():
    context = create_base_context()
    result = AIInvestigationResult(
        incidentId="INC-123", status="SUCCESS", summary="x", severity="HIGH",
        confidence=ConfidenceAssessment(score=1.0, rationale="x", evidenceCompleteness="HIGH", limitations=[]),
        observedFacts=[], inferences=[], unknowns=[], attackProgression=[], affectedAssetIds=[], citedEvidenceIds=[], 
        recommendedActions=[AIRecommendation(id="r-1", actionType="BLOCK_SOURCE", targetIdentifier="10.0.0.1", targetType="IP_ADDRESS", rationale="Block 203.0.113.88", expectedImpact="x", confidence=0.9, supportingEvidenceIds=[])]
    )
    events = validate_identifier_grounding(context, result)
    assert len(events) > 0
    assert any(e.value == "203.0.113.88" for e in events)

def test_valid_compromise_privilege():
    context = create_base_context()
    context.evidence.append(EvidenceItem(id="ev-1", type="TELEMETRY_EVENT", timestamp="now", source="log", summary="admin_role assigned with status': 200", content={}))
    result = AIInvestigationResult(
        incidentId="INC-123", status="SUCCESS", summary="x", severity="HIGH",
        confidence=ConfidenceAssessment(score=1.0, rationale="x", evidenceCompleteness="HIGH", limitations=[]),
        observedFacts=[], inferences=[], unknowns=[], attackProgression=[
            AttackProgressionItem(stepOrder=1, description="x", phase="PRIVILEGE_ESCALATION", evidenceIds=[])
        ], affectedAssetIds=[], citedEvidenceIds=[], recommendedActions=[]
    )
    warnings, validated = validate_attack_phases(context, result)
    assert len(warnings) == 0
    assert validated.attackProgression[0].phase == "PRIVILEGE_ESCALATION"

def test_conflict_detection_db_denied_app_success():
    context = create_base_context()
    context.evidence.append(EvidenceItem(id="ev-1", type="TELEMETRY_EVENT", timestamp="now", source="db", summary="Query failed", content={"session": "sess-xyz"}))
    context.evidence.append(EvidenceItem(id="ev-2", type="TELEMETRY_EVENT", timestamp="now", source="app", summary="Login status': 'success", content={"session": "sess-xyz"}))
    conflicts = detect_evidence_conflicts(context)
    assert len(conflicts) > 0
    assert conflicts[0].conflict_type == "SUCCESS_VS_DENIED"
    assert conflicts[0].entity == "sess-xyz"
