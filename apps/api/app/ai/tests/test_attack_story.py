"""
==============================================================================
FILE: apps/api/app/ai/tests/test_attack_story.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Unit and integration tests for AttackStory generation, chronological
           reconstruction, attempt/success distinctions, evidence grounding,
           and uncertainty preservation.
==============================================================================
"""

import pytest
from app.ai.contracts import (
    InvestigationContext,
    IncidentContext,
    EvidenceItem,
    DetectionContext,
    AssetContext,
    AIInvestigationResult,
    ObservedFact,
    Inference,
    Unknown,
    AttackProgressionItem,
    ConfidenceAssessment,
)
from app.ai.attack_stories import (
    generate_attack_story,
    format_attack_story_markdown,
    format_attack_story_summary,
    convert_to_schema_attack_story,
    create_fallback_attack_story,
)


def make_sample_incident_context() -> InvestigationContext:
    """Constructs a test incident context representing Section 19 synthetic example."""
    return InvestigationContext(
        incident=IncidentContext(
            id="INC-SYNTH-19",
            title="Credential Brute Force and Unauthorized Access Attempt",
            severity="HIGH",
            status="ACTIVE",
            primaryAffectedAssetId="asset-auth-api",
            relatedAssetIds=["asset-customer-db"],
            detectionEventIds=["DET-101", "DET-102"],
            createdAt="2026-09-24T14:32:00Z",
            updatedAt="2026-09-24T14:32:15Z",
        ),
        evidence=[
            EvidenceItem(
                id="E101",
                type="TELEMETRY_EVENT",
                source="asset-auth-api",
                timestamp="2026-09-24T14:32:01Z",
                summary="AUTH_FAILURE from 203.0.113.45",
                content={"sourceIp": "203.0.113.45", "attempt": 1},
                verified=True,
            ),
            EvidenceItem(
                id="E102",
                type="TELEMETRY_EVENT",
                source="asset-auth-api",
                timestamp="2026-09-24T14:32:04Z",
                summary="AUTH_FAILURE from 203.0.113.45",
                content={"sourceIp": "203.0.113.45", "attempt": 2},
                verified=True,
            ),
            EvidenceItem(
                id="E103",
                type="TELEMETRY_EVENT",
                source="asset-auth-api",
                timestamp="2026-09-24T14:32:08Z",
                summary="SUSPICIOUS_REQUEST to /api/v1/auth",
                content={"sourceIp": "203.0.113.45", "endpoint": "/api/v1/auth"},
                verified=True,
            ),
            EvidenceItem(
                id="E104",
                type="TELEMETRY_EVENT",
                source="asset-customer-db",
                timestamp="2026-09-24T14:32:11Z",
                summary="UNAUTHORIZED_RESOURCE_ACCESS attempt on Customer DB",
                content={"sourceIp": "203.0.113.45", "target": "customer_records", "statusCode": 403},
                verified=True,
            ),
        ],
        detections=[
            DetectionContext(
                id="DET-101",
                ruleId="RULE-BRUTE",
                ruleName="Authentication Brute Force",
                description="Consecutive authentication failures",
                severity="HIGH",
                confidence=0.95,
                matchedEventIds=["E101", "E102"],
                primaryAssetId="asset-auth-api",
                timestamp="2026-09-24T14:32:04Z",
                evidenceSummary="Consecutive auth failures from 203.0.113.45",
            ),
            DetectionContext(
                id="DET-102",
                ruleId="RULE-UNAUTH-ACCESS",
                ruleName="Unauthorized Resource Access Attempt",
                description="Blocked attempt to query customer database",
                severity="HIGH",
                confidence=0.9,
                matchedEventIds=["E104"],
                primaryAssetId="asset-customer-db",
                timestamp="2026-09-24T14:32:11Z",
                evidenceSummary="403 Forbidden on Customer DB query from 203.0.113.45",
            ),
        ],
        assets=[
            AssetContext(
                id="asset-auth-api",
                name="Authentication API Gateway",
                type="API_GATEWAY",
                criticality="HIGH",
            ),
            AssetContext(
                id="asset-customer-db",
                name="Customer Database",
                type="DATABASE",
                criticality="CRITICAL",
            ),
        ],
    )


def test_1_successful_attack_story_generation():
    """TEST 1: Valid AIInvestigationResult generates structured, complete AttackStory."""
    context = make_sample_incident_context()
    result = AIInvestigationResult(
        incidentId="INC-SYNTH-19",
        status="SUCCESS",
        summary="Repeated authentication failures were followed by suspicious application activity and an unauthorized access attempt against a sensitive resource.",
        severity="HIGH",
        confidence=ConfidenceAssessment(
            score=0.92,
            rationale="High telemetry correlation across auth and database endpoints.",
            evidenceCompleteness="HIGH",
            limitations=["No data exfiltration established."],
        ),
        observedFacts=[
            ObservedFact(statement="Two consecutive authentication failures occurred from 203.0.113.45.", evidenceIds=["E101", "E102"]),
            ObservedFact(statement="An unauthorized resource access request was blocked with status 403.", evidenceIds=["E104"]),
        ],
        inferences=[
            Inference(
                statement="The attacker attempted to pivot from API gateway to customer records.",
                rationale="Request originated from same source IP within 10 seconds.",
                supportingEvidenceIds=["E103", "E104"],
                confidence=0.88,
            )
        ],
        unknowns=[
            Unknown(
                statement="Whether credential database was targeted directly.",
                significance="Determines if credentials were known beforehand.",
            )
        ],
        attackProgression=[
            AttackProgressionItem(
                stepOrder=1,
                phase="Initial Access",
                timestamp="2026-09-24T14:32:01Z",
                sourceEntity="203.0.113.45",
                targetAssetId="asset-auth-api",
                description="Repeated failed authentication attempts.",
                isAttemptOnly=True,
                evidenceIds=["E101", "E102"],
            ),
            AttackProgressionItem(
                stepOrder=2,
                phase="Discovery",
                timestamp="2026-09-24T14:32:08Z",
                sourceEntity="203.0.113.45",
                targetAssetId="asset-auth-api",
                description="Suspicious request probing API endpoints.",
                isAttemptOnly=False,
                evidenceIds=["E103"],
            ),
            AttackProgressionItem(
                stepOrder=3,
                phase="Unauthorized Access",
                timestamp="2026-09-24T14:32:11Z",
                sourceEntity="203.0.113.45",
                targetAssetId="asset-customer-db",
                description="Unauthorized access attempt against customer database (blocked).",
                isAttemptOnly=True,
                evidenceIds=["E104"],
            ),
        ],
        affectedAssetIds=["asset-auth-api", "asset-customer-db"],
        citedEvidenceIds=["E101", "E102", "E103", "E104"],
    )

    story = generate_attack_story(result, context)

    assert story.incidentId == "INC-SYNTH-19"
    assert len(story.stages) == 3
    assert story.severity == "HIGH"
    assert story.confidence == 0.92
    assert "E101" in story.citedEvidenceIds
    assert "E104" in story.citedEvidenceIds
    assert len(story.observedFacts) == 2
    assert len(story.inferences) == 1
    assert len(story.unknowns) == 1


def test_2_correct_chronological_ordering():
    """TEST 2: AttackStory stages preserve strict chronological ordering."""
    context = make_sample_incident_context()
    result = AIInvestigationResult(
        incidentId="INC-SYNTH-19",
        status="SUCCESS",
        summary="Sequential attack progression.",
        severity="HIGH",
        confidence=ConfidenceAssessment(score=0.9, rationale="Correlated", evidenceCompleteness="HIGH", limitations=[]),
        attackProgression=[
            AttackProgressionItem(
                stepOrder=2,
                phase="Discovery",
                timestamp="2026-09-24T14:32:08Z",
                description="Stage 2",
                evidenceIds=["E103"],
            ),
            AttackProgressionItem(
                stepOrder=1,
                phase="Initial Access",
                timestamp="2026-09-24T14:32:01Z",
                description="Stage 1",
                evidenceIds=["E101"],
            ),
        ],
    )

    story = generate_attack_story(result, context)
    assert len(story.stages) == 2
    assert story.stages[0].order == 1
    assert story.stages[0].description == "Stage 1"
    assert story.stages[1].order == 2
    assert story.stages[1].description == "Stage 2"


def test_3_evidence_ids_preserved_and_unknown_ids_filtered():
    """TEST 3: Valid evidence IDs are preserved; hallucinated IDs are filtered."""
    context = make_sample_incident_context()
    result = AIInvestigationResult(
        incidentId="INC-SYNTH-19",
        status="SUCCESS",
        summary="Testing evidence filtering.",
        severity="HIGH",
        confidence=ConfidenceAssessment(score=0.85, rationale="Rationale", evidenceCompleteness="HIGH", limitations=[]),
        attackProgression=[
            AttackProgressionItem(
                stepOrder=1,
                phase="Execution",
                description="Stage with valid and invalid evidence",
                evidenceIds=["E101", "E-FABRICATED-999"],
            )
        ],
    )

    story = generate_attack_story(result, context)
    assert len(story.stages) == 1
    assert "E101" in story.stages[0].evidenceIds
    assert "E-FABRICATED-999" not in story.stages[0].evidenceIds
    assert "E-FABRICATED-999" not in story.citedEvidenceIds


def test_4_attempt_vs_successful_compromise_distinction():
    """TEST 4: AttackStory preserves isAttemptOnly and does not claim successful breach without proof."""
    context = make_sample_incident_context()
    result = AIInvestigationResult(
        incidentId="INC-SYNTH-19",
        status="SUCCESS",
        summary="Attacker attempted brute force and database access.",
        severity="HIGH",
        confidence=ConfidenceAssessment(score=0.9, rationale="High correlation", evidenceCompleteness="HIGH", limitations=[]),
        attackProgression=[
            AttackProgressionItem(
                stepOrder=1,
                phase="Initial Access",
                description="Authentication failure attempt.",
                isAttemptOnly=True,
                evidenceIds=["E101"],
            )
        ],
    )

    story = generate_attack_story(result, context)
    assert story.stages[0].isAttemptOnly is True
    # Uncertainty explicitly mentions no proof of data exfiltration
    assert "data exfiltration is not established" in story.uncertainty.lower() or "exfiltration" in story.uncertainty.lower()


def test_5_missing_telemetry_stage_remains_uncertain():
    """TEST 5: Explicit unknown / missing intermediate telemetry is highlighted in story uncertainty."""
    context = make_sample_incident_context()
    result = AIInvestigationResult(
        incidentId="INC-SYNTH-19",
        status="SUCCESS",
        summary="Incomplete attack trajectory.",
        severity="MEDIUM",
        confidence=ConfidenceAssessment(score=0.7, rationale="Missing logs", evidenceCompleteness="LOW", limitations=["Missing intermediate proxy logs."]),
        unknowns=[
            Unknown(
                statement="The intermediate lateral traversal path is missing from telemetry.",
                significance="Determines attack route.",
            )
        ],
    )

    story = generate_attack_story(result, context)
    assert "missing" in story.uncertainty.lower() or "unobserved" in story.uncertainty.lower()


def test_6_synthetic_example_section_19():
    """TEST 6: Validates Section 19 prompt example behavior and formatters."""
    context = make_sample_incident_context()
    result = AIInvestigationResult(
        incidentId="INC-SYNTH-19",
        status="SUCCESS",
        summary="Repeated authentication failures were followed by suspicious application activity and an unauthorized access attempt against a sensitive resource. The available evidence does not establish successful data access or exfiltration.",
        severity="HIGH",
        confidence=ConfidenceAssessment(
            score=0.91,
            rationale="All stages grounded in E101-E104.",
            evidenceCompleteness="HIGH",
            limitations=["No data exfiltration established by supplied evidence."],
        ),
        observedFacts=[
            ObservedFact(statement="Failed logins observed from 203.0.113.45.", evidenceIds=["E101", "E102"]),
            ObservedFact(statement="403 Forbidden recorded on Customer DB.", evidenceIds=["E104"]),
        ],
        attackProgression=[
            AttackProgressionItem(stepOrder=1, phase="Initial Access", timestamp="2026-09-24T14:32:01Z", description="Auth failure 1", evidenceIds=["E101"]),
            AttackProgressionItem(stepOrder=2, phase="Initial Access", timestamp="2026-09-24T14:32:04Z", description="Auth failure 2", evidenceIds=["E102"]),
            AttackProgressionItem(stepOrder=3, phase="Suspicious Activity", timestamp="2026-09-24T14:32:08Z", description="Suspicious API request", evidenceIds=["E103"]),
            AttackProgressionItem(stepOrder=4, phase="Resource Access", timestamp="2026-09-24T14:32:11Z", description="Blocked DB access attempt", isAttemptOnly=True, evidenceIds=["E104"]),
        ],
        affectedAssetIds=["asset-auth-api", "asset-customer-db"],
        citedEvidenceIds=["E101", "E102", "E103", "E104"],
    )

    story = generate_attack_story(result, context)

    # Formatters test
    md = format_attack_story_markdown(story)
    assert "# Attack Story:" in md
    assert "Stage 1:" in md
    assert "Stage 4:" in md
    assert "203.0.113.45" in md or "E101" in md

    schema_dict = convert_to_schema_attack_story(story)
    assert "observedFacts" in schema_dict
    assert "reasonableInferences" in schema_dict
    assert "unknownsAndGaps" in schema_dict
    assert "narrativeSummary" in schema_dict
    assert len(schema_dict["observedFacts"]) == 2
