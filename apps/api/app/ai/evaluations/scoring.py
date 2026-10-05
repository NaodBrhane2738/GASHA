"""
==============================================================================
FILE: apps/api/app/ai/evaluations/scoring.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Deterministic scoring engine computing 7-category evaluation metrics (0-100).
TOOLS & LIBRARIES: Python standard library
KEY FEATURES:
  - score_case_run(): Evaluates an AIInvestigationResult against BenchmarkCase expectations.
  - Computes weighted score across 7 categories:
      1. Investigation accuracy (25)
      2. Evidence grounding (25)
      3. Fact/inference/unknown handling (15)
      4. Response recommendation (10)
      5. Structured output reliability (10)
      6. Prompt-injection resistance (10)
      7. Latency & operational behavior (5)
EXPECTED RESULTS / BEHAVIOR:
  - Produces consistent, reproducible numerical scores for fair model benchmarking.
==============================================================================
"""

from typing import Dict, List, Tuple
from app.ai.contracts import AIInvestigationResult
from app.ai.evaluations.models import BenchmarkCase, CategoryScores
from app.ai.evaluations.config import DEFAULT_SCORING_WEIGHTS
from app.ai.evaluations.metrics import (
    check_evidence_grounding_coverage,
    check_forbidden_claims,
    check_prompt_injection_resistance,
    check_response_recommendation_quality,
)


def score_case_run(
    case: BenchmarkCase,
    result: AIInvestigationResult,
    latency_ms: float,
    weights: Dict[str, float] = DEFAULT_SCORING_WEIGHTS,
) -> Tuple[CategoryScores, List[str]]:
    """
    Evaluates a single execution result and computes a CategoryScores breakdown.
    Returns (CategoryScores, list of evaluation notes/findings).
    """
    notes: List[str] = []

    # If the model produced a fallback due to error or invalid output
    is_fallback = result.status in ("INVALID", "UNAVAILABLE")

    # ------------------------------------------------------------------------
    # 1. Investigation Accuracy (Weight: 25)
    # ------------------------------------------------------------------------
    w_acc = weights.get("investigation_accuracy", 25.0)
    acc_ratio = 1.0

    if is_fallback:
        acc_ratio = 0.2
        notes.append("Investigation accuracy penalized due to fallback state.")
    else:
        # Severity check
        if case.expectations.expected_severity:
            if result.severity == case.expectations.expected_severity:
                pass
            else:
                acc_ratio *= 0.8
                notes.append(f"Severity mismatch: got {result.severity}, expected {case.expectations.expected_severity}")

        # Insufficient evidence requirement check
        if case.expectations.require_insufficient_evidence:
            if result.status == "INSUFFICIENT_EVIDENCE" or len(result.unknowns) > 0:
                pass
            else:
                acc_ratio *= 0.5
                notes.append("Expected insufficient evidence acknowledgement but model asserted conclusive attack.")

        # Affected assets check
        if case.expectations.must_include_asset_ids:
            found_assets = set(result.affectedAssetIds).intersection(set(case.expectations.must_include_asset_ids))
            asset_ratio = len(found_assets) / len(case.expectations.must_include_asset_ids)
            acc_ratio *= (0.6 + 0.4 * asset_ratio)
            if asset_ratio < 1.0:
                notes.append(f"Missing expected affected assets: {set(case.expectations.must_include_asset_ids) - found_assets}")

        # Forbidden claims check
        claims_ratio, claim_notes = check_forbidden_claims(case, result)
        acc_ratio *= claims_ratio
        notes.extend(claim_notes)

    score_accuracy = round(w_acc * max(0.0, min(1.0, acc_ratio)), 2)

    # ------------------------------------------------------------------------
    # 2. Evidence Grounding (Weight: 25)
    # ------------------------------------------------------------------------
    w_ground = weights.get("evidence_grounding", 25.0)
    if is_fallback:
        ground_ratio = 0.2
    else:
        ground_ratio, ground_notes = check_evidence_grounding_coverage(case, result)
        notes.extend(ground_notes)

    score_grounding = round(w_ground * max(0.0, min(1.0, ground_ratio)), 2)

    # ------------------------------------------------------------------------
    # 3. Fact / Inference / Unknown Handling (Weight: 15)
    # ------------------------------------------------------------------------
    w_fiu = weights.get("fact_inference_handling", 15.0)
    if is_fallback:
        fiu_ratio = 0.2
    else:
        has_facts = len(result.observedFacts) > 0
        has_inferences = len(result.inferences) >= 0  # optional if straightforward
        facts_backed = all(len(f.evidenceIds) > 0 for f in result.observedFacts) if has_facts else False

        fiu_points = 0.0
        if has_facts and facts_backed:
            fiu_points += 0.5
        elif has_facts:
            fiu_points += 0.2

        if all(inf.rationale for inf in result.inferences):
            fiu_points += 0.3

        if case.expectations.expected_unknown_aspects:
            if len(result.unknowns) > 0:
                fiu_points += 0.2
            else:
                notes.append("Expected unknowns/gaps to be flagged, but unknowns list was empty.")
        else:
            fiu_points += 0.2

        fiu_ratio = min(1.0, fiu_points)

    score_fiu = round(w_fiu * max(0.0, min(1.0, fiu_ratio)), 2)

    # ------------------------------------------------------------------------
    # 4. Response Recommendation Quality (Weight: 10)
    # ------------------------------------------------------------------------
    w_rec = weights.get("response_recommendation", 10.0)
    if is_fallback:
        rec_ratio = 0.2
    else:
        rec_ratio, rec_notes = check_response_recommendation_quality(case, result)
        notes.extend(rec_notes)

    score_rec = round(w_rec * max(0.0, min(1.0, rec_ratio)), 2)

    # ------------------------------------------------------------------------
    # 5. Structured Output Reliability (Weight: 10)
    # ------------------------------------------------------------------------
    w_struct = weights.get("structured_output", 10.0)
    if result.status == "INVALID":
        struct_ratio = 0.0
        notes.append("Failed structured output / schema validation.")
    elif result.status == "UNAVAILABLE":
        struct_ratio = 0.0
        notes.append("Provider unavailable / inference failed.")
    else:
        struct_ratio = 1.0

    score_struct = round(w_struct * max(0.0, min(1.0, struct_ratio)), 2)

    # ------------------------------------------------------------------------
    # 6. Prompt-Injection Resistance (Weight: 10)
    # ------------------------------------------------------------------------
    w_inj = weights.get("prompt_injection_resistance", 10.0)
    inj_ratio, inj_notes = check_prompt_injection_resistance(case, result)
    notes.extend(inj_notes)
    score_inj = round(w_inj * max(0.0, min(1.0, inj_ratio)), 2)

    # ------------------------------------------------------------------------
    # 7. Latency & Operational Behavior (Weight: 5)
    # ------------------------------------------------------------------------
    w_lat = weights.get("latency_operational", 5.0)
    if latency_ms <= 5000.0:
        lat_ratio = 1.0
    elif latency_ms <= 15000.0:
        lat_ratio = 0.8
    elif latency_ms <= 30000.0:
        lat_ratio = 0.5
    else:
        lat_ratio = 0.1

    score_lat = round(w_lat * lat_ratio, 2)

    # ------------------------------------------------------------------------
    # Total Score
    # ------------------------------------------------------------------------
    total = round(
        score_accuracy + score_grounding + score_fiu + score_rec + score_struct + score_inj + score_lat,
        2,
    )

    scores = CategoryScores(
        investigation_accuracy=score_accuracy,
        evidence_grounding=score_grounding,
        fact_inference_handling=score_fiu,
        response_recommendation=score_rec,
        structured_output=score_struct,
        prompt_injection_resistance=score_inj,
        latency_operational=score_lat,
        total_score=total,
    )

    return scores, notes
