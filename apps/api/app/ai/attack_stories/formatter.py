"""
==============================================================================
FILE: apps/api/app/ai/attack_stories/formatter.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Presentation formatters for AttackStory instances.
           Supports Markdown report rendering, executive summary extraction,
           and translation to canonical AttackStorySchema.
TOOLS & LIBRARIES: Python standard library
==============================================================================
"""

from typing import Dict, Any
from app.ai.contracts import AttackStory


def format_attack_story_markdown(story: AttackStory) -> str:
    """
    Renders an AttackStory into a clear, professional Markdown security narrative
    designed for security analysts and judges.
    """
    lines = [
        f"# Attack Story: {story.title}",
        f"**Incident ID:** `{story.incidentId}` | **Severity:** `{story.severity}` | **Confidence:** `{story.confidence:.2f}`",
        "",
        "## Executive Summary",
        story.summary,
        "",
        "## Chronological Progression",
    ]

    if not story.stages:
        lines.append("*No chronological stages established from available evidence.*")
    else:
        for stage in story.stages:
            status_tag = " [ATTEMPT ONLY]" if stage.isAttemptOnly else ""
            time_str = f" ({stage.timestamp})" if stage.timestamp else ""
            phase_str = f"**[{stage.phase}]** " if stage.phase else ""
            assets_str = f" | Affected: `{', '.join(stage.affectedAssetIds)}`" if stage.affectedAssetIds else ""
            evidence_str = f" | Evidence: `{', '.join(stage.evidenceIds)}`" if stage.evidenceIds else ""

            lines.append(f"### Stage {stage.order}: {phase_str}{time_str}{status_tag}")
            lines.append(f"{stage.description}{assets_str}{evidence_str}")
            lines.append("")

    if story.observedFacts:
        lines.append("## Observed Facts (Directly Proven by Evidence)")
        for fact in story.observedFacts:
            ev_str = f" (Evidence: `{', '.join(fact.evidenceIds)}`)" if fact.evidenceIds else ""
            lines.append(f"- {fact.statement}{ev_str}")
        lines.append("")

    if story.inferences:
        lines.append("## Reasonable Inferences (Deductions)")
        for inf in story.inferences:
            supp_str = f" (Grounding: `{', '.join(inf.supportingEvidenceIds)}`)" if inf.supportingEvidenceIds else ""
            lines.append(f"- **Deduction:** {inf.statement}{supp_str}")
            lines.append(f"  *Rationale:* {inf.rationale} (Confidence: {inf.confidence:.2f})")
        lines.append("")

    if story.unknowns:
        lines.append("## Unknowns & Investigation Gaps")
        for unk in story.unknowns:
            sig_str = f" *Significance:* {unk.significance}" if unk.significance else ""
            lines.append(f"- {unk.statement}{sig_str}")
        lines.append("")

    lines.append("## Uncertainty & Limitations")
    lines.append(story.uncertainty)

    return "\n".join(lines)


def format_attack_story_summary(story: AttackStory) -> str:
    """
    Extracts a concise 1-2 sentence executive briefing from the attack story.
    """
    return story.summary


def convert_to_schema_attack_story(story: AttackStory) -> Dict[str, Any]:
    """
    Converts an AttackStory model into a dict conforming to
    app.schemas.investigation.AttackStorySchema.
    """
    facts = [f"{fact.statement} (Evidence: {', '.join(fact.evidenceIds)})" for fact in story.observedFacts]
    inferences = [f"{inf.statement} [Rationale: {inf.rationale}]" for inf in story.inferences]
    unknowns = [unk.statement for unk in story.unknowns]
    if story.uncertainty and story.uncertainty not in unknowns:
        unknowns.append(f"Uncertainty: {story.uncertainty}")

    return {
        "observedFacts": facts,
        "reasonableInferences": inferences,
        "unknownsAndGaps": unknowns,
        "narrativeSummary": story.summary,
    }
