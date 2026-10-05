"""
==============================================================================
FILE: apps/api/app/ai/recommendations/formatter.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Presentation formatters for AIRecommendation lists.
           Renders analyst-facing Markdown reports with evidence grounding
           and manual approval notices.
TOOLS & LIBRARIES: Python standard library
==============================================================================
"""

from typing import List
from app.ai.contracts import AIRecommendation


def format_recommendations_markdown(recommendations: List[AIRecommendation]) -> str:
    """
    Renders a list of AIRecommendations into a clean Markdown advisory table.
    """
    if not recommendations:
        return "*No automated response recommendations available for this incident.*"

    lines = [
        "### Defensive Recommendations (Advisory Only)",
        "> ⚠️ **Notice:** Recommendations require explicit manual authorization by a security operator before execution.",
        "",
        "| Priority | Action | Target | Target Type | Confidence | Evidence Citations | Expected Impact |",
        "|---|---|---|---|---|---|---|",
    ]

    for rec in recommendations:
        prio = rec.priority or "HIGH"
        eids = ", ".join([f"`{eid}`" for eid in rec.supportingEvidenceIds]) if rec.supportingEvidenceIds else "None"
        lines.append(
            f"| **{prio}** | `{rec.actionType}` | `{rec.targetIdentifier}` | `{rec.targetType}` | {rec.confidence:.2f} | {eids} | {rec.expectedImpact} |"
        )

    lines.append("")
    lines.append("#### Detailed Rationales:")
    for rec in recommendations:
        lines.append(f"- **`{rec.actionType}` on `{rec.targetIdentifier}`:** {rec.rationale}")

    return "\n".join(lines)
