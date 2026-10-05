"""
==============================================================================
FILE: apps/api/app/ai/prompts/recommendations.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Prompt templates for Defensive Recommendations in GASHA.
           Constrains the LLM to propose only allowlisted response actions,
           enforces evidence justification, minimum necessary action, and
           prevents autonomous command execution syntax.
TOOLS & LIBRARIES: Python standard library
==============================================================================
"""

import json
from typing import Tuple
from app.ai.contracts import InvestigationContext, AIInvestigationResult

SYSTEM_RECOMMENDATIONS_PROMPT = """You are the GASHA Defensive Recommendation Engine.
Your task is to analyze the validated incident investigation and recommend the minimum necessary set of defensive response actions.

CRITICAL OPERATIONAL CONSTRAINTS:
1. STRICT ACTION ALLOWLIST:
   You may ONLY recommend the following action types:
   - BLOCK_SOURCE (targetType: IP_ADDRESS)
   - DISABLE_SESSION (targetType: USER_SESSION or SESSION_ID)
   - ISOLATE_RESOURCE (targetType: ASSET_ID)
   Do NOT propose shell commands, SQL queries, firewall scripts, or unauthorized action types.

2. MINIMUM NECESSARY ACTION:
   Propose the smallest justified set of actions (1-2 strong recommendations). Do not recommend every available action.

3. EVIDENCE-BACKED JUSTIFICATION:
   Every recommendation must cite supporting evidence IDs from the context.

4. ADVISORY ONLY:
   You are recommending actions for human operator approval. You never execute actions.

5. OUTPUT FORMAT:
   Respond with ONLY a valid JSON array of recommendations:
[
  {
    "id": "rec-1",
    "actionType": "BLOCK_SOURCE" | "DISABLE_SESSION" | "ISOLATE_RESOURCE",
    "targetIdentifier": "<IP, Session ID, or Asset ID>",
    "targetType": "IP_ADDRESS" | "USER_SESSION" | "SESSION_ID" | "ASSET_ID",
    "rationale": "<Grounded reason explaining why this containment is required>",
    "confidence": <float 0.0 to 1.0>,
    "expectedImpact": "<Anticipated containment effect>",
    "supportingEvidenceIds": ["<eid1>"],
    "priority": "IMMEDIATE" | "HIGH" | "MEDIUM" | "LOW"
  }
]
"""


def build_recommendations_prompt(
    investigation_result: AIInvestigationResult,
    context: InvestigationContext,
) -> Tuple[str, str]:
    """
    Constructs the prompt pair for dedicated response recommendations synthesis.
    """
    bundle = {
        "incident": context.incident.model_dump() if context.incident else {},
        "severity": investigation_result.severity,
        "summary": investigation_result.summary,
        "affectedAssetIds": investigation_result.affectedAssetIds,
        "evidence": [e.model_dump() for e in context.evidence],
        "availableResponseActions": [a.model_dump() for a in context.availableResponseActions],
    }

    user_prompt = f"""Recommend defensive response actions for the following security incident:

<untrusted_security_context>
{json.dumps(bundle, indent=2)}
</untrusted_security_context>

Generate the recommendations JSON array:"""

    return SYSTEM_RECOMMENDATIONS_PROMPT, user_prompt
