"""
==============================================================================
FILE: apps/api/app/ai/recommendations/__init__.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Defensive recommendation generation, validation, formatting, and fallback exports.
==============================================================================
"""

from app.ai.contracts import AIRecommendation
from app.ai.recommendations.generator import generate_recommendations
from app.ai.recommendations.validator import (
    validate_recommendation,
    validate_recommendations_list,
)
from app.ai.recommendations.fallback import create_fallback_recommendations
from app.ai.recommendations.formatter import format_recommendations_markdown

__all__ = [
    "AIRecommendation",
    "generate_recommendations",
    "validate_recommendation",
    "validate_recommendations_list",
    "create_fallback_recommendations",
    "format_recommendations_markdown",
]
