"""
==============================================================================
FILE: apps/api/app/ai/attack_stories/__init__.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Attack story generation, formatting, and fallback exports.
==============================================================================
"""

from app.ai.contracts import AttackStory, AttackStoryStage
from app.ai.attack_stories.generator import generate_attack_story
from app.ai.attack_stories.formatter import (
    format_attack_story_markdown,
    format_attack_story_summary,
    convert_to_schema_attack_story,
)
from app.ai.attack_stories.fallback import create_fallback_attack_story

__all__ = [
    "AttackStory",
    "AttackStoryStage",
    "generate_attack_story",
    "format_attack_story_markdown",
    "format_attack_story_summary",
    "convert_to_schema_attack_story",
    "create_fallback_attack_story",
]
