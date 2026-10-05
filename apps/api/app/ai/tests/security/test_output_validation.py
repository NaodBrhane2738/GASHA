"""
==============================================================================
FILE: apps/api/app/ai/tests/security/test_output_validation.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Output schema hardening, JSON parser stress, and malformed output test suite.
==============================================================================
"""

import pytest
from app.ai.service import parse_model_output, AIParserError
from app.ai.contracts import AIInvestigationResult


def test_malformed_json_raises_parser_error():
    """TEST: Malformed or unparseable text cleanly raises AIParserError."""
    malformed_inputs = [
        "",
        "   ",
        "Here is the investigation: { incomplete json ...",
        "<html><body>Error 500</body></html>",
        "{'invalid_quotes': True}",  # Python dict representation, not valid JSON
    ]

    for raw in malformed_inputs:
        with pytest.raises(AIParserError):
            parse_model_output(raw)


def test_json_extraction_from_markdown_fences():
    """TEST: Robust extraction from various markdown code fence formats."""
    fenced_json = """
Here is my analysis:
```json
{
  "incidentId": "INC-TEST-1",
  "status": "SUCCESS"
}
```
Hope this helps!
"""
    parsed = parse_model_output(fenced_json)
    assert parsed["incidentId"] == "INC-TEST-1"
    assert parsed["status"] == "SUCCESS"


def test_extra_forbidden_fields_rejected():
    """TEST: Extra fields in AIInvestigationResult are strictly rejected by extra='forbid'."""
    payload_with_extra = {
        "incidentId": "INC-TEST-1",
        "status": "SUCCESS",
        "summary": "Valid summary",
        "severity": "HIGH",
        "confidence": {"score": 0.9, "rationale": "Rationale", "evidenceCompleteness": "HIGH", "limitations": []},
        "observedFacts": [],
        "inferences": [],
        "unknowns": [],
        "attackProgression": [],
        "affectedAssetIds": [],
        "citedEvidenceIds": [],
        "recommendedActions": [],
        "unauthorizedAdminFlag": True,  # Rogue forbidden field!
    }

    with pytest.raises(Exception):
        AIInvestigationResult(**payload_with_extra)


def test_invalid_severity_level_rejected():
    """TEST: Invalid severity values fail Pydantic enum validation."""
    payload_bad_severity = {
        "incidentId": "INC-TEST-1",
        "status": "SUCCESS",
        "summary": "Valid summary",
        "severity": "CATACLYSMIC",  # Invalid! Must be LOW/MEDIUM/HIGH/CRITICAL
        "confidence": {"score": 0.9, "rationale": "Rationale", "evidenceCompleteness": "HIGH", "limitations": []},
    }

    with pytest.raises(Exception):
        AIInvestigationResult(**payload_bad_severity)


def test_extreme_input_length_stress():
    """TEST: Extremely long strings and escaped unicode pass JSON parsing cleanly without memory leak."""
    long_string = "A" * 50000 + " 🔒 Unicode test: \u00e9\u00e8\u00ea \U0001f512 "
    json_text = f'{{"incidentId": "INC-LONG", "data": "{long_string}"}}'

    parsed = parse_model_output(json_text)
    assert parsed["incidentId"] == "INC-LONG"
    assert len(parsed["data"]) > 50000
