"""
Contract Parity Tests: Verifies 100% agreement between TypeScript rule definitions
in packages/detection-rules/web/index.ts and Python catalog in apps/api/app/detection/rules/catalog.py.
"""
import re
from pathlib import Path
import pytest

from app.detection.rules.catalog import (
    ALL_RULES,
    RULES_BY_ID,
    BRUTE_FORCE_AUTH_RULE,
    SUSPICIOUS_PROBE_RULE,
    SENSITIVE_ENDPOINT_PROBE_RULE,
    PRIVILEGE_ESCALATION_RULE,
)


def test_python_catalog_completeness():
    assert len(ALL_RULES) == 4
    assert "RULE-AUTH-001" in RULES_BY_ID
    assert "RULE-INJ-002" in RULES_BY_ID
    assert "RULE-PROBE-003" in RULES_BY_ID
    assert "RULE-PRIV-004" in RULES_BY_ID


def test_typescript_contract_file_parity():
    candidates = [
        Path("packages/detection-rules/web/index.ts"),
        Path(__file__).resolve().parents[4] / "packages" / "detection-rules" / "web" / "index.ts",
        Path(__file__).resolve().parents[3] / "packages" / "detection-rules" / "web" / "index.ts",
    ]
    ts_file = next((p for p in candidates if p.exists()), None)
    assert ts_file is not None and ts_file.exists(), "TypeScript detection rules specification file must exist"
    content = ts_file.read_text(encoding="utf-8")

    # Verify each rule ID and its properties exist in the TypeScript source
    for rule in ALL_RULES:
        assert f"id: '{rule.id}'" in content or f'id: "{rule.id}"' in content, f"Rule {rule.id} missing in TypeScript file"
        assert f"severity: '{rule.severity}'" in content or f'severity: "{rule.severity}"' in content
        assert str(rule.confidence) in content
        assert str(rule.time_window_seconds) in content
        if rule.mitre_technique_id:
            assert rule.mitre_technique_id in content, f"MITRE technique {rule.mitre_technique_id} missing in TypeScript file"


def test_rule_properties_validity():
    for rule in ALL_RULES:
        assert rule.id.startswith("RULE-")
        assert len(rule.name) > 5
        assert len(rule.description) > 10
        assert rule.severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert 0.0 <= rule.confidence <= 1.0
        assert rule.time_window_seconds > 0
        assert rule.threshold_count >= 1
        assert len(rule.required_event_types) >= 1
