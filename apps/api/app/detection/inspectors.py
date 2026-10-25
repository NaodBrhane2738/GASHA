"""
==============================================================================
FILE: apps/api/app/detection/inspectors.py
ROLE / OWNERSHIP: Cybersecurity Engineers
OBJECTIVE: Deterministic payload inspectors that flag malformed or hostile request content
           and explain *why* each request was flagged (root-cause diagnostics).
TOOLS & LIBRARIES: re, json, urllib.parse
KEY FEATURES:
  - Malformed JSON (with parser position), oversized bodies.
  - Signature checks for SQL injection, path traversal and reflected XSS probes,
    applied to path, query parameters and JSON/form body fields.
EXPECTED RESULTS / BEHAVIOR:
  - Pure functions: no I/O, no state; safe to unit test and to run on telemetry replays.
  - Evidence excerpts are truncated and control characters stripped before storage.
==============================================================================
"""

import json
import re
from dataclasses import dataclass
from typing import Any, Iterator, List, Optional, Tuple
from urllib.parse import parse_qsl, unquote_plus

EVIDENCE_MAX_CHARS = 120


@dataclass(frozen=True)
class Signature:
    rule_id: str
    category: str
    severity: str
    pattern: re.Pattern
    diagnostic: str


SIGNATURES: List[Signature] = [
    Signature(
        "RULE-INJ-002", "SQL_INJECTION", "CRITICAL",
        re.compile(r"(\bunion\b[\s/*]+(all[\s/*]+)?select\b|\bselect\b.+\bfrom\b.+\bwhere\b"
                   r"|;\s*(drop|delete|truncate|alter|insert|update)\b"
                   r"|\b(sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b)", re.I),
        "Input contains SQL control syntax (UNION/stacked query/time-delay function). If this value "
        "is concatenated into a query string the database will execute attacker-supplied SQL.",
    ),
    Signature(
        "RULE-INJ-003", "SQL_INJECTION", "HIGH",
        re.compile(r"(['\"])\s*(or|and)\s+['\"]?(\w+)['\"]?\s*=\s*['\"]?\3\b|(['\"])\s*(--|#|/\*)", re.I),
        "Input closes a string literal and appends a tautology or comment (e.g. ' OR 1=1 --), the "
        "classic pattern for bypassing WHERE clauses in string-built SQL.",
    ),
    Signature(
        "RULE-TRV-001", "PATH_TRAVERSAL", "HIGH",
        re.compile(r"(\.\.[/\\])|(%2e%2e(%2f|%5c|/|\\))|(/etc/(passwd|shadow))|(\\windows\\win\.ini)", re.I),
        "Input contains relative path segments or well-known system file paths. If used to build a "
        "filesystem path without canonicalisation it can escape the intended directory.",
    ),
    Signature(
        "RULE-XSS-001", "XSS_PROBE", "MEDIUM",
        re.compile(r"(<\s*script\b|javascript\s*:|\bon(error|load|mouseover|focus)\s*=|<\s*(iframe|svg|img)\b[^>]*\bon\w+\s*=)", re.I),
        "Input contains executable HTML/JS markup. Rendering it without contextual output encoding "
        "would execute script in other users' browsers.",
    ),
]


@dataclass
class RawFinding:
    rule_id: str
    category: str
    severity: str
    location: str
    diagnostic: str
    field: Optional[str] = None
    evidence: Optional[str] = None


def sanitize_excerpt(value: str, match: Optional[re.Match] = None) -> str:
    """Return a short, printable window around the match for analyst display."""
    if match:
        start = max(0, match.start() - 30)
        value = value[start:start + EVIDENCE_MAX_CHARS]
    else:
        value = value[:EVIDENCE_MAX_CHARS]
    return "".join(ch if ch.isprintable() else "�" for ch in value)


def _iter_json_strings(node: Any, prefix: str = "") -> Iterator[Tuple[str, str]]:
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _iter_json_strings(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(node, list):
        for i, v in enumerate(node[:200]):
            yield from _iter_json_strings(v, f"{prefix}[{i}]")
    elif isinstance(node, str):
        yield prefix or "$", node


def scan_value(value: str, location: str, field: Optional[str]) -> List[RawFinding]:
    results: List[RawFinding] = []
    decoded = unquote_plus(value) if "%" in value or "+" in value else value
    seen = set()
    for sig in SIGNATURES:
        if sig.category in seen:
            continue
        m = sig.pattern.search(decoded)
        if m:
            seen.add(sig.category)
            results.append(RawFinding(
                rule_id=sig.rule_id, category=sig.category, severity=sig.severity,
                location=location, field=field, diagnostic=sig.diagnostic,
                evidence=sanitize_excerpt(decoded, m),
            ))
    return results


def inspect_request(
    path: str,
    query_string: str,
    content_type: Optional[str],
    body: bytes,
    body_truncated: bool = False,
) -> List[RawFinding]:
    findings: List[RawFinding] = scan_value(path, "path", None)

    for name, value in parse_qsl(query_string, keep_blank_values=True):
        findings.extend(scan_value(value, "query", name))

    if not body:
        return findings

    ctype = (content_type or "").split(";")[0].strip().lower()
    text = body.decode("utf-8", errors="replace")

    if ctype == "application/json" or ctype.endswith("+json"):
        if body_truncated:
            # Only part of the body was buffered; JSON cannot be validated reliably.
            findings.extend(scan_value(text, "body", None))
            return findings
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as exc:
            findings.append(RawFinding(
                rule_id="RULE-PAY-001", category="MALFORMED_PAYLOAD", severity="MEDIUM",
                location="body", field=None,
                diagnostic=(f"Declared Content-Type is JSON but the body failed to parse: {exc.msg} "
                            f"at line {exc.lineno}, column {exc.colno}. Malformed bodies are a common "
                            "fuzzing signal and can trigger unhandled parser errors."),
                evidence=sanitize_excerpt(text[max(0, exc.pos - 40):]),
            ))
            return findings
        for field, value in _iter_json_strings(doc):
            findings.extend(scan_value(value, "body", field))
    elif ctype == "application/x-www-form-urlencoded":
        for name, value in parse_qsl(text, keep_blank_values=True):
            findings.extend(scan_value(value, "body", name))
    elif ctype.startswith("text/") or not ctype:
        findings.extend(scan_value(text, "body", None))

    return findings


def oversized_finding(limit_bytes: int) -> RawFinding:
    return RawFinding(
        rule_id="RULE-PAY-002", category="OVERSIZED_PAYLOAD", severity="MEDIUM",
        location="body",
        diagnostic=(f"Request body exceeded the {limit_bytes:,}-byte limit. Unbounded bodies allow "
                    "memory/CPU exhaustion against JSON parsers and upload handlers."),
    )
