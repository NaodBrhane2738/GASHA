"""
==============================================================================
FILE: apps/api/app/adaptive/remediation.py
ROLE / OWNERSHIP: Cybersecurity Engineers
OBJECTIVE: Static, reviewed hardening guidance keyed by finding category. Feeds the SOC
           Remediation & Analysis panel. Deterministic: no LLM output is shown here.
==============================================================================
"""

from typing import Dict, List

from app.schemas.soc import Finding, FindingAnalysis, Recommendation

_CSP = Recommendation(
    title="Ship a strict Content-Security-Policy",
    detail="Nonce-based script-src blocks injected inline script even if encoding is missed somewhere. "
           "Pair with frame-ancestors, base-uri and object-src restrictions.",
    snippet=("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}' 'strict-dynamic'; "
             "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"),
    snippetLanguage="http",
    reference="https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
)

_SCHEMA = Recommendation(
    title="Validate input against a strict schema at the boundary",
    detail="Reject unknown fields, enforce types, lengths and allowed character sets before business logic runs.",
    snippet=("from pydantic import BaseModel, ConfigDict, Field\n\n"
             "class SearchRequest(BaseModel):\n"
             "    model_config = ConfigDict(extra='forbid', strict=True)\n"
             "    query: str = Field(min_length=1, max_length=120, pattern=r'^[\\w\\s.-]+$')\n"
             "    page: int = Field(ge=1, le=500)"),
    snippetLanguage="python",
    reference="https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
)

KB: Dict[str, dict] = {
    "SQL_INJECTION": {
        "root": "A request value contained SQL syntax. The vulnerability exists only where that value is "
                "concatenated or interpolated into a query string instead of being bound as a parameter.",
        "impact": "Data exfiltration, authentication bypass, data tampering or destruction, and in some "
                  "configurations command execution on the database host.",
        "recs": [
            Recommendation(
                title="Use prepared statements / bound parameters everywhere",
                detail="Never build SQL with f-strings, % formatting or string concatenation. Bind values "
                       "and let the driver handle quoting.",
                snippet=("# SQLAlchemy\n"
                         "stmt = text('SELECT id, email FROM users WHERE email = :email')\n"
                         "row = (await session.execute(stmt, {'email': email})).first()\n\n"
                         "# asyncpg\n"
                         "row = await conn.fetchrow('SELECT id FROM users WHERE email = $1', email)"),
                snippetLanguage="python",
                reference="https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html",
            ),
            Recommendation(
                title="Allowlist identifiers that cannot be parameterised",
                detail="Column names and sort directions cannot be bound; map user choices to a fixed set.",
                snippet="SORTABLE = {'created': 'created_at', 'name': 'name'}\ncolumn = SORTABLE.get(sort, 'created_at')",
                snippetLanguage="python",
            ),
            Recommendation(
                title="Run the application with a least-privilege database role",
                detail="No DDL, no superuser, row-level security where available, so a missed injection "
                       "cannot drop tables or read other tenants' data.",
            ),
            _SCHEMA,
        ],
    },
    "PATH_TRAVERSAL": {
        "root": "A request value contained relative path segments or system file paths, targeting code that "
                "joins user input onto a filesystem path.",
        "impact": "Disclosure of configuration, credentials or source code; file overwrite if the path is "
                  "used for writes.",
        "recs": [
            Recommendation(
                title="Canonicalise and confine paths to a base directory",
                detail="Resolve the final path and verify it is still inside the allowed root before opening it.",
                snippet=("BASE = Path('/srv/uploads').resolve()\n"
                         "target = (BASE / user_name).resolve()\n"
                         "if not target.is_relative_to(BASE):\n"
                         "    raise HTTPException(400, 'invalid path')"),
                snippetLanguage="python",
                reference="https://owasp.org/www-community/attacks/Path_Traversal",
            ),
            Recommendation(
                title="Address files by opaque ID, not by name",
                detail="Store uploads under generated UUIDs and keep the user-facing name only as metadata.",
            ),
            _SCHEMA,
        ],
    },
    "XSS_PROBE": {
        "root": "A request value contained HTML/JavaScript markup. It becomes exploitable where the value is "
                "rendered into a page without contextual output encoding.",
        "impact": "Session hijacking, credential phishing inside the trusted origin, and actions performed "
                  "as the victim.",
        "recs": [
            Recommendation(
                title="Encode output for its context",
                detail="Rely on React/Jinja auto-escaping; never pass user input to dangerouslySetInnerHTML, "
                       "innerHTML or |safe. Sanitise rich text with a vetted library (DOMPurify).",
                reference="https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            ),
            _CSP,
            Recommendation(
                title="Harden session cookies",
                detail="Set HttpOnly, Secure and SameSite=Lax/Strict so script cannot read session tokens.",
                snippet="Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict; Path=/",
                snippetLanguage="http",
            ),
        ],
    },
    "MALFORMED_PAYLOAD": {
        "root": "The body did not match its declared Content-Type. This is typical of fuzzers and scanners "
                "probing for unhandled parser exceptions and verbose error pages.",
        "impact": "Stack traces or framework internals leaked in error responses; crashes in hand-rolled parsers.",
        "recs": [
            _SCHEMA,
            Recommendation(
                title="Return generic errors",
                detail="Map parse/validation failures to a fixed problem+json 400 response; log details server-side only.",
            ),
            Recommendation(
                title="Enforce Content-Type and body size limits at the edge",
                detail="Reject unexpected media types with 415 and bodies over the route's maximum with 413.",
            ),
        ],
    },
    "OVERSIZED_PAYLOAD": {
        "root": "The request body exceeded the configured maximum size.",
        "impact": "Memory and CPU exhaustion in body parsers; amplified cost on serverless platforms.",
        "recs": [
            Recommendation(
                title="Set per-route body limits",
                detail="Apply limits at the reverse proxy and in the application; stream large uploads to storage.",
                snippet="client_max_body_size 1m;  # nginx",
                snippetLanguage="nginx",
            ),
        ],
    },
    "RATE_LIMIT_EXCEEDED": {
        "root": "A single source sent more requests than the policy allows within the sliding window.",
        "impact": "Resource exhaustion, scraping, credential stuffing or enumeration at automated speed.",
        "recs": [
            Recommendation(
                title="Tier limits by route sensitivity",
                detail="Apply stricter budgets to login, password reset, search and export endpoints than to static reads.",
            ),
            Recommendation(
                title="Advertise limits with standard headers",
                detail="Return 429 with Retry-After and RateLimit-* headers so well-behaved clients back off.",
                snippet="HTTP/1.1 429 Too Many Requests\nRetry-After: 30\nRateLimit-Limit: 60\nRateLimit-Remaining: 0",
                snippetLanguage="http",
            ),
            Recommendation(
                title="Share counters across instances",
                detail="Move the sliding window to Redis when running more than one API worker so limits are global.",
            ),
        ],
    },
    "BRUTE_FORCE_AUTH": {
        "root": "Repeated authentication failures from one source within a short window.",
        "impact": "Account takeover through password guessing or credential stuffing.",
        "recs": [
            Recommendation(
                title="Require MFA and screen breached passwords",
                detail="MFA defeats stuffed credentials; reject passwords found in known breach corpora.",
                reference="https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            ),
            Recommendation(
                title="Throttle per account as well as per IP",
                detail="Distributed attacks rotate IPs; track failures per username with progressive delays.",
            ),
            Recommendation(
                title="Use uniform login responses",
                detail="Return the same message and timing for unknown users and wrong passwords to prevent enumeration.",
            ),
        ],
    },
}


def analyze(finding: Finding, related: List[Finding]) -> FindingAnalysis:
    entry = KB.get(finding.category)
    if not entry:
        return FindingAnalysis(finding=finding, rootCause=finding.diagnostic, impact="Unknown", recommendations=[],
                               relatedFindings=related)
    return FindingAnalysis(
        finding=finding,
        rootCause=f"{finding.diagnostic} {entry['root']}",
        impact=entry["impact"],
        recommendations=entry["recs"],
        relatedFindings=related,
    )
