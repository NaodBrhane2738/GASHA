// Reviewed hardening guidance per finding category (mirrors apps/api/app/adaptive/remediation.py).

import type { Finding, FindingAnalysis, FindingCategory, Recommendation } from '@/types/soc';

const CSP: Recommendation = {
  title: 'Ship a strict Content-Security-Policy',
  detail: 'Nonce-based script-src blocks injected inline script even if encoding is missed somewhere.',
  snippet:
    "Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
  snippetLanguage: 'http',
  reference: 'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html',
};

const SCHEMA: Recommendation = {
  title: 'Validate input against a strict schema at the boundary',
  detail: 'Reject unknown fields and enforce types, lengths and allowed characters before business logic runs.',
  snippet:
    "class SearchRequest(BaseModel):\n    model_config = ConfigDict(extra='forbid', strict=True)\n    query: str = Field(min_length=1, max_length=120, pattern=r'^[\\w\\s.-]+$')",
  snippetLanguage: 'python',
  reference: 'https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html',
};

const KB: Record<FindingCategory, { root: string; impact: string; recs: Recommendation[] }> = {
  SQL_INJECTION: {
    root: 'The vulnerability exists only where such a value is concatenated into a query string instead of being bound as a parameter.',
    impact: 'Data exfiltration, authentication bypass, data tampering or destruction.',
    recs: [
      {
        title: 'Use prepared statements / bound parameters everywhere',
        detail: 'Never build SQL with string formatting. Bind values and let the driver handle quoting.',
        snippet:
          "stmt = text('SELECT id, email FROM users WHERE email = :email')\nrow = (await session.execute(stmt, {'email': email})).first()",
        snippetLanguage: 'python',
        reference: 'https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html',
      },
      {
        title: 'Allowlist identifiers that cannot be parameterised',
        detail: 'Column names and sort directions cannot be bound; map user choices to a fixed set.',
        snippet: "SORTABLE = {'created': 'created_at', 'name': 'name'}\ncolumn = SORTABLE.get(sort, 'created_at')",
        snippetLanguage: 'python',
      },
      { title: 'Run with a least-privilege database role', detail: 'No DDL, no superuser, row-level security where available.' },
      SCHEMA,
    ],
  },
  PATH_TRAVERSAL: {
    root: 'Exploitable where user input is joined onto a filesystem path without canonicalisation.',
    impact: 'Disclosure of configuration, credentials or source code.',
    recs: [
      {
        title: 'Canonicalise and confine paths to a base directory',
        detail: 'Resolve the final path and verify it is still inside the allowed root.',
        snippet:
          "BASE = Path('/srv/uploads').resolve()\ntarget = (BASE / name).resolve()\nif not target.is_relative_to(BASE):\n    raise HTTPException(400)",
        snippetLanguage: 'python',
        reference: 'https://owasp.org/www-community/attacks/Path_Traversal',
      },
      { title: 'Address files by opaque ID, not by name', detail: 'Store uploads under generated UUIDs.' },
      SCHEMA,
    ],
  },
  XSS_PROBE: {
    root: 'Exploitable where the value is rendered into a page without contextual output encoding.',
    impact: 'Session hijacking and actions performed as the victim.',
    recs: [
      {
        title: 'Encode output for its context',
        detail: 'Rely on framework auto-escaping; never pass user input to dangerouslySetInnerHTML or innerHTML.',
        reference: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
      },
      CSP,
      {
        title: 'Harden session cookies',
        detail: 'HttpOnly, Secure and SameSite stop script from reading session tokens.',
        snippet: 'Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict; Path=/',
        snippetLanguage: 'http',
      },
    ],
  },
  MALFORMED_PAYLOAD: {
    root: 'The body did not match its declared Content-Type, typical of fuzzers probing for unhandled parser errors.',
    impact: 'Leaked stack traces; crashes in hand-rolled parsers.',
    recs: [SCHEMA, { title: 'Return generic errors', detail: 'Map parse failures to a fixed problem+json 400 response.' }],
  },
  OVERSIZED_PAYLOAD: {
    root: 'The request body exceeded the configured maximum size.',
    impact: 'Memory and CPU exhaustion.',
    recs: [{ title: 'Set per-route body limits', detail: 'Apply limits at the proxy and in the application.' }],
  },
  RATE_LIMIT_EXCEEDED: {
    root: 'A single source sent more requests than the policy allows within the sliding window.',
    impact: 'Resource exhaustion, scraping or enumeration at automated speed.',
    recs: [
      { title: 'Tier limits by route sensitivity', detail: 'Stricter budgets for login, search and export endpoints.' },
      {
        title: 'Advertise limits with standard headers',
        detail: 'Return 429 with Retry-After and RateLimit-* headers so clients back off.',
        snippet: 'HTTP/1.1 429 Too Many Requests\nRetry-After: 30\nRateLimit-Limit: 40\nRateLimit-Remaining: 0',
        snippetLanguage: 'http',
      },
      { title: 'Share counters across instances', detail: 'Keep the sliding window in Redis when running multiple workers.' },
    ],
  },
  BRUTE_FORCE_AUTH: {
    root: 'Repeated authentication failures from one source within a short window.',
    impact: 'Account takeover through password guessing or credential stuffing.',
    recs: [
      {
        title: 'Require MFA and screen breached passwords',
        detail: 'MFA defeats stuffed credentials.',
        reference: 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html',
      },
      { title: 'Throttle per account as well as per IP', detail: 'Distributed attempts rotate IPs; track failures per username.' },
      { title: 'Use uniform login responses', detail: 'Same message and timing for unknown users and wrong passwords.' },
    ],
  },
};

export function analyze(finding: Finding, related: Finding[]): FindingAnalysis {
  const e = KB[finding.category];
  return {
    finding,
    rootCause: `${finding.diagnostic} ${e.root}`,
    impact: e.impact,
    recommendations: e.recs,
    relatedFindings: related,
  };
}
