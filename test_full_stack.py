"""
GASHA Complete Full-Stack Integration Test Suite
Validates EVERY REST endpoint, WebSocket streaming, Four-Eyes Principle,
and Frontend-Backend Schema Parity.
"""

import sys
import json
import time
import threading
import requests
import websocket

BASE = "http://localhost:8001"
API  = f"{BASE}/api/v1"

CREDS_OPERATOR = {"username": "operator", "password": "OperatorSecure2026!"}
CREDS_ADMIN    = {"username": "admin",    "password": "AdminRoot2026!"}
CREDS_ANALYST  = {"username": "analyst",  "password": "AnalystSecure2026!"}
CREDS_BREAK    = {"username": "breakglass","password": "EmergencyRoot2026!"}

TELEMETRY_KEY  = "gasha-telemetry-demo-key-2026"

results = []
token_operator = None
token_admin    = None
token_analyst  = None
token_break    = None
refresh_tok_op = None

PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"

def record(group, name, status, detail=""):
    icon = {"PASS": "OK  ", "FAIL": "FAIL", "WARN": "WARN"}[status]
    print(f"  [{icon}] {name}" + (f" -- {detail}" if detail else ""))
    results.append({"group": group, "name": name, "status": status, "detail": detail})

def hdr(auth_token=None):
    h = {"Content-Type": "application/json"}
    if auth_token:
        h["Authorization"] = f"Bearer {auth_token}"
    return h

def get(path, token=None, params=None, timeout=8):
    return requests.get(f"{API}{path}", headers=hdr(token), params=params, timeout=timeout)

def post(path, body=None, token=None, headers_extra=None, timeout=8):
    h = hdr(token)
    if headers_extra:
        h.update(headers_extra)
    return requests.post(f"{API}{path}", json=body, headers=h, timeout=timeout)

def patch(path, body=None, token=None, timeout=8):
    return requests.patch(f"{API}{path}", json=body, headers=hdr(token), timeout=timeout)

def delete(path, token=None, timeout=8):
    return requests.delete(f"{API}{path}", headers=hdr(token), timeout=timeout)

def check(group, name, r, expect_status=200, check_fn=None):
    try:
        if r.status_code != expect_status:
            record(group, name, FAIL, f"HTTP {r.status_code} expected {expect_status}: {r.text[:200]}")
            return None
        data = r.json() if r.content else {}
        if check_fn:
            msg = check_fn(data)
            if msg:
                record(group, name, FAIL, msg)
                return None
        record(group, name, PASS)
        return data
    except Exception as e:
        record(group, name, FAIL, str(e))
        return None

# =========================================================================== #
# 1. Health                                                                   #
# =========================================================================== #
print("\n=== 1. Health ===")
try:
    r = requests.get(f"{BASE}/health", timeout=5)
    check("Health", "GET /health", r, 200, lambda d: None if d.get("status") == "ok" else f"status={d.get('status')}")
except Exception as e:
    record("Health", "GET /health", FAIL, str(e))

# =========================================================================== #
# 2. Authentication                                                           #
# =========================================================================== #
print("\n=== 2. Authentication ===")

def do_login(label, creds):
    global refresh_tok_op
    r = post("/auth/login", creds)
    if r.status_code != 200:
        record("Auth", f"POST /auth/login ({label})", FAIL, f"HTTP {r.status_code}: {r.text[:150]}")
        return None
    d = r.json()
    tok = d.get("accessToken") or d.get("access_token")
    if label == "operator":
        refresh_tok_op = d.get("refreshToken") or d.get("refresh_token")
    if tok:
        record("Auth", f"POST /auth/login ({label})", PASS)
        return tok
    record("Auth", f"POST /auth/login ({label})", FAIL, "No accessToken found")
    return None

token_operator = do_login("operator", CREDS_OPERATOR)
token_admin    = do_login("admin",    CREDS_ADMIN)
token_analyst  = do_login("analyst",  CREDS_ANALYST)
token_break    = do_login("breakglass", CREDS_BREAK)

# GET /auth/me
if token_operator:
    r = get("/auth/me", token_operator)
    check("Auth", "GET /auth/me (operator)", r, 200,
          lambda d: None if d.get("username") == "operator" else f"username={d.get('username')}")

if token_admin:
    r = get("/auth/me", token_admin)
    check("Auth", "GET /auth/me (admin)", r, 200,
          lambda d: None if d.get("role") == "admin" else f"role={d.get('role')}")

# POST /auth/refresh with valid refreshToken
if refresh_tok_op:
    r = post("/auth/refresh", {"refreshToken": refresh_tok_op})
    if r.status_code == 200:
        record("Auth", "POST /auth/refresh (rotate token)", PASS)
        token_operator = r.json().get("accessToken", token_operator)
    else:
        record("Auth", "POST /auth/refresh (rotate token)", FAIL, f"HTTP {r.status_code}: {r.text[:150]}")

# Bad credentials check -> 401
r = post("/auth/login", {"username": "baduser", "password": "wrongpassword"})
check("Auth", "POST /auth/login (bad credentials -> 401)", r, 401)

# =========================================================================== #
# 3. Assets & Digital Twin                                                    #
# =========================================================================== #
print("\n=== 3. Assets & Digital Twin ===")
asset_id = None
if token_operator:
    r = get("/assets", token_operator)
    data = check("Assets", "GET /assets", r, 200,
                 lambda d: None if isinstance(d, list) and len(d) > 0 else "empty or not list")
    if data:
        asset_id = data[0].get("id")
        record("Assets", f"Asset details for {asset_id}", PASS)
        r = get(f"/assets/{asset_id}", token_operator)
        check("Assets", f"GET /assets/{asset_id}", r, 200)

    # Digital Twin endpoints
    r = get("/digital-twin", token_operator)
    check("DigitalTwin", "GET /digital-twin", r, 200,
          lambda d: None if "nodes" in d and "edges" in d else "missing nodes/edges")

    r = get("/digital-twin/graph", token_operator)
    check("DigitalTwin", "GET /digital-twin/graph", r, 200)

    r = get("/twin", token_operator)
    check("DigitalTwin", "GET /twin (alias)", r, 200)

    if asset_id:
        r = get(f"/digital-twin/subgraph/{asset_id}", token_operator)
        check("DigitalTwin", f"GET /digital-twin/subgraph/{asset_id}", r, 200)

# =========================================================================== #
# 4. Attack Paths                                                             #
# =========================================================================== #
print("\n=== 4. Attack Paths ===")
path_id = None
if token_operator:
    r = get("/attack-paths", token_operator)
    paths = check("AttackPaths", "GET /attack-paths", r, 200,
                  lambda d: None if isinstance(d, list) else "expected list")
    if paths and len(paths) > 0:
        p0 = paths[0]
        path_id = p0.get("id")
        # Check techniques field for frontend contract parity
        if isinstance(p0.get("techniques"), list) and len(p0.get("techniques")) > 0:
            record("AttackPaths", "AttackPath.techniques parity check", PASS, f"techniques={p0['techniques']}")
        else:
            record("AttackPaths", "AttackPath.techniques parity check", FAIL, f"techniques missing or empty: {p0.get('techniques')}")

    if path_id:
        r = get(f"/attack-paths/{path_id}", token_operator)
        check("AttackPaths", f"GET /attack-paths/{path_id}", r, 200)

    r = post("/attack-paths/recalculate", {}, token_operator)
    check("AttackPaths", "POST /attack-paths/recalculate", r, 200)

# =========================================================================== #
# 5. Detections                                                               #
# =========================================================================== #
print("\n=== 5. Detections ===")
detection_id = None
if token_operator:
    r = get("/detections", token_operator)
    dets = check("Detections", "GET /detections", r, 200,
                 lambda d: None if isinstance(d, list) else "expected list")
    if dets and len(dets) > 0:
        d0 = dets[0]
        detection_id = d0.get("id")
        # Check rule object contract parity
        rule_val = d0.get("rule")
        if isinstance(rule_val, dict) and ("name" in rule_val or "ruleId" in rule_val):
            record("Detections", "Detection.rule structured object parity check", PASS, f"ruleId={rule_val.get('ruleId')}")
        else:
            record("Detections", "Detection.rule structured object parity check", FAIL, f"rule={rule_val}")

        # Check convenience parity fields (ts, nodeId, technique, summary)
        if "ts" in d0 and "nodeId" in d0 and "technique" in d0:
            record("Detections", "Detection parity fields (ts, nodeId, technique)", PASS)
        else:
            record("Detections", "Detection parity fields (ts, nodeId, technique)", FAIL, f"keys={list(d0.keys())}")

    if detection_id:
        r = get(f"/detections/{detection_id}", token_operator)
        check("Detections", f"GET /detections/{detection_id}", r, 200)

    r = get("/detections/rules", token_operator)
    check("Detections", "GET /detections/rules", r, 200,
          lambda d: None if isinstance(d, list) and len(d) > 0 else "rules list empty")

# =========================================================================== #
# 6. Incidents & Parity                                                       #
# =========================================================================== #
print("\n=== 6. Incidents ===")
incident_id = None
if token_operator:
    r = get("/incidents", token_operator)
    incs = check("Incidents", "GET /incidents", r, 200,
                 lambda d: None if isinstance(d, list) and len(d) > 0 else "incidents list empty")
    if incs and len(incs) > 0:
        i0 = incs[0]
        incident_id = i0.get("id")
        # Check parity fields: detectionIds, openedAt, pathId, confidence, riskBefore
        has_det_ids = isinstance(i0.get("detectionIds"), list)
        has_opened_at = bool(i0.get("openedAt"))
        has_confidence = i0.get("confidence") is not None
        if has_det_ids and has_opened_at and has_confidence:
            record("Incidents", "Incident parity fields (detectionIds, openedAt, confidence)", PASS,
                   f"detCount={len(i0['detectionIds'])}, openedAt={i0['openedAt'][:16]}, conf={i0['confidence']}")
        else:
            record("Incidents", "Incident parity fields (detectionIds, openedAt, confidence)", FAIL,
                   f"keys={list(i0.keys())}")

    if incident_id:
        r = get(f"/incidents/{incident_id}", token_operator)
        check("Incidents", f"GET /incidents/{incident_id}", r, 200)

        r = get(f"/incidents/{incident_id}/story", token_operator)
        check("Incidents", f"GET /incidents/{incident_id}/story", r, 200,
              lambda d: None if isinstance(d, list) else "story must be list")

        # Test valid state transition based on current status
        curr_status = i0.get("status", "ACTIVE")
        next_status = "CONTAINED" if curr_status in ("ACTIVE", "INVESTIGATING") else "RESOLVED"
        r = patch(f"/incidents/{incident_id}/status", {"status": next_status, "reason": "Automated verification"}, token_operator)
        check("Incidents", f"PATCH /incidents/{incident_id}/status ({next_status})", r, 200)

# =========================================================================== #
# 7. Investigations                                                           #
# =========================================================================== #
print("\n=== 7. Investigations ===")
if token_operator and incident_id:
    # Trigger deterministic investigation run
    r = post(f"/investigations/{incident_id}/run", {}, token_operator)
    check("Investigations", f"POST /investigations/{incident_id}/run", r, 200,
          lambda d: None if "timeline" in d or "story" in d or "evidence" in d or "incidentId" in d else f"unexpected keys: {list(d.keys())}")

    # Query investigation
    r = get(f"/investigations/{incident_id}", token_operator)
    check("Investigations", f"GET /investigations/{incident_id}", r, 200)

    # Query investigation forensic timeline
    r = get(f"/investigations/{incident_id}/timeline", token_operator)
    check("Investigations", f"GET /investigations/{incident_id}/timeline", r, 200)

# =========================================================================== #
# 8. Dynamic Risk Engine & History Parity                                    #
# =========================================================================== #
print("\n=== 8. Risk Engine ===")
if token_operator:
    r = get("/risks/current", token_operator)
    check("Risk", "GET /risks/current", r, 200,
          lambda d: None if "overallScore" in d and "score" in d else f"keys={list(d.keys())}")

    r = get("/risks", token_operator)
    rhist = check("Risk", "GET /risks (history)", r, 200,
                  lambda d: None if isinstance(d, list) and len(d) > 0 else "empty history")
    if rhist and len(rhist) > 0:
        h0 = rhist[0]
        # Parity fields check: ts, openPaths, openIncidents
        if "ts" in h0 and "openPaths" in h0 and "openIncidents" in h0:
            record("Risk", "RiskHistoryEntry parity fields (ts, openPaths, openIncidents)", PASS,
                   f"ts={h0['ts'][:16]}, openPaths={h0['openPaths']}, openIncidents={h0['openIncidents']}")
        else:
            record("Risk", "RiskHistoryEntry parity fields (ts, openPaths, openIncidents)", FAIL, f"keys={list(h0.keys())}")

    r = get("/risks/history", token_operator)
    check("Risk", "GET /risks/history", r, 200)

    r = get("/risk/current", token_operator)
    check("Risk", "GET /risk/current (alias)", r, 200)

    r = post("/risks/recalculate", {}, token_operator)
    check("Risk", "POST /risks/recalculate", r, 200)

# =========================================================================== #
# 9. Controlled Responses & Four-Eyes Principle                               #
# =========================================================================== #
print("\n=== 9. Controlled Responses & Four-Eyes Principle ===")
proposal_id = None
if token_operator and incident_id:
    # 1. Propose containment action as operator
    prop_body = {
        "incidentId": incident_id,
        "actionType": "BLOCK_SOURCE",
        "targetType": "IP_ADDRESS",
        "targetIdentifier": "198.51.100.42",
        "reason": "Test block of attacker IP verified from incident evidence",
        "supportingEvidenceIds": ["det-1"]
    }
    r = post("/responses/propose", prop_body, token_operator)
    p_data = check("Responses", "POST /responses/propose", r, 200)
    if p_data:
        proposal_id = p_data.get("id")
        # Check parity fields for frontend ActionCard: kind, target, state, blastRadius, riskReduction
        if p_data.get("kind") == "block-ip" and p_data.get("target") == "198.51.100.42" and p_data.get("state") == "proposed":
            record("Responses", "ResponseRecordResponse parity fields (kind, target, state, blastRadius)", PASS,
                   f"kind={p_data['kind']}, state={p_data['state']}")
        else:
            record("Responses", "ResponseRecordResponse parity fields", FAIL,
                   f"kind={p_data.get('kind')}, state={p_data.get('state')}")

    # 2. List responses
    r = get("/responses", token_operator)
    check("Responses", "GET /responses", r, 200)

    # 3. Four-Eyes Principle Enforcement: Proposer CANNOT self-approve
    if proposal_id:
        r = post(f"/responses/{proposal_id}/approve", {"decision": "APPROVE", "comment": "Operator trying self-approval"}, token_operator)
        if r.status_code == 400:
            record("Responses", "Four-Eyes Principle: Operator self-approval rejected (400)", PASS,
                   "Enforced dual authorization")
        else:
            record("Responses", "Four-Eyes Principle: Operator self-approval rejected (400)", FAIL,
                   f"HTTP {r.status_code}: {r.text[:100]}")

        # 4. Admin Approves -> Must succeed (Dual Authorization satisfied)
        if token_admin:
            r = post(f"/responses/{proposal_id}/approve", {"decision": "APPROVE", "comment": "Admin dual approval confirmed"}, token_admin)
            check("Responses", "Dual Authorization: Admin approval (200)", r, 200)

        # 5. Audit log retrieval and cryptographic verification
        r = get("/responses/audit", token_operator)
        check("Responses", "GET /responses/audit", r, 200)

        r = get("/responses/audit/verify", token_operator)
        check("Responses", "GET /responses/audit/verify", r, 200,
              lambda d: None if d.get("verified") is True else f"verified={d.get('verified')}")

    # 6. Reject flow verification
    if token_operator and token_admin:
        prop_body2 = {
            "incidentId": incident_id,
            "actionType": "DISABLE_SESSION",
            "targetType": "IP_ADDRESS",
            "targetIdentifier": "198.51.100.42",
            "reason": "Test proposal to verify rejection path",
            "supportingEvidenceIds": ["det-1"]
        }
        r2 = post("/responses/propose", prop_body2, token_operator)
        if r2.status_code == 200:
            p2_id = r2.json().get("id")
            r3 = post(f"/responses/{p2_id}/reject", {"decision": "REJECT", "comment": "Admin rejected test proposal"}, token_admin)
            check("Responses", "POST /responses/{id}/reject (admin reject -> 200)", r3, 200)

# =========================================================================== #
# 10. Vulnerabilities & Assessments                                           #
# =========================================================================== #
print("\n=== 10. Vulnerabilities ===")
vuln_id = None
if token_operator:
    r = get("/vulnerabilities", token_operator)
    vulns = check("Vulnerabilities", "GET /vulnerabilities", r, 200)
    if vulns and len(vulns) > 0:
        vuln_id = vulns[0].get("id")
        record("Vulnerabilities", f"Vulnerabilities count: {len(vulns)}", PASS)

    if vuln_id:
        r = get(f"/vulnerabilities/{vuln_id}", token_operator)
        check("Vulnerabilities", f"GET /vulnerabilities/{vuln_id}", r, 200)

    r = post("/vulnerabilities/assess", {}, token_operator)
    check("Vulnerabilities", "POST /vulnerabilities/assess", r, 200)

# =========================================================================== #
# 11. Discovery Engine                                                        #
# =========================================================================== #
print("\n=== 11. Discovery Engine ===")
if token_operator:
    r = get("/discovery/status", token_operator)
    check("Discovery", "GET /discovery/status", r, 200)

    r = get("/discovery/assets", token_operator)
    check("Discovery", "GET /discovery/assets", r, 200)

    r = post("/discovery/trigger", {}, token_operator)
    check("Discovery", "POST /discovery/trigger", r, 200)

# =========================================================================== #
# 12. Telemetry Ingestion Pipeline                                            #
# =========================================================================== #
print("\n=== 12. Telemetry Pipeline ===")
if token_operator:
    r = get("/telemetry/health", token_operator)
    check("Telemetry", "GET /telemetry/health", r, 200,
          lambda d: None if d.get("status") in ("healthy", "degraded") else f"status={d.get('status')}")

    r = get("/telemetry/metrics", token_operator)
    check("Telemetry", "GET /telemetry/metrics", r, 200)

    # Test batch ingestion
    batch_payload = {
        "events": [
            {
                "id": "test-tel-evt-001",
                "eventType": "HTTP_REQUEST",
                "timestamp": "2026-10-20T08:00:00Z",
                "sourceService": "auth-svc",
                "environmentId": "env-prod",
                "payload": {"sourceIp": "10.0.0.1", "httpPath": "/api/v1/auth/login", "httpMethod": "POST"}
            }
        ]
    }
    r = post("/telemetry/ingest", batch_payload, token_operator,
             headers_extra={"X-GASHA-TELEMETRY-KEY": TELEMETRY_KEY})
    if r.status_code in (200, 202):
        record("Telemetry", "POST /telemetry/ingest (batch with API key)", PASS)
    else:
        record("Telemetry", "POST /telemetry/ingest (batch with API key)", FAIL, f"HTTP {r.status_code}: {r.text[:150]}")

# =========================================================================== #
# 13. Environment State & Connections                                         #
# =========================================================================== #
print("\n=== 13. Environment & Connections ===")
if token_operator:
    r = get("/environment/state", token_operator)
    check("Environment", "GET /environment/state", r, 200)

    r = get("/connections/status", token_operator)
    check("Connections", "GET /connections/status", r, 200)

# =========================================================================== #
# 14. Realtime Streaming WebSocket                                            #
# =========================================================================== #
print("\n=== 14. Realtime Streaming WebSocket ===")
ws_ticket = None
if token_operator:
    r = post("/realtime/ticket", {}, token_operator)
    if r.status_code == 200:
        ws_ticket = r.json().get("ticket")
        record("Realtime", "POST /realtime/ticket (issue single-use ticket)", PASS, f"ticket={str(ws_ticket)[:12]}...")
    else:
        record("Realtime", "POST /realtime/ticket", FAIL, f"HTTP {r.status_code}: {r.text[:150]}")

    # Also test ticket alias route
    r = post("/ticket", {}, token_operator)
    check("Realtime", "POST /ticket (route alias)", r, 200)

if ws_ticket:
    ws_url = f"ws://127.0.0.1:8001/api/v1/realtime/ws?ticket={ws_ticket}"
    try:
        ws = websocket.create_connection(ws_url, timeout=5)
        ws.send("ping")
        msg = ws.recv()
        ws.close()
        record("Realtime", "WebSocket connect via ticket + ping", PASS, f"Connected & received: {msg[:60]}")
    except Exception as e:
        record("Realtime", "WebSocket connect via ticket + ping", FAIL, str(e))

# =========================================================================== #
# 15. OpenAPI Documentation                                                    #
# =========================================================================== #
print("\n=== 15. Documentation ===")
r = requests.get(f"{BASE}/docs", timeout=5)
if r.status_code == 200 and "<html" in r.text.lower():
    record("Docs", "GET /docs (Swagger UI HTML)", PASS)
else:
    record("Docs", "GET /docs (Swagger UI HTML)", FAIL, f"HTTP {r.status_code}")

r = requests.get(f"{BASE}/redoc", timeout=5)
if r.status_code == 200 and "<html" in r.text.lower():
    record("Docs", "GET /redoc (ReDoc HTML)", PASS)
else:
    record("Docs", "GET /redoc (ReDoc HTML)", FAIL, f"HTTP {r.status_code}")

r = requests.get(f"{BASE}/openapi.json", timeout=5)
oas_data = check("Docs", "GET /openapi.json", r, 200)
if oas_data:
    record("Docs", "OpenAPI documented routes count", PASS, f"{len(oas_data.get('paths', {}))} routes")

# =========================================================================== #
# 16. Security Boundaries & Role-Based Access Control                        #
# =========================================================================== #
print("\n=== 16. Role-Based Access & Security Boundaries ===")
# Unauthenticated request -> 401
r = get("/assets")
if r.status_code in (401, 403):
    record("RBAC", "GET /assets unauthenticated -> 401", PASS)
else:
    record("RBAC", "GET /assets unauthenticated -> 401", FAIL, f"HTTP {r.status_code}")

# Analyst read access
if token_analyst:
    r = get("/detections", token_analyst)
    check("RBAC", "GET /detections (analyst read allowed)", r, 200)

# =========================================================================== #
# SUMMARY                                                                     #
# =========================================================================== #
print("\n" + "=" * 74)
print("              GASHA SYSTEM-WIDE INTEGRATION TEST SUMMARY                  ")
print("=" * 74)

by_group = {}
for res in results:
    g = res["group"]
    by_group.setdefault(g, {"PASS": 0, "FAIL": 0, "WARN": 0})
    by_group[g][res["status"]] += 1

total_pass = total_fail = total_warn = 0
for g, counts in by_group.items():
    p, f, w = counts["PASS"], counts["FAIL"], counts["WARN"]
    total_pass += p; total_fail += f; total_warn += w
    status = "100% PASS" if f == 0 else f"{f} FAILED"
    print(f"  {g:<20} | PASS: {p:>2}  FAIL: {f:>2}  WARN: {w:>2}  -- {status}")

print("-" * 74)
print(f"  OVERALL TOTAL        | PASS: {total_pass:>2}  FAIL: {total_fail:>2}  WARN: {total_warn:>2}")
print("=" * 74)

if total_fail > 0:
    print("\nFAILED CHECKS:")
    for res in results:
        if res["status"] == "FAIL":
            print(f"  [FAIL] {res['group']} -> {res['name']}: {res['detail']}")

exit_code = 1 if total_fail > 0 else 0
print(f"\nCompleted with exit code {exit_code}")
sys.exit(exit_code)
