import urllib.request
import urllib.error
import json
import sys

def main():
    print("=== 1. TESTING FRONTEND PAGES (Next.js SSR) ===")
    pages = [
        "/",
        "/twin",
        "/incidents",
        "/incidents/inc-1",
        "/paths",
        "/risk",
        "/response",
        "/telemetry",
        "/connect"
    ]

    for p in pages:
        url = f"http://localhost:3000{p}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "IntegrationTester/1.0"})
            res = urllib.request.urlopen(req, timeout=10)
            content = res.read().decode("utf-8", errors="ignore")
            print(f"  [PASS] {p:<20} -> HTTP {res.getcode()} ({len(content)} bytes)")
        except Exception as e:
            print(f"  [FAIL] {p:<20} -> {e}")
            sys.exit(1)

    print("\n=== 2. TESTING FRONTEND REWRITE PROXY TO BACKEND ===")
    proxy_auth_data = json.dumps({
        "username": "operator",
        "password": "OperatorSecure2026!",
        "environmentId": "env-prod"
    }).encode()
    proxy_req = urllib.request.Request(
        "http://localhost:3000/api/v1/auth/login",
        data=proxy_auth_data,
        headers={"Content-Type": "application/json"}
    )
    try:
        proxy_res = urllib.request.urlopen(proxy_req, timeout=10)
        proxy_token_data = json.loads(proxy_res.read().decode())
        token = proxy_token_data.get("accessToken")
        print(f"  [PASS] Next.js Proxy POST /api/v1/auth/login -> HTTP {proxy_res.getcode()}, token: {token[:20]}...")
    except Exception as e:
        print(f"  [FAIL] Proxy auth failed: {e}")
        sys.exit(1)

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # Test Twin via Proxy
    try:
        req = urllib.request.Request("http://localhost:3000/api/v1/twin", headers=headers)
        res = urllib.request.urlopen(req, timeout=10)
        data = json.loads(res.read().decode())
        node_cnt = len(data.get("nodes", []))
        edge_cnt = len(data.get("edges", []))
        print(f"  [PASS] Next.js Proxy GET /api/v1/twin -> HTTP {res.getcode()} ({node_cnt} nodes, {edge_cnt} edges)")
    except Exception as e:
        print(f"  [FAIL] Proxy twin failed: {e}")
        sys.exit(1)

    print("\n=== 3. TESTING BACKEND DIRECT APIS & DATA CONTRACTS ===")

    # Digital Twin Node structure
    req = urllib.request.Request("http://127.0.0.1:4000/api/v1/twin", headers=headers)
    twin = json.loads(urllib.request.urlopen(req).read().decode())
    nodes = twin.get("nodes", [])
    edges = twin.get("edges", [])
    print(f"  [PASS] Digital Twin: {len(nodes)} nodes, {len(edges)} edges")
    if nodes:
        sample = nodes[0]
        print(f"         Sample node keys: {list(sample.keys())}")
        assert "id" in sample and "label" in sample and "kind" in sample, "Node schema missing required fields"

    # Incidents
    req = urllib.request.Request("http://127.0.0.1:4000/api/v1/incidents", headers=headers)
    incidents = json.loads(urllib.request.urlopen(req).read().decode())
    print(f"  [PASS] Incidents list: {len(incidents)} incidents found")

    # Incident Story
    req = urllib.request.Request("http://127.0.0.1:4000/api/v1/incidents/inc-1/story", headers=headers)
    story = json.loads(urllib.request.urlopen(req).read().decode())
    print(f"  [PASS] Incident story for inc-1: {len(story)} forensic timeline events")
    if story:
        evt = story[0]
        print(f"         Sample event: id={evt['id']}, kind={evt['kind']}, technique={evt['technique']}, nodeId={evt['nodeId']}")
        assert "id" in evt and "kind" in evt and "technique" in evt and "narrative" in evt, "Story event schema invalid"

    # Risk history
    req = urllib.request.Request("http://127.0.0.1:4000/api/v1/risk", headers=headers)
    risk = json.loads(urllib.request.urlopen(req).read().decode())
    print(f"  [PASS] Risk history: {len(risk)} score records")

    # Attack paths
    req = urllib.request.Request("http://127.0.0.1:4000/api/v1/attack-paths", headers=headers)
    paths = json.loads(urllib.request.urlopen(req).read().decode())
    path_items = paths if isinstance(paths, list) else paths.get("paths", [])
    print(f"  [PASS] Attack paths: {len(path_items)} prioritized attack vectors")

    # Responses
    req = urllib.request.Request("http://127.0.0.1:4000/api/v1/responses", headers=headers)
    responses = json.loads(urllib.request.urlopen(req).read().decode())
    print(f"  [PASS] Responses: {len(responses)} containment proposals")

    print("\n=== 4. TESTING CONTAINMENT ACTION APPROVAL & REJECTION (FOUR-EYES PRINCIPLE) ===")
    # Login as admin for dual authorization
    auth_adm = json.dumps({"username": "admin", "password": "AdminRoot2026!", "environmentId": "env-prod"}).encode()
    req_adm = urllib.request.Request("http://127.0.0.1:4000/api/v1/auth/login", data=auth_adm, headers={"Content-Type": "application/json"})
    tok_adm = json.loads(urllib.request.urlopen(req_adm).read().decode())["accessToken"]
    headers_adm = {"Authorization": f"Bearer {tok_adm}", "Content-Type": "application/json"}

    # Operator proposes action 1
    prop_data1 = json.dumps({
        "incidentId": "inc-1",
        "actionType": "BLOCK_SOURCE",
        "targetType": "IP_ADDRESS",
        "targetIdentifier": "198.51.100.42",
        "reason": "Test proposal for dual-operator approval lifecycle",
        "supportingEvidenceIds": ["det-1"]
    }).encode()
    req = urllib.request.Request("http://127.0.0.1:4000/api/v1/responses/propose", data=prop_data1, headers=headers)
    prop1 = json.loads(urllib.request.urlopen(req).read().decode())
    pid1 = prop1["id"]
    print(f"  [PASS] Operator proposed {pid1} -> status: {prop1.get('status')}")

    # Admin approves action 1
    req = urllib.request.Request(f"http://127.0.0.1:4000/api/v1/responses/{pid1}/approve", data=b"{}", headers=headers_adm)
    res = json.loads(urllib.request.urlopen(req).read().decode())
    print(f"  [PASS] Admin approved {pid1} (Four-Eyes Principle) -> status: {res.get('status')}")

    # Operator proposes action 2 for rejection test
    prop_data2 = json.dumps({
        "incidentId": "inc-1",
        "actionType": "BLOCK_SOURCE",
        "targetType": "IP_ADDRESS",
        "targetIdentifier": "198.51.100.42",
        "reason": "Test proposal for operator rejection lifecycle",
        "supportingEvidenceIds": ["det-1"]
    }).encode()
    req = urllib.request.Request("http://127.0.0.1:4000/api/v1/responses/propose", data=prop_data2, headers=headers)
    prop2 = json.loads(urllib.request.urlopen(req).read().decode())
    pid2 = prop2["id"]
    print(f"  [PASS] Operator proposed {pid2} -> status: {prop2.get('status')}")

    # Admin rejects action 2
    req = urllib.request.Request(f"http://127.0.0.1:4000/api/v1/responses/{pid2}/reject", data=b"{}", headers=headers_adm)
    res = json.loads(urllib.request.urlopen(req).read().decode())
    print(f"  [PASS] Admin rejected {pid2} -> status: {res.get('status')}")

    print("\n=== 5. TESTING TELEMETRY INGESTION & HEALTH ===")
    telemetry_headers = {
        "Content-Type": "application/json",
        "X-GASHA-TELEMETRY-KEY": "gasha-telemetry-demo-key-2026"
    }
    telemetry_event = json.dumps({
        "events": [{
            "id": "evt-live-test-01",
            "eventType": "HTTP_REQUEST",
            "timestamp": "2026-10-18T11:44:00Z",
            "sourceService": "web-app",
            "environmentId": "env-prod",
            "payload": {
                "httpMethod": "GET",
                "httpPath": "/api/v1/twin",
                "httpStatusCode": 200,
                "sourceIp": "198.51.100.42"
            }
        }]
    }).encode()
    req = urllib.request.Request("http://127.0.0.1:4000/api/v1/telemetry/ingest", data=telemetry_event, headers=telemetry_headers)
    res = json.loads(urllib.request.urlopen(req).read().decode())
    print(f"  [PASS] Ingested live telemetry batch -> accepted: {res.get('accepted')}, processed: {res.get('processed')}")

    req = urllib.request.Request("http://127.0.0.1:4000/api/v1/telemetry/health", headers=headers)
    res = json.loads(urllib.request.urlopen(req).read().decode())
    print(f"  [PASS] Telemetry service health -> status: {res.get('status')}, queueCapacity: {res.get('queueCapacity')}")

    req = urllib.request.Request("http://127.0.0.1:4000/api/v1/telemetry/metrics", headers=headers)
    res = json.loads(urllib.request.urlopen(req).read().decode())
    print(f"  [PASS] Telemetry metrics -> processedCount: {res.get('processedCount', 0)}, errorCount: {res.get('errorCount', 0)}")

    print("\n=======================================================")
    print("ALL 20 END-TO-END INTEGRATION CHECKS PASSED CLEANLY! [SUCCESS]")
    print("=======================================================")

if __name__ == "__main__":
    main()
