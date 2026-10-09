"""
==============================================================================
FILE: scripts/demo/run_attack_scenarios.py
ROLE / OWNERSHIP: Cybersecurity & Automation Engineers
OBJECTIVE: Controlled Attack Simulator for GASHA local competition demos.
           Sends real HTTP traffic against the local demo target service.
           Zero calls to internal GASHA incident/detection repositories.
           Strictly restricted to local loopback targets.
==============================================================================
"""

import argparse
import json
import os
import pathlib
import re
import sys
import time
import uuid
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

import httpx

ALLOWED_HOSTS = {"127.0.0.1", "localhost", "0.0.0.0", "::1"}


def validate_target_url(target_url: str) -> str:
    """Strictly validates target destination is local loopback only."""
    parsed = urlparse(target_url)
    hostname = parsed.hostname or ""
    if hostname.lower() not in ALLOWED_HOSTS:
        raise ValueError(
            f"Security Violation: Target host '{hostname}' is not a permitted local test destination. "
            f"Simulation only permitted against local targets: {sorted(list(ALLOWED_HOSTS))}"
        )
    return target_url.rstrip("/")


class ScenarioRunner:
    def __init__(self, target_url: str, output_dir: Optional[str] = None):
        self.target_url = validate_target_url(target_url)
        self.client = httpx.Client(base_url=self.target_url, timeout=5.0)

        base_dir = pathlib.Path(__file__).resolve().parent.parent.parent
        self.results_dir = pathlib.Path(output_dir) if output_dir else (base_dir / "tests" / "scenarios" / "results" / "phase-5")
        self.results_dir.mkdir(parents=True, exist_ok=True)

    def log(self, msg: str):
        print(f"[*] {msg}", flush=True)

    def run_scenario_a(self) -> Dict[str, Any]:
        """
        Scenario A — Authentication-Failure Threshold
        Sends 5 consecutive failed login attempts from source 198.51.100.101.
        """
        corr_id = f"corr-scen-a-{uuid.uuid4().hex[:8]}"
        attacker_ip = "198.51.100.101"
        self.log(f"=== Starting Scenario A: Authentication Failure Threshold (Correlation ID: {corr_id}) ===")

        requests_log = []
        start_time = time.time()

        for idx in range(1, 6):
            payload = {"username": "admin", "password": f"WrongPassword_{idx}!"}
            headers = {"X-Forwarded-For": attacker_ip, "X-Correlation-ID": corr_id}
            req_start = time.time()
            res = self.client.post("/api/auth/login", json=payload, headers=headers)
            elapsed_ms = round((time.time() - req_start) * 1000, 2)

            self.log(f"  Attempt {idx}/5 -> Status: {res.status_code} ({elapsed_ms}ms) | Outcome: {res.json().get('error', 'OK')}")
            requests_log.append({
                "attempt": idx,
                "status": res.status_code,
                "elapsedMs": elapsed_ms,
                "sourceIp": attacker_ip,
                "user": "admin"
            })
            time.sleep(0.05)

        total_elapsed = round(time.time() - start_time, 2)
        success = all(r["status"] == 401 for r in requests_log) and len(requests_log) == 5
        self.log(f"=== Scenario A Finished in {total_elapsed}s | Success: {success} ===\n")

        return {
            "scenario": "Scenario A - Authentication Failure Threshold",
            "correlationId": corr_id,
            "targetUrl": self.target_url,
            "attackerIp": attacker_ip,
            "totalRequests": len(requests_log),
            "durationSeconds": total_elapsed,
            "success": success,
            "requests": requests_log
        }

    def run_scenario_b(self) -> Dict[str, Any]:
        """
        Scenario B — Suspicious Web Probe
        Sends SQL injection probe to customer lookup endpoint.
        """
        corr_id = f"corr-scen-b-{uuid.uuid4().hex[:8]}"
        attacker_ip = "198.51.100.102"
        self.log(f"=== Starting Scenario B: Suspicious Web Probe (Correlation ID: {corr_id}) ===")

        probe_query = "' UNION SELECT 1,2,3--"
        headers = {"X-Forwarded-For": attacker_ip, "X-Correlation-ID": corr_id}

        start_time = time.time()
        res = self.client.get(f"/api/customers/lookup?query={probe_query}", headers=headers)
        elapsed_ms = round((time.time() - start_time) * 1000, 2)

        data = res.json()
        detected_pattern = data.get("detectedPattern")
        self.log(f"  Probe Request -> Status: {res.status_code} ({elapsed_ms}ms) | Detected Pattern: {detected_pattern}")

        success = res.status_code == 200 and detected_pattern == "SQL_INJECTION" and data.get("status") == "safe_handled"
        self.log(f"=== Scenario B Finished in {round(time.time() - start_time, 2)}s | Success: {success} ===\n")

        return {
            "scenario": "Scenario B - Suspicious Web Probe",
            "correlationId": corr_id,
            "targetUrl": self.target_url,
            "attackerIp": attacker_ip,
            "probePayload": "[REDACTED_PROBE_SQLI]",
            "detectedPattern": detected_pattern,
            "status": res.status_code,
            "durationMs": elapsed_ms,
            "success": success
        }

    def run_scenario_c(self) -> Dict[str, Any]:
        """
        Scenario C — Mixed Authorized and Denied Activity
        1. Normal resource access (tickets).
        2. Denied administrative secrets.
        3. Denied privilege mutation.
        """
        corr_id = f"corr-scen-c-{uuid.uuid4().hex[:8]}"
        client_ip = "198.51.100.103"
        self.log(f"=== Starting Scenario C: Mixed Authorized & Denied Activity (Correlation ID: {corr_id}) ===")

        # Step 1: Login as analyst
        login_res = self.client.post("/api/auth/login", json={"username": "analyst", "password": "AnalystPass2026!"})
        session_token = login_res.json().get("token", "")
        headers = {
            "Authorization": f"Bearer {session_token}",
            "X-Forwarded-For": client_ip,
            "X-Correlation-ID": corr_id
        }

        # Step 2: Normal resource access
        res_normal = self.client.get("/api/tickets", headers=headers)
        self.log(f"  Step 1: Normal Access (/api/tickets) -> Status: {res_normal.status_code}")

        # Step 3: Denied protected resource
        res_denied_res = self.client.get("/api/admin/secrets", headers=headers)
        self.log(f"  Step 2: Denied Resource Access (/api/admin/secrets) -> Status: {res_denied_res.status_code}")

        # Step 4: Denied privilege mutation
        priv_payload = {"targetUser": "analyst", "newRole": "admin"}
        res_denied_priv = self.client.post("/api/admin/privilege-change", json=priv_payload, headers=headers)
        self.log(f"  Step 3: Denied Role Mutation (/api/admin/privilege-change) -> Status: {res_denied_priv.status_code}")

        success = (
            res_normal.status_code == 200 and
            res_denied_res.status_code == 403 and
            res_denied_priv.status_code == 403
        )
        self.log(f"=== Scenario C Finished | Success: {success} ===\n")

        return {
            "scenario": "Scenario C - Mixed Authorized and Denied Activity",
            "correlationId": corr_id,
            "clientIp": client_ip,
            "sessionToken": session_token,
            "normalAccessStatus": res_normal.status_code,
            "deniedResourceStatus": res_denied_res.status_code,
            "deniedPrivilegeStatus": res_denied_priv.status_code,
            "success": success
        }

    def run_scenario_d(self) -> Dict[str, Any]:
        """
        Scenario D — Session Containment Verification
        Tests target behavior before and after session invalidation.
        """
        corr_id = f"corr-scen-d-{uuid.uuid4().hex[:8]}"
        client_ip = "198.51.100.104"
        self.log(f"=== Starting Scenario D: Session Containment (Correlation ID: {corr_id}) ===")

        # 1. Login to obtain session
        login_res = self.client.post("/api/auth/login", json={"username": "analyst", "password": "AnalystPass2026!"})
        session_id = login_res.json().get("token")
        headers = {"Authorization": f"Bearer {session_id}", "X-Forwarded-For": client_ip}

        # 2. Before containment: access permitted
        res_before = self.client.get("/api/tickets", headers=headers)
        self.log(f"  Before Invalidation -> Status: {res_before.status_code} (Expected 200)")

        # 3. Simulate containment by registering session in disabled store via Target Security
        try:
            from apps.demo_target.security.sessions import disable_session
        except ImportError:
            from security.sessions import disable_session
        disable_session(session_id)
        self.log(f"  Enforced Containment: Session '{session_id}' disabled")

        # 4. After containment: request rejected with 401
        res_after = self.client.get("/api/tickets", headers=headers)
        self.log(f"  After Invalidation -> Status: {res_after.status_code} | Error: {res_after.json().get('error')} (Expected 401)")

        success = (res_before.status_code == 200 and res_after.status_code == 401 and res_after.json().get("error") == "SESSION_REVOKED_BY_GASHA")
        self.log(f"=== Scenario D Finished | Success: {success} ===\n")

        return {
            "scenario": "Scenario D - Session Containment Verification",
            "correlationId": corr_id,
            "sessionId": session_id,
            "statusBefore": res_before.status_code,
            "statusAfter": res_after.status_code,
            "success": success
        }

    def run_scenario_e(self) -> Dict[str, Any]:
        """
        Scenario E — Source IP Blocking Verification
        Tests target behavior before and after IP blocklist enforcement.
        """
        corr_id = f"corr-scen-e-{uuid.uuid4().hex[:8]}"
        attacker_ip = "198.51.100.105"
        benign_ip = "198.51.100.200"
        self.log(f"=== Starting Scenario E: Source IP Blocking (Correlation ID: {corr_id}) ===")

        # 1. Before blocking: attacker can reach public endpoint
        res_before = self.client.get("/health", headers={"X-Forwarded-For": attacker_ip})
        self.log(f"  Before Block -> Attacker ({attacker_ip}) Status: {res_before.status_code} (Expected 200)")

        # 2. Enforce blocklist containment
        try:
            from apps.demo_target.security.blocklist import block_ip
        except ImportError:
            from security.blocklist import block_ip
        block_ip(attacker_ip)
        self.log(f"  Enforced Containment: Source IP '{attacker_ip}' added to blocklist")

        # 3. After blocking: attacker rejected with 403 Forbidden
        res_after = self.client.get("/health", headers={"X-Forwarded-For": attacker_ip})
        self.log(f"  After Block -> Attacker ({attacker_ip}) Status: {res_after.status_code} | Error: {res_after.json().get('error')} (Expected 403)")

        # 4. Verify benign client continues normally
        res_benign = self.client.get("/health", headers={"X-Forwarded-For": benign_ip})
        self.log(f"  After Block -> Benign IP ({benign_ip}) Status: {res_benign.status_code} (Expected 200)")

        success = (
            res_before.status_code == 200 and
            res_after.status_code == 403 and
            res_after.json().get("error") == "ACCESS_BLOCKED_BY_GASHA" and
            res_benign.status_code == 200
        )
        self.log(f"=== Scenario E Finished | Success: {success} ===\n")

        return {
            "scenario": "Scenario E - Source IP Blocking Verification",
            "correlationId": corr_id,
            "attackerIp": attacker_ip,
            "benignIp": benign_ip,
            "attackerStatusBefore": res_before.status_code,
            "attackerStatusAfter": res_after.status_code,
            "benignStatus": res_benign.status_code,
            "success": success
        }

    def save_results(self, scenario_name: str, data: Dict[str, Any]):
        filename = f"{scenario_name.lower().replace(' ', '_')}_{int(time.time())}.json"
        path = self.results_dir / filename
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        self.log(f"Saved scenario artifact: {path}")


def main():
    parser = argparse.ArgumentParser(description="GASHA Controlled Attack Simulator")
    parser.add_argument("--target", default="http://127.0.0.1:5000", help="Local demo target base URL")
    parser.add_argument("--scenario", choices=["A", "B", "C", "D", "E", "all"], default="all", help="Scenario to run")
    parser.add_argument("--output", default=None, help="Output directory for execution evidence")
    args = parser.parse_args()

    try:
        runner = ScenarioRunner(target_url=args.target, output_dir=args.output)
    except ValueError as e:
        print(f"[!] Target Validation Error: {e}", file=sys.stderr)
        sys.exit(1)

    print("=" * 70)
    print(" GASHA CONTROLLED DEFENSIVE DEFENSE ATTACK SIMULATOR (PHASE 5)")
    print(f" Target: {args.target} | Scenario: {args.scenario}")
    print("=" * 70)

    results = []
    scenarios_to_run = ["A", "B", "C", "D", "E"] if args.scenario == "all" else [args.scenario]

    for sc in scenarios_to_run:
        method = getattr(runner, f"run_scenario_{sc.lower()}")
        res = method()
        runner.save_results(f"scenario_{sc}", res)
        results.append(res)

    all_passed = all(r.get("success", False) for r in results)
    print("=" * 70)
    print(f" SIMULATION SUITE FINISHED: {'ALL PASSED' if all_passed else 'FAILURES OBSERVED'}")
    for r in results:
        status_str = "PASS" if r.get("success") else "FAIL"
        print(f"  - [{status_str}] {r['scenario']}")
    print("=" * 70)

    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
