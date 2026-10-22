#!/usr/bin/env python3
"""
GASHA demo preflight: one command that says whether the demo is ready.

    python scripts/demo/preflight.py

Reads optional settings from your .env (and the environment). Nothing is printed
that could be a secret, and nothing is changed. Exit code 1 if any check FAILs.

Optional settings (add to your local .env to enable more checks):
    GASHA_API_URL        default http://127.0.0.1:4000
    GASHA_WEB_URL        default http://127.0.0.1:3000
    GASHA_PUBLIC_URL     your ngrok URL (https://....ngrok-free.app)
    CLIENT_SITE_URL      the hosted client website
    GITHUB_TOKEN, VERCEL_API_TOKEN       connector tokens
    NEXT_PUBLIC_API_USER, NEXT_PUBLIC_API_PASSWORD   demo login (same names the frontend uses)
"""
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
try:
    from dotenv import load_dotenv

    load_dotenv(REPO_ROOT / ".env")
except ImportError:
    pass

TIMEOUT = 10
statuses = []


def report(status: str, name: str, detail: str = "") -> None:
    statuses.append(status)
    print(f"{status:<5} {name}" + (f"  - {detail}" if detail else ""))


def http(url, method="GET", headers=None, body=None):
    """Returns (status_code, response_headers, text). Never raises for HTTP errors."""
    request = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return response.status, response.headers, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        return err.code, err.headers, err.read().decode("utf-8", "replace")


def is_gasha_health(text: str) -> bool:
    try:
        return json.loads(text).get("service") == "gasha-api"
    except (ValueError, AttributeError):
        return False


def check_python():
    version = sys.version_info
    if (version.major, version.minor) == (3, 13):
        report("PASS", "Python version", f"{version.major}.{version.minor}")
    else:
        report("FAIL", "Python version", f"running {version.major}.{version.minor}, the team uses 3.13 (recreate .venv with: py -3.13 -m venv .venv)")


def check_backend(api):
    try:
        status, _, text = http(f"{api}/health")
    except Exception as exc:
        report("FAIL", "Backend /health", f"not reachable at {api} ({type(exc).__name__})")
        return
    if status == 200 and is_gasha_health(text):
        report("PASS", "Backend /health", api)
    else:
        report("FAIL", "Backend /health", f"HTTP {status}, unexpected answer")


def check_login_and_data(api):
    user = os.environ.get("NEXT_PUBLIC_API_USER", "")
    password = os.environ.get("NEXT_PUBLIC_API_PASSWORD", "")
    if not user or not password:
        report("SKIP", "Backend login + data", "set NEXT_PUBLIC_API_USER and NEXT_PUBLIC_API_PASSWORD in .env to enable")
        return
    env_id = os.environ.get("NEXT_PUBLIC_API_ENV", "env-prod")
    try:
        status, _, text = http(
            f"{api}/api/v1/auth/login", "POST", {"Content-Type": "application/json"},
            json.dumps({"username": user, "password": password, "environmentId": env_id}).encode(),
        )
        data = json.loads(text) if status == 200 else {}
        token = data.get("accessToken") or data.get("access_token")
        if not token:
            report("FAIL", "Backend login", f"HTTP {status}")
            return
        status, _, _ = http(f"{api}/api/v1/incidents", headers={"Authorization": f"Bearer {token}"})
        report("PASS" if status == 200 else "FAIL", "Backend login + incidents", f"incidents HTTP {status}")
    except Exception as exc:
        report("FAIL", "Backend login + data", type(exc).__name__)


def check_frontend(web):
    try:
        status, _, _ = http(web)
        report("PASS" if status < 400 else "FAIL", "Dashboard (frontend)", f"{web} HTTP {status}")
    except Exception as exc:
        report("FAIL", "Dashboard (frontend)", f"not reachable at {web} ({type(exc).__name__})")


def check_tunnel():
    url = os.environ.get("GASHA_PUBLIC_URL", "").rstrip("/")
    if not url:
        report("SKIP", "Tunnel to this laptop", "set GASHA_PUBLIC_URL (your ngrok address) to enable")
        return
    try:
        status, _, text = http(f"{url}/health", headers={"ngrok-skip-browser-warning": "1"})
        if status == 200 and is_gasha_health(text):
            report("PASS", "Tunnel to this laptop", "public address reaches the backend")
        else:
            report("FAIL", "Tunnel to this laptop", f"HTTP {status}; is ngrok running and pointing at port 4000?")
    except Exception as exc:
        report("FAIL", "Tunnel to this laptop", type(exc).__name__)


def check_client_site():
    url = os.environ.get("CLIENT_SITE_URL", "").rstrip("/")
    if not url:
        report("SKIP", "Client website", "set CLIENT_SITE_URL to enable")
        return
    try:
        status, _, _ = http(url)
        report("PASS" if status < 400 else "FAIL", "Client website", f"HTTP {status}")
    except Exception as exc:
        report("FAIL", "Client website", type(exc).__name__)


def check_github():
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        report("SKIP", "GitHub token", "set GITHUB_TOKEN to enable")
        return
    try:
        status, headers, _ = http("https://api.github.com/user/repos?per_page=1",
                                  headers={"Authorization": f"Bearer {token}", "User-Agent": "gasha-preflight"})
    except Exception as exc:
        report("FAIL", "GitHub token", type(exc).__name__)
        return
    if status != 200:
        report("FAIL", "GitHub token", f"HTTP {status} (expired, revoked, or wrong)")
        return
    expiry = headers.get("github-authentication-token-expiration")
    detail = "valid"
    level = "PASS"
    if expiry:
        try:
            when = datetime.strptime(expiry.replace(" UTC", ""), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            days = (when - datetime.now(timezone.utc)).days
            detail = f"valid, expires in {days} days"
            if days < 10:
                level = "WARN"
        except ValueError:
            pass
    report(level, "GitHub token", detail)


def check_vercel():
    token = os.environ.get("VERCEL_API_TOKEN", "")
    if not token:
        report("SKIP", "Vercel token", "set VERCEL_API_TOKEN to enable")
        return
    try:
        status, _, _ = http("https://api.vercel.com/v2/user", headers={"Authorization": f"Bearer {token}"})
    except Exception as exc:
        report("FAIL", "Vercel token", type(exc).__name__)
        return
    hint = "" if status == 200 else " (the token needs personal-account scope; team-only tokens fail this check)"
    report("PASS" if status == 200 else "FAIL", "Vercel token", f"HTTP {status}{hint}")


def check_storage():
    backend = os.environ.get("GASHA_STORAGE_BACKEND", "memory")
    dialect = os.environ.get("GASHA_DB_DIALECT", "sqlite")
    if backend != "sql":
        report("WARN", "Data storage", "in memory: incidents are lost if the backend restarts (set GASHA_STORAGE_BACKEND=sql to keep them in a local file)")
        return
    if dialect == "postgres":
        url = os.environ.get("DATABASE_URL", "")
        try:
            import psycopg

            with psycopg.connect(url, connect_timeout=8) as conn:
                conn.execute("SELECT 1")
            report("PASS", "Data storage", "Postgres reachable")
        except Exception as exc:
            report("FAIL", "Data storage", f"Postgres not reachable ({type(exc).__name__})")
        return
    path = Path(os.environ.get("GASHA_DATABASE_PATH") or REPO_ROOT / "apps" / "data" / "gasha_storage.db")
    folder = path.parent if path.parent.exists() else path.parent.parent
    if os.access(folder, os.W_OK):
        report("PASS", "Data storage", f"local SQLite file {path.name}, folder writable")
    else:
        report("FAIL", "Data storage", f"cannot write to {folder}")


def main() -> int:
    api = os.environ.get("GASHA_API_URL", "http://127.0.0.1:4000").rstrip("/")
    web = os.environ.get("GASHA_WEB_URL", "http://127.0.0.1:3000").rstrip("/")
    print(f"GASHA preflight  (API {api}, dashboard {web})\n")
    check_python()
    check_backend(api)
    check_login_and_data(api)
    check_frontend(web)
    check_tunnel()
    check_client_site()
    check_github()
    check_vercel()
    check_storage()
    print()
    fails, warns = statuses.count("FAIL"), statuses.count("WARN")
    if fails:
        print(f"NOT READY: {fails} failed, {warns} warning(s).")
        return 1
    print("READY." if not warns else f"READY, with {warns} warning(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())