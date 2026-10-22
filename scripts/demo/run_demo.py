#!/usr/bin/env python3
"""
    python scripts/demo/run_demo.py              # backend + dashboard (production build, fast)
    python scripts/demo/run_demo.py --dev        # dashboard in dev mode (slow first compile)
    python scripts/demo/run_demo.py --persist    # keep incidents in a local SQLite file (this run only)
    python scripts/demo/run_demo.py --no-frontend

"""
import argparse
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
processes = []


def pump(name: str, stream) -> None:
    for line in iter(stream.readline, ""):
        print(f"[{name}] {line.rstrip()}", flush=True)


def start(name: str, command: list, env: dict) -> subprocess.Popen:
    proc = subprocess.Popen(
        command, cwd=REPO_ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace", bufsize=1,
    )
    threading.Thread(target=pump, args=(name, proc.stdout), daemon=True).start()
    processes.append(proc)
    return proc


def stop_all() -> None:
    for proc in processes:
        if proc.poll() is not None:
            continue
        if os.name == "nt":  # also stops the child processes pnpm starts
            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True)
        else:
            proc.terminate()
    for proc in processes:
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def port_in_use(port: int) -> bool:
    with socket.socket() as sock:
        sock.settimeout(1)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def wait_for(url: str, seconds: int) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                if response.status < 500:
                    return True
        except Exception:
            time.sleep(1)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the local GASHA demo.")
    parser.add_argument("--dev", action="store_true", help="dashboard in dev mode instead of the production build")
    parser.add_argument("--persist", action="store_true", help="store incidents in a local SQLite file for this run")
    parser.add_argument("--no-frontend", action="store_true", help="start only the backend")
    parser.add_argument("--port", type=int, default=4000, help="backend port")
    parser.add_argument("--skip-python-check", action="store_true", help="allow a Python other than 3.13")
    args = parser.parse_args()

    if sys.version_info[:2] != (3, 13) and not args.skip_python_check:
        print(f"This Python is {sys.version_info.major}.{sys.version_info.minor}; the team uses 3.13.")
        print("Recreate the environment:  py -3.13 -m venv .venv   (then activate it and reinstall)")
        return 1

    pnpm = shutil.which("pnpm")
    if not args.no_frontend:
        if not pnpm:
            print("pnpm was not found. Install it with:  corepack enable")
            return 1
        if not args.dev and not (REPO_ROOT / "apps" / "web" / ".next" / "BUILD_ID").exists():
            print("The dashboard is not built yet. Run once:  pnpm --filter @gasha/web build")
            print("(or use --dev, which is slower to start).")
            return 1

    busy = [port for port in ([args.port] + ([] if args.no_frontend else [3000])) if port_in_use(port)]
    if busy:
        print(f"Port(s) {busy} already in use. An older backend or dashboard is probably still running.")
        print("Close the other terminal (Ctrl+C), or end the process, then run this again.")
        return 1

    # Treat a terminate signal like Ctrl+C so the child processes are always cleaned up.
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))

    env = os.environ.copy()
    env.setdefault("PYTHONUNBUFFERED", "1")
    if args.persist:
        env["GASHA_STORAGE_BACKEND"] = "sql"
    mode = "local SQLite file" if env.get("GASHA_STORAGE_BACKEND") == "sql" else "in memory (lost on restart)"

    start("api", [sys.executable, "-m", "uvicorn", "app.main:app", "--app-dir", "apps/api", "--port", str(args.port)], env)
    if not args.no_frontend:
        start("web", [pnpm, "--filter", "@gasha/web", "dev" if args.dev else "start"], env)

    try:
        api_ok = wait_for(f"http://127.0.0.1:{args.port}/health", 60)
        print("\n" + "=" * 60)
        print(f"Backend   : http://127.0.0.1:{args.port}/health   {'READY' if api_ok else 'NOT ANSWERING, check the [api] lines'}")
        if not args.no_frontend:
            web_ok = wait_for("http://127.0.0.1:3000", 120 if args.dev else 60)
            print(f"Dashboard : http://localhost:3000            {'READY' if web_ok else 'NOT ANSWERING, check the [web] lines'}")
        print(f"Data      : {mode}")
        print("Check everything with:  python scripts/demo/preflight.py   (in a second terminal)")
        print("Ctrl+C stops both.")
        print("=" * 60 + "\n")
        while all(proc.poll() is None for proc in processes):
            time.sleep(1)
        print("A process exited, stopping the rest.")
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        stop_all()
    return 0


if __name__ == "__main__":
    sys.exit(main())