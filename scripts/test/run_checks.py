#!/usr/bin/env python3
"""
Developer check suite aligned with CONTRIBUTING (lint/tests/contracts).

    python scripts/test/run_checks.py
    python scripts/test/run_checks.py --skip-web
    python scripts/test/run_checks.py --skip-lint

Runs what is available on this machine. Does not deploy or touch remote DBs.
Web lint failures are reported; use --strict-lint to fail the process on lint
(CI currently keeps web lint non-blocking until Frontend clears eslint errors).
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def resolve_pnpm() -> str | None:
    path = shutil.which("pnpm")
    if path:
        return path
    if os.name == "nt":
        return shutil.which("pnpm.cmd")
    return None


def prefer_python() -> str:
    """Prefer repo .venv interpreter when present."""
    if os.name == "nt":
        candidate = REPO_ROOT / ".venv" / "Scripts" / "python.exe"
    else:
        candidate = REPO_ROOT / ".venv" / "bin" / "python"
    if candidate.is_file():
        return str(candidate)
    return sys.executable


def run(label: str, cmd: list[str], cwd: Path | None = None, env: dict | None = None) -> int:
    print(f"\n==> {label}")
    print("    " + " ".join(cmd))
    merged = os.environ.copy()
    if env:
        merged.update(env)
    try:
        proc = subprocess.run(cmd, cwd=str(cwd or REPO_ROOT), env=merged)
    except FileNotFoundError as exc:
        print(f"    FAIL (command not found: {exc})")
        return 1
    status = "OK" if proc.returncode == 0 else "FAIL"
    print(f"    {status} (exit {proc.returncode})")
    return proc.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="Run local GASHA quality checks.")
    parser.add_argument("--skip-web", action="store_true", help="skip frontend lint/build")
    parser.add_argument("--skip-lint", action="store_true", help="skip frontend eslint")
    parser.add_argument(
        "--strict-lint",
        action="store_true",
        help="fail if web lint fails (default: report only, matching current CI)",
    )
    parser.add_argument("--skip-build", action="store_true", help="skip next build")
    args = parser.parse_args()

    failed = 0
    skipped: list[str] = []
    pnpm = resolve_pnpm()
    py = prefer_python()

    if pnpm:
        failed |= run("contracts typecheck", [pnpm, "--filter", "@gasha/contracts", "run", "typecheck"])
        if not args.skip_web:
            if not args.skip_lint:
                code = run("web lint", [pnpm, "--filter", "@gasha/web", "lint"])
                if args.strict_lint:
                    failed |= code
                elif code != 0:
                    print("    NOTE: lint failed but not failing this script (pass --strict-lint).")
                    print("    Blocker: Frontend must clear @typescript-eslint/no-explicit-any before CI can gate lint.")
            if not args.skip_build:
                failed |= run("web build", [pnpm, "--filter", "@gasha/web", "build"])
    else:
        skipped.append("pnpm (contracts/web)")
        print("SKIP  pnpm not on PATH — contracts/web checks not run")

    api = REPO_ROOT / "apps" / "api"
    failed |= run(
        "backend unit tests",
        [py, "-m", "pytest", "tests", "-q"],
        cwd=api,
        env={"PYTHONPATH": f".{os.pathsep}{REPO_ROOT / 'packages' / 'telemetry-sdk' / 'python'}"},
    )
    failed |= run(
        "telemetry SDK tests",
        [py, "-m", "pytest", "packages/telemetry-sdk/python/tests", "-q"],
        env={"PYTHONPATH": str(REPO_ROOT / "packages" / "telemetry-sdk" / "python")},
    )
    failed |= run(
        "ruff (errors only)",
        [py, "-m", "ruff", "check", "apps/api/app", "--select", "E9,F63,F7,F82"],
    )

    print()
    if skipped:
        print(f"Skipped: {', '.join(skipped)}")
    if failed:
        print("DONE with failures.")
        return 1
    print("DONE all executed checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
