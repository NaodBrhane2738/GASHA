#!/usr/bin/env python3
"""
One-time local workspace setup helpers (DevOps).

    python scripts/setup/setup_local.py
    python scripts/setup/setup_local.py --check-only

Does not install packages, start Docker, or overwrite an existing .env.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def resolve_cmd(name: str) -> str | None:
    """Resolve an executable, including Windows .cmd shims (e.g. pnpm.cmd)."""
    path = shutil.which(name)
    if path:
        return path
    if os.name == "nt":
        return shutil.which(f"{name}.cmd") or shutil.which(f"{name}.exe")
    return None


def run_version(executable: str, version_args: list[str]) -> str:
    try:
        out = subprocess.run(
            [executable, *version_args],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
        line = (out.stdout or out.stderr or "").strip().splitlines()
        if out.returncode != 0 and not line:
            return f"unavailable (exit {out.returncode})"
        return line[0] if line else "unknown"
    except Exception as exc:
        return f"unavailable ({exc})"


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare a local GASHA checkout (non-destructive).")
    parser.add_argument("--check-only", action="store_true", help="only print prerequisite status")
    args = parser.parse_args()

    env_example = REPO_ROOT / ".env.example"
    env_path = REPO_ROOT / ".env"

    print(f"Repo: {REPO_ROOT}")
    print()
    print("Prerequisites")
    checks = [
        ("python", sys.executable, ["--version"]),
        ("node", resolve_cmd("node"), ["--version"]),
        ("pnpm", resolve_cmd("pnpm"), ["--version"]),
        ("docker", resolve_cmd("docker"), ["--version"]),
    ]
    missing: list[str] = []
    for name, executable, version_args in checks:
        if not executable:
            print(f"  MISS  {name}")
            missing.append(name)
            continue
        version = run_version(executable, version_args)
        if version.startswith("unavailable"):
            print(f"  MISS  {name}: {version}")
            missing.append(name)
        else:
            label = executable if name == "python" else name
            print(f"  OK    {label}: {version}")

    print()
    if not env_example.is_file():
        print("FAIL: .env.example is missing.")
        return 1

    if args.check_only:
        if missing:
            print(f"Missing tools: {', '.join(missing)}")
            return 1
        print("Check-only: prerequisites look present.")
        return 0

    if env_path.exists():
        print(f"OK    .env already exists (left unchanged): {env_path}")
    else:
        shutil.copy(env_example, env_path)
        print("OK    created .env from .env.example")
        print("      Edit secrets locally. Never commit .env.")

    print()
    print("Next steps")
    print("  1. Edit .env (Session pooler DATABASE_URL for Postgres/Supabase).")
    print("  2. DB only:     docker compose up -d postgres redis")
    print("     Full stack:  docker compose up --build")
    print("  3. pnpm install")
    print("  4. Python:      py -3.13 -m venv .venv  (Windows) then pip install -r apps/api/requirements-dev.txt")
    print("  5. Migrations:  python scripts/dev/migrate.py --status")
    print("                 (Supabase recommended; local Compose PG blocked on service_role — see docs/database-provisioning.md)")
    print("  6. Demo:        python scripts/demo/run_demo.py --persist")
    print("  7. Checks:      python scripts/test/run_checks.py")
    if missing:
        print()
        print(f"WARN: install missing tools before continuing: {', '.join(missing)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
