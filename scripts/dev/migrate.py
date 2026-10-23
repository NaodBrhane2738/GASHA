#!/usr/bin/env python3
"""
Thin wrapper around infra/scripts/apply_migrations.py.

    python scripts/dev/migrate.py --status
    python scripts/dev/migrate.py --dry-run
    python scripts/dev/migrate.py --yes

Requires DATABASE_URL in the environment or repo-root .env.
Does not create database roles or change RLS policies.
"""
from __future__ import annotations

import runpy
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNNER = REPO_ROOT / "infra" / "scripts" / "apply_migrations.py"


def main() -> int:
    if not RUNNER.is_file():
        print(f"FAIL: migration runner missing: {RUNNER}")
        return 1
    # Preserve CLI flags for the runner (__name__ == "__main__" path).
    sys.argv = [str(RUNNER), *sys.argv[1:]]
    try:
        runpy.run_path(str(RUNNER), run_name="__main__")
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else (0 if code is None else 1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
