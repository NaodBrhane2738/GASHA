#!/usr/bin/env python3
"""
Seed entrypoint (README scripts charter).

SQL seed files would live in infra/database/seeds/. That directory is currently
empty (placeholder only). This script refuses to invent demo data.

For local demos, prefer:
  - NODE_ENV=development so the API can use its built-in development seeds, or
  - python scripts/demo/run_demo.py

    python scripts/seed/seed.py
    python scripts/seed/seed.py --check
    python scripts/seed/seed.py --require-sql
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SEEDS = REPO_ROOT / "infra" / "database" / "seeds"


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply SQL seeds if present (none shipped yet).")
    parser.add_argument(
        "--check",
        action="store_true",
        help="report whether seed SQL exists (exit 0 either way; empty seeds is the current valid state)",
    )
    parser.add_argument(
        "--require-sql",
        action="store_true",
        help="exit 1 if no *.sql files exist under infra/database/seeds/",
    )
    args = parser.parse_args()

    sql_files = sorted(SEEDS.glob("*.sql")) if SEEDS.is_dir() else []

    if args.require_sql:
        if sql_files:
            print(f"OK    {len(sql_files)} seed file(s) in {SEEDS}")
            return 0
        print(f"FAIL  no *.sql seeds in {SEEDS} (--require-sql)")
        return 1

    if args.check:
        if sql_files:
            print(f"OK    {len(sql_files)} seed file(s) in {SEEDS}")
        else:
            print(f"OK    no *.sql seeds in {SEEDS} (expected until seed ownership is decided)")
        return 0

    if not sql_files:
        print(f"No SQL seeds found in {SEEDS}.")
        print("Nothing to apply. Do not invent seed data from this script.")
        print("Use development-mode API seeds or scripts/demo/run_demo.py for demos.")
        print("Blocker: seed content ownership (Backend vs DevOps) is unresolved.")
        return 0

    print("Seed SQL files are present but no applicator is configured yet.")
    print("Files:")
    for f in sql_files:
        print(f"  {f.name}")
    print("Ask backend/DevOps leads how these should be applied (not automated here).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
