#!/usr/bin/env python3
"""
Reset entrypoint expected under scripts/reset/ (README scripts charter).

Delegates to scripts/demo/reset_local.py. Never runs without confirmation
unless --yes is passed. Does not touch Postgres/Supabase.

    python scripts/reset/reset_local.py --dry-run
    python scripts/reset/reset_local.py
    python scripts/reset/reset_local.py --yes
"""
from __future__ import annotations

import runpy
import sys
from pathlib import Path

TARGET = Path(__file__).resolve().parents[1] / "demo" / "reset_local.py"


def main() -> int:
    if not TARGET.is_file():
        print(f"FAIL: reset implementation missing: {TARGET}")
        return 1
    sys.argv = [str(TARGET), *sys.argv[1:]]
    try:
        runpy.run_path(str(TARGET), run_name="__main__")
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else (0 if code is None else 1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
