#!/usr/bin/env python3
"""
Reset the local demo data. Safe by design: it MOVES the local SQLite file into a
backup folder (nothing is deleted) and refuses to run while the backend is up.

    python scripts/demo/reset_local.py --dry-run     # show what would happen
    python scripts/demo/reset_local.py               # asks before moving
    python scripts/demo/reset_local.py --yes         # no question

If the backend runs in the default in-memory mode there is no file: just restart the backend.
Restart the backend afterwards so it starts from a clean slate.
"""
import argparse
import os
import shutil
import socket
import sys
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
try:
    from dotenv import load_dotenv

    load_dotenv(REPO_ROOT / ".env")
except ImportError:
    pass


def backend_running(port: int) -> bool:
    with socket.socket() as sock:
        sock.settimeout(1)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Reset local GASHA demo data (moves the SQLite file to a backup).")
    parser.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    parser.add_argument("--dry-run", action="store_true", help="show what would be moved, change nothing")
    parser.add_argument("--port", type=int, default=4000, help="backend port to check (default 4000)")
    args = parser.parse_args()

    db_path = Path(os.environ.get("GASHA_DATABASE_PATH") or REPO_ROOT / "apps" / "data" / "gasha_storage.db")
    candidates = [p for p in (db_path, Path(f"{db_path}-wal"), Path(f"{db_path}-shm")) if p.exists()]

    if not candidates:
        print(f"Nothing to reset: no local file at {db_path}.")
        print("In the default in-memory mode, restarting the backend is the reset.")
        return 0
    if backend_running(args.port):
        print(f"The backend is still running on port {args.port}. Stop it first, then run this again.")
        return 1

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_dir = db_path.parent / "backup"
    print(f"Local database: {db_path}")
    for path in candidates:
        print(f"  would move {path.name} -> backup/{stamp}-{path.name}")
    if args.dry_run:
        print("Dry run: nothing changed.")
        return 0
    if not args.yes and input("Move these files to the backup folder? [y/N] ").strip().lower() != "y":
        print("Cancelled.")
        return 1

    backup_dir.mkdir(parents=True, exist_ok=True)
    for path in candidates:
        shutil.move(str(path), str(backup_dir / f"{stamp}-{path.name}"))
    print(f"Done. Backed up to {backup_dir}. Start the backend again for a clean slate.")
    return 0


if __name__ == "__main__":
    sys.exit(main())