"""
GASHA database migration runner.

Applies the SQL files in infra/database/migrations/ (in filename order) to the
database in DATABASE_URL, and remembers which ones are already applied in a
`schema_migrations` table, so running it twice is safe.

Usage (from the repo root, virtual environment active):
    python infra/scripts/apply_migrations.py --status     # show applied / pending
    python infra/scripts/apply_migrations.py --dry-run    # list what would run
    python infra/scripts/apply_migrations.py              # apply pending (asks first)
    python infra/scripts/apply_migrations.py --yes        # apply without asking (CI)

DATABASE_URL comes from your .env (Supabase: Connect -> Session pooler URI).
The password is never printed.

Migrations 001–003 create RLS policies FOR ALL TO service_role (Supabase).
Stock local PostgreSQL typically has no such role. This script does NOT create
roles or alter those policies — that requires an explicit team decision.
If apply fails on missing role "service_role", point DATABASE_URL at Supabase
or wait for a lead-approved local bootstrap.
"""
import argparse
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS_DIR = REPO_ROOT / "infra" / "database" / "migrations"

try:
    from dotenv import load_dotenv

    load_dotenv(REPO_ROOT / ".env")
except ImportError:
    pass


def describe(url: str) -> str:
    """Host and database name only, never the password."""
    p = urlparse(url)
    return f"{p.hostname}:{p.port or 5432}/{(p.path or '/').lstrip('/')}"


def _hint_for_failure(exc: BaseException) -> str:
    text = str(exc).lower()
    if "service_role" in text or ("does not exist" in text and "role" in text):
        return (
            "\nHint: migrations 001–003 reference PostgreSQL role 'service_role' "
            "(Supabase). This runner will not create that role. Use a Supabase "
            "Session pooler DATABASE_URL, or get team approval for a local role "
            "bootstrap. See docs/database-provisioning.md."
        )
    return ""


def _applied_filenames(conn) -> set[str]:
    """Return applied migration names, or empty set if the tracker table is absent."""
    reg = conn.execute("SELECT to_regclass('public.schema_migrations')").fetchone()[0]
    if reg is None:
        return set()
    return {row[0] for row in conn.execute("SELECT filename FROM schema_migrations")}


def _ensure_tracker(conn) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        "filename TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
    )
    # Supabase exposes every public table through its public API. With row level
    # security on and no policies, only the database owner (this script) can use it.
    conn.execute("ALTER TABLE schema_migrations ENABLE ROW LEVEL SECURITY")


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply GASHA SQL migrations.")
    parser.add_argument("--status", action="store_true", help="show applied and pending migrations")
    parser.add_argument("--dry-run", action="store_true", help="list pending migrations, change nothing")
    parser.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    args = parser.parse_args()

    url = os.environ.get("DATABASE_URL", "")
    if not url or "your-" in url or "[YOUR" in url.upper():
        print("FAIL: DATABASE_URL is missing or still a placeholder. Set it in your .env file.")
        print("      Prefer Supabase Session pooler URI (port 5432). See docs/environment-variables.md.")
        return 1

    files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    if not files:
        print(f"FAIL: no .sql files found in {MIGRATIONS_DIR}")
        return 1

    try:
        import psycopg
    except ImportError:
        print("FAIL: psycopg is not installed. From apps/api: pip install -r requirements.txt")
        return 1

    try:
        conn = psycopg.connect(url, autocommit=True, connect_timeout=15)
    except Exception as exc:
        print(f"FAIL: could not connect to {describe(url)}: {exc}")
        return 1

    with conn:
        # --status / --dry-run must not create tables or toggle RLS.
        applied = _applied_filenames(conn)
        pending = [f for f in files if f.name not in applied]

        print(f"Database: {describe(url)}")
        for f in files:
            print(f"  {'applied' if f.name in applied else 'PENDING'}  {f.name}")

        if args.status or args.dry_run:
            return 0
        if not pending:
            print("Nothing to do. Database is up to date.")
            return 0
        if not args.yes:
            answer = input(f"Apply {len(pending)} migration(s) to {describe(url)}? [y/N] ")
            if answer.strip().lower() != "y":
                print("Cancelled.")
                return 1

        _ensure_tracker(conn)
        # Re-read in case another process applied meanwhile.
        applied = _applied_filenames(conn)
        pending = [f for f in files if f.name not in applied]
        if not pending:
            print("Nothing to do. Database is up to date.")
            return 0

        for f in pending:
            try:
                with conn.transaction():
                    conn.execute(f.read_text(encoding="utf-8"))
                    conn.execute("INSERT INTO schema_migrations (filename) VALUES (%s)", (f.name,))
                print(f"OK    {f.name}")
            except Exception as exc:
                print(f"FAIL  {f.name}: {exc}")
                print("Stopped. Nothing from this file was applied.")
                print(_hint_for_failure(exc), end="")
                return 1

    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
