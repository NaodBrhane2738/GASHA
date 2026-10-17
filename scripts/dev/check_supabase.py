"""
GASHA DevOps health check: can this machine reach the Supabase project?
Run from the repo root with your virtual environment active:
    python scripts/dev/check_supabase.py
Reads SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY from your local .env file.
Never prints the keys.
"""
import os
import sys

from dotenv import load_dotenv

load_dotenv()

EXPECTED_TABLES = [
    "detections",
    "incidents",
    "investigations",
    "response_actions",
    "response_audit_log",
    "users",
    "refresh_tokens",
]

url = os.environ.get("SUPABASE_URL", "")
key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")

if not url or "your-project-id" in url:
    sys.exit("FAIL: SUPABASE_URL is missing or still the placeholder. Check your .env file.")
if not key or key.startswith("your-"):
    sys.exit("FAIL: SUPABASE_SERVICE_ROLE_KEY is missing or still the placeholder.")

from supabase import create_client

try:
    client = create_client(url, key)
except Exception as exc:
    sys.exit(f"FAIL: could not create the Supabase client: {exc}")

failed = False
for table in EXPECTED_TABLES:
    try:
        client.table(table).select("*").limit(1).execute()
        print(f"OK    {table}")
    except Exception as exc:
        failed = True
        print(f"FAIL  {table}: {exc}")

print()
print("All tables reachable." if not failed else "Some tables failed. Did you run both migrations?")
sys.exit(1 if failed else 0)