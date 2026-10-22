"""
Generate strong random values for GASHA's secret settings.

Usage (from the repo root, virtual environment active):
    python scripts/dev/generate_secrets.py

Copy the lines you need into your .env (local) or into your hosting provider's
environment settings (deployed). Use DIFFERENT values for each environment, and
never commit them. Nothing is saved anywhere by this script.
"""
import secrets
import sys

try:
    from cryptography.fernet import Fernet
except ImportError:
    print(
        "FAIL: cryptography is not installed. "
        "Activate the API venv and run: pip install -r apps/api/requirements.txt",
        file=sys.stderr,
    )
    sys.exit(1)

print("# Paste into .env or your host's secret settings. Different values per environment.")
print(f"JWT_SECRET={secrets.token_urlsafe(48)}")
print(f"INTERNAL_API_KEY={secrets.token_urlsafe(32)}")
print(f"GASHA_TELEMETRY_API_KEY={secrets.token_urlsafe(32)}")
print(f"GASHA_PROVISIONING_TOKEN={secrets.token_urlsafe(32)}")
print(f"CREDENTIAL_ENCRYPTION_KEY={Fernet.generate_key().decode()}")
