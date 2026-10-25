"""
==============================================================================
FILE: apps/api/app/core/issue_token.py
ROLE / OWNERSHIP: Backend & DevOps Engineers
OBJECTIVE: Issue a short-lived analyst JWT for the SOC dashboard until a sign-in flow exists.
USAGE (from apps/api, with the same JWT_SECRET as the running API):
    python -m app.core.issue_token alice --hours 8
==============================================================================
"""

import argparse

from app.core.security import create_jwt_token


def main() -> None:
    parser = argparse.ArgumentParser(description="Issue a SOC analyst bearer token")
    parser.add_argument("subject", help="Analyst name or email, recorded in the token")
    parser.add_argument("--hours", type=float, default=8, help="Token lifetime (default 8h)")
    args = parser.parse_args()
    print(create_jwt_token({"sub": args.subject, "role": "analyst"}, expires_seconds=int(args.hours * 3600)))


if __name__ == "__main__":
    main()
