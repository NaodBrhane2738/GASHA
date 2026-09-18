"""
==============================================================================
FILE: apps/api/app/core/logging.py
ROLE / OWNERSHIP: Backend & DevOps Engineers
OBJECTIVE: Structured logging configuration for FastAPI and security event tracing.
TOOLS & LIBRARIES: Python logging, structlog / JSON formatter
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - setup_logging(): Initializes console handlers and structured log levels.
EXPECTED RESULTS / BEHAVIOR:
  - Standardized timestamps, log levels, and module tags for all backend components.
==============================================================================
"""

import logging
import sys
from app.core.config import settings

def setup_logging():
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)]
    )
