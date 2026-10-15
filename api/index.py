"""Vercel Serverless Function entry point for DevFlow 12."""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("DEVFLOW_DB", "/tmp/devflow.sqlite3")
os.environ.setdefault("DEVFLOW_OWNER_MODE", "1")
os.environ.setdefault("DEVFLOW_PUBLIC_ACCESS", "1")

from app.main import app  # noqa: E402
