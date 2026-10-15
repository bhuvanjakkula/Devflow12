"""Local SQLite persistence shared across MVP capabilities."""
from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import HTTPException

ROOT = Path(__file__).resolve().parent.parent
def _resolve_db_path() -> Path:
    configured = os.environ.get("DEVFLOW_DB")
    if configured:
        return Path(configured)
    if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        return Path("/tmp/devflow.sqlite3")
    return ROOT / "data" / "devflow.sqlite3"

DB_PATH = _resolve_db_path()


@contextmanager
def db():
    from app.enterprise import enabled, principal
    identity = principal.get()
    if enabled() and identity is None:
        raise RuntimeError('Enterprise storage requires a tenant context')
    path = identity.database if identity else DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        if identity is not None and conn.total_changes:
            from app.audit import append_event
            append_event(conn, identity, conn.total_changes)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_project(conn: sqlite3.Connection, project_id: int) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return dict(row)


def initialize():
    with db() as conn:
        version = conn.execute('PRAGMA user_version').fetchone()[0]
        if version > 2:
            raise RuntimeError('Database schema is newer than this application; refusing downgrade')
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS ai_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            task TEXT NOT NULL,
            model TEXT NOT NULL,
            input_sha256 TEXT NOT NULL,
            outcome TEXT NOT NULL CHECK(outcome IN ('reserved','completed','failed')),
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ai_requests_created ON ai_requests(created_at);
        CREATE TABLE IF NOT EXISTS security_audit (
            sequence INTEGER PRIMARY KEY,
            payload TEXT NOT NULL,
            previous TEXT NOT NULL,
            digest TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS systems_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            result_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_systems_project ON systems_reports(project_id, id);
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            kind TEXT NOT NULL CHECK(kind IN ('requirements','code')),
            result_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_analysis_project_kind ON analyses(project_id, kind, id);

        CREATE TABLE IF NOT EXISTS feature_requirements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            customer_text TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_feature_project ON feature_requirements(project_id, id);
        CREATE TABLE IF NOT EXISTS acceptance_criteria (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            feature_id INTEGER NOT NULL REFERENCES feature_requirements(id) ON DELETE CASCADE,
            local_code TEXT NOT NULL,
            statement TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','approved')),
            revision INTEGER NOT NULL DEFAULT 1,
            updated_at TEXT NOT NULL,
            UNIQUE(feature_id, local_code)
        );
        CREATE TABLE IF NOT EXISTS code_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            criterion_id INTEGER NOT NULL REFERENCES acceptance_criteria(id) ON DELETE CASCADE,
            reference TEXT NOT NULL,
            file_path TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_links_criterion ON code_links(criterion_id, id);
        CREATE TABLE IF NOT EXISTS test_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            criterion_id INTEGER NOT NULL REFERENCES acceptance_criteria(id) ON DELETE CASCADE,
            code_link_id INTEGER NOT NULL REFERENCES code_links(id) ON DELETE CASCADE,
            criterion_revision INTEGER NOT NULL,
            test_name TEXT NOT NULL,
            outcome TEXT NOT NULL CHECK(outcome IN ('passed','failed','blocked')),
            method TEXT NOT NULL CHECK(method IN ('manual','ci_reported')),
            run_reference TEXT NOT NULL DEFAULT '',
            details TEXT NOT NULL DEFAULT '',
            reported_by TEXT NOT NULL DEFAULT '',
            review_status TEXT NOT NULL DEFAULT 'pending' CHECK(review_status IN ('pending','accepted','rejected')),
            reviewer TEXT NOT NULL DEFAULT '',
            review_note TEXT NOT NULL DEFAULT '',
            reviewed_at TEXT,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_evidence_criterion ON test_evidence(criterion_id, id);
        CREATE TABLE IF NOT EXISTS workflow_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            action TEXT NOT NULL,
            object_type TEXT NOT NULL,
            object_id INTEGER NOT NULL,
            details_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_events_project ON workflow_events(project_id, id);
        CREATE TABLE IF NOT EXISTS engineering_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            result_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_engineering_project ON engineering_reports(project_id, id);
        CREATE TABLE IF NOT EXISTS engineering_decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            details_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS assurance_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            kind TEXT NOT NULL CHECK(kind IN ('specification', 'verification', 'security')),
            criterion_id INTEGER REFERENCES acceptance_criteria(id) ON DELETE CASCADE,
            criterion_revision INTEGER,
            result_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_assurance_project ON assurance_reports(project_id, id);
        CREATE TABLE IF NOT EXISTS engineering_experiments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            kind TEXT NOT NULL CHECK(kind IN ('mutation','replay')),
            result_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_experiments_project ON engineering_experiments(project_id, id);
        """)
        conn.execute('PRAGMA user_version = 2')
