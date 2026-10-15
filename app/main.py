"""Local-first DevFlow 12 MVP API."""
from __future__ import annotations

import json
import sqlite3
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field

from app.analysis import analyze_python_code, analyze_requirements, build_plan
from app.storage import ROOT, db, initialize, now_iso, get_project

@asynccontextmanager
async def lifespan(app: FastAPI):
    from app.enterprise import Configuration, Identity, enabled, principal
    import os
    if enabled():
        if any(os.environ.get(name) for name in ['DEVFLOW_OWNER_MODE', 'DEVFLOW_PUBLIC_OWNER_MODE', 'DEVFLOW_API_TOKEN']):
            raise ValueError('Enterprise mode cannot share local owner or shared-token authentication')
        config = Configuration(os.environ['DEVFLOW_ENTERPRISE_CONFIG'])
        app.state.enterprise = config
        for tenant, database in config.tenants.items():
            context = principal.set(Identity('startup', tenant, 'admin', database, config.audit_key))
            try:
                initialize()
            finally:
                principal.reset(context)
    else:
        app.state.enterprise = None
        initialize()
    yield


app = FastAPI(title="DevFlow 12 Intelligent Software Development Assistant", version="0.19.0", docs_url="/api/docs", redoc_url=None, lifespan=lifespan)


@app.exception_handler(RequestValidationError)
async def safe_validation_errors(request, exc):
    # Do not echo source, secrets, invalid Unicode or unserializable exception contexts.
    def safe(value):
        return str(value).encode('utf-8', errors='replace').decode('utf-8')
    errors = [{'type': safe(error['type']), 'loc': [item if isinstance(item, int) else safe(item) for item in error['loc']],
               'msg': safe(error['msg'])} for error in exc.errors()]
    return JSONResponse({'detail': errors}, status_code=422)

MODULES = [
    {"name": "Requirements", "status": "mvp", "description": "Identify ambiguities and draft acceptance criteria."},
    {"name": "Debugging", "status": "prototype", "description": "Traceback mapping and root-cause hypotheses in /engineering."},
    {"name": "Testing", "status": "mvp", "description": "Draft test plans plus traceable, self-reported test evidence; no automatic execution."},
    {"name": "AI Code Quality", "status": "mvp", "description": "Basic Python static checks; comprehensive validation planned."},
    {"name": "Legacy Code", "status": "prototype", "description": "Static Python signatures and repository import maps."},
    {"name": "Documentation", "status": "mvp", "description": "Draft project documentation from requirements."},
    {"name": "Security", "status": "prototype", "description": "Alias-aware Python risk heuristics; findings require review."},
    {"name": "Integration", "status": "prototype", "description": "Declared route and response-field compatibility checks."},
    {"name": "Deployment", "status": "prototype", "description": "Supplied environment comparison and evidence gaps."},
    {"name": "Maintenance", "status": "prototype", "description": "Baseline comparison and transitive import impact."},
    {"name": "Estimation", "status": "prototype", "description": "Static complexity scenarios using user-supplied calibration."},
    {"name": "Collaboration", "status": "prototype", "description": "Persistent decision log and existing clarification/evidence workflow."},
]


class ProjectCreate(BaseModel):
    name: str = Field(min_length=2, max_length=90)
    description: str = Field(default="", max_length=3000)


class RequirementsInput(BaseModel):
    text: str = Field(min_length=12, max_length=15000)


class CodeInput(BaseModel):
    code: str = Field(min_length=1, max_length=60000)
    language: str = "python"


def latest(conn: sqlite3.Connection, project_id: int, kind: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT result_json, created_at FROM analyses WHERE project_id=? AND kind=? ORDER BY id DESC LIMIT 1",
        (project_id, kind),
    ).fetchone()
    return {"result": json.loads(row["result_json"]), "created_at": row["created_at"]} if row else None


@app.get("/")
def index():
    return FileResponse(ROOT / "static" / "workflow.html", media_type="text/html")


@app.get("/overview")
def overview():
    return FileResponse(ROOT / "static" / "index.html", media_type="text/html")


@app.get("/api/modules")
def list_modules():
    return {"modules": MODULES}


@app.get("/api/projects")
def list_projects():
    with db() as conn:
        return {"projects": [dict(r) for r in conn.execute("SELECT * FROM projects ORDER BY id DESC LIMIT 100")]}


@app.post("/api/projects", status_code=201)
def create_project(item: ProjectCreate):
    name = item.name.strip()
    if len(name) < 2:
        raise HTTPException(status_code=422, detail="Project name must have at least two non-space characters")
    with db() as conn:
        cur = conn.execute("INSERT INTO projects(name, description, created_at) VALUES (?,?,?)", (name, item.description.strip(), now_iso()))
        return get_project(conn, cur.lastrowid)


@app.get("/api/projects/{project_id}")
def project_detail(project_id: int):
    with db() as conn:
        return {"project": get_project(conn, project_id), "requirements": latest(conn, project_id, "requirements"), "code": latest(conn, project_id, "code")}


@app.post("/api/projects/{project_id}/requirements/analyze")
def check_requirements(project_id: int, payload: RequirementsInput):
    result = analyze_requirements(payload.text)
    result["plan"] = build_plan(result)
    with db() as conn:
        get_project(conn, project_id)
        conn.execute("INSERT INTO analyses(project_id, kind, result_json, created_at) VALUES (?,?,?,?)", (project_id, "requirements", json.dumps(result), now_iso()))
    return result


@app.post("/api/projects/{project_id}/code/analyze")
def check_code(project_id: int, payload: CodeInput):
    if payload.language.lower().strip() != "python":
        raise HTTPException(status_code=422, detail="The MVP code analyzer supports Python only")
    result = analyze_python_code(payload.code)
    with db() as conn:
        get_project(conn, project_id)
        conn.execute("INSERT INTO analyses(project_id, kind, result_json, created_at) VALUES (?,?,?,?)", (project_id, "code", json.dumps(result), now_iso()))
    return result


@app.get("/api/projects/{project_id}/report")
def get_report(project_id: int):
    with db() as conn:
        project = get_project(conn, project_id)
        req = latest(conn, project_id, "requirements")
        code = latest(conn, project_id, "code")
    actions = []
    if not req:
        actions.append("Run a requirements analysis to identify missing details and generate test ideas.")
    elif req["result"]["open_questions"]:
        actions.append("Confirm answers to unresolved requirement questions with stakeholders.")
    if not code:
        actions.append("Paste Python code to run the non-executing risk scanner.")
    elif code["result"]["findings"]:
        actions.append("Review the code findings manually and verify them with tests.")
    actions.append("Before production use, implement authentication, access controls, audit logs and secure deployment.")
    return {
        "project": project,
        "requirements_analyzed": req is not None,
        "python_code_scanned": code is not None,
        "latest_requirements": req,
        "latest_code": code,
        "next_actions": actions,
        "modules": MODULES,
        "notice": "No automated check proves correctness, security, or readiness to deploy.",
    }


# The traceability API extends (rather than replaces) the existing MVP API.
from app.workflow import router as workflow_router  # noqa: E402
app.include_router(workflow_router)

from app.engineering import router as engineering_router
app.include_router(engineering_router)

from app.systems import router as systems_router
app.include_router(systems_router)

from app.quality import router as quality_router
app.include_router(quality_router)

from app.protection import router as protection_router
app.include_router(protection_router)

from app.ci_evidence import router as ci_router
app.include_router(ci_router)

from app.assurance import router as assurance_router
app.include_router(assurance_router)

from app.bounded_check import router as bounded_router
app.include_router(bounded_router)

from app.security import install_security
install_security(app)

from app.request_limits import RequestSizeLimit
app.add_middleware(RequestSizeLimit)

from app.enterprise import EnterpriseBoundary
app.add_middleware(EnterpriseBoundary)

from app.operations import router as operations_router
app.include_router(operations_router)

from app.ai_assistant import router as ai_router
app.include_router(ai_router)

@app.get('/ai')
def ai_page():
    return FileResponse(ROOT / 'static' / 'ai.html', media_type='text/html')

@app.get('/security-client.js')
def security_client():
    return FileResponse(ROOT / 'static' / 'security-client.js', media_type='text/javascript')

@app.get('/engineering')
def engineering_page():
    return FileResponse(ROOT / 'static' / 'engineering.html', media_type='text/html')


@app.get('/systems')
def systems_page():
    return FileResponse(ROOT / 'static' / 'systems.html', media_type='text/html')


@app.get('/quality')
def quality_page():
    return FileResponse(ROOT / 'static' / 'quality.html', media_type='text/html')


@app.get('/protection')
def protection_page():
    return FileResponse(ROOT / 'static' / 'protection.html', media_type='text/html')


@app.get('/protection-client.js')
def protection_client():
    return FileResponse(ROOT / 'static' / 'protection-client.js', media_type='text/javascript')
