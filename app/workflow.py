"""Human-reviewed requirements-to-evidence traceability workflow.

All verification claims are *reviewed evidence*, not proof of software correctness.
The prototype never clones repositories, runs supplied code, or calls a CI provider.
"""
from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.analysis import analyze_requirements
from app.storage import db, get_project, now_iso

router = APIRouter(prefix="/api/projects/{project_id}/workflow", tags=["Traceability workflow"])


class FeatureInput(BaseModel):
    customer_text: str = Field(min_length=12, max_length=15000)


class CriterionEdit(BaseModel):
    statement: str = Field(min_length=15, max_length=2500)


class Approval(BaseModel):
    reviewer: str = Field(min_length=2, max_length=100)


class CodeLinkInput(BaseModel):
    reference: str = Field(min_length=3, max_length=350, description="Git commit hash, PR URL, or change identifier (not checked remotely)")
    file_path: str = Field(default="", max_length=350)
    notes: str = Field(default="", max_length=1000)


class EvidenceInput(BaseModel):
    code_link_id: int = Field(gt=0)
    test_name: str = Field(min_length=3, max_length=250)
    outcome: Literal["passed", "failed", "blocked"]
    method: Literal["manual", "ci_reported"] = "manual"
    run_reference: str = Field(default="", max_length=500)
    details: str = Field(default="", max_length=4000)
    reported_by: str = Field(min_length=2, max_length=100)


class EvidenceReview(BaseModel):
    decision: Literal["accepted", "rejected"]
    reviewer: str = Field(min_length=2, max_length=100)
    note: str = Field(default="", max_length=1500)


def must_exist(conn: sqlite3.Connection, table: str, column: str, row_id: int, project_id: int) -> dict:
    # Constant SQL mapping: table and column never originate from user input.
    permitted = {
        ("feature_requirements", "id"): "SELECT * FROM feature_requirements WHERE id=? AND project_id=?",
        ("acceptance_criteria", "id"): """SELECT ac.* FROM acceptance_criteria ac
            JOIN feature_requirements f ON f.id=ac.feature_id WHERE ac.id=? AND f.project_id=?""",
        ("code_links", "id"): """SELECT cl.* FROM code_links cl
            JOIN acceptance_criteria ac ON ac.id=cl.criterion_id
            JOIN feature_requirements f ON f.id=ac.feature_id WHERE cl.id=? AND f.project_id=?""",
        ("test_evidence", "id"): """SELECT ev.* FROM test_evidence ev
            JOIN acceptance_criteria ac ON ac.id=ev.criterion_id
            JOIN feature_requirements f ON f.id=ac.feature_id WHERE ev.id=? AND f.project_id=?""",
    }
    row = conn.execute(permitted[(table, column)], (row_id, project_id)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Item not found in this project")
    return dict(row)


def record_event(conn: sqlite3.Connection, project_id: int, action: str, object_type: str, object_id: int, details: dict):
    conn.execute(
        "INSERT INTO workflow_events(project_id, action, object_type, object_id, details_json, created_at) VALUES (?,?,?,?,?,?)",
        (project_id, action, object_type, object_id, json.dumps(details), now_iso()),
    )


def clean(value: str, label: str, minimum: int = 1) -> str:
    value = value.strip()
    if len(value) < minimum:
        raise HTTPException(status_code=422, detail=f"{label} needs at least {minimum} characters")
    return value


def generate_drafts(customer_text: str) -> list[str]:
    """Draft checkable statements; do not pretend the vague prompts are executable tests."""
    analysis = analyze_requirements(customer_text)
    clauses = analysis["requirements"][:10] or [customer_text]
    statements = []
    for clause in clauses:
        concise = re.sub(r"\s+", " ", clause).strip().rstrip(". ")
        if not concise:
            continue
        statements.append(
            f"Given the agreed prerequisites, when the actor performs: {concise}, "
            "then the observable result must match the behavior approved by the stakeholder. "
            "Specify concrete inputs, expected output, and edge cases before approving."
        )
    return statements or ["Given defined inputs, when the requested action occurs, then the agreed observable result is produced."]


def _feature_snapshot(conn: sqlite3.Connection, feature_id: int) -> dict:
    feature = dict(conn.execute("SELECT * FROM feature_requirements WHERE id=?", (feature_id,)).fetchone())
    rows = conn.execute("SELECT * FROM acceptance_criteria WHERE feature_id=? ORDER BY id", (feature_id,)).fetchall()
    feature["criteria"] = [_criterion_snapshot(conn, dict(row)) for row in rows]
    return feature


def _criterion_snapshot(conn: sqlite3.Connection, criterion: dict) -> dict:
    links = [dict(r) for r in conn.execute("SELECT * FROM code_links WHERE criterion_id=? ORDER BY id", (criterion["id"],))]
    evidence = [dict(r) for r in conn.execute("SELECT * FROM test_evidence WHERE criterion_id=? ORDER BY id", (criterion["id"],))]
    criterion["code_links"] = links
    criterion["evidence"] = evidence
    current_by_link: dict[int, dict] = {}
    for ev in evidence:
        # latest report wins, even if it has not yet been reviewed
        if ev["criterion_revision"] == criterion["revision"]:
            current_by_link[ev["code_link_id"]] = ev

    if criterion["status"] != "approved":
        status, reason = "draft", "Acceptance criterion still needs stakeholder approval."
    elif not links:
        status, reason = "unlinked", "No implementation change is linked to this criterion."
    else:
        latest = [current_by_link.get(link["id"]) for link in links]
        if any(item and item["review_status"] == "accepted" and item["outcome"] == "failed" for item in latest):
            status, reason = "failed", "An accepted test report records a failure on a linked change."
        elif any(item and item["review_status"] == "accepted" and item["outcome"] == "blocked" for item in latest):
            status, reason = "blocked", "An accepted test report records a blocked test."
        elif any(item and item["review_status"] == "pending" for item in latest):
            status, reason = "awaiting_review", "Most recent test report needs human review."
        elif any(item and item["review_status"] == "rejected" for item in latest):
            status, reason = "rejected_evidence", "Most recent test report was rejected; new evidence is needed."
        elif any(item is None for item in latest):
            old = any(ev["criterion_revision"] != criterion["revision"] for ev in evidence)
            status = "stale_evidence" if old else "missing_evidence"
            reason = ("Earlier evidence predates the latest criterion revision. Re-test every linked change."
                      if old else "At least one linked code change lacks test evidence for this revision.")
        elif all(item and item["review_status"] == "accepted" and item["outcome"] == "passed" for item in latest):
            status, reason = "reviewed_pass", "Each linked change has a current accepted passing test report (self-reported, not independently executed)."
        else:
            status, reason = "uncertain", "Current evidence does not justify a passing conclusion."

    criterion["verification"] = {"status": status, "reason": reason, "scope": "reviewed, self-reported evidence only"}
    return criterion


def _report(conn: sqlite3.Connection, project_id: int) -> dict:
    project = get_project(conn, project_id)
    features = [_feature_snapshot(conn, row["id"]) for row in conn.execute("SELECT id FROM feature_requirements WHERE project_id=? ORDER BY id", (project_id,))]
    criteria = [criterion for feature in features for criterion in feature["criteria"]]
    counts = Counter(criterion["verification"]["status"] for criterion in criteria)
    unresolved = [{"feature_id": feat["id"], "criterion_id": c["id"], "criterion_code": c["local_code"],
                   "status": c["verification"]["status"], "reason": c["verification"]["reason"]}
                  for feat in features for c in feat["criteria"] if c["verification"]["status"] != "reviewed_pass"]
    return {
        "project": project,
        "features": features,
        "summary": {"features": len(features), "criteria": len(criteria),
                    "reviewed_pass": counts["reviewed_pass"], "not_reviewed_pass": len(criteria) - counts["reviewed_pass"],
                    "by_status": dict(counts)},
        "unresolved": unresolved,
        "notice": "Reviewed pass means people accepted a self-reported test result for every linked change at the current criterion revision. "
                  "This app does not run tests, verify Git references, check CI authenticity or prove code correctness. "
                  "Local demonstration only: there is no user authentication or independent reviewer identity verification.",
    }


@router.post("/features", status_code=201)
def create_feature(project_id: int, payload: FeatureInput):
    customer_text = clean(payload.customer_text, "Customer requirement", 12)
    with db() as conn:
        get_project(conn, project_id)
        timestamp = now_iso()
        cur = conn.execute("INSERT INTO feature_requirements(project_id, customer_text, created_at) VALUES (?,?,?)",
                           (project_id, customer_text, timestamp))
        feature_id = cur.lastrowid
        for index, statement in enumerate(generate_drafts(customer_text), start=1):
            conn.execute("""INSERT INTO acceptance_criteria(feature_id, local_code, statement, status, revision, updated_at)
                         VALUES (?,?,?,?,?,?)""", (feature_id, f"AC-{index:02d}", statement, "draft", 1, timestamp))
        record_event(conn, project_id, "created", "feature", feature_id, {"drafts": index})
        return _feature_snapshot(conn, feature_id)


@router.get("/features")
def list_features(project_id: int):
    with db() as conn:
        get_project(conn, project_id)
        return {"features": [_feature_snapshot(conn, row["id"]) for row in conn.execute(
            "SELECT id FROM feature_requirements WHERE project_id=? ORDER BY id DESC", (project_id,))]}


@router.get("/features/{feature_id}")
def get_feature(project_id: int, feature_id: int):
    with db() as conn:
        must_exist(conn, "feature_requirements", "id", feature_id, project_id)
        return _feature_snapshot(conn, feature_id)


@router.patch("/criteria/{criterion_id}")
def edit_criterion(project_id: int, criterion_id: int, payload: CriterionEdit):
    statement = clean(payload.statement, "Acceptance criterion", 15)
    with db() as conn:
        criterion = must_exist(conn, "acceptance_criteria", "id", criterion_id, project_id)
        if statement != criterion["statement"]:
            conn.execute("""UPDATE acceptance_criteria SET statement=?, revision=revision+1,
                            status='draft', updated_at=? WHERE id=?""", (statement, now_iso(), criterion_id))
            record_event(conn, project_id, "revised", "criterion", criterion_id, {"new_revision": criterion["revision"] + 1})
            from app.lifecycle import criterion_impact
            revised = must_exist(conn, "acceptance_criteria", "id", criterion_id, project_id)
            record_event(conn, project_id, 'impact_assessed', 'criterion', criterion_id,
                         criterion_impact(conn, project_id, revised))
        updated = must_exist(conn, "acceptance_criteria", "id", criterion_id, project_id)
        return _criterion_snapshot(conn, updated)


@router.post("/criteria/{criterion_id}/approve")
def approve_criterion(project_id: int, criterion_id: int, payload: Approval):
    from app.enterprise import actor
    reviewer = actor(clean(payload.reviewer, "Approver", 2))
    with db() as conn:
        criterion = must_exist(conn, "acceptance_criteria", "id", criterion_id, project_id)
        if criterion["status"] != "approved":
            conn.execute("UPDATE acceptance_criteria SET status='approved', updated_at=? WHERE id=?", (now_iso(), criterion_id))
            record_event(conn, project_id, "approved", "criterion", criterion_id, {"reviewer_entered": reviewer, "revision": criterion["revision"]})
        updated = must_exist(conn, "acceptance_criteria", "id", criterion_id, project_id)
        return _criterion_snapshot(conn, updated)


@router.post("/criteria/{criterion_id}/code-links", status_code=201)
def create_code_link(project_id: int, criterion_id: int, payload: CodeLinkInput):
    reference = clean(payload.reference, "Code reference", 3)
    with db() as conn:
        must_exist(conn, "acceptance_criteria", "id", criterion_id, project_id)
        cur = conn.execute("INSERT INTO code_links(criterion_id, reference, file_path, notes, created_at) VALUES (?,?,?,?,?)",
                           (criterion_id, reference, payload.file_path.strip(), payload.notes.strip(), now_iso()))
        record_event(conn, project_id, "linked", "code_link", cur.lastrowid, {"criterion_id": criterion_id, "reference": reference})
        return dict(conn.execute("SELECT * FROM code_links WHERE id=?", (cur.lastrowid,)).fetchone())


@router.post("/criteria/{criterion_id}/evidence", status_code=201)
def create_evidence(project_id: int, criterion_id: int, payload: EvidenceInput):
    test_name = clean(payload.test_name, "Test name", 3)
    from app.enterprise import actor
    reporter = actor(clean(payload.reported_by, "Reporter", 2))
    if payload.method == "ci_reported" and not payload.run_reference.strip():
        raise HTTPException(status_code=422, detail="CI-reported evidence needs a run reference (the URL is not verified)")
    with db() as conn:
        criterion = must_exist(conn, "acceptance_criteria", "id", criterion_id, project_id)
        if criterion["status"] != "approved":
            raise HTTPException(status_code=409, detail="Approve the current acceptance criterion before submitting test evidence")
        link = must_exist(conn, "code_links", "id", payload.code_link_id, project_id)
        if link["criterion_id"] != criterion_id:
            raise HTTPException(status_code=422, detail="Code link does not belong to this criterion")
        cur = conn.execute("""INSERT INTO test_evidence(criterion_id, code_link_id, criterion_revision,
            test_name, outcome, method, run_reference, details, reported_by, review_status, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (criterion_id, payload.code_link_id, criterion["revision"], test_name, payload.outcome, payload.method,
             payload.run_reference.strip(), payload.details.strip(), reporter, "pending", now_iso()))
        record_event(conn, project_id, "reported", "evidence", cur.lastrowid,
                     {"criterion_id": criterion_id, "outcome": payload.outcome, "method": payload.method})
        return dict(conn.execute("SELECT * FROM test_evidence WHERE id=?", (cur.lastrowid,)).fetchone())


@router.post("/evidence/{evidence_id}/review")
def review_evidence(project_id: int, evidence_id: int, payload: EvidenceReview):
    from app.enterprise import actor, principal
    reviewer = actor(clean(payload.reviewer, "Reviewer", 2))
    with db() as conn:
        evidence = must_exist(conn, "test_evidence", "id", evidence_id, project_id)
        if principal.get() is not None and evidence['reported_by'] == reviewer:
            raise HTTPException(status_code=403, detail='A different verified identity must review this evidence')
        if evidence["review_status"] != "pending":
            raise HTTPException(status_code=409, detail="Evidence has already been reviewed; create a new report to supersede it")
        conn.execute("""UPDATE test_evidence SET review_status=?, reviewer=?, review_note=?, reviewed_at=? WHERE id=?""",
                     (payload.decision, reviewer, payload.note.strip(), now_iso(), evidence_id))
        record_event(conn, project_id, "reviewed", "evidence", evidence_id,
                     {"decision": payload.decision, "reviewer_entered": reviewer})
        return dict(conn.execute("SELECT * FROM test_evidence WHERE id=?", (evidence_id,)).fetchone())


@router.get("/report")
def traceability_report(project_id: int):
    with db() as conn:
        return _report(conn, project_id)


@router.get("/events")
def workflow_events(project_id: int):
    with db() as conn:
        get_project(conn, project_id)
        rows = [dict(row) for row in conn.execute(
            "SELECT * FROM workflow_events WHERE project_id=? ORDER BY id DESC LIMIT 300", (project_id,))]
        for row in rows:
            row["details"] = json.loads(row.pop("details_json"))
        return {"events": rows}


@router.get('/criteria/{criterion_id}/impact')
def requirement_impact(project_id: int, criterion_id: int):
    from app.lifecycle import criterion_impact
    with db() as conn:
        criterion = must_exist(conn, 'acceptance_criteria', 'id', criterion_id, project_id)
        return criterion_impact(conn, project_id, criterion)
