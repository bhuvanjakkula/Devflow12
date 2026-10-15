"""Integration tests exercise real API, SQLite, revisions, evidence and review status."""
from fastapi.testclient import TestClient

from app.main import app
from app import storage


def client_for(monkeypatch, tmp_path):
    monkeypatch.setattr(storage, "DB_PATH", tmp_path / "workflow-test.sqlite3")
    return TestClient(app)


def create_project(client, name="Invoices"):
    response = client.post("/api/projects", json={"name": name})
    assert response.status_code == 201, response.text
    return response.json()["id"]


def post_feature(client, project_id, text="Users must be able to upload an invoice and see its total."):
    response = client.post(f"/api/projects/{project_id}/workflow/features", json={"customer_text": text})
    assert response.status_code == 201, response.text
    return response.json()


def approve(client, project_id, criterion_id):
    response = client.post(f"/api/projects/{project_id}/workflow/criteria/{criterion_id}/approve", json={"reviewer": "Customer representative"})
    assert response.status_code == 200, response.text
    return response.json()


def add_link(client, pid, cid, reference="f2baf44"):
    response = client.post(f"/api/projects/{pid}/workflow/criteria/{cid}/code-links", json={"reference": reference, "file_path": "src/billing.py"})
    assert response.status_code == 201, response.text
    return response.json()["id"]


def evidence(client, pid, cid, link, outcome="passed", method="manual"):
    response = client.post(f"/api/projects/{pid}/workflow/criteria/{cid}/evidence", json={
        "code_link_id": link, "test_name": "invoice_total_matches_sum", "outcome": outcome, "method": method,
        "run_reference": "https://ci.example.invalid/runs/123" if method == "ci_reported" else "",
        "details": "sample input 10+20 yields 30", "reported_by": "QA engineer"})
    assert response.status_code == 201, response.text
    return response.json()["id"]


def review(client, pid, evidence_id, decision="accepted"):
    response = client.post(f"/api/projects/{pid}/workflow/evidence/{evidence_id}/review", json={
        "decision": decision, "reviewer": "Release reviewer", "note": "Manual review of reported result"})
    assert response.status_code == 200, response.text
    return response.json()


def status(client, pid):
    result = client.get(f"/api/projects/{pid}/workflow/report")
    assert result.status_code == 200, result.text
    payload = result.json()
    return payload["features"][0]["criteria"][0]["verification"]["status"], payload


def test_full_workflow_and_revision_invalidates_evidence(monkeypatch, tmp_path):
    with client_for(monkeypatch, tmp_path) as client:
        pid = create_project(client)
        f = post_feature(client, pid)
        assert f["criteria"][0]["status"] == "draft"
        assert f["criteria"][0]["verification"]["status"] == "draft"
        cid = f["criteria"][0]["id"]
        approve(client, pid, cid)
        assert status(client, pid)[0] == "unlinked"
        link = add_link(client, pid, cid)
        assert status(client, pid)[0] == "missing_evidence"
        ev = evidence(client, pid, cid, link)
        assert status(client, pid)[0] == "awaiting_review"
        review(client, pid, ev)
        state, report = status(client, pid)
        assert state == "reviewed_pass"
        assert report["summary"]["reviewed_pass"] == 1
        assert report["summary"]["not_reviewed_pass"] == 0
        assert not report["unresolved"]
        second = add_link(client, pid, cid, "pr-49")
        assert status(client, pid)[0] == "missing_evidence"
        second_ev = evidence(client, pid, cid, second, method="ci_reported")
        review(client, pid, second_ev)
        assert status(client, pid)[0] == "reviewed_pass"
        resp = client.patch(f"/api/projects/{pid}/workflow/criteria/{cid}", json={
            "statement": "Given an invoice with two line items, when uploaded, the displayed total equals their exact sum."})
        assert resp.status_code == 200
        assert resp.json()["revision"] == 2
        assert status(client, pid)[0] == "draft"
        approve(client, pid, cid)
        assert status(client, pid)[0] == "stale_evidence"
        assert client.get(f"/api/projects/{pid}/workflow/events").json()["events"]
        assert client.get(f"/api/projects/{pid}/workflow/features/{f['id']}").status_code == 200


def test_failures_superseding_reports_and_rejections(monkeypatch, tmp_path):
    with client_for(monkeypatch, tmp_path) as client:
        pid = create_project(client)
        cid = post_feature(client, pid)["criteria"][0]["id"]
        approve(client, pid, cid)
        link = add_link(client, pid, cid)
        fail_id = evidence(client, pid, cid, link, outcome="failed")
        review(client, pid, fail_id)
        assert status(client, pid)[0] == "failed"
        blocked_id = evidence(client, pid, cid, link, outcome="blocked")
        review(client, pid, blocked_id)
        assert status(client, pid)[0] == "blocked"
        pass_id = evidence(client, pid, cid, link, outcome="passed")
        review(client, pid, pass_id, "rejected")
        assert status(client, pid)[0] == "rejected_evidence"
        assert client.post(f"/api/projects/{pid}/workflow/evidence/{pass_id}/review", json={
            "decision": "accepted", "reviewer": "Same reviewer"}).status_code == 409
        pass_id = evidence(client, pid, cid, link)
        review(client, pid, pass_id)
        assert status(client, pid)[0] == "reviewed_pass"


def test_cross_project_references_are_rejected(monkeypatch, tmp_path):
    with client_for(monkeypatch, tmp_path) as client:
        p1 = create_project(client, "Project A")
        p2 = create_project(client, "Project B")
        c1 = post_feature(client, p1)["criteria"][0]["id"]
        c2 = post_feature(client, p2)["criteria"][0]["id"]
        l1 = add_link(client, p1, c1)
        assert client.post(f"/api/projects/{p1}/workflow/criteria/{c1}/evidence", json={
            "code_link_id": l1, "test_name": "not yet approved", "outcome": "passed", "reported_by": "Jane Doe"}).status_code == 409
        assert client.post(f"/api/projects/{p2}/workflow/criteria/{c1}/approve", json={"reviewer": "Jane Doe"}).status_code == 404
        approve(client, p2, c2)
        assert client.post(f"/api/projects/{p2}/workflow/criteria/{c2}/evidence", json={
            "code_link_id": l1, "test_name": "no cross project", "outcome": "passed", "reported_by": "Jane Doe"}).status_code == 404
        assert client.get(f"/api/projects/{p2}/workflow/features/999999").status_code == 404
        assert client.get(f"/api/projects/888888/workflow/report").status_code == 404
        assert client.post(f"/api/projects/{p1}/workflow/criteria/{c1}/evidence", json={
            "code_link_id": l1, "test_name": "CI test", "outcome": "passed", "method": "ci_reported", "reported_by": "Jane Doe"}).status_code == 422


def test_blank_text_is_rejected_and_report_without_features(monkeypatch, tmp_path):
    with client_for(monkeypatch, tmp_path) as client:
        pid = create_project(client)
        _, report = None, client.get(f"/api/projects/{pid}/workflow/report").json()
        assert report["summary"]["criteria"] == 0
        assert client.post(f"/api/projects/{pid}/workflow/features", json={"customer_text": "               "}).status_code == 422
        feature = post_feature(client, pid, "A user must upload a valid PDF. A user should be able to view its details.")
        assert len(feature["criteria"]) >= 1


def test_workflow_page_is_served(monkeypatch, tmp_path):
    with client_for(monkeypatch, tmp_path) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert "From customer request" in response.text
        assert "Traceability" in response.text
        assert client.get("/overview").status_code == 200
