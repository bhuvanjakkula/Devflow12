import os
import tempfile
from pathlib import Path

# Must set this before loading the app.
_tmp = tempfile.TemporaryDirectory()
os.environ["DEVFLOW_DB"] = str(Path(_tmp.name) / "test.db")

from fastapi.testclient import TestClient  # noqa: E402
from app.main import app, initialize  # noqa: E402
from app.analysis import analyze_python_code, analyze_requirements  # noqa: E402


def test_requirement_checks():
    result = analyze_requirements("The product must be fast and user-friendly. Users can sign in.")
    assert len(result["ambiguities"]) >= 2
    assert len(result["acceptance_criteria_drafts"]) >= 1


def test_scanner_flags_unsafe_patterns():
    result = analyze_python_code('import subprocess\ndef do(x):\n    return eval(x)\nsubprocess.run("ls", shell=True)\n')
    titles = [f["title"] for f in result["findings"]]
    assert "Use of eval()" in titles
    assert "subprocess shell=True" in titles


def test_scanner_never_executes_code():
    marker = Path(_tmp.name) / "MUST_NOT_EXIST"
    code = f'import pathlib\npathlib.Path({str(marker)!r}).write_text("bad")\n'
    analyze_python_code(code)
    assert not marker.exists()


def test_end_to_end():
    initialize()
    with TestClient(app) as client:
        project = client.post("/api/projects", json={"name": "Test Project", "description": "Local proof of concept"})
        assert project.status_code == 201
        pid = project.json()["id"]
        r = client.post(f"/api/projects/{pid}/requirements/analyze", json={"text": "Users must upload invoices and see totals quickly."})
        assert r.status_code == 200
        assert "plan" in r.json()
        c = client.post(f"/api/projects/{pid}/code/analyze", json={"code": "def add(a,b):\n    return a+b\n", "language": "python"})
        assert c.status_code == 200
        report = client.get(f"/api/projects/{pid}/report")
        assert report.status_code == 200
        assert report.json()["requirements_analyzed"]
        assert report.json()["python_code_scanned"]
        assert len(report.json()["modules"]) == 12
        assert client.get("/api/projects/999999").status_code == 404
