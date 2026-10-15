import json
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app import storage
from app.protection import ProtectionInput, audit


def test_read_only_audit_detections_redaction_and_unknown_controls(tmp_path):
    marker = tmp_path / 'never-executed'
    credential = 'AKIA' + 'A' * 16
    payload = ProtectionInput(files={'app.py': f'import pathlib\npathlib.Path({str(marker)!r}).write_text("executed")\ndef run(x):\n    return eval(x)\n# {credential}\n',
                                    'Dockerfile': 'FROM python:latest\nUSER root\n',
                                    '.github/workflows/build.yml': 'permissions: write-all\non: pull_request_target\nuses: vendor/action@main\n',
                                    'requirements.txt': 'requests>=2\nfastapi==0.115.0\n-r other.txt\n',
                                    'package.json': '{"dependencies":{"a":"^1.2.3","b":"1.2.3"}}'})
    report = audit(payload)
    assert not marker.exists()
    assert credential not in json.dumps(report)
    assert str(marker) not in json.dumps(report)
    rules = {finding['rule'] for finding in report['findings']}
    assert {'EXPOSED_SECRET', 'ROOT_CONTAINER', 'MUTABLE_IMAGE', 'CI_PERMISSIONS', 'CI_TRUST_BOUNDARY',
            'MUTABLE_ACTION', 'DEPENDENCY_REPRODUCIBILITY', 'JS_DEPENDENCY_REPRODUCIBILITY'} <= rules
    assert all(c['status'] == 'unassessed' for c in report['controls'])
    assert not report['production_certified']


def test_unsupported_language_is_explicitly_incomplete():
    report = audit(ProtectionInput(files={'service.ts': 'export const value = 1;'}))
    assert report['status'] == 'incomplete'
    assert 'Language semantics' in report['diagnostics'][0]['reason']
    assert report['protections']['project_modified'] is False


@pytest.mark.parametrize('manifest', ['broken', '[]', '{"dependencies":[]}', '{"dependencies":{"x":3}}'])
def test_invalid_manifests_never_look_complete(manifest):
    report = audit(ProtectionInput(files={'package.json': manifest}))
    assert report['status'] == 'incomplete'
    assert report['diagnostics']


def test_clean_inputs_do_not_certify_reported_controls():
    report = audit(ProtectionInput(files={'app.py': 'def identity(x):\n    """Return input."""\n    return x\n'},
                                  controls={'authentication': True, 'tls': False}))
    assert report['status'] == 'requires_security_review'
    assert {c['status'] for c in report['controls']} == {'reported_enabled', 'reported_disabled', 'unassessed'}
    assert not report['production_certified']


def test_api_limits_pages_and_no_project_storage(monkeypatch, tmp_path):
    monkeypatch.setattr(storage, 'DB_PATH', tmp_path / 'test.db')
    with TestClient(app) as client:
        before = storage.DB_PATH.read_bytes()
        response = client.post('/api/security-audit', json={'files': {'service.py': 'pass'}})
        assert response.status_code == 200
        assert storage.DB_PATH.read_bytes() == before
        assert client.get('/protection').status_code == 200
        for payload in [{'files': {'../escape.py': 'pass'}}, {'files': {'x.py': 'x' * 60001}},
                        {'files': {'x.py': 'pass'}, 'controls': {'tls': 'true'}},
                        {'files': {'x.py': 'pass'}, 'controls': {'unknown': True}},
                        {'files': {'x.py': 'pass'}, 'execute': True}]:
            assert client.post('/api/security-audit', json=payload).status_code == 422
