from datetime import datetime, timedelta, timezone
import json
import pytest
import httpx
from fastapi.testclient import TestClient
from app.main import app
from app.protection import ProtectionInput, Baseline, audit, compare_reports
from app import ci_evidence as ci


def test_baseline_scope_new_and_changed_findings():
    old = audit(ProtectionInput(files={'service.py': 'eval(x)\n', 'removed.py': 'eval(y)\n'}))
    current = audit(ProtectionInput(files={'service.py': 'pass\n', 'new.py': 'eval(z)\n'}))
    diff = compare_reports(current, Baseline.model_validate(old))
    assert diff['counts']['outside_current_scope'] > 0
    assert diff['counts']['not_seen_in_current'] > 0
    assert diff['counts']['new'] > 0
    assert compare_reports(old, Baseline.model_validate(old))['counts']['unchanged'] == len(old['findings'])
    baseline = Baseline.model_validate(old)
    baseline.findings[0].severity = 'low'
    assert compare_reports(old, baseline)['counts']['severity_changed'] == 1


def test_comparison_api_and_bounds():
    with TestClient(app) as client:
        assert client.get('/protection-client.js').status_code == 200
        baseline = client.post('/api/security-audit', json={'files': {'x.py': 'eval(user)'}}).json()
        response = client.post('/api/security-audit/compare', json={'files': {'x.py': 'pass'}, 'baseline': baseline})
        assert response.status_code == 200
        assert response.json()['comparison']['counts']['not_seen_in_current'] > 0
        assert client.post('/api/security-audit/compare', json={'files': {'x.py': 'pass'}, 'baseline': {'schema_version': 8}}).status_code == 422


def sample_run():
    return {'id': 123, 'repository': {'full_name': 'owner/project'}, 'head_sha': 'a' * 40,
            'path': '.github/workflows/tests.yml', 'head_branch': 'main', 'event': 'push',
            'status': 'completed', 'conclusion': 'success', 'updated_at': datetime.now(timezone.utc).isoformat()}


@pytest.mark.parametrize('change', [{'conclusion': 'failure'}, {'head_sha': 'b' * 40}, {'event': 'pull_request_target'},
                                  {'head_branch': 'other'}, {'path': '.github/workflows/untrusted.yml'},
                                  {'updated_at': 'invalid'}, {'repository': None}, {'id': 999},
                                  {'updated_at': (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()}])
def test_ci_policy_rejects_untrusted_or_stale_metadata(change):
    result = ci.assess_run({**sample_run(), **change}, ci.CIRun(run_id=123, expected_sha='a' * 40),
                           'owner/project', '.github/workflows/tests.yml', 'main')
    assert result['status'] == 'does_not_meet_policy'
    assert not result['deployment_authorized']


def test_ci_configuration_and_api_verification(monkeypatch):
    monkeypatch.delenv('DEVFLOW_CI_TOKEN', raising=False)
    with TestClient(app) as client:
        assert not client.get('/api/ci-evidence/status').json()['configured']
        assert client.post('/api/ci-evidence/verify', json={'run_id': 123, 'expected_sha': 'a' * 40}).status_code == 503
        monkeypatch.setenv('DEVFLOW_CI_REPOSITORY', 'owner/project')
        monkeypatch.setenv('DEVFLOW_CI_TOKEN', 'test-only-token')
        monkeypatch.setattr(ci, 'fetch_run', lambda *args: sample_run())
        assert client.get('/api/ci-evidence/status').json()['configured']
        response = client.post('/api/ci-evidence/verify', json={'run_id': 123, 'expected_sha': 'a' * 40})
        assert response.status_code == 200 and response.json()['status'] == 'verified_run_metadata'
        assert 'test-only-token' not in response.text
        assert client.post('/api/ci-evidence/verify', json={'run_id': 123, 'expected_sha': 'a' * 40, 'url': 'http://localhost'}).status_code == 422
        monkeypatch.setenv('DEVFLOW_CI_REPOSITORY', '../../local')
        assert not client.get('/api/ci-evidence/status').json()['configured']


@pytest.mark.parametrize('status,body', [(200, sample_run()), (403, {}), (200, []), (200, 'not-json')])
def test_ci_fetch_fixed_host_redacted_failures(monkeypatch, status, body):
    class Client:
        def __init__(self, **kwargs):
            assert kwargs['follow_redirects'] is False and kwargs['trust_env'] is False
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def get(self, url, headers):
            assert url == 'https://api.github.com/repos/owner/project/actions/runs/123'
            return httpx.Response(status, content=body.encode() if isinstance(body, str) else json.dumps(body).encode())
    monkeypatch.setattr(ci.httpx, 'Client', Client)
    if status == 200 and isinstance(body, dict):
        assert ci.fetch_run('owner/project', 'test-token', 123)['id'] == 123
    else:
        with pytest.raises(Exception) as error:
            ci.fetch_run('owner/project', 'test-token', 123)
        assert getattr(error.value, 'status_code', None) == 502
        assert 'test-token' not in str(error.value)
