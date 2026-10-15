import pytest
from fastapi.testclient import TestClient
from app.main import app
from app import storage


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(storage, 'DB_PATH', tmp_path / 'quality.db')
    with TestClient(app) as instance:
        yield instance


def test_invalid_unicode_source_is_rejected_without_server_error(client):
    pid = client.post('/api/projects', json={'name': 'Unicode regression'}).json()['id']
    response = client.post(f'/api/projects/{pid}/code/analyze', content=b'{"code":"\\ud800"}', headers={'Content-Type': 'application/json'})
    assert response.status_code == 422


def test_all_workbench_modes_and_pages(client):
    pid = client.post('/api/projects', json={'name': 'Whole workbench'}).json()['id']
    base = f'/api/projects/{pid}/engineering'
    samples = {'requirements': {'text': 'Customers must export invoices within 2 seconds and show an error for invalid inputs.'},
               'debug': {'traceback': 'Traceback (most recent call last):\n  File "service.py", line 3, in calculate\nZeroDivisionError: division by zero', 'files': {'service.py': 'pass'}},
               'contracts': {'provider': {'GET /users': {'id': 'integer'}}, 'consumer': {'GET /users': {'id': 'string'}}},
               'environment': {'expected': {'python': '3.12'}, 'actual': {'python': '3.11'}}}
    for mode, payload in samples.items():
        assert client.post(base + '/' + mode, json=payload).status_code == 200
    for path in ['/', '/overview', '/engineering', '/systems', '/quality', '/api/docs', '/docs/oauth2-redirect', '/openapi.json', '/security-client.js']:
        assert client.get(path).status_code == 200
    assert client.get('/engineering').headers['Cache-Control'] == 'no-store'
    for endpoint in ['/api/modules', '/api/quality', f'/api/projects/{pid}', f'/api/projects/{pid}/report', base + '/decisions', base + '/lifecycle', f'/api/projects/{pid}/workflow/features']:
        assert client.get(endpoint).status_code == 200


def test_snapshot_rejects_unknown_options(client):
    pid = client.post('/api/projects', json={'name': 'Strict input'}).json()['id']
    response = client.post(f'/api/projects/{pid}/engineering/systems', json={'files': {'x.py': 'pass'}, 'slo_typo': {}})
    assert response.status_code == 422


def test_security_flow_and_bounded_endpoints(client):
    pid = client.post('/api/projects', json={'name': 'All assurance modes'}).json()['id']
    base = f'/api/projects/{pid}'
    feature = client.post(base + '/workflow/features', json={'customer_text': 'Users must see an accurate numeric total.'}).json()
    cid = feature['criteria'][0]['id']
    response = client.post(base + '/engineering/security-flow', json={'files': {'service.py': 'def run(user):\n    return eval(user)\n'}})
    assert response.status_code == 200 and response.json()['findings']
    payload = {'criterion_id': cid, 'source_file': 'app/rules.py', 'function': 'total',
               'source': 'def total(x):\n    return x + 1\n', 'reference_source': 'def total(x):\n    return x + 1\n',
               'domains': {'x': [-1, 0, 1]}}
    response = client.post(base + '/engineering/bounded-check', json=payload)
    assert response.status_code == 200 and response.json()['status'] == 'matches_declared_domain'
    assert client.post('/api/projects/999999/engineering/bounded-check', json=payload).status_code == 404


def test_quality_report_absence_integrity_and_staleness(client, monkeypatch, tmp_path):
    import json
    from app import quality
    monkeypatch.setattr(quality, 'ROOT', tmp_path)
    monkeypatch.setattr(quality, 'source_digest', lambda: 'current')
    assert client.get('/api/quality').json()['status'] == 'not_run'
    folder = tmp_path / 'data' / 'quality'
    folder.mkdir(parents=True)
    target = folder / 'latest.json'
    target.write_text('broken')
    assert client.get('/api/quality').json()['status'] == 'invalid_report'
    target.write_text('[]')
    assert client.get('/api/quality').json()['status'] == 'invalid_report'
    target.write_text(json.dumps({'schema_version': 1, 'source_sha256': 'current', 'status': 'passed'}))
    assert client.get('/api/quality').json()['status'] == 'passed'
    target.write_text(json.dumps({'schema_version': 1, 'source_sha256': 'old', 'status': 'passed'}))
    assert client.get('/api/quality').json()['status'] == 'stale'


def test_quality_digest_detects_source_and_test_changes(tmp_path):
    from app.quality import source_digest
    (tmp_path / 'app').mkdir()
    source = tmp_path / 'app' / 'rules.py'
    source.write_text('def total():\n    return 1\n')
    before = source_digest(tmp_path)
    source.write_text('def total():\n    return 2\n')
    assert source_digest(tmp_path) != before
    before = source_digest(tmp_path)
    (tmp_path / 'tests').mkdir()
    (tmp_path / 'tests' / 'test_rules.py').write_text('assert 1 == 1')
    assert source_digest(tmp_path) != before


def test_scanner_covers_security_network_and_failure_rules():
    from app.analysis import analyze_python_code, analyze_requirements
    source = '''import os, pickle, yaml, requests
class Service:
    pass
def unsafe(value):
    try:
        os.system(value)
        pickle.loads(value)
        yaml.load(value)
        requests.get("https://example.invalid")
    except Exception:
        pass
'''
    result = analyze_python_code(source)
    titles = {finding['title'] for finding in result['findings']}
    assert {'Shell command execution', 'Pickle deserialization', 'YAML load without explicit loader',
            'HTTP call without timeout', 'Overly broad exception handling'} <= titles
    assert result['metrics']['classes'] == 1
    assert analyze_requirements('')['requirements'] == []
    assert not any('Which user roles' in item for item in analyze_requirements('Users must export reports. Admins can manage accounts.')['open_questions'])
