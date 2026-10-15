import json

from fastapi.testclient import TestClient

from app.main import app
from app.intelligence import (inspect_source, repository_intelligence, requirements_intelligence,
                              debug_traceback, compare_contracts, environment_check)


def test_alias_security_and_behavior_checks():
    result = inspect_source('service.py', '''import subprocess as sp
from requests import get as fetch
import yaml as y
def collect(items=[]):
    sp.run('echo hello', shell=True)
    fetch('https://example.invalid', verify=False)
    y.load('input', Loader=y.Loader)
    return items
''')
    rules = {f.get('rule') for f in result['findings']}
    assert {'SHELL', 'HTTP_TIMEOUT', 'TLS_DISABLED', 'MUTABLE_DEFAULT', 'YAML_LOADER'} <= rules


def test_safe_calls_are_not_flagged():
    result = inspect_source('safe.py', '''import requests as r
import yaml as y
r.get('https://example.invalid', timeout=3)
y.load('input', Loader=y.SafeLoader)
''')
    assert not result['findings']


def test_transitive_change_impact_relative_imports_and_deletions():
    files = {'pkg/__init__.py': '', 'pkg/rules.py': 'def total(x):\n    return sum(x)\n',
             'pkg/service.py': 'from .rules import total\n',
             'tests/test_service.py': 'import pkg.service\n'}
    report = repository_intelligence(files, dict(files, **{'old.py': 'pass'}), ['pkg/rules.py'], 2, 50)
    assert report['dependency_graph']['pkg/service.py'] == ['pkg/rules.py']
    assert {'pkg/rules.py', 'pkg/service.py', 'tests/test_service.py', 'old.py'} <= set(report['impacted_files'])
    assert report['regression_targets'] == ['tests/test_service.py']
    assert not report['release_checks']['tests_executed']
    assert report['snapshot_sha256'] in report['documentation_markdown']


def test_contradiction_and_traceback():
    req = requirements_intelligence('Users must export invoices. Users must not export invoices.')
    assert req['contradictions'] and not req['approval_ready']
    debug = debug_traceback('Traceback:\n  File "C:\\repo\\app\\rules.py", line 2, in total\nZeroDivisionError: division by zero', {'app/rules.py': ''})
    assert debug['likely_failure_location']['matched_files'] == ['app/rules.py']
    assert debug['exception_type'] == 'ZeroDivisionError'


def test_contract_and_environment_drift():
    report = compare_contracts({'GET /users': {'id': 'integer'}}, {'GET /users': {'id': 'string', 'name': 'string'}, 'GET /other': {}})
    assert not report['compatible']
    assert {i['kind'] for i in report['issues']} == {'missing_field', 'type_mismatch', 'missing_route'}
    assert not environment_check({'python': '3.12'}, {'python': '3.10'})['matches']


def test_never_executes_and_snapshot_hash_changes(tmp_path):
    marker = tmp_path / 'forbidden'
    source = f'from pathlib import Path\nPath({str(marker)!r}).touch()\n'
    a = repository_intelligence({'x.py': source}, None, [], 2, 50)
    b = repository_intelligence({'x.py': source + '# changed'}, None, [], 2, 50)
    assert not marker.exists()
    assert a['snapshot_sha256'] != b['snapshot_sha256']
    assert str(marker) not in json.dumps(a)


def test_engineering_api_persistence_isolation_and_validation():
    with TestClient(app) as client:
        pid = client.post('/api/projects', json={'name': 'Engineering test'}).json()['id']
        other = client.post('/api/projects', json={'name': 'Other project'}).json()['id']
        base = f'/api/projects/{pid}/engineering'
        response = client.post(base + '/repository', json={'files': {'a.py': 'eval(user_input)'}, 'changed_files': ['a.py']})
        assert response.status_code == 200
        assert response.json()['release_checks']['status'] == 'blocked_by_findings'
        assert len(client.get(base + '/reports').json()['reports']) == 1
        assert client.get(f'/api/projects/{other}/engineering/reports').json()['reports'] == []
        for bad in ['../secret.py', 'C:/secret.py', '/secret.py', 'a\\b.py', 'a//b.py']:
            assert client.post(base + '/repository', json={'files': {bad: 'pass'}}).status_code == 422
        assert client.post(base + '/repository', json={'files': {'x.py': 'a' * 60001}}).status_code == 422
        assert client.post(base + '/repository', json={'files': {'x.py': 'pass'}, 'changed_files': ['missing.py']}).status_code == 422
        assert client.post('/api/projects/999999/engineering/repository', json={'files': {'a.py': 'pass'}}).status_code == 404
        d = client.post(base + '/decisions', json={'title': 'Use bounded requests', 'rationale': 'Prevent indefinitely blocked workers', 'owner': 'Lead'})
        assert d.status_code == 201
        assert len(client.get(base + '/decisions').json()['decisions']) == 1
        assert client.get('/engineering').status_code == 200


def test_syntax_errors_remain_findings():
    result = inspect_source('bad.py', 'def broken(')
    assert result['findings'][0]['title'] == 'Syntax error'


def test_deleted_dependency_impacts_surviving_importer():
    files = {'service.py': 'import removed\n'}
    report = repository_intelligence(files, {**files, 'removed.py': 'pass'}, [], 2, 50)
    assert report['changed_files'] == ['removed.py']
    assert report['impacted_files'] == ['removed.py', 'service.py']


def test_cli_snapshot_reader(tmp_path):
    from analyze_repo import read_snapshot
    (tmp_path / 'service.py').write_text('def run():\n    return 1\n', encoding='utf-8')
    cache = tmp_path / '__pycache__'
    cache.mkdir()
    (cache / 'ignored.py').write_text('pass', encoding='utf-8')
    assert list(read_snapshot(tmp_path.resolve())) == ['service.py']
