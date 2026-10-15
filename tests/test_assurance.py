import ast
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.dataflow import scan_dataflow
from app.numeric_verifier import verify_numeric


def example(value, expected):
    return {'inputs': {'x': value}, 'expected': expected}


def test_numeric_verifier_detects_real_counterexample():
    result = verify_numeric('def clamp(x):\n    if x < 0:\n        return 1\n    return x\n', 'clamp', [example(-1, 0), example(2, 2)])
    assert result['status'] == 'counterexample_found'
    assert result['cases'][0]['actual'] == 1
    assert result['cases'][1]['status'] == 'passed'


@pytest.mark.parametrize('value', [-10, -1, 0, 1, 10])
def test_supported_interpreter_matches_known_python_semantics(value):
    source = 'def calculate(x):\n    y = x * 2 + 1\n    if y < 0:\n        return -y\n    return y\n'
    result = verify_numeric(source, 'calculate', [example(value, abs(value * 2 + 1))])
    assert result['status'] == 'examples_passed'


def test_short_circuit_prevents_unreached_division_error():
    result = verify_numeric('def calculate(x):\n    return x != 0 and 10 / x > 1\n', 'calculate', [example(0, False), example(2, True)])
    assert result['status'] == 'examples_passed'


def test_boolean_distinct_from_numeric_and_zero_division():
    result = verify_numeric('def calculate(x):\n    return x > 0\n', 'calculate', [example(1, 1)])
    assert result['status'] == 'counterexample_found'
    result = verify_numeric('def calculate(x):\n    return 10 / x\n', 'calculate', [example(0, 0)])
    assert result['cases'][0]['error'] == 'ZeroDivisionError'


def test_verifier_rejects_host_operations_without_running_them(tmp_path):
    marker = tmp_path / 'never-created'
    source = f"def calculate(x):\n    open({str(marker)!r}, 'w').write('bad')\n    return x\n"
    result = verify_numeric(source, 'calculate', [example(1, 1)])
    assert result['status'] == 'unsupported'
    assert not marker.exists()
    # A forbidden call is rejected even on an untested branch.
    result = verify_numeric('def calculate(x):\n    if x < 0:\n        return eval(x)\n    return x\n', 'calculate', [example(1, 1)])
    assert result['status'] == 'unsupported'


@pytest.mark.parametrize('source', ['import os\ndef f(x):\n    return x', 'def f(x):\n    while x:\n        x = x - 1\n    return x', 'def f(x):\n    return x ** 1000000'])
def test_unsupported_syntax_never_claims_a_pass(source):
    assert verify_numeric(source, 'f', [example(1, 1)])['status'] == 'unsupported'


def test_empty_case_set_and_huge_constant_are_rejected():
    assert verify_numeric('def f(x):\n    return x', 'f', [])['status'] == 'unsupported'
    assert verify_numeric('def f(x):\n    return ' + '9' * 500, 'f', [example(1, 1)])['status'] == 'unsupported'


def test_definition_time_side_effects_are_rejected(tmp_path):
    marker = tmp_path / 'annotation-marker'
    source = f"def f(x: open({str(marker)!r}, 'w')):\n    return x\n"
    assert verify_numeric(source, 'f', [example(1, 1)])['status'] == 'unsupported'
    assert not marker.exists()


def test_dataflow_tracks_alias_assignments_and_helper_calls():
    result = scan_dataflow({'app/helpers.py': 'import os as system\ndef run(command):\n    copied = command\n    system.system(copied)\n',
                           'app/service.py': 'from .helpers import run\nfrom flask import request\ndef endpoint():\n    value = request.args.get("cmd")\n    run(value)\n'})
    assert any(f['rule'] == 'CWE-78' and f['path'] == 'app/helpers.py' for f in result['findings'])
    helper = next(f for f in result['findings'] if f['rule'] == 'HELPER_FLOW')
    assert helper['path'] == 'app/service.py'
    assert any(s['kind'].startswith('external:') for s in helper['sources'])


def test_parameterized_sql_and_safe_reassignment_do_not_flag():
    result = scan_dataflow({'safe.py': 'def query(cursor, user):\n    cursor.execute("SELECT * FROM users WHERE id=?", (user,))\n\ndef fixed(command):\n    command = "echo fixed"\n    import os\n    os.system(command)\n'})
    assert not result['findings']


def test_interpolated_query_and_branch_merge_are_flagged():
    result = scan_dataflow({'query.py': 'def query(cursor, user):\n    sql = "SELECT " + user\n    cursor.execute(sql)\n\ndef risky(value, condition):\n    copied = "safe"\n    if condition:\n        copied = value\n    eval(copied)\n'})
    assert {'CWE-89', 'CWE-95'} <= {f['rule'] for f in result['findings']}


def make_project(client):
    pid = client.post('/api/projects', json={'name': 'Assurance project'}).json()['id']
    base = f'/api/projects/{pid}'
    feature = client.post(base + '/workflow/features', json={'customer_text': 'Users must calculate a nonnegative total.'}).json()
    cid = feature['criteria'][0]['id']
    client.post(base + f'/workflow/criteria/{cid}/code-links', json={'reference': 'source-1', 'file_path': 'app/rules.py'})
    return base, cid


def test_structured_spec_clarification_and_real_test_generation(tmp_path):
    with TestClient(app) as client:
        base, cid = make_project(client)
        payload = {'criterion_id': cid, 'actor': 'Customer', 'trigger': 'Submit numeric amount', 'behavior': 'Return the amount with negative values clamped to zero.',
                   'failure_behavior': 'Reject nonnumeric inputs.', 'source_file': 'app/rules.py', 'function': 'clamp', 'examples': [example(-1, 0), example(2, 2)]}
        result = client.post(base + '/engineering/specifications', json=payload).json()
        assert result['status'] == 'ready_for_stakeholder_review'
        ast.parse(result['pytest_source'])
        # Execute generated tests only against this developer-authored fixture.
        package = tmp_path / 'app'
        package.mkdir()
        (package / '__init__.py').write_text('', encoding='utf-8')
        target = package / 'rules.py'
        target.write_text('def clamp(x):\n    return x if x > 0 else 0\n', encoding='utf-8')
        (tmp_path / 'test_generated.py').write_text(result['pytest_source'], encoding='utf-8')
        command = [sys.executable, '-m', 'pytest', 'test_generated.py', '-q', '--basetemp=.generated-test-tmp']
        run = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True, timeout=20)
        assert run.returncode == 0, run.stdout + run.stderr
        target.write_text('def clamp(x):\n    return x if x > 0 else 99\n', encoding='utf-8')
        run = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True, timeout=20)
        assert run.returncode == 1 and 'failed' in run.stdout
        payload['examples'].append(example(-1, 99))
        result = client.post(base + '/engineering/specifications', json=payload).json()
        assert result['status'] == 'needs_clarification' and result['pytest_source'] is None
        assert client.post(base + '/engineering/specifications', json={'behavior': 'The system must be fast.'}).json()['status'] == 'needs_clarification'


def test_verification_is_bound_to_revision_and_source_without_upgrading_evidence():
    source = 'def clamp(x):\n    return x if x > 0 else 0\n'
    with TestClient(app) as client:
        base, cid = make_project(client)
        client.post(base + '/engineering/repository', json={'files': {'app/rules.py': source}})
        payload = {'criterion_id': cid, 'source_file': 'app/rules.py', 'function': 'clamp', 'source': source, 'examples': [example(-1, 0)]}
        result = client.post(base + '/engineering/verify-numeric', json=payload)
        assert result.status_code == 200 and result.json()['status'] == 'examples_passed'
        life = client.get(base + '/engineering/lifecycle').json()
        assert life['computed_verification'][0]['current_revision_and_linked_source']
        assert life['traceability_summary']['reviewed_pass'] == 0
        client.patch(base + f'/workflow/criteria/{cid}', json={'statement': 'Negative amounts must instead produce a validation error.'})
        life = client.get(base + '/engineering/lifecycle').json()
        assert not life['computed_verification'][0]['current_revision_and_linked_source']
        assert 'stale_numeric_verification' in {b['kind'] for b in life['release_review']['blockers']}
        other = client.post('/api/projects', json={'name': 'Different assurance project'}).json()['id']
        assert client.post(f'/api/projects/{other}/engineering/verify-numeric', json=payload).status_code == 404
        payload['examples'] = [{'inputs': {'x': '1'}, 'expected': 1}]
        assert client.post(base + '/engineering/verify-numeric', json=payload).status_code == 422
        assert client.get(base + '/engineering/assurance-reports').json()['reports']
