import copy
import ast

from fastapi.testclient import TestClient

from app.main import app
from app.mutation import mutation_audit
from app.reproducibility import envelope, replay, digest

SOURCE = 'def clamp(x):\n    if x < 0:\n        return 0\n    return x\n'
EXAMPLES = [{'inputs': {'x': 5}, 'expected': 5}]


def test_seeded_mutation_is_reproducible_and_finds_test_gaps():
    a = mutation_audit(SOURCE, 'clamp', EXAMPLES, 42, 20, 20)
    b = mutation_audit(SOURCE, 'clamp', EXAMPLES, 42, 20, 20)
    assert a == b
    assert a['summary']['generated'] > 0
    assert any(m['test_gap_witness'] for m in a['mutants'])
    hashes = [m['source_sha256'] for m in a['mutants']]
    assert len(hashes) == len(set(hashes))
    for mutant in a['mutants']:
        ast.parse(mutant['candidate_source'])
        if mutant['test_gap_witness']:
            assert 'stakeholder confirmation' in mutant['test_gap_witness']['oracle']


def test_stronger_examples_kill_more_mutants():
    weak = mutation_audit(SOURCE, 'clamp', EXAMPLES, 42, 20, 20)
    strong = mutation_audit(SOURCE, 'clamp', EXAMPLES + [{'inputs': {'x': -1}, 'expected': 0}, {'inputs': {'x': 0}, 'expected': 0}], 42, 20, 20)
    assert strong['summary']['killed'] > weak['summary']['killed']


def test_failing_baseline_and_forbidden_source_stop_mutation(tmp_path):
    bad = mutation_audit('def clamp(x):\n    return 99', 'clamp', EXAMPLES)
    assert bad['status'] == 'baseline_not_passing' and not bad['mutants']
    marker = tmp_path / 'forbidden'
    bad = mutation_audit(f"def clamp(x):\n    open({str(marker)!r}, 'w')\n    return x", 'clamp', EXAMPLES)
    assert not bad['mutants'] and not marker.exists()


def test_replay_integrity_source_and_model_checks():
    record = envelope(SOURCE, 'clamp', EXAMPLES)
    assert replay(SOURCE, record)['status'] == 'reproduced'
    assert replay(SOURCE + '\n', record)['status'] == 'source_mismatch'
    corrupt = copy.deepcopy(record)
    corrupt['contract']['examples'][0]['expected'] = 99
    assert replay(SOURCE, corrupt)['status'] == 'record_integrity_mismatch'
    incompatible = dict(record, model_version='unknown-model')
    assert replay(SOURCE, incompatible)['status'] == 'incompatible_model'
    corrupt = copy.deepcopy(record)
    corrupt['result']['status'] = 'unsupported'
    corrupt['result_sha256'] = digest(corrupt['result'])
    assert replay(SOURCE, corrupt)['status'] == 'result_divergence'


def test_local_operator_mutations_change_one_site():
    source = 'def f(x):\n    return (x + 1) + 2\n'
    report = mutation_audit(source, 'f', [{'inputs': {'x': 2}, 'expected': 5}], 0, 20, 5)
    originals = sum(isinstance(n, ast.Add) for n in ast.walk(ast.parse(source)))
    for m in report['mutants']:
        if m['mutation'] == 'Add → Sub':
            assert sum(isinstance(n, ast.Add) for n in ast.walk(ast.parse(m['candidate_source']))) == originals - 1


def test_api_history_isolation_and_stale_requirement_replay():
    with TestClient(app) as client:
        pid = client.post('/api/projects', json={'name': 'Replay project'}).json()['id']
        base = f'/api/projects/{pid}'
        feature = client.post(base + '/workflow/features', json={'customer_text': 'Users must clamp negative values to zero.'}).json()
        cid = feature['criteria'][0]['id']
        payload = {'criterion_id': cid, 'source_file': 'app/rules.py', 'function': 'clamp', 'source': SOURCE, 'examples': EXAMPLES}
        checked = client.post(base + '/engineering/verify-numeric', json=payload)
        assert checked.status_code == 200
        rid = checked.json()['assurance_report_id']
        url = base + f'/engineering/verification/{rid}/replay'
        assert client.post(url, json={'source': SOURCE}).json()['status'] == 'reproduced'
        assert client.post(url, json={'source': SOURCE + '\n'}).json()['status'] == 'source_mismatch'
        client.patch(base + f'/workflow/criteria/{cid}', json={'statement': 'All negative values must instead be rejected as invalid.'})
        r = client.post(url, json={'source': SOURCE}).json()
        assert r['status'] == 'reproduced' and not r['requirement_revision_current']
        other = client.post('/api/projects', json={'name': 'Other replay project'}).json()['id']
        assert client.post(f'/api/projects/{other}/engineering/verification/{rid}/replay', json={'source': SOURCE}).status_code == 404
        assert client.post(base + '/engineering/mutation-audit', json={**payload, 'max_mutants': 21}).status_code == 422
        assert client.post(base + '/engineering/mutation-audit', json=payload).status_code == 200
        assert len(client.get(base + '/engineering/experiments').json()['experiments']) == 4
