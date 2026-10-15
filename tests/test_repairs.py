from app.mutation import mutation_audit, shrink_witness
from app.numeric_verifier import verify_numeric


def test_faulty_clamp_gets_rechecked_repair_proposals():
    source = 'def clamp(x):\n    if x < 0:\n        return 1\n    return x\n'
    examples = [{'inputs': {'x': -1}, 'expected': 0}, {'inputs': {'x': 0}, 'expected': 0}, {'inputs': {'x': 5}, 'expected': 5}]
    result = mutation_audit(source, 'clamp', examples, max_mutants=20, repair=True)
    assert result['baseline']['status'] == 'counterexample_found'
    assert result['repair_proposals'] and result['summary']['mutation_score'] is None
    for proposal in result['repair_proposals']:
        assert proposal['recheck']['status'] == 'examples_passed'
        assert verify_numeric(proposal['source'], 'clamp', examples)['status'] == 'examples_passed'
        assert proposal['diff']


def test_witness_shrinks_while_difference_is_preserved():
    original = 'def f(x):\n    return 0'
    candidate = 'def f(x):\n    return 1 if x >= 10 else 0'
    witness = {'inputs': {'x': 100}, 'expected': 0, 'actual': 1}
    result = shrink_witness(original, candidate, 'f', witness)
    assert 10 <= result['inputs']['x'] < 100
    assert result['shrink_attempts'] <= 32
    assert result['status'] == 'counterexample'


def test_repair_does_not_accept_unsupported_host_operations():
    result = mutation_audit('def f(x):\n    return eval(x)', 'f', [{'inputs': {'x': 1}, 'expected': 1}], repair=True)
    assert not result['mutants'] and result['baseline']['status'] == 'unsupported'
    passing = mutation_audit('def f(x):\n    return x', 'f', [{'inputs': {'x': 1}, 'expected': 1}], repair=True)
    assert passing['status'] == 'no_repair_needed_for_examples' and not passing['repair_proposals']
