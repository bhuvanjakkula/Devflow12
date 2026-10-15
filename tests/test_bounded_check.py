import pytest
from app.bounded_check import compare_bounded, BoundedInput


def test_exhaustive_domain_exposes_boundary_difference():
    candidate = 'def f(x):\n    return x if x >= 0 else 1'
    reference = 'def f(x):\n    return x if x >= 0 else 0'
    r = compare_bounded(candidate, reference, 'f', {'x': [-1, 0, 1]})
    assert r['status'] == 'counterexample_found'
    assert r['checked_combinations'] == 3 and len(r['counterexamples']) == 1


def test_unsupported_reference_never_yields_match():
    r = compare_bounded('def f(x):\n    return x', 'def f(x):\n    return abs(x)', 'f', {'x': [0]})
    assert r['status'] == 'incomplete' and r['checked_combinations'] == 0


def test_matching_domain_and_cartesian_order():
    source = 'def f(x, y):\n    return x + y'
    a = compare_bounded(source, source, 'f', {'y': [1, 2], 'x': [0, 1]})
    b = compare_bounded(source, source, 'f', {'x': [0, 1], 'y': [1, 2]})
    assert a == b and a['checked_combinations'] == 4
    assert a['status'] == 'matches_declared_domain'


def test_domain_product_limit():
    with pytest.raises(ValueError):
        BoundedInput(criterion_id=1, source_file='app/rules.py', function='f', source='pass', reference_source='pass', domains={n: list(range(16)) for n in ['x', 'y', 'z']})
