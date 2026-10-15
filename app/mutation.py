"""Deterministic grammar-constrained mutations and bounded distinguishing-input search."""
import ast
import copy
import hashlib
import random
import difflib

from app.numeric_verifier import verify_numeric

SWAPS = {ast.Add: ast.Sub, ast.Sub: ast.Add, ast.Lt: ast.LtE, ast.LtE: ast.Lt,
         ast.Gt: ast.GtE, ast.GtE: ast.Gt, ast.Eq: ast.NotEq, ast.NotEq: ast.Eq}


def shrink_witness(source, candidate, function, witness, budget=32):
    """Greedily reduce input magnitude while rechecking the behavioral difference."""
    current = dict(witness['inputs'])
    best = dict(witness)
    attempts = 0
    progress = True
    while progress and attempts < budget:
        progress = False
        for name in sorted(current):
            value = current[name]
            candidates = [False] if type(value) is bool else [type(value)(v) for v in (0, 1 if value > 0 else -1, int(value / 2), value - (1 if value > 0 else -1))]
            for smaller in candidates:
                if abs(smaller) >= abs(value) or attempts >= budget:
                    continue
                attempts += 1
                inputs = {**current, name: smaller}
                ref = verify_numeric(source, function, [{'inputs': inputs, 'expected': 0}])
                if not ref['cases'] or 'actual' not in ref['cases'][0]:
                    continue
                check = verify_numeric(candidate, function, [{'inputs': inputs, 'expected': ref['cases'][0]['actual']}])
                if check['status'] == 'counterexample_found':
                    current = inputs
                    best = check['cases'][0]
                    progress = True
                    break
    return {**best, 'shrink_attempts': attempts, 'oracle': 'original implementation; stakeholder confirmation required',
            'minimization_scope': 'Greedy bounded reduction; global minimality is not proven.'}


def mutation_audit(source, function, examples, seed=0, max_mutants=12, probe_count=20, repair=False):
    baseline = verify_numeric(source, function, examples)
    report = {'status': 'baseline_not_passing', 'baseline': baseline, 'seed': seed, 'mutants': [],
              'scope': 'Restricted numeric model, local edits and bounded probes; survivors are not proven equivalent.'}
    report['mode'] = 'repair' if repair else 'audit'
    if repair and baseline['status'] == 'examples_passed':
        report.update(status='no_repair_needed_for_examples', repair_proposals=[])
        return report
    if baseline['status'] != 'examples_passed' and not (repair and baseline['status'] == 'counterexample_found'):
        return report
    tree = ast.parse(source)
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == function)
    edits = []
    for index, node in enumerate(ast.walk(fn)):
        if isinstance(node, ast.BinOp) and type(node.op) in SWAPS:
            edits.append((index, 'binary', SWAPS[type(node.op)]))
        elif isinstance(node, ast.Compare):
            for position, op in enumerate(node.ops):
                if type(op) in SWAPS:
                    edits.append((index, 'comparison', (position, SWAPS[type(op)])))
        elif isinstance(node, ast.Constant) and type(node.value) in (int, float):
            for value in (0, 1, -1):
                value = type(node.value)(value)
                if value != node.value:
                    edits.append((index, 'constant', value))
    rng = random.Random(seed)
    rng.shuffle(edits)
    anchor = examples[0]['inputs']
    probes = []
    # Stable ordering and a persisted seed allow the same probe schedule to be reconstructed.
    boundaries = sorted({-1, 0, 1} | {int(n.value) + delta for n in ast.walk(fn)
                                    if isinstance(n, ast.Constant) and type(n.value) in (int, float) and abs(n.value) <= 1e6
                                    for delta in (-1, 0, 1)})
    for name in sorted(anchor):
        values = [False, True] if type(anchor[name]) is bool else [type(anchor[name])(v) for v in boundaries]
        for value in values:
            probes.append({**anchor, name: value})
    while len(probes) < probe_count:
        probes.append({k: rng.choice([False, True]) if type(v) is bool else type(v)(rng.randint(-100, 100)) for k, v in sorted(anchor.items())})
    probes = probes[:probe_count]
    reference = []
    for inputs in probes:
        checked = verify_numeric(source, function, [{'inputs': inputs, 'expected': 0}])
        rows = checked['cases']
        if rows and 'actual' in rows[0]:
            reference.append({'inputs': inputs, 'expected': rows[0]['actual']})
    seen = set()
    for index, kind, replacement in edits:
        if len(report['mutants']) >= max_mutants:
            break
        candidate = copy.deepcopy(tree)
        candidate_fn = next(n for n in candidate.body if isinstance(n, ast.FunctionDef) and n.name == function)
        nodes = list(ast.walk(candidate_fn))
        original = nodes[index]
        if kind == 'constant':
            original.value = replacement
            description = 'Numeric literal replacement'
        elif kind == 'binary':
            description = type(original.op).__name__ + ' → ' + replacement.__name__
            original.op = replacement()
        else:
            position, operator_type = replacement
            description = type(original.ops[position]).__name__ + ' → ' + operator_type.__name__
            original.ops[position] = operator_type()
        candidate_source = ast.unparse(candidate)
        normalized = ast.dump(candidate, include_attributes=False)
        if normalized in seen:
            continue
        seen.add(normalized)
        result = verify_numeric(candidate_source, function, examples)
        status = 'killed' if result['status'] == 'counterexample_found' else 'survived_examples' if result['status'] == 'examples_passed' else 'unsupported'
        row = {'mutation': description, 'source_sha256': hashlib.sha256(candidate_source.encode()).hexdigest(),
               'candidate_source': candidate_source, 'status': status, 'example_result': result, 'test_gap_witness': None}
        if status == 'survived_examples' and reference and not repair:
            probe_result = verify_numeric(candidate_source, function, reference)
            differences = [c for c in probe_result['cases'] if c['status'] == 'counterexample']
            if differences:
                row['test_gap_witness'] = shrink_witness(source, candidate_source, function, differences[0])
        report['mutants'].append(row)
    total = len(report['mutants'])
    killed = sum(m['status'] == 'killed' for m in report['mutants'])
    supported = sum(m['status'] != 'unsupported' for m in report['mutants'])
    report.update(status='completed', summary={'generated': total, 'killed': killed,
                  'survived': sum(m['status'] == 'survived_examples' for m in report['mutants']),
                  'unsupported': total - supported, 'mutation_score': killed / supported if supported else None},
                  probe_schedule=probes,
                  notice='Mutations preserve selected numeric literal types and comparison/arithmetic operator families. This is not a whole-program type proof, an LLM mutator, or an SMT solver.')
    if repair:
        report['summary']['mutation_score'] = None
        report['repair_proposals'] = [{'source': m['candidate_source'], 'source_sha256': m['source_sha256'],
                                      'change': m['mutation'], 'recheck': m['example_result'],
                                      'diff': ''.join(difflib.unified_diff(source.splitlines(True), (m['candidate_source'] + '\n').splitlines(True), fromfile='original.py', tofile='proposed.py'))}
                                     for m in report['mutants'] if m['status'] == 'survived_examples']
        report['repair_proposals'].sort(key=lambda p: p['source_sha256'])
        report['repair_notice'] = 'One-site candidate patches pass only the fixed examples. No patch is applied or approved; broader tests and human review are required.'
    return report
