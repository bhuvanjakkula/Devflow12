"""Bounded, deterministic engineering analysis. Submitted source is never executed."""
from __future__ import annotations

import ast
import hashlib
import re
from collections import defaultdict
from pathlib import PurePosixPath

from app.analysis import analyze_python_code, analyze_requirements


def qualified(node, aliases):
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        return qualified(node.value, aliases) + '.' + node.attr
    return ''


def inspect_source(path, source):
    result = analyze_python_code(source)
    result.update(path=path, sha256=hashlib.sha256(source.encode()).hexdigest(), imports=[], symbols=[])
    try:
        tree = ast.parse(source)
    except (SyntaxError, RecursionError):
        return result
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split('.')[0]] = item.name if item.asname else item.name.split('.')[0]
                result['imports'].append({'module': item.name, 'level': 0, 'names': []})
        elif isinstance(node, ast.ImportFrom):
            result['imports'].append({'module': node.module or '', 'level': node.level, 'names': [i.name for i in node.names]})
            for item in node.names:
                aliases[item.asname or item.name] = '.'.join(filter(None, [node.module, item.name]))
    def finding(node, rule, severity, message, remedy):
        result['findings'].append({'line': node.lineno, 'rule': rule, 'severity': severity, 'title': message,
                                   'details': 'Review the operation at this source location; literal values omitted.',
                                   'recommendation': remedy})
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            complexity = 1 + sum(isinstance(n, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.IfExp)) for n in ast.walk(node))
            result['symbols'].append({'name': node.name, 'line': node.lineno, 'end_line': node.end_lineno,
                                      'async': isinstance(node, ast.AsyncFunctionDef), 'complexity': complexity,
                                      'arguments': [a.arg for a in node.args.posonlyargs + node.args.args + node.args.kwonlyargs]})
            for value in node.args.defaults + [d for d in node.args.kw_defaults if d is not None]:
                if isinstance(value, (ast.List, ast.Dict, ast.Set)):
                    finding(value, 'MUTABLE_DEFAULT', 'medium', 'Shared mutable default argument', 'Use None and allocate inside the function.')
            if isinstance(node, ast.AsyncFunctionDef):
                for call in ast.walk(node):
                    if isinstance(call, ast.Call) and qualified(call.func, aliases) in {'time.sleep', 'requests.get', 'requests.post'}:
                        finding(call, 'ASYNC_BLOCKING', 'medium', 'Blocking operation in async function', 'Use an async client or a worker thread.')
        if not isinstance(node, ast.Call):
            continue
        name = qualified(node.func, aliases)
        if name in {'builtins.eval', 'builtins.exec', 'pickle.loads', 'pickle.load', 'os.system'}:
            finding(node, 'UNSAFE_EXECUTION', 'high', 'Unsafe execution or deserialization', 'Replace dynamic execution with validated data parsing.')
        if name.startswith('subprocess.') and any(k.arg == 'shell' and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
            finding(node, 'SHELL', 'high', 'Shell execution detected through import alias', 'Use a fixed argument list with shell=False.')
        if name.startswith(('requests.', 'httpx.')):
            if not any(k.arg == 'timeout' for k in node.keywords):
                finding(node, 'HTTP_TIMEOUT', 'medium', 'HTTP timeout not explicitly configured', 'Configure and verify bounded connection/read timeouts.')
            if any(k.arg == 'verify' and isinstance(k.value, ast.Constant) and k.value.value is False for k in node.keywords):
                finding(node, 'TLS_DISABLED', 'high', 'TLS certificate verification disabled', 'Enable certificate verification.')
        if name.endswith(('.execute', '.executemany')) and node.args and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp)):
            finding(node, 'SQL_INTERPOLATION', 'high', 'Interpolated SQL query', 'Use parameterized queries; verify data flow manually.')
        if name == 'yaml.load':
            loaders = [qualified(k.value, aliases) for k in node.keywords if k.arg == 'Loader']
            if not loaders or any(x not in {'yaml.SafeLoader', 'yaml.CSafeLoader'} for x in loaders):
                finding(node, 'YAML_LOADER', 'high', 'YAML loader is not explicitly safe', 'Use yaml.safe_load.')
    # Do not return submitted source: callers receive locations and redacted evidence.
    for f in result['findings']:
        if f.get('rule') in {'UNSAFE_EXECUTION', 'SHELL', 'SQL_INTERPOLATION'}:
            f['details'] = 'Review the operation at this source location; literal values omitted.'
    result['findings'].sort(key=lambda f: ({'high': 0, 'medium': 1, 'low': 2}[f['severity']], f['line']))
    return result


def requirements_intelligence(text):
    result = analyze_requirements(text)
    conflicts = []
    positives, negatives = {}, {}
    for index, clause in enumerate(result['requirements'], 1):
        match = re.search(r'\b(must|shall|should|can|will)\s+(not\s+)?(.+)', clause, re.I)
        if match:
            key = (clause[:match.start()].lower().strip(), re.sub(r'[^a-z0-9 ]', '', match[3].lower()).strip())
            (negatives if match[2] else positives)[key] = index
    for key in positives.keys() & negatives.keys():
        conflicts.append({'requirements': [positives[key], negatives[key]], 'reason': 'Same actor and action are both allowed/required and prohibited.'})
    result['contradictions'] = conflicts
    result['approval_ready'] = not conflicts and not result['open_questions'] and not result['ambiguities']
    result['approval_ready_meaning'] = 'No supported heuristic issue found; stakeholder approval is still required.'
    return result


def repository_intelligence(files, baseline, changed, hours_per_point, hourly_rate):
    modules = {}
    for path in files.keys() | (baseline or {}).keys():
        if path.endswith('.py'):
            mod = path[:-3].replace('/', '.')
            if mod.endswith('.__init__'):
                mod = mod[:-9]
            modules[mod] = path
    analyses = [inspect_source(p, s) for p, s in sorted(files.items()) if p.endswith('.py')]
    graph = {p: set() for p in files}
    for analysis in analyses:
        module = analysis['path'][:-3].replace('/', '.')
        package = module.split('.')[:-1]
        for imp in analysis['imports']:
            if imp['level']:
                base = package[:max(0, len(package) - imp['level'] + 1)]
                target = '.'.join(base + ([imp['module']] if imp['module'] else []))
            else:
                target = imp['module']
            candidates = [target] + [target + '.' + n if target else n for n in imp['names']]
            for candidate in candidates:
                if candidate in modules and modules[candidate] != analysis['path']:
                    graph[analysis['path']].add(modules[candidate])
    changed_set = set(changed)
    if baseline is not None:
        changed_set |= {p for p in files.keys() | baseline.keys() if files.get(p) != baseline.get(p)}
    reverse = defaultdict(set)
    for caller, dependencies in graph.items():
        for dep in dependencies:
            reverse[dep].add(caller)
    impacted = set(changed_set)
    pending = list(impacted)
    while pending:
        for caller in reverse[pending.pop()]:
            if caller not in impacted:
                impacted.add(caller)
                pending.append(caller)
    findings = [dict(f, path=a['path']) for a in analyses for f in a['findings']]
    from app.dataflow import scan_dataflow
    security_flow = scan_dataflow(files)
    findings.extend(security_flow['findings'])
    high = sum(f['severity'] == 'high' for f in findings)
    symbols = [dict(s, path=a['path']) for a in analyses for s in a['symbols']]
    tests = [p for p in files if PurePosixPath(p).name.startswith('test_') or p.endswith('_test.py')]
    plan = [{'path': s['path'], 'symbol': s['name'], 'line': s['line'], 'cases': ['typical valid input', 'empty/missing input', 'boundary values', 'dependency failure'],
             'status': 'suggested, not executed'} for s in symbols if s['path'] not in tests]
    points = sum(max(1, s['complexity']) for s in symbols if s['path'] in impacted) or len(changed_set)
    low, upper = round(points * hours_per_point * .75, 2), round(points * hours_per_point * 2, 2)
    digest = hashlib.sha256(''.join(p + '\0' + hashlib.sha256(s.encode()).hexdigest() for p, s in sorted(files.items())).encode()).hexdigest()
    docs = '\n'.join(['# Repository reference', '', 'Source snapshot: ' + digest, '', 'Generated from static Python syntax; refresh after source changes.', ''] +
                     [f"- `{s['path']}:{s['line']}` — `{s['name']}({', '.join(s['arguments'])})`; branch complexity estimate {s['complexity']}" for s in symbols])
    return {'snapshot_sha256': digest, 'files': analyses, 'security_flow': security_flow, 'dependency_graph': {k: sorted(v) for k, v in graph.items()},
            'changed_files': sorted(changed_set), 'impacted_files': sorted(impacted), 'regression_targets': sorted(set(tests) & impacted),
            'findings': findings, 'test_plan': plan, 'documentation_markdown': docs,
            'estimate': {'complexity_points': points, 'hours_range': [low, upper], 'cost_range': [round(low * hourly_rate, 2), round(upper * hourly_rate, 2)],
                         'hours_per_point': hours_per_point, 'hourly_rate': hourly_rate,
                         'basis': 'User-supplied calibration applied to static branch counts in impacted files. Scenario range, not a validated forecast.'},
            'release_checks': {'high_severity_findings': high, 'test_files_present': bool(tests), 'tests_executed': False,
                               'status': 'blocked_by_findings' if high else 'needs_test_and_deployment_evidence'},
            'limitations': ['Python static imports only; dynamic imports and runtime dispatch are unresolved.',
                            'No submitted code or tests executed. No complete security or correctness guarantee.',
                            'All test files should be run; dependency graph may miss indirect dependencies.']}


def debug_traceback(traceback, files):
    frames = re.findall(r'File "([^"]+)", line (\d+), in ([^\n]+)', traceback)
    last = traceback.strip().splitlines()[-1] if traceback.strip() else ''
    category = last.split(':', 1)[0]
    remedies = {'KeyError': 'Check whether the key exists and whether the input schema matches the caller.',
                'TypeError': 'Check argument types, None handling, and function signature at the failing call.',
                'ModuleNotFoundError': 'Check installed dependencies, package layout, and the active interpreter.',
                'ConnectionError': 'Check endpoint availability and bounded retry/timeout settings.',
                'IndexError': 'Check collection length and empty input before indexing.',
                'ZeroDivisionError': 'Check denominator validation and zero boundary cases.'}
    locations = []
    for path, line, symbol in frames:
        normalized = path.replace('\\', '/')
        matches = [p for p in files if normalized == p or normalized.endswith('/' + p)]
        locations.append({'path': path, 'line': int(line), 'symbol': symbol.strip(), 'matched_files': matches})
    return {'exception_type': category, 'frames': locations, 'likely_failure_location': locations[-1] if locations else None,
            'hypothesis': remedies.get(category, 'Inspect the innermost frame and reproduce using the same inputs and environment.'),
            'verification_steps': ['Reproduce with a minimal input.', 'Add a regression case for that input.', 'Confirm the fix by running the regression and related tests.'],
            'status': 'triage hypothesis; root cause not verified'}


def compare_contracts(provider, consumer):
    issues = []
    for route, expected in consumer.items():
        actual = provider.get(route)
        if actual is None:
            issues.append({'route': route, 'kind': 'missing_route'})
            continue
        for field, typ in expected.items():
            if field not in actual:
                issues.append({'route': route, 'field': field, 'kind': 'missing_field'})
            elif actual[field] != typ:
                issues.append({'route': route, 'field': field, 'kind': 'type_mismatch', 'expected': typ, 'actual': actual[field]})
    return {'compatible': not issues, 'issues': issues, 'scope': 'Exact route identifiers and declared response field types only; no network requests.'}


def environment_check(expected, actual):
    differences = [{'name': k, 'expected': v, 'actual': actual.get(k), 'kind': 'missing' if k not in actual else 'mismatch'}
                   for k, v in expected.items() if actual.get(k) != v]
    return {'matches': not differences, 'differences': differences, 'scope': 'Compares supplied non-secret environment metadata; does not probe production.'}
