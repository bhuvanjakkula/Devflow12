"""Repeatable presubmit gate for this trusted DevFlow checkout only."""
import ast
from datetime import datetime, timezone
import importlib.util
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
for folder in ['.quality-deps', '.pqc-deps', '.enterprise-deps', '.runtime-deps']:
    if (ROOT / folder).is_dir():
        sys.path.insert(0, str(ROOT / folder))
from app.quality import source_digest


def run(args, environment, timeout=180):
    try:
        completed = subprocess.run(args, cwd=ROOT, env=environment, capture_output=True, text=True,
                                   encoding='utf-8', errors='replace', timeout=timeout)
        return completed.returncode, completed.stdout + completed.stderr
    except (OSError, subprocess.TimeoutExpired) as error:
        return 1, type(error).__name__ + ': check tool availability or timeout'


def inventory(path, data):
    tree = ast.parse(path.read_text(encoding='utf-8'))
    statements = set(data.get('executed_lines', [])) | set(data.get('missing_lines', []))
    executed = set(data.get('executed_lines', []))
    functions = []
    def walk(node, prefix=''):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = prefix + child.name
                lines = {line for line in statements if child.body[0].lineno <= line <= child.end_lineno}
                for nested in ast.walk(child):
                    if nested is not child and isinstance(nested, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        lines -= set(range(nested.lineno, nested.end_lineno + 1))
                covered = lines & executed
                functions.append({'name': name, 'line': child.lineno, 'statements': len(lines),
                                  'covered': len(covered), 'missing_lines': sorted(lines - executed),
                                  'status': 'no_executable_body' if not lines else 'not_exercised' if not covered else
                                            'fully_exercised' if lines == covered else 'partially_exercised'})
                walk(child, name + '.')
            elif isinstance(child, ast.ClassDef):
                walk(child, prefix + child.name + '.')
            else:
                walk(child, prefix)
    walk(tree)
    return functions


def main():
    output = ROOT / 'data' / 'quality'
    output.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment['PYTHONPATH'] = os.pathsep.join([str(ROOT), *(str(ROOT / name) for name in ['.runtime-deps', '.enterprise-deps', '.quality-deps', '.pqc-deps'] if (ROOT / name).exists()), environment.get('PYTHONPATH', '')])
    # Test execution must not inherit the running owner's authentication settings.
    for key in ['DEVFLOW_OWNER_MODE', 'DEVFLOW_PUBLIC_OWNER_MODE', 'DEVFLOW_TUNNEL_HOST', 'DEVFLOW_PUBLIC_ORIGIN', 'DEVFLOW_API_TOKEN', 'DEVFLOW_DB', 'DEVFLOW_ENTERPRISE_MODE', 'DEVFLOW_ENTERPRISE_CONFIG']:
        environment.pop(key, None)
    for key in ['OPENAI_API_KEY', 'OPENAI_API_KEY_FILE', 'OPENAI_MODEL', 'DEVFLOW_OPENAI_ENABLED', 'DEVFLOW_OPENAI_TENANTS', 'DEVFLOW_OPENAI_DAILY_LIMIT']:
        environment.pop(key, None)
    environment['COVERAGE_FILE'] = str(output / '.coverage')
    environment['DEVFLOW_QUALITY_TEST_REPORT'] = str(output / 'tests.json')
    initial_digest = source_digest()
    checks = []
    for name in ['tests.json', 'coverage.json']:
        artifact = output / name
        if artifact.is_file():
            artifact.unlink()
    if importlib.util.find_spec('coverage') is None or importlib.util.find_spec('ruff') is None:
        raise SystemExit('Install requirements-quality.txt before running the gate.')
    code, logs = run([sys.executable, '-m', 'coverage', 'run', '--branch', '--source=app,analyze_repo,pqc_cli,public_owner,backup,ops_cli,ops_job', '-m', 'pytest',
                      '-p', 'quality_plugin', '-q', '--basetemp=.test-quality-gate', '--junitxml=' + str(output / 'junit.xml')], environment)
    (output / 'tests.log').write_text(logs, encoding='utf-8')
    checks.append({'name': 'Unit, integration and security tests', 'status': 'passed' if code == 0 else 'failed'})
    coverage_path = output / 'coverage.json'
    export_code, _ = run([sys.executable, '-m', 'coverage', 'json', '-o', str(coverage_path)], environment)
    coverage = json.loads(coverage_path.read_text()) if export_code == 0 else {'totals': {}, 'files': {}}
    segments = []
    for filename, data in sorted(coverage['files'].items()):
        path = Path(filename)
        if not path.is_absolute():
            path = ROOT / path
        if not path.is_relative_to(ROOT / 'app') and path.name not in {'analyze_repo.py', 'pqc_cli.py', 'public_owner.py', 'backup.py', 'ops_cli.py', 'ops_job.py'}:
            continue
        summary = data['summary']
        segments.append({'path': path.relative_to(ROOT).as_posix(), 'summary': summary, 'functions': inventory(path, data)})
    totals = coverage['totals']
    line_percent = 100 * totals.get('covered_lines', 0) / max(1, totals.get('num_statements', 0))
    branch_percent = 100 * totals.get('covered_branches', 0) / max(1, totals.get('num_branches', 0))
    checks.append({'name': 'Coverage thresholds', 'status': 'passed' if export_code == 0 and line_percent >= 90 and branch_percent >= 80 else 'failed',
                   'statement_percent': round(line_percent, 2), 'branch_percent': round(branch_percent, 2),
                   'required_statement_percent': 90, 'required_branch_percent': 80})
    missing_functions = [segment['path'] + ':' + function['name'] for segment in segments for function in segment['functions'] if function['status'] == 'not_exercised']
    checks.append({'name': 'Function body exercise', 'status': 'passed' if segments and not missing_functions else 'failed',
                   'total': sum(len(segment['functions']) for segment in segments), 'missing': missing_functions})
    lint_code, lint_output = run([sys.executable, '-m', 'ruff', 'check', 'app', 'quality_gate.py', 'quality_plugin.py',
                                 '--select', 'E9,F821,F822,F823', '--output-format', 'json'], environment)
    try:
        findings = json.loads(lint_output)
    except ValueError:
        findings = []
    checks.append({'name': 'Static correctness checks', 'status': 'passed' if lint_code == 0 else 'failed', 'finding_count': len(findings)})
    node = shutil.which('node')
    js_checks = []
    for path in sorted((ROOT / 'static').glob('*')):
        scripts = []
        if path.suffix == '.js':
            scripts.append(path.read_text(encoding='utf-8'))
        elif path.suffix == '.html':
            from html.parser import HTMLParser
            class Scripts(HTMLParser):
                def __init__(self):
                    super().__init__(); self.capture = False; self.chunks = []
                def handle_starttag(self, tag, attrs):
                    self.capture = tag == 'script' and not dict(attrs).get('src') if tag == 'script' else self.capture
                def handle_endtag(self, tag):
                    if tag == 'script': self.capture = False; self.chunks.append('\n')
                def handle_data(self, text):
                    if self.capture: self.chunks.append(text)
            parser = Scripts(); parser.feed(path.read_text(encoding='utf-8')); scripts.append(''.join(parser.chunks))
        for script in scripts:
            scratch = output / 'syntax-check.js'
            scratch.write_text(script, encoding='utf-8')
            result, _ = run([node, '--check', str(scratch)], environment) if node else (1, 'Node unavailable')
            js_checks.append({'path': path.relative_to(ROOT).as_posix(), 'status': 'passed' if result == 0 else 'failed'})
    checks.append({'name': 'Browser JavaScript syntax', 'status': 'passed' if node and all(item['status'] == 'passed' for item in js_checks) else 'failed', 'files': js_checks})
    test_report = json.loads((output / 'tests.json').read_text()) if (output / 'tests.json').is_file() else {'outcomes': [], 'routes': []}
    unexercised_routes = [route['route'] for route in test_report['routes'] if not route['successful_response_exercised']]
    checks.append({'name': 'Endpoint response coverage', 'status': 'passed' if test_report['routes'] and not unexercised_routes else 'failed',
                   'total': len(test_report['routes']), 'missing': unexercised_routes})
    pqc = importlib.util.find_spec('pqcrypto') is not None
    skips = [row['test'] for row in test_report['outcomes'] if row['outcome'] == 'skipped']
    checks.append({'name': 'Optional cryptography exercised', 'status': 'passed' if pqc and not any('pqc' in item for item in skips) else 'failed'})
    checks.append({'name': 'Source stable during verification', 'status': 'passed' if initial_digest == source_digest() else 'failed'})
    versions = {}
    for name in ['fastapi', 'starlette', 'pytest', 'httpx', 'coverage', 'ruff', 'pqcrypto', 'cryptography', 'anyio']:
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = 'unavailable'
    report = {'schema_version': 1, 'created_at': datetime.now(timezone.utc).isoformat(), 'source_sha256': initial_digest,
              'environment': {'python': sys.version.split()[0], 'platform': sys.platform, 'packages': versions},
              'status': 'passed' if all(check['status'] == 'passed' for check in checks) else 'needs_attention',
              'checks': checks, 'segments': segments, 'routes': test_report['routes'],
              'tests': {outcome: sum(row['outcome'] == outcome for row in test_report['outcomes']) for outcome in ['passed', 'failed', 'skipped']},
              'limits': ['Execution coverage is not proof of correctness.', 'Only this trusted checkout is executed; uploaded customer code is never run.',
                         'Browser behavior requires a separate UI audit; JavaScript syntax is checked here.',
                         'Local report is not signed or independently authenticated.']}
    scratch = output / 'latest.tmp'
    scratch.write_text(json.dumps(report, indent=2), encoding='utf-8')
    scratch.replace(output / 'latest.json')
    print(json.dumps({'status': report['status'], 'tests': report['tests'], 'checks': checks}, indent=2))
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
