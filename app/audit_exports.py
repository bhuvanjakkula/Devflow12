"""Location-tolerant finding identifiers and redacted engineering exports."""
import ast
from collections import defaultdict
import hashlib
import json
from urllib.parse import quote


def add_finding_context(files, findings):
    scopes = {}
    for path, source in files.items():
        scopes[path] = []
        if not path.endswith('.py'):
            continue
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError, RecursionError):
            continue
        def visit(node, parents):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    name = '.'.join([*parents, child.name])
                    scopes[path].append((child.lineno, child.end_lineno, name))
                    visit(child, [*parents, child.name])
                else:
                    visit(child, parents)
        try:
            visit(tree, [])
        except RecursionError:
            scopes[path] = []
    occurrences = defaultdict(int)
    for finding in sorted(findings, key=lambda f: (f['path'], f['line'], f['rule'], f['title'])):
        containing = [scope for scope in scopes.get(finding['path'], []) if scope[0] <= finding['line'] <= scope[1]]
        scope = min(containing, key=lambda item: item[1] - item[0])[2] if containing else '<module>'
        group = (finding['path'], finding['rule'], finding['title'], scope)
        occurrences[group] += 1
        identity = ['devflow-issue-v1', *group, occurrences[group]]
        finding.update(scope=scope, issue_id=hashlib.sha256(json.dumps(identity, ensure_ascii=False).encode()).hexdigest(),
                       identity_method='path_scope_rule_occurrence_v1')
    return findings


def remediation_plan(report):
    items = [{'issue_id': finding['issue_id'], 'priority': {'high': 'P0', 'medium': 'P1', 'low': 'P2'}[finding['severity']],
              'path': finding['path'], 'line': finding['line'], 'title': finding['title'],
              'action': finding['remediation'], 'verification': 'Review the indicated code/configuration, run relevant regression/security tests, then rescan the same scope.',
              'owner': None, 'status': 'open'} for finding in report['findings']]
    items.extend({'issue_id': 'control:' + control['control'], 'priority': 'P1', 'title': 'Verify ' + control['control'].replace('_', ' '),
                  'action': 'Obtain independent evidence for this production control.', 'verification': 'Record and review a trusted configuration or runtime check.',
                  'owner': None, 'status': 'unassessed'} for control in report['controls'] if control['status'] != 'reported_enabled')
    return {'items': sorted(items, key=lambda item: (item['priority'], item['issue_id'])),
            'snapshot_sha256': report['snapshot_sha256'], 'notice': 'Suggested work only. No patch, test or configuration change is applied.'}


def to_sarif(report):
    rules = sorted({finding['rule'] for finding in report['findings']})
    results = []
    for finding in report['findings']:
        results.append({'ruleId': finding['rule'], 'ruleIndex': rules.index(finding['rule']),
                        'level': {'high': 'error', 'medium': 'warning', 'low': 'note'}[finding['severity']],
                        'message': {'text': finding['title'] + '. ' + finding['remediation']},
                        'locations': [{'physicalLocation': {'artifactLocation': {'uri': quote(finding['path'], safe='/')},
                                                           'region': {'startLine': finding['line']}}}],
                        'partialFingerprints': {'devflowIssueId/v1': finding['issue_id']},
                        'properties': {'confidence': finding['confidence'], 'scope': finding.get('scope')}})
    return {'version': '2.1.0', '$schema': 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json',
            'runs': [{'tool': {'driver': {'name': 'DevFlow Read-only Protection', 'version': '0.16.0',
                                         'rules': [{'id': rule} for rule in rules]}}, 'results': results,
                      'properties': {'snapshot_sha256': report['snapshot_sha256'], 'production_certified': False,
                                     'limitations': report['limitations'], 'project_modified': False}}]}
