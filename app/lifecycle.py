"""Join requirements, source reports and reviewed evidence into one lifecycle view."""
import json
from collections import defaultdict


GROUPS = {
    'Planning': ['Requirements', 'Estimation', 'Collaboration'],
    'Development': ['Debugging', 'AI Code Quality', 'Legacy Code'],
    'Quality': ['Testing', 'Security', 'Documentation'],
    'Operations': ['Integration', 'Deployment', 'Maintenance'],
}


def latest_repository(conn, project_id):
    row = conn.execute('SELECT * FROM engineering_reports WHERE project_id=? ORDER BY id DESC LIMIT 1', (project_id,)).fetchone()
    return {'id': row['id'], 'created_at': row['created_at'], 'result': json.loads(row['result_json'])} if row else None


def criterion_impact(conn, project_id, criterion):
    """Map explicit links through a static dependency graph; no inferred semantic links."""
    snapshot = latest_repository(conn, project_id)
    links = [dict(r) for r in conn.execute('SELECT * FROM code_links WHERE criterion_id=? ORDER BY id', (criterion['id'],))]
    graph = snapshot['result']['dependency_graph'] if snapshot else {}
    reverse = defaultdict(set)
    for importer, dependencies in graph.items():
        for dependency in dependencies:
            reverse[dependency].add(importer)
    known = set(graph) | {dep for deps in graph.values() for dep in deps}
    matched = {link['file_path'] for link in links if link['file_path'] in known}
    unresolved = [{'link_id': link['id'], 'file_path': link['file_path'],
                   'reason': 'No repository snapshot' if not snapshot else 'Path is empty or absent from the snapshot'}
                  for link in links if link['file_path'] not in known]
    impacted = set(matched)
    queue = list(matched)
    while queue:
        for importer in reverse[queue.pop()]:
            if importer not in impacted:
                impacted.add(importer)
                queue.append(importer)
    result = snapshot['result'] if snapshot else {}
    test_paths = {p for p in graph if p.rsplit('/', 1)[-1].startswith('test_') or p.endswith('_test.py')}
    stale_evidence = [r['id'] for r in conn.execute('SELECT id FROM test_evidence WHERE criterion_id=? AND criterion_revision<>?',
                                                  (criterion['id'], criterion['revision']))]
    scan_revision = result.get('criterion_revisions', {}).get(str(criterion['id']))
    return {'criterion_id': criterion['id'], 'revision': criterion['revision'],
            'repository_report_id': snapshot['id'] if snapshot else None,
            'linked_files': sorted(matched), 'impacted_files': sorted(impacted),
            'test_targets': sorted(impacted & test_paths), 'unmapped_links': unresolved,
            'unlinked': not links, 'stale_evidence_ids': stale_evidence,
            'documentation': {'source_snapshot': result.get('snapshot_sha256'),
                              'criterion_revision_at_scan': scan_revision,
                              'status': 'missing' if not snapshot else 'refresh_required' if scan_revision != criterion['revision'] else 'matches_requirement_revision'},
            'risk_findings': [f for f in result.get('findings', []) if f['path'] in impacted],
            'actions': ['Review linked implementation against the revised requirement.',
                        'Run affected tests and the full regression suite.',
                        'Refresh source documentation and repository analysis.',
                        'Reapprove changed criteria and submit current reviewed test evidence.'],
            'scope': 'Explicit code links and static Python imports; test targets are suggestions, not executed checks.'}


def lifecycle_report(conn, project_id):
    from app.workflow import _report
    traceability = _report(conn, project_id)
    snapshot = latest_repository(conn, project_id)
    criteria = [c for f in traceability['features'] for c in f['criteria']]
    impacts = [criterion_impact(conn, project_id, c) for c in criteria]
    blockers = []
    if not criteria:
        blockers.append({'kind': 'missing_requirements', 'message': 'Create and approve acceptance criteria.'})
    if not snapshot:
        blockers.append({'kind': 'missing_repository', 'message': 'Analyze a source snapshot.'})
    for criterion, impact in zip(criteria, impacts):
        if criterion['verification']['status'] != 'reviewed_pass':
            blockers.append({'kind': 'criterion_evidence', 'criterion_id': criterion['id'], 'status': criterion['verification']['status']})
        if impact['unlinked'] or impact['unmapped_links']:
            blockers.append({'kind': 'unmapped_implementation', 'criterion_id': criterion['id']})
        if impact['documentation']['status'] != 'matches_requirement_revision':
            blockers.append({'kind': 'documentation_refresh', 'criterion_id': criterion['id']})
    if snapshot:
        high = sum(f['severity'] == 'high' for f in snapshot['result']['findings'])
        if high:
            blockers.append({'kind': 'high_severity_findings', 'count': high})
        if snapshot['result'].get('security_flow', {}).get('status') == 'incomplete':
            blockers.append({'kind': 'incomplete_security_analysis'})
    computed = []
    current_criteria = {c['id']: c for c in criteria}
    current_hashes = {f['path']: f['sha256'] for f in snapshot['result']['files']} if snapshot else {}
    latest_by_criterion = {}
    for row in conn.execute("SELECT * FROM assurance_reports WHERE project_id=? AND kind='verification' ORDER BY id", (project_id,)):
        latest_by_criterion[row['criterion_id']] = row
    for cid, row in latest_by_criterion.items():
        result = json.loads(row['result_json'])
        revision_current = cid in current_criteria and row['criterion_revision'] == current_criteria[cid]['revision']
        hash_current = current_hashes.get(result['source_file']) == result['source_sha256']
        linked_paths = {link['file_path'] for link in current_criteria[cid]['code_links']} if cid in current_criteria else set()
        is_current = revision_current and hash_current and result['source_file'] in linked_paths
        computed.append({'report_id': row['id'], 'criterion_id': cid, 'status': result['status'],
                         'current_revision_and_linked_source': is_current,
                         'scope': result['scope']})
        if not is_current:
            blockers.append({'kind': 'stale_numeric_verification', 'criterion_id': cid})
        elif result['status'] != 'examples_passed':
            blockers.append({'kind': 'numeric_verification_issue', 'criterion_id': cid, 'status': result['status']})
    decisions = [dict(r) for r in conn.execute('SELECT id, details_json, created_at FROM engineering_decisions WHERE project_id=? ORDER BY id DESC LIMIT 20', (project_id,))]
    audit_by_criterion = {}
    for row in conn.execute("SELECT * FROM engineering_experiments WHERE project_id=? AND kind='mutation' ORDER BY id", (project_id,)):
        audit = json.loads(row['result_json'])
        if 'specification_report_id' in audit and audit.get('mode') != 'repair':
            audit_by_criterion[audit['criterion_id']] = (row['id'], audit)
    audits = []
    for cid, (report_id, audit) in audit_by_criterion.items():
        criterion = current_criteria.get(cid)
        current = bool(criterion and criterion['revision'] == audit['criterion_revision'] and
                       current_hashes.get(audit['source_file']) == audit['source_sha256'] and
                       audit['source_file'] in {link['file_path'] for link in criterion['code_links']})
        gaps = sum(bool(m['test_gap_witness']) for m in audit['mutants'])
        audits.append({'experiment_id': report_id, 'criterion_id': cid, 'specification_report_id': audit['specification_report_id'],
                       'current_revision_and_linked_source': current, 'status': audit['status'],
                       'summary': audit.get('summary'), 'suggested_test_gaps': gaps})
        if not current:
            blockers.append({'kind': 'stale_specification_audit', 'criterion_id': cid})
        elif audit['status'] != 'completed':
            blockers.append({'kind': 'specification_audit_incomplete', 'criterion_id': cid})
        elif gaps:
            blockers.append({'kind': 'suggested_mutation_test_gaps', 'criterion_id': cid, 'count': gaps})
    for decision in decisions:
        decision['details'] = json.loads(decision.pop('details_json'))
    return {'project': traceability['project'], 'groups': GROUPS, 'traceability_summary': traceability['summary'],
            'requirement_impacts': impacts, 'latest_repository': snapshot, 'decisions': decisions, 'computed_verification': computed, 'specification_audits': audits,
            'release_review': {'status': 'needs_attention' if blockers else 'ready_for_human_review', 'blockers': blockers,
                               'deployment_authorized': False,
                               'notice': 'Advisory gate only. Test results and identities are self-reported; no deployment or CI validation occurs.'}}
