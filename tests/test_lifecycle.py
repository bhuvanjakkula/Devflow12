from fastapi.testclient import TestClient
from app.main import app


def setup_feature(client):
    pid = client.post('/api/projects', json={'name': 'Lifecycle project'}).json()['id']
    base = f'/api/projects/{pid}'
    feature = client.post(base + '/workflow/features', json={'customer_text': 'Users must see the calculated order total.'}).json()
    cid = feature['criteria'][0]['id']
    client.post(base + f'/workflow/criteria/{cid}/approve', json={'reviewer': 'Owner'})
    link = client.post(base + f'/workflow/criteria/{cid}/code-links', json={'reference': 'commit-123', 'file_path': 'app/rules.py'}).json()
    return base, cid, link['id']


FILES = {'app/rules.py': 'def total(items):\n    """Calculate total."""\n    return sum(items)\n',
         'app/service.py': 'from app.rules import total\n',
         'tests/test_service.py': 'import app.service\n'}


def test_requirement_revision_propagates_through_modules():
    with TestClient(app) as client:
        base, cid, link = setup_feature(client)
        client.post(base + '/engineering/repository', json={'files': FILES})
        ev = client.post(base + f'/workflow/criteria/{cid}/evidence', json={'code_link_id': link, 'test_name': 'total regression', 'outcome': 'passed', 'reported_by': 'Tester'}).json()
        client.post(base + f"/workflow/evidence/{ev['id']}/review", json={'decision': 'accepted', 'reviewer': 'Reviewer'})
        before = client.get(base + '/engineering/lifecycle').json()
        assert before['release_review']['status'] == 'ready_for_human_review'
        assert not before['release_review']['deployment_authorized']
        assert len(before['groups']) == 4 and sum(map(len, before['groups'].values())) == 12
        assert '## Requirement snapshot' in before['latest_repository']['result']['documentation_markdown']
        client.patch(base + f'/workflow/criteria/{cid}', json={'statement': 'When an order contains no items, its total must be zero.'})
        impact = client.get(base + f'/workflow/criteria/{cid}/impact').json()
        assert impact['impacted_files'] == ['app/rules.py', 'app/service.py', 'tests/test_service.py']
        assert impact['test_targets'] == ['tests/test_service.py']
        assert impact['stale_evidence_ids'] == [ev['id']]
        assert impact['documentation']['status'] == 'refresh_required'
        events = client.get(base + '/workflow/events').json()['events']
        assert events[0]['action'] == 'impact_assessed' and events[0]['details']['revision'] == 2
        assert client.get(base + '/engineering/lifecycle').json()['release_review']['status'] == 'needs_attention'
        client.post(base + '/engineering/repository', json={'files': FILES})
        refreshed = client.get(base + f'/workflow/criteria/{cid}/impact').json()
        assert refreshed['documentation']['status'] == 'matches_requirement_revision'
        assert refreshed['stale_evidence_ids']  # rescanning never upgrades evidence


def test_missing_snapshot_and_cross_project_impact():
    with TestClient(app) as client:
        base, cid, _ = setup_feature(client)
        impact = client.get(base + f'/workflow/criteria/{cid}/impact').json()
        assert impact['documentation']['status'] == 'missing'
        assert impact['unmapped_links'] and not impact['impacted_files']
        pid = client.post('/api/projects', json={'name': 'Other lifecycle'}).json()['id']
        assert client.get(f'/api/projects/{pid}/workflow/criteria/{cid}/impact').status_code == 404
        empty = client.get(f'/api/projects/{pid}/engineering/lifecycle').json()
        assert {'missing_requirements', 'missing_repository'} <= {b['kind'] for b in empty['release_review']['blockers']}


def test_unmapped_links_and_high_findings_block_review():
    with TestClient(app) as client:
        base, cid, _ = setup_feature(client)
        client.post(base + '/engineering/repository', json={'files': {'other.py': 'eval(user_input)'}})
        report = client.get(base + '/engineering/lifecycle').json()
        assert {'unmapped_implementation', 'high_severity_findings'} <= {b['kind'] for b in report['release_review']['blockers']}
