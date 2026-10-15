from fastapi.testclient import TestClient
from app.main import app


def test_locked_oracle_lifecycle_and_revision_guard():
    with TestClient(app) as c:
        pid = c.post('/api/projects', json={'name': 'Locked oracle'}).json()['id']
        base = f'/api/projects/{pid}'
        cid = c.post(base + '/workflow/features', json={'customer_text': 'Users must clamp negative values to zero.'}).json()['criteria'][0]['id']
        spec = {'criterion_id': cid, 'actor': 'Customer', 'trigger': 'Submit amount', 'behavior': 'Clamp negative amounts to zero.', 'failure_behavior': 'Reject nonnumeric values.', 'function': 'clamp', 'examples': [{'inputs': {'x': 5}, 'expected': 5}]}
        sid = c.post(base + '/engineering/specifications', json=spec).json()['assurance_report_id']
        url = base + f'/engineering/specifications/{sid}/mutation-check'
        source = 'def clamp(x):\n    return x if x >= 0 else 0'
        payload = {'source': source, 'seed': 42}
        assert c.post(url, json=payload).status_code == 409
        c.post(base + f'/workflow/criteria/{cid}/approve', json={'reviewer': 'Owner'})
        assert c.post(url, json={**payload, 'examples': []}).status_code == 422
        r = c.post(url, json=payload)
        assert r.status_code == 200 and r.json()['specification_report_id'] == sid
        c.post(base + f'/workflow/criteria/{cid}/code-links', json={'reference': 'commit-1', 'file_path': 'app/rules.py'})
        c.post(base + '/engineering/repository', json={'files': {'app/rules.py': source}})
        report = c.get(base + '/engineering/lifecycle').json()
        assert report['specification_audits'][0]['current_revision_and_linked_source']
        other = c.post('/api/projects', json={'name': 'Other oracle'}).json()['id']
        assert c.post(f'/api/projects/{other}/engineering/specifications/{sid}/mutation-check', json=payload).status_code == 404
        c.patch(base + f'/workflow/criteria/{cid}', json={'statement': 'Negative values must instead produce validation errors.'})
        assert c.post(url, json=payload).status_code == 409
        assert not c.get(base + '/engineering/lifecycle').json()['specification_audits'][0]['current_revision_and_linked_source']
