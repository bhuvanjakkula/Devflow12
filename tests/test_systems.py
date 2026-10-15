from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient
import pytest
from pydantic import ValidationError

from app.main import app
from app import storage
from app.intelligence import repository_intelligence
from app.systems import Boundary, SLO, architecture, reliability


FILES = {'app/api.py': 'from app.storage import save\n',
         'app/storage.py': 'from app.api import checkout\n',
         'tests/test_api.py': 'from app.api import checkout\n'}
RULE = {'name': 'Storage must not import API', 'source_prefix': 'app/storage.py', 'forbidden_prefix': 'app/api.py'}


def slo(**updates):
    data = {'service': 'Checkout', 'target': .999, 'window_days': 30,
            'measured_at': datetime.now(timezone.utc).isoformat(),
            'full_window': {'total': 1000000, 'bad': 1200},
            'recent': {'5m': {'total': 1000, 'bad': 20}, '30m': {'total': 6000, 'bad': 120},
                       '1h': {'total': 12000, 'bad': 240}, '6h': {'total': 72000, 'bad': 600}}}
    data.update(updates)
    return data


def test_architecture_cycles_boundaries_and_impact():
    repo = repository_intelligence(FILES, None, ['app/storage.py'], 2, 50)
    result = architecture(repo, [Boundary(**RULE)])
    assert result['cycles'] == [['app/api.py', 'app/storage.py']]
    assert result['boundary_violations'] == [{'rule': RULE['name'], 'source': 'app/storage.py', 'dependency': 'app/api.py'}]
    assert result['hotspots'][0]['path'] == 'app/api.py'
    assert repo['regression_targets'] == ['tests/test_api.py']
    assert result['status'] == 'needs_attention'
    broken = repository_intelligence({'broken.py': 'def :'}, None, [], 2, 50)
    assert architecture(broken, [])['status'] == 'incomplete'
    assert architecture(broken, [])['syntax_error_files'] == ['broken.py']
    nonpython = repository_intelligence({'README.md': '# Docs'}, None, [], 2, 50)
    assert architecture(nonpython, [])['status'] == 'incomplete'


def test_error_budget_and_multiwindow_alerts():
    result = reliability(SLO(**slo()))
    assert result['allowed_bad_events'] == 1000
    assert result['budget_used_percent'] == 120
    assert result['budget_remaining_percent'] == 0
    assert result['burn_rates']['5m'] == 20
    assert [alert['state'] for alert in result['alerts']] == ['firing', 'firing']
    assert result['release_policy'] == 'focus_on_reliability'
    # Long-window spikes require a confirming short window.
    quiet = slo(full_window={'total': 1000000, 'bad': 500})
    quiet['recent']['5m']['bad'] = 0
    quiet['recent']['30m']['bad'] = 0
    quiet['recent']['6h']['bad'] = 400
    result = reliability(SLO(**quiet))
    assert result['budget_remaining_percent'] == 50
    assert all(alert['state'] == 'quiet' for alert in result['alerts'])
    assert result['release_policy'] == 'continue_subject_to_other_gates'


def test_no_data_and_stale_data_never_signal_readiness():
    empty = reliability(SLO(**slo(full_window={'total': 0, 'bad': 0}, recent={})))
    assert empty['status'] == 'no_traffic' and empty['budget_remaining_percent'] is None
    assert empty['release_policy'] == 'needs_measurement'
    old = datetime.now(timezone.utc) - timedelta(days=2)
    result = reliability(SLO(**slo(measured_at=old.isoformat())))
    assert result['status'] == 'stale_measurement'
    assert result['release_policy'] == 'needs_measurement'
    assert all(a['state'] == 'unassessed' for a in result['alerts'])
    assert reliability(None)['status'] == 'unmeasured'
    short = reliability(SLO(**slo(window_days=7)))
    assert short['alerts'][0]['threshold'] == pytest.approx(14.4 * 7 / 30)


@pytest.mark.parametrize('updates', [
    {'target': 1}, {'target': float('nan')},
    {'full_window': {'total': 5, 'bad': 6}, 'recent': {}},
    {'full_window': {'total': True, 'bad': 0}, 'recent': {}},
    {'measured_at': '2026-01-01T00:00:00'},
    {'measured_at': (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()},
    {'recent': {'5m': {'total': 10, 'bad': 2}, '1h': {'total': 5, 'bad': 3}}},
    {'recent': {'5m': {'total': 10, 'bad': 2}, '1h': {'total': 11, 'bad': 8}}},
])
def test_invalid_telemetry_is_rejected(updates):
    with pytest.raises(ValidationError):
        SLO(**slo(**updates))


def test_saved_report_current_gaps_and_source_staleness(monkeypatch, tmp_path):
    monkeypatch.setattr(storage, 'DB_PATH', tmp_path / 'systems.db')
    with TestClient(app) as client:
        pid = client.post('/api/projects', json={'name': 'Systems project'}).json()['id']
        endpoint = f'/api/projects/{pid}/engineering/systems'
        assert client.get(endpoint).json()['report'] is None
        response = client.post(endpoint, json={'files': FILES, 'changed_files': ['app/storage.py'],
                                                'boundaries': [RULE], 'slo': slo()})
        assert response.status_code == 200
        report = response.json()
        assert not report['source_stale']
        assert any(a['priority'] == 'P0' and a['area'] == 'Reliability' for a in report['readiness']['actions'])
        assert not report['readiness']['deployment_authorized']
        saved = client.get(endpoint).json()
        assert saved['report']['id'] == report['report']['id']
        assert saved['readiness']['actions'] == report['readiness']['actions']
        assert client.get('/api/projects/99999/engineering/systems').status_code == 404
        client.post(f'/api/projects/{pid}/engineering/repository', json={'files': {'app/api.py': 'def checkout():\n    return 0\n'}})
        fresh = client.get(endpoint).json()
        assert fresh['source_stale']
        assert any('latest source snapshot' in a['title'] for a in fresh['readiness']['actions'])
        assert client.post(endpoint, json={'files': {'../escape.py': 'pass'}}).status_code == 422
        assert client.post(endpoint, json={'files': FILES, 'boundaries': [{**RULE, 'source_prefix': '../'}]}).status_code == 422


def test_source_is_not_executed_or_persisted(monkeypatch, tmp_path):
    monkeypatch.setattr(storage, 'DB_PATH', tmp_path / 'safe.db')
    marker = tmp_path / 'must-not-exist'
    source = f'import pathlib\npathlib.Path({str(marker)!r}).write_text("EXECUTION_MARKER")\n'
    with TestClient(app) as client:
        pid = client.post('/api/projects', json={'name': 'Safe source'}).json()['id']
        response = client.post(f'/api/projects/{pid}/engineering/systems', json={'files': {'service.py': source}})
        assert response.status_code == 200
        assert not marker.exists()
        with storage.db() as conn:
            record = conn.execute('SELECT result_json FROM systems_reports').fetchone()[0]
            assert 'EXECUTION_MARKER' not in record


def test_freshness_recomputed_after_report_is_saved(monkeypatch, tmp_path):
    monkeypatch.setattr(storage, 'DB_PATH', tmp_path / 'stale.db')
    with TestClient(app) as client:
        pid = client.post('/api/projects', json={'name': 'Fresh telemetry'}).json()['id']
        endpoint = f'/api/projects/{pid}/engineering/systems'
        client.post(endpoint, json={'files': FILES, 'slo': slo()})
        with storage.db() as conn:
            import json
            row = conn.execute('SELECT id,result_json FROM systems_reports').fetchone()
            report = json.loads(row['result_json'])
            report['slo_input']['measured_at'] = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
            conn.execute('UPDATE systems_reports SET result_json=? WHERE id=?', (json.dumps(report), row['id']))
        assert client.get(endpoint).json()['report']['reliability']['status'] == 'stale_measurement'
