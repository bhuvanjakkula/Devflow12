from fastapi.testclient import TestClient
from app.main import app


def test_malformed_origin_is_rejected_without_crashing(monkeypatch):
    monkeypatch.delenv('DEVFLOW_API_TOKEN', raising=False)
    with TestClient(app) as client:
        response = client.post('/api/projects', json={'name': 'Invalid origin'}, headers={'Origin': 'http://['})
        assert response.status_code == 403


def test_malformed_hosts_fail_closed(monkeypatch):
    monkeypatch.setenv('DEVFLOW_OWNER_MODE', '1')
    with TestClient(app) as client:
        for host in ['[', 'localhost:invalid', 'localhost/evil', 'user@localhost']:
            assert client.get('/api/projects', headers={'Host': host}).status_code == 400


def test_token_protection_and_invalid_configuration(monkeypatch):
    with TestClient(app) as client:
        monkeypatch.setenv('DEVFLOW_API_TOKEN', 'x' * 40)
        assert client.get('/api/projects').status_code == 401
        assert client.get('/api/projects', headers={'Authorization': 'Bearer incorrect'}).status_code == 401
        r = client.get('/api/security/status', headers={'Authorization': 'Bearer ' + 'x' * 40})
        assert r.status_code == 200 and r.json()['api_token_configured']
        assert not r.json()['tls_pqc_enabled']
        monkeypatch.setenv('DEVFLOW_API_TOKEN', '')
        assert client.get('/api/projects').status_code == 503


def test_browser_origin_and_response_headers(monkeypatch):
    monkeypatch.delenv('DEVFLOW_API_TOKEN', raising=False)
    with TestClient(app) as client:
        assert client.post('/api/projects', json={'name': 'Blocked origin'}, headers={'Origin': 'https://attacker.invalid'}).status_code == 403
        response = client.post('/api/projects', json={'name': 'Same origin'}, headers={'Origin': 'http://testserver'})
        assert response.status_code == 201
        assert response.headers['Cache-Control'] == 'no-store'
        assert response.headers['X-Content-Type-Options'] == 'nosniff'
