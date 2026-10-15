from fastapi.testclient import TestClient
from app.main import app


def test_public_origin_requires_secret_and_loopback(monkeypatch):
    monkeypatch.setenv('DEVFLOW_PUBLIC_OWNER_MODE', '1')
    monkeypatch.setenv('DEVFLOW_TUNNEL_HOST', 'a' * 64 + '.localhost')
    monkeypatch.setenv('DEVFLOW_PUBLIC_ORIGIN', 'https://owner.trycloudflare.com')
    with TestClient(app) as client:
        assert client.get('/engineering').status_code == 401
        assert client.get('/owner/enter?token=anything').status_code == 401
        headers = {'Host': 'a' * 64 + '.localhost'}
        assert client.get('/engineering', headers=headers).status_code == 200
        assert client.get('/owner/status', headers=headers).json()['email_verified']
        assert client.post('/api/projects', headers={**headers, 'Origin': 'https://evil.trycloudflare.com'},
                           json={'name': 'Rejected'}).status_code == 403
        response = client.post('/api/projects', headers={**headers, 'Origin': 'https://owner.trycloudflare.com'},
                               json={'name': 'Owner project'})
        assert response.status_code in {200, 201}
    with TestClient(app, client=('203.0.113.1', 123)) as remote:
        assert remote.get('/api/projects', headers=headers).status_code == 401


def test_public_mode_fails_closed_without_secret(monkeypatch):
    monkeypatch.setenv('DEVFLOW_PUBLIC_OWNER_MODE', '1')
    monkeypatch.delenv('DEVFLOW_TUNNEL_HOST', raising=False)
    with TestClient(app) as client:
        assert client.get('/api/projects').status_code == 401
