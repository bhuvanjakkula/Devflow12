from urllib.parse import urlsplit
from fastapi.testclient import TestClient
from app.main import app
from app import owner_access as owner


def test_owner_link_one_use_session_and_logout(monkeypatch):
    monkeypatch.setenv('DEVFLOW_OWNER_MODE', '1')
    monkeypatch.setenv('DEVFLOW_API_TOKEN', 'not-needed-in-owner-mode')
    link = owner.issue_link()
    path = urlsplit(link).path + '?' + urlsplit(link).query
    with TestClient(app) as c:
        assert c.get('/api/projects').status_code == 401
        assert c.get('/engineering', follow_redirects=False).headers['location'] == '/owner/login'
        entered = c.get(path, follow_redirects=False)
        assert entered.status_code == 303 and entered.headers['location'] == '/engineering'
        cookie = entered.headers['set-cookie'].lower()
        assert 'httponly' in cookie and 'samesite=strict' in cookie
        assert c.get('/api/projects').status_code == 200
        status = c.get('/owner/status').json()
        assert status['owner_email'] == 'bhuvanjakkula@gmail.com' and status['role'] == 'owner'
        assert not status['email_verified']
        assert c.get(path, follow_redirects=False).status_code == 401
        assert c.post('/owner/logout').status_code == 200
        assert c.get('/api/projects').status_code == 401


def test_invalid_expired_links_and_session_expiry(monkeypatch):
    monkeypatch.setenv('DEVFLOW_OWNER_MODE', '1')
    owner.issue_link()
    with TestClient(app) as c:
        assert c.get('/owner/enter?token=incorrect').status_code == 401
        with owner._lock:
            owner._bootstrap = (owner._bootstrap[0], 0)
        assert c.get('/owner/enter?token=incorrect').status_code == 401
        link = owner.issue_link()
        c.get(urlsplit(link).path + '?' + urlsplit(link).query)
        assert c.get('/api/projects').status_code == 200
        with owner._lock:
            for key in owner._sessions:
                owner._sessions[key] = 0
        assert c.get('/api/projects').status_code == 401


def test_new_launcher_revokes_old_sessions_and_bad_host(monkeypatch):
    monkeypatch.setenv('DEVFLOW_OWNER_MODE', '1')
    link = owner.issue_link()
    path = urlsplit(link).path + '?' + urlsplit(link).query
    with TestClient(app) as c:
        assert c.get(path, headers={'Host': 'attacker.invalid'}, follow_redirects=False).status_code == 403
        c.get(path)
        assert c.get('/api/projects').status_code == 200
        owner.issue_link()
        assert c.get('/api/projects').status_code == 401


def test_owner_mode_cannot_be_bypassed_with_api_token(monkeypatch):
    monkeypatch.setenv('DEVFLOW_OWNER_MODE', '1')
    monkeypatch.setenv('DEVFLOW_API_TOKEN', 'x' * 40)
    with TestClient(app) as c:
        assert c.get('/api/projects', headers={'Authorization': 'Bearer ' + 'x' * 40}).status_code == 401
        assert c.get('/owner/login').status_code == 200


def test_confirmation_page_preserves_link_until_explicit_post(monkeypatch):
    from urllib.parse import parse_qs
    monkeypatch.setenv('DEVFLOW_OWNER_MODE', '1')
    link = owner.issue_link()
    token = parse_qs(urlsplit(link).query)['token'][0]
    with TestClient(app) as c:
        for _ in range(2):
            assert c.get('/owner/confirm', params={'token': token}).status_code == 200
        assert c.get('/api/projects').status_code == 401
        assert c.post('/owner/confirm', data={'token': token}, follow_redirects=False).status_code == 303
        assert c.get('/api/projects').status_code == 200
        assert c.post('/owner/confirm', data={'token': token}).status_code == 401
        assert c.post('/owner/confirm', content=b'invalid').status_code == 400


def test_opaque_browser_login_requires_valid_nonce_and_does_not_allow_api_writes(monkeypatch):
    from urllib.parse import parse_qs
    monkeypatch.setenv('DEVFLOW_OWNER_MODE', '1')
    token = parse_qs(urlsplit(owner.issue_link()).query)['token'][0]
    with TestClient(app) as c:
        assert c.post('/owner/confirm', data={'token': 'invalid'}, headers={'Origin': 'null'}).status_code == 403
        assert c.post('/owner/confirm', data={'token': token}, headers={'Origin': 'null'}, follow_redirects=False).status_code == 303
        assert c.get('/engineering').status_code == 200
        assert c.post('/api/projects', json={'name': 'Blocked origin'}, headers={'Origin': 'null'}).status_code == 403
