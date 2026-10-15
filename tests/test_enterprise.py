import asyncio
import json
from pathlib import Path
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
import os

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient

from app.main import app
from app.enterprise import Configuration, Identity, principal
from app.audit import verify_chain
from app import storage


@pytest.fixture
def enterprise(monkeypatch, tmp_path):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = tmp_path / 'public.pem'
    public.write_bytes(private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    key = tmp_path / 'audit.key'
    key.write_bytes(b'a' * 32)
    data = {'issuer': 'https://identity.example', 'audience': 'devflow-api', 'origin': 'https://enterprise.example',
            'public_key': str(public), 'audit_key': str(key), 'data_root': str(tmp_path / 'tenants'),
            'tenants': ['alpha', 'beta'],
            'identities': [{'subject': subject, 'tenant': tenant, 'role': role} for subject, tenant, role in [
                ('alice', 'alpha', 'editor'), ('bob', 'beta', 'editor'), ('reader', 'alpha', 'viewer'),
                ('reviewer', 'alpha', 'reviewer'), ('admin', 'alpha', 'admin')]]}
    filename = tmp_path / 'enterprise.json'
    filename.write_text(json.dumps(data))
    monkeypatch.setenv('DEVFLOW_ENTERPRISE_MODE', '1')
    monkeypatch.setenv('DEVFLOW_ENTERPRISE_CONFIG', str(filename))
    for name in ['DEVFLOW_OWNER_MODE', 'DEVFLOW_PUBLIC_OWNER_MODE', 'DEVFLOW_API_TOKEN']:
        monkeypatch.delenv(name, raising=False)

    def token(subject='alice', **claims):
        now = int(time.time())
        values = {'sub': subject, 'iss': data['issuer'], 'aud': data['audience'], 'iat': now, 'nbf': now, 'exp': now + 300}
        values.update(claims)
        return {'Authorization': 'Bearer ' + jwt.encode(values, private, algorithm='RS256', headers={'typ': 'at+jwt'})}

    return data, filename, private, token


def test_enterprise_identity_and_tenant_isolation(enterprise):
    data, _, _, token = enterprise
    with TestClient(app, base_url=data['origin']) as client:
        assert client.get('/health/live').json() == {'status': 'alive'}
        assert client.get('/api/projects').status_code == 401
        assert client.get('/owner/status').status_code == 404
        assert client.get('/api/projects', headers={'Host': 'evil.example'}).status_code == 400
        assert client.get('/api/projects', headers={'X-Forwarded-User': 'admin', 'X-Tenant': 'alpha'}).status_code == 401
        identity = client.get('/api/identity', headers=token()).json()
        assert identity['tenant'] == 'alpha' and identity['role'] == 'editor'
        alpha = client.post('/api/projects', headers=token(), json={'name': 'Alpha secret'}).json()
        beta = client.post('/api/projects', headers={**token('bob'), 'X-Tenant': 'alpha'}, json={'name': 'Beta secret'}).json()
        assert alpha['id'] == beta['id'] == 1  # IDs collide safely in separate databases.
        assert client.get('/api/projects/1', headers=token('bob')).json()['project']['name'] == 'Beta secret'
        assert client.get('/api/projects', headers=token()).json()['projects'][0]['name'] == 'Alpha secret'
        assert client.post('/api/projects', headers=token('reader'), json={'name': 'Forbidden'}).status_code == 403
        assert client.post('/api/projects', headers={**token(), 'Origin': 'https://evil.example'}, json={'name': 'Forbidden'}).status_code == 403
        assert client.get('/api/ops/readiness', headers=token('reader')).status_code == 403
        assert client.get('/api/ops/readiness', headers=token('admin')).json()['schema_version'] == 2
        audit = client.get('/api/ops/audit', headers=token('admin')).json()
        assert audit['status'] == 'valid' and audit['events'] == 1
        assert client.get('/api/ops/metrics', headers=token('admin')).json()['requests'] > 0
        assert 'Pinned RS256' in client.get('/api/security/status', headers=token()).json()['identity_scope']
        assert client.get('/api/ci-evidence/status', headers=token()).status_code == 503
    assert principal.get() is None
    assert all((Path(data['data_root']) / (tenant + '.sqlite3')).exists() for tenant in data['tenants'])


def test_tokens_fail_closed(enterprise):
    data, _, private, token = enterprise
    with TestClient(app, base_url=data['origin']) as client:
        rogue_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        for bad in [token('unknown'), token(aud='wrong'), token(iss='https://evil.example'), token(exp=None), token(exp=float('inf')),
                    token(exp=int(time.time()) - 1), token(nbf=int(time.time()) + 100),
                    token(exp=int(time.time()) + 7200), token(iat=True),
                    {'Authorization': 'Bearer invalid'},
                    {'Authorization': 'Bearer ' + jwt.encode({'sub': 'admin'}, 'wrong' * 8, algorithm='HS256', headers={'typ': 'at+jwt'})},
                    {'Authorization': 'Bearer ' + jwt.encode({'sub': 'admin'}, rogue_key, algorithm='RS256', headers={'typ': 'at+jwt'})},
                    {'Authorization': 'Bearer ' + jwt.encode({'sub': 'admin'}, private, algorithm='RS256')}]:
            assert client.get('/api/projects', headers=bad).status_code == 401
        assert client.get('/api/projects', headers=token('alice', role='admin', tenant='beta')).status_code == 200
        assert client.post('/api/projects/1/workflow/criteria/1/approve', headers=token('alice', role='admin'), json={'reviewer': 'Spoof'}).status_code == 403
        assert client.get('http://enterprise.example/api/projects', headers=token()).status_code == 400
        assert client.get('/api/identity', headers=[('Authorization', 'Bearer a'), ('Authorization', 'Bearer b')]).status_code == 400


def test_verified_review_identity_and_self_review_prevention(enterprise):
    data, _, _, token = enterprise
    with TestClient(app, base_url=data['origin']) as client:
        pid = client.post('/api/projects', headers=token(), json={'name': 'Review project'}).json()['id']
        base = f'/api/projects/{pid}/workflow'
        feature = client.post(base + '/features', headers=token(), json={'customer_text': 'Users must see a correct invoice total after upload.'}).json()
        cid = feature['criteria'][0]['id']
        assert client.post(base + f'/criteria/{cid}/approve', headers=token('reviewer'), json={'reviewer': 'Impersonated'}).status_code == 200
        link = client.post(base + f'/criteria/{cid}/code-links', headers=token(), json={'reference': 'abcdef1'}).json()['id']
        evidence = client.post(base + f'/criteria/{cid}/evidence', headers=token('admin'), json={
            'code_link_id': link, 'test_name': 'Total test', 'outcome': 'passed', 'reported_by': 'Fake user'}).json()
        assert evidence['reported_by'].startswith('oidc:') and evidence['reported_by'] != 'Fake user'
        review = base + f"/evidence/{evidence['id']}/review"
        assert client.post(review, headers=token('admin'), json={'decision': 'accepted', 'reviewer': 'Different fake name'}).status_code == 403
        result = client.post(review, headers=token('reviewer'), json={'decision': 'accepted', 'reviewer': 'Fake reviewer'})
        assert result.status_code == 200 and result.json()['reviewer'].startswith('oidc:')
        assert result.json()['reviewer'] != evidence['reported_by']


def test_rate_and_concurrency_bounds(enterprise):
    data, _, _, token = enterprise
    with TestClient(app, base_url=data['origin']) as client:
        app.state.enterprise.requests_per_minute = 1
        assert client.get('/api/identity', headers=token()).status_code == 200
        assert client.get('/api/identity', headers=token()).status_code == 429
        # Other principals have independent rate buckets.
        assert client.get('/api/identity', headers=token('bob')).status_code == 200
        boundary = app.middleware_stack
        while boundary.__class__.__name__ != 'EnterpriseBoundary':
            boundary = boundary.app
        boundary.active = app.state.enterprise.max_concurrency
        assert client.get('/api/identity', headers=token('admin')).status_code == 503
        boundary.active = 0


def test_configuration_rejects_unsafe_bindings(enterprise):
    data, filename, _, _ = enterprise
    for update in [{'origin': 'http://enterprise.example'}, {'tenants': ['../escape']},
                   {'max_concurrency': 0}, {'identities': data['identities'] * 2},
                   {'identities': [{'subject': 'alice', 'tenant': 'unknown', 'role': 'admin'}]}]:
        filename.write_text(json.dumps({**data, **update}))
        with pytest.raises(ValueError):
            Configuration(filename)


def test_audit_tampering_and_schema_upgrade(monkeypatch, tmp_path):
    monkeypatch.setattr(storage, 'DB_PATH', tmp_path / 'database.sqlite3')
    storage.initialize()
    with sqlite3.connect(storage.DB_PATH) as conn:
        assert conn.execute('PRAGMA user_version').fetchone()[0] == 2
    identity = Identity('alice', 'alpha', 'admin', storage.DB_PATH, b'k' * 32)
    context = principal.set(identity)
    try:
        with storage.db() as conn:
            conn.execute("INSERT INTO projects(name, created_at) VALUES ('Audit test', 'today')")
        with storage.db() as conn:
            result = verify_chain(conn, identity.audit_key)
            assert result['status'] == 'valid' and result['events'] == 1
            assert verify_chain(conn, identity.audit_key, result['head'])['externally_anchored']
            assert verify_chain(conn, identity.audit_key, '0' * 64)['status'] == 'anchor_mismatch'
        with pytest.raises(RuntimeError):
            with storage.db() as conn:
                conn.execute("INSERT INTO projects(name, created_at) VALUES ('Rolled back', 'today')")
                raise RuntimeError('Abort')
        with storage.db() as conn:
            assert conn.execute('SELECT COUNT(*) FROM projects').fetchone()[0] == 1
        with sqlite3.connect(storage.DB_PATH) as conn:
            conn.execute("UPDATE security_audit SET payload='tampered' WHERE sequence=1")
            assert verify_chain(conn, identity.audit_key)['status'] == 'invalid'
    finally:
        principal.reset(context)
    storage.initialize()  # Idempotent upgrade of pre-existing schema.
    with sqlite3.connect(storage.DB_PATH) as conn:
        conn.execute('PRAGMA user_version = 99')
    with pytest.raises(RuntimeError, match='refusing downgrade'):
        storage.initialize()


def test_local_operations_routes():
    with TestClient(app) as client:
        assert client.get('/health/live').status_code == 200
        assert client.get('/api/identity').json()['mode'] == 'local'
        assert client.get('/api/ops/readiness').status_code == 200
        assert client.get('/api/ops/audit').json()['status'] == 'enterprise_mode_required'
        assert client.get('/api/ops/metrics').json()['status'] == 'enterprise_mode_required'


def test_concurrent_tenant_writes_and_audit(enterprise):
    data, _, _, token = enterprise
    credentials = {'alpha': token('alice'), 'beta': token('bob')}
    with TestClient(app, base_url=data['origin']) as client:
        def create(index):
            tenant = 'alpha' if index % 2 == 0 else 'beta'
            return client.post('/api/projects', headers=credentials[tenant], json={'name': tenant + ' project ' + str(index)})

        with ThreadPoolExecutor(max_workers=4) as workers:
            responses = list(workers.map(create, range(40)))
        assert all(response.status_code == 201 for response in responses)
        for tenant in ['alpha', 'beta']:
            rows = client.get('/api/projects', headers=credentials[tenant]).json()['projects']
            assert len(rows) == 20 and all(row['name'].startswith(tenant) for row in rows)
        result = client.get('/api/ops/audit', headers=token('admin')).json()
        assert result['status'] == 'valid' and result['events'] == 20


def test_scheduled_backup_job(enterprise, tmp_path, monkeypatch, capsys):
    from ops_job import main
    data, filename, _, token = enterprise
    with TestClient(app, base_url=data['origin']) as client:
        assert client.post('/api/projects', headers=token(), json={'name': 'Scheduled recovery'}).status_code == 201
    key = tmp_path / 'backup.key'
    key.write_bytes(os.urandom(32))
    monkeypatch.setattr('sys.argv', ['ops_job.py', 'backup', '--config', str(filename), '--backup-key', str(key), '--output-root', str(tmp_path / 'off-device')])
    assert main() == 0
    report = json.loads(capsys.readouterr().out)
    assert report['status'] == 'passed' and len(report['results']) == 2
    for result in report['results']:
        manifest = json.loads(Path(result['manifest']).read_text())
        assert manifest['payload']['audit']['status'] == 'valid'
        assert len(manifest['hmac_sha256']) == 64


def test_ai_tenant_allowlist_and_roles(enterprise, monkeypatch):
    from app import ai_assistant
    data, _, _, token = enterprise
    monkeypatch.setenv('DEVFLOW_OPENAI_ENABLED', '1')
    monkeypatch.setenv('OPENAI_API_KEY', 'test-only-not-real')
    monkeypatch.setenv('OPENAI_MODEL', 'test-model')
    monkeypatch.setenv('DEVFLOW_OPENAI_TENANTS', 'alpha')
    monkeypatch.delenv('OPENAI_API_KEY_FILE', raising=False)
    calls = []

    def suggestions(*args):
        calls.append(args)
        return {'summary': 'Test only'}

    monkeypatch.setattr(ai_assistant, 'request_suggestions', suggestions)
    with TestClient(app, base_url=data['origin']) as client:
        assert client.get('/api/ai/status', headers=token()).json()['available']
        assert not client.get('/api/ai/status', headers=token('bob')).json()['available']
        for user in ['alice', 'bob']:
            assert client.post('/api/projects', headers=token(user), json={'name': 'AI tenant project'}).status_code == 201
        payload = {'task': 'requirements', 'text': 'An invoice requirement', 'consent_to_send': True}
        endpoint = '/api/projects/1/ai/assist'
        assert client.post(endpoint, headers=token('reader'), json=payload).status_code == 403
        assert client.post(endpoint, headers=token('bob'), json=payload).status_code == 403
        assert client.post('/api/projects/99/ai/assist', headers=token(), json=payload).status_code == 404
        assert client.post(endpoint, headers=token(), json=payload).status_code == 200
        assert len(calls) == 1
