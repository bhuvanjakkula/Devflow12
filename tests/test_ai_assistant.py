import json

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app import storage
from app.ai_assistant import request_suggestions, AssistanceInput

RESULT = {'summary': 'Check empty inputs.', 'findings': ['An empty list can trigger division by zero.'],
          'suggested_actions': ['Define empty-input behavior.'], 'acceptance_criteria': ['Empty input returns the agreed result.'],
          'verification_steps': ['Test zero, one and several inputs.'], 'limitations': ['No code was executed.']}


def response_body(result=RESULT):
    return {'status': 'completed', 'output': [{'type': 'message', 'content': [{'type': 'output_text', 'text': json.dumps(result)}]}]}


@pytest.fixture
def configured(monkeypatch, tmp_path):
    monkeypatch.setattr(storage, 'DB_PATH', tmp_path / 'ai.sqlite3')
    monkeypatch.setenv('DEVFLOW_OPENAI_ENABLED', '1')
    monkeypatch.setenv('OPENAI_API_KEY', 'test-key-not-a-real-credential')
    monkeypatch.setenv('OPENAI_MODEL', 'test-model')
    monkeypatch.delenv('OPENAI_API_KEY_FILE', raising=False)
    monkeypatch.delenv('DEVFLOW_OPENAI_DAILY_LIMIT', raising=False)
    original = httpx.Client

    def provider(handler):
        monkeypatch.setattr('app.ai_assistant.httpx.Client', lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs))

    return provider


def test_all_tasks_and_no_automatic_changes(configured):
    requests = []

    def respond(request):
        payload = json.loads(request.content)
        assert request.url == 'https://api.openai.com/v1/responses'
        assert payload['store'] is False and payload['max_output_tokens'] == 2000
        assert payload['text']['format']['strict'] and 'tools' not in payload
        requests.append(payload)
        return httpx.Response(200, json=response_body())

    configured(respond)
    with TestClient(app) as client:
        assert client.get('/ai').status_code == 200
        assert client.get('/api/ai/status').json()['available']
        pid = client.post('/api/projects', json={'name': 'AI project'}).json()['id']
        for task in ['requirements', 'debug', 'explain']:
            response = client.post(f'/api/projects/{pid}/ai/assist', json={
                'task': task, 'text': 'Explain this private example', 'context': 'def total(xs): return sum(xs)/len(xs)', 'consent_to_send': True})
            assert response.status_code == 200, response.text
            assert response.json()['suggestions'] == RESULT and response.json()['verified'] is False
        assert len(requests) == 3
        assert client.get(f'/api/projects/{pid}/workflow/features').json()['features'] == []
    with storage.db() as conn:
        rows = [dict(row) for row in conn.execute('SELECT * FROM ai_requests')]
        assert len(rows) == 3 and all(row['outcome'] == 'completed' for row in rows)
        assert 'private example' not in json.dumps(rows) and 'empty-input behavior' not in json.dumps(rows)


def test_explicit_consent_configuration_and_quota(configured, monkeypatch):
    calls = []
    configured(lambda request: (calls.append(request), httpx.Response(200, json=response_body()))[1])
    with TestClient(app) as client:
        pid = client.post('/api/projects', json={'name': 'Consent project'}).json()['id']
        endpoint = f'/api/projects/{pid}/ai/assist'
        payload = {'task': 'debug', 'text': 'A division error', 'consent_to_send': True}
        assert client.post(endpoint, json={**payload, 'consent_to_send': False}).status_code == 422
        assert client.post(endpoint, json={**payload, 'consent_to_send': 1}).status_code == 422
        assert client.post(endpoint, json={'task': 'debug', 'text': 'A division error'}).status_code == 422
        monkeypatch.setenv('DEVFLOW_OPENAI_ENABLED', '0')
        assert not client.get('/api/ai/status').json()['available']
        assert client.post(endpoint, json=payload).status_code == 503
        monkeypatch.setenv('DEVFLOW_OPENAI_ENABLED', '1')
        monkeypatch.setenv('DEVFLOW_OPENAI_DAILY_LIMIT', '1')
        assert client.post(endpoint, json=payload).status_code == 200
        assert client.post(endpoint, json=payload).status_code == 429
        assert len(calls) == 1
        monkeypatch.setenv('DEVFLOW_OPENAI_DAILY_LIMIT', 'invalid')
        assert client.post(endpoint, json=payload).status_code == 503
        monkeypatch.setenv('OPENAI_API_KEY_FILE', '/nonexistent/private-key')
        assert not client.get('/api/ai/status').json()['configured']


@pytest.mark.parametrize('kind,status', [('quota', 503), ('denied', 502), ('incomplete', 502), ('refusal', 422),
                                         ('invalid', 502), ('oversize', 502), ('timeout', 504), ('network', 502)])
def test_provider_failures_are_safe_and_not_retried(configured, kind, status):
    calls = []

    def respond(request):
        calls.append(request)
        if kind == 'timeout':
            raise httpx.ReadTimeout('secret provider diagnostics')
        if kind == 'network':
            raise httpx.ConnectError('secret provider diagnostics')
        if kind == 'quota':
            return httpx.Response(429, text='secret provider diagnostics')
        if kind == 'denied':
            return httpx.Response(401, text='secret provider diagnostics')
        if kind == 'incomplete':
            return httpx.Response(200, json={'status': 'incomplete'})
        if kind == 'refusal':
            return httpx.Response(200, json={'status': 'completed', 'output': [{'type': 'message', 'content': [{'type': 'refusal'}]}]})
        if kind == 'oversize':
            return httpx.Response(200, content=b'x' * 262145)
        return httpx.Response(200, json=response_body({'unexpected': 'secret provider diagnostics'}))

    configured(respond)
    with TestClient(app) as client:
        pid = client.post('/api/projects', json={'name': 'Error project'}).json()['id']
        response = client.post(f'/api/projects/{pid}/ai/assist', json={'task': 'debug', 'text': 'Some error', 'consent_to_send': True})
        assert response.status_code == status and 'secret provider diagnostics' not in response.text
        assert len(calls) == 1
    with storage.db() as conn:
        assert conn.execute('SELECT outcome FROM ai_requests').fetchone()[0] == 'failed'
