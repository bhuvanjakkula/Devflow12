import asyncio
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.request_limits import RequestSizeLimit
from backup import snapshot, validate


def test_large_body_is_rejected_before_project_creation():
    with TestClient(app) as client:
        response = client.post('/api/projects', content=b'x' * (8 * 1024 * 1024 + 1))
        assert response.status_code == 413
        assert client.get('/api/projects').status_code == 200


def test_stream_limit_and_malformed_lengths():
    async def run(headers, messages):
        sent = []
        called = []

        async def receive():
            return messages.pop(0)

        async def send(message):
            sent.append(message)

        async def downstream(scope, receive, send):
            called.append((await receive()).get('body'))

        await RequestSizeLimit(downstream, max_bytes=4)(
            {'type': 'http', 'headers': headers}, receive, send)
        return sent, called

    sent, called = asyncio.run(run([], [
        {'type': 'http.request', 'body': b'abc', 'more_body': True},
        {'type': 'http.request', 'body': b'de'}]))
    assert sent[0]['status'] == 413 and not called
    for lengths in [[(b'content-length', b'-1')], [(b'content-length', b'1')] * 2]:
        sent, called = asyncio.run(run(lengths, []))
        assert sent[0]['status'] == 400 and not called
    sent, called = asyncio.run(run([], [{'type': 'http.request', 'body': b'abcd'}]))
    assert not sent and called == [b'abcd']
    sent, called = asyncio.run(run([], [{'type': 'http.disconnect'}]))
    assert not sent and not called


def test_recovery_preserves_records_and_refuses_overwrite(tmp_path):
    source = tmp_path / 'source.sqlite3'
    with sqlite3.connect(source) as conn:
        conn.executescript('''
            CREATE TABLE projects(id INTEGER PRIMARY KEY, name TEXT);
            CREATE TABLE acceptance_criteria(id INTEGER PRIMARY KEY);
            CREATE TABLE test_evidence(id INTEGER PRIMARY KEY);
            INSERT INTO projects VALUES(1, 'Recovery example');
        ''')
    backup = tmp_path / 'backup.sqlite3'
    report = snapshot(source, backup)
    restored = tmp_path / 'restored.sqlite3'
    recovery = snapshot(backup, restored, report['sha256'])
    assert report['row_counts'] == recovery['row_counts'] == validate(source)
    with sqlite3.connect(restored) as conn:
        assert conn.execute('SELECT name FROM projects').fetchone()[0] == 'Recovery example'
    before = restored.read_bytes()
    with pytest.raises(FileExistsError):
        snapshot(backup, restored)
    assert restored.read_bytes() == before
    with pytest.raises(ValueError, match='checksum'):
        snapshot(backup, tmp_path / 'invalid.sqlite3', '0' * 64)
    assert not (tmp_path / 'invalid.sqlite3').exists()
    with pytest.raises(ValueError, match='does not exist'):
        snapshot(tmp_path / 'missing', restored)
    empty = tmp_path / 'empty.sqlite3'
    sqlite3.connect(empty).close()
    with pytest.raises(ValueError, match='Not a DevFlow'):
        snapshot(empty, tmp_path / 'empty-backup')
