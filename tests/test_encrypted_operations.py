import json
import os
from pathlib import Path
import sqlite3
import httpx

import pytest
from cryptography.exceptions import InvalidTag

from app import storage
from ops_cli import encrypted_backup, recover, drill, encryption_key, main


def test_encrypted_recovery_and_tamper_rejection(monkeypatch, tmp_path, capsys):
    source = tmp_path / 'source.sqlite3'
    monkeypatch.setattr(storage, 'DB_PATH', source)
    storage.initialize()
    with storage.db() as conn:
        conn.execute("INSERT INTO projects(name, created_at) VALUES ('Private customer information', 'today')")
    key = tmp_path / 'backup.key'
    key.write_bytes(os.urandom(32))
    result = encrypted_backup(source, tmp_path / 'off-device', key)
    encrypted = Path(result['path'])
    assert b'Private customer information' not in encrypted.read_bytes()
    assert result['row_counts']['projects'] == 1
    destination = tmp_path / 'new.sqlite3'
    restored = recover(encrypted, destination, key)
    assert restored['row_counts'] == result['row_counts']
    assert drill(encrypted, key)['status'] == 'restore_verified'
    with pytest.raises(FileExistsError):
        recover(encrypted, destination, key)
    wrong_key = tmp_path / 'wrong.key'
    wrong_key.write_bytes(os.urandom(32))
    with pytest.raises(InvalidTag):
        drill(encrypted, wrong_key)
    data = bytearray(encrypted.read_bytes())
    data[-1] ^= 1
    encrypted.write_bytes(data)
    with pytest.raises(InvalidTag):
        drill(encrypted, key)
    key.write_bytes(b'invalid')
    with pytest.raises(ValueError):
        encryption_key(key)


def test_operations_cli(monkeypatch, tmp_path, capsys):
    source = tmp_path / 'source.sqlite3'
    monkeypatch.setattr(storage, 'DB_PATH', source)
    storage.initialize()
    key = tmp_path / 'backup.key'
    key.write_bytes(os.urandom(32))
    for args in [['backup', str(source), str(tmp_path / 'backups'), '--key', str(key)],
                 ['audit', str(source), '--key', str(key)]]:
        monkeypatch.setattr('sys.argv', ['ops_cli.py', *args])
        assert main() == 0
        json.loads(capsys.readouterr().out)
    encrypted = next((tmp_path / 'backups').glob('*.dfbackup'))
    for args in [['drill', str(encrypted), '--key', str(key)],
                 ['restore', str(encrypted), str(tmp_path / 'restored.sqlite3'), '--key', str(key)]]:
        monkeypatch.setattr('sys.argv', ['ops_cli.py', *args])
        assert main() == 0
        json.loads(capsys.readouterr().out)
    from backup import main as plain_backup_main
    monkeypatch.setattr('sys.argv', ['backup.py', str(source), str(tmp_path / 'plain.sqlite3')])
    plain_backup_main()
    assert json.loads(capsys.readouterr().out)['integrity'] == 'ok'


def test_authenticated_health_probe(tmp_path):
    from ops_job import probe
    token_file = tmp_path / 'token'
    token_file.write_text('opaque-secret-token')

    def respond(request):
        assert request.headers['Authorization'] == 'Bearer opaque-secret-token'
        statuses = {'readiness': 'ready', 'audit': 'valid', 'metrics': 'measured_in_process'}
        return httpx.Response(200, json={'status': statuses[request.url.path.split('/')[-1]]})

    report = probe('https://enterprise.example', token_file, httpx.MockTransport(respond))
    assert report['status'] == 'passed' and 'opaque-secret-token' not in json.dumps(report)
    with pytest.raises(ValueError):
        probe('http://enterprise.example', token_file)
    with pytest.raises(ValueError, match='probe failed'):
        probe('https://enterprise.example', token_file, httpx.MockTransport(lambda request: httpx.Response(401)))
