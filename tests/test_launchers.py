import json
import sys

import pytest


def test_repository_cli_excludes_dependency_caches_and_writes_report(monkeypatch, tmp_path):
    import analyze_repo
    (tmp_path / 'service.py').write_text('def calculate(x):\n    return x + 1\n')
    for folder in ['.pqc-deps', '.auth-deps', '.quality-deps', '.bin', '.ruff_cache']:
        (tmp_path / folder).mkdir()
        (tmp_path / folder / 'large.py').write_text('x' * 60001)
    output = tmp_path / 'report.json'
    monkeypatch.setattr(sys, 'argv', ['analyze_repo.py', str(tmp_path), '--changed', 'service.py', '--output', str(output)])
    analyze_repo.main()
    report = json.loads(output.read_text())
    assert [file['path'] for file in report['files']] == ['service.py']


def test_public_launcher_missing_client_and_missing_protection(monkeypatch, tmp_path):
    import public_owner
    monkeypatch.setattr(public_owner, '__file__', str(tmp_path / 'public_owner.py'))
    with pytest.raises(SystemExit, match='Install the official'):
        public_owner.main()
    (tmp_path / '.bin').mkdir()
    (tmp_path / '.bin' / 'cloudflared.exe').write_text('test placeholder')
    monkeypatch.setattr(public_owner.subprocess, 'check_output', lambda *args, **kwargs: 'old client')
    with pytest.raises(SystemExit, match='does not support'):
        public_owner.main()


def test_public_launcher_protection_process_exit_and_cleanup(monkeypatch, tmp_path):
    import public_owner
    monkeypatch.setattr(public_owner, '__file__', str(tmp_path / 'public_owner.py'))
    (tmp_path / '.bin').mkdir()
    (tmp_path / '.bin' / 'cloudflared.exe').write_text('test placeholder')
    monkeypatch.setattr(public_owner.subprocess, 'check_output', lambda *args, **kwargs: '--allowed-mail')
    processes = []
    class Process:
        def __init__(self, args, **kwargs):
            self.args = args
            self.env = kwargs.get('env')
            self.stdout = iter(['https://protected-test.trycloudflare.com\n'])
            self.stopped = False
            processes.append(self)
        def poll(self):
            return 0 if self.stopped or self.env else None
        def terminate(self):
            self.stopped = True
        def wait(self, timeout=None):
            return 0
    monkeypatch.setattr(public_owner.subprocess, 'Popen', Process)
    with pytest.raises(SystemExit, match='tunnel or server exited'):
        public_owner.main()
    assert '--allowed-mail' in processes[0].args
    assert 'bhuvanjakkula@gmail.com' in processes[0].args
    assert '--no-proxy-headers' in processes[1].args
    assert processes[1].env['DEVFLOW_PUBLIC_OWNER_MODE'] == '1'
    assert len(processes[1].env['DEVFLOW_TUNNEL_HOST']) > 32
    assert processes[0].stopped
    assert not (tmp_path / 'data' / 'public-url.txt').exists()


def test_pqc_cli_keygen_seal_verify_open_and_overwrite_refusal(monkeypatch, tmp_path):
    pytest.importorskip('pqcrypto')
    import pqc_cli
    monkeypatch.setattr(pqc_cli.getpass, 'getpass', lambda *args: 'test-only-long-passphrase')
    keys = tmp_path / 'keys'
    def invoke(*args):
        monkeypatch.setattr(sys, 'argv', ['pqc_cli.py', *map(str, args)])
        pqc_cli.main()
    invoke('keygen', '--directory', keys)
    report = tmp_path / 'report.json'
    report.write_text(json.dumps({'project': 'CLI regression', 'result': 'reviewed'}))
    envelope = tmp_path / 'envelope.json'
    invoke('seal', '--report', report, '--private', keys / 'private.pqc.json', '--recipient', keys / 'public.pqc.json', '--output', envelope)
    invoke('verify', '--envelope', envelope, '--sender', keys / 'public.pqc.json')
    restored = tmp_path / 'restored.json'
    invoke('open', '--envelope', envelope, '--private', keys / 'private.pqc.json', '--sender', keys / 'public.pqc.json', '--output', restored)
    assert json.loads(restored.read_text()) == json.loads(report.read_text())
    with pytest.raises(FileExistsError):
        pqc_cli.write(restored, {'overwrite': 'must not happen'})
    assert json.loads(restored.read_text()) == json.loads(report.read_text())
