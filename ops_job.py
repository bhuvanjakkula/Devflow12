"""One-shot scheduled recovery validation and authenticated health probes."""
import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import tempfile
from urllib.parse import urlsplit

import httpx

from app.enterprise import Configuration
from ops_cli import encrypted_backup, recover, audit


def backup_job(config_file, backup_key, output_root):
    config = Configuration(config_file)
    results = []
    for tenant, database in config.tenants.items():
        result = encrypted_backup(database, Path(output_root) / tenant, backup_key)
        with tempfile.TemporaryDirectory(prefix='devflow-job-') as temporary:
            restored = Path(temporary) / 'restored.sqlite3'
            recovery = recover(result['path'], restored, backup_key)
            integrity = audit(restored, json.loads(Path(config_file).read_text())['audit_key'])
            if integrity['status'] != 'valid':
                raise ValueError('Backup contains an invalid audit chain')
        payload = {'tenant': tenant, 'backup': result, 'restore_seconds': recovery['duration_seconds'],
                   'audit': integrity, 'created_at': datetime.now(timezone.utc).isoformat()}
        canonical = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        manifest = {'payload': payload, 'hmac_sha256': hmac.new(config.audit_key, canonical.encode(), hashlib.sha256).hexdigest()}
        target = Path(result['path']).with_suffix('.manifest.json')
        with target.open('x', encoding='utf-8') as output:
            json.dump(manifest, output, indent=2)
        results.append({'tenant': tenant, 'manifest': str(target), 'status': 'backup_and_restore_verified'})
    return {'status': 'passed', 'results': results}


def probe(origin, token_file, transport=None):
    parsed = urlsplit(origin)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.query or parsed.fragment or parsed.path:
        raise ValueError('Probe requires a bare HTTPS origin')
    token = Path(token_file).read_text(encoding='utf-8').strip()
    results = {}
    with httpx.Client(timeout=10, follow_redirects=False, trust_env=False, transport=transport) as client:
        for name in ['readiness', 'audit', 'metrics']:
            response = client.get(origin + '/api/ops/' + name, headers={'Authorization': 'Bearer ' + token})
            if response.status_code != 200:
                raise ValueError('Authenticated operations probe failed: ' + name)
            results[name] = response.json()
    passed = results['readiness'].get('status') == 'ready' and results['audit'].get('status') == 'valid'
    return {'status': 'passed' if passed else 'failed', 'observations': results,
            'scope': 'Authenticated readiness and audit health. Scrape metrics deltas externally for SLO alerting.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    backup = commands.add_parser('backup')
    backup.add_argument('--config', required=True)
    backup.add_argument('--backup-key', required=True)
    backup.add_argument('--output-root', required=True)
    health = commands.add_parser('probe')
    health.add_argument('--origin', required=True)
    health.add_argument('--token-file', required=True)
    args = parser.parse_args()
    result = backup_job(args.config, args.backup_key, args.output_root) if args.command == 'backup' else probe(args.origin, args.token_file)
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
