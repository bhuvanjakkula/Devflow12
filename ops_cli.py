"""Encrypted backups, restore drills and externally anchored audit verification."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import uuid
from contextlib import closing

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backup import snapshot, validate
from app.audit import verify_chain

MAGIC = b'DEVFLOW-BACKUP-1\x00'
MAX_BACKUP = 256 * 1024 * 1024


def encryption_key(path):
    key = Path(path).read_bytes()
    if len(key) != 32:
        raise ValueError('Backup key file must contain exactly 32 random bytes')
    return key


def encrypted_backup(source, directory, key_file):
    started = time.monotonic()
    key = encryption_key(key_file)
    source = Path(source).resolve()
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='devflow-backup-') as temporary:
        plain = Path(temporary) / 'snapshot.sqlite3'
        report = snapshot(source, plain)
        if plain.stat().st_size > MAX_BACKUP:
            raise ValueError('Snapshot exceeds the supported 256 MiB encrypted-backup limit')
        nonce = os.urandom(12)
        blob = MAGIC + nonce + AESGCM(key).encrypt(nonce, plain.read_bytes(), MAGIC)
        name = 'devflow-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex + '.dfbackup'
        destination = directory / name
        with destination.open('xb') as output:
            output.write(blob)
            output.flush()
            os.fsync(output.fileno())
    return {'path': str(destination), 'sha256': hashlib.sha256(blob).hexdigest(),
            'row_counts': report['row_counts'], 'duration_seconds': time.monotonic() - started,
            'created_at': datetime.now(timezone.utc).isoformat(), 'encryption': 'AES-256-GCM'}


def decrypt_snapshot(source, key_file, destination):
    source = Path(source)
    if source.stat().st_size > MAX_BACKUP + len(MAGIC) + 28:
        raise ValueError('Encrypted snapshot exceeds supported size')
    blob = source.read_bytes()
    if not blob.startswith(MAGIC):
        raise ValueError('Unsupported encrypted backup format')
    nonce = blob[len(MAGIC):len(MAGIC) + 12]
    content = AESGCM(encryption_key(key_file)).decrypt(nonce, blob[len(MAGIC) + 12:], MAGIC)
    with Path(destination).open('xb') as output:
        output.write(content)
    return validate(destination)


def recover(source, destination, key_file):
    started = time.monotonic()
    destination = Path(destination).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.recovery-', dir=destination.parent) as temporary:
        plain = Path(temporary) / 'snapshot.sqlite3'
        decrypt_snapshot(source, key_file, plain)
        report = snapshot(plain, destination)
    report['duration_seconds'] = time.monotonic() - started
    return report


def drill(source, key_file):
    with tempfile.TemporaryDirectory(prefix='devflow-drill-') as temporary:
        report = recover(source, Path(temporary) / 'restored.sqlite3', key_file)
        report.pop('destination')
    report['status'] = 'restore_verified'
    report['scope'] = 'Database integrity and row counts; not an application failover or measured production RTO'
    return report


def audit(database, key_file, expected_head=None):
    with closing(sqlite3.connect(Path(database).resolve().as_uri() + '?mode=ro', uri=True)) as conn:
        return verify_chain(conn, Path(key_file).read_bytes(), expected_head)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ['backup', 'restore', 'drill', 'audit']:
        child = commands.add_parser(command)
        child.add_argument('source', type=Path)
        child.add_argument('--key', type=Path, required=True)
        if command in {'backup', 'restore'}:
            child.add_argument('destination', type=Path)
        if command == 'audit':
            child.add_argument('--expected-head')
    args = parser.parse_args()
    if args.command == 'backup':
        result = encrypted_backup(args.source, args.destination, args.key)
    elif args.command == 'restore':
        result = recover(args.source, args.destination, args.key)
    elif args.command == 'drill':
        result = drill(args.source, args.key)
    else:
        result = audit(args.source, args.key, args.expected_head)
    print(json.dumps(result, indent=2))
    return 1 if result.get('status') in {'invalid', 'anchor_mismatch'} else 0


if __name__ == '__main__':
    raise SystemExit(main())
