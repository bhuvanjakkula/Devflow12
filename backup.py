"""Local SQLite snapshot and verified recovery drill. Never overwrites a database."""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
from contextlib import closing


def checksum(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def validate(path):
    with closing(sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)) as conn:
        if conn.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
            raise ValueError('SQLite integrity check failed')
        if conn.execute('PRAGMA foreign_key_check').fetchone() is not None:
            raise ValueError('SQLite foreign key check failed')
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {'projects', 'acceptance_criteria', 'test_evidence'}.issubset(tables):
            raise ValueError('Not a DevFlow workflow database')
        queries = {'projects': 'SELECT COUNT(*) FROM projects',
                   'acceptance_criteria': 'SELECT COUNT(*) FROM acceptance_criteria',
                   'test_evidence': 'SELECT COUNT(*) FROM test_evidence'}
        return {table: conn.execute(query).fetchone()[0] for table, query in queries.items()}


def snapshot(source, destination, expected_sha256=None):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    if not source.is_file():
        raise ValueError('Source database does not exist')
    if expected_sha256 is not None and checksum(source) != expected_sha256:
        raise ValueError('Backup checksum mismatch')
    validate(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation refuses active databases, existing backups and symlink targets.
    with destination.open('xb'):
        pass
    try:
        with closing(sqlite3.connect(source.as_uri() + '?mode=ro', uri=True)) as original:
            with closing(sqlite3.connect(destination)) as target:
                original.backup(target)
        counts = validate(destination)
        digest = checksum(destination)
        return {'destination': str(destination), 'sha256': digest, 'row_counts': counts,
                'integrity': 'ok', 'foreign_keys': 'ok'}
    except Exception:
        destination.unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--expected-sha256', help='Verify a saved backup hash before restoring to a NEW file')
    args = parser.parse_args()
    print(json.dumps(snapshot(args.source, args.destination, args.expected_sha256), indent=2))


if __name__ == '__main__':
    main()
