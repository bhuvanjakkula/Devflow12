"""Analyze a trusted local repository without importing or executing its source."""
import argparse
import json
from pathlib import Path

from app.intelligence import repository_intelligence

IGNORED = {'.git', '.venv', 'venv', 'node_modules', '__pycache__', '.pytest_cache', 'data', '.pqc-deps', '.auth-deps', '.quality-deps', '.bin', '.ruff_cache'}


def read_snapshot(root):
    files = {}
    for path in sorted(root.rglob('*.py')):
        relative = path.relative_to(root)
        if any(part in IGNORED or part.startswith('.test') for part in relative.parts):
            continue
        if path.is_symlink() or any((root / parent).is_symlink() for parent in relative.parents if parent != Path('.')):
            continue
        if not path.resolve().is_relative_to(root):
            continue
        if path.stat().st_size > 60000:
            raise ValueError(f'File too large: {relative}')
        files[relative.as_posix()] = path.read_text(encoding='utf-8-sig')
        if len(files) > 100 or sum(len(s.encode()) for s in files.values()) > 500000:
            raise ValueError('Snapshot exceeds 100 files or 500 KB; select a smaller directory')
    if not files:
        raise ValueError('No Python files found')
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('repository', type=Path)
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--changed', action='append', default=[])
    parser.add_argument('--hours-per-point', type=float, default=2)
    parser.add_argument('--hourly-rate', type=float, default=50)
    parser.add_argument('--output', type=Path, default=Path('engineering-report.json'))
    args = parser.parse_args()
    from app.engineering import Snapshot
    payload = Snapshot(files=read_snapshot(args.repository.resolve()),
                       baseline=read_snapshot(args.baseline.resolve()) if args.baseline else None,
                       changed_files=args.changed, hours_per_point=args.hours_per_point, hourly_rate=args.hourly_rate)
    report = repository_intelligence(payload.files, payload.baseline, payload.changed_files,
                                     payload.hours_per_point, payload.hourly_rate)
    args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(f'Report saved: {args.output.resolve()}')
    print(f"Static findings: {len(report['findings'])}; impacted files: {len(report['impacted_files'])}")


if __name__ == '__main__':
    main()
