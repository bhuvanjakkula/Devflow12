"""Read-only results of the trusted CLI quality gate. No web-triggered code execution."""
import hashlib
import json
from pathlib import Path

from fastapi import APIRouter
from app.storage import ROOT

router = APIRouter(tags=['Product quality'])


def source_digest(root=ROOT):
    paths = []
    for folder in ['app', 'static', 'tests', '.github', 'deploy']:
        paths.extend(path for path in (root / folder).rglob('*') if path.is_file() and '__pycache__' not in path.parts
                     and path.suffix in {'.py', '.js', '.html', '.yml', '.yaml', '.json', '.conf', '.service', '.timer'})
    paths.extend(path for path in root.glob('*') if path.is_file() and (path.suffix in {'.py', '.txt', '.toml', '.ps1', '.cmd', '.lock', '.yaml'} or path.name in {'Dockerfile', '.dockerignore', '.gitignore'}))
    digest = hashlib.sha256()
    for path in sorted(set(paths)):
        digest.update(path.relative_to(root).as_posix().encode() + b'\0')
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


@router.get('/api/quality')
def quality_status():
    target = ROOT / 'data' / 'quality' / 'latest.json'
    if not target.is_file():
        return {'status': 'not_run', 'report': None, 'notice': 'Run python quality_gate.py in your local terminal.'}
    try:
        if target.stat().st_size > 3000000:
            raise ValueError('Report too large')
        report = json.loads(target.read_text(encoding='utf-8'))
        if not isinstance(report, dict) or report.get('schema_version') != 1 or not isinstance(report.get('source_sha256'), str) or report.get('status') not in {'passed', 'needs_attention'}:
            raise ValueError('Unsupported report')
    except (OSError, ValueError):
        return {'status': 'invalid_report', 'report': None, 'notice': 'Run the local quality gate again.'}
    stale = report['source_sha256'] != source_digest()
    return {'status': 'stale' if stale else report['status'], 'source_stale': stale, 'report': report,
            'notice': 'Locally generated test evidence, not signed CI attestation or proof that every possible behavior is correct.'}
