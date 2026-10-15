"""Read-only GitHub Actions provenance checks against administrator-configured scope."""
from datetime import datetime, timezone
import os
import re

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

router = APIRouter(tags=['CI evidence verification'])


class CIRun(BaseModel):
    model_config = ConfigDict(extra='forbid')
    run_id: int = Field(gt=0, le=10**15, strict=True)
    expected_sha: str = Field(pattern=r'^[a-fA-F0-9]{40}$')


def configuration():
    repository = os.environ.get('DEVFLOW_CI_REPOSITORY', '')
    token = os.environ.get('DEVFLOW_CI_TOKEN', '')
    workflow = os.environ.get('DEVFLOW_CI_WORKFLOW', '.github/workflows/tests.yml')
    branch = os.environ.get('DEVFLOW_CI_BRANCH', 'main')
    configured = bool(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) and token and
                      re.fullmatch(r'\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml', workflow) and branch)
    return repository, token, workflow, branch, configured


@router.get('/api/ci-evidence/status')
def ci_status():
    repository, _, workflow, branch, configured = configuration()
    return {'configured': configured, 'repository': repository if configured else None,
            'workflow': workflow if configured else None, 'branch': branch if configured else None,
            'notice': 'Server configuration requires a fine-grained GitHub token with Actions read access. Do not enter tokens in the browser.'}


def fetch_run(repository, token, run_id):
    try:
        with httpx.Client(timeout=5, follow_redirects=False, trust_env=False) as client:
            response = client.get(f'https://api.github.com/repos/{repository}/actions/runs/{run_id}',
                                  headers={'Accept': 'application/vnd.github+json', 'Authorization': 'Bearer ' + token,
                                           'X-GitHub-Api-Version': '2026-03-10'})
            if response.status_code != 200:
                raise HTTPException(502, 'GitHub did not return the requested run; check repository access and run ID')
            if len(response.content) > 2000000:
                raise HTTPException(502, 'CI response exceeds supported size')
            result = response.json()
            if not isinstance(result, dict):
                raise ValueError('Expected run object')
            return result
    except (httpx.HTTPError, ValueError):
        raise HTTPException(502, 'CI provider request failed or returned invalid data')


def assess_run(run, payload, repository, workflow, branch):
    now = datetime.now(timezone.utc)
    try:
        updated = datetime.fromisoformat(run['updated_at'].replace('Z', '+00:00'))
        fresh = updated.utcoffset() is not None and 0 <= (now - updated).total_seconds() <= 7 * 86400
    except (KeyError, TypeError, ValueError, AttributeError):
        fresh = False
    checks = {'repository_matches': isinstance(run.get('repository'), dict) and run['repository'].get('full_name', '').lower() == repository.lower(),
              'run_matches': run.get('id') == payload.run_id,
              'commit_matches': str(run.get('head_sha', '')).lower() == payload.expected_sha.lower(),
              'workflow_matches': str(run.get('path', '')).split('@', 1)[0] == workflow,
              'branch_matches': run.get('head_branch') == branch,
              'trusted_event': run.get('event') in {'push', 'workflow_dispatch'},
              'completed_successfully': run.get('status') == 'completed' and run.get('conclusion') == 'success',
              'recent_within_seven_days': fresh}
    return {'status': 'verified_run_metadata' if all(checks.values()) else 'does_not_meet_policy',
            'checks': checks, 'run_id': payload.run_id, 'repository': repository,
            'head_sha': run.get('head_sha'), 'checked_at': now.isoformat(),
            'run_url': f'https://github.com/{repository}/actions/runs/{payload.run_id}',
            'deployment_authorized': False,
            'scope': 'GitHub API run metadata checked against configured repository, workflow, branch, commit and freshness. Artifact contents and test completeness are not verified.'}


@router.post('/api/ci-evidence/verify')
def verify_ci(payload: CIRun):
    repository, token, workflow, branch, configured = configuration()
    if not configured:
        raise HTTPException(503, 'CI verification is not configured; set server repository and read-only credentials first')
    return assess_run(fetch_run(repository, token, payload.run_id), payload, repository, workflow, branch)
