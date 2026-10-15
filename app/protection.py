"""Read-only, offline source/configuration audit. Never executes or alters input."""
import hashlib
import json
import re

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator
from typing import Literal

from app.engineering import Snapshot
from app.intelligence import repository_intelligence
from app.audit_exports import add_finding_context, remediation_plan, to_sarif

router = APIRouter(tags=['Read-only security audit'])
CONTROLS = ['authentication', 'authorization', 'tls', 'secret_management', 'audit_logging',
            'backup_restore_tested', 'rate_limiting', 'dependency_vulnerability_scan', 'independent_security_review']


class ProtectionInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    files: dict[str, str] = Field(min_length=1, max_length=100)
    controls: dict[str, StrictBool | None] = Field(default_factory=dict, max_length=9)

    @model_validator(mode='after')
    def bounded(self):
        Snapshot(files=self.files)
        if set(self.controls) - set(CONTROLS):
            raise ValueError('Unknown production control')
        return self


def audit(payload):
    findings, diagnostics, dependencies = [], [], []
    def finding(path, line, rule, severity, title, remedy):
        findings.append({'path': path, 'line': line, 'rule': rule, 'severity': severity,
                         'title': title, 'remediation': remedy, 'confidence': 'potential issue; human verification required'})
    try:
        source = repository_intelligence(payload.files, None, [], 2, 0)
    except (RecursionError, MemoryError, ValueError):
        raise HTTPException(422, 'Input exceeds the supported analysis structure')
    for item in source['findings']:
        finding(item['path'], item['line'], item.get('rule', 'PYTHON_STATIC'), item['severity'],
                item['title'], item.get('recommendation', 'Inspect the indicated operation in your trusted editor.'))
    diagnostics.extend(source['security_flow']['diagnostics'])
    for path, text in sorted(payload.files.items()):
        if path.endswith(('.js', '.ts', '.tsx', '.java', '.go', '.rs')):
            diagnostics.append({'path': path, 'reason': 'Language semantics are not analyzed; only selected text/secret patterns are checked'})
        for number, line in enumerate(text.splitlines(), 1):
            if re.search(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bAKIA[A-Z0-9]{16}\b|\bgh[pousr]_[A-Za-z0-9]{30,}\b', line):
                finding(path, number, 'EXPOSED_SECRET', 'high', 'Possible credential or private key material',
                        'Verify locally, revoke/rotate exposed credentials and remove them from source/history.')
            if path.rsplit('/', 1)[-1].startswith('requirements') and path.endswith('.txt'):
                entry = line.strip()
                if entry and not entry.startswith('#'):
                    if re.fullmatch(r'[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[A-Za-z0-9_.+!-]+', entry):
                        dependencies.append({'path': path, 'line': number, 'pin_status': 'exact_pin', 'vulnerability_status': 'not_checked'})
                    elif entry.startswith(('-r ', '--requirement ')):
                        diagnostics.append({'path': path, 'line': number, 'reason': 'Included requirements need separate submitted files and review'})
                    else:
                        finding(path, number, 'DEPENDENCY_REPRODUCIBILITY', 'medium', 'Dependency declaration requires reproducibility review',
                                'Use a reviewed lockfile with exact versions and integrity hashes; run an up-to-date advisory scanner.')
            if path.rsplit('/', 1)[-1].startswith('Dockerfile'):
                if re.match(r'\s*FROM\s+\S+:latest(?:\s|$)', line, re.I):
                    finding(path, number, 'MUTABLE_IMAGE', 'medium', 'Mutable latest container image tag', 'Pin a reviewed image digest and scan the image.')
                if re.match(r'\s*USER\s+(?:root|0)(?:\s|$)', line, re.I):
                    finding(path, number, 'ROOT_CONTAINER', 'medium', 'Container explicitly runs as root', 'Use a least-privilege non-root runtime user.')
            if path.startswith('.github/workflows/'):
                if re.search(r'permissions:\s*write-all', line):
                    finding(path, number, 'CI_PERMISSIONS', 'high', 'Broad workflow write permissions', 'Declare only required token permissions per job.')
                if re.search(r'pull_request_target', line):
                    finding(path, number, 'CI_TRUST_BOUNDARY', 'medium', 'Privileged pull-request workflow needs review', 'Verify that untrusted pull-request content cannot execute with privileged credentials.')
                if re.search(r'\buses:\s*[^\s]+@(?:main|master|latest)\b', line):
                    finding(path, number, 'MUTABLE_ACTION', 'medium', 'Action references a mutable branch', 'Pin a reviewed action commit and maintain its updates.')
        if path.endswith('package.json'):
            try:
                manifest = json.loads(text)
                if not isinstance(manifest, dict):
                    raise ValueError('Expected object')
                for section in ['dependencies', 'devDependencies']:
                    values = manifest.get(section, {})
                    if not isinstance(values, dict):
                        raise ValueError('Expected dependency object')
                    for version in values.values():
                        if not isinstance(version, str):
                            raise ValueError('Expected version string')
                        dependencies.append({'path': path, 'pin_status': 'exact_pin' if re.fullmatch(r'\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?', version) else 'range_or_source', 'vulnerability_status': 'not_checked'})
                if any(d['path'] == path and d['pin_status'] == 'range_or_source' for d in dependencies):
                    finding(path, 1, 'JS_DEPENDENCY_REPRODUCIBILITY', 'medium', 'JavaScript dependency ranges or sources need lockfile review', 'Review the lockfile integrity and run an up-to-date dependency audit.')
            except (ValueError, RecursionError):
                diagnostics.append({'path': path, 'reason': 'Package manifest could not be analyzed'})
    unique = {(f['path'], f['line'], f['rule'], f['title']): f for f in findings}
    findings = sorted(unique.values(), key=lambda f: ({'high': 0, 'medium': 1, 'low': 2}[f['severity']], f['path'], f['line'], f['rule']))
    add_finding_context(payload.files, findings)
    controls = [{'control': name, 'status': 'reported_enabled' if payload.controls.get(name) is True else
                 'reported_disabled' if payload.controls.get(name) is False else 'unassessed',
                 'provenance': 'Requester declaration; not independently tested'} for name in CONTROLS]
    digest = hashlib.sha256(json.dumps({p: hashlib.sha256(s.encode()).hexdigest() for p, s in sorted(payload.files.items())}, sort_keys=True).encode()).hexdigest()
    report = {'schema_version': 1, 'status': 'findings_require_action' if any(f['severity'] == 'high' for f in findings) else 'incomplete' if diagnostics else 'requires_security_review',
            'snapshot_sha256': digest, 'files_examined': len(payload.files), 'findings': findings, 'diagnostics': diagnostics,
            'files': [{'path': path, 'sha256': hashlib.sha256(text.encode()).hexdigest()} for path, text in sorted(payload.files.items())],
            'controls': controls, 'dependencies': dependencies,
            'segments': {'python_source': source['security_flow']['status'], 'secret_patterns': 'scanned_selected_patterns',
                         'dependency_declarations': 'offline_metadata_only', 'container_configuration': 'selected_text_rules',
                         'ci_configuration': 'selected_text_rules', 'production_controls': 'self_reported_only'},
            'protections': {'project_modified': False, 'source_executed': False, 'network_requests': False,
                            'source_persisted': False, 'secret_values_returned': False},
            'production_certified': False,
            'limitations': ['Static Python and selected text rules only; unsupported languages and runtime behavior require separate checks.',
                            'No live penetration tests, exploitation, network scanning, dependency advisory lookup or automatic repairs.',
                            'No findings does not mean secure or bug-free. Production controls require independently verified evidence.']}
    report['remediation_plan'] = remediation_plan(report)
    report['sarif'] = to_sarif(report)
    return report


@router.post('/api/security-audit')
def protection_audit(payload: ProtectionInput):
    return audit(payload)


class BaselineFinding(BaseModel):
    model_config = ConfigDict(extra='ignore')
    path: str = Field(min_length=1, max_length=250)
    line: int = Field(ge=1)
    rule: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=500)
    severity: Literal['high', 'medium', 'low']
    issue_id: str | None = Field(default=None, pattern=r'^[a-f0-9]{64}$')


class Baseline(BaseModel):
    model_config = ConfigDict(extra='ignore')
    schema_version: Literal[1]
    snapshot_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    findings: list[BaselineFinding] = Field(max_length=1000)


class ComparisonInput(ProtectionInput):
    baseline: Baseline


def compare_reports(current, baseline):
    def legacy_key(item):
        return (item['path'], item['line'], item['rule'], item['title'])
    prior_rows = [f.model_dump() for f in baseline.findings]
    legacy = {legacy_key(row) for row in prior_rows if not row.get('issue_id')}
    def key(item):
        fallback = legacy_key(item)
        return ('legacy', *fallback) if fallback in legacy or not item.get('issue_id') else ('issue', item['issue_id'])
    prior = {key(f): f for f in prior_rows}
    latest = {key(f): f for f in current['findings']}
    scope = {file['path'] for file in current['files']}
    changes = []
    for identity in sorted(prior.keys() | latest.keys()):
        old, new = prior.get(identity), latest.get(identity)
        state = 'new' if old is None else 'severity_changed' if new and old['severity'] != new['severity'] else 'location_changed' if new and old['line'] != new['line'] else 'unchanged' if new else 'not_seen_in_current' if old['path'] in scope else 'outside_current_scope'
        changes.append({'state': state, 'finding': new or old})
    return {'baseline_sha256': baseline.snapshot_sha256, 'current_sha256': current['snapshot_sha256'],
            'counts': {state: sum(c['state'] == state for c in changes) for state in
                       ['new', 'unchanged', 'location_changed', 'severity_changed', 'not_seen_in_current', 'outside_current_scope']},
            'changes': changes, 'provenance': 'User-supplied baseline metadata; authenticity is not verified',
            'notice': 'New reports match path, scope, rule and occurrence; line-only moves are tracked. Legacy reports use exact locations. Renames/reordered duplicate findings may need manual review. Not seen does not prove remediation.'}


@router.post('/api/security-audit/compare')
def protection_compare(payload: ComparisonInput):
    current = audit(ProtectionInput(files=payload.files, controls=payload.controls))
    return {'report': current, 'comparison': compare_reports(current, payload.baseline)}
