"""Architecture fitness checks, SRE calculations and evidence-linked readiness."""
from collections import defaultdict
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.engineering import Snapshot, repository
from app.lifecycle import lifecycle_report, latest_repository
from app.storage import db, get_project, now_iso

router = APIRouter(prefix='/api/projects/{project_id}/engineering', tags=['Systems engineering'])


class Boundary(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str = Field(min_length=2, max_length=100)
    source_prefix: str = Field(min_length=1, max_length=200)
    forbidden_prefix: str = Field(min_length=1, max_length=200)

    @model_validator(mode='after')
    def safe_paths(self):
        for path in (self.source_prefix, self.forbidden_prefix):
            if path.startswith('/') or '\\' in path or ':' in path or any(p in {'.', '..', ''} for p in path.rstrip('/').split('/')):
                raise ValueError('Boundary prefixes must be relative forward-slash paths')
        return self


class Counts(BaseModel):
    model_config = ConfigDict(extra='forbid')
    total: int = Field(ge=0, le=10**15, strict=True)
    bad: int = Field(ge=0, le=10**15, strict=True)

    @model_validator(mode='after')
    def valid_counts(self):
        if self.bad > self.total:
            raise ValueError('Bad events cannot exceed total events')
        return self


class SLO(BaseModel):
    model_config = ConfigDict(extra='forbid')
    service: str = Field(min_length=2, max_length=100)
    target: float = Field(default=.999, gt=0, lt=1, allow_inf_nan=False)
    window_days: int = Field(default=30, ge=7, le=90)
    measured_at: datetime
    full_window: Counts
    recent: dict[Literal['5m', '30m', '1h', '6h'], Counts] = Field(default_factory=dict)

    @model_validator(mode='after')
    def valid_windows(self):
        if self.measured_at.utcoffset() is None:
            raise ValueError('Measurement time requires a timezone')
        if self.measured_at > datetime.now(timezone.utc):
            raise ValueError('Measurement time cannot be in the future')
        previous = Counts(total=0, bad=0)
        for key in ['5m', '30m', '1h', '6h', 'full']:
            counts = self.full_window if key == 'full' else self.recent.get(key)
            if counts is None:
                continue
            if counts.total < previous.total or counts.bad < previous.bad or counts.total - counts.bad < previous.total - previous.bad:
                raise ValueError('Aligned nested windows must contain the shorter windows')
            previous = counts
        return self


class SystemsRequest(Snapshot):
    boundaries: list[Boundary] = Field(default_factory=list, max_length=30)
    slo: SLO | None = None


def architecture(report, boundaries):
    graph = report['dependency_graph']
    # Tarjan's strongly connected components, bounded by Snapshot's 100 files.
    counter = 0
    indexes, low, stack, active, cycles = {}, {}, [], set(), []
    def visit(node):
        nonlocal counter
        indexes[node] = low[node] = counter
        counter += 1
        stack.append(node)
        active.add(node)
        for dependency in graph.get(node, []):
            if dependency not in indexes:
                visit(dependency)
                low[node] = min(low[node], low[dependency])
            elif dependency in active:
                low[node] = min(low[node], indexes[dependency])
        if low[node] == indexes[node]:
            component = []
            while True:
                item = stack.pop()
                active.remove(item)
                component.append(item)
                if item == node:
                    break
            if len(component) > 1:
                cycles.append(sorted(component))
    for node in sorted(graph):
        if node not in indexes:
            visit(node)
    violations = []
    fan_in = defaultdict(int)
    for source, dependencies in sorted(graph.items()):
        for dependency in dependencies:
            fan_in[dependency] += 1
            for rule in boundaries:
                if source.startswith(rule.source_prefix) and dependency.startswith(rule.forbidden_prefix):
                    violations.append({'rule': rule.name, 'source': source, 'dependency': dependency})
    syntax_errors = [f['path'] for f in report['files'] if any(item['title'] == 'Syntax error' for item in f['findings'])]
    return {'status': 'incomplete' if syntax_errors or not report['files'] else 'needs_attention' if cycles or violations else 'supported_checks_passed',
            'cycles': sorted(cycles), 'boundary_violations': violations, 'syntax_error_files': syntax_errors,
            'hotspots': sorted([{'path': path, 'dependents': fan_in[path], 'dependencies': len(deps)} for path, deps in graph.items()],
                               key=lambda x: (-x['dependents'], x['path']))[:10],
            'edges': [{'source': source, 'target': target} for source, deps in sorted(graph.items()) for target in deps],
            'rules_checked': len(boundaries), 'scope': 'Static Python imports in submitted files; dynamic dispatch and external dependencies are not resolved.'}


def reliability(slo, now=None):
    if slo is None:
        return {'status': 'unmeasured', 'alerts': [], 'release_policy': 'needs_measurement',
                'provenance': 'No service measurements supplied'}
    now = now or datetime.now(timezone.utc)
    fraction = Decimal('1') - Decimal(str(slo.target))
    allowed = Decimal(slo.full_window.total) * fraction
    bad = Decimal(slo.full_window.bad)
    stale = (now - slo.measured_at).total_seconds() > 86400
    no_traffic = slo.full_window.total == 0
    budget_used = bad / allowed if allowed else None
    rates = {key: float(Decimal(value.bad) / Decimal(value.total) / fraction) if value.total else None
             for key, value in slo.recent.items()}
    alerts = []
    # The familiar 14.4x/6x thresholds assume a 30-day window; scale with the configured period.
    scale = slo.window_days / 30
    rules = [('fast_burn', 'page', '1h', '5m', 14.4 * scale), ('slow_burn', 'ticket', '6h', '30m', 6 * scale)]
    for name, severity, long, short, threshold in rules:
        pair = [rates.get(long), rates.get(short)]
        alerts.append({'name': name, 'severity': severity, 'windows': [long, short], 'threshold': threshold,
                       'state': 'unassessed' if stale or any(rate is None for rate in pair) else
                                'firing' if all(rate >= threshold for rate in pair) else 'quiet'})
    status = 'no_traffic' if no_traffic else 'stale_measurement' if stale else 'budget_exhausted' if bad >= allowed else 'within_budget'
    freeze = status == 'budget_exhausted' or any(alert['state'] == 'firing' and alert['severity'] == 'page' for alert in alerts)
    return {'service': slo.service, 'status': status, 'target': slo.target, 'window_days': slo.window_days,
            'measured_at': slo.measured_at.isoformat(), 'allowed_bad_events': float(allowed),
            'observed_bad_events': slo.full_window.bad, 'budget_used_percent': float(budget_used * 100) if budget_used is not None else None,
            'budget_remaining_percent': max(0, float((1 - budget_used) * 100)) if budget_used is not None else None,
            'observed_good_ratio': 1 - slo.full_window.bad / slo.full_window.total if slo.full_window.total else None,
            'burn_rates': rates, 'alerts': alerts,
            'release_policy': 'needs_measurement' if stale or no_traffic else 'focus_on_reliability' if freeze else 'continue_subject_to_other_gates',
            'provenance': 'User-supplied aggregate counters; computed locally, not connected to production telemetry',
            'assumptions': 'Windows share one end timestamp and one event-based SLI; measurements older than 24 hours are stale.'}


def readiness(lifecycle, system_report, stale):
    actions = []
    def add(priority, area, title, evidence):
        identity = hashlib.sha256(json.dumps([area, title, evidence], sort_keys=True).encode()).hexdigest()[:12]
        actions.append({'id': identity, 'priority': priority, 'area': area, 'title': title, 'evidence': evidence})
    for blocker in lifecycle['release_review']['blockers']:
        priority = 'P0' if blocker['kind'] in {'high_severity_findings', 'numeric_verification_issue'} else 'P1'
        add(priority, 'Evidence', blocker['kind'].replace('_', ' ').capitalize(), blocker)
    if stale:
        add('P1', 'Architecture', 'Refresh systems report against the latest source snapshot', {})
    if system_report is None:
        add('P1', 'Architecture', 'Analyze a repository snapshot and architecture rules', {})
    else:
        arch = system_report['architecture']
        for cycle in arch['cycles']:
            add('P1', 'Architecture', 'Break a circular dependency', {'files': cycle})
        for violation in arch['boundary_violations']:
            add('P1', 'Architecture', 'Restore an architecture boundary', violation)
        if arch['status'] == 'incomplete':
            add('P1', 'Architecture', 'Resolve incomplete source analysis', {'syntax_error_files': arch['syntax_error_files']})
        if not arch['rules_checked']:
            add('P2', 'Architecture', 'Define dependency boundary rules', {})
        slo = system_report['reliability']
        if slo['release_policy'] == 'needs_measurement':
            add('P1', 'Reliability', 'Supply fresh service-level measurements', {'status': slo['status']})
        if slo['release_policy'] == 'focus_on_reliability':
            add('P0', 'Reliability', 'Restore reliability before feature releases', {'status': slo['status'], 'alerts': slo['alerts']})
        if any(alert['state'] == 'unassessed' for alert in slo['alerts']):
            add('P1', 'Reliability', 'Supply all four burn-rate measurement windows', {})
        elif any(alert['state'] == 'firing' and alert['severity'] == 'ticket' for alert in slo['alerts']):
            add('P1', 'Reliability', 'Investigate sustained error-budget consumption', {'alerts': slo['alerts']})
    actions.sort(key=lambda item: (item['priority'], item['area'], item['id']))
    return {'status': 'needs_attention' if any(a['priority'] in {'P0', 'P1'} for a in actions) else 'ready_for_human_review',
            'actions': actions, 'deployment_authorized': False,
            'notice': 'Advisory review based on static analysis, bounded checks and reported evidence. No tests or deployments are executed here.'}


def enrich(conn, project_id, record):
    lifecycle = lifecycle_report(conn, project_id)
    latest = latest_repository(conn, project_id)
    stale = bool(record and latest and record['snapshot_sha256'] != latest['result']['snapshot_sha256'])
    if record and record.get('slo_input'):
        record['reliability'] = reliability(SLO.model_validate(record['slo_input']))
    return {'project': lifecycle['project'], 'report': record, 'source_stale': stale,
            'readiness': readiness(lifecycle, record, stale), 'traceability_summary': lifecycle['traceability_summary'],
            'computed_verification': lifecycle['computed_verification']}


@router.post('/systems')
def analyze_systems(project_id: int, payload: SystemsRequest):
    result = repository(project_id, payload)
    report = {'snapshot_sha256': result['snapshot_sha256'], 'repository_report_id': result['report_id'],
              'created_at': now_iso(), 'architecture': architecture(result, payload.boundaries),
              'reliability': reliability(payload.slo), 'slo_input': payload.slo.model_dump(mode='json') if payload.slo else None,
              'change_impact': {'changed_files': result['changed_files'], 'impacted_files': result['impacted_files'],
                                'regression_targets': result['regression_targets'], 'tests_executed': False},
              'finding_count': len(result['findings'])}
    with db() as conn:
        get_project(conn, project_id)
        cursor = conn.execute('INSERT INTO systems_reports(project_id, result_json, created_at) VALUES (?,?,?)',
                              (project_id, json.dumps(report), now_iso()))
        report['id'] = cursor.lastrowid
        return enrich(conn, project_id, report)


@router.get('/systems')
def latest_systems(project_id: int):
    with db() as conn:
        get_project(conn, project_id)
        row = conn.execute('SELECT * FROM systems_reports WHERE project_id=? ORDER BY id DESC LIMIT 1', (project_id,)).fetchone()
        record = dict(json.loads(row['result_json']), id=row['id']) if row else None
        return enrich(conn, project_id, record)
