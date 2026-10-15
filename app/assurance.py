"""Structured specifications and independent finite-example checking."""
import keyword
import hashlib
import json
import math
import re
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictFloat, StrictInt, model_validator

from app.analysis import UNCLEAR_TERMS
from app.dataflow import scan_dataflow
from app.engineering import Snapshot
from app.numeric_verifier import verify_numeric
from app.reproducibility import envelope, replay, digest
from app.mutation import mutation_audit
from app.storage import db, get_project, now_iso
from app.workflow import must_exist

router = APIRouter(prefix='/api/projects/{project_id}/engineering', tags=['Specification and assurance'])
Number = StrictInt | StrictFloat | StrictBool


class Example(BaseModel):
    inputs: dict[str, Number] = Field(min_length=1, max_length=20)
    expected: Number

    @model_validator(mode='after')
    def finite_values(self):
        for key in self.inputs:
            if len(key) > 100 or not key.isidentifier() or keyword.iskeyword(key):
                raise ValueError('Input names must be Python identifiers')
        for value in [*self.inputs.values(), self.expected]:
            if abs(value) > 1e9 or not math.isfinite(value):
                raise ValueError('Examples require finite numeric/boolean values within +/- 1e9')
        return self


class Specification(BaseModel):
    criterion_id: int | None = Field(default=None, gt=0)
    actor: str = Field(default='', max_length=100)
    trigger: str = Field(default='', max_length=500)
    behavior: str = Field(min_length=10, max_length=2500)
    failure_behavior: str = Field(default='', max_length=1000)
    constraints: list[str] = Field(default_factory=list, max_length=20)
    source_file: str = Field(default='app/rules.py', max_length=250)
    function: str = Field(default='calculate', max_length=100)
    examples: list[Example] = Field(default_factory=list, max_length=50)

    @model_validator(mode='after')
    def valid_target(self):
        validate_target(self.source_file, self.function)
        if any(len(c) > 500 for c in self.constraints):
            raise ValueError('Maximum 500 characters per constraint')
        return self


def validate_target(path, function):
    if not path.endswith('.py') or not all(p.isidentifier() and not keyword.iskeyword(p) for p in path[:-3].split('/')):
        raise ValueError('Use an importable Python relative source path, e.g. app/rules.py')
    if not function.isidentifier() or keyword.iskeyword(function):
        raise ValueError('Function must be a Python identifier')


class Verification(BaseModel):
    criterion_id: int = Field(gt=0)
    source_file: str = Field(max_length=250)
    function: str = Field(max_length=100)
    source: str = Field(min_length=1, max_length=60000)
    examples: list[Example] = Field(min_length=1, max_length=50)

    @model_validator(mode='after')
    def valid_target(self):
        validate_target(self.source_file, self.function)
        return self


def save(conn, project_id, kind, criterion, result):
    result['criterion_id'] = criterion['id'] if criterion else None
    result['criterion_revision'] = criterion['revision'] if criterion else None
    cur = conn.execute('INSERT INTO assurance_reports(project_id, kind, criterion_id, criterion_revision, result_json, created_at) VALUES (?,?,?,?,?,?)',
                       (project_id, kind, result['criterion_id'], result['criterion_revision'], json.dumps(result), now_iso()))
    result['assurance_report_id'] = cur.lastrowid
    return result


@router.post('/specifications')
def specification(project_id: int, payload: Specification):
    gaps = []
    for field in ['actor', 'trigger', 'failure_behavior']:
        if not getattr(payload, field).strip():
            gaps.append({'field': field, 'question': 'Specify ' + field.replace('_', ' ') + '.'})
    text = ' '.join([payload.actor, payload.trigger, payload.behavior, payload.failure_behavior, *payload.constraints])
    for term, recommendation in UNCLEAR_TERMS.items():
        if re.search(r'(?<!\w)' + re.escape(term) + r'(?!\w)', text, re.I):
            gaps.append({'field': 'wording', 'term': term, 'question': recommendation})
    if not payload.examples:
        gaps.append({'field': 'examples', 'question': 'Provide concrete input/output examples approved by the stakeholder.'})
    if payload.examples and any(set(e.inputs) != set(payload.examples[0].inputs) for e in payload.examples):
        gaps.append({'field': 'examples', 'question': 'All examples must use the same parameter names.'})
    seen = {}
    for example in payload.examples:
        key = tuple(sorted((name, type(value) is bool, value) for name, value in example.inputs.items()))
        expected = (type(example.expected) is bool, example.expected)
        if key in seen and seen[key] != expected:
            gaps.append({'field': 'examples', 'question': 'Identical inputs have conflicting expected outputs; clarify the intended rule.'})
        seen[key] = expected
    module = payload.source_file[:-3].replace('/', '.')
    rows = [(e.inputs, e.expected) for e in payload.examples]
    tests = ('"""Generated from stakeholder examples; run only in your trusted test environment."""\n'
             'import importlib\nimport pytest\n\n'
             f'@pytest.mark.parametrize("inputs,expected", {rows!r})\n'
             f'def test_{payload.function}_examples(inputs, expected):\n'
             f'    actual = getattr(importlib.import_module({module!r}), {payload.function!r})(**inputs)\n'
             '    assert actual == expected\n'
             '    assert isinstance(actual, bool) == isinstance(expected, bool)\n')
    result = {'specification': payload.model_dump(), 'clarifications': gaps,
              'status': 'needs_clarification' if gaps else 'ready_for_stakeholder_review',
              'given_when_then': {'given': payload.actor, 'when': payload.trigger, 'then': payload.behavior,
                                  'on_failure': payload.failure_behavior},
              'pytest_source': tests if payload.examples and not any(g['field'] == 'examples' for g in gaps) else None,
              'notice': 'Examples are authored by the requester, not derived from the implementation. Generated tests are not run by this endpoint.'}
    with db() as conn:
        get_project(conn, project_id)
        criterion = must_exist(conn, 'acceptance_criteria', 'id', payload.criterion_id, project_id) if payload.criterion_id else None
        return save(conn, project_id, 'specification', criterion, result)


@router.post('/verify-numeric')
def verification(project_id: int, payload: Verification):
    with db() as conn:
        get_project(conn, project_id)
        criterion = must_exist(conn, 'acceptance_criteria', 'id', payload.criterion_id, project_id)
        record = envelope(payload.source, payload.function, [e.model_dump() for e in payload.examples])
        result = dict(record['result'])
        result['replay_record'] = record
        result['source_file'] = payload.source_file
        result['evidence_status'] = 'computed_model_result; not a runtime test or stakeholder approval'
        return save(conn, project_id, 'verification', criterion, result)


@router.post('/security-flow')
def security(project_id: int, payload: Snapshot):
    with db() as conn:
        get_project(conn, project_id)
    try:
        result = scan_dataflow(payload.files)
    except RecursionError:
        raise HTTPException(422, 'Source nesting exceeds analyzer limits')
    with db() as conn:
        return save(conn, project_id, 'security', None, result)


@router.get('/assurance-reports')
def reports(project_id: int):
    with db() as conn:
        get_project(conn, project_id)
        return {'reports': [{'id': row['id'], 'kind': row['kind'], 'created_at': row['created_at'], 'result': json.loads(row['result_json'])}
                            for row in conn.execute('SELECT * FROM assurance_reports WHERE project_id=? ORDER BY id DESC LIMIT 50', (project_id,))]}


class ReplayInput(BaseModel):
    source: str = Field(min_length=1, max_length=60000)


class MutationInput(Verification):
    source: str = Field(min_length=1, max_length=12000)
    seed: int = Field(default=0, ge=0, le=4294967295)
    max_mutants: int = Field(default=12, ge=1, le=20)
    probe_count: int = Field(default=20, ge=1, le=30)


class LockedAuditInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    mode: Literal['audit', 'repair'] = 'audit'
    source: str = Field(min_length=1, max_length=12000)
    seed: int = Field(default=0, ge=0, le=4294967295)
    max_mutants: int = Field(default=12, ge=1, le=20)
    probe_count: int = Field(default=20, ge=1, le=30)


@router.post('/specifications/{specification_id}/mutation-check')
def locked_mutation(project_id: int, specification_id: int, payload: LockedAuditInput):
    with db() as conn:
        row = conn.execute("SELECT * FROM assurance_reports WHERE id=? AND project_id=? AND kind='specification'", (specification_id, project_id)).fetchone()
        if row is None:
            raise HTTPException(404, 'Specification not found in this project')
        saved = json.loads(row['result_json'])
        if row['criterion_id'] is None:
            raise HTTPException(409, 'Specification must be linked to an acceptance criterion')
        criterion = must_exist(conn, 'acceptance_criteria', 'id', row['criterion_id'], project_id)
        if criterion['status'] != 'approved' or criterion['revision'] != row['criterion_revision']:
            raise HTTPException(409, 'Approve the current criterion and create a specification for its current revision')
        if saved['status'] != 'ready_for_stakeholder_review':
            raise HTTPException(409, 'Resolve specification clarifications before auditing')
        spec = saved['specification']
        result = mutation_audit(payload.source, spec['function'], spec['examples'], payload.seed, payload.max_mutants, payload.probe_count, repair=payload.mode == 'repair')
        result.update(specification_report_id=specification_id, contract_sha256=digest(spec),
                      source_file=spec['source_file'], source_sha256=hashlib.sha256(payload.source.encode()).hexdigest())
        return save_experiment(conn, project_id, 'mutation', criterion, result)


def save_experiment(conn, project_id, kind, criterion, result):
    result['criterion_id'] = criterion['id']
    result['criterion_revision'] = criterion['revision']
    cur = conn.execute('INSERT INTO engineering_experiments(project_id, kind, result_json, created_at) VALUES (?,?,?,?)',
                       (project_id, kind, json.dumps(result), now_iso()))
    result['experiment_id'] = cur.lastrowid
    return result


@router.post('/mutation-audit')
def mutations(project_id: int, payload: MutationInput):
    with db() as conn:
        criterion = must_exist(conn, 'acceptance_criteria', 'id', payload.criterion_id, project_id)
        result = mutation_audit(payload.source, payload.function, [e.model_dump() for e in payload.examples],
                                payload.seed, payload.max_mutants, payload.probe_count)
        result['source_file'] = payload.source_file
        result['source_sha256'] = hashlib.sha256(payload.source.encode()).hexdigest()
        return save_experiment(conn, project_id, 'mutation', criterion, result)


@router.post('/verification/{report_id}/replay')
def replay_verification(project_id: int, report_id: int, payload: ReplayInput):
    with db() as conn:
        row = conn.execute("SELECT * FROM assurance_reports WHERE id=? AND project_id=? AND kind='verification'", (report_id, project_id)).fetchone()
        if row is None:
            raise HTTPException(404, 'Verification report not found in this project')
        stored = json.loads(row['result_json'])
        record = stored.get('replay_record')
        if record is None:
            raise HTTPException(409, 'Legacy report has no replay record; run a new verification')
        criterion = must_exist(conn, 'acceptance_criteria', 'id', row['criterion_id'], project_id)
        result = replay(payload.source, record)
        result.update(verification_report_id=report_id, original_criterion_revision=row['criterion_revision'],
                      requirement_revision_current=row['criterion_revision'] == criterion['revision'])
        return save_experiment(conn, project_id, 'replay', criterion, result)


@router.get('/experiments')
def experiments(project_id: int):
    with db() as conn:
        get_project(conn, project_id)
        return {'experiments': [{'id': r['id'], 'kind': r['kind'], 'created_at': r['created_at'], 'result': json.loads(r['result_json'])}
                                for r in conn.execute('SELECT * FROM engineering_experiments WHERE project_id=? ORDER BY id DESC LIMIT 30', (project_id,))]}
