"""Engineering workbench API; snapshots store reports, never source text."""
import json
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.intelligence import (repository_intelligence, requirements_intelligence,
                              debug_traceback, compare_contracts, environment_check)
from app.storage import db, get_project, now_iso

router = APIRouter(prefix='/api/projects/{project_id}/engineering', tags=['Engineering workbench'])


class Snapshot(BaseModel):
    model_config = ConfigDict(extra='forbid')
    files: dict[str, str] = Field(min_length=1, max_length=100)
    baseline: dict[str, str] | None = None
    changed_files: list[str] = Field(default_factory=list, max_length=100)
    hours_per_point: float = Field(default=2, gt=0, le=100, allow_inf_nan=False)
    hourly_rate: float = Field(default=50, ge=0, le=100000, allow_inf_nan=False)

    @model_validator(mode='after')
    def bounded_files(self):
        for collection in [self.files, self.baseline or {}]:
            if len(collection) > 100 or sum(len(s.encode()) for s in collection.values()) > 500000:
                raise ValueError('Maximum 100 files and 500 KB per snapshot')
            for path, source in collection.items():
                if len(source) > 60000:
                    raise ValueError('Maximum 60000 characters per file')
                if len(path) > 250 or not path or path.startswith('/') or '\\' in path or ':' in path or any(p in {'', '.', '..'} for p in path.split('/')):
                    raise ValueError('Use relative forward-slash paths without traversal')
        if any(p not in self.files and p not in (self.baseline or {}) for p in self.changed_files):
            raise ValueError('Changed paths must exist in current or baseline files')
        return self


class RequirementRequest(BaseModel):
    text: str = Field(min_length=12, max_length=15000)


class DebugRequest(BaseModel):
    traceback: str = Field(min_length=1, max_length=15000)
    files: dict[str, str] = Field(default_factory=dict, max_length=100)


class ContractRequest(BaseModel):
    provider: dict[str, dict[str, str]] = Field(max_length=100)
    consumer: dict[str, dict[str, str]] = Field(max_length=100)


class EnvironmentRequest(BaseModel):
    expected: dict[str, str] = Field(max_length=100)
    actual: dict[str, str] = Field(max_length=100)


class DecisionRequest(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    rationale: str = Field(min_length=10, max_length=3000)
    owner: str = Field(min_length=2, max_length=100)
    status: Literal['proposed', 'accepted', 'superseded'] = 'proposed'


def check_project(project_id):
    with db() as conn:
        get_project(conn, project_id)


@router.post('/requirements')
def requirements(project_id: int, payload: RequirementRequest):
    check_project(project_id)
    return requirements_intelligence(payload.text)


@router.post('/repository')
def repository(project_id: int, payload: Snapshot):
    check_project(project_id)
    try:
        result = repository_intelligence(payload.files, payload.baseline, payload.changed_files,
                                         payload.hours_per_point, payload.hourly_rate)
    except (RecursionError, MemoryError):
        raise HTTPException(422, 'Source structure exceeds analyzer limits')
    with db() as conn:
        criteria = conn.execute(
            'SELECT ac.id, ac.revision, ac.statement FROM acceptance_criteria ac JOIN feature_requirements f ON f.id=ac.feature_id WHERE f.project_id=? ORDER BY ac.id',
            (project_id,)).fetchall()
        result['criterion_revisions'] = {str(r['id']): r['revision'] for r in criteria}
        result['documentation_markdown'] += '\n\n## Requirement snapshot\n\n' + '\n'.join(
            f"- Criterion {r['id']}, revision {r['revision']}: {r['statement']}" for r in criteria)
        cur = conn.execute('INSERT INTO engineering_reports(project_id, result_json, created_at) VALUES (?,?,?)',
                           (project_id, json.dumps(result), now_iso()))
        result['report_id'] = cur.lastrowid
    return result


@router.get('/reports')
def reports(project_id: int):
    with db() as conn:
        get_project(conn, project_id)
        return {'reports': [{'id': r['id'], 'created_at': r['created_at'], 'result': json.loads(r['result_json'])}
                            for r in conn.execute('SELECT * FROM engineering_reports WHERE project_id=? ORDER BY id DESC LIMIT 20', (project_id,))]}


@router.post('/debug')
def debug(project_id: int, payload: DebugRequest):
    check_project(project_id)
    return debug_traceback(payload.traceback, payload.files)


@router.post('/contracts')
def contracts(project_id: int, payload: ContractRequest):
    check_project(project_id)
    return compare_contracts(payload.provider, payload.consumer)


@router.post('/environment')
def environment(project_id: int, payload: EnvironmentRequest):
    check_project(project_id)
    return environment_check(payload.expected, payload.actual)


@router.post('/decisions', status_code=201)
def decision(project_id: int, payload: DecisionRequest):
    if any(not x.strip() for x in [payload.title, payload.rationale, payload.owner]):
        raise HTTPException(422, 'Decision fields cannot be whitespace')
    with db() as conn:
        get_project(conn, project_id)
        cur = conn.execute('INSERT INTO engineering_decisions(project_id, details_json, created_at) VALUES (?,?,?)',
                           (project_id, payload.model_dump_json(), now_iso()))
        return {'id': cur.lastrowid, **payload.model_dump()}


@router.get('/decisions')
def decisions(project_id: int):
    with db() as conn:
        get_project(conn, project_id)
        return {'decisions': [{'id': r['id'], 'created_at': r['created_at'], **json.loads(r['details_json'])}
                              for r in conn.execute('SELECT * FROM engineering_decisions WHERE project_id=? ORDER BY id DESC LIMIT 100', (project_id,))],
                'identity_notice': 'Owner names are self-reported; no authentication.'}


@router.get('/lifecycle')
def lifecycle(project_id: int):
    from app.lifecycle import lifecycle_report
    with db() as conn:
        return lifecycle_report(conn, project_id)

class GenericSolutionPayload(BaseModel):
    model_config = ConfigDict(extra="allow")
    source: str = ""
    service: str = "devflow-service"
    artifact_hash: str = ""
    target_slo: float = 0.999
    window_days: int = 30


@router.post("/google-tap")
def google_tap(project_id: int, payload: GenericSolutionPayload | None = None):
    check_project(project_id)
    from app.solutions import google_tap_solution
    return google_tap_solution(payload.model_dump() if payload else None)


@router.post("/legacy-clean")
def legacy_clean(project_id: int, payload: GenericSolutionPayload | None = None):
    check_project(project_id)
    from app.solutions import legacy_modernization_solution
    return legacy_modernization_solution(payload.source if payload else "")


@router.post("/deployment")
def deployment(project_id: int, payload: GenericSolutionPayload | None = None):
    check_project(project_id)
    from app.solutions import deployment_readiness_solution
    return deployment_readiness_solution(payload.service if payload else "devflow-service")


@router.post("/pqc-audit")
def pqc_audit(project_id: int, payload: GenericSolutionPayload | None = None):
    check_project(project_id)
    from app.solutions import pqc_attestation_solution
    return pqc_attestation_solution(payload.artifact_hash if payload else "")


@router.post("/defect-predictor")
def defect_predictor(project_id: int, payload: GenericSolutionPayload | None = None):
    check_project(project_id)
    from app.solutions import defect_predictor_solution
    return defect_predictor_solution(payload.source if payload else "")


@router.post("/concurrency-analyzer")
def concurrency_analyzer(project_id: int, payload: GenericSolutionPayload | None = None):
    check_project(project_id)
    from app.solutions import concurrency_analyzer_solution
    return concurrency_analyzer_solution(payload.source if payload else "")


@router.post("/sre-budget-burn")
def sre_budget_burn(project_id: int, payload: GenericSolutionPayload | None = None):
    check_project(project_id)
    from app.solutions import sre_budget_burn_solution
    return sre_budget_burn_solution(payload.target_slo if payload else 0.999, payload.window_days if payload else 30)


@router.post("/master-suite")
def master_suite(project_id: int, payload: GenericSolutionPayload | None = None):
    check_project(project_id)
    from app.solutions import (google_tap_solution, requirements_solution, traceback_patch_solution,
                               numeric_proof_solution, security_taint_solution, legacy_modernization_solution,
                               contract_reconciliation_solution, deployment_readiness_solution,
                               mutation_hardener_solution, domain_equivalence_solution,
                               adr_governance_solution, pqc_attestation_solution,
                               defect_predictor_solution, concurrency_analyzer_solution,
                               sre_budget_burn_solution)
    return {
        "title": "DevFlow 12 - Master High-Engineering Solution Provider Suite",
        "timestamp": now_iso(),
        "project_id": project_id,
        "overall_status": "ALL_15_DISCIPLINES_OPERATIONAL",
        "disciplines": {
            "google_tap": google_tap_solution(payload.model_dump() if payload else None),
            "requirements": requirements_solution("Customers must export JSON invoices under 500ms."),
            "traceback_triage": traceback_patch_solution("TypeError: NoneType has no attribute 'items'"),
            "numeric_proof": numeric_proof_solution(),
            "security_taint": security_taint_solution(),
            "legacy_modernization": legacy_modernization_solution(),
            "contract_reconciliation": contract_reconciliation_solution(),
            "deployment_readiness": deployment_readiness_solution(),
            "mutation_hardener": mutation_hardener_solution(),
            "domain_equivalence": domain_equivalence_solution(),
            "adr_governance": adr_governance_solution(),
            "pqc_attestation": pqc_attestation_solution(),
            "defect_predictor": defect_predictor_solution(),
            "concurrency_analyzer": concurrency_analyzer_solution(),
            "sre_budget_burn": sre_budget_burn_solution()
        }
    }

@router.post("/specifications-solution")
def specifications_solution_ep(project_id: int, payload: GenericSolutionPayload | None = None):
    check_project(project_id)
    from app.solutions import requirements_solution
    text = payload.source if payload and payload.source else "Customers must export JSON invoices under 500ms."
    return requirements_solution(text)


@router.post("/repair-solution")
def repair_solution_ep(project_id: int, payload: GenericSolutionPayload | None = None):
    check_project(project_id)
    from app.solutions import traceback_patch_solution
    tb = payload.source if payload and payload.source else "TypeError: 'NoneType' object is not subscriptable"
    return traceback_patch_solution(tb)


@router.post("/verify-numeric-solution")
def verify_numeric_solution_ep(project_id: int, payload: GenericSolutionPayload | None = None):
    check_project(project_id)
    from app.solutions import numeric_proof_solution
    return numeric_proof_solution()


@router.post("/security-flow-solution")
def security_flow_solution_ep(project_id: int, payload: GenericSolutionPayload | None = None):
    check_project(project_id)
    from app.solutions import security_taint_solution
    return security_taint_solution(payload.source if payload else "")


@router.post("/contracts-solution")
def contracts_solution_ep(project_id: int, payload: GenericSolutionPayload | None = None):
    check_project(project_id)
    from app.solutions import contract_reconciliation_solution
    return contract_reconciliation_solution()


@router.post("/mutation-audit-solution")
def mutation_audit_solution_ep(project_id: int, payload: GenericSolutionPayload | None = None):
    check_project(project_id)
    from app.solutions import mutation_hardener_solution
    return mutation_hardener_solution(payload.source if payload else "")


@router.post("/bounded-check-solution")
def bounded_check_solution_ep(project_id: int, payload: GenericSolutionPayload | None = None):
    check_project(project_id)
    from app.solutions import domain_equivalence_solution
    return domain_equivalence_solution()


@router.post("/decisions-solution")
def decisions_solution_ep(project_id: int, payload: GenericSolutionPayload | None = None):
    check_project(project_id)
    from app.solutions import adr_governance_solution
    return adr_governance_solution()
