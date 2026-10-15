"""Exhaustive finite-domain comparisons in the restricted numeric model."""
import itertools
import hashlib

from fastapi import APIRouter
from pydantic import BaseModel, Field, model_validator
from app.assurance import Number, Example, validate_target
from app.numeric_verifier import verify_numeric
from app.reproducibility import digest
from app.storage import db
from app.workflow import must_exist

router = APIRouter(prefix='/api/projects/{project_id}/engineering')


class BoundedInput(BaseModel):
    criterion_id: int = Field(gt=0)
    source_file: str = Field(max_length=250)
    function: str = Field(max_length=100)
    source: str = Field(min_length=1, max_length=12000)
    reference_source: str = Field(min_length=1, max_length=12000)
    domains: dict[str, list[Number]] = Field(min_length=1, max_length=4)

    @model_validator(mode='after')
    def bounded(self):
        validate_target(self.source_file, self.function)
        count = 1
        for name, values in self.domains.items():
            if not values or len(values) > 16:
                raise ValueError('Each domain requires 1 to 16 values')
            for value in values:
                Example(inputs={name: value}, expected=0)
            count *= len(values)
        if count > 256:
            raise ValueError('Maximum 256 input combinations')
        return self


def compare_bounded(source, reference, function, domains):
    names = sorted(domains)
    counterexamples, incomplete = [], []
    checked = 0
    for values in itertools.product(*(domains[n] for n in names)):
        inputs = dict(zip(names, values))
        oracle = verify_numeric(reference, function, [{'inputs': inputs, 'expected': 0}])
        rows = oracle['cases']
        if not rows or 'actual' not in rows[0]:
            incomplete.append({'inputs': inputs, 'reason': 'Reference has no supported numeric result'})
            continue
        candidate = verify_numeric(source, function, [{'inputs': inputs, 'expected': rows[0]['actual']}])
        if candidate['status'] in {'unsupported', 'incomplete'}:
            incomplete.append({'inputs': inputs, 'reason': candidate.get('reason', 'Candidate exceeds supported model')})
        elif candidate['status'] == 'counterexample_found':
            counterexamples.append(candidate['cases'][0])
            checked += 1
        else:
            checked += 1
    return {'status': 'counterexample_found' if counterexamples else 'incomplete' if incomplete else 'matches_declared_domain',
            'checked_combinations': checked, 'counterexamples': counterexamples, 'incomplete_inputs': incomplete,
            'domain_sha256': digest(domains), 'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
            'reference_sha256': hashlib.sha256(reference.encode()).hexdigest(),
            'scope': 'Exhaustive only over the declared finite domain in the numeric interpreter. Reference correctness is assumed, not proven.'}


@router.post('/bounded-check')
def bounded_check(project_id: int, payload: BoundedInput):
    with db() as conn:
        criterion = must_exist(conn, 'acceptance_criteria', 'id', payload.criterion_id, project_id)
    result = compare_bounded(payload.source, payload.reference_source, payload.function, payload.domains)
    result.update(criterion_id=criterion['id'], criterion_revision=criterion['revision'], source_file=payload.source_file)
    return result
