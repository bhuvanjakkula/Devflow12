import json
from pathlib import Path
import pytest
from jsonschema import Draft7Validator, FormatChecker
from app.protection import ProtectionInput, Baseline, audit, compare_reports
from app.audit_exports import add_finding_context


def test_finding_identity_survives_line_shifts_and_scopes_are_distinct():
    source = 'class Service:\n    def run(self, value):\n        return eval(value)\n'
    old = audit(ProtectionInput(files={'service.py': source}))
    new = audit(ProtectionInput(files={'service.py': '# New comment\n\n' + source}))
    assert {f['issue_id'] for f in old['findings']} == {f['issue_id'] for f in new['findings']}
    assert any(f['scope'] == 'Service.run' for f in new['findings'])
    comparison = compare_reports(new, Baseline.model_validate(old))
    assert comparison['counts']['new'] == 0
    assert comparison['counts']['location_changed'] == len(old['findings'])
    assert comparison['counts']['not_seen_in_current'] == 0


def test_duplicate_findings_have_distinct_identifiers():
    source = 'def run(x):\n    eval(x)\n    return eval(x)\n'
    report = audit(ProtectionInput(files={'service.py': source}))
    ids = [f['issue_id'] for f in report['findings']]
    assert len(ids) == len(set(ids))
    assert add_finding_context({'broken.py': 'def ('}, [{'path': 'broken.py', 'line': 1, 'rule': 'SYNTAX', 'title': 'Syntax issue'}])[0]['scope'] == '<module>'


def test_legacy_reports_keep_exact_location_compatibility():
    current = audit(ProtectionInput(files={'x.py': 'eval(x)\n'}))
    legacy = {**current, 'findings': [{k:v for k,v in f.items() if k not in {'issue_id','identity_method','scope'}} for f in current['findings']]}
    assert compare_reports(current, Baseline.model_validate(legacy))['counts']['unchanged'] == len(current['findings'])


@pytest.mark.parametrize('files', [{'app rules.py': 'eval(user)\n'}, {'app.py': 'def identity(x):\n    """Return x."""\n    return x\n'},
                                  {'Dockerfile': 'FROM python:latest\nUSER root\n'}, {'package.json': '[]'}])
def test_sarif_validates_against_official_schema(files):
    report = audit(ProtectionInput(files=files))
    schema = json.loads((Path(__file__).parent / 'fixtures' / 'sarif-schema-2.1.0.json').read_text())
    Draft7Validator(schema, format_checker=FormatChecker()).validate(report['sarif'])
    assert report['sarif']['runs'][0]['properties']['project_modified'] is False
    assert 'contents' not in report['sarif']['runs'][0]


def test_export_redacts_literals_and_plan_prioritizes_without_modifying_source(tmp_path):
    marker = tmp_path / 'untouched'
    token = 'AKIA' + 'Z' * 16
    source = f'import pathlib\npathlib.Path({str(marker)!r}).write_text("executed")\n# {token}\n'
    report = audit(ProtectionInput(files={'app.py': source}))
    assert not marker.exists()
    assert token not in json.dumps(report)
    assert str(marker) not in json.dumps(report)
    plan = report['remediation_plan']
    assert plan['items'][0]['priority'] == 'P0'
    assert all(item['status'] in {'open', 'unassessed'} for item in plan['items'])
    assert all(item['owner'] is None for item in plan['items'])
