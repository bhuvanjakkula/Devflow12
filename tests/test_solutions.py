"""Comprehensive test suite for DevFlow 15 engineering disciplines and solutions."""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.solutions import (
    google_tap_solution, requirements_solution, traceback_patch_solution,
    numeric_proof_solution, security_taint_solution, legacy_modernization_solution,
    contract_reconciliation_solution, deployment_readiness_solution,
    mutation_hardener_solution, domain_equivalence_solution,
    adr_governance_solution, pqc_attestation_solution,
    defect_predictor_solution, concurrency_analyzer_solution,
    sre_budget_burn_solution
)


def test_direct_solution_generators():
    # Test all 15 discipline generators directly
    tap = google_tap_solution({"flakiness_audit": {"trials": 10}})
    assert tap["certification_status"] == "CERTIFIED_HERMETIC"
    assert "Hermetic" in tap["generated_solution"]["title"]

    req = requirements_solution("Customers must export JSON invoices under 500ms.")
    assert "Feature:" in req["synthesized_gherkin"]
    assert req["clarity_score"] > 0

    trace = traceback_patch_solution("TypeError: NoneType has no attribute 'items'")
    assert trace["remediation_status"] == "PATCH_SYNTHESIZED"

    proof = numeric_proof_solution(function_name="clamp", bounds=(0, 100))
    assert proof["proof_status"] == "MATHEMATICALLY_PROVEN"

    sec = security_taint_solution("eval('1+1')")
    assert sec["hardening_status"] == "SECURE_BY_CONSTRUCTION"

    legacy = legacy_modernization_solution("class OldService: pass")
    assert "dataclass" in legacy["solution_code"]

    contract = contract_reconciliation_solution()
    assert contract["compatibility_status"] == "ADAPTER_BRIDGED"

    dep = deployment_readiness_solution("api-service")
    assert "USER 10001:10001" in dep["solution_code"]

    mut = mutation_hardener_solution()
    assert mut["mutation_score"] == "100.00%"

    eq = domain_equivalence_solution()
    assert eq["equivalence_status"] == "EXHAUSTIVELY_PROVEN_EQUIVALENT"

    adr = adr_governance_solution("Adopt Hermetic Testing")
    assert adr["governance_status"] == "CHAIN_SEALED"

    pqc = pqc_attestation_solution()
    assert pqc["verification_status"] == "POST_QUANTUM_CERTIFIED"

    pred = defect_predictor_solution()
    assert pred["status"] == "PROACTIVELY_PROTECTED"

    conc = concurrency_analyzer_solution()
    assert conc["compliance"] == "STRICT_ASYNCIO_DETERMINISTIC"

    sre = sre_budget_burn_solution(0.999, 30)
    assert sre["sre_metrics"]["window_days"] == "30 days"


def test_engineering_api_endpoints():
    with TestClient(app) as client:
        # Create a project
        p = client.post("/api/projects", json={"name": "Engineering Suite Test"}).json()
        pid = p["id"]

        # Test new discipline endpoints
        res_tap = client.post(f"/api/projects/{pid}/engineering/google-tap", json={})
        assert res_tap.status_code == 200

        res_leg = client.post(f"/api/projects/{pid}/engineering/legacy-clean", json={"source": "def foo(): pass"})
        assert res_leg.status_code == 200

        res_dep = client.post(f"/api/projects/{pid}/engineering/deployment", json={"service": "prod-app"})
        assert res_dep.status_code == 200

        res_pqc = client.post(f"/api/projects/{pid}/engineering/pqc-audit", json={"artifact_hash": "abc"})
        assert res_pqc.status_code == 200

        res_pred = client.post(f"/api/projects/{pid}/engineering/defect-predictor", json={"source": "x = 1"})
        assert res_pred.status_code == 200

        res_conc = client.post(f"/api/projects/{pid}/engineering/concurrency-analyzer", json={"source": "async def f(): pass"})
        assert res_conc.status_code == 200

        res_sre = client.post(f"/api/projects/{pid}/engineering/sre-budget-burn", json={"target_slo": 0.999, "window_days": 30})
        assert res_sre.status_code == 200

        for ep in ["specifications-solution", "repair-solution", "verify-numeric-solution",
                   "security-flow-solution", "contracts-solution", "mutation-audit-solution",
                   "bounded-check-solution", "decisions-solution"]:
            res_ep = client.post(f"/api/projects/{pid}/engineering/{ep}", json={})
            assert res_ep.status_code == 200

        res_master = client.post(f"/api/projects/{pid}/engineering/master-suite", json={})
        assert res_master.status_code == 200
        assert res_master.json()["overall_status"] == "ALL_15_DISCIPLINES_OPERATIONAL"


def test_owner_instant_enter_routes(monkeypatch):
    monkeypatch.setenv('DEVFLOW_OWNER_MODE', '1')
    with TestClient(app) as client:
        res_post = client.post("/owner/instant-enter", follow_redirects=False)
        assert res_post.status_code == 303
        assert res_post.headers["location"] == "/engineering"

        res_get = client.get("/owner/instant-enter", follow_redirects=False)
        assert res_get.status_code == 303
        assert res_get.headers["location"] == "/engineering"



def test_owner_signup_and_support_enquiry(monkeypatch):
    monkeypatch.setenv('DEVFLOW_OWNER_MODE', '1')
    with TestClient(app) as client:
        # Test signup endpoint
        res_signup = client.post('/owner/signup', data={'email': 'user@example.com', 'password': 'pw', 'mobile': '1234567890'}, follow_redirects=False)
        assert res_signup.status_code == 303
        assert res_signup.headers['location'] == '/engineering'

        # Test support enquiry GET
        res_supp_get = client.get('/api/support/enquiry')
        assert res_supp_get.status_code == 200
        assert res_supp_get.json()['support_email'] == 'bjtmusic12@gmail.com'

        # Test support enquiry POST
        res_supp_post = client.post('/api/support/enquiry', json={'name': 'Test User', 'message': 'Need assistance', 'to': 'bjtmusic12@gmail.com'})
        assert res_supp_post.status_code == 200
        assert 'bjtmusic12@gmail.com' in res_supp_post.json()['support_email']
        # Test pricing endpoint
        res_price = client.get('/api/pricing')
        assert res_price.status_code == 200
        assert res_price.json()['currency'] == 'USD'
