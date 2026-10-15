"""Pytest-only route and outcome recorder for the trusted local quality gate."""
import json
import os
from pathlib import Path
import tempfile

_routes = {}
_outcomes = []
_tmp = None


def pytest_sessionstart(session):
    global _tmp
    _tmp = tempfile.TemporaryDirectory(prefix='devflow-quality-')
    os.environ['DEVFLOW_DB'] = str(Path(_tmp.name) / 'test.sqlite3')
    from app.main import app

    @app.middleware('http')
    async def route_probe(request, call_next):
        response = await call_next(request)
        route = request.scope.get('route')
        key = request.method + ' ' + (route.path if route is not None else request.url.path)
        _routes.setdefault(key, set()).add(response.status_code)
        return response


def pytest_runtest_logreport(report):
    if report.when == 'call' or report.failed or report.skipped:
        _outcomes.append({'test': report.nodeid, 'phase': report.when, 'outcome': report.outcome})


def pytest_sessionfinish(session, exitstatus):
    from app.main import app
    expected = {method.upper() + ' ' + path for path, methods in app.openapi()['paths'].items()
                for method in methods if method in {'get', 'post', 'put', 'patch', 'delete', 'options'}}
    expected.update({'GET /api/docs', 'GET /docs/oauth2-redirect', 'GET /openapi.json'})
    expected = sorted(expected)
    target = os.environ.get('DEVFLOW_QUALITY_TEST_REPORT')
    if target:
        Path(target).write_text(json.dumps({'exit_code': int(exitstatus), 'outcomes': _outcomes,
                                          'routes': [{'route': route, 'statuses': sorted(_routes.get(route, set())),
                                                      'successful_response_exercised': any(200 <= code < 400 for code in _routes.get(route, set()))}
                                                     for route in expected]}, indent=2), encoding='utf-8')
    if _tmp:
        _tmp.cleanup()
