"""Tenant-scoped readiness, identity, audit verification and service counters."""
from fastapi import APIRouter, HTTPException, Request

from app.enterprise import principal
from app.storage import db
from app.audit import verify_chain

router = APIRouter(tags=['Operations'])


@router.get('/health/live')
def live():
    return {'status': 'alive'}


@router.get('/api/identity')
def identity_status():
    identity = principal.get()
    return {'mode': 'enterprise' if identity else 'local',
            'actor': identity.actor if identity else None,
            'tenant': identity.tenant if identity else None,
            'role': identity.role if identity else None}


def require_operator():
    identity = principal.get()
    if identity is not None and identity.role != 'admin':
        raise HTTPException(403, 'Tenant administrator required')
    return identity


@router.get('/api/ops/readiness')
def readiness():
    require_operator()
    with db() as conn:
        version = conn.execute('PRAGMA user_version').fetchone()[0]
        conn.execute('SELECT 1 FROM projects LIMIT 1').fetchall()
    return {'status': 'ready', 'schema_version': version}


@router.get('/api/ops/audit')
def audit_status():
    identity = require_operator()
    if identity is None:
        return {'status': 'enterprise_mode_required'}
    with db() as conn:
        return verify_chain(conn, identity.audit_key)


@router.get('/api/ops/metrics')
def metrics(request: Request):
    identity = require_operator()
    if identity is None:
        return {'status': 'enterprise_mode_required'}
    result = request.app.state.enterprise.metrics[identity.tenant].copy()
    result['status'] = 'measured_in_process'
    result['scope'] = 'Completed authenticated requests for this tenant in this worker; resets on restart'
    return result
