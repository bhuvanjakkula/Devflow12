"""Transaction-bound audit chain. External head retention detects tail deletion."""
from contextvars import ContextVar
from datetime import datetime, timezone
import hashlib
import hmac
import json
import uuid

request_metadata = ContextVar('devflow_request_metadata', default={})


def signature(key, previous, payload):
    return hmac.new(key, (previous + '\n' + payload).encode(), hashlib.sha256).hexdigest()


def append_event(conn, identity, changes):
    row = conn.execute('SELECT sequence, digest FROM security_audit ORDER BY sequence DESC LIMIT 1').fetchone()
    sequence, previous = (row[0] + 1, row[1]) if row else (1, '0' * 64)
    payload = json.dumps({'sequence': sequence, 'tenant': identity.tenant, 'actor': identity.actor,
                          'role': identity.role, 'changed_rows': changes,
                          'created_at': datetime.now(timezone.utc).isoformat(),
                          'request': request_metadata.get(), 'event_id': str(uuid.uuid4())},
                         sort_keys=True, separators=(',', ':'))
    digest = signature(identity.audit_key, previous, payload)
    conn.execute('INSERT INTO security_audit(sequence, payload, previous, digest) VALUES(?,?,?,?)',
                 (sequence, payload, previous, digest))


def verify_chain(conn, key, expected_head=None):
    previous = '0' * 64
    count = 0
    for sequence, payload, parent, digest in conn.execute('SELECT sequence, payload, previous, digest FROM security_audit ORDER BY sequence'):
        count += 1
        if sequence != count or parent != previous or not hmac.compare_digest(digest, signature(key, previous, payload)):
            return {'status': 'invalid', 'first_invalid_sequence': sequence}
        previous = digest
    if expected_head is not None and not hmac.compare_digest(expected_head, previous):
        return {'status': 'anchor_mismatch', 'events': count, 'head': previous}
    return {'status': 'valid', 'events': count, 'head': previous,
            'externally_anchored': expected_head is not None}
