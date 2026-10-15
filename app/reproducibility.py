"""Canonical audit envelopes and replay for the restricted numeric model."""
import hashlib
import json
import platform

from app.numeric_verifier import verify_numeric

MODEL_VERSION = 'devflow-numeric-1'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def envelope(source, function, examples):
    result = verify_numeric(source, function, examples)
    contract = {'function': function, 'examples': examples}
    return {'schema_version': 1, 'model_version': MODEL_VERSION, 'python_version': platform.python_version(),
            'source_sha256': hashlib.sha256(source.encode()).hexdigest(), 'contract': contract,
            'contract_sha256': digest(contract), 'result': result, 'result_sha256': digest(result),
            'notice': 'Hashes detect content changes, not authenticity. Replay is scoped to this interpreter and these examples.'}


def replay(source, record):
    if record.get('schema_version') != 1 or record.get('model_version') != MODEL_VERSION:
        return {'status': 'incompatible_model'}
    if hashlib.sha256(source.encode()).hexdigest() != record['source_sha256']:
        return {'status': 'source_mismatch'}
    if digest(record['contract']) != record['contract_sha256'] or digest(record['result']) != record['result_sha256']:
        return {'status': 'record_integrity_mismatch'}
    result = verify_numeric(source, record['contract']['function'], record['contract']['examples'])
    return {'status': 'reproduced' if digest(result) == record['result_sha256'] else 'result_divergence',
            'result': result, 'same_python_version': record.get('python_version') == platform.python_version(),
            'notice': 'No general SMT determinism or cross-platform numerical equivalence is claimed.'}
