import copy
import pytest

pytest.importorskip('pqcrypto', reason='Install requirements-pqc.txt for real cryptographic tests')
from cryptography.exceptions import InvalidTag
from app.pqc_export import generate_keys, protect_keys, unlock_keys, seal, open_report, verify_envelope, encode, decode


@pytest.fixture(scope='module')
def keys():
    return generate_keys(), generate_keys(), generate_keys()


def test_real_pqc_signed_encrypted_roundtrip(keys):
    (sender_pub, sender), (recipient_pub, recipient), _ = keys
    report = {'project': 'DevFlow', 'findings': ['private audit finding'], 'revision': 8}
    record = seal(report, sender, recipient_pub)
    assert 'private audit finding' not in str(record)
    assert verify_envelope(record, sender_pub)
    assert open_report(record, recipient, sender_pub) == report
    assert seal(report, sender, recipient_pub) != record


@pytest.mark.parametrize('field', ['ciphertext', 'signature', 'kem_ciphertext', 'nonce'])
def test_tampering_fails_verification(keys, field):
    (sender_pub, sender), (recipient_pub, _), _ = keys
    record = seal({'secret': 'audit'}, sender, recipient_pub)
    target = record['header'] if field in {'kem_ciphertext', 'nonce'} else record
    value = bytearray(decode(target[field]))
    value[0] ^= 1
    target[field] = encode(bytes(value))
    with pytest.raises(ValueError):
        verify_envelope(record, sender_pub)


def test_wrong_sender_recipient_and_downgrade_rejected(keys):
    (sender_pub, sender), (recipient_pub, _), (other_pub, other) = keys
    record = seal({'report': 1}, sender, recipient_pub)
    with pytest.raises(ValueError):
        verify_envelope(record, other_pub)
    with pytest.raises(ValueError):
        open_report(record, other, sender_pub)
    downgraded = copy.deepcopy(record)
    downgraded['header']['suite'] = 'RSA'
    with pytest.raises(ValueError):
        verify_envelope(downgraded, sender_pub)


def test_private_keys_encrypted_and_wrong_password_rejected(keys):
    _, private = keys[0]
    password = 'a-long-test-passphrase-012345'
    record = protect_keys(private, password)
    assert private['kem_secret'] not in str(record)
    assert unlock_keys(record, password) == private
    with pytest.raises(InvalidTag):
        unlock_keys(record, password + 'wrong')
    with pytest.raises(ValueError):
        protect_keys(private, 'short')
