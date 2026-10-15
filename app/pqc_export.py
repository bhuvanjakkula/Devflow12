"""Offline authenticated report exports using library PQC primitives."""
import base64
import hashlib
import hmac
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from pqcrypto.kem import ml_kem_768 as kem
from pqcrypto.sign import ml_dsa_65 as sig

SUITE = 'ML-KEM-768/HKDF-SHA256/AES-256-GCM/ML-DSA-65'
DOMAIN = b'DevFlow-PQC-report-v1\0'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def encode(value):
    return base64.b64encode(value).decode('ascii')


def decode(value, size=None):
    if not isinstance(value, str) or len(value) > 12000000:
        raise ValueError('Invalid encoded field')
    result = base64.b64decode(value, validate=True)
    if size is not None and len(result) != size:
        raise ValueError('Invalid cryptographic field size')
    return result


def key_id(public):
    return hashlib.sha256(canonical(public)).hexdigest()


def validate_public(public):
    if set(public) != {'version', 'kem', 'signature', 'kem_public', 'signature_public'} or public['version'] != 1 or public['kem'] != 'ML-KEM-768' or public['signature'] != 'ML-DSA-65':
        raise ValueError('Unsupported public key format')
    decode(public['kem_public'], kem.PUBLIC_KEY_SIZE)
    decode(public['signature_public'], sig.PUBLIC_KEY_SIZE)


def generate_keys():
    kp, ks = kem.generate_keypair()
    sp, ss = sig.generate_keypair()
    public = {'version': 1, 'kem': 'ML-KEM-768', 'signature': 'ML-DSA-65', 'kem_public': encode(kp), 'signature_public': encode(sp)}
    return public, {'public': public, 'kem_secret': encode(ks), 'signature_secret': encode(ss)}


def password_key(password, salt):
    if len(password) < 16:
        raise ValueError('Use a strong passphrase of at least 16 characters')
    return Scrypt(salt=salt, length=32, n=32768, r=8, p=1).derive(password.encode())


def protect_keys(private, password):
    salt, nonce = os.urandom(16), os.urandom(12)
    header = {'version': 1, 'suite': 'scrypt-32768-8-1/AES-256-GCM', 'salt': encode(salt), 'nonce': encode(nonce)}
    return {'header': header, 'ciphertext': encode(AESGCM(password_key(password, salt)).encrypt(nonce, canonical(private), canonical(header)))}


def unlock_keys(record, password):
    if set(record) != {'header', 'ciphertext'}:
        raise ValueError('Invalid key record')
    header = record['header']
    if set(header) != {'version', 'suite', 'salt', 'nonce'} or header['version'] != 1 or header['suite'] != 'scrypt-32768-8-1/AES-256-GCM':
        raise ValueError('Unsupported key encryption format')
    plain = AESGCM(password_key(password, decode(header['salt'], 16))).decrypt(decode(header['nonce'], 12), decode(record['ciphertext']), canonical(header))
    private = json.loads(plain)
    validate_public(private['public'])
    secret = decode(private['signature_secret'], sig.SECRET_KEY_SIZE)
    challenge = b'DevFlow-key-consistency-v1'
    if not sig.verify(decode(private['public']['signature_public']), challenge, sig.sign(secret, challenge)):
        raise ValueError('Signature key mismatch')
    cipher, shared = kem.encrypt(decode(private['public']['kem_public']))
    if not hmac.compare_digest(shared, kem.decrypt(decode(private['kem_secret'], kem.SECRET_KEY_SIZE), cipher)):
        raise ValueError('KEM key mismatch')
    return private


def report_key(shared, header):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=DOMAIN + canonical(header)).derive(shared)


def seal(report, sender_private, recipient_public):
    validate_public(recipient_public)
    validate_public(sender_private['public'])
    plain = canonical(report)
    if len(plain) > 8000000:
        raise ValueError('Report exceeds 8 MB')
    cipher, shared = kem.encrypt(decode(recipient_public['kem_public'], kem.PUBLIC_KEY_SIZE))
    nonce = os.urandom(12)
    header = {'version': 1, 'suite': SUITE, 'sender_key_id': key_id(sender_private['public']),
              'recipient_key_id': key_id(recipient_public), 'kem_ciphertext': encode(cipher), 'nonce': encode(nonce)}
    body = {'header': header, 'ciphertext': encode(AESGCM(report_key(shared, header)).encrypt(nonce, plain, canonical(header)))}
    return {**body, 'signature': encode(sig.sign(decode(sender_private['signature_secret'], sig.SECRET_KEY_SIZE), DOMAIN + canonical(body)))}


def verify_envelope(record, trusted_sender_public):
    validate_public(trusted_sender_public)
    if set(record) != {'header', 'ciphertext', 'signature'}:
        raise ValueError('Invalid report envelope')
    header = record['header']
    if set(header) != {'version', 'suite', 'sender_key_id', 'recipient_key_id', 'kem_ciphertext', 'nonce'} or header['version'] != 1 or header['suite'] != SUITE:
        raise ValueError('Unsupported report format or suite')
    if header['sender_key_id'] != key_id(trusted_sender_public):
        raise ValueError('Sender is not the pinned trusted key')
    decode(header['kem_ciphertext'], kem.CIPHERTEXT_SIZE)
    decode(header['nonce'], 12)
    decode(record['ciphertext'])
    body = {'header': header, 'ciphertext': record['ciphertext']}
    if not sig.verify(decode(trusted_sender_public['signature_public']), DOMAIN + canonical(body), decode(record['signature'])):
        raise ValueError('Signature verification failed')
    return True


def open_report(record, recipient_private, trusted_sender_public):
    verify_envelope(record, trusted_sender_public)
    header = record['header']
    if header['recipient_key_id'] != key_id(recipient_private['public']):
        raise ValueError('Recipient key mismatch')
    shared = kem.decrypt(decode(recipient_private['kem_secret'], kem.SECRET_KEY_SIZE), decode(header['kem_ciphertext'], kem.CIPHERTEXT_SIZE))
    plain = AESGCM(report_key(shared, header)).decrypt(decode(header['nonce'], 12), decode(record['ciphertext']), canonical(header))
    return json.loads(plain)
