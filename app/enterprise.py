"""Opt-in signed identity, operator-provisioned tenancy and bounded service entry."""
import asyncio
from contextvars import ContextVar
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import time
from urllib.parse import urlsplit

from starlette.responses import JSONResponse

principal = ContextVar('devflow_principal', default=None)


def enabled():
    return os.environ.get('DEVFLOW_ENTERPRISE_MODE') == '1'


@dataclass(frozen=True)
class Identity:
    subject: str
    tenant: str
    role: str
    database: Path
    audit_key: bytes = field(default=b'', repr=False)

    @property
    def actor(self):
        return 'oidc:' + hashlib.sha256(self.subject.encode()).hexdigest()


class Configuration:
    def __init__(self, filename):
        import jwt
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
        data = json.loads(Path(filename).read_text(encoding='utf-8'))
        self.issuer = data['issuer']
        self.audience = data['audience']
        self.origin = data['origin']
        for url in [self.issuer, self.origin]:
            parsed = urlsplit(url)
            if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise ValueError('Enterprise issuer and origin must be HTTPS URLs')
        if urlsplit(self.origin).path not in {'', '/'} or self.origin.endswith('/') or not self.audience:
            raise ValueError('Use an origin without a path or trailing slash and a nonempty audience')
        self.host = urlsplit(self.origin).netloc
        self.key = load_pem_public_key(Path(data['public_key']).read_bytes())
        if not isinstance(self.key, RSAPublicKey) or self.key.key_size < 2048:
            raise ValueError('A pinned RSA public key of at least 2048 bits is required')
        root = Path(data['data_root']).resolve()
        self.tenants = {}
        for tenant in data['tenants']:
            if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,62}', tenant):
                raise ValueError('Invalid tenant identifier')
            path = (root / (tenant + '.sqlite3')).resolve()
            if path.parent != root or (root / (tenant + '.sqlite3')).is_symlink():
                raise ValueError('Tenant database must remain within the configured directory')
            self.tenants[tenant] = path
        self.identities = {}
        self.audit_key = Path(data['audit_key']).read_bytes()
        if len(self.audit_key) < 32:
            raise ValueError('Audit HMAC key must contain at least 32 bytes')
        for row in data['identities']:
            subject = row['subject']
            if not isinstance(subject, str) or not 1 <= len(subject) <= 512 or subject in self.identities:
                raise ValueError('Invalid or duplicate identity subject')
            if row['tenant'] not in self.tenants or row['role'] not in {'viewer', 'editor', 'reviewer', 'admin'}:
                raise ValueError('Invalid tenant or role binding')
            self.identities[subject] = Identity(subject, row['tenant'], row['role'], self.tenants[row['tenant']], self.audit_key)
        if not self.tenants or not self.identities:
            raise ValueError('Provision at least one tenant and identity')
        self.max_concurrency = int(data.get('max_concurrency', 8))
        self.requests_per_minute = int(data.get('requests_per_minute', 120))
        if not 1 <= self.max_concurrency <= 64 or not 1 <= self.requests_per_minute <= 10000:
            raise ValueError('Service resource limits are out of range')
        self.jwt = jwt
        self.metrics = {tenant: {'requests': 0, 'server_errors': 0, 'duration_seconds': 0.0} for tenant in self.tenants}
        self.buckets = {}

    def authenticate(self, authorization):
        if not authorization.startswith('Bearer ') or len(authorization) > 16384:
            raise ValueError('Bearer access token required')
        if self.jwt.get_unverified_header(authorization[7:]).get('typ') != 'at+jwt':
            raise ValueError('An RFC 9068 JWT access token is required')
        claims = self.jwt.decode(authorization[7:], self.key, algorithms=['RS256'],
                                 issuer=self.issuer, audience=self.audience,
                                 options={'require': ['exp', 'iat', 'nbf', 'iss', 'aud', 'sub']})
        if not isinstance(claims.get('sub'), str) or claims['sub'] not in self.identities:
            raise ValueError('Identity is not provisioned')
        if not all(isinstance(claims[name], (int, float)) and not isinstance(claims[name], bool) for name in ['exp', 'iat', 'nbf']):
            raise ValueError('Invalid token timestamps')
        if claims['exp'] - claims['iat'] > 3600 or claims['exp'] <= claims['iat']:
            raise ValueError('Access token lifetime exceeds policy')
        return self.identities[claims['sub']]


def actor(entered):
    identity = principal.get()
    return identity.actor if identity else entered


def can_write(identity, path):
    review = path.endswith('/approve') or path.endswith('/review')
    return identity.role in ({'reviewer', 'admin'} if review else {'editor', 'admin'})


class EnterpriseBoundary:
    def __init__(self, app):
        self.app = app
        self.active = 0

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or not enabled():
            return await self.app(scope, receive, send)
        config = getattr(scope['app'].state, 'enterprise', None)
        status = 500

        async def reject(code, detail):
            nonlocal status
            status = code
            await JSONResponse({'detail': detail}, status_code=code,
                               headers={'Cache-Control': 'no-store', 'Retry-After': '60'} if code == 429 else {'Cache-Control': 'no-store'})(scope, receive, send)

        if config is None:
            return await reject(503, 'Enterprise configuration unavailable')
        headers = dict(scope.get('headers', []))
        if any(sum(name == selected for name, _ in scope.get('headers', [])) > 1 for selected in [b'host', b'authorization']):
            return await reject(400, 'Ambiguous security headers')
        if headers.get(b'host', b'').decode('latin1') != config.host or scope.get('scheme') != 'https':
            return await reject(400, 'Configured HTTPS host required')
        if scope['path'].startswith('/owner/'):
            return await reject(404, 'Not found')
        if scope['path'] == '/health/live':
            return await JSONResponse({'status': 'alive'})(scope, receive, send)
        if self.active >= config.max_concurrency:
            return await reject(503, 'Service capacity reached')
        self.active += 1
        context = None
        metadata_context = None
        identity = None
        started = time.monotonic()
        status = 500

        async def measured_send(message):
            nonlocal status
            if message['type'] == 'http.response.start':
                status = message['status']
            await send(message)
        try:
            if scope['path'].startswith('/api/') or scope['path'] == '/openapi.json':
                try:
                    identity = await asyncio.to_thread(config.authenticate, headers.get(b'authorization', b'').decode('latin1'))
                except (ValueError, TypeError, OverflowError, config.jwt.PyJWTError):
                    return await reject(401, 'Valid provisioned enterprise identity required')
                minute = int(time.monotonic() // 60)
                previous_minute, count = config.buckets.get(identity.subject, (minute, 0))
                count = count + 1 if previous_minute == minute else 1
                config.buckets[identity.subject] = (minute, count)
                if count > config.requests_per_minute:
                    return await reject(429, 'Identity request rate exceeded')
                if scope['method'] not in {'GET', 'HEAD', 'OPTIONS'}:
                    if headers.get(b'origin') not in {None, config.origin.encode()}:
                        return await reject(403, 'Cross-origin write rejected')
                    if not can_write(identity, scope['path']):
                        return await reject(403, 'Role does not permit this operation')
                if scope['path'].startswith('/api/ci-evidence/'):
                    return await reject(503, 'Tenant-scoped CI integration is not provisioned; shared provider credentials are unavailable in enterprise mode')
                context = principal.set(identity)
                from app.audit import request_metadata
                metadata_context = request_metadata.set({'method': scope['method'], 'path': scope['path']})
            elif scope['method'] not in {'GET', 'HEAD'}:
                return await reject(403, 'Unsupported operation')
            await self.app(scope, receive, measured_send)
        finally:
            if identity is not None:
                metric = config.metrics[identity.tenant]
                metric['requests'] += 1
                metric['server_errors'] += int(status >= 500)
                metric['duration_seconds'] += time.monotonic() - started
            if context is not None:
                principal.reset(context)
            if metadata_context is not None:
                request_metadata.reset(metadata_context)
            self.active -= 1
