"""Optional local API bearer protection and browser-origin checks."""
import hmac
import importlib.util
import os
from urllib.parse import urlsplit

from fastapi.responses import JSONResponse
from app.owner_access import protect, enabled, install_owner_routes, tunnel_authenticated, valid_local_confirmation, local_request


def install_security(app):
    @app.middleware('http')
    async def boundaries(request, call_next):
        host = request.headers.get('host', '')
        try:
            parsed_host = urlsplit('http://' + host)
            if not parsed_host.hostname or parsed_host.netloc != host or parsed_host.username is not None:
                raise ValueError('Invalid host')
            parsed_host.port  # Validate bracket and port syntax before constructing request URLs.
        except ValueError:
            return JSONResponse({'detail': 'Malformed Host header'}, status_code=400)
        owner_response = protect(request)
        if owner_response is not None:
            return owner_response
        token = os.environ.get('DEVFLOW_API_TOKEN')
        if not enabled() and request.url.path.startswith('/api/') and request.url.path != '/api/docs' and token is not None:
            if len(token) < 32:
                return JSONResponse({'detail': 'API token configuration must contain at least 32 characters'}, status_code=503)
            supplied = request.headers.get('authorization', '')
            if not hmac.compare_digest(supplied.encode(), ('Bearer ' + token).encode()):
                return JSONResponse({'detail': 'API access token required'}, status_code=401, headers={'WWW-Authenticate': 'Bearer'})
        origin = request.headers.get('origin')
        if request.method not in {'GET', 'HEAD', 'OPTIONS'} and origin:
            proto = request.headers.get('x-forwarded-proto') or request.url.scheme
            host_hdr = request.headers.get('x-forwarded-host') or request.headers.get('host', '')
            expected_origin = os.environ.get('DEVFLOW_PUBLIC_ORIGIN', '') if tunnel_authenticated(request) else proto + '://' + host_hdr
            nonce_confirmation = (origin == 'null' and request.url.path == '/owner/confirm'
                                  and request.method == 'POST' and await valid_local_confirmation(request))
            is_valid_local = False
            if local_request(request) and not tunnel_authenticated(request):
                if request.url.path in {'/owner/login', '/owner/instant-enter', '/owner/signup', '/api/support/enquiry'}:
                    is_valid_local = True
                else:
                    try:
                        parsed_orig = urlsplit(origin)
                        parsed_h = urlsplit('http://' + request.headers.get('host', ''))
                        local_hosts = {'127.0.0.1', 'localhost', '::1', '0.0.0.0'}
                        if parsed_orig.hostname in local_hosts and parsed_h.hostname in local_hosts:
                            orig_port = parsed_orig.port or (443 if parsed_orig.scheme == 'https' else 80)
                            h_port = parsed_h.port or (443 if parsed_h.scheme == 'https' else 80)
                            if parsed_orig.scheme in {'http', 'https'}:
                                if orig_port == h_port or orig_port in {80, 8000} or h_port in {80, 8000}:
                                    is_valid_local = True
                    except Exception:
                        is_valid_local = False
            is_same_host = False
            try:
                parsed_orig = urlsplit(origin)
                parsed_exp = urlsplit(expected_origin)
                if parsed_orig.hostname and parsed_exp.hostname and parsed_orig.hostname.lower() == parsed_exp.hostname.lower():
                    is_same_host = True
            except Exception:
                is_same_host = False
            if origin != expected_origin and not nonce_confirmation and not is_valid_local and not is_same_host:
                return JSONResponse({'detail': 'Cross-origin write rejected'}, status_code=403)
        response = await call_next(request)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'no-referrer'
        if request.url.path.startswith('/api/') or response.headers.get('content-type', '').startswith(('text/html', 'text/javascript')):
            response.headers['Cache-Control'] = 'no-store'
        return response

    @app.get('/api/security/status')
    def security_status():
        from app.enterprise import principal
        identity = principal.get()
        return {'api_token_configured': os.environ.get('DEVFLOW_API_TOKEN') is not None,
                'pqc_library_available': importlib.util.find_spec('pqcrypto') is not None,
                'pqc_scope': 'Offline signed and encrypted report exports only',
                'tls_pqc_enabled': False, 'database_encrypted': False,
                'identity_scope': 'Pinned RS256 issuer/audience verification; operator-bound tenant and role; separate tenant databases' if identity else 'Local owner launcher session; email is configured, not verified' if enabled() else 'Optional shared bearer token; no per-user roles or tenant isolation',
                'private_key_web_endpoints': False}

    original_openapi = app.openapi
    def authenticated_schema():
        from app.enterprise import enabled as enterprise_enabled
        schema = original_openapi()
        scheme = 'EnterpriseAccessToken' if enterprise_enabled() else 'OwnerSession' if enabled() else 'DevFlowToken'
        schema.setdefault('components', {}).setdefault('securitySchemes', {})[scheme] = {'type': 'apiKey', 'in': 'cookie', 'name': 'devflow_owner_session'} if enabled() else {'type': 'http', 'scheme': 'bearer'}
        for path, methods in schema['paths'].items():
            if path.startswith('/api/'):
                for method, operation in methods.items():
                    if method in {'get', 'post', 'put', 'patch', 'delete'}:
                        operation['security'] = [{scheme: []}]
        return schema
    app.openapi = authenticated_schema
    install_owner_routes(app)
