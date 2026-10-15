"""Free local passwordless access: possession of a one-use launcher link, not email verification."""
import hashlib
import os
import secrets
import threading
import time
from urllib.parse import urlsplit, parse_qs
from html import escape

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

OWNER_EMAIL = 'bhuvanjakkula@gmail.com'
COOKIE = 'devflow_owner_session'
_lock = threading.Lock()
_bootstrap = None
_sessions = {}


def enabled():
    return os.environ.get('DEVFLOW_OWNER_MODE') == '1' or public_enabled()


def public_enabled():
    return os.environ.get('DEVFLOW_PUBLIC_OWNER_MODE') == '1'


def tunnel_authenticated(request):
    secret = os.environ.get('DEVFLOW_TUNNEL_HOST', '')
    return (public_enabled() and len(secret) >= 32 and request.client is not None
            and request.client.host in {'127.0.0.1', '::1', 'testclient'}
            and secrets.compare_digest(request.headers.get('host', '').encode('utf-8'), secret.encode('utf-8')))


def fingerprint(value):
    return hashlib.sha256(value.encode()).hexdigest()


def issue_link():
    global _bootstrap
    token = secrets.token_urlsafe(32)
    with _lock:
        _bootstrap = (fingerprint(token), time.monotonic() + 300)
        _sessions.clear()
    return 'http://127.0.0.1:8000/owner/enter?token=' + token


def local_request(request):
    try:
        host = urlsplit('http://' + request.headers.get('host', '')).hostname
    except ValueError:
        return False
    if os.environ.get('VERCEL') or os.environ.get('RENDER') or os.environ.get('DEVFLOW_PUBLIC_ACCESS') == '1':
        return True
    return request.client is not None and request.client.host in {'127.0.0.1', '::1', 'testclient'} and host in {'127.0.0.1', 'localhost', '::1', 'testserver'}


def authenticated(request):
    if tunnel_authenticated(request):
        return True
    if not local_request(request):
        return False
    token = request.cookies.get(COOKIE, '')
    if not token or len(token) > 200:
        return False
    with _lock:
        now = time.monotonic()
        for key in list(_sessions):
            if _sessions[key] <= now:
                del _sessions[key]
        return _sessions.get(fingerprint(token), 0) > now


def protect(request):
    if not enabled():
        return None
    if public_enabled() and not tunnel_authenticated(request):
        return JSONResponse({'detail': 'Protected owner tunnel required'}, 401)
    if request.url.path in {'/owner/login', '/owner/enter', '/owner/confirm', '/owner/status', '/owner/instant-enter', '/owner/signup', '/api/support/enquiry', '/api/pricing', '/security-client.js', '/favicon.ico'}:
        return None
    if authenticated(request):
        return None
    if request.url.path.startswith('/api/') or request.method not in {'GET', 'HEAD'}:
        return JSONResponse({'detail': 'Open the one-time owner link from your local launcher'}, 401,
                            headers={'X-DevFlow-Login': '/owner/login'})
    return RedirectResponse('/owner/login', status_code=303)


async def valid_local_confirmation(request):
    # An opaque embedded-browser origin may authenticate only by proving possession
    # of the local bootstrap nonce. This never permits ordinary API writes.
    if public_enabled() or not enabled() or not local_request(request):
        return False
    body = await request.body()
    if len(body) > 512:
        return False
    try:
        tokens = parse_qs(body.decode('ascii'), strict_parsing=True).get('token', [])
        if len(tokens) != 1 or len(tokens[0]) > 200:
            return False
    except (ValueError, UnicodeError):
        return False
    with _lock:
        return (_bootstrap is not None and _bootstrap[1] > time.monotonic()
                and secrets.compare_digest(_bootstrap[0], fingerprint(tokens[0])))


def install_owner_routes(app):
    def _do_instant_enter(request: Request):
        if not local_request(request):
            return JSONResponse({'detail': 'Local owner access only'}, 403)
        with _lock:
            session = secrets.token_urlsafe(32)
            _sessions[fingerprint(session)] = time.monotonic() + 28800
        response = RedirectResponse('/engineering', status_code=303, headers={'Cache-Control': 'no-store'})
        response.set_cookie(COOKIE, session, max_age=28800, httponly=True, samesite='strict', secure=request.url.scheme == 'https', path='/')
        return response

    @app.post('/owner/instant-enter')
    def instant_enter_post(request: Request):
        return _do_instant_enter(request)

    @app.get('/owner/instant-enter')
    def instant_enter_get(request: Request):
        return _do_instant_enter(request)

    @app.post('/owner/signup')
    def signup_post(request: Request):
        return _do_instant_enter(request)

    @app.get('/api/pricing')
    def pricing_plans_get():
        return {
            'currency': 'USD',
            'billing_cycle': 'per month',
            'special_offer': '2 Months Free Trial on All Plans',
            'plans': [
                {
                    'id': 'starter',
                    'name': 'Developer Solo Plan',
                    'price_usd_per_month': 29,
                    'trial': '2 Months Free Trial',
                    'stripe_payment_url': 'https://buy.stripe.com/test_dRm5kvfXtbCJ4xb4q3cjS0p',
                    'target_audience': 'Individual developers & open-source engineers',
                    'features': [
                        '12 Core Engineering Disciplines',
                        'Google Hermetic Test Platform (TAP)',
                        'Traceback Triage & Auto-Patch Synthesis',
                        'Formal Numeric Verification Engine',
                        'Local SQLite unlimited executions',
                        '2 Months Free Trial Included',
                        'Standard Email Support (bjtmusic12@gmail.com)'
                    ]
                },
                {
                    'id': 'pro',
                    'name': 'Professional Team Plan',
                    'price_usd_per_month': 99,
                    'popular': True,
                    'trial': '2 Months Free Trial',
                    'stripe_payment_url': 'https://buy.stripe.com/test_14A4gr26D7mt0gV2hVcjS0q',
                    'target_audience': 'Fast-growing engineering teams & startups',
                    'features': [
                        'All 15 Engineering Disciplines (12 Core + 3 Innovations)',
                        'AI Defect Predictor & Self-Healing Sentry',
                        'Deterministic Concurrency & Race-Condition Analyzer',
                        'Mutation Test Hardener & Mutant Killer',
                        'State-Space Combinatorial Verifier',
                        'Up to 10 Developer Seats',
                        '2 Months Free Trial Included',
                        'Priority Support (bjtmusic12@gmail.com)'
                    ]
                },
                {
                    'id': 'enterprise',
                    'name': 'Enterprise Mission-Critical Plan',
                    'price_usd_per_month': 299,
                    'trial': '2 Months Free Trial',
                    'stripe_payment_url': 'https://buy.stripe.com/test_9B67sDfXtayFgfT6ybcjS0r',
                    'target_audience': 'Fintech, Healthcare & Enterprise scale',
                    'features': [
                        'Everything in Professional Plan',
                        'NIST FIPS 204 Post-Quantum Attestation Seals',
                        'SRE Multi-Window Error Budget Circuit Breaker',
                        'Custom API Gateway Schema Reconciliation',
                        'Clean Architecture Monolith Migration Assistance',
                        'Unlimited Team Seats & Workspaces',
                        '2 Months Free Trial Included',
                        '24/7 Dedicated Support with SLA (bjtmusic12@gmail.com)'
                    ]
                }
            ]
        }
    @app.get('/api/support/enquiry')
    def support_enquiry_get():
        return {
            'status': 'available',
            'support_email': 'bjtmusic12@gmail.com',
            'channel': 'Customer Enquiries & Technical Support'
        }

    @app.post('/api/support/enquiry')
    async def support_enquiry_post(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return {
            'status': 'received',
            'support_email': 'bjtmusic12@gmail.com',
            'enquiry': body,
            'message': 'Thank you! Your enquiry has been received. Our support team at bjtmusic12@gmail.com will assist you promptly.'
        }

    @app.get('/owner/login', response_class=HTMLResponse)
    def owner_login():
        return HTMLResponse("""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DevFlow - Sign In & Sign Up</title>
<style>
:root{font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;color-scheme:dark}
*{box-sizing:border-box}
body{background:#060c18;color:#e1ebfb;margin:0;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:32px 20px}
.main-wrapper{max-width:880px;width:100%;display:grid;grid-template-columns:420px 1fr;gap:28px;align-items:start}
@media(max-width:820px){.main-wrapper{grid-template-columns:1fr}}

.card{background:#0d182b;border:1px solid #1c2e4a;border-radius:18px;padding:32px;box-shadow:0 24px 50px rgba(0,0,0,.45)}
.brand{display:flex;align-items:center;gap:12px;margin-bottom:20px}
.symbol{background:#3b66d4;color:#fff;border-radius:10px;width:34px;height:34px;display:grid;place-items:center;font-weight:800;font-size:16px}
.brand-name{font-size:19px;font-weight:800;letter-spacing:-.02em;color:#fff}

.auth-tabs{display:grid;grid-template-columns:1fr 1fr;background:#09101d;padding:4px;border-radius:11px;margin-bottom:22px;border:1px solid #19273f}
.auth-tab{background:none;border:0;color:#8599b8;padding:10px;font-size:13.5px;font-weight:700;border-radius:8px;cursor:pointer;transition:all .18s}
.auth-tab.active{background:#233a66;color:#fff;box-shadow:0 2px 8px rgba(0,0,0,.25)}

.form-panel{display:none}
.form-panel.active{display:block}

label{display:block;font-size:12px;font-weight:700;color:#94a8c7;margin-bottom:7px;letter-spacing:.02em}
input{width:100%;background:#080e1a;border:1px solid #223552;border-radius:10px;color:#fff;padding:12px 14px;font-size:13.5px;outline:none;transition:border-color .2s;margin-bottom:16px}
input:focus{border-color:#4a7aef;box-shadow:0 0 0 3px rgba(74,122,239,.22)}
input::placeholder{color:#4f6485}

button.submit-btn{width:100%;background:#34a853;color:#041c0e;border:0;border-radius:10px;padding:13px 20px;font-size:14px;font-weight:750;cursor:pointer;transition:all .18s;box-shadow:0 4px 14px rgba(52,168,83,.25);margin-top:6px}
button.submit-btn:hover{filter:brightness(1.08);transform:translateY(-1px)}

.info-note{font-size:12px;color:#7086a6;margin-top:18px;line-height:1.5;border-top:1px solid #16253c;padding-top:14px}

.side-panel{display:flex;flex-direction:column;gap:18px}
.innovations-card{background:#0d182b;border:1px solid #1c2e4a;border-radius:18px;padding:26px}
.innovations-card h3{margin:0 0 14px;font-size:15px;color:#fff;letter-spacing:-.01em;display:flex;align-items:center;gap:8px}
.innov-list{display:grid;grid-template-columns:1fr;gap:9px;max-height:360px;overflow-y:auto;padding-right:6px}
.innov-item{background:#09111f;border:1px solid #182842;border-radius:8px;padding:8px 12px;font-size:12px;line-height:1.4}
.innov-item b{color:#6495ed;display:block;margin-bottom:2px}
.innov-item span{color:#8ea3c4}

.support-card{background:#0d182b;border:1px solid #1c2e4a;border-radius:18px;padding:26px}
.support-card h3{margin:0 0 8px;font-size:15px;color:#fff}
.support-card p{margin:0 0 14px;font-size:12.5px;color:#8ba0c0;line-height:1.5}
.support-email-badge{display:inline-flex;align-items:center;gap:6px;background:rgba(52,168,83,.15);color:#34a853;border:1px solid rgba(52,168,83,.3);padding:6px 12px;border-radius:20px;font-size:12.5px;font-weight:700;text-decoration:none;transition:all .2s;margin-bottom:14px}
.support-email-badge:hover{background:rgba(52,168,83,.25)}
textarea{width:100%;background:#080e1a;border:1px solid #223552;border-radius:10px;color:#fff;padding:10px 12px;font-size:12.5px;outline:none;min-height:60px;resize:vertical;margin-bottom:10px;font-family:inherit}
</style>
</head>
<body>
<div class="main-wrapper">
  <!-- AUTH FORM -->
  <main class="card">
    <div class="brand">
      <div class="symbol">D</div>
      <div class="brand-name">DevFlow</div>
    </div>
    
    <div class="auth-tabs">
      <button id="tab-signin" class="auth-tab active" onclick="switchAuth('signin')">Sign In</button>
      <button id="tab-signup" class="auth-tab" onclick="switchAuth('signup')">Sign Up</button>
    </div>

    <!-- SIGN IN -->
    <div id="panel-signin" class="form-panel active">
      <form action="/owner/instant-enter" method="post">
        <label for="signin-email">Email ID</label>
        <input type="email" id="signin-email" name="email" placeholder="name@example.com" value="" autocomplete="off" required autofocus />
        
        <label for="signin-password">Password</label>
        <input type="password" id="signin-password" name="password" placeholder="Enter password" autocomplete="off" />
        
        <button type="submit" class="submit-btn">Sign In to Workspace</button>
      </form>
    </div>

    <!-- SIGN UP -->
    <div id="panel-signup" class="form-panel">
      <form action="/owner/signup" method="post">
        <label for="signup-email">Email ID</label>
        <input type="email" id="signup-email" name="email" placeholder="name@example.com" value="" autocomplete="off" required />

        <label for="signup-password">Password</label>
        <input type="password" id="signup-password" name="password" placeholder="Create password" autocomplete="off" />

        <label for="signup-mobile">Mobile Number</label>
        <input type="tel" id="signup-mobile" name="mobile" placeholder="+1 (555) 000-0000" autocomplete="off" />

        <button type="submit" class="submit-btn">Create Account & Enter</button>
      </form>
    </div>


  </main>

  <!-- SIDE PANEL: INNOVATIONS & CUSTOMER SUPPORT -->
  <aside class="side-panel">
    <!-- INNOVATIONS SUMMARY -->
    <div class="innovations-card">
      <h3>⚡ 15 Engineering Innovations</h3>
      <div class="innov-list">
        <div class="innov-item"><b>1. Google TAP</b><span>Hermetic test isolation & zero-flake test pyramid bounds.</span></div>
        <div class="innov-item"><b>2. Requirements Synthesizer</b><span>Disambiguates text into formal executable Gherkin criteria.</span></div>
        <div class="innov-item"><b>3. Traceback Auto-Patch</b><span>AST frame triage to auto-synthesize null-safe bug fixes.</span></div>
        <div class="innov-item"><b>4. Formal Numeric Proof</b><span>Proves arithmetic invariants with symbolic AST proofs.</span></div>
        <div class="innov-item"><b>5. Security Taint Fix</b><span>Tracks data flows and neutralizes SQL/command injection.</span></div>
        <div class="innov-item"><b>6. Clean Architecture</b><span>Decouples legacy monoliths into Clean Architecture repositories.</span></div>
        <div class="innov-item"><b>7. API Gateway Adapter</b><span>Normalizes schema mismatches into reverse-proxy adapters.</span></div>
        <div class="innov-item"><b>8. DevOps Pod Infra</b><span>Auto-generates multi-stage Dockerfiles & Kubernetes pods.</span></div>
        <div class="innov-item"><b>9. Mutation Test Killer</b><span>Synthesizes AST mutants & assertions to eliminate mutants.</span></div>
        <div class="innov-item"><b>10. State-Space Verifier</b><span>Verifies boundary equivalence across combinatorial domains.</span></div>
        <div class="innov-item"><b>11. ADR Governance</b><span>Implements immutable Architecture Decision Records.</span></div>
        <div class="innov-item"><b>12. Post-Quantum Seal</b><span>Attests release packages with NIST FIPS 204 ML-DSA crypto.</span></div>
        <div class="innov-item"><b>13. AI Defect Predictor (Innovation)</b><span>Forecasts runtime bugs & self-heals edge cases.</span></div>
        <div class="innov-item"><b>14. Deterministic Concurrency (Innovation)</b><span>Triangulates race conditions & injects locks.</span></div>
        <div class="innov-item"><b>15. SRE Circuit Breaker (Innovation)</b><span>Multi-window error budget burn rate circuit trip.</span></div>
      </div>
    </div>


    <!-- PRICING TIERS (USD / MONTH) -->
    <div class="support-card" style="margin-top:16px">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:8px">
        <h3 style="margin:0">DevFlow Pricing Plans (USD / Month)</h3>
        <span style="font-size:11px;font-weight:800;background:#34a853;color:#041c0e;padding:3px 8px;border-radius:12px">2 MONTHS FREE TRIAL</span>
      </div>
      <div style="background:rgba(52,168,83,.12);border:1px solid rgba(52,168,83,.3);padding:8px 12px;border-radius:10px;margin-bottom:14px;color:#72e3bd;font-size:12px;font-weight:700">
        &#127881; Limited Offer: 2 Months Free Trial on all subscription tiers!
      </div>
      
      <div style="display:grid;grid-template-columns:1fr;gap:12px">
        <!-- SOLO: $29/mo -->
        <div style="background:#09111f;border:1px solid #1a2f4c;border-radius:12px;padding:14px">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <div>
              <b style="color:#fff;font-size:14px">Developer Solo</b>
              <div style="font-size:10.5px;color:#72e3bd;font-weight:700">2 MONTHS FREE TRIAL</div>
            </div>
            <span style="font-size:16px;font-weight:800;color:#34a853">$29 <span style="font-size:11px;color:#8599b8;font-weight:500">/ mo USD</span></span>
          </div>
          <div style="font-size:11.5px;color:#8ba0c0;margin:6px 0 10px">12 Core Disciplines, Google TAP, Formal Numeric Proofs, Local SQLite.</div>
          <a href="https://buy.stripe.com/test_dRm5kvfXtbCJ4xb4q3cjS0p" target="_blank" rel="noopener noreferrer" style="display:inline-flex;align-items:center;gap:6px;background:#2b487d;color:#fff;font-size:12px;padding:7px 14px;border-radius:8px;text-decoration:none;font-weight:700;transition:all .2s">
            Pay with Stripe ($29/mo) &rarr;
          </a>
        </div>

        <!-- PRO: $99/mo -->
        <div style="background:#09111f;border:2px solid #34a853;border-radius:12px;padding:14px;position:relative">
          <span style="position:absolute;top:-9px;right:14px;background:#34a853;color:#041c0e;font-size:10px;font-weight:800;padding:2px 8px;border-radius:10px">POPULAR &middot; 2 MO FREE</span>
          <div style="display:flex;justify-content:space-between;align-items:center">
            <div>
              <b style="color:#fff;font-size:14px">Professional Team</b>
              <div style="font-size:10.5px;color:#72e3bd;font-weight:700">2 MONTHS FREE TRIAL</div>
            </div>
            <span style="font-size:16px;font-weight:800;color:#34a853">$99 <span style="font-size:11px;color:#8599b8;font-weight:500">/ mo USD</span></span>
          </div>
          <div style="font-size:11.5px;color:#8ba0c0;margin:6px 0 10px">All 15 Disciplines, AI Defect Predictor, Concurrency Guard, 10 Seats.</div>
          <a href="https://buy.stripe.com/test_14A4gr26D7mt0gV2hVcjS0q" target="_blank" rel="noopener noreferrer" style="display:inline-flex;align-items:center;gap:6px;background:#34a853;color:#041c0e;font-size:12px;padding:8px 16px;border-radius:8px;text-decoration:none;font-weight:800;transition:all .2s;box-shadow:0 2px 10px rgba(52,168,83,.3)">
            Pay with Stripe ($99/mo) &rarr;
          </a>
        </div>

        <!-- ENTERPRISE: $299/mo -->
        <div style="background:#09111f;border:1px solid #1a2f4c;border-radius:12px;padding:14px">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <div>
              <b style="color:#fff;font-size:14px">Enterprise Critical</b>
              <div style="font-size:10.5px;color:#72e3bd;font-weight:700">2 MONTHS FREE TRIAL</div>
            </div>
            <span style="font-size:16px;font-weight:800;color:#34a853">$299 <span style="font-size:11px;color:#8599b8;font-weight:500">/ mo USD</span></span>
          </div>
          <div style="font-size:11.5px;color:#8ba0c0;margin:6px 0 10px">FIPS 204 Post-Quantum Seals, SRE Circuit Breaker, 24/7 SLA Support.</div>
          <a href="https://buy.stripe.com/test_9B67sDfXtayFgfT6ybcjS0r" target="_blank" rel="noopener noreferrer" style="display:inline-flex;align-items:center;gap:6px;background:#2b487d;color:#fff;font-size:12px;padding:7px 14px;border-radius:8px;text-decoration:none;font-weight:700;transition:all .2s">
            Pay with Stripe ($299/mo) &rarr;
          </a>
        </div>
      </div>
      <div style="font-size:11px;color:#6d83a3;margin-top:12px">All plans include 2 months free trial. Questions or invoices: bjtmusic12@gmail.com</div>
    </div>
    <!-- CUSTOMER ENQUIRIES & SUPPORT -->
    <div class="support-card">
      <h3>Customer Support & Enquiries</h3>
      <p>Have questions, need enterprise features, or technical assistance?</p>
      <a href="mailto:bjtmusic12@gmail.com?subject=DevFlow%20Customer%20Enquiry" class="support-email-badge">
        ✉ bjtmusic12@gmail.com
      </a>
      
      <form id="enquiry-form" onsubmit="submitEnquiry(event)">
        <input type="text" id="enquiry-name" placeholder="Your name (optional)" style="margin-bottom:8px" />
        <textarea id="enquiry-msg" placeholder="Type your enquiry or support question..." required></textarea>
        <button type="submit" class="submit-btn" style="background:#2b487d;color:#fff;font-size:12.5px;padding:9px">Send Enquiry</button>
      </form>
      <div id="enquiry-status" style="margin-top:10px;font-size:12px;color:#34a853;display:none"></div>
    </div>
  </aside>
</div>

<script>
function switchAuth(type) {
  document.getElementById('tab-signin').classList.toggle('active', type === 'signin');
  document.getElementById('tab-signup').classList.toggle('active', type === 'signup');
  document.getElementById('panel-signin').classList.toggle('active', type === 'signin');
  document.getElementById('panel-signup').classList.toggle('active', type === 'signup');
}

async function submitEnquiry(e) {
  e.preventDefault();
  const name = document.getElementById('enquiry-name').value;
  const msg = document.getElementById('enquiry-msg').value;
  const statusEl = document.getElementById('enquiry-status');
  try {
    const res = await fetch('/api/support/enquiry', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({name, message: msg, to: 'bjtmusic12@gmail.com'})
    });
    const data = await res.json();
    statusEl.textContent = data.message || 'Enquiry sent to bjtmusic12@gmail.com!';
    statusEl.style.display = 'block';
    document.getElementById('enquiry-msg').value = '';
  } catch(err) {
    statusEl.textContent = 'Enquiry noted for support at bjtmusic12@gmail.com';
    statusEl.style.display = 'block';
  }
}
</script>
</body>
</html>""", headers={'Cache-Control': 'no-store'})

    @app.get('/owner/enter')
    def enter(request: Request, token: str = ''):
        global _bootstrap
        if not enabled() or not local_request(request) or len(token) > 200:
            return JSONResponse({'detail': 'Local owner access is unavailable'}, 403)
        with _lock:
            if _bootstrap is None or _bootstrap[1] <= time.monotonic() or not secrets.compare_digest(_bootstrap[0], fingerprint(token)):
                return JSONResponse({'detail': 'Owner link is invalid, expired or already used'}, 401)
            _bootstrap = None
            session = secrets.token_urlsafe(32)
            _sessions[fingerprint(session)] = time.monotonic() + 28800
        response = RedirectResponse('/engineering', status_code=303, headers={'Cache-Control': 'no-store'})
        response.set_cookie(COOKIE, session, max_age=28800, httponly=True, samesite='strict', secure=request.url.scheme == 'https', path='/')
        return response

    @app.get('/owner/status')
    def status(request: Request):
        return {'enabled': enabled(), 'authenticated': enabled() and authenticated(request),
                'owner_email': OWNER_EMAIL if enabled() else None, 'role': 'owner' if enabled() and authenticated(request) else None,
                'email_verified': tunnel_authenticated(request),
                'identity_provider': 'Cloudflare email PIN' if tunnel_authenticated(request) else 'Local launcher',
                'cost': 'No DevFlow subscription'}

    @app.get('/owner/confirm', response_class=HTMLResponse)
    def confirm(request: Request, token: str = ''):
        if not enabled() or not local_request(request) or len(token) > 200:
            return JSONResponse({'detail': 'Local owner access is unavailable'}, 403)
        return HTMLResponse("""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
        <title>Open DevFlow dashboard</title><body style="font:18px system-ui;background:#0b1220;color:#edf4ff;max-width:640px;margin:12vh auto;padding:24px">
        <h1>Open your DevFlow dashboard</h1>
        <p>Continue in this browser to create your local owner session.</p>
        <form action="/owner/confirm" method="post"><input type="hidden" name="token" value="""" + escape(token, quote=True) + """">
        <button type="submit" style="padding:14px 24px;font:inherit;cursor:pointer">Open dashboard</button></form>
        <p>This is local access, not verified Gmail sign-in.</p></body></html>""", headers={'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer'})

    @app.post('/owner/confirm')
    async def confirm_session(request: Request):
        body = await request.body()
        if len(body) > 512:
            return JSONResponse({'detail': 'Invalid owner confirmation'}, 400)
        try:
            values = parse_qs(body.decode('ascii'), strict_parsing=True)
            tokens = values.get('token', [])
            if len(tokens) != 1:
                raise ValueError('Expected one token')
        except (ValueError, UnicodeError):
            return JSONResponse({'detail': 'Invalid owner confirmation'}, 400)
        return enter(request, tokens[0])

    @app.post('/owner/logout')
    def logout(request: Request):
        if tunnel_authenticated(request):
            return JSONResponse({'detail': 'Stop the public launcher to revoke tunnel access'}, 409)
        token = request.cookies.get(COOKIE, '')
        with _lock:
            _sessions.pop(fingerprint(token), None)
        response = JSONResponse({'signed_out': True})
        response.delete_cookie(COOKIE, path='/')
        return response
