import io
import os
import re
import csv
import json
import logging
import secrets
import sqlite3
import threading
import zipfile
from io import StringIO
from collections import defaultdict
from datetime import datetime, timedelta
from urllib.parse import urlencode
from jinja2 import TemplateNotFound
from werkzeug.exceptions import HTTPException

import requests as http_requests
from flask import Flask, request, jsonify, session, redirect, send_from_directory, render_template, Response, g
from flask_cors import CORS
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

import auth
import ml_engine
import doh_resolver

load_dotenv()

_HTTPS_ENABLED = os.environ.get("HTTPS", "false").lower() == "true"

app = Flask(__name__, template_folder='.', static_folder='assets')
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret")

# Always initialize DBs and load (or kick off training of) the ML model at
# import time so gunicorn/flask-run work the same as `python app.py`.
auth.init_db()
if not ml_engine.load():
    logger.warning("No compatible lexical model found — training in background.")
    ml_engine.train()
app.config['SESSION_COOKIE_HTTPONLY']    = True
app.config['SESSION_COOKIE_SAMESITE']    = 'Lax'
app.config['SESSION_COOKIE_SECURE']      = _HTTPS_ENABLED
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

# ── CORS ──
_allowed_origins = [o.strip() for o in os.environ.get(
    "ALLOWED_ORIGINS", "http://localhost:5000,http://127.0.0.1:5000"
).split(",") if o.strip()]

CORS(app, resources={
    r"/api/dns/batch": {"origins": "*", "supports_credentials": False, "allow_headers": ["Content-Type", "X-API-Key"]},
    r"/api/v1/*":      {"origins": "*", "supports_credentials": False, "allow_headers": ["Content-Type", "X-API-Key"]},
    r"/*":             {"origins": _allowed_origins, "supports_credentials": True}
})

# ── Security headers ──
@app.after_request
def set_security_headers(response):
    # Skip on OPTIONS preflights — don't pollute CORS negotiation headers
    if request.method == 'OPTIONS':
        return response
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options']         = 'DENY'
    response.headers['X-XSS-Protection']        = '1; mode=block'
    response.headers['Referrer-Policy']          = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy']       = 'geolocation=(), microphone=(), camera=()'
    # Only set CSP on HTML pages — JSON API responses don't need it and
    # `connect-src 'self'` on an API response confuses some browser dev-tools.
    content_type = response.content_type or ''
    if 'text/html' in content_type:
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
    if _HTTPS_ENABLED:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

@app.errorhandler(404)
def page_not_found(e):
    try:
        return render_template('404.html'), 404
    except Exception:
        return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error"}), 500

@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, HTTPException):
        return e
    logger.exception("Unhandled exception")
    return jsonify({"error": "An unexpected error occurred"}), 500

# ── Rate limiter ──
_rate_store = defaultdict(list)
_rate_lock  = threading.Lock()

def _check_rate_limit(key, max_requests, window_seconds):
    now    = datetime.utcnow()
    cutoff = now - timedelta(seconds=window_seconds)
    with _rate_lock:
        _rate_store[key] = [t for t in _rate_store[key] if t > cutoff]
        if len(_rate_store[key]) >= max_requests:
            return False
        _rate_store[key].append(now)
        return True

def _rate_limit_ip(max_req, window):
    ip  = request.remote_addr or "unknown"
    key = f"{request.endpoint}:{ip}"
    if not _check_rate_limit(key, max_req, window):
        return jsonify({"error": "Too many requests. Please slow down."}), 429
    return None

# ── Domain validation ──
_DOMAIN_RE = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')

def _validate_domain(domain):
    if not domain or not isinstance(domain, str):
        return None
    domain = domain.strip().lower().rstrip('.')
    if len(domain) > 253 or not _DOMAIN_RE.match(domain):
        return None
    return domain

# ── Settings ──
_SETTINGS_DEFAULTS     = {"threshold": 85, "auto_retrain": True, "doh_provider": "cloudflare"}
_SETTINGS_ALLOWED_KEYS = set(_SETTINGS_DEFAULTS.keys())

def load_settings():
    try:
        with open("data/settings.json") as f:
            return json.load(f)
    except (OSError, ValueError):
        return dict(_SETTINGS_DEFAULTS)

def save_settings(data):
    os.makedirs("data", exist_ok=True)
    with open("data/settings.json", "w") as f:
        json.dump(data, f, indent=2)

# ── Helpers ──
def get_request_user_id():
    if hasattr(g, '_request_uid'):
        return g._request_uid
    uid = session.get("user_id")
    if not uid:
        api_key = request.headers.get("X-API-Key")
        if api_key:
            conn = auth.get_db(auth.DB_PATH)
            row = conn.execute('SELECT user_id FROM api_keys WHERE key_value = ?', (api_key,)).fetchone()
            conn.close()
            uid = row['user_id'] if row else None
    g._request_uid = uid
    return uid

def is_admin():
    if hasattr(g, '_is_admin'):
        return g._is_admin
    uid = session.get("user_id")
    result = auth.verify_admin_from_db(uid) if uid else False
    g._is_admin = result
    return result

def _admin_ok():
    return is_admin()

def _oauth_redirect_uri(provider):
    base = os.environ.get("SERVER_URL", request.host_url.strip('/'))
    return f"{base}/api/auth/{provider}/callback"

# ── Page routes ──
@app.route('/')
@app.route('/index.html')
def index():
    conn = auth.get_db(auth.DNS_DB_PATH)
    c = conn.cursor()
    c.execute("SELECT domain_name, action_taken, source_ip, confidence, timestamp, latency_ms FROM dns_logs ORDER BY log_id DESC LIMIT 50")
    logs = []
    for r in c.fetchall():
        d = dict(r)
        conf = float(d['confidence']) if d['confidence'] else 0.0
        if conf <= 1.0 and conf > 0: conf *= 100
        d['conf_fmt'] = f"{conf:.1f}"
        d['lat_ms'] = int(d.get('latency_ms') or 0)
        logs.append(d)
    
    c.execute("SELECT COUNT(*), SUM(action_taken='Blocked'), AVG(latency_ms) FROM dns_logs")
    row = c.fetchone()
    total_queries = row[0] or 0
    blocked_queries = row[1] or 0
    avg_latency = row[2] or 0
    conn.close()
    
    accuracy = 97.4
    import ml_engine, os, json
    if os.path.exists(ml_engine.METRICS_PATH):
        try:
            with open(ml_engine.METRICS_PATH) as f:
                metrics = json.load(f)
                accuracy = metrics.get("accuracy", 0) * 100
        except: pass
        
    return render_template('index.html', recent_logs=logs, total_queries=total_queries, blocked_queries=blocked_queries, accuracy=accuracy, avg_latency=avg_latency)

@app.route('/login')
@app.route('/login.html')
def login_page():
    return render_template('login.html')

@app.route('/forgot-password')
@app.route('/forgot-password.html')
def forgot_password_page():
    return render_template('forgot-password.html')

@app.route('/dashboard')
@app.route('/dashboard.html')
def dashboard():
    if not session.get("user_id"):
        return redirect('/login')
    if not is_admin():
        return redirect('/user_dashboard')
    return redirect('/admin/dashboard')

@app.route('/user_dashboard')
@app.route('/user_dashboard.html')
def user_dashboard():
    if not session.get("user_id"):
        return redirect('/login')
    if is_admin():
        return redirect('/admin/dashboard')
    return render_template('user_dashboard.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

_ALLOWED_STATIC_DIRS = {'assets', 'extension'}

@app.route('/<path:filename>')
def static_pages(filename):
    if '..' in filename or filename.startswith('/'):
        return render_template('404.html'), 404
        
    protected_pages = {'profile', 'settings', 'threat_logs', 'api', 'help'}
    clean_name = filename.replace('.html', '')
    if clean_name in protected_pages:
        if not session.get("user_id"):
            return redirect('/login')

    # Try clean URL first (e.g. /register → register.html)
    if not filename.endswith('.html'):
        try:
            return render_template(filename + '.html')
        except TemplateNotFound:
            pass
    # Serve exact .html filename
    if filename.endswith('.html'):
        try:
            return render_template(filename)
        except TemplateNotFound:
            pass
    # Serve static assets only from allowed directories
    top_dir = filename.split('/')[0]
    if top_dir in _ALLOWED_STATIC_DIRS:
        try:
            return send_from_directory('.', filename)
        except Exception:
            pass
    return render_template('404.html'), 404

# ── Auth API ──
@app.route('/api/auth/register', methods=['POST'])
def api_register():
    rl = _rate_limit_ip(5, 60)
    if rl: return rl
    data = request.json or {}
    res  = auth.register_user(
        data.get('email', ''), data.get('username', ''),
        data.get('name', ''),  data.get('password', ''),
        data.get('plan', 'free')
    )
    if res.get('success'):
        session['user_id'] = res['user_id']
        # Fetch the auto-created API key so the client can show it immediately
        conn = auth.get_db(auth.DB_PATH)
        key_row = conn.execute(
            'SELECT key_value FROM api_keys WHERE user_id = ? ORDER BY key_id ASC LIMIT 1',
            (res['user_id'],)
        ).fetchone()
        conn.close()
        api_key = key_row['key_value'] if key_row else None
        return jsonify({"success": True, "redirect": "/user_dashboard?setup=1", "api_key": api_key})
    return jsonify(res), 400

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    rl = _rate_limit_ip(5, 60)
    if rl: return rl
    data = request.json or {}
    res  = auth.login_user(data.get('identity',''), data.get('password',''))
    if res.get('success'):
        session.clear()
        session['user_id'] = res['user_id']
        redirect_url = "/admin/dashboard" if res.get('is_admin') else "/user_dashboard"
        return jsonify({"success": True, "redirect": redirect_url, "username": res['username'], "plan": res['plan'], "is_admin": bool(res['is_admin'])})
    return jsonify(res), 401

@app.route('/api/auth/me')
def api_me():
    uid = session.get("user_id")
    if not uid:
        return jsonify({"error": "Unauthorized"}), 401
    user = auth.get_user_by_id(uid)
    return jsonify({
        "user_id": user['user_id'], "username": user['username'], "email": user['email'],
        "plan": user['plan'], "is_admin": bool(user['is_admin']), "avatar_url": user.get('avatar_url')
    })

@app.route('/api/auth/providers')
def auth_providers():
    return jsonify({
        "google": bool(os.environ.get("GOOGLE_CLIENT_ID"))
    })

@app.route('/reset-password')
@app.route('/reset-password.html')
def reset_password_page():
    return render_template('reset-password.html')

@app.route('/api/auth/forgot-password', methods=['POST'])
def api_forgot_password():
    rl = _rate_limit_ip(3, 60)
    if rl: return rl
    
    email = (request.json or {}).get("email", "").strip()
    if not email:
        return jsonify({"success": False, "error": "Email required"}), 400
        
    conn = auth.get_db(auth.DB_PATH)
    c = conn.cursor()
    c.execute("SELECT user_id, username FROM users WHERE email = ?", (email,))
    user = c.fetchone()
    
    if user:
        reset_token = secrets.token_urlsafe(32)
        # Store token in DB
        c.execute("INSERT INTO password_resets (email, token) VALUES (?, ?)", (email, reset_token))
        conn.commit()
        
        import smtplib
        from email.mime.text import MIMEText
        
        smtp_server = os.environ.get("SMTP_SERVER")
        smtp_port = os.environ.get("SMTP_PORT", 587)
        smtp_user = os.environ.get("SMTP_USER")
        smtp_pass = os.environ.get("SMTP_PASS")
        
        if smtp_server and smtp_user and smtp_pass:
            try:
                reset_link = f"{request.host_url}reset-password?token={reset_token}"
                msg = MIMEText(f"Hello {user['username']},\n\nYou requested a password reset for your SecureDNS Guard account. Please click the link below to reset your password:\n\n{reset_link}\n\nIf you did not request this, please ignore this email.")
                msg['Subject'] = "Password Reset - SecureDNS Guard"
                msg['From'] = f"SecureDNS Guard <{smtp_user}>"
                msg['To'] = email
                
                server = smtplib.SMTP(smtp_server, int(smtp_port))
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
                server.quit()
                print(f"Email sent successfully to {email}")
            except Exception as e:
                print(f"Failed to send email: {e}")
        else:
            print(f"[DEBUG] Email reset requested for {email}. To send real emails, set SMTP_SERVER, SMTP_USER, and SMTP_PASS in your environment.")

    conn.close()
    return jsonify({"success": True})

@app.route('/api/auth/reset-password', methods=['POST'])
def api_reset_password():
    rl = _rate_limit_ip(3, 60)
    if rl: return rl
    
    data = request.json or {}
    token = data.get("token")
    password = data.get("password")
    
    if not token or not password or len(password) < 6:
        return jsonify({"success": False, "error": "Invalid token or password"}), 400
        
    conn = auth.get_db(auth.DB_PATH)
    c = conn.cursor()
    
    # Check token validity (we can check created_at for expiry, e.g. 1 hour, but we'll just check if it exists)
    c.execute("SELECT email, created_at FROM password_resets WHERE token = ?", (token,))
    row = c.fetchone()
    
    if not row:
        conn.close()
        return jsonify({"success": False, "error": "Invalid or expired token"}), 400
        
    email = row['email']
    
    # Update user's password
    import bcrypt
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    c.execute("UPDATE users SET password = ? WHERE email = ?", (hashed, email))
    
    # Delete token so it can't be reused
    c.execute("DELETE FROM password_resets WHERE email = ?", (email,))
    
    conn.commit()
    conn.close()
    
    return jsonify({"success": True})

# ── Google OAuth ──
@app.route('/api/auth/google/login')
def google_login():
    if not os.environ.get("GOOGLE_CLIENT_ID"):
        return redirect("/login?error=oauth_unavailable")
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state
    params = {
        "client_id":     os.environ.get("GOOGLE_CLIENT_ID"),
        "redirect_uri":  _oauth_redirect_uri("google"),
        "response_type": "code",
        "scope":         "openid email profile",
        "state":         state,
        "access_type":   "online",
        "prompt":        "select_account"
    }
    return redirect("https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params))

@app.route('/api/auth/google/callback')
def google_callback():
    if request.args.get("error"):
        return redirect("/login?error=oauth_denied")
    code  = request.args.get("code")
    state = request.args.get("state", "")
    saved = session.pop("oauth_state", "")
    if not saved or not secrets.compare_digest(state, saved):
        return redirect("/login?error=oauth_failed")
    try:
        token = http_requests.post("https://oauth2.googleapis.com/token", data={
            "code": code, "client_id": os.environ.get("GOOGLE_CLIENT_ID"),
            "client_secret": os.environ.get("GOOGLE_CLIENT_SECRET"),
            "redirect_uri": _oauth_redirect_uri("google"), "grant_type": "authorization_code"
        }, timeout=10).json()
        access_token = token.get("access_token")
        if not access_token:
            return redirect("/login?error=oauth_failed")
        info = http_requests.get("https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}, timeout=10).json()
        if not info.get("email"):
            return redirect("/login?error=oauth_no_email")
        user = auth.get_or_create_oauth_user(info["email"], info.get("name",""), "google", str(info.get("id","")), info.get("picture",""))
        session.clear()
        session["user_id"] = user["user_id"]
        if auth.verify_admin_from_db(user["user_id"]):
            return redirect("/admin/dashboard")
        return redirect("/user_dashboard")
    except Exception:
        logger.exception("Google OAuth error")
        return redirect("/login?error=oauth_failed")


# ── Classification ──
@app.route('/api/classify', methods=['POST'])
def api_classify():
    domain = _validate_domain((request.json or {}).get('domain'))
    if not domain:
        return jsonify({"error": "Invalid domain"}), 400
    uid = get_request_user_id()
    res = ml_engine.classify(domain)
    conn = auth.get_db(auth.DNS_DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO dns_logs (timestamp, source_ip, domain_name, prediction, attack_type, action_taken, confidence, entropy, domain_length, subdomain_count, user_id)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
              (datetime.utcnow().isoformat(), request.remote_addr, domain,
               res.get('prediction'), res.get('attack_type'), res.get('action'),
               res.get('confidence'), res['features'][3], res['features'][0], res['features'][1], uid))
    conn.commit()
    conn.close()
    return jsonify(res)

@app.route('/api/diag', methods=['GET', 'OPTIONS'])
def api_diag():
    """No-auth diagnostic endpoint — visit in browser to confirm server is up."""
    if request.method == 'OPTIONS':
        return _cors_preflight_response('GET, OPTIONS')
    uid = get_request_user_id()
    resp = jsonify({
        "ok": True,
        "server": "SecureDNS Guard",
        "model_loaded": ml_engine.lexical_model is not None,
        "authenticated": uid is not None,
        "message": "Server is running. Add X-API-Key header to authenticate."
    })
    resp.headers['Access-Control-Allow-Origin'] = '*'
    return resp

def _cors_preflight_response(methods='POST, OPTIONS'):
    resp = Response('', status=200)
    resp.headers['Access-Control-Allow-Origin']  = '*'
    resp.headers['Access-Control-Allow-Methods'] = methods
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-API-Key'
    resp.headers['Access-Control-Max-Age']       = '86400'
    return resp

@app.route('/api/auth/ping', methods=['GET', 'OPTIONS'])
def api_auth_ping():
    """Public endpoint that validates an X-API-Key header. Used by the extension popup."""
    if request.method == 'OPTIONS':
        return _cors_preflight_response('GET, OPTIONS')
    uid = get_request_user_id()
    if not uid:
        resp = jsonify({'ok': False, 'error': 'Invalid or missing API key'})
        resp.headers['Access-Control-Allow-Origin'] = '*'
        return resp, 401
    resp = jsonify({'ok': True})
    resp.headers['Access-Control-Allow-Origin'] = '*'
    return resp

@app.route('/api/dns/batch', methods=['POST', 'OPTIONS'])
def api_dns_batch():
    if request.method == 'OPTIONS':
        return _cors_preflight_response()
    uid = get_request_user_id()
    if not uid:
        resp = jsonify({"error": "API key required. Add your key in extension Settings."})
        resp.headers['Access-Control-Allow-Origin'] = '*'
        return resp, 401
    rl = _rate_limit_ip(60, 60)
    if rl: return rl
    data       = request.json or {}
    domains_raw = data.get('domains', [])
    if not isinstance(domains_raw, list):
        return jsonify({"error": "domains must be an array"}), 400
    domains_raw = domains_raw[:50]
    seen, domains = set(), []
    for d in domains_raw:
        cleaned = _validate_domain(d)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            domains.append(cleaned)
    if not domains:
        resp = jsonify({"processed": 0, "blocked": 0, "safe": 0, "results": []})
        resp.headers['Access-Control-Allow-Origin'] = '*'
        return resp, 200
    results, blocked_count = [], 0
    now_iso = datetime.utcnow().isoformat()
    now_ms  = int(datetime.utcnow().timestamp() * 1000)
    conn = auth.get_db(auth.DNS_DB_PATH)
    cur  = conn.cursor()
    for domain in domains:
        try:
            res        = ml_engine.classify(domain)
            is_blocked = bool(res.get('blocked'))
            cur.execute('''INSERT INTO dns_logs (timestamp, source_ip, domain_name, prediction, attack_type, action_taken, confidence, entropy, domain_length, subdomain_count, user_id)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                        (now_iso, request.remote_addr, domain, res.get('prediction'), res.get('attack_type'),
                         res.get('action'), res.get('confidence'), res['features'][3], res['features'][0], res['features'][1], uid))
            results.append({"domain": domain, "blocked": is_blocked, "prediction": res.get('prediction'),
                            "attack_type": res.get('attack_type'), "confidence": res.get('confidence', 0),
                            "ts": now_ms})
            if is_blocked:
                blocked_count += 1
        except Exception:
            continue
    conn.commit()
    conn.close()
    processed = len(results)
    resp = jsonify({"processed": processed, "blocked": blocked_count,
                    "safe": processed - blocked_count, "results": results})
    resp.headers['Access-Control-Allow-Origin'] = '*'
    return resp

@app.route('/api/classify/flow', methods=['POST'])
def api_classify_flow():
    uid = get_request_user_id()
    if not uid:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json or {}
    flow = data.get('flow')
    if not flow or not isinstance(flow, dict):
        return jsonify({"error": "flow dict required with CIRA-CIC-DoHBrw-2020 feature keys"}), 400
    return jsonify(ml_engine.classify_flow(flow))


@app.route('/api/proxy/query', methods=['POST'])
def api_proxy_query():
    domain = _validate_domain((request.json or {}).get('domain'))
    if not domain:
        return jsonify({"error": "Invalid domain"}), 400
    uid = get_request_user_id()
    res = ml_engine.classify(domain)
    doh_used, doh_provider, latency, resolved_ip = 0, None, 0, None
    if not res.get('blocked'):
        doh_res     = doh_resolver.resolve(domain, preferred=load_settings().get('doh_provider', 'cloudflare'))
        doh_used    = 1
        doh_provider = doh_res.get('provider')
        latency     = doh_res.get('latency_ms', 0)
        resolved_ip = doh_res.get('ip')
    conn = auth.get_db(auth.DNS_DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO dns_logs (timestamp, source_ip, domain_name, prediction, attack_type, action_taken, confidence, entropy, domain_length, subdomain_count, doh_used, doh_provider, latency_ms, user_id)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
              (datetime.utcnow().isoformat(), request.remote_addr, domain,
               res.get('prediction'), res.get('attack_type'), res.get('action'),
               res.get('confidence'), res['features'][3], res['features'][0], res['features'][1],
               doh_used, doh_provider, latency, uid))
    conn.commit()
    conn.close()
    return jsonify({**res, "resolved_ip": resolved_ip, "latency_ms": latency, "doh_provider": doh_provider})

# ── Stats ──
@app.route('/api/stats/overview')
def stats_overview():
    uid   = get_request_user_id()
    if not uid and not is_admin():
        return jsonify({"error": "Unauthorized"}), 401
    admin = is_admin()
    conn  = auth.get_db(auth.DNS_DB_PATH)
    c     = conn.cursor()
    extra  = "" if admin else "WHERE user_id=?"
    params = () if admin else (uid,)
    c.execute(f"SELECT COUNT(*), SUM(action_taken='Blocked') FROM dns_logs {extra}", params)
    row = c.fetchone()
    total, blocked = row[0] or 0, row[1] or 0
    conn.close()
    metrics = {}
    if os.path.exists(ml_engine.METRICS_PATH):
        with open(ml_engine.METRICS_PATH) as f:
            metrics = json.load(f)
    return jsonify({"total_queries": total, "blocked_queries": blocked, "safe_queries": total - blocked, "model_accuracy": metrics.get("accuracy", 0)})

@app.route('/api/stats/hourly')
def stats_hourly():
    uid    = get_request_user_id()
    admin  = is_admin()
    conn   = auth.get_db(auth.DNS_DB_PATH)
    c      = conn.cursor()
    params = () if admin else (uid,)
    extra  = "" if admin else "AND user_id = ?"
    c.execute(f"SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as hr, action_taken, COUNT(*) FROM dns_logs WHERE timestamp >= datetime('now', '-24 hours') {extra} GROUP BY hr, action_taken", params)
    rows = c.fetchall()
    conn.close()
    data = {}
    for r in rows:
        hr, action, count = r[0], r[1], r[2]
        if hr not in data: data[hr] = {"safe": 0, "blocked": 0}
        if action == "Blocked": data[hr]["blocked"] = count
        else: data[hr]["safe"] = count
    return jsonify([{"hour": k, **v} for k, v in sorted(data.items())])

# ── Logs ──
def build_logs_query(req_args):
    uid      = get_request_user_id()
    filter_uid = req_args.get('user_id') if is_admin() else uid
    where, params = ["1=1"], []
    if filter_uid:
        where.append("user_id = ?")
        params.append(filter_uid)
    verdict = req_args.get('verdict', 'all')
    if verdict.lower() == 'safe': where.append("action_taken != 'Blocked'")
    elif verdict.lower() == 'malicious': where.append("action_taken = 'Blocked'")
    attack_type = req_args.get('attack_type', 'all')
    if attack_type != 'all':
        where.append("attack_type = ?")
        params.append(attack_type)
    try:
        min_conf = float(req_args.get('min_confidence', 0) or 0)
    except ValueError:
        min_conf = 0
    if min_conf > 0:
        where.append("confidence >= ?")
        params.append(min_conf / 100.0 if min_conf > 1 else min_conf)
    search = req_args.get('search', '').strip()
    if search:
        escaped = search.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        where.append("domain_name LIKE ? ESCAPE '\\'")
        params.append(f"%{escaped}%")
    if req_args.get('date_from'):
        where.append("timestamp >= ?")
        params.append(req_args['date_from'])
    if req_args.get('date_to'):
        where.append("timestamp <= ?")
        params.append(req_args['date_to'] + "T23:59:59")
    return " AND ".join(where), params

@app.route('/api/logs')
def api_logs():
    if not is_admin() and not get_request_user_id():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        page  = max(1, int(request.args.get('page', 1)))
        limit = min(max(1, int(request.args.get('limit', 50))), 200)
    except ValueError:
        page, limit = 1, 50
    where_sql, params = build_logs_query(request.args)
    offset = (page - 1) * limit
    conn = auth.get_db(auth.DNS_DB_PATH)
    c = conn.cursor()
    c.execute(f"SELECT COUNT(*) FROM dns_logs WHERE {where_sql}", params)
    total = c.fetchone()[0]
    c.execute(f"SELECT * FROM dns_logs WHERE {where_sql} ORDER BY log_id DESC LIMIT ? OFFSET ?", params + [limit, offset])
    logs = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify({"logs": logs, "pagination": {"page": page, "limit": limit, "total": total,
        "pages": (total + limit - 1) // limit if total > 0 else 1,
        "has_next": (page * limit) < total, "has_prev": page > 1}})

@app.route('/api/logs/export')
def api_logs_export():
    if not is_admin() and not get_request_user_id():
        return jsonify({"error": "Unauthorized"}), 401
    where_sql, params = build_logs_query(request.args)
    conn = auth.get_db(auth.DNS_DB_PATH)
    c = conn.cursor()
    c.execute(f"SELECT * FROM dns_logs WHERE {where_sql} ORDER BY log_id DESC LIMIT 50000", params)
    logs = [dict(r) for r in c.fetchall()]
    conn.close()
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Time', 'Source IP', 'Domain', 'Prediction', 'Attack Type', 'Confidence', 'Action'])
    for log in logs:
        cw.writerow([log['timestamp'], log['source_ip'], log['domain_name'],
                     log.get('prediction',''), log.get('attack_type',''),
                     log.get('confidence',''), log.get('action_taken','')])
    return Response(si.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=dns_logs.csv'})

@app.route('/api/logs/<int:log_id>/explain')
def explain_log(log_id):
    uid = get_request_user_id()
    if not uid:
        return jsonify({"error": "Unauthorized"}), 401
    admin  = is_admin()
    conn   = auth.get_db(auth.DNS_DB_PATH)
    c      = conn.cursor()
    query  = "SELECT domain_name FROM dns_logs WHERE log_id=?" + ("" if admin else " AND user_id=?")
    params = (log_id,) if admin else (log_id, uid)
    c.execute(query, params)
    row = c.fetchone()
    conn.close()
    if not row: return jsonify({"error": "Not found"}), 404
    feats = ml_engine.extract_features(row[0])
    return jsonify({"features": {
        "Domain Length":              feats[0],
        "Subdomain Count":            feats[1],
        "Max Label Length":           feats[2],
        "Entropy":                    round(feats[3], 2),
        "Subdomain Entropy":          round(feats[4], 2),
        "Digit Ratio":                round(feats[5], 2),
        "Vowel Ratio":                round(feats[6], 2),
        "Char Diversity":             round(feats[7], 2),
        "Max Consecutive Consonants": int(feats[8]),
        "TLD Risk":                   feats[9],
    }})

@app.route('/api/logs/recent-alerts')
def recent_alerts():
    uid = get_request_user_id()
    if not uid:
        return jsonify({"error": "Unauthorized"}), 401
    extra  = "" if is_admin() else "AND user_id = ?"
    params = () if is_admin() else (uid,)
    conn   = auth.get_db(auth.DNS_DB_PATH)
    c      = conn.cursor()
    c.execute(f"SELECT * FROM dns_logs WHERE action_taken='Blocked' {extra} ORDER BY timestamp DESC LIMIT 10", params)
    logs = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify(logs)

@app.route('/api/alerts/check')
def alerts_check():
    uid    = get_request_user_id()
    if not uid and not is_admin():
        return jsonify({"alert": False}), 200
    extra  = "" if is_admin() else "AND user_id = ?"
    params = () if is_admin() else (uid,)
    conn   = auth.get_db(auth.DNS_DB_PATH)
    c      = conn.cursor()
    c.execute(f"SELECT COUNT(*) FROM dns_logs WHERE action_taken='Blocked' {extra} AND timestamp >= datetime('now', '-30 minutes')", params)
    count = c.fetchone()[0]
    conn.close()
    return jsonify({"alert": count > 0})

# ── Settings ──
@app.route('/api/settings', methods=['GET', 'POST'])
def api_settings():
    if request.method == 'POST':
        if not _admin_ok(): return jsonify({"error": "Forbidden"}), 403
        data     = request.json or {}
        settings = load_settings()
        for k, v in data.items():
            if k in _SETTINGS_ALLOWED_KEYS:
                settings[k] = v
        save_settings(settings)
        ml_engine.set_threshold(settings.get("threshold", 85))
        return jsonify({"success": True, "settings": settings})
    if not is_admin() and not get_request_user_id():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(load_settings())

# ── Blacklist ──
@app.route('/api/blacklist')
def get_blacklist():
    if not is_admin() and not get_request_user_id():
        return jsonify({"error": "Unauthorized"}), 401
    conn = auth.get_db(auth.DNS_DB_PATH)
    c    = conn.cursor()
    c.execute("SELECT domain FROM blacklist")
    domains = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify(domains)

@app.route('/api/blacklist/add', methods=['POST'])
def add_blacklist():
    if not _admin_ok(): return jsonify({"error": "Forbidden"}), 403
    domain = _validate_domain((request.json or {}).get('domain'))
    if not domain: return jsonify({"error": "Invalid domain"}), 400
    conn = auth.get_db(auth.DNS_DB_PATH)
    c    = conn.cursor()
    try:
        c.execute("INSERT INTO blacklist (domain, added_at) VALUES (?, ?)", (domain, datetime.utcnow().isoformat()))
        conn.commit()
    except Exception:
        pass
    conn.close()
    return jsonify({"success": True})

@app.route('/api/blacklist/remove', methods=['DELETE'])
def remove_blacklist():
    if not _admin_ok(): return jsonify({"error": "Forbidden"}), 403
    domain = (request.json or {}).get('domain', '').strip()
    conn   = auth.get_db(auth.DNS_DB_PATH)
    c      = conn.cursor()
    c.execute("DELETE FROM blacklist WHERE domain=?", (domain,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


# ── Model ──
@app.route('/api/model/retrain', methods=['POST'])
def retrain_model():
    if not _admin_ok(): return jsonify({"error": "Forbidden"}), 403
    started = ml_engine.train()
    return jsonify({"success": started, "message": "Training started" if started else "Already training"})

# ── API Keys ──
@app.route('/api/v1/keys', methods=['GET', 'POST'])
def api_keys():
    uid = get_request_user_id()
    if not uid: return jsonify([]), 401
    if request.method == 'POST':
        name = (request.json or {}).get('name', 'New Key')
        if auth.generate_api_key(uid, name) is None:
            return jsonify({"error": "API key limit reached for your plan"}), 403
    return jsonify(auth.get_user_keys(uid))

@app.route('/api/v1/keys/<int:key_id>', methods=['DELETE'])
def api_key_delete(key_id):
    uid = get_request_user_id()
    if not uid: return jsonify({"error": "Unauthorized"}), 401
    if not auth.delete_api_key(uid, key_id):
        return jsonify({"error": "Key not found"}), 404
    return jsonify({"success": True})

@app.route('/api/v1/check', methods=['POST'])
@auth.require_api_key
def v1_check():
    domain = _validate_domain((request.json or {}).get('domain'))
    if not domain: return jsonify({"error": "Invalid domain"}), 400
    return jsonify(ml_engine.classify(domain))

# ── Admin pages ──
@app.route('/admin/login')
def admin_login():
    return render_template('admin/login.html')

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect('/admin/login')

@app.route('/admin/dashboard')
def admin_dashboard():
    if not _admin_ok(): return redirect('/admin/login')
    return render_template('admin/dashboard.html')

@app.route('/admin/logs')
def admin_logs():
    if not _admin_ok(): return redirect('/admin/login')
    return render_template('admin/logs.html')

@app.route('/admin/users')
def admin_users():
    if not _admin_ok(): return redirect('/admin/login')
    return render_template('admin/users.html')

@app.route('/admin/model')
def admin_model():
    if not _admin_ok(): return redirect('/admin/login')
    return render_template('admin/model.html')

@app.route('/admin/settings')
def admin_settings_page():
    if not _admin_ok(): return redirect('/admin/login')
    return render_template('admin/settings.html')

# ── Admin API ──
def _admin_guard():
    if not _admin_ok():
        return jsonify({"error": "Forbidden"}), 403
    return None

@app.route('/admin/api/overview')
def admin_overview():
    err = _admin_guard()
    if err: return err
    conn = auth.get_db(auth.DNS_DB_PATH)
    c    = conn.cursor()
    c.execute("SELECT COUNT(*) FROM dns_logs"); total   = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM dns_logs WHERE action_taken='Blocked'"); blocked = c.fetchone()[0]
    conn.close()
    conn2 = auth.get_db(auth.DB_PATH)
    c2    = conn2.cursor()
    c2.execute("SELECT COUNT(*) FROM users"); users = c2.fetchone()[0]
    conn2.close()
    metrics = {}
    if os.path.exists(ml_engine.METRICS_PATH):
        with open(ml_engine.METRICS_PATH) as f: metrics = json.load(f)
    return jsonify({"total_users": users, "total_queries": total, "total_blocked": blocked, "model_accuracy": metrics.get("accuracy", 0)})

@app.route('/admin/api/users')
def admin_get_users():
    err = _admin_guard()
    if err: return err
    return jsonify(auth.get_all_users())

@app.route('/admin/api/all-logs')
def admin_all_logs():
    err = _admin_guard()
    if err: return err
    conn = auth.get_db(auth.DNS_DB_PATH)
    c    = conn.cursor()
    c.execute("SELECT * FROM dns_logs ORDER BY log_id DESC LIMIT 1000")
    logs = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify(logs)

@app.route('/admin/api/update-plan', methods=['PATCH'])
def admin_update_plan():
    err = _admin_guard()
    if err: return err
    data = request.json or {}
    user_id = data.get('user_id')
    plan    = data.get('plan')
    if not user_id or not plan:
        return jsonify({"error": "user_id and plan are required"}), 400
    auth.update_user_plan(user_id, plan)
    return jsonify({"success": True})

@app.route('/admin/api/toggle-admin', methods=['POST'])
def admin_toggle_admin():
    err = _admin_guard()
    if err: return err
    data = request.json or {}
    user_id  = data.get('user_id')
    is_admin_flag = data.get('is_admin')
    if user_id is None or is_admin_flag is None:
        return jsonify({"error": "user_id and is_admin are required"}), 400
    auth.toggle_admin(user_id, is_admin_flag)
    return jsonify({"success": True})

@app.route('/admin/api/delete-user/<int:user_id>', methods=['DELETE'])
def admin_delete_user(user_id):
    err = _admin_guard()
    if err: return err
    auth.delete_user(user_id)
    return jsonify({"success": True})


@app.route('/admin/api/clear-logs', methods=['POST'])
def admin_clear_logs():
    err = _admin_guard()
    if err: return err
    conn = auth.get_db(auth.DNS_DB_PATH)
    conn.execute("DELETE FROM dns_logs")
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route('/admin/api/model-metrics')
def admin_model_metrics():
    err = _admin_guard()
    if err: return err
    if not os.path.exists(ml_engine.METRICS_PATH):
        return jsonify({}), 404
    with open(ml_engine.METRICS_PATH) as f:
        return jsonify(json.load(f))

@app.route('/admin/api/training-status')
def admin_training_status():
    err = _admin_guard()
    if err: return err
    return jsonify(ml_engine.TRAINING_STATUS)


@app.route('/admin/api/flow-metrics')
def admin_flow_metrics():
    err = _admin_guard()
    if err: return err
    if not os.path.exists(ml_engine.FLOW_METRICS_PATH):
        return jsonify({}), 404
    with open(ml_engine.FLOW_METRICS_PATH) as f:
        return jsonify(json.load(f))

@app.route('/admin/api/retrain', methods=['POST'])
def admin_retrain():
    err = _admin_guard()
    if err: return err
    started = ml_engine.train()
    return jsonify({"success": started, "message": "Training started" if started else "Already training"})



def _init_feedback_db():
    conn = sqlite3.connect(auth.DNS_DB_PATH)
    conn.execute('''CREATE TABLE IF NOT EXISTS feedback (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        log_id         INTEGER,
        domain         TEXT NOT NULL,
        correct_label  TEXT NOT NULL,
        submitted_by   INTEGER,
        submitted_at   TEXT
    )''')
    try:
        conn.execute("ALTER TABLE dns_logs ADD COLUMN user_label TEXT")
    except Exception:
        pass
    conn.commit()
    conn.close()


def _maybe_auto_retrain():
    """Delegate entirely to ml_engine which tracks its own retrain counter."""
    if not load_settings().get('auto_retrain', True):
        return
    if ml_engine.TRAINING_STATUS["is_training"]:
        return
    try:
        conn = sqlite3.connect(auth.DNS_DB_PATH)
        total = conn.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
        conn.close()
        new_since = total - ml_engine._last_retrain_count
        if new_since >= ml_engine._FEEDBACK_RETRAIN_THRESHOLD:
            ml_engine._last_retrain_count = total
            ml_engine.train()
            logger.info("Auto-retrain triggered by %d new feedback entries", new_since)
    except Exception:
        pass


# ── Feedback ──
@app.route('/api/logs/<int:log_id>/feedback', methods=['POST'])
def feedback_log(log_id):
    uid = get_request_user_id()
    if not uid:
        return jsonify({"error": "Unauthorized"}), 401
    label = (request.json or {}).get('label', '').strip().lower()
    if label not in ('safe', 'malicious', 'tunneling'):
        return jsonify({"error": "label must be safe, malicious, or tunneling"}), 400
    admin = is_admin()
    conn  = auth.get_db(auth.DNS_DB_PATH)
    c     = conn.cursor()
    query  = "SELECT domain_name FROM dns_logs WHERE log_id=?" + ("" if admin else " AND user_id=?")
    params = (log_id,) if admin else (log_id, uid)
    c.execute(query, params)
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Not found"}), 404
    domain = row['domain_name']
    now    = datetime.utcnow().isoformat()
    c.execute("UPDATE dns_logs SET user_label=? WHERE log_id=?", (label, log_id))
    c.execute("DELETE FROM feedback WHERE log_id=?", (log_id,))
    c.execute("INSERT INTO feedback (log_id, domain, correct_label, submitted_by, submitted_at) VALUES (?,?,?,?,?)",
              (log_id, domain, label, uid, now))
    conn.commit()
    conn.close()
    _maybe_auto_retrain()
    return jsonify({"success": True, "label": label, "domain": domain})


@app.route('/api/feedback/stats')
def feedback_stats():
    if not get_request_user_id():
        return jsonify({"error": "Unauthorized"}), 401
    conn = sqlite3.connect(auth.DNS_DB_PATH)
    total = conn.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
    safe  = conn.execute("SELECT COUNT(*) FROM feedback WHERE correct_label='safe'").fetchone()[0]
    mal   = conn.execute("SELECT COUNT(*) FROM feedback WHERE correct_label='malicious'").fetchone()[0]
    conn.close()
    next_retrain = max(0, ml_engine._FEEDBACK_RETRAIN_THRESHOLD - (total - ml_engine._last_retrain_count))
    return jsonify({"total": total, "safe": safe, "malicious": mal, "next_retrain_in": next_retrain})


# ── DNS-over-HTTPS JSON endpoint (RFC 8484 JSON format) ──────────────
# Compatible with Firefox TRR and DoH clients that support JSON mode.
# URL: /dns-query?name=<domain>&type=A[&key=<api-key>]
# Classifies the domain, blocks malicious ones (NXDOMAIN), and resolves
# safe ones via the upstream DoH client.
@app.route('/dns-query', methods=['GET', 'POST'])
def dns_query_doh():
    # Extract domain from query params (JSON DoH uses ?name=)
    name = request.args.get('name', '').strip().rstrip('.')
    if not name:
        return jsonify({"Status": 2, "Comment": "missing name"}), 400

    domain = _validate_domain(name)
    if not domain:
        return jsonify({"Status": 2, "Comment": "invalid name"}), 400

    # Authenticate via ?key= query param or X-API-Key header
    api_key = request.args.get('key') or request.headers.get('X-API-Key')
    uid = None
    if api_key:
        conn = auth.get_db(auth.DB_PATH)
        row = conn.execute('SELECT user_id FROM api_keys WHERE key_value = ?', (api_key,)).fetchone()
        conn.close()
        uid = row['user_id'] if row else None

    res = ml_engine.classify(domain)
    is_blocked = bool(res.get('blocked'))

    # Log the query
    try:
        conn = auth.get_db(auth.DNS_DB_PATH)
        conn.execute(
            '''INSERT INTO dns_logs (timestamp, source_ip, domain_name, prediction, attack_type,
               action_taken, confidence, entropy, domain_length, subdomain_count, doh_used, doh_provider, user_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'DoH-JSON', ?)''',
            (datetime.utcnow().isoformat(), request.remote_addr, domain,
             res.get('prediction'), res.get('attack_type'), res.get('action'),
             res.get('confidence'), res['features'][3], res['features'][0], res['features'][1], uid)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

    if is_blocked:
        # Return NXDOMAIN so the browser treats the domain as non-existent
        return jsonify({
            "Status": 3,  # NXDOMAIN
            "TC": False, "RD": True, "RA": True, "AD": False, "CD": False,
            "Question": [{"name": domain + ".", "type": 1}],
            "Authority": [],
            "Comment": "Blocked by SecureDNS Guard ML classifier"
        }), 200, {"Content-Type": "application/dns-json"}

    # Resolve safely via DoH
    doh_res = doh_resolver.resolve(domain, preferred=load_settings().get('doh_provider', 'cloudflare'))
    ip = doh_res.get('ip')
    answers = [{"name": domain + ".", "type": 1, "TTL": 300, "data": ip}] if ip else []

    return jsonify({
        "Status": 0,  # NOERROR
        "TC": False, "RD": True, "RA": True, "AD": False, "CD": False,
        "Question": [{"name": domain + ".", "type": 1}],
        "Answer": answers,
    }), 200, {"Content-Type": "application/dns-json"}


# ── Onboarding ──
@app.route('/api/user/onboarding')
def api_onboarding():
    uid = get_request_user_id()
    if not uid:
        return jsonify({"error": "Unauthorized"}), 401

    # Does the user have any DNS queries yet?
    conn = auth.get_db(auth.DNS_DB_PATH)
    total = conn.execute("SELECT COUNT(*) FROM dns_logs WHERE user_id=?", (uid,)).fetchone()[0]
    conn.close()

    # Fetch their first API key
    keys = auth.get_user_keys(uid)
    first_key = keys[0]['key_value'] if keys else None

    server_url = os.environ.get("SERVER_URL", request.host_url.strip('/'))

    return jsonify({
        "has_queries":  total > 0,
        "total_queries": total,
        "api_key":      first_key,
        "server_url":   server_url,
    })


# ── Extension download — packages the extension/ folder into a zip on the fly ──
@app.route('/download/extension.zip')
def download_extension():
    uid = get_request_user_id()
    if not uid:
        return redirect('/login?next=/download/extension.zip')

    ext_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'extension')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, _dirs, files in os.walk(ext_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                arcname = os.path.relpath(fpath, os.path.dirname(ext_dir))
                zf.write(fpath, arcname)
    buf.seek(0)
    return Response(
        buf.read(),
        mimetype='application/zip',
        headers={'Content-Disposition': 'attachment; filename=securednsgard-extension.zip'}
    )


if __name__ == "__main__":
    if os.environ.get("SECRET_KEY", "dev_secret") in ("dev_secret", "change-this-to-a-random-64-char-string", ""):
        print("WARNING: SECRET_KEY is not set. Set a strong random value in .env before deploying.")
    if os.environ.get("ADMIN_PASSWORD", "admin123") == "admin123":
        print("WARNING: ADMIN_PASSWORD is using the default 'admin123'. Change it in .env immediately.")
    auth.init_db()
    _init_feedback_db()
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@network.local")
    conn = auth.get_db(auth.DB_PATH)
    if not conn.execute("SELECT 1 FROM users WHERE email=?", (admin_email,)).fetchone():
        res = auth.register_user(
            admin_email, os.environ.get("ADMIN_USERNAME", "admin"),
            "Admin",     os.environ.get("ADMIN_PASSWORD", "admin123"), "pro"
        )
        if res.get('success'):
            conn.execute("UPDATE users SET is_admin=1 WHERE email=?", (admin_email,))
            conn.commit()
    conn.close()
    if not ml_engine.load():
        ml_engine.train()
    settings = load_settings()
    ml_engine.set_threshold(settings.get("threshold", 85))
    ml_engine.start_auto_retrain()
    app.run(host=os.environ.get("HOST", "0.0.0.0"), port=int(os.environ.get("PORT", 5000)), debug=False)
