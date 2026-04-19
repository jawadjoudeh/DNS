import os
import random
import json
import csv
from io import StringIO
from datetime import datetime
import subprocess
import sys
from flask import Flask, request, jsonify, session, redirect, send_file, send_from_directory, render_template, Response
from flask_cors import CORS
from dotenv import load_dotenv

import auth
import ml_engine
import doh_resolver

load_dotenv()

app = Flask(__name__, template_folder='.', static_folder='assets')
CORS(app, supports_credentials=True)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret")

_proxy_process = None
_proxy_thread = None
_proxy_status = {
    "running": False,
    "started_at": None,
    "pid": None,
    "error": None
}

def load_settings():
    try:
        if os.path.exists("data/settings.json"):
            return json.load(open("data/settings.json"))
    except:
        pass
    return {
        "doh_provider": "cloudflare",
        "auto_block": True,
        "threshold": 85,
        "auto_retrain": True
    }

def save_settings(data):
    os.makedirs("data", exist_ok=True)
    json.dump(data, open("data/settings.json", "w"), indent=2)

def get_request_user_id():
    if "user_id" in session:
        return session["user_id"]
    api_key = request.headers.get("X-API-Key")
    if api_key:
        conn = auth.get_db(auth.DB_PATH)
        c = conn.cursor()
        c.execute('SELECT user_id FROM api_keys WHERE key_value = ?', (api_key,))
        row = c.fetchone()
        conn.close()
        if row:
            return row['user_id']
    return None

def is_admin():
    uid = session.get("user_id")
    return auth.verify_admin_from_db(uid) if uid else False

@app.route('/')
@app.route('/index.html')
def index():
    return render_template('index.html')

@app.route('/login')
@app.route('/login.html')
def login_page():
    return render_template('login.html')

@app.route('/dashboard')
@app.route('/dashboard.html')
def dashboard():
    if not session.get("user_id"):
        return redirect('/login.html')
    if is_admin():
        return render_template('dashboard.html')
    return render_template('user_dashboard.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login.html')

@app.route('/<path:filename>')
def static_pages(filename):
    if filename.endswith('.html') and filename not in ['index.html', 'login.html', 'dashboard.html', 'user_dashboard.html']:
        return render_template(filename)
    return send_from_directory('.', filename)

@app.route('/api/auth/register', methods=['POST'])
def api_register():
    data = request.json
    res = auth.register_user(data['email'], data['username'], data.get('name', ''), data['password'], data.get('plan', 'free'))
    if res.get('success'):
        session['user_id'] = res['user_id']
        return jsonify({"success": True, "redirect": "/dashboard"})
    return jsonify(res), 400

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.json
    res = auth.login_user(data['identity'], data['password'])
    if res.get('success') is not False:
        session['user_id'] = res['user_id']
        return jsonify({"success": True, "redirect": "/dashboard", "username": res['username'], "plan": res['plan'], "is_admin": bool(res['is_admin'])})
    return jsonify(res), 401

@app.route('/api/auth/me', methods=['GET'])
def api_me():
    uid = session.get("user_id")
    if not uid:
        return jsonify({"error": "Unauthorized"}), 401
    user = auth.get_user_by_id(uid)
    return jsonify({
        "user_id": user['user_id'], "username": user['username'], "email": user['email'],
        "plan": user['plan'], "is_admin": bool(user['is_admin']),
        "avatar_url": user.get('avatar_url')
    })

@app.route('/api/auth/providers')
def auth_providers():
    return jsonify({
        "google": bool(os.environ.get("GOOGLE_CLIENT_ID")),
        "github": bool(os.environ.get("GITHUB_CLIENT_ID"))
    })

@app.route('/api/classify', methods=['POST'])
def api_classify():
    domain = request.json.get('domain')
    uid = get_request_user_id()
    res = ml_engine.classify(domain)
    
    conn = auth.get_db(auth.DNS_DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO dns_logs (timestamp, source_ip, domain_name, prediction, attack_type, action_taken, confidence, entropy, domain_length, subdomain_count, user_id)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
              (datetime.utcnow().isoformat(), request.remote_addr, domain, res.get('prediction'), res.get('attack_type'), res.get('action'), res.get('confidence'), res['features'][3], res['features'][0], res['features'][1], uid))
    conn.commit()
    conn.close()
    
    return jsonify(res)

@app.route('/api/proxy/query', methods=['POST'])
def api_proxy_query():
    domain = request.json.get('domain')
    uid = get_request_user_id()
    res = ml_engine.classify(domain)
    
    doh_used = 0
    doh_provider = None
    latency = 0
    if not res.get('blocked'):
        doh_res = doh_resolver.resolve(domain)
        doh_used = 1
        doh_provider = doh_res['provider']
        latency = doh_res['latency_ms']
        
    conn = auth.get_db(auth.DNS_DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO dns_logs (timestamp, source_ip, domain_name, prediction, attack_type, action_taken, confidence, entropy, domain_length, subdomain_count, doh_used, doh_provider, latency_ms, user_id)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
              (datetime.utcnow().isoformat(), request.remote_addr, domain, res.get('prediction'), res.get('attack_type'), res.get('action'), res.get('confidence'), res['features'][3], res['features'][0], res['features'][1], doh_used, doh_provider, latency, uid))
    conn.commit()
    conn.close()
    return jsonify(res)

@app.route('/api/proxy/status')
def proxy_status():
    global _proxy_process, _proxy_status
    if _proxy_process and _proxy_process.poll() is not None:
        _proxy_status["running"] = False
        _proxy_status["pid"] = None
        _proxy_status["error"] = "Process exited unexpectedly"
    return jsonify(_proxy_status)

@app.route('/api/proxy/control', methods=['POST'])
def proxy_control():
    global _proxy_process, _proxy_status
    if not is_admin():
        return jsonify({"error": "Forbidden"}), 403
    
    action = request.json.get('action')
    if action == "start":
        if _proxy_status["running"] and _proxy_process and _proxy_process.poll() is None:
            return jsonify({"error": "Already running"}), 400
        try:
            cmd = [sys.executable, "dns_proxy.py"]
            _proxy_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            _proxy_status["running"] = True
            _proxy_status["started_at"] = datetime.utcnow().isoformat()
            _proxy_status["pid"] = _proxy_process.pid
            _proxy_status["error"] = None
            return jsonify({"success": True, "status": _proxy_status})
        except Exception as e:
            _proxy_status["running"] = False
            _proxy_status["error"] = str(e)
            return jsonify({"error": str(e)}), 500
    
    elif action == "stop":
        if not _proxy_status["running"] or not _proxy_process:
            return jsonify({"error": "Not running"}), 400
        _proxy_process.terminate()
        try:
            _proxy_process.wait(timeout=5)
        except:
            _proxy_process.kill()
        _proxy_status["running"] = False
        _proxy_status["pid"] = None
        return jsonify({"success": True, "status": _proxy_status})
        
    return jsonify({"error": "Invalid action"}), 400

@app.route('/api/stats/overview')
def stats_overview():
    uid = get_request_user_id()
    filter_sql = "" if is_admin() else "WHERE user_id = ?"
    params = () if is_admin() else (uid,)
    
    conn = auth.get_db(auth.DNS_DB_PATH)
    c = conn.cursor()
    c.execute(f"SELECT COUNT(*) FROM dns_logs {filter_sql}", params)
    total = c.fetchone()[0]
    c.execute(f"SELECT COUNT(*) FROM dns_logs WHERE action_taken='Blocked' {'AND user_id=?' if not is_admin() else ''}", params)
    blocked = c.fetchone()[0]
    safe = total - blocked
    
    metrics = {}
    if os.path.exists(ml_engine.METRICS_PATH):
        with open(ml_engine.METRICS_PATH) as f:
            metrics = json.load(f)
            
    conn.close()
    return jsonify({
        "total_queries": total, "blocked_queries": blocked, "safe_queries": safe,
        "model_accuracy": metrics.get("accuracy", 0)
    })

@app.route('/api/stats/hourly')
def stats_hourly():
    uid = get_request_user_id()
    filter_sql = "" if is_admin() else "AND user_id = ?"
    params = () if is_admin() else (uid,)
    conn = auth.get_db(auth.DNS_DB_PATH)
    c = conn.cursor()
    c.execute(f"SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as hr, action_taken, COUNT(*) FROM dns_logs WHERE timestamp >= datetime('now', '-24 hours') {filter_sql} GROUP BY hr, action_taken", params)
    rows = c.fetchall()
    conn.close()
    
    data = {}
    for r in rows:
        hr, action, count = r[0], r[1], r[2]
        if hr not in data: data[hr] = {"safe":0, "blocked":0}
        if action == "Blocked": data[hr]["blocked"] = count
        else: data[hr]["safe"] = count
    return jsonify([{"hour": k, **v} for k,v in sorted(data.items())])

def build_logs_query(req_args):
    uid = get_request_user_id()
    filter_uid = req_args.get('user_id') if is_admin() else uid
    
    where = ["1=1"]
    params = []
    
    if filter_uid:
        where.append("user_id = ?")
        params.append(filter_uid)
        
    verdict = req_args.get('verdict', 'all')
    if verdict != 'all':
        if verdict.lower() == 'safe':
            where.append("action_taken != 'Blocked'")
        elif verdict.lower() == 'malicious':
            where.append("action_taken = 'Blocked'")
            
    attack_type = req_args.get('attack_type', 'all')
    if attack_type != 'all':
        where.append("attack_type = ?")
        params.append(attack_type)
        
    min_conf = float(req_args.get('min_confidence', 0))
    if min_conf > 0:
        where.append("confidence >= ?")
        params.append(min_conf / 100.0 if min_conf > 1 else min_conf)
        
    search = req_args.get('search', '')
    if search:
        where.append("domain_name LIKE ?")
        params.append(f"%{search}%")
        
    date_from = req_args.get('date_from', '')
    if date_from:
        where.append("timestamp >= ?")
        params.append(date_from)
        
    date_to = req_args.get('date_to', '')
    if date_to:
        where.append("timestamp <= ?")
        params.append(date_to + "T23:59:59")
        
    return " AND ".join(where), params

@app.route('/api/logs')
def api_logs():
    if not is_admin() and not get_request_user_id():
        return jsonify({"error": "Unauthorized"}), 401
        
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 50))
    limit = min(limit, 200)
    
    where_sql, params = build_logs_query(request.args)
    offset = (page - 1) * limit
    
    conn = auth.get_db(auth.DNS_DB_PATH)
    c = conn.cursor()
    c.execute(f"SELECT COUNT(*) FROM dns_logs WHERE {where_sql}", params)
    total = c.fetchone()[0]
    
    c.execute(f"SELECT * FROM dns_logs WHERE {where_sql} ORDER BY log_id DESC LIMIT ? OFFSET ?", params + [limit, offset])
    logs = [dict(r) for r in c.fetchall()]
    conn.close()
    
    return jsonify({
        "logs": logs,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "pages": (total + limit - 1) // limit if total > 0 else 1,
            "has_next": (page * limit) < total,
            "has_prev": page > 1
        }
    })

@app.route('/api/logs/export')
def api_logs_export():
    if not is_admin() and not get_request_user_id():
        return jsonify({"error": "Unauthorized"}), 401
        
    where_sql, params = build_logs_query(request.args)
    conn = auth.get_db(auth.DNS_DB_PATH)
    c = conn.cursor()
    c.execute(f"SELECT * FROM dns_logs WHERE {where_sql} ORDER BY log_id DESC", params)
    logs = [dict(r) for r in c.fetchall()]
    conn.close()
    
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Time', 'Source IP', 'Domain', 'Prediction', 'Attack Type', 'Confidence', 'Action'])
    for log in logs:
        cw.writerow([log['timestamp'], log['source_ip'], log['domain_name'], log.get('prediction',''), log.get('attack_type',''), log.get('confidence',''), log.get('action_taken','')])
        
    return Response(si.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=dns_logs.csv'})

@app.route('/api/logs/<int:log_id>/explain')
def explain_log(log_id):
    conn = auth.get_db(auth.DNS_DB_PATH)
    c = conn.cursor()
    c.execute("SELECT domain_name FROM dns_logs WHERE log_id=?", (log_id,))
    row = c.fetchone()
    conn.close()
    if not row: return jsonify({"error": "Not found"}), 404
    domain = row[0]
    feats = ml_engine.extract_features(domain)
    return jsonify({
        "features": {
            "Domain Length": feats[0],
            "Subdomain Count": feats[1],
            "Entropy": round(feats[3], 2),
            "Digit Ratio": round(feats[5], 2),
            "Vowel Ratio": round(feats[6], 2),
            "Has Base64": feats[9]
        }
    })

@app.route('/api/logs/recent-alerts')
def recent_alerts():
    uid = get_request_user_id()
    filter_sql = "" if is_admin() else "AND user_id = ?"
    params = () if is_admin() else (uid,)
    conn = auth.get_db(auth.DNS_DB_PATH)
    c = conn.cursor()
    c.execute(f"SELECT * FROM dns_logs WHERE action_taken='Blocked' {filter_sql} ORDER BY timestamp DESC LIMIT 10", params)
    logs = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify(logs)

@app.route('/api/alerts/check')
def alerts_check():
    uid = get_request_user_id()
    filter_sql = "" if is_admin() else "AND user_id = ?"
    params = () if is_admin() else (uid,)
    conn = auth.get_db(auth.DNS_DB_PATH)
    c = conn.cursor()
    c.execute(f"SELECT COUNT(*) FROM dns_logs WHERE action_taken='Blocked' {filter_sql} AND timestamp >= datetime('now', '-30 minutes')", params)
    recent_blocks = c.fetchone()[0]
    conn.close()
    return jsonify({"alert": recent_blocks > 0})

@app.route('/api/settings', methods=['GET', 'POST'])
def api_settings():
    if request.method == 'POST':
        if not is_admin(): return jsonify({"error": "Forbidden"}), 403
        data = request.json
        settings = load_settings()
        settings.update(data)
        save_settings(settings)
        ml_engine.set_threshold(settings.get("threshold", 85))
        return jsonify({"success": True, "settings": settings, "message": f"Threshold updated to {settings.get('threshold')}%"})
    
    if not is_admin() and not get_request_user_id():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(load_settings())

@app.route('/api/blacklist', methods=['GET'])
def get_blacklist():
    if not is_admin() and not get_request_user_id():
        return jsonify({"error": "Unauthorized"}), 401
    conn = auth.get_db(auth.DNS_DB_PATH)
    c = conn.cursor()
    c.execute("SELECT domain FROM blacklist")
    domains = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify(domains)

@app.route('/api/blacklist/add', methods=['POST'])
def add_blacklist():
    if not is_admin(): return jsonify({"error": "Forbidden"}), 403
    domain = request.json.get('domain')
    conn = auth.get_db(auth.DNS_DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO blacklist (domain, added_at) VALUES (?, ?)", (domain, datetime.utcnow().isoformat()))
        conn.commit()
    except:
        pass
    conn.close()
    return jsonify({"success": True})

@app.route('/api/blacklist/remove', methods=['DELETE'])
def remove_blacklist():
    if not is_admin(): return jsonify({"error": "Forbidden"}), 403
    domain = request.json.get('domain')
    conn = auth.get_db(auth.DNS_DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM blacklist WHERE domain=?", (domain,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route('/api/model/retrain', methods=['POST'])
def retrain_model():
    if not is_admin(): return jsonify({"error": "Forbidden"}), 403
    ml_engine.train()
    return jsonify({"success": True})

@app.route('/api/v1/keys', methods=['GET', 'POST'])
def api_keys():
    uid = get_request_user_id()
    if not uid: return jsonify([]), 401
    if request.method == 'POST':
        name = request.json.get('name', 'New Key')
        auth.generate_api_key(uid, name)
    keys = auth.get_user_keys(uid)
    return jsonify(keys)

@app.route('/api/v1/check', methods=['POST'])
@auth.require_api_key
def v1_check():
    domain = request.json.get('domain')
    res = ml_engine.classify(domain)
    return jsonify(res)

@app.route('/api/proxy/download')
def proxy_download():
    if not session.get("user_id"): return "Unauthorized", 401
    user = auth.get_user_by_id(session["user_id"])
    keys = auth.get_user_keys(user["user_id"])
    if not keys: key = auth.generate_api_key(user["user_id"])
    else: key = keys[0]["key_value"]
    
    with open('dns_proxy.py', 'r') as f:
        content = f.read()
    
    server_url = os.environ.get("SERVER_URL", request.host_url.strip('/'))
    content = content.replace('YOUR_API_KEY_HERE', key)
    content = content.replace('https://YOUR_SERVER_URL/api/classify', f"{server_url}/api/classify")
    
    dl_path = f"dns_proxy_{user['username']}.py"
    with open(dl_path, 'w') as f:
        f.write(content)
        
    return send_file(dl_path, as_attachment=True)

if __name__ == "__main__":
    auth.init_db()
    
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@network.local")
    conn = auth.get_db(auth.DB_PATH)
    if not conn.execute("SELECT 1 FROM users WHERE email=?", (admin_email,)).fetchone():
        auth.register_user(admin_email, os.environ.get("ADMIN_USERNAME", "admin"), "Admin", os.environ.get("ADMIN_PASSWORD", "admin123"), "pro")
        conn.execute("UPDATE users SET is_admin=1 WHERE email=?", (admin_email,))
        conn.commit()
    conn.close()

    if not ml_engine.load():
        ml_engine.train()

    settings = load_settings()
    ml_engine.set_threshold(settings.get("threshold", 85))

    ml_engine.start_auto_retrain()
    app.run(host=os.environ.get("HOST", "0.0.0.0"), port=int(os.environ.get("PORT", 5000)))
