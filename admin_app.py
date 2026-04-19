import os
import sqlite3
from flask import Flask, request, jsonify, session, redirect, render_template
from dotenv import load_dotenv
import json

load_dotenv()
import auth
import ml_engine

admin_app = Flask(__name__, template_folder='admin', static_folder='assets', static_url_path='/assets')
admin_app.secret_key = os.environ.get("ADMIN_SECRET_KEY", "admin_secret_key_123")
ADMIN_TOKEN = os.environ.get("ADMIN_PANEL_TOKEN", "super_secret_token")

def require_admin_session(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_authenticated"):
            return redirect('/admin/login')
        return f(*args, **kwargs)
    return decorated

@admin_app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        token = request.form.get('token')
        if token == ADMIN_TOKEN:
            session["admin_authenticated"] = True
            return redirect('/admin/dashboard')
        return render_template('login.html', error="Invalid Token")
    return render_template('login.html')

@admin_app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect('/admin/login')

@admin_app.route('/admin/dashboard')
@require_admin_session
def admin_dashboard():
    return render_template('dashboard.html')

@admin_app.route('/admin/users')
@require_admin_session
def admin_users():
    return render_template('users.html')

@admin_app.route('/admin/logs')
@require_admin_session
def admin_logs():
    return render_template('logs.html')

@admin_app.route('/admin/model')
@require_admin_session
def admin_model():
    return render_template('model.html')

@admin_app.route('/admin/api/overview')
@require_admin_session
def api_overview():
    conn = auth.get_db(auth.DB_PATH)
    conn.execute('ATTACH DATABASE ? AS dns_db', (auth.DNS_DB_PATH,))
    c = conn.cursor()
    
    total_users = c.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    total_queries = c.execute('SELECT COUNT(*) FROM dns_db.dns_logs').fetchone()[0]
    total_blocked = c.execute('SELECT COUNT(*) FROM dns_db.dns_logs WHERE action_taken="Blocked"').fetchone()[0]
    
    metrics = {}
    if os.path.exists(ml_engine.METRICS_PATH):
        with open(ml_engine.METRICS_PATH) as f:
            metrics = json.load(f)
            
    conn.close()
    return jsonify({
        "total_users": total_users,
        "total_queries": total_queries,
        "total_blocked": total_blocked,
        "model_accuracy": metrics.get("accuracy", 0),
        "system_status": "healthy"
    })

@admin_app.route('/admin/api/users')
@require_admin_session
def api_users():
    return jsonify(auth.get_all_users())

@admin_app.route('/admin/api/all-logs')
@require_admin_session
def api_all_logs():
    conn = auth.get_db(auth.DNS_DB_PATH)
    conn.execute('ATTACH DATABASE ? AS auth_db', (auth.DB_PATH,))
    c = conn.cursor()
    c.execute('''
        SELECT d.*, u.username 
        FROM dns_logs d
        LEFT JOIN auth_db.users u ON d.user_id = u.user_id
        ORDER BY d.timestamp DESC LIMIT 100
    ''')
    logs = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify(logs)

@admin_app.route('/admin/api/update-plan', methods=['PATCH'])
@require_admin_session
def update_plan():
    data = request.json
    auth.update_user_plan(data['user_id'], data['plan'])
    return jsonify({"success": True})

@admin_app.route('/admin/api/toggle-admin', methods=['POST'])
@require_admin_session
def api_toggle_admin():
    data = request.json
    auth.toggle_admin(data['user_id'], data['is_admin'])
    return jsonify({"success": True})

@admin_app.route('/admin/api/delete-user/<int:id>', methods=['DELETE'])
@require_admin_session
def api_delete_user(id):
    auth.delete_user(id)
    return jsonify({"success": True})

@admin_app.route('/admin/api/training-status')
@require_admin_session
def training_status():
    return jsonify(ml_engine.TRAINING_STATUS)

@admin_app.route('/admin/api/retrain', methods=['POST'])
@require_admin_session
def retrain():
    ml_engine.train()
    return jsonify({"status": "started"})

if __name__ == "__main__":
    admin_app.run(host='0.0.0.0', port=int(os.environ.get("ADMIN_PORT", 5001)))
