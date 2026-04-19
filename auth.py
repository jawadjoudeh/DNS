import sqlite3
import bcrypt
import secrets
from functools import wraps
from flask import request, jsonify, g
import os
from datetime import datetime

DB_PATH = os.environ.get("AUTH_DB_PATH", "data/users.db")
DNS_DB_PATH = os.environ.get("DB_PATH", "dns_logs.db")

PLANS = {
    "free": {"keys": 1, "daily_limit": 100,   "batch": False},
    "pro":  {"keys": 5, "daily_limit": 10000,  "batch": True}
}

def get_db(path):
    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else '.', exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            name TEXT,
            password TEXT,
            plan TEXT DEFAULT 'free',
            is_admin INTEGER DEFAULT 0,
            oauth_provider TEXT DEFAULT NULL,
            oauth_id TEXT DEFAULT NULL,
            avatar_url TEXT DEFAULT NULL,
            created_at TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS api_keys (
            key_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(user_id),
            key_value TEXT UNIQUE NOT NULL,
            name TEXT DEFAULT 'Default Key',
            created_at TEXT,
            uses_today INTEGER DEFAULT 0,
            last_reset TEXT
        )
    ''')
    conn.commit()
    conn.close()

    conn2 = get_db(DNS_DB_PATH)
    c2 = conn2.cursor()
    c2.execute('''
        CREATE TABLE IF NOT EXISTS dns_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            domain_name TEXT NOT NULL,
            prediction TEXT,
            attack_type TEXT NULLABLE,
            action_taken TEXT DEFAULT 'Blocked',
            confidence REAL,
            entropy REAL,
            domain_length INTEGER,
            subdomain_count INTEGER,
            doh_used INTEGER DEFAULT 0,
            doh_provider TEXT,
            latency_ms REAL,
            user_id INTEGER DEFAULT NULL
        )
    ''')
    c2.execute('''
        CREATE TABLE IF NOT EXISTS blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            added_at TEXT,
            added_by TEXT
        )
    ''')
    conn2.commit()
    conn2.close()

def register_user(email, username, name, password, plan="free"):
    conn = get_db(DB_PATH)
    c = conn.cursor()
    
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8') if password else None
    created_at = datetime.utcnow().isoformat()
    
    try:
        c.execute('''
            INSERT INTO users (email, username, name, password, plan, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (email, username, name, hashed, plan, created_at))
        user_id = c.lastrowid
        conn.commit()
        
        generate_api_key(user_id, 'Default Key')
        return {"success": True, "user_id": user_id, "username": username}
    except sqlite3.IntegrityError:
        return {"success": False, "error": "Email or username already taken"}
    finally:
        conn.close()

def login_user(identity, password):
    conn = get_db(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE email = ? OR username = ?', (identity, identity))
    user = c.fetchone()
    
    if user and user['password']:
        if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            today = datetime.utcnow().date().isoformat()
            c.execute('UPDATE api_keys SET uses_today = 0, last_reset = ? WHERE user_id = ? AND (last_reset != ? OR last_reset IS NULL)', (today, user['user_id'], today))
            conn.commit()
            conn.close()
            return {"success": True, **dict(user)}
            
    conn.close()
    return {"success": False, "error": "Invalid credentials"}

def get_user_by_id(uid):
    conn = get_db(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE user_id = ?', (uid,))
    user = c.fetchone()
    conn.close()
    return dict(user) if user else None

def get_all_users():
    conn = get_db(DB_PATH)
    conn.execute('ATTACH DATABASE ? AS dns_db', (DNS_DB_PATH,))
    c = conn.cursor()
    c.execute('''
        SELECT u.*, 
               COUNT(d.log_id) as total_queries,
               SUM(CASE WHEN d.action_taken='Blocked' THEN 1 ELSE 0 END) as blocked_today
        FROM users u
        LEFT JOIN dns_db.dns_logs d ON u.user_id = d.user_id AND (DATE(d.timestamp) = DATE('now') OR d.timestamp IS NULL)
        GROUP BY u.user_id
    ''')
    users = [dict(row) for row in c.fetchall()]
    conn.close()
    return users

def get_user_keys(uid):
    conn = get_db(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM api_keys WHERE user_id = ?', (uid,))
    keys = [dict(row) for row in c.fetchall()]
    conn.close()
    return keys

def generate_api_key(uid, name="New Key"):
    conn = get_db(DB_PATH)
    c = conn.cursor()
    key = "sk-" + secrets.token_hex(32)
    today = datetime.utcnow().date().isoformat()
    created_at = datetime.utcnow().isoformat()
    
    c.execute('''
        INSERT INTO api_keys (user_id, key_value, name, created_at, uses_today, last_reset)
        VALUES (?, ?, ?, ?, 0, ?)
    ''', (uid, key, name, created_at, today))
    conn.commit()
    conn.close()
    return key

def check_rate_limit(key_id, plan):
    conn = get_db(DB_PATH)
    c = conn.cursor()
    today = datetime.utcnow().date().isoformat()
    c.execute('UPDATE api_keys SET uses_today = 0, last_reset = ? WHERE key_id = ? AND (last_reset != ? OR last_reset IS NULL)', (today, key_id, today))
    c.execute('SELECT uses_today FROM api_keys WHERE key_id = ?', (key_id,))
    row = c.fetchone()
    conn.commit()
    conn.close()
    
    if not row: return 0
    uses = row['uses_today']
    limit = PLANS.get(plan, PLANS['free'])['daily_limit']
    return limit - uses

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({"error": "API key required"}), 401
            
        conn = get_db(DB_PATH)
        c = conn.cursor()
        c.execute('''
            SELECT a.key_id, a.uses_today, u.user_id, u.plan, u.username
            FROM api_keys a
            JOIN users u ON a.user_id = u.user_id
            WHERE a.key_value = ?
        ''', (api_key,))
        row = c.fetchone()
        
        if not row:
            conn.close()
            return jsonify({"error": "Invalid API key"}), 401
            
        user_id = row['user_id']
        key_id = row['key_id']
        plan = row['plan']
        username = row['username']
        uses_today = row['uses_today']
        
        today = datetime.utcnow().date().isoformat()
        c.execute('UPDATE api_keys SET uses_today = 0, last_reset = ? WHERE key_id = ? AND (last_reset != ? OR last_reset IS NULL)', (today, key_id, today))
        if c.rowcount > 0:
            uses_today = 0
            conn.commit()
        conn.close()
        
        limit = PLANS.get(plan, PLANS['free'])['daily_limit']
        if uses_today >= limit:
            return jsonify({"error": "Daily rate limit exceeded"}), 429
            
        request.user = {"user_id": user_id, "key_id": key_id, "plan": plan, "username": username}
        request.rate = {"used": uses_today, "limit": limit, "remaining": limit - uses_today}
        return f(*args, **kwargs)
    return decorated_function

def increment_usage(user_id, key_id, domain, verdict, confidence, blocked, ip):
    conn = get_db(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE api_keys SET uses_today = uses_today + 1 WHERE key_id = ?', (key_id,))
    conn.commit()
    conn.close()

def get_user_stats(uid, days):
    conn = get_db(DNS_DB_PATH)
    c = conn.cursor()
    c.execute(f"SELECT COUNT(*) as total FROM dns_logs WHERE user_id = ? AND timestamp > datetime('now', '-{days} days')", (uid,))
    total = c.fetchone()['total']
    
    c.execute(f"SELECT COUNT(*) as blocked FROM dns_logs WHERE user_id = ? AND action_taken = 'Blocked' AND timestamp > datetime('now', '-{days} days')", (uid,))
    blocked = c.fetchone()['blocked']
    conn.close()
    return {"total": total, "blocked": blocked}

def verify_admin_from_db(uid):
    conn = get_db(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT is_admin FROM users WHERE user_id = ?', (uid,))
    row = c.fetchone()
    conn.close()
    return bool(row['is_admin']) if row else False

def get_or_create_oauth_user(email, name, provider, oauth_id, avatar_url):
    conn = get_db(DB_PATH)
    c = conn.cursor()
    
    c.execute('SELECT * FROM users WHERE oauth_provider = ? AND oauth_id = ?', (provider, oauth_id))
    user = c.fetchone()
    if user:
        conn.close()
        return dict(user)
        
    c.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = c.fetchone()
    if user:
        c.execute('UPDATE users SET oauth_provider = ?, oauth_id = ?, avatar_url = ? WHERE user_id = ?', 
                  (provider, oauth_id, avatar_url, user['user_id']))
        conn.commit()
        c.execute('SELECT * FROM users WHERE user_id = ?', (user['user_id'],))
        user = c.fetchone()
        conn.close()
        return dict(user)
        
    base_username = name.replace(" ", "").lower() if name else email.split("@")[0]
    username = base_username
    c.execute('SELECT 1 FROM users WHERE username = ?', (username,))
    while c.fetchone():
        import random
        username = f"{base_username}{random.randint(1000, 9999)}"
        c.execute('SELECT 1 FROM users WHERE username = ?', (username,))
        
    created_at = datetime.utcnow().isoformat()
    c.execute('''
        INSERT INTO users (email, username, name, plan, oauth_provider, oauth_id, avatar_url, created_at)
        VALUES (?, ?, ?, 'free', ?, ?, ?, ?)
    ''', (email, username, name, provider, oauth_id, avatar_url, created_at))
    user_id = c.lastrowid
    conn.commit()
    conn.close()
    generate_api_key(user_id, 'Default OAuth Key')
    return get_user_by_id(user_id)

def toggle_admin(user_id, is_admin_bool):
    conn = get_db(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE users SET is_admin = ? WHERE user_id = ?', (int(is_admin_bool), user_id))
    conn.commit()
    conn.close()

def update_user_plan(user_id, plan):
    conn = get_db(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE users SET plan = ? WHERE user_id = ?', (plan, user_id))
    conn.commit()
    conn.close()

def delete_user(user_id):
    conn = get_db(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM api_keys WHERE user_id = ?', (user_id,))
    c.execute('DELETE FROM users WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    conn2 = get_db(DNS_DB_PATH)
    c2 = conn2.cursor()
    c2.execute('UPDATE dns_logs SET user_id = NULL WHERE user_id = ?', (user_id,))
    conn2.commit()
    conn2.close()
