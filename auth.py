import os
import re
import sqlite3
import secrets
from datetime import datetime, timezone
from functools import wraps

import bcrypt
from dotenv import load_dotenv
from flask import request, jsonify

load_dotenv()

DB_PATH = os.environ.get("AUTH_DB_PATH", "data/users.db")
DNS_DB_PATH = os.environ.get("DB_PATH", "dns_logs.db")

PLANS = {
    "free": {"keys": 1, "daily_limit": 100,   "batch": False},
    "pro":  {"keys": 5, "daily_limit": 10000,  "batch": True},
}

_USER_COLS = "user_id, email, username, name, plan, is_admin, oauth_provider, oauth_id, avatar_url, created_at"
_USER_COLS_U = ", ".join(f"u.{c.strip()}" for c in _USER_COLS.split(","))

# Pre-computed at startup for constant-time dummy checks (prevents user-enumeration timing oracle)
_DUMMY_HASH = bcrypt.hashpw(b"dummy", bcrypt.gensalt())


def _ensure_dirs():
    for path in (DB_PATH, DNS_DB_PATH):
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)


def get_db(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    _ensure_dirs()
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
            user_id INTEGER NOT NULL,
            key_value TEXT UNIQUE NOT NULL,
            name TEXT DEFAULT 'Default Key',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            uses_today INTEGER DEFAULT 0,
            last_reset DATE DEFAULT CURRENT_DATE,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS password_resets (
            email TEXT NOT NULL,
            token TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
            attack_type TEXT,
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
    email    = (email    or '').strip().lower()
    username = (username or '').strip()
    password = (password or '')

    if not email or not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return {"success": False, "error": "Invalid email address"}
    if not re.match(r'^[a-zA-Z0-9_]{3,30}$', username):
        return {"success": False, "error": "Username must be 3–30 characters (letters, numbers, underscores only)"}
    if password and len(password) < 8:
        return {"success": False, "error": "Password must be at least 8 characters"}

    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8') if password else None
    now = datetime.now(timezone.utc)
    created_at = now.isoformat()
    today = now.date().isoformat()
    key = "sk-" + secrets.token_hex(32)

    conn = get_db(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('''
            INSERT INTO users (email, username, name, password, plan, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (email, username, name, hashed, plan, created_at))
        user_id = c.lastrowid
        c.execute('''
            INSERT INTO api_keys (user_id, key_value, name, created_at, uses_today, last_reset)
            VALUES (?, ?, 'Default Key', ?, 0, ?)
        ''', (user_id, key, created_at, today))
        conn.commit()
        return {"success": True, "user_id": user_id, "username": username}
    except sqlite3.IntegrityError:
        return {"success": False, "error": "Email or username already taken"}
    finally:
        conn.close()


def login_user(identity, password):
    conn = get_db(DB_PATH)
    c = conn.cursor()
    c.execute(f'SELECT {_USER_COLS}, password FROM users WHERE email = ? OR username = ?', (identity, identity))
    user = c.fetchone()
    conn.close()

    if user and user['password']:
        if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            row = {k: user[k] for k in user.keys() if k != 'password'}
            return {"success": True, **row}
    else:
        bcrypt.checkpw(b"dummy", _DUMMY_HASH)

    return {"success": False, "error": "Invalid credentials"}


def get_user_by_id(uid):
    conn = get_db(DB_PATH)
    c = conn.cursor()
    c.execute(f'SELECT {_USER_COLS} FROM users WHERE user_id = ?', (uid,))
    user = c.fetchone()
    conn.close()
    return dict(user) if user else None


def get_all_users():
    conn = get_db(DB_PATH)
    conn.execute('ATTACH DATABASE ? AS dns_db', (DNS_DB_PATH,))
    c = conn.cursor()
    c.execute(f'''
        SELECT {_USER_COLS_U},
               COUNT(d.log_id) as total_queries,
               SUM(CASE WHEN d.action_taken='Blocked' THEN 1 ELSE 0 END) as blocked_today
        FROM users u
        LEFT JOIN dns_db.dns_logs d ON u.user_id = d.user_id AND DATE(d.timestamp) = DATE('now')
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

    plan_row = c.execute('SELECT plan FROM users WHERE user_id = ?', (uid,)).fetchone()
    plan = plan_row['plan'] if plan_row else 'free'
    max_keys = PLANS.get(plan, PLANS['free'])['keys']
    existing = c.execute('SELECT COUNT(*) FROM api_keys WHERE user_id = ?', (uid,)).fetchone()[0]
    if existing >= max_keys:
        conn.close()
        return None

    now = datetime.now(timezone.utc)
    key = "sk-" + secrets.token_hex(32)
    c.execute('''
        INSERT INTO api_keys (user_id, key_value, name, created_at, uses_today, last_reset)
        VALUES (?, ?, ?, ?, 0, ?)
    ''', (uid, key, name, now.isoformat(), now.date().isoformat()))
    conn.commit()
    conn.close()
    return key


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

        user_id    = row['user_id']
        key_id     = row['key_id']
        plan       = row['plan']
        username   = row['username']
        uses_today = row['uses_today']

        today = datetime.now(timezone.utc).date().isoformat()
        c.execute(
            'UPDATE api_keys SET uses_today = 0, last_reset = ? WHERE key_id = ? AND (last_reset != ? OR last_reset IS NULL)',
            (today, key_id, today),
        )
        if c.rowcount > 0:
            uses_today = 0
            conn.commit()

        limit = PLANS.get(plan, PLANS['free'])['daily_limit']
        if uses_today >= limit:
            conn.close()
            return jsonify({"error": "Daily rate limit exceeded"}), 429

        c.execute('UPDATE api_keys SET uses_today = uses_today + 1 WHERE key_id = ?', (key_id,))
        conn.commit()
        conn.close()

        request.user = {"user_id": user_id, "key_id": key_id, "plan": plan, "username": username}
        request.rate = {"used": uses_today, "limit": limit, "remaining": limit - uses_today - 1}
        return f(*args, **kwargs)
    return decorated_function


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

    c.execute(f'SELECT {_USER_COLS} FROM users WHERE oauth_provider = ? AND oauth_id = ?', (provider, oauth_id))
    user = c.fetchone()
    if user:
        conn.close()
        return dict(user)

    c.execute(f'SELECT {_USER_COLS} FROM users WHERE email = ?', (email,))
    user = c.fetchone()
    if user:
        c.execute(
            'UPDATE users SET oauth_provider = ?, oauth_id = ?, avatar_url = ? WHERE user_id = ?',
            (provider, oauth_id, avatar_url, user['user_id']),
        )
        conn.commit()
        c.execute(f'SELECT {_USER_COLS} FROM users WHERE user_id = ?', (user['user_id'],))
        updated = c.fetchone()
        conn.close()
        return dict(updated)

    raw = name if name else email.split("@")[0]
    base_username = re.sub(r'[^a-z0-9]', '', raw.lower())[:30] or "user"
    username = base_username
    for _ in range(20):
        c.execute('SELECT 1 FROM users WHERE username = ?', (username,))
        if not c.fetchone():
            break
        username = f"{base_username}{secrets.randbelow(9000) + 1000}"
    else:
        conn.close()
        raise RuntimeError("Could not generate a unique username after 20 attempts")

    now = datetime.now(timezone.utc)
    created_at = now.isoformat()
    today = now.date().isoformat()
    key = "sk-" + secrets.token_hex(32)
    try:
        c.execute('''
            INSERT INTO users (email, username, name, plan, oauth_provider, oauth_id, avatar_url, created_at)
            VALUES (?, ?, ?, 'free', ?, ?, ?, ?)
        ''', (email, username, name, provider, oauth_id, avatar_url, created_at))
        user_id = c.lastrowid
        c.execute('''
            INSERT INTO api_keys (user_id, key_value, name, created_at, uses_today, last_reset)
            VALUES (?, ?, 'Default OAuth Key', ?, 0, ?)
        ''', (user_id, key, created_at, today))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise
    conn.close()
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


def delete_api_key(user_id, key_id):
    conn = get_db(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM api_keys WHERE key_id = ? AND user_id = ?', (key_id, user_id))
    deleted = c.rowcount
    conn.commit()
    conn.close()
    return deleted > 0


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
