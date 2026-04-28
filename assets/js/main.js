/* assets/js/main.js – Shared utilities for all app pages */

document.addEventListener("DOMContentLoaded", () => {
    setActiveNavLink();
    initMobileMenu();
    initThemeToggle();
});

/* ─── Navigation highlighting ─── */
function setActiveNavLink() {
    const currentPath = window.location.pathname;
    document.querySelectorAll('.nav-item').forEach(link => {
        link.classList.remove('active');
        const href = link.getAttribute('href');
        if (href && (
            currentPath === href ||
            currentPath.endsWith(href) ||
            (href !== '/' && href !== '/index.html' && currentPath.includes(href.replace('.html', '')))
        )) {
            link.classList.add('active');
        }
    });
}

/* ─── Mobile menu ─── */
function initMobileMenu() {
    const toggle = document.querySelector('.mobile-toggle');
    const sidebar = document.querySelector('.sidebar');
    const overlay = document.querySelector('.sidebar-overlay');
    if (!toggle) return;
    toggle.addEventListener('click', () => {
        sidebar.classList.toggle('open');
        overlay.classList.toggle('active');
    });
    if (overlay) {
        overlay.addEventListener('click', () => {
            sidebar.classList.remove('open');
            overlay.classList.remove('active');
        });
    }
}

/* ─── Theme toggle (light ↔ dark) ─── */
function initThemeToggle() {
    const btn = document.getElementById('theme-toggle');
    if (!btn) return;
    const saved = localStorage.getItem('theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    if (saved === 'dark' || (!saved && prefersDark)) {
        document.documentElement.setAttribute('data-theme', 'dark');
        btn.textContent = '☀️';
    } else {
        document.documentElement.setAttribute('data-theme', 'light');
        btn.textContent = '🌙';
    }
    btn.addEventListener('click', () => {
        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        document.documentElement.setAttribute('data-theme', isDark ? 'light' : 'dark');
        localStorage.setItem('theme', isDark ? 'light' : 'dark');
        btn.textContent = isDark ? '🌙' : '☀️';
    });
}

/* ─── Toast notifications ─── */
function showToast(message, type = 'success', duration = 3000) {
    let container = document.querySelector('.toast-container');
    if (!container) {
        container = document.createElement('div');
        container.className = 'toast-container';
        document.body.appendChild(container);
    }
    const icons = { success: '✓', error: '✕', warning: '⚠', info: 'ℹ' };
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<span style="font-size:1.1rem;">${icons[type] || 'ℹ'}</span> <span>${message}</span>`;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

/* ─── Auth check ─── */
async function checkAuth() {
    try {
        const res = await fetch('/api/auth/me');
        if (!res.ok) { window.location.href = '/login.html'; return null; }
        return await res.json();
    } catch {
        window.location.href = '/login.html';
        return null;
    }
}

/* ─── Render sidebar ─── */
function renderSidebar(isAdmin) {
    const dashHref = isAdmin ? '/dashboard.html' : '/user_dashboard.html';
    return `
        <div class="sidebar-header">
            <svg viewBox="0 0 24 24" fill="var(--accent)" width="30" height="30"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/></svg>
            <span class="sidebar-title">SecureDNS</span>
        </div>
        <div class="nav-menu">
            <a href="${dashHref}" class="nav-item"><i>📊</i> Dashboard</a>
            <a href="/threat_logs.html" class="nav-item"><i>📋</i> Query Log</a>
            <a href="/settings.html" class="nav-item"><i>⚙️</i> Settings</a>
            <a href="/profile.html" class="nav-item"><i>🔑</i> API Keys</a>
            <a href="/api.html" class="nav-item"><i>📖</i> Setup Guide</a>
            <a href="/help.html" class="nav-item"><i>❓</i> Help</a>
            <div style="flex:1;"></div>
            <a href="/logout" class="nav-item" style="color: var(--danger);"><i>🚪</i> Logout</a>
        </div>
    `;
}

/* ─── Render top bar ─── */
function renderTopbar(user) {
    return `
        <div class="d-flex align-items-center gap-2">
            <button class="mobile-toggle">☰</button>
        </div>
        <div class="topbar-right">
            <button class="theme-toggle" id="theme-toggle" title="Toggle theme">🌙</button>
            <div class="user-menu">
                <div class="user-avatar">${user.username.charAt(0).toUpperCase()}</div>
                <span class="hide-mobile" style="font-weight:600;">${user.username}</span>
                ${user.is_admin ? '<span class="badge red" style="font-size:0.65rem;">ADMIN</span>' : `<span class="badge blue" style="font-size:0.65rem;">${(user.plan || 'free').toUpperCase()}</span>`}
            </div>
        </div>
    `;
}

/* ─── Dashboard KPI poller ─── */
function initDashboardPoller() {
    const update = async () => {
        try {
            const res = await fetch('/api/stats/overview');
            if (!res.ok) return;
            const d = await res.json();
            const set = (id, val) => {
                const el = document.getElementById(id);
                if (el) { el.classList.remove('skeleton'); el.textContent = val; }
            };
            set('kpi-total', d.total_queries.toLocaleString());
            set('kpi-blocked', d.blocked_queries.toLocaleString());
            set('kpi-safe', d.safe_queries.toLocaleString());
            set('kpi-acc', (d.model_accuracy * 100).toFixed(1) + '%');
        } catch {}
    };
    update();
    setInterval(update, 10000);
}

/* ─── Animate number counting ─── */
function animateValue(el, start, end, duration) {
    if (start === end) return;
    const range = end - start;
    const startTime = performance.now();
    function step(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.floor(start + range * eased).toLocaleString();
        if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
}
