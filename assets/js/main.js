/* Shared utilities for all app pages */

/* ─── Auth check ─── */
async function checkAuth() {
    try {
        const res = await fetch('/api/auth/me');
        if (!res.ok) { window.location.href = '/login'; return null; }
        return await res.json();
    } catch {
        window.location.href = '/login';
        return null;
    }
}

/* ─── Active nav link ─── */
function setActiveNavLink() {
    const path = window.location.pathname;
    document.querySelectorAll('.nav-item').forEach(link => {
        link.classList.remove('active');
        const href = link.getAttribute('href');
        if (!href || href === '#') return;
        const clean = href.replace(/\.html$/, '');
        if (path === href || path === clean || (clean !== '/' && path.startsWith(clean))) {
            link.classList.add('active');
        }
    });
}

/* ─── Mobile sidebar ─── */
function initMobileMenu() {
    const toggle  = document.querySelector('.mobile-toggle');
    const sidebar = document.querySelector('.sidebar');
    const overlay = document.querySelector('.sidebar-overlay');
    if (!toggle || !sidebar) return;
    toggle.addEventListener('click', () => {
        sidebar.classList.toggle('open');
        overlay?.classList.toggle('active');
    });
    overlay?.addEventListener('click', () => {
        sidebar.classList.remove('open');
        overlay.classList.remove('active');
    });
}

/* ─── Toast ─── */
function showToast(message, type = 'success', duration = 3200) {
    let container = document.querySelector('.toast-container');
    if (!container) {
        container = document.createElement('div');
        container.className = 'toast-container';
        document.body.appendChild(container);
    }
    const icons = { success: '✓', error: '✕', warning: '⚠', info: 'ℹ' };
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<span style="opacity:.7;">${icons[type] || 'ℹ'}</span><span>${message}</span>`;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.animation = 'slideOut 0.25s ease forwards';
        setTimeout(() => toast.remove(), 250);
    }, duration);
}

/* ─── Confirm dialog ─── */
function showConfirm(message, okLabel = 'Delete') {
    return new Promise(resolve => {
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay open';
        overlay.innerHTML = `
        <div class="modal-content" style="max-width:420px;">
            <div class="modal-header">
                <h3 class="modal-title">Confirm</h3>
                <button class="modal-close" id="_conf-x">✕</button>
            </div>
            <p style="margin-bottom:1.5rem;color:var(--text-secondary);">${message}</p>
            <div style="display:flex;justify-content:flex-end;gap:0.75rem;">
                <button class="btn outline" id="_conf-cancel">Cancel</button>
                <button class="btn danger" id="_conf-ok">${okLabel}</button>
            </div>
        </div>`;
        document.body.appendChild(overlay);
        const close = v => { overlay.remove(); resolve(v); };
        overlay.querySelector('#_conf-x').onclick      = () => close(false);
        overlay.querySelector('#_conf-cancel').onclick = () => close(false);
        overlay.querySelector('#_conf-ok').onclick     = () => close(true);
        overlay.onclick = e => { if (e.target === overlay) close(false); };
    });
}

const _svgIcon = (d, extra='') =>
    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" width="16" height="16" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" ${extra}>${d}</svg>`;

const NAV_ICONS = {
    overview:  _svgIcon('<line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/>'),
    logs:      _svgIcon('<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>'),
    settings:  _svgIcon('<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/>'),
    apikeys:   _svgIcon('<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/>'),
    setup:     _svgIcon('<path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/>'),
    help:      _svgIcon('<circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/>'),
    logout:    _svgIcon('<path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>'),
};

/* ─── Render sidebar ─── */
function renderSidebar(isAdmin) {
    const home = isAdmin ? '/admin/dashboard' : '/user_dashboard';
    return `
    <div class="sidebar-header">
        <div class="sidebar-logo">
            <svg viewBox="0 0 24 24" fill="none" stroke="#050f08" width="18" height="18" stroke-linecap="round" stroke-linejoin="round" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
        </div>
        <div>
            <div class="sidebar-title">Secure DNS Queries</div>
            <div class="sidebar-subtitle">Guard</div>
        </div>
    </div>
    <div class="nav-menu">
        <a href="${home}" class="nav-item"><i>${NAV_ICONS.overview}</i> Overview</a>
        <a href="/threat_logs" class="nav-item"><i>${NAV_ICONS.logs}</i> Query Log</a>
        <a href="/settings" class="nav-item"><i>${NAV_ICONS.settings}</i> Settings</a>
        <a href="/profile" class="nav-item"><i>${NAV_ICONS.apikeys}</i> API Keys</a>
        <a href="#" class="nav-item" onclick="event.preventDefault(); openSetupModal()"><i>${NAV_ICONS.setup}</i> Setup Guide</a>
        <a href="/help" class="nav-item"><i>${NAV_ICONS.help}</i> Help</a>
        <div style="flex:1;"></div>
        <div class="nav-divider"></div>
        <a href="/logout" class="nav-item" style="color:var(--danger);"><i>${NAV_ICONS.logout}</i> Sign out</a>
    </div>`;
}

/* ─── Render topbar ─── */
function renderTopbar(user) {
    const initial = user.username.charAt(0).toUpperCase();
    const planBadge = user.is_admin
        ? `<span class="badge red">ADMIN</span>`
        : `<span class="badge gray">${(user.plan || 'free').toUpperCase()}</span>`;
    return `
    <div class="d-flex align-items-center gap-2">
        <button class="mobile-toggle" aria-label="Open menu">☰</button>
    </div>
    <div class="topbar-right">
        <div class="user-menu">
            <div class="user-avatar">${initial}</div>
            <div class="hide-mobile" style="line-height:1.2;">
                <div class="user-name">${user.username}</div>
            </div>
            ${planBadge}
        </div>
    </div>`;
}

/* ─── Dashboard KPI poller ─── */
function initDashboardPoller() {
    const set = (id, val) => {
        const el = document.getElementById(id);
        if (el) { el.classList.remove('skeleton'); el.textContent = val; }
    };
    const update = async () => {
        try {
            const res = await fetch('/api/stats/overview');
            if (!res.ok) return;
            const d = await res.json();
            set('kpi-total',   d.total_queries.toLocaleString());
            set('kpi-blocked', d.blocked_queries.toLocaleString());
            set('kpi-safe',    d.safe_queries.toLocaleString());
            set('kpi-acc',     (d.model_accuracy * 100).toFixed(1) + '%');
            const total = d.total_queries || 1;
            const sub = (id2, v) => { const el = document.getElementById(id2); if (el) el.textContent = v; };
            sub('kpi-total-sub',   'last 24 hours');
            sub('kpi-blocked-sub', ((d.blocked_queries / total) * 100).toFixed(1) + '% of total');
            sub('kpi-safe-sub',    ((d.safe_queries    / total) * 100).toFixed(1) + '% of total');
        } catch {}
    };
    update();
    setInterval(update, 30000);
}

/* ─── HTML escape helper ─── */
function _h(s) {
    const d = document.createElement('div');
    d.textContent = String(s ?? '');
    return d.innerHTML;
}

/* ─── Getting Started / Setup modal ───────────────────────────────────
 *
 *  Shows automatically when a user has 0 DNS queries (first launch).
 *  Also reachable by clicking "Setup Guide" in the sidebar.
 *
 *  Two methods offered:
 *    A) Chrome Extension  – download zip → load unpacked → paste API key
 *    B) Browser DoH       – configure browser's Secure DNS to our endpoint
 * ─────────────────────────────────────────────────────────────────── */
/* Always open the modal (used by sidebar link) */
async function openSetupModal() {
    try {
        const res = await fetch('/api/user/onboarding');
        if (!res.ok) return;
        const d = await res.json();
        showSetupModal(d.api_key, d.server_url);
    } catch {}
}

async function maybeShowSetupModal() {
    /* Don't show if user dismissed it before */
    if (localStorage.getItem('sdg_setup_done') === '1') return;
    try {
        const res = await fetch('/api/user/onboarding');
        if (!res.ok) return;
        const d = await res.json();
        if (d.has_queries) {
            localStorage.setItem('sdg_setup_done', '1');
            return;
        }
        showSetupModal(d.api_key, d.server_url);
    } catch {}
}

function showSetupModal(apiKey, serverUrl) {
    if (document.getElementById('_sdg-setup-modal')) return; /* already open */

    serverUrl = serverUrl || window.location.origin;
    const masked = apiKey ? apiKey.slice(0, 10) + '••••••••••••' + apiKey.slice(-4) : '(no key yet)';

    const overlay = document.createElement('div');
    overlay.id        = '_sdg-setup-modal';
    overlay.className = 'modal-overlay open';
    overlay.innerHTML = `
<div class="modal-content" style="max-width:620px; padding:0; overflow:hidden;">

  <!-- Header -->
  <div class="modal-header" style="padding:1.25rem 1.5rem; border-bottom:1px solid var(--border-color);">
    <h3 class="modal-title" style="display:flex; align-items:center; gap:0.6rem;">
      <svg viewBox="0 0 24 24" fill="none" stroke="var(--accent)" width="20" height="20" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
      Get Started — Connect Your Browser
    </h3>
    <button class="modal-close" id="_sdg-close">✕</button>
  </div>

  <!-- Method tabs -->
  <div style="display:flex; border-bottom:1px solid var(--border-color); background:var(--bg-base);">
    <button id="_tab-ext" onclick="_setupTab('ext')" style="flex:1; padding:0.75rem; border:none; background:var(--bg-card); color:var(--accent); font-weight:700; font-size:0.85rem; cursor:pointer; border-bottom:2px solid var(--accent);">
      🧩 Chrome Extension
    </button>
    <button id="_tab-doh" onclick="_setupTab('doh')" style="flex:1; padding:0.75rem; border:none; background:var(--bg-base); color:var(--text-secondary); font-weight:600; font-size:0.85rem; cursor:pointer; border-bottom:2px solid transparent;">
      🌐 Browser DNS (no extension)
    </button>
  </div>

  <!-- Step 0: Your API Key (always visible) -->
  <div style="padding:1.25rem 1.5rem; background:var(--accent-glow, rgba(16,185,129,0.05)); border-bottom:1px solid var(--border-color);">
    <div style="font-size:0.78rem; font-weight:700; color:var(--text-secondary); text-transform:uppercase; letter-spacing:.06em; margin-bottom:.5rem;">Your API Key</div>
    <div style="display:flex; gap:.6rem; align-items:center;">
      <input id="_sdg-key-inp" type="text" value="${_h(masked)}" readonly
             style="font-family:'Courier New',monospace; font-size:.82rem; flex:1; padding:.45rem .7rem;
                    background:var(--bg-base); border:1px solid var(--border-color); border-radius:6px; color:var(--text-primary);">
      <button onclick="_copySetupKey()" class="btn" style="padding:.4rem .9rem; font-size:.82rem; white-space:nowrap;">Copy Key</button>
    </div>
    <div style="font-size:.75rem; color:var(--text-secondary); margin-top:.4rem;">Keep this secret — it authenticates all API requests.</div>
  </div>

  <!-- Extension tab -->
  <div id="_panel-ext" style="padding:1.25rem 1.5rem;">
    <div style="display:flex; flex-direction:column; gap:1.1rem;">

      <div style="display:flex; gap:1rem;">
        <div style="min-width:28px; height:28px; border-radius:50%; background:var(--accent-glow,rgba(16,185,129,.12)); color:var(--accent); font-weight:800; display:flex; align-items:center; justify-content:center; font-size:.85rem;">1</div>
        <div>
          <div style="font-weight:700; margin-bottom:.25rem;">Download the extension</div>
          <a href="/download/extension.zip" class="btn" style="font-size:.82rem; padding:.4rem .9rem; display:inline-flex; align-items:center; gap:.4rem;">
            ⬇ Download extension.zip
          </a>
          <div class="text-muted" style="font-size:.78rem; margin-top:.35rem;">Then unzip it to any folder on your computer.</div>
        </div>
      </div>

      <div style="display:flex; gap:1rem;">
        <div style="min-width:28px; height:28px; border-radius:50%; background:var(--accent-glow,rgba(16,185,129,.12)); color:var(--accent); font-weight:800; display:flex; align-items:center; justify-content:center; font-size:.85rem;">2</div>
        <div>
          <div style="font-weight:700; margin-bottom:.25rem;">Load it in Chrome</div>
          <ol style="margin-left:1.1rem; color:var(--text-secondary); font-size:.83rem; line-height:1.8;">
            <li>Open <code style="background:var(--bg-base);padding:.1rem .35rem;border-radius:3px;">chrome://extensions</code></li>
            <li>Enable <strong>Developer mode</strong> (toggle top-right)</li>
            <li>Click <strong>Load unpacked</strong> → select the unzipped folder</li>
          </ol>
        </div>
      </div>

      <div style="display:flex; gap:1rem;">
        <div style="min-width:28px; height:28px; border-radius:50%; background:var(--accent-glow,rgba(16,185,129,.12)); color:var(--accent); font-weight:800; display:flex; align-items:center; justify-content:center; font-size:.85rem;">3</div>
        <div>
          <div style="font-weight:700; margin-bottom:.25rem;">Paste your API key</div>
          <div class="text-muted" style="font-size:.83rem; line-height:1.7;">
            Click the 🛡 extension icon → open <strong>Settings</strong> → paste your API key and set Server URL to
            <code style="background:var(--bg-base);padding:.1rem .35rem;border-radius:3px;">${_h(serverUrl)}</code>
            → click <strong>Save</strong>.
          </div>
        </div>
      </div>

    </div>
  </div>

  <!-- DoH tab (hidden by default) -->
  <div id="_panel-doh" style="padding:1.25rem 1.5rem; display:none;">
    <p class="text-muted" style="font-size:.85rem; margin-bottom:1rem;">
      Configure your browser to send all DNS queries through Secure DNS Queries — <strong>no extension required</strong>.
      The server classifies every query and logs results to your dashboard.
    </p>

    <div style="display:flex; flex-direction:column; gap:1rem;">

      <!-- Chrome -->
      <details style="border:1px solid var(--border-color); border-radius:8px; overflow:hidden;">
        <summary style="padding:.75rem 1rem; background:var(--bg-base); cursor:pointer; font-weight:700; font-size:.85rem; list-style:none; display:flex; align-items:center; gap:.5rem;">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" width="16" height="16" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg>
          Chrome / Edge / Brave
        </summary>
        <div style="padding:.9rem 1rem; font-size:.83rem; color:var(--text-secondary); line-height:1.8;">
          <ol style="margin-left:1.1rem;">
            <li>Go to <code style="background:var(--bg-base);padding:.1rem .35rem;border-radius:3px;">Settings → Privacy and Security → Security</code></li>
            <li>Scroll to <strong>"Use secure DNS"</strong> and set it to <strong>With: Custom</strong></li>
            <li>Enter: <code style="background:var(--bg-base);padding:.1rem .35rem;border-radius:3px;">${_h(serverUrl)}/dns-query</code></li>
          </ol>
          <div style="margin-top:.6rem; padding:.6rem; background:rgba(234,179,8,.07); border:1px solid rgba(234,179,8,.2); border-radius:6px; font-size:.78rem; color:var(--text-secondary);">
            ⚠ Chrome uses wire-format DoH. For full per-user tracking include your API key in the URL:
            <code style="word-break:break-all;">${_h(serverUrl)}/dns-query?key=${_h(apiKey || 'YOUR_KEY')}</code>
          </div>
        </div>
      </details>

      <!-- Firefox -->
      <details style="border:1px solid var(--border-color); border-radius:8px; overflow:hidden;">
        <summary style="padding:.75rem 1rem; background:var(--bg-base); cursor:pointer; font-weight:700; font-size:.85rem; list-style:none; display:flex; align-items:center; gap:.5rem;">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" width="16" height="16" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>
          Firefox
        </summary>
        <div style="padding:.9rem 1rem; font-size:.83rem; color:var(--text-secondary); line-height:1.8;">
          <ol style="margin-left:1.1rem;">
            <li>Go to <code style="background:var(--bg-base);padding:.1rem .35rem;border-radius:3px;">Settings → Privacy &amp; Security → DNS over HTTPS</code></li>
            <li>Choose <strong>Max Protection</strong> → Custom → enter:<br>
              <code style="word-break:break-all;">${_h(serverUrl)}/dns-query?key=${_h(apiKey || 'YOUR_KEY')}</code>
            </li>
          </ol>
        </div>
      </details>

    </div>
  </div>

  <!-- Footer -->
  <div style="padding:.9rem 1.5rem; border-top:1px solid var(--border-color); display:flex; justify-content:space-between; align-items:center; background:var(--bg-base);">
    <label style="font-size:.8rem; color:var(--text-secondary); display:flex; align-items:center; gap:.4rem; cursor:pointer;">
      <input type="checkbox" id="_sdg-dont-show"> Don't show again
    </label>
    <div style="display:flex; gap:.5rem;">
      <a href="/api" class="btn outline" style="font-size:.82rem; padding:.4rem .85rem;">Full API Docs</a>
      <button onclick="_closeSetupModal()" class="btn" style="font-size:.82rem; padding:.4rem .85rem;">Done</button>
    </div>
  </div>

</div>`;

    document.body.appendChild(overlay);

    /* Store ref to apiKey for copy button */
    overlay._apiKey = apiKey;

    document.getElementById('_sdg-close').onclick = _closeSetupModal;
    overlay.addEventListener('click', e => { if (e.target === overlay) _closeSetupModal(); });
}

function _setupTab(name) {
    const tabs   = { ext: document.getElementById('_tab-ext'),  doh: document.getElementById('_tab-doh') };
    const panels = { ext: document.getElementById('_panel-ext'), doh: document.getElementById('_panel-doh') };
    Object.keys(tabs).forEach(k => {
        const active = k === name;
        tabs[k].style.background     = active ? 'var(--bg-card)'  : 'var(--bg-base)';
        tabs[k].style.color          = active ? 'var(--accent)'    : 'var(--text-secondary)';
        tabs[k].style.fontWeight     = active ? '700' : '600';
        tabs[k].style.borderBottom   = active ? '2px solid var(--accent)' : '2px solid transparent';
        panels[k].style.display      = active ? 'block' : 'none';
    });
}

function _copySetupKey() {
    const overlay = document.getElementById('_sdg-setup-modal');
    const key = overlay?._apiKey;
    if (!key) { showToast('No API key found', 'error'); return; }
    const inp = document.getElementById('_sdg-key-inp');
    navigator.clipboard.writeText(key).then(() => {
        if (inp) { inp.value = key; setTimeout(() => { inp.value = key.slice(0,10)+'••••••••••••'+key.slice(-4); }, 3000); }
        showToast('API key copied!', 'success');
    }).catch(() => showToast('Copy failed', 'error'));
}

function _closeSetupModal() {
    const overlay = document.getElementById('_sdg-setup-modal');
    if (!overlay) return;
    const cb = document.getElementById('_sdg-dont-show');
    if (cb?.checked) localStorage.setItem('sdg_setup_done', '1');
    overlay.remove();
}
