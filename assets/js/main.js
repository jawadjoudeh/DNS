document.addEventListener("DOMContentLoaded", () => {
    setActiveNavLink();
    initMobileMenu();
});

function setActiveNavLink() {
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.nav-item');
    navLinks.forEach(link => {
        link.classList.remove('active');
        const href = link.getAttribute('href');
        if (href && (
            currentPath === href ||
            currentPath.endsWith(href) ||
            (href !== '/' && currentPath.includes(href.replace('.html','')))
        )) {
            link.classList.add('active');
        }
    });
}

function initMobileMenu() {
    const hamburger = document.querySelector('.hamburger-btn');
    const sidebar   = document.querySelector('.sidebar');
    const overlay   = document.querySelector('.sidebar-overlay');
    
    if (!hamburger) return;
    
    hamburger.addEventListener('click', () => {
        sidebar.classList.toggle('open');
        overlay.classList.toggle('visible');
    });
    
    if (overlay) {
        overlay.addEventListener('click', () => {
            sidebar.classList.remove('open');
            overlay.classList.remove('visible');
        });
    }
}

function showToast(message, type = 'success', duration = 3000) {
    const colors = {
        success: '#22c55e', error: '#ef4444',
        warning: '#f59e0b', info: '#6366f1'
    };
    const icons = {
        success: '✓', error: '✕', warning: '⚠', info: 'ℹ'
    };
    
    const toast = document.createElement('div');
    toast.style.cssText = `
        position: fixed; bottom: 24px; right: 24px; z-index: 9999;
        background: var(--bg-secondary); border: 1px solid ${colors[type]};
        border-left: 4px solid ${colors[type]};
        color: var(--text-primary); padding: 12px 20px;
        border-radius: 8px; font-size: 0.875rem;
        display: flex; align-items: center; gap: 10px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        animation: slideInRight 0.3s ease;
        max-width: 320px;
    `;
    toast.innerHTML = `
        <span style="color:${colors[type]};font-weight:700">
            ${icons[type]}
        </span>
        <span>${message}</span>
    `;
    document.body.appendChild(toast);
    setTimeout(() => {
        toast.style.animation = 'slideOutRight 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

async function checkAuth() {
    const res = await fetch('/api/auth/me');
    if (!res.ok) {
        window.location.href = '/login.html';
        return null;
    }
    return await res.json();
}

function initDashboardPoller() {
    const fetchOverview = async () => {
        const res = await fetch('/api/stats/overview');
        if (res.ok) {
            const data = await res.json();
            const totalEl = document.getElementById('kpi-total');
            const blockedEl = document.getElementById('kpi-blocked');
            const safeEl = document.getElementById('kpi-safe');
            const accEl = document.getElementById('kpi-acc');
            
            if (totalEl) { totalEl.classList.remove('skeleton'); totalEl.textContent = data.total_queries; }
            if (blockedEl) { blockedEl.classList.remove('skeleton'); blockedEl.textContent = data.blocked_queries; }
            if (safeEl) { safeEl.classList.remove('skeleton'); safeEl.textContent = data.safe_queries; }
            if (accEl) { accEl.classList.remove('skeleton'); accEl.textContent = (data.model_accuracy * 100).toFixed(1) + '%'; }
        }
    };

    fetchOverview();
    setInterval(fetchOverview, 5000);
}
