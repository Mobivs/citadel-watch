// PRD: Dashboard Navigation & Tab Integration (P2.1.5-T5)
// Reference: PHASE_2_SPEC.md
//
// Provides tabbed navigation within the main dashboard:
//   1. Intelligence — overview (Phase 1 Web Components)
//   2. Charts — threat visualisations (charts.html content)
//   3. Timeline — event history (timeline.html content)
//   4. Risk Metrics — threat indicators (risk-metrics.html content)
//   5. Assets — asset overview (assets.html content)
//
// Features:
//   - Tab switching via show/hide content panels
//   - Active tab persistence (localStorage)
//   - WebSocket connection at startup
//   - Error handling for disconnects/reconnects
//   - Tab-change custom event broadcasting

// ── Constants ──────────────────────────────────────────────────────

const TAB_IDS = ['intelligence', 'charts', 'timeline', 'risk-metrics', 'assets'];

const STORAGE_KEY = 'citadel_active_tab';

const TAB_CONFIG = {
    intelligence: { label: 'Intelligence', icon: '🖥️', src: null },
    charts:       { label: 'Charts',       icon: '📊', src: 'charts.html' },
    timeline:     { label: 'Timeline',     icon: '📋', src: 'timeline.html' },
    'risk-metrics': { label: 'Risk',       icon: '🎯', src: 'risk-metrics.html' },
    assets:       { label: 'Assets',       icon: '💻', src: 'assets.html' },
};


// ── State ──────────────────────────────────────────────────────────

let _activeTab = 'intelligence';
let _initialised = false;


// ── Tab persistence ────────────────────────────────────────────────

function loadSavedTab() {
    try {
        const saved = localStorage.getItem(STORAGE_KEY);
        if (saved && TAB_IDS.includes(saved)) {
            return saved;
        }
    } catch (_) {
        // localStorage unavailable (private browsing, etc.)
    }
    return 'intelligence';
}

function saveTab(tabId) {
    try {
        localStorage.setItem(STORAGE_KEY, tabId);
    } catch (_) {
        // silently ignore
    }
}


// ── Panel visibility ───────────────────────────────────────────────

function showPanel(tabId) {
    TAB_IDS.forEach(id => {
        const panel = document.getElementById(`tab-panel-${id}`);
        if (!panel) return;

        if (id === tabId) {
            panel.style.display = '';
            panel.removeAttribute('aria-hidden');
        } else {
            panel.style.display = 'none';
            panel.setAttribute('aria-hidden', 'true');
        }
    });
}


function updateTabButtons(tabId) {
    TAB_IDS.forEach(id => {
        const btn = document.getElementById(`tab-btn-${id}`);
        if (!btn) return;

        if (id === tabId) {
            btn.classList.add('tab-active');
            btn.setAttribute('aria-selected', 'true');
        } else {
            btn.classList.remove('tab-active');
            btn.setAttribute('aria-selected', 'false');
        }
    });
}


// ── Iframe loading ─────────────────────────────────────────────────

const _loadedIframes = new Set();

function loadIframe(tabId) {
    if (tabId === 'intelligence') return; // no iframe for overview
    if (_loadedIframes.has(tabId)) return; // already loaded

    const iframe = document.getElementById(`tab-iframe-${tabId}`);
    const config = TAB_CONFIG[tabId];
    if (!iframe || !config || !config.src) return;

    iframe.src = config.src;
    _loadedIframes.add(tabId);
}


// ── Core switch ────────────────────────────────────────────────────

function switchTab(tabId) {
    if (!TAB_IDS.includes(tabId)) return;

    _activeTab = tabId;
    showPanel(tabId);
    updateTabButtons(tabId);
    saveTab(tabId);
    loadIframe(tabId);

    // Broadcast tab change event
    window.dispatchEvent(new CustomEvent('tab-changed', {
        detail: { tab: tabId, label: TAB_CONFIG[tabId]?.label || tabId }
    }));
}


// ── Connection status badge ────────────────────────────────────────

function updateConnectionBadge(connected) {
    const badge = document.getElementById('nav-conn-badge');
    const dot   = document.getElementById('nav-conn-dot');
    const text  = document.getElementById('nav-conn-text');
    if (!badge || !dot || !text) return;

    if (connected) {
        badge.style.background = 'rgba(0,204,102,0.15)';
        badge.style.color      = '#00cc66';
        badge.style.border     = '1px solid rgba(0,204,102,0.3)';
        dot.style.background   = '#00cc66';
        text.textContent       = 'Live';
        badge.setAttribute('aria-label', 'WebSocket connection status: Live');
    } else {
        badge.style.background = 'rgba(255,51,51,0.15)';
        badge.style.color      = '#ff3333';
        badge.style.border     = '1px solid rgba(255,51,51,0.3)';
        dot.style.background   = '#ff3333';
        text.textContent       = 'Offline';
        badge.setAttribute('aria-label', 'WebSocket connection status: Offline');
    }
}


// ── Error toast ────────────────────────────────────────────────────

function showError(message, showRetry = false) {
    const container = document.getElementById('nav-error-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = 'nav-error-toast';
    toast.innerHTML = `
        <div style="display: flex; align-items: center; justify-content: space-between; gap: 1rem;">
            <span>${escapeHtml(message)}</span>
            <div style="display: flex; gap: 0.5rem;">
                ${showRetry ? `<button class="retry-btn" style="padding: 0.25rem 0.75rem; border-radius: 4px; background: rgba(255,255,255,0.2); border: none; color: white; font-size: 0.75rem; cursor: pointer; transition: background 0.2s;" onmouseover="this.style.background='rgba(255,255,255,0.3)'" onmouseout="this.style.background='rgba(255,255,255,0.2)'">Retry</button>` : ''}
                <button class="close-btn" style="padding: 0.25rem 0.75rem; border-radius: 4px; background: rgba(255,255,255,0.2); border: none; color: white; font-size: 0.75rem; cursor: pointer; transition: background 0.2s;" onmouseover="this.style.background='rgba(255,255,255,0.3)'" onmouseout="this.style.background='rgba(255,255,255,0.2)'" onclick="this.closest('.nav-error-toast').classList.add('nav-error-fade'); setTimeout(() => this.closest('.nav-error-toast').remove(), 400);">Close</button>
            </div>
        </div>
    `;
    container.appendChild(toast);

    // Auto-dismiss
    setTimeout(() => {
        toast.classList.add('nav-error-fade');
        setTimeout(() => toast.remove(), 400);
    }, 5000);
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;');
}


// ── Keyboard navigation ───────────────────────────────────────────

function setupKeyboard() {
    const tabBar = document.getElementById('dashboard-tab-bar');
    if (!tabBar) return;

    tabBar.addEventListener('keydown', (e) => {
        const currentIdx = TAB_IDS.indexOf(_activeTab);
        let newIdx = -1;

        if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
            e.preventDefault();
            newIdx = (currentIdx + 1) % TAB_IDS.length;
        } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
            e.preventDefault();
            newIdx = (currentIdx - 1 + TAB_IDS.length) % TAB_IDS.length;
        } else if (e.key === 'Home') {
            e.preventDefault();
            newIdx = 0;
        } else if (e.key === 'End') {
            e.preventDefault();
            newIdx = TAB_IDS.length - 1;
        }

        if (newIdx >= 0) {
            switchTab(TAB_IDS[newIdx]);
            const btn = document.getElementById(`tab-btn-${TAB_IDS[newIdx]}`);
            if (btn) btn.focus();
        }
    });
}


// ── Initialisation ─────────────────────────────────────────────────

function initDashboardNav() {
    if (_initialised) return;
    _initialised = true;

    // Wire up tab buttons
    TAB_IDS.forEach(id => {
        const btn = document.getElementById(`tab-btn-${id}`);
        if (btn) {
            btn.addEventListener('click', () => switchTab(id));
        }
    });

    // Keyboard navigation
    setupKeyboard();

    // Restore saved tab
    const saved = loadSavedTab();
    switchTab(saved);

    // Listen for connection events from main.js / api.js
    window.addEventListener('ws-connected', () => updateConnectionBadge(true));
    window.addEventListener('ws-disconnected', () => updateConnectionBadge(false));

    console.log('🗂️ Dashboard navigation initialised');
}


// ── Auto-init on DOMContentLoaded ──────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    initDashboardNav();
});


// ── Exports (for testing & external use) ───────────────────────────

export {
    TAB_IDS,
    TAB_CONFIG,
    STORAGE_KEY,
    switchTab,
    loadSavedTab,
    saveTab,
    showPanel,
    updateTabButtons,
    loadIframe,
    updateConnectionBadge,
    showError,
    initDashboardNav,
};
