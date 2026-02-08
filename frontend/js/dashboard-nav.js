// PRD: Dashboard Navigation & Tab Integration (P2.1.5-T5)
// Reference: PHASE_2_SPEC.md
//
// Provides tabbed navigation within the main dashboard:
//   1. Intelligence — overview (Phase 1 Web Components, always inline)
//   2. Charts — threat visualisations (loaded dynamically)
//   3. Timeline — event history (loaded dynamically)
//   4. Risk Metrics — threat indicators (loaded dynamically)
//   5. Assets — asset overview (loaded dynamically)
//   6. Remote Shield — VPS monitoring (loaded dynamically)
//
// Architecture:
//   - Intelligence panel is always in the DOM (Web Components)
//   - Other tabs are loaded on demand via tab-loader.js (fetch + inject)
//   - Only one non-intelligence tab's content exists in DOM at a time
//   - This prevents ID collisions between pages sharing element IDs
//
// Features:
//   - Tab switching via show/hide + dynamic content loading
//   - Active tab persistence (localStorage)
//   - WebSocket connection badge in header
//   - Error handling for load failures
//   - Tab-change custom event broadcasting
//   - Keyboard navigation (arrow keys, Home/End)

import { activate, deactivate } from './tab-loader.js';

// ── Constants ──────────────────────────────────────────────────────

const TAB_IDS = ['intelligence', 'charts', 'timeline', 'risk-metrics', 'assets', 'remote-shield'];

const STORAGE_KEY = 'citadel_active_tab';

const TAB_CONFIG = {
    intelligence:    { label: 'Intelligence',  src: null },
    charts:          { label: 'Charts',        src: 'charts.html' },
    timeline:        { label: 'Timeline',      src: 'timeline.html' },
    'risk-metrics':  { label: 'Risk',          src: 'risk-metrics.html' },
    assets:          { label: 'Assets',        src: 'assets.html' },
    'remote-shield': { label: 'Remote Shield', src: 'remote-shield.html' },
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
    // Intelligence panel is always in the DOM; other panels share a dynamic area
    const intellPanel = document.getElementById('tab-panel-intelligence');
    const dynamicPanel = document.getElementById('tab-panel-dynamic');

    if (tabId === 'intelligence') {
        if (intellPanel) { intellPanel.style.display = ''; intellPanel.removeAttribute('aria-hidden'); }
        if (dynamicPanel) { dynamicPanel.style.display = 'none'; dynamicPanel.setAttribute('aria-hidden', 'true'); }
    } else {
        if (intellPanel) { intellPanel.style.display = 'none'; intellPanel.setAttribute('aria-hidden', 'true'); }
        if (dynamicPanel) {
            dynamicPanel.style.display = '';
            dynamicPanel.removeAttribute('aria-hidden');
            dynamicPanel.setAttribute('aria-labelledby', `tab-btn-${tabId}`);
        }
    }
}


function updateTabButtons(tabId) {
    TAB_IDS.forEach(id => {
        const btn = document.getElementById(`tab-btn-${id}`);
        if (!btn) return;

        if (id === tabId) {
            btn.classList.add('tab-active');
            btn.setAttribute('aria-selected', 'true');
            btn.setAttribute('tabindex', '0');
        } else {
            btn.classList.remove('tab-active');
            btn.setAttribute('aria-selected', 'false');
            btn.setAttribute('tabindex', '-1');
        }
    });
}


// ── Core switch ────────────────────────────────────────────────────

async function switchTab(tabId) {
    if (!TAB_IDS.includes(tabId)) return;

    const prevTab = _activeTab;
    _activeTab = tabId;

    // 1. Update UI immediately (buttons + panel visibility)
    showPanel(tabId);
    updateTabButtons(tabId);
    saveTab(tabId);

    // 2. Load content for non-intelligence tabs
    if (tabId !== 'intelligence') {
        try {
            await activate(tabId);
        } catch (err) {
            console.error(`[nav] Failed to load tab ${tabId}:`, err);
            showError(`Failed to load ${TAB_CONFIG[tabId]?.label || tabId}`);
        }
    }

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
        badge.classList.remove('conn-offline');
        badge.classList.add('conn-live');
        text.textContent = 'Live';
        badge.setAttribute('aria-label', 'WebSocket connection status: Live');
    } else {
        badge.classList.remove('conn-live');
        badge.classList.add('conn-simulated');
        text.textContent = 'Simulated';
        badge.setAttribute('aria-label', 'WebSocket connection status: Simulated data');
    }
}


// ── Error toast ────────────────────────────────────────────────────

function showError(message, showRetry = false) {
    const container = document.getElementById('nav-error-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = 'nav-error-toast';
    toast.setAttribute('role', 'alert');
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

    console.log('[nav] Dashboard navigation initialised');
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
    updateConnectionBadge,
    showError,
    initDashboardNav,
};
