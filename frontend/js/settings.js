// PRD: Settings & Developer Tools Management
// Reference: Phase 2 - Settings Panel & Dev Tools
//
// Provides:
//   1. Settings modal overlay with menu options
//   2. Developer Tools panel for E2E testing
//   3. Test events UI integration
//   4. WebSocket & API status checks

class SettingsManager {
    constructor() {
        this.settingsModal = null;
        this.devToolsModal = null;
    }

    init() {
        this.settingsModal = document.getElementById('settings-modal');
        this.devToolsModal = document.getElementById('dev-tools-modal');

        if (!this.settingsModal || !this.devToolsModal) {
            console.error('[settings] Modal elements not found');
            return;
        }

        this.setupEventListeners();
        console.log('[settings] Settings manager initialized');
    }

    setupEventListeners() {
        // Settings button in header
        const settingsBtn = document.getElementById('settings-btn');
        if (settingsBtn) {
            settingsBtn.addEventListener('click', () => this.openSettings());
        }

        // Settings modal close buttons
        document.getElementById('settings-modal-close')?.addEventListener('click', () => this.closeSettings());
        this.settingsModal?.addEventListener('click', (e) => {
            if (e.target === this.settingsModal) this.closeSettings();
        });

        // Developer Tools modal close buttons
        document.getElementById('dev-tools-modal-close')?.addEventListener('click', () => this.closeDevTools());
        this.devToolsModal?.addEventListener('click', (e) => {
            if (e.target === this.devToolsModal) this.closeDevTools();
        });

        // Settings menu buttons
        document.getElementById('settings-general')?.addEventListener('click', () => this.openGeneralSettings());
        document.getElementById('settings-notifications')?.addEventListener('click', () => this.openNotifications());
        document.getElementById('settings-dev-tools')?.addEventListener('click', () => this.openDevTools());

        // Keyboard escape to close modals
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                if (this.devToolsModal?.classList.contains('open')) {
                    this.closeDevTools();
                } else if (this.settingsModal?.classList.contains('open')) {
                    this.closeSettings();
                }
            }
        });
    }

    openSettings() {
        if (this.settingsModal) {
            this.settingsModal.classList.add('open');
        }
    }

    closeSettings() {
        if (this.settingsModal) {
            this.settingsModal.classList.remove('open');
        }
        // Reset to menu view for next open
        this.closeGeneralSettings();
    }

    openGeneralSettings() {
        // Show general settings panel, hide menu list
        const menuList = document.getElementById('settings-menu-list');
        const panel = document.getElementById('settings-general-panel');
        if (menuList) menuList.style.display = 'none';
        if (panel) panel.style.display = '';

        // Wire back button
        const backBtn = document.getElementById('settings-general-back');
        if (backBtn && !backBtn._wired) {
            backBtn._wired = true;
            backBtn.addEventListener('click', () => this.closeGeneralSettings());
        }

        // Wire mode toggle buttons
        const techBtn = document.getElementById('mode-btn-technical');
        const simpBtn = document.getElementById('mode-btn-simplified');
        if (techBtn && !techBtn._wired) {
            techBtn._wired = true;
            techBtn.addEventListener('click', () => this.saveMode('technical'));
        }
        if (simpBtn && !simpBtn._wired) {
            simpBtn._wired = true;
            simpBtn.addEventListener('click', () => this.saveMode('simplified'));
        }

        // Load current mode and highlight correct button
        this.loadCurrentMode();
        this.loadDndState();
    }

    closeGeneralSettings() {
        const menuList = document.getElementById('settings-menu-list');
        const panel = document.getElementById('settings-general-panel');
        if (panel) panel.style.display = 'none';
        if (menuList) menuList.style.display = '';
    }

    async loadDndState() {
        // Read from localStorage instantly, then confirm with API
        const cached = localStorage.getItem('citadel_guardian_muted') === 'true';
        this._applyDndUI(cached);

        try {
            const resp = await window.apiClient?.get('/api/preferences/guardian_muted');
            if (resp && resp.ok) {
                const data = await resp.json();
                const muted = data.value === 'true';
                this._applyDndUI(muted);
                localStorage.setItem('citadel_guardian_muted', String(muted));
            }
        } catch (_) {}
    }

    async toggleDnd() {
        const current = localStorage.getItem('citadel_guardian_muted') === 'true';
        const next = !current;
        this._applyDndUI(next);
        localStorage.setItem('citadel_guardian_muted', String(next));

        try {
            await window.apiClient?.put('/api/preferences/guardian_muted', { value: String(next) });
        } catch (_) {}
    }

    _applyDndUI(muted) {
        const btn = document.getElementById('dnd-toggle-btn');
        const label = document.getElementById('dnd-label');
        if (!btn || !label) return;

        if (muted) {
            btn.style.border = '1px solid rgba(255,153,0,0.4)';
            btn.style.background = 'rgba(255,153,0,0.1)';
            btn.style.color = '#ff9900';
            label.textContent = 'Do Not Disturb: ON — click to resume';
        } else {
            btn.style.border = '1px solid rgba(255,255,255,0.1)';
            btn.style.background = 'transparent';
            btn.style.color = '#9CA3AF';
            label.textContent = 'Enable Do Not Disturb';
        }

        // Update header indicator
        this._updateHeaderDndBadge(muted);
    }

    _updateHeaderDndBadge(muted) {
        let badge = document.getElementById('dnd-header-badge');
        if (muted && !badge) {
            badge = document.createElement('span');
            badge.id = 'dnd-header-badge';
            badge.title = 'Do Not Disturb active — Guardian messages paused';
            badge.style.cssText = 'display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:9999px;font-size:0.65rem;font-weight:600;background:rgba(255,153,0,0.15);color:#ff9900;border:1px solid rgba(255,153,0,0.3);margin-left:8px;';
            badge.innerHTML = '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/><line x1="1" y1="1" x2="23" y2="23"/></svg>DND';
            const header = document.querySelector('.app-header') || document.querySelector('header');
            if (header) header.appendChild(badge);
        } else if (!muted && badge) {
            badge.remove();
        }
    }

    async loadCurrentMode() {
        // Instant: read from localStorage
        const cached = localStorage.getItem('citadel_dashboard_mode') || 'technical';
        this.highlightModeButton(cached);

        // Authoritative: fetch from API
        try {
            const resp = await window.apiClient?.get('/api/preferences/dashboard_mode');
            if (resp && resp.ok) {
                const data = await resp.json();
                const mode = data.value || 'technical';
                this.highlightModeButton(mode);
                localStorage.setItem('citadel_dashboard_mode', mode);
            }
        } catch (_) {
            // API unavailable — localStorage value stands
        }
    }

    async saveMode(mode) {
        this.highlightModeButton(mode);
        localStorage.setItem('citadel_dashboard_mode', mode);

        // Persist to API
        try {
            await window.apiClient?.put('/api/preferences/dashboard_mode', { value: mode });
        } catch (_) {
            // Best-effort persistence
        }

        // Broadcast to all listeners (dashboard-nav, remote-shield, assets)
        window.dispatchEvent(new CustomEvent('dashboard-mode-changed', { detail: { mode } }));
    }

    highlightModeButton(mode) {
        const techBtn = document.getElementById('mode-btn-technical');
        const simpBtn = document.getElementById('mode-btn-simplified');
        if (!techBtn || !simpBtn) return;

        if (mode === 'simplified') {
            simpBtn.classList.add('mode-active');
            simpBtn.style.border = '1px solid rgba(0, 217, 255, 0.3)';
            simpBtn.style.background = 'rgba(0, 217, 255, 0.12)';
            simpBtn.style.color = '#00D9FF';
            techBtn.classList.remove('mode-active');
            techBtn.style.border = '1px solid rgba(255, 255, 255, 0.1)';
            techBtn.style.background = 'transparent';
            techBtn.style.color = '#9CA3AF';
        } else {
            techBtn.classList.add('mode-active');
            techBtn.style.border = '1px solid rgba(0, 217, 255, 0.3)';
            techBtn.style.background = 'rgba(0, 217, 255, 0.12)';
            techBtn.style.color = '#00D9FF';
            simpBtn.classList.remove('mode-active');
            simpBtn.style.border = '1px solid rgba(255, 255, 255, 0.1)';
            simpBtn.style.background = 'transparent';
            simpBtn.style.color = '#9CA3AF';
        }
    }

    openNotifications() {
        alert('Notification Settings coming in Phase 3!');
    }

    async openDevTools() {
        // Close the settings menu
        this.closeSettings();

        // Open the dev tools modal
        if (this.devToolsModal) {
            this.devToolsModal.classList.add('open');
        }

        // Always reload dev tools content (no caching - dev tool changes often)
        await this.loadDevToolsContent();
    }

    closeDevTools() {
        if (this.devToolsModal) {
            this.devToolsModal.classList.remove('open');
        }
    }

    async loadDevToolsContent() {
        const content = document.getElementById('dev-tools-content');
        if (!content) return;

        try {
            // Fetch the test-events.html (cache-busted to always get latest)
            const response = await fetch('test-events.html', { cache: 'no-store' });
            if (!response.ok) {
                throw new Error(`Failed to load test events: ${response.status}`);
            }

            const html = await response.text();

            // Parse the HTML and extract the body content
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, 'text/html');

            // Extract styles from the parsed document
            const styleElements = doc.querySelectorAll('head style');
            let stylesHTML = '';
            
            styleElements.forEach(style => {
                stylesHTML += style.outerHTML;
            });

            // Get the main container (skip header/footer)
            const container = doc.querySelector('.container');
            if (!container) {
                throw new Error('Could not find container in test-events.html');
            }

            // Extract scripts from the parsed document
            const scriptElements = doc.querySelectorAll('body script');
            let scriptsHTML = '';
            
            scriptElements.forEach(script => {
                scriptsHTML += script.outerHTML;
            });

            // Inject styles + content + scripts (scripts must be last for proper execution)
            content.innerHTML = stylesHTML + container.innerHTML + scriptsHTML;

            // Re-run any scripts in the injected content to ensure they execute
            this.reloadScripts(content);

            console.log('[settings] Developer Tools content loaded with scripts enabled');

        } catch (error) {
            console.error('[settings] Failed to load dev tools:', error);
            content.innerHTML = `
                <div style="text-align: center; padding: 2rem; color: #f44336;">
                    <p><strong>Failed to load Developer Tools</strong></p>
                    <p style="font-size: 0.9rem; color: #9CA3AF; margin-top: 1rem;">${error.message}</p>
                    <p style="font-size: 0.85rem; color: #9CA3AF; margin-top: 1rem;">
                        You can also access it directly at: <a href="test-events.html" target="_blank" style="color: #00D9FF; text-decoration: underline;">test-events.html</a>
                    </p>
                </div>
            `;
        }
    }

    reloadScripts(element) {
        // Find all script tags in the injected content
        const scripts = element.querySelectorAll('script');
        scripts.forEach(oldScript => {
            const newScript = document.createElement('script');
            if (oldScript.src) {
                newScript.src = oldScript.src;
            } else {
                newScript.textContent = oldScript.textContent;
            }
            // Insert the new script before removing the old one to preserve execution order
            oldScript.parentNode.insertBefore(newScript, oldScript);
            oldScript.parentNode.removeChild(oldScript);
        });
    }
}

// Initialize on DOMContentLoaded
document.addEventListener('DOMContentLoaded', () => {
    const settingsManager = new SettingsManager();
    settingsManager.init();

    // Make accessible globally for debugging
    window.settingsManager = settingsManager;
});

export { SettingsManager };
