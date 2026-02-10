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
        this.devToolsLoaded = false;
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
    }

    openGeneralSettings() {
        alert('General Settings coming in Phase 3!');
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

        // Load dev tools content if not already loaded
        if (!this.devToolsLoaded) {
            await this.loadDevToolsContent();
        }
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
            // Fetch the test-events.html
            const response = await fetch('../test-events.html');
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

            this.devToolsLoaded = true;
            console.log('[settings] Developer Tools content loaded with scripts enabled');

        } catch (error) {
            console.error('[settings] Failed to load dev tools:', error);
            content.innerHTML = `
                <div style="text-align: center; padding: 2rem; color: #f44336;">
                    <p><strong>Failed to load Developer Tools</strong></p>
                    <p style="font-size: 0.9rem; color: #9CA3AF; margin-top: 1rem;">${error.message}</p>
                    <p style="font-size: 0.85rem; color: #9CA3AF; margin-top: 1rem;">
                        You can also access it directly at: <a href="../test-events.html" target="_blank" style="color: #00D9FF; text-decoration: underline;">test-events.html</a>
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
