// PRD: Vault - Main Vault Manager
// Reference: docs/PRD.md v0.2.4, Section: Vault
//
// Coordinates vault unlock, password list, and password viewer
// Exports init() / destroy() for tab-loader lifecycle

import { apiClient } from './utils/api-client.js';

let _instance = null;

class VaultManager {
    constructor() {
        this.isUnlocked = false;
        this.vaultExists = false;

        // Auto-lock timeout (15 minutes of inactivity)
        this.autoLockTimeout = null;
        this.autoLockDelay = 15 * 60 * 1000;

        // Bound handlers for cleanup
        this._onVaultUnlocked = () => {
            this.isUnlocked = true;
            this.vaultExists = true;
            this.startAutoLock();
            this.updateUI();
        };
        this._onVaultCreated = () => {
            this.vaultExists = true;
        };
        this._onPasswordSelected = (e) => {
            if (this.passwordViewer) {
                this.passwordViewer.showView(e.detail.id);
            }
        };
        this._onPasswordAdded = () => {};
        this._onPasswordDeleted = () => {};
        this._resetTimer = () => this.resetAutoLock();
    }

    async init() {
        await apiClient.initialize();
        await this.checkStatus();
        this.setupComponents();
        this.setupEventListeners();
    }

    async checkStatus() {
        try {
            const response = await apiClient.get('/api/vault/status');
            if (response.ok) {
                const status = await response.json();
                this.isUnlocked = status.is_unlocked;
                this.vaultExists = status.vault_exists;
            }
        } catch (error) {
            console.error('Failed to check vault status:', error);
        }
    }

    setupComponents() {
        this.unlockModal = document.querySelector('vault-unlock');
        this.passwordList = document.querySelector('vault-password-list');
        this.passwordViewer = document.querySelector('vault-password-viewer');
        this.updateUI();
    }

    setupEventListeners() {
        // Window events (vault lifecycle)
        window.addEventListener('vault-unlocked', this._onVaultUnlocked);
        window.addEventListener('vault-created', this._onVaultCreated);
        window.addEventListener('password-selected', this._onPasswordSelected);
        window.addEventListener('password-added', this._onPasswordAdded);
        window.addEventListener('password-deleted', this._onPasswordDeleted);

        // Activity tracking for auto-lock
        document.addEventListener('click', this._resetTimer);
        document.addEventListener('keydown', this._resetTimer);
        document.addEventListener('mousemove', this._resetTimer);

        // Add password button
        const addBtn = document.getElementById('add-password-btn');
        if (addBtn) {
            addBtn.addEventListener('click', () => {
                if (this.isUnlocked && this.passwordViewer) {
                    this.passwordViewer.showAdd();
                } else {
                    this.showUnlock();
                }
            });
        }

        // Unlock vault button
        const unlockBtn = document.getElementById('unlock-vault-btn');
        if (unlockBtn) {
            unlockBtn.addEventListener('click', () => {
                this.showUnlock();
            });
        }

        // Lock vault button
        const lockBtn = document.getElementById('lock-vault-btn');
        if (lockBtn) {
            lockBtn.addEventListener('click', async () => {
                await this.lockVault();
            });
        }
    }

    removeEventListeners() {
        window.removeEventListener('vault-unlocked', this._onVaultUnlocked);
        window.removeEventListener('vault-created', this._onVaultCreated);
        window.removeEventListener('password-selected', this._onPasswordSelected);
        window.removeEventListener('password-added', this._onPasswordAdded);
        window.removeEventListener('password-deleted', this._onPasswordDeleted);

        document.removeEventListener('click', this._resetTimer);
        document.removeEventListener('keydown', this._resetTimer);
        document.removeEventListener('mousemove', this._resetTimer);
    }

    updateUI() {
        const lockedState = document.getElementById('vault-locked-state');
        const unlockedState = document.getElementById('vault-unlocked-state');
        const lockBtn = document.getElementById('lock-vault-btn');

        if (!lockedState) return;

        if (this.isUnlocked) {
            lockedState.classList.add('hidden');
            if (unlockedState) unlockedState.classList.remove('hidden');
            if (lockBtn) lockBtn.classList.remove('hidden');
            if (this.passwordList) this.passwordList.loadPasswords();
        } else {
            lockedState.classList.remove('hidden');
            if (unlockedState) unlockedState.classList.add('hidden');
            if (lockBtn) lockBtn.classList.add('hidden');

            // Update locked state messaging based on vault existence
            const title = document.getElementById('vault-locked-title');
            const desc = document.getElementById('vault-locked-desc');
            const btn = document.getElementById('unlock-vault-btn');
            if (title && desc && btn) {
                if (this.vaultExists) {
                    title.textContent = 'Vault is Locked';
                    desc.innerHTML = 'Your passwords are encrypted and secure.<br>Unlock with your master password to access them.';
                    btn.textContent = 'Unlock Vault';
                } else {
                    title.textContent = 'No Vault Found';
                    desc.innerHTML = 'Create a vault to start securely storing<br>your passwords, API keys, and credentials.';
                    btn.textContent = 'Create Vault';
                }
            }
        }
    }

    showUnlock() {
        if (this.unlockModal) {
            this.unlockModal.setMode(this.vaultExists ? 'unlock' : 'create');
            this.unlockModal.show();
        }
    }

    async lockVault() {
        try {
            const response = await apiClient.post('/api/vault/lock', {});
            if (response.ok) {
                this.isUnlocked = false;
                this.stopAutoLock();
                this.updateUI();
            }
        } catch (error) {
            console.error('Failed to lock vault:', error);
        }
    }

    startAutoLock() {
        this.stopAutoLock();
        this.autoLockTimeout = setTimeout(async () => {
            if (this.isUnlocked) {
                await this.lockVault();
                alert('Vault auto-locked after 15 minutes of inactivity');
            }
        }, this.autoLockDelay);
    }

    resetAutoLock() {
        if (this.isUnlocked) {
            this.startAutoLock();
        }
    }

    stopAutoLock() {
        if (this.autoLockTimeout) {
            clearTimeout(this.autoLockTimeout);
            this.autoLockTimeout = null;
        }
    }

    destroy() {
        this.stopAutoLock();
        this.removeEventListeners();
    }
}

// ── Init / Destroy (tab-loader lifecycle) ───────────────────────────

async function init() {
    destroy();
    _instance = new VaultManager();
    await _instance.init();
}

function destroy() {
    if (_instance) {
        _instance.destroy();
        _instance = null;
    }
}

// ── Auto-init (standalone page use) ─────────────────────────────────

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}

// ── Exports ─────────────────────────────────────────────────────────

export { init, destroy };
