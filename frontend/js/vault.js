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
        // Always set up components and event listeners first so the UI is
        // interactive even if the backend isn't responding yet.
        this.setupComponents();
        this.setupEventListeners();

        try {
            await apiClient.initialize();
            await this.checkStatus();
            this.updateUI();
        } catch (error) {
            console.warn('[vault] Backend not available, UI ready in offline mode:', error.message);
        }
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

        // Add SSH Key button
        const addSshBtn = document.getElementById('add-ssh-btn');
        if (addSshBtn) {
            addSshBtn.addEventListener('click', () => {
                if (this.isUnlocked) {
                    this.showSshModal(null);
                } else {
                    this.showUnlock();
                }
            });
        }

        // SSH modal wiring
        document.getElementById('ssh-modal-cancel')?.addEventListener('click', () => this.hideSshModal());
        document.getElementById('ssh-modal-delete')?.addEventListener('click', () => this.handleSshDelete());
        document.getElementById('ssh-modal-form')?.addEventListener('submit', async (e) => {
            e.preventDefault();
            await this.handleSshSave();
        });
        document.getElementById('ssh-modal-auth-type')?.addEventListener('change', (e) => {
            const isKey = e.target.value === 'key';
            document.getElementById('ssh-key-fields').style.display = isKey ? '' : 'none';
            document.getElementById('ssh-password-field').style.display = isKey ? 'none' : '';
        });

        document.getElementById('ssh-generate-btn')?.addEventListener('click', () => this.handleSshGenerate());
        document.getElementById('ssh-copy-pubkey')?.addEventListener('click', () => {
            const pubkey = document.getElementById('ssh-pubkey-text')?.textContent || '';
            navigator.clipboard.writeText(pubkey).then(() => {
                const btn = document.getElementById('ssh-copy-pubkey');
                if (btn) { btn.textContent = 'Copied!'; setTimeout(() => { btn.textContent = 'Copy'; }, 2000); }
            });
        });

        // Unlock vault button
        const unlockBtn = document.getElementById('unlock-vault-btn');
        if (unlockBtn) {
            unlockBtn.addEventListener('click', () => this.showUnlock());
        }

        // Lock vault button
        const lockBtn = document.getElementById('lock-vault-btn');
        if (lockBtn) {
            lockBtn.addEventListener('click', async () => {
                await this.lockVault();
            });
        }

        // Auto-unlock controls
        document.getElementById('auto-unlock-enable-btn')?.addEventListener('click', () => this.enableAutoUnlock());
        document.getElementById('auto-unlock-disable-btn')?.addEventListener('click', () => this.disableAutoUnlock());
        document.getElementById('auto-unlock-confirm-btn')?.addEventListener('click', () => this._submitEnableAutoUnlock());
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
            this.loadSshCredentials();
            this.refreshAutoUnlockStatus();
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
        // Re-query if not found during initial setup (custom element upgrade timing)
        if (!this.unlockModal) {
            this.unlockModal = document.querySelector('vault-unlock');
        }
        if (this.unlockModal && typeof this.unlockModal.show === 'function') {
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

    // ── SSH Credential Methods ────────────────────────────────────────

    async loadSshCredentials() {
        const container = document.getElementById('ssh-cred-list');
        if (!container) return;
        try {
            const resp = await apiClient.get('/api/vault/ssh-credentials');
            if (!resp.ok) {
                container.innerHTML = `<div style="text-align:center;padding:1rem;color:#94a3b8;font-size:0.8rem;">Could not load SSH keys.</div>`;
                return;
            }
            const data = await resp.json();
            const creds = data.credentials || [];
            if (creds.length === 0) {
                container.innerHTML = `
                    <div style="text-align:center;padding:1.5rem 1rem;color:#94a3b8;font-size:0.8rem;">
                        <div style="opacity:0.4;display:flex;justify-content:center;margin-bottom:0.5rem">
                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>
                        </div>
                        <p>No SSH keys stored yet</p>
                        <p style="font-size:0.7rem;color:#6B7280;margin-top:0.25rem">Click "Add SSH Key" to store a private key for Guardian AI to use</p>
                    </div>`;
                return;
            }
            container.innerHTML = creds.map(c => `
                <div class="ssh-cred-card" data-id="${c.id}" style="background:rgba(15,23,42,0.4);border:1px solid rgba(0,217,255,0.1);border-radius:10px;padding:0.875rem;cursor:pointer;transition:all 0.2s;margin-bottom:0.5rem">
                    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.25rem">
                        <div style="font-weight:600;color:#e2e8f0;font-size:0.85rem">${this._esc(c.title)}</div>
                        <span style="padding:0.125rem 0.5rem;border-radius:8px;font-size:0.65rem;font-weight:500;background:rgba(0,217,255,0.15);color:#00D9FF">ssh-key</span>
                    </div>
                    <div style="display:flex;gap:0.75rem;font-size:0.75rem;color:#94a3b8">
                        <span>${this._esc(c.username || 'root')} · port ${c.notes ? (JSON.parse(c.notes||'{}').default_port || 22) : 22}</span>
                    </div>
                </div>
            `).join('');
            container.querySelectorAll('.ssh-cred-card').forEach(card => {
                card.addEventListener('mouseenter', () => { card.style.borderColor = 'rgba(0,217,255,0.3)'; card.style.background = 'rgba(15,23,42,0.6)'; });
                card.addEventListener('mouseleave', () => { card.style.borderColor = 'rgba(0,217,255,0.1)'; card.style.background = 'rgba(15,23,42,0.4)'; });
                card.addEventListener('click', () => this.showSshModal(card.dataset.id));
            });
        } catch (e) {
            container.innerHTML = `<div style="text-align:center;padding:1rem;color:#94a3b8;font-size:0.8rem;">Error loading SSH keys.</div>`;
        }
    }

    showSshModal(credId = null) {
        const overlay = document.getElementById('ssh-modal-overlay');
        if (!overlay) return;
        // Reset form
        document.getElementById('ssh-modal-form').reset();
        document.getElementById('ssh-modal-id').value = credId || '';
        document.getElementById('ssh-modal-title').textContent = credId ? 'SSH Key Details' : 'Add SSH Key';
        document.getElementById('ssh-modal-delete').style.display = credId ? '' : 'none';
        document.getElementById('ssh-modal-success').style.display = 'none';
        document.getElementById('ssh-modal-error').style.display = 'none';
        document.getElementById('ssh-key-fields').style.display = '';
        document.getElementById('ssh-password-field').style.display = 'none';

        if (credId) {
            document.getElementById('ssh-modal-private-key').required = false;
            // Fetch full credential (includes decrypted private key) and populate all fields
            apiClient.get(`/api/vault/ssh-credentials/${credId}`)
                .then(r => r.json())
                .then(cred => {
                    document.getElementById('ssh-modal-title-input').value = cred.title || '';
                    document.getElementById('ssh-modal-username').value = cred.default_username || 'root';
                    document.getElementById('ssh-modal-port').value = cred.default_port || 22;
                    const isKey = cred.auth_type === 'key';
                    document.getElementById('ssh-modal-auth-type').value = cred.auth_type || 'key';
                    document.getElementById('ssh-key-fields').style.display = isKey ? '' : 'none';
                    document.getElementById('ssh-password-field').style.display = isKey ? 'none' : '';
                    if (isKey) {
                        document.getElementById('ssh-modal-private-key').value = cred.private_key || '';
                        document.getElementById('ssh-modal-passphrase').value = cred.key_passphrase || '';
                        const pubBox = document.getElementById('ssh-pubkey-box');
                        const pubText = document.getElementById('ssh-pubkey-text');
                        if (pubBox && pubText && cred.public_key) {
                            pubText.textContent = cred.public_key;
                            pubBox.style.display = '';
                        }
                    } else {
                        document.getElementById('ssh-modal-password').value = cred.password || '';
                    }
                })
                .catch(() => {
                    document.getElementById('ssh-modal-private-key').placeholder = '(failed to load — vault may be locked)';
                });
        } else {
            document.getElementById('ssh-modal-private-key').required = true;
        }

        overlay.style.display = 'flex';
        document.getElementById('ssh-modal-title-input').focus();
    }

    hideSshModal() {
        const overlay = document.getElementById('ssh-modal-overlay');
        if (overlay) overlay.style.display = 'none';
    }

    async handleSshGenerate() {
        const btn = document.getElementById('ssh-generate-btn');
        const errEl = document.getElementById('ssh-modal-error');
        errEl.style.display = 'none';
        if (btn) { btn.textContent = 'Generating...'; btn.disabled = true; }

        try {
            const resp = await apiClient.post('/api/vault/ssh-credentials/generate', {});
            if (!resp.ok) {
                const err = await resp.json().catch(() => ({}));
                errEl.textContent = err.detail || 'Key generation failed';
                errEl.style.display = '';
                return;
            }
            const data = await resp.json();
            // Populate public key display
            const pubBox = document.getElementById('ssh-pubkey-box');
            const pubText = document.getElementById('ssh-pubkey-text');
            if (pubBox && pubText) {
                pubText.textContent = data.public_key;
                pubBox.style.display = '';
            }
            // Populate private key field — shown once for backup; saved by clicking Save Key
            const privKeyField = document.getElementById('ssh-modal-private-key');
            if (privKeyField && data.private_key) {
                privKeyField.value = data.private_key;
                privKeyField.required = false;
            }
            // Show instructions — user still needs to click Save Key to store in vault
            const okEl = document.getElementById('ssh-modal-success');
            if (okEl) {
                okEl.textContent = 'Key pair generated. Copy the public key to your server\'s authorized_keys, back up the private key if needed, then click Save Key.';
                okEl.style.display = '';
            }
        } catch (e) {
            errEl.textContent = 'Error: ' + e.message;
            errEl.style.display = '';
        } finally {
            if (btn) { btn.textContent = 'Generate New Key'; btn.disabled = false; }
        }
    }

    async handleSshSave() {
        const credId   = document.getElementById('ssh-modal-id').value;
        const title    = document.getElementById('ssh-modal-title-input').value.trim();
        const authType = document.getElementById('ssh-modal-auth-type').value;
        const privKey  = document.getElementById('ssh-modal-private-key').value.trim();
        const passphrase = document.getElementById('ssh-modal-passphrase').value;
        const password = document.getElementById('ssh-modal-password').value;
        const username = document.getElementById('ssh-modal-username').value.trim() || 'root';
        const port     = parseInt(document.getElementById('ssh-modal-port').value, 10) || 22;

        const errEl = document.getElementById('ssh-modal-error');
        const okEl  = document.getElementById('ssh-modal-success');
        errEl.style.display = 'none';
        okEl.style.display  = 'none';

        if (!title) { errEl.textContent = 'Name is required'; errEl.style.display = ''; return; }
        if (authType === 'key' && !privKey && !credId) {
            errEl.textContent = 'Private key is required'; errEl.style.display = ''; return;
        }

        const payload = {
            title, auth_type: authType,
            default_username: username, default_port: port,
        };
        if (authType === 'key') {
            if (privKey) payload.private_key = privKey;
            payload.key_passphrase = passphrase;
        } else {
            payload.password = password;
        }

        try {
            // If editing and new key provided — delete old then add new
            if (credId && privKey) {
                await apiClient.delete(`/api/vault/passwords/${credId}`);
            }
            if (!credId || privKey) {
                const resp = await apiClient.post('/api/vault/ssh-credentials', payload);
                if (!resp.ok) {
                    const err = await resp.json().catch(() => ({}));
                    errEl.textContent = err.detail || 'Failed to save SSH key';
                    errEl.style.display = '';
                    return;
                }
            }
            okEl.textContent = 'SSH key saved!';
            okEl.style.display = '';
            setTimeout(() => { this.hideSshModal(); this.loadSshCredentials(); }, 1200);
        } catch (e) {
            errEl.textContent = 'Error saving SSH key: ' + e.message;
            errEl.style.display = '';
        }
    }

    async handleSshDelete() {
        const credId = document.getElementById('ssh-modal-id').value;
        if (!credId || !confirm('Delete this SSH key? This cannot be undone.')) return;
        try {
            const resp = await apiClient.delete(`/api/vault/passwords/${credId}`);
            if (resp.ok) {
                this.hideSshModal();
                this.loadSshCredentials();
            } else {
                document.getElementById('ssh-modal-error').textContent = 'Failed to delete';
                document.getElementById('ssh-modal-error').style.display = '';
            }
        } catch (e) {
            document.getElementById('ssh-modal-error').textContent = 'Error: ' + e.message;
            document.getElementById('ssh-modal-error').style.display = '';
        }
    }

    _esc(text) {
        const d = document.createElement('div');
        d.textContent = text || '';
        return d.innerHTML;
    }

    // ── Auto-Unlock Methods ───────────────────────────────────────────

    async refreshAutoUnlockStatus() {
        const badge = document.getElementById('auto-unlock-status-badge');
        const enableBtn = document.getElementById('auto-unlock-enable-btn');
        const disableBtn = document.getElementById('auto-unlock-disable-btn');
        const warning = document.getElementById('auto-unlock-warning');
        const pwRow = document.getElementById('auto-unlock-pw-row');
        if (!badge) return;

        try {
            const resp = await apiClient.get('/api/vault/auto-unlock/status');
            if (!resp.ok) throw new Error('status error');
            const data = await resp.json();
            const active = data.configured || data.env_var_set;

            badge.textContent = data.env_var_set ? 'Active (env var)' : data.configured ? 'Active' : 'Disabled';
            badge.style.background = active ? 'rgba(0,204,102,0.15)' : 'rgba(100,116,139,0.2)';
            badge.style.color = active ? '#00cc66' : '#64748b';
            badge.style.borderColor = active ? 'rgba(0,204,102,0.3)' : 'rgba(100,116,139,0.3)';

            if (data.env_var_set) {
                // Env var is set — no UI toggle needed
                if (enableBtn) enableBtn.style.display = 'none';
                if (disableBtn) disableBtn.style.display = 'none';
                if (warning) { warning.style.display = ''; }
                if (pwRow) pwRow.style.display = 'none';
            } else if (data.configured) {
                if (enableBtn) enableBtn.style.display = 'none';
                if (disableBtn) disableBtn.style.display = '';
                if (warning) warning.style.display = '';
                if (pwRow) pwRow.style.display = 'none';
            } else {
                if (enableBtn) enableBtn.style.display = '';
                if (disableBtn) disableBtn.style.display = 'none';
                if (warning) warning.style.display = 'none';
                if (pwRow) pwRow.style.display = 'none';
            }
        } catch (e) {
            if (badge) badge.textContent = 'Unavailable';
        }
    }

    async enableAutoUnlock() {
        const pwRow = document.getElementById('auto-unlock-pw-row');
        const enableBtn = document.getElementById('auto-unlock-enable-btn');
        // If row is already visible, this button now acts as Cancel
        if (pwRow && pwRow.style.display !== 'none') {
            pwRow.style.display = 'none';
            const pwInput = document.getElementById('auto-unlock-pw-input');
            if (pwInput) pwInput.value = '';
            if (enableBtn) enableBtn.textContent = 'Enable';
            return;
        }
        // First click: show password row
        if (pwRow) pwRow.style.display = '';
        document.getElementById('auto-unlock-pw-input')?.focus();
        if (enableBtn) enableBtn.textContent = 'Cancel';
    }

    async _submitEnableAutoUnlock() {
        const pwInput = document.getElementById('auto-unlock-pw-input');
        const password = pwInput?.value?.trim();
        if (!password) return;

        try {
            const resp = await apiClient.post('/api/vault/auto-unlock/enable', { master_password: password });
            if (resp.ok) {
                if (pwInput) pwInput.value = '';
                const pwRow = document.getElementById('auto-unlock-pw-row');
                if (pwRow) pwRow.style.display = 'none';
                await this.refreshAutoUnlockStatus();
            } else {
                const err = await resp.json().catch(() => ({}));
                alert('Failed to enable auto-unlock: ' + (err.detail || 'Unknown error'));
            }
        } catch (e) {
            alert('Error: ' + e.message);
        }
    }

    async disableAutoUnlock() {
        if (!confirm('Disable auto-unlock? The vault will require manual unlock after each restart.')) return;
        try {
            const resp = await apiClient.delete('/api/vault/auto-unlock');
            if (resp.ok) await this.refreshAutoUnlockStatus();
        } catch (e) {
            alert('Error: ' + e.message);
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

// NOTE: No auto-init here — tab-loader.js manages the init/destroy lifecycle.

// ── Exports ─────────────────────────────────────────────────────────

export { init, destroy };
