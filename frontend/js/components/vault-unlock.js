// PRD: Vault - Unlock / Create Modal Component
// Reference: docs/PRD.md v0.2.4, Section: Vault
//
// Modal for unlocking vault with master password
// Also supports "create" mode for first-time vault setup

import { apiClient } from '../utils/api-client.js';

class VaultUnlockModal extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({ mode: 'open' });
        this._mode = 'unlock'; // 'unlock' or 'create'
    }

    connectedCallback() {
        this.render();
        this.setupEventListeners();
    }

    /** Set modal mode: 'unlock' or 'create' */
    setMode(mode) {
        this._mode = mode;
        this._updateMode();
    }

    _updateMode() {
        const title = this.shadowRoot.getElementById('modal-title');
        const subtitle = this.shadowRoot.getElementById('modal-subtitle');
        const submitBtn = this.shadowRoot.getElementById('submit-btn');
        const confirmGroup = this.shadowRoot.getElementById('confirm-group');
        const requirements = this.shadowRoot.getElementById('password-requirements');

        if (!title) return;

        if (this._mode === 'create') {
            title.textContent = 'Create Vault';
            subtitle.textContent = 'Set a master password to secure your vault';
            submitBtn.textContent = 'Create Vault';
            confirmGroup.classList.remove('hidden');
            requirements.classList.remove('hidden');
        } else {
            title.textContent = 'Unlock Vault';
            subtitle.textContent = 'Enter your master password to access stored passwords';
            submitBtn.textContent = 'Unlock';
            confirmGroup.classList.add('hidden');
            requirements.classList.add('hidden');
        }
    }

    render() {
        this.shadowRoot.innerHTML = `
            <style>
                .modal-overlay {
                    position: fixed;
                    top: 0;
                    left: 0;
                    right: 0;
                    bottom: 0;
                    background: rgba(0, 0, 0, 0.8);
                    backdrop-filter: blur(10px);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    z-index: 1000;
                    animation: fadeIn 0.3s ease-out;
                }

                .hidden {
                    display: none;
                }

                .modal-card {
                    background: rgba(15, 23, 42, 0.95);
                    border: 1px solid rgba(0, 217, 255, 0.3);
                    border-radius: 10px;
                    padding: 1.25rem;
                    max-width: 380px;
                    width: 90%;
                    box-shadow: 0 12px 40px rgba(0, 217, 255, 0.15);
                    animation: slideUp 0.3s ease-out;
                }

                .modal-header {
                    text-align: center;
                    margin-bottom: 1.25rem;
                }

                .vault-icon {
                    margin-bottom: 0.75rem;
                    display: flex;
                    justify-content: center;
                }

                h2 {
                    color: #00D9FF;
                    font-size: 1.1rem;
                    margin: 0 0 0.25rem 0;
                }

                .subtitle {
                    color: #94a3b8;
                    font-size: 0.75rem;
                }

                .form-group {
                    margin-bottom: 1rem;
                }

                label {
                    display: block;
                    color: #e2e8f0;
                    font-size: 0.75rem;
                    margin-bottom: 0.375rem;
                    font-weight: 500;
                }

                input {
                    width: 100%;
                    padding: 0.5rem 0.75rem;
                    background: rgba(15, 23, 42, 0.6);
                    border: 1px solid rgba(0, 217, 255, 0.2);
                    border-radius: 6px;
                    color: #e2e8f0;
                    font-size: 0.8rem;
                    transition: all 0.2s ease;
                    box-sizing: border-box;
                }

                input:focus {
                    outline: none;
                    border-color: #00D9FF;
                    box-shadow: 0 0 0 2px rgba(0, 217, 255, 0.1);
                }

                .password-requirements {
                    margin-top: 0.5rem;
                    padding: 0.5rem 0.75rem;
                    background: rgba(0, 217, 255, 0.05);
                    border: 1px solid rgba(0, 217, 255, 0.1);
                    border-radius: 6px;
                }

                .req {
                    font-size: 0.7rem;
                    color: #94a3b8;
                    display: flex;
                    align-items: center;
                    gap: 0.375rem;
                    margin-bottom: 0.25rem;
                }

                .req:last-child {
                    margin-bottom: 0;
                }

                .req .check {
                    width: 10px;
                    height: 10px;
                    border-radius: 50%;
                    border: 1px solid #475569;
                    flex-shrink: 0;
                }

                .req.met .check {
                    background: #00cc66;
                    border-color: #00cc66;
                }

                .req.met {
                    color: #00cc66;
                }

                .strength-bar {
                    height: 3px;
                    background: #1e293b;
                    border-radius: 2px;
                    margin-top: 0.5rem;
                    overflow: hidden;
                }

                .strength-fill {
                    height: 100%;
                    border-radius: 2px;
                    transition: width 0.3s, background 0.3s;
                    width: 0%;
                }

                .button-group {
                    display: flex;
                    gap: 0.75rem;
                    margin-top: 1.25rem;
                }

                button {
                    flex: 1;
                    padding: 0.5rem 1rem;
                    border: none;
                    border-radius: 6px;
                    font-size: 0.8rem;
                    font-weight: 600;
                    cursor: pointer;
                    transition: all 0.2s ease;
                }

                .btn-primary {
                    background: linear-gradient(135deg, #00D9FF 0%, #0099CC 100%);
                    color: white;
                    box-shadow: 0 2px 10px rgba(0, 217, 255, 0.25);
                }

                .btn-primary:hover {
                    transform: translateY(-1px);
                    box-shadow: 0 4px 14px rgba(0, 217, 255, 0.35);
                }

                .btn-primary:disabled {
                    opacity: 0.5;
                    cursor: not-allowed;
                    transform: none;
                }

                .btn-secondary {
                    background: rgba(0, 217, 255, 0.1);
                    color: #00D9FF;
                    border: 1px solid rgba(0, 217, 255, 0.3);
                }

                .btn-secondary:hover {
                    background: rgba(0, 217, 255, 0.2);
                }

                .error-message {
                    background: rgba(239, 68, 68, 0.1);
                    border-left: 3px solid #EF4444;
                    padding: 0.5rem 0.75rem;
                    border-radius: 6px;
                    color: #fca5a5;
                    font-size: 0.75rem;
                    margin-bottom: 0.75rem;
                    display: none;
                }

                .error-message.visible {
                    display: block;
                    animation: shake 0.5s;
                }

                .success-message {
                    background: rgba(0, 204, 102, 0.1);
                    border-left: 3px solid #00cc66;
                    padding: 0.5rem 0.75rem;
                    border-radius: 6px;
                    color: #6ee7b7;
                    font-size: 0.75rem;
                    margin-bottom: 0.75rem;
                    display: none;
                }

                .success-message.visible {
                    display: block;
                }

                @keyframes fadeIn {
                    from { opacity: 0; }
                    to { opacity: 1; }
                }

                @keyframes slideUp {
                    from { opacity: 0; transform: translateY(12px); }
                    to { opacity: 1; transform: translateY(0); }
                }

                @keyframes shake {
                    0%, 100% { transform: translateX(0); }
                    25% { transform: translateX(-6px); }
                    75% { transform: translateX(6px); }
                }

                .loading {
                    display: inline-block;
                    width: 12px;
                    height: 12px;
                    border: 2px solid rgba(255, 255, 255, 0.3);
                    border-top-color: white;
                    border-radius: 50%;
                    animation: spin 0.8s linear infinite;
                    margin-left: 0.375rem;
                }

                @keyframes spin {
                    to { transform: rotate(360deg); }
                }
            </style>

            <div class="modal-overlay hidden" id="overlay">
                <div class="modal-card">
                    <div class="modal-header">
                        <div class="vault-icon">
                            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#00D9FF" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                        </div>
                        <h2 id="modal-title">Unlock Vault</h2>
                        <p class="subtitle" id="modal-subtitle">Enter your master password to access stored passwords</p>
                    </div>

                    <div class="error-message" id="error-message"></div>
                    <div class="success-message" id="success-message"></div>

                    <form id="unlock-form">
                        <div class="form-group">
                            <label for="master-password">Master Password</label>
                            <input
                                type="password"
                                id="master-password"
                                placeholder="Enter your master password"
                                autocomplete="off"
                                required
                            />
                        </div>

                        <div class="form-group hidden" id="confirm-group">
                            <label for="confirm-password">Confirm Password</label>
                            <input
                                type="password"
                                id="confirm-password"
                                placeholder="Re-enter your master password"
                                autocomplete="off"
                            />
                        </div>

                        <div class="hidden" id="password-requirements">
                            <div class="password-requirements">
                                <div class="req" id="req-length"><span class="check"></span> At least 12 characters</div>
                                <div class="req" id="req-upper"><span class="check"></span> One uppercase letter</div>
                                <div class="req" id="req-lower"><span class="check"></span> One lowercase letter</div>
                                <div class="req" id="req-number"><span class="check"></span> One number</div>
                            </div>
                            <div class="strength-bar">
                                <div class="strength-fill" id="strength-fill"></div>
                            </div>
                        </div>

                        <div class="button-group">
                            <button type="button" class="btn-secondary" id="cancel-btn">Cancel</button>
                            <button type="submit" class="btn-primary" id="submit-btn">
                                Unlock
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        `;
    }

    setupEventListeners() {
        const form = this.shadowRoot.getElementById('unlock-form');
        const cancelBtn = this.shadowRoot.getElementById('cancel-btn');
        const input = this.shadowRoot.getElementById('master-password');
        const errorMsg = this.shadowRoot.getElementById('error-message');

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (this._mode === 'create') {
                await this.handleCreate();
            } else {
                await this.handleUnlock();
            }
        });

        cancelBtn.addEventListener('click', () => {
            this.hide();
        });

        input.addEventListener('input', () => {
            errorMsg.classList.remove('visible');
            if (this._mode === 'create') {
                this._updateRequirements(input.value);
            }
        });
    }

    _updateRequirements(password) {
        const checks = {
            'req-length': password.length >= 12,
            'req-upper': /[A-Z]/.test(password),
            'req-lower': /[a-z]/.test(password),
            'req-number': /\d/.test(password),
        };

        let met = 0;
        for (const [id, passed] of Object.entries(checks)) {
            const el = this.shadowRoot.getElementById(id);
            if (el) {
                el.classList.toggle('met', passed);
                if (passed) met++;
            }
        }

        // Strength bar
        const fill = this.shadowRoot.getElementById('strength-fill');
        if (fill) {
            const pct = (met / 4) * 100;
            fill.style.width = `${pct}%`;
            if (met <= 1) fill.style.background = '#ff3333';
            else if (met <= 2) fill.style.background = '#ff9900';
            else if (met <= 3) fill.style.background = '#e6b800';
            else fill.style.background = '#00cc66';
        }
    }

    async handleCreate() {
        const input = this.shadowRoot.getElementById('master-password');
        const confirmInput = this.shadowRoot.getElementById('confirm-password');
        const submitBtn = this.shadowRoot.getElementById('submit-btn');
        const password = input.value;
        const confirm = confirmInput.value;

        if (!password) {
            this.showError('Please enter a master password');
            return;
        }

        if (password !== confirm) {
            this.showError('Passwords do not match');
            return;
        }

        // Client-side validation (server also validates)
        if (password.length < 12) {
            this.showError('Password must be at least 12 characters');
            return;
        }

        submitBtn.disabled = true;
        submitBtn.innerHTML = 'Creating<span class="loading"></span>';

        try {
            const response = await apiClient.post('/api/vault/initialize', {
                master_password: password
            });

            if (response.ok) {
                // Show success, then auto-unlock
                this.showSuccess('Vault created! Unlocking...');
                submitBtn.disabled = true;

                // Now unlock with the same password
                const unlockResp = await apiClient.post('/api/vault/unlock', {
                    master_password: password
                });

                if (unlockResp.ok) {
                    this.dispatchEvent(new CustomEvent('vault-unlocked', {
                        bubbles: true,
                        composed: true
                    }));
                    this.dispatchEvent(new CustomEvent('vault-created', {
                        bubbles: true,
                        composed: true
                    }));

                    setTimeout(() => {
                        this.hide();
                        input.value = '';
                        confirmInput.value = '';
                    }, 600);
                } else {
                    const data = await unlockResp.json();
                    this.showError(data.detail || 'Vault created but failed to unlock. Try unlocking manually.');
                }
            } else {
                const data = await response.json();
                this.showError(data.detail || 'Failed to create vault');
            }
        } catch (error) {
            this.showError('Failed to connect to vault service. Is the backend running?');
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Create Vault';
        }
    }

    async handleUnlock() {
        const input = this.shadowRoot.getElementById('master-password');
        const submitBtn = this.shadowRoot.getElementById('submit-btn');
        const password = input.value.trim();

        if (!password) {
            this.showError('Please enter your master password');
            return;
        }

        submitBtn.disabled = true;
        submitBtn.innerHTML = 'Unlocking<span class="loading"></span>';

        try {
            const response = await apiClient.post('/api/vault/unlock', {
                master_password: password
            });

            if (response.ok) {
                this.dispatchEvent(new CustomEvent('vault-unlocked', {
                    bubbles: true,
                    composed: true
                }));
                this.hide();
                input.value = '';
            } else {
                const data = await response.json();
                this.showError(data.detail || 'Incorrect password');
            }
        } catch (error) {
            this.showError('Failed to connect to vault. Please try again.');
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Unlock';
        }
    }

    showError(message) {
        const errorMsg = this.shadowRoot.getElementById('error-message');
        const successMsg = this.shadowRoot.getElementById('success-message');
        successMsg.classList.remove('visible');
        errorMsg.textContent = message;
        errorMsg.classList.add('visible');
    }

    showSuccess(message) {
        const errorMsg = this.shadowRoot.getElementById('error-message');
        const successMsg = this.shadowRoot.getElementById('success-message');
        errorMsg.classList.remove('visible');
        successMsg.textContent = message;
        successMsg.classList.add('visible');
    }

    show() {
        const overlay = this.shadowRoot.getElementById('overlay');
        overlay.classList.remove('hidden');
        this._updateMode();
        setTimeout(() => {
            this.shadowRoot.getElementById('master-password').focus();
        }, 300);
    }

    hide() {
        const overlay = this.shadowRoot.getElementById('overlay');
        overlay.classList.add('hidden');
        const input = this.shadowRoot.getElementById('master-password');
        const confirmInput = this.shadowRoot.getElementById('confirm-password');
        const errorMsg = this.shadowRoot.getElementById('error-message');
        const successMsg = this.shadowRoot.getElementById('success-message');
        input.value = '';
        confirmInput.value = '';
        errorMsg.classList.remove('visible');
        successMsg.classList.remove('visible');
        // Reset requirements
        this._updateRequirements('');
    }
}

customElements.define('vault-unlock', VaultUnlockModal);
