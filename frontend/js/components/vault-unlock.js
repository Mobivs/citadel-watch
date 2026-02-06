// PRD: Vault - Unlock Modal Component
// Reference: docs/PRD.md v0.2.3, Section: Vault
//
// Modal for unlocking vault with master password
// Shown when user first accesses Vault

import { apiClient } from '../utils/api-client.js';

class VaultUnlockModal extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({ mode: 'open' });
    }

    connectedCallback() {
        this.render();
        this.setupEventListeners();
    }

    render() {
        this.shadowRoot.innerHTML = `
            <style>
                /* Modal Overlay */
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

                /* Modal Card */
                .modal-card {
                    background: rgba(15, 23, 42, 0.95);
                    border: 2px solid rgba(0, 217, 255, 0.3);
                    border-radius: 20px;
                    padding: 2rem;
                    max-width: 450px;
                    width: 90%;
                    box-shadow: 0 20px 60px rgba(0, 217, 255, 0.2);
                    animation: slideUp 0.3s ease-out;
                }

                /* Header */
                .modal-header {
                    text-align: center;
                    margin-bottom: 2rem;
                }

                .vault-icon {
                    font-size: 3rem;
                    margin-bottom: 1rem;
                }

                h2 {
                    color: #00D9FF;
                    font-size: 1.5rem;
                    margin: 0 0 0.5rem 0;
                }

                .subtitle {
                    color: #94a3b8;
                    font-size: 0.9rem;
                }

                /* Form */
                .form-group {
                    margin-bottom: 1.5rem;
                }

                label {
                    display: block;
                    color: #e2e8f0;
                    font-size: 0.9rem;
                    margin-bottom: 0.5rem;
                    font-weight: 500;
                }

                input {
                    width: 100%;
                    padding: 0.75rem 1rem;
                    background: rgba(15, 23, 42, 0.6);
                    border: 1px solid rgba(0, 217, 255, 0.2);
                    border-radius: 8px;
                    color: #e2e8f0;
                    font-size: 1rem;
                    transition: all 0.3s ease;
                    box-sizing: border-box;
                }

                input:focus {
                    outline: none;
                    border-color: #00D9FF;
                    box-shadow: 0 0 0 3px rgba(0, 217, 255, 0.1);
                }

                /* Buttons */
                .button-group {
                    display: flex;
                    gap: 1rem;
                    margin-top: 2rem;
                }

                button {
                    flex: 1;
                    padding: 0.75rem 1.5rem;
                    border: none;
                    border-radius: 8px;
                    font-size: 1rem;
                    font-weight: 600;
                    cursor: pointer;
                    transition: all 0.3s ease;
                }

                .btn-primary {
                    background: linear-gradient(135deg, #00D9FF 0%, #0099CC 100%);
                    color: white;
                    box-shadow: 0 4px 15px rgba(0, 217, 255, 0.3);
                }

                .btn-primary:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 6px 20px rgba(0, 217, 255, 0.4);
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

                /* Error Message */
                .error-message {
                    background: rgba(239, 68, 68, 0.1);
                    border-left: 4px solid #EF4444;
                    padding: 0.75rem 1rem;
                    border-radius: 8px;
                    color: #fca5a5;
                    font-size: 0.9rem;
                    margin-bottom: 1rem;
                    display: none;
                }

                .error-message.visible {
                    display: block;
                    animation: shake 0.5s;
                }

                /* Animations */
                @keyframes fadeIn {
                    from { opacity: 0; }
                    to { opacity: 1; }
                }

                @keyframes slideUp {
                    from {
                        opacity: 0;
                        transform: translateY(20px);
                    }
                    to {
                        opacity: 1;
                        transform: translateY(0);
                    }
                }

                @keyframes shake {
                    0%, 100% { transform: translateX(0); }
                    25% { transform: translateX(-10px); }
                    75% { transform: translateX(10px); }
                }

                /* Loading State */
                .loading {
                    display: inline-block;
                    width: 16px;
                    height: 16px;
                    border: 3px solid rgba(255, 255, 255, 0.3);
                    border-top-color: white;
                    border-radius: 50%;
                    animation: spin 0.8s linear infinite;
                    margin-left: 0.5rem;
                }

                @keyframes spin {
                    to { transform: rotate(360deg); }
                }
            </style>

            <div class="modal-overlay hidden" id="overlay">
                <div class="modal-card">
                    <div class="modal-header">
                        <div class="vault-icon">🔐</div>
                        <h2>Unlock Vault</h2>
                        <p class="subtitle">Enter your master password to access stored passwords</p>
                    </div>

                    <div class="error-message" id="error-message"></div>

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

                        <div class="button-group">
                            <button type="button" class="btn-secondary" id="cancel-btn">Cancel</button>
                            <button type="submit" class="btn-primary" id="unlock-btn">
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
        const unlockBtn = this.shadowRoot.getElementById('unlock-btn');
        const input = this.shadowRoot.getElementById('master-password');
        const errorMsg = this.shadowRoot.getElementById('error-message');

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            await this.handleUnlock();
        });

        cancelBtn.addEventListener('click', () => {
            this.hide();
        });

        // Clear error on input
        input.addEventListener('input', () => {
            errorMsg.classList.remove('visible');
        });
    }

    async handleUnlock() {
        const input = this.shadowRoot.getElementById('master-password');
        const unlockBtn = this.shadowRoot.getElementById('unlock-btn');
        const errorMsg = this.shadowRoot.getElementById('error-message');
        const password = input.value.trim();

        if (!password) {
            this.showError('Please enter your master password');
            return;
        }

        // Show loading state
        unlockBtn.disabled = true;
        unlockBtn.innerHTML = 'Unlocking<span class="loading"></span>';

        try {
            const response = await apiClient.post('/api/vault/unlock', {
                master_password: password
            });

            if (response.ok) {
                // Success! Dispatch event
                this.dispatchEvent(new CustomEvent('vault-unlocked', {
                    bubbles: true,
                    composed: true
                }));
                this.hide();
                input.value = ''; // Clear password
            } else {
                const data = await response.json();
                this.showError(data.detail || 'Incorrect password');
            }
        } catch (error) {
            this.showError('Failed to connect to vault. Please try again.');
        } finally {
            unlockBtn.disabled = false;
            unlockBtn.textContent = 'Unlock';
        }
    }

    showError(message) {
        const errorMsg = this.shadowRoot.getElementById('error-message');
        errorMsg.textContent = message;
        errorMsg.classList.add('visible');
    }

    show() {
        const overlay = this.shadowRoot.getElementById('overlay');
        overlay.classList.remove('hidden');

        // Focus password input
        setTimeout(() => {
            this.shadowRoot.getElementById('master-password').focus();
        }, 300);
    }

    hide() {
        const overlay = this.shadowRoot.getElementById('overlay');
        overlay.classList.add('hidden');

        // Clear form
        const input = this.shadowRoot.getElementById('master-password');
        const errorMsg = this.shadowRoot.getElementById('error-message');
        input.value = '';
        errorMsg.classList.remove('visible');
    }
}

customElements.define('vault-unlock', VaultUnlockModal);
