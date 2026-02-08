// PRD: Vault - Password Viewer/Editor Component
// Reference: docs/PRD.md v0.2.4, Section: Vault
//
// Modal for viewing/editing/adding passwords

import { apiClient } from '../utils/api-client.js';

class VaultPasswordViewer extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({ mode: 'open' });
        this.mode = 'add';
        this.passwordData = null;
    }

    connectedCallback() {
        this.render();
        this.setupEventListeners();
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
                    max-width: 420px;
                    width: 90%;
                    max-height: 90vh;
                    overflow-y: auto;
                    box-shadow: 0 12px 40px rgba(0, 217, 255, 0.15);
                    scrollbar-width: thin;
                    scrollbar-color: rgba(0, 217, 255, 0.2) transparent;
                }

                .modal-card::-webkit-scrollbar { width: 4px; }
                .modal-card::-webkit-scrollbar-track { background: transparent; margin-block: 12px; }
                .modal-card::-webkit-scrollbar-thumb { background: rgba(0, 217, 255, 0.2); border-radius: 99px; }
                .modal-card::-webkit-scrollbar-thumb:hover { background: rgba(0, 217, 255, 0.4); }

                h2 {
                    color: #00D9FF;
                    font-size: 1.1rem;
                    margin: 0 0 1rem 0;
                }

                .form-group {
                    margin-bottom: 0.875rem;
                }

                label {
                    display: block;
                    color: #e2e8f0;
                    font-size: 0.75rem;
                    margin-bottom: 0.375rem;
                    font-weight: 500;
                }

                input, textarea, select {
                    width: 100%;
                    padding: 0.5rem 0.75rem;
                    background: rgba(15, 23, 42, 0.6);
                    border: 1px solid rgba(0, 217, 255, 0.2);
                    border-radius: 6px;
                    color: #e2e8f0;
                    font-size: 0.8rem;
                    box-sizing: border-box;
                    font-family: inherit;
                }

                input:focus, textarea:focus, select:focus {
                    outline: none;
                    border-color: #00D9FF;
                    box-shadow: 0 0 0 2px rgba(0, 217, 255, 0.1);
                }

                textarea {
                    resize: vertical;
                    min-height: 60px;
                }

                .password-field {
                    position: relative;
                }

                .password-field input {
                    padding-right: 5.5rem;
                }

                .password-actions {
                    position: absolute;
                    right: 0.375rem;
                    top: 50%;
                    transform: translateY(-50%);
                    display: flex;
                    gap: 0.25rem;
                }

                .icon-btn {
                    background: rgba(0, 217, 255, 0.1);
                    border: 1px solid rgba(0, 217, 255, 0.25);
                    border-radius: 4px;
                    padding: 0.25rem;
                    cursor: pointer;
                    transition: all 0.2s ease;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    color: #00D9FF;
                }

                .icon-btn:hover {
                    background: rgba(0, 217, 255, 0.2);
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
                }

                .btn-primary:hover {
                    transform: translateY(-1px);
                    box-shadow: 0 4px 14px rgba(0, 217, 255, 0.3);
                }

                .btn-secondary {
                    background: rgba(0, 217, 255, 0.1);
                    color: #00D9FF;
                    border: 1px solid rgba(0, 217, 255, 0.3);
                }

                .btn-danger {
                    background: rgba(239, 68, 68, 0.1);
                    color: #EF4444;
                    border: 1px solid rgba(239, 68, 68, 0.3);
                }

                .btn-danger:hover {
                    background: rgba(239, 68, 68, 0.2);
                }

                .success-message {
                    background: rgba(16, 185, 129, 0.1);
                    border-left: 3px solid #10B981;
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
            </style>

            <div class="modal-overlay hidden" id="overlay">
                <div class="modal-card">
                    <h2 id="modal-title">Add Password</h2>

                    <div class="success-message" id="success-message"></div>

                    <form id="password-form">
                        <div class="form-group">
                            <label for="title">Title *</label>
                            <input type="text" id="title" placeholder="e.g., Gmail Account" required />
                        </div>

                        <div class="form-group">
                            <label for="username">Username / Email</label>
                            <input type="text" id="username" placeholder="e.g., user@example.com" />
                        </div>

                        <div class="form-group">
                            <label for="password">Password *</label>
                            <div class="password-field">
                                <input type="password" id="password" placeholder="Enter password" required />
                                <div class="password-actions">
                                    <button type="button" class="icon-btn" id="toggle-visibility" title="Show/Hide">
                                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                                    </button>
                                    <button type="button" class="icon-btn" id="copy-password" title="Copy">
                                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                                    </button>
                                </div>
                            </div>
                        </div>

                        <div class="form-group">
                            <label for="website">Website URL</label>
                            <input type="url" id="website" placeholder="https://example.com" />
                        </div>

                        <div class="form-group">
                            <label for="category">Category</label>
                            <select id="category">
                                <option value="general">General</option>
                                <option value="email">Email</option>
                                <option value="banking">Banking</option>
                                <option value="social">Social Media</option>
                                <option value="work">Work</option>
                            </select>
                        </div>

                        <div class="form-group">
                            <label for="notes">Notes</label>
                            <textarea id="notes" placeholder="Optional notes..."></textarea>
                        </div>

                        <div class="button-group">
                            <button type="button" class="btn-secondary" id="cancel-btn">Cancel</button>
                            <button type="button" class="btn-danger hidden" id="delete-btn">Delete</button>
                            <button type="submit" class="btn-primary" id="save-btn">Save</button>
                        </div>
                    </form>
                </div>
            </div>
        `;
    }

    setupEventListeners() {
        const form = this.shadowRoot.getElementById('password-form');
        const cancelBtn = this.shadowRoot.getElementById('cancel-btn');
        const deleteBtn = this.shadowRoot.getElementById('delete-btn');
        const toggleBtn = this.shadowRoot.getElementById('toggle-visibility');
        const copyBtn = this.shadowRoot.getElementById('copy-password');
        const passwordInput = this.shadowRoot.getElementById('password');

        // SVG icons for toggle
        const eyeOpenSvg = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
        const eyeClosedSvg = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            await this.handleSave();
        });

        cancelBtn.addEventListener('click', () => this.hide());

        deleteBtn.addEventListener('click', async () => {
            if (confirm('Delete this password? This cannot be undone.')) {
                await this.handleDelete();
            }
        });

        toggleBtn.addEventListener('click', () => {
            const type = passwordInput.type === 'password' ? 'text' : 'password';
            passwordInput.type = type;
            toggleBtn.innerHTML = type === 'password' ? eyeOpenSvg : eyeClosedSvg;
        });

        copyBtn.addEventListener('click', async () => {
            try {
                const password = passwordInput.value;
                await navigator.clipboard.writeText(password);
                this.showSuccess('Password copied! (Auto-clears in 30s)');

                setTimeout(async () => {
                    try {
                        const currentClipboard = await navigator.clipboard.readText();
                        if (currentClipboard === password) {
                            await navigator.clipboard.writeText('');
                        }
                    } catch (error) {
                        // Clipboard read permission may be denied
                    }
                }, 30000);
            } catch (error) {
                alert('Failed to copy password');
            }
        });
    }

    async handleSave() {
        const formData = {
            title: this.shadowRoot.getElementById('title').value,
            username: this.shadowRoot.getElementById('username').value,
            password: this.shadowRoot.getElementById('password').value,
            website: this.shadowRoot.getElementById('website').value,
            category: this.shadowRoot.getElementById('category').value,
            notes: this.shadowRoot.getElementById('notes').value
        };

        try {
            const response = await apiClient.post('/api/vault/passwords', formData);

            if (response.ok) {
                this.showSuccess('Password saved successfully!');
                setTimeout(() => {
                    this.dispatchEvent(new CustomEvent('password-added', {
                        bubbles: true,
                        composed: true
                    }));
                    this.hide();
                }, 1500);
            } else {
                alert('Failed to save password');
            }
        } catch (error) {
            alert('Failed to connect to vault');
        }
    }

    async handleDelete() {
        if (!this.passwordData) return;

        try {
            const response = await apiClient.delete(`/api/vault/passwords/${this.passwordData.id}`);

            if (response.ok) {
                this.dispatchEvent(new CustomEvent('password-deleted', {
                    bubbles: true,
                    composed: true
                }));
                this.hide();
            } else {
                alert('Failed to delete password');
            }
        } catch (error) {
            alert('Failed to connect to vault');
        }
    }

    showSuccess(message) {
        const successMsg = this.shadowRoot.getElementById('success-message');
        successMsg.textContent = message;
        successMsg.classList.add('visible');
        setTimeout(() => successMsg.classList.remove('visible'), 3000);
    }

    async showAdd() {
        this.mode = 'add';
        this.passwordData = null;

        this.shadowRoot.getElementById('modal-title').textContent = 'Add Password';
        this.shadowRoot.getElementById('delete-btn').classList.add('hidden');
        this.shadowRoot.getElementById('save-btn').textContent = 'Save';
        this.shadowRoot.getElementById('password-form').reset();

        this.show();
    }

    async showView(passwordId) {
        this.mode = 'view';

        try {
            const response = await apiClient.get(`/api/vault/passwords/${passwordId}`);
            if (response.ok) {
                this.passwordData = await response.json();

                this.shadowRoot.getElementById('title').value = this.passwordData.title || '';
                this.shadowRoot.getElementById('username').value = this.passwordData.username || '';
                this.shadowRoot.getElementById('password').value = this.passwordData.password || '';
                this.shadowRoot.getElementById('website').value = this.passwordData.website || '';
                this.shadowRoot.getElementById('category').value = this.passwordData.category || 'general';
                this.shadowRoot.getElementById('notes').value = this.passwordData.notes || '';

                this.shadowRoot.getElementById('modal-title').textContent = 'View Password';
                this.shadowRoot.getElementById('delete-btn').classList.remove('hidden');
                this.shadowRoot.getElementById('save-btn').textContent = 'Update';

                this.show();
            }
        } catch (error) {
            alert('Failed to load password');
        }
    }

    show() {
        this.shadowRoot.getElementById('overlay').classList.remove('hidden');
    }

    hide() {
        this.shadowRoot.getElementById('overlay').classList.add('hidden');
        this.shadowRoot.getElementById('password-form').reset();
        this.shadowRoot.getElementById('success-message').classList.remove('visible');
    }
}

customElements.define('vault-password-viewer', VaultPasswordViewer);
