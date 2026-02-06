// PRD: Vault - Password Viewer/Editor Component
// Reference: docs/PRD.md v0.2.3, Section: Vault
//
// Modal for viewing/editing/adding passwords
// Shows decrypted password with copy-to-clipboard

import { apiClient } from '../utils/api-client.js';

class VaultPasswordViewer extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({ mode: 'open' });
        this.mode = 'add'; // 'add' or 'view'
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
                    border: 2px solid rgba(0, 217, 255, 0.3);
                    border-radius: 20px;
                    padding: 2rem;
                    max-width: 500px;
                    width: 90%;
                    max-height: 90vh;
                    overflow-y: auto;
                    box-shadow: 0 20px 60px rgba(0, 217, 255, 0.2);
                }

                h2 {
                    color: #00D9FF;
                    margin: 0 0 1.5rem 0;
                }

                .form-group {
                    margin-bottom: 1.25rem;
                }

                label {
                    display: block;
                    color: #e2e8f0;
                    font-size: 0.875rem;
                    margin-bottom: 0.5rem;
                    font-weight: 500;
                }

                input, textarea, select {
                    width: 100%;
                    padding: 0.75rem;
                    background: rgba(15, 23, 42, 0.6);
                    border: 1px solid rgba(0, 217, 255, 0.2);
                    border-radius: 8px;
                    color: #e2e8f0;
                    font-size: 0.95rem;
                    box-sizing: border-box;
                    font-family: inherit;
                }

                input:focus, textarea:focus, select:focus {
                    outline: none;
                    border-color: #00D9FF;
                    box-shadow: 0 0 0 3px rgba(0, 217, 255, 0.1);
                }

                textarea {
                    resize: vertical;
                    min-height: 80px;
                }

                /* Password Field with Toggle/Copy */
                .password-field {
                    position: relative;
                }

                .password-actions {
                    position: absolute;
                    right: 0.5rem;
                    top: 50%;
                    transform: translateY(-50%);
                    display: flex;
                    gap: 0.5rem;
                }

                .icon-btn {
                    background: rgba(0, 217, 255, 0.1);
                    border: 1px solid rgba(0, 217, 255, 0.3);
                    border-radius: 6px;
                    padding: 0.5rem;
                    cursor: pointer;
                    transition: all 0.3s ease;
                    font-size: 1rem;
                }

                .icon-btn:hover {
                    background: rgba(0, 217, 255, 0.2);
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
                }

                .btn-primary:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 4px 15px rgba(0, 217, 255, 0.3);
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
                    border-left: 4px solid #10B981;
                    padding: 0.75rem 1rem;
                    border-radius: 8px;
                    color: #6ee7b7;
                    margin-bottom: 1rem;
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

                        <div class="form-group password-field">
                            <label for="password">Password *</label>
                            <input type="password" id="password" placeholder="Enter password" required />
                            <div class="password-actions">
                                <button type="button" class="icon-btn" id="toggle-visibility" title="Show/Hide">👁️</button>
                                <button type="button" class="icon-btn" id="copy-password" title="Copy">📋</button>
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
            toggleBtn.textContent = type === 'password' ? '👁️' : '🙈';
        });

        copyBtn.addEventListener('click', async () => {
            try {
                const password = passwordInput.value;
                await navigator.clipboard.writeText(password);
                this.showSuccess('Password copied to clipboard! (Will auto-clear in 30s)');

                // Security: Auto-clear clipboard after 30 seconds
                setTimeout(async () => {
                    try {
                        // Only clear if clipboard still contains the password
                        const currentClipboard = await navigator.clipboard.readText();
                        if (currentClipboard === password) {
                            await navigator.clipboard.writeText('');
                            console.log('🔒 Clipboard auto-cleared for security');
                        }
                    } catch (error) {
                        // Clipboard read permission might be denied, ignore
                        console.log('Unable to auto-clear clipboard:', error);
                    }
                }, 30000); // 30 seconds
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

        // Clear form
        this.shadowRoot.getElementById('password-form').reset();

        this.show();
    }

    async showView(passwordId) {
        this.mode = 'view';

        // Fetch password details
        try {
            const response = await apiClient.get(`/api/vault/passwords/${passwordId}`);
            if (response.ok) {
                this.passwordData = await response.json();

                // Populate form
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
