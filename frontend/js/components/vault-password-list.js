// PRD: Vault - Password List Component
// Reference: docs/PRD.md v0.2.3, Section: Vault
//
// Displays list of stored passwords (without showing actual passwords)
// Click to view/copy password

import { apiClient } from '../utils/api-client.js';

class VaultPasswordList extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({ mode: 'open' });
        this.passwords = [];
    }

    connectedCallback() {
        this.render();
        // Don't load passwords automatically - wait for vault to be unlocked
        // Passwords will be loaded by VaultManager.updateUI() when vault is unlocked

        // Listen for password added/deleted events
        window.addEventListener('password-added', () => this.loadPasswords());
        window.addEventListener('password-deleted', () => this.loadPasswords());
    }

    async loadPasswords() {
        try {
            const response = await apiClient.get('/api/vault/passwords');
            if (response.ok) {
                const data = await response.json();
                this.passwords = data.passwords || [];
                this.renderPasswords();
            }
        } catch (error) {
            console.error('Failed to load passwords:', error);
        }
    }

    render() {
        this.shadowRoot.innerHTML = `
            <style>
                :host {
                    display: block;
                }

                .password-list {
                    display: flex;
                    flex-direction: column;
                    gap: 0.75rem;
                    max-height: 500px;
                    overflow-y: auto;
                }

                /* Empty State */
                .empty-state {
                    text-align: center;
                    padding: 3rem 1rem;
                    color: #94a3b8;
                }

                .empty-icon {
                    font-size: 3rem;
                    margin-bottom: 1rem;
                    opacity: 0.5;
                }

                /* Password Card */
                .password-card {
                    background: rgba(15, 23, 42, 0.4);
                    border: 1px solid rgba(0, 217, 255, 0.1);
                    border-radius: 12px;
                    padding: 1rem;
                    cursor: pointer;
                    transition: all 0.3s ease;
                }

                .password-card:hover {
                    border-color: rgba(0, 217, 255, 0.3);
                    background: rgba(15, 23, 42, 0.6);
                    transform: translateX(4px);
                }

                .card-header {
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    margin-bottom: 0.5rem;
                }

                .card-title {
                    font-weight: 600;
                    color: #e2e8f0;
                    font-size: 1rem;
                }

                .category-badge {
                    padding: 0.25rem 0.75rem;
                    border-radius: 12px;
                    font-size: 0.75rem;
                    font-weight: 500;
                }

                .category-email { background: rgba(16, 185, 129, 0.2); color: #10B981; }
                .category-banking { background: rgba(245, 158, 11, 0.2); color: #F59E0B; }
                .category-social { background: rgba(139, 92, 246, 0.2); color: #8B5CF6; }
                .category-work { background: rgba(59, 130, 246, 0.2); color: #3B82F6; }
                .category-general { background: rgba(100, 116, 139, 0.2); color: #64748b; }

                .card-meta {
                    display: flex;
                    gap: 1rem;
                    font-size: 0.875rem;
                    color: #94a3b8;
                }

                .meta-item {
                    display: flex;
                    align-items: center;
                    gap: 0.25rem;
                }

                /* Loading State */
                .loading {
                    text-align: center;
                    padding: 2rem;
                    color: #94a3b8;
                }

                /* Scrollbar */
                .password-list::-webkit-scrollbar {
                    width: 8px;
                }

                .password-list::-webkit-scrollbar-track {
                    background: rgba(15, 23, 42, 0.4);
                    border-radius: 4px;
                }

                .password-list::-webkit-scrollbar-thumb {
                    background: rgba(0, 217, 255, 0.3);
                    border-radius: 4px;
                }

                .password-list::-webkit-scrollbar-thumb:hover {
                    background: rgba(0, 217, 255, 0.5);
                }
            </style>

            <div class="password-list" id="password-list">
                <div class="loading">Loading passwords...</div>
            </div>
        `;
    }

    renderPasswords() {
        const container = this.shadowRoot.getElementById('password-list');

        if (this.passwords.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">🔑</div>
                    <p>No passwords stored yet</p>
                    <p style="font-size: 0.875rem; margin-top: 0.5rem;">Click "Add Password" to get started</p>
                </div>
            `;
            return;
        }

        container.innerHTML = this.passwords.map(pwd => `
            <div class="password-card" data-id="${pwd.id}">
                <div class="card-header">
                    <div class="card-title">${this.escapeHtml(pwd.title)}</div>
                    <span class="category-badge category-${pwd.category}">${pwd.category}</span>
                </div>
                <div class="card-meta">
                    ${pwd.username ? `
                        <div class="meta-item">
                            <span>👤</span>
                            <span>${this.escapeHtml(pwd.username)}</span>
                        </div>
                    ` : ''}
                    ${pwd.website ? `
                        <div class="meta-item">
                            <span>🌐</span>
                            <span>${this.escapeHtml(this.getDomain(pwd.website))}</span>
                        </div>
                    ` : ''}
                </div>
            </div>
        `).join('');

        // Add click handlers
        container.querySelectorAll('.password-card').forEach(card => {
            card.addEventListener('click', () => {
                const id = card.dataset.id;
                this.dispatchEvent(new CustomEvent('password-selected', {
                    detail: { id },
                    bubbles: true,
                    composed: true
                }));
            });
        });
    }

    getDomain(url) {
        try {
            const domain = new URL(url).hostname;
            return domain.replace('www.', '');
        } catch {
            return url;
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

customElements.define('vault-password-list', VaultPasswordList);
