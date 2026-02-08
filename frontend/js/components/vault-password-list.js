// PRD: Vault - Password List Component
// Reference: docs/PRD.md v0.2.4, Section: Vault
//
// Displays list of stored passwords (without showing actual passwords)

import { apiClient } from '../utils/api-client.js';

class VaultPasswordList extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({ mode: 'open' });
        this.passwords = [];
    }

    connectedCallback() {
        this.render();
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
                    gap: 0.5rem;
                    max-height: 500px;
                    overflow-y: auto;
                }

                .empty-state {
                    text-align: center;
                    padding: 1.5rem 1rem;
                    color: #94a3b8;
                }

                .empty-icon {
                    margin-bottom: 0.5rem;
                    display: flex;
                    justify-content: center;
                    opacity: 0.4;
                }

                .empty-state p {
                    font-size: 0.8rem;
                    margin: 0;
                }

                .empty-state .hint {
                    font-size: 0.7rem;
                    margin-top: 0.375rem;
                    color: #6B7280;
                }

                .password-card {
                    background: rgba(15, 23, 42, 0.4);
                    border: 1px solid rgba(0, 217, 255, 0.1);
                    border-radius: 10px;
                    padding: 0.875rem;
                    cursor: pointer;
                    transition: all 0.2s ease;
                }

                .password-card:hover {
                    border-color: rgba(0, 217, 255, 0.3);
                    background: rgba(15, 23, 42, 0.6);
                    transform: translateX(3px);
                }

                .card-header {
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    margin-bottom: 0.375rem;
                }

                .card-title {
                    font-weight: 600;
                    color: #e2e8f0;
                    font-size: 0.85rem;
                }

                .category-badge {
                    padding: 0.125rem 0.5rem;
                    border-radius: 8px;
                    font-size: 0.65rem;
                    font-weight: 500;
                }

                .category-email { background: rgba(16, 185, 129, 0.15); color: #10B981; }
                .category-banking { background: rgba(245, 158, 11, 0.15); color: #F59E0B; }
                .category-social { background: rgba(0, 217, 255, 0.15); color: #00D9FF; }
                .category-work { background: rgba(0, 204, 102, 0.15); color: #00cc66; }
                .category-general { background: rgba(100, 116, 139, 0.15); color: #64748b; }

                .card-meta {
                    display: flex;
                    gap: 0.75rem;
                    font-size: 0.75rem;
                    color: #94a3b8;
                }

                .meta-item {
                    display: flex;
                    align-items: center;
                    gap: 0.25rem;
                }

                .meta-item svg {
                    opacity: 0.6;
                }

                .loading {
                    text-align: center;
                    padding: 1.5rem;
                    color: #94a3b8;
                    font-size: 0.8rem;
                }

                .password-list::-webkit-scrollbar {
                    width: 6px;
                }

                .password-list::-webkit-scrollbar-track {
                    background: rgba(15, 23, 42, 0.4);
                    border-radius: 3px;
                }

                .password-list::-webkit-scrollbar-thumb {
                    background: rgba(0, 217, 255, 0.25);
                    border-radius: 3px;
                }

                .password-list::-webkit-scrollbar-thumb:hover {
                    background: rgba(0, 217, 255, 0.4);
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
                    <div class="empty-icon">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>
                    </div>
                    <p>No passwords stored yet</p>
                    <p class="hint">Click "Add Password" to get started</p>
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
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                            <span>${this.escapeHtml(pwd.username)}</span>
                        </div>
                    ` : ''}
                    ${pwd.website ? `
                        <div class="meta-item">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
                            <span>${this.escapeHtml(this.getDomain(pwd.website))}</span>
                        </div>
                    ` : ''}
                </div>
            </div>
        `).join('');

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
