// PRD: Dashboard - Guardian Status Component
// Reference: docs/PRD.md v0.2.3, Section: Dashboard
// Shows: Guardian active/inactive, security level, real-time status

class GuardianStatus extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({ mode: 'open' });
        this.isActive = false;
        this.securityLevel = 'guardian';
    }

    connectedCallback() {
        this.render();
        // Set accessible label with current state
        this.setAttribute('aria-label', `Guardian status: ${this.isActive ? 'Active' : 'Inactive'}, Security level: ${this.securityLevel}`);
        // Listen for state updates
        window.addEventListener('guardian-status-changed', (e) => {
            this.updateStatus(e.detail);
        });
    }

    updateStatus({ isActive, securityLevel }) {
        this.isActive = isActive;
        this.securityLevel = securityLevel;
        this.setAttribute('aria-label', `Guardian status: ${this.isActive ? 'Active' : 'Inactive'}, Security level: ${this.securityLevel}`);
        this.render();
    }

    render() {
        const statusColor = this.isActive ? 'status-green' : 'status-red';
        const statusText = this.isActive ? 'Active' : 'Inactive';
        const statusIcon = this.isActive ? '🟢' : '🔴';

        this.shadowRoot.innerHTML = `
            <style>
                /* Import parent styles */
                @import url('../css/styles.css');

                :host {
                    display: block;
                    height: 100%;
                }

                .card {
                    background: rgba(15, 23, 42, 0.6);
                    backdrop-filter: blur(20px);
                    border: 1px solid rgba(0, 217, 255, 0.1);
                    border-radius: 16px;
                    padding: 1.5rem;
                    transition: all 0.3s ease;
                    box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
                    height: 100%;
                    box-sizing: border-box;
                    overflow: hidden;
                }

                .card:hover {
                    border-color: rgba(0, 217, 255, 0.3);
                    transform: translateY(-2px);
                }

                .status-badge {
                    display: inline-flex;
                    align-items: center;
                    gap: 0.5rem;
                    padding: 0.5rem 1rem;
                    border-radius: 9999px;
                    font-size: 0.875rem;
                    font-weight: 600;
                }

                .status-active {
                    background: rgba(16, 185, 129, 0.2);
                    color: #10B981;
                }

                .status-inactive {
                    background: rgba(239, 68, 68, 0.2);
                    color: #EF4444;
                }

                .title {
                    font-size: 0.875rem;
                    color: #9CA3AF;
                    margin-bottom: 0.5rem;
                }

                .value {
                    font-size: 1.5rem;
                    font-weight: 700;
                    color: #F3F4F6;
                    margin-bottom: 1rem;
                }

                .security-level {
                    font-size: 0.75rem;
                    color: #00D9FF;
                    text-transform: capitalize;
                }
            </style>

            <div class="card">
                <div class="title">Guardian Status</div>
                <div class="value">
                    <span class="status-badge ${this.isActive ? 'status-active' : 'status-inactive'}">
                        ${statusIcon} ${statusText}
                    </span>
                </div>
                <div class="security-level">
                    Security Level: ${this.securityLevel}
                </div>
            </div>
        `;
    }
}

customElements.define('guardian-status', GuardianStatus);
