// PRD: Dashboard - Threat Level Component
// Reference: docs/PRD.md v0.2.3, Section: Dashboard
// Shows: Real-time threat level (green/yellow/red)

class ThreatLevel extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({ mode: 'open' });
        this.level = 'green'; // green, yellow, red
        this.threatsBlocked = 0;
    }

    connectedCallback() {
        this.render();
        // Set accessible label with current threat level
        const config = this.getLevelConfig();
        this.setAttribute('aria-label', `Threat level: ${config.text}. ${this.threatsBlocked} threats blocked today.`);
        window.addEventListener('threat-level-changed', (e) => {
            this.updateLevel(e.detail);
        });
    }

    updateLevel({ level, threatsBlocked }) {
        this.level = level;
        this.threatsBlocked = threatsBlocked;
        const config = this.getLevelConfig();
        this.setAttribute('aria-label', `Threat level: ${config.text}. ${this.threatsBlocked} threats blocked today.`);
        this.render();
    }

    getLevelConfig() {
        const dot = (c) => `<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:${c};box-shadow:0 0 8px ${c};"></span>`;
        const configs = {
            green: {
                color: '#10B981',
                icon: dot('#10B981'),
                text: 'All Clear',
                message: "You're protected. No active threats detected."
            },
            yellow: {
                color: '#F59E0B',
                icon: dot('#F59E0B'),
                text: 'Investigating',
                message: "I'm checking something unusual. You're still protected."
            },
            red: {
                color: '#EF4444',
                icon: dot('#EF4444'),
                text: 'Active Threats',
                message: "Threats detected and blocked. You're safe."
            }
        };
        return configs[this.level] || configs.green;
    }

    render() {
        const config = this.getLevelConfig();

        this.shadowRoot.innerHTML = `
            <style>
                :host {
                    display: block;
                    height: 100%;
                }

                .card {
                    background: rgba(15, 23, 42, 0.6);
                    backdrop-filter: blur(20px);
                    border: 1px solid rgba(0, 217, 255, 0.1);
                    border-radius: 10px;
                    padding: 0.875rem;
                    transition: all 0.3s ease;
                    box-shadow: 0 4px 16px 0 rgba(0, 0, 0, 0.37);
                    height: 100%;
                    box-sizing: border-box;
                    overflow: hidden;
                }

                .card:hover {
                    border-color: rgba(0, 217, 255, 0.3);
                    transform: translateY(-1px);
                }

                .title {
                    font-size: 0.75rem;
                    color: #9CA3AF;
                    margin-bottom: 0.25rem;
                }

                .level-display {
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                    margin-bottom: 0.375rem;
                }

                .level-icon {
                    font-size: 1.25rem;
                }

                .level-text {
                    font-size: 1.1rem;
                    font-weight: 700;
                    color: ${config.color};
                }

                .message {
                    font-size: 0.75rem;
                    color: #D1D5DB;
                    margin-bottom: 0.5rem;
                }

                .stats {
                    display: flex;
                    justify-content: space-between;
                    padding-top: 0.5rem;
                    border-top: 1px solid rgba(0, 217, 255, 0.1);
                }

                .stat-item {
                    text-align: center;
                }

                .stat-value {
                    font-size: 1rem;
                    font-weight: 700;
                    color: #00D9FF;
                }

                .stat-label {
                    font-size: 0.65rem;
                    color: #9CA3AF;
                }
            </style>

            <div class="card">
                <div class="title">Threat Level</div>
                <div class="level-display">
                    <span class="level-icon">${config.icon}</span>
                    <span class="level-text">${config.text}</span>
                </div>
                <div class="message">${config.message}</div>
                <div class="stats">
                    <div class="stat-item">
                        <div class="stat-value">${this.threatsBlocked}</div>
                        <div class="stat-label">Blocked Today</div>
                    </div>
                </div>
            </div>
        `;
    }
}

customElements.define('threat-level', ThreatLevel);
