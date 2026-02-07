// PRD: Dashboard - AI Insights Component
// Shows AI's latest analysis and recommendations

class AIInsights extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({ mode: 'open' });
        this.insight = {
            message: "All systems nominal. No threats detected in the last hour.",
            type: 'info'
        };
    }

    connectedCallback() {
        this.render();
        this.updateAriaLabel();
        window.addEventListener('ai-insight', (e) => {
            this.updateInsight(e.detail);
        });
    }

    updateInsight(insight) {
        this.insight = insight;
        this.updateAriaLabel();
        this.render();
    }

    updateAriaLabel() {
        const typeLabel = {
            info: 'Information',
            investigate: 'Investigation',
            alert: 'Alert',
            critical: 'Critical'
        }[this.insight.type] || 'Information';
        this.setAttribute('aria-label', `AI Insight: ${typeLabel}. ${this.insight.message}`);
    }

    render() {
        const typeClass = `alert-${this.insight.type}`;
        const icon = {
            info: '✅',
            investigate: '🔍',
            alert: '🛡️',
            critical: '⚠️'
        }[this.insight.type] || 'ℹ️';

        this.shadowRoot.innerHTML = `
            <style>
                .card {
                    background: rgba(15, 23, 42, 0.6);
                    backdrop-filter: blur(20px);
                    border: 1px solid rgba(0, 217, 255, 0.1);
                    border-radius: 16px;
                    padding: 1.5rem;
                    box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
                }
                .header {
                    display: flex;
                    align-items: center;
                    gap: 0.75rem;
                    margin-bottom: 1rem;
                }
                .icon { font-size: 1.5rem; }
                .title {
                    font-size: 1.125rem;
                    font-weight: 700;
                    color: #00D9FF;
                }
                .message {
                    font-size: 0.875rem;
                    color: #D1D5DB;
                    line-height: 1.6;
                }
            </style>
            <div class="card">
                <div class="header">
                    <span class="icon">${icon}</span>
                    <span class="title">AI Insights</span>
                </div>
                <div class="message">${this.insight.message}</div>
            </div>
        `;
    }
}

customElements.define('ai-insights', AIInsights);
