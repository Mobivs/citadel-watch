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
        const svgAttr = 'width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"';
        const icon = {
            info: `<svg ${svgAttr} style="color:#10B981"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`,
            investigate: `<svg ${svgAttr} style="color:#F59E0B"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`,
            alert: `<svg ${svgAttr} style="color:#FF9900"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
            critical: `<svg ${svgAttr} style="color:#EF4444"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`
        }[this.insight.type] || `<svg ${svgAttr} style="color:#00D9FF"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`;

        this.shadowRoot.innerHTML = `
            <style>
                .card {
                    background: rgba(15, 23, 42, 0.6);
                    backdrop-filter: blur(20px);
                    border: 1px solid rgba(0, 217, 255, 0.1);
                    border-radius: 10px;
                    padding: 0.875rem;
                    box-shadow: 0 4px 16px 0 rgba(0, 0, 0, 0.37);
                }
                .header {
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                    margin-bottom: 0.5rem;
                }
                .icon { font-size: 1rem; }
                .title {
                    font-size: 0.85rem;
                    font-weight: 700;
                    color: #00D9FF;
                }
                .message {
                    font-size: 0.8rem;
                    color: #D1D5DB;
                    line-height: 1.5;
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
