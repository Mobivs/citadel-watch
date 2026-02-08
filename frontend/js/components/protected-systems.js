// PRD: Dashboard - Protected Systems Component
class ProtectedSystems extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({ mode: 'open' });
    }

    connectedCallback() {
        this.render();
        // Set accessible label
        this.setAttribute('aria-label', 'Protected systems: 1 system, Local Machine Windows 11');
    }

    render() {
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
                    box-shadow: 0 4px 16px 0 rgba(0, 0, 0, 0.37);
                    height: 100%;
                    box-sizing: border-box;
                    overflow: hidden;
                }
                .title { font-size: 0.75rem; color: #9CA3AF; margin-bottom: 0.25rem; }
                .value { font-size: 1.25rem; font-weight: 700; color: #F3F4F6; }
                .subtitle { font-size: 0.7rem; color: #00D9FF; margin-top: 0.25rem; }
            </style>
            <div class="card">
                <div class="title">Protected Systems</div>
                <div class="value">1 System</div>
                <div class="subtitle">Local Machine (Windows 11)</div>
            </div>
        `;
    }
}

customElements.define('protected-systems', ProtectedSystems);
