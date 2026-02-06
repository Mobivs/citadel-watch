// PRD: Dashboard - Protected Systems Component
class ProtectedSystems extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({ mode: 'open' });
    }

    connectedCallback() {
        this.render();
    }

    render() {
        this.shadowRoot.innerHTML = `
            <style>
                .card {
                    background: rgba(15, 23, 42, 0.6);
                    backdrop-filter: blur(20px);
                    border: 1px solid rgba(0, 217, 255, 0.1);
                    border-radius: 16px;
                    padding: 1.5rem;
                    box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
                    height: 100%;
                }
                .title { font-size: 0.875rem; color: #9CA3AF; margin-bottom: 0.5rem; }
                .value { font-size: 1.5rem; font-weight: 700; color: #F3F4F6; }
                .subtitle { font-size: 0.75rem; color: #00D9FF; margin-top: 0.5rem; }
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
