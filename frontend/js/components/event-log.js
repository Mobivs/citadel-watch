// PRD: Dashboard - Event Log Component
// Shows recent security events with severity color coding

class EventLog extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({ mode: 'open' });
        this.events = [];
    }

    connectedCallback() {
        this.render();
        window.addEventListener('new-event', (e) => {
            this.addEvent(e.detail);
        });
    }

    addEvent(event) {
        this.events.unshift(event); // Add to beginning
        if (this.events.length > 10) this.events.pop(); // Keep last 10
        this.render();
    }

    getSeverityIcon(severity) {
        const icons = {
            info: '🟢',
            investigate: '🟡',
            alert: '🟠',
            critical: '🔴'
        };
        return icons[severity] || '⚪';
    }

    render() {
        const eventsHTML = this.events.length > 0
            ? this.events.map(event => `
                <div class="event-item fade-in">
                    <span class="severity-icon">${this.getSeverityIcon(event.severity)}</span>
                    <div class="event-content">
                        <div class="event-message">${event.message}</div>
                        <div class="event-time">${new Date(event.timestamp).toLocaleTimeString()}</div>
                    </div>
                </div>
            `).join('')
            : '<div class="no-events">No recent events. All clear! 🟢</div>';

        this.shadowRoot.innerHTML = `
            <style>
                :host { display: block; max-height: 400px; overflow-y: auto; }
                .event-item {
                    display: flex;
                    gap: 0.75rem;
                    padding: 0.75rem;
                    margin-bottom: 0.5rem;
                    background: rgba(0, 217, 255, 0.05);
                    border-radius: 8px;
                    border-left: 3px solid rgba(0, 217, 255, 0.3);
                    transition: all 0.3s ease;
                }
                .event-item:hover {
                    background: rgba(0, 217, 255, 0.1);
                    transform: translateX(4px);
                }
                .severity-icon { font-size: 1.25rem; }
                .event-content { flex: 1; }
                .event-message {
                    font-size: 0.875rem;
                    color: #F3F4F6;
                    margin-bottom: 0.25rem;
                }
                .event-time {
                    font-size: 0.75rem;
                    color: #9CA3AF;
                }
                .no-events {
                    text-align: center;
                    padding: 2rem;
                    color: #9CA3AF;
                    font-size: 0.875rem;
                }
                @keyframes fadeIn {
                    from { opacity: 0; transform: translateY(10px); }
                    to { opacity: 1; transform: translateY(0); }
                }
                .fade-in { animation: fadeIn 0.5s ease-out; }

                /* Scrollbar */
                ::-webkit-scrollbar { width: 6px; }
                ::-webkit-scrollbar-track { background: rgba(15, 23, 42, 0.4); }
                ::-webkit-scrollbar-thumb { background: rgba(0, 217, 255, 0.3); border-radius: 3px; }
            </style>
            <div class="events-container">${eventsHTML}</div>
        `;
    }
}

customElements.define('event-log', EventLog);
