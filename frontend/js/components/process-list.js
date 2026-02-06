// PRD: Dashboard - Process List Component
// Shows running processes with CPU/memory usage

class ProcessList extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({ mode: 'open' });
        this.processes = [];
    }

    connectedCallback() {
        this.render();
        window.addEventListener('processes-updated', (e) => {
            this.updateProcesses(e.detail);
        });
    }

    updateProcesses(processes) {
        this.processes = processes.slice(0, 8); // Top 8 processes
        this.render();
    }

    render() {
        const processesHTML = this.processes.length > 0
            ? this.processes.map(proc => `
                <div class="process-item">
                    <div class="process-name">${proc.name}</div>
                    <div class="process-stats">
                        <span class="cpu">CPU: ${proc.cpu_percent?.toFixed(1) || '0.0'}%</span>
                        <span class="mem">RAM: ${proc.memory_percent?.toFixed(1) || '0.0'}%</span>
                    </div>
                </div>
            `).join('')
            : '<div class="no-data">Loading processes...</div>';

        this.shadowRoot.innerHTML = `
            <style>
                :host { display: block; max-height: 400px; overflow-y: auto; }
                .process-item {
                    padding: 0.75rem;
                    margin-bottom: 0.5rem;
                    background: rgba(0, 217, 255, 0.05);
                    border-radius: 8px;
                    transition: all 0.3s ease;
                }
                .process-item:hover {
                    background: rgba(0, 217, 255, 0.1);
                }
                .process-name {
                    font-size: 0.875rem;
                    color: #F3F4F6;
                    margin-bottom: 0.25rem;
                    font-weight: 500;
                }
                .process-stats {
                    display: flex;
                    gap: 1rem;
                    font-size: 0.75rem;
                }
                .cpu { color: #00D9FF; }
                .mem { color: #9CA3AF; }
                .no-data {
                    text-align: center;
                    padding: 2rem;
                    color: #9CA3AF;
                    font-size: 0.875rem;
                }
                ::-webkit-scrollbar { width: 6px; }
                ::-webkit-scrollbar-track { background: rgba(15, 23, 42, 0.4); }
                ::-webkit-scrollbar-thumb { background: rgba(0, 217, 255, 0.3); border-radius: 3px; }
            </style>
            <div class="processes-container">${processesHTML}</div>
        `;
    }
}

customElements.define('process-list', ProcessList);
