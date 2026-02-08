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
        this.updateAriaLabel();
        window.addEventListener('processes-updated', (e) => {
            this.updateProcesses(e.detail);
        });
    }

    updateProcesses(processes) {
        this.processes = processes.slice(0, 8); // Top 8 processes
        this.updateAriaLabel();
        this.render();
    }

    updateAriaLabel() {
        const processCount = this.processes.length;
        this.setAttribute('aria-label', `Running processes: Showing top ${processCount} process${processCount !== 1 ? 'es' : ''} by resource usage with CPU and RAM percentages.`);
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
                :host {
                    display: block;
                    height: 100%;
                    overflow: hidden;
                }
                .processes-container {
                    height: 100%;
                    overflow-y: auto;
                    padding-right: 4px;
                }
                .process-item {
                    padding: 0.5rem;
                    margin-bottom: 0.25rem;
                    background: rgba(0, 217, 255, 0.05);
                    border-radius: 6px;
                    transition: all 0.3s ease;
                }
                .process-item:hover {
                    background: rgba(0, 217, 255, 0.1);
                }
                .process-name {
                    font-size: 0.8rem;
                    color: #F3F4F6;
                    margin-bottom: 0.125rem;
                    font-weight: 500;
                }
                .process-stats {
                    display: flex;
                    gap: 0.75rem;
                    font-size: 0.7rem;
                }
                .cpu { color: #00D9FF; }
                .mem { color: #9CA3AF; }
                .no-data {
                    text-align: center;
                    padding: 2rem;
                    color: #9CA3AF;
                    font-size: 0.875rem;
                }
                * { scrollbar-width: thin; scrollbar-color: rgba(0, 217, 255, 0.2) transparent; }
                ::-webkit-scrollbar { width: 5px; }
                ::-webkit-scrollbar-track { background: transparent; margin-block: 12px; }
                ::-webkit-scrollbar-thumb { background: rgba(0, 217, 255, 0.2); border-radius: 99px; }
                ::-webkit-scrollbar-thumb:hover { background: rgba(0, 217, 255, 0.4); }
                ::-webkit-scrollbar-button { display: none; }
            </style>
            <div class="processes-container">${processesHTML}</div>
        `;
    }
}

customElements.define('process-list', ProcessList);
