// Remote Shield — VPS agent monitoring, threat timeline, and heatmap.
// Uses its own WebSocket connection for remote shield events.
// PRD: Remote Shield page - P2.1.5

const API_BASE = '/api';
let agentsData = {};
let threatsData = [];
let _ws = null;
let _refreshInterval = null;

// ── WebSocket ────────────────────────────────────────────────────────

function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    _ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

    _ws.addEventListener('message', (event) => {
        const message = JSON.parse(event.data);

        if (message.type === 'threat' || message.type === 'threat:remote-shield') {
            threatsData.unshift(message.data);
            if (threatsData.length > 100) threatsData.pop();
            renderThreats();
            updateStats();
            updateHeatmap();
        }

        if (message.type === 'agent_update') {
            if (message.data.id) {
                agentsData[message.data.id] = message.data;
            }
            renderAgents();
            updateHeatmap();
        }
    });

    _ws.addEventListener('error', (error) => {
        console.error('Remote Shield WebSocket error:', error);
    });

    _ws.addEventListener('close', () => {
        console.log('Remote Shield WebSocket closed, reconnecting...');
        setTimeout(initWebSocket, 3000);
    });
}

// ── API fetchers ─────────────────────────────────────────────────────

async function fetchAgents() {
    try {
        const response = await fetch(`${API_BASE}/agents`);
        const agents = await response.json();
        agents.forEach(agent => {
            agentsData[agent.id] = agent;
        });
        renderAgents();
        updateHeatmap();
    } catch (error) {
        console.error('Failed to fetch agents:', error);
    }
}

async function fetchThreats() {
    try {
        const response = await fetch(`${API_BASE}/threats/remote-shield?limit=50`);
        threatsData = await response.json();
        renderThreats();
        updateStats();
    } catch (error) {
        console.error('Failed to fetch threats:', error);
    }
}

// ── Renderers ────────────────────────────────────────────────────────

function renderAgents() {
    const container = document.getElementById('agents-container');
    if (!container) return;

    if (Object.keys(agentsData).length === 0) {
        container.innerHTML = `
            <div class="empty-state" style="grid-column: 1 / -1;">
                <div class="empty-state-icon">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;opacity:0.4"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
                </div>
                <div>No agents connected</div>
            </div>
        `;
        return;
    }

    container.innerHTML = Object.values(agentsData).map(agent => {
        const isActive = agent.status === 'active';
        const lastHeartbeat = agent.last_heartbeat ? new Date(agent.last_heartbeat).toLocaleString() : 'Never';
        const lastScan = agent.last_scan_at ? new Date(agent.last_scan_at).toLocaleString() : 'Never';

        return `
            <div class="agent-panel">
                <div class="agent-header">
                    <div class="agent-status-indicator ${isActive ? 'active' : 'inactive'}"></div>
                    <div class="agent-name">${escapeHtml(agent.hostname)}</div>
                </div>
                <div class="agent-info">
                    <div class="info-row">
                        <span class="info-label">Status:</span>
                        <span class="info-value">${escapeHtml(agent.status.toUpperCase())}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">IP Address:</span>
                        <span class="info-value">${escapeHtml(agent.ip_address)}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Last Heartbeat:</span>
                        <span class="info-value">${lastHeartbeat}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Last Scan:</span>
                        <span class="info-value">${lastScan}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Registered:</span>
                        <span class="info-value">${new Date(agent.registered_at).toLocaleDateString()}</span>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function renderThreats() {
    const container = document.getElementById('threat-timeline-container');
    if (!container) return;

    if (threatsData.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;opacity:0.4"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                </div>
                <div>No threats detected</div>
            </div>
        `;
        return;
    }

    container.innerHTML = threatsData.map(threat => {
        const severity = threat.severity || 5;
        let severityClass = 'low';
        if (severity >= 8) severityClass = 'critical';
        else if (severity >= 6) severityClass = 'high';
        else if (severity >= 5) severityClass = 'medium';

        const threatTime = new Date(threat.reported_at || threat.timestamp).toLocaleString();

        return `
            <div class="threat-item severity-${severityClass}">
                <div class="threat-title">
                    ${escapeHtml(threat.title)}
                    <span class="threat-badge ${severityClass}">S${severity}</span>
                </div>
                <div class="threat-meta">
                    <span class="threat-meta-item">${escapeHtml(threat.hostname)}</span>
                    <span class="threat-meta-item">${escapeHtml(threat.type)}</span>
                    <span class="threat-meta-item">${threatTime}</span>
                </div>
                ${threat.details ? `<div style="font-size: 0.65rem; color: #6B7280; margin-top: 0.25rem;">Details: ${escapeHtml(JSON.stringify(threat.details).substring(0, 100))}...</div>` : ''}
            </div>
        `;
    }).join('');
}

function updateHeatmap() {
    const grid = document.getElementById('heatmap-grid');
    if (!grid) return;

    if (Object.keys(agentsData).length === 0) {
        grid.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;opacity:0.4"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
                </div>
                <div>No agents registered yet</div>
            </div>
        `;
        return;
    }

    grid.innerHTML = Object.values(agentsData).map(agent => {
        const agentThreats = threatsData.filter(t => t.agent_id === agent.id || t.hostname === agent.hostname);
        const threatCount = agentThreats.length;
        let level = 'none';
        if (threatCount >= 5) level = 'critical';
        else if (threatCount >= 3) level = 'high';
        else if (threatCount > 0) level = 'medium';

        return `
            <div class="heatmap-cell">
                <div class="heatmap-hostname">${escapeHtml(agent.hostname)}</div>
                <div class="heatmap-count">${threatCount}</div>
                <div class="heatmap-level ${level}">${level.toUpperCase()}</div>
            </div>
        `;
    }).join('');
}

function updateStats() {
    const totalAgents = Object.keys(agentsData).length;
    const activeAgents = Object.values(agentsData).filter(a => a.status === 'active').length;
    const totalThreats = threatsData.length;
    const criticalThreats = threatsData.filter(t => (t.severity || 5) >= 8).length;

    const el = (id, val) => { const e = document.getElementById(id); if (e) e.textContent = val; };
    el('total-agents', totalAgents);
    el('active-agents', activeAgents);
    el('total-threats', totalThreats);
    el('critical-threats', criticalThreats);
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

// ── Init / Destroy ───────────────────────────────────────────────────

async function init() {
    destroy();
    initWebSocket();
    await Promise.all([fetchAgents(), fetchThreats()]);
    _refreshInterval = setInterval(() => {
        fetchAgents();
        fetchThreats();
    }, 30000);
}

function destroy() {
    if (_refreshInterval) { clearInterval(_refreshInterval); _refreshInterval = null; }
    if (_ws) {
        _ws.onclose = null; // prevent reconnect
        _ws.close();
        _ws = null;
    }
    agentsData = {};
    threatsData = [];
}

// ── Auto-init (standalone page use) ──────────────────────────────────

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}

// ── Exports ──────────────────────────────────────────────────────────

export { init, destroy };
