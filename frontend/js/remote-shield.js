// Remote Shield — VPS agent monitoring, threat timeline, and heatmap.
// Uses its own WebSocket connection for remote shield events.
// PRD: Remote Shield page - P2.1.5

import { apiClient } from './utils/api-client.js';

const API_BASE = '/api';
let agentsData = {};
let threatsData = [];
let _ws = null;
let _refreshInterval = null;
let _currentMode = 'technical';
let _modeListener = null;

// ── Threat Guidance (plain-English translations) ────────────────────

const THREAT_GUIDANCE = {
    defender_disabled: {
        title: (h) => `Windows Defender was turned off on ${h}`,
        guidance: 'Open Windows Security on that computer and make sure Real-time protection is turned on.',
    },
    firewall_disabled: {
        title: (h) => `The firewall was turned off on ${h}`,
        guidance: 'Open Windows Security > Firewall & network protection and turn on the firewall for all networks.',
    },
    logon_failure: {
        title: (h) => `Multiple failed login attempts on ${h}`,
        guidance: 'Someone may be trying to guess the password. Make sure the account uses a strong, unique password.',
    },
    audit_log_cleared: {
        title: (h) => `Security logs were cleared on ${h}`,
        guidance: 'This could indicate someone is hiding their tracks. Check who has admin access to this computer.',
    },
    process_anomaly: {
        title: (h) => `A suspicious program was detected on ${h}`,
        guidance: 'Run a full antivirus scan on that computer. Avoid downloading software from unknown sources.',
    },
    suspicious_software: {
        title: (h) => `Unfamiliar software was found on ${h}`,
        guidance: 'Check Programs & Features for software you don\'t recognize. Remove anything suspicious.',
    },
    unauthorized_access: {
        title: (h) => `Unauthorized account activity on ${h}`,
        guidance: 'Review who has access to this computer. Change passwords and check for unfamiliar user accounts.',
    },
    windows_update_overdue: {
        title: (h) => `${h} needs a Windows update`,
        guidance: 'Open Settings > Windows Update and install all available updates to stay protected.',
    },
};

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
            if (_currentMode === 'simplified') renderSimplifiedView();
        }

        if (message.type === 'agent_update') {
            if (message.data.id) {
                agentsData[message.data.id] = message.data;
            }
            renderAgents();
            updateHeatmap();
            if (_currentMode === 'simplified') renderSimplifiedView();
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
        renderPatchStatus();  // patch_status included in agent data
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

async function queueCheckUpdates(agentId) {
    try {
        const resp = await fetch(`${API_BASE}/agents/${agentId}/commands`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ command_type: 'check_updates', payload: {} }),
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        // Brief visual feedback
        const btn = document.querySelector(`[data-patch-agent="${agentId}"] .patch-check-btn`);
        if (btn) {
            btn.textContent = 'Queued';
            btn.disabled = true;
            setTimeout(() => { btn.textContent = 'Check for Updates'; btn.disabled = false; }, 5000);
        }
    } catch (err) {
        console.error('Failed to queue check_updates:', err);
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

// ── Patch status rendering ───────────────────────────────────────────

function _patchStatusClass(ps) {
    if (!ps || ps.check_status === 'unknown' || ps.check_status === 'error') return 'unknown';
    if (ps.reboot_required) return 'critical';
    if ((ps.oldest_pending_days || 0) >= 7) return 'critical';
    if ((ps.pending_count || 0) > 0) return 'warning';
    return 'ok';
}

function _patchStatusLabel(ps) {
    const cls = _patchStatusClass(ps);
    if (cls === 'ok') return 'Up to Date';
    if (cls === 'warning') return 'Updates Pending';
    if (cls === 'critical') return ps && ps.reboot_required ? 'Reboot Required' : 'Overdue';
    return 'Unknown';
}

function renderPatchStatus() {
    const container = document.getElementById('patch-status-container');
    if (!container) return;

    const agents = Object.values(agentsData).filter(a => a.platform === 'windows');
    if (agents.length === 0) {
        container.innerHTML = '<div class="empty-state"><div>No Windows agents reporting updates yet.</div></div>';
        return;
    }

    container.innerHTML = agents.map(agent => {
        const ps = agent.patch_status || {};
        const cls = _patchStatusClass(ps);
        const label = _patchStatusLabel(ps);
        const lastCheck = ps.last_check_date ? new Date(ps.last_check_date).toLocaleString() : 'Never';
        const lastInstall = ps.last_install_date ? new Date(ps.last_install_date).toLocaleString() : 'Never';

        return `
            <div class="patch-card" data-patch-agent="${escapeHtml(agent.id)}">
                <div class="agent-header">
                    <div class="patch-dot ${cls}"></div>
                    <div class="agent-name">${escapeHtml(agent.hostname)}</div>
                    <span class="patch-status-badge ${cls}">${label}</span>
                </div>
                <div class="agent-info">
                    <div class="info-row">
                        <span class="info-label">Pending:</span>
                        <span class="info-value">${ps.pending_count ?? '?'}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Installed:</span>
                        <span class="info-value">${ps.installed_count ?? '?'}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Last Check:</span>
                        <span class="info-value">${lastCheck}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Last Install:</span>
                        <span class="info-value">${lastInstall}</span>
                    </div>
                    ${ps.pending_titles && ps.pending_titles.length > 0
                        ? `<div class="info-row" style="flex-direction:column;align-items:flex-start;gap:0.15rem;margin-top:0.25rem;">
                               <span class="info-label">Pending updates:</span>
                               ${ps.pending_titles.slice(0, 3).map(t =>
                                   `<span class="info-value" style="font-size:0.6rem;color:#9CA3AF;">${escapeHtml(t)}</span>`
                               ).join('')}
                               ${ps.pending_titles.length > 3 ? `<span class="info-value" style="font-size:0.6rem;color:#6B7280;">+${ps.pending_titles.length - 3} more</span>` : ''}
                           </div>`
                        : ''}
                </div>
                <button class="patch-check-btn" onclick="window._rsQueueCheck && window._rsQueueCheck('${escapeHtml(agent.id)}')">Check for Updates</button>
            </div>`;
    }).join('');
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}

// ── Simplified mode rendering ────────────────────────────────────────

function applyViewMode(mode) {
    _currentMode = mode;
    const techView = document.getElementById('rs-technical-view');
    const simpView = document.getElementById('rs-simplified-view');
    if (!techView || !simpView) return;

    if (mode === 'simplified') {
        techView.style.display = 'none';
        simpView.style.display = '';
        renderSimplifiedView();
    } else {
        techView.style.display = '';
        simpView.style.display = 'none';
    }
}

function renderSimplifiedView() {
    renderHeroStatus();
    renderDeviceList();
    renderAlertCards();
}

function renderHeroStatus() {
    const iconEl = document.getElementById('rs-hero-icon');
    const titleEl = document.getElementById('rs-hero-title');
    const subtitleEl = document.getElementById('rs-hero-subtitle');
    if (!iconEl || !titleEl || !subtitleEl) return;

    const agents = Object.values(agentsData);
    const critCount = threatsData.filter(t => (t.severity || 5) >= 8).length;
    const highCount = threatsData.filter(t => { const s = t.severity || 5; return s >= 6 && s < 8; }).length;
    const hasAgents = agents.length > 0;

    if (!hasAgents) {
        iconEl.innerHTML = `<svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#6B7280" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`;
        titleEl.textContent = 'No Devices Connected';
        titleEl.style.color = '#9CA3AF';
        subtitleEl.textContent = 'Add a device from the Assets tab to start monitoring.';
    } else if (critCount > 0) {
        iconEl.innerHTML = `<svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#ff3333" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
        titleEl.textContent = 'Action Required';
        titleEl.style.color = '#ff3333';
        subtitleEl.textContent = `${critCount} critical alert${critCount > 1 ? 's' : ''} need your attention.`;
    } else if (highCount > 0) {
        iconEl.innerHTML = `<svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#ff9900" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`;
        titleEl.textContent = 'Attention Needed';
        titleEl.style.color = '#ff9900';
        subtitleEl.textContent = `${highCount} alert${highCount > 1 ? 's' : ''} to review.`;
    } else {
        iconEl.innerHTML = `<svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#00cc66" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`;
        titleEl.textContent = 'All Systems Protected';
        titleEl.style.color = '#00cc66';
        subtitleEl.textContent = `${agents.length} device${agents.length > 1 ? 's' : ''} monitored. No issues found.`;
    }
}

function renderDeviceList() {
    const container = document.getElementById('rs-device-list');
    if (!container) return;

    const agents = Object.values(agentsData);
    if (agents.length === 0) {
        container.innerHTML = '<div style="text-align:center;padding:1rem;color:#6B7280;font-size:0.8rem;">No devices connected yet.</div>';
        return;
    }

    container.innerHTML = agents.map(agent => {
        const isActive = agent.status === 'active';
        const agentThreats = threatsData.filter(t => t.agent_id === agent.id || t.hostname === agent.hostname);
        const hasCritical = agentThreats.some(t => (t.severity || 5) >= 8);
        const hasHigh = agentThreats.some(t => { const s = t.severity || 5; return s >= 6 && s < 8; });

        let dotColor = '#00cc66';
        let statusText = 'Protected';
        if (!isActive) { dotColor = '#6B7280'; statusText = 'Offline'; }
        else if (hasCritical) { dotColor = '#ff3333'; statusText = 'Needs attention'; }
        else if (hasHigh) { dotColor = '#ff9900'; statusText = 'Review alerts'; }

        // Update status line for simplified mode
        const ps = agent.patch_status;
        const patchCls = _patchStatusClass(ps);
        let updateLine = '';
        if (ps && ps.check_status !== 'unknown' && ps.check_status !== 'error') {
            const patchLabel = _patchStatusLabel(ps);
            const patchColor = patchCls === 'ok' ? '#00cc66' : patchCls === 'warning' ? '#e6b800' : patchCls === 'critical' ? '#ff3333' : '#6B7280';
            updateLine = `<div style="font-size:0.65rem;color:${patchColor};margin-top:0.15rem;">Updates: ${patchLabel}</div>`;
        }

        return `
            <div style="display:flex;align-items:center;gap:0.75rem;padding:0.75rem 1rem;background:var(--card-bg,rgba(15,23,42,0.6));border:1px solid rgba(0,217,255,0.1);border-radius:10px;">
                <div style="width:10px;height:10px;border-radius:50%;background:${dotColor};flex-shrink:0;box-shadow:0 0 6px ${dotColor};"></div>
                <div style="flex:1;min-width:0;">
                    <div style="font-size:0.85rem;font-weight:600;color:#E5E7EB;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(agent.hostname)}</div>
                    <div style="font-size:0.7rem;color:#9CA3AF;">${statusText}</div>
                    ${updateLine}
                </div>
            </div>`;
    }).join('');
}

function renderAlertCards() {
    const section = document.getElementById('rs-alert-cards-section');
    const container = document.getElementById('rs-alert-cards');
    if (!section || !container) return;

    // Only show critical + high threats in simplified mode
    const importantThreats = threatsData.filter(t => (t.severity || 5) >= 6);
    if (importantThreats.length === 0) {
        section.style.display = 'none';
        return;
    }

    section.style.display = '';
    container.innerHTML = importantThreats.slice(0, 10).map(threat => {
        const type = (threat.type || '').toLowerCase().replace(/\s+/g, '_');
        const hostname = escapeHtml(threat.hostname || 'a device');
        const guidance = THREAT_GUIDANCE[type];
        const isCritical = (threat.severity || 5) >= 8;
        const borderColor = isCritical ? '#ff3333' : '#ff9900';

        const friendlyTitle = guidance
            ? guidance.title(hostname)
            : `${escapeHtml(threat.title || threat.type || 'Security alert')} on ${hostname}`;
        const friendlyGuidance = guidance
            ? guidance.guidance
            : 'Open Windows Security and run a full scan to be safe.';

        return `
            <div style="padding:0.875rem 1rem;background:var(--card-bg,rgba(15,23,42,0.6));border-left:3px solid ${borderColor};border-radius:8px;">
                <div style="font-size:0.85rem;font-weight:600;color:#E5E7EB;margin-bottom:0.375rem;">${friendlyTitle}</div>
                <div style="font-size:0.75rem;color:#9CA3AF;margin-bottom:0.5rem;">${new Date(threat.reported_at || threat.timestamp).toLocaleString()}</div>
                <div style="font-size:0.78rem;color:#00D9FF;background:rgba(0,217,255,0.06);padding:0.5rem 0.75rem;border-radius:6px;">
                    <strong>What to do:</strong> ${friendlyGuidance}
                </div>
            </div>`;
    }).join('');
}

// ── Group Policies ──────────────────────────────────────────────────

let _policyGroups = [];

function _authHeaders(extra = {}) {
    const h = { ...extra };
    if (apiClient && apiClient.sessionToken) {
        h['X-Session-Token'] = apiClient.sessionToken;
    }
    return h;
}

async function fetchPolicyGroups() {
    try {
        const res = await fetch(`${API_BASE}/policies/groups`, { headers: _authHeaders() });
        if (!res.ok) return;
        const data = await res.json();
        _policyGroups = data.groups || [];
        renderPolicyGroups();
    } catch (err) {
        console.error('Failed to fetch policy groups:', err);
    }
}

function renderPolicyGroups() {
    const container = document.getElementById('policy-groups-container');
    if (!container) return;

    if (_policyGroups.length === 0) {
        container.innerHTML = '<div class="empty-state" style="font-size:0.75rem;color:#6B7280;padding:0.5rem 0;">No policy groups defined yet</div>';
        return;
    }

    container.innerHTML = _policyGroups.map(g => {
        const mc = g.member_count || 0;
        const cls = mc > 0 ? 'ok' : 'none';
        const ruleCount = Object.keys(g.rules || {}).length;
        const safeId = escapeHtml(g.group_id);
        const jsId = g.group_id.replace(/[^a-zA-Z0-9_-]/g, '');
        return `<div class="policy-card" data-group-id="${safeId}">
            <div class="policy-card-info">
                <div class="policy-card-name">${escapeHtml(g.name)}</div>
                <div class="policy-card-meta">${mc} agent${mc !== 1 ? 's' : ''} &middot; ${ruleCount} rule${ruleCount !== 1 ? 's' : ''} &middot; priority ${g.priority}</div>
            </div>
            <div class="policy-card-actions">
                <span class="compliance-badge ${cls}">${mc} member${mc !== 1 ? 's' : ''}</span>
                <button class="patch-check-btn" onclick="window._rsApplyPolicy('${jsId}')" title="Apply policy to all members">Apply</button>
            </div>
        </div>`;
    }).join('');
}

async function createPolicyGroup() {
    const name = prompt('Policy group name:');
    if (!name) return;
    try {
        const res = await fetch(`${API_BASE}/policies/groups`, {
            method: 'POST',
            headers: _authHeaders({ 'Content-Type': 'application/json' }),
            body: JSON.stringify({ name, description: '', rules: {}, priority: 100 }),
        });
        if (res.ok) await fetchPolicyGroups();
    } catch (err) {
        console.error('Failed to create policy group:', err);
    }
}

async function applyPolicy(groupId) {
    try {
        const res = await fetch(`${API_BASE}/policies/groups/${groupId}/apply`, {
            method: 'POST',
            headers: _authHeaders(),
        });
        if (res.ok) {
            const data = await res.json();
            console.log(`[Policy] Applied: queued=${data.queued}, skipped=${data.skipped}`);
            await fetchPolicyGroups();
        }
    } catch (err) {
        console.error('Failed to apply policy:', err);
    }
}

// ── Init / Destroy ───────────────────────────────────────────────────

async function init() {
    destroy();

    // Apply current dashboard mode
    _currentMode = localStorage.getItem('citadel_dashboard_mode') || 'technical';
    applyViewMode(_currentMode);

    // Listen for mode changes
    _modeListener = (e) => {
        const mode = e.detail?.mode || 'technical';
        applyViewMode(mode);
    };
    window.addEventListener('dashboard-mode-changed', _modeListener);

    // Expose command triggers for onclick
    window._rsQueueCheck = queueCheckUpdates;
    window._rsApplyPolicy = applyPolicy;

    // Wire add-group button
    const addBtn = document.getElementById('add-policy-btn');
    if (addBtn) addBtn.addEventListener('click', createPolicyGroup);

    initWebSocket();
    await Promise.all([fetchAgents(), fetchThreats(), fetchPolicyGroups()]);

    // Re-render simplified view after data loads
    if (_currentMode === 'simplified') renderSimplifiedView();

    _refreshInterval = setInterval(() => {
        fetchAgents();
        fetchThreats();
        fetchPolicyGroups();
        if (_currentMode === 'simplified') renderSimplifiedView();
    }, 30000);
}

function destroy() {
    if (_refreshInterval) { clearInterval(_refreshInterval); _refreshInterval = null; }
    if (_ws) {
        _ws.onclose = null; // prevent reconnect
        _ws.close();
        _ws = null;
    }
    if (_modeListener) {
        window.removeEventListener('dashboard-mode-changed', _modeListener);
        _modeListener = null;
    }
    delete window._rsQueueCheck;
    delete window._rsApplyPolicy;
    agentsData = {};
    threatsData = [];
    _policyGroups = [];
}

// NOTE: No auto-init here — tab-loader.js manages the init/destroy lifecycle.

// ── Exports ──────────────────────────────────────────────────────────

export { init, destroy, THREAT_GUIDANCE, fetchPolicyGroups, renderPolicyGroups, createPolicyGroup, applyPolicy };
