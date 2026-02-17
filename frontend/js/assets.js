// PRD: Multi-Asset View - Frontend asset table
// Reference: PHASE_2_SPEC.md, P2.1.5-T4
//
// Fetches asset data from /api/asset-view (enriched) and /api/assets (CRUD),
// paginated table with colour-coded threat levels, drill-down detail
// panel, and real-time WebSocket updates.

import { apiClient } from './utils/api-client.js';
import { wsHandler } from './websocket-handler.js';

// ── Constants ───────────────────────────────────────────────────────

const THREAT_RANK = { low: 0, medium: 1, high: 2, critical: 3 };
const STATUS_RANK = { online: 0, protected: 1, unknown: 2, offline: 3, compromised: 4 };

const ROW_COLOURS = {
    critical: 'rgba(255, 51, 51, 0.08)',
    high:     'rgba(255, 153, 0, 0.06)',
    medium:   'rgba(255, 204, 0, 0.04)',
    low:      'transparent',
};

// ── State ───────────────────────────────────────────────────────────

let allAssets = [];
let filteredAssets = [];
let currentPage = 1;
let pageSize = 25;
let sortField = 'threat_level';
let sortOrder = 'desc';
let selectedAssetId = null;
let refreshInterval = null;
let _wsUnsubs = [];
let _onWsConnected = null;
let _onWsDisconnected = null;
let _boundCleanups = [];  // Tracks listeners for destroy()
let _currentMode = 'technical';
let _modeListener = null;

// ── API ─────────────────────────────────────────────────────────────

async function fetchAssets() {
    try {
        // Use enriched view endpoint (includes event counts from EventAggregator)
        const resp = await apiClient.get('/api/asset-view');
        if (!resp.ok) {
            // Fallback to CRUD endpoint if asset-view unavailable
            const fallback = await apiClient.get('/api/assets');
            if (!fallback.ok) return null;
            return await fallback.json();
        }
        return await resp.json();
    } catch (err) {
        console.error('Assets fetch failed:', err);
        return null;
    }
}

// ── Filtering ───────────────────────────────────────────────────────

function getFilters() {
    return {
        status: document.getElementById('filter-status')?.value || '',
        threat: document.getElementById('filter-threat')?.value || '',
        search: document.getElementById('search-input')?.value || '',
    };
}

function applyFilters(assets) {
    const { status, threat, search } = getFilters();
    let result = assets;

    if (status) {
        result = result.filter(a => a.status.toLowerCase() === status.toLowerCase());
    }
    if (threat) {
        // Map event_count to threat level for filtering
        result = result.filter(a => {
            const level = assetThreatLevel(a);
            return level === threat.toLowerCase();
        });
    }
    if (search) {
        const q = search.toLowerCase();
        result = result.filter(a =>
            (a.name || '').toLowerCase().includes(q) ||
            (a.asset_id || '').toLowerCase().includes(q) ||
            (a.hostname || '').toLowerCase().includes(q) ||
            (a.ip_address || '').toLowerCase().includes(q)
        );
    }
    return result;
}

function hasActiveFilters() {
    const f = getFilters();
    return !!(f.status || f.threat || f.search);
}

// ── Threat level derivation ─────────────────────────────────────────

function assetThreatLevel(asset) {
    if (asset.status === 'compromised') return 'critical';
    if (!asset.guardian_active) return 'low';
    const ec = asset.event_count || 0;
    if (ec > 50) return 'critical';
    if (ec > 20) return 'high';
    if (ec > 5) return 'medium';
    return 'low';
}

// ── Sorting ─────────────────────────────────────────────────────────

function sortAssets(assets, field, order) {
    const mult = order === 'desc' ? -1 : 1;

    return [...assets].sort((a, b) => {
        let va, vb;
        switch (field) {
            case 'name':
                va = (a.name || a.asset_id || '').toLowerCase();
                vb = (b.name || b.asset_id || '').toLowerCase();
                break;
            case 'status':
                va = STATUS_RANK[a.status.toLowerCase()] || 0;
                vb = STATUS_RANK[b.status.toLowerCase()] || 0;
                break;
            case 'threat_level':
                va = THREAT_RANK[assetThreatLevel(a)] || 0;
                vb = THREAT_RANK[assetThreatLevel(b)] || 0;
                break;
            case 'last_event':
                va = a.last_seen || '';
                vb = b.last_seen || '';
                break;
            case 'event_count':
                va = a.event_count || 0;
                vb = b.event_count || 0;
                break;
            default:
                va = (a.name || '').toLowerCase();
                vb = (b.name || '').toLowerCase();
        }
        if (va < vb) return -1 * mult;
        if (va > vb) return 1 * mult;
        return 0;
    });
}

// ── Pagination ──────────────────────────────────────────────────────

function getPage(assets, page, size) {
    const total = assets.length;
    const totalPages = Math.max(1, Math.ceil(total / size));
    const safePage = Math.max(1, Math.min(page, totalPages));
    const start = (safePage - 1) * size;
    const end = start + size;
    return {
        items: assets.slice(start, end),
        page: safePage,
        totalPages,
        total,
        start: start + 1,
        end: Math.min(end, total),
    };
}

// ── Rendering ───────────────────────────────────────────────────────

function renderTable() {
    if (_currentMode === 'simplified') {
        renderSimplifiedAssets();
        return;
    }

    filteredAssets = applyFilters(allAssets);
    const sorted = sortAssets(filteredAssets, sortField, sortOrder);
    const pg = getPage(sorted, currentPage, pageSize);

    const tbody = document.getElementById('asset-tbody');
    if (!tbody) return;

    if (pg.items.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="5" class="text-center text-gray-500 py-12">
                    ${allAssets.length === 0 ? 'No assets registered' : 'No assets match filters'}
                </td>
            </tr>`;
    } else {
        tbody.innerHTML = pg.items.map(asset => {
            const threat = assetThreatLevel(asset);
            const bgColour = ROW_COLOURS[threat] || 'transparent';
            const selected = asset.asset_id === selectedAssetId ? ' selected' : '';
            const name = escapeHtml(asset.name || asset.asset_id);
            const lastEvent = formatTimestamp(asset.last_seen);

            return `<tr data-asset-id="${escapeHtml(asset.asset_id)}" class="${selected}" style="background:${bgColour};">
                <td data-label="Asset Name">
                    <div class="flex items-center gap-2">
                        <span class="text-sm font-medium text-gray-200">${name}</span>
                        ${asset.guardian_active ? '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#00D9FF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" title="Guardian active" style="flex-shrink:0"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>' : ''}
                    </div>
                    <span class="text-xs text-gray-500">${escapeHtml(asset.hostname || asset.ip_address || '')}</span>
                </td>
                <td data-label="Status">
                    <span class="status-badge status-${asset.status.toLowerCase()}">
                        <span class="status-dot"></span>
                        ${asset.status}
                    </span>
                </td>
                <td data-label="Threat Level">
                    <span class="threat-badge threat-${threat}">${threat}</span>
                </td>
                <td data-label="Last Event" class="text-xs text-gray-400" title="${escapeHtml(asset.last_seen || '')}">${lastEvent}</td>
                <td data-label="Events (24h)">
                    <span class="text-sm font-medium ${(asset.event_count || 0) > 20 ? 'text-orange-400' : 'text-gray-300'}">${asset.event_count ?? 0}</span>
                </td>
            </tr>`;
        }).join('');
    }

    // Pagination info
    const infoEl = document.getElementById('pagination-info');
    if (infoEl) {
        infoEl.textContent = pg.total === 0
            ? 'No assets'
            : `Showing ${pg.start}-${pg.end} of ${pg.total}`;
    }

    setText('page-indicator', `Page ${pg.page} / ${pg.totalPages}`);

    const prevBtn = document.getElementById('page-prev');
    const nextBtn = document.getElementById('page-next');
    if (prevBtn) prevBtn.disabled = pg.page <= 1;
    if (nextBtn) nextBtn.disabled = pg.page >= pg.totalPages;

    // Clear filters button
    const clearBtn = document.getElementById('clear-filters-btn');
    if (clearBtn) clearBtn.style.display = hasActiveFilters() ? 'block' : 'none';

    updateStats();
}

function updateStats() {
    const online = allAssets.filter(a => a.status === 'online').length;
    const protected_ = allAssets.filter(a => a.status === 'protected').length;
    setText('stat-online', online);
    setText('stat-protected', protected_);
    setText('stat-total', allAssets.length);
}

// ── Simplified Mode Rendering ────────────────────────────────────────

function renderSimplifiedAssets() {
    const tbody = document.getElementById('asset-tbody');
    if (!tbody) return;

    // In simplified mode, show all assets without filters, 3-column view
    const sorted = sortAssets(allAssets, 'name', 'asc');

    if (sorted.length === 0) {
        tbody.innerHTML = `
            <tr><td colspan="3" class="text-center text-gray-500 py-12">
                No devices registered yet
            </td></tr>`;
    } else {
        tbody.innerHTML = sorted.map(asset => {
            const threat = assetThreatLevel(asset);
            let dotColor = '#00cc66';
            let statusLabel = 'Protected';
            if (asset.status === 'offline') { dotColor = '#6B7280'; statusLabel = 'Offline'; }
            else if (asset.status === 'compromised' || threat === 'critical') { dotColor = '#ff3333'; statusLabel = 'Needs attention'; }
            else if (threat === 'high') { dotColor = '#ff9900'; statusLabel = 'Review alerts'; }
            else if (threat === 'medium') { dotColor = '#e6b800'; statusLabel = 'Minor alerts'; }

            return `<tr data-asset-id="${escapeHtml(asset.asset_id)}" style="cursor:pointer;">
                <td data-label="Device">
                    <span class="text-sm font-medium text-gray-200">${escapeHtml(asset.name || asset.asset_id)}</span>
                </td>
                <td data-label="Status">
                    <span style="display:inline-flex;align-items:center;gap:0.4rem;">
                        <span style="width:8px;height:8px;border-radius:50%;background:${dotColor};display:inline-block;box-shadow:0 0 4px ${dotColor};"></span>
                        <span class="text-sm" style="color:${dotColor};">${statusLabel}</span>
                    </span>
                </td>
                <td data-label="Last Check" class="text-xs text-gray-400">${formatTimestamp(asset.last_seen)}</td>
            </tr>`;
        }).join('');
    }

    // Update pagination info for simplified
    const infoEl = document.getElementById('pagination-info');
    if (infoEl) infoEl.textContent = sorted.length === 0 ? 'No devices' : `${sorted.length} device${sorted.length > 1 ? 's' : ''}`;

    setText('page-indicator', '');
    updateStats();
}

function openSimplifiedDetail(assetId) {
    const asset = allAssets.find(a => a.asset_id === assetId);
    if (!asset) return;

    selectedAssetId = assetId;
    const content = document.getElementById('detail-content');
    if (!content) return;

    const threat = assetThreatLevel(asset);
    let iconColor = '#00cc66';
    let statusMsg = 'This device is protected and running normally.';
    let actionMsg = 'No action needed.';
    if (asset.status === 'offline') {
        iconColor = '#6B7280'; statusMsg = 'This device is currently offline.';
        actionMsg = 'Check that the device is powered on and connected to the internet.';
    } else if (threat === 'critical') {
        iconColor = '#ff3333'; statusMsg = 'This device needs your attention.';
        actionMsg = 'Open Windows Security and run a full scan. Check alerts below for details.';
    } else if (threat === 'high') {
        iconColor = '#ff9900'; statusMsg = 'There are alerts to review on this device.';
        actionMsg = 'Check the Remote Shield tab for alert details.';
    }

    content.innerHTML = `
        <div style="text-align:center;padding:1.5rem;">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="${iconColor}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;margin-bottom:0.75rem;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            <h4 style="font-size:1.1rem;font-weight:700;color:#E5E7EB;margin-bottom:0.25rem;">${escapeHtml(asset.name || asset.asset_id)}</h4>
            <p style="font-size:0.8rem;color:${iconColor};margin-bottom:1rem;">${statusMsg}</p>
        </div>
        <div style="padding:0.75rem 1rem;background:rgba(0,217,255,0.06);border-radius:8px;margin:0 1rem 1rem;">
            <div style="font-size:0.75rem;font-weight:600;color:#00D9FF;margin-bottom:0.25rem;">Suggested Action</div>
            <div style="font-size:0.8rem;color:#D1D5DB;">${actionMsg}</div>
        </div>
        <div style="padding:0 1rem;">
            <div style="font-size:0.7rem;color:#6B7280;">Last seen: ${formatTimestamp(asset.last_seen)}</div>
        </div>
    `;

    document.getElementById('detail-panel')?.classList.add('open');
    document.getElementById('detail-overlay')?.classList.add('open');
}

// ── CRUD Operations ─────────────────────────────────────────────────

async function createAsset(data) {
    try {
        const resp = await apiClient.post('/api/assets', data);
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${resp.status}`);
        }
        return await resp.json();
    } catch (err) {
        console.error('Create asset failed:', err);
        throw err;
    }
}

async function updateAsset(assetId, data) {
    try {
        const resp = await apiClient.put(`/api/assets/${assetId}`, data);
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${resp.status}`);
        }
        return await resp.json();
    } catch (err) {
        console.error('Update asset failed:', err);
        throw err;
    }
}

async function deleteAsset(assetId) {
    try {
        const resp = await apiClient.delete(`/api/assets/${assetId}`);
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${resp.status}`);
        }
        return await resp.json();
    } catch (err) {
        console.error('Delete asset failed:', err);
        throw err;
    }
}

async function testConnection(assetId) {
    try {
        const resp = await apiClient.post(`/api/assets/${assetId}/test-connection`);
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${resp.status}`);
        }
        return await resp.json();
    } catch (err) {
        console.error('Test connection failed:', err);
        throw err;
    }
}

// ── Modal ───────────────────────────────────────────────────────────

let _editingAssetId = null;

function openAssetModal(asset = null) {
    _editingAssetId = asset ? asset.asset_id : null;

    const title = document.getElementById('asset-modal-title');
    const submitText = document.getElementById('asset-form-submit-text');
    if (title) title.textContent = asset ? 'Edit Asset' : 'Add Asset';
    if (submitText) submitText.textContent = asset ? 'Save Changes' : 'Create Asset';

    // Populate form
    document.getElementById('asset-form-id').value = asset?.asset_id || '';
    document.getElementById('asset-form-name').value = asset?.name || '';
    document.getElementById('asset-form-hostname').value = asset?.hostname || '';
    document.getElementById('asset-form-ip').value = asset?.ip_address || '';
    document.getElementById('asset-form-platform').value = asset?.platform || 'linux';
    document.getElementById('asset-form-type').value = asset?.asset_type || 'vps';
    document.getElementById('asset-form-ssh-port').value = asset?.ssh_port || 22;
    document.getElementById('asset-form-ssh-user').value = asset?.ssh_username || 'root';
    document.getElementById('asset-form-tags').value = (asset?.tags || []).join(', ');
    document.getElementById('asset-form-notes').value = asset?.notes || '';

    // Clear error
    const errEl = document.getElementById('asset-form-error');
    if (errEl) { errEl.style.display = 'none'; errEl.textContent = ''; }

    document.getElementById('asset-modal-overlay')?.classList.add('open');
    document.getElementById('asset-form-name')?.focus();
}

function closeAssetModal() {
    document.getElementById('asset-modal-overlay')?.classList.remove('open');
    _editingAssetId = null;
}

async function handleAssetFormSubmit(e) {
    e.preventDefault();
    const errEl = document.getElementById('asset-form-error');
    const submitBtn = document.getElementById('asset-form-submit');

    const name = document.getElementById('asset-form-name')?.value.trim();
    if (!name) {
        if (errEl) { errEl.textContent = 'Name is required'; errEl.style.display = 'block'; }
        return;
    }

    const tagsRaw = document.getElementById('asset-form-tags')?.value || '';
    const tags = tagsRaw.split(',').map(t => t.trim()).filter(Boolean);

    const payload = {
        name,
        hostname: document.getElementById('asset-form-hostname')?.value.trim() || '',
        ip_address: document.getElementById('asset-form-ip')?.value.trim() || '',
        platform: document.getElementById('asset-form-platform')?.value || 'linux',
        asset_type: document.getElementById('asset-form-type')?.value || 'vps',
        ssh_port: parseInt(document.getElementById('asset-form-ssh-port')?.value, 10) || 22,
        ssh_username: document.getElementById('asset-form-ssh-user')?.value.trim() || 'root',
        tags,
        notes: document.getElementById('asset-form-notes')?.value.trim() || '',
    };

    if (submitBtn) submitBtn.disabled = true;
    if (errEl) { errEl.style.display = 'none'; }

    try {
        if (_editingAssetId) {
            await updateAsset(_editingAssetId, payload);
        } else {
            await createAsset(payload);
        }
        closeAssetModal();
        await refreshData();
    } catch (err) {
        if (errEl) {
            errEl.textContent = err.message || 'Operation failed';
            errEl.style.display = 'block';
        }
    } finally {
        if (submitBtn) submitBtn.disabled = false;
    }
}

async function handleDeleteAsset(assetId) {
    if (!confirm('Delete this asset? This cannot be undone.')) return;
    try {
        await deleteAsset(assetId);
        closeDetail();
        await refreshData();
    } catch (err) {
        alert('Failed to delete asset: ' + (err.message || 'Unknown error'));
    }
}

function _trackListener(el, event, handler) {
    if (!el) return;
    el.addEventListener(event, handler);
    _boundCleanups.push(() => el.removeEventListener(event, handler));
}

function setupModal() {
    // "Add Asset" button opens invite modal (primary flow)
    _trackListener(document.getElementById('add-asset-btn'), 'click', () => openInviteModal());

    // Manual asset modal wiring (reachable via "add manually" link)
    _trackListener(document.getElementById('asset-modal-close'), 'click', closeAssetModal);
    _trackListener(document.getElementById('asset-modal-cancel'), 'click', closeAssetModal);
    _trackListener(document.getElementById('asset-modal-overlay'), 'click', (e) => {
        if (e.target === e.currentTarget) closeAssetModal();
    });
    _trackListener(document.getElementById('asset-form'), 'submit', handleAssetFormSubmit);

    // Invite modal wiring
    _trackListener(document.getElementById('invite-modal-close'), 'click', closeInviteModal);
    _trackListener(document.getElementById('invite-cancel'), 'click', closeInviteModal);
    _trackListener(document.getElementById('invite-modal-overlay'), 'click', (e) => {
        if (e.target === e.currentTarget) closeInviteModal();
    });
    _trackListener(document.getElementById('invite-generate-btn'), 'click', handleGenerateInvitation);
    _trackListener(document.getElementById('invite-copy-btn'), 'click', handleCopyInvitation);
    _trackListener(document.getElementById('invite-share-email-btn'), 'click', handleShareViaEmail);
    _trackListener(document.getElementById('invite-open-page-btn'), 'click', handleOpenEnrollmentPage);
    _trackListener(document.getElementById('invite-done-btn'), 'click', closeInviteModal);
    _trackListener(document.getElementById('invite-add-manually'), 'click', () => {
        closeInviteModal();
        openAssetModal();
    });
}

// ── Invite Modal ─────────────────────────────────────────────────────

let _invitationString = '';
let _enrollmentUrl = '';
let _mailtoUrl = '';
let _inviteStatusInterval = null;
let _copyFeedbackTimer = null;

function openInviteModal() {
    _invitationString = '';
    _enrollmentUrl = '';
    _mailtoUrl = '';
    stopInviteStatusPolling();
    // Reset to generate step
    const stepGen = document.getElementById('invite-step-generate');
    const stepRes = document.getElementById('invite-step-result');
    if (stepGen) { stepGen.classList.add('active'); }
    if (stepRes) { stepRes.classList.remove('active'); }
    // Clear fields
    const nameInput = document.getElementById('invite-agent-name');
    if (nameInput) nameInput.value = '';
    const typeSelect = document.getElementById('invite-agent-type');
    if (typeSelect) typeSelect.value = 'vps';
    const recipientName = document.getElementById('invite-recipient-name');
    if (recipientName) recipientName.value = '';
    const recipientEmail = document.getElementById('invite-recipient-email');
    if (recipientEmail) recipientEmail.value = '';
    const errEl = document.getElementById('invite-generate-error');
    if (errEl) { errEl.style.display = 'none'; errEl.textContent = ''; }
    // Reset status badge
    setInviteStatus('waiting');
    // Show modal
    document.getElementById('invite-modal-overlay')?.classList.add('open');
    nameInput?.focus();
}

function closeInviteModal() {
    document.getElementById('invite-modal-overlay')?.classList.remove('open');
    _invitationString = '';
    _enrollmentUrl = '';
    _mailtoUrl = '';
    stopInviteStatusPolling();
}

async function handleGenerateInvitation() {
    const nameInput = document.getElementById('invite-agent-name');
    const errEl = document.getElementById('invite-generate-error');
    const genBtn = document.getElementById('invite-generate-btn');
    const agentName = nameInput?.value.trim();

    if (!agentName) {
        if (errEl) { errEl.textContent = 'Agent name is required'; errEl.style.display = 'block'; }
        return;
    }

    const agentType = document.getElementById('invite-agent-type')?.value || 'vps';
    const recipientName = document.getElementById('invite-recipient-name')?.value.trim() || '';
    const recipientEmail = document.getElementById('invite-recipient-email')?.value.trim() || '';
    if (genBtn) genBtn.disabled = true;
    if (errEl) errEl.style.display = 'none';

    try {
        const body = {
            agent_name: agentName,
            agent_type: agentType,
            ttl_seconds: 600,
        };
        if (recipientName) body.recipient_name = recipientName;
        if (recipientEmail) body.recipient_email = recipientEmail;

        const resp = await apiClient.post('/api/ext-agents/invitations', body);
        if (!resp.ok) {
            const data = await resp.json().catch(() => ({}));
            throw new Error(data.detail || `HTTP ${resp.status}`);
        }
        const data = await resp.json();
        _invitationString = data.compact_string;
        _enrollmentUrl = data.enrollment_url || '';
        _mailtoUrl = data.mailto_url || '';

        // Switch to result step
        document.getElementById('invite-step-generate')?.classList.remove('active');
        document.getElementById('invite-step-result')?.classList.add('active');
        const titleEl = document.getElementById('invite-modal-title');
        if (titleEl) titleEl.textContent = 'Invitation Ready';

        const codeBox = document.getElementById('invite-code-box');
        if (codeBox) codeBox.textContent = _invitationString;

        // Show/hide share buttons based on available URLs
        const emailBtn = document.getElementById('invite-share-email-btn');
        if (emailBtn) emailBtn.style.display = _mailtoUrl ? 'inline-flex' : 'none';
        const pageBtn = document.getElementById('invite-open-page-btn');
        if (pageBtn) pageBtn.style.display = _enrollmentUrl ? 'inline-flex' : 'none';

        // Show platform-specific instructions
        const instructionsList = document.getElementById('invite-instructions');
        if (instructionsList) {
            if (agentType === 'workstation' && _enrollmentUrl) {
                instructionsList.innerHTML = `
                    <li data-step="1.">Share the enrollment link via email or copy it</li>
                    <li data-step="2.">Recipient opens the link on their Windows PC</li>
                    <li data-step="3.">They follow the one-click install instructions</li>
                `;
            } else if (agentType === 'workstation') {
                instructionsList.innerHTML = `
                    <li data-step="1.">Copy windows_shield.py to the family PC</li>
                    <li data-step="2.">Open PowerShell on the family PC</li>
                    <li data-step="3.">Run: python windows_shield.py enroll &lt;server_url&gt; &lt;invitation&gt;</li>
                `;
            } else {
                instructionsList.innerHTML = `
                    <li data-step="1.">SSH into the remote server</li>
                    <li data-step="2.">Open Claude Code in the terminal</li>
                    <li data-step="3.">Paste the invitation string above</li>
                `;
            }
        }

        // Start status polling
        setInviteStatus('waiting');
        startInviteStatusPolling();
    } catch (err) {
        if (errEl) {
            errEl.textContent = err.message || 'Failed to generate invitation';
            errEl.style.display = 'block';
        }
    } finally {
        if (genBtn) genBtn.disabled = false;
    }
}

async function handleCopyInvitation() {
    if (!_invitationString) return;
    try {
        await navigator.clipboard.writeText(_invitationString);
    } catch {
        // Fallback for older browsers / non-HTTPS
        const ta = document.createElement('textarea');
        ta.value = _invitationString;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
    }
    const feedback = document.getElementById('invite-copy-feedback');
    if (feedback) {
        feedback.classList.add('show');
        if (_copyFeedbackTimer) clearTimeout(_copyFeedbackTimer);
        _copyFeedbackTimer = setTimeout(() => {
            feedback.classList.remove('show');
            _copyFeedbackTimer = null;
        }, 1500);
    }
}

function handleShareViaEmail() {
    if (!_mailtoUrl) return;
    window.open(_mailtoUrl, '_self');
}

function handleOpenEnrollmentPage() {
    if (!_enrollmentUrl) return;
    window.open(_enrollmentUrl, '_blank');
}

function setInviteStatus(state) {
    const badge = document.getElementById('invite-status-badge');
    const text = document.getElementById('invite-status-text');
    if (!badge || !text) return;

    badge.className = 'status-badge';
    switch (state) {
        case 'waiting':
            badge.classList.add('status-unknown');
            text.textContent = 'Waiting...';
            break;
        case 'redeemed':
            badge.classList.add('status-online');
            text.textContent = 'Installed!';
            break;
        case 'expired':
            badge.classList.add('status-offline');
            text.textContent = 'Expired';
            break;
        default:
            badge.classList.add('status-unknown');
            text.textContent = 'Waiting...';
    }
}

function startInviteStatusPolling() {
    stopInviteStatusPolling();
    if (!_enrollmentUrl) return;

    // Extract invitation_id and secret from enrollment URL for status endpoint
    // enrollment URL format: http://host/enroll/{id}?s={secret}
    let statusUrl = '';
    try {
        const url = new URL(_enrollmentUrl);
        const pathParts = url.pathname.split('/');
        // /enroll/{invitation_id} → pathParts = ['', 'enroll', '{id}']
        const invitationId = pathParts[pathParts.length - 1];
        const secret = url.searchParams.get('s') || '';
        statusUrl = `${url.origin}/enroll/${invitationId}/status?s=${encodeURIComponent(secret)}`;
    } catch {
        return; // Can't parse URL, skip polling
    }

    _inviteStatusInterval = setInterval(async () => {
        try {
            const resp = await fetch(statusUrl);
            if (!resp.ok) return;
            const result = await resp.json();
            if (result.status === 'redeemed') {
                setInviteStatus('redeemed');
                stopInviteStatusPolling();
                // Refresh asset list — new agent may have enrolled
                refreshData();
            } else if (result.status === 'expired') {
                setInviteStatus('expired');
                stopInviteStatusPolling();
            }
        } catch { /* best-effort */ }
    }, 5000);
}

function stopInviteStatusPolling() {
    if (_inviteStatusInterval) {
        clearInterval(_inviteStatusInterval);
        _inviteStatusInterval = null;
    }
}

// ── Drill-down ──────────────────────────────────────────────────────

function openDetail(assetId) {
    if (_currentMode === 'simplified') {
        openSimplifiedDetail(assetId);
        return;
    }
    const asset = allAssets.find(a => a.asset_id === assetId);
    if (!asset) return;

    selectedAssetId = assetId;

    const content = document.getElementById('detail-content');
    if (!content) return;

    const threat = assetThreatLevel(asset);
    const eventCount = asset.event_count ?? 0;

    content.innerHTML = `
        <!-- Asset header -->
        <div class="glass-card p-4 mb-4">
            <div class="flex items-center justify-between mb-2">
                <h4 class="text-lg font-semibold text-gray-200">${escapeHtml(asset.name || asset.asset_id)}</h4>
                <span class="status-badge status-${asset.status.toLowerCase()}">
                    <span class="status-dot"></span>
                    ${asset.status}
                </span>
            </div>
            <span class="threat-badge threat-${threat}">${threat.toUpperCase()}</span>
        </div>

        <!-- Metadata -->
        <div class="grid grid-cols-2 gap-3 mb-6">
            <div>
                <p class="text-xs text-gray-500 mb-1">Asset ID</p>
                <p class="text-sm text-gray-300 font-mono">${escapeHtml(asset.asset_id)}</p>
            </div>
            <div>
                <p class="text-xs text-gray-500 mb-1">Platform</p>
                <p class="text-sm text-gray-300">${escapeHtml(asset.platform || '—')}</p>
            </div>
            <div>
                <p class="text-xs text-gray-500 mb-1">Hostname</p>
                <p class="text-sm text-gray-300">${escapeHtml(asset.hostname || '—')}</p>
            </div>
            <div>
                <p class="text-xs text-gray-500 mb-1">IP Address</p>
                <p class="text-sm text-gray-300 font-mono">${escapeHtml(asset.ip_address || '—')}</p>
            </div>
            <div>
                <p class="text-xs text-gray-500 mb-1">Asset Type</p>
                <p class="text-sm text-gray-300">${escapeHtml(asset.asset_type || '—')}</p>
            </div>
            <div>
                <p class="text-xs text-gray-500 mb-1">SSH</p>
                <p class="text-sm text-gray-300 font-mono">${escapeHtml(asset.ssh_username || 'root')}@:${asset.ssh_port || 22}</p>
            </div>
            <div>
                <p class="text-xs text-gray-500 mb-1">Guardian</p>
                <p class="text-sm ${asset.guardian_active ? 'text-green-400' : 'text-gray-500'}">${asset.guardian_active ? 'Active' : 'Inactive'}</p>
            </div>
            <div>
                <p class="text-xs text-gray-500 mb-1">Events (24h)</p>
                <p class="text-sm text-gray-300 font-medium">${eventCount}</p>
            </div>
            <div>
                <p class="text-xs text-gray-500 mb-1">Last Seen</p>
                <p class="text-sm text-gray-300">${formatTimestamp(asset.last_seen)}</p>
            </div>
            <div>
                <p class="text-xs text-gray-500 mb-1">Registered</p>
                <p class="text-sm text-gray-300">${formatTimestamp(asset.registered_at)}</p>
            </div>
        </div>

        ${(asset.tags && asset.tags.length) ? `
        <div class="mb-4">
            <p class="text-xs text-gray-500 mb-2">Tags</p>
            <div class="flex flex-wrap gap-1.5">
                ${asset.tags.map(t => `<span class="px-2 py-0.5 rounded-full text-xs bg-neon-blue/10 text-neon-blue border border-neon-blue/20">${escapeHtml(t)}</span>`).join('')}
            </div>
        </div>` : ''}

        ${asset.notes ? `
        <div class="mb-4">
            <p class="text-xs text-gray-500 mb-1">Notes</p>
            <p class="text-sm text-gray-400">${escapeHtml(asset.notes)}</p>
        </div>` : ''}

        <!-- Actions -->
        <div class="border-t border-white/5 pt-4">
            <h4 class="text-sm font-semibold text-gray-400 mb-3">Actions</h4>
            <div class="flex gap-2 flex-wrap">
                <a href="timeline.html" class="px-3 py-1.5 rounded-lg text-xs font-medium bg-neon-blue/10 border border-neon-blue/20 text-neon-blue hover:bg-neon-blue/20 transition-colors">
                    View Timeline
                </a>
                <button id="test-conn-btn" class="px-3 py-1.5 rounded-lg text-xs font-medium bg-green-500/10 border border-green-500/20 text-green-400 hover:bg-green-500/20 transition-colors" onclick="window._testConnectionFromDetail && window._testConnectionFromDetail('${escapeHtml(asset.asset_id)}')">
                    Test Connection
                </button>
                <button class="px-3 py-1.5 rounded-lg text-xs font-medium bg-neon-blue/10 border border-neon-blue/20 text-neon-blue hover:bg-neon-blue/20 transition-colors" onclick="window._editAssetFromDetail && window._editAssetFromDetail('${escapeHtml(asset.asset_id)}')">
                    Edit Asset
                </button>
                <button class="px-3 py-1.5 rounded-lg text-xs font-medium bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500/20 transition-colors" onclick="window._deleteAssetFromDetail && window._deleteAssetFromDetail('${escapeHtml(asset.asset_id)}')">
                    Delete Asset
                </button>
                <button id="onboard-btn" class="px-3 py-1.5 rounded-lg text-xs font-medium bg-purple-500/10 border border-purple-500/20 text-purple-400 hover:bg-purple-500/20 transition-colors" onclick="window._onboardAssetFromDetail && window._onboardAssetFromDetail('${escapeHtml(asset.asset_id)}')">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:inline;vertical-align:-1px;margin-right:3px;"><path d="M12 5v14"/><path d="M5 12h14"/><circle cx="12" cy="12" r="10"/></svg>Onboard Node
                </button>
            </div>
        </div>

        <!-- Onboarding progress (hidden by default) -->
        <div id="onboarding-progress" style="display:none;" class="border-t border-white/5 pt-4 mt-4">
            <h4 class="text-sm font-semibold text-gray-400 mb-3">Onboarding Progress</h4>
            <div id="onboarding-steps" class="space-y-2"></div>
        </div>
    `;

    // Wire up inline action handlers
    window._editAssetFromDetail = (id) => {
        const a = allAssets.find(x => x.asset_id === id);
        if (a) { closeDetail(); openAssetModal(a); }
    };
    window._deleteAssetFromDetail = (id) => handleDeleteAsset(id);
    window._testConnectionFromDetail = async (id) => {
        const btn = document.getElementById('test-conn-btn');
        if (btn) { btn.disabled = true; btn.textContent = 'Testing...'; }
        try {
            const result = await testConnection(id);
            if (result.connection_status === 'success') {
                if (btn) { btn.textContent = 'Connected'; btn.style.color = '#00cc66'; }
                await refreshData();
                // Re-open detail to show updated status
                openDetail(id);
            } else {
                if (btn) { btn.textContent = 'Failed'; btn.style.color = '#ff3333'; }
                alert('Connection failed: ' + (result.error || 'Unknown error'));
            }
        } catch (err) {
            if (btn) { btn.textContent = 'Error'; btn.style.color = '#ff3333'; }
            alert('Test connection error: ' + (err.message || 'Unknown error'));
        }
    };

    window._onboardAssetFromDetail = (id) => startOnboarding(id);

    document.getElementById('detail-panel')?.classList.add('open');
    document.getElementById('detail-overlay')?.classList.add('open');
    renderTable();
}

function closeDetail() {
    document.getElementById('detail-panel')?.classList.remove('open');
    document.getElementById('detail-overlay')?.classList.remove('open');
    selectedAssetId = null;
    renderTable();
}

// ── Onboarding ─────────────────────────────────────────────────────

const ONBOARD_STEPS = ['validate', 'connect', 'deploy', 'harden', 'firewall', 'verify'];
const STEP_LABELS = {
    validate: 'Validate Asset',
    connect: 'Test SSH Connection',
    deploy: 'Deploy Shield Agent',
    harden: 'SSH Hardening',
    firewall: 'Firewall Rules',
    verify: 'Verify Agent',
};

function renderOnboardingSteps(steps) {
    const container = document.getElementById('onboarding-steps');
    if (!container) return;

    container.innerHTML = ONBOARD_STEPS.map(step => {
        const data = steps[step] || { status: 'pending', message: '' };
        const statusIcon = {
            pending: '<span style="color:#6B7280;">&#9679;</span>',
            running: '<span style="color:#e6b800;" class="animate-pulse">&#9679;</span>',
            completed: '<span style="color:#00cc66;">&#10003;</span>',
            failed: '<span style="color:#ff3333;">&#10007;</span>',
            skipped: '<span style="color:#6B7280;">&#8722;</span>',
        }[data.status] || '<span style="color:#6B7280;">&#9679;</span>';

        return `
            <div class="flex items-center gap-2 py-1.5 px-3 rounded-lg" style="background:rgba(15,23,42,0.4);border:1px solid rgba(255,255,255,0.03);">
                <span style="font-size:0.85rem;width:16px;text-align:center;">${statusIcon}</span>
                <span class="text-xs font-medium ${data.status === 'running' ? 'text-neon-blue' : 'text-gray-400'}" style="min-width:120px;">${STEP_LABELS[step]}</span>
                <span class="text-xs text-gray-500 truncate flex-1">${data.message || ''}</span>
                ${data.status === 'failed' ? `<button onclick="window._retryOnboardStep && window._retryOnboardStep('${step}')" class="text-xs text-neon-blue hover:underline">Retry</button>` : ''}
            </div>`;
    }).join('');
}

let _currentOnboardSessionId = null;

async function startOnboarding(assetId) {
    const btn = document.getElementById('onboard-btn');
    if (btn) { btn.disabled = true; btn.textContent = 'Starting...'; }

    // Show progress section
    const progressDiv = document.getElementById('onboarding-progress');
    if (progressDiv) progressDiv.style.display = 'block';

    // Initialize steps as pending
    const initialSteps = {};
    ONBOARD_STEPS.forEach(s => { initialSteps[s] = { status: 'pending', message: '' }; });
    renderOnboardingSteps(initialSteps);

    try {
        const resp = await apiClient.post('/api/onboarding/start', {
            asset_id: assetId,
        });
        const data = await resp.json();
        _currentOnboardSessionId = data.session_id;

        if (data.steps) renderOnboardingSteps(data.steps);

        if (btn) {
            btn.textContent = data.success ? 'Onboarded' : 'Partial';
            btn.style.color = data.success ? '#00cc66' : '#e6b800';
        }
    } catch (err) {
        if (btn) { btn.textContent = 'Error'; btn.style.color = '#ff3333'; }
        const errSteps = {};
        ONBOARD_STEPS.forEach(s => { errSteps[s] = { status: 'failed', message: err.message || 'Request failed' }; });
        renderOnboardingSteps(errSteps);
    }
}

window._retryOnboardStep = async (step) => {
    if (!_currentOnboardSessionId) return;
    try {
        const resp = await apiClient.post(`/api/onboarding/${_currentOnboardSessionId}/retry/${step}`, {});
        const data = await resp.json();
        // Refresh the full status
        const statusResp = await apiClient.get(`/api/onboarding/${_currentOnboardSessionId}`);
        const statusData = await statusResp.json();
        if (statusData.steps) renderOnboardingSteps(statusData.steps);
    } catch (err) {
        alert('Retry failed: ' + (err.message || 'Unknown error'));
    }
};

function handleOnboardingProgress(msg) {
    // WebSocket message: { type: "onboarding_progress", asset_id, step, status, message }
    if (msg.asset_id !== selectedAssetId) return;
    const progressDiv = document.getElementById('onboarding-progress');
    if (progressDiv) progressDiv.style.display = 'block';

    // Update just the one step in the UI
    const container = document.getElementById('onboarding-steps');
    if (!container) return;
    // Re-fetch full status for simplicity
    if (_currentOnboardSessionId) {
        apiClient.get(`/api/onboarding/${_currentOnboardSessionId}`)
            .then(r => r.json())
            .then(data => { if (data.steps) renderOnboardingSteps(data.steps); })
            .catch(() => {});
    }
}

// ── WebSocket ───────────────────────────────────────────────────────

function connectWebSocket() {
    _wsUnsubs.push(wsHandler.subscribe('event', handleWebSocketMessage));
    _wsUnsubs.push(wsHandler.subscribe('threat_detected', handleWebSocketMessage));
    _wsUnsubs.push(wsHandler.subscribe('security_level_changed', handleWebSocketMessage));
    _wsUnsubs.push(wsHandler.subscribe('asset_status_changed', handleWebSocketMessage));
    _wsUnsubs.push(wsHandler.subscribe('onboarding_progress', handleOnboardingProgress));

    _onWsConnected = () => setLiveStatus(true);
    _onWsDisconnected = () => setLiveStatus(false);
    window.addEventListener('ws-connected', _onWsConnected);
    window.addEventListener('ws-disconnected', _onWsDisconnected);

    // Poll connection status continuously (handles race where ws-connected
    // event fired before our listener was registered, and catches later
    // disconnects if the ws-disconnected event is missed).
    setLiveStatus(wsHandler.connected);
    const poll = setInterval(() => setLiveStatus(wsHandler.connected), 2000);
    _wsUnsubs.push(() => clearInterval(poll));
}

function handleWebSocketMessage(msg) {
    if (msg.type === 'event' || msg.type === 'threat_detected' ||
        msg.type === 'security_level_changed') {
        refreshData();
    }
}

function setLiveStatus(connected) {
    const badge = document.getElementById('live-badge');
    const dot = document.getElementById('live-dot');
    const text = document.getElementById('live-text');
    if (!badge) return;

    if (connected) {
        badge.style.background = 'rgba(0,204,102,0.15)';
        badge.style.color = '#00cc66';
        badge.style.borderColor = 'rgba(0,204,102,0.3)';
        if (dot) dot.style.background = '#00cc66';
        if (text) text.textContent = 'Live';
    } else {
        badge.style.background = 'rgba(230,184,0,0.15)';
        badge.style.color = '#e6b800';
        badge.style.borderColor = 'rgba(230,184,0,0.3)';
        if (dot) dot.style.background = '#e6b800';
        if (text) text.textContent = 'Offline';
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

function formatTimestamp(iso) {
    if (!iso) return '—';
    try {
        const d = new Date(iso);
        if (isNaN(d.getTime())) return iso;
        return d.toLocaleString([], {
            month: 'short', day: 'numeric',
            hour: '2-digit', minute: '2-digit',
        });
    } catch {
        return iso;
    }
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;');
}

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

// ── Event Handlers ──────────────────────────────────────────────────

function setupSortHeaders() {
    document.querySelectorAll('.asset-table thead th[data-sort]').forEach(th => {
        const handler = () => {
            const field = th.dataset.sort;
            if (sortField === field) {
                sortOrder = sortOrder === 'desc' ? 'asc' : 'desc';
            } else {
                sortField = field;
                sortOrder = 'desc';
            }

            document.querySelectorAll('.asset-table thead th').forEach(h => {
                h.classList.remove('sorted');
                h.setAttribute('aria-sort', 'none');
                const arrow = h.querySelector('.sort-arrow');
                if (arrow) arrow.textContent = '▼';
            });
            th.classList.add('sorted');
            th.setAttribute('aria-sort', sortOrder === 'desc' ? 'descending' : 'ascending');
            const arrow = th.querySelector('.sort-arrow');
            if (arrow) arrow.textContent = sortOrder === 'desc' ? '▼' : '▲';

            currentPage = 1;
            renderTable();
        };
        _trackListener(th, 'click', handler);
    });
}

function setupFilters() {
    ['filter-status', 'filter-threat'].forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            const handler = () => { currentPage = 1; renderTable(); };
            _trackListener(el, 'change', handler);
        }
    });

    let searchTimer = null;
    const searchEl = document.getElementById('search-input');
    if (searchEl) {
        const handler = () => {
            clearTimeout(searchTimer);
            searchTimer = setTimeout(() => { currentPage = 1; renderTable(); }, 300);
        };
        _trackListener(searchEl, 'input', handler);
    }

    const clearBtn = document.getElementById('clear-filters-btn');
    if (clearBtn) {
        const handler = () => {
            const fs = document.getElementById('filter-status');
            const ft = document.getElementById('filter-threat');
            const si = document.getElementById('search-input');
            if (fs) fs.value = '';
            if (ft) ft.value = '';
            if (si) si.value = '';
            currentPage = 1;
            renderTable();
        };
        _trackListener(clearBtn, 'click', handler);
    }
}

function setupPagination() {
    _trackListener(document.getElementById('page-prev'), 'click', () => {
        if (currentPage > 1) {
            currentPage--;
            renderTable();
            document.getElementById('table-scroll-container')?.scrollTo(0, 0);
        }
    });

    _trackListener(document.getElementById('page-next'), 'click', () => {
        currentPage++;
        renderTable();
        document.getElementById('table-scroll-container')?.scrollTo(0, 0);
    });

    _trackListener(document.getElementById('page-size-select'), 'change', (e) => {
        pageSize = parseInt(e.target.value, 10) || 25;
        currentPage = 1;
        renderTable();
    });
}

function setupTableClicks() {
    _trackListener(document.getElementById('asset-tbody'), 'click', (e) => {
        const row = e.target.closest('tr[data-asset-id]');
        if (!row) return;
        openDetail(row.dataset.assetId);
    });
}

function setupDetailPanel() {
    _trackListener(document.getElementById('detail-close'), 'click', closeDetail);
    _trackListener(document.getElementById('detail-overlay'), 'click', closeDetail);
    const keyHandler = (e) => {
        if (e.key === 'Escape') {
            // Close topmost modal first, then detail panel
            const inviteModal = document.getElementById('invite-modal-overlay');
            if (inviteModal?.classList.contains('open')) {
                closeInviteModal();
                return;
            }
            const modal = document.getElementById('asset-modal-overlay');
            if (modal?.classList.contains('open')) {
                closeAssetModal();
            } else {
                closeDetail();
            }
        }
    };
    document.addEventListener('keydown', keyHandler);
    _boundCleanups.push(() => document.removeEventListener('keydown', keyHandler));
}

// ── Refresh ─────────────────────────────────────────────────────────

async function refreshData() {
    const data = await fetchAssets();
    if (!data) return;
    allAssets = data.assets || [];
    renderTable();
}

// ── Cleanup ─────────────────────────────────────────────────────────

function destroy() {
    if (refreshInterval) { clearInterval(refreshInterval); refreshInterval = null; }
    _wsUnsubs.forEach(fn => { if (typeof fn === 'function') fn(); });
    _wsUnsubs = [];
    if (_onWsConnected) { window.removeEventListener('ws-connected', _onWsConnected); _onWsConnected = null; }
    if (_onWsDisconnected) { window.removeEventListener('ws-disconnected', _onWsDisconnected); _onWsDisconnected = null; }
    if (_modeListener) { window.removeEventListener('dashboard-mode-changed', _modeListener); _modeListener = null; }

    // Remove all tracked DOM listeners (sort, filter, pagination, detail, modal, keydown)
    _boundCleanups.forEach(fn => fn());
    _boundCleanups = [];

    // Clean up window globals set by openDetail()
    delete window._editAssetFromDetail;
    delete window._deleteAssetFromDetail;
    delete window._testConnectionFromDetail;
    delete window._onboardAssetFromDetail;
    delete window._retryOnboardStep;

    _currentOnboardSessionId = null;
    _invitationString = '';
    _enrollmentUrl = '';
    _mailtoUrl = '';
    stopInviteStatusPolling();
    if (_copyFeedbackTimer) { clearTimeout(_copyFeedbackTimer); _copyFeedbackTimer = null; }
    allAssets = [];
    filteredAssets = [];
    currentPage = 1;
    selectedAssetId = null;
}

// ── Init ────────────────────────────────────────────────────────────

async function init() {
    destroy();

    // Apply current dashboard mode
    _currentMode = localStorage.getItem('citadel_dashboard_mode') || 'technical';

    // Listen for mode changes
    _modeListener = (e) => {
        _currentMode = e.detail?.mode || 'technical';
        renderTable();  // Re-render with new mode
    };
    window.addEventListener('dashboard-mode-changed', _modeListener);

    try {
        await apiClient.initialize();
    } catch (err) {
        console.error('API client init failed:', err);
    }

    await refreshData();

    setupSortHeaders();
    setupFilters();
    setupPagination();
    setupTableClicks();
    setupDetailPanel();
    setupModal();
    connectWebSocket();

    refreshInterval = setInterval(refreshData, 30000);
}

// Note: init() is called by tab-loader, not self-invoked (prevents double-init)

// ── Exports ─────────────────────────────────────────────────────────

export {
    init,
    destroy,
    THREAT_RANK,
    STATUS_RANK,
    ROW_COLOURS,
    fetchAssets,
    createAsset,
    updateAsset,
    deleteAsset,
    testConnection,
    applyFilters,
    sortAssets,
    getPage,
    assetThreatLevel,
    formatTimestamp,
    escapeHtml,
    handleWebSocketMessage,
    setLiveStatus,
    openDetail,
    closeDetail,
    openAssetModal,
    closeAssetModal,
    handleShareViaEmail,
    handleOpenEnrollmentPage,
    setInviteStatus,
    pageSize,
};
