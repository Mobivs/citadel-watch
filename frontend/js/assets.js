// PRD: Multi-Asset View - Frontend asset table
// Reference: PHASE_2_SPEC.md, P2.1.5-T4
//
// Fetches asset data from /api/assets, renders a sortable, filterable,
// paginated table with colour-coded threat levels, drill-down detail
// panel, and real-time WebSocket updates.

import { apiClient } from './utils/api-client.js';
import { wsHandler } from './websocket-handler.js';

// ── Constants ───────────────────────────────────────────────────────

const THREAT_RANK = { low: 0, medium: 1, high: 2, critical: 3 };
const STATUS_RANK = { online: 0, protected: 1, offline: 2, compromised: 3 };

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

// ── API ─────────────────────────────────────────────────────────────

async function fetchAssets() {
    try {
        const resp = await apiClient.get('/api/assets');
        if (!resp.ok) return null;
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
    if (!asset.guardian_active) return 'low';
    if (asset.status === 'compromised') return 'critical';
    if (asset.event_count > 50) return 'critical';
    if (asset.event_count > 20) return 'high';
    if (asset.event_count > 5) return 'medium';
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
                <td>
                    <div class="flex items-center gap-2">
                        <span class="text-sm font-medium text-gray-200">${name}</span>
                        ${asset.guardian_active ? '<span class="text-xs text-neon-blue" title="Guardian active">🛡️</span>' : ''}
                    </div>
                    <span class="text-xs text-gray-500">${escapeHtml(asset.hostname || asset.ip_address || '')}</span>
                </td>
                <td>
                    <span class="status-badge status-${asset.status.toLowerCase()}">
                        <span class="status-dot"></span>
                        ${asset.status}
                    </span>
                </td>
                <td>
                    <span class="threat-badge threat-${threat}">${threat}</span>
                </td>
                <td class="text-xs text-gray-400" title="${escapeHtml(asset.last_seen || '')}">${lastEvent}</td>
                <td>
                    <span class="text-sm font-medium ${asset.event_count > 20 ? 'text-orange-400' : 'text-gray-300'}">${asset.event_count}</span>
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

// ── Drill-down ──────────────────────────────────────────────────────

function openDetail(assetId) {
    const asset = allAssets.find(a => a.asset_id === assetId);
    if (!asset) return;

    selectedAssetId = assetId;

    const content = document.getElementById('detail-content');
    if (!content) return;

    const threat = assetThreatLevel(asset);

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
                <p class="text-xs text-gray-500 mb-1">Guardian</p>
                <p class="text-sm ${asset.guardian_active ? 'text-green-400' : 'text-gray-500'}">${asset.guardian_active ? 'Active' : 'Inactive'}</p>
            </div>
            <div>
                <p class="text-xs text-gray-500 mb-1">Events (24h)</p>
                <p class="text-sm text-gray-300 font-medium">${asset.event_count}</p>
            </div>
            <div>
                <p class="text-xs text-gray-500 mb-1">Last Seen</p>
                <p class="text-sm text-gray-300">${formatTimestamp(asset.last_seen)}</p>
            </div>
        </div>

        <!-- Actions (Phase 2.2 placeholders) -->
        <div class="border-t border-white/5 pt-4">
            <h4 class="text-sm font-semibold text-gray-400 mb-3">Actions</h4>
            <div class="flex gap-2">
                <a href="timeline.html" class="px-3 py-1.5 rounded-lg text-xs font-medium bg-neon-blue/10 border border-neon-blue/20 text-neon-blue hover:bg-neon-blue/20 transition-colors">
                    View Timeline
                </a>
                <button class="px-3 py-1.5 rounded-lg text-xs font-medium bg-white/5 border border-white/10 text-gray-400 cursor-not-allowed" disabled title="Coming in Phase 2.2">
                    Remove Asset
                </button>
            </div>
        </div>
    `;

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

// ── WebSocket ───────────────────────────────────────────────────────

function connectWebSocket() {
    wsHandler.subscribe('event', handleWebSocketMessage);
    wsHandler.subscribe('threat_detected', handleWebSocketMessage);
    wsHandler.subscribe('security_level_changed', handleWebSocketMessage);
    wsHandler.subscribe('asset_status_changed', handleWebSocketMessage);

    window.addEventListener('ws-connected', () => setLiveStatus(true));
    window.addEventListener('ws-disconnected', () => setLiveStatus(false));

    wsHandler.connect();
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
        badge.style.background = 'rgba(255,51,51,0.15)';
        badge.style.color = '#ff3333';
        badge.style.borderColor = 'rgba(255,51,51,0.3)';
        if (dot) dot.style.background = '#ff3333';
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
        th.addEventListener('click', () => {
            const field = th.dataset.sort;
            if (sortField === field) {
                sortOrder = sortOrder === 'desc' ? 'asc' : 'desc';
            } else {
                sortField = field;
                sortOrder = 'desc';
            }

            document.querySelectorAll('.asset-table thead th').forEach(h => {
                h.classList.remove('sorted');
                const arrow = h.querySelector('.sort-arrow');
                if (arrow) arrow.textContent = '▼';
            });
            th.classList.add('sorted');
            const arrow = th.querySelector('.sort-arrow');
            if (arrow) arrow.textContent = sortOrder === 'desc' ? '▼' : '▲';

            currentPage = 1;
            renderTable();
        });
    });
}

function setupFilters() {
    ['filter-status', 'filter-threat'].forEach(id => {
        document.getElementById(id)?.addEventListener('change', () => {
            currentPage = 1;
            renderTable();
        });
    });

    let searchTimer = null;
    document.getElementById('search-input')?.addEventListener('input', () => {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(() => {
            currentPage = 1;
            renderTable();
        }, 300);
    });

    document.getElementById('clear-filters-btn')?.addEventListener('click', () => {
        document.getElementById('filter-status').value = '';
        document.getElementById('filter-threat').value = '';
        document.getElementById('search-input').value = '';
        currentPage = 1;
        renderTable();
    });
}

function setupPagination() {
    document.getElementById('page-prev')?.addEventListener('click', () => {
        if (currentPage > 1) {
            currentPage--;
            renderTable();
            document.getElementById('table-scroll-container')?.scrollTo(0, 0);
        }
    });

    document.getElementById('page-next')?.addEventListener('click', () => {
        currentPage++;
        renderTable();
        document.getElementById('table-scroll-container')?.scrollTo(0, 0);
    });

    document.getElementById('page-size-select')?.addEventListener('change', (e) => {
        pageSize = parseInt(e.target.value, 10) || 25;
        currentPage = 1;
        renderTable();
    });
}

function setupTableClicks() {
    document.getElementById('asset-tbody')?.addEventListener('click', (e) => {
        const row = e.target.closest('tr[data-asset-id]');
        if (!row) return;
        openDetail(row.dataset.assetId);
    });
}

function setupDetailPanel() {
    document.getElementById('detail-close')?.addEventListener('click', closeDetail);
    document.getElementById('detail-overlay')?.addEventListener('click', closeDetail);
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeDetail();
    });
}

// ── Refresh ─────────────────────────────────────────────────────────

async function refreshData() {
    const data = await fetchAssets();
    if (!data) return;
    allAssets = data.assets || [];
    renderTable();
}

// ── Init ────────────────────────────────────────────────────────────

async function init() {
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
    connectWebSocket();

    refreshInterval = setInterval(refreshData, 30000);
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}

// ── Exports ─────────────────────────────────────────────────────────

export {
    THREAT_RANK,
    STATUS_RANK,
    ROW_COLOURS,
    fetchAssets,
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
    pageSize,
};
