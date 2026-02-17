// PRD: Alert Timeline - Frontend interactive timeline
// Reference: PHASE_2_SPEC.md, P2.1.5-T2
//
// Fetches alert events from /api/timeline, renders them in a sortable,
// filterable, paginated table with D3.js scatter visualization,
// drill-down detail panel, and real-time WebSocket updates.

import { apiClient } from './utils/api-client.js';
import { wsHandler } from './websocket-handler.js';

// ── Severity colour mapping ────────────────────────────────────────

const SEV_COLOURS = {
    info:        { fg: '#00cc66', bg: 'rgba(0,204,102,0.15)',  border: 'rgba(0,204,102,0.3)' },
    investigate: { fg: '#ffcc00', bg: 'rgba(255,204,0,0.15)',  border: 'rgba(255,204,0,0.3)' },
    alert:       { fg: '#ff9900', bg: 'rgba(255,153,0,0.15)',  border: 'rgba(255,153,0,0.3)' },
    critical:    { fg: '#ff3333', bg: 'rgba(255,51,51,0.15)',  border: 'rgba(255,51,51,0.3)' },
};

const SEV_RANK = { info: 1, investigate: 2, alert: 3, critical: 4 };

const SOURCE_COLOURS = {
    local:           { label: 'Local',       cls: 'source-local',       stroke: '#00cc66' },
    'remote-shield': { label: 'Remote',      cls: 'source-remote',      stroke: '#00D9FF' },
    correlation:     { label: 'Correlation', cls: 'source-correlation', stroke: '#A855F7' },
};

const CATEGORY_COLOURS = {
    file:    '#3B82F6',
    process: '#A855F7',
    network: '#00D9FF',
    vault:   '#ffcc00',
    system:  '#6B7280',
    ai:      '#EC4899',
    user:    '#00cc66',
    intel:   '#ff9900',
};

// ── State ───────────────────────────────────────────────────────────

let allEntries = [];         // full dataset
let filteredEntries = [];    // after filters
let currentPage = 1;
const PAGE_SIZE = 50;
let sortField = 'time';
let sortOrder = 'desc';
let selectedEventId = null;
let refreshInterval = null;
let _wsUnsubs = [];
let _onWsConnected = null;
let _onWsDisconnected = null;

// ── API ─────────────────────────────────────────────────────────────

async function fetchTimeline(limit) {
    try {
        const f = getFilters();
        let url = `/api/timeline/unified?limit=${limit}`;
        if (f.severity) url += `&severity=${encodeURIComponent(f.severity)}`;
        if (f.source) url += `&source=${encodeURIComponent(f.source)}`;
        const resp = await apiClient.get(url);
        if (!resp.ok) {
            console.error('Timeline API error:', resp.status);
            return null;
        }
        return await resp.json();
    } catch (err) {
        console.error('Timeline fetch failed:', err);
        return null;
    }
}

// ── Filtering ───────────────────────────────────────────────────────

function getFilters() {
    return {
        severity: document.getElementById('filter-severity')?.value || '',
        asset:    document.getElementById('filter-asset')?.value || '',
        eventType: document.getElementById('filter-event-type')?.value || '',
        source:   document.getElementById('filter-source')?.value || '',
        search:   document.getElementById('search-input')?.value || '',
    };
}

function applyFilters(entries) {
    const { severity, asset, eventType, source, search } = getFilters();
    let result = entries;

    if (severity) {
        result = result.filter(e => e.severity.toLowerCase() === severity.toLowerCase());
    }
    if (asset) {
        result = result.filter(e => e.asset_id === asset);
    }
    if (eventType) {
        result = result.filter(e => e.event_type === eventType);
    }
    if (source) {
        result = result.filter(e => e.source === source);
    }
    if (search) {
        const q = search.toLowerCase();
        result = result.filter(e =>
            e.message.toLowerCase().includes(q) ||
            e.event_type.toLowerCase().includes(q) ||
            e.asset_id.toLowerCase().includes(q) ||
            e.category.toLowerCase().includes(q)
        );
    }
    return result;
}

function hasActiveFilters() {
    const f = getFilters();
    return !!(f.severity || f.asset || f.eventType || f.source || f.search);
}

// ── Sorting ─────────────────────────────────────────────────────────

function sortEntries(entries, field, order) {
    const mult = order === 'desc' ? -1 : 1;

    return [...entries].sort((a, b) => {
        let va, vb;
        switch (field) {
            case 'time':
                va = a.timestamp;
                vb = b.timestamp;
                break;
            case 'severity':
                va = SEV_RANK[a.severity.toLowerCase()] || 0;
                vb = SEV_RANK[b.severity.toLowerCase()] || 0;
                break;
            case 'asset':
                va = a.asset_id.toLowerCase();
                vb = b.asset_id.toLowerCase();
                break;
            case 'event_type':
                va = a.event_type.toLowerCase();
                vb = b.event_type.toLowerCase();
                break;
            case 'category':
                va = a.category.toLowerCase();
                vb = b.category.toLowerCase();
                break;
            case 'source':
                va = (a.source || '').toLowerCase();
                vb = (b.source || '').toLowerCase();
                break;
            default:
                va = a.timestamp;
                vb = b.timestamp;
        }
        if (va < vb) return -1 * mult;
        if (va > vb) return 1 * mult;
        return 0;
    });
}

// ── Pagination ──────────────────────────────────────────────────────

function getPage(entries, page) {
    const total = entries.length;
    const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
    const safePage = Math.max(1, Math.min(page, totalPages));
    const start = (safePage - 1) * PAGE_SIZE;
    const end = start + PAGE_SIZE;
    return {
        items: entries.slice(start, end),
        page: safePage,
        totalPages,
        total,
        start: start + 1,
        end: Math.min(end, total),
    };
}

// ── Rendering ───────────────────────────────────────────────────────

function renderTable() {
    filteredEntries = applyFilters(allEntries);
    const sorted = sortEntries(filteredEntries, sortField, sortOrder);
    const pg = getPage(sorted, currentPage);

    const tbody = document.getElementById('timeline-tbody');
    if (!tbody) return;

    if (pg.items.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center text-gray-500 py-12">
                    ${allEntries.length === 0 ? 'No events loaded' : 'No events match filters'}
                </td>
            </tr>`;
    } else {
        tbody.innerHTML = pg.items.map(entry => {
            const sev = entry.severity.toLowerCase();
            const sevStyle = SEV_COLOURS[sev] || SEV_COLOURS.info;
            const ts = formatTimestamp(entry.timestamp);
            const selected = entry.event_id === selectedEventId ? ' selected' : '';
            const src = SOURCE_COLOURS[entry.source] || SOURCE_COLOURS.local;

            return `<tr data-event-id="${escapeHtml(entry.event_id)}" class="${selected}">
                <td data-label="Timestamp" title="${escapeHtml(entry.timestamp)}">${ts}</td>
                <td data-label="Severity"><span class="sev-badge sev-${sev}">${sev}</span></td>
                <td data-label="Asset" title="${escapeHtml(entry.asset_id)}">${escapeHtml(entry.asset_id || '—')}</td>
                <td data-label="Event Type">${escapeHtml(entry.event_type)}</td>
                <td data-label="Category"><span class="cat-tag">${escapeHtml(entry.category)}</span></td>
                <td data-label="Source"><span class="source-badge ${src.cls}">${src.label}</span></td>
                <td data-label="Description" title="${escapeHtml(entry.message)}">${escapeHtml(truncate(entry.message, 80))}</td>
            </tr>`;
        }).join('');
    }

    // Update pagination info
    const infoEl = document.getElementById('pagination-info');
    if (infoEl) {
        if (pg.total === 0) {
            infoEl.textContent = 'No events';
        } else {
            infoEl.textContent = `Showing ${pg.start}-${pg.end} of ${pg.total} events`;
        }
    }

    const indicatorEl = document.getElementById('page-indicator');
    if (indicatorEl) {
        indicatorEl.textContent = `Page ${pg.page} / ${pg.totalPages}`;
    }

    const prevBtn = document.getElementById('page-prev');
    const nextBtn = document.getElementById('page-next');
    if (prevBtn) prevBtn.disabled = pg.page <= 1;
    if (nextBtn) nextBtn.disabled = pg.page >= pg.totalPages;

    // Show/hide clear filters button
    const clearBtn = document.getElementById('clear-filters-btn');
    if (clearBtn) {
        clearBtn.style.display = hasActiveFilters() ? 'block' : 'none';
    }

    // Update stats
    updateStats();
}

function updateStats() {
    const critCount = allEntries.filter(e => e.severity.toLowerCase() === 'critical').length;
    const highCount = allEntries.filter(e => e.severity.toLowerCase() === 'alert').length;
    const totalCount = allEntries.length;

    setTextContent('stat-critical-count', critCount);
    setTextContent('stat-high-count', highCount);
    setTextContent('stat-total-count', totalCount);

    // Source breakdown pills — show only if we have multi-source data
    const localCount = allEntries.filter(e => e.source === 'local').length;
    const remoteCount = allEntries.filter(e => e.source === 'remote-shield').length;
    const corrCount = allEntries.filter(e => e.source === 'correlation').length;
    const hasMultiple = (localCount > 0) + (remoteCount > 0) + (corrCount > 0) > 1;

    const lPill = document.getElementById('stat-local-pill');
    const rPill = document.getElementById('stat-remote-pill');
    const cPill = document.getElementById('stat-correlation-pill');
    if (lPill) { lPill.style.display = hasMultiple && localCount ? 'inline-flex' : 'none'; setTextContent('stat-local-count', localCount); }
    if (rPill) { rPill.style.display = hasMultiple && remoteCount ? 'inline-flex' : 'none'; setTextContent('stat-remote-count', remoteCount); }
    if (cPill) { cPill.style.display = hasMultiple && corrCount ? 'inline-flex' : 'none'; setTextContent('stat-correlation-count', corrCount); }
}

function populateFilterDropdowns() {
    // Unique assets
    const assets = [...new Set(allEntries.map(e => e.asset_id).filter(Boolean))].sort();
    const assetSelect = document.getElementById('filter-asset');
    if (assetSelect) {
        const currentVal = assetSelect.value;
        assetSelect.innerHTML = '<option value="">All Assets</option>' +
            assets.map(a => `<option value="${escapeHtml(a)}">${escapeHtml(a)}</option>`).join('');
        assetSelect.value = currentVal;
    }

    // Unique event types
    const types = [...new Set(allEntries.map(e => e.event_type))].sort();
    const typeSelect = document.getElementById('filter-event-type');
    if (typeSelect) {
        const currentVal = typeSelect.value;
        typeSelect.innerHTML = '<option value="">All Event Types</option>' +
            types.map(t => `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`).join('');
        typeSelect.value = currentVal;
    }
}

// ── D3 Timeline Visualization ───────────────────────────────────────

function renderD3Timeline() {
    const container = document.getElementById('d3-timeline-viz');
    if (!container || typeof d3 === 'undefined') return;

    // Clear previous
    container.innerHTML = '';

    const entries = filteredEntries.length > 0 ? filteredEntries : allEntries;
    if (entries.length === 0) {
        container.innerHTML = '<div class="text-center text-gray-600 text-xs py-8">No events to visualize</div>';
        return;
    }

    const margin = { top: 10, right: 20, bottom: 24, left: 20 };
    const width = container.clientWidth - margin.left - margin.right;
    const height = 80;

    const svg = d3.select(container)
        .append('svg')
        .attr('width', width + margin.left + margin.right)
        .attr('height', height + margin.top + margin.bottom)
        .append('g')
        .attr('transform', `translate(${margin.left},${margin.top})`);

    // Parse timestamps
    const parsed = entries
        .map(e => ({ ...e, _ts: new Date(e.timestamp) }))
        .filter(e => !isNaN(e._ts.getTime()));

    if (parsed.length === 0) return;

    // X scale: time
    const xExtent = d3.extent(parsed, d => d._ts);
    const x = d3.scaleTime()
        .domain(xExtent)
        .range([0, width]);

    // Y scale: severity
    const y = d3.scaleLinear()
        .domain([0, 5])
        .range([height, 0]);

    // X axis
    svg.append('g')
        .attr('transform', `translate(0,${height})`)
        .call(d3.axisBottom(x).ticks(6).tickFormat(d3.timeFormat('%H:%M')))
        .selectAll('text')
        .attr('fill', '#6B7280')
        .attr('font-size', '10px');

    svg.selectAll('.domain, .tick line')
        .attr('stroke', 'rgba(255,255,255,0.06)');

    // Dots
    svg.selectAll('.d3-dot')
        .data(parsed)
        .enter()
        .append('circle')
        .attr('class', 'd3-dot')
        .attr('cx', d => x(d._ts))
        .attr('cy', d => y(SEV_RANK[d.severity.toLowerCase()] || 1))
        .attr('r', 4)
        .attr('fill', d => {
            const sev = d.severity.toLowerCase();
            return SEV_COLOURS[sev]?.fg || '#6B7280';
        })
        .attr('stroke', d => SOURCE_COLOURS[d.source]?.stroke || '#6B7280')
        .attr('stroke-width', d => d.source === 'local' ? 0 : 1.5)
        .attr('opacity', 0.7)
        .on('click', (event, d) => {
            openDetail(d.event_id);
        });
}

// ── Drill-down Detail Panel ─────────────────────────────────────────

function renderSourceDetail(entry) {
    const d = entry.source_detail || {};
    if (entry.source === 'remote-shield') {
        return `<div class="border-t border-white/5 pt-4 mb-4">
            <h4 class="text-sm font-semibold text-gray-400 mb-3">Remote Shield Detail</h4>
            <div class="grid grid-cols-2 gap-3">
                <div>
                    <p class="text-xs text-gray-500 mb-1">Agent ID</p>
                    <p class="text-sm text-gray-300 font-mono">${escapeHtml(d.agent_id || '—')}</p>
                </div>
                <div>
                    <p class="text-xs text-gray-500 mb-1">Hostname</p>
                    <p class="text-sm text-gray-300">${escapeHtml(d.hostname || '—')}</p>
                </div>
                <div>
                    <p class="text-xs text-gray-500 mb-1">Original Severity</p>
                    <p class="text-sm text-gray-300">${d.original_severity != null ? d.original_severity + '/10' : '—'}</p>
                </div>
                <div>
                    <p class="text-xs text-gray-500 mb-1">Status</p>
                    <p class="text-sm text-gray-300">${escapeHtml(d.status || '—')}</p>
                </div>
            </div>
        </div>`;
    }
    if (entry.source === 'correlation') {
        const assets = Array.isArray(d.affected_assets) ? d.affected_assets.join(', ') : (d.affected_assets || '—');
        return `<div class="border-t border-white/5 pt-4 mb-4">
            <h4 class="text-sm font-semibold text-gray-400 mb-3">Correlation Detail</h4>
            <div class="grid grid-cols-2 gap-3">
                <div>
                    <p class="text-xs text-gray-500 mb-1">Correlation Type</p>
                    <p class="text-sm text-gray-300">${escapeHtml(d.correlation_type || '—')}</p>
                </div>
                <div>
                    <p class="text-xs text-gray-500 mb-1">Indicator</p>
                    <p class="text-sm text-gray-300 font-mono">${escapeHtml(d.indicator || '—')}</p>
                </div>
                <div>
                    <p class="text-xs text-gray-500 mb-1">Affected Assets</p>
                    <p class="text-sm text-gray-300">${escapeHtml(assets)}</p>
                </div>
                <div>
                    <p class="text-xs text-gray-500 mb-1">Event Count</p>
                    <p class="text-sm text-gray-300">${d.event_count || 0}</p>
                </div>
            </div>
        </div>`;
    }
    return '';
}

function openDetail(eventId) {
    const entry = allEntries.find(e => e.event_id === eventId);
    if (!entry) return;

    selectedEventId = eventId;

    const content = document.getElementById('detail-content');
    if (!content) return;

    const sev = entry.severity.toLowerCase();
    const sevStyle = SEV_COLOURS[sev] || SEV_COLOURS.info;

    // Find related events (same asset or event type, within 30 min)
    const targetTs = new Date(entry.timestamp).getTime();
    const windowMs = 30 * 60 * 1000;
    const related = allEntries.filter(e => {
        if (e.event_id === eventId) return false;
        const ts = new Date(e.timestamp).getTime();
        if (Math.abs(ts - targetTs) > windowMs) return false;
        return (e.asset_id === entry.asset_id && entry.asset_id) ||
               e.event_type === entry.event_type;
    }).slice(0, 20);

    content.innerHTML = `
        <!-- Severity banner -->
        <div class="rounded-lg p-4 mb-6" style="background:${sevStyle.bg}; border:1px solid ${sevStyle.border};">
            <div class="flex items-center justify-between">
                <span class="sev-badge sev-${sev}" style="font-size:0.8rem;">${sev.toUpperCase()}</span>
                <span class="text-xs" style="color:${sevStyle.fg};">${formatTimestamp(entry.timestamp)}</span>
            </div>
            <p class="mt-2 text-sm text-gray-200">${escapeHtml(entry.message)}</p>
        </div>

        <!-- Metadata grid -->
        <div class="grid grid-cols-2 gap-3 mb-6">
            <div>
                <p class="text-xs text-gray-500 mb-1">Event ID</p>
                <p class="text-sm text-gray-300 font-mono">${escapeHtml(entry.event_id)}</p>
            </div>
            <div>
                <p class="text-xs text-gray-500 mb-1">Asset</p>
                <p class="text-sm text-gray-300">${escapeHtml(entry.asset_id || '—')}</p>
            </div>
            <div>
                <p class="text-xs text-gray-500 mb-1">Event Type</p>
                <p class="text-sm text-gray-300">${escapeHtml(entry.event_type)}</p>
            </div>
            <div>
                <p class="text-xs text-gray-500 mb-1">Category</p>
                <p class="text-sm text-gray-300"><span class="cat-tag">${escapeHtml(entry.category)}</span></p>
            </div>
            <div>
                <p class="text-xs text-gray-500 mb-1">Source</p>
                <p class="text-sm text-gray-300"><span class="source-badge ${(SOURCE_COLOURS[entry.source] || SOURCE_COLOURS.local).cls}">${(SOURCE_COLOURS[entry.source] || SOURCE_COLOURS.local).label}</span></p>
            </div>
            <div>
                <p class="text-xs text-gray-500 mb-1">Full Timestamp</p>
                <p class="text-sm text-gray-300 font-mono">${escapeHtml(entry.timestamp)}</p>
            </div>
        </div>

        ${entry.source_detail ? renderSourceDetail(entry) : ''}

        <!-- Related events -->
        <div class="border-t border-white/5 pt-4">
            <h4 class="text-sm font-semibold text-gray-400 mb-3">
                Related Events
                <span class="text-xs text-gray-600 font-normal ml-1">(${related.length} within 30 min)</span>
            </h4>
            ${related.length === 0
                ? '<p class="text-xs text-gray-600">No related events found</p>'
                : related.map(r => {
                    const rs = r.severity.toLowerCase();
                    return `<div class="flex items-center gap-2 py-2 border-b border-white/3 cursor-pointer hover:bg-white/3 px-2 rounded" data-related-id="${escapeHtml(r.event_id)}">
                        <span class="sev-badge sev-${rs}" style="font-size:0.65rem;">${rs}</span>
                        <span class="text-xs text-gray-400 flex-shrink-0">${formatTimestamp(r.timestamp)}</span>
                        <span class="text-xs text-gray-300 truncate">${escapeHtml(truncate(r.message, 50))}</span>
                    </div>`;
                }).join('')
            }
        </div>
    `;

    // Open panel
    document.getElementById('detail-panel')?.classList.add('open');
    document.getElementById('detail-overlay')?.classList.add('open');

    // Re-render table to highlight selected row
    renderTable();

    // Click on related event to navigate
    content.querySelectorAll('[data-related-id]').forEach(el => {
        el.addEventListener('click', () => {
            openDetail(el.dataset.relatedId);
        });
    });
}

function closeDetail() {
    document.getElementById('detail-panel')?.classList.remove('open');
    document.getElementById('detail-overlay')?.classList.remove('open');
    selectedEventId = null;
    renderTable();
}

// ── WebSocket ───────────────────────────────────────────────────────

function connectWebSocket() {
    _wsUnsubs.push(wsHandler.subscribe('event', handleWebSocketMessage));
    _wsUnsubs.push(wsHandler.subscribe('threat_detected', handleWebSocketMessage));
    _wsUnsubs.push(wsHandler.subscribe('alert_created', handleWebSocketMessage));
    _wsUnsubs.push(wsHandler.subscribe('threat:remote-shield', handleWebSocketMessage));
    _wsUnsubs.push(wsHandler.subscribe('threat:correlation', handleWebSocketMessage));

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
        msg.type === 'threat:remote-shield' || msg.type === 'threat:correlation') {
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
    try {
        const d = new Date(iso);
        if (isNaN(d.getTime())) return iso;
        return d.toLocaleString([], {
            month: 'short', day: 'numeric',
            hour: '2-digit', minute: '2-digit', second: '2-digit',
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

function truncate(str, max) {
    if (!str) return '';
    return str.length > max ? str.slice(0, max) + '...' : str;
}

function setTextContent(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
}

// ── Event handlers ──────────────────────────────────────────────────

function setupSortHeaders() {
    document.querySelectorAll('.timeline-table thead th[data-sort]').forEach(th => {
        th.addEventListener('click', () => {
            const field = th.dataset.sort;
            if (sortField === field) {
                sortOrder = sortOrder === 'desc' ? 'asc' : 'desc';
            } else {
                sortField = field;
                sortOrder = 'desc';
            }

            // Update header styles
            document.querySelectorAll('.timeline-table thead th').forEach(h => {
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
        });
    });
}

function setupFilters() {
    const filterIds = ['filter-severity', 'filter-asset', 'filter-event-type', 'filter-source'];
    filterIds.forEach(id => {
        document.getElementById(id)?.addEventListener('change', () => {
            currentPage = 1;
            renderTable();
            renderD3Timeline();
        });
    });

    // Search with debounce
    let searchTimer = null;
    document.getElementById('search-input')?.addEventListener('input', () => {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(() => {
            currentPage = 1;
            renderTable();
            renderD3Timeline();
        }, 300);
    });

    // Clear filters
    document.getElementById('clear-filters-btn')?.addEventListener('click', () => {
        document.getElementById('filter-severity').value = '';
        document.getElementById('filter-asset').value = '';
        document.getElementById('filter-event-type').value = '';
        document.getElementById('filter-source').value = '';
        document.getElementById('search-input').value = '';
        currentPage = 1;
        renderTable();
        renderD3Timeline();
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
}

function setupTableRowClicks() {
    document.getElementById('timeline-tbody')?.addEventListener('click', (e) => {
        const row = e.target.closest('tr[data-event-id]');
        if (!row) return;
        openDetail(row.dataset.eventId);
    });
}

function setupDetailPanel() {
    document.getElementById('detail-close')?.addEventListener('click', closeDetail);
    document.getElementById('detail-overlay')?.addEventListener('click', closeDetail);

    // Close on Escape
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeDetail();
    });
}

// ── Refresh ─────────────────────────────────────────────────────────

async function refreshData() {
    const data = await fetchTimeline(1000);
    if (!data) return;

    allEntries = data.entries || [];
    populateFilterDropdowns();
    renderTable();
    renderD3Timeline();
}

// ── Cleanup ─────────────────────────────────────────────────────────

function destroy() {
    if (refreshInterval) { clearInterval(refreshInterval); refreshInterval = null; }
    _wsUnsubs.forEach(fn => { if (typeof fn === 'function') fn(); });
    _wsUnsubs = [];
    if (_onWsConnected) { window.removeEventListener('ws-connected', _onWsConnected); _onWsConnected = null; }
    if (_onWsDisconnected) { window.removeEventListener('ws-disconnected', _onWsDisconnected); _onWsDisconnected = null; }
    allEntries = [];
    filteredEntries = [];
    currentPage = 1;
    selectedEventId = null;
}

// ── Initialization ──────────────────────────────────────────────────

async function init() {
    destroy();
    // Initialize API client
    try {
        await apiClient.initialize();
    } catch (err) {
        console.error('Failed to initialize API client:', err);
    }

    // Fetch initial data
    await refreshData();

    // Setup event handlers
    setupSortHeaders();
    setupFilters();
    setupPagination();
    setupTableRowClicks();
    setupDetailPanel();

    // Connect WebSocket
    connectWebSocket();

    // Auto-refresh every 30 seconds
    refreshInterval = setInterval(refreshData, 30000);
}

// NOTE: No auto-init here — tab-loader.js manages the init/destroy lifecycle.

// ── Exports for testing ─────────────────────────────────────────────

export {
    init,
    destroy,
    SEV_COLOURS,
    SEV_RANK,
    SOURCE_COLOURS,
    CATEGORY_COLOURS,
    PAGE_SIZE,
    fetchTimeline,
    applyFilters,
    sortEntries,
    getPage,
    formatTimestamp,
    escapeHtml,
    truncate,
    handleWebSocketMessage,
    setLiveStatus,
    openDetail,
    closeDetail,
    renderD3Timeline,
    renderSourceDetail,
};
