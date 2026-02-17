/**
 * Performance Analytics module — fleet health + per-asset attention scores.
 * v0.3.34: Read-only analytics over existing data sources.
 *
 * Lifecycle: init() on tab load, destroy() on tab switch.
 */

import { apiClient } from './utils/api-client.js';
import { wsHandler } from './websocket-handler.js';

// ── Constants ────────────────────────────────────────────────────────

const CATEGORY_COLORS = {
    critical:  { fg: '#ff3333', bg: 'rgba(255,51,51,0.15)' },
    attention: { fg: '#ff9900', bg: 'rgba(255,153,0,0.15)' },
    watch:     { fg: '#e6b800', bg: 'rgba(230,184,0,0.15)' },
    healthy:   { fg: '#00cc66', bg: 'rgba(0,204,102,0.15)' },
};

const CRITICAL_REASONS = new Set([
    'Compromised status', 'Offline',
]);

const WARNING_REASONS = new Set([
    'Guardian inactive', 'Reboot required',
]);

// ── State ────────────────────────────────────────────────────────────

let _allScores = [];
let _fleetData = null;
let _refreshInterval = null;
let _wsUnsubs = [];
let _currentSort = 'attention';
let _currentFilter = 'all';
let _debounceTimer = null;

// ── Init / Destroy ──────────────────────────────────────────────────

export async function init() {
    setupControls();
    connectWebSocket();
    await refreshAll();
    _refreshInterval = setInterval(refreshAll, 60000);
}

export function destroy() {
    if (_refreshInterval) {
        clearInterval(_refreshInterval);
        _refreshInterval = null;
    }
    if (_debounceTimer) {
        clearTimeout(_debounceTimer);
        _debounceTimer = null;
    }
    _wsUnsubs.forEach(fn => { if (typeof fn === 'function') fn(); });
    _wsUnsubs = [];
    _allScores = [];
    _fleetData = null;
}

// ── Data Fetching ───────────────────────────────────────────────────

async function fetchPerformance() {
    try {
        const data = await apiClient.get('/api/performance');
        _fleetData = data.fleet || {};
        _allScores = data.assets || [];
        return true;
    } catch (e) {
        console.error('[performance] Failed to fetch:', e);
        return false;
    }
}

async function refreshAll() {
    const ok = await fetchPerformance();
    if (!ok) return;

    updateFleetSummary(_fleetData);
    renderFleetHealthBar(_fleetData);
    renderAssetCards(applyFilterSort(_allScores, _currentFilter, _currentSort));
    updateLastUpdated();
}

// ── Fleet Summary ───────────────────────────────────────────────────

function updateFleetSummary(fleet) {
    setText('fleet-total', fleet.total_systems || 0);
    setText('fleet-healthy', fleet.healthy || 0);
    setText('fleet-watch', (fleet.watch || 0) + (fleet.attention || 0));  // label reads "Watch / Attn"
    setText('fleet-critical', fleet.critical || 0);
    setText('fleet-score-value', Math.round(fleet.fleet_score || 0));

    const label = document.getElementById('fleet-score-label');
    if (label) {
        const cat = fleet.fleet_category || 'healthy';
        const color = (CATEGORY_COLORS[cat] || CATEGORY_COLORS.healthy).fg;
        label.textContent = capitalize(cat);
        label.style.color = color;
    }
}

function renderFleetHealthBar(fleet) {
    const bar = document.getElementById('fleet-health-bar');
    if (!bar) return;

    const total = fleet.total_systems || 0;
    if (total === 0) {
        bar.innerHTML = '';
        return;
    }

    const segments = [
        { key: 'healthy', count: fleet.healthy || 0, cls: 'bar-seg-healthy' },
        { key: 'watch', count: fleet.watch || 0, cls: 'bar-seg-watch' },
        { key: 'attention', count: fleet.attention || 0, cls: 'bar-seg-attention' },
        { key: 'critical', count: fleet.critical || 0, cls: 'bar-seg-critical' },
    ];

    bar.innerHTML = segments
        .filter(s => s.count > 0)
        .map(s => {
            const pct = (s.count / total * 100).toFixed(1);
            return `<div class="bar-seg ${s.cls}" style="width:${pct}%" title="${capitalize(s.key)}: ${s.count}"></div>`;
        })
        .join('');
}

// ── Asset Cards ─────────────────────────────────────────────────────

function renderAssetCards(scores) {
    const container = document.getElementById('asset-cards-container');
    const empty = document.getElementById('perf-empty');
    if (!container) return;

    if (scores.length === 0) {
        if (empty) empty.style.display = 'block';
        // Remove any existing cards but keep empty state
        container.querySelectorAll('.asset-attention-card').forEach(c => c.remove());
        return;
    }

    if (empty) empty.style.display = 'none';
    // Remove old cards but preserve empty-state div
    container.querySelectorAll('.asset-attention-card').forEach(c => c.remove());
    container.insertAdjacentHTML('beforeend', scores.map(buildAssetCard).join(''));
}

function buildAssetCard(score) {
    const cat = score.category || 'healthy';
    const color = (CATEGORY_COLORS[cat] || CATEGORY_COLORS.healthy).fg;
    const bg = (CATEGORY_COLORS[cat] || CATEGORY_COLORS.healthy).bg;
    const safeName = escapeHtml(score.name || score.hostname || 'Unknown');
    const platform = escapeHtml(score.platform || '');
    const ip = escapeHtml(score.ip_address || '');

    return `
    <div class="asset-attention-card cat-${cat}">
        <div class="card-top">
            <div>
                <div class="category-badge" style="background:${bg};color:${color}">${cat.toUpperCase()}</div>
                <div class="card-name">${safeName}</div>
                <div class="card-meta">${platform}${ip ? ' &middot; ' + ip : ''}</div>
            </div>
            <div class="card-score">
                <div class="score-number" style="color:${color}">${score.attention_score}</div>
                <div class="score-max">/100</div>
            </div>
        </div>
        <div class="score-bar-track">
            <div class="score-bar-fill" style="width:${score.attention_score}%;background:${color}"></div>
        </div>
        ${buildSubScoreGrid(score)}
        <div class="reason-chips">${buildReasonChips(score.reasons || [])}</div>
    </div>`;
}

function buildSubScoreGrid(score) {
    const items = [
        { label: 'Status', value: score.status_score || 0, max: 40 },
        { label: 'Threats', value: score.threat_score || 0, max: 25 },
        { label: 'Patches', value: score.patch_score || 0, max: 20 },
        { label: 'Heartbeat', value: score.heartbeat_score || 0, max: 10 },
        { label: 'Guardian', value: score.guardian_score || 0, max: 5 },
    ];

    return `<div class="sub-score-grid">${items.map(i =>
        `<div class="sub-score-item">
            <div class="sub-score-value">${i.value}</div>
            <div class="sub-score-label">${i.label}</div>
        </div>`
    ).join('')}</div>`;
}

function buildReasonChips(reasons) {
    if (!reasons || reasons.length === 0) return '';
    return reasons.map(r => {
        let cls = 'reason-chip';
        if (CRITICAL_REASONS.has(r)) cls += ' chip-critical';
        else if (WARNING_REASONS.has(r)) cls += ' chip-warning';
        else if (r.includes('critical') || r.includes('Compromised')) cls += ' chip-critical';
        else if (r.includes('pending') || r.includes('overdue') || r.includes('heartbeat')) cls += ' chip-warning';
        else cls += ' chip-info';
        return `<span class="${cls}">${escapeHtml(r)}</span>`;
    }).join('');
}

// ── Sort / Filter ───────────────────────────────────────────────────

function applyFilterSort(scores, filter, sort) {
    let filtered = scores;
    if (filter !== 'all') {
        filtered = scores.filter(s => s.category === filter);
    }

    const sorted = [...filtered];
    if (sort === 'attention') {
        sorted.sort((a, b) => b.attention_score - a.attention_score);
    } else if (sort === 'name') {
        sorted.sort((a, b) => (a.name || '').localeCompare(b.name || ''));
    } else if (sort === 'status') {
        const order = { compromised: 0, offline: 1, unknown: 2, online: 3, protected: 4 };
        sorted.sort((a, b) => (order[a.status] ?? 5) - (order[b.status] ?? 5));
    }
    return sorted;
}

function setupControls() {
    const sortEl = document.getElementById('perf-sort-select');
    const filterEl = document.getElementById('perf-filter-select');

    if (sortEl) {
        sortEl.value = _currentSort;
        sortEl.addEventListener('change', () => {
            _currentSort = sortEl.value;
            renderAssetCards(applyFilterSort(_allScores, _currentFilter, _currentSort));
        });
    }
    if (filterEl) {
        filterEl.value = _currentFilter;
        filterEl.addEventListener('change', () => {
            _currentFilter = filterEl.value;
            renderAssetCards(applyFilterSort(_allScores, _currentFilter, _currentSort));
        });
    }
}

// ── WebSocket ───────────────────────────────────────────────────────

function debouncedRefresh() {
    if (_debounceTimer) clearTimeout(_debounceTimer);
    _debounceTimer = setTimeout(() => { _debounceTimer = null; refreshAll(); }, 2000);
}

function connectWebSocket() {
    _wsUnsubs.push(wsHandler.subscribe('event', debouncedRefresh));
    _wsUnsubs.push(wsHandler.subscribe('threat_detected', debouncedRefresh));

    setLiveStatus(wsHandler.connected);
    const poll = setInterval(() => setLiveStatus(wsHandler.connected), 2000);
    _wsUnsubs.push(() => clearInterval(poll));
}

function setLiveStatus(connected) {
    const dot = document.getElementById('perf-live-dot');
    const text = document.getElementById('perf-live-text');
    if (dot) {
        dot.classList.toggle('disconnected', !connected);
    }
    if (text) {
        text.textContent = connected ? 'Live' : 'Disconnected';
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function capitalize(s) {
    return s ? s.charAt(0).toUpperCase() + s.slice(1) : '';
}

function escapeHtml(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
}

function updateLastUpdated() {
    const el = document.getElementById('perf-last-updated');
    if (el) {
        el.textContent = 'Updated ' + new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
}
