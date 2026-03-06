// LAN Sentinel — local network device inventory and monitoring.
// Polls /api/lan/devices on load and every 30s, listens for
// lan_device_discovered WebSocket events for instant new-device alerts.
// Exports init() / destroy() for tab-loader lifecycle.

import { apiClient } from './utils/api-client.js';
import { wsHandler } from './websocket-handler.js';

// ── State ────────────────────────────────────────────────────────────

let devicesData = [];
let scannerStatus = {};
let _refreshInterval = null;
let _wsUnsubs = [];
let _toastTimer = null;

// ── API ──────────────────────────────────────────────────────────────

async function loadDevices() {
    try {
        const resp = await apiClient.get('/api/lan/devices');
        if (resp.ok) devicesData = await resp.json();
    } catch (err) {
        console.warn('[LAN] loadDevices failed:', err);
    }
}

async function loadStatus() {
    try {
        const resp = await apiClient.get('/api/lan/status');
        if (resp.ok) scannerStatus = await resp.json();
    } catch (err) {
        console.warn('[LAN] loadStatus failed:', err);
    }
}

async function triggerScan() {
    const btn = document.getElementById('lan-scan-btn');
    if (btn) { btn.disabled = true; btn.textContent = 'Scanning...'; }
    try {
        const resp = await apiClient.post('/api/lan/scan', {});
        if (resp.ok) {
            const result = await resp.json();
            scannerStatus = {
                last_scan: result.timestamp,
                subnet: result.subnet,
                mode: result.mode,
                scan_interval: scannerStatus.scan_interval,
                scanner_active: true,
                device_count: result.total,
                new_count: result.new_total,
            };
            await loadDevices();
            renderDevices();
            renderFooter();
        }
    } catch (err) {
        console.warn('[LAN] triggerScan failed:', err);
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Scan Now'; }
    }
}

async function markKnown(mac, label) {
    try {
        const resp = await apiClient.post(`/api/lan/devices/${encodeURIComponent(mac)}/known`, { label: label || null });
        if (resp.ok) {
            const device = devicesData.find(d => d.mac === mac);
            if (device) { device.is_known = 1; device.label = label || device.label; }
            renderDevices();
            renderHeader();
        }
    } catch (err) {
        console.warn('[LAN] markKnown failed:', err);
    }
}

// ── Rendering ────────────────────────────────────────────────────────

function renderHeader() {
    const total = devicesData.length;
    const newCount = devicesData.filter(d => !d.is_known).length;

    const totalPill = document.getElementById('lan-total-pill');
    const newPill   = document.getElementById('lan-new-pill');
    const cleanPill = document.getElementById('lan-clean-pill');
    if (totalPill) totalPill.textContent = `${total} device${total !== 1 ? 's' : ''}`;
    if (newPill)   { newPill.textContent = `${newCount} unknown`; newPill.style.display = newCount > 0 ? '' : 'none'; }
    if (cleanPill) cleanPill.style.display = (total > 0 && newCount === 0) ? '' : 'none';
}

function renderFooter() {
    const s = scannerStatus;
    setTextContent('lan-last-scan', s.last_scan ? formatTs(s.last_scan) : '—');
    setTextContent('lan-subnet',    s.subnet    || '—');
    setTextContent('lan-mode',      s.mode      || '—');
    setTextContent('lan-interval',  s.scan_interval ? `${s.scan_interval}s` : '—');
}

function renderDevices() {
    const tbody = document.getElementById('lan-tbody');
    if (!tbody) return;
    renderHeader();

    if (devicesData.length === 0) {
        tbody.innerHTML = `
            <tr><td colspan="9" style="text-align:center; padding:3rem; color:#6B7280;">
                No devices found yet — click Scan Now or wait for the first automatic scan.
            </td></tr>`;
        return;
    }

    tbody.innerHTML = devicesData.map(d => {
        const isNew = !d.is_known;
        const rowCls = isNew ? ' class="is-new"' : '';
        const badge = isNew
            ? `<span class="device-status-badge new-device">&#x25CF; Unknown</span>`
            : `<span class="device-status-badge known">&#x2713; Known</span>`;
        const actionBtn = isNew
            ? `<button class="btn-mark-known" data-mac="${escapeHtml(d.mac)}">Mark Known</button>`
            : '';
        return `
        <tr${rowCls}>
            <td>${badge}</td>
            <td><span class="ip-mono">${escapeHtml(d.ip || '—')}</span></td>
            <td><span class="mac-mono">${escapeHtml(d.mac || '—')}</span></td>
            <td>${escapeHtml(d.hostname || '—')}</td>
            <td style="color:#94a3b8;">${escapeHtml(d.manufacturer || '—')}</td>
            <td style="color:#6B7280; font-size:0.65rem;">${escapeHtml(formatTs(d.first_seen))}</td>
            <td style="color:#6B7280; font-size:0.65rem;">${escapeHtml(formatTs(d.last_seen))}</td>
            <td style="color:#94a3b8;">${escapeHtml(d.label || '—')}</td>
            <td>${actionBtn}</td>
        </tr>`;
    }).join('');

    // Wire Mark Known buttons
    tbody.querySelectorAll('[data-mac]').forEach(btn => {
        btn.addEventListener('click', async () => {
            const mac = btn.dataset.mac;
            const label = prompt(`Friendly name for ${mac} (optional):`);
            if (label !== null) await markKnown(mac, label);
        });
    });
}

// ── WebSocket ─────────────────────────────────────────────────────────

function handleWsMessage(msg) {
    if (msg.type === 'lan_device_discovered') {
        const d = msg.device || {};
        showToast(`New device on LAN: ${d.ip || '?'} (${d.mac || '?'})`);
        // Refresh full list to pick up the new record
        Promise.all([loadDevices(), loadStatus()]).then(() => {
            renderDevices();
            renderFooter();
        });
    }
}

function setLiveStatus(connected) {
    const dot  = document.getElementById('lan-live-dot');
    const text = document.getElementById('lan-live-text');
    if (dot)  { dot.className  = `live-dot${connected ? ' connected' : ''}`; }
    if (text) text.textContent = connected ? 'Live' : 'Offline';
}

// ── Toast ─────────────────────────────────────────────────────────────

function showToast(message) {
    const el = document.getElementById('lan-toast');
    if (!el) return;
    el.textContent = message;
    el.classList.add('show');
    if (_toastTimer) clearTimeout(_toastTimer);
    _toastTimer = setTimeout(() => el.classList.remove('show'), 5000);
}

// ── Helpers ───────────────────────────────────────────────────────────

function formatTs(iso) {
    if (!iso) return '—';
    try {
        const d = new Date(iso);
        if (isNaN(d)) return iso;
        return d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    } catch { return iso; }
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function setTextContent(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
}

// ── Lifecycle ─────────────────────────────────────────────────────────

async function init() {
    destroy();

    try { await apiClient.initialize(); } catch (err) {
        console.error('[LAN] API client init failed:', err);
    }

    // Expose scan trigger for onclick in HTML
    window._lanScanNow = triggerScan;

    // Load data
    await Promise.all([loadDevices(), loadStatus()]);
    renderDevices();
    renderFooter();

    // WebSocket: live updates
    _wsUnsubs.push(wsHandler.subscribe('lan_device_discovered', handleWsMessage));
    setLiveStatus(wsHandler.connected);
    const pollLive = setInterval(() => setLiveStatus(wsHandler.connected), 2000);
    _wsUnsubs.push(() => clearInterval(pollLive));

    // Periodic refresh every 30s (lighter than scanner interval)
    _refreshInterval = setInterval(async () => {
        await Promise.all([loadDevices(), loadStatus()]);
        renderDevices();
        renderFooter();
    }, 30000);
}

function destroy() {
    if (_refreshInterval) { clearInterval(_refreshInterval); _refreshInterval = null; }
    _wsUnsubs.forEach(fn => { if (typeof fn === 'function') fn(); });
    _wsUnsubs = [];
    if (_toastTimer) { clearTimeout(_toastTimer); _toastTimer = null; }
    delete window._lanScanNow;
    devicesData = [];
    scannerStatus = {};
}

export { init, destroy };
