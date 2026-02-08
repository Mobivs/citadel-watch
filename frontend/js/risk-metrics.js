// PRD: Risk Metrics - Frontend threat gauges, bars, sparklines
// Reference: PHASE_2_SPEC.md, P2.1.5-T3
//
// Fetches risk data from /api/threat-score and /api/charts,
// renders threat counters with sparklines, a needle gauge,
// asset risk bar chart, and trending line chart.
// Auto-refreshes every 30 seconds with WebSocket live updates.

import { apiClient } from './utils/api-client.js';
import { wsHandler } from './websocket-handler.js';

// ── Colour constants ────────────────────────────────────────────────

const COLOURS = {
    critical: { fg: '#ff3333', bg: 'rgba(255,51,51,0.15)' },
    high:     { fg: '#ff9900', bg: 'rgba(255,153,0,0.15)' },
    medium:   { fg: '#ffcc00', bg: 'rgba(255,204,0,0.15)' },
    low:      { fg: '#00cc66', bg: 'rgba(0,204,102,0.15)' },
};

const GAUGE_ZONES = [
    { min: 0.00, max: 0.25, colour: '#00cc66', label: 'Safe' },
    { min: 0.25, max: 0.50, colour: '#ffcc00', label: 'Elevated' },
    { min: 0.50, max: 0.75, colour: '#ff9900', label: 'High' },
    { min: 0.75, max: 1.00, colour: '#ff3333', label: 'Critical' },
];

// Chart.js global defaults
Chart.defaults.color = '#9CA3AF';
Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.06)';
Chart.defaults.font.family = 'system-ui, -apple-system, sans-serif';

// ── State ───────────────────────────────────────────────────────────

let trendChart = null;
let assetRiskChart = null;
let refreshInterval = null;
let currentSensitivity = 'moderate';
let _wsUnsubs = [];
let _onWsConnected = null;
let _onWsDisconnected = null;

// ── API ─────────────────────────────────────────────────────────────

async function fetchThreatScore() {
    try {
        const resp = await apiClient.get('/api/threat-score');
        if (!resp.ok) return null;
        return await resp.json();
    } catch (err) {
        console.error('Threat score fetch failed:', err);
        return null;
    }
}

async function fetchChartData(hours, bucketHours) {
    try {
        const resp = await apiClient.get(
            `/api/charts?hours=${hours}&bucket_hours=${bucketHours}`
        );
        if (!resp.ok) return null;
        return await resp.json();
    } catch (err) {
        console.error('Charts fetch failed:', err);
        return null;
    }
}

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

// ── Threat Counter Cards ────────────────────────────────────────────

function updateCounters(threatScore) {
    const byLevel = threatScore.by_risk_level || {};
    setText('count-critical', byLevel.critical || 0);
    setText('count-high', byLevel.high || 0);
    setText('count-medium', byLevel.medium || 0);
    setText('count-low', byLevel.low || 0);
}

// ── Sparklines (Canvas 2D) ──────────────────────────────────────────

function drawSparkline(containerId, data, colour) {
    const container = document.getElementById(containerId);
    if (!container) return;

    // Clear previous
    container.innerHTML = '';

    const canvas = document.createElement('canvas');
    const w = container.clientWidth || 200;
    const h = 60;
    canvas.width = w * 2;  // retina
    canvas.height = h * 2;
    canvas.style.width = w + 'px';
    canvas.style.height = h + 'px';
    container.appendChild(canvas);

    const ctx = canvas.getContext('2d');
    ctx.scale(2, 2);  // retina

    if (!data || data.length === 0) return;

    const max = Math.max(...data, 1);
    const step = w / Math.max(data.length - 1, 1);
    const padding = 4;

    // Draw fill
    ctx.beginPath();
    ctx.moveTo(0, h);
    for (let i = 0; i < data.length; i++) {
        const x = i * step;
        const y = h - padding - ((data[i] / max) * (h - padding * 2));
        if (i === 0) ctx.lineTo(x, y);
        else ctx.lineTo(x, y);
    }
    ctx.lineTo((data.length - 1) * step, h);
    ctx.closePath();
    ctx.fillStyle = colour.replace(')', ',0.1)').replace('rgb', 'rgba');
    ctx.fill();

    // Draw line
    ctx.beginPath();
    for (let i = 0; i < data.length; i++) {
        const x = i * step;
        const y = h - padding - ((data[i] / max) * (h - padding * 2));
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    }
    ctx.strokeStyle = colour;
    ctx.lineWidth = 1.5;
    ctx.lineJoin = 'round';
    ctx.stroke();
}

function updateSparklines(chartData) {
    if (!chartData || !chartData.points) return;

    const criticalData = chartData.points.map(p => p.critical);
    const highData = chartData.points.map(p => p.high);
    const mediumData = chartData.points.map(p => p.medium);
    const lowData = chartData.points.map(p => p.low);

    drawSparkline('sparkline-critical', criticalData, COLOURS.critical.fg);
    drawSparkline('sparkline-high', highData, COLOURS.high.fg);
    drawSparkline('sparkline-medium', mediumData, COLOURS.medium.fg);
    drawSparkline('sparkline-low', lowData, COLOURS.low.fg);
}

// ── Threat Gauge (Canvas 2D needle) ─────────────────────────────────

function drawGauge(value) {
    const canvas = document.getElementById('threat-gauge');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;
    const cx = w / 2;
    const cy = h - 10;
    const radius = Math.min(cx, cy) - 20;

    ctx.clearRect(0, 0, w, h);

    // Draw zone arcs (half circle, from PI to 0)
    const startAngle = Math.PI;
    const endAngle = 0;
    const totalArc = Math.PI;

    for (const zone of GAUGE_ZONES) {
        const zStart = startAngle + (zone.min * totalArc);
        const zEnd = startAngle + (zone.max * totalArc);

        ctx.beginPath();
        ctx.arc(cx, cy, radius, zStart, zEnd);
        ctx.lineWidth = 18;
        ctx.strokeStyle = zone.colour + '40'; // 25% opacity
        ctx.stroke();
    }

    // Active zone highlight
    const clampedVal = Math.max(0, Math.min(1, value));
    const activeZone = GAUGE_ZONES.find(z => clampedVal >= z.min && clampedVal < z.max)
        || GAUGE_ZONES[GAUGE_ZONES.length - 1];

    const activeStart = startAngle;
    const activeEnd = startAngle + (clampedVal * totalArc);

    ctx.beginPath();
    ctx.arc(cx, cy, radius, activeStart, activeEnd);
    ctx.lineWidth = 18;
    ctx.strokeStyle = activeZone.colour + 'CC'; // 80% opacity
    ctx.lineCap = 'round';
    ctx.stroke();

    // Needle
    const needleAngle = startAngle + (clampedVal * totalArc);
    const needleLen = radius - 30;
    const nx = cx + Math.cos(needleAngle) * needleLen;
    const ny = cy + Math.sin(needleAngle) * needleLen;

    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(nx, ny);
    ctx.strokeStyle = '#E5E7EB';
    ctx.lineWidth = 2.5;
    ctx.lineCap = 'round';
    ctx.stroke();

    // Center dot
    ctx.beginPath();
    ctx.arc(cx, cy, 5, 0, Math.PI * 2);
    ctx.fillStyle = '#00D9FF';
    ctx.fill();

    // Update text
    const pct = Math.round(clampedVal * 100);
    setText('gauge-value-text', pct + '%');

    const zone = getZoneLabel(clampedVal);
    setText('gauge-zone-text', zone);
    setText('gauge-zone-label', zone);
}

function getZoneLabel(value) {
    if (value >= 0.75) return 'Critical';
    if (value >= 0.50) return 'High';
    if (value >= 0.25) return 'Elevated';
    return 'Safe';
}

// ── Trending Chart (Chart.js line) ──────────────────────────────────

function buildTrendChart(ctx, chartData) {
    const points = chartData?.points || [];
    const labels = points.map(p => {
        const d = new Date(p.timestamp);
        return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    });

    return new Chart(ctx, {
        type: 'line',
        data: {
            labels,
            datasets: [
                {
                    label: 'Total',
                    data: points.map(p => p.total),
                    backgroundColor: 'rgba(147, 51, 234, 0.15)',
                    borderColor: 'rgba(147, 51, 234, 1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.3,
                    pointRadius: 1,
                },
                {
                    label: 'Critical',
                    data: points.map(p => p.critical),
                    borderColor: COLOURS.critical.fg,
                    borderWidth: 1.5,
                    fill: false,
                    tension: 0.3,
                    pointRadius: 1,
                },
                {
                    label: 'High',
                    data: points.map(p => p.high),
                    borderColor: COLOURS.high.fg,
                    borderWidth: 1.5,
                    fill: false,
                    tension: 0.3,
                    pointRadius: 1,
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { intersect: false, mode: 'index' },
            plugins: {
                legend: { position: 'bottom', labels: { boxWidth: 10, padding: 12, font: { size: 11 } } },
            },
            scales: {
                x: { grid: { display: false }, ticks: { maxTicksLimit: 8, font: { size: 10 } } },
                y: { beginAtZero: true, ticks: { stepSize: 1, font: { size: 10 } } },
            },
        },
    });
}

function updateTrendChart(chart, chartData) {
    const points = chartData?.points || [];
    chart.data.labels = points.map(p => {
        const d = new Date(p.timestamp);
        return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    });
    chart.data.datasets[0].data = points.map(p => p.total);
    chart.data.datasets[1].data = points.map(p => p.critical);
    chart.data.datasets[2].data = points.map(p => p.high);
    chart.update('none');
}

// ── Asset Risk Bar Chart (Chart.js) ─────────────────────────────────

function buildAssetRiskChart(ctx, assetsData) {
    const assets = assetsData?.assets || [];
    const labels = assets.map(a => a.name || a.asset_id);

    // Build stacked bar data from event counts and status
    const eventCounts = assets.map(a => a.event_count || 0);

    setText('asset-count-label', `${assets.length} assets`);

    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels,
            datasets: [{
                label: 'Events',
                data: eventCounts,
                backgroundColor: assets.map(a => {
                    if (!a.guardian_active) return 'rgba(107, 114, 128, 0.6)';
                    if (a.event_count > 50) return COLOURS.critical.fg + 'CC';
                    if (a.event_count > 20) return COLOURS.high.fg + 'CC';
                    if (a.event_count > 5) return COLOURS.medium.fg + 'CC';
                    return COLOURS.low.fg + 'CC';
                }),
                borderColor: assets.map(a => {
                    if (!a.guardian_active) return 'rgba(107, 114, 128, 1)';
                    if (a.event_count > 50) return COLOURS.critical.fg;
                    if (a.event_count > 20) return COLOURS.high.fg;
                    if (a.event_count > 5) return COLOURS.medium.fg;
                    return COLOURS.low.fg;
                }),
                borderWidth: 1,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            plugins: {
                legend: { display: false },
            },
            scales: {
                x: { beginAtZero: true, ticks: { stepSize: 1, font: { size: 10 } } },
                y: { grid: { display: false }, ticks: { font: { size: 11 } } },
            },
        },
    });
}

function updateAssetRiskChart(chart, assetsData) {
    const assets = assetsData?.assets || [];
    chart.data.labels = assets.map(a => a.name || a.asset_id);
    chart.data.datasets[0].data = assets.map(a => a.event_count || 0);
    chart.data.datasets[0].backgroundColor = assets.map(a => {
        if (!a.guardian_active) return 'rgba(107, 114, 128, 0.6)';
        if (a.event_count > 50) return COLOURS.critical.fg + 'CC';
        if (a.event_count > 20) return COLOURS.high.fg + 'CC';
        if (a.event_count > 5) return COLOURS.medium.fg + 'CC';
        return COLOURS.low.fg + 'CC';
    });
    setText('asset-count-label', `${assets.length} assets`);
    chart.update('none');
}

// ── Compute gauge value from threat score ───────────────────────────

function computeGaugeValue(threatScore) {
    const byLevel = threatScore.by_risk_level || {};
    const c = byLevel.critical || 0;
    const h = byLevel.high || 0;
    const m = byLevel.medium || 0;
    const l = byLevel.low || 0;
    const total = c + h + m + l;
    if (total === 0) return 0;
    const weighted = (c * 4 + h * 3 + m * 2 + l * 1);
    const maxPossible = total * 4;
    return Math.min(1.0, weighted / maxPossible);
}

// ── Sensitivity Control ─────────────────────────────────────────────

function setupSensitivity() {
    const container = document.getElementById('sensitivity-selector');
    if (!container) return;

    container.addEventListener('click', (e) => {
        const btn = e.target.closest('.sens-btn');
        if (!btn) return;

        container.querySelectorAll('.sens-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        currentSensitivity = btn.dataset.sensitivity;

        // No backend endpoint for sensitivity yet — stored locally
        // Will be wired when /api/sensitivity endpoint is added
        console.log('Sensitivity set to:', currentSensitivity);
    });
}

// ── WebSocket ───────────────────────────────────────────────────────

function connectWebSocket() {
    _wsUnsubs.push(wsHandler.subscribe('event', handleWebSocketMessage));
    _wsUnsubs.push(wsHandler.subscribe('threat_detected', handleWebSocketMessage));
    _wsUnsubs.push(wsHandler.subscribe('security_level_changed', handleWebSocketMessage));
    _wsUnsubs.push(wsHandler.subscribe('alert_created', handleWebSocketMessage));

    _onWsConnected = () => setLiveStatus(true);
    _onWsDisconnected = () => setLiveStatus(false);
    window.addEventListener('ws-connected', _onWsConnected);
    window.addEventListener('ws-disconnected', _onWsDisconnected);

    wsHandler.connect();
}

function handleWebSocketMessage(msg) {
    if (msg.type === 'event' || msg.type === 'threat_detected' ||
        msg.type === 'security_level_changed') {
        refreshAll();
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
        if (text) text.textContent = 'Simulated';
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

// ── Refresh ─────────────────────────────────────────────────────────

async function refreshAll() {
    const [threatScore, chartData, assetsData] = await Promise.all([
        fetchThreatScore(),
        fetchChartData(24, 1),
        fetchAssets(),
    ]);

    // Counters
    if (threatScore) {
        updateCounters(threatScore);
        drawGauge(computeGaugeValue(threatScore));
    } else {
        drawGauge(0);
    }

    // Sparklines
    if (chartData) {
        updateSparklines(chartData);
    }

    // Trend chart
    if (chartData) {
        if (trendChart) {
            updateTrendChart(trendChart, chartData);
        }
    }

    // Asset risk chart
    if (assetsData) {
        if (assetRiskChart) {
            updateAssetRiskChart(assetRiskChart, assetsData);
        }
    }
}

// ── Cleanup ─────────────────────────────────────────────────────────

function destroy() {
    if (refreshInterval) { clearInterval(refreshInterval); refreshInterval = null; }
    if (trendChart) { trendChart.destroy(); trendChart = null; }
    if (assetRiskChart) { assetRiskChart.destroy(); assetRiskChart = null; }
    _wsUnsubs.forEach(fn => { if (typeof fn === 'function') fn(); });
    _wsUnsubs = [];
    if (_onWsConnected) { window.removeEventListener('ws-connected', _onWsConnected); _onWsConnected = null; }
    if (_onWsDisconnected) { window.removeEventListener('ws-disconnected', _onWsDisconnected); _onWsDisconnected = null; }
}

// ── Initialization ──────────────────────────────────────────────────

async function init() {
    destroy();
    // Initialize API client
    try {
        await apiClient.initialize();
    } catch (err) {
        console.error('API client init failed:', err);
    }

    // Fetch initial data
    const [threatScore, chartData, assetsData] = await Promise.all([
        fetchThreatScore(),
        fetchChartData(24, 1),
        fetchAssets(),
    ]);

    // Counters
    if (threatScore) {
        updateCounters(threatScore);
    }

    // Gauge
    const gaugeValue = threatScore ? computeGaugeValue(threatScore) : 0;
    drawGauge(gaugeValue);

    // Sparklines
    if (chartData) {
        updateSparklines(chartData);
    }

    // Trend chart
    const trendCtx = document.getElementById('trend-chart');
    if (trendCtx) {
        trendChart = buildTrendChart(
            trendCtx.getContext('2d'),
            chartData || { points: [] }
        );
    }

    // Asset risk chart
    const assetCtx = document.getElementById('asset-risk-chart');
    if (assetCtx) {
        assetRiskChart = buildAssetRiskChart(
            assetCtx.getContext('2d'),
            assetsData || { assets: [] }
        );
    }

    // Setup controls
    setupSensitivity();

    // WebSocket
    connectWebSocket();

    // Auto-refresh every 30 seconds
    refreshInterval = setInterval(refreshAll, 30000);
}

// Start
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}

// ── Exports for testing ─────────────────────────────────────────────

export {
    init,
    destroy,
    COLOURS,
    GAUGE_ZONES,
    fetchThreatScore,
    fetchChartData,
    fetchAssets,
    updateCounters,
    drawSparkline,
    drawGauge,
    getZoneLabel,
    computeGaugeValue,
    buildTrendChart,
    updateTrendChart,
    buildAssetRiskChart,
    updateAssetRiskChart,
    handleWebSocketMessage,
    setLiveStatus,
    refreshAll,
    currentSensitivity,
};
