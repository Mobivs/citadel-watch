// PRD: Charts & Visualization - Frontend chart rendering
// Reference: PHASE_2_SPEC.md, P2.1.5-T1
//
// Fetches threat data from /api/charts, renders 4 Chart.js charts,
// auto-refreshes every 30 seconds, and receives real-time WebSocket updates.

import { apiClient } from './utils/api-client.js';
import { wsHandler } from './websocket-handler.js';

// ── Chart colour constants (matches ChartTheme in chart_data.py) ────

const COLOURS = {
    low:      { bg: 'rgba(0, 204, 102, 0.3)',   border: 'rgba(0, 204, 102, 1)' },
    medium:   { bg: 'rgba(255, 204, 0, 0.3)',   border: 'rgba(255, 204, 0, 1)' },
    high:     { bg: 'rgba(255, 153, 0, 0.3)',   border: 'rgba(255, 153, 0, 1)' },
    critical: { bg: 'rgba(255, 51, 51, 0.3)',   border: 'rgba(255, 51, 51, 1)' },
};

const CATEGORY_COLOURS = {
    file:    { bg: 'rgba(59, 130, 246, 0.7)',  border: 'rgba(59, 130, 246, 1)' },
    process: { bg: 'rgba(168, 85, 247, 0.7)',  border: 'rgba(168, 85, 247, 1)' },
    network: { bg: 'rgba(0, 217, 255, 0.7)',   border: 'rgba(0, 217, 255, 1)' },
    vault:   { bg: 'rgba(255, 204, 0, 0.7)',   border: 'rgba(255, 204, 0, 1)' },
    system:  { bg: 'rgba(107, 114, 128, 0.7)', border: 'rgba(107, 114, 128, 1)' },
    ai:      { bg: 'rgba(236, 72, 153, 0.7)',  border: 'rgba(236, 72, 153, 1)' },
    user:    { bg: 'rgba(0, 204, 102, 0.7)',   border: 'rgba(0, 204, 102, 1)' },
    intel:   { bg: 'rgba(255, 153, 0, 0.7)',   border: 'rgba(255, 153, 0, 1)' },
};

// ── Chart.js global defaults (dark theme) ───────────────────────────

Chart.defaults.color = '#9CA3AF';
Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.06)';
Chart.defaults.font.family = 'system-ui, -apple-system, sans-serif';

// ── State ───────────────────────────────────────────────────────────

let trendChart = null;
let severityChart = null;
let timelineChart = null;
let categoryChart = null;
let refreshInterval = null;
let selectedHours = 24;
let _wsUnsubs = [];
let _onWsConnected = null;
let _onWsDisconnected = null;

// ── API fetch ───────────────────────────────────────────────────────

async function fetchChartData(hours, bucketHours) {
    try {
        const resp = await apiClient.get(
            `/api/charts?hours=${hours}&bucket_hours=${bucketHours}`
        );
        if (!resp.ok) {
            console.error('Charts API error:', resp.status);
            return null;
        }
        return await resp.json();
    } catch (err) {
        console.error('Charts fetch failed:', err);
        return null;
    }
}

async function fetchTimeline(limit, severity) {
    try {
        let url = `/api/timeline?limit=${limit}`;
        if (severity) url += `&severity=${severity}`;
        const resp = await apiClient.get(url);
        if (!resp.ok) return null;
        return await resp.json();
    } catch (err) {
        console.error('Timeline fetch failed:', err);
        return null;
    }
}

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

// ── Chart builders ──────────────────────────────────────────────────

function buildTrendChart(ctx, data) {
    const labels = data.points.map(p => {
        const d = new Date(p.timestamp);
        return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    });

    const config = {
        type: 'line',
        data: {
            labels,
            datasets: [
                {
                    label: 'Low',
                    data: data.points.map(p => p.low),
                    backgroundColor: COLOURS.low.bg,
                    borderColor: COLOURS.low.border,
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 2,
                },
                {
                    label: 'Medium',
                    data: data.points.map(p => p.medium),
                    backgroundColor: COLOURS.medium.bg,
                    borderColor: COLOURS.medium.border,
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 2,
                },
                {
                    label: 'High',
                    data: data.points.map(p => p.high),
                    backgroundColor: COLOURS.high.bg,
                    borderColor: COLOURS.high.border,
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 2,
                },
                {
                    label: 'Critical',
                    data: data.points.map(p => p.critical),
                    backgroundColor: COLOURS.critical.bg,
                    borderColor: COLOURS.critical.border,
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 2,
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { intersect: false, mode: 'index' },
            plugins: {
                legend: { position: 'bottom', labels: { boxWidth: 12, padding: 16 } },
                title: { display: false },
            },
            scales: {
                x: { grid: { display: false } },
                y: { beginAtZero: true, ticks: { stepSize: 1 } },
            },
        },
    };

    return new Chart(ctx, config);
}

function buildSeverityChart(ctx, data) {
    // Aggregate severity counts from trend points
    const counts = { low: 0, medium: 0, high: 0, critical: 0 };
    for (const p of data.points) {
        counts.low += p.low;
        counts.medium += p.medium;
        counts.high += p.high;
        counts.critical += p.critical;
    }

    const config = {
        type: 'doughnut',
        data: {
            labels: ['Low', 'Medium', 'High', 'Critical'],
            datasets: [{
                data: [counts.low, counts.medium, counts.high, counts.critical],
                backgroundColor: [
                    COLOURS.low.bg.replace('0.3', '0.8'),
                    COLOURS.medium.bg.replace('0.3', '0.8'),
                    COLOURS.high.bg.replace('0.3', '0.8'),
                    COLOURS.critical.bg.replace('0.3', '0.8'),
                ],
                borderColor: [
                    COLOURS.low.border,
                    COLOURS.medium.border,
                    COLOURS.high.border,
                    COLOURS.critical.border,
                ],
                borderWidth: 1,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'bottom', labels: { boxWidth: 12, padding: 16 } },
            },
            cutout: '60%',
        },
    };

    return new Chart(ctx, config);
}

function buildTimelineScatterChart(ctx, timelineData) {
    // Map timeline entries to scatter points
    const severityY = { info: 1, investigate: 2, alert: 3, critical: 4 };
    const groups = { low: [], medium: [], high: [], critical: [] };

    if (timelineData && timelineData.entries) {
        for (const entry of timelineData.entries) {
            const sev = entry.severity.toLowerCase();
            const y = severityY[sev] || 1;
            const x = new Date(entry.timestamp).getTime();
            const point = { x, y };

            if (sev === 'info' || sev === 'investigate') {
                groups.low.push(point);
            } else if (sev === 'alert') {
                groups.high.push(point);
            } else if (sev === 'critical') {
                groups.critical.push(point);
            } else {
                groups.medium.push(point);
            }
        }
    }

    const config = {
        type: 'scatter',
        data: {
            datasets: [
                {
                    label: 'Low',
                    data: groups.low,
                    backgroundColor: COLOURS.low.bg.replace('0.3', '0.7'),
                    borderColor: COLOURS.low.border,
                    pointRadius: 5,
                },
                {
                    label: 'Medium',
                    data: groups.medium,
                    backgroundColor: COLOURS.medium.bg.replace('0.3', '0.7'),
                    borderColor: COLOURS.medium.border,
                    pointRadius: 5,
                },
                {
                    label: 'High',
                    data: groups.high,
                    backgroundColor: COLOURS.high.bg.replace('0.3', '0.7'),
                    borderColor: COLOURS.high.border,
                    pointRadius: 5,
                },
                {
                    label: 'Critical',
                    data: groups.critical,
                    backgroundColor: COLOURS.critical.bg.replace('0.3', '0.7'),
                    borderColor: COLOURS.critical.border,
                    pointRadius: 5,
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'bottom', labels: { boxWidth: 12, padding: 16 } },
            },
            scales: {
                x: {
                    type: 'linear',
                    ticks: {
                        callback(val) {
                            return new Date(val).toLocaleTimeString([], {
                                hour: '2-digit', minute: '2-digit',
                            });
                        },
                    },
                    grid: { display: false },
                },
                y: {
                    beginAtZero: true,
                    max: 5,
                    ticks: {
                        stepSize: 1,
                        callback(val) {
                            return ['', 'Low', 'Medium', 'High', 'Critical'][val] || '';
                        },
                    },
                },
            },
        },
    };

    return new Chart(ctx, config);
}

function buildCategoryChart(ctx, timelineData) {
    const counts = {};
    if (timelineData && timelineData.entries) {
        for (const entry of timelineData.entries) {
            const cat = entry.category || 'unknown';
            counts[cat] = (counts[cat] || 0) + 1;
        }
    }

    // Sort by count descending
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    const labels = sorted.map(([k]) => k.charAt(0).toUpperCase() + k.slice(1));
    const values = sorted.map(([, v]) => v);
    const bgColours = sorted.map(([k]) => {
        const c = CATEGORY_COLOURS[k.toLowerCase()];
        return c ? c.bg : 'rgba(107, 114, 128, 0.7)';
    });
    const borderColours = sorted.map(([k]) => {
        const c = CATEGORY_COLOURS[k.toLowerCase()];
        return c ? c.border : 'rgba(107, 114, 128, 1)';
    });

    const config = {
        type: 'bar',
        data: {
            labels,
            datasets: [{
                label: 'Events',
                data: values,
                backgroundColor: bgColours,
                borderColor: borderColours,
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
                x: { beginAtZero: true, ticks: { stepSize: 1 } },
                y: { grid: { display: false } },
            },
        },
    };

    return new Chart(ctx, config);
}

// ── Update helpers ──────────────────────────────────────────────────

function updateTrendChart(chart, data) {
    const labels = data.points.map(p => {
        const d = new Date(p.timestamp);
        return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    });
    chart.data.labels = labels;
    chart.data.datasets[0].data = data.points.map(p => p.low);
    chart.data.datasets[1].data = data.points.map(p => p.medium);
    chart.data.datasets[2].data = data.points.map(p => p.high);
    chart.data.datasets[3].data = data.points.map(p => p.critical);
    chart.update('none');
}

function updateSeverityChart(chart, data) {
    const counts = { low: 0, medium: 0, high: 0, critical: 0 };
    for (const p of data.points) {
        counts.low += p.low;
        counts.medium += p.medium;
        counts.high += p.high;
        counts.critical += p.critical;
    }
    chart.data.datasets[0].data = [counts.low, counts.medium, counts.high, counts.critical];
    chart.update('none');
}

function updateTimelineScatter(chart, timelineData) {
    const severityY = { info: 1, investigate: 2, alert: 3, critical: 4 };
    const groups = { low: [], medium: [], high: [], critical: [] };

    if (timelineData && timelineData.entries) {
        for (const entry of timelineData.entries) {
            const sev = entry.severity.toLowerCase();
            const y = severityY[sev] || 1;
            const x = new Date(entry.timestamp).getTime();
            if (sev === 'info' || sev === 'investigate') groups.low.push({ x, y });
            else if (sev === 'alert') groups.high.push({ x, y });
            else if (sev === 'critical') groups.critical.push({ x, y });
            else groups.medium.push({ x, y });
        }
    }

    chart.data.datasets[0].data = groups.low;
    chart.data.datasets[1].data = groups.medium;
    chart.data.datasets[2].data = groups.high;
    chart.data.datasets[3].data = groups.critical;
    chart.update('none');
}

function updateCategoryChart(chart, timelineData) {
    const counts = {};
    if (timelineData && timelineData.entries) {
        for (const entry of timelineData.entries) {
            const cat = entry.category || 'unknown';
            counts[cat] = (counts[cat] || 0) + 1;
        }
    }
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    chart.data.labels = sorted.map(([k]) => k.charAt(0).toUpperCase() + k.slice(1));
    chart.data.datasets[0].data = sorted.map(([, v]) => v);
    chart.data.datasets[0].backgroundColor = sorted.map(([k]) => {
        const c = CATEGORY_COLOURS[k.toLowerCase()];
        return c ? c.bg : 'rgba(107, 114, 128, 0.7)';
    });
    chart.data.datasets[0].borderColor = sorted.map(([k]) => {
        const c = CATEGORY_COLOURS[k.toLowerCase()];
        return c ? c.border : 'rgba(107, 114, 128, 1)';
    });
    chart.update('none');
}

function updateSummaryStats(chartData) {
    const elTotal = document.getElementById('stat-total');
    const elCritical = document.getElementById('stat-critical');
    const elHigh = document.getElementById('stat-high');
    const elMedium = document.getElementById('stat-medium');
    if (!elTotal) return; // DOM not present (tab switched away)

    let total = 0, critical = 0, high = 0, medium = 0;
    if (chartData && chartData.points) {
        for (const p of chartData.points) {
            total += p.total;
            critical += p.critical;
            high += p.high;
            medium += p.medium;
        }
    }
    elTotal.textContent = total;
    if (elCritical) elCritical.textContent = critical;
    if (elHigh) elHigh.textContent = high;
    if (elMedium) elMedium.textContent = medium;
}

function updateLastRefresh() {
    const el = document.getElementById('last-update');
    if (el) {
        const now = new Date();
        el.textContent = `Updated ${now.toLocaleTimeString()}`;
    }
}

// ── WebSocket ───────────────────────────────────────────────────────

function connectWebSocket() {
    // Subscribe to relevant message types via shared handler
    _wsUnsubs.push(wsHandler.subscribe('event', handleWebSocketMessage));
    _wsUnsubs.push(wsHandler.subscribe('threat_detected', handleWebSocketMessage));
    _wsUnsubs.push(wsHandler.subscribe('security_level_changed', handleWebSocketMessage));
    _wsUnsubs.push(wsHandler.subscribe('alert_created', handleWebSocketMessage));

    // Track connection status
    _onWsConnected = () => setLiveStatus(true);
    _onWsDisconnected = () => setLiveStatus(false);
    window.addEventListener('ws-connected', _onWsConnected);
    window.addEventListener('ws-disconnected', _onWsDisconnected);

    // Connect if not already
    wsHandler.connect();
}

function handleWebSocketMessage(msg) {
    // Refresh charts on relevant events
    if (msg.type === 'event' || msg.type === 'threat_detected' ||
        msg.type === 'security_level_changed') {
        refreshAllCharts();
    }
}

function setLiveStatus(connected) {
    const badge = document.getElementById('live-badge');
    const dot = document.getElementById('live-dot');
    const text = document.getElementById('live-text');
    if (!badge) return;

    if (connected) {
        badge.className = 'live-badge connected';
        dot.className = 'live-dot connected';
        text.textContent = 'Live';
    } else {
        badge.className = 'live-badge simulated';
        dot.className = 'live-dot simulated';
        text.textContent = 'Simulated';
    }
}

// ── Refresh logic ───────────────────────────────────────────────────

async function refreshAllCharts() {
    const bucketHours = selectedHours <= 24 ? 1 : selectedHours <= 48 ? 2 : 6;

    const [chartData, timelineData] = await Promise.all([
        fetchChartData(selectedHours, bucketHours),
        fetchTimeline(500),
    ]);

    if (chartData) {
        if (trendChart) updateTrendChart(trendChart, chartData);
        if (severityChart) updateSeverityChart(severityChart, chartData);
        updateSummaryStats(chartData);
    }

    if (timelineData) {
        if (timelineChart) updateTimelineScatter(timelineChart, timelineData);
        if (categoryChart) updateCategoryChart(categoryChart, timelineData);
    }

    updateLastRefresh();
}

// ── Time range selector ─────────────────────────────────────────────

function setupTimeRangeSelector() {
    const container = document.getElementById('time-range-selector');
    if (!container) return;

    container.addEventListener('click', (e) => {
        const btn = e.target.closest('.time-btn');
        if (!btn) return;

        // Update active button
        container.querySelectorAll('.time-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        // Update selected hours and refresh
        selectedHours = parseInt(btn.dataset.hours, 10) || 24;

        // Update subtitle
        const subtitle = document.getElementById('trend-subtitle');
        if (subtitle) {
            subtitle.textContent = selectedHours <= 24 ? 'Hourly' : selectedHours <= 48 ? '2-Hour Buckets' : '6-Hour Buckets';
        }

        refreshAllCharts();
    });
}

// ── Cleanup ─────────────────────────────────────────────────────────

function destroy() {
    // Clear auto-refresh
    if (refreshInterval) { clearInterval(refreshInterval); refreshInterval = null; }

    // Destroy Chart.js instances
    if (trendChart) { trendChart.destroy(); trendChart = null; }
    if (severityChart) { severityChart.destroy(); severityChart = null; }
    if (timelineChart) { timelineChart.destroy(); timelineChart = null; }
    if (categoryChart) { categoryChart.destroy(); categoryChart = null; }

    // Unsubscribe WebSocket
    _wsUnsubs.forEach(fn => { if (typeof fn === 'function') fn(); });
    _wsUnsubs = [];

    // Remove event listeners
    if (_onWsConnected) { window.removeEventListener('ws-connected', _onWsConnected); _onWsConnected = null; }
    if (_onWsDisconnected) { window.removeEventListener('ws-disconnected', _onWsDisconnected); _onWsDisconnected = null; }
}

// ── Initialization ──────────────────────────────────────────────────

async function init() {
    // Clean up any previous state (idempotent re-init)
    destroy();

    // Initialize API client (fetches session token)
    try {
        await apiClient.initialize();
    } catch (err) {
        console.error('Failed to initialize API client:', err);
    }

    // Get canvas contexts
    const trendCtx = document.getElementById('threat-trend-chart');
    const severityCtx = document.getElementById('severity-distribution-chart');
    const timelineCtx = document.getElementById('timeline-scatter-chart');
    const categoryCtx = document.getElementById('category-breakdown-chart');

    // Fetch initial data
    const bucketHours = 1;
    const [chartData, timelineData] = await Promise.all([
        fetchChartData(selectedHours, bucketHours),
        fetchTimeline(500),
    ]);

    // Build charts
    if (trendCtx) {
        trendChart = buildTrendChart(
            trendCtx.getContext('2d'),
            chartData || { points: [] }
        );
    }

    if (severityCtx) {
        severityChart = buildSeverityChart(
            severityCtx.getContext('2d'),
            chartData || { points: [] }
        );
    }

    if (timelineCtx) {
        timelineChart = buildTimelineScatterChart(
            timelineCtx.getContext('2d'),
            timelineData || { entries: [] }
        );
    }

    if (categoryCtx) {
        categoryChart = buildCategoryChart(
            categoryCtx.getContext('2d'),
            timelineData || { entries: [] }
        );
    }

    // Update summary stats
    if (chartData) updateSummaryStats(chartData);
    updateLastRefresh();

    // Setup controls
    setupTimeRangeSelector();

    // Connect WebSocket
    connectWebSocket();

    // Start auto-refresh (every 30 seconds)
    refreshInterval = setInterval(refreshAllCharts, 30000);
}

// Start when DOM is ready
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
    CATEGORY_COLOURS,
    fetchChartData,
    fetchTimeline,
    fetchThreatScore,
    buildTrendChart,
    buildSeverityChart,
    buildTimelineScatterChart,
    buildCategoryChart,
    updateTrendChart,
    updateSeverityChart,
    updateTimelineScatter,
    updateCategoryChart,
    updateSummaryStats,
    handleWebSocketMessage,
    setLiveStatus,
    refreshAllCharts,
    selectedHours,
};
