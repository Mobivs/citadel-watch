// ── Citadel Archer — Ops Center Module ────────────────────────────────────────
// ES module loaded by tab-loader.js when the "Ops Center" tab is activated.
//
// Architecture:
//   • All state (events, metrics, attackers, WS connection) is MODULE-LEVEL —
//     it persists across tab switches. No data is lost when the user navigates
//     away and returns.
//   • DOM references (canvas, ctx) are RE-BOUND in every init() call, because
//     tab-loader.js replaces #tab-panel-dynamic innerHTML on each activation.
//   • The WebSocket connection and metrics poll interval stay alive across
//     tab switches — no reconnect overhead on re-activation.
//   • init()    — called by tab-loader when this tab becomes active
//   • destroy() — called by tab-loader when the user switches away

import { apiClient } from './utils/api-client.js';

// ── Connection config  ◀ WIRE UP ──────────────────────────────────────────────
// Relative to whatever host the app is served on (localhost or Tailscale IP).
// When you add the FastAPI endpoints, these paths are all you need to change.
const _wsProto = location.protocol === 'https:' ? 'wss:' : 'ws:';
const WS_URL   = `${_wsProto}//${location.host}/ws/ops`;   // WebSocket push stream
const API_BASE = '/api/ops';                                // REST base

// ── Module state (persists across tab switches) ───────────────────────────────
const stats        = { total: 0, today: 0, hr: 0 };
const events       = [];           // event log entries (newest first)
const attackers    = [];           // { id, nodeId, country, ip, svc, sev, isCrit, born }
let   _eid         = 0;            // monotone event ID counter
let   _atkId       = 0;            // monotone attacker node ID counter
// Map<eid → alarmTileId> — keeps track of which alarm tile each CRIT owns.
// Using a Map (not Set) so ackCrit() clears exactly the right tile even
// when multiple different CRITs reference different alarms simultaneously.
const unackedCrits = new Map();
// nodeStatus tracks agent reachability — drives future ♥ color progression.
// Populated dynamically from the topology endpoint; keyed by agent_id.
const nodeStatus   = {};
let   t            = 0;            // frame counter — never reset, keeps animations smooth

// Alarm tile → human-readable service label (UI layer only, not sim data)
const ALARM_SVC = {
  'al-ssh':   'SSH :22',
  'al-proc':  'PROCESS',
  'al-file':  'FILE INTEG',
  'al-res':   'RESOURCE',
  'al-ts':    'TS VPN',
  'al-patch': 'PACKAGES',
};

// Live metrics — keyed by agent_id, auto-created on first receive.
// Canvas bars redraw from this object on every animation frame.
const nodeMetrics = {};

// Network topology — populated dynamically from GET /api/ops/topology.
// Refreshed on every tab activation so newly-enrolled agents appear
// without a page reload.
let TOPO = { nodes: [] };

// ── Security: XSS escape + input validation ───────────────────────────────────
// All backend-supplied strings must pass through esc() before innerHTML injection.
function esc(s) {
  const d = document.createElement('div');
  d.appendChild(document.createTextNode(String(s ?? '')));
  return d.innerHTML;
}
// Only accept known-good values for fields used as CSS class names / DOM IDs
const VALID_SEVS   = new Set(['INFO', 'WARN', 'HIGH', 'CRIT']);
const VALID_ALARMS = new Set(['al-ssh', 'al-file', 'al-patch', 'al-proc', 'al-res', 'al-ts']);
const VALID_STATUS = new Set(['ok', 'warn', 'critical', 'offline']);

function now() { return new Date().toLocaleTimeString('en', { hour12: false }); }

// ═══════════════════════════════════════════════════════════════════════════════
// DATA INGESTION — these are the ONLY functions that write to state.
// Call them from your WebSocket handler or REST response.
// ═══════════════════════════════════════════════════════════════════════════════

// ─── ingestEvent  ◀ WIRE UP ───────────────────────────────────────────────────
// Call whenever a security event arrives from the backend.
// Drives: event log, alarm tiles, CRIT pinning, attacker nodes, counters.
//
// Expected shape (WS push or REST array item):
// {
//   sev:      'INFO'|'WARN'|'HIGH'|'CRIT',   // required
//   nodeId:   '<agent_id>',                   // required — from topology
//   msg:      'Human-readable description',   // required
//   alarm:    'al-ssh'|'al-file'|'al-patch'| // required — drives alarm tile
//             'al-proc'|'al-res'|'al-ts',
//   isAttack: true|false,                     // required — spawns attacker node
//   isCrit:   true|false,                     // required if isAttack
//   country:  'CHN'|'RUS'|...,               // required if isAttack
//   ip:       '1.2.3.4',                      // required if isAttack
//   svc:      'SSH :22'|...,                  // optional — falls back to ALARM_SVC
//   time:     'HH:MM:SS',                     // optional — defaults to client clock
// }
//
// FastAPI example (citadel-archer/src/routes/ops.py):
//   @router.websocket('/ws/ops')
//   async def ops_ws(ws: WebSocket):
//       await ws.accept()
//       async for event in event_stream():
//           await ws.send_json({ "type": "event", **event })
//
function ingestEvent(e) {
  if (!e || !e.sev || !e.nodeId || !e.msg) {
    console.warn('[ops-center] Dropped event — missing required fields', e);
    return;
  }
  const sev   = VALID_SEVS.has(e.sev)     ? e.sev   : 'INFO';
  const alarm = VALID_ALARMS.has(e.alarm) ? e.alarm : null;
  const topoNode  = TOPO.nodes.find(n => n.id === e.nodeId);
  const nodeLabel = topoNode ? topoNode.label : String(e.nodeId).slice(0, 12);

  const entry = { eid: ++_eid, time: e.time || now(), sev, node: nodeLabel, msg: String(e.msg), alarm };
  events.unshift(entry);
  if (events.length > 40) events.pop();

  // CRIT events stay pinned in the log until the operator ACKs them.
  // Map stores eid → alarmId so ackCrit() can clear the exact tile.
  if (sev === 'CRIT') unackedCrits.set(entry.eid, alarm);

  // Alarm tile — CRIT stays lit (class 'hi') until ACK; others auto-clear after 4s
  if (alarm) {
    const tile = document.getElementById(alarm);
    if (tile) {
      tile.classList.add(sev === 'CRIT' ? 'hi' : 'on');
      if (sev !== 'CRIT') setTimeout(() => tile.classList.remove('on'), 4000);
    }
  }

  // Attack events spawn a labelled attacker node in the topology canvas
  if (e.isAttack) {
    attackers.push({
      id:      ++_atkId,
      nodeId:  e.nodeId,
      country: e.country || '???',
      ip:      e.ip      || '0.0.0.0',
      svc:     e.svc     || ALARM_SVC[alarm] || 'NET',
      sev,
      isCrit:  e.isCrit  || false,
      born:    performance.now(), // wall-clock ms — frame-rate independent
    });
    if (attackers.length > 12) attackers.shift();
    stats.total++; stats.today++; stats.hr++;
    updateCounters();
  }

  renderEventLog();
}

// ─── ingestMetrics  ◀ WIRE UP ─────────────────────────────────────────────────
// Call whenever fresh resource metrics arrive for a node.
// Canvas bars redraw automatically on the next animation frame.
//
// Expected shape: { nodeId:'<agent_id>', cpu:0-100, mem:0-100, dsk:0-100, patches:N }
// nodeId must match an agent_id returned by GET /api/ops/topology.
//
function ingestMetrics(nodeId, m) {
  if (!nodeMetrics[nodeId]) nodeMetrics[nodeId] = { cpu: 0, mem: 0, dsk: 0, patches: 0 };
  // Clamp to 0-100 and reject non-numeric values — guards against NaN in canvas bars
  const pct = v => { const n = Number(v); return Number.isFinite(n) ? Math.max(0, Math.min(100, n)) : undefined; };
  const cnt = v => { const n = Number(v); return Number.isFinite(n) ? Math.max(0, Math.round(n))   : undefined; };
  const cpu = pct(m.cpu), mem = pct(m.mem), dsk = pct(m.dsk), patches = cnt(m.patches);
  if (cpu     !== undefined) nodeMetrics[nodeId].cpu     = cpu;
  if (mem     !== undefined) nodeMetrics[nodeId].mem     = mem;
  if (dsk     !== undefined) nodeMetrics[nodeId].dsk     = dsk;
  if (patches !== undefined) nodeMetrics[nodeId].patches = patches;
}

// ─── ingestNodeStatus  ◀ WIRE UP ──────────────────────────────────────────────
// Call when a node's reachability/health status changes.
// Status drives the ♥ heartbeat color progression (ok→warn→critical→offline).
//
// Expected shape: { nodeId:'<agent_id>', status:'ok'|'warn'|'critical'|'offline' }
//
// Backend sources:
//   • Tailscale API: GET /api/v1/status → .Peer[ip].Online
//   • Agent ping / SSH keepalive timeout
//   • Guardian AI health check escalation
//
function ingestNodeStatus(nodeId, status) {
  if (!VALID_STATUS.has(status)) {
    console.warn('[ops-center] Unknown node status', status, 'for', nodeId);
    return;
  }
  nodeStatus[nodeId] = status;
  // TODO: when ♥ color progression is implemented, trigger repaint here.
  // Color map: ok=#00CC66, warn=#FF9900, critical=#FF3333, offline=#444
}

// Internal — dashboard status messages (not a wire-up point)
function setLog(msg) {
  events.unshift({ eid: ++_eid, time: now(), sev: 'INFO', node: 'SYSTEM', msg });
  renderEventLog();
}

// ═══════════════════════════════════════════════════════════════════════════════
// CANVAS RENDERING
// ═══════════════════════════════════════════════════════════════════════════════

// Canvas state — re-bound in every init() since tab-loader replaces the DOM
let canvas = null, ctx = null, W = 0, H = 0;

// Fixed world coordinate system — node spacing never changes with screen size
const WORLD_W = 620, WORLD_H = 450;

// Pan / zoom state (persists across tab switches — user keeps their view)
let panX = 0, panY = 0, zoom = 1;
let isDragging = false, dragSX = 0, dragSY = 0, dragPX = 0, dragPY = 0;
let tgtPanX = null, tgtPanY = null, tgtZoom = null;
let focusedNode = null;

function fitView() {
  const pad = 24;
  zoom = Math.min((W - pad * 2) / WORLD_W, (H - pad * 2) / WORLD_H);
  panX = (W - WORLD_W * zoom) / 2;
  panY = (H - WORLD_H * zoom) / 2;
  tgtZoom = tgtPanX = tgtPanY = null;
  focusedNode = null;
}

function animateTo(tz, tx, ty) { tgtZoom = tz; tgtPanX = tx; tgtPanY = ty; }

function fitViewAnimated() {
  const pad = 24;
  const tz = Math.min((W - pad * 2) / WORLD_W, (H - pad * 2) / WORLD_H);
  animateTo(tz, (W - WORLD_W * tz) / 2, (H - WORLD_H * tz) / 2);
  focusedNode = null;
}

// ─── Canvas resize ────────────────────────────────────────────────────────────
// Guards against zero-dimension containers (e.g. embedded before layout completes)
function resizeCanvas() {
  if (!canvas) return;
  const el = canvas.parentElement;
  if (!el) return;
  const w = el.clientWidth, h = el.clientHeight;
  if (w < 1 || h < 1) return; // not yet laid out — requestAnimationFrame retry handles this
  W = canvas.width  = w;
  H = canvas.height = h;
  fitView();
}

// ─── Layout sync ──────────────────────────────────────────────────────────────
// Sets #tab-panel-dynamic to an explicit pixel height so #oc-root { height:100% }
// resolves correctly. Also clips the page footer that would otherwise show below.
function syncLayout() {
  const appMain  = document.querySelector('.app-main');
  const dynPanel = document.getElementById('tab-panel-dynamic');
  if (!appMain || !dynPanel) return;
  appMain.style.overflow  = 'hidden';
  dynPanel.style.height   = appMain.clientHeight + 'px';
  dynPanel.style.overflow = 'hidden';
}

// ─── Drawing helpers ──────────────────────────────────────────────────────────
function roundRect(x, y, w, h, r) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.lineTo(x + w - r, y);
  ctx.quadraticCurveTo(x + w, y, x + w, y + r);
  ctx.lineTo(x + w, y + h - r);
  ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
  ctx.lineTo(x + r, y + h);
  ctx.quadraticCurveTo(x, y + h, x, y + h - r);
  ctx.lineTo(x, y + r);
  ctx.quadraticCurveTo(x, y, x + r, y);
  ctx.closePath();
}

// ─── Topology draw ────────────────────────────────────────────────────────────
function drawTopology() {
  // Tailscale mesh links between adjacent nodes — drawn under nodes
  if (TOPO.nodes.length === 0) {
    ctx.fillStyle = '#6B7280'; ctx.font = '11px Courier New'; ctx.textAlign = 'center';
    ctx.fillText('No enrolled agents — add a Shield agent in the Assets tab', WORLD_W / 2, WORLD_H / 2);
    return;
  }
  for (let ci = 0; ci < TOPO.nodes.length - 1; ci++) {
    const a = TOPO.nodes[ci], b = TOPO.nodes[ci + 1];
    const ax = a.col * WORLD_W, ay = a.row * WORLD_H;
    const bx = b.col * WORLD_W, by = b.row * WORLD_H;
    ctx.strokeStyle = '#A855F7'; ctx.lineWidth = 1;
    ctx.setLineDash([4, 5]); ctx.globalAlpha = 0.35;
    ctx.beginPath(); ctx.moveTo(ax, ay); ctx.lineTo(bx, by); ctx.stroke();
    ctx.setLineDash([]); ctx.globalAlpha = 1;
    ctx.fillStyle = '#A855F7'; ctx.font = '7px Courier New';
    ctx.textAlign = 'center'; ctx.globalAlpha = 0.7;
    ctx.fillText('TS HEARTBEAT', (ax + bx) / 2, (ay + by) / 2 - 6);
    ctx.globalAlpha = 1;
  }

  // Main topology nodes
  const boxW = 128, boxH = 98;
  TOPO.nodes.forEach((node, i) => {
    const nx = node.col * WORLD_W, ny = node.row * WORLD_H;
    const bx = nx - boxW / 2, by = ny - boxH / 2;

    // Glow + fill
    ctx.shadowBlur = 20; ctx.shadowColor = node.color + '33';
    ctx.fillStyle = '#0D1230';
    roundRect(bx, by, boxW, boxH, 4); ctx.fill();
    ctx.shadowBlur = 0;

    // Border
    ctx.strokeStyle = node.color; ctx.lineWidth = 1.3; ctx.globalAlpha = 0.7;
    roundRect(bx, by, boxW, boxH, 4); ctx.stroke();
    ctx.globalAlpha = 1;

    // Heart icon — sharp cubic heartbeat pulse, each node offset by 2.1 rad
    const beat = 0.3 + 0.7 * Math.pow(Math.max(0, Math.sin(t * 0.07 + i * 2.1)), 3);
    ctx.fillStyle = node.color; ctx.font = 'bold 13px serif'; ctx.textAlign = 'left';
    ctx.globalAlpha = beat;
    ctx.shadowBlur = beat > 0.75 ? 14 : 3; ctx.shadowColor = node.color;
    ctx.fillText('\u2665', bx + 5, by + 17); // ♥
    ctx.shadowBlur = 0; ctx.globalAlpha = 1;

    // Node labels
    ctx.fillStyle = node.color; ctx.font = 'bold 11px Courier New'; ctx.textAlign = 'center';
    ctx.fillText(node.label, nx, by + 20);
    ctx.fillStyle = '#9CA3AF'; ctx.font = '8px Courier New';
    ctx.fillText(node.sub, nx, by + 31);
    ctx.fillStyle = '#6B7280'; ctx.fillText('TS: ' + node.ts, nx, by + 41);
    if (node.os) {
      ctx.fillStyle = '#9CA3AF'; ctx.font = '7px Courier New';
      ctx.fillText(node.os, nx, by + 50);
    }

    // Separator line
    ctx.strokeStyle = node.color; ctx.lineWidth = 0.4; ctx.globalAlpha = 0.18;
    ctx.beginPath();
    ctx.moveTo(bx + 6, by + 55); ctx.lineTo(bx + boxW - 6, by + 55);
    ctx.stroke(); ctx.globalAlpha = 1;

    // Metric bars
    const m = nodeMetrics[node.id] || { cpu: 0, mem: 0, dsk: 0, patches: 0 };
    const blx = bx + 7, barX = bx + 30, bbarW = boxW - 40, bbarH = 5;
    const metRows = [
      [m.cpu, '#00D9FF', 'CPU', by + 63],
      [m.mem, '#00CC66', 'MEM', by + 74],
      [m.dsk, '#FF9900', 'DSK', by + 85],
    ];

    metRows.forEach(([val, baseCol, lbl, rowY]) => {
      const pct = val / 100;
      const col = val > 80 ? '#FF3333' : val > 60 ? '#FF9900' : baseCol;
      ctx.fillStyle = '#6B7280'; ctx.font = '6px Courier New'; ctx.textAlign = 'left';
      ctx.fillText(lbl, blx, rowY + 4);
      ctx.fillStyle = '#040d18';
      roundRect(barX, rowY, bbarW, bbarH, 1); ctx.fill();
      if (pct > 0) {
        ctx.fillStyle = col;
        roundRect(barX, rowY, Math.max(2, bbarW * pct), bbarH, 1); ctx.fill();
      }
      ctx.fillStyle = col; ctx.font = '6px Courier New'; ctx.textAlign = 'right';
      ctx.fillText(Math.round(val) + '%', bx + boxW - 4, rowY + 4);
    });

    // Footer status line inside node box
    if (m.patches > 0) {
      ctx.fillStyle = '#FF9900'; ctx.font = '6px Courier New'; ctx.textAlign = 'center';
      ctx.globalAlpha = 0.85;
      ctx.fillText('\u26A0 ' + m.patches + ' PATCHES PENDING', nx, by + 95); // ⚠
      ctx.globalAlpha = 1;
    }
  });

  // Service endpoint chips below each main node
  const chipW = 36, chipH = 16, chipGap = 3, chipCols = 3;
  TOPO.nodes.forEach(node => {
    if (!node.services || node.services.length === 0) return;
    const nx   = node.col * WORLD_W;
    const nBot = node.row * WORLD_H + boxH / 2;
    const totalCW = chipCols * chipW + (chipCols - 1) * chipGap;
    const csX = nx - totalCW / 2, csY = nBot + 14;

    // Short connector from box bottom to chip area label
    ctx.strokeStyle = node.color; ctx.lineWidth = 0.5; ctx.globalAlpha = 0.2;
    ctx.setLineDash([2, 3]);
    ctx.beginPath(); ctx.moveTo(nx, nBot); ctx.lineTo(nx, nBot + 10); ctx.stroke();
    ctx.setLineDash([]); ctx.globalAlpha = 1;

    ctx.fillStyle = node.color; ctx.font = '6px Courier New'; ctx.textAlign = 'center';
    ctx.globalAlpha = 0.45;
    ctx.fillText('EXPOSED', nx, nBot + 10);
    ctx.globalAlpha = 1;

    node.services.forEach((svc, si) => {
      const col = si % chipCols, row = Math.floor(si / chipCols);
      const cx = csX + col * (chipW + chipGap), cy = csY + row * (chipH + chipGap);

      ctx.fillStyle = '#080C20';
      roundRect(cx, cy, chipW, chipH, 2); ctx.fill();
      ctx.strokeStyle = svc.color; ctx.lineWidth = 0.7; ctx.globalAlpha = 0.45;
      roundRect(cx, cy, chipW, chipH, 2); ctx.stroke(); ctx.globalAlpha = 1;

      ctx.fillStyle = svc.color; ctx.font = 'bold 6px Courier New'; ctx.textAlign = 'left';
      ctx.globalAlpha = 0.9;
      ctx.fillText(svc.label, cx + 3, cy + 7); ctx.globalAlpha = 1;

      ctx.fillStyle = '#6B7280'; ctx.font = '6px Courier New'; ctx.textAlign = 'right';
      ctx.fillText(svc.port, cx + chipW - 2, cy + 14);
    });
  });

  // Attacker nodes — wall-clock timing (frame-rate independent)
  const _now = performance.now();
  // Prune entries older than 11 000 ms from the front of the array
  while (attackers.length > 0 && _now - attackers[0].born > 11000) attackers.shift();

  const aW = 90, aH = 34;
  const atkByNode = {};
  attackers.forEach(a => { (atkByNode[a.nodeId] = atkByNode[a.nodeId] || []).push(a); });

  Object.entries(atkByNode).forEach(([nodeId, atks]) => {
    const tnode = TOPO.nodes.find(n => n.id === nodeId);
    if (!tnode) return;
    const tx       = tnode.col * WORLD_W;
    const nodeTopY = tnode.row * WORLD_H - 98 / 2;
    const visible  = atks.slice(-2); // at most 2 per target node

    visible.forEach((atk, si) => {
      const age     = _now - atk.born;
      const fadeIn  = Math.min(1, age / 333);        // 0.3s fade-in
      const fadeOut = age > 9333 ? Math.max(0, 1 - (age - 9333) / 1333) : 1; // 1.3s fade-out
      const alpha   = fadeIn * fadeOut;
      if (alpha <= 0) return;

      const ax  = tx - aW / 2, ay = 10 + si * (aH + 7);
      const col = atk.isCrit ? '#FF3333' : atk.sev === 'HIGH' ? '#FF9900' : '#e6b800';

      // Dashed line from attacker box to node top
      ctx.strokeStyle = col; ctx.lineWidth = 0.8; ctx.setLineDash([3, 4]);
      ctx.globalAlpha = alpha * 0.4;
      ctx.beginPath(); ctx.moveTo(tx, ay + aH); ctx.lineTo(tx, nodeTopY); ctx.stroke();
      ctx.setLineDash([]);

      // Box
      ctx.globalAlpha = alpha;
      ctx.fillStyle = '#070B1C'; roundRect(ax, ay, aW, aH, 3); ctx.fill();
      ctx.strokeStyle = col; ctx.lineWidth = 0.9;
      roundRect(ax, ay, aW, aH, 3); ctx.stroke();

      // Country label
      ctx.fillStyle = col; ctx.font = 'bold 7px Courier New'; ctx.textAlign = 'left';
      ctx.globalAlpha = alpha;
      ctx.fillText('\u25B2 ' + atk.country, ax + 5, ay + 11); // ▲

      // Service targeted
      ctx.font = '6px Courier New'; ctx.globalAlpha = alpha * 0.9;
      ctx.fillText('\u2192 ' + atk.svc, ax + 5, ay + 22); // →

      // IP address
      ctx.fillStyle = '#9CA3AF'; ctx.textAlign = 'right'; ctx.globalAlpha = alpha * 0.7;
      ctx.fillText(atk.ip, ax + aW - 4, ay + 32);
      ctx.globalAlpha = 1;
    });
  });
}

// ─── HUD overlay ──────────────────────────────────────────────────────────────
function drawHUD() {
  const pad = 8, w = 78, h = 46;
  const x = W - w - pad, y = H - h - pad;
  ctx.fillStyle = '#080C1E'; ctx.strokeStyle = '#0af3'; ctx.lineWidth = 1;
  roundRect(x, y, w, h, 3); ctx.fill();
  roundRect(x, y, w, h, 3); ctx.stroke();
  ctx.fillStyle = '#9CA3AF'; ctx.font = '7px Courier New'; ctx.textAlign = 'center';
  const cx = x + w / 2;
  ctx.fillText('ZOOM  ' + Math.round(zoom * 100) + '%', cx, y + 11);
  ctx.fillStyle = '#6B7280';
  ctx.fillText('\u2295 scroll to zoom',  cx, y + 23);  // ⊕
  ctx.fillText('\u2725 drag to pan',     cx, y + 33);  // ✥
  ctx.fillText('\u21BA dbl-click reset', cx, y + 43);  // ↺

  if (focusedNode) {
    const node = TOPO.nodes.find(n => n.id === focusedNode);
    if (node) {
      const bw = 180, bh = 20, bx = W / 2 - bw / 2, by = H - bh - 8;
      ctx.fillStyle = '#080C1E'; roundRect(bx, by, bw, bh, 3); ctx.fill();
      ctx.strokeStyle = node.color + '88'; ctx.lineWidth = 1;
      roundRect(bx, by, bw, bh, 3); ctx.stroke();
      ctx.fillStyle = node.color; ctx.font = '7px Courier New'; ctx.textAlign = 'center';
      ctx.fillText('\u25C8 ' + node.label + ' \u2014 click node or empty space to reset', W / 2, by + 13);
    }
  }
}

// ─── Main render loop ─────────────────────────────────────────────────────────
let _raf = null;

function loop() {
  // Skip frame if dimensions not yet known (embedded container not laid out yet)
  if (!W || !H || !canvas || !ctx) { _raf = requestAnimationFrame(loop); t++; return; }

  // Smooth pan/zoom animation
  if (tgtZoom !== null) {
    const s = 0.13;
    panX += (tgtPanX - panX) * s;
    panY += (tgtPanY - panY) * s;
    zoom += (tgtZoom - zoom) * s;
    if (Math.abs(tgtZoom - zoom) < 0.002 &&
        Math.abs(tgtPanX - panX) < 0.5  &&
        Math.abs(tgtPanY - panY) < 0.5) {
      zoom = tgtZoom; panX = tgtPanX; panY = tgtPanY;
      tgtZoom = tgtPanX = tgtPanY = null;
    }
  }

  ctx.fillStyle = '#0A0E27';
  ctx.fillRect(0, 0, W, H);
  ctx.save();
  ctx.translate(panX, panY);
  ctx.scale(zoom, zoom);
  drawTopology();
  ctx.restore();
  drawHUD();
  t++;
  _raf = requestAnimationFrame(loop);
}

// ═══════════════════════════════════════════════════════════════════════════════
// UI UPDATES — null-guarded because the tab may be inactive when called
// ═══════════════════════════════════════════════════════════════════════════════

function updateCounters() {
  const total = document.getElementById('oc-c-total');
  if (!total) return; // tab not active
  total.textContent = stats.total;
  const today = document.getElementById('oc-c-today');
  if (today) today.textContent = stats.today;
  const hr = document.getElementById('oc-c-hr');
  if (hr) hr.textContent = stats.hr;
}

function renderEventLog() {
  const el = document.getElementById('oc-evt-scroll');
  if (!el) return; // tab not active — state updates silently, DOM rebuilt on re-init

  const pinnedHTML = events
    .filter(e => unackedCrits.has(e.eid))
    .map(e => `
    <div class="evt-row CRIT pinned">
      <button class="ack-btn" onclick="window.ackCrit(${e.eid})">&#9873; ACK</button>
      <span class="evt-time">${esc(e.time)}</span>
      <span class="evt-node"> [${esc(e.node)}]</span>
      <span class="sev CRIT">CRIT</span>
      <div class="evt-msg">${esc(e.msg)}</div>
    </div>`).join('');

  const streamHTML = events
    .filter(e => !unackedCrits.has(e.eid))
    .slice(0, 15)
    .map(e => `
    <div class="evt-row ${e.sev}">
      <span class="evt-time">${esc(e.time)}</span>
      <span class="evt-node"> [${esc(e.node)}]</span>
      <span class="sev ${e.sev}">${e.sev}</span>
      <div class="evt-msg">${esc(e.msg)}</div>
    </div>`).join('');

  el.innerHTML = pinnedHTML + streamHTML;
}

// Restores alarm tile 'hi' class after a tab switch re-creates the DOM
function restoreAlarmTiles() {
  document.querySelectorAll('#oc-alarms .alarm-tile').forEach(el => el.classList.remove('hi', 'on'));
  unackedCrits.forEach(alarm => {
    if (alarm) {
      const tile = document.getElementById(alarm);
      if (tile) tile.classList.add('hi');
    }
  });
}

// ACK a pinned CRIT — clears it from the log and clears its alarm tile
// if no other unacked CRIT still references the same alarm.
function ackCrit(eid) {
  const alarm = unackedCrits.get(eid);
  unackedCrits.delete(eid);
  if (alarm) {
    const stillActive = [...unackedCrits.values()].some(a => a === alarm);
    if (!stillActive) {
      const tile = document.getElementById(alarm);
      if (tile) tile.classList.remove('hi', 'on');
    }
  }
  renderEventLog();
}

// ═══════════════════════════════════════════════════════════════════════════════
// CANVAS EVENT LISTENERS
// Re-attached on each init() — safe because the canvas is a new element each time
// ═══════════════════════════════════════════════════════════════════════════════

function attachCanvasEvents() {
  if (!canvas) return;
  canvas.style.cursor = 'grab';

  canvas.addEventListener('wheel', e => {
    e.preventDefault();
    tgtZoom = tgtPanX = tgtPanY = null; focusedNode = null;
    const rect = canvas.getBoundingClientRect();
    const sx = canvas.width / rect.width, sy = canvas.height / rect.height;
    const mx = (e.clientX - rect.left) * sx, my = (e.clientY - rect.top) * sy;
    const factor = e.deltaY < 0 ? 1.12 : 1 / 1.12;
    const nz = Math.max(0.25, Math.min(4.0, zoom * factor));
    panX = mx - (mx - panX) * (nz / zoom);
    panY = my - (my - panY) * (nz / zoom);
    zoom = nz;
  }, { passive: false });

  canvas.addEventListener('mousedown', e => {
    tgtZoom = tgtPanX = tgtPanY = null;
    isDragging = true;
    dragSX = e.clientX; dragSY = e.clientY;
    dragPX = panX;      dragPY = panY;
    canvas.style.cursor = 'grabbing';
  });

  canvas.addEventListener('mousemove', e => {
    const rect = canvas.getBoundingClientRect();
    const sx = canvas.width / rect.width, sy = canvas.height / rect.height;
    if (isDragging) {
      panX = dragPX + (e.clientX - dragSX) * sx;
      panY = dragPY + (e.clientY - dragSY) * sy;
      return;
    }
    const mx = (e.clientX - rect.left) * sx, my = (e.clientY - rect.top) * sy;
    const wx = (mx - panX) / zoom, wy = (my - panY) / zoom;
    const bW = 128, bH = 98;
    const onNode = TOPO.nodes.some(n =>
      wx >= n.col * WORLD_W - bW / 2 && wx <= n.col * WORLD_W + bW / 2 &&
      wy >= n.row * WORLD_H - bH / 2 && wy <= n.row * WORLD_H + bH / 2
    );
    canvas.style.cursor = onNode ? 'pointer' : 'grab';
  });

  canvas.addEventListener('mouseup',    () => { isDragging = false; canvas.style.cursor = 'grab'; });
  canvas.addEventListener('mouseleave', () => { isDragging = false; canvas.style.cursor = 'grab'; });
  canvas.addEventListener('dblclick',   () => fitViewAnimated());

  canvas.addEventListener('click', e => {
    const dx = e.clientX - dragSX, dy = e.clientY - dragSY;
    if (dx * dx + dy * dy > 25) return; // was a drag, not a click
    const rect = canvas.getBoundingClientRect();
    const sx = canvas.width / rect.width, sy = canvas.height / rect.height;
    const mx = (e.clientX - rect.left) * sx, my = (e.clientY - rect.top) * sy;
    const wx = (mx - panX) / zoom, wy = (my - panY) / zoom;
    const bW = 128, bH = 98;
    const hit = TOPO.nodes.find(n =>
      wx >= n.col * WORLD_W - bW / 2 && wx <= n.col * WORLD_W + bW / 2 &&
      wy >= n.row * WORLD_H - bH / 2 && wy <= n.row * WORLD_H + bH / 2
    );
    if (hit && focusedNode !== hit.id) {
      focusedNode = hit.id;
      const nx = hit.col * WORLD_W, ny = hit.row * WORLD_H;
      const tz = Math.min(3.5, Math.min((W * 0.82) / bW, (H * 0.68) / (bH + 80)));
      animateTo(tz, W / 2 - nx * tz, H / 2 - ny * tz);
    } else {
      fitViewAnimated();
    }
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONNECTION  ◀ WIRE UP
// ═══════════════════════════════════════════════════════════════════════════════

let _ws = null;
let _wsDelay = 3000;    // backoff state — persists across tab switches
const _wsDelayMax = 60000;
let _metricsIntervalId = null;
let _initialized = false; // first-time flag — prevents duplicate WS + interval setup

// ─── WebSocket ────────────────────────────────────────────────────────────────
// WS message envelopes from FastAPI:
//   { "type": "event",       sev, nodeId, msg, alarm, isAttack, ... }
//   { "type": "metrics",     nodeId, cpu, mem, dsk, patches }
//   { "type": "node_status", nodeId, status }
//
function connect() {
  _ws = new WebSocket(WS_URL);

  _ws.onopen = () => {
    _wsDelay = 3000; // reset backoff on successful connect
    setLog('Connection established \u2014 live data active'); // —
  };

  _ws.onmessage = ({ data }) => {
    let msg;
    try { msg = JSON.parse(data); } catch {
      console.warn('[ops-center] Non-JSON WebSocket message', data); return;
    }
    switch (msg.type) {
      case 'event':       ingestEvent(msg);                       break;
      case 'metrics':     ingestMetrics(msg.nodeId, msg);         break;
      case 'node_status': ingestNodeStatus(msg.nodeId, msg.status); break;
      default: console.warn('[ops-center] Unknown WS message type', msg.type, msg);
    }
  };

  _ws.onclose = () => {
    _ws = null;
    const jitter = Math.random() * 1000;
    const delay  = Math.min(_wsDelay + jitter, _wsDelayMax);
    setLog(`Connection lost \u2014 reconnecting in ${Math.round(delay / 1000)}s\u2026`); // — …
    setTimeout(connect, delay);
    _wsDelay = Math.min(_wsDelay * 2, _wsDelayMax); // exponential backoff
  };

  _ws.onerror = () => { if (_ws) _ws.close(); }; // triggers onclose → backoff
}

// ─── Topology fetch ───────────────────────────────────────────────────────────
// Fetches enrolled agents from the backend and rebuilds TOPO.nodes.
// Called on every tab activation so new agents appear without a page reload.
async function fetchTopology() {
  try {
    const res = await apiClient.request(`${API_BASE}/topology`);
    if (!res.ok) return;
    const nodes = await res.json();
    TOPO = { nodes };
    // Seed nodeStatus and nodeMetrics for any node we don't know yet
    nodes.forEach(n => {
      if (nodeStatus[n.id]   === undefined) nodeStatus[n.id]   = 'ok';
      if (nodeMetrics[n.id]  === undefined) nodeMetrics[n.id]  = { cpu: 0, mem: 0, dsk: 0, patches: 0 };
    });
  } catch { /* backend not reachable — keep existing TOPO */ }
}

// ─── REST initial load  ◀ WIRE UP ─────────────────────────────────────────────
// Populates metrics + recent events before the WS stream catches up.
// Sequential startup (fetchInitial → connect) prevents duplicate events.
//
// GET /api/ops/metrics → { vps1:{cpu,mem,dsk,patches}, home:{...}, vps2:{...} }
// GET /api/ops/events  → [ { type:'event', sev, nodeId, msg, alarm, ... }, ... ]
//
async function fetchInitial() {
  try {
    const res = await apiClient.request(`${API_BASE}/metrics`);
    if (res.ok) {
      const data = await res.json();
      Object.entries(data).forEach(([nodeId, m]) => ingestMetrics(nodeId, m));
    }
  } catch { /* backend not yet reachable — WS will push metrics when ready */ }

  try {
    const res = await apiClient.request(`${API_BASE}/events`);
    if (res.ok) {
      const evts = await res.json();
      // Reverse so newest ends up at top after all unshifts
      [...evts].reverse().forEach(e => ingestEvent(e));
    }
  } catch { /* no prior events available */ }
}

// ─── Metrics polling fallback  ◀ WIRE UP ──────────────────────────────────────
// Keeps metric bars live while WS push is not yet implemented on the backend.
// Remove or increase the interval once WS metrics push is working.
function startMetricsPoll() {
  if (_metricsIntervalId) return; // only one poll interval ever
  _metricsIntervalId = setInterval(async () => {
    try {
      const res = await apiClient.request(`${API_BASE}/metrics`);
      if (res.ok) {
        const data = await res.json();
        Object.entries(data).forEach(([nodeId, m]) => ingestMetrics(nodeId, m));
      }
    } catch { /* silent — WS stream is primary */ }
  }, 30_000);
}

// ═══════════════════════════════════════════════════════════════════════════════
// TAB LIFECYCLE  — exported for tab-loader.js
// ═══════════════════════════════════════════════════════════════════════════════

// init() is called by tab-loader every time the Ops Center tab is activated.
// It re-binds DOM elements (new canvas each time), starts the RAF loop,
// and restores UI state from the persistent module-level state.
export async function init() {
  // 0. Initialize session token so all authenticated REST calls succeed
  try {
    await apiClient.initialize();
  } catch (err) {
    console.error('[ops-center] Failed to initialize API client:', err);
  }

  // 1. Re-bind canvas (new element every tab-loader activation)
  canvas = document.getElementById('oc-cv');
  if (!canvas) { console.error('[ops-center] #oc-cv not found — init aborted'); return; }
  ctx = canvas.getContext('2d');

  // 2. Make the tab fill the full app-main height (canvas needs a sized container)
  syncLayout();
  window.addEventListener('resize', syncLayout);

  // 3. Size canvas — retry on next paint if container not yet laid out
  W = 0; H = 0;
  resizeCanvas();
  requestAnimationFrame(resizeCanvas);
  window.addEventListener('resize', resizeCanvas);

  // 4. Wire up canvas mouse / wheel events
  attachCanvasEvents();

  // 5. Expose globals for innerHTML onclick and parent app / Guardian AI
  window.ackCrit = ackCrit;
  window.CitadelDash = {
    // Reset the UI — counters, log, alarm tiles. Does NOT touch the backend.
    // Usage: CitadelDash.reset()
    reset() {
      events.length = 0; attackers.length = 0; unackedCrits.clear();
      Object.assign(stats, { total: 0, today: 0, hr: 0 });
      Object.keys(nodeStatus).forEach(k => nodeStatus[k] = 'ok');
      document.querySelectorAll('#oc-alarms .alarm-tile').forEach(el => el.classList.remove('hi', 'on'));
      renderEventLog(); updateCounters();
      setLog('Dashboard reset \u2014 counters and log cleared');
    },
    // Inject a synthetic event — useful for testing without a backend.
    // Usage: CitadelDash.testEvent({ sev:'CRIT', nodeId:'<agent-id>', msg:'Test attack',
    //          alarm:'al-ssh', isAttack:true, isCrit:true, country:'CHN', ip:'1.2.3.4' })
    testEvent(e) { ingestEvent(e); },
  };

  // 6. Start render loop
  if (_raf) cancelAnimationFrame(_raf);
  _raf = requestAnimationFrame(loop);

  // 7. Restore UI from persisted module state (fast path on re-activation)
  updateCounters();
  renderEventLog();
  restoreAlarmTiles();

  // 8. Refresh topology on every activation (picks up newly-enrolled agents)
  await fetchTopology();

  // 9. First-time backend connection (only runs once per page load)
  if (!_initialized) {
    _initialized = true;
    setLog('Ops Center online \u2014 connecting to backend\u2026');
    await fetchInitial();  // REST load completes before WS opens (prevents duplicates)
    connect();
    startMetricsPoll();
  }
}

// destroy() is called by tab-loader when the user switches to a different tab.
// Stops the RAF loop and cleans up listeners. WS and metrics poll stay alive
// so data continues accumulating in module state while the tab is inactive.
export function destroy() {
  // 1. Stop render loop
  if (_raf) { cancelAnimationFrame(_raf); _raf = null; }

  // 2. Remove listeners (using named function refs — removeEventListener works correctly)
  window.removeEventListener('resize', resizeCanvas);
  window.removeEventListener('resize', syncLayout);

  // 3. Remove globals — ackCrit is only valid while the Ops Center DOM exists
  if (window.ackCrit === ackCrit) delete window.ackCrit;

  // 4. Restore app-main layout (undo the overflow:hidden + explicit height)
  const appMain  = document.querySelector('.app-main');
  const dynPanel = document.getElementById('tab-panel-dynamic');
  if (appMain)  appMain.style.overflow  = '';
  if (dynPanel) { dynPanel.style.height = ''; dynPanel.style.overflow = ''; }

  // 5. Null DOM references — avoids stale refs from a previous activation
  canvas = null; ctx = null; W = 0; H = 0;

  // NOTE: _ws stays alive — seamless data continuity across tab switches
  // NOTE: _metricsIntervalId stays alive — metrics keep refreshing in background
}
