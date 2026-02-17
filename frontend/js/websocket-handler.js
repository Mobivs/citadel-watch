// PRD: WebSocket Real-Time Integration (P2.1.5-T7)
// Reference: PHASE_2_SPEC.md
//
// Shared WebSocket manager for all dashboard pages.
// Provides:
//   - Single connection per page (singleton)
//   - Exponential backoff reconnection (max 5 retries)
//   - Subscribe/unsubscribe by message type
//   - Window event broadcasting (ws-connected / ws-disconnected)
//   - Memory leak prevention (cleanup on disconnect)
//
// Message types handled:
//   - threat_detected      → threat counters + gauge update
//   - asset_status_changed → asset table refresh
//   - alert_created        → timeline refresh
//   - event                → generic event (backward compat)
//   - security_level_changed → system status update

// ── Constants ──────────────────────────────────────────────────────

const MAX_RETRIES = 5;
const BASE_DELAY_MS = 1000;    // 1s initial delay
const MAX_DELAY_MS = 30000;    // 30s cap

const MESSAGE_TYPES = [
    'threat_detected',
    'asset_status_changed',
    'alert_created',
    'event',
    'security_level_changed',
    'guardian_started',
    'guardian_stopped',
    'process_killed',
    'threat:remote-shield',
    'threat:correlation',
];


// ── WebSocket Handler Class ────────────────────────────────────────

class WebSocketHandler {
    constructor() {
        this._ws = null;
        this._subscribers = new Map();  // type → Set<callback>
        this._retryCount = 0;
        this._retryTimer = null;
        this._connected = false;
        this._disposed = false;
        this._url = null;
    }

    // ── Connection ─────────────────────────────────────────────────

    /**
     * Open a WebSocket connection. Safe to call multiple times;
     * subsequent calls are no-ops while a connection is active.
     *
     * @param {string} [url] - Override WebSocket URL (for testing).
     */
    connect(url) {
        if (this._disposed) return;
        if (this._ws && (this._ws.readyState === WebSocket.OPEN ||
                         this._ws.readyState === WebSocket.CONNECTING)) {
            return; // already connected / connecting
        }

        if (!url) {
            const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
            url = `${protocol}//${location.host}/ws`;
        }
        this._url = url;
        console.log('[WS] Connecting to', url);

        try {
            this._ws = new WebSocket(url);
        } catch (err) {
            console.error('[WS] Constructor failed:', err);
            this._onDisconnect();
            return;
        }

        this._ws.onopen = () => this._onConnect();
        this._ws.onclose = (e) => {
            console.warn('[WS] Close: code=%d reason=%s wasClean=%s', e.code, e.reason, e.wasClean);
            this._onDisconnect();
        };
        this._ws.onerror = (e) => console.warn('[WS] Error:', e.type || e);
        this._ws.onmessage = (evt) => this._onMessage(evt);
    }

    /**
     * Cleanly close the connection. Stops reconnection attempts.
     */
    disconnect() {
        this._clearRetryTimer();
        this._disposed = true;
        if (this._ws) {
            this._ws.onclose = null; // prevent reconnect
            this._ws.close();
            this._ws = null;
        }
        if (this._connected) {
            this._connected = false;
            this._broadcastStatus(false);
        }
    }

    /**
     * Reset disposed state so connect() works again after disconnect().
     */
    reset() {
        this._disposed = false;
        this._retryCount = 0;
    }

    // ── Subscribe / Unsubscribe ────────────────────────────────────

    /**
     * Register a callback for a specific message type.
     *
     * @param {string} type   - Message type (e.g. 'threat_detected').
     * @param {Function} cb   - Callback receiving the parsed message object.
     * @returns {Function}     Unsubscribe function.
     */
    subscribe(type, cb) {
        if (!this._subscribers.has(type)) {
            this._subscribers.set(type, new Set());
        }
        this._subscribers.get(type).add(cb);

        // Return unsubscribe function
        return () => {
            const subs = this._subscribers.get(type);
            if (subs) {
                subs.delete(cb);
                if (subs.size === 0) {
                    this._subscribers.delete(type);
                }
            }
        };
    }

    /**
     * Remove a specific callback for a message type.
     */
    unsubscribe(type, cb) {
        const subs = this._subscribers.get(type);
        if (subs) {
            subs.delete(cb);
            if (subs.size === 0) {
                this._subscribers.delete(type);
            }
        }
    }

    /**
     * Remove ALL subscribers (used for cleanup / testing).
     */
    clearSubscribers() {
        this._subscribers.clear();
    }

    // ── State Queries ──────────────────────────────────────────────

    /** @returns {boolean} Whether the WebSocket is currently open. */
    get connected() {
        return this._connected;
    }

    /** @returns {number} Current retry count (resets on successful connect). */
    get retryCount() {
        return this._retryCount;
    }

    /** @returns {number} Number of active subscriber types. */
    get subscriberCount() {
        let total = 0;
        for (const subs of this._subscribers.values()) {
            total += subs.size;
        }
        return total;
    }

    // ── Internals ──────────────────────────────────────────────────

    /** @private */
    _onConnect() {
        this._connected = true;
        this._retryCount = 0;
        this._clearRetryTimer();
        console.log('[WS] Connected');
        this._broadcastStatus(true);
    }

    /** @private */
    _onDisconnect() {
        const wasConnected = this._connected;
        this._connected = false;
        this._ws = null;

        if (wasConnected) {
            console.log('[WS] Disconnected');
            this._broadcastStatus(false);
        }

        if (!this._disposed) {
            this._scheduleReconnect();
        }
    }

    /** @private */
    _onMessage(evt) {
        let msg;
        try {
            msg = JSON.parse(evt.data);
        } catch {
            return; // non-JSON (ping echo) — ignore
        }

        const type = msg.type;
        if (!type) return;

        // Notify type-specific subscribers
        const subs = this._subscribers.get(type);
        if (subs) {
            for (const cb of subs) {
                try {
                    cb(msg);
                } catch (err) {
                    console.error(`[WS] Subscriber error (${type}):`, err);
                }
            }
        }

        // Also notify wildcard subscribers ('*')
        const wildcards = this._subscribers.get('*');
        if (wildcards) {
            for (const cb of wildcards) {
                try {
                    cb(msg);
                } catch (err) {
                    console.error('[WS] Wildcard subscriber error:', err);
                }
            }
        }
    }

    // ── Reconnection (exponential backoff) ─────────────────────────

    /** @private */
    _scheduleReconnect() {
        if (this._retryCount >= MAX_RETRIES) {
            // Don't give up permanently — slow-poll every 30s so the WS
            // can recover when the backend becomes available.
            console.warn(`[WS] Fast retries exhausted. Slow-polling every 30s...`);
            this._retryTimer = setTimeout(() => {
                this._retryTimer = null;
                this._retryCount = 0;  // reset for fresh fast retries
                this.connect(this._url);
            }, 30000);
            return;
        }

        const delay = computeBackoff(this._retryCount, BASE_DELAY_MS, MAX_DELAY_MS);
        this._retryCount++;
        console.log(`[WS] Reconnecting in ${delay}ms (attempt ${this._retryCount}/${MAX_RETRIES})...`);

        this._retryTimer = setTimeout(() => {
            this._retryTimer = null;
            this.connect(this._url);
        }, delay);
    }

    /** @private */
    _clearRetryTimer() {
        if (this._retryTimer !== null) {
            clearTimeout(this._retryTimer);
            this._retryTimer = null;
        }
    }

    /** @private – Broadcast connection status via window events. */
    _broadcastStatus(connected) {
        const eventName = connected ? 'ws-connected' : 'ws-disconnected';
        try {
            window.dispatchEvent(new CustomEvent(eventName, {
                detail: { connected, retryCount: this._retryCount }
            }));
        } catch {
            // SSR / test environment without window
        }
    }

    /** @private – Notify subscribers on an internal channel. */
    _notifySubscribers(type, data) {
        const subs = this._subscribers.get(type);
        if (subs) {
            for (const cb of subs) {
                try { cb(data); } catch { /* swallow */ }
            }
        }
    }
}


// ── Backoff computation (exported for testing) ─────────────────────

/**
 * Exponential backoff with jitter.
 *
 * @param {number} attempt   - Zero-based retry attempt.
 * @param {number} baseMs    - Base delay in milliseconds.
 * @param {number} maxMs     - Maximum delay cap.
 * @returns {number}          Delay in milliseconds.
 */
function computeBackoff(attempt, baseMs, maxMs) {
    const exp = Math.min(baseMs * Math.pow(2, attempt), maxMs);
    // Add ±25% jitter to prevent thundering herd
    const jitter = exp * 0.25 * (Math.random() * 2 - 1);
    return Math.max(0, Math.round(exp + jitter));
}


// ── Singleton ──────────────────────────────────────────────────────

const wsHandler = new WebSocketHandler();


// ── Auto-connect ─────────────────────────────────────────────────
// Module scripts are deferred (DOM is ready when this executes).
// Connecting here instead of waiting for DOMContentLoaded avoids a
// potential race where the event already fired before registration.
wsHandler.connect();


// ── Exports ────────────────────────────────────────────────────────

export {
    WebSocketHandler,
    wsHandler,
    computeBackoff,
    MAX_RETRIES,
    BASE_DELAY_MS,
    MAX_DELAY_MS,
    MESSAGE_TYPES,
};
