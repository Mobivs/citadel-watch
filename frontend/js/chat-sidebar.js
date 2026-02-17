// PRD: SecureChat — Always-Visible Sidebar
// Reference: Plan Milestone 1
//
// The chat sidebar is the user's primary interface for commanding the
// system at a high level: onboarding servers, strategic decisions,
// AI assistant interaction, and escalation alerts.
//
// Architecture:
//   - Runs independently of tab-loader (not a tab page)
//   - Initializes on DOMContentLoaded (always present)
//   - Uses wsHandler for real-time message push
//   - Collapse/expand state saved to localStorage

import { wsHandler } from './websocket-handler.js';
import { apiClient } from './utils/api-client.js';

// ── Constants ──────────────────────────────────────────────────────

const STORAGE_KEY_COLLAPSED = 'citadel_chat_collapsed';
const MAX_DISPLAY_MESSAGES = 200;

// Message type → color mapping (matches style guidelines)
const TYPE_COLORS = {
    command:   '#00D9FF',  // neon blue
    event:     '#ff9900',  // high severity orange
    setup:     '#00D9FF',
    response:  '#E5E7EB',  // light gray
    text:      '#E5E7EB',
    heartbeat: '#6B7280',  // muted gray
    query:     '#a78bfa',  // purple
};

// Participant → display config
const PARTICIPANT_LABELS = {
    user:      { name: 'You',          color: '#00D9FF' },
    citadel:   { name: 'Citadel',      color: '#10B981' },
    assistant: { name: 'AI Assistant',  color: '#a78bfa' },
};

// ── State ──────────────────────────────────────────────────────────

let _collapsed = false;
let _messages = [];
let _unreadCount = 0;
let _wsUnsub = null;
let _initialized = false;

// ── DOM references ─────────────────────────────────────────────────

let $sidebar, $messageList, $input, $sendBtn, $toggleBtn, $unreadBadge, $header;

function cacheDom() {
    $sidebar     = document.getElementById('chat-sidebar');
    $messageList = document.getElementById('chat-message-list');
    $input       = document.getElementById('chat-input');
    $sendBtn     = document.getElementById('chat-send-btn');
    $toggleBtn   = document.getElementById('chat-toggle-btn');
    $unreadBadge = document.getElementById('chat-unread-badge');
    $header      = document.getElementById('chat-sidebar-header');
}

// ── Rendering ──────────────────────────────────────────────────────

function renderMessage(msg) {
    const div = document.createElement('div');
    div.className = 'chat-msg';
    div.dataset.type = msg.msg_type;
    div.dataset.from = msg.from_id;

    const fromLabel = getParticipantLabel(msg.from_id);
    const fromColor = getParticipantColor(msg.from_id);
    const typeColor = TYPE_COLORS[msg.msg_type] || '#E5E7EB';
    const time = formatTimestamp(msg.timestamp);
    const text = escapeHtml(msg.payload?.text || JSON.stringify(msg.payload));

    // Check for copy-able content (install commands)
    const hasCopyable = msg.payload?.copyable;
    const copyableText = msg.payload?.copyable || '';

    div.innerHTML = `
        <div class="chat-msg-header">
            <span class="chat-msg-from" style="color: ${fromColor}">${fromLabel}</span>
            <span class="chat-msg-time">${time}</span>
        </div>
        <div class="chat-msg-body" style="border-left: 2px solid ${typeColor}">
            ${text}
            ${hasCopyable ? `
                <div class="chat-msg-copy">
                    <code class="chat-msg-code">${escapeHtml(copyableText)}</code>
                    <button class="chat-copy-btn" data-copy="${escapeAttr(copyableText)}" title="Copy to clipboard">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                        Copy
                    </button>
                </div>
            ` : ''}
        </div>
    `;

    return div;
}

function renderAllMessages() {
    if (!$messageList) return;
    $messageList.innerHTML = '';
    for (const msg of _messages) {
        $messageList.appendChild(renderMessage(msg));
    }
    scrollToBottom();
}

function appendMessage(msg) {
    _messages.push(msg);
    if (_messages.length > MAX_DISPLAY_MESSAGES) {
        _messages.shift();
    }

    if ($messageList) {
        $messageList.appendChild(renderMessage(msg));
        // Trim DOM to match
        while ($messageList.children.length > MAX_DISPLAY_MESSAGES) {
            $messageList.removeChild($messageList.firstChild);
        }
        scrollToBottom();
    }

    // Update unread if collapsed
    if (_collapsed) {
        _unreadCount++;
        updateUnreadBadge();
    }
}

function scrollToBottom() {
    if ($messageList) {
        $messageList.scrollTop = $messageList.scrollHeight;
    }
}

function updateUnreadBadge() {
    if (!$unreadBadge) return;
    if (_unreadCount > 0) {
        $unreadBadge.textContent = _unreadCount > 99 ? '99+' : String(_unreadCount);
        $unreadBadge.style.display = 'flex';
    } else {
        $unreadBadge.style.display = 'none';
    }
}

// ── Collapse / Expand ──────────────────────────────────────────────

function setCollapsed(collapsed) {
    _collapsed = collapsed;
    if (!$sidebar) return;

    if (collapsed) {
        $sidebar.classList.add('chat-collapsed');
    } else {
        $sidebar.classList.remove('chat-collapsed');
        _unreadCount = 0;
        updateUnreadBadge();
        // Re-scroll after expand
        requestAnimationFrame(scrollToBottom);
    }

    try {
        localStorage.setItem(STORAGE_KEY_COLLAPSED, collapsed ? '1' : '0');
    } catch (_) {}
}

function loadCollapsedState() {
    try {
        return localStorage.getItem(STORAGE_KEY_COLLAPSED) === '1';
    } catch (_) {
        return false;
    }
}

// ── Sending messages ───────────────────────────────────────────────

async function sendMessage() {
    if (!$input) return;
    const text = $input.value.trim();
    if (!text) return;

    $input.value = '';
    $input.focus();

    try {
        await apiClient.post('/api/chat/send', { text });
    } catch (err) {
        console.error('[chat] Send failed:', err);
        // Show error inline
        appendMessage({
            id: `err_${Date.now()}`,
            from_id: 'citadel',
            to_id: 'user',
            msg_type: 'event',
            payload: { text: `Failed to send: ${err.message}` },
            timestamp: new Date().toISOString(),
        });
    }
}

// ── WebSocket ──────────────────────────────────────────────────────

function onWsMessage(data) {
    if (data.type === 'chat_message' && data.message) {
        appendMessage(data.message);
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

function getParticipantLabel(id) {
    if (PARTICIPANT_LABELS[id]) return PARTICIPANT_LABELS[id].name;
    if (id.startsWith('agent:')) return `Agent ${id.slice(6, 18)}`;
    return id;
}

function getParticipantColor(id) {
    if (PARTICIPANT_LABELS[id]) return PARTICIPANT_LABELS[id].color;
    if (id.startsWith('agent:')) return '#F59E0B';
    return '#9CA3AF';
}

function formatTimestamp(ts) {
    try {
        const d = new Date(ts);
        const now = new Date();
        if (d.toDateString() === now.toDateString()) {
            return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        }
        return d.toLocaleDateString([], { month: 'short', day: 'numeric' }) +
               ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch (_) {
        return '';
    }
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function escapeAttr(str) {
    return escapeHtml(str).replace(/'/g, '&#39;');
}

// ── Copy button handler ────────────────────────────────────────────

function handleCopyClick(e) {
    const btn = e.target.closest('.chat-copy-btn');
    if (!btn) return;
    const text = btn.dataset.copy;
    if (!text) return;

    navigator.clipboard.writeText(text).then(() => {
        const orig = btn.innerHTML;
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.innerHTML = orig; }, 1500);
    }).catch(() => {
        // Fallback
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        const orig = btn.innerHTML;
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.innerHTML = orig; }, 1500);
    });
}

// ── Init / Destroy ─────────────────────────────────────────────────

async function init() {
    if (_initialized) return;
    _initialized = true;

    cacheDom();
    if (!$sidebar) {
        console.warn('[chat] Sidebar element not found');
        return;
    }

    // Restore collapsed state
    setCollapsed(loadCollapsedState());

    // Wire events
    if ($sendBtn) {
        $sendBtn.addEventListener('click', sendMessage);
    }
    if ($input) {
        $input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        });
    }
    if ($toggleBtn) {
        $toggleBtn.addEventListener('click', () => setCollapsed(!_collapsed));
    }

    // Copy button delegation
    if ($messageList) {
        $messageList.addEventListener('click', handleCopyClick);
    }

    // Subscribe to WebSocket for real-time messages
    _wsUnsub = wsHandler.subscribe('chat_message', onWsMessage);

    // Load message history
    try {
        const res = await apiClient.get('/api/chat/messages?limit=50');
        if (res && res.messages) {
            _messages = res.messages;
            renderAllMessages();
        }
    } catch (err) {
        console.warn('[chat] Failed to load history:', err);
    }

    console.log('[chat] Sidebar initialized');
}

function destroy() {
    if (_wsUnsub) {
        _wsUnsub();
        _wsUnsub = null;
    }
    _initialized = false;
    _messages = [];
    _unreadCount = 0;
}

// ── Auto-init ──────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    init();
});

export { init, destroy };
