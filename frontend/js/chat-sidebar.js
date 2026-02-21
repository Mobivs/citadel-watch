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
let _wsThinkingUnsub = null;
let _initialized = false;

// ── DOM references ─────────────────────────────────────────────────

let $sidebar, $messageList, $input, $sendBtn, $toggleBtn, $unreadBadge, $header,
    $thinkingIndicator, $thinkingDetail;

function cacheDom() {
    $sidebar           = document.getElementById('chat-sidebar');
    $messageList       = document.getElementById('chat-message-list');
    $input             = document.getElementById('chat-input');
    $sendBtn           = document.getElementById('chat-send-btn');
    $toggleBtn         = document.getElementById('chat-toggle-btn');
    $unreadBadge       = document.getElementById('chat-unread-badge');
    $header            = document.getElementById('chat-sidebar-header');
    $thinkingIndicator = document.getElementById('chat-thinking-indicator');
    $thinkingDetail    = document.getElementById('chat-thinking-detail');
}

// ── Rendering ──────────────────────────────────────────────────────

/**
 * Convert markdown text to HTML, handling Mermaid fenced blocks specially.
 * Mermaid blocks become <div class="mermaid"> containers; mermaid.run()
 * is called after DOM insertion to render them asynchronously.
 */
function renderWithMermaid(rawText) {
    // Replace ```mermaid ... ``` blocks with mermaid div placeholders
    // before marked processes the text (marked would turn them into <pre><code>).
    const MERMAID_RE = /```mermaid\s*\n([\s\S]*?)```/g;
    let hasMermaid = false;
    const withPlaceholders = rawText.replace(MERMAID_RE, (_match, diagram) => {
        hasMermaid = true;
        return `<div class="mermaid">${escapeHtml(diagram.trim())}</div>`;
    });

    const html = marked.parse(withPlaceholders, { breaks: true, gfm: true });

    if (hasMermaid && typeof mermaid !== 'undefined') {
        // Schedule rendering after the element is appended to the DOM
        setTimeout(() => mermaid.run(), 50);
    }

    return html;
}

function renderMessage(msg) {
    const div = document.createElement('div');
    div.className = 'chat-msg';
    div.dataset.type = msg.msg_type;
    div.dataset.from = msg.from_id;

    const fromLabel = getParticipantLabel(msg.from_id);
    const fromColor = getParticipantColor(msg.from_id);
    const typeColor = TYPE_COLORS[msg.msg_type] || '#E5E7EB';
    const time = formatTimestamp(msg.timestamp);
    const rawText = msg.payload?.text || JSON.stringify(msg.payload);
    // Render markdown when available (marked.js loaded in index.html),
    // fall back to plain escaped text so the sidebar degrades gracefully.
    // Mermaid fenced code blocks are replaced with diagram containers before
    // marked processes the rest; mermaid.run() renders them asynchronously.
    const text = (typeof marked !== 'undefined')
        ? renderWithMermaid(rawText)
        : escapeHtml(rawText);

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

    // Approval request: render Approve / Deny buttons
    if (msg.payload?.action_type === 'approval_request') {
        const actionUuid = msg.payload?.action_uuid || '';
        const actionId   = msg.payload?.action_id   || '';
        const agentName  = msg.payload?.agent_name  || '';

        const bar = document.createElement('div');
        bar.className = 'msg-action-bar';
        bar.dataset.uuid = actionUuid;
        bar.innerHTML = `
            <span class="action-bar-label">
                Action: <strong>${escapeHtml(actionId)}</strong>
                ${agentName ? `on <strong>${escapeHtml(agentName)}</strong>` : ''}
            </span>
            <div class="action-bar-btns">
                <button class="btn-action-approve" data-uuid="${escapeAttr(actionUuid)}">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                    Approve
                </button>
                <button class="btn-action-deny" data-uuid="${escapeAttr(actionUuid)}">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                    Deny
                </button>
            </div>
        `;

        const approveBtn = bar.querySelector('.btn-action-approve');
        const denyBtn    = bar.querySelector('.btn-action-deny');

        approveBtn.addEventListener('click', async () => {
            approveBtn.disabled = true;
            denyBtn.disabled    = true;
            try {
                const resp = await apiClient.post(`/api/ext-agents/actions/${actionUuid}/approve`, {});
                if (!resp.ok) throw new Error(`Server error: ${resp.status}`);
                bar.innerHTML = '<span class="action-result action-approved">Approved — queued for next heartbeat</span>';
            } catch (e) {
                approveBtn.disabled = false;
                denyBtn.disabled    = false;
                bar.insertAdjacentHTML('beforeend', `<span class="action-error">Error: ${escapeHtml(String(e))}</span>`);
            }
        });

        denyBtn.addEventListener('click', async () => {
            approveBtn.disabled = true;
            denyBtn.disabled    = true;
            try {
                const resp = await apiClient.post(`/api/ext-agents/actions/${actionUuid}/deny`, {});
                if (!resp.ok) throw new Error(`Server error: ${resp.status}`);
                bar.innerHTML = '<span class="action-result action-denied">Denied</span>';
            } catch (e) {
                approveBtn.disabled = false;
                denyBtn.disabled    = false;
                bar.insertAdjacentHTML('beforeend', `<span class="action-error">Error: ${escapeHtml(String(e))}</span>`);
            }
        });

        div.querySelector('.chat-msg-body').appendChild(bar);
    }

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

function showThinking(active, detail = 'Analyzing...') {
    if (!$thinkingIndicator) return;
    if (active) {
        if ($thinkingDetail) $thinkingDetail.textContent = detail;
        $thinkingIndicator.hidden = false;
    } else {
        $thinkingIndicator.hidden = true;
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
        // Re-scroll and re-measure textarea after expand (input was display:none)
        requestAnimationFrame(() => {
            scrollToBottom();
            autoResizeInput();
        });
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

// ── Textarea auto-resize ───────────────────────────────────────────

function autoResizeInput() {
    if (!$input) return;
    // Collapse to auto so scrollHeight reflects actual content height
    $input.style.height = 'auto';
    const maxHeight = 87; // matches CSS max-height (5 lines × ~15px + 12px padding)
    const newHeight = Math.min($input.scrollHeight, maxHeight);
    $input.style.height = newHeight + 'px';
    // Use 'scroll' (not 'auto') to avoid scrollbar-flicker in the narrow sidebar
    $input.style.overflowY = $input.scrollHeight > maxHeight ? 'scroll' : 'hidden';
}

// ── Sending messages ───────────────────────────────────────────────

async function sendMessage() {
    if (!$input) return;
    const text = $input.value.trim();
    if (!text) return;

    $input.value = '';
    autoResizeInput(); // reset height back to single line
    $input.focus();

    try {
        const resp = await apiClient.post('/api/chat/send', { text });
        if (!resp.ok) throw new Error(`Server error: ${resp.status}`);
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
    if (data.type === 'chat_thinking') {
        showThinking(data.active, data.detail || 'Analyzing...');
        return;
    }
    if (data.type === 'chat_message' && data.message) {
        // Clear thinking indicator when a real response arrives
        if (data.message.from_id === 'assistant') {
            showThinking(false);
        }
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
            if (e.key === 'Enter' && !e.shiftKey && !e.ctrlKey) {
                e.preventDefault();
                sendMessage();
            }
        });
        $input.addEventListener('input', autoResizeInput);
    }
    if ($toggleBtn) {
        $toggleBtn.addEventListener('click', () => setCollapsed(!_collapsed));
    }

    // Copy button delegation
    if ($messageList) {
        $messageList.addEventListener('click', handleCopyClick);
    }

    // Subscribe to WebSocket for real-time messages and thinking indicator
    _wsUnsub = wsHandler.subscribe('chat_message', onWsMessage);
    _wsThinkingUnsub = wsHandler.subscribe('chat_thinking', onWsMessage);

    // Load message history
    try {
        const resp = await apiClient.get('/api/chat/messages?limit=50');
        if (resp && resp.ok) {
            const res = await resp.json();
            if (res && res.messages) {
                _messages = res.messages;
                renderAllMessages();
            }
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
    if (_wsThinkingUnsub) {
        _wsThinkingUnsub();
        _wsThinkingUnsub = null;
    }
    showThinking(false);
    _initialized = false;
    _messages = [];
    _unreadCount = 0;
}

// ── Auto-init ──────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    init();
});

export { init, destroy };
