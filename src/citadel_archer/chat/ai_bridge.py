# PRD: AI Brain — SecureChat Bridge
# Reference: docs/PRD.md v0.2.6, AI-Centric Architecture
#
# Connects the SecureChat message layer to AI backends (Claude API + Ollama).
#
# Listens for messages requiring command-level attention:
#   - User TEXT messages (questions, requests, conversation)
#   - Agent ESCALATION events (critical/high from agent poller)
#
# Builds context (chat history + system state), calls AI with tools,
# routes responses back through ChatManager as "assistant" messages.
#
# Backend priority:
#   1. Claude API (cloud) — primary, highest capability
#   2. Ollama (local) — fallback when Claude unavailable or no API key
#
# Gracefully degrades: if neither backend is available, the bridge is disabled
# and chat commands (add vps, deploy agent) still work normally.

import asyncio
import json
import logging
import os
import re as _ssh_re
import string as _string
import threading as _ssh_threading
import time as _ssh_time
from collections import defaultdict as _defaultdict
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from .ai_audit import get_ai_audit_logger
from .message import (
    ChatMessage,
    MessageType,
    PARTICIPANT_ASSISTANT,
    PARTICIPANT_CITADEL,
    PARTICIPANT_USER,
)

if TYPE_CHECKING:
    from .chat_manager import ChatManager

logger = logging.getLogger(__name__)


# ── Security Helpers ───────────────────────────────────────────────────

def _is_localhost_url(url: str) -> bool:
    """Check if a URL points to localhost/loopback.

    SECURITY: Used to gate Ollama connections. Only localhost is allowed
    by default — remote Ollama servers require explicit opt-in via
    OLLAMA_ALLOW_REMOTE=1 to prevent accidental data leakage to
    untrusted LLM endpoints.
    """
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        return host in (
            "localhost",
            "127.0.0.1",
            "::1",
            "0.0.0.0",  # As a connect-to address, resolves to local machine
        )
    except Exception:
        return False


# ── Inference Tiers ────────────────────────────────────────────────────
#
# Tier 0 — zero inference: template responses from cached state (no API call)
# Tier 1 — Haiku: simple single-event queries, status summaries, explanations
# Tier 2 — Sonnet: multi-event correlation, incident investigation, complex analysis
#
# Cost targets: Tier 0 70-80%, Tier 1 15-20%, Tier 2 5-10%, Opus never.

import re as _re

# ── SSH Command Safety ─────────────────────────────────────────────────

_SAFE_READ_COMMANDS = frozenset({
    # Linux/macOS read-only
    # NOTE: "find" is intentionally excluded — it supports -exec/-delete/-execdir
    # which can run arbitrary commands or delete files even in a "read" invocation.
    "echo", "ls", "cat", "head", "tail", "grep", "du", "df",
    "ps", "top", "htop", "netstat", "ss", "lsof",
    "journalctl", "dmesg", "last", "lastlog", "who", "w",
    "systemctl status", "docker ps", "docker logs",
    "iptables -l", "ip addr", "ip route", "nft list ruleset",
    "free", "vmstat", "iostat", "uptime", "uname", "id", "hostname",
    "cat /etc/", "cat /var/log/", "tail -",
    # Linux package management — read-only queries only (no install/upgrade/remove)
    "apt list", "apt-cache show", "apt-cache policy", "apt-cache search",
    # apt-get -s / --simulate: dry-run mode, prints actions but does NOT modify the system.
    # Prefix-matched, so "apt-get -s install foo" passes — safe because -s suppresses all
    # side-effects in all current Debian/Ubuntu versions.
    "apt-get -s", "apt-get --simulate",
    "dpkg -l", "dpkg --list", "dpkg -s", "dpkg --status",
    # Windows PowerShell read-only (lowercase — compared case-insensitively)
    "get-process", "get-filehash", "get-authenticodesignature",
    "get-childitem", "get-item", "get-acl", "get-itemproperty",
    "get-netfirewallrule", "get-nettcpconnection", "get-netadapter",
    "get-service", "get-scheduledtask", "get-scheduledtaskinfo",
    "get-localuser", "get-localgroup", "get-localgroupmember",
    "get-winevent", "get-eventlog",
    "get-hotfix", "get-windowsoptionalfeature", "get-installedmodule",
    # Windows cmd read-only
    "tasklist", "ipconfig", "systeminfo", "whoami", "dir", "type",
    "net user", "net localgroup", "sc query", "schtasks /query",
    "wmic process", "wmic service", "wmic product",
})

_SHELL_METACHAR = _ssh_re.compile(r'[;&|`$><\\]')
# Windows metacharacters — backslash omitted (valid path separator); parentheses
# included because PowerShell subexpressions like Get-Item (Remove-Item x) can
# execute a nested command before passing its result to the outer cmdlet.
_PS_METACHAR = _ssh_re.compile(r'[;&|`$><()]')
# Quoted-string stripper — removes content inside single or double quotes before
# the metachar check so paths like "C:\Program Files (x86)\..." or
# 'C:\Program Files (x86)\...' don't false-positive on the parentheses guard.
# Only applied to Windows commands (PowerShell uses both quoting styles).
_QUOTED_STR_RE = _ssh_re.compile(r'"(?:[^"\\]|\\.)*"|\'[^\']*\'')

# Commands that are PowerShell cmdlets (Get-Verb pattern)
_PS_CMDLET_PREFIX = _ssh_re.compile(r'^get-', _ssh_re.IGNORECASE)

# Windows cmd-line tools that accept paths with backslashes
_WINDOWS_CMD_TOOLS = frozenset({
    "tasklist", "ipconfig", "systeminfo", "whoami", "dir", "type",
    "net user", "net localgroup", "sc query", "schtasks /query",
    "wmic process", "wmic service", "wmic product",
})


def _is_safe_read_only(command: str) -> bool:
    """Return True if the command is whitelisted and has no shell metacharacters.

    Windows commands (PowerShell cmdlets and cmd tools) use a relaxed metachar
    set — backslash is allowed because Windows paths use it as a separator.
    """
    cmd = command.strip()
    cmd_lower = cmd.lower()

    # Detect Windows commands: PowerShell cmdlets or known cmd tools
    is_windows_command = bool(_PS_CMDLET_PREFIX.match(cmd_lower)) or any(
        cmd_lower == safe or cmd_lower.startswith(safe + " ")
        for safe in _SAFE_READ_COMMANDS
        if safe.startswith("get-")
    ) or any(
        cmd_lower == wc or cmd_lower.startswith(wc + " ")
        for wc in _WINDOWS_CMD_TOOLS
    )
    metachar_re = _PS_METACHAR if is_windows_command else _SHELL_METACHAR

    cmd_for_metachar = _QUOTED_STR_RE.sub('""', cmd) if is_windows_command else cmd
    if metachar_re.search(cmd_for_metachar):
        return False
    return any(
        cmd_lower == safe or cmd_lower.startswith(safe + " ")
        for safe in _SAFE_READ_COMMANDS
    )


# Per-asset SSH rate limiter — 10 commands / minute
_SSH_RATE: Dict[str, list] = _defaultdict(list)
_SSH_RATE_LIMIT = 10
_SSH_RATE_LOCK = _ssh_threading.Lock()


def _check_ssh_rate(asset_id: str) -> bool:
    """Return True if within rate limit (10 cmd/min per asset)."""
    now = _ssh_time.time()
    with _SSH_RATE_LOCK:
        window = [t for t in _SSH_RATE[asset_id] if now - t < 60]
        if not window:
            # Remove stale entry — deleted/renamed assets don't accumulate forever
            _SSH_RATE.pop(asset_id, None)
            window = []
        _SSH_RATE[asset_id] = window
        if len(window) >= _SSH_RATE_LIMIT:
            return False
        _SSH_RATE[asset_id].append(now)
        return True


_MODEL_HAIKU = "claude-haiku-4-5-20251001"
_MODEL_SONNET = "claude-sonnet-4-5-20250929"

# Maximum characters of chat history to include in a single AI call.
# Derived from the compaction threshold: 10K tokens × 3.8 chars/token = 38K chars.
# MUST be >= compaction_tokens × 3.8 to avoid the "context gap" — messages
# silently dropped from a sliding window before compaction fires.  If this is
# smaller than the compaction trigger you lose context without any summarisation.
_HISTORY_CHAR_BUDGET = 26_600  # 7K tokens × 3.8 chars — matches compaction threshold


def _trim_to_char_budget(messages: list, budget: int) -> list:
    """Return the most-recent messages that fit within budget characters.

    Walks newest-to-oldest, accumulating content length, and stops when the
    budget is exceeded. Returns messages in original chronological order.
    Uses the same text extraction as _format_messages_for_claude so the
    budget estimate is accurate.
    """
    total = 0
    selected = []
    for msg in reversed(messages):
        content = msg.text or json.dumps(msg.payload or {})
        total += len(content)
        if total > budget:
            break
        selected.append(msg)
    return list(reversed(selected))

# Keywords that signal complex analysis requiring Sonnet.
_SONNET_KEYWORDS = (
    "investigat", "correlat", "attack chain", "posture", "threat hunt",
    "incident", "compromise", "breach", "malware", "intrusion",
    "privilege escalat", "lateral movement", "persistence", "root cause",
    "pattern", "timeline", "forensic", "audit trail", "compare",
)

# Tier 0 patterns: pure data-retrieval queries, no AI judgment needed.
# Each entry is (compiled_regex, handler_fn(state) -> str).
# Only fire if the ENTIRE query is clearly a data lookup — conservative list.
def _t0_status(s: dict) -> str:
    threat = s.get("threat_level", "unknown").upper()
    uptime = s.get("uptime", "unknown")
    assets = s.get("assets", [])
    online = sum(1 for a in assets if a.get("status") in ("online", "active"))
    level = s.get("security_level", "guardian").title()
    return (
        f"**System Status**\n"
        f"Threat Level: {threat}\n"
        f"Security Mode: {level}\n"
        f"Assets: {len(assets)} managed ({online} online)\n"
        f"Uptime: {uptime}"
    )

def _t0_threat(s: dict) -> str:
    return f"Current threat level: **{s.get('threat_level', 'unknown').upper()}**"

def _t0_asset_count(s: dict) -> str:
    assets = s.get("assets", [])
    online = sum(1 for a in assets if a.get("status") in ("online", "active"))
    return f"{len(assets)} managed asset(s), {online} online."

_TIER0_RULES = [
    (_re.compile(
        r"^\s*(what('?s| is) (the )?)?(system |current )?status\??\s*$",
        _re.IGNORECASE,
    ), _t0_status),
    (_re.compile(
        r"^\s*(what('?s| is) (the )?)?(current )?threat.?level\??\s*$",
        _re.IGNORECASE,
    ), _t0_threat),
    (_re.compile(
        r"^\s*(how many (assets?|machines?|devices?)|asset count)\??\s*$",
        _re.IGNORECASE,
    ), _t0_asset_count),
]


# ── System Prompt ──────────────────────────────────────────────────────
#
# Split into two parts for Anthropic prompt caching:
#   _SYSTEM_BASE     — static, never changes → tagged with cache_control
#   _SYSTEM_DYNAMIC  — per-call state (uptime, assets, memory) → not cached
#
# The Anthropic SDK caches blocks that haven't changed since the last call.
# Separating the large static base from the tiny dynamic tail means the
# static block gets a cache hit on every turn after the first, cutting
# input token costs by ~85% on the static portion.

_SYSTEM_BASE = """\
You are the Citadel Archer AI — the defensive brain of a personal security platform.

## Your Role
- Analyze security events and explain them in plain, calm language.
- Advise the user on threats, hardening, and best practices.
- Take action within your security level guardrails (use tools).
- When something is normal, say so clearly. When dangerous, explain what and why.

## Personality
- Trusted security advisor, not an alarm system.
- Speak like a knowledgeable friend, not a technical manual.
- Be direct and honest. Don't hedge unnecessarily.
- When you've taken action, state what you did and why.

## Response Length — STRICT
- Default: 1-3 sentences. No preamble, no summary at the end.
- Actions taken: one short sentence stating what was done.
- Analysis/investigation: bullet points only, no prose paragraphs.
- Only elaborate when the user explicitly asks for detail or an explanation is complex.
- NEVER start with "Certainly", "Of course", "Great question", or similar filler.

## Security Level Options
- Observer: Analyze and explain only. Do NOT take autonomous actions.
- Guardian: May block known threats, deploy agents, rotate credentials if breach detected.
- Sentinel: Full autonomy — kill processes, block IPs, modify firewall, auto-escalate.

## Rules
- NEVER reveal Vault secrets, SSH private keys, or API keys.
- NEVER run offensive security tools.
- If you don't know, say so. Don't invent threat details.
- Use tools to get fresh data before answering questions about system state.
- Prefer action over questions when confidence is high and security level allows.

## Executing Commands on Assets
When the user asks you to run, execute, check, create, delete, or modify ANYTHING on a
managed asset — ALWAYS call execute_ssh_command. Do NOT describe how to do it manually.
This applies to ALL assets including the local machine (asset_id='localhost').
- Read-only commands (Get-Process, ps, df, etc.) execute immediately.
- Write/modify commands (New-Item, rm, kill, Set-Content, etc.) automatically show an
  approval card in the chat for the user to confirm — just call the tool and the system
  handles the rest. You do not need to ask permission first; call the tool and let the
  approval flow handle it.

## Multi-Asset Operations — Serial Only
When performing write/destructive operations across multiple assets, ALWAYS do them
one at a time in series — complete and verify on the first asset before touching the
next. Never send simultaneous approval requests for write operations on multiple servers.
Parallel execution is acceptable for read-only checks only.

## SSH Credential Management — CRITICAL RULES
SSH key rotation in this platform is BUMPLESS — the new key is installed and verified
before the old key is ever removed. Violating this order causes immediate lockout.

The correct rotation order (enforced by the Assets UI "Rotate" button):
1. Generate new keypair
2. APPEND new public key to remote ~/.ssh/authorized_keys (both keys valid simultaneously)
3. Update asset to use new credential
4. Verify SSH connection works with new key only
5. ONLY THEN remove old public key from authorized_keys
6. Delete old private key from vault

**Never do this manually via execute_ssh_command.** Always use the "Rotate" button in the
Assets tab. If the user asks you to rotate an SSH key, instruct them to use the UI button.

Hard constraints:
- NEVER remove or overwrite authorized_keys before the new key is verified working
- NEVER remove keys with the comment "citadel-recovery-*" — these are emergency fallbacks
- NEVER revoke or delete the current active SSH key as a first step
- If SSH is already broken (can't connect), use "Emergency Recovery" in the Assets UI,
  not manual key manipulation
"""

# Dynamic tail — rebuilt on every call, NOT cached (contains timestamps / live state).
# Uses string.Template ($-syntax) instead of str.format() so that AI-generated
# content in $memory_index or $system_state can never crash on literal {curly braces}.
_SYSTEM_DYNAMIC = _string.Template("""
## Active Security Level: $security_level

## Current System State
$system_state

## Past Session Memory
$memory_index
""")


# ── Tool Definitions (Anthropic API format) ────────────────────────────

TOOLS = [
    {
        "name": "get_system_status",
        "description": (
            "Get current security status: threat level (green/yellow/red), "
            "guardian active status, server uptime, and asset count."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "get_asset_list",
        "description": (
            "Get all managed assets (machines in the asset inventory). Each entry "
            "represents one physical or virtual machine. has_shield_daemon=True means "
            "a Citadel Shield daemon is running on that machine (deployed via the "
            "Assets tab one-liner). Use get_vps_summary() to see enrolled AI agents "
            "and Shield daemon details together."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "get_agent_events",
        "description": (
            "Get recent security events from a specific asset's Citadel Shield "
            "agent. Returns threat type, severity, detail, and actions taken."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "asset_id": {
                    "type": "string",
                    "description": "The asset ID to query events for.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max events to return (default 20).",
                },
            },
            "required": ["asset_id"],
        },
    },
    {
        "name": "deploy_agent",
        "description": (
            "Deploy the Citadel Shield protection agent to a VPS asset. "
            "Requires Guardian or Sentinel security level. The asset must "
            "have an SSH credential linked."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "asset_id": {
                    "type": "string",
                    "description": "The asset ID to deploy the agent to.",
                },
            },
            "required": ["asset_id"],
        },
    },
    {
        "name": "get_vps_summary",
        "description": (
            "Get an overview of all enrolled security agents: citadel_daemon agents "
            "(vps/cloud type enrolled via one-liner) appear under enrolled_agents. "
            "Use get_daemon_threats() to see what those daemons have actually found. "
            "SSH-deployed Shield agents appear under shield_daemon_agents."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "get_daemon_threats",
        "description": (
            "Get security findings reported by enrolled Citadel Daemon agents "
            "(Linux VPS/cloud machines running citadel_daemon.py). Covers all "
            "daemon sensors: auth_log (SSH brute force, failed logins), processes "
            "(crypto miners, high CPU, suspicious ports), cron (tampered jobs), "
            "file_integrity (changed system files), patches (pending updates). "
            "Use this whenever the user asks about VPS security, what the daemon "
            "found, remote threats, or patch status. Optionally filter by agent_id."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "Filter to one daemon's agent_id (optional).",
                },
                "limit": {
                    "type": "integer",
                    "description": "Max events to return (default 30).",
                },
            },
            "required": [],
        },
    },
    {
        "name": "execute_defensive_action",
        "description": (
            "Execute a pre-approved defensive response on one or more enrolled daemon agents. "
            "Low-risk actions (kill_process, block_ip, disable_cron_job, collect_forensics) "
            "execute automatically on the next heartbeat. Medium-risk actions "
            "(rotate_ssh_keys, restart_service, apply_patches, harden_vps) are queued for user "
            "approval first. Supports distributed response via the 'assets' parameter — "
            "use assets=[\"all\"] to target every enrolled daemon at once (e.g. block an "
            "attacker IP across all machines). Use get_defensive_playbook() first. "
            "NEVER use this for offensive operations."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "asset_id": {
                    "type": "string",
                    "description": (
                        "Single target: daemon agent_id, hostname, or asset name. "
                        "Use get_vps_summary() to list valid agents. "
                        "Omit when using 'assets' for multi-target dispatch."
                    ),
                },
                "assets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Multi-target list: array of agent_ids, hostnames, or names. "
                        "Use [\"all\"] to target every enrolled daemon. "
                        "Ideal for distributed blocks (block attacker IP everywhere). "
                        "If provided, takes precedence over asset_id."
                    ),
                },
                "action_id": {
                    "type": "string",
                    "description": (
                        "Action to execute. One of: kill_process, block_ip, "
                        "disable_cron_job, collect_forensics, "
                        "restart_service, apply_patches, harden_vps. "
                        "NOTE: rotate_ssh_keys is NOT available — for SSH key "
                        "rotation direct the user to the Assets UI 'Rotate' button."
                    ),
                },
                "parameters": {
                    "type": "object",
                    "description": "Action parameters (e.g. {pid: 1234} for kill_process).",
                },
                "threat_id": {
                    "type": "string",
                    "description": "Optional: the threat event that triggered this action.",
                },
                "require_approval": {
                    "type": "boolean",
                    "description": (
                        "Override approval requirement. Cannot disable approval "
                        "for medium-risk actions."
                    ),
                },
            },
            "required": ["action_id"],
        },
    },
    {
        "name": "get_defensive_playbook",
        "description": (
            "Get the list of all pre-approved defensive actions with their risk "
            "levels, approval requirements, and parameter definitions. Use this "
            "before execute_defensive_action to confirm the action exists and check "
            "what parameters are needed."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "action_id": {
                    "type": "string",
                    "description": "Return details for a specific action only (optional).",
                },
            },
            "required": [],
        },
    },
    {
        "name": "get_action_history",
        "description": (
            "Get the audit trail of defensive actions executed (or pending/denied) "
            "on daemon agents. Shows action_id, status (queued/sent/success/failed/"
            "pending_approval/denied), target agent, parameters, timestamps, and "
            "execution results. Use this to check if a previous action succeeded."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "asset_id": {
                    "type": "string",
                    "description": "Filter to a specific agent_id (optional).",
                },
                "action_id": {
                    "type": "string",
                    "description": "Filter to a specific action type (optional).",
                },
                "status": {
                    "type": "string",
                    "description": (
                        "Filter by status: queued, sent, success, failed, "
                        "pending_approval, denied (optional)."
                    ),
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results to return (default 20).",
                },
            },
            "required": [],
        },
    },
    {
        "name": "get_local_events",
        "description": (
            "Get recent security events from the local Guardian (file monitor, "
            "process monitor) on this Windows machine. Returns event type, "
            "severity, timestamp, message, and file path when available. "
            "Use this when the user asks about local file changes, process "
            "activity, or when a Local Guardian alert has been escalated."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Max events to return (default 20, max 100).",
                },
                "severity": {
                    "type": "string",
                    "description": (
                        "Filter by minimum severity: 'info', 'warning', 'alert', "
                        "'critical'. Omit to return all severities."
                    ),
                },
            },
            "required": [],
        },
    },
    {
        "name": "read_memory_log",
        "description": (
            "Read the full content of a past session memory log. "
            "The Past Session Memory index in your system prompt lists available "
            "log filenames and 2-sentence summaries. Call this when you need full "
            "detail from a past session — e.g. the user references something that "
            "happened before, or you need to recall a specific IP, hostname, "
            "threat finding, or action taken in a prior conversation."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "filename": {
                    "type": "string",
                    "description": (
                        "The memory log filename from the index "
                        "(e.g. 'session_20260221_143000.md')."
                    ),
                },
            },
            "required": ["filename"],
        },
    },
    {
        "name": "hostinger_vps_action",
        "description": (
            "Directly manage VPS servers via the Hostinger REST API. "
            "Use this when: a daemon is unreachable and you need to check or reboot "
            "the underlying VPS; the user asks about VPS resource usage (CPU/RAM/disk); "
            "you need to list all Hostinger VPS to find one by hostname. "
            "Requires a Hostinger API key in Settings > Integrations."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["list", "status", "metrics", "reboot"],
                    "description": (
                        "list=enumerate all VPS (no vps_id needed); "
                        "status=get state and IPs for one VPS; "
                        "metrics=CPU/RAM/disk for one VPS; "
                        "reboot=hard-restart one VPS via Hostinger API (immediate, no approval)."
                    ),
                },
                "vps_id": {
                    "type": "integer",
                    "description": (
                        "Hostinger VPS numeric ID. Required for status/metrics/reboot. "
                        "Omit for list. Use list first if you don't know the ID."
                    ),
                },
            },
            "required": ["action"],
        },
    },
    {
        "name": "mark_event_resolved",
        "description": (
            "Mark a security event as resolved after taking a defensive action. "
            "Call this AFTER successfully blocking an IP, killing a process, patching a vuln, "
            "or any other remediation so the user can see the resolution status in the timeline "
            "and threat views. The original severity badge is preserved; a green chip shows "
            "the action taken and timestamp. "
            "Use source='local' for EventAggregator events, 'remote-shield' for daemon threats, "
            "'correlation' for cross-asset correlation events."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "event_id": {
                    "type": "string",
                    "description": "Event UUID (from EventAggregator) or threat ID (from daemon).",
                },
                "source": {
                    "type": "string",
                    "enum": ["local", "remote-shield", "correlation"],
                    "description": "Which event source this ID belongs to.",
                },
                "action_taken": {
                    "type": "string",
                    "description": (
                        "Short label for the action taken, e.g. 'block_ip', 'kill_process', "
                        "'apply_patches', 'quarantine_file', 'update_firewall'."
                    ),
                },
                "notes": {
                    "type": "string",
                    "description": "Optional detail about what was done (shown in detail panel).",
                },
            },
            "required": ["event_id", "source", "action_taken"],
        },
    },
    {
        "name": "execute_ssh_command",
        "description": (
            "Execute a shell command on a managed asset. "
            "Remote assets use SSH; the local host machine (platform=local, asset_id='localhost') "
            "uses subprocess — NO SSH credential needed for localhost. "
            "Use for investigation (logs, processes, network, disk, system info) and "
            "defensive actions (kill processes, block IPs, modify firewall, create/delete files). "
            "Read-only commands (Get-Process, ps, df, journalctl, Get-NetTCPConnection, etc.) "
            "execute immediately. "
            "Write/modify commands (New-Item, Set-Content, Remove-Item, systemctl, rm, kill, "
            "iptables -A/D) are automatically routed to an approval flow — call this tool and "
            "an approval card will appear in chat for the user to confirm before execution."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "asset_id": {
                    "type": "string",
                    "description": "Asset ID, hostname, or name. Use get_asset_list() if unsure.",
                },
                "command": {
                    "type": "string",
                    "description": "Shell command to run (e.g. 'journalctl -u citadel-daemon -n 50').",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Seconds before abort (default 30, max 120).",
                },
                "justification": {
                    "type": "string",
                    "description": "Why this command is needed — recorded in audit trail.",
                },
            },
            "required": ["asset_id", "command"],
        },
        # cache_control on the LAST tool caches all tool definitions up to this point.
        # The Anthropic API caches the entire tools block (2000+ static tokens) on
        # every call after the first, reducing input token costs by ~85% on tools.
        "cache_control": {"type": "ephemeral"},
    },
]


# ── AI Bridge Class ────────────────────────────────────────────────────


class AIBridge:
    """Connects SecureChat to the AI Brain (Claude API).

    Listens for messages needing AI attention, builds context,
    calls Claude with tools, routes responses back through chat.

    Args:
        chat_manager: The ChatManager instance to listen on and send through.
        api_key: Anthropic API key. Falls back to ANTHROPIC_API_KEY env var.
        model: Claude model to use. Falls back to CITADEL_AI_MODEL env var.
    """

    def __init__(
        self,
        chat_manager: "ChatManager",
        api_key: Optional[str] = None,
        model: Optional[str] = None,
    ):
        self._chat = chat_manager
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._model = model or os.environ.get(
            "CITADEL_AI_MODEL", "claude-sonnet-4-5-20250929"
        )
        self._client = None
        self._enabled = False
        self._processing = False  # one-at-a-time guard
        self._pending_msgs: "deque[ChatMessage]" = __import__("collections").deque(maxlen=20)
        self._shield_db = None  # cached RemoteShieldDatabase instance
        self._last_call_meta: Dict[str, Any] = {}  # model + token info for last AI call

        # Ollama local LLM backend (fallback when Claude is unavailable)
        self._ollama = None
        self._active_backend = "none"  # "claude", "ollama", or "none"
        self._current_task: Optional[asyncio.Task] = None  # track in-flight task
        self._compactor = None  # MemoryCompactor — set after Claude client is ready

        if self._api_key:
            try:
                import anthropic

                self._client = anthropic.AsyncAnthropic(api_key=self._api_key)
                self._enabled = True
                self._active_backend = "claude"
                logger.info("AI Bridge initialized (model=%s)", self._model)
                # Memory compactor requires the Anthropic client
                from .memory_compactor import MemoryCompactor
                self._compactor = MemoryCompactor(self._client, chat_manager.store)
            except ImportError:
                logger.warning(
                    "anthropic package not installed — run: pip install anthropic. "
                    "Trying Ollama fallback."
                )

        # Initialize Ollama backend (always, for fallback or primary use)
        try:
            from .ollama_backend import OllamaBackend
            ollama_url = os.environ.get("OLLAMA_URL", "http://localhost:11434")

            # SECURITY: Only allow localhost connections by default.
            # Remote Ollama servers must be explicitly allowed via env var.
            if not _is_localhost_url(ollama_url):
                allow_remote = os.environ.get("OLLAMA_ALLOW_REMOTE", "").lower()
                if allow_remote not in ("1", "true", "yes"):
                    logger.warning(
                        "Ollama URL %s is not localhost. Set OLLAMA_ALLOW_REMOTE=1 "
                        "to allow remote connections. Ollama disabled for security.",
                        ollama_url,
                    )
                    ollama_url = None

            if ollama_url:
                self._ollama = OllamaBackend(base_url=ollama_url)
                if not self._enabled:
                    # No Claude API — Ollama is primary
                    self._enabled = True
                    self._active_backend = "ollama"
                    logger.info(
                        "AI Bridge initialized with Ollama fallback (url=%s)",
                        ollama_url,
                    )
                else:
                    logger.info("Ollama backend available as fallback (url=%s)", ollama_url)
        except Exception:
            logger.debug("Ollama backend not available", exc_info=True)

        if not self._enabled:
            logger.info(
                "No AI backend configured. AI Bridge disabled. "
                "Set ANTHROPIC_API_KEY or install Ollama to enable AI responses."
            )

        # Register as the completion notification handler so API routes can
        # push action results back to Guardian without circular imports.
        try:
            from ..agent.guardian_notifications import register_handler
            register_handler(self._on_completion_event)
        except Exception:
            logger.debug("Could not register guardian notification handler", exc_info=True)

    # ── Properties ─────────────────────────────────────────────────────

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def active_backend(self) -> str:
        """Current active AI backend: 'claude', 'ollama', or 'none'."""
        return self._active_backend

    async def ollama_status(self) -> Dict[str, Any]:
        """Return Ollama backend status for API display."""
        if self._ollama is None:
            return {"available": False, "reason": "Ollama backend not initialized"}
        return await self._ollama.status()

    async def set_ollama_model(self, model: str) -> Dict[str, Any]:
        """Switch the Ollama model. Validates the model exists first."""
        if self._ollama is None:
            return {"error": "Ollama backend not initialized"}
        # Validate model exists locally before switching
        if not await self._ollama.has_model(model):
            available = await self._ollama.list_models()
            return {
                "error": f"Model '{model}' not found locally",
                "available": [m.name for m in available],
            }
        old = self._ollama.model
        self._ollama.model = model
        logger.info("Ollama model changed: %s -> %s", old, model)
        return {"previous": old, "current": model}

    async def list_ollama_models(self) -> Dict[str, Any]:
        """List available Ollama models for API display."""
        if self._ollama is None:
            return {"models": [], "current": None}
        models = await self._ollama.list_models()
        return {
            "models": [m.to_dict() for m in models],
            "current": self._ollama.model,
        }

    # ── Registration ───────────────────────────────────────────────────

    def register(self):
        """Register as a wildcard listener on ChatManager."""
        if not self._enabled:
            return
        self._chat.subscribe("*", self._on_message)
        logger.info("AI Bridge registered on ChatManager")

    def interrupt(self) -> bool:
        """Cancel the current AI processing task (user-requested stop).

        Returns True if a task was actually cancelled, False if nothing was running.
        """
        task = self._current_task
        if task and not task.done():
            task.cancel()
            logger.info("AI Bridge: processing interrupted by user")
            return True
        return False

    # ── Message Handler ────────────────────────────────────────────────

    async def _on_message(self, msg: ChatMessage):
        """Decide if a message needs AI attention, dispatch if so."""
        # Never respond to our own messages (prevents loops)
        if msg.from_id == PARTICIPANT_ASSISTANT:
            return

        # ── IMPORTANT: check needs_ai BEFORE the _processing guard ──────
        # The processing guard queues messages for later. We must filter first
        # so that system-generated messages (approval cards, SSH results) are
        # never queued and re-triggered as new AI calls.
        needs_ai = False

        # 1. User sent plain text (not a command — commands already handled)
        if msg.from_id == PARTICIPANT_USER and msg.msg_type == MessageType.TEXT:
            needs_ai = True

        # Check Do Not Disturb once — applies to all non-user triggers
        try:
            from ..core.user_preferences import get_user_preferences
            _dnd_muted = get_user_preferences().get("guardian_muted", "false") == "true"
        except Exception:
            _dnd_muted = False

        # 2. Agent escalation event (critical/high posted by poller)
        if msg.from_id == PARTICIPANT_CITADEL and msg.msg_type == MessageType.EVENT:
            if not _dnd_muted:
                text = (msg.text or "").lower()
                if "critical" in text or "high" in text:
                    needs_ai = True
            # Completion events pierce DND — the user already approved the action
            # and must always receive a follow-up analysis (success or failure)
            if msg.payload.get("action_type") == "completion_event":
                needs_ai = True

        # 3. External AI agent sent a text message (Trigger 1b)
        if msg.from_id.startswith("ext-agent:") and msg.msg_type == MessageType.TEXT:
            if not _dnd_muted:
                needs_ai = True

        if not needs_ai:
            return  # No AI needed — discard silently, never queue

        # If already processing, queue for later (only messages that need AI)
        if self._processing:
            self._pending_msgs.append(msg)
            return

        # SCS token quota check — prevent budget exhaustion
        from .scs_quota import get_scs_quota_tracker

        quota = get_scs_quota_tracker()
        estimated = quota.estimate_tokens(msg.text or "")
        allowed, info = quota.check(msg.from_id, estimated_tokens=estimated)
        if not allowed:
            logger.warning(
                "SCS quota exceeded for %s: %s", msg.from_id, info["reason"]
            )
            try:
                await self._chat.send_system(
                    f"[Rate limit] {info['reason']} Try again in a few minutes."
                )
            except Exception:
                pass  # best-effort notification
            return

        # Show thinking indicator immediately — response may take 5-30s
        self._broadcast_thinking(True, "Analyzing...")

        # Process in background to avoid blocking the listener pipeline
        self._current_task = asyncio.create_task(self._process(msg))

    # ── Core Processing Loop ───────────────────────────────────────────

    async def _process(self, trigger: ChatMessage):
        """Build context → call Claude → handle response."""
        self._processing = True
        _interrupted = False
        try:
            # 1. Gather system state
            state = self._gather_system_state()

            # 1b. Check if memory compaction is needed (token threshold exceeded)
            if self._compactor and self._compactor.should_compact():
                self._broadcast_thinking(True, "Compacting memory...")
                await self._compactor.compact()

            # 2. Build conversation history in Claude message format
            # Exclude the trigger message (it's appended separately below)
            history = self._build_history(exclude_id=trigger.id)

            # 3. Append the trigger message
            trigger_text = trigger.text or json.dumps(trigger.payload)
            if trigger.from_id == PARTICIPANT_CITADEL:
                trigger_text = f"[System escalation — {trigger.msg_type.value}] {trigger_text}"
            history.append({"role": "user", "content": trigger_text})

            # 3b. Tier 0 — zero-inference fast path (user messages only).
            # System escalations and agent messages always need AI reasoning.
            if trigger.from_id == PARTICIPANT_USER:
                t0 = self._tier0_response(trigger.text or "", state)
                if t0 is not None:
                    ai_msg = ChatMessage(
                        from_id=PARTICIPANT_ASSISTANT,
                        to_id=PARTICIPANT_USER,
                        msg_type=MessageType.RESPONSE,
                        payload={"text": t0},
                    )
                    await self._chat.send(ai_msg)
                    return  # no API call

            # 4. Build system prompt (static base + per-call dynamic tail)
            security_level = state.get("security_level", "guardian")
            from .memory_compactor import load_memory_index
            memory_index = load_memory_index()
            memory_section = memory_index if memory_index else "(No past sessions recorded yet.)"
            system = _SYSTEM_BASE + _SYSTEM_DYNAMIC.substitute(
                security_level=security_level.title(),
                system_state=self._format_state(state),
                memory_index=memory_section,
            )

            # 5. Determine trigger type for audit logging + select inference tier
            selected_model: Optional[str] = None
            if trigger.from_id == PARTICIPANT_USER:
                trigger_type = "user_text"
                selected_model = self._select_model(trigger.text or "", state)
                logger.debug("Inference tier: %s", selected_model)
                # Refine the thinking indicator with the actual tier being used
                if selected_model == _MODEL_SONNET:
                    self._broadcast_thinking(True, "Running deep analysis (Sonnet)...")
                else:
                    self._broadcast_thinking(True, "Analyzing (Haiku)...")
            elif trigger.from_id.startswith("ext-agent:"):
                trigger_type = "agent_text"
            else:
                trigger_type = "citadel_event"

            # 6. Call Claude with tool loop (model=None → Sonnet for escalations/agents)
            final_text = await self._call_with_tools(
                system, history, trigger_type, trigger.id,
                participant_id=trigger.from_id,
                model=selected_model,
            )

            # 7. Send AI response to chat (include model + token info for display)
            if final_text:
                ai_msg = ChatMessage(
                    from_id=PARTICIPANT_ASSISTANT,
                    to_id=PARTICIPANT_USER,
                    msg_type=MessageType.RESPONSE,
                    payload={"text": final_text, **self._last_call_meta},
                )
                await self._chat.send(ai_msg)

        except asyncio.CancelledError:
            _interrupted = True
            # Notify user via a new fire-and-forget task (safe after cancel)
            asyncio.ensure_future(self._chat.send_system("Stopped."))
            raise  # must propagate so asyncio knows the task was cancelled
        except asyncio.TimeoutError:
            logger.warning("AI Bridge: Claude API call timed out")
            try:
                await self._chat.send_system(
                    "AI assistant timed out. Try again or check your connection."
                )
            except Exception:
                pass
        except Exception:
            logger.exception("AI Bridge processing error")
            try:
                await self._chat.send_system(
                    "AI assistant encountered an error. Check logs for details."
                )
            except Exception:
                pass
        finally:
            self._processing = False
            self._current_task = None
            self._broadcast_thinking(False)
            # Don't auto-process queued messages after a user interrupt
            if not _interrupted:
                if self._pending_msgs:
                    asyncio.create_task(self._process(self._pending_msgs.popleft()))
            else:
                self._pending_msgs.clear()

    # ── Context Building ───────────────────────────────────────────────

    def _gather_system_state(self) -> Dict[str, Any]:
        """Snapshot current system state for the AI context."""
        state: Dict[str, Any] = {}

        # Security level
        try:
            from ..core import get_security_manager

            state["security_level"] = get_security_manager().current_level.value
        except Exception:
            state["security_level"] = "guardian"

        # Threat level + uptime
        try:
            from ..api.main import _calculate_threat_level, _format_uptime

            state["threat_level"] = _calculate_threat_level()
            state["uptime"] = _format_uptime()
        except Exception:
            state["threat_level"] = "unknown"
            state["uptime"] = "unknown"

        # Managed assets (summary only — details available via tools)
        asset_list = []
        try:
            from ..api.asset_routes import get_inventory

            for a in get_inventory().all():
                asset_list.append({
                    "id": a.asset_id,
                    "name": a.name,
                    "ip": a.ip_address,
                    "type": getattr(a, "asset_type", "unknown"),
                    "status": getattr(a.status, "value", str(a.status)),
                    "has_shield_daemon": bool(getattr(a, "remote_shield_agent_id", None)),
                    "source": "inventory",
                })
        except Exception:
            pass

        # AI agents (AgentRegistry) are NOT assets — they are participants.
        # Per PRD: one asset = one managed_assets record. AI agents appear in
        # get_vps_summary() under enrolled_agents, not in the asset list.

        state["assets"] = asset_list

        # Enrolled citadel_daemon agents (Shield type: vps/cloud/workstation)
        # shown here so the AI knows about remote machines without a tool call.
        try:
            from ..api.agent_api_routes import get_agent_registry
            _shield_types = {"vps", "cloud", "workstation"}
            state["enrolled_daemons"] = [
                {
                    "name":     a.get("name", a["agent_id"]),
                    "hostname": a.get("hostname") or "",
                    "type":     a.get("agent_type"),
                    "last_seen": a.get("last_seen") or a.get("enrolled_at", ""),
                }
                for a in get_agent_registry().list_agents()
                if a.get("agent_type") in _shield_types
                and a.get("status") != "revoked"
            ]
        except Exception:
            state["enrolled_daemons"] = []

        return state

    def _get_history_char_budget(self) -> int:
        """Return the history char budget for this call.

        Priority:
          1. ai.history_chars preference (user-dialled explicit value)
          2. ai.compaction_tokens × 3.8  (auto-sync: no context gap)
          3. _HISTORY_CHAR_BUDGET module constant (ultimate fallback)

        Auto-sync (priority 2) ensures the history window always covers ALL
        uncompacted messages — context grows until compaction fires rather than
        being silently trimmed by a mismatched budget.
        """
        try:
            from ..core.user_preferences import get_user_preferences
            prefs = get_user_preferences()
            raw = prefs.get("ai.history_chars")
            if raw:
                return max(10_000, min(500_000, int(raw)))
            # Auto-derive from compaction threshold so the two stay in sync
            comp_raw = prefs.get("ai.compaction_tokens")
            if comp_raw:
                comp_tokens = max(20_000, min(500_000, int(comp_raw)))
                return int(comp_tokens * 3.8)
        except Exception:
            pass
        return _HISTORY_CHAR_BUDGET

    def _build_history(self, exclude_id: Optional[str] = None) -> List[Dict[str, str]]:
        """Convert chat messages to Claude's alternating message format.

        Includes ALL uncompacted messages up to _HISTORY_CHAR_BUDGET characters,
        ensuring Guardian has full continuity after a restart without silently
        dropping context. Once the compaction threshold is hit, compaction fires
        and future calls use [summary] + all post-compaction messages within budget.

        Claude requires: user/assistant messages alternating, starting with user.
        System messages are prefixed with [System] and folded into user turns.
        Consecutive same-role messages are merged.

        Args:
            exclude_id: Message ID to exclude (the trigger message, which is
                        appended separately to avoid duplication).
        """
        # --- Compacted history path ---
        if self._compactor:
            summary = self._compactor.get_latest_summary()
            if summary:
                marker_ts = self._compactor.get_latest_marker_timestamp()
                return self._build_compacted_history(summary, marker_ts, exclude_id)

        # --- Full history path (no compaction yet) ---
        # Use all messages since the beginning (get_messages_for_compaction returns
        # the full history when no compaction marker exists), trimmed to budget.
        all_msgs = self._chat.store.get_messages_for_compaction()
        if exclude_id:
            all_msgs = [m for m in all_msgs if m.id != exclude_id]
        trimmed = _trim_to_char_budget(all_msgs, self._get_history_char_budget())
        return self._format_messages_for_claude(trimmed)

    def _build_compacted_history(
        self,
        summary: str,
        marker_ts: Optional[str],
        exclude_id: Optional[str],
    ) -> List[Dict[str, str]]:
        """Build history as [summary_context] + all post-compaction messages within budget.

        Includes every message since the last compaction marker up to
        _HISTORY_CHAR_BUDGET characters, so Guardian never has a blind spot
        between compaction events.
        """
        if marker_ts:
            recent = self._chat.store.get_messages_for_compaction()
        else:
            recent = self._chat.get_recent(limit=500)

        # Filter: exclude compaction markers and the trigger message
        recent = [
            m for m in recent
            if not m.payload.get("compaction_summary")
            and m.id != exclude_id
        ]

        # Trim to budget (most-recent messages within character limit)
        recent = _trim_to_char_budget(recent, self._get_history_char_budget())

        # Bootstrap with summary as framing context
        merged: List[Dict[str, str]] = [
            {
                "role": "user",
                "content": (
                    "[Previous conversation summary — use this as full context]\n"
                    f"{summary}"
                ),
            },
            {
                "role": "assistant",
                "content": (
                    "Understood. I have full context from the previous session "
                    "and am ready to continue."
                ),
            },
        ]

        # Append the recent messages using the shared formatter
        for entry in self._format_messages_for_claude(recent):
            if merged and merged[-1]["role"] == entry["role"]:
                merged[-1]["content"] += f"\n{entry['content']}"
            else:
                merged.append(entry)

        # Ensure we don't end on assistant
        if merged and merged[-1]["role"] == "assistant":
            merged.append({"role": "user", "content": "[Awaiting new input]"})

        return merged

    def _format_messages_for_claude(
        self, messages: List
    ) -> List[Dict[str, str]]:
        """Convert a list of ChatMessages to Claude's {role, content} format.

        Merges consecutive same-role entries and ensures the sequence starts
        with a user turn.
        """
        raw: List[Dict[str, str]] = []

        for msg in messages:
            text = msg.text or json.dumps(msg.payload)

            if msg.from_id == PARTICIPANT_ASSISTANT:
                role = "assistant"
            elif msg.from_id == PARTICIPANT_USER:
                role = "user"
            else:
                role = "user"
                label = "System"
                if msg.from_id.startswith("ext-agent:"):
                    label = f"ExtAgent {msg.payload.get('agent_name', msg.from_id[10:])}"
                elif msg.from_id.startswith("agent:"):
                    label = f"Agent {msg.from_id[6:]}"
                text = f"[{label}: {msg.msg_type.value}] {text}"

            raw.append({"role": role, "content": text})

        merged: List[Dict[str, str]] = []
        for entry in raw:
            if merged and merged[-1]["role"] == entry["role"]:
                merged[-1]["content"] += f"\n{entry['content']}"
            else:
                merged.append(dict(entry))

        if merged and merged[0]["role"] != "user":
            merged.insert(0, {"role": "user", "content": "[Chat history begins]"})

        if merged and merged[-1]["role"] == "assistant":
            merged.append({"role": "user", "content": "[Awaiting new input]"})

        return merged

    def _format_state(self, state: Dict[str, Any]) -> str:
        """Render system state as concise text for the system prompt."""
        lines = [
            f"Threat Level: {state.get('threat_level', 'unknown')}",
            f"Server Uptime: {state.get('uptime', 'unknown')}",
        ]

        assets = state.get("assets", [])
        if assets:
            lines.append(f"Managed Assets ({len(assets)}):")
            for a in assets:
                agent = "agent deployed" if a.get("has_agent") else "no agent"
                lines.append(
                    f"  - {a['name']} ({a['ip']}) — {a['status']}, {agent}"
                )
        else:
            lines.append("Managed Assets: none")

        daemons = state.get("enrolled_daemons", [])
        if daemons:
            lines.append(f"Enrolled Citadel Daemons ({len(daemons)}):")
            for d in daemons:
                lines.append(
                    f"  - {d['name']} ({d.get('type', 'vps')}) "
                    f"hostname={d.get('hostname', '?')} "
                    f"last_seen={d.get('last_seen', 'never')}"
                )
            lines.append(
                "  Use get_daemon_threats() to see what these daemons have found."
            )

        return "\n".join(lines)

    # ── Inference Tier Routing ───────────────────────────────────────────

    def _tier0_response(self, text: str, state: dict) -> Optional[str]:
        """Try to answer with a template response (no AI inference).

        Returns a formatted string if the query matches a Tier 0 pattern,
        or None if the query needs AI reasoning.
        """
        for pattern, handler in _TIER0_RULES:
            if pattern.match(text):
                return handler(state)
        return None

    def _broadcast_thinking(self, active: bool, detail: str = "") -> None:
        """Push a chat_thinking event to all WebSocket clients.

        active=True  — show thinking indicator with optional detail text.
        active=False — hide indicator (analysis complete or failed).

        Best-effort: never raises, never blocks.
        """
        if not self._chat._ws_broadcast:
            return
        try:
            payload = {"type": "chat_thinking", "active": active, "detail": detail}
            result = self._chat._ws_broadcast(payload)
            if asyncio.iscoroutine(result):
                asyncio.ensure_future(result)
        except Exception:
            pass

    def _select_model(self, text: str, state: dict) -> str:
        """Choose Haiku or Sonnet based on query complexity.

        Tier 2 (Sonnet) — complex multi-event analysis, investigation keywords,
            or high-severity escalations with active threat context.
        Tier 1 (Haiku) — everything else that reaches the AI.
        """
        text_lower = text.lower()

        # Sonnet for queries with investigation / correlation keywords
        if any(kw in text_lower for kw in _SONNET_KEYWORDS):
            return _MODEL_SONNET

        # Sonnet when the system is under active threat and user is asking
        # about alerts, events, or threats — context matters
        if state.get("threat_level") in ("critical", "high") and any(
            kw in text_lower for kw in ("alert", "threat", "critical", "high", "event")
        ):
            return _MODEL_SONNET

        return _MODEL_HAIKU

    # ── Claude API Call with Tool Loop ──────────────────────────────────

    async def _call_with_tools(
        self,
        system: str,
        messages: List[Dict],
        trigger_type: str = "unknown",
        trigger_message_id: str = "",
        participant_id: str = "user",
        model: Optional[str] = None,
    ) -> Optional[str]:
        """Call AI backend with tool loop. Tries Claude first, falls back to Ollama.

        Backend priority:
          1. Claude API (cloud) — if API key configured and client available
          2. Ollama (local) — fallback when Claude fails or unavailable

        SECURITY: All Ollama calls are audit-logged. Sensitive data (secrets,
        keys) must never appear in messages — this is enforced upstream by
        the system prompt rules and tool handlers.
        """
        audit = get_ai_audit_logger()
        from .scs_quota import get_scs_quota_tracker

        quota = get_scs_quota_tracker()
        self._last_call_meta = {}  # reset so failed calls never leak previous metadata

        # -- Try Claude first --
        if self._client:
            result = await self._call_claude(
                system, messages, trigger_type, trigger_message_id,
                participant_id, audit, quota,
                model=model,
            )
            if result is not None:
                return result
            # Claude failed — try Ollama fallback
            if self._ollama:
                logger.info("Claude API failed, falling back to Ollama")

        # -- Ollama fallback (or primary if no Claude) --
        if self._ollama:
            result = await self._call_ollama(
                system, messages, trigger_type, trigger_message_id,
                participant_id, audit, quota,
            )
            return result

        return None

    async def _call_claude(
        self,
        system: str,
        messages: List[Dict],
        trigger_type: str,
        trigger_message_id: str,
        participant_id: str,
        audit,
        quota,
        model: Optional[str] = None,
    ) -> Optional[str]:
        """Call Claude API with tool loop. Returns text or None on failure.

        Args:
            model: Override the default model for this call. None → self._model.
                   Pass _MODEL_HAIKU for Tier 1 or _MODEL_SONNET for Tier 2.
        """
        _model = model or self._model

        # Build cached system blocks: static base is tagged cache_control so the
        # Anthropic API can cache it across calls.  Dynamic tail (state/memory)
        # always changes so it is sent uncached as a second block.
        _api_system = [
            {
                "type": "text",
                "text": _SYSTEM_BASE,
                "cache_control": {"type": "ephemeral"},
            },
            {
                "type": "text",
                "text": system[len(_SYSTEM_BASE):],
            },
        ]

        try:
            ctx = audit.start_call(trigger_type, trigger_message_id, _model, 0)
            try:
                response = await asyncio.wait_for(
                    self._client.messages.create(
                        model=_model,
                        max_tokens=8192,
                        system=_api_system,
                        messages=messages,
                        tools=TOOLS,
                    ),
                    timeout=90,
                )
                record = audit.finish_call(ctx, response=response)
                if record:
                    quota.record(participant_id, record.total_tokens)
            except Exception as exc:
                audit.finish_call(ctx, error=type(exc).__name__)
                raise

            # Tool use loop — Claude may call tools before giving final answer
            max_iterations = 20  # raised from 5 to support multi-step approval chains
            _TOOL_LOOP_MAX_SECONDS = 1800  # 30-min hard ceiling (covers long downloads)
            iteration = 0
            _loop_start = asyncio.get_event_loop().time()

            while response.stop_reason == "tool_use" and iteration < max_iterations:
                iteration += 1

                # Elapsed-time guard — prevent infinite loops on runaway chains
                if asyncio.get_event_loop().time() - _loop_start > _TOOL_LOOP_MAX_SECONDS:
                    logger.warning(
                        "Tool loop exceeded %ds total time budget after %d iterations",
                        _TOOL_LOOP_MAX_SECONDS, iteration,
                    )
                    break

                # Re-check quota before each tool-loop API call
                allowed, _qinfo = quota.check(participant_id, estimated_tokens=2000)
                if not allowed:
                    logger.warning(
                        "SCS quota exhausted during tool loop for %s",
                        participant_id,
                    )
                    break

                # Execute each tool call
                tool_results = []
                for block in response.content:
                    if block.type == "tool_use":
                        logger.info(
                            "AI tool call: %s(%s)", block.name, block.input
                        )
                        result = await self._execute_tool(block.name, block.input)
                        tool_results.append(
                            {
                                "type": "tool_result",
                                "tool_use_id": block.id,
                                "content": json.dumps(result, default=str),
                            }
                        )

                # Continue conversation with tool results
                messages = messages + [
                    {"role": "assistant", "content": response.content},
                    {"role": "user", "content": tool_results},
                ]

                ctx = audit.start_call(
                    "tool_loop", trigger_message_id, _model, iteration
                )
                try:
                    response = await asyncio.wait_for(
                        self._client.messages.create(
                            model=_model,
                            max_tokens=8192,
                            system=_api_system,
                            messages=messages,
                            tools=TOOLS,
                        ),
                        timeout=90,
                    )
                    record = audit.finish_call(ctx, response=response)
                    if record:
                        quota.record(participant_id, record.total_tokens)
                except Exception as exc:
                    audit.finish_call(ctx, error=type(exc).__name__)
                    raise

            # Extract final text from response
            texts = []
            for block in response.content:
                if hasattr(block, "text") and block.text:
                    texts.append(block.text)

            self._active_backend = "claude"
            self._last_call_meta = {
                "model": _model,
                "input_tokens": getattr(response.usage, "input_tokens", None),
                "cache_read_input_tokens": getattr(response.usage, "cache_read_input_tokens", None),
                "cache_creation_input_tokens": getattr(response.usage, "cache_creation_input_tokens", None),
            }
            return "\n".join(texts) if texts else None

        except Exception:
            logger.exception("Claude API call failed")
            return None

    async def _call_ollama(
        self,
        system: str,
        messages: List[Dict],
        trigger_type: str,
        trigger_message_id: str,
        participant_id: str,
        audit,
        quota,
    ) -> Optional[str]:
        """Call Ollama backend with tool loop. Returns text or None on failure.

        SECURITY: Audit-logged identically to Claude calls. The Ollama backend
        only connects to localhost by default (enforced in __init__).
        """
        if not await self._ollama.is_available():
            logger.warning("Ollama backend not available")
            return None

        # Audit log the Ollama call
        ollama_model = self._ollama.model
        ctx = audit.start_call(
            f"ollama_{trigger_type}", trigger_message_id, ollama_model, 0
        )

        try:
            # Convert messages: strip any Claude-specific content blocks
            # (Ollama expects plain {role, content} dicts)
            clean_messages = []
            for m in messages:
                content = m.get("content", "")
                if isinstance(content, list):
                    # Claude tool_result format — flatten to text
                    parts = []
                    for block in content:
                        if isinstance(block, dict):
                            parts.append(block.get("content", str(block)))
                        else:
                            parts.append(str(block))
                    content = "\n".join(parts)
                elif not isinstance(content, str):
                    content = str(content)
                clean_messages.append({"role": m["role"], "content": content})

            # Tool executor for the Ollama tool loop
            async def tool_executor(name, args):
                return await self._execute_tool(name, args)

            response = await self._ollama.chat_with_tools(
                messages=clean_messages,
                system=system,
                tools=TOOLS,
                tool_executor=tool_executor,
                max_iterations=5,
                max_tokens=8192,
                temperature=0.3,
            )

            if response is None:
                audit.finish_call(ctx, error="OllamaNoResponse")
                return None

            # Record token usage for quota
            total_tokens = response.input_tokens + response.output_tokens
            audit.finish_call(ctx, ollama_response={
                "model": response.model,
                "input_tokens": response.input_tokens,
                "output_tokens": response.output_tokens,
            })
            quota.record(participant_id, total_tokens)

            self._active_backend = "ollama"
            self._last_call_meta = {
                "model": response.model,
                "input_tokens": response.input_tokens,
            }
            return response.text

        except Exception:
            logger.exception("Ollama call failed")
            audit.finish_call(ctx, error="OllamaException")
            return None

    # ── Tool Execution ─────────────────────────────────────────────────

    # Human-readable status text for each tool (shown in thinking indicator).
    _TOOL_LABELS: Dict[str, str] = {
        "get_system_status":        "Checking system status...",
        "get_asset_list":           "Fetching asset inventory...",
        "get_agent_events":         "Pulling security events...",
        "deploy_agent":             "Deploying agent...",
        "get_vps_summary":          "Gathering VPS summary...",
        "get_daemon_threats":       "Pulling daemon threat reports...",
        "execute_defensive_action": "Executing defensive action...",
        "get_defensive_playbook":   "Loading defensive playbook...",
        "get_action_history":       "Pulling action history...",
        "get_local_events":         "Reading local event log...",
        "read_memory_log":          "Reading memory log...",
        "hostinger_vps_action":     "Querying Hostinger API...",
        "mark_event_resolved":      "Recording resolution...",
        "execute_ssh_command":      "Running SSH command...",
    }

    async def _execute_tool(self, name: str, tool_input: Dict) -> Any:
        """Dispatch a tool call to the appropriate handler."""
        self._broadcast_thinking(True, self._TOOL_LABELS.get(name, f"Running {name}..."))
        handlers = {
            "get_system_status":        self._tool_system_status,
            "get_asset_list":           self._tool_asset_list,
            "get_agent_events":         self._tool_agent_events,
            "deploy_agent":             self._tool_deploy_agent,
            "get_vps_summary":          self._tool_vps_summary,
            "get_daemon_threats":       self._tool_daemon_threats,
            "execute_defensive_action": self._tool_execute_defensive_action,
            "get_defensive_playbook":   self._tool_get_defensive_playbook,
            "get_action_history":       self._tool_get_action_history,
            "get_local_events":         self._tool_local_events,
            "read_memory_log":          self._tool_read_memory_log,
            "hostinger_vps_action":     self._tool_hostinger_vps_action,
            "mark_event_resolved":      self._tool_mark_event_resolved,
            "execute_ssh_command":      self._tool_execute_ssh_command,
        }

        handler = handlers.get(name)
        if not handler:
            return {"error": f"Unknown tool: {name}"}

        try:
            return await handler(tool_input)
        except Exception as exc:
            logger.warning("Tool %s failed: %s", name, exc)
            return {"error": str(exc)}

    async def _tool_system_status(self, _input: Dict) -> Dict:
        state = self._gather_system_state()
        return {
            "threat_level": state.get("threat_level"),
            "security_level": state.get("security_level"),
            "uptime": state.get("uptime"),
            "asset_count": len(state.get("assets", [])),
        }

    async def _tool_asset_list(self, _input: Dict) -> List[Dict]:
        state = self._gather_system_state()
        return state.get("assets", [])

    def _get_shield_db(self):
        """Lazy-load and cache the RemoteShieldDatabase instance."""
        if self._shield_db is None:
            from ..remote.shield_database import RemoteShieldDatabase
            self._shield_db = RemoteShieldDatabase()
        return self._shield_db

    async def _tool_agent_events(self, tool_input: Dict) -> Dict:
        asset_id = tool_input.get("asset_id", "")
        limit = tool_input.get("limit", 20)

        db = self._get_shield_db()
        agent_id = f"shield_{asset_id}"
        threats = db.list_threats(agent_id=agent_id, limit=limit)
        agent = db.get_agent(agent_id)

        # Severity breakdown
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for t in threats:
            sev = t.get("severity", 5)
            if sev >= 9:
                severity_counts["critical"] += 1
            elif sev >= 7:
                severity_counts["high"] += 1
            elif sev >= 4:
                severity_counts["medium"] += 1
            else:
                severity_counts["low"] += 1

        return {
            "asset_id": asset_id,
            "agent": {
                "agent_id": agent_id,
                "hostname": agent.get("hostname", "") if agent else "",
                "version": agent.get("version", "") if agent else "",
                "last_heartbeat": agent.get("last_heartbeat", "") if agent else "",
                "status": "online" if agent else "unknown",
            },
            "threats": threats,
            "severity_breakdown": severity_counts,
            "total_threats": len(threats),
        }

    async def _tool_deploy_agent(self, tool_input: Dict) -> Dict:
        # Gate by security level
        try:
            from ..core import get_security_manager

            level = get_security_manager().current_level.value
            if level == "observer":
                return {
                    "error": (
                        "Cannot deploy agents in Observer mode. "
                        "Switch to Guardian or Sentinel first."
                    )
                }
        except Exception:
            pass

        asset_id = tool_input.get("asset_id", "")

        from ..api.asset_routes import get_inventory, get_ssh_manager
        from ..remote.agent_deployer import AgentDeployer

        inv = get_inventory()
        asset = inv.get(asset_id)
        if not asset:
            # Check if this is an enrolled AI agent (Tailscale / API-enrolled).
            # Those aren't SSH-managed so AgentDeployer can't reach them, but
            # the user can still deploy the citadel daemon via the one-liner.
            try:
                from ..api.agent_api_routes import get_agent_registry
                enrolled = get_agent_registry().get_agent(asset_id)
                if enrolled:
                    ip = enrolled.get("ip_address") or "unknown"
                    name = enrolled.get("name", asset_id)
                    return {
                        "action": "one_liner_required",
                        "reason": (
                            f"{name} is an API-enrolled AI agent, not an "
                            "SSH-managed asset. To deploy the citadel daemon "
                            "on it, use the one-liner setup script."
                        ),
                        "agent_name": name,
                        "agent_ip": ip,
                        "steps": [
                            "1. Open the Assets tab and create a new invitation "
                            "with type=vps (or workstation) for this machine.",
                            "2. Copy the one-liner command from the invitation modal.",
                            "3. SSH to the machine (or run directly on it) and "
                            "paste the one-liner. It installs and starts the "
                            "citadel daemon automatically.",
                            "4. Verify with: systemctl status citadel-daemon",
                        ],
                    }
            except Exception:
                pass
            return {"error": f"Asset not found: {asset_id}"}

        if not asset.ssh_credential_id:
            return {
                "error": (
                    f"Asset {asset_id} has no SSH credential. "
                    "Use 'add vps <ip>' to onboard it first."
                )
            }

        ssh = get_ssh_manager()
        deployer = AgentDeployer(ssh, chat_manager=self._chat)
        return await deployer.deploy(asset_id)

    async def _tool_vps_summary(self, _input: Dict) -> Dict:
        db = self._get_shield_db()
        shield_agents = db.list_agents()
        all_threats = db.list_threats(status="open", limit=200)

        # Group threats by shield daemon agent
        per_agent = {}
        for a in shield_agents:
            agent_id = a["agent_id"]
            agent_threats = [t for t in all_threats if t.get("agent_id") == agent_id]
            per_agent[a.get("hostname", agent_id)] = {
                "agent_id": agent_id,
                "type": "shield_daemon",
                "last_heartbeat": a.get("last_heartbeat", ""),
                "version": a.get("version", ""),
                "open_threats": len(agent_threats),
                "critical": sum(1 for t in agent_threats if t.get("severity", 0) >= 9),
                "high": sum(1 for t in agent_threats if 7 <= t.get("severity", 0) < 9),
            }

        # Also include enrolled AI agents (claude_code, forge, custom) from
        # AgentRegistry.  These live in a separate store from shield daemons
        # but represent real connected machines the user cares about.
        enrolled: list = []
        try:
            from ..api.agent_api_routes import get_agent_registry
            for agent in get_agent_registry().list_agents():
                if agent.get("status") == "revoked":
                    continue
                enrolled.append({
                    "agent_id": agent["agent_id"],
                    "name": agent.get("name", agent["agent_id"]),
                    "type": agent.get("agent_type", "enrolled"),
                    "status": agent.get("status", "enrolled"),
                    "ip": agent.get("ip_address") or "",
                    "hostname": agent.get("hostname") or "",
                })
        except Exception:
            pass

        return {
            "total_agents": len(shield_agents) + len(enrolled),
            "shield_daemon_agents": len(shield_agents),
            "enrolled_ai_agents": len(enrolled),
            "total_open_threats": len(all_threats),
            "agents": per_agent,
            "enrolled_agents": enrolled,
        }

    async def _tool_daemon_threats(self, tool_input: Dict) -> Dict:
        """Return threat reports from enrolled citadel_daemon agents."""
        limit = min(int(tool_input.get("limit", 30)), 100)
        agent_id_filter = tool_input.get("agent_id", "")

        try:
            from ..core.audit_log import get_audit_logger, EventType
            audit = get_audit_logger()
            raw = audit.query_events(
                event_types=[EventType.REMOTE_THREAT, EventType.REMOTE_PATCH],
                limit=limit * 3,
            )
        except Exception as exc:
            return {"error": str(exc), "threats": [], "total": 0}

        threats = []
        for entry in raw:
            details = entry.get("details", {})
            if details.get("source") != "citadel_daemon":
                continue
            if agent_id_filter and details.get("agent_id") != agent_id_filter:
                continue
            host = details.get("hostname", "unknown")
            threats.append({
                "hostname":    host,
                "agent_id":    details.get("agent_id"),
                "agent_name":  details.get("agent_name", host),
                "type":        details.get("threat_type", entry.get("event_type")),
                "severity":    entry.get("severity"),
                "title":       entry.get("message", "").replace(f"[daemon:{host}] ", ""),
                "timestamp":   entry.get("timestamp"),
                "details":     {k: v for k, v in details.items()
                                if k not in ("source", "agent_id", "agent_name",
                                             "hostname", "threat_type", "severity",
                                             "timestamp")},
            })
            if len(threats) >= limit:
                break

        # Per-host summary
        by_host: Dict[str, Dict] = {}
        for t in threats:
            h = t["hostname"]
            if h not in by_host:
                by_host[h] = {
                    "hostname":    h,
                    "agent_id":    t.get("agent_id"),
                    "agent_name":  t.get("agent_name", h),
                    "total":       0,
                    "critical":    0,
                    "alert":       0,
                    "investigate": 0,
                    "info":        0,
                }
            by_host[h]["total"] += 1
            sev = t.get("severity", "")
            if sev in by_host[h]:
                by_host[h][sev] += 1

        if not threats:
            return {
                "total": 0,
                "by_host": [],
                "threats": [],
                "note": "No daemon threats reported yet — daemon may be running clean "
                        "or hasn't completed its first scan cycle.",
            }

        return {
            "total":    len(threats),
            "by_host":  list(by_host.values()),
            "threats":  threats,
        }

    async def _tool_execute_defensive_action(self, tool_input: Dict) -> Dict:
        """Queue a defensive action for one or more enrolled daemons."""
        asset_id = tool_input.get("asset_id", "").strip()
        assets_list = tool_input.get("assets")          # list or None
        action_id = tool_input.get("action_id", "").strip()
        parameters = tool_input.get("parameters") or {}
        threat_id = tool_input.get("threat_id", "")
        approval_override = tool_input.get("require_approval")

        from ..agent.defensive_playbook import PLAYBOOK, is_allowed, requires_approval
        from ..agent.actions_database import queue_action, init_db

        if not is_allowed(action_id):
            return {
                "error": f"Unknown action '{action_id}'. "
                         f"Available: {sorted(PLAYBOOK.keys())}",
            }

        entry = PLAYBOOK[action_id]
        needs_approval = requires_approval(action_id, approval_override)

        try:
            from ..api.agent_api_routes import get_agent_registry
            all_agents = get_agent_registry().list_agents()
        except Exception:
            all_agents = []

        targets = self._resolve_targets(asset_id, assets_list, all_agents)
        if not targets:
            if not asset_id and not assets_list:
                return {
                    "error": "No target specified. Provide 'asset_id' for a single daemon "
                             "or 'assets' (e.g. [\"all\"]) for multiple daemons.",
                }
            return {
                "error": f"No enrolled daemon matched {asset_id or assets_list!r}. "
                         "Use get_vps_summary() to list enrolled agents.",
            }

        init_db()

        if len(targets) == 1:
            agent_id, agent_name = targets[0]
            return await self._queue_single_action(
                agent_id, agent_name, action_id, entry, parameters, needs_approval, threat_id,
            )

        # Multi-target dispatch: always require approval regardless of risk level.
        # The operator must confirm the full asset list before a distributed
        # action fires — prevents a single AI call from affecting every machine.
        needs_approval = True
        return await self._queue_distributed_action(
            targets, action_id, entry, parameters, needs_approval, threat_id,
        )

    def _resolve_targets(
        self, asset_id: str, assets_list, all_agents: List[Dict]
    ) -> List[tuple]:
        """Return [(agent_id, agent_name)] for the requested targets.

        Priority: assets_list > asset_id.
        Only daemon agents (vps/cloud/workstation) are valid targets.
        """
        daemon_agents = [
            a for a in all_agents
            if a.get("agent_type") in ("vps", "cloud", "workstation")
            and a.get("status") != "revoked"
        ]

        if assets_list is not None:
            # Normalise: accept string "all" or list ["all"]
            if assets_list == "all" or assets_list == ["all"]:
                return [
                    (a["agent_id"], a.get("name", a["agent_id"]))
                    for a in daemon_agents
                ]
            seen: set = set()
            targets = []
            for identifier in assets_list:
                identifier = str(identifier).strip()
                for a in daemon_agents:
                    if (
                        a.get("agent_id") == identifier
                        or a.get("hostname", "").lower() == identifier.lower()
                        or a.get("name", "").lower() == identifier.lower()
                    ):
                        aid = a["agent_id"]
                        if aid not in seen:
                            seen.add(aid)
                            targets.append((aid, a.get("name", identifier)))
                        break
            return targets

        if asset_id:
            for a in daemon_agents:
                if (
                    a.get("agent_id") == asset_id
                    or a.get("hostname", "").lower() == asset_id.lower()
                    or a.get("name", "").lower() == asset_id.lower()
                ):
                    return [(a["agent_id"], a.get("name", asset_id))]
            return []  # No match — do not fabricate a target for an unknown ID

        return []

    async def _queue_single_action(
        self, agent_id: str, agent_name: str, action_id: str,
        entry: Dict, parameters: Dict, needs_approval: bool, threat_id: str,
    ) -> Dict:
        """Queue action on one agent and return standard response dict."""
        from ..agent.actions_database import queue_action
        uuid = queue_action(
            agent_id=agent_id,
            action_id=action_id,
            parameters=parameters,
            require_approval=needs_approval,
            risk_level=entry.get("risk", "low"),
            description=entry.get("description", action_id),
            threat_id=threat_id,
        )
        if needs_approval:
            await self._send_approval_request(uuid, action_id, entry, parameters, agent_name)
            return {
                "status": "pending_approval",
                "action_uuid": uuid,
                "agent": agent_name,
                "message": (
                    "Approval request sent. The user must approve before the command "
                    "is delivered to the daemon."
                ),
            }
        return {
            "status": "queued",
            "action_uuid": uuid,
            "agent": agent_name,
            "action_id": action_id,
            "message": (
                "Command queued. It will be delivered on the daemon's next heartbeat "
                "(up to 5 minutes). Use get_action_history() to check the result."
            ),
        }

    async def _queue_distributed_action(
        self, targets: List[tuple], action_id: str, entry: Dict,
        parameters: Dict, needs_approval: bool, threat_id: str,
    ) -> Dict:
        """Queue the same action on multiple agents and return a summary."""
        from ..agent.actions_database import queue_action
        target_names = [name for _, name in targets]
        # Cap display to 5 names to avoid bloating the description column and
        # AI context window when many daemons are enrolled.
        display = target_names[:5]
        suffix = f" +{len(target_names) - 5} more" if len(target_names) > 5 else ""
        target_summary = ", ".join(display) + suffix
        multi_description = (
            f"{entry.get('description', action_id)} "
            f"[Multi-target: {len(targets)} asset(s): {target_summary}]"
        )

        results = []
        for agent_id, agent_name in targets:
            uuid = queue_action(
                agent_id=agent_id,
                action_id=action_id,
                parameters=parameters,
                require_approval=needs_approval,
                risk_level=entry.get("risk", "low"),
                description=multi_description,
                threat_id=threat_id,
            )
            if needs_approval:
                await self._send_approval_request(
                    uuid, action_id, entry, parameters, agent_name,
                )
            results.append({
                "agent":       agent_name,
                "agent_id":    agent_id,
                "action_uuid": uuid,
                "status":      "pending_approval" if needs_approval else "queued",
            })

        deliver_note = (
            "Approval cards sent — one per agent. Approve each to authorize execution."
            if needs_approval else
            "Commands will be delivered to each daemon on its next heartbeat (up to 5 min)."
        )
        return {
            "status":       "distributed",
            "action_id":    action_id,
            "target_count": len(targets),
            "actions":      results,
            "message":      f"Queued {action_id} on {len(targets)} daemon(s). {deliver_note}",
        }

    async def _send_approval_request(
        self,
        action_uuid: str,
        action_id: str,
        playbook_entry: Dict,
        parameters: Dict,
        agent_name: str,
    ) -> None:
        """Broadcast an approval-request message into the chat sidebar."""
        try:
            from ..chat.message import ChatMessage, MessageType, PARTICIPANT_CITADEL
            desc = playbook_entry.get("description", action_id)
            risk = playbook_entry.get("risk", "medium").upper()
            param_lines = "\n".join(
                f"  - **{k}**: `{v}`" for k, v in parameters.items()
            ) or "  *(no parameters)*"
            text = (
                f"**Action Approval Required** ({risk} RISK)\n\n"
                f"**Action:** {action_id}\n"
                f"**Target:** {agent_name}\n"
                f"**Description:** {desc}\n\n"
                f"**Parameters:**\n{param_lines}\n\n"
                f"*This action requires your approval before it is sent to the daemon.*"
            )
            msg = ChatMessage(
                from_id=PARTICIPANT_CITADEL,
                to_id=PARTICIPANT_USER,
                msg_type=MessageType.RESPONSE,
                payload={
                    "text": text,
                    "action_type": "approval_request",
                    "action_uuid": action_uuid,
                    "action_id": action_id,
                    "agent_name": agent_name,
                },
            )
            await self._chat.send(msg)
        except Exception:
            logger.exception("Failed to send approval request message")

    async def _tool_get_defensive_playbook(self, tool_input: Dict) -> Dict:
        """Return the defensive action playbook."""
        from ..agent.defensive_playbook import PLAYBOOK
        action_id = tool_input.get("action_id", "").strip()
        if action_id:
            entry = PLAYBOOK.get(action_id)
            if not entry:
                return {"error": f"Unknown action '{action_id}'"}
            return {action_id: entry}
        return {
            "playbook": PLAYBOOK,
            "summary": {
                "auto_execute": [k for k, v in PLAYBOOK.items() if not v["require_approval"]],
                "require_approval": [k for k, v in PLAYBOOK.items() if v["require_approval"]],
            },
        }

    async def _tool_get_action_history(self, tool_input: Dict) -> Dict:
        """Return the audit trail of defensive actions."""
        from ..agent.actions_database import list_actions, init_db
        init_db()
        agent_id = tool_input.get("asset_id", "")
        action_id_filter = tool_input.get("action_id", "")
        status_filter = tool_input.get("status", "")
        limit = min(int(tool_input.get("limit", 20)), 100)

        actions = list_actions(
            agent_id=agent_id,
            action_id=action_id_filter,
            status=status_filter,
            limit=limit,
        )
        summary: Dict[str, int] = {}
        for a in actions:
            s = a.get("status", "unknown")
            summary[s] = summary.get(s, 0) + 1

        return {
            "total": len(actions),
            "status_summary": summary,
            "actions": [
                {
                    "action_uuid": a["action_uuid"],
                    "agent_id":    a["agent_id"],
                    "action_id":   a["action_id"],
                    "status":      a["status"],
                    "risk":        a["risk_level"],
                    "created_at":  a["created_at"],
                    "executed_at": a.get("executed_at"),
                    "result":      a.get("result"),
                }
                for a in actions
            ],
        }

    async def _tool_read_memory_log(self, tool_input: Dict) -> Dict:
        """Read the full content of a past-session memory log file."""
        from .memory_compactor import _MEMORY_DIR

        filename = tool_input.get("filename", "").strip()
        if not filename:
            return {"error": "filename is required"}

        # Safety: only allow simple filenames, no path traversal
        if "/" in filename or "\\" in filename or ".." in filename:
            return {"error": "Invalid filename"}

        log_path = _MEMORY_DIR / filename
        if not log_path.exists():
            available = sorted(p.name for p in _MEMORY_DIR.glob("session_*.md")) if _MEMORY_DIR.exists() else []
            return {
                "error": f"Memory log '{filename}' not found.",
                "available_logs": available,
            }

        try:
            content = log_path.read_text(encoding="utf-8")
            return {"filename": filename, "content": content}
        except Exception as exc:
            return {"error": f"Failed to read memory log: {exc}"}

    async def _tool_local_events(self, tool_input: Dict) -> Dict:
        """Return recent local Guardian events from the audit log."""
        limit = min(int(tool_input.get("limit", 20)), 100)
        severity_filter = tool_input.get("severity", "").lower()

        # Severity ordering for minimum-severity filtering
        _SEV_ORDER = {"info": 0, "warning": 1, "alert": 2, "critical": 3}
        min_sev = _SEV_ORDER.get(severity_filter, -1)

        try:
            from ..core.audit_log import get_audit_logger, EventType
            audit = get_audit_logger()
            # Query guardian-related event types (file + process sensor events)
            guardian_types = [
                EventType.FILE_CREATED,
                EventType.FILE_MODIFIED,
                EventType.FILE_DELETED,
                EventType.FILE_QUARANTINED,
                EventType.PROCESS_STARTED,
                EventType.PROCESS_KILLED,
                EventType.PROCESS_SUSPICIOUS,
            ]
            raw_events = audit.query_events(event_types=guardian_types, limit=limit * 3)
        except Exception as exc:
            logger.warning("get_local_events: audit query failed: %s", exc)
            return {"error": str(exc), "events": []}

        events_out = []
        for ev in raw_events:
            sev = ev.get("severity", "info").lower()
            if min_sev >= 0 and _SEV_ORDER.get(sev, 0) < min_sev:
                continue

            details = ev.get("details", {}) or {}
            events_out.append({
                "timestamp": ev.get("timestamp", ""),
                "event_type": ev.get("event_type", ""),
                "severity": sev,
                "message": ev.get("message", ""),
                "file_path": (
                    details.get("file_path")
                    or details.get("path")
                    or details.get("file")
                    or ""
                ),
                "details": details,
            })
            if len(events_out) >= limit:
                break

        return {
            "total": len(events_out),
            "events": events_out,
        }

    async def _tool_hostinger_vps_action(self, tool_input: Dict) -> Dict:
        """Call the Hostinger REST API to manage VPS servers directly."""
        from ..integrations.hostinger import HostingerClient

        action = tool_input.get("action", "")
        vps_id = tool_input.get("vps_id")

        try:
            client = HostingerClient()
        except ValueError as exc:
            msg = str(exc)
            asyncio.ensure_future(self._chat.send_system(msg))
            return {"error": msg}

        try:
            if action == "list":
                vms = await client.list_vps()
                # Summarise to avoid overwhelming context
                summary = []
                for vm in vms:
                    summary.append({
                        "id":       vm.get("id"),
                        "hostname": vm.get("hostname") or vm.get("label"),
                        "state":    vm.get("state") or vm.get("status"),
                        "ips":      [
                            ip.get("address") or ip
                            for ip in (vm.get("ip_addresses") or vm.get("ips") or [])
                            if ip
                        ],
                    })
                return {"vps_count": len(summary), "virtual_machines": summary}

            if vps_id is None:
                return {"error": f"vps_id is required for action '{action}'"}

            if action == "status":
                vm = await client.get_vps(int(vps_id))
                return {
                    "id":       vm.get("id"),
                    "hostname": vm.get("hostname") or vm.get("label"),
                    "state":    vm.get("state") or vm.get("status"),
                    "ips":      [
                        ip.get("address") or ip
                        for ip in (vm.get("ip_addresses") or vm.get("ips") or [])
                        if ip
                    ],
                    "plan":     vm.get("plan") or vm.get("type"),
                }

            if action == "metrics":
                return await client.get_metrics(int(vps_id))

            if action == "reboot":
                # Reboot is destructive — require Sentinel level or explicit user confirmation.
                # At Guardian/Observer, return a soft block so Claude asks the user to confirm.
                try:
                    from ..core import get_security_manager as _gsm_vps
                    _vps_level = _gsm_vps().current_level.value
                except Exception:
                    _vps_level = "guardian"
                if _vps_level != "sentinel":
                    return {
                        "requires_confirmation": True,
                        "action": "reboot",
                        "vps_id": vps_id,
                        "message": (
                            f"Rebooting VPS {vps_id} will interrupt all running services. "
                            "Reply 'confirm reboot' to proceed, or set security level to "
                            "Sentinel to allow auto-execution of destructive actions."
                        ),
                    }
                result = await client.restart_vps(int(vps_id))
                return {"status": "rebooting", "vps_id": vps_id, "api_response": result}

            return {"error": f"Unknown action '{action}'"}

        except Exception as exc:
            import httpx as _httpx
            if isinstance(exc, _httpx.HTTPStatusError) and exc.response.status_code in (401, 403):
                msg = (
                    "Hostinger API key is invalid or expired. "
                    "Update it in Settings > Integrations and click Test Connection."
                )
                asyncio.ensure_future(self._chat.send_system(msg))
                return {"error": msg}
            return {"error": f"Hostinger API error: {exc}"}

    async def _tool_mark_event_resolved(self, tool_input: Dict) -> Dict:
        """Record that a security event has been resolved by Guardian AI."""
        event_id = tool_input.get("event_id", "").strip()
        source = tool_input.get("source", "local").strip()
        action_taken = tool_input.get("action_taken", "").strip()
        notes = tool_input.get("notes")

        if not event_id or not action_taken:
            return {"error": "event_id and action_taken are required"}

        from ..intel.resolution_store import get_resolution_store
        from ..core.audit_log import log_security_event, EventType, EventSeverity

        record = get_resolution_store().resolve(
            source=source,
            external_id=event_id,
            action_taken=action_taken,
            resolved_by="guardian_ai",
            notes=notes,
        )
        log_security_event(
            EventType.SYSTEM_EVENT,
            EventSeverity.INFO,
            f"Event resolved by Guardian AI: {event_id} via {action_taken}",
            details={
                "source": source,
                "event_id": event_id,
                "action_taken": action_taken,
                "notes": notes,
            },
        )
        return {
            "success": True,
            "event_id": event_id,
            "source": source,
            "action_taken": action_taken,
            "resolved_at": record["resolved_at"],
            "message": f"Event marked resolved: {action_taken}",
        }

    async def _tool_execute_ssh_command(self, tool_input: Dict) -> Dict:
        """Execute a shell command on a managed asset via SSH."""
        asset_id_or_name = tool_input.get("asset_id", "").strip()
        command = tool_input.get("command", "").strip()
        timeout = max(5, min(int(tool_input.get("timeout", 30)), 120))
        justification = tool_input.get("justification", "")

        if not command:
            return {"error": "command is required"}

        # Resolve asset by ID, hostname, or name
        from ..api.asset_routes import get_inventory
        inv = get_inventory()
        asset = inv.get(asset_id_or_name)
        if asset is None:
            asset = next(
                (
                    a for a in inv.all()
                    if asset_id_or_name.lower() in (a.hostname or "").lower()
                    or asset_id_or_name.lower() in (a.name or "").lower()
                ),
                None,
            )
        if asset is None:
            return {
                "error": (
                    f"Asset '{asset_id_or_name}' not found. "
                    "Use get_asset_list() to see available assets."
                )
            }

        asset_id = asset.asset_id
        asset_label = asset.name or asset.hostname or asset_id

        # ── Local-platform routing ────────────────────────────────────
        # The local host machine uses subprocess instead of SSH.
        # No credentials needed — skip the SSH credential check entirely.
        from ..intel.assets import AssetPlatform as _AssetPlatform
        if asset.platform == _AssetPlatform.LOCAL:
            return await self._tool_execute_local_command(
                asset_id, asset_label, command, justification, timeout
            )
        # ── End local routing ─────────────────────────────────────────

        if not asset.ssh_credential_id:
            return {
                "error": (
                    f"Asset '{asset_label}' has no SSH credential linked. "
                    "Add one in Assets → SSH Settings."
                )
            }

        # Pre-flight: verify the linked credential actually exists in vault and
        # has a private key before creating an approval request.  This prevents
        # the user from clicking Approve and then getting "Permission denied"
        # because the credential was deleted or never imported.
        try:
            _cred_check = self.vault.get_ssh_credential(asset.ssh_credential_id)
            if _cred_check is None:
                _cred_msg = (
                    f"The SSH credential linked to '{asset_label}' no longer exists in the vault "
                    f"(credential ID: {asset.ssh_credential_id[:8]}…). "
                    "Go to Assets → select this asset → link a valid SSH credential."
                )
                asyncio.ensure_future(self._chat.send_system(_cred_msg))
                return {"error": _cred_msg}
            if _cred_check.get("auth_type") == "key" and not _cred_check.get("private_key"):
                _cred_msg = (
                    f"The SSH credential '{_cred_check.get('label', asset.ssh_credential_id[:8])}' "
                    f"linked to '{asset_label}' has no private key stored. "
                    "Re-import the private key in the Vault tab."
                )
                asyncio.ensure_future(self._chat.send_system(_cred_msg))
                return {"error": _cred_msg}
        except Exception:
            pass  # Vault locked — let the normal execution path surface that error

        if not _check_ssh_rate(asset_id):
            return {
                "error": (
                    f"SSH rate limit reached for '{asset_label}' "
                    f"(max {_SSH_RATE_LIMIT}/min). Try again shortly."
                )
            }

        safe = _is_safe_read_only(command)

        if safe:
            # Execute immediately — read-only, no approval needed
            try:
                from ..api.asset_routes import get_ssh_manager
                from ..remote.ssh_manager import (
                    NoCredentialError, VaultLockedError,
                    ConnectionFailedError, CommandTimeoutError,
                )
                from ..core.audit_log import log_security_event, EventType, EventSeverity

                ssh = get_ssh_manager()
                result = await ssh.execute(asset_id, command, timeout=timeout)

                log_security_event(
                    EventType.SSH_COMMAND_EXECUTED,
                    EventSeverity.INFO,
                    f"SSH read command on {asset_label}: {command!r}",
                    details={
                        "asset_id": asset_id,
                        "command": command,
                        "exit_code": result.exit_code,
                        "duration_ms": result.duration_ms,
                        "justification": justification,
                        "executed_by": "guardian_ai",
                    },
                )

                return {
                    "asset": asset_label,
                    "command": command,
                    "success": result.exit_code == 0,
                    "stdout": result.stdout[:4000],
                    "stderr": result.stderr[:1000],
                    "exit_code": result.exit_code,
                    "execution_time_ms": result.duration_ms,
                }

            except Exception as exc:
                # Map well-known exceptions to friendly messages
                exc_name = type(exc).__name__
                if "VaultLocked" in exc_name:
                    msg = (
                        "Vault is locked — cannot retrieve SSH credentials. "
                        "Unlock the vault in the Vault tab, or enable Startup Auto-Unlock "
                        "so Guardian always has access."
                    )
                    asyncio.ensure_future(self._chat.send_system(msg))
                    return {"error": msg}
                if "NoCredential" in exc_name:
                    msg = f"No SSH credential stored for '{asset_label}'. Add one via Assets > SSH Settings."
                    asyncio.ensure_future(self._chat.send_system(msg))
                    return {"error": msg}
                if "ConnectionFailed" in exc_name:
                    msg = f"SSH connection to '{asset_label}' failed — check connectivity and firewall."
                    asyncio.ensure_future(self._chat.send_system(msg))
                    return {"error": msg}
                if "CommandTimeout" in exc_name:
                    msg = f"Command timed out on '{asset_label}' after {timeout}s — asset may be offline."
                    asyncio.ensure_future(self._chat.send_system(msg))
                    return {"error": msg}
                return {"error": f"SSH execution error: {exc}"}

        # Check security level — Sentinel auto-executes remote write commands
        # (mirrors the local-command path in _tool_execute_local_command)
        try:
            from ..core import get_security_manager as _gsm
            _ssh_level = _gsm().current_level.value
        except Exception:
            _ssh_level = "guardian"

        if _ssh_level == "sentinel":
            try:
                from ..api.asset_routes import get_ssh_manager as _get_ssh
                from ..core.audit_log import log_security_event as _lse, EventType as _ET, EventSeverity as _ES
                _ssh_res = await _get_ssh().execute(asset_id, command, timeout=timeout)
                _lse(
                    _ET.SSH_COMMAND_EXECUTED,
                    _ES.ALERT,
                    f"SSH write command (auto-sentinel) on {asset_label}: {command!r}",
                    details={
                        "asset_id": asset_id, "command": command,
                        "exit_code": _ssh_res.exit_code, "mode": "ssh_sentinel",
                        "justification": justification,
                    },
                )
                return {
                    "asset": asset_label, "command": command,
                    "success": _ssh_res.exit_code == 0,
                    "stdout": _ssh_res.stdout[:4000],
                    "stderr": _ssh_res.stderr[:1000],
                    "exit_code": _ssh_res.exit_code,
                    "execution_time_ms": _ssh_res.duration_ms,
                }
            except Exception as _exc:
                return {"error": f"SSH sentinel execution error: {_exc}"}

        # Write command — require user approval (serial — await Future)
        from ..api.asset_routes import register_pending_ssh, create_approval_future
        from ..core.audit_log import log_security_event, EventType, EventSeverity

        approval_uuid = register_pending_ssh(asset_id, command, timeout)
        approval_future = create_approval_future(approval_uuid)
        log_security_event(
            EventType.SSH_COMMAND_BLOCKED,
            EventSeverity.ALERT,
            f"SSH write command pending approval on {asset_label}: {command!r}",
            details={
                "asset_id": asset_id,
                "command": command,
                "approval_uuid": approval_uuid,
                "justification": justification,
            },
        )
        await self._send_ssh_approval_request(
            approval_uuid, asset_id, asset_label, command, justification
        )

        # Show "waiting for approval" in the thinking indicator so the user
        # understands why the AI is paused (not just spinning indefinitely).
        short_cmd = command[:60] + ("..." if len(command) > 60 else "")
        self._broadcast_thinking(True, f"Waiting for approval: {short_cmd}")

        # Block until user approves or denies (max 5 min)
        try:
            decision = await asyncio.wait_for(approval_future, timeout=300)
        except asyncio.TimeoutError:
            # Clean up orphaned Future and pending command so a late Approve click
            # cannot silently execute the command after the tool loop has moved on.
            from ..api.asset_routes import _APPROVAL_FUTURES, _APPROVAL_FUTURES_LOCK, _PENDING_SSH, _PENDING_SSH_LOCK
            with _APPROVAL_FUTURES_LOCK:
                _APPROVAL_FUTURES.pop(approval_uuid, None)
            with _PENDING_SSH_LOCK:
                _PENDING_SSH.pop(approval_uuid, None)
            return {
                "status": "timeout",
                "command": command,
                "message": "Approval timed out after 5 minutes. Command was not executed.",
            }

        if decision.get("denied"):
            return {
                "status": "denied",
                "command": command,
                "message": "User denied this command. It was not executed.",
            }

        # SSH connection failure — surface the error clearly so the AI stops and
        # reports to the user rather than silently retrying.
        if decision.get("connection_error"):
            error_msg = decision.get("error", "SSH connection failed")
            asyncio.ensure_future(self._chat.send_system(
                f"SSH connection to '{asset_label}' failed: {error_msg}\n\n"
                "The command was not executed. Fix the SSH connection before retrying."
            ))
            return {
                "status": "connection_failed",
                "asset": asset_label,
                "command": command,
                "error": error_msg,
                "success": False,
                "message": (
                    f"STOP — SSH connection to '{asset_label}' failed: {error_msg}. "
                    "Do not retry this command. Report this failure to the user and wait for instructions."
                ),
            }

        # Return the actual execution result so Claude can report it
        return {
            "asset": asset_label,
            "command": command,
            "success": decision.get("success", False),
            "stdout": decision.get("stdout", ""),
            "stderr": decision.get("stderr", ""),
            "exit_code": decision.get("exit_code", -1),
            "execution_time_ms": decision.get("execution_time_ms", 0),
        }

    async def _tool_execute_local_command(
        self,
        asset_id: str,
        asset_label: str,
        command: str,
        justification: str,
        timeout: int,
    ) -> Dict:
        """Execute a command on the local host machine via subprocess (no SSH).

        Read-only commands auto-execute. Write commands require approval at
        Guardian/Observer level; at Sentinel they execute immediately.
        """
        from ..core.audit_log import log_security_event, EventType, EventSeverity

        if not _check_ssh_rate(asset_id):
            return {
                "error": (
                    f"Rate limit reached for '{asset_label}' "
                    f"(max {_SSH_RATE_LIMIT}/min). Try again shortly."
                )
            }

        safe = _is_safe_read_only(command)
        logger.warning(
            "[LocalCmd] asset=%s safe=%s command=%r",
            asset_id, safe, command[:120],
        )

        if safe:
            # Read-only — execute immediately, no approval needed
            try:
                from ..local.local_defender import LocalHostDefender
                result = await LocalHostDefender().execute_command_async(command, timeout)

                log_security_event(
                    EventType.SSH_COMMAND_EXECUTED,
                    EventSeverity.INFO,
                    f"Local read command on {asset_label}: {command!r}",
                    details={
                        "asset_id": asset_id,
                        "command": command,
                        "exit_code": result.exit_code,
                        "duration_ms": result.duration_ms,
                        "justification": justification,
                        "executed_by": "guardian_ai",
                        "mode": "local",
                    },
                )
                return {
                    "asset": asset_label,
                    "command": command,
                    "success": result.success,
                    "stdout": result.stdout[:4000],
                    "stderr": result.stderr[:1000],
                    "exit_code": result.exit_code,
                    "execution_time_ms": result.duration_ms,
                }
            except TimeoutError as exc:
                return {"error": f"Local command timed out: {exc}"}
            except RuntimeError as exc:
                return {"error": f"Local execution failed: {exc}"}

        # Write command — check security level
        try:
            from ..core import get_security_manager
            level = get_security_manager().current_level.value
        except Exception as _sec_exc:
            logger.warning("Could not read security level, defaulting to guardian: %s", _sec_exc)
            level = "guardian"

        if level == "sentinel":
            # Sentinel: auto-execute write commands, log at ALERT severity
            try:
                from ..local.local_defender import LocalHostDefender
                result = await LocalHostDefender().execute_command_async(command, timeout)

                log_security_event(
                    EventType.SSH_COMMAND_EXECUTED,
                    EventSeverity.ALERT,
                    f"Local write command (auto-sentinel) on {asset_label}: {command!r}",
                    details={
                        "asset_id": asset_id,
                        "command": command,
                        "exit_code": result.exit_code,
                        "duration_ms": result.duration_ms,
                        "justification": justification,
                        "executed_by": "guardian_ai",
                        "mode": "local_sentinel",
                    },
                )
                return {
                    "asset": asset_label,
                    "command": command,
                    "success": result.success,
                    "stdout": result.stdout[:4000],
                    "stderr": result.stderr[:1000],
                    "exit_code": result.exit_code,
                    "execution_time_ms": result.duration_ms,
                }
            except TimeoutError as exc:
                return {"error": f"Local command timed out: {exc}"}
            except RuntimeError as exc:
                return {"error": f"Local execution failed: {exc}"}

        # Guardian/Observer: require user approval (serial — await Future)
        from ..api.asset_routes import register_pending_ssh, create_approval_future
        approval_uuid = register_pending_ssh(asset_id, command, timeout)
        approval_future = create_approval_future(approval_uuid)

        log_security_event(
            EventType.SSH_COMMAND_BLOCKED,
            EventSeverity.ALERT,
            f"Local write command pending approval on {asset_label}: {command!r}",
            details={
                "asset_id": asset_id,
                "command": command,
                "approval_uuid": approval_uuid,
                "justification": justification,
                "mode": "local",
            },
        )
        await self._send_ssh_approval_request(
            approval_uuid, asset_id, asset_label, command, justification
        )

        # Show "waiting for approval" in the thinking indicator so the user
        # understands why the AI is paused (not just spinning indefinitely).
        short_cmd = command[:60] + ("..." if len(command) > 60 else "")
        self._broadcast_thinking(True, f"Waiting for approval: {short_cmd}")

        # Block until user approves or denies (max 5 min)
        try:
            decision = await asyncio.wait_for(approval_future, timeout=300)
        except asyncio.TimeoutError:
            # Clean up orphaned Future and pending command so a late Approve click
            # cannot silently execute the command after the tool loop has moved on.
            from ..api.asset_routes import _APPROVAL_FUTURES, _APPROVAL_FUTURES_LOCK, _PENDING_SSH, _PENDING_SSH_LOCK
            with _APPROVAL_FUTURES_LOCK:
                _APPROVAL_FUTURES.pop(approval_uuid, None)
            with _PENDING_SSH_LOCK:
                _PENDING_SSH.pop(approval_uuid, None)
            return {
                "status": "timeout",
                "command": command,
                "message": "Approval timed out after 5 minutes. Command was not executed.",
            }

        if decision.get("denied"):
            return {
                "status": "denied",
                "command": command,
                "message": "User denied this command. It was not executed.",
            }

        # Return the actual execution result so Claude can report it
        return {
            "asset": asset_label,
            "command": command,
            "success": decision.get("success", False),
            "stdout": decision.get("stdout", ""),
            "stderr": decision.get("stderr", ""),
            "exit_code": decision.get("exit_code", -1),
            "execution_time_ms": decision.get("execution_time_ms", 0),
        }

    async def _send_ssh_approval_request(
        self,
        approval_uuid: str,
        asset_id: str,
        asset_label: str,
        command: str,
        justification: str,
    ) -> None:
        """Send an SSH approval card into the chat sidebar."""
        try:
            from ..chat.message import ChatMessage, MessageType, PARTICIPANT_CITADEL
            reason_line = f"**Reason:** {justification}\n" if justification else ""
            text = (
                f"**SSH Command Approval Required**\n\n"
                f"**Asset:** {asset_label}\n"
                f"**Command:** `{command}`\n"
                f"{reason_line}"
                f"\n*This command modifies system state and requires your approval.*"
            )
            msg = ChatMessage(
                from_id=PARTICIPANT_CITADEL,
                to_id=PARTICIPANT_USER,
                msg_type=MessageType.RESPONSE,
                payload={
                    "text": text,
                    "action_type": "ssh_approval_request",
                    "approval_uuid": approval_uuid,
                    "asset_id": asset_id,
                    "asset_label": asset_label,
                    "command": command,
                },
            )
            await self._chat.send(msg)
        except Exception:
            logger.exception("Failed to send SSH approval request")

    async def _on_completion_event(self, event_type: str, data: dict) -> None:
        """Handle action completion events pushed from API route handlers.

        Only triggers a Guardian AI turn for events that need analysis:
          - failures and denials (always)
          - successes with meaningful output (forensics, command output)
        Silent successes with no output are logged to chat but don't trigger
        an AI turn — Guardian confirming "all good" wastes tokens for no value.
        """
        try:
            from ..chat.message import ChatMessage, MessageType, PARTICIPANT_CITADEL

            text: str = ""
            should_trigger: bool = False  # only True when Guardian needs to react

            if event_type == "daemon_action_result":
                status    = data.get("status", "unknown")
                host      = data.get("hostname") or data.get("agent_id", "daemon")
                action    = data.get("action_id", "")
                result    = data.get("result", "")
                forensics = data.get("forensics", "")
                icon  = "[OK]" if status == "success" else "[FAIL]"
                lines = [f"{icon} Daemon action on {host}: {action} — {status.upper()}"]
                if result:
                    lines.append(f"Output: {str(result)[:500]}")
                if forensics:
                    lines.append(f"Forensics: {str(forensics)[:300]}")
                text = "\n".join(lines)
                # Trigger AI on failure, or success with forensics worth analyzing.
                # 'result' is always a non-empty dict (daemon always populates it),
                # so bool(result) would always be True — use 'forensics' instead.
                should_trigger = (status != "success") or bool(forensics)

            elif event_type == "daemon_action_approved":
                # Approved → queued: Guardian already knows it submitted the action.
                # Skip entirely — no chat message, no AI turn needed.
                return

            elif event_type == "daemon_action_denied":
                action = data.get("action_id", data.get("action_uuid", ""))
                host   = data.get("agent_name") or data.get("agent_id", "daemon")
                text   = f"[DENIED] Daemon action {action!r} on {host} was denied by user."
                should_trigger = True

            elif event_type == "ssh_command_result":
                asset_id  = data.get("asset_id", "")
                command   = data.get("command", "")
                success   = data.get("success", False)
                exit_code = data.get("exit_code", -1)
                stdout    = (data.get("stdout") or "")[:500]
                stderr    = (data.get("stderr") or "")[:300]
                icon  = "[OK]" if success else "[FAIL]"
                lines = [f"{icon} SSH on {asset_id}: `{command}` — exit {exit_code}"]
                if not success and stderr:
                    lines.append(f"Stderr: {stderr}")
                elif stdout:
                    lines.append(f"Output: {stdout}")
                text = "\n".join(lines)
                # Trigger AI on failure only; stderr from write commands is often
                # informational (e.g. "Stopping service...") and not worth an AI turn.
                should_trigger = not success

            elif event_type == "ssh_command_denied":
                asset_id = data.get("asset_id", "")
                command  = data.get("command", "")
                text     = f"[DENIED] SSH command on {asset_id} was denied by user: `{command}`"
                should_trigger = True

            if not text:
                return

            if should_trigger:
                # Truncate large fields before storing in the payload
                clean_data = dict(data)
                for _key in ("stdout", "stderr", "result", "forensics"):
                    if _key in clean_data and isinstance(clean_data[_key], str):
                        clean_data[_key] = clean_data[_key][:500]

                # Send as EVENT — _on_message will start a new Guardian AI turn
                msg = ChatMessage(
                    from_id=PARTICIPANT_CITADEL,
                    to_id=PARTICIPANT_ASSISTANT,
                    msg_type=MessageType.EVENT,
                    payload={
                        "text":        text,
                        "action_type": "completion_event",
                        "event_type":  event_type,
                        "data":        clean_data,
                    },
                )
                await self._chat.send(msg)
            else:
                # Log to chat for audit trail but don't burn tokens on a Guardian turn
                await self._chat.send_system(text)

        except Exception:
            logger.exception("_on_completion_event failed for %s", event_type)

