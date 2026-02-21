"""Defensive Response Playbook — pre-approved actions for Citadel Daemon.

Each entry defines:
  - description: human-readable action description
  - risk:        "low" (auto-execute) | "medium" (require approval)
  - require_approval: bool default; can be overridden by AI tool call
  - parameters:  dict of param_name → {type, required, description}

The daemon maintains a SEPARATE hard-coded ALLOWED_ACTIONS frozenset.
This playbook controls what the coordinator/AI can initiate.
"""

from typing import Any, Dict, Optional

PLAYBOOK: Dict[str, Dict[str, Any]] = {
    # ── Auto-Execute (Low Risk) ───────────────────────────────────────────
    "kill_process": {
        "description": "Kill a suspicious process by PID",
        "risk": "low",
        "require_approval": False,
        "parameters": {
            "pid": {
                "type": "integer",
                "required": True,
                "description": "Process ID to terminate",
            },
            "process_name": {
                "type": "string",
                "required": False,
                "description": "Expected process name (safety check, optional)",
            },
        },
    },
    "block_ip": {
        "description": "Block an attacker IP via iptables (up to 72 hours)",
        "risk": "low",
        "require_approval": False,
        "parameters": {
            "source_ip": {
                "type": "string",
                "required": True,
                "description": "IPv4 address to block",
            },
            "duration_hours": {
                "type": "integer",
                "required": False,
                "description": "Block duration in hours (default 24, max 72)",
            },
            "reason": {
                "type": "string",
                "required": False,
                "description": "Reason for the block (logged in iptables comment)",
            },
        },
    },
    "disable_cron_job": {
        "description": "Comment out a suspicious cron job entry",
        "risk": "low",
        "require_approval": False,
        "parameters": {
            "cron_pattern": {
                "type": "string",
                "required": True,
                "description": "Pattern to match against cron entries (substring match)",
            },
            "username": {
                "type": "string",
                "required": False,
                "description": "User whose crontab to modify (default: all users + /etc/cron*)",
            },
        },
    },
    "collect_forensics": {
        "description": (
            "Collect forensics snapshot: process list, network connections, "
            "recent logins, disk usage, memory usage"
        ),
        "risk": "low",
        "require_approval": False,
        "parameters": {},
    },

    # ── Require User Approval (Medium Risk) ───────────────────────────────
    "rotate_ssh_keys": {
        "description": "Revoke all existing SSH authorized_keys for a user",
        "risk": "medium",
        "require_approval": True,
        "parameters": {
            "username": {
                "type": "string",
                "required": False,
                "description": "User whose SSH keys to rotate (default: root)",
            },
        },
    },
    "restart_service": {
        "description": "Restart a system service via systemctl",
        "risk": "medium",
        "require_approval": True,
        "parameters": {
            "service_name": {
                "type": "string",
                "required": True,
                "description": "systemd service name (e.g. 'nginx', 'sshd')",
            },
        },
    },
    "apply_patches": {
        "description": "Apply pending OS security patches (apt/dnf)",
        "risk": "medium",
        "require_approval": True,
        "parameters": {
            "security_only": {
                "type": "boolean",
                "required": False,
                "description": "Apply security patches only (default: True)",
            },
        },
    },
}


def is_allowed(action_id: str) -> bool:
    """Return True if action_id is in the playbook."""
    return action_id in PLAYBOOK


def requires_approval(action_id: str, override: Optional[bool] = None) -> bool:
    """Return whether an action requires user approval.

    Args:
        action_id:  Action identifier.
        override:   If not None, use this value instead of playbook default.
                    The AI tool can lower risk (e.g. force auto-execute) only
                    for low-risk actions; raising to medium is always allowed.

    Returns:
        True if the action should be queued for approval before delivery.
    """
    entry = PLAYBOOK.get(action_id, {})
    default = entry.get("require_approval", True)  # safe default: require approval
    if override is None:
        return default
    # Never allow an override that removes approval for medium-risk actions
    if entry.get("risk") == "medium" and override is False:
        return True  # ignore the override — medium risk always requires approval
    return override
