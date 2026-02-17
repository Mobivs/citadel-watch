"""Group Policy Engine — fan-out security rules to multiple Remote Shield agents.

Compiles named policy groups into per-agent commands and distributes them
via the existing command queue (shield_database.queue_command).

Supported rule types (v0.3.30):
  - alert_threshold (int 0-10): Agent-side severity filter
  - update_schedule ("daily" | "weekly" | "manual"): Update check frequency
  - firewall_rules (list of rule dicts): Firewall deny/allow entries

Conflict resolution when an agent belongs to multiple groups:
  - Scalar values: lowest priority number (= highest priority) wins
  - Firewall rules: union of all groups, deduplicated by (source, port)
"""

import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional

from .shield_database import RemoteShieldDatabase

logger = logging.getLogger(__name__)

# Schedule ordering for conflict resolution (most frequent wins)
_SCHEDULE_ORDER = {"daily": 0, "weekly": 1, "manual": 2}


class GroupPolicyEngine:
    """Compiles group policies into agent commands and fans them out."""

    SUPPORTED_RULE_TYPES = {"alert_threshold", "update_schedule", "firewall_rules"}

    def __init__(self, shield_db: RemoteShieldDatabase):
        self._db = shield_db

    def apply_policy(self, group_id: str) -> dict:
        """Fan-out policy to all group members via the command queue.

        Returns:
            {"queued": N, "skipped": N, "errors": [str]}
        """
        group = self._db.get_policy_group(group_id)
        if group is None:
            return {"queued": 0, "skipped": 0, "errors": [f"Group {group_id} not found"]}

        members = self._db.get_group_members(group_id)
        if not members:
            return {"queued": 0, "skipped": 0, "errors": []}

        queued = 0
        skipped = 0
        errors: List[str] = []

        for agent_id in members:
            try:
                effective = self.resolve_effective_rules(agent_id)
                payload = self._compile_command_payload(effective)
                command_id = str(uuid.uuid4())
                application_id = str(uuid.uuid4())

                self._db.queue_command(
                    command_id=command_id,
                    agent_id=agent_id,
                    command_type="apply_policy",
                    payload=payload,
                )
                self._db.log_policy_application(
                    application_id=application_id,
                    group_id=group_id,
                    agent_id=agent_id,
                    command_id=command_id,
                )
                queued += 1
            except Exception as exc:
                logger.warning("Failed to queue policy for agent %s: %s", agent_id, exc)
                errors.append(f"{agent_id}: {exc}")
                skipped += 1

        return {"queued": queued, "skipped": skipped, "errors": errors}

    def resolve_effective_rules(self, agent_id: str) -> dict:
        """Merge rules from all groups the agent belongs to.

        Conflict resolution:
        - alert_threshold: highest-priority group (lowest priority number) wins
        - update_schedule: most frequent wins (daily > weekly > manual)
        - firewall_rules: union of all groups, deduplicated by (source, port)
        """
        groups = self._db.get_agent_groups(agent_id)  # sorted by priority ASC
        if not groups:
            return {}

        effective: Dict = {}
        seen_fw: set = set()  # (source, port) dedup keys

        for group in groups:
            rules = group.get("rules", {})

            # Scalar: first (highest priority) wins
            if "alert_threshold" in rules and "alert_threshold" not in effective:
                effective["alert_threshold"] = rules["alert_threshold"]

            # Schedule: most frequent wins
            if "update_schedule" in rules:
                new = rules["update_schedule"]
                existing = effective.get("update_schedule")
                if existing is None or _SCHEDULE_ORDER.get(new, 99) < _SCHEDULE_ORDER.get(existing, 99):
                    effective["update_schedule"] = new

            # Firewall: union with dedup
            for fw in rules.get("firewall_rules", []):
                key = (fw.get("source", ""), fw.get("port", ""))
                if key not in seen_fw:
                    seen_fw.add(key)
                    effective.setdefault("firewall_rules", []).append(fw)

        return effective

    def _compile_command_payload(self, rules: dict) -> dict:
        """Convert resolved rules into an apply_policy command payload."""
        return {
            "policy_version": datetime.utcnow().isoformat(),
            "alert_threshold": rules.get("alert_threshold"),
            "update_schedule": rules.get("update_schedule"),
            "firewall_rules": rules.get("firewall_rules", []),
        }

    def get_compliance_summary(self, group_id: str) -> dict:
        """Return per-agent compliance status for a policy group.

        Returns:
            {"group_id": str, "members": [{"agent_id", "status", "applied_at", "last_push"}]}
        """
        compliance = self._db.get_policy_compliance(group_id)
        applied = sum(1 for c in compliance if c["status"] == "applied")
        pending = sum(1 for c in compliance if c["status"] == "pending")
        return {
            "group_id": group_id,
            "total": len(compliance),
            "applied": applied,
            "pending": pending,
            "members": compliance,
        }
