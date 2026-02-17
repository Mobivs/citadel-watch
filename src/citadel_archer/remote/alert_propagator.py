"""Propagate cross-system correlation alerts to affected Remote Shield agents.

When the CrossAssetCorrelator detects a pattern spanning multiple assets (e.g.,
the same attacker IP on both local and a remote agent), this module queues
'threat_alert' commands to the affected remote agents so they are aware of the
cross-system threat.

v0.3.29: Initial implementation — log-only on agent side.
"""

import logging
import uuid
from typing import Dict, Optional

from .shield_database import RemoteShieldDatabase

logger = logging.getLogger(__name__)


class AlertPropagator:
    """Queues 'threat_alert' commands to remote agents when correlations fire."""

    def __init__(self, shield_db: RemoteShieldDatabase):
        self._db = shield_db
        self._agent_cache: Dict[str, str] = {}  # asset_id → agent_id

    def propagate(self, threat) -> int:
        """Queue alert commands to agents whose assets are affected.

        Args:
            threat: A CorrelatedThreat dataclass instance.

        Returns:
            Number of commands queued.
        """
        count = 0
        for asset_id in threat.affected_assets:
            agent_id = self._resolve_agent(asset_id)
            if not agent_id:
                continue
            try:
                self._db.queue_command(
                    command_id=str(uuid.uuid4()),
                    agent_id=agent_id,
                    command_type="threat_alert",
                    payload={
                        "correlation_id": threat.correlation_id,
                        "correlation_type": threat.correlation_type.value,
                        "severity": threat.severity,
                        "description": threat.description,
                        "indicator": threat.indicator,
                        "affected_assets": threat.affected_assets,
                    },
                )
                count += 1
            except Exception:
                logger.warning(
                    "Failed to queue threat_alert for agent %s", agent_id,
                    exc_info=True,
                )
        return count

    def _resolve_agent(self, asset_id: str) -> Optional[str]:
        """Resolve an asset_id to the corresponding agent_id, if any."""
        if asset_id in self._agent_cache:
            result = self._agent_cache[asset_id]
            return result if result else None  # empty string = known-missing sentinel
        # Refresh cache from DB
        try:
            agents = self._db.list_agents()
            self._agent_cache = {
                a.get("asset_id", ""): a["id"]
                for a in agents
                if a.get("asset_id")
            }
        except Exception:
            logger.warning("Failed to refresh agent cache", exc_info=True)
            return None
        result = self._agent_cache.get(asset_id)
        if result is None:
            self._agent_cache[asset_id] = ""  # sentinel: known-missing
        return result

    def clear_cache(self) -> None:
        """Clear the agent resolution cache (e.g., after agent changes)."""
        self._agent_cache.clear()
