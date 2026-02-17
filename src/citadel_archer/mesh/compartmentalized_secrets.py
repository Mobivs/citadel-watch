"""Compartmentalized secrets — each node only has credentials it needs.

v0.3.41: No single VPS compromise exposes the entire system. Secrets are
partitioned by node role:

    Desktop (PRIMARY):
      - Vault (all secrets), all SSH keys, full asset registry
      - All HMAC keys, master audit log, AI API keys

    VPS Agent (AGENT):
      - Its own config and heartbeat HMAC key
      - Escalation endpoint URL, rate-limited SCS API token
      - NO access to other agents' keys or full asset registry

    Secondary Brain (SECONDARY):
      - Asset registry (read-only, sanitized — no raw secrets)
      - Its own SSH key + encrypted API key for AI
      - Coordination audit log
      - NO access to Vault or other agents' SSH keys

Zero AI tokens — pure secret management policy.
"""

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# ── Secret Classification ───────────────────────────────────────────


class SecretScope(str, Enum):
    """Classification of a secret's scope / sensitivity."""

    GLOBAL = "global"          # Desktop-only (Vault master, all SSH keys)
    BRAIN = "brain"            # Secondary brain (encrypted API key, coord log)
    AGENT = "agent"            # Per-agent (own config, own HMAC key)
    MESH = "mesh"              # Mesh-wide (heartbeat HMAC, shared by all peers)


class SecretType(str, Enum):
    """Types of secrets managed in the mesh."""

    SSH_PRIVATE_KEY = "ssh_private_key"
    SSH_PUBLIC_KEY = "ssh_public_key"
    HMAC_PSK = "hmac_psk"
    API_KEY = "api_key"
    VAULT_MASTER_KEY = "vault_master_key"
    AGENT_CONFIG = "agent_config"
    ESCALATION_TOKEN = "escalation_token"
    ASSET_REGISTRY = "asset_registry"


# ── Node Secret Manifest ────────────────────────────────────────────


@dataclass
class SecretEntry:
    """A single secret entry in a node's manifest."""

    secret_id: str
    secret_type: str            # SecretType value
    scope: str                  # SecretScope value
    description: str = ""
    node_id: str = ""           # Which node owns this secret
    fingerprint: str = ""       # SHA-256 fingerprint (for verification)
    provisioned_at: str = ""
    rotated_at: str = ""

    def __post_init__(self):
        if not self.provisioned_at:
            self.provisioned_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "secret_id": self.secret_id,
            "secret_type": self.secret_type,
            "scope": self.scope,
            "description": self.description,
            "node_id": self.node_id,
            "fingerprint": self.fingerprint,
            "provisioned_at": self.provisioned_at,
            "rotated_at": self.rotated_at,
        }


@dataclass
class NodeSecretManifest:
    """What secrets a particular node is allowed to have."""

    node_id: str
    role: str  # BrainRole value: "primary", "secondary", "agent"
    secrets: List[SecretEntry] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "role": self.role,
            "secret_count": len(self.secrets),
            "secrets": [s.to_dict() for s in self.secrets],
        }


# ── Access Policy ───────────────────────────────────────────────────


# Which secret scopes each role can access
_ROLE_ACCESS: Dict[str, Set[str]] = {
    "primary": {
        SecretScope.GLOBAL.value,
        SecretScope.BRAIN.value,
        SecretScope.AGENT.value,
        SecretScope.MESH.value,
    },
    "secondary": {
        SecretScope.BRAIN.value,
        SecretScope.MESH.value,
    },
    "agent": {
        SecretScope.AGENT.value,
        SecretScope.MESH.value,
    },
}

# Which secret types each role can access
_ROLE_SECRET_TYPES: Dict[str, Set[str]] = {
    "primary": {t.value for t in SecretType},  # All types
    "secondary": {
        SecretType.HMAC_PSK.value,
        SecretType.API_KEY.value,
        SecretType.SSH_PUBLIC_KEY.value,
        SecretType.ASSET_REGISTRY.value,
        SecretType.ESCALATION_TOKEN.value,
    },
    "agent": {
        SecretType.HMAC_PSK.value,
        SecretType.AGENT_CONFIG.value,
        SecretType.SSH_PUBLIC_KEY.value,
        SecretType.ESCALATION_TOKEN.value,
    },
}


def can_access_scope(role: str, scope: str) -> bool:
    """Check if a role can access a given secret scope."""
    allowed = _ROLE_ACCESS.get(role, set())
    return scope in allowed


def can_access_secret_type(role: str, secret_type: str) -> bool:
    """Check if a role can access a given secret type."""
    allowed = _ROLE_SECRET_TYPES.get(role, set())
    return secret_type in allowed


# ── Secret Compartment Manager ──────────────────────────────────────


class SecretCompartmentManager:
    """Manages secret compartmentalization across mesh nodes.

    Ensures each node only receives the secrets it needs based on its
    role in the mesh hierarchy. Tracks provisioned secrets per node
    and enforces access policies.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._manifests: Dict[str, NodeSecretManifest] = {}
        self._audit: List[dict] = []
        self._max_audit = 500

    # ── Manifest Management ───────────────────────────────────────

    def register_node(self, node_id: str, role: str) -> NodeSecretManifest:
        """Register a node and create its secret manifest."""
        with self._lock:
            manifest = NodeSecretManifest(node_id=node_id, role=role)
            self._manifests[node_id] = manifest
            self._log_audit("node_registered", {
                "node_id": node_id,
                "role": role,
            })
            return manifest

    def remove_node(self, node_id: str) -> bool:
        """Remove a node's secret manifest (e.g., on decommission)."""
        with self._lock:
            removed = self._manifests.pop(node_id, None)
            if removed:
                self._log_audit("node_removed", {
                    "node_id": node_id,
                    "secrets_revoked": len(removed.secrets),
                })
            return removed is not None

    def get_manifest(self, node_id: str) -> Optional[NodeSecretManifest]:
        with self._lock:
            return self._manifests.get(node_id)

    def list_manifests(self) -> List[dict]:
        with self._lock:
            return [m.to_dict() for m in self._manifests.values()]

    # ── Secret Provisioning ───────────────────────────────────────

    def provision_secret(
        self, node_id: str, entry: SecretEntry
    ) -> bool:
        """Provision a secret to a node if the access policy allows it.

        Returns True if the secret was provisioned, False if denied.
        """
        with self._lock:
            manifest = self._manifests.get(node_id)
            if manifest is None:
                return False

            # Check access policy
            if not can_access_scope(manifest.role, entry.scope):
                self._log_audit("provision_denied", {
                    "node_id": node_id,
                    "role": manifest.role,
                    "scope": entry.scope,
                    "secret_type": entry.secret_type,
                    "reason": "scope_not_allowed",
                })
                return False

            if not can_access_secret_type(manifest.role, entry.secret_type):
                self._log_audit("provision_denied", {
                    "node_id": node_id,
                    "role": manifest.role,
                    "secret_type": entry.secret_type,
                    "reason": "type_not_allowed",
                })
                return False

            entry.node_id = node_id
            manifest.secrets.append(entry)
            self._log_audit("secret_provisioned", {
                "node_id": node_id,
                "secret_id": entry.secret_id,
                "secret_type": entry.secret_type,
                "scope": entry.scope,
            })
            return True

    def revoke_secret(self, node_id: str, secret_id: str) -> bool:
        """Revoke a specific secret from a node."""
        with self._lock:
            manifest = self._manifests.get(node_id)
            if manifest is None:
                return False

            original_len = len(manifest.secrets)
            manifest.secrets = [
                s for s in manifest.secrets if s.secret_id != secret_id
            ]
            revoked = len(manifest.secrets) < original_len
            if revoked:
                self._log_audit("secret_revoked", {
                    "node_id": node_id,
                    "secret_id": secret_id,
                })
            return revoked

    def revoke_all_secrets(self, node_id: str) -> int:
        """Revoke all secrets from a node. Returns count."""
        with self._lock:
            manifest = self._manifests.get(node_id)
            if manifest is None:
                return 0
            count = len(manifest.secrets)
            manifest.secrets = []
            if count:
                self._log_audit("all_secrets_revoked", {
                    "node_id": node_id,
                    "count": count,
                })
            return count

    # ── Queries ───────────────────────────────────────────────────

    def get_node_secrets(self, node_id: str) -> List[dict]:
        """Get all secrets provisioned to a node (metadata only)."""
        with self._lock:
            manifest = self._manifests.get(node_id)
            if manifest is None:
                return []
            return [s.to_dict() for s in manifest.secrets]

    def get_secret_distribution(self) -> dict:
        """Summary of how secrets are distributed across the mesh."""
        with self._lock:
            result = {}
            for node_id, manifest in self._manifests.items():
                result[node_id] = {
                    "role": manifest.role,
                    "secret_count": len(manifest.secrets),
                    "by_type": {},
                }
                for s in manifest.secrets:
                    t = s.secret_type
                    result[node_id]["by_type"][t] = (
                        result[node_id]["by_type"].get(t, 0) + 1
                    )
            return result

    def check_compliance(self, node_id: str) -> dict:
        """Verify a node only has secrets it should have.

        Returns compliance report with any violations.
        """
        with self._lock:
            manifest = self._manifests.get(node_id)
            if manifest is None:
                return {"node_id": node_id, "compliant": True, "violations": []}

            violations = []
            for s in manifest.secrets:
                if not can_access_scope(manifest.role, s.scope):
                    violations.append({
                        "secret_id": s.secret_id,
                        "issue": "scope_violation",
                        "scope": s.scope,
                        "role": manifest.role,
                    })
                if not can_access_secret_type(manifest.role, s.secret_type):
                    violations.append({
                        "secret_id": s.secret_id,
                        "issue": "type_violation",
                        "secret_type": s.secret_type,
                        "role": manifest.role,
                    })

            return {
                "node_id": node_id,
                "role": manifest.role,
                "compliant": len(violations) == 0,
                "violations": violations,
                "total_secrets": len(manifest.secrets),
            }

    # ── Audit Log ─────────────────────────────────────────────────

    def _log_audit(self, event: str, details: dict) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "details": details,
        }
        self._audit.append(entry)
        if len(self._audit) > self._max_audit:
            self._audit = self._audit[-self._max_audit:]

    def get_audit_log(self, limit: int = 50) -> List[dict]:
        with self._lock:
            return list(reversed(self._audit[-limit:]))


# ── Singleton ────────────────────────────────────────────────────────

_instance: Optional[SecretCompartmentManager] = None


def get_secret_compartment_manager() -> SecretCompartmentManager:
    global _instance
    if _instance is None:
        _instance = SecretCompartmentManager()
    return _instance


def set_secret_compartment_manager(m: Optional[SecretCompartmentManager]) -> None:
    global _instance
    _instance = m
