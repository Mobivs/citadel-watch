"""
Node Onboarding Orchestrator — Guided enrollment of remote VPS/computers.

Runs a 6-step workflow:
  1. validate  — Check asset exists, has credential, SSH host set
  2. connect   — Test SSH connection, gather OS info
  3. deploy    — SCP shield.py, install systemd service, verify running
  4. harden    — Apply SSH hardening config (optional)
  5. firewall  — Push default firewall rules + geo-blocks (optional)
  6. verify    — Check sensors active, agent reporting, poll test

Each step tracks status independently (pending/running/completed/failed/skipped).
Progress is broadcast via WebSocket for real-time UI updates.
"""

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .ssh_manager import SSHConnectionManager
    from .shield_database import RemoteShieldDatabase
    from .agent_deployer import AgentDeployer
    from .ssh_hardening import SSHHardeningOrchestrator, HardeningConfig
    from .firewall_manager import DesktopFirewallManager
    from ..intel.assets import AssetInventory
    from ..chat.chat_manager import ChatManager

logger = logging.getLogger(__name__)

ONBOARDING_STEPS = ["validate", "connect", "deploy", "harden", "firewall", "verify"]


@dataclass
class OnboardingConfig:
    """Configuration for onboarding a node."""
    asset_id: str
    skip_hardening: bool = False
    skip_firewall: bool = False
    hardening_config: Optional[Dict] = None
    default_firewall_rules: Optional[List[Dict]] = None

    def to_dict(self) -> dict:
        return {
            "asset_id": self.asset_id,
            "skip_hardening": self.skip_hardening,
            "skip_firewall": self.skip_firewall,
            "hardening_config": self.hardening_config,
            "default_firewall_rules": self.default_firewall_rules,
        }


@dataclass
class StepResult:
    """Result of a single onboarding step."""
    step: str
    status: str  # completed | failed | skipped
    message: str = ""


@dataclass
class OnboardingResult:
    """Overall result of an onboarding session."""
    session_id: str
    asset_id: str
    success: bool
    status: str  # completed | partial | failed
    steps: Dict[str, Dict] = field(default_factory=dict)
    error: str = ""


class OnboardingOrchestrator:
    """Orchestrates node onboarding as a multi-step workflow.

    Args:
        ssh_manager: SSH connection manager.
        shield_db: Shield database for persistence.
        inventory: Asset inventory for validation.
        vault: Vault manager (used by SSH manager).
        agent_deployer: Agent deployer for step 3.
        hardening_orch: SSH hardening orchestrator for step 4.
        firewall_mgr: Firewall manager for step 5.
        chat_manager: Optional chat for progress messages.
        ws_broadcast: Optional async callable for WebSocket broadcasts.
    """

    def __init__(
        self,
        ssh_manager: "SSHConnectionManager",
        shield_db: "RemoteShieldDatabase",
        inventory: "AssetInventory",
        vault=None,
        agent_deployer: Optional["AgentDeployer"] = None,
        hardening_orch: Optional["SSHHardeningOrchestrator"] = None,
        firewall_mgr: Optional["DesktopFirewallManager"] = None,
        chat_manager: Optional["ChatManager"] = None,
        ws_broadcast: Optional[Callable] = None,
    ):
        self._ssh = ssh_manager
        self._db = shield_db
        self._inventory = inventory
        self._vault = vault
        self._deployer = agent_deployer
        self._hardening = hardening_orch
        self._firewall = firewall_mgr
        self._chat = chat_manager
        self._ws_broadcast = ws_broadcast

    async def _broadcast(self, asset_id: str, step: str, status: str, message: str):
        """Broadcast progress via WebSocket."""
        if self._ws_broadcast:
            try:
                await self._ws_broadcast({
                    "type": "onboarding_progress",
                    "asset_id": asset_id,
                    "step": step,
                    "status": status,
                    "message": message,
                })
            except Exception:
                pass

    async def _chat_msg(self, text: str):
        """Post a progress message to SecureChat."""
        if self._chat:
            try:
                await self._chat.send_system(text)
            except Exception:
                pass

    async def start_onboarding(
        self, config: OnboardingConfig
    ) -> OnboardingResult:
        """Run the full onboarding workflow.

        Returns an OnboardingResult with per-step status.
        """
        session_id = str(uuid.uuid4())
        asset_id = config.asset_id

        # Create DB session
        self._db.create_onboarding_session(
            session_id, asset_id, config.to_dict()
        )
        self._db.update_onboarding_status(session_id, "running")

        await self._chat_msg(f"Starting onboarding for {asset_id}...")

        steps_status: Dict[str, Dict] = {}
        failed_steps = []

        # Step 1: Validate
        result = await self._step_validate(session_id, asset_id)
        steps_status["validate"] = {"status": result.status, "message": result.message}
        if result.status == "failed":
            failed_steps.append("validate")
            # Can't continue without valid asset
            self._db.update_onboarding_status(session_id, "failed")
            return OnboardingResult(
                session_id=session_id,
                asset_id=asset_id,
                success=False,
                status="failed",
                steps=steps_status,
                error=result.message,
            )

        # Step 2: Connect
        result = await self._step_connect(session_id, asset_id)
        steps_status["connect"] = {"status": result.status, "message": result.message}
        if result.status == "failed":
            failed_steps.append("connect")
            self._db.update_onboarding_status(session_id, "failed")
            return OnboardingResult(
                session_id=session_id,
                asset_id=asset_id,
                success=False,
                status="failed",
                steps=steps_status,
                error=result.message,
            )

        # Step 3: Deploy
        result = await self._step_deploy(session_id, asset_id)
        steps_status["deploy"] = {"status": result.status, "message": result.message}
        if result.status == "failed":
            failed_steps.append("deploy")

        # Step 4: Harden (optional)
        if config.skip_hardening:
            steps_status["harden"] = {"status": "skipped", "message": "Skipped by user"}
            self._db.update_onboarding_step(session_id, "harden", "skipped", "Skipped by user")
        else:
            result = await self._step_harden(session_id, asset_id, config.hardening_config)
            steps_status["harden"] = {"status": result.status, "message": result.message}
            if result.status == "failed":
                failed_steps.append("harden")

        # Step 5: Firewall (optional)
        if config.skip_firewall:
            steps_status["firewall"] = {"status": "skipped", "message": "Skipped by user"}
            self._db.update_onboarding_step(session_id, "firewall", "skipped", "Skipped by user")
        else:
            result = await self._step_firewall(
                session_id, asset_id, config.default_firewall_rules
            )
            steps_status["firewall"] = {"status": result.status, "message": result.message}
            if result.status == "failed":
                failed_steps.append("firewall")

        # Step 6: Verify
        result = await self._step_verify(session_id, asset_id)
        steps_status["verify"] = {"status": result.status, "message": result.message}
        if result.status == "failed":
            failed_steps.append("verify")

        # Determine overall status
        if not failed_steps:
            overall_status = "completed"
            success = True
        elif len(failed_steps) < len(ONBOARDING_STEPS):
            overall_status = "partial"
            success = False
        else:
            overall_status = "failed"
            success = False

        self._db.update_onboarding_status(session_id, overall_status)

        msg = f"Onboarding {overall_status} for {asset_id}"
        if failed_steps:
            msg += f" (failed: {', '.join(failed_steps)})"
        await self._chat_msg(msg)

        return OnboardingResult(
            session_id=session_id,
            asset_id=asset_id,
            success=success,
            status=overall_status,
            steps=steps_status,
            error=", ".join(failed_steps) if failed_steps else "",
        )

    async def retry_step(
        self, session_id: str, step_name: str
    ) -> StepResult:
        """Re-run a single failed step."""
        session = self._db.get_onboarding_session(session_id)
        if not session:
            return StepResult(step=step_name, status="failed", message="Session not found")

        asset_id = session["asset_id"]
        config = session.get("config", {})

        step_map = {
            "validate": lambda: self._step_validate(session_id, asset_id),
            "connect": lambda: self._step_connect(session_id, asset_id),
            "deploy": lambda: self._step_deploy(session_id, asset_id),
            "harden": lambda: self._step_harden(
                session_id, asset_id, config.get("hardening_config")
            ),
            "firewall": lambda: self._step_firewall(
                session_id, asset_id, config.get("default_firewall_rules")
            ),
            "verify": lambda: self._step_verify(session_id, asset_id),
        }

        runner = step_map.get(step_name)
        if not runner:
            return StepResult(step=step_name, status="failed", message="Unknown step")

        result = await runner()

        # Re-read session from DB to get the step's updated status
        # (each step implementation writes to DB via update_onboarding_step)
        updated_session = self._db.get_onboarding_session(session_id)
        if updated_session:
            steps = updated_session.get("steps", {})
            all_completed = all(
                steps.get(s, {}).get("status") in ("completed", "skipped")
                for s in ONBOARDING_STEPS
            )
            if all_completed:
                self._db.update_onboarding_status(session_id, "completed")

        return result

    def get_status(self, session_id: str) -> Optional[dict]:
        """Get current session state."""
        return self._db.get_onboarding_session(session_id)

    # ── Step implementations ────────────────────────────────────────

    async def _step_validate(self, session_id: str, asset_id: str) -> StepResult:
        """Step 1: Validate asset exists and has required config."""
        self._db.update_onboarding_step(session_id, "validate", "running")
        await self._broadcast(asset_id, "validate", "running", "Validating asset...")

        try:
            asset = self._inventory.get(asset_id)
            if not asset:
                msg = f"Asset {asset_id} not found in inventory"
                self._db.update_onboarding_step(session_id, "validate", "failed", msg)
                await self._broadcast(asset_id, "validate", "failed", msg)
                return StepResult(step="validate", status="failed", message=msg)

            if not getattr(asset, "ip_address", None):
                msg = f"Asset {asset_id} has no IP address configured"
                self._db.update_onboarding_step(session_id, "validate", "failed", msg)
                await self._broadcast(asset_id, "validate", "failed", msg)
                return StepResult(step="validate", status="failed", message=msg)

            msg = f"Asset validated: {asset_id} ({asset.ip_address})"
            self._db.update_onboarding_step(session_id, "validate", "completed", msg)
            await self._broadcast(asset_id, "validate", "completed", msg)
            return StepResult(step="validate", status="completed", message=msg)

        except Exception as exc:
            msg = f"Validation error: {exc}"
            self._db.update_onboarding_step(session_id, "validate", "failed", msg)
            await self._broadcast(asset_id, "validate", "failed", msg)
            return StepResult(step="validate", status="failed", message=msg)

    async def _step_connect(self, session_id: str, asset_id: str) -> StepResult:
        """Step 2: Test SSH connection and gather OS info."""
        self._db.update_onboarding_step(session_id, "connect", "running")
        await self._broadcast(asset_id, "connect", "running", "Testing SSH connection...")

        try:
            await self._ssh.connect(asset_id)

            # Gather OS info
            result = await self._ssh.execute(asset_id, "uname -a", timeout=10)
            os_info = result.stdout.strip() if result.success else "unknown"

            msg = f"SSH connected. OS: {os_info[:80]}"
            self._db.update_onboarding_step(session_id, "connect", "completed", msg)
            await self._broadcast(asset_id, "connect", "completed", msg)
            return StepResult(step="connect", status="completed", message=msg)

        except Exception as exc:
            msg = f"SSH connection failed: {exc}"
            self._db.update_onboarding_step(session_id, "connect", "failed", msg)
            await self._broadcast(asset_id, "connect", "failed", msg)
            return StepResult(step="connect", status="failed", message=msg)

    async def _step_deploy(self, session_id: str, asset_id: str) -> StepResult:
        """Step 3: Deploy shield agent."""
        self._db.update_onboarding_step(session_id, "deploy", "running")
        await self._broadcast(asset_id, "deploy", "running", "Deploying Citadel Shield agent...")

        if not self._deployer:
            msg = "Agent deployer not available"
            self._db.update_onboarding_step(session_id, "deploy", "failed", msg)
            await self._broadcast(asset_id, "deploy", "failed", msg)
            return StepResult(step="deploy", status="failed", message=msg)

        try:
            result = await self._deployer.deploy(asset_id)
            if result.get("success"):
                version = result.get("agent_status", {}).get("version", "?")
                msg = f"Agent deployed successfully (v{version})"
                self._db.update_onboarding_step(session_id, "deploy", "completed", msg)
                await self._broadcast(asset_id, "deploy", "completed", msg)
                return StepResult(step="deploy", status="completed", message=msg)
            else:
                msg = f"Deploy failed: {result.get('error', 'unknown')}"
                self._db.update_onboarding_step(session_id, "deploy", "failed", msg)
                await self._broadcast(asset_id, "deploy", "failed", msg)
                return StepResult(step="deploy", status="failed", message=msg)

        except Exception as exc:
            msg = f"Deploy error: {exc}"
            self._db.update_onboarding_step(session_id, "deploy", "failed", msg)
            await self._broadcast(asset_id, "deploy", "failed", msg)
            return StepResult(step="deploy", status="failed", message=msg)

    async def _step_harden(
        self, session_id: str, asset_id: str, hardening_config: Optional[Dict]
    ) -> StepResult:
        """Step 4: Apply SSH hardening."""
        self._db.update_onboarding_step(session_id, "harden", "running")
        await self._broadcast(asset_id, "harden", "running", "Applying SSH hardening...")

        if not self._hardening:
            msg = "SSH hardening orchestrator not available"
            self._db.update_onboarding_step(session_id, "harden", "failed", msg)
            await self._broadcast(asset_id, "harden", "failed", msg)
            return StepResult(step="harden", status="failed", message=msg)

        try:
            from .ssh_hardening import HardeningConfig

            if hardening_config:
                hconfig = HardeningConfig.from_dict(hardening_config)
            else:
                hconfig = HardeningConfig()  # safe defaults

            result = await self._hardening.harden_asset(asset_id, hconfig)
            if result.success:
                msg = f"SSH hardening applied ({len(result.changes_applied)} changes)"
                self._db.update_onboarding_step(session_id, "harden", "completed", msg)
                await self._broadcast(asset_id, "harden", "completed", msg)
                return StepResult(step="harden", status="completed", message=msg)
            else:
                msg = f"Hardening failed: {result.error}"
                self._db.update_onboarding_step(session_id, "harden", "failed", msg)
                await self._broadcast(asset_id, "harden", "failed", msg)
                return StepResult(step="harden", status="failed", message=msg)

        except Exception as exc:
            msg = f"Hardening error: {exc}"
            self._db.update_onboarding_step(session_id, "harden", "failed", msg)
            await self._broadcast(asset_id, "harden", "failed", msg)
            return StepResult(step="harden", status="failed", message=msg)

    async def _step_firewall(
        self, session_id: str, asset_id: str, default_rules: Optional[List[Dict]]
    ) -> StepResult:
        """Step 5: Configure and push firewall rules."""
        self._db.update_onboarding_step(session_id, "firewall", "running")
        await self._broadcast(asset_id, "firewall", "running", "Configuring firewall...")

        if not self._firewall:
            msg = "Firewall manager not available"
            self._db.update_onboarding_step(session_id, "firewall", "failed", msg)
            await self._broadcast(asset_id, "firewall", "failed", msg)
            return StepResult(step="firewall", status="failed", message=msg)

        try:
            # Add default rules if provided
            if default_rules:
                for rule in default_rules:
                    self._firewall.add_rule(asset_id, rule)

            # Push to VPS
            result = await self._firewall.push_rules(asset_id)
            if result["success"]:
                msg = f"Firewall configured ({result['pushed_count']} rules pushed)"
                self._db.update_onboarding_step(session_id, "firewall", "completed", msg)
                await self._broadcast(asset_id, "firewall", "completed", msg)
                return StepResult(step="firewall", status="completed", message=msg)
            else:
                msg = f"Firewall push failed: {result['error']}"
                self._db.update_onboarding_step(session_id, "firewall", "failed", msg)
                await self._broadcast(asset_id, "firewall", "failed", msg)
                return StepResult(step="firewall", status="failed", message=msg)

        except Exception as exc:
            msg = f"Firewall error: {exc}"
            self._db.update_onboarding_step(session_id, "firewall", "failed", msg)
            await self._broadcast(asset_id, "firewall", "failed", msg)
            return StepResult(step="firewall", status="failed", message=msg)

    async def _step_verify(self, session_id: str, asset_id: str) -> StepResult:
        """Step 6: Verify agent is running and sensors are active."""
        self._db.update_onboarding_step(session_id, "verify", "running")
        await self._broadcast(asset_id, "verify", "running", "Verifying agent status...")

        try:
            result = await self._ssh.execute(
                asset_id,
                "python3 /opt/citadel-shield/shield.py status",
                timeout=10,
            )
            if not result.success:
                msg = f"Status check failed: {result.error}"
                self._db.update_onboarding_step(session_id, "verify", "failed", msg)
                await self._broadcast(asset_id, "verify", "failed", msg)
                return StepResult(step="verify", status="failed", message=msg)

            status = json.loads(result.stdout.strip())
            if status.get("running"):
                msg = (
                    f"Agent verified: v{status.get('version', '?')}, "
                    f"{status.get('unsynced_events', 0)} pending events"
                )
                self._db.update_onboarding_step(session_id, "verify", "completed", msg)
                await self._broadcast(asset_id, "verify", "completed", msg)
                return StepResult(step="verify", status="completed", message=msg)
            else:
                msg = "Agent installed but not running"
                self._db.update_onboarding_step(session_id, "verify", "failed", msg)
                await self._broadcast(asset_id, "verify", "failed", msg)
                return StepResult(step="verify", status="failed", message=msg)

        except Exception as exc:
            msg = f"Verify error: {exc}"
            self._db.update_onboarding_step(session_id, "verify", "failed", msg)
            await self._broadcast(asset_id, "verify", "failed", msg)
            return StepResult(step="verify", status="failed", message=msg)
