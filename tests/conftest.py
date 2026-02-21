"""
Shared pytest fixtures for the Citadel Archer test suite.

Autouse fixtures below isolate tests from the live application data:
  - Audit logger    -> temp directory  (prevents fake events in dashboard)
  - Asset inventory -> memory-only     (prevents ghost assets in assets.db)
  - Chat store      -> temp directory  (prevents test messages in securechat.db)
  - Agent registry  -> temp directory  (prevents ghost agents in agent_registry.db)
"""

import tempfile
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolate_audit_logs(tmp_path, monkeypatch):
    """Redirect the global AuditLogger to a temp directory for every test.

    Without this, any test that (directly or indirectly) calls
    ``get_audit_logger().log_event(...)`` writes into the real
    ``./audit_logs/`` directory, producing fake critical/alert entries
    that show up in the live dashboard.
    """
    import citadel_archer.core.audit_log as audit_mod

    # Reset the singleton so the next call to get_audit_logger() creates
    # a fresh instance pointing at the temp directory.
    old_logger = audit_mod._audit_logger
    audit_mod._audit_logger = None

    # Patch the default so any new AuditLogger() without explicit log_dir
    # goes to the temp directory.
    orig_init = audit_mod.AuditLogger.__init__

    def patched_init(self, log_dir=None, encrypt=False):
        orig_init(self, log_dir=log_dir or tmp_path / "audit_logs", encrypt=encrypt)

    monkeypatch.setattr(audit_mod.AuditLogger, "__init__", patched_init)

    yield

    # Restore the original singleton so subsequent imports in the same
    # process don't keep the temp logger around.
    audit_mod._audit_logger = old_logger


@pytest.fixture(autouse=True)
def _isolate_chat_store(tmp_path, monkeypatch):
    """Redirect ChatStore to a temp directory for every test.

    Without this, tests that create a ChatManager (directly or via API)
    write messages into the real ``data/securechat.db``, producing fake
    escalation alerts and system messages in the live chat window.
    """
    from citadel_archer.chat.chat_store import ChatStore
    import citadel_archer.api.chat_routes as chat_mod

    # Reset the singleton chat manager so a fresh one is created per test.
    old_manager = getattr(chat_mod, "_chat_manager", None)
    chat_mod._chat_manager = None

    orig_init = ChatStore.__init__
    tmp_db = tmp_path / "securechat.db"

    def patched_init(self, db_path=None):
        # None means "use the module default path" — redirect to temp.
        effective = tmp_db if db_path is None else db_path
        orig_init(self, db_path=effective)

    monkeypatch.setattr(ChatStore, "__init__", patched_init)

    yield

    chat_mod._chat_manager = old_manager


@pytest.fixture(autouse=True)
def _isolate_agent_registry(tmp_path, monkeypatch):
    """Redirect AgentRegistry to a temp directory for every test.

    Without this, tests that enroll agents write to the real
    ``data/agent_registry.db``, producing ghost agents in the dashboard.
    """
    import citadel_archer.api.agent_api_routes as agent_mod

    old_registry = getattr(agent_mod, "_registry", None)
    agent_mod._registry = None

    from citadel_archer.chat.agent_registry import AgentRegistry
    orig_init = AgentRegistry.__init__
    tmp_db = tmp_path / "agent_registry.db"

    def patched_init(self, db_path=None):
        # db_path=None means "use default" — redirect to temp for tests.
        if db_path is None:
            orig_init(self, db_path=str(tmp_db))
        else:
            orig_init(self, db_path=db_path)

    monkeypatch.setattr(AgentRegistry, "__init__", patched_init)

    yield

    agent_mod._registry = old_registry


@pytest.fixture(autouse=True)
def _isolate_asset_inventory():
    """Reset the global AssetInventory singleton for every test.

    Without this, tests that create assets (directly or via API calls)
    write to the real ``data/assets.db``, producing ghost entries like
    ``test-vps-01`` that show up in the live dashboard.

    After this fixture runs, ``get_inventory()`` returns a memory-only
    inventory (db_path=None) that is discarded at the end of each test.
    """
    from citadel_archer.api.asset_routes import (
        _inventory,
        set_inventory,
    )
    import citadel_archer.api.asset_routes as asset_mod

    old_inventory = asset_mod._inventory
    # Force the next get_inventory() call to create a memory-only instance
    asset_mod._inventory = None

    # Patch AssetInventory default to memory-only
    from citadel_archer.intel.assets import AssetInventory
    orig_init = AssetInventory.__init__

    _real_default = object()

    def patched_init(self, db_path=_real_default):
        if db_path is _real_default:
            # Default invocation -> memory-only for tests
            orig_init(self, db_path=None)
        else:
            # Explicit db_path (e.g. test passing tmp_path) -> honour it
            orig_init(self, db_path=db_path)

    AssetInventory.__init__ = patched_init

    yield

    # Restore
    AssetInventory.__init__ = orig_init
    asset_mod._inventory = old_inventory
