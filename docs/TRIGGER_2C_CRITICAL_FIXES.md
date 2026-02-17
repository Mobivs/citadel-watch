# Trigger 2c Critical Fixes - Action Required

**Status**: 🔴 **BLOCKING ISSUES FOUND**
**Files Affected**: 2 critical bugs, 3 medium-priority issues
**Review Date**: 2026-02-14

---

## 🔴 CRITICAL BUG #1: NameError in `activate_panic_v2`

**File**: `src/citadel_archer/api/panic_routes.py:683`
**Impact**: 100% crash rate when v2 activation endpoint is called
**Fix Effort**: 1 line

### Problem

```python
@router.post("/activate/v2", response_model=dict)
async def activate_panic_v2(
    request: PanicActivateV2Request,
    current_user: dict = Depends(get_current_user)
) -> dict:
    # ... validation code ...

    # Line 683 - ERROR: 'manager' is not defined!
    chat = getattr(manager, '_chat_manager', None)  # NameError!
```

Variable `manager` does not exist in this function scope. This is a copy-paste error from the v1 activation endpoint.

### Fix

Add this line **before line 682** (before "# Escalate to AI via SecureChat"):

```python
    # Store in database
    db = _get_db()
    db.create_session(session)

    # Add this line:
    manager = get_panic_manager()

    # Escalate to AI via SecureChat (Trigger 2c)
    chat = getattr(manager, '_chat_manager', None)
```

**Complete fixed section (lines 678-696)**:

```python
    # Store in database
    db = _get_db()
    db.create_session(session)

    # Get panic manager for chat escalation
    manager = get_panic_manager()

    # Escalate to AI via SecureChat (Trigger 2c)
    chat = getattr(manager, '_chat_manager', None)
    if chat:
        try:
            summary = (
                f"[Panic Room] ACTIVATED — {request.reason}\n"
                f"Playbooks: {'; '.join(request.playbooks)}\n"
                f"Target assets: {'; '.join(target_assets)}\n"
                f"Session: {session_id}\n"
                f"Critical/high-priority emergency response initiated."
            )
            await chat.send_system(summary, MessageType.EVENT)
        except Exception:
            pass  # Chat failure must never block panic activation
```

---

## 🔴 CRITICAL BUG #2: Type Error in `_notify_failure`

**File**: `src/citadel_archer/panic/panic_manager.py:581`
**Impact**: Crash when non-string errors are passed
**Fix Effort**: 3 lines

### Problem

```python
async def _notify_failure(self, session: PanicSession, error: str):
    """Send failure notification to AI via SecureChat (Trigger 2c)."""
    logger.error(f"Panic session {session.id} failed: {error}")
    chat = self._chat_manager
    if chat:
        try:
            summary = (
                f"[Panic Room] Session FAILED — {session.trigger_reason}\n"
                f"Session: {session.id} | Error: {error[:200]}\n"  # ← Crash if error is not a string!
                # ...
```

If `error` is `None`, an `Exception` object, or any non-string type, `error[:200]` will raise `TypeError`.

### Fix

Replace lines 573-586 with:

```python
async def _notify_failure(self, session: PanicSession, error: str):
    """Send failure notification to AI via SecureChat (Trigger 2c)."""
    logger.error(f"Panic session {session.id} failed: {error}")

    # Defensive string conversion
    error_str = str(error) if error is not None else "Unknown error"

    chat = self._chat_manager
    if chat:
        try:
            summary = (
                f"[Panic Room] Session FAILED — {session.trigger_reason}\n"
                f"Session: {session.id} | Error: {error_str[:200]}\n"
                f"Critical/high-priority action failed. Manual intervention may be needed."
            )
            await chat.send_system(summary, MessageType.EVENT)
        except Exception:
            logger.warning("Failed to send panic failure to chat")
```

---

## ✅ VERIFIED: DB Interface Compatibility

**Files**: `panic_manager.py`, `panic_routes.py`, `panic_database.py`
**Status**: ✅ **NO ACTION REQUIRED**

### Investigation Result

`PanicDatabase` **correctly implements** asyncpg-compatible interface:

```python
# panic_database.py:128-138
@contextlib.asynccontextmanager
async def acquire(self):
    """asyncpg-compatible acquire() — returns a _ConnWrapper.

    Reuses a single shared wrapper per PanicDatabase instance to avoid
    opening a new SQLite connection on every call. The wrapper is
    created lazily and kept alive for the lifetime of the database.
    """
    if not hasattr(self, '_shared_wrapper') or self._shared_wrapper is None:
        self._shared_wrapper = _ConnWrapper(self.db_path)
    yield self._shared_wrapper
```

**Conclusion**: The docstring at line 120-122 explicitly states this was designed for asyncpg compatibility:

> "Also exposes an asyncpg-compatible ``acquire()`` async context
> manager so that action classes (which were written for asyncpg)
> work without modification."

**No fix needed** — this was a well-architected adapter pattern from the start.

---

## 🟡 MEDIUM PRIORITY #4: Standardize Attribute Access

**Files**: `panic_manager.py:561`, `panic_routes.py:188,683`
**Impact**: Code clarity and maintainability
**Fix Effort**: 2 lines

### Problem

Inconsistent pattern for accessing `_chat_manager`:

```python
# panic_manager.py (direct access):
chat = self._chat_manager

# panic_routes.py (defensive access):
chat = getattr(manager, '_chat_manager', None)
```

### Fix

Since `_chat_manager` is **always** initialized in `__init__` (line 60), use direct access everywhere:

```python
# panic_routes.py - Change line 188 and 683:
# From:
chat = getattr(manager, '_chat_manager', None)

# To:
chat = manager._chat_manager
```

---

## 🟡 MEDIUM PRIORITY #5: Document Thread Safety

**File**: `panic_manager.py:62-64`
**Impact**: Future maintainability
**Fix Effort**: Documentation only

### Problem

`set_chat_manager()` is called from startup code but reads happen in async background tasks. Thread safety relies on Python's GIL and atomic reference assignment, but this isn't documented.

### Fix

Add docstring:

```python
def set_chat_manager(self, chat_manager):
    """Wire ChatManager for AI escalation (Trigger 2c).

    Thread-safety note: This method performs a single atomic reference
    assignment which is safe under Python's GIL. The _notify_completion
    and _notify_failure methods capture the reference to a local variable
    before use, ensuring consistency even if chat_manager is replaced
    during execution.

    This method should only be called during application startup or
    hot-reload scenarios. Do not call repeatedly during normal operation.
    """
    self._chat_manager = chat_manager
```

---

## Test Coverage Needed

### Add to `tests/test_panic_routes_integration.py`:

```python
@pytest.mark.asyncio
async def test_activate_v2_chat_escalation():
    """Integration test: v2 activation triggers chat escalation."""
    # Mock ChatManager
    # POST to /api/panic/activate/v2
    # Verify chat.send_system called with correct format
    pass

@pytest.mark.asyncio
async def test_activate_v2_chat_failure_non_blocking():
    """Verify chat failure doesn't block v2 activation."""
    # Mock ChatManager to raise exception
    # POST to /api/panic/activate/v2
    # Should return 200 (activation succeeds despite chat failure)
    pass
```

### Add to `tests/test_panic_escalation.py`:

```python
@pytest.mark.asyncio
async def test_notify_failure_with_exception_object():
    """_notify_failure should handle Exception objects safely."""
    chat = _make_chat_manager()
    pm = _make_panic_manager(chat)
    session = _make_session()

    # Pass an Exception object (not a string)
    exception = ValueError("Network timeout")
    await pm._notify_failure(session, exception)  # Should not crash

    # Verify chat.send_system was called
    chat.send_system.assert_called_once()
    text = chat.send_system.call_args[0][0]
    assert "Network timeout" in text

@pytest.mark.asyncio
async def test_notify_failure_with_none():
    """_notify_failure should handle None error safely."""
    chat = _make_chat_manager()
    pm = _make_panic_manager(chat)
    session = _make_session()

    await pm._notify_failure(session, None)  # Should not crash

    chat.send_system.assert_called_once()
    text = chat.send_system.call_args[0][0]
    assert "Unknown error" in text or "None" in text
```

---

## Pre-Merge Checklist

- [ ] **CRITICAL**: Fix bug #1 (add `manager = get_panic_manager()` to v2 route)
- [ ] **CRITICAL**: Fix bug #2 (add defensive `str()` conversion in `_notify_failure`)
- [x] ~~**CRITICAL**: Verify `PanicDatabase.acquire()` exists and works~~ ✅ VERIFIED
- [ ] **MEDIUM**: Run integration tests for v2 activation
- [ ] **MEDIUM**: Add test for non-string error handling
- [ ] **MEDIUM**: Standardize attribute access pattern (optional)
- [ ] **MEDIUM**: Add thread-safety documentation (optional)

---

## Files to Modify

1. **`src/citadel_archer/api/panic_routes.py`**
   - Line 682: Add `manager = get_panic_manager()`
   - Line 188, 683 (optional): Replace `getattr()` with direct access

2. **`src/citadel_archer/panic/panic_manager.py`**
   - Line 573-586: Add defensive `str()` conversion
   - Line 62 (optional): Add docstring for `set_chat_manager()`

3. **`tests/test_panic_escalation.py`** (new tests)
   - Add `test_notify_failure_with_exception_object()`
   - Add `test_notify_failure_with_none()`

4. **`tests/test_panic_routes_integration.py`** (new file, recommended)
   - Add integration tests for v2 activation

---

## Estimated Fix Time

- **Critical fixes**: 15 minutes
- **Verification testing**: 30 minutes
- **New test cases**: 1 hour
- **Total**: ~2 hours to production-ready

---

## Risk If Not Fixed

| Bug | Risk Level | Failure Mode |
|-----|-----------|--------------|
| #1 (v2 NameError) | 🔴 **CRITICAL** | 100% crash on v2 activation → no panic room functionality for v2 API |
| #2 (Type error) | 🔴 **CRITICAL** | Panic failures don't escalate to AI → operator unaware of critical failures |
| ~~#3 (DB interface)~~ | ✅ **VERIFIED OK** | ~~No issue found — PanicDatabase implements asyncpg interface~~ |
| #4 (Attribute access) | 🟢 **LOW** | Code maintainability issue only |
| #5 (Thread safety) | 🟢 **LOW** | Documentation gap, no functional issue |

---

## Approval Status

**Before fixes**: ❌ **NOT READY FOR PRODUCTION**
**After critical fixes**: ✅ **READY FOR STAGING**
**After all fixes**: ✅ **PRODUCTION READY**

---

**Reviewer**: Claude Code
**Next Steps**: Apply fixes #1-2, verify #3, then re-test before merge.
