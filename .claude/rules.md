# Citadel Archer Project Rules

**These rules are automatically enforced by Claude Code for all work in this project.**

## 1. PRD-First Development

### MANDATORY: Before ANY Implementation
1. **Read the PRD** section relevant to the task
2. **Quote the requirement** in your response to user
3. **Explain alignment** between PRD and your implementation approach
4. **Flag deviations** if your approach differs from PRD

**Example Response Format**:
> "I'm implementing Guardian file monitoring.
>
> **PRD Reference** (Section: Guardian Module):
> 'Real-time filesystem monitoring (unauthorized changes, suspicious binaries)'
>
> **Implementation Approach**:
> I'll use Python's `watchdog` library for filesystem events, with filters for:
> - Unauthorized changes (files modified in system directories)
> - Suspicious binaries (unsigned .exe, double extensions)
>
> **PRD Compliance**: ✅ This aligns with PRD's 'Python agent with OS-level hooks (watchdog, psutil)'"

### If PRD Doesn't Cover It
If user requests something not in PRD:
1. Acknowledge it's not in current PRD
2. Explain which phase it might belong to (or if it's new)
3. Propose updating PRD BEFORE implementing
4. Get user approval on PRD update

**Do NOT** implement features not in PRD without this process.

---

## 2. Code Standards (Enforced)

### Every Python File MUST Have:
```python
"""
Module: [name]
PRD Reference: [Section]
Phase: [1-6]
Purpose: [Brief description matching PRD]

Security Level: [How this respects Observer/Guardian/Sentinel]
"""
```

### Every Security Decision MUST:
- Check current security level
- Log the decision and rationale
- Respect user's chosen autonomy level

**Example**:
```python
def quarantine_file(file_path: str):
    """
    Quarantine suspicious file.
    PRD: Guardian Module - Auto-quarantine malware signatures
    Security Level: Guardian+ only (Observer mode alerts instead)
    """
    if self.security_level == SecurityLevel.OBSERVER:
        self.alert_user(f"Suspicious file detected: {file_path}")
        return

    # Guardian and Sentinel can auto-quarantine
    self.audit_log.security_action(
        action="quarantine_file",
        target=file_path,
        reason="Matched malware signature XYZ",
        security_level=self.security_level
    )
    shutil.move(file_path, QUARANTINE_DIR)
```

---

## 3. Phase Discipline

**Current Phase**: Phase 1 - Foundation

### Phase 1 In-Scope:
- Guardian agent (file, process monitoring)
- Basic Vault (password storage, encryption)
- Basic Dashboard (status, alerts)
- Threat rules engine
- Dark glassmorphic UI

### Out of Scope for Phase 1:
- AI threat analysis (Phase 2)
- Panic Room (Phase 3)
- SecureChat (Phase 4)
- Remote Shield (Phase 5)
- Community features (Phase 6)

**If user asks for out-of-scope feature**:
> "That's a great feature! According to the PRD, [Feature] is planned for Phase [X].
>
> We're currently in Phase 1 focusing on [in-scope items].
>
> Would you like to:
> A) Add it to Phase [X] backlog
> B) Re-prioritize and move it to Phase 1 (requires PRD update)
> C) Build a simplified version now, full version later"

---

## 4. Technology Constraints

### Allowed (PRD-Locked):
- **Backend**: Python 3.11+, FastAPI, pywebview
- **Frontend**: React 18+, TypeScript, Tailwind CSS
- **Database**: SQLCipher (Vault), SQLite (logs)
- **AI**: Claude API or OpenAI API
- **Platform**: Windows 10/11 (Phase 1)

### NOT Allowed Without PRD Update:
- Different languages (C#, Rust, Go, etc.)
- Different frameworks (Django, Express, etc.)
- Different UI libraries (Angular, Svelte, Vue)
- Cloud databases (PostgreSQL, MongoDB in cloud)

**If you need to deviate**:
> "The PRD specifies [X], but I recommend [Y] because [reason].
>
> This would require a PRD update. Should I:
> 1. Proceed with PRD approach [X]
> 2. Draft PRD amendment to use [Y] instead
> 3. Discuss trade-offs before deciding"

---

## 5. Security & Privacy Non-Negotiables

### NEVER:
- ❌ Add telemetry or data collection
- ❌ Send user data to external servers (except user's own AI API)
- ❌ Implement offensive security features
- ❌ Profile users or collect behavioral data
- ❌ Create backdoors or disable user's ability to control the AI

### ALWAYS:
- ✅ Encrypt sensitive data (AES-256)
- ✅ Respect user's security level choice
- ✅ Log all AI security decisions (audit trail)
- ✅ Ask before destructive actions
- ✅ Local-first storage (user's machine)

---

## 6. Documentation Requirements

### For Every Feature:
1. **Code comments**: Reference PRD section
2. **Docstrings**: Explain security implications
3. **Audit logs**: Record all security decisions
4. **User-facing**: Update docs/ if user-visible

### When Completing a Module:
- Update relevant checklist (docs/checklists/)
- Mark PRD requirements as ✅ complete
- Document any deviations in ADR (docs/adr/)

---

## 7. Testing Requirements

### Every Security Feature Needs:
- **Unit tests**: Core functionality works
- **Security level tests**: Respects Observer/Guardian/Sentinel
- **Integration tests**: Works with AI brain
- **User acceptance**: Matches PRD user story

**Test naming convention**:
```python
def test_guardian_file_monitor_prd_compliant():
    """
    PRD Compliance Test: Guardian Module
    Requirement: "Real-time filesystem monitoring"
    """
```

---

## 8. AI Assistant Behavior (You, Claude!)

### When User Asks to Implement Something:
1. ✅ Check PRD first
2. ✅ Quote relevant section
3. ✅ Explain how your approach aligns
4. ✅ Implement with PRD comments
5. ✅ Suggest tests to verify compliance

### When You Notice Drift:
> "⚠️ **PRD Drift Alert**: The code in [file] implements [X], but the PRD specifies [Y].
>
> Should we:
> A) Update code to match PRD
> B) Update PRD to reflect this better approach (explain why)
> C) Discuss the discrepancy"

### Weekly Reminder:
Every Monday (or after 7 days of work), proactively run:
> "It's been a week. Should I run `/check-prd` to verify we're still aligned with the PRD?"

---

## 9. Git Commit Standards

### Commit Message Format:
```
<type>: <description> (PRD:<section>)

Examples:
feat: Add file monitoring to Guardian (PRD:Guardian:FileMonitoring)
fix: Respect Observer security level in quarantine (PRD:SecurityLevels)
docs: Update Phase 1 completion checklist (PRD:Phase1)
refactor: Simplify AI decision engine (PRD:AI-Centric)
```

### Branch Naming:
```
feature/prd-guardian-file-monitor
fix/prd-security-level-observer
phase1/prd-vault-encryption
```

---

## 10. User Communication

### Be Transparent About PRD:
- Tell user which PRD section you're working on
- Explain when something is out of scope
- Celebrate when features are PRD-compliant
- Flag deviations early

### Example:
> "✅ Guardian file monitoring is now complete and PRD-compliant!
>
> **Implemented**:
> - Real-time filesystem monitoring (watchdog)
> - Suspicious binary detection
> - Security level integration
>
> **PRD Section**: Guardian Module - Local Machine Protection
>
> **Next PRD Requirement**: Process monitoring
>
> Ready to move forward?"

---

## Quick Commands

- `/check-prd` - Run PRD compliance audit
- `git log --grep="PRD:"` - See all PRD-referenced commits
- Read `.claude/knowledge/prd-core.md` - Quick PRD reference

---

**These rules ensure we build what we promised in the PRD, not what randomly emerges during development.**
