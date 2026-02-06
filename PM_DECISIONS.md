# PM Decisions — Section 8 Clarifications

**Project:** Citadel-Archer Phase 1
**Date:** 2026-02-06
**Source:** Scott Vickrey (Product Owner) — Telegram 14:49 UTC
**Status:** ✅ RESOLVED

---

## Question 1: Where is existing Citadel Archer code located?

**Answer:** GitHub repository at https://github.com/Mobivs/citadel-watch

**Details:**
- Public repo (already cloned to `/tmp/citadel-watch/` for team access)
- Contains:
  - PRD v0.2.3 (docs/PRD.md)
  - Phase 1 compliance checklist (docs/checklists/phase-1-compliance.md)
  - Skeleton code in src/, frontend/
  - Tests and documentation started
- **Dev Agent task:** Clone fresh to `/projects/active/citadel-archer/citadel-watch-source/` for working copy, preserve existing code structure

**Reasoning:**
- Code exists, so Dev Agent should extend/refactor rather than rewrite
- Per SPEC Section 1: "Dev Agent should audit and understand the current codebase before writing new code"
- Having a working copy in project directory keeps builds isolated

---

## Question 2: Which messaging service does Forge use to reach Scott?

**Answer:** Telegram

**Details:**
- Scott's Telegram user ID: 7663070732
- Already paired and operational
- Used for all alerts, status updates, notifications
- Direct messaging channel between Forge and Scott

**Reasoning:**
- Simple, reliable, already set up
- No configuration needed
- Use existing Telegram integration for all Citadel-Archer team notifications

---

## Question 3: How many distinct secrets exist today? (5? 50?)

**Answer:** Unknown (to be audited as part of Phase 1)

**Details:**
- Exact count unknown at this time
- Categories likely include:
  - Anthropic API keys
  - Messaging service credentials (Telegram)
  - Git/GitHub tokens
  - Hostinger API tokens
  - Database passwords
  - SSL/TLS certificates
  - Any other service credentials
- **Phase 1 task:** Audit and inventory all current secrets as first task

**Reasoning:**
- This is a MUST-HAVE for Phase 1 anyway (per SPEC: "Secrets encrypted at rest")
- Dev Agent can do a comprehensive audit as Task 1
- Knowing the exact count informs secret store design (if 5 keys ≠ 50 keys, storage approach differs)

**Decision:** Mark as "TBD — Audit in Phase 1 Task 1"

---

## Question 4: Any secrets shared between services?

**Answer:** Secrets are isolated per service. Will be stored in Vault (consolidated secret store).

**Details:**
- Current state: Each service has its own credentials
- Future state (Phase 1): All secrets stored in centralized encrypted vault
- No current sharing identified, but will be reviewed during audit
- Vault design must support:
  - Per-service credential isolation
  - Scoped access (agent gets only what it needs)
  - Rotation without breaking services

**Reasoning:**
- Vault provides the isolation mechanism
- Phase 1 SPEC requires scoped access, so sharing will be prevented by design
- Audit (Task 1) will identify any current sharing that needs remediation

---

## Question 5: What's the VPS backup strategy?

**Answer:** Manual daily snapshot + weekly auto backup by Hostinger

**Details:**
- **Manual:** Scott runs daily snapshot (likely via Hostinger panel or CLI)
- **Automated:** Hostinger provides weekly auto backups (built-in, no action needed)
- Recovery: Restore from snapshot/backup via Hostinger control panel
- RPO (Recovery Point Objective): 1 day (daily snapshots)
- RTO (Recovery Time Objective): Unknown (depends on restore speed)

**Implications for Citadel-Archer:**
- Encryption keys MUST be backed up securely (if we encrypt secrets, key loss = data loss)
- Vault design must account for backup/restore scenarios
- Consider: Store encryption key separately from secrets, or make it recoverable from Hostinger backups

**Reasoning:**
- Hostinger backups mean VPS is protected
- Secret encryption key must survive VPS restoration
- Task: Include backup/recovery testing in Phase 1 testing plan

---

## Summary for ARCHITECTURE.md

**Ready for Opus Lead to design around:**
1. ✅ Code location: GitHub, clone to project directory
2. ✅ Messaging: Telegram (already integrated)
3. ✅ Secrets count: Unknown, will audit in Phase 1 Task 1
4. ✅ Secret sharing: None planned, Vault enforces isolation
5. ✅ Backups: Daily manual + weekly auto, key recovery must be designed

**No blockers.** All answers sufficient for ARCHITECTURE.md design.

---

## Next Steps

1. ✅ **Opus Lead:** Write ARCHITECTURE.md + TASKS.md (now unblocked)
2. ⏳ **Dev Agent:** Execute Phase 1 tasks starting with secret audit
3. ⏳ **Forge:** Monitor progress, update STATUS.md

**Timeline:** Opus Lead architecture design can start immediately.

---

*Decisions documented by: Forge (AI Liaison)*
*Approved by: Scott Vickrey (Product Owner)*
