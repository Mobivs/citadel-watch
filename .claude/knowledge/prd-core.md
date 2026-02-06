# Citadel Archer - PRD Core Principles

**This file is automatically loaded by Claude Code for every conversation in this project.**

## 🚨 CRITICAL: THIS IS A DESKTOP APPLICATION 🚨

**CITADEL ARCHER IS A WINDOWS DESKTOP APPLICATION (subprocess + Edge app mode), NOT A WEB APP**

Read this EVERY time before responding:
- ✅ **DESKTOP APP** - Opens in native-looking window (Edge app mode via subprocess), NOT browser
- ✅ **EMBEDDED BACKEND** - FastAPI runs internally in background thread, managed by desktop app
- ✅ **SINGLE EXECUTABLE** - User runs ONE app, backend starts automatically
- ✅ **PROCESS LIFECYCLE** - App manages all processes, cleans up on exit (no ghost processes)
- ❌ **NOT A WEB APP** - No browser deployment, no SaaS
- ❌ **NOT SEPARATE BACKEND** - Backend is internal, NOT independently run

**Architecture Pattern**: See global knowledge base → `desktop-app-pattern.md` for complete reusable pattern.

**If you suggest browser-based features, web deployment, or separate backend server, you've FAILED to remember this.**

## Project Identity
- **Name**: Citadel Archer
- **Version**: 0.2.3 (MVP Phase 1 in progress)
- **PRD Location**: `docs/PRD.md`
- **Philosophy**: AI-centric defensive security platform (proprietary, with free tier)
- **Application Type**: **WINDOWS DESKTOP APP** (subprocess + Edge app mode + FastAPI embedded)
- **Latest Changes**:
  - **DESKTOP APP** (subprocess + Edge): Zero dependencies, native window, embedded backend (v0.2.3) 🖥️ CRITICAL
  - **VANILLA JS OVER REACT**: Security-first frontend (fewer deps = more auditable) (v0.2.3) 🛡️
  - **PROACTIVE PROTECTION**: AI acts FIRST, informs AFTER. Questions are RARE. (v0.2.2) ⚠️ CRITICAL
  - Progressive Disclosure UX: Simple by default, advanced on-demand (v0.2.1)
  - VPS Protection (Remote Shield) moved to Phase 2 (user priority) (v0.2.0)

## Core Operating Principles

### 1. PRD is the Source of Truth
- **ALWAYS** reference the PRD before implementing features
- **NEVER** implement features not defined in PRD without updating PRD first
- If PRD conflicts with implementation needs, UPDATE PRD (with rationale), then code

### 2. Every Task References PRD
When working on ANY feature or task:
1. State which PRD section you're implementing
2. Quote the relevant PRD requirement
3. Explain how your implementation fulfills it
4. Flag any deviations (and propose PRD update)

**Example**:
```
Implementing: Guardian File Monitoring
PRD Reference: Section "Guardian - Local Machine Protection"
PRD Quote: "Real-time filesystem monitoring (unauthorized changes, suspicious binaries)"
Implementation: Using watchdog library for real-time events, psutil for process context
Compliance: ✅ Fully aligned with PRD technical approach
```

### 3. AI-Centric Development
- AI (Claude) should be treated as the "brain" of the system
- Modules (Guardian, Watchtower, Vault) are sensors/tools for the AI
- Security levels (Observer/Guardian/Sentinel) must be respected in ALL code
- Every security decision goes through AI analysis

### 4. Security-First Mindset
- No offensive capabilities (defense only)
- Privacy first (local-first, no telemetry)
- Proprietary code (protect algorithms from attackers)
- User control (transparency about AI capabilities)

### 5. Phase Discipline
We're currently in **Phase 1: Foundation (Months 1-3)**

**In scope for Phase 1:**
- Core Guardian agent (file monitoring, process monitoring)
- Basic Dashboard (system status, manual scan)
- Vault (password storage, basic encryption)
- Threat detection rules engine
- Initial dark glassmorphic UI

**Phase 2 Scope (Months 4-6)** - Next Up! 🔥
- Intel module + AI threat analysis
- **Remote Shield VPS agent (Ubuntu/Debian)**
- SSH hardening, firewall management
- Unified threat analysis (local + VPS)

**OUT of scope for Phase 1:**
- AI-powered threat analysis (Phase 2)
- VPS protection (Phase 2) - **MOVED FROM PHASE 5**
- Panic Room (Phase 3)
- SecureChat (Phase 4)
- Family computer protection (Phase 5)

**Important**: VPS protection is now Phase 2 (not Phase 5). This is a core priority, not an afterthought.

If user requests out-of-scope features, acknowledge them and propose adding to appropriate phase.

## Technology Constraints

**Locked-in Tech Stack:**
- **Backend**: Python 3.11+, FastAPI (embedded in background thread)
- **Desktop Wrapper**: subprocess + Edge app mode (no external GUI framework)
- **Frontend**: Vanilla JavaScript (ES6+ modules), Web Components, Tailwind CSS
- **Database**: SQLCipher (for Vault)
- **Platform**: Windows 10/11 (Phase 1), Ubuntu (Phase 2 for VPS)
- **AI**: Cloud LLMs (Claude API, OpenAI) - local models in Phase 3+

**DO NOT** introduce different frameworks without PRD update and explicit approval.

## UX & Communication Standards

### CRITICAL: Proactive Protection (ACT, Don't Ask)

**🚨 MOST IMPORTANT PRINCIPLE 🚨**:
> **AI acts FIRST (within security level), informs AFTER. Questions are RARE (<5% of cases).**
>
> If we're asking "Should I block this malware?" we've already FAILED.

**Decision Flow**:
```
Threat Detected
    ↓
Confidence >95%? → YES → ACT NOW → Inform user after
                → NO
                    ↓
User involved? → YES → Ask (they might know context)
               → NO → Act conservatively (monitor/block) → Escalate if needed
```

**When AI ACTS AUTONOMOUSLY (No questions)**:
- Known malware/C2/exploits → Block/quarantine immediately
- Obvious malicious behavior → Kill process immediately
- 95%+ confidence → Act first, explain after

**When AI ASKS (RARE, <5%)**:
- User explicitly initiated suspicious action ("You're about to run crack.exe...")
- Ambiguous + HIGH impact (wants to delete entire user folder)
- Conflicting signals (legit software acting weird)

**Default Behavior**: Protect proactively, explain clearly, allow override if needed.

---

### Progressive Disclosure (Simplicity First)

**CRITICAL**: Most users are NOT security experts. UI and AI communication must be simple by default.

**AI Communication Rules**:
1. ✅ **ACT FIRST, inform AFTER**: "I blocked it. You're safe." NOT "Should I block this?"
2. ✅ **Plain language first**: "A suspicious program tried to connect to a hacker server" NOT "CVE-2024-1337 exploitation attempt detected"
3. ✅ **Calm and reassuring**: "I blocked it. You're safe." NOT "CRITICAL THREAT DETECTED"
4. ✅ **Action-oriented**: Tell user what happened and what to do (if anything)
5. ✅ **Technical details on-demand**: Always available via "Show Details", never forced
6. ✅ **Color coding**: 🟢 Safe | 🟡 Investigating | 🟠 Action Taken | 🔴 Critical

**Alert Levels**:
- **🟢 INFO**: Normal activity, no alert needed (logged only)
- **🟡 INVESTIGATE**: AI is checking something unusual
- **🟠 ALERT**: AI took action (blocked, quarantined), user informed
- **🔴 CRITICAL**: User decision required

**Dashboard Views**:
- **Simple Mode** (Default): Green status, count of threats blocked, "You're protected"
- **Advanced Mode**: Technical details, event streams, forensic logs

**When Writing UI Code**:
- Default to Simple Mode
- Make "Show Details" / "Advanced View" clearly available
- Never overwhelm user with jargon
- AI explains WHY something is a threat, not just WHAT it is

---

## Code Standards

### Required in ALL Code:
1. **PRD Reference Comment** at top of files/classes:
   ```python
   # PRD: Guardian Module - File Monitoring
   # Reference: docs/PRD.md v0.1.0, Section: Guardian
   ```

2. **Security Level Checks** where relevant:
   ```python
   if security_level == SecurityLevel.OBSERVER:
       # Alert only, no autonomous action
   elif security_level == SecurityLevel.GUARDIAN:
       # Auto-respond to known threats
   ```

3. **Audit Logging** for all security decisions:
   ```python
   logger.security(f"AI Decision: {action} - Reason: {rationale}")
   ```

## When to Update PRD

Update PRD (docs/PRD.md) BEFORE implementing if:
- Technical constraint makes PRD approach impossible
- Security concern requires different approach
- User feedback changes requirements
- Better implementation discovered that changes architecture

**Process**:
1. Increment version (0.1.0 → 0.2.0)
2. Add entry to CHANGELOG section
3. Mark changed sections
4. Get user approval
5. THEN implement

## Phase Completion Checklist

Before moving from Phase 1 to Phase 2, we MUST verify:
- [ ] All Phase 1 PRD requirements implemented
- [ ] All deviations documented in PRD
- [ ] Phase 1 compliance checklist 100% complete
- [ ] User acceptance testing passed
- [ ] No broken features from PRD scope

## Quick Reference

- **Full PRD**: `docs/PRD.md`
- **Phase 1 Checklist**: `docs/checklists/phase-1-compliance.md` (to be created)
- **ADR Template**: `docs/adr/000-template.md` (to be created)
- **Current Phase**: Phase 1 - Foundation
- **Target**: Windows 10/11 local machine protection

---

**REMEMBER**: The PRD is not just documentation - it's the contract with the user about what we're building. Honor it.
