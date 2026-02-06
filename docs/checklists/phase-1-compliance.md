# Phase 1: Foundation - PRD Compliance Checklist

**Phase Duration**: Months 1-3
**PRD Reference**: Development Roadmap, Phase 1
**Status**: 🚧 In Progress
**Completion**: 0% (0/25 items)

---

## Core Guardian Agent

**PRD Section**: Guardian - Local Machine Protection
**Priority**: 🔴 Critical (MVP blocker)

### File Monitoring
- [ ] Real-time filesystem monitoring implemented (watchdog library)
- [ ] Detects unauthorized file changes
- [ ] Detects suspicious binaries (unsigned .exe, double extensions)
- [ ] Monitors critical system directories (System32, Program Files, etc.)
- [ ] Logs all file events for forensics

### Process Monitoring
- [ ] Real-time process monitoring implemented (psutil library)
- [ ] Detects suspicious processes (crypto miners, keyloggers)
- [ ] Detects privilege escalation attempts
- [ ] Monitors parent/child process relationships
- [ ] Can kill processes (respects security levels)

### Threat Detection Rules Engine
- [ ] Rule engine implemented (pattern matching)
- [ ] Known malware signatures loaded
- [ ] Known C2 IP/domain blocklist loaded
- [ ] Rules can be updated (manual for Phase 1)
- [ ] Rules respect security levels (Observer/Guardian/Sentinel)

### Logging & Forensics
- [ ] Immutable audit log implemented (append-only)
- [ ] All Guardian events logged (file, process, network)
- [ ] Logs include timestamps, user context, AI decisions
- [ ] Logs stored encrypted
- [ ] Log viewer in Dashboard

---

## Basic Dashboard

**PRD Section**: Dashboard - Unified Control Center
**Priority**: 🟡 High (User-facing)

### Core UI
- [ ] Dark mode implemented (default)
- [ ] Glassmorphic design (frosted glass cards, blur effects)
- [ ] Neon blue accent color (#00D9FF)
- [ ] Responsive layout (works on different screen sizes)
- [ ] React + TypeScript + Tailwind CSS setup

### System Status Display
- [ ] Shows Guardian status (active/inactive)
- [ ] Shows real-time threat level (green/yellow/red)
- [ ] Shows recent file/process events
- [ ] Shows security level (Observer/Guardian/Sentinel)
- [ ] Visual health indicators

### Real-time Updates
- [ ] WebSocket connection to backend
- [ ] Real-time event stream in UI
- [ ] Live notifications for threats
- [ ] No page refresh needed

### pywebview Integration
- [ ] Desktop app wraps web UI
- [ ] Single executable (PyInstaller)
- [ ] System tray integration
- [ ] Runs on Windows 10/11

---

## Vault - Password Manager

**PRD Section**: Vault - Secrets Management
**Priority**: 🟡 High (Security critical)

### Core Vault Features
- [ ] SQLCipher database setup (encrypted at rest)
- [ ] Master password implementation (PBKDF2 key derivation)
- [ ] Password storage (unlimited passwords)
- [ ] Password generation (configurable complexity)
- [ ] AES-256 encryption

### First-Time Setup
- [ ] Master password creation flow
- [ ] Password strength validation
- [ ] Warning about master password importance
- [ ] Initial vault seeding

### Vault UI
- [ ] Password list view
- [ ] Add new password form
- [ ] Edit existing password
- [ ] Delete password (with confirmation)
- [ ] Search/filter passwords
- [ ] Copy to clipboard (with auto-clear after 30s)

---

## Technical Infrastructure

**PRD Section**: Technical Architecture
**Priority**: 🔴 Critical (Foundation)

### Backend Setup
- [ ] Python 3.11+ environment
- [ ] FastAPI REST API setup
- [ ] WebSocket endpoint for real-time updates
- [ ] CORS configuration (local only)
- [ ] Error handling and logging

### Project Structure
- [ ] Proper Python package layout (src/ directory)
- [ ] Requirements.txt with pinned versions
- [ ] Virtual environment setup instructions
- [ ] .gitignore configured
- [ ] README.md with setup instructions

### Security Infrastructure
- [ ] Security level enum (Observer/Guardian/Sentinel)
- [ ] Security level check decorator
- [ ] Audit logging system
- [ ] Encryption utilities (AES-256)
- [ ] Secure configuration storage

---

## First-Time User Experience

**PRD Section**: User Experience - First Launch Experience
**Priority**: 🟡 High (User onboarding)

### Onboarding Flow
- [ ] Welcome screen (philosophy, mission)
- [ ] Tier selection (Free vs. Premium) - UI only for Phase 1
- [ ] AI provider setup (API key entry) - Phase 1 just stores it
- [ ] Security level selection (Observer/Guardian/Sentinel)
- [ ] Master password setup (Vault)

### Quick Scan
- [ ] Initial security assessment (runs Guardian scan)
- [ ] Report findings (vulnerabilities, issues)
- [ ] AI analysis placeholder (Phase 2 will add real AI)

### Guided Hardening
- [ ] Step-by-step hardening recommendations
- [ ] One-click fixes where possible
- [ ] Manual fix instructions where needed
- [ ] Progress tracking

---

## Testing

**PRD Section**: Implicit - Required for Quality
**Priority**: 🟡 High (Quality assurance)

### Unit Tests
- [ ] Guardian file monitor tests
- [ ] Guardian process monitor tests
- [ ] Vault encryption tests
- [ ] Security level tests
- [ ] API endpoint tests

### Integration Tests
- [ ] Guardian → Dashboard communication
- [ ] Vault → Dashboard communication
- [ ] WebSocket real-time updates
- [ ] End-to-end onboarding flow

### Security Tests
- [ ] Encryption strength verification
- [ ] Security level enforcement tests
- [ ] Audit log immutability tests
- [ ] Master password strength tests

---

## Documentation

**PRD Section**: Implicit - Required for Usability
**Priority**: 🟢 Medium (Can iterate)

### Code Documentation
- [ ] All files have PRD reference comments
- [ ] All functions have docstrings
- [ ] Security implications documented
- [ ] Complex logic explained

### User Documentation
- [ ] README.md (setup, usage)
- [ ] Installation guide (Windows 10/11)
- [ ] User guide (how to use Dashboard)
- [ ] FAQ (common questions)

---

## Phase 1 Milestone Definition

**Phase 1 is COMPLETE when**:
- ✅ User can install Citadel Archer on Windows 10/11
- ✅ Guardian actively monitors files and processes
- ✅ User sees real-time security status in Dashboard
- ✅ User can store passwords securely in Vault
- ✅ User completes onboarding and chooses security level
- ✅ All manual tests pass
- ✅ No critical bugs
- ✅ User feels "my machine is more secure now"

**Not Required for Phase 1** (defer to Phase 2):
- ❌ AI-powered threat analysis (Phase 2)
- ❌ Automatic threat intel updates (Phase 2)
- ❌ Advanced forensics (Phase 2+)
- ❌ Remote system support (Phase 5)

---

## Deviations from PRD

**Document any deviations here**:

| Item | PRD Says | We Did Instead | Rationale | PRD Updated? |
|------|----------|----------------|-----------|--------------|
| - | - | - | - | - |

*(None yet - table will be populated if deviations occur)*

---

## Progress Tracking

**Last Updated**: 2026-02-01
**Items Complete**: 0/80
**Completion Percentage**: 0%

**Phase Status**: 🟢 On track | 🟡 At risk | 🔴 Blocked

**Next 3 Priorities**:
1. Project structure setup
2. Guardian file monitoring
3. Basic Dashboard skeleton

---

## Sign-off

**Phase 1 Ready for Review**: [ ] Yes / [x] No

When all items are checked, request user review:
- Run `/check-prd phase1` to generate compliance report
- Demo all features to user
- Get explicit approval to move to Phase 2

**User Approval**: _______________ (Date/Signature)
