# Citadel Archer - Product Requirements Document (PRD)

**Version:** 0.2.3
**Last Updated:** 2026-02-02
**Status:** Active Development

---

## Version History & Changelog

### v0.2.3 (2026-02-02) - Vanilla JS Over React (Security-First Frontend)
**Status**: Active - Frontend architecture simplified

**Changes**:
- ✅ **Replaced React with Vanilla JS + Web Components**: Simpler, more secure, smaller attack surface
- ✅ **Rationale**: For a security-focused desktop app, fewer dependencies = more auditable code
- ✅ **Still Modern**: ES6 modules, Web Components, Shadow DOM, Tailwind CSS
- ✅ **No Build Complexity**: Direct deployment, faster cold start, no npm ecosystem risk

**Sections Updated**:
- Technical Architecture → Technology Stack (Frontend)

**Rationale**:
1. **Security**: React apps have 1000+ npm dependencies (supply chain risk). Vanilla JS has near-zero external dependencies.
2. **Simplicity**: No Babel, Webpack, JSX transforms. Just HTML/CSS/JS that users can audit.
3. **Performance**: No virtual DOM overhead. Direct DOM manipulation in pywebview.
4. **Appropriate**: Our Phase 1 UI is simple (status dashboard, process list, event log). React is overkill.
5. **Desktop Context**: No SSR, no code splitting, no SEO. Browser APIs (WebSocket, Fetch) are sufficient.

For a proprietary security product where users need to trust the code, minimal dependencies is a feature, not a limitation.

---

### v0.2.2 (2026-02-01) - Proactive Protection (ACT, Don't Ask)
**Status**: Active - Critical UX principle added

**Changes**:
- ✅ **PROACTIVE PROTECTION**: AI acts FIRST, informs AFTER (not ask before)
- ✅ **Minimize User Questions**: Questions are RARE, only for truly ambiguous AND important situations
- ✅ **Default to Autonomous Action**: Within security level, AI decides and acts immediately

**Key Principle**:
> "If we're asking the user 'Should I block this malware?' we've already failed.
> ACT proactively, then INFORM. Don't ASK unless absolutely necessary."

**Rationale**: Target users are NOT security experts. They don't know if "update.exe connecting to 185.220.101.42" is dangerous. By the time they decide, damage could be done. AI must act autonomously (within security level), then explain what it did and why.

---

### v0.2.1 (2026-02-01) - UX Clarity for Non-Technical Users
**Status**: Active - UX principles clarified

**Changes**:
- ✅ **Added Progressive Disclosure UX Principle**: Simple view by default, advanced details on-demand
- ✅ **AI as Expert Advisor**: AI explains threats in plain language ("This is normal" vs "This needs attention NOW")
- ✅ **Prevent Alert Panic**: Users rely on AI to distinguish serious threats from normal activity

**Sections Updated**:
- Core Philosophy (added "Accessible to Non-Experts")
- User Experience (added Progressive Disclosure section)
- Dashboard UX (simplified primary view, advanced drill-down)
- AI Communication guidelines

**Rationale**: Most users aren't security experts. They'll see alerts and panic unless the AI guides them with clear, calm explanations. Security tools that overwhelm users with technical jargon create alert fatigue and get disabled.

---

### v0.2.0 (2026-02-01) - VPS Protection Prioritized
**Status**: Active - Updated roadmap

**Changes**:
- ✅ **Moved Remote Shield (VPS) from Phase 5 → Phase 2** (Months 4-6 instead of 13-15)
- ✅ **Rationale**: VPS protection is a core use case, not a late addition. User experiences VPS compromises within days and needs rapid defense capability.
- ✅ **Phase 2 Now Includes**: Intel module + AI threat analysis + Remote Shield VPS agent
- ✅ **Phase 5 Adjusted**: Focus shifts to family computer protection and multi-system orchestration

**Sections Updated**:
- Development Roadmap (Phase 2 and Phase 5)
- Platform Support timeline (Ubuntu moved to Phase 2)

**Rationale**: VPS management is first-class, not second-class. Moving it to Phase 2 ensures:
1. User gets end-to-end protection (local + VPS) within 6 months
2. Intelligence layer (Phase 2) benefits both local and remote systems simultaneously
3. Remote Shield gets proper development time, not rushed
4. Aligns with user's primary use case (protecting VPS from rapid compromise)

---

### v0.1.0 (2026-02-01) - Initial PRD
**Status**: Active - This is our locked baseline

**Major Decisions**:
- ✅ AI-centric architecture (AI as central brain, modules as sensors/tools)
- ✅ Proprietary licensing (not open source) to protect defensive algorithms
- ✅ Freemium model (Free/Premium/Enterprise tiers)
- ✅ Windows 10/11 first, Ubuntu for VPS second
- ✅ Cloud LLMs for MVP (Claude API, OpenAI), local models later
- ✅ User-configurable security levels (Observer/Guardian/Sentinel)

**Sections Established**:
- Executive Summary & Philosophy
- Problem Statement & Target Users
- 8 Core Modules (Guardian, Watchtower, Panic Room, Vault, SecureChat, Intel, Remote Shield, Dashboard)
- AI-Centric Architecture (detailed)
- Technical Architecture & Stack
- User Experience Flows
- 18-Month Development Roadmap (6 phases)
- Monetization Strategy (3 tiers with revenue projections)
- Security Considerations & Threat Model
- Decided Architecture (locked decisions)

**Next Steps**:
- Begin Phase 1 implementation
- Update to v0.2.0 if any architecture changes occur

---

### Version Update Process

**When to update PRD version**:
- **Patch (0.1.X)**: Minor clarifications, typo fixes, no functionality change
- **Minor (0.X.0)**: Feature additions/removals, priority changes, phase adjustments
- **Major (X.0.0)**: Fundamental architecture changes, business model pivots

**Process**:
1. Identify need for change (technical constraint, user feedback, better approach)
2. Update relevant PRD section(s)
3. Increment version number
4. Add entry to Changelog (above)
5. Mark changed sections with ~~strikethrough~~ for old, **bold** for new
6. Create ADR in `docs/adr/` if architectural decision
7. Get user approval before implementing

**All changes must be documented - never silently deviate from PRD.**

---

## Executive Summary

**Citadel Archer** is a comprehensive defensive security platform that empowers individuals to protect their digital presence with the sophistication typically available only to well-funded organizations. Built on the principle that **freedom requires security**, Citadel Archer provides active monitoring, rapid threat response, secure communications, and proactive defense against persistent threats.

**Core Philosophy:**
- **Defense, Not Offense**: White hat protection only - no profiling, no offensive capabilities
- **Privacy First**: User data stays with the user - no telemetry, no tracking
- **Power to Individuals**: Enterprise-grade security accessible to everyone
- **Rapid Response**: Automated mitigation measured in seconds, not days
- **AI-Centric Protection**: AI as the adaptive brain that learns and defends your unique environment
- **Strategic Closed Source**: Proprietary algorithms to prevent attackers from studying our defenses
- **Accessible to Non-Experts**: AI explains threats in plain language; simple UI by default, advanced details on-demand
- **Proactive Protection**: AI acts FIRST (within security level), informs AFTER. Questions only when truly necessary.

---

## Problem Statement

### The Current Reality
Modern users face sophisticated, persistent threats:
- **Personal machines** are compromised through phishing, malicious links, and drive-by downloads
- **Remote servers (VPS)** are penetrated within days of deployment despite firewalls
- **Recovery is painful**: Taking weeks to rebuild trust in compromised systems
- **Asymmetric power**: Attackers have sophisticated tools; defenders have fragmented solutions
- **Privacy erosion**: Security tools often become surveillance tools themselves
- **Technical barrier**: Effective security requires expertise most people don't have

### What Users Need
- **Early warning system**: Detect intrusions immediately, not months later
- **One-click mitigation**: Rapid response without technical expertise
- **Secure communications**: Chat with friends and AI without surveillance
- **Secrets management**: Credentials that can be rotated instantly under attack
- **Remote protection**: Secure VPS and family computers from a single interface
- **Peace of mind**: Confidence that protection is active and current

---

## Target Users

### Primary: Individual Power Users
- Technical enough to run VPS or manage family tech
- Targeted by persistent threats (activists, journalists, small business owners)
- Value privacy and autonomy
- Willing to learn but need tools that "just work"

### Secondary: Family & Friends
- Non-technical users protected through Citadel Archer's remote management
- Benefit from "panic button" and automated protection
- Need simple, clear alerts

### Tertiary: Security & Privacy Community
- Third-party security auditors validate our approaches (annual audits)
- Privacy-focused users benefit from shared threat intelligence (opt-in, anonymized)
- Beta testers help refine features and detection capabilities
- Free tier ensures accessibility for activists, journalists, and those at risk

---

## Core Modules

### 1. **Guardian** - Local Machine Protection
**Purpose**: Secure and actively monitor the user's workstation

**Key Features:**
- Real-time filesystem monitoring (unauthorized changes, suspicious binaries)
- Network traffic analysis (outbound C2 connections, data exfiltration)
- Process monitoring (suspicious processes, privilege escalation attempts)
- Browser protection (hooks, extensions, injected scripts)
- Memory scanning for rootkits and injected code
- Boot integrity verification
- Automated quarantine and cleanup

**Technical Approach:**
- Python agent with OS-level hooks (pywin32 for Windows, equivalent for Linux/Mac)
- Local ML model for behavior analysis
- Signature updates from Intel module
- Logs all activity for forensics

---

### 2. **Watchtower** - Intrusion Detection System (IDS)
**Purpose**: Active monitoring and alerting across all protected assets

**Key Features:**
- Multi-asset dashboard (local machine, VPS instances, remote systems)
- Real-time threat scoring and prioritization
- Alert aggregation and noise reduction
- Attack pattern recognition
- Automated response playbooks
- Historical attack timeline
- Forensic log collection

**Technical Approach:**
- Central event collection service
- Rule engine for known attack patterns
- AI model for anomaly detection
- Integration with Guardian and Remote Shield agents

---

### 3. **Panic Room** - Emergency Response System
**Purpose**: Instant security posture reset when under active attack

**Key Features:**
- One-click "Panic Button" activation
- Automated credential rotation across all services
- Emergency network isolation (cut all non-essential connections)
- Snapshot current state for forensics
- Secure backup of critical data
- Step-by-step recovery guidance
- Post-incident analysis and hardening

**Technical Approach:**
- Pre-configured playbooks for different threat scenarios
- Integration with Vault for credential management
- API connections to services for automated rotation
- Network firewall rules for isolation
- Encrypted backup to secure location

---

### 4. **Vault** - Secrets Management
**Purpose**: Secure storage and management of credentials, API keys, certificates

**Key Features:**
- Military-grade encryption at rest (AES-256)
- Master password + optional hardware key (YubiKey support)
- Automatic credential rotation scheduling
- Password generation (configurable complexity)
- Secure sharing with trusted contacts (encrypted, time-limited)
- Breach monitoring (check credentials against known breaches)
- Auto-fill integration (browser, SSH, applications)
- Emergency access delegation ("dead man's switch")

**Technical Approach:**
- Local SQLCipher database (not cloud-based)
- PBKDF2 key derivation from master password
- Zero-knowledge architecture
- Integration with system keychains (Windows Credential Manager, macOS Keychain)
- Panic Room integration for instant rotation

---

### 5. **SecureChat** - Private Communications
**Purpose**: End-to-end encrypted chat with friends and AI assistants

**Key Features:**
- End-to-end encryption (Signal protocol or similar)
- No server-side message storage (ephemeral or user-controlled)
- AI assistant integration (Claude, other LLMs) with local processing
- Secure file sharing (encrypted, self-destructing)
- Video/voice chat (encrypted)
- Group conversations
- Metadata minimization (onion routing optional)
- Self-destructing messages (timer-based)

**Technical Approach:**
- P2P connections where possible (STUN/TURN for NAT traversal)
- Optional relay server (user-controlled, open source)
- libsodium for cryptography
- WebRTC for voice/video
- Local AI inference for privacy (Ollama integration)
- Optional Tor integration for metadata protection

---

### 6. **Intel** - Threat Intelligence
**Purpose**: Stay current with latest threats, tactics, and vulnerabilities

**Key Features:**
- Daily automated threat feeds (CVEs, malware signatures, IOCs)
- AI-powered threat analysis (summarize, prioritize, contextualize)
- Automatic security updates for Guardian signatures
- Threat actor profiling (understand who targets you)
- Vulnerability scanning (outdated software, misconfigurations)
- Community threat sharing (anonymized, opt-in)
- Custom threat research (search by keyword, technique)

**Technical Approach:**
- Aggregation from public threat feeds (MITRE ATT&CK, CVE databases, etc.)
- Local LLM for analysis and summarization
- Push notifications for critical threats
- Integration with Guardian for automatic rule updates
- Privacy-preserving contribution to community intelligence

---

### 7. **Remote Shield** - VPS & Remote System Protection
**Purpose**: Extend Citadel Archer protection to remote servers and family computers

**Key Features:**
- Remote agent deployment (one-click install script)
- Centralized monitoring from local dashboard
- SSH hardening (key-only auth, port knocking, fail2ban++)
- Firewall management (dynamic rules, geo-blocking)
- Service monitoring (unexpected services, privilege escalation)
- File integrity monitoring (tripwire-style)
- Automated patching (OS and software updates)
- Remote panic button (isolate and lock down)

**Technical Approach:**
- Lightweight Python agent on remote systems
- Encrypted C2 channel back to Watchtower
- Certificate-based mutual authentication
- Ansible/Salt-like configuration management
- Agent auto-updates from trusted source

---

### 8. **Dashboard** - Unified Control Center
**Purpose**: Single interface for all Citadel Archer functions

**Key Features:**
- Real-time security status (all assets, color-coded health)
- Threat feed and alerts (prioritized, actionable)
- Quick actions (panic button, isolate asset, rotate credentials)
- Asset management (add/remove/configure protected systems)
- Settings and preferences (notification rules, auto-response config)
- Reports and forensics (incident timelines, log search)
- Help and documentation (context-sensitive, tutorials)

**UI/UX Design:**
- **Dark mode by default** (OLED-friendly, easy on eyes)
- **Glassmorphic design** (frosted glass cards, depth, translucency)
- **Neon blue accent color** (#00D9FF or similar)
- **Cyberpunk aesthetic** (but functional, not cluttered)
- **Responsive layout** (works on all screen sizes)
- **Animations** (smooth transitions, loading states)
- **Data visualization** (charts for threat trends, network activity)

**Technical Approach:**
- Python backend (FastAPI or Flask for REST API)
- Modern web frontend (React or Vue with Tailwind CSS)
- pywebview for native wrapper
- WebSocket for real-time updates
- Local-first architecture (works offline)

---

## AI-Centric Architecture

### The AI Brain Concept

Citadel Archer is **fundamentally AI-driven**, not just "AI-assisted." The AI serves as the central intelligence that:
- **Learns your environment**: Understands your normal behavior, applications, and patterns
- **Makes holistic decisions**: Analyzes data from all sensors (Guardian, Watchtower, Intel) together
- **Adapts in real-time**: Responds to novel threats that no static rules could catch
- **Operates autonomously**: Takes action within user-defined guardrails

**Why AI-Centric?**
Since our code is proprietary (not open source), attackers cannot study our algorithms. But even if they could, the AI's adaptive nature means each installation learns unique patterns for each user - making generic attacks ineffective.

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│                     USER INTERFACE                       │
│              (Dashboard, Controls, Alerts)               │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ↓
┌─────────────────────────────────────────────────────────┐
│                      AI BRAIN 🧠                         │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Context Engine (learns user's normal behavior)  │  │
│  │  Decision Engine (threat analysis & response)    │  │
│  │  Policy Engine (respects user security level)    │  │
│  └──────────────────────────────────────────────────┘  │
│                                                          │
│  Powered by: Claude API, OpenAI, or user's choice      │
└──────┬────────────┬────────────┬────────────┬──────────┘
       │            │            │            │
       ↓            ↓            ↓            ↓
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│ Guardian │  │Watchtower│  │  Intel   │  │  Vault   │
│ (Sensor) │  │ (Sensor) │  │ (Intel)  │  │ (Tool)   │
└────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘
     │             │             │             │
     └─────────────┴─────────────┴─────────────┘
                   │
                   ↓
         ┌─────────────────┐
         │  System Actions  │
         │ (quarantine,     │
         │  block, kill,    │
         │  alert, rotate)  │
         └─────────────────┘
```

### How It Works

1. **Sensors Collect Data**:
   - Guardian monitors files, processes, network, memory
   - Watchtower aggregates events across all assets
   - Intel provides threat intelligence updates

2. **AI Brain Analyzes Holistically**:
   - "Is this file change normal for this user?"
   - "Does this network connection match known C2 patterns?"
   - "Is this process behavior consistent with the application's purpose?"
   - "Should I act autonomously or ask the user?"

3. **AI Takes Action**:
   - Within user's security level (Observer/Guardian/Sentinel)
   - Executes via tools (Vault for credential rotation, system APIs for quarantine/block)
   - Logs all decisions for forensics and learning

4. **AI Learns Continuously**:
   - Builds profile of user's normal behavior
   - Adapts to new legitimate software and patterns
   - Gets smarter over time, reducing false positives

### User-Configurable Security Levels

Users choose their comfort level during onboarding (can change anytime):

#### Level 1: "Observer" 🔍
**Best for**: Users who want full control, or evaluating Citadel Archer

**AI Capabilities**:
- ✅ Monitor all system activity
- ✅ Analyze logs and network traffic
- ✅ Alert user to potential threats
- ❌ No autonomous actions (user approves everything)

**Use Case**: "Show me everything, but let me decide what to do."

---

#### Level 2: "Guardian" 🛡️ (RECOMMENDED)
**Best for**: Most users - balances security and convenience

**AI Capabilities**:
- ✅ Everything in Observer, PLUS:
- ✅ Auto-quarantine files matching known malware signatures
- ✅ Auto-block connections to known malicious IPs/domains
- ✅ Auto-kill obviously malicious processes (ransomware, cryptominers, keyloggers)
- ✅ Rotate credentials on Vault when breach detected
- ⚠️ Ask before: Killing legitimate-looking processes, modifying system config, blocking entire ports

**Use Case**: "Protect me from known threats automatically, but ask about ambiguous situations."

---

#### Level 3: "Sentinel" ⚔️
**Best for**: High-risk users (activists, journalists) or those under active attack

**AI Capabilities**:
- ✅ Everything in Guardian, PLUS:
- ✅ Modify firewall rules proactively (block suspicious IPs/ports)
- ✅ Kill suspicious processes based on behavior analysis
- ✅ Modify system configuration (disable vulnerable services, harden registry)
- ✅ Auto-enable "panic mode" when sustained attack detected
- ⚠️ Ask only for: Destructive actions (delete files, format disks)

**Use Case**: "I'm under attack. Do whatever it takes to protect me."

---

### AI Tool Access

The AI Brain has access to these tools (within security level constraints):

**Monitoring Tools** (read-only):
- Filesystem access (read file contents, metadata, permissions)
- Process information (running processes, memory usage, parent/child relationships)
- Network traffic (connections, DNS queries, packet analysis)
- System logs (Event Viewer on Windows, syslog on Linux)
- Registry access (Windows) or config files (Linux)

**Action Tools** (write access, controlled by security level):
- File operations (quarantine to isolated location, delete if confirmed malware)
- Process control (kill process, suspend process)
- Network control (block IP/domain, modify firewall rules, force disconnect)
- System configuration (modify registry, disable services, update Group Policy)
- Vault operations (rotate passwords, regenerate API keys)
- Backup/restore (snapshot system state, restore from backup)

**Communication Tools**:
- User alerts (push notification, dashboard alert, email if critical)
- Logging (immutable audit trail of all AI decisions and actions)
- External APIs (query threat intel feeds, check hash reputation)

### AI Provider Support

**MVP (Phase 1-2)**: Cloud LLM APIs
- Anthropic Claude API (primary recommendation)
- OpenAI GPT-4 API (alternative)
- User brings their own API key (free tier)
- Premium tier includes subsidized API access

**Future (Phase 3+)**: Local LLM Support
- Ollama integration for local inference
- Privacy-focused users can run 100% offline
- Trade-off: Less capable than cloud models, but full privacy

### Why This Approach Wins

**Traditional security software**:
- Static rules and signatures
- Attackers study the code (if open source) or reverse engineer (if closed)
- Easily defeated once patterns are known

**Citadel Archer's AI approach**:
- Learns each user's unique environment
- Adapts to novel attack techniques
- Even if attackers know our architecture, they can't predict the AI's decisions
- Each installation is effectively a unique defense system

---

## Technical Architecture

### Technology Stack

**Desktop Application:**
- **Language**: Python 3.11+
- **GUI Framework**: pywebview (native wrapper)
- **Frontend**: Vanilla JavaScript (ES6+ modules) with Web Components
- **Styling**: Tailwind CSS + custom glassmorphic components
- **State Management**: Native JavaScript (simple reactive patterns)
- **API**: FastAPI (local REST server + WebSocket)
- **TypeScript**: Optional (can add for type safety without React overhead)

**Backend Services:**
- **Guardian Agent**: Python with OS-specific libraries (pywin32, watchdog, psutil)
- **Watchtower**: Python with AI/ML (scikit-learn, lightweight models)
- **Vault**: SQLCipher database + cryptography library
- **SecureChat**: Python + WebRTC (aiortc), libsodium bindings
- **Intel**: Python scraping + LLM integration (Ollama for local inference)
- **Remote Shield**: Lightweight Python agent (minimal dependencies)

**Security:**
- **Encryption**: AES-256 (at rest), TLS 1.3 (in transit)
- **Key Management**: PBKDF2 key derivation, hardware key support
- **Code Signing**: Sign all executables and updates
- **Sandboxing**: Principle of least privilege, process isolation
- **Audit Logging**: Immutable logs for all security events

**Deployment:**
- **Packaging**: PyInstaller for single-executable distribution
- **Updates**: Secure auto-update mechanism (signature verification)
- **Platform Support**:
  - **Phase 1**: Windows 10/11 (primary development and testing platform)
  - **Phase 2**: Ubuntu/Debian Linux (for VPS Remote Shield agent)
  - **Future**: macOS, other Linux distros

---

## User Experience

### First Launch Experience
1. **Welcome & Philosophy**: Brief intro to Citadel Archer's mission and defensive approach
2. **Choose Your Tier**: Free (bring your own API key) vs. Premium (we handle AI costs)
3. **AI Provider Setup**:
   - Free tier: Enter Claude or OpenAI API key
   - Premium tier: No setup needed (we handle it)
4. **Security Level Selection**: Choose Observer, Guardian, or Sentinel (explained with examples)
5. **Master Password Setup**: Create Vault master password (strong, memorable, we validate strength)
6. **Quick Scan**: Immediate assessment of current machine security (AI analyzes results)
7. **Guided Hardening**: Step-by-step AI-recommended fixes for identified issues
8. **Dashboard**: User sees their first "green status" and can explore features

### Daily Usage
- Launch app → Dashboard shows security status
- Glance at threat feed (any new alerts?)
- Everything green? Continue work with peace of mind
- Suspicious activity? Alert notification with recommended action
- One click to investigate, mitigate, or panic

### Emergency (Under Attack)
1. User suspects compromise or sees alert
2. Click **Panic Button** (prominent, red, impossible to miss)
3. System asks: "Isolate network? Rotate credentials? Lock down?"
4. User confirms → Automated response executes in <30 seconds
5. Dashboard shows "Safe Mode" with recovery steps
6. User follows guided recovery process

### Progressive Disclosure UX (Simplicity by Default)

**Core Principle**: Most users are NOT security experts. The UI must be simple, calm, and guided by AI explanations.

**Primary View (Default - For Everyone)**:
- 🟢 **Green Status**: "Everything is normal. You're protected."
- 🟡 **Yellow Alert**: "Something unusual detected. Investigating..." (AI explains what)
- 🔴 **Red Alert**: "Threat detected. [AI ACTION TAKEN]" (AI explains threat + response)

**AI Communication Style**:
```
❌ BAD (Technical Jargon):
"Detected process 'svchost.exe' (PID 4821) with suspicious memory
allocation pattern matching CVE-2024-1337 exploitation attempt.
Network connection established to 185.220.101.42:443 (known C2)."

✅ GOOD (Plain Language):
"🔴 THREAT BLOCKED
A suspicious program tried to connect to a known hacker server.
I stopped it and quarantined the file.

You're safe now. No action needed.

[Show Details] ← Click if you want to learn more"
```

**Advanced View (On-Demand)**:
User clicks "Show Details" to see:
- Technical details (process name, PID, CVE, IOCs)
- Attack timeline (what happened when)
- AI reasoning ("I blocked this because...")
- Forensic logs (for technical users or reporting)

**Alert Priority Levels** (AI decides):

1. **🟢 INFO** (No action needed):
   - "Windows Update installed successfully"
   - "New software detected: Visual Studio Code (safe)"
   - User sees: Subtle notification, dismisses automatically

2. **🟡 INVESTIGATE** (AI is checking):
   - "Unusual network activity from Chrome. Checking..."
   - "File modified in System32. Verifying legitimacy..."
   - User sees: AI is working on it, will update soon

3. **🟠 ALERT** (AI took action, user informed):
   - "Blocked connection to suspicious website"
   - "Quarantined file matching malware signature"
   - User sees: What happened, what AI did, why they're safe

4. **🔴 CRITICAL** (User decision needed):
   - "Ransomware detected. I blocked it. Panic Room recommended?"
   - "Multiple failed login attempts. Credential rotation suggested?"
   - User sees: Clear explanation + recommended action

**Dashboard Simplification**:

**Simple Mode** (Default):
```
┌────────────────────────────────────┐
│  🟢 You're Protected                │
│                                     │
│  Last Scan: 2 minutes ago          │
│  Threats Blocked Today: 3          │
│  Everything looks good!            │
│                                     │
│  [View Details] [Settings]         │
└────────────────────────────────────┘
```

**Advanced Mode** (Click "View Details"):
```
┌────────────────────────────────────┐
│  Guardian Status: Active            │
│  - File Monitor: 1,247 events/hr   │
│  - Process Monitor: 43 processes   │
│  - Network Monitor: 12 connections │
│                                     │
│  Threats Blocked Today: 3          │
│  - 2x Malicious URLs (Chrome)      │
│  - 1x Suspicious Process (killed)  │
│                                     │
│  [Forensic Logs] [Export Report]   │
└────────────────────────────────────┘
```

**Proactive Action > Reactive Questions**:

**CRITICAL PRINCIPLE**: AI acts FIRST (within security level), asks RARELY.

**When AI ACTS AUTONOMOUSLY (No Questions)**:
- ✅ Known malware signatures → Quarantine immediately, inform user
- ✅ Known C2 servers → Block connection immediately, inform user
- ✅ Obvious malicious behavior → Kill process, inform user
- ✅ Suspicious but low-risk → Monitor closely, inform if escalates
- ✅ 95%+ confidence it's a threat → Act first, explain after

**When AI MIGHT Ask (RARE, <5% of cases)**:
- ⚠️ Ambiguous activity with HIGH potential impact (e.g., process wants to delete entire user folder)
- ⚠️ User-initiated action that looks dangerous (e.g., user about to run ransomware.exe they downloaded)
- ⚠️ Conflicting signals (legitimate software behaving suspiciously)

**Example - AI Acts Proactively** (95% of cases):
```
┌────────────────────────────────────┐
│  🟠 THREAT BLOCKED                  │
│                                     │
│  "I blocked 'update.exe' from      │
│  connecting to a suspicious server.│
│                                     │
│  This looked like malware trying   │
│  to download more threats. I       │
│  quarantined it for safety.        │
│                                     │
│  You're protected. ✓               │
│                                     │
│  [Show Details] [Restore if Safe]  │
└────────────────────────────────────┘
```
*AI decided, acted, explained. User can override if needed.*

**Example - AI Asks (RARE, <5% of cases)**:
```
┌────────────────────────────────────┐
│  🟡 UNUSUAL - Your Input Needed     │
│                                     │
│  "You're about to run 'crack.exe'  │
│  which looks like piracy/malware.  │
│                                     │
│  I STRONGLY recommend blocking it. │
│                                     │
│  But you downloaded it, so maybe   │
│  you know something I don't?       │
│                                     │
│  [🛡️ Block (Recommended)] [✅ Run]│
└────────────────────────────────────┘
```
*AI asks because user explicitly initiated this action.*

**Decision Tree**:
```
Threat Detected
    ↓
Is confidence >95%?
    ↓ YES → ACT NOW (block/quarantine/kill) → Inform user after
    ↓ NO
Is user explicitly involved?
    ↓ YES → Ask user (they might know context)
    ↓ NO → ACT CONSERVATIVELY (monitor, log) → Escalate if needed
```

**Settings: Verbosity Control**:

Users can adjust how much detail they want:
- **Minimal**: Only show critical alerts requiring user action
- **Balanced** (Default): Show threats + AI actions taken
- **Detailed**: Show everything including INFO-level events
- **Expert**: Full technical logs, real-time event stream

**Onboarding Sets Expectations**:

During first launch, AI asks:
```
"How comfortable are you with security alerts?

🟢 Beginner: Show me only what I need to know, explain everything
🟡 Intermediate: I know some security basics, give me context
🔴 Expert: Give me all the technical details"
```

This sets the default verbosity + UI complexity.

**Key UX Principles**:

1. ✅ **Assume user is NOT a security expert**
2. ✅ **AI is the trusted advisor, not an alarm system**
3. ✅ **ACT FIRST, inform AFTER** (proactive protection, not reactive questions)
4. ✅ **Questions are RARE** (<5% of cases, only when truly ambiguous + high impact)
5. ✅ **Default to calm, clear, actionable language**
6. ✅ **Technical details available on-demand, not forced**
7. ✅ **Color coding is universal** (🟢 = safe, 🟡 = checking, 🟠 = action taken, 🔴 = critical)
8. ✅ **"You're safe" is the most important message**
9. ✅ **Reduce alert fatigue** (don't cry wolf about normal activity)
10. ✅ **User can override AI decisions** (restore quarantined files, unblock if false positive)

---

## Success Metrics

### Security Effectiveness
- **Detection Rate**: % of known threats detected in testing
- **False Positive Rate**: Keep under 1% (don't cry wolf)
- **Response Time**: Average time from detection to mitigation
- **Recovery Time**: Time from panic button to restored confidence

### User Experience
- **Time to First Green**: How quickly can new user secure their machine?
- **Daily Interaction Time**: Should be <30 seconds unless incident
- **User Confidence Score**: Self-reported "I feel safe" metric
- **Community Growth**: Active users, contributors, shared threat intel

### Technical Performance
- **Resource Usage**: CPU/RAM footprint (should be minimal)
- **Agent Uptime**: Reliability of monitoring agents
- **Update Success Rate**: Auto-updates that work smoothly
- **Crash Rate**: Target 99.9% stability

---

## Development Roadmap

### Phase 1: Foundation (Months 1-3)
- [ ] Core Guardian agent (file monitoring, process monitoring)
- [ ] Basic Dashboard (system status, manual scan)
- [ ] Vault (password storage, basic encryption)
- [ ] Threat detection rules engine
- [ ] Initial dark glassmorphic UI

**Milestone**: User can secure their local machine and store secrets

### Phase 2: Intelligence & VPS Protection (Months 4-6) 🔥 **PRIORITY**
**Focus**: Add AI threat analysis + Extend protection to VPS (Ubuntu)

**Intelligence Layer**:
- [ ] Intel module (threat feed aggregation from AlienVault OTX, abuse.ch, MITRE ATT&CK, NVD)
- [ ] Watchtower (centralized monitoring, multi-asset dashboard)
- [ ] AI-powered anomaly detection (context engine learns user behavior)
- [ ] Automatic Guardian signature updates
- [ ] Advanced UI (charts, timelines, threat scoring)

**Remote Shield - VPS Protection**:
- [ ] Lightweight Python agent for Ubuntu/Debian VPS
- [ ] Remote agent deployment (one-click install script)
- [ ] SSH hardening (key-only auth, port knocking, fail2ban++)
- [ ] VPS firewall management (dynamic rules, geo-blocking, automated responses)
- [ ] Remote file integrity monitoring (tripwire-style)
- [ ] Remote process monitoring (detect unauthorized services, crypto miners)
- [ ] Encrypted C2 channel back to local Watchtower (certificate-based auth)
- [ ] AI threat analysis for VPS (same AI brain, different sensor)

**Milestone**: System proactively detects threats across local machine AND VPS, with AI-powered analysis protecting both

### Phase 3: Response (Months 7-9)
- [ ] Panic Room (emergency response playbooks)
- [ ] Automated credential rotation
- [ ] Network isolation capabilities
- [ ] Backup and recovery system
- [ ] Incident forensics and reporting

**Milestone**: One-click response to active attacks

### Phase 4: Communication (Months 10-12)
- [ ] SecureChat (E2E encrypted messaging)
- [ ] AI assistant integration (local LLM)
- [ ] Secure file sharing
- [ ] Group chat and contact management
- [ ] Voice/video calls (optional)

**Milestone**: Secure communications channel operational

### Phase 5: Family & Multi-System Orchestration (Months 13-15)
**Focus**: Extend protection to family computers + Advanced multi-system management

**Family Computer Protection**:
- [ ] Windows Remote Shield agent (for family PCs)
- [ ] Simplified "protected mode" for non-technical users
- [ ] Remote monitoring without overwhelming alerts
- [ ] Automated patching (OS and software updates)
- [ ] Parental controls integration (optional)
- [ ] Easy deployment (email invite → one-click install)

**Multi-System Orchestration**:
- [ ] Unified dashboard for all protected systems (local, VPS, family PCs)
- [ ] Cross-system threat correlation (attack on one system alerts others)
- [ ] Group policies (apply security rules to multiple systems)
- [ ] Remote panic capabilities (isolate any system from dashboard)
- [ ] Backup and sync across systems
- [ ] Performance analytics (which systems need attention)

**Milestone**: Protect entire digital ecosystem (user's machines + VPS + family) from single dashboard

### Phase 6: Community & Polish (Months 16-18)
- [ ] Third-party security audit (annual)
- [ ] Community threat sharing (anonymized, opt-in)
- [ ] Plugin architecture for extensions
- [ ] Comprehensive documentation and tutorials
- [ ] Beta program for early adopters
- [ ] Premium tier launch

**Milestone**: Production-ready, audited, and scalable platform

---

## Monetization Strategy

### Licensing & Business Model

**Proprietary Software with Free Tier** - Citadel Archer is **not open source** to protect defensive algorithms from attackers. However, we remain committed to accessibility and transparency through:
- Free tier for individuals
- Third-party security audits (public reports)
- Clear documentation of capabilities
- User-controlled data (no vendor lock-in)

### Tier Structure

#### 🆓 Free Tier: "Defender"
**Target**: Individual users, activists, journalists, students

**Includes**:
- ✅ Full Guardian local protection
- ✅ Basic Watchtower monitoring
- ✅ Vault password manager (unlimited passwords)
- ✅ Manual threat intel updates
- ✅ Observer & Guardian security levels
- ✅ Community threat intelligence (receive only)
- ⚠️ **Requires**: User brings their own AI API key (Claude, OpenAI, etc.)
- ⚠️ **Limitation**: AI analysis rate-limited by user's API quota

**Cost**: $0 forever

**Why free tier?**
- Security should be accessible to all
- Activists and journalists need protection without payment barriers
- Builds community and word-of-mouth growth
- Users become advocates when they see value

---

#### 💎 Premium Tier: "Sentinel"
**Target**: Power users, small teams, freelancers

**Everything in Free, PLUS**:
- ✅ **Subsidized AI access** (no need for your own API key - we handle it)
- ✅ Sentinel security level (maximum AI autonomy)
- ✅ Automatic real-time threat intel updates
- ✅ Priority support (email, <24hr response)
- ✅ SecureChat with unlimited contacts
- ✅ Up to 3 remote systems (VPS, family PCs)
- ✅ Advanced forensics and reporting
- ✅ Community threat intelligence (send & receive)

**AI Usage Included**:
- Up to 10,000 AI requests/month (covers typical usage)
- Equivalent to ~$50-75 of API costs at retail rates
- We negotiate bulk pricing to offer this at lower cost

**Cost**: $19.99/month or $199/year (save 17%)

**Value proposition**:
- Save money vs. buying your own AI API credits
- No usage anxiety - we handle the AI costs
- More features and faster updates
- Support real humans who respond

---

#### 🏢 Enterprise Tier: "Fortress"
**Target**: Small businesses, agencies, security teams

**Everything in Premium, PLUS**:
- ✅ **Unlimited AI access** (no rate limits)
- ✅ Unlimited remote systems (VPS, employee machines, servers)
- ✅ Centralized management dashboard
- ✅ Team collaboration features
- ✅ Custom threat intel feeds
- ✅ Dedicated account manager
- ✅ Priority support (phone, Slack, <4hr response, 24/7 emergency)
- ✅ Custom playbooks and automation
- ✅ Compliance reporting (SOC 2, GDPR, HIPAA-ready logs)
- ✅ Volume discounts for seats

**AI Usage Included**:
- Unlimited AI requests
- Optional: Private AI deployment (your own API key + our infra)
- Optional: Fine-tuned models for your specific environment

**Cost**: Custom pricing (starts at $99/user/month, volume discounts)

**Why Enterprise?**
- SMBs need security but can't afford dedicated teams
- Managed service feel without managed service costs
- We handle the AI complexity and scaling

---

### Revenue Projections

**Year 1 Goals** (Post-MVP):
- 10,000 free tier users (word of mouth, community)
- 500 premium subscribers ($120K ARR)
- 5 enterprise customers ($60K ARR)
- **Total Year 1**: ~$180K ARR

**Year 2 Goals**:
- 50,000 free tier users
- 2,500 premium subscribers ($600K ARR)
- 25 enterprise customers ($300K ARR)
- **Total Year 2**: ~$900K ARR

**Path to profitability**:
- Break even at ~150 premium subscribers (covers hosting, AI costs, 1 FTE)
- Profitable at 250+ premium subscribers
- Enterprise deals accelerate profitability

---

### Why This Model Works

**For Users**:
- Free tier removes barriers to entry
- Premium tier is cheaper than buying AI API access directly
- Enterprise tier provides white-glove service for businesses

**For Us**:
- Free tier builds user base and reputation
- Premium tier provides predictable recurring revenue
- Enterprise tier funds rapid development and infrastructure
- LLM bulk pricing gives us margin (buy at $0.003/1K tokens, effective user cost ~$0.005/1K tokens)

**Competitive Advantage**:
- Most security tools are either expensive enterprise products OR free but feature-limited
- We're high-quality AND accessible
- AI-centric approach is novel - no direct competitors yet
- Proprietary algorithms can't be copied by open source alternatives

---

### Future Monetization Opportunities (Phase 3+)

1. **White-label licensing** - Security companies can rebrand and resell
2. **Managed Security Service** - We monitor and respond for you (SOC-as-a-service)
3. **Threat Intel Marketplace** - Organizations can purchase curated threat feeds
4. **Training & Certification** - Courses on using Citadel Archer effectively
5. **API Access** - Other security tools can integrate with our threat intelligence

---

## Security Considerations

### Threat Model
**What we protect against:**
- Malware and ransomware
- Phishing and social engineering
- Remote intrusions and lateral movement
- Credential theft and reuse
- Data exfiltration
- Persistent backdoors
- Zero-day exploits (through behavior analysis)

**What we DON'T protect against:**
- Nation-state actors with unlimited resources (but we make it harder)
- Physical access to unlocked machine
- User intentionally disabling protection
- Supply chain attacks on hardware (beyond our scope)

### Privacy Guarantees
- **Local-first**: All data stored on user's machine, not cloud
- **No telemetry**: Zero data collection without explicit user opt-in
- **Third-party audits**: Annual security audits by reputable firms (published reports)
- **Encrypted everything**: Data at rest and in transit (AES-256, TLS 1.3)
- **User control**: User owns their data, can export/delete anytime
- **Transparent capabilities**: Clear documentation of what the AI can access and do

### Attack Surface Minimization
- Principle of least privilege (no unnecessary permissions)
- Code signing and integrity verification
- Minimal dependencies (reduce supply chain risk)
- Sandboxed components where possible
- Regular security audits and penetration testing

---

## Decided Architecture (Locked In)

1. ✅ **Platform Priority**: Windows 10/11 first, Ubuntu for VPS agents second
2. ✅ **AI Models**: Cloud LLMs (Claude API, OpenAI) for MVP; add local Ollama support in later phase
3. ✅ **Update Mechanism**: Notify + one-click install with signature verification
4. ✅ **SecureChat Architecture**: Pure P2P for MVP; optional relay server in future phase
5. ✅ **Threat Intel Sources**: AlienVault OTX, abuse.ch (URLhaus, MalwareBazaar), MITRE ATT&CK, NVD/CVE feeds
6. ✅ **Licensing**: Proprietary with free tier (protects defensive algorithms from attackers)
7. ✅ **Monetization**: Freemium model with LLM access subsidies and premium features
8. ✅ **AI Autonomy**: Hybrid approach (auto-respond to known threats, ask for novel situations)
9. ✅ **AI Access Level**: User-configurable (Observer/Guardian/Sentinel security levels)
10. ✅ **Hardware Keys**: Phase 2 or 3 (not critical for MVP)

## Open Questions (Deferred to Later Phases)

1. **Community Features**: Anonymous threat sharing - what data is safe to share? (Phase 6)
2. **Mobile**: Native mobile app or just manage from desktop? (Phase 5+)
3. **Local LLM Integration**: Specific Ollama models and configuration (Phase 2+)
4. **SecureChat Relay**: Optional relay server architecture and deployment (Phase 4+)

---

## Glossary

- **C2**: Command and Control (attacker's remote access mechanism)
- **CVE**: Common Vulnerabilities and Exposures (public vulnerability database)
- **E2E**: End-to-End Encryption
- **IOC**: Indicator of Compromise (evidence of breach)
- **IDS**: Intrusion Detection System
- **MITRE ATT&CK**: Framework of adversary tactics and techniques
- **VPS**: Virtual Private Server
- **Zero-day**: Previously unknown vulnerability

---

## Appendix: Design Inspiration

### UI/UX References
- Glassmorphism: [glassmorphism.com](https://glassmorphism.com)
- Neon blue aesthetic: Cyberpunk 2077 UI, Tron Legacy
- Security dashboards: Splunk, Datadog, Grafana (but prettier)

### Security Tool References
- **OSSEC**: Host-based IDS (inspiration for Guardian)
- **Snort/Suricata**: Network IDS (inspiration for Watchtower)
- **Bitwarden**: Password manager (inspiration for Vault)
- **Signal**: Secure messaging (inspiration for SecureChat)

---

**End of PRD v0.1.0**

*This is a living document. We'll iterate and refine as we build.*
