# SPEC: Citadel Archer

**Project ID:** citadel-archer  
**Status:** Phase 1 — Definition  
**Created:** 2026-02-05  
**Authors:** Scott (Product Owner) + Opus Lead (Technical)  

---

## 1. What Is Citadel Archer?

Citadel Archer is a security hardening and operations tool purpose-built for our autonomous development team. It secures the infrastructure that our agent team runs on — the VPS, the secrets agents need to operate, the communication channels between Forge and Scott, and the boundaries between agents.

This is not a general-purpose security product. It is built for our team's specific needs and grows alongside the team.

### What It Builds On

Citadel Archer builds on existing code in the repository. The Dev Agent should audit and understand the current codebase before writing new code, and extend or refactor existing work rather than rewriting from scratch unless technically necessary.

---

## 2. Target Users

- **Scott** — needs to trust that the system is secure without auditing everything himself
- **Forge** — needs secure access to the secrets required to operate (API keys, credentials) without those secrets leaking
- **Dev Agent / Opus Lead** — need scoped access to only what their tasks require
- **The system itself** — needs to be hardened against external threats and internal misconfiguration

---

## 3. Core Capabilities (Phase 1)

### 3.1 Secrets Management

**Current state:** Secrets live in .env files on the VPS. This works but has risks — any agent or process with filesystem access can read all secrets, there's no rotation policy, and if a secret leaks to git history, it's hard to detect.

**What Citadel Archer provides:**

- **Encrypted secret store** — Secrets encrypted at rest, not stored as plaintext .env files. Use a lightweight solution appropriate for a single-VPS setup (e.g., age encryption, sops, or a simple encrypted vault file). No heavy infrastructure like HashiCorp Vault — we don't need it at this scale.
- **Scoped access** — Agents receive only the secrets they need for their current task. Forge gets Anthropic API keys and messaging credentials. Dev Agent gets git credentials. Opus Lead gets read access for review. No agent sees everything.
- **Secret injection** — Secrets are injected into agent sessions at spawn time (environment variables or temp files), not read directly from the store by agents.
- **Rotation support** — CLI command to rotate a secret: update the store, and on next agent spawn the new value is used. No manual editing of .env files.
- **Audit trail** — Log every secret access: who, when, which secret (name only, not value).

**Constraints:**
- Must work on a single VPS (no distributed secret management)
- Must not break Forge's ability to spawn Claude Code sessions
- Migration from current .env setup must be incremental (can run both systems in parallel during transition)

### 3.2 Agent Sandboxing & Boundaries

**Current state:** Agents run under the same VPS user with full filesystem access. Convention-based boundaries only (agent prompts say "don't touch files outside your scope").

**What Citadel Archer provides:**

- **Filesystem boundaries audit** — Scan and report what each agent process can currently access
- **Boundary enforcement** — Implement file permission controls so agents can only write to their designated directories (/projects/active/{project}/ for their assigned tasks, their git branch)
- **Git credential scoping** — Agents can only push to their assigned feature branches, not to main or other agents' branches
- **Process isolation assessment** — Document what level of isolation Claude Code sessions provide by default, and recommend improvements if gaps exist

**Constraints:**
- Must not break Claude Code's ability to function (it needs read access to project files, write access to its working area)
- Start with the most impactful boundaries first; full sandboxing may require multiple phases

### 3.3 VPS Hardening (Beyond SSH)

**Current state:** SSH is already hardened (key-only auth, non-standard port). Other aspects need audit.

**What Citadel Archer provides:**

- **Service audit** — What's running, what's listening on ports, what's exposed to the internet
- **Firewall review** — Verify firewall rules, tighten to explicit allow-list if not already done
- **Automated hardening script** — Idempotent script that applies and verifies security configurations. Includes a --dry-run mode that reports what it would change without changing anything.
- **Baseline report** — Snapshot of current security posture that future runs can diff against to detect drift

**Constraints:**
- Must not lock Scott or Forge out of the VPS
- Script must be safe to run repeatedly (idempotent)
- --dry-run is mandatory before any production changes

### 3.4 Secure Communications Audit

**Current state:** Forge communicates with Scott via a messaging service. API calls go to Anthropic. Details of TLS, credential handling, and channel security need verification.

**What Citadel Archer provides:**

- **Communication channel audit** — Verify TLS on all outbound connections (Anthropic API, messaging service, git remote)
- **API key scoping** — Ensure API keys have minimal required permissions
- **Credential rotation documentation** — Runbook for rotating each credential (Anthropic API key, messaging service credentials, git tokens)

**Constraints:**
- Audit and documentation only for Phase 1 (no automated rotation of external service credentials yet)

### 3.5 Agent Action Logging

**Current state:** No centralized logging of agent activity beyond git commits.

**What Citadel Archer provides:**

- **Action log** — Centralized, append-only log of agent activity: session spawned, files modified, commands run, secrets accessed, session ended
- **Log viewer** — Simple CLI tool or readable log file that Scott can review to see what agents have been doing
- **Anomaly flags** — Basic checks: did an agent modify files outside its scope? Did a session run unusually long? Did an agent access secrets it shouldn't need?

**Constraints:**
- Keep it simple — a structured log file is fine, no need for ELK stack or similar
- Logging must not significantly slow down agent operations

---

## 4. What Citadel Archer Is NOT (Phase 1)

- Not a network intrusion detection system
- Not a compliance framework (SOC2, etc.)
- Not a multi-server orchestration tool
- Not a replacement for external security services (DDoS protection, etc.)
- Not a user-facing product — this is internal tooling for our team

---

## 5. Success Criteria

### Must Have (Phase 1 ships only if ALL pass)

- [ ] Secrets are encrypted at rest — no plaintext .env files in production use
- [ ] Agent secret access is scoped — Dev Agent cannot read Forge's API keys
- [ ] Secret access is logged — every access recorded with agent name + timestamp
- [ ] Secret rotation works via CLI — rotate a secret without manually editing files
- [ ] Migration path exists — can transition from .env files incrementally
- [ ] VPS hardening script runs in --dry-run without errors
- [ ] VPS hardening script is idempotent (running twice produces same result)
- [ ] Service/port audit report generated
- [ ] Firewall rules reviewed and tightened
- [ ] All outbound connections verified for TLS
- [ ] Agent action log captures session start/end, files modified, secrets accessed
- [ ] Scott can review agent activity in under 5 minutes using the log viewer
- [ ] Nothing breaks — Forge can still spawn agents, agents can still code and push, Scott can still access VPS

### Nice to Have (Phase 1 if easy, otherwise Phase 2)

- [ ] Filesystem permission boundaries enforced (not just convention)
- [ ] Git branch protection enforced programmatically
- [ ] Anomaly detection flags in action log
- [ ] Credential rotation runbook for all external services
- [ ] Security posture baseline with drift detection

---

## 6. Known Constraints

- **Single VPS** — all solutions must work on one machine, no distributed infrastructure
- **Budget** — no paid security tools or services; open-source and built-in OS tools only
- **No downtime** — Forge and the agent pipeline must keep running during implementation
- **Incremental migration** — old .env system must work alongside new system during transition
- **Claude Code compatibility** — any sandboxing must not break Claude Code's ability to read project files and write code

---

## 7. Technical Preferences

- **Language:** Match whatever the existing codebase uses. If starting new modules, Python or Bash are preferred for ops tooling (widely understood, easy to maintain).
- **Encryption:** Lightweight. age or sops preferred over GPG. No heavy key management infrastructure.
- **Logging:** Structured text files (JSON lines or similar). No database required.
- **CLI-first:** All tools should be usable from the command line. No web UI required for Phase 1.

---

## 8. Questions for Scott (Pre-Architecture)

These should be answered before Opus Lead writes ARCHITECTURE.md:

1. **Existing codebase:** Can you point the Dev Agent to the specific repo/directory where Citadel Archer's existing code lives? (Forge should ensure this is accessible in the project directory or documented in a README.)

2. **Forge's messaging service:** Can you name the service Forge uses to contact you? (Doesn't need to be in this doc if sensitive — but Opus Lead needs to know for the comms audit.)

3. **How many distinct secrets exist today?** Rough count — are we talking 5 keys or 50? This affects whether we need categories/namespaces in the secret store.

4. **Any secrets shared between services?** E.g., does Forge and some other process share the same Anthropic API key? This affects rotation planning.

5. **Backup strategy:** Is the VPS backed up? If we encrypt secrets and lose the encryption key, what's the recovery plan? (This isn't blocking, but Opus Lead should design with it in mind.)

---

## 9. Future Phases (Out of Scope for Phase 1)

- **Phase 2:** Full agent sandboxing with OS-level enforcement, automated credential rotation for external services, security scanning of agent-produced code
- **Phase 3:** Intrusion detection, automated security regression testing, security posture dashboard
- **Phase N:** If the team grows or the product becomes external-facing, revisit compliance, multi-user access controls, and network segmentation

---

**Ready for:** Scott to answer Section 8 questions, then Opus Lead writes ARCHITECTURE.md

*Created: 2026-02-05*  
*Last updated: 2026-02-06 03:26 UTC by Forge (write to state management)*
