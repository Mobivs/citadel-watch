# Citadel Archer - Claude Code Configuration

This directory contains project-specific configuration for Claude Code (AI-assisted development).

## Purpose

**Problem**: Projects often drift from their original vision as development progresses. Features get added without planning, requirements get forgotten, and the PRD becomes outdated documentation instead of a living contract.

**Solution**: We've built a **systematic PRD adherence system** using Claude Code's infrastructure to ensure we stay locked to our Product Requirements Document throughout the entire project lifecycle.

## How It Works

### 1. Automatic PRD Context (`.claude/knowledge/`)

**File**: `knowledge/prd-core.md`

This file is **automatically loaded** by Claude Code in every conversation about this project. It contains:
- Core PRD principles
- Current phase scope (what's in/out)
- Technology constraints
- Code standards
- Operating rules

**Effect**: Every time you work with Claude Code, it already knows the PRD and will reference it proactively.

### 2. Project Rules (`.claude/rules.md`)

**File**: `rules.md`

Enforced rules that Claude Code follows automatically:
- **PRD-first development**: Read PRD → Quote requirement → Implement
- **Phase discipline**: Stay in current phase, flag out-of-scope requests
- **Technology constraints**: No framework changes without PRD update
- **Security standards**: Non-negotiable privacy and security rules
- **Code standards**: PRD reference comments, security level checks, audit logging
- **Documentation**: Every feature needs PRD references

**Effect**: Claude Code will actively enforce these rules and call out violations.

### 3. PRD Compliance Skill (`.claude/skills/`)

**Skill**: `check-prd.md`

User-invocable command: `/check-prd [module]`

Runs a comprehensive compliance audit:
- Compares PRD requirements vs. actual implementation
- Reports: ✅ Compliant | ⚠️ Partial | ❌ Missing | 🚨 Scope Creep
- Suggests next steps to achieve full compliance
- Calculates compliance percentage

**Usage**:
```bash
/check-prd              # Overall project
/check-prd guardian     # Guardian module only
/check-prd phase1       # Phase 1 completion check
```

### 4. Compliance Checklists (`docs/checklists/`)

**File**: `docs/checklists/phase-1-compliance.md`

Detailed checklist for each phase with:
- Every PRD requirement broken down
- Checkboxes for tracking progress
- Priorities (Critical/High/Medium)
- Deviations table
- Sign-off section

**Usage**: Check items as you complete them. Before moving to next phase, verify 100% completion.

### 5. Architecture Decision Records (`docs/adr/`)

**Template**: `docs/adr/000-template.md`

When making significant architectural decisions:
1. Create new ADR: `docs/adr/001-decision-name.md`
2. Document context, decision, rationale, consequences
3. Note PRD alignment (compliant/deviation/addition)
4. Update PRD if needed

**Effect**: Every major decision is documented with reasoning, creating a decision history.

### 6. PRD Version Control

**File**: `docs/PRD.md` (Changelog section at top)

The PRD itself tracks all changes:
- Version history (0.1.0, 0.2.0, etc.)
- Changelog for each version
- What changed and why
- Strikethrough old text, bold new text

**Process**:
1. Need to change PRD? Update it FIRST
2. Increment version
3. Add changelog entry
4. THEN implement code

---

## Workflow Integration

### Daily Development

**When implementing a feature**:
1. Claude Code automatically references PRD (via `knowledge/prd-core.md`)
2. Quotes relevant PRD section
3. Implements with PRD comments in code
4. Suggests tests to verify compliance

**Example**:
```
User: "Add file monitoring to Guardian"

Claude: "Reading PRD Section: Guardian Module...

The PRD specifies: 'Real-time filesystem monitoring (unauthorized changes,
suspicious binaries)'

I'll implement using watchdog for real-time events. This aligns with
PRD technical approach: 'Python agent with OS-level hooks (watchdog, psutil)'

[Implements with PRD comments in code]

PRD Compliance: ✅ Fully aligned"
```

### Weekly Check-ins

Every week (or after major feature):
```bash
/check-prd
```

Review the compliance report:
- Are we still aligned?
- Any scope creep?
- What needs PRD updates?

### Phase Transitions

Before moving to next phase:
1. Open `docs/checklists/phase-N-compliance.md`
2. Verify 100% completion
3. Run `/check-prd phaseN` for final audit
4. Get user sign-off
5. Create Phase N retrospective ADR

### When PRD Changes

If you discover PRD needs updating:
1. Discuss with team/user
2. Update `docs/PRD.md`
3. Increment version (0.1.0 → 0.2.0)
4. Add changelog entry
5. Create ADR if architectural (docs/adr/)
6. Update code to match
7. Update checklist if affects current phase

---

## File Structure

```
.claude/
├── README.md           # This file - explains the system
├── rules.md            # Enforced project rules (auto-loaded)
├── knowledge/
│   └── prd-core.md     # PRD essentials (auto-loaded in every chat)
└── skills/
    └── check-prd.md    # /check-prd command definition

docs/
├── PRD.md              # Source of truth (versioned)
├── adr/
│   ├── 000-template.md # ADR template
│   └── 001-*.md        # Actual decisions
└── checklists/
    ├── phase-1-compliance.md
    ├── phase-2-compliance.md
    └── ...
```

---

## Benefits of This System

### 1. **Automatic PRD Awareness**
Claude Code always knows the PRD context without you having to paste it every time.

### 2. **Proactive Compliance Checking**
Claude Code will call out drift before it becomes a problem:
> "⚠️ PRD Drift Alert: This feature isn't in the PRD. Should we add it or is this scope creep?"

### 3. **Traceable Decisions**
Every architectural decision is documented in ADRs with PRD alignment noted.

### 4. **Phase Discipline**
Clear boundaries on what's in/out of scope prevent feature bloat.

### 5. **Compliance Verification**
`/check-prd` gives objective compliance score, not subjective feelings.

### 6. **Living Documentation**
PRD stays up-to-date because changes are required before implementation.

### 7. **Knowledge Transfer**
New team members can read PRD + ADRs to understand all decisions.

---

## Common Commands

```bash
# Check overall PRD compliance
/check-prd

# Check specific module compliance
/check-prd guardian
/check-prd vault
/check-prd dashboard

# Check phase completion
/check-prd phase1

# View PRD core principles
cat .claude/knowledge/prd-core.md

# View project rules
cat .claude/rules.md

# View phase checklist
cat docs/checklists/phase-1-compliance.md

# View PRD
cat docs/PRD.md

# See all PRD-related commits
git log --grep="PRD:"
```

---

## Maintenance

### This System Requires:
- ✅ Keeping PRD up-to-date (versioned, with changelog)
- ✅ Checking phase checklists regularly
- ✅ Running `/check-prd` weekly
- ✅ Creating ADRs for major decisions
- ✅ Updating `.claude/knowledge/prd-core.md` when PRD fundamentals change

### This System Prevents:
- ❌ PRD becoming outdated documentation
- ❌ Scope creep without discussion
- ❌ Implementing features not in PRD
- ❌ Forgetting why decisions were made
- ❌ Drifting from original vision
- ❌ Building features nobody asked for

---

## For New Developers

If you're joining this project:

1. **Read** `docs/PRD.md` thoroughly (especially your phase)
2. **Understand** `.claude/knowledge/prd-core.md` (core principles)
3. **Follow** `.claude/rules.md` (enforced standards)
4. **Use** `/check-prd` before major commits
5. **Update** checklists as you complete items
6. **Create** ADRs for architectural decisions
7. **Ask** if something seems to conflict with PRD

The PRD is not a suggestion - it's a contract with our users about what we're building.

---

## Questions?

- **Is this too rigid?** No - the PRD can be updated anytime with proper versioning. This just ensures updates are deliberate, not accidental.
- **What if PRD is wrong?** Update it! Document why in the changelog. PRD should evolve based on learnings.
- **Can we deviate?** Yes - with ADR explaining why, PRD update, and user approval. Just don't deviate silently.
- **Is this overhead?** Initially yes, but it saves massive time by preventing "wait, why did we build this?" situations 6 months later.

**The goal**: Build exactly what we promised in the PRD, and if we change our minds, update the PRD first so everyone knows.

---

**This system ensures Citadel Archer stays true to its vision: AI-centric defensive security that empowers individuals.**
