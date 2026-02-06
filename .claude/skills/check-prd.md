# Check PRD Compliance

**Skill Name**: `check-prd`
**Description**: Verify current work aligns with PRD requirements
**User Invocable**: Yes

## Purpose

This skill checks whether the current state of the project (or a specific feature) complies with the PRD (Product Requirements Document) at `docs/PRD.md`.

## Usage

```
/check-prd [module-name]
```

**Examples**:
- `/check-prd` - Check overall project compliance
- `/check-prd guardian` - Check Guardian module specifically
- `/check-prd phase1` - Check Phase 1 completion status

## What This Skill Does

1. **Read the PRD** (`docs/PRD.md`) to understand requirements
2. **Analyze current codebase** to see what's implemented
3. **Compare PRD requirements vs. implementation**
4. **Report**:
   - ✅ What's compliant
   - ⚠️ What's partially implemented
   - ❌ What's missing from PRD scope
   - 🚨 What's implemented but NOT in PRD (scope creep!)
5. **Suggest next steps** to achieve full compliance

## Prompt for Claude

When user invokes `/check-prd [module]`:

```
You are performing a PRD compliance audit for Citadel Archer.

**Your task:**
1. Read docs/PRD.md thoroughly (especially the section relevant to [module] if specified)
2. Read the current codebase in the relevant directories:
   - For "guardian": src/guardian/
   - For "vault": src/vault/
   - For "dashboard": src/dashboard/ and frontend/
   - For "phase1": All Phase 1 scope areas
   - For overall: Entire project

3. Create a compliance report with:

**PRD Compliance Report: [Module/Phase]**

## Requirements Analysis

### ✅ Fully Implemented (PRD Compliant)
- [Requirement 1]: [File/location where implemented]
- [Requirement 2]: [File/location where implemented]

### ⚠️ Partially Implemented (Needs Work)
- [Requirement 3]: [What's missing] - [Files: ]

### ❌ Not Yet Implemented (PRD Scope)
- [Requirement 4]: [Priority: High/Medium/Low]
- [Requirement 5]: [Priority: High/Medium/Low]

### 🚨 Scope Creep (Not in PRD!)
- [Feature X]: Found in [file] but not defined in PRD
  - Action: Remove OR update PRD to include it

## Technical Approach Compliance
- Language: [Python 3.11+ ✅/❌]
- Framework: [FastAPI ✅/❌]
- Frontend: [React + TypeScript ✅/❌]
- Security levels: [Implemented ✅/❌]

## Deviations from PRD
[List any deviations and whether they're documented]

## Recommendations
1. [Next step to improve compliance]
2. [PRD sections that need updating]
3. [Code that needs refactoring]

## Compliance Score: [X]%
[Percentage of PRD requirements met for this module/phase]

---

Be thorough, objective, and specific. Reference exact PRD section numbers and file paths.
```

## Expected Output

A detailed compliance report that helps us stay locked to the PRD.

## When to Use This Skill

- **Weekly**: Check overall project compliance
- **End of Sprint**: Verify completed work matches PRD
- **Before Phase Completion**: Ensure 100% compliance before moving to next phase
- **When Concerned**: If you feel the project is drifting from PRD
- **After Major Feature**: Verify the feature was implemented as specified

## Related Files

- PRD: `docs/PRD.md`
- PRD Core Principles: `.claude/knowledge/prd-core.md`
- Phase Checklists: `docs/checklists/phase-[N]-compliance.md`
