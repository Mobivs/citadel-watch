# ADR 001: Move VPS Protection (Remote Shield) to Phase 2

**Status**: Accepted
**Date**: 2026-02-01
**PRD Impact**: Development Roadmap (Phase 2 and Phase 5)
**Deciders**: John Vickrey (User/Product Owner), Claude (Technical Advisor)

---

## Context

The initial PRD (v0.1.0) placed Remote Shield (VPS protection) in Phase 5 (Months 13-15). This would mean:
- Users wait 13+ months for VPS protection
- VPS security is treated as an "extension" rather than core functionality
- User's primary pain point (VPS compromised within days) goes unaddressed for over a year

**User's Situation**:
- Runs VPS servers that get penetrated within days despite firewalls
- Attackers are "creative at tunneling through walls"
- Has battled persistent intrusions for years
- VPS protection is a core use case, not a nice-to-have feature

**The Question**: Should VPS protection be prioritized earlier in the roadmap?

## Decision

**Move Remote Shield from Phase 5 → Phase 2** (Months 4-6)

Phase 2 becomes "Intelligence & VPS Protection" and includes:
- Intel module (threat intelligence)
- AI-powered anomaly detection
- Remote Shield agent for Ubuntu/Debian VPS
- Unified threat analysis across local + remote systems

Phase 5 refocuses on "Family & Multi-System Orchestration"

- Family computer protection (Windows agent for non-technical users)
- Multi-system management and cross-system threat correlation

## Rationale

### Option A: Keep Phase 5 (Rejected)
- **Pro**: Focus on local machine first (simpler)
- **Con**: 13 months is too long to wait for core functionality
- **Con**: Doesn't align with user's primary pain point
- **Con**: Risk of treating VPS as "second-class citizen"

### Option B: Move to Phase 1 (Rejected)
- **Pro**: Immediate VPS protection
- **Con**: Phase 1 becomes too large (local + remote simultaneously)
- **Con**: Risk of compromised local machine managing VPS (security concern)
- **Con**: Harder to maintain focus and ship MVP

### Option C: Move to Phase 2 (CHOSEN) ✅
- **Pro**: VPS protection within 6 months (not 13+)
- **Pro**: Local machine secured first (Phase 1), then extend to VPS (Phase 2)
- **Pro**: Intelligence layer (AI, threat feeds) benefits both local AND remote simultaneously
- **Pro**: Remote Shield gets proper development time, not rushed
- **Pro**: Aligns perfectly with Phase 2's theme (adding intelligence and extending reach)
- **Con**: Phase 2 is larger, but manageable

## Consequences

### Positive:
- ✅ User gets end-to-end protection (local + VPS) within 6 months
- ✅ VPS protection is treated as first-class, not an afterthought
- ✅ AI brain learns from both local and remote threats simultaneously
- ✅ Faster value delivery for user's primary use case
- ✅ Phase 2 becomes a major capability jump (intelligence + remote protection)

### Negative:
- ⚠️ Phase 2 has more scope (AI + VPS), potentially longer than 2 months
  - **Mitigation**: Can extend Phase 2 to 3 months if needed (Months 4-6)
- ⚠️ Need Ubuntu VPS for testing earlier
  - **Mitigation**: User has VPS available for testing

### Neutral:
- Phase 5 shifts focus to family computers and multi-system orchestration
- Ubuntu platform support moved from "Phase 5+" to "Phase 2" (already reflected in PRD)

## PRD Alignment

- ⚠️ **Deviation**: Original PRD had Remote Shield in Phase 5
- ✅ **Update**: PRD v0.2.0 now reflects Phase 2
- ✅ **Reason**: User feedback and strategic prioritization (VPS is core, not extension)

**PRD Update Required?** ✅ Yes - **COMPLETED**
- Updated PRD to v0.2.0
- Added changelog entry explaining change
- Updated Phase 2 and Phase 5 descriptions
- Updated Platform Support timeline

## Implementation Notes

**Phase 2 Will Include**:

**Intelligence (AI & Threat Intel)**:
- Intel module with threat feed aggregation
- Watchtower centralized monitoring
- AI anomaly detection (context engine)
- Automatic Guardian signature updates
- Advanced UI (charts, timelines)

**Remote Shield (VPS Protection)**:
- Lightweight Python agent for Ubuntu/Debian
- Remote deployment automation
- SSH hardening (key-only, fail2ban++)
- Firewall management (dynamic rules, AI-driven)
- File integrity monitoring
- Process monitoring (detect crypto miners, unauthorized services)
- Encrypted C2 channel to Watchtower
- AI threat analysis for remote systems

**Technical Approach**:
- Same AI brain analyzes both local (Guardian) and remote (Remote Shield) sensors
- Remote Shield agent is minimal footprint (~10MB, low CPU/RAM)
- Communication uses certificate-based mutual authentication
- Agent auto-updates from trusted source
- Works on: Ubuntu 20.04+, Debian 10+

**Testing Strategy**:
- User's actual VPS will be primary test environment
- Simulate real-world attacks (tunneling, port scanning, brute force SSH)
- Verify Remote Shield detects and blocks attacks Guardian would miss
- Ensure AI correctly correlates local + remote threats

## References

- PRD v0.1.0: Section "Development Roadmap, Phase 5"
- PRD v0.2.0: Updated "Development Roadmap, Phase 2 and Phase 5"
- User Quote: "Let's just please be sure not to make the VPS Management a second class project"
- Problem Statement: "Remote servers (VPS) are penetrated within days of deployment despite firewalls"

---

## Revision History

| Date | Change | Reason |
|------|--------|--------|
| 2026-02-01 | Initial ADR | Document decision to prioritize VPS protection in Phase 2 |
