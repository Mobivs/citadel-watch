# ADR-003: Panic Room Design Decisions

## Status
Accepted

## Context
Phase 3 introduces the Panic Room emergency response system. Several key architectural decisions need to be made regarding triggers, isolation strategies, and rollback capabilities.

## Decisions

### 1. Trigger Mechanism

#### Decision: Hybrid Approach (Manual + AI)
We will support both manual user triggers and AI-based automatic triggers.

**Rationale:**
- Manual triggers give users immediate control in obvious threat situations
- AI triggers provide protection when users aren't present or don't recognize threats
- Confirmation requirements prevent false positives from causing disruption

**Alternatives Considered:**
- Manual-only: Too slow for automated attacks
- AI-only: Users lose control, higher false positive risk

### 2. Network Isolation Strategy

#### Decision: Smart Isolation with Whitelist
Network isolation will use a whitelist approach, maintaining essential connections while blocking everything else.

**Whitelist includes:**
- Citadel Commander API (localhost:8888)
- VPS agent IPs (user-configurable)
- DNS servers (for domain resolution)
- Backup destinations
- Critical update servers

**Rationale:**
- Complete isolation would break Citadel Commander itself
- Whitelist approach maintains command & control
- Allows continued monitoring and response coordination

**Alternatives Considered:**
- Complete isolation: Would lose C2 capability
- Blacklist approach: Too permissive, might miss threats

### 3. Credential Rotation

#### Decision: Archive Old Credentials
Old credentials will be archived (encrypted) rather than immediately deleted.

**Rationale:**
- Forensic analysis may need credential timeline
- Rollback might require restoration
- Audit trail for compliance
- Can be securely deleted after investigation

**Storage:**
- Encrypted with panic session key
- Stored in separate forensics database
- Auto-purge after 30 days (configurable)

### 4. Playbook Execution Order

#### Decision: Priority-Based Parallel Execution
Playbooks execute based on priority levels, with same-priority playbooks running in parallel.

**Priority Levels:**
1. Network Isolation (Priority 1) - Immediate threat containment
2. Credential Rotation (Priority 2) - Prevent lateral movement
3. Process Termination (Priority 3) - Stop active threats
4. System Snapshot (Priority 4) - Capture forensics
5. Secure Backup (Priority 5) - Protect data

**Rationale:**
- Network isolation must happen first to contain threat
- Parallel execution within priorities speeds response
- Clear ordering prevents conflicts

### 5. Rollback Capability

#### Decision: Component-Level Rollback
Each component can be rolled back independently rather than all-or-nothing.

**Components:**
- Network configuration
- Credentials
- Processes
- System settings

**Rationale:**
- Granular control over recovery
- Some components might need to stay isolated
- Reduces risk of re-exposing vulnerabilities

### 6. Pre-flight Checks

#### Decision: Non-Blocking Checks with Override
Pre-flight checks warn but don't block execution (except critical failures).

**Critical Failures (blocking):**
- No database access (can't log)
- No memory for forensics
- Corrupted playbook definitions

**Warnings (non-blocking):**
- Backup destination unreachable
- Low disk space
- Some VPS agents offline

**Rationale:**
- Emergency response shouldn't be delayed by minor issues
- User can override warnings if needed
- Critical failures would prevent any meaningful response

### 7. State Storage

#### Decision: Separate Forensics Database
Panic room state stored in separate database/tables from normal operations.

**Structure:**
- panic_sessions: Overall panic events
- panic_logs: Detailed action logs
- recovery_states: Rollback information

**Rationale:**
- Isolation prevents tampering
- Easier to backup/export for analysis
- Can be encrypted differently
- Performance isolation from main app

### 8. WebSocket Updates

#### Decision: Dedicated Panic WebSocket Channel
Real-time updates via dedicated WebSocket channel per panic session.

**Channel Format:** `/ws/panic/{session_id}`

**Events:**
- action_started
- action_completed
- action_failed
- progress_update
- session_completed

**Rationale:**
- Real-time feedback critical during emergency
- Per-session channels prevent confusion
- Can be recorded for post-incident review

### 9. Confirmation Requirements

#### Decision: Sliding Scale Based on Severity
Different confirmation levels based on action severity.

**No Confirmation:**
- System snapshot
- Forensics collection
- Non-destructive monitoring

**Single Confirmation:**
- Network isolation
- Credential rotation
- Process termination

**Double Confirmation:**
- Data deletion
- System shutdown
- Factory reset

**Rationale:**
- Balances speed with safety
- Critical actions need extra protection
- Non-destructive actions can be immediate

### 10. Integration with Existing Systems

#### Decision: Loosely Coupled via APIs
Panic Room integrates with Phase 2 components via APIs, not direct database access.

**Integration Points:**
- Vault API for credential rotation
- Guardian API for process monitoring
- Remote Shield API for VPS commands
- Threat Scorer API for AI triggers

**Rationale:**
- Maintains component independence
- Easier testing and development
- Can upgrade components independently
- Clear interface boundaries

## Consequences

### Positive
- Flexible trigger system accommodates different threat scenarios
- Granular rollback reduces recovery risk
- Parallel execution speeds response time
- Strong audit trail for compliance/forensics
- Integration approach maintains modularity

### Negative
- More complex than single-trigger system
- Parallel execution requires careful coordination
- Whitelist maintenance requires ongoing updates
- Separate forensics database increases storage needs

### Risks
- False positives could disrupt operations
- Incomplete rollback might leave system vulnerable
- Network isolation might prevent remote recovery
- Credential rotation could lock out legitimate users

### Mitigations
- Confirmation requirements prevent accidental triggers
- Component-level rollback provides granular recovery
- Whitelist includes recovery endpoints
- Archive old credentials for emergency restoration