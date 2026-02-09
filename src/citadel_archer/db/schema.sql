-- PostgreSQL Schema for Citadel Archer
-- Phase 2: Security Hardening - Database Persistence
-- Date: 2026-02-09

-- ============================================================================
-- Agents Table
-- ============================================================================
-- Remote Shield agent registration and status
CREATE TABLE IF NOT EXISTS agents (
    id VARCHAR(36) PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL UNIQUE,
    ip_address VARCHAR(45) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'inactive' CHECK (status IN ('active', 'inactive', 'offline')),
    last_heartbeat TIMESTAMP NULL,
    registered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_scan_at TIMESTAMP NULL,
    public_key TEXT NULL,
    scan_interval_seconds INTEGER NOT NULL DEFAULT 300
);

CREATE INDEX idx_agent_hostname ON agents(hostname);
CREATE INDEX idx_agent_status ON agents(status);
CREATE INDEX idx_agent_last_heartbeat ON agents(last_heartbeat);
CREATE INDEX idx_agent_registered_at ON agents(registered_at);

-- ============================================================================
-- Agent Tokens Table
-- ============================================================================
-- API tokens with bcrypt hashing and TTL
CREATE TABLE IF NOT EXISTS agent_tokens (
    id VARCHAR(36) PRIMARY KEY,
    agent_id VARCHAR(36) NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMP NULL,
    last_used_at TIMESTAMP NULL
);

CREATE INDEX idx_token_agent_id ON agent_tokens(agent_id);
CREATE INDEX idx_token_expires_at ON agent_tokens(expires_at);
CREATE INDEX idx_token_is_revoked ON agent_tokens(is_revoked);
CREATE INDEX idx_token_issued_at ON agent_tokens(issued_at);

-- ============================================================================
-- Threats Table
-- ============================================================================
-- Detected threats from Remote Shield agents
CREATE TABLE IF NOT EXISTS threats (
    id VARCHAR(36) PRIMARY KEY,
    agent_id VARCHAR(36) NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    threat_type VARCHAR(50) NOT NULL,
    severity INTEGER NOT NULL CHECK (severity >= 1 AND severity <= 10),
    hostname VARCHAR(255) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NULL,
    details JSONB NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved')),
    detected_at TIMESTAMP NOT NULL,
    reported_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL,
    resolution_notes TEXT NULL
);

CREATE INDEX idx_threat_agent_id ON threats(agent_id);
CREATE INDEX idx_threat_type ON threats(threat_type);
CREATE INDEX idx_threat_severity ON threats(severity);
CREATE INDEX idx_threat_hostname ON threats(hostname);
CREATE INDEX idx_threat_status ON threats(status);
CREATE INDEX idx_threat_detected_at ON threats(detected_at);
CREATE INDEX idx_threat_reported_at ON threats(reported_at);

-- ============================================================================
-- Audit Logs Table
-- ============================================================================
-- Security audit trail for all operations
CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(36) PRIMARY KEY,
    agent_id VARCHAR(36) NULL REFERENCES agents(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('info', 'warning', 'error', 'critical')),
    actor VARCHAR(255) NOT NULL,
    action VARCHAR(255) NOT NULL,
    details JSONB NULL,
    ip_address VARCHAR(45) NULL,
    result VARCHAR(20) NOT NULL CHECK (result IN ('success', 'failure')),
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_agent_id ON audit_logs(agent_id);
CREATE INDEX idx_audit_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_severity ON audit_logs(severity);
CREATE INDEX idx_audit_actor ON audit_logs(actor);
CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_result ON audit_logs(result);

-- ============================================================================
-- Composite Indexes
-- ============================================================================
-- Common query patterns
CREATE INDEX idx_threat_agent_status ON threats(agent_id) INCLUDE (status);
CREATE INDEX idx_audit_agent_timestamp ON audit_logs(agent_id, timestamp);
CREATE INDEX idx_token_agent_revoked ON agent_tokens(agent_id, is_revoked);
