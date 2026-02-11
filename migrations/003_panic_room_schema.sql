-- Migration: Phase 3 Panic Room Schema
-- Version: 003
-- Date: 2026-02-10
-- Description: Add tables for panic room functionality

-- Panic session tracking
CREATE TABLE IF NOT EXISTS panic_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    triggered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    trigger_source TEXT NOT NULL CHECK (trigger_source IN ('manual', 'ai', 'remote', 'deadman')),
    trigger_reason TEXT,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'executing', 'completed', 'failed', 'rolled_back')),
    user_id INTEGER REFERENCES users(id),
    confirmation_token TEXT,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Action execution log
CREATE TABLE IF NOT EXISTS panic_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES panic_sessions(id) ON DELETE CASCADE,
    playbook_id TEXT NOT NULL,
    playbook_name TEXT NOT NULL,
    action_name TEXT NOT NULL,
    action_type TEXT NOT NULL,
    priority INTEGER DEFAULT 0,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'executing', 'success', 'failed', 'skipped', 'rolled_back')),
    result JSONB DEFAULT '{}',
    error_message TEXT,
    execution_time_ms INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Recovery state for rollback
CREATE TABLE IF NOT EXISTS recovery_states (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES panic_sessions(id) ON DELETE CASCADE,
    component TEXT NOT NULL CHECK (component IN ('network', 'credentials', 'processes', 'data', 'system')),
    component_id TEXT NOT NULL, -- Specific item (e.g., 'ssh_key_1', 'firewall_rule_22')
    pre_panic_state JSONB NOT NULL,
    current_state JSONB,
    rollback_available BOOLEAN DEFAULT true,
    rollback_attempted BOOLEAN DEFAULT false,
    rollback_succeeded BOOLEAN,
    rollback_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(session_id, component, component_id)
);

-- Playbook definitions
CREATE TABLE IF NOT EXISTS playbooks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    category TEXT CHECK (category IN ('network', 'credentials', 'processes', 'data', 'system', 'custom')),
    priority INTEGER NOT NULL DEFAULT 50,
    is_active BOOLEAN DEFAULT true,
    requires_confirmation BOOLEAN DEFAULT true,
    actions JSONB NOT NULL DEFAULT '[]', -- Array of action definitions
    pre_checks JSONB DEFAULT '[]', -- Array of pre-flight checks
    rollback_actions JSONB DEFAULT '[]', -- Array of rollback actions
    estimated_duration_seconds INTEGER,
    metadata JSONB DEFAULT '{}',
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Credential rotation tracking
CREATE TABLE IF NOT EXISTS credential_rotations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID REFERENCES panic_sessions(id) ON DELETE CASCADE,
    credential_type TEXT NOT NULL CHECK (credential_type IN ('ssh_key', 'api_token', 'password', 'certificate', 'oauth_token', 'other')),
    credential_name TEXT NOT NULL,
    vault_path TEXT, -- Reference to Vault storage
    old_credential_hash TEXT, -- SHA256 of old credential for verification
    new_credential_hash TEXT, -- SHA256 of new credential
    old_credential_archived BOOLEAN DEFAULT false,
    archive_path TEXT, -- Where old credential is stored
    rotation_status TEXT NOT NULL DEFAULT 'pending' CHECK (rotation_status IN ('pending', 'rotating', 'completed', 'failed', 'rolled_back')),
    rotated_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE, -- When archived credential will be deleted
    error_message TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Network isolation rules
CREATE TABLE IF NOT EXISTS isolation_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID REFERENCES panic_sessions(id) ON DELETE CASCADE,
    rule_type TEXT NOT NULL CHECK (rule_type IN ('firewall', 'route', 'dns', 'proxy')),
    direction TEXT CHECK (direction IN ('inbound', 'outbound', 'both')),
    protocol TEXT, -- tcp, udp, icmp, all
    source_ip TEXT,
    source_port INTEGER,
    destination_ip TEXT,
    destination_port INTEGER,
    action TEXT NOT NULL CHECK (action IN ('allow', 'deny', 'redirect')),
    priority INTEGER DEFAULT 100,
    is_active BOOLEAN DEFAULT true,
    applied_at TIMESTAMP WITH TIME ZONE,
    removed_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Forensics snapshots
CREATE TABLE IF NOT EXISTS forensic_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID REFERENCES panic_sessions(id) ON DELETE CASCADE,
    snapshot_type TEXT NOT NULL CHECK (snapshot_type IN ('processes', 'network', 'files', 'memory', 'logs', 'full')),
    snapshot_data JSONB NOT NULL,
    file_path TEXT, -- If snapshot saved to file
    file_size_bytes BIGINT,
    checksum TEXT, -- SHA256 of snapshot data
    compression TEXT, -- gzip, bzip2, none
    encrypted BOOLEAN DEFAULT false,
    encryption_key_id TEXT, -- Reference to key used
    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE, -- Auto-delete old snapshots
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Panic room whitelist (persistent)
CREATE TABLE IF NOT EXISTS panic_whitelist (
    id SERIAL PRIMARY KEY,
    resource_type TEXT NOT NULL CHECK (resource_type IN ('ip', 'domain', 'port', 'process', 'file')),
    resource_value TEXT NOT NULL,
    description TEXT,
    is_permanent BOOLEAN DEFAULT false, -- Can't be removed during panic
    is_active BOOLEAN DEFAULT true,
    added_by INTEGER REFERENCES users(id),
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(resource_type, resource_value)
);

-- Panic room configuration
CREATE TABLE IF NOT EXISTS panic_config (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    description TEXT,
    is_sensitive BOOLEAN DEFAULT false,
    updated_by INTEGER REFERENCES users(id),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX idx_panic_sessions_status ON panic_sessions(status);
CREATE INDEX idx_panic_sessions_trigger ON panic_sessions(trigger_source);
CREATE INDEX idx_panic_sessions_user ON panic_sessions(user_id);
CREATE INDEX idx_panic_logs_session ON panic_logs(session_id);
CREATE INDEX idx_panic_logs_status ON panic_logs(status);
CREATE INDEX idx_panic_logs_playbook ON panic_logs(playbook_id);
CREATE INDEX idx_recovery_states_session ON recovery_states(session_id);
CREATE INDEX idx_recovery_states_component ON recovery_states(component);
CREATE INDEX idx_credential_rotations_session ON credential_rotations(session_id);
CREATE INDEX idx_credential_rotations_type ON credential_rotations(credential_type);
CREATE INDEX idx_isolation_rules_session ON isolation_rules(session_id);
CREATE INDEX idx_isolation_rules_active ON isolation_rules(is_active);
CREATE INDEX idx_forensic_snapshots_session ON forensic_snapshots(session_id);
CREATE INDEX idx_forensic_snapshots_type ON forensic_snapshots(snapshot_type);
CREATE INDEX idx_panic_whitelist_type ON panic_whitelist(resource_type);
CREATE INDEX idx_panic_whitelist_active ON panic_whitelist(is_active);

-- Insert default playbooks
INSERT INTO playbooks (id, name, description, category, priority, requires_confirmation, actions, pre_checks, rollback_actions, estimated_duration_seconds) VALUES
('isolate_network', 'Network Isolation', 'Isolate system from network threats', 'network', 1, true, 
 '[{"name": "block_all_incoming", "type": "firewall"}, {"name": "whitelist_essential", "type": "firewall"}, {"name": "snapshot_connections", "type": "forensics"}]',
 '[{"name": "verify_whitelist", "critical": true}, {"name": "check_vpn_status", "critical": false}]',
 '[{"name": "restore_firewall_rules", "type": "firewall"}, {"name": "restart_network", "type": "system"}]',
 30),

('rotate_credentials', 'Credential Rotation', 'Rotate all sensitive credentials', 'credentials', 2, false,
 '[{"name": "inventory_credentials", "type": "vault"}, {"name": "generate_new_keys", "type": "crypto"}, {"name": "update_vault", "type": "vault"}, {"name": "archive_old", "type": "backup"}]',
 '[{"name": "verify_vault_access", "critical": true}, {"name": "check_key_generator", "critical": true}]',
 '[{"name": "restore_credentials", "type": "vault"}, {"name": "update_authorized_keys", "type": "system"}]',
 45),

('kill_suspicious', 'Terminate Suspicious Processes', 'Kill processes identified as threats', 'processes', 3, false,
 '[{"name": "identify_threats", "type": "analysis"}, {"name": "capture_memory", "type": "forensics"}, {"name": "terminate_processes", "type": "system"}]',
 '[{"name": "scan_process_tree", "critical": false}, {"name": "check_critical_processes", "critical": true}]',
 '[{"name": "restart_services", "type": "system"}]',
 20),

('snapshot_system', 'System Snapshot', 'Capture complete system state for forensics', 'system', 4, false,
 '[{"name": "dump_processes", "type": "forensics"}, {"name": "capture_network", "type": "forensics"}, {"name": "hash_files", "type": "forensics"}, {"name": "collect_logs", "type": "forensics"}]',
 '[{"name": "check_disk_space", "critical": false}, {"name": "verify_tools", "critical": true}]',
 '[]',
 60),

('secure_backup', 'Secure Backup', 'Backup critical data with encryption', 'data', 5, false,
 '[{"name": "identify_critical_data", "type": "analysis"}, {"name": "encrypt_data", "type": "crypto"}, {"name": "transfer_backup", "type": "network"}, {"name": "verify_integrity", "type": "validation"}]',
 '[{"name": "check_backup_destination", "critical": true}, {"name": "verify_encryption_keys", "critical": true}]',
 '[]',
 120);

-- Insert default whitelist entries
INSERT INTO panic_whitelist (resource_type, resource_value, description, is_permanent) VALUES
('ip', '127.0.0.1', 'Localhost - Citadel Commander API', true),
('ip', '::1', 'IPv6 Localhost', true),
('port', '8888', 'Citadel Commander API Port', true),
('port', '22', 'SSH Port', false),
('port', '443', 'HTTPS Port', false),
('port', '53', 'DNS Port', true),
('domain', 'localhost', 'Local domain', true),
('process', 'citadel_commander', 'Main application', true),
('process', 'postgres', 'Database server', true);

-- Insert default configuration
INSERT INTO panic_config (key, value, description) VALUES
('auto_trigger_enabled', 'false', 'Enable AI-based automatic panic triggers'),
('confirmation_timeout_seconds', '30', 'Timeout for user confirmation'),
('max_parallel_actions', '5', 'Maximum concurrent actions during panic'),
('forensics_retention_days', '30', 'Days to keep forensic snapshots'),
('credential_archive_days', '30', 'Days to keep old credentials'),
('network_isolation_mode', '"smart"', 'Isolation mode: smart, soft, or hard'),
('rollback_enabled', 'true', 'Allow rollback of panic actions'),
('notification_channels', '["email", "sms", "dashboard"]', 'Where to send panic notifications');

-- Add trigger to update updated_at timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_panic_sessions_updated_at BEFORE UPDATE ON panic_sessions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_playbooks_updated_at BEFORE UPDATE ON playbooks
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_panic_whitelist_updated_at BEFORE UPDATE ON panic_whitelist
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_panic_config_updated_at BEFORE UPDATE ON panic_config
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();