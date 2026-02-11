"""
Panic Room Data Models
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any
from uuid import UUID


@dataclass
class PanicSession:
    """Represents a panic room session"""
    id: UUID
    triggered_at: datetime
    trigger_source: str
    trigger_reason: str
    status: str
    user_id: Optional[int] = None
    confirmation_token: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class PanicLog:
    """Log entry for panic action execution"""
    id: UUID
    session_id: UUID
    playbook_id: str
    playbook_name: str
    action_name: str
    action_type: str
    priority: int
    started_at: datetime
    completed_at: Optional[datetime]
    status: str
    result: Dict[str, Any]
    error_message: Optional[str]
    execution_time_ms: Optional[int]


@dataclass
class RecoveryState:
    """Recovery state for rollback operations"""
    id: UUID
    session_id: UUID
    component: str
    component_id: str
    pre_panic_state: Dict[str, Any]
    current_state: Optional[Dict[str, Any]]
    rollback_available: bool = True
    rollback_attempted: bool = False
    rollback_succeeded: Optional[bool] = None
    rollback_at: Optional[datetime] = None


@dataclass
class IsolationRule:
    """Network isolation rule"""
    id: UUID
    session_id: UUID
    rule_type: str  # firewall, route, dns, proxy
    direction: Optional[str]  # inbound, outbound, both
    protocol: Optional[str]  # tcp, udp, icmp, all
    source_ip: Optional[str]
    source_port: Optional[int]
    destination_ip: Optional[str]
    destination_port: Optional[int]
    action: str  # allow, deny, redirect
    priority: int = 100
    is_active: bool = True
    applied_at: Optional[datetime] = None
    removed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = None


@dataclass
class ForensicSnapshot:
    """Forensic snapshot of system state"""
    id: UUID
    session_id: UUID
    snapshot_type: str  # processes, network, files, memory, logs, full
    snapshot_data: Dict[str, Any]
    file_path: Optional[str] = None
    file_size_bytes: Optional[int] = None
    checksum: Optional[str] = None
    compression: Optional[str] = None  # gzip, bzip2, none
    encrypted: bool = False
    encryption_key_id: Optional[str] = None
    captured_at: datetime = None
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.captured_at is None:
            self.captured_at = datetime.utcnow()
        if self.metadata is None:
            self.metadata = {}


@dataclass
class CredentialRotation:
    """Track credential rotation during panic"""
    id: UUID
    session_id: UUID
    credential_type: str  # ssh_key, api_token, password, certificate, oauth_token
    credential_name: str
    vault_path: Optional[str]
    old_credential_hash: Optional[str]
    new_credential_hash: Optional[str]
    old_credential_archived: bool = False
    archive_path: Optional[str] = None
    rotation_status: str = "pending"  # pending, rotating, completed, failed, rolled_back
    rotated_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = None