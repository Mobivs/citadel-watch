"""
Database models for Citadel Archer.

SQLAlchemy ORM models for:
- agents: Remote Shield agent registration
- agent_tokens: API tokens with bcrypt hashing and TTL
- threats: Detected threats from agents
- audit_logs: Security audit trail
"""

from sqlalchemy import (
    Column, String, Integer, DateTime, Float, Boolean, Text, JSON,
    ForeignKey, Index, UniqueConstraint, Enum, LargeBinary
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

Base = declarative_base()


class AgentModel(Base):
    """
    Remote Shield Agent registration.
    
    Attributes:
        id: UUID primary key
        hostname: Agent hostname (unique)
        ip_address: Agent IP address
        status: active | inactive | offline
        last_heartbeat: Last heartbeat timestamp
        registered_at: Registration timestamp
        last_scan_at: Last scan timestamp
        public_key: mTLS public key (optional)
        scan_interval_seconds: Configured scan interval (default: 300)
    """
    __tablename__ = "agents"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    hostname = Column(String(255), unique=True, nullable=False)
    ip_address = Column(String(45), nullable=False)  # IPv4 or IPv6
    status = Column(String(20), default="inactive", nullable=False)  # active, inactive, offline
    last_heartbeat = Column(DateTime, nullable=True)
    registered_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_scan_at = Column(DateTime, nullable=True)
    public_key = Column(Text, nullable=True)
    scan_interval_seconds = Column(Integer, default=300, nullable=False)
    
    # Relationships
    tokens = relationship("TokenModel", back_populates="agent", cascade="all, delete-orphan")
    threats = relationship("ThreatModel", back_populates="agent", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLogModel", back_populates="agent", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index("idx_agent_hostname", "hostname"),
        Index("idx_agent_status", "status"),
        Index("idx_agent_last_heartbeat", "last_heartbeat"),
        Index("idx_agent_registered_at", "registered_at"),
    )


class TokenModel(Base):
    """
    Agent API tokens with bcrypt hashing and TTL.
    
    Attributes:
        id: UUID primary key
        agent_id: Foreign key to agents
        token_hash: Bcrypt hashed token (never store plaintext)
        issued_at: Token issue timestamp
        expires_at: Token expiration timestamp (24 hours by default)
        is_revoked: Soft-delete for revoked tokens
        revoked_at: Revocation timestamp
        last_used_at: Last usage timestamp
    """
    __tablename__ = "agent_tokens"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String(36), ForeignKey("agents.id"), nullable=False)
    token_hash = Column(String(255), nullable=False)  # bcrypt hash
    issued_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    is_revoked = Column(Boolean, default=False, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    
    # Relationships
    agent = relationship("AgentModel", back_populates="tokens")
    
    # Indexes
    __table_args__ = (
        Index("idx_token_agent_id", "agent_id"),
        Index("idx_token_expires_at", "expires_at"),
        Index("idx_token_is_revoked", "is_revoked"),
        Index("idx_token_issued_at", "issued_at"),
    )


class ThreatModel(Base):
    """
    Detected threats from Remote Shield agents.
    
    Attributes:
        id: UUID primary key
        agent_id: Foreign key to agents
        threat_type: Type of threat (port_scan_anomaly, etc.)
        severity: Severity level (1-10)
        hostname: Agent hostname (denormalized for queries)
        title: Human-readable title
        description: Detailed description
        details: JSON object with threat-specific data
        status: open | acknowledged | resolved
        detected_at: Detection timestamp
        reported_at: Report timestamp
        resolved_at: Resolution timestamp
        resolution_notes: Notes on resolution
    """
    __tablename__ = "threats"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String(36), ForeignKey("agents.id"), nullable=False)
    threat_type = Column(String(50), nullable=False)
    severity = Column(Integer, nullable=False)  # 1-10
    hostname = Column(String(255), nullable=False)  # Denormalized for queries
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    details = Column(JSON, nullable=True)  # Threat-specific data
    status = Column(String(20), default="open", nullable=False)  # open, acknowledged, resolved
    detected_at = Column(DateTime, nullable=False)
    reported_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    resolved_at = Column(DateTime, nullable=True)
    resolution_notes = Column(Text, nullable=True)
    
    # Relationships
    agent = relationship("AgentModel", back_populates="threats")
    
    # Indexes
    __table_args__ = (
        Index("idx_threat_agent_id", "agent_id"),
        Index("idx_threat_type", "threat_type"),
        Index("idx_threat_severity", "severity"),
        Index("idx_threat_hostname", "hostname"),
        Index("idx_threat_status", "status"),
        Index("idx_threat_detected_at", "detected_at"),
        Index("idx_threat_reported_at", "reported_at"),
    )


class AuditLogModel(Base):
    """
    Security audit trail.
    
    Attributes:
        id: UUID primary key
        agent_id: Foreign key to agents (nullable for system-level events)
        event_type: Type of event (agent_registered, token_issued, threat_detected, etc.)
        severity: Event severity (info, warning, error, critical)
        actor: Who performed the action (agent ID, system, etc.)
        action: What was done
        details: JSON object with event-specific data
        ip_address: Source IP address (for authentication events)
        result: success | failure
        timestamp: Event timestamp
    """
    __tablename__ = "audit_logs"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String(36), ForeignKey("agents.id"), nullable=True)
    event_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)  # info, warning, error, critical
    actor = Column(String(255), nullable=False)  # Agent ID or system
    action = Column(String(255), nullable=False)
    details = Column(JSON, nullable=True)
    ip_address = Column(String(45), nullable=True)
    result = Column(String(20), nullable=False)  # success, failure
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    agent = relationship("AgentModel", back_populates="audit_logs")
    
    # Indexes
    __table_args__ = (
        Index("idx_audit_agent_id", "agent_id"),
        Index("idx_audit_event_type", "event_type"),
        Index("idx_audit_severity", "severity"),
        Index("idx_audit_actor", "actor"),
        Index("idx_audit_timestamp", "timestamp"),
        Index("idx_audit_result", "result"),
    )
