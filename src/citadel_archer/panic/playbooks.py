"""
Panic Room Playbooks - Phase 3 Implementation
Pre-configured emergency response playbooks
"""

import json
import subprocess
import shutil
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class PlaybookLibrary:
    """Library of pre-configured panic response playbooks"""
    
    PLAYBOOKS = {
        "IsolateNetwork": {
            "id": "isolate_network",
            "name": "Network Isolation",
            "description": "Block all network traffic except localhost",
            "category": "Network",
            "priority": 1,
            "requires_confirmation": True,
            "actions": [
                {
                    "name": "Backup IPTables",
                    "type": "backup_config",
                    "params": {"target": "iptables"}
                },
                {
                    "name": "Apply Isolation Rules",
                    "type": "network_isolation",
                    "params": {"mode": "strict", "allow_localhost": True}
                }
            ],
            "rollback_actions": [
                {
                    "name": "Restore IPTables",
                    "type": "restore_config",
                    "params": {"target": "iptables"}
                }
            ]
        },
        
        "RotateCredentials": {
            "id": "rotate_credentials",
            "name": "Credential Rotation",
            "description": "Rotate all stored credentials and API keys",
            "category": "Security",
            "priority": 1,
            "requires_confirmation": True,
            "actions": [
                {
                    "name": "Backup Current Credentials",
                    "type": "backup_credentials",
                    "params": {"vault_path": "/vault/credentials"}
                },
                {
                    "name": "Generate New Credentials",
                    "type": "generate_credentials",
                    "params": {"strength": "high"}
                },
                {
                    "name": "Deploy New Credentials",
                    "type": "deploy_credentials",
                    "params": {"notify": True}
                }
            ]
        },
        
        "SnapshotSystem": {
            "id": "snapshot_system",
            "name": "System State Snapshot",
            "description": "Create comprehensive system state snapshot",
            "category": "Forensics",
            "priority": 2,
            "requires_confirmation": False,
            "actions": [
                {
                    "name": "Process Snapshot",
                    "type": "capture_processes",
                    "params": {"include_memory": False}
                },
                {
                    "name": "Network Connections",
                    "type": "capture_network",
                    "params": {"include_packets": False}
                },
                {
                    "name": "File System State",
                    "type": "capture_filesystem",
                    "params": {"paths": ["/etc", "/home", "/var/log"]}
                }
            ]
        },
        
        "SecureBackup": {
            "id": "secure_backup",
            "name": "Secure Critical Data",
            "description": "Backup and encrypt critical data",
            "category": "Data",
            "priority": 2,
            "requires_confirmation": False,
            "actions": [
                {
                    "name": "Identify Critical Data",
                    "type": "scan_critical_data",
                    "params": {"config_path": "/etc/citadel/backup_config.json"}
                },
                {
                    "name": "Create Encrypted Backup",
                    "type": "create_backup",
                    "params": {"encryption": "gpg", "compression": "gzip"}
                },
                {
                    "name": "Verify Backup Integrity",
                    "type": "verify_backup",
                    "params": {"generate_hash": True}
                }
            ]
        },
        
        "KillProcesses": {
            "id": "kill_processes",
            "name": "Terminate Suspicious Processes",
            "description": "Kill all non-whitelisted processes",
            "category": "System",
            "priority": 1,
            "requires_confirmation": True,
            "actions": [
                {
                    "name": "Identify Suspicious Processes",
                    "type": "scan_processes",
                    "params": {"whitelist_path": "/etc/citadel/process_whitelist.json"}
                },
                {
                    "name": "Terminate Processes",
                    "type": "kill_processes",
                    "params": {"signal": "SIGTERM", "force_after": 5}
                }
            ]
        },
        
        "LockdownAccess": {
            "id": "lockdown_access",
            "name": "Access Control Lockdown",
            "description": "Disable all remote access and lock user accounts",
            "category": "Access",
            "priority": 1,
            "requires_confirmation": True,
            "actions": [
                {
                    "name": "Disable SSH",
                    "type": "disable_service",
                    "params": {"service": "sshd"}
                },
                {
                    "name": "Lock User Accounts",
                    "type": "lock_accounts",
                    "params": {"exclude": ["root", "citadel"]}
                },
                {
                    "name": "Revoke Active Sessions",
                    "type": "revoke_sessions",
                    "params": {"all": True}
                }
            ]
        },
        
        "QuarantineFiles": {
            "id": "quarantine_files",
            "name": "Quarantine Suspicious Files",
            "description": "Move suspicious files to quarantine",
            "category": "Malware",
            "priority": 2,
            "requires_confirmation": False,
            "actions": [
                {
                    "name": "Scan for Threats",
                    "type": "scan_threats",
                    "params": {"paths": ["/tmp", "/var/tmp", "/home"]}
                },
                {
                    "name": "Quarantine Files",
                    "type": "quarantine_move",
                    "params": {"destination": "/var/lib/citadel/quarantine"}
                },
                {
                    "name": "Generate Report",
                    "type": "generate_report",
                    "params": {"format": "json"}
                }
            ]
        }
    }
    
    @classmethod
    def get_playbook(cls, playbook_id: str) -> Optional[Dict]:
        """Get a playbook by ID"""
        for key, playbook in cls.PLAYBOOKS.items():
            if playbook['id'] == playbook_id or key == playbook_id:
                return playbook
        return None
    
    @classmethod
    def list_playbooks(cls) -> List[Dict]:
        """List all available playbooks"""
        return list(cls.PLAYBOOKS.values())
    
    @classmethod
    def get_playbooks_by_category(cls, category: str) -> List[Dict]:
        """Get playbooks by category"""
        return [p for p in cls.PLAYBOOKS.values() if p['category'] == category]
    
    @classmethod
    def get_playbook_categories(cls) -> List[str]:
        """Get unique playbook categories"""
        categories = set()
        for playbook in cls.PLAYBOOKS.values():
            categories.add(playbook['category'])
        return sorted(list(categories))


class PlaybookValidator:
    """Validates playbook execution conditions"""
    
    @staticmethod
    def validate_prerequisites(playbook: Dict) -> tuple[bool, List[str]]:
        """Check if playbook can be executed"""
        issues = []
        
        # Check for required binaries
        required_commands = PlaybookValidator._get_required_commands(playbook)
        for cmd in required_commands:
            if not shutil.which(cmd):
                issues.append(f"Required command not found: {cmd}")
        
        # Check for required paths
        required_paths = PlaybookValidator._get_required_paths(playbook)
        for path_str in required_paths:
            path = Path(path_str)
            if not path.exists():
                issues.append(f"Required path not found: {path_str}")
        
        # Check for sufficient permissions
        if PlaybookValidator._requires_root(playbook):
            import os
            if os.geteuid() != 0:
                issues.append("Playbook requires root privileges")
        
        return len(issues) == 0, issues
    
    @staticmethod
    def _get_required_commands(playbook: Dict) -> List[str]:
        """Extract required system commands from playbook"""
        commands = []
        
        # Map action types to required commands
        action_command_map = {
            "network_isolation": ["iptables"],
            "backup_config": ["tar", "gzip"],
            "capture_processes": ["ps", "lsof"],
            "capture_network": ["netstat", "ss"],
            "create_backup": ["tar", "gpg"],
            "disable_service": ["systemctl"],
            "scan_threats": ["find", "file"]
        }
        
        for action in playbook.get('actions', []):
            action_type = action.get('type')
            if action_type in action_command_map:
                commands.extend(action_command_map[action_type])
        
        return list(set(commands))
    
    @staticmethod
    def _get_required_paths(playbook: Dict) -> List[str]:
        """Extract required file paths from playbook"""
        paths = []
        
        for action in playbook.get('actions', []):
            params = action.get('params', {})
            
            # Check for config paths
            if 'config_path' in params:
                paths.append(params['config_path'])
            if 'whitelist_path' in params:
                paths.append(params['whitelist_path'])
            if 'vault_path' in params:
                paths.append(params['vault_path'])
        
        return paths
    
    @staticmethod
    def _requires_root(playbook: Dict) -> bool:
        """Check if playbook requires root privileges"""
        root_required_actions = {
            "network_isolation", "disable_service", 
            "lock_accounts", "kill_processes"
        }
        
        for action in playbook.get('actions', []):
            if action.get('type') in root_required_actions:
                return True
        
        return False


class PlaybookScheduler:
    """Schedules and prioritizes playbook execution"""
    
    @staticmethod
    def create_execution_plan(playbook_ids: List[str]) -> List[Dict]:
        """Create optimized execution plan for multiple playbooks"""
        plan = []
        
        # Get all playbooks
        playbooks = []
        for pid in playbook_ids:
            playbook = PlaybookLibrary.get_playbook(pid)
            if playbook:
                playbooks.append(playbook)
        
        # Sort by priority (lower number = higher priority)
        playbooks.sort(key=lambda x: x.get('priority', 999))
        
        # Group by dependency requirements
        for playbook in playbooks:
            # Validate prerequisites
            valid, issues = PlaybookValidator.validate_prerequisites(playbook)
            
            plan.append({
                "playbook_id": playbook['id'],
                "name": playbook['name'],
                "priority": playbook['priority'],
                "can_execute": valid,
                "issues": issues,
                "estimated_duration": PlaybookScheduler._estimate_duration(playbook),
                "requires_confirmation": playbook.get('requires_confirmation', False)
            })
        
        return plan
    
    @staticmethod
    def _estimate_duration(playbook: Dict) -> int:
        """Estimate execution duration in seconds"""
        # Simple estimation based on action count and type
        base_duration = 5
        action_durations = {
            "backup_config": 10,
            "network_isolation": 5,
            "create_backup": 30,
            "scan_threats": 60,
            "capture_filesystem": 20,
            "kill_processes": 10
        }
        
        total = base_duration
        for action in playbook.get('actions', []):
            action_type = action.get('type')
            total += action_durations.get(action_type, 5)
        
        return total