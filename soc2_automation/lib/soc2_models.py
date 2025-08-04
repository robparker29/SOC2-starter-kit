#!/usr/bin/env python3
"""
SOC 2 Common Data Models
Standardized data structures used across all SOC 2 automation scripts
"""

import datetime
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any

@dataclass
class UserAccessRecord:
    """Standardized user access record across all systems"""
    username: str
    email: str
    system: str                                    # 'AWS', 'ActiveDirectory', 'GitHub', etc.
    user_id: str                                   # System-specific user ID
    last_login: Optional[datetime.datetime]
    permissions: List[str]                         # List of permissions/roles
    manager: str
    department: str
    status: str                                    # 'Active', 'Disabled', 'Locked'
    created_date: Optional[datetime.datetime]
    mfa_enabled: bool = False
    risk_score: int = 0
    group_memberships: List[str] = None
    
    def __post_init__(self):
        if self.group_memberships is None:
            self.group_memberships = []

@dataclass
class SystemConfiguration:
    """Standardized system configuration record"""
    system_id: str                                 # Unique identifier
    system_type: str                              # 'aws_security_group', 'linux_server', etc.
    config_name: str                              # Human-readable name
    config_data: Dict[str, Any]                   # Actual configuration data
    collection_date: datetime.datetime
    config_hash: str                              # For integrity checking
    tags: Dict[str, str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = {}

@dataclass
class EvidenceItem:
    """Standard format for collected evidence items"""
    evidence_id: str
    soc2_control: str                             # Primary SOC 2 control this evidence supports
    evidence_type: str                            # Category: 'ACCESS', 'CONFIG', 'MONITORING', etc.
    source_system: str                            # System where evidence was collected
    collection_date: datetime.datetime
    evidence_period: str                          # Time period this evidence covers
    file_path: str                                # Location of collected evidence file
    file_hash: str                                # SHA256 hash for integrity verification
    description: str                              # Human-readable description of evidence
    completeness_status: str                      # 'COMPLETE', 'PARTIAL', 'MISSING'
    validation_notes: str                         # Any issues or observations during collection
    audit_relevance: str                          # How this evidence supports the control

@dataclass
class DriftFinding:
    """Configuration drift detection result"""
    finding_id: str
    system_id: str
    config_name: str
    drift_type: str                               # 'UNAUTHORIZED_CHANGE', 'MISSING_CONFIG', 'NEW_CONFIG'
    severity: str                                 # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    detected_at: datetime.datetime
    baseline_value: str
    current_value: str
    risk_impact: str
    soc2_controls_affected: List[str]
    remediation_action: str
    auto_fixable: bool = False

@dataclass
class AccessReviewFinding:
    """Access review finding result"""
    finding_id: str
    finding_type: str                             # 'INACTIVE_USER', 'EXCESSIVE_PERMISSIONS', etc.
    severity: str                                 # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    user_record: UserAccessRecord
    details: str
    soc2_control: str
    remediation_action: str
    created_date: datetime.datetime
    status: str = 'OPEN'                          # 'OPEN', 'IN_PROGRESS', 'RESOLVED'

# Utility functions for data models
def serialize_dataclass(obj) -> Dict:
    """Convert dataclass to dictionary with datetime handling"""
    def convert_datetime(item):
        if isinstance(item, datetime.datetime):
            return item.isoformat()
        return item
    
    data = asdict(obj)
    # Convert datetime objects to strings
    for key, value in data.items():
        data[key] = convert_datetime(value)
    
    return data

def deserialize_datetime(date_string: str) -> datetime.datetime:
    """Convert ISO datetime string back to datetime object"""
    if isinstance(date_string, str):
        return datetime.datetime.fromisoformat(date_string.replace('Z', '+00:00'))
    return date_string
