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
    config_id: str                                # Unique identifier
    system_name: str                              # Human-readable name
    config_type: str                              # 'SECURITY_GROUP', 'FIREWALL', 'IAM_POLICY', etc.
    config_data: Dict[str, Any]                   # Actual configuration data
    last_updated: datetime.datetime
    compliance_status: str = 'UNKNOWN'            # 'COMPLIANT', 'NON_COMPLIANT', 'UNKNOWN'
    tags: Dict[str, str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = {}

@dataclass
class CloudResource:
    """Multi-cloud resource representation"""
    resource_id: str
    resource_name: str
    resource_type: str                            # 'EC2_INSTANCE', 'AZURE_VM', 'GCP_INSTANCE'
    cloud_provider: str                           # 'AWS', 'AZURE', 'GCP'
    account_id: str                               # Account/Subscription/Project ID
    region: str
    created_date: Optional[datetime.datetime]
    last_modified: Optional[datetime.datetime]
    status: str                                   # 'RUNNING', 'STOPPED', 'TERMINATED', etc.
    configuration: Dict[str, Any]
    tags: Dict[str, str] = None
    compliance_findings: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = {}
        if self.compliance_findings is None:
            self.compliance_findings = []

@dataclass
class MultiCloudIdentity:
    """Enhanced identity record for multi-cloud environments"""
    identity_id: str
    username: str
    email: str
    display_name: str
    cloud_provider: str                           # 'AWS', 'AZURE', 'GCP', 'HYBRID'
    account_id: str
    identity_type: str                            # 'USER', 'SERVICE_ACCOUNT', 'GROUP'
    roles: List[str]
    permissions: List[str]
    last_login: Optional[datetime.datetime]
    mfa_enabled: bool
    created_date: Optional[datetime.datetime]
    status: str                                   # 'ACTIVE', 'INACTIVE', 'DISABLED'
    source_systems: List[str]                     # For federated identities
    risk_indicators: Dict[str, Any] = None
    cloud_specific_data: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.risk_indicators is None:
            self.risk_indicators = {}
        if self.cloud_specific_data is None:
            self.cloud_specific_data = {}

@dataclass 
class NetworkSecurityRule:
    """Multi-cloud network security rule"""
    rule_id: str
    rule_name: str
    cloud_provider: str                           # 'AWS', 'AZURE', 'GCP'
    resource_group: str                           # Security Group/NSG/Firewall name
    direction: str                                # 'INBOUND', 'OUTBOUND'
    protocol: str                                 # 'TCP', 'UDP', 'ICMP', 'ALL'
    source_addresses: List[str]
    destination_addresses: List[str]
    source_ports: List[str]
    destination_ports: List[str]
    action: str                                   # 'ALLOW', 'DENY'
    priority: Optional[int]
    description: str
    created_date: Optional[datetime.datetime]
    last_modified: Optional[datetime.datetime]
    compliance_status: str = 'UNKNOWN'
    risk_level: str = 'UNKNOWN'                   # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    
@dataclass
class CloudAuditLog:
    """Multi-cloud audit log entry"""
    log_id: str
    event_name: str
    cloud_provider: str                           # 'AWS', 'AZURE', 'GCP'
    service_name: str
    event_time: datetime.datetime
    user_identity: str
    user_type: str                                # 'USER', 'SERVICE_ACCOUNT', 'ASSUMED_ROLE'
    source_ip: str
    user_agent: str
    account_id: str
    region: str
    resources_affected: List[str]
    event_outcome: str                            # 'SUCCESS', 'FAILURE', 'PARTIAL'
    error_code: Optional[str]
    event_details: Dict[str, Any]
    security_classification: str = 'INFO'         # 'INFO', 'WARNING', 'ALERT', 'CRITICAL'
    soc2_relevance: List[str] = None              # Related SOC 2 controls
    
    def __post_init__(self):
        if self.soc2_relevance is None:
            self.soc2_relevance = []

@dataclass
class ComplianceFinding:
    """Multi-cloud compliance finding"""
    finding_id: str
    finding_type: str                             # 'ACCESS_CONTROL', 'NETWORK_SECURITY', 'LOGGING', etc.
    severity: str                                 # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    cloud_provider: str                           # 'AWS', 'AZURE', 'GCP', 'MULTI_CLOUD'
    resource_id: str
    resource_type: str
    account_id: str
    region: str
    title: str
    description: str
    evidence: Dict[str, Any]                      # Supporting evidence data
    soc2_controls: List[str]                      # Affected SOC 2 controls
    other_frameworks: List[str] = None            # ISO27001, PCI-DSS, etc.
    remediation_steps: List[str] = None
    auto_remediable: bool = False
    detected_date: datetime.datetime = None
    due_date: Optional[datetime.datetime] = None
    status: str = 'OPEN'                          # 'OPEN', 'IN_PROGRESS', 'RESOLVED', 'ACCEPTED_RISK'
    assigned_to: str = ''
    
    def __post_init__(self):
        if self.other_frameworks is None:
            self.other_frameworks = []
        if self.remediation_steps is None:
            self.remediation_steps = []
        if self.detected_date is None:
            self.detected_date = datetime.datetime.now()

@dataclass
class CrossCloudReport:
    """Report spanning multiple cloud providers"""
    report_id: str
    report_type: str                              # 'ACCESS_REVIEW', 'EVIDENCE_COLLECTION', 'COMPLIANCE_ASSESSMENT'
    report_date: datetime.datetime
    cloud_providers: List[str]                    # Providers included in report
    accounts_covered: Dict[str, List[str]]        # Provider -> list of accounts
    soc2_controls: List[str]                      # Controls assessed
    summary_statistics: Dict[str, Any]
    findings_summary: Dict[str, int]              # Severity -> count
    evidence_items: List[str] = None              # Evidence file paths
    recommendations: List[str] = None
    next_review_date: Optional[datetime.datetime] = None
    
    def __post_init__(self):
        if self.evidence_items is None:
            self.evidence_items = []
        if self.recommendations is None:
            self.recommendations = []

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
