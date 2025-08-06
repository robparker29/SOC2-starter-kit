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

@dataclass
class DatabaseSecurityEvidence:
    """Database security evidence for SOC 2 compliance"""
    database_id: str
    database_name: str
    database_type: str                            # 'PostgreSQL', 'MySQL', 'MongoDB', 'RDS', 'Azure SQL', etc.
    cloud_provider: Optional[str]                 # 'AWS', 'AZURE', 'GCP' for cloud databases, None for on-premise
    host_location: str
    encryption_at_rest: bool
    encryption_in_transit: bool
    encryption_key_management: str                # How encryption keys are managed
    audit_logging_enabled: bool
    audit_log_location: str
    backup_encryption: bool
    access_control_method: str                    # 'RBAC', 'IAM', 'Native', etc.
    user_privileges: List[Dict[str, Any]]         # List of user privilege information
    network_isolation: bool
    ssl_tls_enforced: bool
    password_policy_enforced: bool
    multi_factor_auth_required: bool
    compliance_findings: List[str]
    soc2_controls: List[str]                      # ['CC6.1', 'CC6.2', 'CC6.7']
    evidence_date: datetime.datetime
    evidence_source: str                          # 'CONFIG_FILE', 'AUDIT_LOG', 'CLOUD_API'
    
    def __post_init__(self):
        if self.user_privileges is None:
            self.user_privileges = []
        if self.compliance_findings is None:
            self.compliance_findings = []
        if self.soc2_controls is None:
            self.soc2_controls = []

@dataclass
class NetworkSecurityEvidence:
    """Network security configuration evidence"""
    rule_id: str
    rule_name: str
    resource_id: str                              # Security group, firewall, NSG ID
    cloud_provider: str                           # 'AWS', 'AZURE', 'GCP'
    account_id: str
    region: str
    rule_type: str                                # 'SECURITY_GROUP', 'FIREWALL', 'NSG', 'NACL'
    direction: str                                # 'INBOUND', 'OUTBOUND'
    protocol: str                                 # 'TCP', 'UDP', 'ICMP', 'ALL'
    port_range: str                               # '80', '443', '22-80', 'ALL'
    source: str                                   # IP ranges, security group IDs, etc.
    destination: str
    action: str                                   # 'ALLOW', 'DENY'
    priority: Optional[int]
    description: str
    network_segmentation_purpose: str            # Purpose of this rule for network segmentation
    compliance_risk_level: str                   # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    soc2_controls: List[str]                      # ['CC6.7', 'CC7.1']
    created_date: Optional[datetime.datetime]
    last_modified: Optional[datetime.datetime]
    evidence_date: datetime.datetime
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
        if self.soc2_controls is None:
            self.soc2_controls = []

@dataclass
class VendorAccessEvidence:
    """Third-party and vendor access evidence"""
    vendor_id: str
    vendor_name: str
    integration_type: str                         # 'API', 'SSO', 'VPN', 'DIRECT_ACCESS', 'SERVICE_ACCOUNT'
    access_method: str                            # How vendor accesses systems
    access_scope: List[str]                       # Systems/data they can access
    access_permissions: List[str]                 # Specific permissions granted
    authentication_method: str                    # 'API_KEY', 'OAUTH', 'SAML', 'USERNAME_PASSWORD'
    multi_factor_auth_required: bool
    access_logging_enabled: bool
    access_log_location: str
    data_access_agreement: bool                   # Whether DPA/BAA is in place
    security_assessment_date: Optional[datetime.datetime]
    access_review_frequency: str                  # 'MONTHLY', 'QUARTERLY', 'ANNUALLY'
    last_access_review: Optional[datetime.datetime]
    access_expiration_date: Optional[datetime.datetime]
    emergency_access_procedure: bool              # Whether emergency access procedures exist
    compliance_status: str                        # 'COMPLIANT', 'NON_COMPLIANT', 'NEEDS_REVIEW'
    risk_level: str                               # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    findings: List[str]                           # Compliance issues found
    soc2_controls: List[str]                      # ['CC9.1', 'CC9.2']
    evidence_date: datetime.datetime
    next_review_due: Optional[datetime.datetime]
    
    def __post_init__(self):
        if self.access_scope is None:
            self.access_scope = []
        if self.access_permissions is None:
            self.access_permissions = []
        if self.findings is None:
            self.findings = []
        if self.soc2_controls is None:
            self.soc2_controls = []

@dataclass
class ConsolidatedEvidenceReport:
    """Master evidence report combining all collection results"""
    report_id: str
    report_date: datetime.datetime
    reporting_period_start: datetime.datetime
    reporting_period_end: datetime.datetime
    organization_name: str
    environment: str                              # 'PRODUCTION', 'STAGING', 'DEVELOPMENT'
    evidence_summary: Dict[str, int]              # Count of evidence items by type
    database_evidence: List[DatabaseSecurityEvidence]
    network_evidence: List[NetworkSecurityEvidence]
    vendor_evidence: List[VendorAccessEvidence]
    soc2_control_coverage: Dict[str, List[str]]   # Control -> evidence types mapping
    compliance_gaps: List[str]                    # Areas needing attention
    recommendations: List[str]                    # Recommended actions
    evidence_collection_status: Dict[str, str]    # Status of each collection type
    total_evidence_items: int
    report_completeness: str                      # 'COMPLETE', 'PARTIAL', 'INCOMPLETE'
    
    def __post_init__(self):
        if self.database_evidence is None:
            self.database_evidence = []
        if self.network_evidence is None:
            self.network_evidence = []
        if self.vendor_evidence is None:
            self.vendor_evidence = []
        if self.evidence_summary is None:
            self.evidence_summary = {}
        if self.soc2_control_coverage is None:
            self.soc2_control_coverage = {}
        if self.compliance_gaps is None:
            self.compliance_gaps = []
        if self.recommendations is None:
            self.recommendations = []
        if self.evidence_collection_status is None:
            self.evidence_collection_status = {}

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

@dataclass
class ChangeManagementEvidence:
    """Change management evidence for SOC 2 compliance"""
    change_id: str
    change_title: str
    change_type: str                              # 'CODE', 'INFRASTRUCTURE', 'CONFIGURATION', 'SECURITY'
    change_category: str                          # 'EMERGENCY', 'STANDARD', 'PRE_APPROVED'
    requester: str
    approver: str
    implementation_date: datetime.datetime
    change_description: str
    business_justification: str
    risk_assessment: str                          # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    rollback_plan: bool
    testing_evidence: List[str]                   # Links to test results
    approval_workflow: List[Dict[str, Any]]       # Approval chain with timestamps
    deployment_method: str                        # 'AUTOMATED', 'MANUAL', 'HYBRID'
    environment_target: str                       # 'PRODUCTION', 'STAGING', 'DEVELOPMENT'
    systems_affected: List[str]
    downtime_required: bool
    scheduled_downtime_duration: Optional[str]
    success_criteria: List[str]
    post_implementation_review: bool
    change_status: str                            # 'PENDING', 'APPROVED', 'IMPLEMENTED', 'FAILED', 'ROLLED_BACK'
    compliance_findings: List[str]
    soc2_controls: List[str]                      # ['CC8.1']
    evidence_date: datetime.datetime
    evidence_source: str                          # 'CHANGE_MGMT_SYSTEM', 'TICKETING_SYSTEM', 'VERSION_CONTROL'
    
    def __post_init__(self):
        if self.testing_evidence is None:
            self.testing_evidence = []
        if self.approval_workflow is None:
            self.approval_workflow = []
        if self.systems_affected is None:
            self.systems_affected = []
        if self.success_criteria is None:
            self.success_criteria = []
        if self.compliance_findings is None:
            self.compliance_findings = []
        if self.soc2_controls is None:
            self.soc2_controls = []

@dataclass
class IncidentResponseEvidence:
    """Security incident response evidence for SOC 2 compliance"""
    incident_id: str
    incident_title: str
    incident_type: str                            # 'SECURITY_BREACH', 'DATA_BREACH', 'SYSTEM_OUTAGE', 'MALWARE'
    severity_level: str                           # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    detection_date: datetime.datetime
    detection_method: str                         # 'AUTOMATED_ALERT', 'USER_REPORT', 'AUDIT_FINDING'
    initial_responder: str
    incident_commander: str
    affected_systems: List[str]
    affected_data_types: List[str]                # 'CUSTOMER_DATA', 'EMPLOYEE_DATA', 'FINANCIAL_DATA'
    potential_impact: str
    containment_actions: List[Dict[str, Any]]     # Actions taken with timestamps
    eradication_actions: List[Dict[str, Any]]
    recovery_actions: List[Dict[str, Any]]
    communication_log: List[Dict[str, Any]]       # Internal and external communications
    regulatory_notifications: List[Dict[str, Any]] # Breach notifications to authorities
    customer_notifications: bool
    incident_status: str                          # 'OPEN', 'CONTAINED', 'ERADICATED', 'RECOVERED', 'CLOSED'
    resolution_date: Optional[datetime.datetime]
    total_resolution_time: Optional[str]          # Duration from detection to resolution
    root_cause_analysis: str
    lessons_learned: List[str]
    preventive_measures: List[str]
    compliance_findings: List[str]
    soc2_controls: List[str]                      # ['CC7.3', 'CC7.4', 'CC7.5']
    evidence_date: datetime.datetime
    evidence_source: str                          # 'INCIDENT_MGMT_SYSTEM', 'SIEM', 'SECURITY_LOGS'
    
    def __post_init__(self):
        if self.affected_systems is None:
            self.affected_systems = []
        if self.affected_data_types is None:
            self.affected_data_types = []
        if self.containment_actions is None:
            self.containment_actions = []
        if self.eradication_actions is None:
            self.eradication_actions = []
        if self.recovery_actions is None:
            self.recovery_actions = []
        if self.communication_log is None:
            self.communication_log = []
        if self.regulatory_notifications is None:
            self.regulatory_notifications = []
        if self.lessons_learned is None:
            self.lessons_learned = []
        if self.preventive_measures is None:
            self.preventive_measures = []
        if self.compliance_findings is None:
            self.compliance_findings = []
        if self.soc2_controls is None:
            self.soc2_controls = []

def deserialize_datetime(date_string: str) -> datetime.datetime:
    """Convert ISO datetime string back to datetime object"""
    if isinstance(date_string, str):
        return datetime.datetime.fromisoformat(date_string.replace('Z', '+00:00'))
    return date_string
