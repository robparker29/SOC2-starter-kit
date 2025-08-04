#!/usr/bin/env python3
"""
SOC 2 Evidence Collection Automation
Maps to SOC 2 Common Criteria: CC1.4, CC2.1, CC3.1, CC6.1, CC6.2, CC6.3, CC6.7, CC6.8, CC7.1, CC7.2

This script automates the collection of audit evidence required for SOC 2 Type II compliance.
It systematically gathers evidence from multiple sources, validates completeness, and organizes 
output in audit-ready formats.

Key Evidence Types Collected:
- Access control evidence (user lists, permissions, reviews)
- System configuration evidence (security settings, baselines)
- Monitoring evidence (logs, alerts, incident reports)
- Change management evidence (tickets, approvals, deployments)
- Security awareness evidence (training records, acknowledgments)
- Vendor management evidence (contracts, assessments, reviews)

Author: Parker Robertson
Purpose: Streamline SOC 2 audit preparation and ongoing evidence collection
"""

import os
import json
import csv
import datetime
import logging
import hashlib
import zipfile
import shutil
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import boto3
import requests
import paramiko
from jira import JIRA
import pandas as pd

# Configure logging for audit trail
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('evidence_collection.log'),
        logging.StreamHandler()
    ]
)

@dataclass
class EvidenceItem:
    """Standard format for collected evidence items"""
    evidence_id: str
    soc2_control: str               # Primary SOC 2 control this evidence supports
    evidence_type: str              # Category: 'ACCESS', 'CONFIG', 'MONITORING', etc.
    source_system: str              # System where evidence was collected
    collection_date: datetime.datetime
    evidence_period: str            # Time period this evidence covers
    file_path: str                  # Location of collected evidence file
    file_hash: str                  # SHA256 hash for integrity verification
    description: str                # Human-readable description of evidence
    completeness_status: str        # 'COMPLETE', 'PARTIAL', 'MISSING'
    validation_notes: str           # Any issues or observations during collection
    audit_relevance: str            # How this evidence supports the control

@dataclass
class EvidenceRequest:
    """Defines what evidence needs to be collected"""
    control_id: str
    evidence_type: str
    source_system: str
    collection_method: str
    file_format: str
    retention_period: int           # Days to retain this evidence
    collection_frequency: str       # 'DAILY', 'WEEKLY', 'MONTHLY', 'QUARTERLY'
    validation_rules: List[str]     # Rules to validate evidence completeness
    
class SOC2EvidenceCollector:
    """Main evidence collection engine for SOC 2 compliance"""
    
    def __init__(self, config_path: str, evidence_requests_path: str):
        """
        Initialize evidence collector with configuration and evidence requirements
        
        Args:
            config_path: Path to system configuration file
            evidence_requests_path: Path to evidence collection requirements
        """
        # Load system configurations
        with open(config_path, 'r') as f:
            self.config = json.load(f)
            
        # Load evidence collection requirements
        with open(evidence_requests_path, 'r') as f:
            requests_data = json.load(f)
            self.evidence_requests = [EvidenceRequest(**req) for req in requests_data]
        
        # Initialize collection tracking
        self.collected_evidence = []
        self.collection_session_id = f"EVIDENCE_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.output_directory = f"evidence_collection_{datetime.datetime.now().strftime('%Y%m%d')}"
        
        # Create output directory structure
        self._setup_output_directories()
        
        # Initialize audit logging
        self.audit_logger = logging.getLogger('evidence_audit')
        
        logging.info(f"Evidence collection session started: {self.collection_session_id}")
    
    def _setup_output_directories(self):
        """Create organized directory structure for evidence collection"""
        base_path = Path(self.output_directory)
        
        # Create main evidence categories
        directories = [
            'access_controls',          # CC6.1, CC6.2, CC6.3 evidence
            'system_configurations',    # CC6.7, CC6.8 evidence  
            'monitoring_logs',          # CC7.1, CC7.2 evidence
            'change_management',        # CC8.1 evidence
            'security_awareness',       # CC2.1 evidence
            'vendor_management',        # CC9.1 evidence
            'risk_assessment',          # CC3.1 evidence
            'incident_response',        # CC7.3 evidence
            'validation_reports',       # Evidence completeness validation
            'audit_trail'               # Collection audit trail
        ]
        
        for directory in directories:
            (base_path / directory).mkdir(parents=True, exist_ok=True)
            
        logging.info(f"Evidence collection directories created: {base_path}")
    
    def collect_access_control_evidence(self) -> List[EvidenceItem]:
        """
        Collect evidence for SOC 2 access control requirements (CC6.1, CC6.2, CC6.3)
        
        Returns:
            List of collected evidence items
        """
        logging.info("🔐 Collecting access control evidence...")
        evidence_items = []
        
        # Evidence 1: Current user access listings from all systems
        user_access_evidence = self._collect_user_access_listings()
        evidence_items.extend(user_access_evidence)
        
        # Evidence 2: Quarterly access reviews documentation
        access_review_evidence = self._collect_access_review_records()
        evidence_items.extend(access_review_evidence)
        
        # Evidence 3: Privileged user monitoring
        privileged_user_evidence = self._collect_privileged_user_activity()
        evidence_items.extend(privileged_user_evidence)
        
        # Evidence 4: Authentication configuration
        auth_config_evidence = self._collect_authentication_configs()
        evidence_items.extend(auth_config_evidence)
        
        logging.info(f"Access control evidence collection complete: {len(evidence_items)} items")
        return evidence_items
    
    def _collect_user_access_listings(self) -> List[EvidenceItem]:
        """Collect comprehensive user access listings from all systems"""
        evidence_items = []
        collection_date = datetime.datetime.now()
        
        # AWS IAM users and roles
        try:
            logging.info("  📊 Collecting AWS IAM user access...")
            aws_evidence = self._collect_aws_user_access()
            if aws_evidence:
                evidence_items.append(EvidenceItem(
                    evidence_id=f"ACC-AWS-{collection_date.strftime('%Y%m%d')}",
                    soc2_control="CC6.1",
                    evidence_type="ACCESS_LISTING",
                    source_system="AWS IAM",
                    collection_date=collection_date,
                    evidence_period=f"{collection_date.strftime('%Y-%m-%d')}",
                    file_path=aws_evidence['file_path'],
                    file_hash=aws_evidence['file_hash'],
                    description="Complete listing of AWS IAM users, roles, and permissions",
                    completeness_status="COMPLETE",
                    validation_notes="Includes all active users with detailed permission analysis",
                    audit_relevance="Demonstrates logical access controls and permission management"
                ))
        except Exception as e:
            logging.error(f"AWS user access collection failed: {str(e)}")
            
        # Active Directory users
        try:
            logging.info("  📊 Collecting Active Directory user access...")
            ad_evidence = self._collect_ad_user_access()
            if ad_evidence:
                evidence_items.append(EvidenceItem(
                    evidence_id=f"ACC-AD-{collection_date.strftime('%Y%m%d')}",
                    soc2_control="CC6.1",
                    evidence_type="ACCESS_LISTING",
                    source_system="Active Directory",
                    collection_date=collection_date,
                    evidence_period=f"{collection_date.strftime('%Y-%m-%d')}",
                    file_path=ad_evidence['file_path'],
                    file_hash=ad_evidence['file_hash'],
                    description="Complete Active Directory user and group membership listing",
                    completeness_status="COMPLETE",
                    validation_notes="Includes all domain users with group memberships and last login",
                    audit_relevance="Demonstrates network access controls and user management"
                ))
        except Exception as e:
            logging.error(f"Active Directory access collection failed: {str(e)}")
            
        # Application-specific access (GitHub, Jira, etc.)
        for app_config in self.config.get('applications', []):
            try:
                logging.info(f"  📊 Collecting {app_config['name']} user access...")
                app_evidence = self._collect_application_access(app_config)
                if app_evidence:
                    evidence_items.append(EvidenceItem(
                        evidence_id=f"ACC-{app_config['name'].upper()}-{collection_date.strftime('%Y%m%d')}",
                        soc2_control="CC6.1",
                        evidence_type="ACCESS_LISTING", 
                        source_system=app_config['name'],
                        collection_date=collection_date,
                        evidence_period=f"{collection_date.strftime('%Y-%m-%d')}",
                        file_path=app_evidence['file_path'],
                        file_hash=app_evidence['file_hash'],
                        description=f"User access listing for {app_config['name']}",
                        completeness_status="COMPLETE",
                        validation_notes=f"All {app_config['name']} users with role assignments",
                        audit_relevance="Demonstrates application access controls"
                    ))
            except Exception as e:
                logging.error(f"{app_config['name']} access collection failed: {str(e)}")
        
        return evidence_items
    
    def _collect_aws_user_access(self) -> Optional[Dict[str, str]]:
        """Collect detailed AWS IAM user access information"""
        iam = boto3.client('iam',
                          aws_access_key_id=self.config['aws']['access_key'],
                          aws_secret_access_key=self.config['aws']['secret_key'])
        
        # Collect comprehensive user data
        user_data = []
        
        # Get all IAM users
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                user_info = {
                    'username': user['UserName'],
                    'user_id': user['UserId'],
                    'created_date': user['CreateDate'].strftime('%Y-%m-%d %H:%M:%S'),
                    'last_used': 'Never',
                    'mfa_enabled': False,
                    'access_keys': [],
                    'attached_policies': [],
                    'group_memberships': [],
                    'inline_policies': []
                }
                
                # Get last access information
                try:
                    access_info = iam.get_access_key_last_used(AccessKeyId=user['AccessKeyId']) 
                    if 'AccessKeyLastUsed' in access_info and 'LastUsedDate' in access_info['AccessKeyLastUsed']:
                        user_info['last_used'] = access_info['AccessKeyLastUsed']['LastUsedDate'].strftime('%Y-%m-%d %H:%M:%S')
                except:
                    pass
                    
                # Get MFA devices
                mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])
                user_info['mfa_enabled'] = len(mfa_devices['MFADevices']) > 0
                
                # Get access keys
                access_keys = iam.list_access_keys(UserName=user['UserName'])
                user_info['access_keys'] = [
                    {
                        'access_key_id': key['AccessKeyId'],
                        'status': key['Status'],
                        'created_date': key['CreateDate'].strftime('%Y-%m-%d')
                    }
                    for key in access_keys['AccessKeyMetadata']
                ]
                
                # Get attached policies
                attached_policies = iam.list_attached_user_policies(UserName=user['UserName'])
                user_info['attached_policies'] = [
                    {
                        'policy_name': policy['PolicyName'],
                        'policy_arn': policy['PolicyArn']
                    }
                    for policy in attached_policies['AttachedPolicies']
                ]
                
                # Get group memberships
                groups = iam.get_groups_for_user(UserName=user['UserName'])
                user_info['group_memberships'] = [group['GroupName'] for group in groups['Groups']]
                
                # Get inline policies
                inline_policies = iam.list_user_policies(UserName=user['UserName'])
                user_info['inline_policies'] = inline_policies['PolicyNames']
                
                user_data.append(user_info)
        
        # Save to CSV file
        output_file = f"{self.output_directory}/access_controls/aws_iam_users_{datetime.datetime.now().strftime('%Y%m%d')}.csv"
        
        # Flatten data for CSV export
        csv_data = []
        for user in user_data:
            csv_data.append({
                'Username': user['username'],
                'User_ID': user['user_id'],
                'Created_Date': user['created_date'],
                'Last_Used': user['last_used'],
                'MFA_Enabled': user['mfa_enabled'],
                'Access_Keys_Count': len(user['access_keys']),
                'Active_Access_Keys': len([k for k in user['access_keys'] if k['status'] == 'Active']),
                'Attached_Policies': '; '.join([p['policy_name'] for p in user['attached_policies']]),
                'Group_Memberships': '; '.join(user['group_memberships']),
                'Inline_Policies': '; '.join(user['inline_policies']),
                'Total_Permissions': len(user['attached_policies']) + len(user['group_memberships']) + len(user['inline_policies'])
            })
        
        # Write CSV file
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            if csv_data:
                fieldnames = csv_data[0].keys()
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(csv_data)
        
        # Calculate file hash for integrity verification
        file_hash = self._calculate_file_hash(output_file)
        
        logging.info(f"  ✅ AWS user access collected: {len(user_data)} users -> {output_file}")
        return {
            'file_path': output_file,
            'file_hash': file_hash,
            'record_count': len(user_data)
        }
    
    def _collect_ad_user_access(self) -> Optional[Dict[str, str]]:
        """Collect Active Directory user access information"""
        import ldap3
        
        # Connect to Active Directory
        server = ldap3.Server(self.config['active_directory']['server'])
        conn = ldap3.Connection(
            server, 
            user=self.config['active_directory']['user'],
            password=self.config['active_directory']['password']
        )
        
        if not conn.bind():
            raise Exception(f"Failed to connect to Active Directory: {conn.last_error}")
        
        # Search for all users
        search_base = self.config['active_directory']['search_base']
        conn.search(
            search_base, 
            '(&(objectClass=person)(!(objectClass=computer)))',
            attributes=['sAMAccountName', 'displayName', 'mail', 'department', 
                       'title', 'manager', 'memberOf', 'lastLogon', 'userAccountControl',
                       'whenCreated', 'pwdLastSet']
        )
        
        user_data = []
        for entry in conn.entries:
            # Parse last logon timestamp
            last_logon = 'Never'
            if hasattr(entry, 'lastLogon') and entry.lastLogon.value:
                # Convert Windows timestamp to readable format
                last_logon = self._parse_windows_timestamp(entry.lastLogon.value)
            
            # Parse account status
            account_disabled = bool(entry.userAccountControl.value & 2) if hasattr(entry, 'userAccountControl') else False
            
            # Parse group memberships
            groups = []
            if hasattr(entry, 'memberOf'):
                groups = [self._extract_cn_from_dn(dn) for dn in entry.memberOf.values]
            
            user_info = {
                'Username': str(entry.sAMAccountName),
                'Display_Name': str(entry.displayName) if hasattr(entry, 'displayName') else '',
                'Email': str(entry.mail) if hasattr(entry, 'mail') else '',
                'Department': str(entry.department) if hasattr(entry, 'department') else '',
                'Title': str(entry.title) if hasattr(entry, 'title') else '',
                'Manager': str(entry.manager) if hasattr(entry, 'manager') else '',
                'Account_Status': 'Disabled' if account_disabled else 'Active',
                'Last_Logon': last_logon,
                'Created_Date': str(entry.whenCreated) if hasattr(entry, 'whenCreated') else '',
                'Group_Count': len(groups),
                'Group_Memberships': '; '.join(groups[:10]),  # Limit to first 10 groups for readability
                'Privileged_Groups': '; '.join([g for g in groups if any(priv in g.lower() for priv in ['admin', 'domain', 'enterprise', 'schema'])])
            }
            user_data.append(user_info)
        
        conn.unbind()
        
        # Save to CSV file
        output_file = f"{self.output_directory}/access_controls/ad_users_{datetime.datetime.now().strftime('%Y%m%d')}.csv"
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            if user_data:
                fieldnames = user_data[0].keys()
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(user_data)
        
        file_hash = self._calculate_file_hash(output_file)
        
        logging.info(f"  ✅ AD user access collected: {len(user_data)} users -> {output_file}")
        return {
            'file_path': output_file,
            'file_hash': file_hash,
            'record_count': len(user_data)
        }
    
    def _collect_application_access(self, app_config: Dict) -> Optional[Dict[str, str]]:
        """Collect user access information from business applications"""
        if app_config['type'] == 'github':
            return self._collect_github_access(app_config)
        elif app_config['type'] == 'jira':
            return self._collect_jira_access(app_config)
        elif app_config['type'] == 'salesforce':
            return self._collect_salesforce_access(app_config)
        else:
            logging.warning(f"Unknown application type: {app_config['type']}")
            return None
    
    def _collect_github_access(self, app_config: Dict) -> Optional[Dict[str, str]]:
        """Collect GitHub organization member access"""
        from github import Github
        
        g = Github(app_config['token'])
        org = g.get_organization(app_config['org_name'])
        
        member_data = []
        
        # Get all organization members
        for member in org.get_members():
            member_info = {
                'Username': member.login,
                'Name': member.name or '',
                'Email': member.email or '',
                'Role': 'Member',  # Default role
                'Public_Repos': member.public_repos,
                'Followers': member.followers,
                'Company': member.company or '',
                'Location': member.location or '',
                'Created_Date': member.created_at.strftime('%Y-%m-%d') if member.created_at else '',
                'Team_Memberships': '',
                'Repository_Access': ''
            }
            
            # Get member role in organization
            try:
                membership = org.get_membership(member)
                member_info['Role'] = membership.role
            except:
                pass
            
            # Get team memberships (limited by API rate limits)
            try:
                teams = list(org.get_teams())[:5]  # Limit to avoid rate limits
                member_teams = []
                for team in teams:
                    if team.has_in_members(member):
                        member_teams.append(team.name)
                member_info['Team_Memberships'] = '; '.join(member_teams)
            except:
                pass
            
            member_data.append(member_info)
        
        # Save to CSV file
        output_file = f"{self.output_directory}/access_controls/github_members_{datetime.datetime.now().strftime('%Y%m%d')}.csv"
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            if member_data:
                fieldnames = member_data[0].keys()
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(member_data)
        
        file_hash = self._calculate_file_hash(output_file)
        
        logging.info(f"  ✅ GitHub access collected: {len(member_data)} members -> {output_file}")
        return {
            'file_path': output_file,
            'file_hash': file_hash,
            'record_count': len(member_data)
        }
    
    def collect_system_configuration_evidence(self) -> List[EvidenceItem]:
        """
        Collect evidence for system configuration controls (CC6.7, CC6.8)
        
        Returns:
            List of collected configuration evidence items
        """
        logging.info("⚙️ Collecting system configuration evidence...")
        evidence_items = []
        
        # Evidence 1: Security group configurations
        security_config_evidence = self._collect_security_configurations()
        evidence_items.extend(security_config_evidence)
        
        # Evidence 2: System hardening evidence
        hardening_evidence = self._collect_system_hardening_evidence()
        evidence_items.extend(hardening_evidence)
        
        # Evidence 3: Network configuration evidence
        network_evidence = self._collect_network_configuration_evidence()
        evidence_items.extend(network_evidence)
        
        logging.info(f"System configuration evidence collection complete: {len(evidence_items)} items")
        return evidence_items
    
    def collect_monitoring_evidence(self) -> List[EvidenceItem]:
        """
        Collect evidence for monitoring and logging controls (CC7.1, CC7.2)
        
        Returns:
            List of collected monitoring evidence items
        """
        logging.info("📊 Collecting monitoring and logging evidence...")
        evidence_items = []
        
        # Evidence 1: Security event logs
        security_logs = self._collect_security_event_logs()
        evidence_items.extend(security_logs)
        
        # Evidence 2: System monitoring configurations
        monitoring_configs = self._collect_monitoring_configurations()
        evidence_items.extend(monitoring_configs)
        
        # Evidence 3: Alert and incident evidence
        incident_evidence = self._collect_incident_response_evidence()
        evidence_items.extend(incident_evidence)
        
        logging.info(f"Monitoring evidence collection complete: {len(evidence_items)} items")
        return evidence_items
    
    def validate_evidence_completeness(self, evidence_items: List[EvidenceItem]) -> Dict[str, Any]:
        """
        Validate that all required evidence has been collected and is complete
        
        Args:
            evidence_items: List of collected evidence items
            
        Returns:
            Validation report with completeness status
        """
        logging.info("🔍 Validating evidence completeness...")
        
        validation_report = {
            'validation_date': datetime.datetime.now().isoformat(),
            'total_evidence_items': len(evidence_items),
            'validation_results': {},
            'missing_evidence': [],
            'incomplete_evidence': [],
            'overall_status': 'COMPLETE'
        }
        
        # Group evidence by SOC 2 control
        evidence_by_control = {}
        for item in evidence_items:
            if item.soc2_control not in evidence_by_control:
                evidence_by_control[item.soc2_control] = []
            evidence_by_control[item.soc2_control].append(item)
        
        # Check each required control has evidence
        required_controls = ['CC6.1', 'CC6.2', 'CC6.3', 'CC6.7', 'CC6.8', 'CC7.1', 'CC7.2']
        
        for control in required_controls:
            control_evidence = evidence_by_control.get(control, [])
            
            validation_results = {
                'evidence_count': len(control_evidence),
                'complete_items': len([e for e in control_evidence if e.completeness_status == 'COMPLETE']),
                'partial_items': len([e for e in control_evidence if e.completeness_status == 'PARTIAL']),
                'missing_items': len([e for e in control_evidence if e.completeness_status == 'MISSING']),
                'status': 'COMPLETE' if len(control_evidence) > 0 and all(e.completeness_status == 'COMPLETE' for e in control_evidence) else 'INCOMPLETE'
            }
            
            validation_report['validation_results'][control] = validation_results
            
            if validation_results['status'] == 'INCOMPLETE':
                validation_report['overall_status'] = 'INCOMPLETE'
                if len(control_evidence) == 0:
                    validation_report['missing_evidence'].append(control)
                else:
                    validation_report['incomplete_evidence'].append(control)
        
        # Validate file integrity
        integrity_issues = []
        for item in evidence_items:
            if os.path.exists(item.file_path):
                current_hash = self._calculate_file_hash(item.file_path)
                if current_hash != item.file_hash:
                    integrity_issues.append({
                        'evidence_id': item.evidence_id,
                        'file_path': item.file_path,
                        'expected_hash': item.file_hash,
                        'current_hash': current_hash
                    })
        
        validation_report['integrity_issues'] = integrity_issues
        
        # Save validation report
        report_file = f"{self.output_directory}/validation_reports/evidence_validation_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(validation_report, f, indent=2)
        
        logging.info(f"Evidence validation complete: {validation_report['overall_status']}")
        return validation_report
    
    def generate_audit_package(self, evidence_items: List[EvidenceItem]) -> str:
        """
        Generate a comprehensive audit package with all collected evidence
        
        Args:
            evidence_items: List of all collected evidence
            
        Returns:
            Path to generated audit package zip file
        """
        logging.info("📦 Generating audit evidence package...")
        
        package_name = f"SOC2_Evidence_Package_{datetime.datetime.now().strftime('%Y%m%d')}.zip"
        package_path = f"{self.output_directory}/{package_name}"
        
        with zipfile.ZipFile(package_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Add all evidence files
            for item in evidence_items:
                if os.path.exists(item.file_path):
                    # Create organized structure in zip
                    arcname = f"{item.evidence_type}/{os.path.basename(item.file_path)}"
                    zipf.write(item.file_path, arcname)
            
            # Add evidence inventory
            inventory_data = [asdict(item) for item in evidence_items]
            inventory_file = f"{self.output_directory}/evidence_inventory.json"
            with open(inventory_file, 'w') as f:
                json.dump(inventory_data, f, indent=2, default=str)
            zipf.write(inventory_file, "evidence_inventory.json")
            
            # Add collection audit trail
            zipf.write("evidence_collection.log", "audit_trail/evidence_collection.log")
        
        logging.info(f"Audit package generated: {package_path}")
        return package_path
    
    def run_full_evidence_collection(self) -> Dict[str, Any]:
        """
        Execute complete evidence collection process for SOC 2 compliance
        
        Returns:
            Summary of collection results
        """
        logging.info("🚀 Starting SOC 2 evidence collection...")
        
        all_evidence = []
        
        try:
            # Collect all evidence types
            all_evidence.extend(self.collect_access_control_evidence())
            all_evidence.extend(self.collect_system_configuration_evidence())
            all_evidence.extend(self.collect_monitoring_evidence())
            
            # Validate completeness
            validation_report = self.validate_evidence_completeness(all_evidence)
            
            # Generate audit package
            package_path = self.generate_audit_package(all_evidence)
            
            # Generate summary report
            summary = {
                'collection_session_id': self.collection_session_id,
                'collection_date': datetime.datetime.now().isoformat(),
                'total_evidence_items': len(all_evidence),
                'evidence_by_control': {},
                'validation_status': validation_report['overall_status'],
                'audit_package_path': package_path,
                'collection_duration': 'calculated_at_runtime'
            }
            
            # Group evidence by control for summary
            for item in all_evidence:
                if item.soc2_control not in summary['evidence_by_control']:
                    summary['evidence_by_control'][item.soc2_control] = 0
                summary['evidence_by_control'][item.soc2_control] += 1
            
            logging.info(f"✅ Evidence collection complete: {len(all_evidence)} items collected")
            return summary
            
        except Exception as e:
            logging.error(f"Evidence collection failed: {str(e)}")
            raise
    
    # Helper methods for evidence collection
    def _collect_access_review_records(self) -> List[EvidenceItem]:
        """Collect quarterly access review documentation from ticketing system"""
        evidence_items = []
        
        try:
            # Connect to Jira to get access review tickets
            jira = JIRA(
                server=self.config['jira']['server'],
                basic_auth=(self.config['jira']['username'], self.config['jira']['api_token'])
            )
            
            # Search for access review tickets in the last quarter
            quarter_start = datetime.datetime.now() - datetime.timedelta(days=90)
            jql = f'project = "{self.config["jira"]["project_key"]}" AND labels = "access-review" AND created >= "{quarter_start.strftime("%Y-%m-%d")}"'
            
            issues = jira.search_issues(jql, maxResults=1000)
            
            # Compile access review data
            review_data = []
            for issue in issues:
                review_info = {
                    'Ticket_ID': issue.key,
                    'Summary': issue.fields.summary,
                    'Status': issue.fields.status.name,
                    'Created_Date': str(issue.fields.created),
                    'Assignee': str(issue.fields.assignee) if issue.fields.assignee else 'Unassigned',
                    'Reporter': str(issue.fields.reporter),
                    'Labels': ', '.join(issue.fields.labels),
                    'Resolution': str(issue.fields.resolution) if issue.fields.resolution else 'Unresolved',
                    'Description': str(issue.fields.description)[:500] if issue.fields.description else ''
                }
                review_data.append(review_info)
            
            # Save access review evidence
            output_file = f"{self.output_directory}/access_controls/access_reviews_{datetime.datetime.now().strftime('%Y%m%d')}.csv"
            
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                if review_data:
                    fieldnames = review_data[0].keys()
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(review_data)
            
            file_hash = self._calculate_file_hash(output_file)
            
            evidence_items.append(EvidenceItem(
                evidence_id=f"ACC-REV-{datetime.datetime.now().strftime('%Y%m%d')}",
                soc2_control="CC6.3",
                evidence_type="ACCESS_REVIEW",
                source_system="Jira",
                collection_date=datetime.datetime.now(),
                evidence_period=f"Q{((datetime.datetime.now().month-1)//3)+1} {datetime.datetime.now().year}",
                file_path=output_file,
                file_hash=file_hash,
                description="Quarterly access review tickets and completion status",
                completeness_status="COMPLETE" if len(review_data) > 0 else "MISSING",
                validation_notes=f"Found {len(review_data)} access review tickets",
                audit_relevance="Demonstrates periodic access review process and remediation"
            ))
            
            logging.info(f"  ✅ Access review evidence collected: {len(review_data)} reviews")
            
        except Exception as e:
            logging.error(f"Access review collection failed: {str(e)}")
            
        return evidence_items
    
    def _collect_privileged_user_activity(self) -> List[EvidenceItem]:
        """Collect evidence of privileged user monitoring and activity logs"""
        evidence_items = []
        
        try:
            # Collect AWS CloudTrail logs for privileged actions
            cloudtrail = boto3.client('cloudtrail',
                                    aws_access_key_id=self.config['aws']['access_key'],
                                    aws_secret_access_key=self.config['aws']['secret_key'])
            
            # Look for privileged actions in the last 30 days
            end_time = datetime.datetime.now()
            start_time = end_time - datetime.timedelta(days=30)
            
            # Get events for privileged operations
            privileged_events = []
            event_names = [
                'CreateUser', 'DeleteUser', 'AttachUserPolicy', 'DetachUserPolicy',
                'CreateRole', 'DeleteRole', 'PutUserPolicy', 'DeleteUserPolicy',
                'CreateAccessKey', 'DeleteAccessKey', 'CreateGroup', 'DeleteGroup'
            ]
            
            for event_name in event_names:
                response = cloudtrail.lookup_events(
                    LookupAttributes=[
                        {
                            'AttributeKey': 'EventName',
                            'AttributeValue': event_name
                        }
                    ],
                    StartTime=start_time,
                    EndTime=end_time
                )
                
                for event in response.get('Events', []):
                    event_info = {
                        'Event_Time': event['EventTime'].strftime('%Y-%m-%d %H:%M:%S'),
                        'Event_Name': event['EventName'],
                        'User_Name': event.get('Username', 'Unknown'),
                        'Source_IP': event.get('SourceIPAddress', 'Unknown'),
                        'User_Agent': event.get('UserAgent', 'Unknown'),
                        'AWS_Region': event.get('AwsRegion', 'Unknown'),
                        'Event_Source': event.get('EventSource', 'Unknown'),
                        'Resources': '; '.join([r.get('ResourceName', 'Unknown') for r in event.get('Resources', [])])
                    }
                    privileged_events.append(event_info)
            
            # Save privileged activity evidence
            output_file = f"{self.output_directory}/access_controls/privileged_activity_{datetime.datetime.now().strftime('%Y%m%d')}.csv"
            
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                if privileged_events:
                    fieldnames = privileged_events[0].keys()
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(privileged_events)
            
            file_hash = self._calculate_file_hash(output_file)
            
            evidence_items.append(EvidenceItem(
                evidence_id=f"PRIV-ACT-{datetime.datetime.now().strftime('%Y%m%d')}",
                soc2_control="CC6.2",
                evidence_type="PRIVILEGED_MONITORING",
                source_system="AWS CloudTrail",
                collection_date=datetime.datetime.now(),
                evidence_period="Last 30 days",
                file_path=output_file,
                file_hash=file_hash,
                description="Privileged user activity monitoring from AWS CloudTrail",
                completeness_status="COMPLETE",
                validation_notes=f"Captured {len(privileged_events)} privileged operations",
                audit_relevance="Demonstrates monitoring of privileged access and administrative activities"
            ))
            
            logging.info(f"  ✅ Privileged activity evidence collected: {len(privileged_events)} events")
            
        except Exception as e:
            logging.error(f"Privileged activity collection failed: {str(e)}")
            
        return evidence_items
    
    def _collect_authentication_configs(self) -> List[EvidenceItem]:
        """Collect authentication configuration evidence"""
        evidence_items = []
        
        # Collect MFA configuration evidence from AWS
        try:
            iam = boto3.client('iam',
                              aws_access_key_id=self.config['aws']['access_key'],
                              aws_secret_access_key=self.config['aws']['secret_key'])
            
            # Get account password policy
            try:
                password_policy = iam.get_account_password_policy()
                policy_info = password_policy['PasswordPolicy']
            except:
                policy_info = {'Error': 'No password policy configured'}
            
            # Get MFA devices for all users
            mfa_data = []
            paginator = iam.get_paginator('list_users')
            
            for page in paginator.paginate():
                for user in page['Users']:
                    mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])
                    
                    user_mfa_info = {
                        'Username': user['UserName'],
                        'MFA_Devices_Count': len(mfa_devices['MFADevices']),
                        'MFA_Enabled': len(mfa_devices['MFADevices']) > 0,
                        'MFA_Device_Types': '; '.join([d['SerialNumber'].split('/')[-1] for d in mfa_devices['MFADevices']]),
                        'Virtual_MFA': any('mfa' in d['SerialNumber'].lower() for d in mfa_devices['MFADevices']),
                        'Hardware_MFA': any('mfa' not in d['SerialNumber'].lower() for d in mfa_devices['MFADevices'])
                    }
                    mfa_data.append(user_mfa_info)
            
            # Save authentication configuration evidence
            config_file = f"{self.output_directory}/access_controls/auth_config_{datetime.datetime.now().strftime('%Y%m%d')}.json"
            
            auth_config = {
                'collection_date': datetime.datetime.now().isoformat(),
                'aws_password_policy': policy_info,
                'mfa_statistics': {
                    'total_users': len(mfa_data),
                    'users_with_mfa': len([u for u in mfa_data if u['MFA_Enabled']]),
                    'mfa_adoption_rate': len([u for u in mfa_data if u['MFA_Enabled']]) / len(mfa_data) * 100 if mfa_data else 0
                },
                'user_mfa_details': mfa_data
            }
            
            with open(config_file, 'w') as f:
                json.dump(auth_config, f, indent=2)
            
            file_hash = self._calculate_file_hash(config_file)
            
            evidence_items.append(EvidenceItem(
                evidence_id=f"AUTH-CFG-{datetime.datetime.now().strftime('%Y%m%d')}",
                soc2_control="CC6.1",
                evidence_type="AUTHENTICATION_CONFIG",
                source_system="AWS IAM",
                collection_date=datetime.datetime.now(),
                evidence_period=datetime.datetime.now().strftime('%Y-%m-%d'),
                file_path=config_file,
                file_hash=file_hash,
                description="Authentication configuration including password policy and MFA settings",
                completeness_status="COMPLETE",
                validation_notes=f"MFA adoption rate: {auth_config['mfa_statistics']['mfa_adoption_rate']:.1f}%",
                audit_relevance="Demonstrates strong authentication controls and MFA implementation"
            ))
            
            logging.info(f"  ✅ Authentication config collected: {len(mfa_data)} users analyzed")
            
        except Exception as e:
            logging.error(f"Authentication config collection failed: {str(e)}")
            
        return evidence_items
    
    def _collect_security_configurations(self) -> List[EvidenceItem]:
        """Collect security configuration evidence from various systems"""
        evidence_items = []
        
        # AWS Security Group configurations
        try:
            ec2 = boto3.client('ec2',
                              aws_access_key_id=self.config['aws']['access_key'],
                              aws_secret_access_key=self.config['aws']['secret_key'])
            
            # Get all security groups
            response = ec2.describe_security_groups()
            
            sg_data = []
            for sg in response['SecurityGroups']:
                sg_info = {
                    'Group_ID': sg['GroupId'],
                    'Group_Name': sg['GroupName'],
                    'Description': sg['Description'],
                    'VPC_ID': sg.get('VpcId', 'EC2-Classic'),
                    'Inbound_Rules_Count': len(sg['IpPermissions']),
                    'Outbound_Rules_Count': len(sg['IpPermissionsEgress']),
                    'Open_To_Internet': any('0.0.0.0/0' in str(rule) for rule in sg['IpPermissions']),
                    'SSH_Access': any('22' in str(rule) for rule in sg['IpPermissions']),
                    'RDP_Access': any('3389' in str(rule) for rule in sg['IpPermissions']),
                    'Tags': '; '.join([f"{tag['Key']}={tag['Value']}" for tag in sg.get('Tags', [])])
                }
                sg_data.append(sg_info)
            
            # Save security group configuration
            output_file = f"{self.output_directory}/system_configurations/aws_security_groups_{datetime.datetime.now().strftime('%Y%m%d')}.csv"
            
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                if sg_data:
                    fieldnames = sg_data[0].keys()
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(sg_data)
            
            file_hash = self._calculate_file_hash(output_file)
            
            evidence_items.append(EvidenceItem(
                evidence_id=f"SEC-CFG-AWS-{datetime.datetime.now().strftime('%Y%m%d')}",
                soc2_control="CC6.7",
                evidence_type="SECURITY_CONFIG",
                source_system="AWS EC2",
                collection_date=datetime.datetime.now(),
                evidence_period=datetime.datetime.now().strftime('%Y-%m-%d'),
                file_path=output_file,
                file_hash=file_hash,
                description="AWS Security Group configurations and network access controls",
                completeness_status="COMPLETE",
                validation_notes=f"Analyzed {len(sg_data)} security groups",
                audit_relevance="Demonstrates network-level access controls and segmentation"
            ))
            
            logging.info(f"  ✅ AWS security config collected: {len(sg_data)} security groups")
            
        except Exception as e:
            logging.error(f"AWS security config collection failed: {str(e)}")
            
        return evidence_items
    
    def _collect_system_hardening_evidence(self) -> List[EvidenceItem]:
        """Collect system hardening configuration evidence"""
        evidence_items = []
        
        # Collect hardening evidence from Linux servers
        for server_config in self.config.get('linux_servers', []):
            try:
                # SSH connection to server
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(
                    hostname=server_config['hostname'],
                    username=server_config['username'],
                    key_filename=server_config.get('key_file'),
                    password=server_config.get('password')
                )
                
                # Collect hardening configurations
                hardening_checks = {
                    'SSH_Config': 'sudo cat /etc/ssh/sshd_config | grep -E "(PermitRootLogin|PasswordAuthentication|Protocol|MaxAuthTries)"',
                    'Firewall_Status': 'sudo systemctl status iptables || sudo systemctl status ufw',
                    'User_Accounts': 'cat /etc/passwd | grep -E "(sh|bash)$" | wc -l',
                    'Sudo_Config': 'sudo cat /etc/sudoers | grep -v "^#" | grep -v "^$"',
                    'Service_Status': 'sudo systemctl list-units --type=service --state=running | grep -E "(ssh|http|ftp|telnet)"',
                    'File_Permissions': 'ls -la /etc/passwd /etc/shadow /etc/group',
                    'Kernel_Version': 'uname -r',
                    'Package_Updates': 'sudo apt list --upgradable 2>/dev/null | wc -l || sudo yum check-update 2>/dev/null | wc -l'
                }
                
                hardening_results = {}
                for check_name, command in hardening_checks.items():
                    try:
                        stdin, stdout, stderr = ssh.exec_command(command)
                        output = stdout.read().decode().strip()
                        hardening_results[check_name] = output
                    except Exception as e:
                        hardening_results[check_name] = f"Error: {str(e)}"
                
                ssh.close()
                
                # Save hardening evidence
                output_file = f"{self.output_directory}/system_configurations/hardening_{server_config['hostname']}_{datetime.datetime.now().strftime('%Y%m%d')}.json"
                
                hardening_data = {
                    'server': server_config['hostname'],
                    'collection_date': datetime.datetime.now().isoformat(),
                    'hardening_checks': hardening_results
                }
                
                with open(output_file, 'w') as f:
                    json.dump(hardening_data, f, indent=2)
                
                file_hash = self._calculate_file_hash(output_file)
                
                evidence_items.append(EvidenceItem(
                    evidence_id=f"HARD-{server_config['hostname'].replace('.', '-')}-{datetime.datetime.now().strftime('%Y%m%d')}",
                    soc2_control="CC6.8",
                    evidence_type="SYSTEM_HARDENING",
                    source_system=server_config['hostname'],
                    collection_date=datetime.datetime.now(),
                    evidence_period=datetime.datetime.now().strftime('%Y-%m-%d'),
                    file_path=output_file,
                    file_hash=file_hash,
                    description=f"System hardening configuration for {server_config['hostname']}",
                    completeness_status="COMPLETE",
                    validation_notes="Captured key security configurations and hardening status",
                    audit_relevance="Demonstrates system-level security controls and hardening practices"
                ))
                
                logging.info(f"  ✅ Hardening evidence collected: {server_config['hostname']}")
                
            except Exception as e:
                logging.error(f"Hardening evidence collection failed for {server_config['hostname']}: {str(e)}")
        
        return evidence_items
    
    def _collect_network_configuration_evidence(self) -> List[EvidenceItem]:
        """Collect network configuration evidence"""
        # This would collect firewall rules, VPN configurations, etc.
        # Implementation similar to other collection methods
        return []
    
    def _collect_security_event_logs(self) -> List[EvidenceItem]:
        """Collect security event logs for monitoring evidence"""
        evidence_items = []
        
        # Collect AWS CloudTrail security events
        try:
            cloudtrail = boto3.client('cloudtrail',
                                    aws_access_key_id=self.config['aws']['access_key'],
                                    aws_secret_access_key=self.config['aws']['secret_key'])
            
            # Get security-relevant events from the last 7 days
            end_time = datetime.datetime.now()
            start_time = end_time - datetime.timedelta(days=7)
            
            # Security event types to collect
            security_events = [
                'ConsoleLogin', 'AssumeRole', 'CreateUser', 'DeleteUser',
                'CreateAccessKey', 'DeleteAccessKey', 'PutBucketPolicy'
            ]
            
            all_events = []
            for event_name in security_events:
                try:
                    response = cloudtrail.lookup_events(
                        LookupAttributes=[{
                            'AttributeKey': 'EventName',
                            'AttributeValue': event_name
                        }],
                        StartTime=start_time,
                        EndTime=end_time
                    )
                    
                    for event in response.get('Events', []):
                        event_data = {
                            'Event_Time': event['EventTime'].strftime('%Y-%m-%d %H:%M:%S'),
                            'Event_Name': event['EventName'],
                            'User_Name': event.get('Username', 'Unknown'),
                            'Source_IP': event.get('SourceIPAddress', 'Unknown'),
                            'User_Agent': event.get('UserAgent', 'Unknown'),
                            'AWS_Region': event.get('AwsRegion', 'Unknown'),
                            'Event_Source': event.get('EventSource', 'Unknown'),
                            'Error_Code': event.get('ErrorCode', ''),
                            'Error_Message': event.get('ErrorMessage', '')
                        }
                        all_events.append(event_data)
                        
                except Exception as e:
                    logging.warning(f"Could not collect {event_name} events: {str(e)}")
            
            if all_events:
                # Save security events
                output_file = f"{self.output_directory}/monitoring_logs/security_events_{datetime.datetime.now().strftime('%Y%m%d')}.csv"
                
                with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                    fieldnames = all_events[0].keys()
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(all_events)
                
                file_hash = self._calculate_file_hash(output_file)
                
                evidence_items.append(EvidenceItem(
                    evidence_id=f"SEC-LOG-{datetime.datetime.now().strftime('%Y%m%d')}",
                    soc2_control="CC7.2",
                    evidence_type="SECURITY_LOGS",
                    source_system="AWS CloudTrail",
                    collection_date=datetime.datetime.now(),
                    evidence_period="Last 7 days",
                    file_path=output_file,
                    file_hash=file_hash,
                    description="Security event logs from AWS CloudTrail",
                    completeness_status="COMPLETE",
                    validation_notes=f"Collected {len(all_events)} security events",
                    audit_relevance="Demonstrates security event logging and monitoring capabilities"
                ))
                
                logging.info(f"  ✅ Security logs collected: {len(all_events)} events")
            
        except Exception as e:
            logging.error(f"Security logs collection failed: {str(e)}")
        
        return evidence_items
    
    def _collect_monitoring_configurations(self) -> List[EvidenceItem]:
        """Collect monitoring system configurations"""
        # Implementation for monitoring configs (CloudWatch, Splunk, etc.)
        return []
    
    def _collect_incident_response_evidence(self) -> List[EvidenceItem]:
        """Collect incident response and alert evidence"""
        # Implementation for incident response evidence
        return []
    
    # Utility helper methods
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file for integrity verification"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def _parse_windows_timestamp(self, timestamp: int) -> str:
        """Convert Windows FILETIME timestamp to readable format"""
        try:
            # Windows FILETIME epoch starts at 1601-01-01
            epoch = datetime.datetime(1601, 1, 1)
            readable_time = epoch + datetime.timedelta(microseconds=timestamp/10)
            return readable_time.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return 'Invalid timestamp'
    
    def _extract_cn_from_dn(self, dn: str) -> str:
        """Extract Common Name from Distinguished Name"""
        try:
            # Extract CN= part from DN string
            cn_part = [part for part in dn.split(',') if part.strip().startswith('CN=')]
            if cn_part:
                return cn_part[0].replace('CN=', '').strip()
            return dn
        except:
            return dn

if __name__ == "__main__":
    # Example usage
    collector = SOC2EvidenceCollector(
        config_path='config/systems_config.json',
        evidence_requests_path='config/evidence_requests.json'
    )
    
    # Run full evidence collection
    results = collector.run_full_evidence_collection()
    
    print(f"\n🎯 Evidence Collection Summary:")
    print(f"   Session ID: {results['collection_session_id']}")
    print(f"   Total Evidence Items: {results['total_evidence_items']}")
    print(f"   Validation Status: {results['validation_status']}")
    print(f"   Audit Package: {results['audit_package_path']}")
    
    print(f"\n📊 Evidence by SOC 2 Control:")
    for control, count in results['evidence_by_control'].items():
        print(f"   {control}: {count} items")
