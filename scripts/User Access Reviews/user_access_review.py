#!/usr/bin/env python3
"""
SOC 2 User Access Review Automation
Maps to SOC 2 Common Criteria: CC6.1, CC6.2, CC6.3

This script automates quarterly user access reviews by:
1. Pulling user data from multiple systems (AD, AWS, GitHub, etc.)
2. Identifying inactive users, orphaned accounts, and excessive permissions
3. Generating audit-ready reports with remediation recommendations
4. Creating Jira tickets for access cleanup

Author: Parker Robertson
Purpose: Demonstrate automated compliance controls for SOC 2 audit readiness
"""

import json
import csv
import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
import boto3
import requests
from github import Github
import ldap3

@dataclass
class UserAccessRecord:
    """Standard format for user access across all systems"""
    username: str
    email: str
    system: str
    last_login: Optional[datetime.datetime]
    permissions: List[str]
    manager: str
    department: str
    status: str
    risk_score: int = 0
    
class AccessReviewEngine:
    def __init__(self, config_path: str):
        """Initialize with configuration for all integrated systems"""
        with open(config_path, 'r') as f:
            self.config = json.load(f)
        
        self.findings = []
        self.users_data = []
        
    def collect_ad_users(self) -> List[UserAccessRecord]:
        """Pull users from Active Directory"""
        print("🔍 Collecting Active Directory users...")
        
        # Connect to AD (simplified example)
        server = ldap3.Server(self.config['ad']['server'])
        conn = ldap3.Connection(server, self.config['ad']['user'], self.config['ad']['password'])
        
        users = []
        # Search for all users in the domain
        conn.search('dc=company,dc=com', '(objectClass=person)', attributes=['*'])
        
        for entry in conn.entries:
            last_login = self._parse_ad_timestamp(entry.lastLogon.value) if hasattr(entry, 'lastLogon') else None
            
            user = UserAccessRecord(
                username=str(entry.sAMAccountName),
                email=str(entry.mail) if hasattr(entry, 'mail') else '',
                system='Active Directory',
                last_login=last_login,
                permissions=self._extract_ad_groups(entry),
                manager=str(entry.manager) if hasattr(entry, 'manager') else 'Unknown',
                department=str(entry.department) if hasattr(entry, 'department') else 'Unknown',
                status='Active' if entry.userAccountControl.value & 2 == 0 else 'Disabled'
            )
            users.append(user)
            
        return users
    
    def collect_aws_users(self) -> List[UserAccessRecord]:
        """Pull IAM users from AWS"""
        print("☁️  Collecting AWS IAM users...")
        
        iam = boto3.client('iam',
                          aws_access_key_id=self.config['aws']['access_key'],
                          aws_secret_access_key=self.config['aws']['secret_key'])
        
        users = []
        paginator = iam.get_paginator('list_users')
        
        for page in paginator.paginate():
            for user in page['Users']:
                # Get user's last activity
                try:
                    access_key_last_used = iam.get_access_key_last_used(AccessKeyId=user['AccessKeyId'])
                    last_used = access_key_last_used.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                except:
                    last_used = None
                
                # Get user's permissions
                policies = iam.list_attached_user_policies(UserName=user['UserName'])
                permissions = [p['PolicyName'] for p in policies['AttachedPolicies']]
                
                user_record = UserAccessRecord(
                    username=user['UserName'],
                    email=user.get('Tags', {}).get('Email', ''),
                    system='AWS IAM',
                    last_login=last_used,
                    permissions=permissions,
                    manager=user.get('Tags', {}).get('Manager', 'Unknown'),
                    department=user.get('Tags', {}).get('Department', 'Unknown'),
                    status='Active'
                )
                users.append(user_record)
                
        return users
    
    def collect_github_users(self) -> List[UserAccessRecord]:
        """Pull users from GitHub organization"""
        print("🐙 Collecting GitHub organization users...")
        
        g = Github(self.config['github']['token'])
        org = g.get_organization(self.config['github']['org_name'])
        
        users = []
        for member in org.get_members():
            # Get user's repositories and permissions
            repos = list(member.get_repos())
            permissions = [f"Repo: {repo.name}" for repo in repos[:5]]  # Limit for brevity
            
            user_record = UserAccessRecord(
                username=member.login,
                email=member.email or '',
                system='GitHub',
                last_login=None,  # GitHub API doesn't provide last login
                permissions=permissions,
                manager='Unknown',
                department='Engineering',  # Assumption for GitHub users
                status='Active'
            )
            users.append(user_record)
            
        return users
    
    def analyze_access_risks(self, users: List[UserAccessRecord]) -> List[Dict]:
        """Analyze collected user data for SOC 2 compliance risks"""
        print("🔍 Analyzing access risks...")
        
        findings = []
        current_date = datetime.datetime.now()
        
        for user in users:
            # Risk 1: Inactive users (90+ days without login)
            if user.last_login:
                days_inactive = (current_date - user.last_login).days
                if days_inactive > 90:
                    findings.append({
                        'type': 'INACTIVE_USER',
                        'severity': 'HIGH' if days_inactive > 180 else 'MEDIUM',
                        'user': user.username,
                        'system': user.system,
                        'details': f'User inactive for {days_inactive} days',
                        'control': 'CC6.1 - Logical Access Controls',
                        'remediation': 'Disable account and remove access'
                    })
            
            # Risk 2: Excessive permissions
            if len(user.permissions) > 10:  # Configurable threshold
                findings.append({
                    'type': 'EXCESSIVE_PERMISSIONS',
                    'severity': 'MEDIUM',
                    'user': user.username,
                    'system': user.system,
                    'details': f'User has {len(user.permissions)} permissions',
                    'control': 'CC6.2 - Least Privilege',
                    'remediation': 'Review and reduce permissions to minimum required'
                })
            
            # Risk 3: Users without managers
            if user.manager in ['Unknown', '', None]:
                findings.append({
                    'type': 'MISSING_MANAGER',
                    'severity': 'LOW',
                    'user': user.username,
                    'system': user.system,
                    'details': 'No manager assigned for access approval',
                    'control': 'CC6.3 - Access Review and Approval',
                    'remediation': 'Assign manager for proper access governance'
                })
        
        return findings
    
    def generate_audit_report(self, findings: List[Dict], output_path: str):
        """Generate SOC 2 audit-ready report"""
        print(f"📊 Generating audit report: {output_path}")
        
        # Create summary statistics
        total_findings = len(findings)
        high_risk = len([f for f in findings if f['severity'] == 'HIGH'])
        medium_risk = len([f for f in findings if f['severity'] == 'MEDIUM'])
        low_risk = len([f for f in findings if f['severity'] == 'LOW'])
        
        report_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        with open(output_path, 'w', newline='') as csvfile:
            fieldnames = ['Finding_ID', 'Date', 'Severity', 'Type', 'User', 'System', 
                         'SOC2_Control', 'Details', 'Remediation', 'Status']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            
            for i, finding in enumerate(findings, 1):
                writer.writerow({
                    'Finding_ID': f'UAR-{i:04d}',
                    'Date': report_date,
                    'Severity': finding['severity'],
                    'Type': finding['type'],
                    'User': finding['user'],
                    'System': finding['system'],
                    'SOC2_Control': finding['control'],
                    'Details': finding['details'],
                    'Remediation': finding['remediation'],
                    'Status': 'OPEN'
                })
        
        # Print summary
        print(f"\n📈 Access Review Summary ({report_date})")
        print(f"Total Findings: {total_findings}")
        print(f"  🔴 High Risk: {high_risk}")
        print(f"  🟡 Medium Risk: {medium_risk}")
        print(f"  🟢 Low Risk: {low_risk}")
        
    def create_jira_tickets(self, findings: List[Dict]):
        """Create Jira tickets for high-priority findings"""
        print("🎫 Creating Jira tickets for remediation...")
        
        high_priority_findings = [f for f in findings if f['severity'] == 'HIGH']
        
        for finding in high_priority_findings:
            # Jira ticket creation (simplified)
            ticket_data = {
                'summary': f"SOC 2 Access Review: {finding['type']} - {finding['user']}",
                'description': f"""
**SOC 2 Control:** {finding['control']}
**System:** {finding['system']}
**User:** {finding['user']}
**Details:** {finding['details']}
**Recommended Action:** {finding['remediation']}

This ticket was auto-generated by the SOC 2 User Access Review automation.
                """,
                'priority': 'High',
                'labels': ['SOC2', 'AccessReview', 'Security']
            }
            
            # In real implementation, use Jira API
            print(f"  ✅ Created ticket for {finding['user']} - {finding['type']}")
    
    def run_full_review(self):
        """Execute complete user access review process"""
        print("🚀 Starting SOC 2 User Access Review...")
        
        # Collect users from all systems
        all_users = []
        all_users.extend(self.collect_ad_users())
        all_users.extend(self.collect_aws_users())
        all_users.extend(self.collect_github_users())
        
        self.users_data = all_users
        
        # Analyze for compliance risks
        findings = self.analyze_access_risks(all_users)
        self.findings = findings
        
        # Generate outputs
        report_filename = f"soc2_access_review_{datetime.datetime.now().strftime('%Y%m%d')}.csv"
        self.generate_audit_report(findings, report_filename)
        self.create_jira_tickets(findings)
        
        print(f"\n✅ Access review complete! Report saved as {report_filename}")
        return findings

    def _parse_ad_timestamp(self, timestamp):
        """Helper to parse AD timestamp format"""
        # Simplified timestamp parsing
        return datetime.datetime.now() - datetime.timedelta(days=30)  # Example
    
    def _extract_ad_groups(self, entry):
        """Helper to extract AD group memberships"""
        return ['Domain Users', 'VPN Users']  # Example

if __name__ == "__main__":
    # Example usage
    review_engine = AccessReviewEngine('config/systems_config.json')
    findings = review_engine.run_full_review()
