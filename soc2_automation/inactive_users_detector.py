#!/usr/bin/env python3
"""
SOC 2 AWS Inactive Users Detection Script
Maps to SOC 2 Common Criteria: CC6.1, CC6.2, CC6.3

This script identifies inactive AWS IAM users by analyzing:
1. Console login activity patterns
2. Access key usage patterns  
3. Cross-account user analysis
4. Automated remediation ticket creation

Author: Parker Robertson
Purpose: Detect inactive users for SOC 2 compliance and security risk reduction
"""

import argparse
import datetime
import json
from typing import Dict, List, Optional, Any
import boto3
from botocore.exceptions import ClientError

from lib.soc2_collectors import SystemDataCollector
from lib.soc2_models import UserAccessRecord, AccessReviewFinding, serialize_dataclass
from lib.soc2_utils import SOC2Utils


class InactiveUsersDetector(SystemDataCollector):
    """AWS Inactive Users Detection integrated with SOC 2 automation framework"""
    
    def __init__(self, config_path: str):
        """Initialize detector with configuration"""
        self.config = SOC2Utils.load_json_config(config_path)
        super().__init__(self.config)
        
        # Load inactive users specific config
        self.inactive_config = self.config.get('inactive_users', {})
        self.console_threshold = self.inactive_config.get('console_threshold_days', 90)
        self.access_key_threshold = self.inactive_config.get('access_key_threshold_days', 180)
        self.create_tickets = self.inactive_config.get('create_tickets', False)
        
        self.findings = []
        self.processed_accounts = []
        
    def analyze_inactive_users(self, accounts: List[str] = None) -> List[AccessReviewFinding]:
        """
        Main method to analyze inactive users across single or multiple AWS accounts
        
        Args:
            accounts: List of account IDs to analyze (if None, uses config accounts)
            
        Returns:
            List of AccessReviewFinding objects for inactive users
        """
        self.logger.info("🔍 Starting AWS inactive users analysis...")
        
        # Determine accounts to analyze
        target_accounts = self._get_target_accounts(accounts)
        
        all_findings = []
        for account_config in target_accounts:
            try:
                self.logger.info(f"Analyzing account: {account_config.get('account_id', 'current')}")
                account_findings = self._analyze_account(account_config)
                all_findings.extend(account_findings)
                self.processed_accounts.append(account_config.get('account_id', 'current'))
                
            except Exception as e:
                self.logger.error(f"Failed to analyze account {account_config.get('account_id', 'unknown')}: {str(e)}")
                continue
        
        self.findings = all_findings
        self.logger.info(f"✅ Analysis complete. Found {len(all_findings)} inactive user findings across {len(self.processed_accounts)} accounts")
        
        return all_findings
    
    def _get_target_accounts(self, accounts: List[str]) -> List[Dict]:
        """Get list of account configurations to analyze"""
        if accounts:
            # Filter config accounts by provided account IDs
            config_accounts = self.config.get('aws', {}).get('accounts', [])
            return [acc for acc in config_accounts if acc.get('account_id') in accounts]
        elif 'accounts' in self.config.get('aws', {}):
            # Use all configured accounts
            return self.config['aws']['accounts']
        else:
            # Single account mode using main AWS config
            return [{'account_id': 'current', 'aws_config': self.config.get('aws', {})}]
    
    def _analyze_account(self, account_config: Dict) -> List[AccessReviewFinding]:
        """Analyze inactive users in a single AWS account"""
        account_id = account_config.get('account_id', 'current')
        
        # Get AWS client for this account
        iam_client = self._get_account_iam_client(account_config)
        
        # Collect all users in this account
        users = self._collect_account_users(iam_client, account_id)
        
        # Analyze each user for inactivity
        findings = []
        for user in users:
            user_findings = self._analyze_user_activity(user, iam_client)
            findings.extend(user_findings)
        
        return findings
    
    def _get_account_iam_client(self, account_config: Dict):
        """Get IAM client for specified account (with cross-account role support)"""
        if account_config.get('account_id') == 'current':
            # Use main AWS configuration
            return SOC2Utils.initialize_aws_client('iam', self.config)
        
        # Cross-account access using STS assume role
        if 'role_arn' in account_config:
            return self._assume_cross_account_role(account_config)
        else:
            # Direct access with account-specific credentials
            temp_config = {'aws': account_config.get('aws_config', {})}
            return SOC2Utils.initialize_aws_client('iam', temp_config)
    
    def _assume_cross_account_role(self, account_config: Dict):
        """Assume cross-account IAM role for multi-account access"""
        try:
            # Create STS client with base credentials
            sts_client = SOC2Utils.initialize_aws_client('sts', self.config)
            
            # Assume the cross-account role
            assumed_role = sts_client.assume_role(
                RoleArn=account_config['role_arn'],
                RoleSessionName=f"SOC2-InactiveUsers-{account_config['account_id']}"
            )
            
            # Create IAM client with assumed role credentials
            credentials = assumed_role['Credentials']
            iam_client = boto3.client(
                'iam',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=account_config.get('region', 'us-east-1')
            )
            
            return iam_client
            
        except Exception as e:
            raise ConnectionError(f"Failed to assume role {account_config['role_arn']}: {str(e)}")
    
    def _collect_account_users(self, iam_client, account_id: str) -> List[UserAccessRecord]:
        """Collect all users from specified account"""
        try:
            # Reuse existing user collection logic but for specific client
            temp_config = {'aws': self.config['aws']}  # Use base config structure
            temp_collector = SystemDataCollector(temp_config)
            temp_collector.logger = self.logger
            
            # Override the IAM client to use our account-specific client
            users = []
            paginator = iam_client.get_paginator('list_users')
            
            for page in paginator.paginate():
                for user_data in page['Users']:
                    user_record = self._process_aws_user(user_data, iam_client, account_id)
                    users.append(user_record)
            
            return users
            
        except Exception as e:
            self.logger.error(f"Failed to collect users from account {account_id}: {str(e)}")
            return []
    
    def _process_aws_user(self, user_data: Dict, iam_client, account_id: str) -> UserAccessRecord:
        """Process individual AWS user data for specified account"""
        username = user_data['UserName']
        
        # Get last console login
        console_last_login = self._get_console_last_login(username, iam_client)
        
        # Get access key last activity
        access_key_last_activity = self._get_access_key_last_activity(username, iam_client)
        
        # Use the most recent activity as overall last login
        last_login = None
        if console_last_login and access_key_last_activity:
            last_login = max(console_last_login, access_key_last_activity)
        elif console_last_login:
            last_login = console_last_login
        elif access_key_last_activity:
            last_login = access_key_last_activity
        
        # Get basic permissions info
        permissions, group_memberships = self._get_aws_user_permissions(username, iam_client)
        
        # Get user tags
        tags = self._get_aws_user_tags(username, iam_client)
        
        return UserAccessRecord(
            username=username,
            email=tags.get('Email', ''),
            system=f'AWS IAM ({account_id})',
            user_id=user_data['UserId'],
            last_login=last_login,
            permissions=permissions,
            manager=tags.get('Manager', 'Unknown'),
            department=tags.get('Department', 'Unknown'),
            status='Active',
            created_date=user_data.get('CreateDate'),
            mfa_enabled=self._get_aws_user_mfa_status(username, iam_client),
            group_memberships=group_memberships
        )
    
    def _get_console_last_login(self, username: str, iam_client) -> Optional[datetime.datetime]:
        """Get user's last console login date"""
        try:
            # Get user's password last used (indicates console login)
            user_info = iam_client.get_user(UserName=username)
            return user_info['User'].get('PasswordLastUsed')
        except:
            return None
    
    def _get_access_key_last_activity(self, username: str, iam_client) -> Optional[datetime.datetime]:
        """Get user's last access key activity"""
        try:
            access_keys = iam_client.list_access_keys(UserName=username)
            latest_activity = None
            
            for key in access_keys['AccessKeyMetadata']:
                if key['Status'] == 'Active':
                    try:
                        last_used = iam_client.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                        if 'AccessKeyLastUsed' in last_used and 'LastUsedDate' in last_used['AccessKeyLastUsed']:
                            activity_date = last_used['AccessKeyLastUsed']['LastUsedDate']
                            if latest_activity is None or activity_date > latest_activity:
                                latest_activity = activity_date
                    except:
                        continue
            
            return latest_activity
        except:
            return None
    
    def _analyze_user_activity(self, user: UserAccessRecord, iam_client) -> List[AccessReviewFinding]:
        """Analyze individual user for inactivity patterns"""
        findings = []
        current_date = datetime.datetime.now(datetime.timezone.utc)
        
        # Get detailed activity info for this user
        console_last_login = self._get_console_last_login(user.username, iam_client)
        access_key_last_activity = self._get_access_key_last_activity(user.username, iam_client)
        
        # Check console login inactivity
        if console_last_login:
            days_since_console = (current_date - console_last_login.replace(tzinfo=datetime.timezone.utc)).days
            if days_since_console >= self.console_threshold:
                findings.append(self._create_finding(
                    user=user,
                    finding_type='CONSOLE_INACTIVE',
                    severity='HIGH',
                    details=f'Console login inactive for {days_since_console} days (last: {console_last_login.strftime("%Y-%m-%d")})',
                    control='CC6.1 - Logical Access Controls',
                    remediation='Review user necessity and disable console access if no longer needed'
                ))
        else:
            # No console login history
            account_age = (current_date - user.created_date.replace(tzinfo=datetime.timezone.utc)).days if user.created_date else 0
            if account_age >= self.console_threshold:
                findings.append(self._create_finding(
                    user=user,
                    finding_type='CONSOLE_NEVER_USED',
                    severity='HIGH',
                    details=f'Console access never used in {account_age} days since account creation',
                    control='CC6.1 - Logical Access Controls',
                    remediation='Review if console access is needed, consider removing console permissions'
                ))
        
        # Check access key inactivity
        if access_key_last_activity:
            days_since_keys = (current_date - access_key_last_activity.replace(tzinfo=datetime.timezone.utc)).days
            if days_since_keys >= self.access_key_threshold:
                findings.append(self._create_finding(
                    user=user,
                    finding_type='ACCESS_KEY_INACTIVE',
                    severity='MEDIUM',
                    details=f'Access keys inactive for {days_since_keys} days (last: {access_key_last_activity.strftime("%Y-%m-%d")})',
                    control='CC6.2 - Least Privilege',
                    remediation='Review programmatic access necessity and rotate or delete unused access keys'
                ))
        else:
            # Check if user has access keys but never used them
            try:
                access_keys = iam_client.list_access_keys(UserName=user.username)
                if access_keys['AccessKeyMetadata']:
                    oldest_key_age = min(
                        (current_date - key['CreateDate'].replace(tzinfo=datetime.timezone.utc)).days 
                        for key in access_keys['AccessKeyMetadata']
                    )
                    if oldest_key_age >= self.access_key_threshold:
                        findings.append(self._create_finding(
                            user=user,
                            finding_type='ACCESS_KEY_NEVER_USED',
                            severity='MEDIUM',
                            details=f'Access keys never used in {oldest_key_age} days since creation',
                            control='CC6.2 - Least Privilege',
                            remediation='Review if programmatic access is needed, consider deleting unused access keys'
                        ))
            except:
                pass
        
        return findings
    
    def _create_finding(self, user: UserAccessRecord, finding_type: str, severity: str, 
                       details: str, control: str, remediation: str) -> AccessReviewFinding:
        """Create standardized access review finding"""
        finding_id = f"IAU-{user.username}-{finding_type}-{datetime.datetime.now().strftime('%Y%m%d')}"
        
        return AccessReviewFinding(
            finding_id=finding_id,
            finding_type=finding_type,
            severity=severity,
            user_record=user,
            details=details,
            soc2_control=control,
            remediation_action=remediation,
            created_date=datetime.datetime.now(),
            status='OPEN'
        )
    
    def generate_reports(self, output_dir: str = None) -> Dict[str, str]:
        """Generate CSV and JSON reports for findings"""
        if not output_dir:
            output_dir = SOC2Utils.create_output_directory('inactive_users')
        
        report_paths = {}
        
        if not self.findings:
            self.logger.warning("No findings to report")
            return report_paths
        
        # Generate CSV report
        csv_data = []
        for finding in self.findings:
            csv_data.append({
                'Finding_ID': finding.finding_id,
                'Account': finding.user_record.system,
                'Username': finding.user_record.username,
                'Email': finding.user_record.email,
                'Finding_Type': finding.finding_type,
                'Severity': finding.severity,
                'Details': finding.details,
                'SOC2_Control': finding.soc2_control,
                'Remediation': finding.remediation_action,
                'Department': finding.user_record.department,
                'Manager': finding.user_record.manager,
                'Created_Date': finding.user_record.created_date.strftime('%Y-%m-%d') if finding.user_record.created_date else '',
                'Last_Login': finding.user_record.last_login.strftime('%Y-%m-%d %H:%M:%S') if finding.user_record.last_login else 'Never',
                'MFA_Enabled': finding.user_record.mfa_enabled,
                'Status': finding.status
            })
        
        csv_path = f"{output_dir}/inactive_users_findings.csv"
        SOC2Utils.write_csv_report(csv_data, csv_path)
        report_paths['csv'] = csv_path
        
        # Generate JSON report
        json_data = {
            'analysis_date': datetime.datetime.now().isoformat(),
            'accounts_analyzed': self.processed_accounts,
            'configuration': {
                'console_threshold_days': self.console_threshold,
                'access_key_threshold_days': self.access_key_threshold
            },
            'summary': {
                'total_findings': len(self.findings),
                'high_severity': sum(1 for f in self.findings if f.severity == 'HIGH'),
                'medium_severity': sum(1 for f in self.findings if f.severity == 'MEDIUM'),
                'low_severity': sum(1 for f in self.findings if f.severity == 'LOW')
            },
            'findings': [serialize_dataclass(finding) for finding in self.findings]
        }
        
        json_path = f"{output_dir}/inactive_users_findings.json"
        SOC2Utils.write_json_report(json_data, json_path)
        report_paths['json'] = json_path
        
        # Print summary
        self._print_analysis_summary(json_data['summary'])
        
        return report_paths
    
    def _print_analysis_summary(self, summary: Dict):
        """Print analysis summary to console"""
        print(f"\n📊 AWS Inactive Users Analysis Summary")
        print(f"Analysis Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Accounts Analyzed: {len(self.processed_accounts)}")
        print(f"Total Findings: {summary['total_findings']}")
        print(f"  🔴 High Severity: {summary['high_severity']}")
        print(f"  🟡 Medium Severity: {summary['medium_severity']}")
        print(f"  🟢 Low Severity: {summary['low_severity']}")
        print(f"\nConfiguration:")
        print(f"  Console Inactivity Threshold: {self.console_threshold} days")
        print(f"  Access Key Inactivity Threshold: {self.access_key_threshold} days")
    
    def create_remediation_tickets(self):
        """Create remediation tickets for high-severity findings (if enabled)"""
        if not self.create_tickets:
            self.logger.info("Ticket creation disabled in configuration")
            return
        
        high_severity_findings = [f for f in self.findings if f.severity == 'HIGH']
        
        if not high_severity_findings:
            self.logger.info("No high-severity findings requiring tickets")
            return
        
        self.logger.info(f"Creating {len(high_severity_findings)} remediation tickets...")
        
        for finding in high_severity_findings:
            self._create_jira_ticket(finding)
    
    def _create_jira_ticket(self, finding: AccessReviewFinding):
        """Create individual Jira ticket for finding"""
        ticket_data = {
            'summary': f"SOC 2 Inactive User: {finding.finding_type} - {finding.user_record.username}",
            'description': f"""
**SOC 2 Control:** {finding.soc2_control}
**Account:** {finding.user_record.system}
**User:** {finding.user_record.username} ({finding.user_record.email})
**Department:** {finding.user_record.department}
**Manager:** {finding.user_record.manager}
**Severity:** {finding.severity}
**Details:** {finding.details}
**Recommended Action:** {finding.remediation_action}

**User Details:**
- Created: {finding.user_record.created_date.strftime('%Y-%m-%d') if finding.user_record.created_date else 'Unknown'}
- Last Login: {finding.user_record.last_login.strftime('%Y-%m-%d %H:%M:%S') if finding.user_record.last_login else 'Never'}
- MFA Enabled: {finding.user_record.mfa_enabled}
- Permissions: {', '.join(finding.user_record.permissions[:5])}{'...' if len(finding.user_record.permissions) > 5 else ''}

This ticket was auto-generated by the SOC 2 AWS Inactive Users Detection automation.
            """,
            'priority': 'High',
            'labels': ['SOC2', 'InactiveUser', 'Security', 'AccessReview']
        }
        
        # In production, integrate with actual Jira API
        self.logger.info(f"  ✅ Would create ticket for {finding.user_record.username} - {finding.finding_type}")
        print(f"    📋 Ticket: {ticket_data['summary']}")


def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='SOC 2 AWS Inactive Users Detection')
    parser.add_argument('--config', required=True, help='Path to configuration JSON file')
    parser.add_argument('--accounts', nargs='*', help='Specific account IDs to analyze')
    parser.add_argument('--output-dir', help='Custom output directory for reports')
    parser.add_argument('--create-tickets', action='store_true', help='Create remediation tickets')
    parser.add_argument('--console-threshold', type=int, help='Console inactivity threshold in days')
    parser.add_argument('--access-key-threshold', type=int, help='Access key inactivity threshold in days')
    
    args = parser.parse_args()
    
    try:
        # Initialize detector
        detector = InactiveUsersDetector(args.config)
        
        # Override thresholds if provided
        if args.console_threshold:
            detector.console_threshold = args.console_threshold
        if args.access_key_threshold:
            detector.access_key_threshold = args.access_key_threshold
        if args.create_tickets:
            detector.create_tickets = True
        
        # Run analysis
        findings = detector.analyze_inactive_users(args.accounts)
        
        # Generate reports
        report_paths = detector.generate_reports(args.output_dir)
        
        # Create tickets if enabled
        if detector.create_tickets:
            detector.create_remediation_tickets()
        
        # Output results
        if report_paths:
            print(f"\n📄 Reports generated:")
            for format_type, path in report_paths.items():
                print(f"  {format_type.upper()}: {path}")
        
        print(f"\n✅ Analysis complete!")
        
        return 0 if len(findings) == 0 else 1  # Return 1 if findings exist for CI/CD
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return 2


if __name__ == "__main__":
    exit(main())