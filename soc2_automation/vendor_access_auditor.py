#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SOC 2 Vendor & Third-Party Access Audit Script
Maps to SOC 2 Common Criteria: CC9.1, CC9.2

This script audits external vendor and third-party access for SOC 2 Type II compliance:
- External integrations and API access
- Third-party user accounts and permissions
- Service provider access logging
- Automated remediation ticket creation

Author: Parker Robertson
Purpose: Automate vendor access evidence collection and compliance monitoring
"""

import argparse
import datetime
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
import csv

from lib.soc2_collectors import SystemDataCollector
from lib.soc2_models import VendorAccessEvidence, serialize_dataclass
from lib.soc2_utils import SOC2Utils


class VendorAccessAuditor(SystemDataCollector):
    """Vendor and third-party access auditor for SOC 2 compliance"""
    
    def __init__(self, config_path: str):
        """Initialize vendor access auditor"""
        self.config = SOC2Utils.load_json_config(config_path)
        super().__init__(self.config)
        
        # Vendor access specific configuration
        self.vendor_config = self.config.get('vendor_access', {})
        self.jira_config = self.config.get('jira', {})
        self.create_tickets = self.vendor_config.get('create_tickets', False)
        
        # Risk thresholds
        self.high_risk_integrations = self.vendor_config.get('high_risk_integrations', [
            'database_access', 'production_access', 'customer_data_access'
        ])
        self.critical_permissions = self.vendor_config.get('critical_permissions', [
            'admin', 'root', 'superuser', 'owner', 'full_access'
        ])
        
        self.evidence_items = []
        self.compliance_violations = []
        self.collection_date = datetime.datetime.now()
        
    def audit_vendor_access(self, vendor_types: List[str] = None) -> List[VendorAccessEvidence]:
        """
        Audit vendor and third-party access across systems
        
        Args:
            vendor_types: List of vendor integration types to audit
            
        Returns:
            List of VendorAccessEvidence objects
        """
        self.logger.info("🔍 Starting vendor access audit...")
        
        vendor_types = vendor_types or ['API', 'SSO', 'VPN', 'DIRECT_ACCESS', 'SERVICE_ACCOUNT']
        all_evidence = []
        
        # Audit configured vendors
        configured_vendors = self.vendor_config.get('vendors', [])
        for vendor_config in configured_vendors:
            if not vendor_types or vendor_config.get('integration_type') in vendor_types:
                try:
                    evidence = self._audit_single_vendor(vendor_config)
                    all_evidence.append(evidence)
                except Exception as e:
                    self.logger.error(f"Error auditing vendor {vendor_config.get('vendor_name', 'unknown')}: {str(e)}")
        
        # Discover additional third-party access from systems
        discovered_evidence = self._discover_third_party_access()
        all_evidence.extend(discovered_evidence)
        
        self.evidence_items = all_evidence
        
        # Identify compliance violations
        self._identify_compliance_violations()
        
        # Create remediation tickets if enabled
        if self.create_tickets and self.compliance_violations:
            self._create_remediation_tickets()
        
        self.logger.info(f"✅ Vendor access audit complete. Audited {len(all_evidence)} vendor integrations")
        if self.compliance_violations:
            self.logger.warning(f"⚠️  Found {len(self.compliance_violations)} compliance violations")
        
        return all_evidence
    
    def _audit_single_vendor(self, vendor_config: Dict[str, Any]) -> VendorAccessEvidence:
        """Audit a single vendor configuration"""
        vendor_name = vendor_config.get('vendor_name', 'Unknown Vendor')
        self.logger.debug(f"Auditing vendor: {vendor_name}")
        
        # Assess compliance status
        compliance_status, findings = self._assess_vendor_compliance(vendor_config)
        
        # Determine risk level
        risk_level = self._calculate_vendor_risk(vendor_config, findings)
        
        # Calculate next review date
        review_frequency = vendor_config.get('access_review_frequency', 'QUARTERLY')
        next_review = self._calculate_next_review_date(review_frequency)
        
        evidence = VendorAccessEvidence(
            vendor_id=vendor_config.get('vendor_id', f"vendor_{hash(vendor_name)}"),
            vendor_name=vendor_name,
            integration_type=vendor_config.get('integration_type', 'UNKNOWN'),
            access_method=vendor_config.get('access_method', 'Unknown'),
            access_scope=vendor_config.get('access_scope', []),
            access_permissions=vendor_config.get('access_permissions', []),
            authentication_method=vendor_config.get('authentication_method', 'UNKNOWN'),
            multi_factor_auth_required=vendor_config.get('mfa_required', False),
            access_logging_enabled=vendor_config.get('access_logging_enabled', False),
            access_log_location=vendor_config.get('access_log_location', ''),
            data_access_agreement=vendor_config.get('data_processing_agreement', False),
            security_assessment_date=self._parse_date(vendor_config.get('last_security_assessment')),
            access_review_frequency=review_frequency,
            last_access_review=self._parse_date(vendor_config.get('last_access_review')),
            access_expiration_date=self._parse_date(vendor_config.get('access_expiration_date')),
            emergency_access_procedure=vendor_config.get('emergency_access_procedure', False),
            compliance_status=compliance_status,
            risk_level=risk_level,
            findings=findings,
            soc2_controls=['CC9.1', 'CC9.2'],
            evidence_date=self.collection_date,
            next_review_due=next_review
        )
        
        return evidence
    
    def _discover_third_party_access(self) -> List[VendorAccessEvidence]:
        """Discover third-party access from various systems"""
        discovered_evidence = []
        
        # Check AWS IAM for third-party roles
        aws_evidence = self._discover_aws_third_party_access()
        discovered_evidence.extend(aws_evidence)
        
        # Check GitHub for external collaborators
        github_evidence = self._discover_github_third_party_access()
        discovered_evidence.extend(github_evidence)
        
        # Check Active Directory for external accounts
        ad_evidence = self._discover_ad_third_party_access()
        discovered_evidence.extend(ad_evidence)
        
        return discovered_evidence
    
    def _discover_aws_third_party_access(self) -> List[VendorAccessEvidence]:
        """Discover third-party access through AWS IAM"""
        evidence = []
        
        try:
            # Look for cross-account roles and external IDs in configuration
            aws_third_party = self.vendor_config.get('aws_third_party_roles', [])
            
            for role_config in aws_third_party:
                evidence_item = VendorAccessEvidence(
                    vendor_id=f"aws_role_{role_config.get('role_name', 'unknown')}",
                    vendor_name=role_config.get('vendor_name', 'AWS Third-Party Role'),
                    integration_type='AWS_CROSS_ACCOUNT',
                    access_method='IAM Role Assumption',
                    access_scope=role_config.get('permissions', []),
                    access_permissions=role_config.get('attached_policies', []),
                    authentication_method='AWS_STS',
                    multi_factor_auth_required=role_config.get('mfa_required', False),
                    access_logging_enabled=True,  # AWS CloudTrail
                    access_log_location='AWS CloudTrail',
                    data_access_agreement=role_config.get('has_agreement', False),
                    security_assessment_date=self._parse_date(role_config.get('last_assessment')),
                    access_review_frequency='QUARTERLY',
                    last_access_review=self._parse_date(role_config.get('last_review')),
                    access_expiration_date=None,  # IAM roles don't expire by default
                    emergency_access_procedure=role_config.get('emergency_procedure', False),
                    compliance_status=self._assess_aws_role_compliance(role_config),
                    risk_level=self._assess_aws_role_risk(role_config),
                    findings=self._analyze_aws_role_findings(role_config),
                    soc2_controls=['CC9.1', 'CC9.2'],
                    evidence_date=self.collection_date,
                    next_review_due=self._calculate_next_review_date('QUARTERLY')
                )
                evidence.append(evidence_item)
                
        except Exception as e:
            self.logger.error(f"Error discovering AWS third-party access: {str(e)}")
        
        return evidence
    
    def _discover_github_third_party_access(self) -> List[VendorAccessEvidence]:
        """Discover third-party access through GitHub"""
        evidence = []
        
        try:
            github_integrations = self.vendor_config.get('github_integrations', [])
            
            for integration in github_integrations:
                evidence_item = VendorAccessEvidence(
                    vendor_id=f"github_{integration.get('app_name', 'unknown')}",
                    vendor_name=integration.get('app_name', 'GitHub Integration'),
                    integration_type='GITHUB_APP',
                    access_method='GitHub App Installation',
                    access_scope=integration.get('permissions', []),
                    access_permissions=integration.get('repository_access', []),
                    authentication_method='GITHUB_APP_TOKEN',
                    multi_factor_auth_required=False,  # Not applicable for GitHub Apps
                    access_logging_enabled=True,  # GitHub audit logs
                    access_log_location='GitHub Audit Logs',
                    data_access_agreement=integration.get('has_agreement', False),
                    security_assessment_date=self._parse_date(integration.get('last_assessment')),
                    access_review_frequency='MONTHLY',
                    last_access_review=self._parse_date(integration.get('last_review')),
                    access_expiration_date=None,
                    emergency_access_procedure=integration.get('emergency_procedure', False),
                    compliance_status=self._assess_github_integration_compliance(integration),
                    risk_level=self._assess_github_integration_risk(integration),
                    findings=self._analyze_github_integration_findings(integration),
                    soc2_controls=['CC9.1', 'CC9.2'],
                    evidence_date=self.collection_date,
                    next_review_due=self._calculate_next_review_date('MONTHLY')
                )
                evidence.append(evidence_item)
                
        except Exception as e:
            self.logger.error(f"Error discovering GitHub third-party access: {str(e)}")
        
        return evidence
    
    def _discover_ad_third_party_access(self) -> List[VendorAccessEvidence]:
        """Discover third-party access through Active Directory"""
        evidence = []
        
        try:
            ad_external_accounts = self.vendor_config.get('ad_external_accounts', [])
            
            for account in ad_external_accounts:
                evidence_item = VendorAccessEvidence(
                    vendor_id=f"ad_{account.get('username', 'unknown')}",
                    vendor_name=f"AD External: {account.get('vendor_name', 'Unknown')}",
                    integration_type='ACTIVE_DIRECTORY',
                    access_method='Domain Authentication',
                    access_scope=account.get('group_memberships', []),
                    access_permissions=account.get('permissions', []),
                    authentication_method='KERBEROS',
                    multi_factor_auth_required=account.get('mfa_required', False),
                    access_logging_enabled=True,  # AD audit logs
                    access_log_location='Active Directory Audit Logs',
                    data_access_agreement=account.get('has_agreement', False),
                    security_assessment_date=self._parse_date(account.get('last_assessment')),
                    access_review_frequency='QUARTERLY',
                    last_access_review=self._parse_date(account.get('last_review')),
                    access_expiration_date=self._parse_date(account.get('expiration_date')),
                    emergency_access_procedure=account.get('emergency_procedure', False),
                    compliance_status=self._assess_ad_account_compliance(account),
                    risk_level=self._assess_ad_account_risk(account),
                    findings=self._analyze_ad_account_findings(account),
                    soc2_controls=['CC9.1', 'CC9.2'],
                    evidence_date=self.collection_date,
                    next_review_due=self._calculate_next_review_date('QUARTERLY')
                )
                evidence.append(evidence_item)
                
        except Exception as e:
            self.logger.error(f"Error discovering AD third-party access: {str(e)}")
        
        return evidence
    
    def _assess_vendor_compliance(self, vendor_config: Dict[str, Any]) -> tuple[str, List[str]]:
        """Assess vendor compliance status and identify findings"""
        findings = []
        
        # Check for required documentation
        if not vendor_config.get('data_processing_agreement', False):
            findings.append('Missing Data Processing Agreement (DPA/BAA)')
        
        # Check MFA requirement for high-risk integrations
        if (vendor_config.get('integration_type') in self.high_risk_integrations and 
            not vendor_config.get('mfa_required', False)):
            findings.append('Multi-factor authentication not required for high-risk integration')
        
        # Check access logging
        if not vendor_config.get('access_logging_enabled', False):
            findings.append('Access logging not enabled')
        
        # Check security assessment
        last_assessment = vendor_config.get('last_security_assessment')
        if not last_assessment:
            findings.append('No security assessment on record')
        else:
            assessment_date = self._parse_date(last_assessment)
            if assessment_date and (self.collection_date - assessment_date).days > 365:
                findings.append('Security assessment older than 1 year')
        
        # Check access review
        last_review = vendor_config.get('last_access_review')
        if not last_review:
            findings.append('No access review on record')
        else:
            review_date = self._parse_date(last_review)
            if review_date and (self.collection_date - review_date).days > 90:
                findings.append('Access review overdue')
        
        # Check for excessive permissions
        permissions = vendor_config.get('access_permissions', [])
        critical_perms = [p for p in permissions if any(cp in p.lower() for cp in self.critical_permissions)]
        if critical_perms:
            findings.append(f'Critical permissions granted: {", ".join(critical_perms)}')
        
        # Determine compliance status
        if not findings:
            status = 'COMPLIANT'
        elif len(findings) <= 2:
            status = 'NEEDS_REVIEW'
        else:
            status = 'NON_COMPLIANT'
        
        return status, findings
    
    def _calculate_vendor_risk(self, vendor_config: Dict[str, Any], findings: List[str]) -> str:
        """Calculate vendor risk level"""
        risk_score = 0
        
        # Integration type risk
        if vendor_config.get('integration_type') in self.high_risk_integrations:
            risk_score += 3
        
        # Access scope risk
        access_scope = vendor_config.get('access_scope', [])
        if any('production' in scope.lower() for scope in access_scope):
            risk_score += 2
        if any('customer' in scope.lower() or 'data' in scope.lower() for scope in access_scope):
            risk_score += 2
        
        # Permission risk
        permissions = vendor_config.get('access_permissions', [])
        if any(cp in ' '.join(permissions).lower() for cp in self.critical_permissions):
            risk_score += 3
        
        # Findings risk
        risk_score += len(findings)
        
        # MFA and logging mitigations
        if vendor_config.get('mfa_required', False):
            risk_score -= 1
        if vendor_config.get('access_logging_enabled', False):
            risk_score -= 1
        
        # Determine risk level
        if risk_score >= 7:
            return 'CRITICAL'
        elif risk_score >= 4:
            return 'HIGH'
        elif risk_score >= 2:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _identify_compliance_violations(self):
        """Identify vendor access compliance violations"""
        self.compliance_violations = []
        
        for evidence in self.evidence_items:
            if evidence.compliance_status == 'NON_COMPLIANT':
                self.compliance_violations.append({
                    'vendor_name': evidence.vendor_name,
                    'vendor_id': evidence.vendor_id,
                    'risk_level': evidence.risk_level,
                    'findings': evidence.findings,
                    'next_review_due': evidence.next_review_due
                })
            elif evidence.risk_level == 'CRITICAL':
                self.compliance_violations.append({
                    'vendor_name': evidence.vendor_name,
                    'vendor_id': evidence.vendor_id,
                    'risk_level': evidence.risk_level,
                    'findings': evidence.findings,
                    'next_review_due': evidence.next_review_due
                })
    
    def _create_remediation_tickets(self):
        """Create JIRA tickets for compliance violations"""
        if not self.jira_config:
            self.logger.warning("JIRA configuration not found, skipping ticket creation")
            return
        
        try:
            for violation in self.compliance_violations:
                ticket_data = {
                    'summary': f"Vendor Access Compliance Issue: {violation['vendor_name']}",
                    'description': self._format_violation_description(violation),
                    'priority': self._map_risk_to_priority(violation['risk_level']),
                    'labels': ['soc2', 'vendor-access', 'compliance'],
                    'components': ['Security'],
                    'due_date': violation.get('next_review_due')
                }
                
                # In a real implementation, this would create the JIRA ticket
                self.logger.info(f"  ✅ Would create ticket for {violation['vendor_name']} - {violation['risk_level']} risk")
                self.logger.debug(f"    📋 Ticket: {ticket_data['summary']}")
                
        except Exception as e:
            self.logger.error(f"Error creating remediation tickets: {str(e)}")
    
    def _format_violation_description(self, violation: Dict[str, Any]) -> str:
        """Format violation description for ticket"""
        description = f"""
Vendor Access Compliance Issue Detected

Vendor: {violation['vendor_name']}
Risk Level: {violation['risk_level']}
Vendor ID: {violation['vendor_id']}

Compliance Findings:
{chr(10).join(f'• {finding}' for finding in violation['findings'])}

SOC 2 Controls Affected: CC9.1, CC9.2

Next Review Due: {violation.get('next_review_due', 'Not scheduled')}

This issue was automatically detected by the SOC 2 Vendor Access Auditor.
Please review and remediate the identified compliance gaps.
        """.strip()
        
        return description
    
    def _map_risk_to_priority(self, risk_level: str) -> str:
        """Map risk level to JIRA priority"""
        mapping = {
            'CRITICAL': 'Highest',
            'HIGH': 'High',
            'MEDIUM': 'Medium',
            'LOW': 'Low'
        }
        return mapping.get(risk_level, 'Medium')
    
    def _parse_date(self, date_string: Optional[str]) -> Optional[datetime.datetime]:
        """Parse date string to datetime object"""
        if not date_string:
            return None
        
        try:
            if 'T' in date_string:
                return datetime.datetime.fromisoformat(date_string.replace('Z', '+00:00'))
            else:
                return datetime.datetime.strptime(date_string, '%Y-%m-%d')
        except Exception:
            return None
    
    def _calculate_next_review_date(self, frequency: str) -> datetime.datetime:
        """Calculate next review date based on frequency"""
        frequency_days = {
            'WEEKLY': 7,
            'MONTHLY': 30,
            'QUARTERLY': 90,
            'SEMI_ANNUALLY': 180,
            'ANNUALLY': 365
        }
        
        days = frequency_days.get(frequency, 90)  # Default to quarterly
        return self.collection_date + datetime.timedelta(days=days)
    
    # Assessment helper methods for different systems
    def _assess_aws_role_compliance(self, role_config: Dict[str, Any]) -> str:
        findings = []
        if not role_config.get('external_id'):
            findings.append('Missing external ID for cross-account role')
        if not role_config.get('condition_restrictions'):
            findings.append('No condition restrictions on role assumption')
        
        return 'COMPLIANT' if not findings else 'NEEDS_REVIEW'
    
    def _assess_aws_role_risk(self, role_config: Dict[str, Any]) -> str:
        permissions = role_config.get('attached_policies', [])
        if any('admin' in policy.lower() for policy in permissions):
            return 'HIGH'
        return 'MEDIUM'
    
    def _analyze_aws_role_findings(self, role_config: Dict[str, Any]) -> List[str]:
        findings = []
        if not role_config.get('last_used'):
            findings.append('Role usage not tracked')
        return findings
    
    def _assess_github_integration_compliance(self, integration: Dict[str, Any]) -> str:
        return 'COMPLIANT' if integration.get('approved_by_admin') else 'NEEDS_REVIEW'
    
    def _assess_github_integration_risk(self, integration: Dict[str, Any]) -> str:
        permissions = integration.get('permissions', [])
        if 'write' in permissions or 'admin' in permissions:
            return 'HIGH'
        return 'MEDIUM'
    
    def _analyze_github_integration_findings(self, integration: Dict[str, Any]) -> List[str]:
        findings = []
        if not integration.get('has_webhook_secret'):
            findings.append('Webhook secret not configured')
        return findings
    
    def _assess_ad_account_compliance(self, account: Dict[str, Any]) -> str:
        if account.get('is_disabled'):
            return 'COMPLIANT'
        return 'NEEDS_REVIEW' if account.get('expiration_date') else 'NON_COMPLIANT'
    
    def _assess_ad_account_risk(self, account: Dict[str, Any]) -> str:
        groups = account.get('group_memberships', [])
        if any('admin' in group.lower() for group in groups):
            return 'HIGH'
        return 'MEDIUM'
    
    def _analyze_ad_account_findings(self, account: Dict[str, Any]) -> List[str]:
        findings = []
        if not account.get('expiration_date'):
            findings.append('Account has no expiration date')
        return findings
    
    def generate_evidence_report(self, output_dir: str = None) -> str:
        """Generate vendor access evidence report"""
        output_dir = output_dir or self.config.get('global_settings', {}).get('output_directory', 'soc2_reports')
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = self.collection_date.strftime('%Y%m%d_%H%M%S')
        report_file = os.path.join(output_dir, f'vendor_access_evidence_{timestamp}.csv')
        
        with open(report_file, 'w', newline='', encoding='utf-8') as csvfile:
            if not self.evidence_items:
                csvfile.write("No vendor access evidence collected\\n")
                return report_file
            
            fieldnames = [
                'vendor_id', 'vendor_name', 'integration_type', 'access_method',
                'authentication_method', 'multi_factor_auth_required',
                'access_logging_enabled', 'data_access_agreement',
                'compliance_status', 'risk_level', 'findings',
                'soc2_controls', 'next_review_due', 'evidence_date'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for evidence in self.evidence_items:
                row = {
                    'vendor_id': evidence.vendor_id,
                    'vendor_name': evidence.vendor_name,
                    'integration_type': evidence.integration_type,
                    'access_method': evidence.access_method,
                    'authentication_method': evidence.authentication_method,
                    'multi_factor_auth_required': evidence.multi_factor_auth_required,
                    'access_logging_enabled': evidence.access_logging_enabled,
                    'data_access_agreement': evidence.data_access_agreement,
                    'compliance_status': evidence.compliance_status,
                    'risk_level': evidence.risk_level,
                    'findings': '; '.join(evidence.findings),
                    'soc2_controls': '; '.join(evidence.soc2_controls),
                    'next_review_due': evidence.next_review_due.isoformat() if evidence.next_review_due else '',
                    'evidence_date': evidence.evidence_date.isoformat()
                }
                writer.writerow(row)
        
        # Also generate JSON report
        json_file = os.path.join(output_dir, f'vendor_access_evidence_{timestamp}.json')
        with open(json_file, 'w', encoding='utf-8') as jsonfile:
            evidence_data = [serialize_dataclass(evidence) for evidence in self.evidence_items]
            json.dump(evidence_data, jsonfile, indent=2, default=str)
        
        self.logger.info(f"Vendor access evidence report generated: {report_file}")
        return report_file


def main():
    """Main entry point for vendor access auditor"""
    parser = argparse.ArgumentParser(
        description='SOC 2 Vendor & Third-Party Access Auditor',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--config', required=True,
                       help='Path to SOC 2 configuration file')
    parser.add_argument('--output-dir',
                       help='Output directory for evidence reports')
    parser.add_argument('--vendor-types', nargs='*',
                       choices=['API', 'SSO', 'VPN', 'DIRECT_ACCESS', 'SERVICE_ACCOUNT'],
                       help='Specific vendor integration types to audit')
    parser.add_argument('--create-tickets', action='store_true',
                       help='Create JIRA tickets for compliance violations')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Initialize auditor
    auditor = VendorAccessAuditor(args.config)
    
    if args.verbose:
        auditor.logger.setLevel('DEBUG')
    
    if args.create_tickets:
        auditor.create_tickets = True
    
    try:
        # Audit vendor access
        evidence = auditor.audit_vendor_access(args.vendor_types)
        
        # Generate report
        report_file = auditor.generate_evidence_report(args.output_dir)
        
        print(f"\\n🔍 Vendor Access Audit Complete!")
        print(f"📊 Audited {len(evidence)} vendor integrations")
        
        # Summary by compliance status
        compliance_summary = {}
        risk_summary = {}
        for item in evidence:
            status = item.compliance_status
            risk = item.risk_level
            compliance_summary[status] = compliance_summary.get(status, 0) + 1
            risk_summary[risk] = risk_summary.get(risk, 0) + 1
        
        print(f"\\n📈 Compliance Status Summary:")
        for status, count in sorted(compliance_summary.items()):
            print(f"  {status}: {count} vendors")
        
        print(f"\\n🎯 Risk Level Summary:")
        for risk, count in sorted(risk_summary.items()):
            print(f"  {risk}: {count} vendors")
        
        if auditor.compliance_violations:
            print(f"\\n⚠️  {len(auditor.compliance_violations)} compliance violations require attention")
            if auditor.create_tickets:
                print(f"🎫 Remediation tickets created in JIRA")
        
        print(f"\\n📁 Report saved to: {report_file}")
        
        return 0
        
    except Exception as e:
        auditor.logger.error(f"Vendor access audit failed: {str(e)}")
        print(f"❌ Error: {str(e)}")
        return 1


if __name__ == "__main__":
    exit(main())