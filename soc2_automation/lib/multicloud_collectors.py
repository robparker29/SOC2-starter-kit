#!/usr/bin/env python3
"""
Multi-Cloud Data Collectors for SOC 2 Automation
Extends the existing SOC 2 framework to support AWS, Azure, and GCP

This module provides unified data collection across multiple cloud providers
while maintaining compatibility with existing SOC 2 automation scripts.

Author: Parker Robertson
Purpose: Enable multi-cloud SOC 2 compliance automation
"""

import logging
import asyncio
import concurrent.futures
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta

from .soc2_collectors import SystemDataCollector
from .cloud_providers import CloudProviderFactory, CloudProvider
from .soc2_models import (
    UserAccessRecord, SystemConfiguration, EvidenceItem,
    MultiCloudIdentity, NetworkSecurityRule, CloudAuditLog,
    ComplianceFinding, CrossCloudReport, serialize_dataclass
)
from .soc2_utils import SOC2Utils


class MultiCloudDataCollector(SystemDataCollector):
    """Enhanced data collector supporting multiple cloud providers"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize multi-cloud collector"""
        super().__init__(config)
        self.cloud_providers: Dict[str, CloudProvider] = {}
        self.supported_providers = ['aws', 'azure', 'gcp']
        self.parallel_execution = config.get('global_settings', {}).get('parallel_execution', True)
        self.max_concurrent_clouds = config.get('global_settings', {}).get('max_concurrent_clouds', 3)
        
        # Initialize cloud providers
        self._initialize_cloud_providers()
    
    def _initialize_cloud_providers(self):
        """Initialize all configured cloud providers"""
        try:
            self.cloud_providers = CloudProviderFactory.create_multi_cloud_session(
                self.config, self.logger
            )
            
            if not self.cloud_providers:
                self.logger.warning("No cloud providers could be initialized")
            else:
                provider_names = list(self.cloud_providers.keys())
                self.logger.info(f"Initialized cloud providers: {', '.join(provider_names)}")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize cloud providers: {str(e)}")
    
    def collect_multi_cloud_identities(self, providers: List[str] = None) -> Dict[str, List[MultiCloudIdentity]]:
        """Collect user identities from all cloud providers"""
        providers = providers or list(self.cloud_providers.keys())
        results = {}
        
        if self.parallel_execution:
            results = self._collect_identities_parallel(providers)
        else:
            results = self._collect_identities_sequential(providers)
        
        # Log summary
        total_identities = sum(len(identities) for identities in results.values())
        self.logger.info(f"Collected {total_identities} identities across {len(results)} cloud providers")
        
        return results
    
    def _collect_identities_parallel(self, providers: List[str]) -> Dict[str, List[MultiCloudIdentity]]:
        """Collect identities in parallel across cloud providers"""
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_concurrent_clouds) as executor:
            # Submit tasks for each provider
            future_to_provider = {}
            for provider_name in providers:
                if provider_name.upper() in self.cloud_providers:
                    provider = self.cloud_providers[provider_name.upper()]
                    future = executor.submit(self._collect_provider_identities, provider_name, provider)
                    future_to_provider[future] = provider_name
            
            # Collect results
            for future in concurrent.futures.as_completed(future_to_provider):
                provider_name = future_to_provider[future]
                try:
                    identities = future.result()
                    results[provider_name] = identities
                except Exception as e:
                    self.logger.error(f"Failed to collect identities from {provider_name}: {str(e)}")
                    results[provider_name] = []
        
        return results
    
    def _collect_identities_sequential(self, providers: List[str]) -> Dict[str, List[MultiCloudIdentity]]:
        """Collect identities sequentially across cloud providers"""
        results = {}
        
        for provider_name in providers:
            if provider_name.upper() in self.cloud_providers:
                provider = self.cloud_providers[provider_name.upper()]
                try:
                    identities = self._collect_provider_identities(provider_name, provider)
                    results[provider_name] = identities
                except Exception as e:
                    self.logger.error(f"Failed to collect identities from {provider_name}: {str(e)}")
                    results[provider_name] = []
        
        return results
    
    def _collect_provider_identities(self, provider_name: str, provider: CloudProvider) -> List[MultiCloudIdentity]:
        """Collect identities from a specific cloud provider"""
        try:
            # Get cloud identities from provider
            cloud_identities = provider.get_identities()
            
            # Convert to MultiCloudIdentity objects
            multi_cloud_identities = []
            for identity in cloud_identities:
                multi_cloud_identity = MultiCloudIdentity(
                    identity_id=identity.user_id,
                    username=identity.username,
                    email=identity.email,
                    display_name=identity.display_name,
                    cloud_provider=identity.cloud_provider,
                    account_id=identity.account_id,
                    identity_type='USER',  # Could be enhanced to detect service accounts
                    roles=identity.roles,
                    permissions=identity.permissions,
                    last_login=identity.last_login,
                    mfa_enabled=identity.mfa_enabled,
                    created_date=identity.created_date,
                    status=identity.status,
                    source_systems=[identity.cloud_provider],
                    cloud_specific_data=identity.metadata
                )
                multi_cloud_identities.append(multi_cloud_identity)
            
            self.logger.info(f"Collected {len(multi_cloud_identities)} identities from {provider_name}")
            return multi_cloud_identities
            
        except Exception as e:
            self.logger.error(f"Error collecting identities from {provider_name}: {str(e)}")
            return []
    
    def collect_multi_cloud_network_rules(self, providers: List[str] = None) -> Dict[str, List[NetworkSecurityRule]]:
        """Collect network security rules from all cloud providers"""
        providers = providers or list(self.cloud_providers.keys())
        results = {}
        
        for provider_name in providers:
            if provider_name.upper() in self.cloud_providers:
                provider = self.cloud_providers[provider_name.upper()]
                try:
                    # Get network rules from provider
                    cloud_rules = provider.get_network_rules()
                    
                    # Convert to unified NetworkSecurityRule format
                    network_rules = []
                    for rule in cloud_rules:
                        network_rule = NetworkSecurityRule(
                            rule_id=rule.rule_id,
                            rule_name=rule.rule_name,
                            cloud_provider=rule.cloud_provider,
                            resource_group=rule.resource_id,
                            direction=rule.direction,
                            protocol=rule.protocol,
                            source_addresses=[rule.source] if rule.source else [],
                            destination_addresses=[rule.destination] if rule.destination else [],
                            source_ports=[],  # Would need to parse from port_range
                            destination_ports=[rule.port_range] if rule.port_range else [],
                            action=rule.action,
                            priority=rule.priority,
                            description=f"{rule.rule_name} - {rule.cloud_provider}",
                            created_date=rule.created_date,
                            last_modified=rule.created_date
                        )
                        network_rules.append(network_rule)
                    
                    results[provider_name] = network_rules
                    self.logger.info(f"Collected {len(network_rules)} network rules from {provider_name}")
                    
                except Exception as e:
                    self.logger.error(f"Failed to collect network rules from {provider_name}: {str(e)}")
                    results[provider_name] = []
        
        return results
    
    def collect_multi_cloud_audit_logs(self, providers: List[str] = None, 
                                     time_range_days: int = 30) -> Dict[str, List[CloudAuditLog]]:
        """Collect audit logs from all cloud providers"""
        providers = providers or list(self.cloud_providers.keys())
        results = {}
        
        for provider_name in providers:
            if provider_name.upper() in self.cloud_providers:
                provider = self.cloud_providers[provider_name.upper()]
                try:
                    # Get audit events from provider
                    audit_events = provider.get_audit_events(time_range_days)
                    
                    # Convert to unified CloudAuditLog format
                    audit_logs = []
                    for event in audit_events:
                        audit_log = CloudAuditLog(
                            log_id=event.event_id,
                            event_name=event.event_name,
                            cloud_provider=event.cloud_provider,
                            service_name=event.source_service,
                            event_time=event.event_time,
                            user_identity=event.user_identity,
                            user_type='USER',  # Could be enhanced
                            source_ip=event.source_ip,
                            user_agent=event.user_agent,
                            account_id='',  # Would need to extract from event details
                            region='',  # Would need to extract from event details
                            resources_affected=event.resources,
                            event_outcome=event.event_outcome,
                            error_code=None,
                            event_details=event.event_details
                        )
                        audit_logs.append(audit_log)
                    
                    results[provider_name] = audit_logs
                    self.logger.info(f"Collected {len(audit_logs)} audit logs from {provider_name}")
                    
                except Exception as e:
                    self.logger.error(f"Failed to collect audit logs from {provider_name}: {str(e)}")
                    results[provider_name] = []
        
        return results
    
    def run_cross_cloud_compliance_assessment(self, 
                                            assessment_types: List[str] = None,
                                            soc2_controls: List[str] = None) -> CrossCloudReport:
        """Run comprehensive compliance assessment across all cloud providers"""
        
        assessment_types = assessment_types or ['access_review', 'network_security', 'compliance_check']
        soc2_controls = soc2_controls or ['CC6.1', 'CC6.2', 'CC6.3', 'CC7.1', 'CC7.2']
        
        # Initialize report
        report = CrossCloudReport(
            report_id=f"cross-cloud-assessment-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            report_type='COMPLIANCE_ASSESSMENT',
            report_date=datetime.now(),
            cloud_providers=list(self.cloud_providers.keys()),
            accounts_covered={},
            soc2_controls=soc2_controls,
            summary_statistics={},
            findings_summary={'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        )
        
        all_findings = []
        
        # Run assessments by type
        for assessment_type in assessment_types:
            try:
                if assessment_type == 'access_review':
                    findings = self._assess_access_controls()
                elif assessment_type == 'network_security':
                    findings = self._assess_network_security()
                elif assessment_type == 'compliance_check':
                    findings = self._assess_compliance_posture()
                else:
                    self.logger.warning(f"Unknown assessment type: {assessment_type}")
                    continue
                
                all_findings.extend(findings)
                
            except Exception as e:
                self.logger.error(f"Failed to run {assessment_type} assessment: {str(e)}")
        
        # Update report with findings
        for finding in all_findings:
            report.findings_summary[finding.severity] += 1
        
        report.summary_statistics = {
            'total_findings': len(all_findings),
            'cloud_providers_assessed': len(self.cloud_providers),
            'assessment_types_completed': len(assessment_types)
        }
        
        self.logger.info(f"Cross-cloud assessment complete: {len(all_findings)} findings across {len(self.cloud_providers)} providers")
        
        return report
    
    def _assess_access_controls(self) -> List[ComplianceFinding]:
        """Assess access controls across all cloud providers"""
        findings = []
        
        # Collect identities from all providers
        all_identities = self.collect_multi_cloud_identities()
        
        for provider_name, identities in all_identities.items():
            for identity in identities:
                # Check for inactive users
                if identity.last_login:
                    inactive_days = (datetime.now() - identity.last_login.replace(tzinfo=None)).days
                    if inactive_days > 90:
                        finding = ComplianceFinding(
                            finding_id=f"access-{provider_name}-{identity.username}-inactive",
                            finding_type='ACCESS_CONTROL',
                            severity='HIGH' if inactive_days > 180 else 'MEDIUM',
                            cloud_provider=identity.cloud_provider,
                            resource_id=identity.identity_id,
                            resource_type='USER_IDENTITY',
                            account_id=identity.account_id,
                            region='N/A',
                            title=f'Inactive user detected in {provider_name}',
                            description=f'User {identity.username} has been inactive for {inactive_days} days',
                            evidence={'last_login': identity.last_login.isoformat(), 'inactive_days': inactive_days},
                            soc2_controls=['CC6.1', 'CC6.2'],
                            remediation_steps=[
                                f'Review user necessity in {provider_name}',
                                'Disable or remove account if no longer needed',
                                'Update access review procedures'
                            ]
                        )
                        findings.append(finding)
                
                # Check for excessive permissions
                if len(identity.permissions) > 10:  # Configurable threshold
                    finding = ComplianceFinding(
                        finding_id=f"access-{provider_name}-{identity.username}-excessive-perms",
                        finding_type='ACCESS_CONTROL',
                        severity='MEDIUM',
                        cloud_provider=identity.cloud_provider,
                        resource_id=identity.identity_id,
                        resource_type='USER_IDENTITY',
                        account_id=identity.account_id,
                        region='N/A',
                        title=f'Excessive permissions detected in {provider_name}',
                        description=f'User {identity.username} has {len(identity.permissions)} permissions',
                        evidence={'permission_count': len(identity.permissions), 'permissions': identity.permissions[:10]},
                        soc2_controls=['CC6.2'],
                        remediation_steps=[
                            'Review and reduce permissions to minimum required',
                            'Implement principle of least privilege',
                            'Regular access review and cleanup'
                        ]
                    )
                    findings.append(finding)
        
        return findings
    
    def _assess_network_security(self) -> List[ComplianceFinding]:
        """Assess network security across all cloud providers"""
        findings = []
        
        # Collect network rules from all providers
        all_rules = self.collect_multi_cloud_network_rules()
        
        for provider_name, rules in all_rules.items():
            for rule in rules:
                # Check for overly permissive rules
                if ('0.0.0.0/0' in rule.source_addresses and 
                    rule.action == 'ALLOW' and 
                    rule.direction == 'INBOUND'):
                    
                    severity = 'CRITICAL'
                    if 'ssh' in rule.destination_ports or '22' in rule.destination_ports:
                        severity = 'CRITICAL'
                    elif 'rdp' in rule.destination_ports or '3389' in rule.destination_ports:
                        severity = 'CRITICAL'
                    else:
                        severity = 'HIGH'
                    
                    finding = ComplianceFinding(
                        finding_id=f"network-{provider_name}-{rule.rule_id}-open",
                        finding_type='NETWORK_SECURITY',
                        severity=severity,
                        cloud_provider=rule.cloud_provider,
                        resource_id=rule.rule_id,
                        resource_type='NETWORK_SECURITY_RULE',
                        account_id='',  # Would need to extract
                        region='',  # Would need to extract
                        title=f'Overly permissive network rule in {provider_name}',
                        description=f'Rule {rule.rule_name} allows inbound traffic from 0.0.0.0/0',
                        evidence={
                            'source_addresses': rule.source_addresses,
                            'destination_ports': rule.destination_ports,
                            'protocol': rule.protocol
                        },
                        soc2_controls=['CC7.1'],
                        remediation_steps=[
                            'Restrict source IP ranges to specific networks',
                            'Review business justification for open access',
                            'Implement network segmentation'
                        ]
                    )
                    findings.append(finding)
        
        return findings
    
    def _assess_compliance_posture(self) -> List[ComplianceFinding]:
        """Assess overall compliance posture"""
        findings = []
        
        # Check if MFA is enabled for privileged accounts
        all_identities = self.collect_multi_cloud_identities()
        
        for provider_name, identities in all_identities.items():
            privileged_users = [
                identity for identity in identities 
                if any('admin' in role.lower() or 'owner' in role.lower() 
                      for role in identity.roles)
            ]
            
            for user in privileged_users:
                if not user.mfa_enabled:
                    finding = ComplianceFinding(
                        finding_id=f"compliance-{provider_name}-{user.username}-no-mfa",
                        finding_type='COMPLIANCE_CHECK',
                        severity='HIGH',
                        cloud_provider=user.cloud_provider,
                        resource_id=user.identity_id,
                        resource_type='USER_IDENTITY',
                        account_id=user.account_id,
                        region='N/A',
                        title=f'MFA not enabled for privileged user in {provider_name}',
                        description=f'Privileged user {user.username} does not have MFA enabled',
                        evidence={'roles': user.roles, 'mfa_enabled': user.mfa_enabled},
                        soc2_controls=['CC6.1'],
                        remediation_steps=[
                            'Enable MFA for all privileged accounts',
                            'Implement conditional access policies',
                            'Regular privileged access review'
                        ]
                    )
                    findings.append(finding)
        
        return findings
    
    def generate_cross_cloud_report(self, report: CrossCloudReport, output_dir: str = None) -> Dict[str, str]:
        """Generate cross-cloud compliance report"""
        if not output_dir:
            output_dir = SOC2Utils.create_output_directory('cross_cloud_reports')
        
        report_paths = {}
        
        # Generate comprehensive JSON report
        json_data = serialize_dataclass(report)
        json_path = f"{output_dir}/{report.report_id}.json"
        SOC2Utils.write_json_report(json_data, json_path)
        report_paths['json'] = json_path
        
        # Generate executive summary CSV
        csv_data = [{
            'Report_ID': report.report_id,
            'Report_Date': report.report_date.strftime('%Y-%m-%d %H:%M:%S'),
            'Cloud_Providers': ', '.join(report.cloud_providers),
            'SOC2_Controls': ', '.join(report.soc2_controls),
            'Total_Findings': report.summary_statistics.get('total_findings', 0),
            'Critical_Findings': report.findings_summary.get('CRITICAL', 0),
            'High_Findings': report.findings_summary.get('HIGH', 0),
            'Medium_Findings': report.findings_summary.get('MEDIUM', 0),
            'Low_Findings': report.findings_summary.get('LOW', 0)
        }]
        
        csv_path = f"{output_dir}/{report.report_id}_summary.csv"
        SOC2Utils.write_csv_report(csv_data, csv_path)
        report_paths['csv'] = csv_path
        
        # Print summary
        self._print_cross_cloud_summary(report)
        
        return report_paths
    
    def _print_cross_cloud_summary(self, report: CrossCloudReport):
        """Print cross-cloud assessment summary"""
        print(f"\n🌐 Cross-Cloud Compliance Assessment Summary")
        print(f"=" * 60)
        print(f"Report ID: {report.report_id}")
        print(f"Assessment Date: {report.report_date.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Cloud Providers: {', '.join(report.cloud_providers)}")
        print(f"SOC 2 Controls: {', '.join(report.soc2_controls)}")
        print(f"\nFindings Summary:")
        print(f"  🔴 Critical: {report.findings_summary.get('CRITICAL', 0)}")
        print(f"  🟠 High: {report.findings_summary.get('HIGH', 0)}")
        print(f"  🟡 Medium: {report.findings_summary.get('MEDIUM', 0)}")
        print(f"  🟢 Low: {report.findings_summary.get('LOW', 0)}")
        print(f"\nTotal Findings: {report.summary_statistics.get('total_findings', 0)}")