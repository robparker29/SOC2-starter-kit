#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SOC 2 Change Management Evidence Collector
Maps to SOC 2 Common Criteria: CC8.1

This script collects change management evidence for SOC 2 Type II compliance:
- Change request approvals and workflows
- Deployment pipeline configurations
- Rollback procedures and testing evidence
- Post-implementation reviews

Author: Parker Robertson
Purpose: Automate change management evidence collection for SOC 2 audits
"""

import argparse
import datetime
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
import csv
import re

from lib.soc2_collectors import SystemDataCollector
from lib.soc2_models import ChangeManagementEvidence, serialize_dataclass
from lib.soc2_utils import SOC2Utils


class ChangeManagementCollector(SystemDataCollector):
    """Change management evidence collector for SOC 2 compliance"""
    
    def __init__(self, config_path: str):
        """Initialize change management collector"""
        self.config = SOC2Utils.load_json_config(config_path)
        super().__init__(self.config)
        
        # Change management specific configuration
        self.change_config = self.config.get('change_management', {})
        self.supported_systems = ['JIRA', 'ServiceNow', 'GitHub', 'GitLab', 'Azure DevOps']
        self.change_types = ['CODE', 'INFRASTRUCTURE', 'CONFIGURATION', 'SECURITY']
        self.risk_thresholds = {
            'CRITICAL': ['production', 'customer_data', 'security'],
            'HIGH': ['infrastructure', 'database', 'api'],
            'MEDIUM': ['staging', 'development', 'documentation'],
            'LOW': ['minor_fix', 'cosmetic', 'logging']
        }
        
        self.evidence_items = []
        self.collection_date = datetime.datetime.now()
        
    def collect_change_evidence(self, 
                               systems: List[str] = None, 
                               date_range_days: int = 30) -> List[ChangeManagementEvidence]:
        """
        Collect change management evidence from specified systems
        
        Args:
            systems: List of change management systems to collect from
            date_range_days: Number of days back to collect changes
            
        Returns:
            List of ChangeManagementEvidence objects
        """
        self.logger.info("📋 Starting change management evidence collection...")
        
        systems = systems or self.supported_systems
        all_evidence = []
        
        # Calculate date range
        end_date = self.collection_date
        start_date = end_date - datetime.timedelta(days=date_range_days)
        
        self.logger.info(f"Collecting changes from {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}")
        
        # Collect from configured systems
        for system in systems:
            if system.upper() in [s.upper() for s in self.supported_systems]:
                try:
                    system_evidence = self._collect_from_system(system, start_date, end_date)
                    all_evidence.extend(system_evidence)
                    self.logger.info(f"✅ Collected {len(system_evidence)} changes from {system}")
                except Exception as e:
                    self.logger.error(f"Error collecting from {system}: {str(e)}")
        
        # Collect from version control systems
        vcs_evidence = self._collect_from_version_control(start_date, end_date)
        all_evidence.extend(vcs_evidence)
        
        # Collect from CI/CD pipelines
        pipeline_evidence = self._collect_from_pipelines(start_date, end_date)
        all_evidence.extend(pipeline_evidence)
        
        self.evidence_items = all_evidence
        self.logger.info(f"✅ Change management evidence collection complete. Found {len(all_evidence)} changes")
        
        return all_evidence
    
    def _collect_from_system(self, system: str, start_date: datetime.datetime, end_date: datetime.datetime) -> List[ChangeManagementEvidence]:
        """Collect change evidence from specific change management system"""
        evidence = []
        
        if system.upper() == 'JIRA':
            evidence = self._collect_from_jira(start_date, end_date)
        elif system.upper() == 'SERVICENOW':
            evidence = self._collect_from_servicenow(start_date, end_date)
        elif system.upper() == 'GITHUB':
            evidence = self._collect_from_github(start_date, end_date)
        elif system.upper() == 'GITLAB':
            evidence = self._collect_from_gitlab(start_date, end_date)
        elif system.upper() == 'AZURE DEVOPS':
            evidence = self._collect_from_azure_devops(start_date, end_date)
        
        return evidence
    
    def _collect_from_jira(self, start_date: datetime.datetime, end_date: datetime.datetime) -> List[ChangeManagementEvidence]:
        """Collect change evidence from JIRA"""
        evidence = []
        
        try:
            # Load JIRA change records from configuration (in real implementation, this would query JIRA API)
            jira_changes = self.change_config.get('jira_changes', [])
            
            for change_data in jira_changes:
                change_date = self._parse_date(change_data.get('implementation_date'))
                if change_date and start_date <= change_date <= end_date:
                    
                    change_evidence = ChangeManagementEvidence(
                        change_id=change_data.get('issue_key', 'unknown'),
                        change_title=change_data.get('summary', 'Unknown Change'),
                        change_type=self._categorize_change_type(change_data.get('description', '')),
                        change_category=change_data.get('priority', 'STANDARD').upper(),
                        requester=change_data.get('reporter', 'Unknown'),
                        approver=change_data.get('assignee', 'Unknown'),
                        implementation_date=change_date,
                        change_description=change_data.get('description', ''),
                        business_justification=change_data.get('business_justification', ''),
                        risk_assessment=self._assess_change_risk(change_data),
                        rollback_plan=change_data.get('rollback_plan_exists', False),
                        testing_evidence=change_data.get('test_links', []),
                        approval_workflow=self._parse_approval_workflow(change_data.get('approval_history', [])),
                        deployment_method=change_data.get('deployment_method', 'MANUAL'),
                        environment_target=change_data.get('environment', 'PRODUCTION'),
                        systems_affected=change_data.get('systems_affected', []),
                        downtime_required=change_data.get('requires_downtime', False),
                        scheduled_downtime_duration=change_data.get('downtime_duration'),
                        success_criteria=change_data.get('success_criteria', []),
                        post_implementation_review=change_data.get('post_review_completed', False),
                        change_status=change_data.get('status', 'UNKNOWN').upper(),
                        compliance_findings=self._analyze_change_compliance(change_data),
                        soc2_controls=['CC8.1'],
                        evidence_date=self.collection_date,
                        evidence_source='JIRA'
                    )
                    evidence.append(change_evidence)
                    
        except Exception as e:
            self.logger.error(f"Error collecting JIRA change evidence: {str(e)}")
        
        return evidence
    
    def _collect_from_servicenow(self, start_date: datetime.datetime, end_date: datetime.datetime) -> List[ChangeManagementEvidence]:
        """Collect change evidence from ServiceNow"""
        evidence = []
        
        try:
            servicenow_changes = self.change_config.get('servicenow_changes', [])
            
            for change_data in servicenow_changes:
                change_date = self._parse_date(change_data.get('implementation_date'))
                if change_date and start_date <= change_date <= end_date:
                    
                    change_evidence = ChangeManagementEvidence(
                        change_id=change_data.get('change_number', 'unknown'),
                        change_title=change_data.get('short_description', 'Unknown Change'),
                        change_type=change_data.get('type', 'CONFIGURATION'),
                        change_category=change_data.get('category', 'STANDARD').upper(),
                        requester=change_data.get('requested_by', 'Unknown'),
                        approver=change_data.get('approved_by', 'Unknown'),
                        implementation_date=change_date,
                        change_description=change_data.get('description', ''),
                        business_justification=change_data.get('justification', ''),
                        risk_assessment=change_data.get('risk', 'MEDIUM'),
                        rollback_plan=change_data.get('backout_plan') is not None,
                        testing_evidence=change_data.get('test_plan', []),
                        approval_workflow=self._parse_servicenow_approvals(change_data.get('approvals', [])),
                        deployment_method=change_data.get('implementation_method', 'MANUAL'),
                        environment_target=change_data.get('environment', 'PRODUCTION'),
                        systems_affected=change_data.get('affected_cis', []),
                        downtime_required=change_data.get('outage_required', False),
                        scheduled_downtime_duration=change_data.get('outage_duration'),
                        success_criteria=change_data.get('success_criteria', []),
                        post_implementation_review=change_data.get('review_completed', False),
                        change_status=change_data.get('state', 'UNKNOWN').upper(),
                        compliance_findings=self._analyze_servicenow_compliance(change_data),
                        soc2_controls=['CC8.1'],
                        evidence_date=self.collection_date,
                        evidence_source='ServiceNow'
                    )
                    evidence.append(change_evidence)
                    
        except Exception as e:
            self.logger.error(f"Error collecting ServiceNow change evidence: {str(e)}")
        
        return evidence
    
    def _collect_from_version_control(self, start_date: datetime.datetime, end_date: datetime.datetime) -> List[ChangeManagementEvidence]:
        """Collect change evidence from version control systems"""
        evidence = []
        
        try:
            # Collect from Git repositories
            git_repos = self.change_config.get('git_repositories', [])
            
            for repo_config in git_repos:
                repo_evidence = self._collect_git_changes(repo_config, start_date, end_date)
                evidence.extend(repo_evidence)
                
        except Exception as e:
            self.logger.error(f"Error collecting version control evidence: {str(e)}")
        
        return evidence
    
    def _collect_git_changes(self, repo_config: Dict[str, Any], start_date: datetime.datetime, end_date: datetime.datetime) -> List[ChangeManagementEvidence]:
        """Collect changes from Git repository"""
        evidence = []
        
        try:
            # Load git commits from configuration (in real implementation, this would query Git API)
            commits = repo_config.get('recent_commits', [])
            
            for commit_data in commits:
                commit_date = self._parse_date(commit_data.get('date'))
                if commit_date and start_date <= commit_date <= end_date:
                    
                    # Determine if this is a production deployment
                    is_production_change = self._is_production_deployment(commit_data, repo_config)
                    
                    if is_production_change:
                        change_evidence = ChangeManagementEvidence(
                            change_id=f"{repo_config.get('name', 'unknown')}-{commit_data.get('sha', 'unknown')[:8]}",
                            change_title=commit_data.get('message', 'Unknown Commit').split('\\n')[0],
                            change_type='CODE',
                            change_category=self._categorize_commit(commit_data),
                            requester=commit_data.get('author', 'Unknown'),
                            approver=commit_data.get('merger', commit_data.get('author', 'Unknown')),
                            implementation_date=commit_date,
                            change_description=commit_data.get('message', ''),
                            business_justification=self._extract_business_justification(commit_data),
                            risk_assessment=self._assess_commit_risk(commit_data),
                            rollback_plan=True,  # Git always allows rollback
                            testing_evidence=self._extract_test_evidence(commit_data),
                            approval_workflow=self._parse_git_approvals(commit_data),
                            deployment_method='AUTOMATED',
                            environment_target='PRODUCTION',
                            systems_affected=[repo_config.get('name', 'unknown')],
                            downtime_required=False,  # Assume zero-downtime deployments
                            scheduled_downtime_duration=None,
                            success_criteria=self._extract_success_criteria(commit_data),
                            post_implementation_review=commit_data.get('has_post_review', False),
                            change_status='IMPLEMENTED',
                            compliance_findings=self._analyze_git_compliance(commit_data),
                            soc2_controls=['CC8.1'],
                            evidence_date=self.collection_date,
                            evidence_source=f"Git - {repo_config.get('name', 'unknown')}"
                        )
                        evidence.append(change_evidence)
                        
        except Exception as e:
            self.logger.error(f"Error collecting Git changes from {repo_config.get('name', 'unknown')}: {str(e)}")
        
        return evidence
    
    def _collect_from_pipelines(self, start_date: datetime.datetime, end_date: datetime.datetime) -> List[ChangeManagementEvidence]:
        """Collect change evidence from CI/CD pipelines"""
        evidence = []
        
        try:
            # Collect from various CI/CD systems
            pipeline_systems = self.change_config.get('cicd_systems', [])
            
            for system_config in pipeline_systems:
                system_type = system_config.get('type', '').upper()
                
                if system_type == 'JENKINS':
                    system_evidence = self._collect_jenkins_deployments(system_config, start_date, end_date)
                elif system_type == 'GITHUB_ACTIONS':
                    system_evidence = self._collect_github_actions(system_config, start_date, end_date)
                elif system_type == 'AZURE_PIPELINES':
                    system_evidence = self._collect_azure_pipelines(system_config, start_date, end_date)
                else:
                    system_evidence = []
                
                evidence.extend(system_evidence)
                
        except Exception as e:
            self.logger.error(f"Error collecting CI/CD pipeline evidence: {str(e)}")
        
        return evidence
    
    def _collect_jenkins_deployments(self, config: Dict[str, Any], start_date: datetime.datetime, end_date: datetime.datetime) -> List[ChangeManagementEvidence]:
        """Collect Jenkins deployment evidence"""
        evidence = []
        
        try:
            deployments = config.get('recent_deployments', [])
            
            for deployment in deployments:
                deploy_date = self._parse_date(deployment.get('timestamp'))
                if deploy_date and start_date <= deploy_date <= end_date:
                    
                    change_evidence = ChangeManagementEvidence(
                        change_id=f"jenkins-{deployment.get('build_number', 'unknown')}",
                        change_title=f"Jenkins Deployment - {deployment.get('job_name', 'Unknown Job')}",
                        change_type='INFRASTRUCTURE',
                        change_category='AUTOMATED',
                        requester=deployment.get('triggered_by', 'System'),
                        approver=deployment.get('approved_by', 'Automated'),
                        implementation_date=deploy_date,
                        change_description=deployment.get('description', ''),
                        business_justification='Automated deployment pipeline',
                        risk_assessment=self._assess_deployment_risk(deployment),
                        rollback_plan=deployment.get('rollback_available', True),
                        testing_evidence=deployment.get('test_results', []),
                        approval_workflow=[],  # Jenkins typically doesn't have manual approvals
                        deployment_method='AUTOMATED',
                        environment_target=deployment.get('environment', 'PRODUCTION'),
                        systems_affected=deployment.get('affected_services', []),
                        downtime_required=deployment.get('requires_downtime', False),
                        scheduled_downtime_duration=deployment.get('downtime_window'),
                        success_criteria=deployment.get('success_criteria', []),
                        post_implementation_review=deployment.get('post_deploy_check', False),
                        change_status=deployment.get('result', 'UNKNOWN').upper(),
                        compliance_findings=self._analyze_jenkins_compliance(deployment),
                        soc2_controls=['CC8.1'],
                        evidence_date=self.collection_date,
                        evidence_source='Jenkins'
                    )
                    evidence.append(change_evidence)
                    
        except Exception as e:
            self.logger.error(f"Error collecting Jenkins deployment evidence: {str(e)}")
        
        return evidence
    
    # Helper methods for data parsing and analysis
    def _categorize_change_type(self, description: str) -> str:
        """Categorize change type based on description"""
        description_lower = description.lower()
        
        if any(keyword in description_lower for keyword in ['code', 'function', 'method', 'class']):
            return 'CODE'
        elif any(keyword in description_lower for keyword in ['infrastructure', 'server', 'network', 'cloud']):
            return 'INFRASTRUCTURE'
        elif any(keyword in description_lower for keyword in ['config', 'setting', 'parameter']):
            return 'CONFIGURATION'
        elif any(keyword in description_lower for keyword in ['security', 'auth', 'permission', 'access']):
            return 'SECURITY'
        else:
            return 'CONFIGURATION'
    
    def _assess_change_risk(self, change_data: Dict[str, Any]) -> str:
        """Assess risk level of change"""
        description = change_data.get('description', '').lower()
        environment = change_data.get('environment', '').lower()
        systems = ' '.join(change_data.get('systems_affected', [])).lower()
        
        # Check for critical risk indicators
        for risk_level, keywords in self.risk_thresholds.items():
            if any(keyword in description or keyword in environment or keyword in systems 
                   for keyword in keywords):
                return risk_level
        
        return 'MEDIUM'
    
    def _parse_approval_workflow(self, approval_history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse approval workflow from change data"""
        workflow = []
        
        for approval in approval_history:
            workflow.append({
                'approver': approval.get('approver', 'Unknown'),
                'approval_date': approval.get('date'),
                'status': approval.get('status', 'APPROVED'),
                'comments': approval.get('comments', '')
            })
        
        return workflow
    
    def _analyze_change_compliance(self, change_data: Dict[str, Any]) -> List[str]:
        """Analyze change for compliance issues"""
        findings = []
        
        # Check for missing approval
        if not change_data.get('approval_history'):
            findings.append('No approval history documented')
        
        # Check for missing rollback plan
        if not change_data.get('rollback_plan_exists', False):
            findings.append('Rollback plan not documented')
        
        # Check for missing testing evidence
        if not change_data.get('test_links'):
            findings.append('Testing evidence not provided')
        
        # Check for post-implementation review
        if not change_data.get('post_review_completed', False):
            findings.append('Post-implementation review not completed')
        
        return findings
    
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
    
    def _is_production_deployment(self, commit_data: Dict[str, Any], repo_config: Dict[str, Any]) -> bool:
        """Determine if commit represents a production deployment"""
        # Check if this commit was deployed to production
        deploy_branches = repo_config.get('production_branches', ['main', 'master', 'production'])
        branch = commit_data.get('branch', 'unknown')
        
        return branch in deploy_branches
    
    def _categorize_commit(self, commit_data: Dict[str, Any]) -> str:
        """Categorize commit based on message"""
        message = commit_data.get('message', '').lower()
        
        if any(keyword in message for keyword in ['hotfix', 'critical', 'urgent']):
            return 'EMERGENCY'
        elif any(keyword in message for keyword in ['feat', 'feature', 'enhancement']):
            return 'STANDARD'
        else:
            return 'PRE_APPROVED'
    
    def _extract_business_justification(self, commit_data: Dict[str, Any]) -> str:
        """Extract business justification from commit"""
        message = commit_data.get('message', '')
        # Look for patterns like "Business justification:" or "Reason:"
        for line in message.split('\\n'):
            if any(keyword in line.lower() for keyword in ['justification', 'reason', 'purpose']):
                return line.strip()
        
        return 'See commit message for details'
    
    def _assess_commit_risk(self, commit_data: Dict[str, Any]) -> str:
        """Assess risk level of commit"""
        files_changed = commit_data.get('files_changed', [])
        additions = commit_data.get('additions', 0)
        deletions = commit_data.get('deletions', 0)
        
        # High risk indicators
        if any('security' in f.lower() or 'auth' in f.lower() for f in files_changed):
            return 'HIGH'
        
        if additions + deletions > 500:
            return 'HIGH'
        
        if len(files_changed) > 20:
            return 'MEDIUM'
        
        return 'LOW'
    
    def generate_evidence_report(self, output_dir: str = None) -> str:
        """Generate change management evidence report"""
        output_dir = output_dir or self.config.get('global_settings', {}).get('output_directory', 'soc2_reports')
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = self.collection_date.strftime('%Y%m%d_%H%M%S')
        report_file = os.path.join(output_dir, f'change_management_evidence_{timestamp}.csv')
        
        with open(report_file, 'w', newline='', encoding='utf-8') as csvfile:
            if not self.evidence_items:
                csvfile.write("No change management evidence collected\\n")
                return report_file
            
            fieldnames = [
                'change_id', 'change_title', 'change_type', 'change_category',
                'requester', 'approver', 'implementation_date', 'risk_assessment',
                'rollback_plan', 'deployment_method', 'environment_target',
                'change_status', 'compliance_findings', 'soc2_controls', 'evidence_source'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for evidence in self.evidence_items:
                row = {
                    'change_id': evidence.change_id,
                    'change_title': evidence.change_title,
                    'change_type': evidence.change_type,
                    'change_category': evidence.change_category,
                    'requester': evidence.requester,
                    'approver': evidence.approver,
                    'implementation_date': evidence.implementation_date.isoformat() if evidence.implementation_date else '',
                    'risk_assessment': evidence.risk_assessment,
                    'rollback_plan': evidence.rollback_plan,
                    'deployment_method': evidence.deployment_method,
                    'environment_target': evidence.environment_target,
                    'change_status': evidence.change_status,
                    'compliance_findings': '; '.join(evidence.compliance_findings),
                    'soc2_controls': '; '.join(evidence.soc2_controls),
                    'evidence_source': evidence.evidence_source
                }
                writer.writerow(row)
        
        # Also generate JSON report
        json_file = os.path.join(output_dir, f'change_management_evidence_{timestamp}.json')
        with open(json_file, 'w', encoding='utf-8') as jsonfile:
            evidence_data = [serialize_dataclass(evidence) for evidence in self.evidence_items]
            json.dump(evidence_data, jsonfile, indent=2, default=str)
        
        self.logger.info(f"Change management evidence report generated: {report_file}")
        return report_file


def main():
    """Main entry point for change management collector"""
    parser = argparse.ArgumentParser(
        description='SOC 2 Change Management Evidence Collector',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--config', required=True,
                       help='Path to SOC 2 configuration file')
    parser.add_argument('--output-dir',
                       help='Output directory for evidence reports')
    parser.add_argument('--systems', nargs='*',
                       choices=['JIRA', 'ServiceNow', 'GitHub', 'GitLab', 'Azure DevOps'],
                       help='Specific change management systems to collect from')
    parser.add_argument('--days', type=int, default=30,
                       help='Number of days back to collect changes (default: 30)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Initialize collector
    collector = ChangeManagementCollector(args.config)
    
    if args.verbose:
        collector.logger.setLevel('DEBUG')
    
    try:
        # Collect evidence
        evidence = collector.collect_change_evidence(args.systems, args.days)
        
        # Generate report
        report_file = collector.generate_evidence_report(args.output_dir)
        
        print(f"\\n📋 Change Management Evidence Collection Complete!")
        print(f"📊 Collected evidence for {len(evidence)} changes")
        
        # Summary by change type and risk
        type_summary = {}
        risk_summary = {}
        for item in evidence:
            change_type = item.change_type
            risk = item.risk_assessment
            type_summary[change_type] = type_summary.get(change_type, 0) + 1
            risk_summary[risk] = risk_summary.get(risk, 0) + 1
        
        print(f"\\n📈 Change Type Summary:")
        for change_type, count in sorted(type_summary.items()):
            print(f"  {change_type}: {count} changes")
        
        print(f"\\n🎯 Risk Level Summary:")
        for risk, count in sorted(risk_summary.items()):
            print(f"  {risk}: {count} changes")
        
        print(f"\\n📁 Report saved to: {report_file}")
        
        return 0
        
    except Exception as e:
        collector.logger.error(f"Change management evidence collection failed: {str(e)}")
        print(f"❌ Error: {str(e)}")
        return 1


if __name__ == "__main__":
    exit(main())