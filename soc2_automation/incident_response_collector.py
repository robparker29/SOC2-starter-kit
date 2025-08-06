#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SOC 2 Incident Response Evidence Compiler
Maps to SOC 2 Common Criteria: CC7.3, CC7.4, CC7.5

This script compiles security incident response evidence for SOC 2 Type II compliance:
- Security incident logs and response records
- Communication logs and resolution timelines
- Root cause analysis and lessons learned
- Regulatory notification records

Author: Parker Robertson
Purpose: Automate incident response evidence collection for SOC 2 audits
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
from lib.soc2_models import IncidentResponseEvidence, serialize_dataclass
from lib.soc2_utils import SOC2Utils


class IncidentResponseCollector(SystemDataCollector):
    """Security incident response evidence collector for SOC 2 compliance"""
    
    def __init__(self, config_path: str):
        """Initialize incident response collector"""
        self.config = SOC2Utils.load_json_config(config_path)
        super().__init__(self.config)
        
        # Incident response specific configuration
        self.incident_config = self.config.get('incident_response', {})
        self.supported_systems = ['PagerDuty', 'Jira Service Management', 'ServiceNow', 'Splunk', 'Slack']
        self.incident_types = ['SECURITY_BREACH', 'DATA_BREACH', 'SYSTEM_OUTAGE', 'MALWARE', 'UNAUTHORIZED_ACCESS']
        self.severity_levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        
        # Response time thresholds (in minutes)
        self.response_time_thresholds = {
            'CRITICAL': 15,
            'HIGH': 60,
            'MEDIUM': 240,
            'LOW': 1440
        }
        
        self.evidence_items = []
        self.collection_date = datetime.datetime.now()
        
    def collect_incident_evidence(self, 
                                systems: List[str] = None, 
                                date_range_days: int = 90) -> List[IncidentResponseEvidence]:
        """
        Collect incident response evidence from specified systems
        
        Args:
            systems: List of incident management systems to collect from
            date_range_days: Number of days back to collect incidents
            
        Returns:
            List of IncidentResponseEvidence objects
        """
        self.logger.info("🚨 Starting incident response evidence collection...")
        
        systems = systems or self.supported_systems
        all_evidence = []
        
        # Calculate date range
        end_date = self.collection_date
        start_date = end_date - datetime.timedelta(days=date_range_days)
        
        self.logger.info(f"Collecting incidents from {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}")
        
        # Collect from configured incident management systems
        for system in systems:
            if system in self.supported_systems:
                try:
                    system_evidence = self._collect_from_system(system, start_date, end_date)
                    all_evidence.extend(system_evidence)
                    self.logger.info(f"✅ Collected {len(system_evidence)} incidents from {system}")
                except Exception as e:
                    self.logger.error(f"Error collecting from {system}: {str(e)}")
        
        # Collect from security logs and SIEM
        siem_evidence = self._collect_from_siem(start_date, end_date)
        all_evidence.extend(siem_evidence)
        
        # Collect from communication platforms
        comm_evidence = self._collect_from_communications(start_date, end_date)
        all_evidence.extend(comm_evidence)
        
        self.evidence_items = all_evidence
        self.logger.info(f"✅ Incident response evidence collection complete. Found {len(all_evidence)} incidents")
        
        return all_evidence
    
    def _collect_from_system(self, system: str, start_date: datetime.datetime, end_date: datetime.datetime) -> List[IncidentResponseEvidence]:
        """Collect incident evidence from specific incident management system"""
        evidence = []
        
        if system == 'PagerDuty':
            evidence = self._collect_from_pagerduty(start_date, end_date)
        elif system == 'Jira Service Management':
            evidence = self._collect_from_jira_sm(start_date, end_date)
        elif system == 'ServiceNow':
            evidence = self._collect_from_servicenow_incidents(start_date, end_date)
        elif system == 'Splunk':
            evidence = self._collect_from_splunk(start_date, end_date)
        elif system == 'Slack':
            evidence = self._collect_from_slack(start_date, end_date)
        
        return evidence
    
    def _collect_from_pagerduty(self, start_date: datetime.datetime, end_date: datetime.datetime) -> List[IncidentResponseEvidence]:
        """Collect incident evidence from PagerDuty"""
        evidence = []
        
        try:
            # Load PagerDuty incidents from configuration (in real implementation, this would query PagerDuty API)
            pagerduty_incidents = self.incident_config.get('pagerduty_incidents', [])
            
            for incident_data in pagerduty_incidents:
                incident_date = self._parse_date(incident_data.get('created_at'))
                if incident_date and start_date <= incident_date <= end_date:
                    
                    # Only collect security-related incidents
                    if self._is_security_incident(incident_data):
                        incident_evidence = IncidentResponseEvidence(
                            incident_id=incident_data.get('id', 'unknown'),
                            incident_title=incident_data.get('title', 'Unknown Incident'),
                            incident_type=self._categorize_incident_type(incident_data.get('description', '')),
                            severity_level=incident_data.get('urgency', 'MEDIUM').upper(),
                            detection_date=incident_date,
                            detection_method='AUTOMATED_ALERT',
                            initial_responder=incident_data.get('assigned_to', 'Unknown'),
                            incident_commander=incident_data.get('incident_commander', incident_data.get('assigned_to', 'Unknown')),
                            affected_systems=incident_data.get('affected_services', []),
                            affected_data_types=self._identify_data_types(incident_data),
                            potential_impact=incident_data.get('summary', ''),
                            containment_actions=self._parse_timeline_actions(incident_data.get('timeline', []), 'containment'),
                            eradication_actions=self._parse_timeline_actions(incident_data.get('timeline', []), 'eradication'),
                            recovery_actions=self._parse_timeline_actions(incident_data.get('timeline', []), 'recovery'),
                            communication_log=self._parse_communication_log(incident_data.get('log_entries', [])),
                            regulatory_notifications=self._extract_regulatory_notifications(incident_data),
                            customer_notifications=incident_data.get('customer_notified', False),
                            incident_status=incident_data.get('status', 'open').upper(),
                            resolution_date=self._parse_date(incident_data.get('resolved_at')),
                            total_resolution_time=self._calculate_resolution_time(incident_data),
                            root_cause_analysis=incident_data.get('root_cause', ''),
                            lessons_learned=incident_data.get('lessons_learned', []),
                            preventive_measures=incident_data.get('preventive_actions', []),
                            compliance_findings=self._analyze_incident_compliance(incident_data),
                            soc2_controls=['CC7.3', 'CC7.4', 'CC7.5'],
                            evidence_date=self.collection_date,
                            evidence_source='PagerDuty'
                        )
                        evidence.append(incident_evidence)
                        
        except Exception as e:
            self.logger.error(f"Error collecting PagerDuty incident evidence: {str(e)}")
        
        return evidence
    
    def _collect_from_jira_sm(self, start_date: datetime.datetime, end_date: datetime.datetime) -> List[IncidentResponseEvidence]:
        """Collect incident evidence from Jira Service Management"""
        evidence = []
        
        try:
            jira_incidents = self.incident_config.get('jira_incidents', [])
            
            for incident_data in jira_incidents:
                incident_date = self._parse_date(incident_data.get('created'))
                if incident_date and start_date <= incident_date <= end_date:
                    
                    if self._is_security_incident(incident_data):
                        incident_evidence = IncidentResponseEvidence(
                            incident_id=incident_data.get('key', 'unknown'),
                            incident_title=incident_data.get('summary', 'Unknown Incident'),
                            incident_type=self._categorize_incident_type(incident_data.get('description', '')),
                            severity_level=incident_data.get('priority', 'Medium').upper(),
                            detection_date=incident_date,
                            detection_method=self._determine_detection_method(incident_data),
                            initial_responder=incident_data.get('assignee', 'Unknown'),
                            incident_commander=incident_data.get('incident_commander', incident_data.get('assignee', 'Unknown')),
                            affected_systems=incident_data.get('affected_systems', []),
                            affected_data_types=self._identify_data_types(incident_data),
                            potential_impact=incident_data.get('impact_description', ''),
                            containment_actions=self._parse_jira_actions(incident_data.get('containment_steps', [])),
                            eradication_actions=self._parse_jira_actions(incident_data.get('eradication_steps', [])),
                            recovery_actions=self._parse_jira_actions(incident_data.get('recovery_steps', [])),
                            communication_log=self._parse_jira_comments(incident_data.get('comments', [])),
                            regulatory_notifications=self._extract_regulatory_notifications(incident_data),
                            customer_notifications=incident_data.get('customer_communication', False),
                            incident_status=incident_data.get('status', 'Open').upper(),
                            resolution_date=self._parse_date(incident_data.get('resolved')),
                            total_resolution_time=self._calculate_jira_resolution_time(incident_data),
                            root_cause_analysis=incident_data.get('root_cause_analysis', ''),
                            lessons_learned=incident_data.get('lessons_learned', []),
                            preventive_measures=incident_data.get('corrective_actions', []),
                            compliance_findings=self._analyze_incident_compliance(incident_data),
                            soc2_controls=['CC7.3', 'CC7.4', 'CC7.5'],
                            evidence_date=self.collection_date,
                            evidence_source='Jira Service Management'
                        )
                        evidence.append(incident_evidence)
                        
        except Exception as e:
            self.logger.error(f"Error collecting Jira Service Management incident evidence: {str(e)}")
        
        return evidence
    
    def _collect_from_siem(self, start_date: datetime.datetime, end_date: datetime.datetime) -> List[IncidentResponseEvidence]:
        """Collect incident evidence from SIEM systems"""
        evidence = []
        
        try:
            siem_alerts = self.incident_config.get('siem_alerts', [])
            
            for alert_data in siem_alerts:
                alert_date = self._parse_date(alert_data.get('timestamp'))
                if alert_date and start_date <= alert_date <= end_date:
                    
                    # Only high-severity alerts that triggered incident response
                    if alert_data.get('severity', '').upper() in ['HIGH', 'CRITICAL'] and alert_data.get('incident_created', False):
                        incident_evidence = IncidentResponseEvidence(
                            incident_id=f"siem-{alert_data.get('alert_id', 'unknown')}",
                            incident_title=alert_data.get('rule_name', 'SIEM Alert'),
                            incident_type=self._map_siem_to_incident_type(alert_data.get('category', '')),
                            severity_level=alert_data.get('severity', 'MEDIUM').upper(),
                            detection_date=alert_date,
                            detection_method='AUTOMATED_ALERT',
                            initial_responder=alert_data.get('analyst_assigned', 'SOC Team'),
                            incident_commander=alert_data.get('incident_lead', 'Unknown'),
                            affected_systems=alert_data.get('affected_hosts', []),
                            affected_data_types=self._analyze_siem_data_types(alert_data),
                            potential_impact=alert_data.get('description', ''),
                            containment_actions=self._parse_siem_response_actions(alert_data.get('response_actions', [])),
                            eradication_actions=[],  # SIEM typically doesn't track detailed response actions
                            recovery_actions=[],
                            communication_log=[],
                            regulatory_notifications=[],
                            customer_notifications=False,
                            incident_status=alert_data.get('status', 'OPEN').upper(),
                            resolution_date=self._parse_date(alert_data.get('closed_time')),
                            total_resolution_time=self._calculate_siem_resolution_time(alert_data),
                            root_cause_analysis=alert_data.get('analysis', ''),
                            lessons_learned=[],
                            preventive_measures=[],
                            compliance_findings=self._analyze_siem_compliance(alert_data),
                            soc2_controls=['CC7.3'],  # SIEM primarily covers detection
                            evidence_date=self.collection_date,
                            evidence_source=f"SIEM - {alert_data.get('source_system', 'Unknown')}"
                        )
                        evidence.append(incident_evidence)
                        
        except Exception as e:
            self.logger.error(f"Error collecting SIEM incident evidence: {str(e)}")
        
        return evidence
    
    def _collect_from_communications(self, start_date: datetime.datetime, end_date: datetime.datetime) -> List[IncidentResponseEvidence]:
        """Collect incident evidence from communication platforms"""
        evidence = []
        
        try:
            # Collect from Slack incident channels
            slack_incidents = self.incident_config.get('slack_incident_channels', [])
            
            for channel_data in slack_incidents:
                incident_date = self._parse_date(channel_data.get('created'))
                if incident_date and start_date <= incident_date <= end_date:
                    
                    incident_evidence = IncidentResponseEvidence(
                        incident_id=f"slack-{channel_data.get('channel_id', 'unknown')}",
                        incident_title=channel_data.get('incident_title', 'Slack Incident Channel'),
                        incident_type=self._categorize_incident_type(channel_data.get('description', '')),
                        severity_level=channel_data.get('severity', 'MEDIUM').upper(),
                        detection_date=incident_date,
                        detection_method='USER_REPORT',
                        initial_responder=channel_data.get('incident_lead', 'Unknown'),
                        incident_commander=channel_data.get('incident_commander', 'Unknown'),
                        affected_systems=channel_data.get('affected_services', []),
                        affected_data_types=[],
                        potential_impact=channel_data.get('impact_summary', ''),
                        containment_actions=self._parse_slack_actions(channel_data.get('messages', []), 'containment'),
                        eradication_actions=self._parse_slack_actions(channel_data.get('messages', []), 'eradication'),
                        recovery_actions=self._parse_slack_actions(channel_data.get('messages', []), 'recovery'),
                        communication_log=self._parse_slack_communications(channel_data.get('messages', [])),
                        regulatory_notifications=[],
                        customer_notifications=channel_data.get('customer_update_sent', False),
                        incident_status=channel_data.get('status', 'OPEN').upper(),
                        resolution_date=self._parse_date(channel_data.get('resolved_time')),
                        total_resolution_time=self._calculate_slack_resolution_time(channel_data),
                        root_cause_analysis=channel_data.get('postmortem_summary', ''),
                        lessons_learned=channel_data.get('lessons_learned', []),
                        preventive_measures=channel_data.get('action_items', []),
                        compliance_findings=self._analyze_slack_compliance(channel_data),
                        soc2_controls=['CC7.4', 'CC7.5'],  # Communication and recovery
                        evidence_date=self.collection_date,
                        evidence_source='Slack'
                    )
                    evidence.append(incident_evidence)
                    
        except Exception as e:
            self.logger.error(f"Error collecting communication platform incident evidence: {str(e)}")
        
        return evidence
    
    # Helper methods for data parsing and analysis
    def _is_security_incident(self, incident_data: Dict[str, Any]) -> bool:
        """Determine if incident is security-related"""
        title = incident_data.get('title', '').lower()
        description = incident_data.get('description', '').lower()
        tags = ' '.join(incident_data.get('tags', [])).lower()
        
        security_keywords = [
            'security', 'breach', 'unauthorized', 'malware', 'phishing', 
            'attack', 'vulnerability', 'intrusion', 'suspicious'
        ]
        
        return any(keyword in title or keyword in description or keyword in tags 
                  for keyword in security_keywords)
    
    def _categorize_incident_type(self, description: str) -> str:
        """Categorize incident type based on description"""
        description_lower = description.lower()
        
        if any(keyword in description_lower for keyword in ['breach', 'unauthorized access', 'data compromise']):
            return 'SECURITY_BREACH'
        elif any(keyword in description_lower for keyword in ['data breach', 'data leak', 'data exposure']):
            return 'DATA_BREACH'
        elif any(keyword in description_lower for keyword in ['malware', 'virus', 'trojan', 'ransomware']):
            return 'MALWARE'
        elif any(keyword in description_lower for keyword in ['outage', 'down', 'unavailable']):
            return 'SYSTEM_OUTAGE'
        else:
            return 'UNAUTHORIZED_ACCESS'
    
    def _identify_data_types(self, incident_data: Dict[str, Any]) -> List[str]:
        """Identify types of data potentially affected"""
        description = incident_data.get('description', '').lower()
        affected_systems = ' '.join(incident_data.get('affected_systems', [])).lower()
        
        data_types = []
        
        if any(keyword in description or keyword in affected_systems 
               for keyword in ['customer', 'user', 'profile']):
            data_types.append('CUSTOMER_DATA')
        
        if any(keyword in description or keyword in affected_systems 
               for keyword in ['employee', 'hr', 'payroll']):
            data_types.append('EMPLOYEE_DATA')
        
        if any(keyword in description or keyword in affected_systems 
               for keyword in ['payment', 'financial', 'credit card', 'billing']):
            data_types.append('FINANCIAL_DATA')
        
        if any(keyword in description or keyword in affected_systems 
               for keyword in ['health', 'medical', 'phi']):
            data_types.append('HEALTH_DATA')
        
        return data_types
    
    def _parse_timeline_actions(self, timeline: List[Dict[str, Any]], action_type: str) -> List[Dict[str, Any]]:
        """Parse actions from incident timeline"""
        actions = []
        
        for entry in timeline:
            if action_type.lower() in entry.get('type', '').lower():
                actions.append({
                    'action': entry.get('summary', ''),
                    'timestamp': entry.get('at'),
                    'user': entry.get('user', 'Unknown'),
                    'details': entry.get('details', '')
                })
        
        return actions
    
    def _parse_communication_log(self, log_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse communication log from incident data"""
        communications = []
        
        for entry in log_entries:
            if entry.get('type') == 'notification' or 'communic' in entry.get('summary', '').lower():
                communications.append({
                    'timestamp': entry.get('created_at'),
                    'type': entry.get('channel', 'INTERNAL'),
                    'recipient': entry.get('user', 'Unknown'),
                    'message': entry.get('summary', ''),
                    'method': entry.get('notification_type', 'EMAIL')
                })
        
        return communications
    
    def _extract_regulatory_notifications(self, incident_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract regulatory notification information"""
        notifications = []
        
        # Look for breach notification indicators
        if incident_data.get('data_breach_notification', False):
            notifications.append({
                'regulator': incident_data.get('notification_authority', 'Unknown'),
                'notification_date': incident_data.get('notification_date'),
                'notification_type': 'DATA_BREACH',
                'status': incident_data.get('notification_status', 'PENDING')
            })
        
        return notifications
    
    def _calculate_resolution_time(self, incident_data: Dict[str, Any]) -> Optional[str]:
        """Calculate total resolution time"""
        created_at = self._parse_date(incident_data.get('created_at'))
        resolved_at = self._parse_date(incident_data.get('resolved_at'))
        
        if created_at and resolved_at:
            duration = resolved_at - created_at
            hours = duration.total_seconds() / 3600
            return f"{hours:.1f} hours"
        
        return None
    
    def _analyze_incident_compliance(self, incident_data: Dict[str, Any]) -> List[str]:
        """Analyze incident for compliance issues"""
        findings = []
        
        # Check response time
        severity = incident_data.get('severity', '').upper()
        if severity in self.response_time_thresholds:
            created_at = self._parse_date(incident_data.get('created_at'))
            first_response = self._parse_date(incident_data.get('first_response_at'))
            
            if created_at and first_response:
                response_time_minutes = (first_response - created_at).total_seconds() / 60
                threshold = self.response_time_thresholds[severity]
                
                if response_time_minutes > threshold:
                    findings.append(f'Response time exceeded threshold: {response_time_minutes:.0f} min > {threshold} min')
        
        # Check for missing documentation
        if not incident_data.get('root_cause'):
            findings.append('Root cause analysis not documented')
        
        if not incident_data.get('lessons_learned'):
            findings.append('Lessons learned not documented')
        
        # Check for data breach notification requirements
        if self._is_potential_data_breach(incident_data) and not incident_data.get('data_breach_notification'):
            findings.append('Potential data breach - regulatory notification not documented')
        
        return findings
    
    def _is_potential_data_breach(self, incident_data: Dict[str, Any]) -> bool:
        """Determine if incident is a potential data breach"""
        data_types = self._identify_data_types(incident_data)
        incident_type = self._categorize_incident_type(incident_data.get('description', ''))
        
        return (incident_type in ['DATA_BREACH', 'SECURITY_BREACH'] and 
                any(dt in ['CUSTOMER_DATA', 'FINANCIAL_DATA', 'HEALTH_DATA'] for dt in data_types))
    
    def _parse_date(self, date_string: Optional[str]) -> Optional[datetime.datetime]:
        """Parse date string to datetime object"""
        if not date_string:
            return None
        
        try:
            if 'T' in date_string:
                return datetime.datetime.fromisoformat(date_string.replace('Z', '+00:00'))
            else:
                return datetime.datetime.strptime(date_string, '%Y-%m-%d %H:%M:%S')
        except Exception:
            return None
    
    def generate_evidence_report(self, output_dir: str = None) -> str:
        """Generate incident response evidence report"""
        output_dir = output_dir or self.config.get('global_settings', {}).get('output_directory', 'soc2_reports')
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = self.collection_date.strftime('%Y%m%d_%H%M%S')
        report_file = os.path.join(output_dir, f'incident_response_evidence_{timestamp}.csv')
        
        with open(report_file, 'w', newline='', encoding='utf-8') as csvfile:
            if not self.evidence_items:
                csvfile.write("No incident response evidence collected\\n")
                return report_file
            
            fieldnames = [
                'incident_id', 'incident_title', 'incident_type', 'severity_level',
                'detection_date', 'detection_method', 'initial_responder', 'incident_commander',
                'incident_status', 'resolution_date', 'total_resolution_time',
                'affected_systems', 'affected_data_types', 'customer_notifications',
                'compliance_findings', 'soc2_controls', 'evidence_source'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for evidence in self.evidence_items:
                row = {
                    'incident_id': evidence.incident_id,
                    'incident_title': evidence.incident_title,
                    'incident_type': evidence.incident_type,
                    'severity_level': evidence.severity_level,
                    'detection_date': evidence.detection_date.isoformat() if evidence.detection_date else '',
                    'detection_method': evidence.detection_method,
                    'initial_responder': evidence.initial_responder,
                    'incident_commander': evidence.incident_commander,
                    'incident_status': evidence.incident_status,
                    'resolution_date': evidence.resolution_date.isoformat() if evidence.resolution_date else '',
                    'total_resolution_time': evidence.total_resolution_time or '',
                    'affected_systems': '; '.join(evidence.affected_systems),
                    'affected_data_types': '; '.join(evidence.affected_data_types),
                    'customer_notifications': evidence.customer_notifications,
                    'compliance_findings': '; '.join(evidence.compliance_findings),
                    'soc2_controls': '; '.join(evidence.soc2_controls),
                    'evidence_source': evidence.evidence_source
                }
                writer.writerow(row)
        
        # Also generate JSON report
        json_file = os.path.join(output_dir, f'incident_response_evidence_{timestamp}.json')
        with open(json_file, 'w', encoding='utf-8') as jsonfile:
            evidence_data = [serialize_dataclass(evidence) for evidence in self.evidence_items]
            json.dump(evidence_data, jsonfile, indent=2, default=str)
        
        self.logger.info(f"Incident response evidence report generated: {report_file}")
        return report_file


def main():
    """Main entry point for incident response collector"""
    parser = argparse.ArgumentParser(
        description='SOC 2 Incident Response Evidence Compiler',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--config', required=True,
                       help='Path to SOC 2 configuration file')
    parser.add_argument('--output-dir',
                       help='Output directory for evidence reports')
    parser.add_argument('--systems', nargs='*',
                       choices=['PagerDuty', 'Jira Service Management', 'ServiceNow', 'Splunk', 'Slack'],
                       help='Specific incident management systems to collect from')
    parser.add_argument('--days', type=int, default=90,
                       help='Number of days back to collect incidents (default: 90)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Initialize collector
    collector = IncidentResponseCollector(args.config)
    
    if args.verbose:
        collector.logger.setLevel('DEBUG')
    
    try:
        # Collect evidence
        evidence = collector.collect_incident_evidence(args.systems, args.days)
        
        # Generate report
        report_file = collector.generate_evidence_report(args.output_dir)
        
        print(f"\\n🚨 Incident Response Evidence Collection Complete!")
        print(f"📊 Collected evidence for {len(evidence)} security incidents")
        
        # Summary by incident type and severity
        type_summary = {}
        severity_summary = {}
        for item in evidence:
            incident_type = item.incident_type
            severity = item.severity_level
            type_summary[incident_type] = type_summary.get(incident_type, 0) + 1
            severity_summary[severity] = severity_summary.get(severity, 0) + 1
        
        print(f"\\n📈 Incident Type Summary:")
        for incident_type, count in sorted(type_summary.items()):
            print(f"  {incident_type}: {count} incidents")
        
        print(f"\\n🎯 Severity Level Summary:")
        for severity, count in sorted(severity_summary.items()):
            print(f"  {severity}: {count} incidents")
        
        # Compliance issues summary
        total_findings = sum(len(item.compliance_findings) for item in evidence)
        if total_findings > 0:
            print(f"\\n⚠️  {total_findings} compliance findings require attention")
        
        print(f"\\n📁 Report saved to: {report_file}")
        
        return 0
        
    except Exception as e:
        collector.logger.error(f"Incident response evidence collection failed: {str(e)}")
        print(f"❌ Error: {str(e)}")
        return 1


if __name__ == "__main__":
    exit(main())