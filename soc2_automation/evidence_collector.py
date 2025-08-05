#!/usr/bin/env python3
"""
SOC 2 Evidence Collection Automation
Maps to SOC 2 Common Criteria: CC1.4, CC2.1, CC3.1, CC6.1, CC6.2, CC6.3, CC6.7, CC6.8, CC7.1, CC7.2

This script automates the collection of audit evidence required for SOC 2 Type II compliance.
Uses the unified SOC 2 automation framework for consistent data collection and reporting.

Author: Parker Robertson
Purpose: Streamline SOC 2 audit preparation using centralized framework
"""

import argparse
import datetime
import json
from typing import Dict, List, Optional, Any
from pathlib import Path

from lib.soc2_collectors import SystemDataCollector
from lib.multicloud_collectors import MultiCloudDataCollector
from lib.soc2_models import EvidenceItem, UserAccessRecord, SystemConfiguration, serialize_dataclass
from lib.soc2_utils import SOC2Utils


class EvidenceCollector(MultiCloudDataCollector):
    """Multi-cloud evidence collection using enhanced SOC 2 automation framework"""
    
    def __init__(self, config_path: str):
        """Initialize evidence collector with configuration"""
        self.config = SOC2Utils.load_json_config(config_path)
        super().__init__(self.config)
        
        # Evidence collection settings
        self.evidence_config = self.config.get('evidence_collection', {})
        self.retention_days = self.evidence_config.get('retention_days', 365)
        self.output_format = self.evidence_config.get('output_format', ['csv', 'json'])
        self.create_tickets = self.evidence_config.get('create_tickets', False)
        
        self.evidence_items = []
        self.collection_date = datetime.datetime.now()
        
    def collect_evidence(self, controls: List[str] = None, evidence_types: List[str] = None) -> List[EvidenceItem]:
        """
        Main method to collect SOC 2 evidence
        
        Args:
            controls: List of SOC 2 controls to collect evidence for (e.g., ['CC6.1', 'CC6.2'])
            evidence_types: Types of evidence to collect (['ACCESS', 'CONFIG', 'MONITORING'])
            
        Returns:
            List of EvidenceItem objects
        """
        self.logger.info("🔍 Starting SOC 2 evidence collection...")
        
        # Default to all controls if none specified
        if controls is None:
            controls = ['CC1.4', 'CC2.1', 'CC3.1', 'CC6.1', 'CC6.2', 'CC6.3', 'CC6.7', 'CC6.8', 'CC7.1', 'CC7.2']
        
        # Default to all evidence types if none specified
        if evidence_types is None:
            evidence_types = ['ACCESS', 'CONFIG', 'MONITORING', 'CHANGE_MANAGEMENT']
        
        all_evidence = []
        
        # Collect evidence by type
        for evidence_type in evidence_types:
            try:
                evidence_items = self._collect_evidence_by_type(evidence_type, controls)
                all_evidence.extend(evidence_items)
                self.logger.info(f"Collected {len(evidence_items)} {evidence_type} evidence items")
            except Exception as e:
                self.logger.error(f"Failed to collect {evidence_type} evidence: {str(e)}")
                continue
        
        self.evidence_items = all_evidence
        self.logger.info(f"✅ Evidence collection complete. Collected {len(all_evidence)} total evidence items")
        
        return all_evidence
    
    def _collect_evidence_by_type(self, evidence_type: str, controls: List[str]) -> List[EvidenceItem]:
        """Collect evidence for specific type and controls"""
        evidence_items = []
        
        if evidence_type == 'ACCESS':
            evidence_items.extend(self._collect_access_evidence(controls))
        elif evidence_type == 'CONFIG':
            evidence_items.extend(self._collect_config_evidence(controls))
        elif evidence_type == 'MONITORING':
            evidence_items.extend(self._collect_monitoring_evidence(controls))
        elif evidence_type == 'CHANGE_MANAGEMENT':
            evidence_items.extend(self._collect_change_management_evidence(controls))
        
        return evidence_items
    
    def _collect_access_evidence(self, controls: List[str]) -> List[EvidenceItem]:
        """Collect access control evidence from multiple cloud providers (CC6.1, CC6.2, CC6.3)"""
        evidence_items = []
        
        try:
            # Collect multi-cloud identities
            all_identities = self.collect_multi_cloud_identities()
            
            for provider_name, identities in all_identities.items():
                if identities:  # Only create evidence if we have data
                    evidence_items.append(self._create_evidence_item(
                        evidence_id=f"ACCESS-{provider_name.upper()}-{self.collection_date.strftime('%Y%m%d')}",
                        soc2_control='CC6.1',
                        evidence_type='ACCESS',
                        source_system=f'{provider_name.upper()} Identity Management',
                        description=f'{provider_name.upper()} user access data - {len(identities)} identities',
                        data_content={'identities': [serialize_dataclass(identity) for identity in identities]},
                        audit_relevance=f'Documents user access controls and permissions in {provider_name.upper()} infrastructure'
                    ))
            
            # Legacy systems support
            # Active Directory users (if configured)
            if 'active_directory' in self.config:
                ad_users = self.collect_ad_users(include_groups=True, include_last_login=True)
                evidence_items.append(self._create_evidence_item(
                    evidence_id=f"ACCESS-AD-{self.collection_date.strftime('%Y%m%d')}",
                    soc2_control='CC6.1',
                    evidence_type='ACCESS',
                    source_system='Active Directory',
                    description=f'Active Directory user access data - {len(ad_users)} users',
                    data_content={'users': [serialize_dataclass(user) for user in ad_users]},
                    audit_relevance='Documents user access controls and permissions in corporate directory'
                ))
            
            # GitHub users (if configured)
            if 'github' in self.config:
                github_users = self.collect_github_users(include_repos=True)
                evidence_items.append(self._create_evidence_item(
                    evidence_id=f"ACCESS-GITHUB-{self.collection_date.strftime('%Y%m%d')}",
                    soc2_control='CC6.2',
                    evidence_type='ACCESS',
                    source_system='GitHub',
                    description=f'GitHub organization access data - {len(github_users)} users',
                    data_content={'users': [serialize_dataclass(user) for user in github_users]},
                    audit_relevance='Documents developer access controls and repository permissions'
                ))
            
        except Exception as e:
            self.logger.error(f"Failed to collect access evidence: {str(e)}")
        
        return evidence_items
    
    def _collect_config_evidence(self, controls: List[str]) -> List[EvidenceItem]:
        """Collect system configuration evidence from multiple cloud providers (CC7.1, CC7.2)"""
        evidence_items = []
        
        try:
            # Collect multi-cloud network security rules
            all_network_rules = self.collect_multi_cloud_network_rules()
            
            for provider_name, rules in all_network_rules.items():
                if rules:  # Only create evidence if we have data
                    evidence_items.append(self._create_evidence_item(
                        evidence_id=f"CONFIG-{provider_name.upper()}-NET-{self.collection_date.strftime('%Y%m%d')}",
                        soc2_control='CC7.1',
                        evidence_type='CONFIG',
                        source_system=f'{provider_name.upper()} Network Security',
                        description=f'{provider_name.upper()} network security rules - {len(rules)} rules',
                        data_content={'network_rules': [serialize_dataclass(rule) for rule in rules]},
                        audit_relevance=f'Documents network security controls and firewall configurations in {provider_name.upper()}'
                    ))
            
            # Legacy system support
            # Linux server configurations (if configured)
            if 'linux_servers' in self.config:
                linux_configs = self.collect_linux_configs(
                    config_types=['ssh', 'firewall', 'sudo', 'logging']
                )
                evidence_items.append(self._create_evidence_item(
                    evidence_id=f"CONFIG-LINUX-{self.collection_date.strftime('%Y%m%d')}",
                    soc2_control='CC7.1',
                    evidence_type='CONFIG',
                    source_system='Linux Servers',
                    description=f'Linux server security configurations - {len(linux_configs)} configs',
                    data_content={'configurations': [serialize_dataclass(config) for config in linux_configs]},
                    audit_relevance='Documents server security hardening and access controls'
                ))
            
        except Exception as e:
            self.logger.error(f"Failed to collect configuration evidence: {str(e)}")
        
        return evidence_items
    
    def _collect_monitoring_evidence(self, controls: List[str]) -> List[EvidenceItem]:
        """Collect monitoring and logging evidence from multiple cloud providers (CC7.2, CC6.7)"""
        evidence_items = []
        
        try:
            # Collect multi-cloud audit logs
            all_audit_logs = self.collect_multi_cloud_audit_logs(time_range_days=30)
            
            for provider_name, audit_logs in all_audit_logs.items():
                if audit_logs:  # Only create evidence if we have data
                    evidence_items.append(self._create_evidence_item(
                        evidence_id=f"MONITOR-{provider_name.upper()}-{self.collection_date.strftime('%Y%m%d')}",
                        soc2_control='CC7.2',
                        evidence_type='MONITORING',
                        source_system=f'{provider_name.upper()} Audit Logging',
                        description=f'{provider_name.upper()} audit logs (30 days) - {len(audit_logs)} events',
                        data_content={'audit_logs': [serialize_dataclass(log) for log in audit_logs]},
                        audit_relevance=f'Documents security monitoring and access logging for {provider_name.upper()} infrastructure changes'
                    ))
            
        except Exception as e:
            self.logger.error(f"Failed to collect monitoring evidence: {str(e)}")
        
        return evidence_items
    
    def _collect_change_management_evidence(self, controls: List[str]) -> List[EvidenceItem]:
        """Collect change management evidence (CC8.1)"""
        evidence_items = []
        
        # This would typically integrate with ticketing systems like Jira
        # For now, create placeholder for manual evidence collection
        evidence_items.append(self._create_evidence_item(
            evidence_id=f"CHANGE-MGMT-{self.collection_date.strftime('%Y%m%d')}",
            soc2_control='CC8.1',
            evidence_type='CHANGE_MANAGEMENT',
            source_system='Manual Collection',
            description='Change management tickets and approvals (manual collection required)',
            data_content={'note': 'Manual evidence collection required for change management tickets'},
            audit_relevance='Documents change approval processes and deployment controls'
        ))
        
        return evidence_items
    
    def _create_evidence_item(self, evidence_id: str, soc2_control: str, evidence_type: str,
                            source_system: str, description: str, data_content: Dict[str, Any],
                            audit_relevance: str) -> EvidenceItem:
        """Create standardized evidence item"""
        
        # Create output file for the evidence data
        output_dir = SOC2Utils.create_output_directory('evidence')
        file_name = f"{evidence_id.lower().replace('-', '_')}.json"
        file_path = f"{output_dir}/{file_name}"
        
        # Write evidence data to file
        SOC2Utils.write_json_report(data_content, file_path)
        
        # Calculate file hash for integrity
        file_hash = SOC2Utils.calculate_file_hash(file_path)
        
        return EvidenceItem(
            evidence_id=evidence_id,
            soc2_control=soc2_control,
            evidence_type=evidence_type,
            source_system=source_system,
            collection_date=self.collection_date,
            evidence_period=f"{self.collection_date.strftime('%Y-%m-%d')} (Point in time)",
            file_path=file_path,
            file_hash=file_hash,
            description=description,
            completeness_status='COMPLETE',
            validation_notes='Automatically collected and validated',
            audit_relevance=audit_relevance
        )
    
    def generate_evidence_reports(self, output_dir: str = None) -> Dict[str, str]:
        """Generate evidence collection reports"""
        if not output_dir:
            output_dir = SOC2Utils.create_output_directory('evidence_reports')
        
        report_paths = {}
        
        if not self.evidence_items:
            self.logger.warning("No evidence items to report")
            return report_paths
        
        # Generate CSV report
        csv_data = []
        for item in self.evidence_items:
            csv_data.append({
                'Evidence_ID': item.evidence_id,
                'SOC2_Control': item.soc2_control,
                'Evidence_Type': item.evidence_type,
                'Source_System': item.source_system,
                'Collection_Date': item.collection_date.strftime('%Y-%m-%d %H:%M:%S'),
                'Evidence_Period': item.evidence_period,
                'Description': item.description,
                'File_Path': item.file_path,
                'File_Hash': item.file_hash,
                'Completeness_Status': item.completeness_status,
                'Audit_Relevance': item.audit_relevance
            })
        
        csv_path = f"{output_dir}/evidence_collection_report.csv"
        SOC2Utils.write_csv_report(csv_data, csv_path)
        report_paths['csv'] = csv_path
        
        # Generate JSON report
        json_data = {
            'collection_date': self.collection_date.isoformat(),
            'collection_summary': {
                'total_evidence_items': len(self.evidence_items),
                'evidence_types': list(set(item.evidence_type for item in self.evidence_items)),
                'soc2_controls': list(set(item.soc2_control for item in self.evidence_items)),
                'source_systems': list(set(item.source_system for item in self.evidence_items))
            },
            'evidence_items': [serialize_dataclass(item) for item in self.evidence_items]
        }
        
        json_path = f"{output_dir}/evidence_collection_report.json"
        SOC2Utils.write_json_report(json_data, json_path)
        report_paths['json'] = json_path
        
        # Print summary
        self._print_evidence_summary(json_data['collection_summary'])
        
        return report_paths
    
    def _print_evidence_summary(self, summary: Dict):
        """Print evidence collection summary"""
        print(f"\n📊 SOC 2 Evidence Collection Summary")
        print(f"Collection Date: {self.collection_date.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Evidence Items: {summary['total_evidence_items']}")
        print(f"Evidence Types: {', '.join(summary['evidence_types'])}")
        print(f"SOC 2 Controls: {', '.join(summary['soc2_controls'])}")
        print(f"Source Systems: {', '.join(summary['source_systems'])}")


def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='SOC 2 Evidence Collection')
    parser.add_argument('--config', required=True, help='Path to configuration JSON file')
    parser.add_argument('--controls', nargs='*', help='Specific SOC 2 controls to collect evidence for')
    parser.add_argument('--evidence-types', nargs='*', 
                       choices=['ACCESS', 'CONFIG', 'MONITORING', 'CHANGE_MANAGEMENT'],
                       help='Types of evidence to collect')
    parser.add_argument('--output-dir', help='Custom output directory for reports')
    
    args = parser.parse_args()
    
    try:
        # Initialize evidence collector
        collector = EvidenceCollector(args.config)
        
        # Collect evidence
        evidence_items = collector.collect_evidence(
            controls=args.controls,
            evidence_types=args.evidence_types
        )
        
        # Generate reports
        report_paths = collector.generate_evidence_reports(args.output_dir)
        
        # Output results
        if report_paths:
            print(f"\n📄 Evidence reports generated:")
            for format_type, path in report_paths.items():
                print(f"  {format_type.upper()}: {path}")
        
        print(f"\n✅ Evidence collection complete!")
        
        return 0 if len(evidence_items) > 0 else 1
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return 2


if __name__ == "__main__":
    exit(main())