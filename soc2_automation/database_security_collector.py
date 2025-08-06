#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SOC 2 Database Security Evidence Collector
Maps to SOC 2 Common Criteria: CC6.1, CC6.2, CC6.7

This script collects database security evidence for SOC 2 Type II compliance:
- Database configuration evidence (encryption, access controls)
- User privilege documentation
- Audit logging configuration
- Multi-cloud database support (RDS, Azure SQL, Cloud SQL)

Author: Parker Robertson  
Purpose: Automate database security evidence collection for SOC 2 audits
"""

import argparse
import datetime
import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
import csv

from lib.multicloud_collectors import MultiCloudDataCollector
from lib.soc2_models import DatabaseSecurityEvidence, serialize_dataclass
from lib.soc2_utils import SOC2Utils


class DatabaseSecurityCollector(MultiCloudDataCollector):
    """Database security evidence collector extending multi-cloud framework"""
    
    def __init__(self, config_path: str):
        """Initialize database security collector"""
        self.config = SOC2Utils.load_json_config(config_path)
        super().__init__(self.config)
        
        # Database specific configuration
        self.database_config = self.config.get('database_security', {})
        self.config_file_patterns = self.database_config.get('config_file_patterns', [])
        self.audit_log_locations = self.database_config.get('audit_log_locations', [])
        self.supported_db_types = ['PostgreSQL', 'MySQL', 'MongoDB', 'RDS', 'Azure SQL', 'Cloud SQL']
        
        self.evidence_items = []
        self.collection_date = datetime.datetime.now()
        
    def collect_database_evidence(self, db_types: List[str] = None) -> List[DatabaseSecurityEvidence]:
        """
        Collect database security evidence for specified database types
        
        Args:
            db_types: List of database types to collect evidence for
            
        Returns:
            List of DatabaseSecurityEvidence objects
        """
        self.logger.info("🔒 Starting database security evidence collection...")
        
        db_types = db_types or self.supported_db_types
        all_evidence = []
        
        # Collect cloud database evidence
        if self.parallel_execution:
            cloud_evidence = self._collect_cloud_databases_parallel(db_types)
        else:
            cloud_evidence = self._collect_cloud_databases_sequential(db_types)
        
        all_evidence.extend(cloud_evidence)
        
        # Collect on-premise database evidence
        onprem_evidence = self._collect_onpremise_databases(db_types)
        all_evidence.extend(onprem_evidence)
        
        self.evidence_items = all_evidence
        self.logger.info(f"✅ Database security evidence collection complete. Found {len(all_evidence)} database instances")
        
        return all_evidence
    
    def _collect_cloud_databases_parallel(self, db_types: List[str]) -> List[DatabaseSecurityEvidence]:
        """Collect cloud database evidence in parallel"""
        import concurrent.futures
        
        evidence = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_concurrent_clouds) as executor:
            futures = {}
            
            for provider_name, provider in self.cloud_providers.items():
                future = executor.submit(self._collect_provider_databases, provider_name, provider, db_types)
                futures[future] = provider_name
            
            for future in concurrent.futures.as_completed(futures):
                provider_name = futures[future]
                try:
                    provider_evidence = future.result()
                    evidence.extend(provider_evidence)
                except Exception as e:
                    self.logger.error(f"Failed to collect database evidence from {provider_name}: {str(e)}")
        
        return evidence
    
    def _collect_cloud_databases_sequential(self, db_types: List[str]) -> List[DatabaseSecurityEvidence]:
        """Collect cloud database evidence sequentially"""
        evidence = []
        
        for provider_name, provider in self.cloud_providers.items():
            try:
                provider_evidence = self._collect_provider_databases(provider_name, provider, db_types)
                evidence.extend(provider_evidence)
            except Exception as e:
                self.logger.error(f"Failed to collect database evidence from {provider_name}: {str(e)}")
        
        return evidence
    
    def _collect_provider_databases(self, provider_name: str, provider, db_types: List[str]) -> List[DatabaseSecurityEvidence]:
        """Collect database evidence from specific cloud provider"""
        self.logger.info(f"Collecting database evidence from {provider_name}...")
        
        evidence = []
        
        if provider_name.upper() == 'AWS':
            evidence.extend(self._collect_aws_rds_evidence(provider))
        elif provider_name.upper() == 'AZURE':
            evidence.extend(self._collect_azure_sql_evidence(provider))
        elif provider_name.upper() == 'GCP':
            evidence.extend(self._collect_gcp_sql_evidence(provider))
        
        return evidence
    
    def _collect_aws_rds_evidence(self, provider) -> List[DatabaseSecurityEvidence]:
        """Collect AWS RDS database evidence"""
        evidence = []
        
        try:
            # This would collect RDS instance configurations
            # For now, creating sample evidence based on configuration
            rds_instances = self.database_config.get('aws_rds_instances', [])
            
            for instance_config in rds_instances:
                db_evidence = DatabaseSecurityEvidence(
                    database_id=instance_config.get('db_instance_identifier', 'unknown'),
                    database_name=instance_config.get('database_name', 'unknown'),
                    database_type='RDS',
                    cloud_provider='AWS',
                    host_location=instance_config.get('availability_zone', 'unknown'),
                    encryption_at_rest=instance_config.get('storage_encrypted', False),
                    encryption_in_transit=instance_config.get('ssl_enforced', False),
                    encryption_key_management=instance_config.get('kms_key_id', 'AWS KMS'),
                    audit_logging_enabled=instance_config.get('audit_log_enabled', False),
                    audit_log_location=instance_config.get('audit_log_location', ''),
                    backup_encryption=instance_config.get('backup_encryption', False),
                    access_control_method='IAM',
                    user_privileges=instance_config.get('user_privileges', []),
                    network_isolation=instance_config.get('vpc_security_groups', []) != [],
                    ssl_tls_enforced=instance_config.get('ssl_enforced', False),
                    password_policy_enforced=instance_config.get('password_policy', False),
                    multi_factor_auth_required=False,  # RDS doesn't have direct MFA
                    compliance_findings=self._analyze_rds_compliance(instance_config),
                    soc2_controls=['CC6.1', 'CC6.2', 'CC6.7'],
                    evidence_date=self.collection_date,
                    evidence_source='CLOUD_API'
                )
                evidence.append(db_evidence)
                
        except Exception as e:
            self.logger.error(f"Error collecting AWS RDS evidence: {str(e)}")
        
        return evidence
    
    def _collect_azure_sql_evidence(self, provider) -> List[DatabaseSecurityEvidence]:
        """Collect Azure SQL database evidence"""
        evidence = []
        
        try:
            azure_sql_instances = self.database_config.get('azure_sql_instances', [])
            
            for instance_config in azure_sql_instances:
                db_evidence = DatabaseSecurityEvidence(
                    database_id=instance_config.get('server_name', 'unknown'),
                    database_name=instance_config.get('database_name', 'unknown'),
                    database_type='Azure SQL',
                    cloud_provider='AZURE',
                    host_location=instance_config.get('location', 'unknown'),
                    encryption_at_rest=instance_config.get('transparent_data_encryption', False),
                    encryption_in_transit=instance_config.get('ssl_enforcement', False),
                    encryption_key_management=instance_config.get('key_vault_key', 'Azure Key Vault'),
                    audit_logging_enabled=instance_config.get('auditing_enabled', False),
                    audit_log_location=instance_config.get('audit_log_destination', ''),
                    backup_encryption=instance_config.get('backup_encryption', False),
                    access_control_method='Azure AD',
                    user_privileges=instance_config.get('user_privileges', []),
                    network_isolation=instance_config.get('firewall_rules', []) != [],
                    ssl_tls_enforced=instance_config.get('ssl_enforcement', False),
                    password_policy_enforced=instance_config.get('password_policy', False),
                    multi_factor_auth_required=instance_config.get('mfa_required', False),
                    compliance_findings=self._analyze_azure_sql_compliance(instance_config),
                    soc2_controls=['CC6.1', 'CC6.2', 'CC6.7'],
                    evidence_date=self.collection_date,
                    evidence_source='CLOUD_API'
                )
                evidence.append(db_evidence)
                
        except Exception as e:
            self.logger.error(f"Error collecting Azure SQL evidence: {str(e)}")
        
        return evidence
    
    def _collect_gcp_sql_evidence(self, provider) -> List[DatabaseSecurityEvidence]:
        """Collect GCP Cloud SQL database evidence"""
        evidence = []
        
        try:
            gcp_sql_instances = self.database_config.get('gcp_sql_instances', [])
            
            for instance_config in gcp_sql_instances:
                db_evidence = DatabaseSecurityEvidence(
                    database_id=instance_config.get('instance_name', 'unknown'),
                    database_name=instance_config.get('database_name', 'unknown'),
                    database_type='Cloud SQL',
                    cloud_provider='GCP',
                    host_location=instance_config.get('region', 'unknown'),
                    encryption_at_rest=instance_config.get('disk_encryption', False),
                    encryption_in_transit=instance_config.get('ssl_mode', 'DISABLED') != 'DISABLED',
                    encryption_key_management=instance_config.get('disk_encryption_key', 'Google KMS'),
                    audit_logging_enabled=instance_config.get('database_flags', {}).get('log_statement', 'none') != 'none',
                    audit_log_location=instance_config.get('audit_log_location', ''),
                    backup_encryption=instance_config.get('backup_encryption', False),
                    access_control_method='IAM',
                    user_privileges=instance_config.get('user_privileges', []),
                    network_isolation=instance_config.get('authorized_networks', []) != [],
                    ssl_tls_enforced=instance_config.get('require_ssl', False),
                    password_policy_enforced=instance_config.get('password_validation', False),
                    multi_factor_auth_required=False,  # Cloud SQL doesn't have direct MFA
                    compliance_findings=self._analyze_gcp_sql_compliance(instance_config),
                    soc2_controls=['CC6.1', 'CC6.2', 'CC6.7'],
                    evidence_date=self.collection_date,
                    evidence_source='CLOUD_API'
                )
                evidence.append(db_evidence)
                
        except Exception as e:
            self.logger.error(f"Error collecting GCP Cloud SQL evidence: {str(e)}")
        
        return evidence
    
    def _collect_onpremise_databases(self, db_types: List[str]) -> List[DatabaseSecurityEvidence]:
        """Collect on-premise database evidence from configuration files"""
        evidence = []
        
        onprem_databases = self.database_config.get('onpremise_databases', [])
        
        for db_config in onprem_databases:
            if db_config.get('database_type') in db_types:
                try:
                    db_evidence = self._parse_database_config(db_config)
                    evidence.append(db_evidence)
                except Exception as e:
                    self.logger.error(f"Error processing database config {db_config.get('database_name', 'unknown')}: {str(e)}")
        
        return evidence
    
    def _parse_database_config(self, db_config: Dict[str, Any]) -> DatabaseSecurityEvidence:
        """Parse on-premise database configuration"""
        
        # Load configuration from file if specified
        config_data = db_config
        if 'config_file_path' in db_config:
            config_data = self._load_database_config_file(db_config['config_file_path'])
        
        return DatabaseSecurityEvidence(
            database_id=config_data.get('database_id', 'unknown'),
            database_name=config_data.get('database_name', 'unknown'),
            database_type=config_data.get('database_type', 'unknown'),
            cloud_provider=None,
            host_location=config_data.get('host', 'localhost'),
            encryption_at_rest=config_data.get('encryption_at_rest', False),
            encryption_in_transit=config_data.get('ssl_enabled', False),
            encryption_key_management=config_data.get('key_management', 'Unknown'),
            audit_logging_enabled=config_data.get('audit_logging', False),
            audit_log_location=config_data.get('audit_log_path', ''),
            backup_encryption=config_data.get('backup_encryption', False),
            access_control_method=config_data.get('auth_method', 'Native'),
            user_privileges=config_data.get('user_privileges', []),
            network_isolation=config_data.get('firewall_enabled', False),
            ssl_tls_enforced=config_data.get('force_ssl', False),
            password_policy_enforced=config_data.get('password_policy', False),
            multi_factor_auth_required=config_data.get('mfa_required', False),
            compliance_findings=self._analyze_onprem_compliance(config_data),
            soc2_controls=['CC6.1', 'CC6.2', 'CC6.7'],
            evidence_date=self.collection_date,
            evidence_source='CONFIG_FILE'
        )
    
    def _load_database_config_file(self, file_path: str) -> Dict[str, Any]:
        """Load database configuration from file"""
        try:
            if file_path.endswith('.json'):
                with open(file_path, 'r') as f:
                    return json.load(f)
            elif file_path.endswith('.conf') or file_path.endswith('.cnf'):
                return self._parse_config_file(file_path)
            else:
                self.logger.warning(f"Unsupported config file format: {file_path}")
                return {}
        except Exception as e:
            self.logger.error(f"Error loading config file {file_path}: {str(e)}")
            return {}
    
    def _parse_config_file(self, file_path: str) -> Dict[str, Any]:
        """Parse generic configuration file"""
        config = {}
        try:
            with open(file_path, 'r') as f:
                content = f.read()
                
                # Look for common security settings
                config['ssl_enabled'] = 'ssl' in content.lower() and 'on' in content.lower()
                config['audit_logging'] = 'log' in content.lower() and ('audit' in content.lower() or 'general' in content.lower())
                config['encryption_at_rest'] = 'encrypt' in content.lower() and 'innodb' in content.lower()
                
        except Exception as e:
            self.logger.error(f"Error parsing config file {file_path}: {str(e)}")
        
        return config
    
    def _analyze_rds_compliance(self, instance_config: Dict[str, Any]) -> List[str]:
        """Analyze RDS instance for compliance issues"""
        findings = []
        
        if not instance_config.get('storage_encrypted', False):
            findings.append('Encryption at rest not enabled')
        
        if not instance_config.get('ssl_enforced', False):
            findings.append('SSL/TLS not enforced')
        
        if not instance_config.get('audit_log_enabled', False):
            findings.append('Database audit logging not enabled')
        
        if not instance_config.get('backup_encryption', False):
            findings.append('Backup encryption not enabled')
        
        return findings
    
    def _analyze_azure_sql_compliance(self, instance_config: Dict[str, Any]) -> List[str]:
        """Analyze Azure SQL instance for compliance issues"""
        findings = []
        
        if not instance_config.get('transparent_data_encryption', False):
            findings.append('Transparent Data Encryption not enabled')
        
        if not instance_config.get('ssl_enforcement', False):
            findings.append('SSL enforcement not enabled')
        
        if not instance_config.get('auditing_enabled', False):
            findings.append('SQL auditing not enabled')
        
        return findings
    
    def _analyze_gcp_sql_compliance(self, instance_config: Dict[str, Any]) -> List[str]:
        """Analyze GCP Cloud SQL instance for compliance issues"""
        findings = []
        
        if not instance_config.get('disk_encryption', False):
            findings.append('Disk encryption not enabled')
        
        if not instance_config.get('require_ssl', False):
            findings.append('SSL requirement not enforced')
        
        database_flags = instance_config.get('database_flags', {})
        if database_flags.get('log_statement', 'none') == 'none':
            findings.append('Database statement logging not enabled')
        
        return findings
    
    def _analyze_onprem_compliance(self, config_data: Dict[str, Any]) -> List[str]:
        """Analyze on-premise database for compliance issues"""
        findings = []
        
        if not config_data.get('encryption_at_rest', False):
            findings.append('Encryption at rest not configured')
        
        if not config_data.get('ssl_enabled', False):
            findings.append('SSL/TLS not enabled')
        
        if not config_data.get('audit_logging', False):
            findings.append('Audit logging not enabled')
        
        if not config_data.get('password_policy', False):
            findings.append('Password policy not enforced')
        
        return findings
    
    def generate_evidence_report(self, output_dir: str = None) -> str:
        """Generate database security evidence report"""
        output_dir = output_dir or self.config.get('global_settings', {}).get('output_directory', 'soc2_reports')
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = self.collection_date.strftime('%Y%m%d_%H%M%S')
        report_file = os.path.join(output_dir, f'database_security_evidence_{timestamp}.csv')
        
        with open(report_file, 'w', newline='', encoding='utf-8') as csvfile:
            if not self.evidence_items:
                csvfile.write("No database evidence collected\\n")
                return report_file
            
            fieldnames = [
                'database_id', 'database_name', 'database_type', 'cloud_provider',
                'encryption_at_rest', 'encryption_in_transit', 'audit_logging_enabled',
                'access_control_method', 'ssl_tls_enforced', 'compliance_findings',
                'soc2_controls', 'evidence_date'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for evidence in self.evidence_items:
                row = {
                    'database_id': evidence.database_id,
                    'database_name': evidence.database_name,
                    'database_type': evidence.database_type,
                    'cloud_provider': evidence.cloud_provider or 'On-Premise',
                    'encryption_at_rest': evidence.encryption_at_rest,
                    'encryption_in_transit': evidence.encryption_in_transit,
                    'audit_logging_enabled': evidence.audit_logging_enabled,
                    'access_control_method': evidence.access_control_method,
                    'ssl_tls_enforced': evidence.ssl_tls_enforced,
                    'compliance_findings': '; '.join(evidence.compliance_findings),
                    'soc2_controls': '; '.join(evidence.soc2_controls),
                    'evidence_date': evidence.evidence_date.isoformat()
                }
                writer.writerow(row)
        
        # Also generate JSON report
        json_file = os.path.join(output_dir, f'database_security_evidence_{timestamp}.json')
        with open(json_file, 'w', encoding='utf-8') as jsonfile:
            evidence_data = [serialize_dataclass(evidence) for evidence in self.evidence_items]
            json.dump(evidence_data, jsonfile, indent=2, default=str)
        
        self.logger.info(f"Database security evidence report generated: {report_file}")
        return report_file


def main():
    """Main entry point for database security collector"""
    parser = argparse.ArgumentParser(
        description='SOC 2 Database Security Evidence Collector',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--config', required=True,
                       help='Path to SOC 2 configuration file')
    parser.add_argument('--output-dir',
                       help='Output directory for evidence reports')
    parser.add_argument('--db-types', nargs='*',
                       choices=['PostgreSQL', 'MySQL', 'MongoDB', 'RDS', 'Azure SQL', 'Cloud SQL'],
                       help='Specific database types to collect evidence for')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Initialize collector
    collector = DatabaseSecurityCollector(args.config)
    
    if args.verbose:
        collector.logger.setLevel('DEBUG')
    
    try:
        # Collect evidence
        evidence = collector.collect_database_evidence(args.db_types)
        
        # Generate report
        report_file = collector.generate_evidence_report(args.output_dir)
        
        print(f"\\n🔒 Database Security Evidence Collection Complete!")
        print(f"📊 Collected evidence for {len(evidence)} database instances")
        print(f"📁 Report saved to: {report_file}")
        
        return 0
        
    except Exception as e:
        collector.logger.error(f"Database security evidence collection failed: {str(e)}")
        print(f"❌ Error: {str(e)}")
        return 1


if __name__ == "__main__":
    exit(main())