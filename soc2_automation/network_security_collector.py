#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SOC 2 Network Security Configuration Collector
Maps to SOC 2 Common Criteria: CC6.7, CC7.1

This script collects network security configuration evidence for SOC 2 Type II compliance:
- Firewall rules and security groups
- Network ACLs and security policies
- VPN configurations and network segmentation
- Multi-cloud support (AWS Security Groups, Azure NSGs, GCP Firewall Rules)

Author: Parker Robertson
Purpose: Automate network security evidence collection for SOC 2 audits
"""

import argparse
import datetime
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
import csv

from lib.multicloud_collectors import MultiCloudDataCollector
from lib.soc2_models import NetworkSecurityEvidence, serialize_dataclass
from lib.soc2_utils import SOC2Utils


class NetworkSecurityCollector(MultiCloudDataCollector):
    """Network security configuration collector extending multi-cloud framework"""
    
    def __init__(self, config_path: str):
        """Initialize network security collector"""
        self.config = SOC2Utils.load_json_config(config_path)
        super().__init__(self.config)
        
        # Network security specific configuration
        self.network_config = self.config.get('network_security', {})
        self.supported_rule_types = ['SECURITY_GROUP', 'FIREWALL', 'NSG', 'NACL']
        self.risk_level_mapping = {
            'open_to_internet': 'CRITICAL',
            'ssh_open': 'HIGH',
            'rdp_open': 'HIGH',
            'database_ports_open': 'HIGH',
            'internal_only': 'LOW'
        }
        
        self.evidence_items = []
        self.collection_date = datetime.datetime.now()
        
    def collect_network_evidence(self, providers: List[str] = None) -> List[NetworkSecurityEvidence]:
        """
        Collect network security evidence from specified cloud providers
        
        Args:
            providers: List of cloud providers to collect from
            
        Returns:
            List of NetworkSecurityEvidence objects
        """
        self.logger.info("🔒 Starting network security evidence collection...")
        
        providers = providers or list(self.cloud_providers.keys())
        all_evidence = []
        
        # Collect cloud network security evidence
        if self.parallel_execution:
            cloud_evidence = self._collect_network_rules_parallel(providers)
        else:
            cloud_evidence = self._collect_network_rules_sequential(providers)
        
        all_evidence.extend(cloud_evidence)
        
        # Collect on-premise network evidence
        onprem_evidence = self._collect_onpremise_network_rules()
        all_evidence.extend(onprem_evidence)
        
        self.evidence_items = all_evidence
        self.logger.info(f"✅ Network security evidence collection complete. Found {len(all_evidence)} network rules")
        
        return all_evidence
    
    def _collect_network_rules_parallel(self, providers: List[str]) -> List[NetworkSecurityEvidence]:
        """Collect network rules in parallel across cloud providers"""
        import concurrent.futures
        
        evidence = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_concurrent_clouds) as executor:
            futures = {}
            
            for provider_name in providers:
                if provider_name.upper() in self.cloud_providers:
                    provider = self.cloud_providers[provider_name.upper()]
                    future = executor.submit(self._collect_provider_network_rules, provider_name, provider)
                    futures[future] = provider_name
            
            for future in concurrent.futures.as_completed(futures):
                provider_name = futures[future]
                try:
                    provider_evidence = future.result()
                    evidence.extend(provider_evidence)
                except Exception as e:
                    self.logger.error(f"Failed to collect network evidence from {provider_name}: {str(e)}")
        
        return evidence
    
    def _collect_network_rules_sequential(self, providers: List[str]) -> List[NetworkSecurityEvidence]:
        """Collect network rules sequentially"""
        evidence = []
        
        for provider_name in providers:
            if provider_name.upper() in self.cloud_providers:
                provider = self.cloud_providers[provider_name.upper()]
                try:
                    provider_evidence = self._collect_provider_network_rules(provider_name, provider)
                    evidence.extend(provider_evidence)
                except Exception as e:
                    self.logger.error(f"Failed to collect network evidence from {provider_name}: {str(e)}")
        
        return evidence
    
    def _collect_provider_network_rules(self, provider_name: str, provider) -> List[NetworkSecurityEvidence]:
        """Collect network security rules from specific cloud provider"""
        self.logger.info(f"Collecting network security rules from {provider_name}...")
        
        evidence = []
        
        if provider_name.upper() == 'AWS':
            evidence.extend(self._collect_aws_security_groups(provider))
            evidence.extend(self._collect_aws_nacls(provider))
        elif provider_name.upper() == 'AZURE':
            evidence.extend(self._collect_azure_nsgs(provider))
        elif provider_name.upper() == 'GCP':
            evidence.extend(self._collect_gcp_firewall_rules(provider))
        
        return evidence
    
    def _collect_aws_security_groups(self, provider) -> List[NetworkSecurityEvidence]:
        """Collect AWS Security Group rules"""
        evidence = []
        
        try:
            # Load security group data from configuration (in real implementation, this would query AWS API)
            security_groups = self.network_config.get('aws_security_groups', [])
            
            for sg_config in security_groups:
                # Process inbound rules
                for rule in sg_config.get('inbound_rules', []):
                    sg_evidence = NetworkSecurityEvidence(
                        rule_id=f"{sg_config['group_id']}-in-{rule.get('port_range', 'all')}",
                        rule_name=f"{sg_config['group_name']} Inbound {rule.get('port_range', 'all')}",
                        resource_id=sg_config['group_id'],
                        cloud_provider='AWS',
                        account_id=sg_config.get('account_id', 'unknown'),
                        region=sg_config.get('region', 'unknown'),
                        rule_type='SECURITY_GROUP',
                        direction='INBOUND',
                        protocol=rule.get('protocol', 'TCP').upper(),
                        port_range=str(rule.get('port_range', 'ALL')),
                        source=rule.get('source', '0.0.0.0/0'),
                        destination='SELF',
                        action='ALLOW',  # Security groups are allow-only
                        priority=None,
                        description=rule.get('description', 'AWS Security Group Rule'),
                        network_segmentation_purpose=self._determine_segmentation_purpose(rule),
                        compliance_risk_level=self._assess_rule_risk(rule, 'inbound'),
                        soc2_controls=['CC6.7', 'CC7.1'],
                        created_date=None,  # Would be available from API
                        last_modified=None,
                        evidence_date=self.collection_date,
                        metadata={
                            'vpc_id': sg_config.get('vpc_id'),
                            'owner_id': sg_config.get('owner_id'),
                            'tags': sg_config.get('tags', {})
                        }
                    )
                    evidence.append(sg_evidence)
                
                # Process outbound rules
                for rule in sg_config.get('outbound_rules', []):
                    sg_evidence = NetworkSecurityEvidence(
                        rule_id=f"{sg_config['group_id']}-out-{rule.get('port_range', 'all')}",
                        rule_name=f"{sg_config['group_name']} Outbound {rule.get('port_range', 'all')}",
                        resource_id=sg_config['group_id'],
                        cloud_provider='AWS',
                        account_id=sg_config.get('account_id', 'unknown'),
                        region=sg_config.get('region', 'unknown'),
                        rule_type='SECURITY_GROUP',
                        direction='OUTBOUND',
                        protocol=rule.get('protocol', 'TCP').upper(),
                        port_range=str(rule.get('port_range', 'ALL')),
                        source='SELF',
                        destination=rule.get('destination', '0.0.0.0/0'),
                        action='ALLOW',
                        priority=None,
                        description=rule.get('description', 'AWS Security Group Rule'),
                        network_segmentation_purpose=self._determine_segmentation_purpose(rule),
                        compliance_risk_level=self._assess_rule_risk(rule, 'outbound'),
                        soc2_controls=['CC6.7', 'CC7.1'],
                        created_date=None,
                        last_modified=None,
                        evidence_date=self.collection_date,
                        metadata={
                            'vpc_id': sg_config.get('vpc_id'),
                            'owner_id': sg_config.get('owner_id'),
                            'tags': sg_config.get('tags', {})
                        }
                    )
                    evidence.append(sg_evidence)
                    
        except Exception as e:
            self.logger.error(f"Error collecting AWS Security Group evidence: {str(e)}")
        
        return evidence
    
    def _collect_aws_nacls(self, provider) -> List[NetworkSecurityEvidence]:
        """Collect AWS Network ACL rules"""
        evidence = []
        
        try:
            nacls = self.network_config.get('aws_nacls', [])
            
            for nacl_config in nacls:
                for entry in nacl_config.get('entries', []):
                    nacl_evidence = NetworkSecurityEvidence(
                        rule_id=f"{nacl_config['nacl_id']}-{entry.get('rule_number')}",
                        rule_name=f"NACL Rule {entry.get('rule_number')}",
                        resource_id=nacl_config['nacl_id'],
                        cloud_provider='AWS',
                        account_id=nacl_config.get('account_id', 'unknown'),
                        region=nacl_config.get('region', 'unknown'),
                        rule_type='NACL',
                        direction='INBOUND' if entry.get('egress', False) == False else 'OUTBOUND',
                        protocol=entry.get('protocol', 'ALL').upper(),
                        port_range=str(entry.get('port_range', 'ALL')),
                        source=entry.get('cidr_block', '0.0.0.0/0'),
                        destination=entry.get('cidr_block', '0.0.0.0/0'),
                        action=entry.get('rule_action', 'ALLOW').upper(),
                        priority=entry.get('rule_number'),
                        description=f"Network ACL {entry.get('rule_action', 'allow')} rule",
                        network_segmentation_purpose='Network-level access control',
                        compliance_risk_level=self._assess_nacl_risk(entry),
                        soc2_controls=['CC6.7', 'CC7.1'],
                        created_date=None,
                        last_modified=None,
                        evidence_date=self.collection_date,
                        metadata={
                            'vpc_id': nacl_config.get('vpc_id'),
                            'subnet_associations': nacl_config.get('subnet_associations', [])
                        }
                    )
                    evidence.append(nacl_evidence)
                    
        except Exception as e:
            self.logger.error(f"Error collecting AWS NACL evidence: {str(e)}")
        
        return evidence
    
    def _collect_azure_nsgs(self, provider) -> List[NetworkSecurityEvidence]:
        """Collect Azure Network Security Group rules"""
        evidence = []
        
        try:
            nsgs = self.network_config.get('azure_nsgs', [])
            
            for nsg_config in nsgs:
                for rule in nsg_config.get('security_rules', []):
                    nsg_evidence = NetworkSecurityEvidence(
                        rule_id=f"{nsg_config['nsg_name']}-{rule.get('name')}",
                        rule_name=rule.get('name', 'Unknown NSG Rule'),
                        resource_id=nsg_config['nsg_id'],
                        cloud_provider='AZURE',
                        account_id=nsg_config.get('subscription_id', 'unknown'),
                        region=nsg_config.get('location', 'unknown'),
                        rule_type='NSG',
                        direction=rule.get('direction', 'INBOUND').upper(),
                        protocol=rule.get('protocol', 'TCP').upper(),
                        port_range=str(rule.get('destination_port_range', 'ALL')),
                        source=rule.get('source_address_prefix', '*'),
                        destination=rule.get('destination_address_prefix', '*'),
                        action=rule.get('access', 'Allow').upper(),
                        priority=rule.get('priority'),
                        description=rule.get('description', 'Azure NSG Rule'),
                        network_segmentation_purpose=self._determine_azure_segmentation_purpose(rule),
                        compliance_risk_level=self._assess_azure_rule_risk(rule),
                        soc2_controls=['CC6.7', 'CC7.1'],
                        created_date=None,
                        last_modified=None,
                        evidence_date=self.collection_date,
                        metadata={
                            'resource_group': nsg_config.get('resource_group'),
                            'provisioning_state': rule.get('provisioning_state'),
                            'tags': nsg_config.get('tags', {})
                        }
                    )
                    evidence.append(nsg_evidence)
                    
        except Exception as e:
            self.logger.error(f"Error collecting Azure NSG evidence: {str(e)}")
        
        return evidence
    
    def _collect_gcp_firewall_rules(self, provider) -> List[NetworkSecurityEvidence]:
        """Collect GCP Firewall rules"""
        evidence = []
        
        try:
            firewall_rules = self.network_config.get('gcp_firewall_rules', [])
            
            for rule_config in firewall_rules:
                gcp_evidence = NetworkSecurityEvidence(
                    rule_id=rule_config.get('name', 'unknown'),
                    rule_name=rule_config.get('name', 'Unknown GCP Firewall Rule'),
                    resource_id=rule_config.get('self_link', 'unknown'),
                    cloud_provider='GCP',
                    account_id=rule_config.get('project_id', 'unknown'),
                    region='global',  # GCP firewall rules are global
                    rule_type='FIREWALL',
                    direction=rule_config.get('direction', 'INGRESS').upper(),
                    protocol='MIXED' if len(rule_config.get('allowed', [])) > 1 else 
                             rule_config.get('allowed', [{}])[0].get('IPProtocol', 'TCP').upper(),
                    port_range=self._format_gcp_ports(rule_config.get('allowed', [])),
                    source=';'.join(rule_config.get('source_ranges', ['0.0.0.0/0'])),
                    destination=';'.join(rule_config.get('destination_ranges', ['0.0.0.0/0'])),
                    action='ALLOW' if rule_config.get('allowed') else 'DENY',
                    priority=rule_config.get('priority'),
                    description=rule_config.get('description', 'GCP Firewall Rule'),
                    network_segmentation_purpose=self._determine_gcp_segmentation_purpose(rule_config),
                    compliance_risk_level=self._assess_gcp_rule_risk(rule_config),
                    soc2_controls=['CC6.7', 'CC7.1'],
                    created_date=None,
                    last_modified=None,
                    evidence_date=self.collection_date,
                    metadata={
                        'network': rule_config.get('network'),
                        'source_tags': rule_config.get('source_tags', []),
                        'target_tags': rule_config.get('target_tags', [])
                    }
                )
                evidence.append(gcp_evidence)
                
        except Exception as e:
            self.logger.error(f"Error collecting GCP Firewall evidence: {str(e)}")
        
        return evidence
    
    def _collect_onpremise_network_rules(self) -> List[NetworkSecurityEvidence]:
        """Collect on-premise firewall and network rules"""
        evidence = []
        
        try:
            onprem_rules = self.network_config.get('onpremise_firewalls', [])
            
            for firewall_config in onprem_rules:
                for rule in firewall_config.get('rules', []):
                    onprem_evidence = NetworkSecurityEvidence(
                        rule_id=f"{firewall_config['firewall_name']}-{rule.get('rule_id', 'unknown')}",
                        rule_name=rule.get('rule_name', 'Unknown Firewall Rule'),
                        resource_id=firewall_config['firewall_name'],
                        cloud_provider='ON_PREMISE',
                        account_id='N/A',
                        region=firewall_config.get('location', 'unknown'),
                        rule_type='FIREWALL',
                        direction=rule.get('direction', 'INBOUND').upper(),
                        protocol=rule.get('protocol', 'TCP').upper(),
                        port_range=str(rule.get('port', 'ALL')),
                        source=rule.get('source', '0.0.0.0/0'),
                        destination=rule.get('destination', 'ANY'),
                        action=rule.get('action', 'ALLOW').upper(),
                        priority=rule.get('priority'),
                        description=rule.get('description', 'On-premise firewall rule'),
                        network_segmentation_purpose=rule.get('purpose', 'Network access control'),
                        compliance_risk_level=self._assess_onprem_rule_risk(rule),
                        soc2_controls=['CC6.7', 'CC7.1'],
                        created_date=None,
                        last_modified=None,
                        evidence_date=self.collection_date,
                        metadata={
                            'firewall_type': firewall_config.get('type'),
                            'vendor': firewall_config.get('vendor')
                        }
                    )
                    evidence.append(onprem_evidence)
                    
        except Exception as e:
            self.logger.error(f"Error collecting on-premise network evidence: {str(e)}")
        
        return evidence
    
    def _determine_segmentation_purpose(self, rule: Dict[str, Any]) -> str:
        """Determine network segmentation purpose for AWS rules"""
        port_range = str(rule.get('port_range', '')).lower()
        source = rule.get('source', '').lower()
        
        if '22' in port_range or 'ssh' in port_range:
            return 'SSH administrative access'
        elif '3389' in port_range or 'rdp' in port_range:
            return 'RDP administrative access'
        elif any(db_port in port_range for db_port in ['3306', '5432', '1433', '27017']):
            return 'Database access control'
        elif '80' in port_range or '443' in port_range:
            return 'Web application access'
        elif '0.0.0.0/0' in source:
            return 'Internet-facing service'
        else:
            return 'Internal network segmentation'
    
    def _determine_azure_segmentation_purpose(self, rule: Dict[str, Any]) -> str:
        """Determine network segmentation purpose for Azure NSG rules"""
        return self._determine_segmentation_purpose(rule)  # Similar logic
    
    def _determine_gcp_segmentation_purpose(self, rule_config: Dict[str, Any]) -> str:
        """Determine network segmentation purpose for GCP firewall rules"""
        allowed = rule_config.get('allowed', [])
        if not allowed:
            return 'Traffic blocking rule'
        
        ports = []
        for allow_rule in allowed:
            ports.extend(allow_rule.get('ports', []))
        
        if any('22' in port for port in ports):
            return 'SSH administrative access'
        elif any('80' in port or '443' in port for port in ports):
            return 'Web application access'
        else:
            return 'Network access control'
    
    def _assess_rule_risk(self, rule: Dict[str, Any], direction: str) -> str:
        """Assess risk level of AWS security group rule"""
        source = rule.get('source', '').lower()
        port_range = str(rule.get('port_range', '')).lower()
        
        # Critical risks
        if '0.0.0.0/0' in source and direction == 'inbound':
            if '22' in port_range or 'ssh' in port_range:
                return 'CRITICAL'
            elif '3389' in port_range or 'rdp' in port_range:
                return 'CRITICAL'
            elif any(db_port in port_range for db_port in ['3306', '5432', '1433', '27017']):
                return 'HIGH'
            elif 'all' in port_range or port_range == '0-65535':
                return 'CRITICAL'
        
        # Medium risks
        if '0.0.0.0/0' in source and ('80' in port_range or '443' in port_range):
            return 'MEDIUM'
        
        # Internal traffic
        if any(internal in source for internal in ['10.', '172.', '192.168.']):
            return 'LOW'
        
        return 'MEDIUM'
    
    def _assess_nacl_risk(self, entry: Dict[str, Any]) -> str:
        """Assess risk level of AWS NACL entry"""
        action = entry.get('rule_action', 'allow').lower()
        cidr = entry.get('cidr_block', '').lower()
        
        if action == 'deny':
            return 'LOW'  # Deny rules are good for security
        
        if '0.0.0.0/0' in cidr:
            return 'HIGH'
        
        return 'MEDIUM'
    
    def _assess_azure_rule_risk(self, rule: Dict[str, Any]) -> str:
        """Assess risk level of Azure NSG rule"""
        return self._assess_rule_risk(rule, rule.get('direction', 'inbound').lower())
    
    def _assess_gcp_rule_risk(self, rule_config: Dict[str, Any]) -> str:
        """Assess risk level of GCP firewall rule"""
        source_ranges = rule_config.get('source_ranges', [])
        direction = rule_config.get('direction', 'INGRESS').lower()
        
        if '0.0.0.0/0' in source_ranges and direction == 'ingress':
            allowed = rule_config.get('allowed', [])
            for allow_rule in allowed:
                ports = allow_rule.get('ports', [])
                if any('22' in str(port) for port in ports):
                    return 'CRITICAL'
                elif any('3389' in str(port) for port in ports):
                    return 'CRITICAL'
            return 'HIGH'
        
        return 'MEDIUM'
    
    def _assess_onprem_rule_risk(self, rule: Dict[str, Any]) -> str:
        """Assess risk level of on-premise firewall rule"""
        return self._assess_rule_risk(rule, rule.get('direction', 'inbound').lower())
    
    def _format_gcp_ports(self, allowed_rules: List[Dict[str, Any]]) -> str:
        """Format GCP allowed ports for display"""
        if not allowed_rules:
            return 'ALL'
        
        all_ports = []
        for rule in allowed_rules:
            protocol = rule.get('IPProtocol', 'tcp')
            ports = rule.get('ports', ['ALL'])
            for port in ports:
                all_ports.append(f"{protocol.upper()}:{port}")
        
        return ';'.join(all_ports)
    
    def generate_evidence_report(self, output_dir: str = None) -> str:
        """Generate network security evidence report"""
        output_dir = output_dir or self.config.get('global_settings', {}).get('output_directory', 'soc2_reports')
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = self.collection_date.strftime('%Y%m%d_%H%M%S')
        report_file = os.path.join(output_dir, f'network_security_evidence_{timestamp}.csv')
        
        with open(report_file, 'w', newline='', encoding='utf-8') as csvfile:
            if not self.evidence_items:
                csvfile.write("No network security evidence collected\\n")
                return report_file
            
            fieldnames = [
                'rule_id', 'rule_name', 'cloud_provider', 'rule_type', 'direction',
                'protocol', 'port_range', 'source', 'destination', 'action',
                'compliance_risk_level', 'network_segmentation_purpose',
                'soc2_controls', 'evidence_date'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for evidence in self.evidence_items:
                row = {
                    'rule_id': evidence.rule_id,
                    'rule_name': evidence.rule_name,
                    'cloud_provider': evidence.cloud_provider,
                    'rule_type': evidence.rule_type,
                    'direction': evidence.direction,
                    'protocol': evidence.protocol,
                    'port_range': evidence.port_range,
                    'source': evidence.source,
                    'destination': evidence.destination,
                    'action': evidence.action,
                    'compliance_risk_level': evidence.compliance_risk_level,
                    'network_segmentation_purpose': evidence.network_segmentation_purpose,
                    'soc2_controls': '; '.join(evidence.soc2_controls),
                    'evidence_date': evidence.evidence_date.isoformat()
                }
                writer.writerow(row)
        
        # Also generate JSON report
        json_file = os.path.join(output_dir, f'network_security_evidence_{timestamp}.json')
        with open(json_file, 'w', encoding='utf-8') as jsonfile:
            evidence_data = [serialize_dataclass(evidence) for evidence in self.evidence_items]
            json.dump(evidence_data, jsonfile, indent=2, default=str)
        
        self.logger.info(f"Network security evidence report generated: {report_file}")
        return report_file


def main():
    """Main entry point for network security collector"""
    parser = argparse.ArgumentParser(
        description='SOC 2 Network Security Configuration Collector',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--config', required=True,
                       help='Path to SOC 2 configuration file')
    parser.add_argument('--output-dir',
                       help='Output directory for evidence reports')
    parser.add_argument('--cloud-providers', nargs='*',
                       choices=['aws', 'azure', 'gcp'],
                       help='Specific cloud providers to collect from')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Initialize collector
    collector = NetworkSecurityCollector(args.config)
    
    if args.verbose:
        collector.logger.setLevel('DEBUG')
    
    try:
        # Collect evidence
        evidence = collector.collect_network_evidence(args.cloud_providers)
        
        # Generate report
        report_file = collector.generate_evidence_report(args.output_dir)
        
        print(f"\\n🔒 Network Security Evidence Collection Complete!")
        print(f"📊 Collected evidence for {len(evidence)} network security rules")
        
        # Summary by risk level
        risk_summary = {}
        for item in evidence:
            risk_level = item.compliance_risk_level
            risk_summary[risk_level] = risk_summary.get(risk_level, 0) + 1
        
        print(f"\\n📈 Risk Level Summary:")
        for risk_level, count in sorted(risk_summary.items()):
            print(f"  {risk_level}: {count} rules")
        
        print(f"\\n📁 Report saved to: {report_file}")
        
        return 0
        
    except Exception as e:
        collector.logger.error(f"Network security evidence collection failed: {str(e)}")
        print(f"❌ Error: {str(e)}")
        return 1


if __name__ == "__main__":
    exit(main())