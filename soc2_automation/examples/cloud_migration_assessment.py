#!/usr/bin/env python3
"""
Cloud Migration SOC 2 Assessment Example
Demonstrates SOC 2 compliance assessment during cloud migration scenarios

This example shows how to:
1. Compare security postures between cloud providers
2. Assess compliance gaps during migration
3. Generate migration readiness reports
4. Identify security risks across hybrid environments

Author: Parker Robertson
Purpose: Support SOC 2 compliance during cloud migrations
"""

import sys
import os
from pathlib import Path
from datetime import datetime

# Add the parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.multicloud_collectors import MultiCloudDataCollector
from lib.soc2_models import ComplianceFinding, CrossCloudReport
from lib.soc2_utils import SOC2Utils


class CloudMigrationAssessment:
    """Cloud migration SOC 2 compliance assessment"""
    
    def __init__(self, config_path: str):
        """Initialize migration assessment"""
        self.config = SOC2Utils.load_json_config(config_path)
        self.collector = MultiCloudDataCollector(self.config)
        self.logger = SOC2Utils.setup_logging()
        
    def compare_security_postures(self, source_provider: str, target_provider: str):
        """Compare security postures between source and target cloud providers"""
        
        print(f"\n🔍 Comparing security postures: {source_provider.upper()} → {target_provider.upper()}")
        print("-" * 60)
        
        # Collect identities from both providers
        identities = self.collector.collect_multi_cloud_identities([source_provider, target_provider])
        
        source_identities = identities.get(source_provider, [])
        target_identities = identities.get(target_provider, [])
        
        print(f"👥 User Identities:")
        print(f"  {source_provider.upper()}: {len(source_identities)} users")
        print(f"  {target_provider.upper()}: {len(target_identities)} users")
        
        # Analyze MFA coverage
        source_mfa_enabled = sum(1 for user in source_identities if user.mfa_enabled)
        target_mfa_enabled = sum(1 for user in target_identities if user.mfa_enabled)
        
        source_mfa_rate = (source_mfa_enabled / len(source_identities) * 100) if source_identities else 0
        target_mfa_rate = (target_mfa_enabled / len(target_identities) * 100) if target_identities else 0
        
        print(f"\n🔐 MFA Coverage:")
        print(f"  {source_provider.upper()}: {source_mfa_rate:.1f}% ({source_mfa_enabled}/{len(source_identities)})")
        print(f"  {target_provider.upper()}: {target_mfa_rate:.1f}% ({target_mfa_enabled}/{len(target_identities)})")
        
        # Collect network rules from both providers
        network_rules = self.collector.collect_multi_cloud_network_rules([source_provider, target_provider])
        
        source_rules = network_rules.get(source_provider, [])
        target_rules = network_rules.get(target_provider, [])
        
        print(f"\n🔥 Network Security Rules:")
        print(f"  {source_provider.upper()}: {len(source_rules)} rules")
        print(f"  {target_provider.upper()}: {len(target_rules)} rules")
        
        # Analyze overly permissive rules
        source_open_rules = sum(1 for rule in source_rules 
                               if '0.0.0.0/0' in rule.source_addresses and rule.action == 'ALLOW')
        target_open_rules = sum(1 for rule in target_rules 
                               if '0.0.0.0/0' in rule.source_addresses and rule.action == 'ALLOW')
        
        print(f"\n⚠️  Overly Permissive Rules:")
        print(f"  {source_provider.upper()}: {source_open_rules} rules allow 0.0.0.0/0")
        print(f"  {target_provider.upper()}: {target_open_rules} rules allow 0.0.0.0/0")
        
        # Generate recommendations
        recommendations = []
        
        if target_mfa_rate < source_mfa_rate:
            recommendations.append(f"Improve MFA coverage in {target_provider.upper()} to match {source_provider.upper()}")
        
        if target_open_rules > source_open_rules:
            recommendations.append(f"Review and restrict overly permissive network rules in {target_provider.upper()}")
        
        if len(target_identities) > len(source_identities) * 1.2:
            recommendations.append(f"Potential over-provisioning of users in {target_provider.upper()}")
        
        print(f"\n💡 Migration Recommendations:")
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
        
        return {
            'source_provider': source_provider,
            'target_provider': target_provider,
            'source_mfa_rate': source_mfa_rate,
            'target_mfa_rate': target_mfa_rate,
            'source_open_rules': source_open_rules,
            'target_open_rules': target_open_rules,
            'recommendations': recommendations
        }
    
    def assess_migration_readiness(self, target_provider: str):
        """Assess migration readiness for target cloud provider"""
        
        print(f"\n📋 Migration Readiness Assessment: {target_provider.upper()}")
        print("-" * 50)
        
        readiness_score = 100
        issues = []
        
        # Check target provider configuration
        if target_provider not in self.config:
            issues.append(f"{target_provider.upper()} not configured in automation framework")
            readiness_score -= 30
        
        # Test connectivity
        try:
            from lib.cloud_providers import CloudProviderFactory
            providers = CloudProviderFactory.create_multi_cloud_session(self.config, self.logger)
            
            if target_provider.upper() not in providers:
                issues.append(f"Cannot connect to {target_provider.upper()} - check credentials")
                readiness_score -= 40
            else:
                connectivity = providers[target_provider.upper()].validate_connectivity()
                failed_services = [svc for svc, status in connectivity.items() if not status]
                
                if failed_services:
                    issues.append(f"{target_provider.upper()} services not accessible: {', '.join(failed_services)}")
                    readiness_score -= 10 * len(failed_services)
        
        except Exception as e:
            issues.append(f"Error testing {target_provider.upper()} connectivity: {str(e)}")
            readiness_score -= 25
        
        # Check baseline security controls
        try:
            identities = self.collector.collect_multi_cloud_identities([target_provider])
            target_identities = identities.get(target_provider, [])
            
            if target_identities:
                privileged_users = [user for user in target_identities 
                                  if any('admin' in role.lower() for role in user.roles)]
                privileged_without_mfa = [user for user in privileged_users if not user.mfa_enabled]
                
                if privileged_without_mfa:
                    issues.append(f"{len(privileged_without_mfa)} privileged users without MFA in {target_provider.upper()}")
                    readiness_score -= 15
            
            network_rules = self.collector.collect_multi_cloud_network_rules([target_provider])
            target_rules = network_rules.get(target_provider, [])
            
            critical_open_rules = [rule for rule in target_rules 
                                 if '0.0.0.0/0' in rule.source_addresses 
                                 and ('22' in rule.destination_ports or '3389' in rule.destination_ports)]
            
            if critical_open_rules:
                issues.append(f"{len(critical_open_rules)} critical services exposed to internet in {target_provider.upper()}")
                readiness_score -= 20
        
        except Exception as e:
            issues.append(f"Error assessing {target_provider.upper()} security controls: {str(e)}")
            readiness_score -= 15
        
        # Determine readiness level
        if readiness_score >= 90:
            readiness_level = "🟢 READY"
        elif readiness_score >= 70:
            readiness_level = "🟡 READY WITH MINOR ISSUES"
        elif readiness_score >= 50:
            readiness_level = "🟠 NEEDS ATTENTION"
        else:
            readiness_level = "🔴 NOT READY"
        
        print(f"Migration Readiness: {readiness_level} (Score: {readiness_score}/100)")
        
        if issues:
            print(f"\n❌ Issues to Address:")
            for i, issue in enumerate(issues, 1):
                print(f"  {i}. {issue}")
        else:
            print(f"\n✅ No critical issues found")
        
        return {
            'target_provider': target_provider,
            'readiness_score': readiness_score,
            'readiness_level': readiness_level,
            'issues': issues
        }
    
    def generate_migration_report(self, assessment_data: dict):
        """Generate comprehensive migration assessment report"""
        
        report_id = f"migration-assessment-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        
        report = CrossCloudReport(
            report_id=report_id,
            report_type='MIGRATION_ASSESSMENT',
            report_date=datetime.now(),
            cloud_providers=[assessment_data.get('source_provider', ''), assessment_data.get('target_provider', '')],
            accounts_covered={},
            soc2_controls=['CC6.1', 'CC6.2', 'CC6.3', 'CC7.1', 'CC7.2'],
            summary_statistics=assessment_data,
            findings_summary={},
            recommendations=assessment_data.get('recommendations', [])
        )
        
        # Generate report files
        output_dir = SOC2Utils.create_output_directory('migration_reports')
        report_paths = self.collector.generate_cross_cloud_report(report, output_dir)
        
        return report_paths


def main():
    """Main migration assessment example"""
    print("🚀 Cloud Migration SOC 2 Assessment Example")
    print("=" * 50)
    
    # Configuration
    config_path = Path(__file__).parent.parent / 'config' / 'soc2_multicloud_config.json'
    
    if not config_path.exists():
        print(f"❌ Configuration file not found: {config_path}")
        return 1
    
    try:
        # Initialize migration assessment
        assessment = CloudMigrationAssessment(str(config_path))
        
        # Example: AWS to Azure migration
        print("\n🔄 Scenario: AWS to Azure Migration")
        comparison = assessment.compare_security_postures('aws', 'azure')
        
        # Assess Azure readiness
        readiness = assessment.assess_migration_readiness('azure')
        
        # Generate migration report
        migration_data = {**comparison, **readiness}
        report_paths = assessment.generate_migration_report(migration_data)
        
        print(f"\n📄 Migration Assessment Report Generated:")
        for format_type, path in report_paths.items():
            print(f"  {format_type.upper()}: {path}")
        
        print(f"\n✅ Migration assessment completed!")
        
        return 0
        
    except Exception as e:
        print(f"❌ Assessment failed: {str(e)}")
        return 1


if __name__ == "__main__":
    exit(main())