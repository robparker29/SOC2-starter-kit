#!/usr/bin/env python3
"""
Multi-Cloud SOC 2 Automation Example
Demonstrates how to use the enhanced SOC 2 framework across AWS, Azure, and GCP

This example shows:
1. Multi-cloud configuration setup
2. Cross-cloud identity collection
3. Network security assessment
4. Comprehensive compliance reporting

Author: Parker Robertson
Purpose: Demonstrate multi-cloud SOC 2 automation capabilities
"""

import sys
import os
from pathlib import Path

# Add the parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from lib.multicloud_collectors import MultiCloudDataCollector
from lib.cloud_providers import CloudProviderFactory
from lib.soc2_utils import SOC2Utils


def main():
    """Main example execution"""
    print("🌐 Multi-Cloud SOC 2 Automation Example")
    print("=" * 50)
    
    # 1. Load multi-cloud configuration
    print("\n1. Loading multi-cloud configuration...")
    config_path = Path(__file__).parent.parent / 'config' / 'soc2_multicloud_config.json'
    
    if not config_path.exists():
        print(f"❌ Configuration file not found: {config_path}")
        print("Please copy and customize the multi-cloud configuration template")
        return 1
    
    try:
        config = SOC2Utils.load_json_config(str(config_path))
        print("✅ Configuration loaded successfully")
        
        # Display configured providers
        enabled_providers = []
        for provider in ['aws', 'azure', 'gcp']:
            if provider in config and config[provider].get('_enabled', True):
                enabled_providers.append(provider.upper())
        
        print(f"📦 Configured providers: {', '.join(enabled_providers)}")
        
    except Exception as e:
        print(f"❌ Failed to load configuration: {str(e)}")
        return 1
    
    # 2. Test cloud provider connectivity
    print("\n2. Testing cloud provider connectivity...")
    try:
        logger = SOC2Utils.setup_logging()
        providers = CloudProviderFactory.create_multi_cloud_session(config, logger)
        
        if not providers:
            print("❌ No cloud providers could be initialized")
            print("Please check your credentials and SDK installations")
            return 1
        
        for provider_name, provider in providers.items():
            print(f"\n{provider_name}:")
            connectivity = provider.validate_connectivity()
            
            for service, status in connectivity.items():
                status_icon = "✅" if status else "❌"
                print(f"  {status_icon} {service}")
        
    except Exception as e:
        print(f"❌ Connectivity test failed: {str(e)}")
        return 1
    
    # 3. Initialize multi-cloud collector
    print("\n3. Initializing multi-cloud data collector...")
    try:
        collector = MultiCloudDataCollector(config)
        print("✅ Multi-cloud collector initialized")
        
    except Exception as e:
        print(f"❌ Failed to initialize collector: {str(e)}")
        return 1
    
    # 4. Collect multi-cloud identities
    print("\n4. Collecting user identities across cloud providers...")
    try:
        all_identities = collector.collect_multi_cloud_identities()
        
        total_identities = 0
        for provider_name, identities in all_identities.items():
            count = len(identities)
            total_identities += count
            print(f"  {provider_name}: {count} identities")
        
        print(f"✅ Total identities collected: {total_identities}")
        
    except Exception as e:
        print(f"❌ Failed to collect identities: {str(e)}")
        return 1
    
    # 5. Collect network security rules
    print("\n5. Collecting network security rules...")
    try:
        all_network_rules = collector.collect_multi_cloud_network_rules()
        
        total_rules = 0
        for provider_name, rules in all_network_rules.items():
            count = len(rules)
            total_rules += count
            print(f"  {provider_name}: {count} network rules")
        
        print(f"✅ Total network rules collected: {total_rules}")
        
    except Exception as e:
        print(f"❌ Failed to collect network rules: {str(e)}")
        return 1
    
    # 6. Run cross-cloud compliance assessment
    print("\n6. Running cross-cloud compliance assessment...")
    try:
        assessment_report = collector.run_cross_cloud_compliance_assessment(
            assessment_types=['access_review', 'network_security', 'compliance_check'],
            soc2_controls=['CC6.1', 'CC6.2', 'CC6.3', 'CC7.1', 'CC7.2']
        )
        
        print(f"✅ Assessment completed: {assessment_report.summary_statistics['total_findings']} findings")
        
        # Display findings summary
        print(f"\nFindings Summary:")
        for severity, count in assessment_report.findings_summary.items():
            if count > 0:
                print(f"  {severity}: {count}")
    
    except Exception as e:
        print(f"❌ Failed to run compliance assessment: {str(e)}")
        return 1
    
    # 7. Generate cross-cloud report
    print("\n7. Generating cross-cloud compliance report...")
    try:
        report_paths = collector.generate_cross_cloud_report(assessment_report)
        
        print(f"📄 Reports generated:")
        for format_type, path in report_paths.items():
            print(f"  {format_type.upper()}: {path}")
        
    except Exception as e:
        print(f"❌ Failed to generate reports: {str(e)}")
        return 1
    
    print("\n✅ Multi-cloud SOC 2 automation example completed successfully!")
    print("\nNext steps:")
    print("- Review the generated reports")
    print("- Customize thresholds in the configuration")
    print("- Integrate with your ticketing system")
    print("- Schedule regular assessments")
    
    return 0


if __name__ == "__main__":
    exit(main())