#!/usr/bin/env python3
"""
Example usage of the AWS Inactive Users Detection Script
This demonstrates how to integrate with the SOC 2 automation framework
"""

import sys
import os
import json
from pathlib import Path

# Add the parent directory to the path so we can import the detector
sys.path.insert(0, str(Path(__file__).parent.parent))

from inactive_users_detector import InactiveUsersDetector
from lib.soc2_utils import SOC2Utils

def create_example_config():
    """Create an example configuration file"""
    config = {
        "aws": {
            "access_key": "YOUR_AWS_ACCESS_KEY",
            "secret_key": "YOUR_AWS_SECRET_KEY", 
            "region": "us-east-1"
        },
        "inactive_users": {
            "console_threshold_days": 90,
            "access_key_threshold_days": 180,
            "create_tickets": False
        },
        "logging": {
            "level": "INFO",
            "file": "logs/inactive_users_example.log"
        }
    }
    
    config_path = "config/example_inactive_users.json"
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"📝 Example configuration created at: {config_path}")
    print("Please update the AWS credentials before running the analysis.")
    return config_path

def run_analysis_example():
    """Example of running the inactive users analysis"""
    print("🔍 AWS Inactive Users Detection Example")
    print("=" * 50)
    
    # Create example config if it doesn't exist
    config_path = "config/example_inactive_users.json"
    if not os.path.exists(config_path):
        config_path = create_example_config()
        print("⚠️  Please update the configuration file with your AWS credentials and run again.")
        return
    
    try:
        # Initialize detector
        print("1. Initializing detector...")
        detector = InactiveUsersDetector(config_path)
        
        # Run analysis
        print("2. Running inactive users analysis...")
        findings = detector.analyze_inactive_users()
        
        # Generate reports
        print("3. Generating reports...")
        report_paths = detector.generate_reports()
        
        # Display results
        print(f"\n📊 Analysis Results:")
        print(f"Total findings: {len(findings)}")
        
        if findings:
            severity_counts = {}
            for finding in findings:
                severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            
            for severity, count in severity_counts.items():
                print(f"  {severity}: {count}")
            
            print(f"\n📄 Reports generated:")
            for format_type, path in report_paths.items():
                print(f"  {format_type.upper()}: {path}")
        else:
            print("✅ No inactive users found!")
        
        # Example of creating tickets (if enabled)
        if detector.create_tickets and findings:
            print("4. Creating remediation tickets...")
            detector.create_remediation_tickets()
        
        print("\n✅ Example completed successfully!")
        
    except Exception as e:
        print(f"❌ Error running example: {str(e)}")
        print("Please check your configuration and AWS credentials.")

def demonstrate_integration():
    """Demonstrate integration with existing SOC 2 framework"""
    print("\n🔧 Integration Example")
    print("=" * 30)
    
    # Show how this integrates with the existing collector
    try:
        from lib.soc2_collectors import SystemDataCollector
        
        # Example configuration
        config = {
            "aws": {
                "access_key": "demo",
                "secret_key": "demo",
                "region": "us-east-1"
            }
        }
        
        # Create base collector
        collector = SystemDataCollector(config)
        
        # Show that the new method is available
        if hasattr(collector, 'analyze_inactive_users'):
            print("✅ analyze_inactive_users method available in SystemDataCollector")
            print("   This method can be called directly:")
            print("   findings = collector.analyze_inactive_users(console_threshold=90, access_key_threshold=180)")
        else:
            print("❌ analyze_inactive_users method not found")
        
        print("\n🏗️  Architecture Integration:")
        print("   - Extends existing SystemDataCollector class")
        print("   - Uses standard UserAccessRecord and AccessReviewFinding models")
        print("   - Leverages SOC2Utils for AWS clients and reporting")
        print("   - Follows established logging and error handling patterns")
        
    except ImportError as e:
        print(f"⚠️  Could not import SOC 2 framework components: {e}")

if __name__ == "__main__":
    print("🚀 SOC 2 AWS Inactive Users Detection - Example Script")
    print("=" * 60)
    
    # Run the main example
    run_analysis_example()
    
    # Demonstrate integration
    demonstrate_integration()
    
    print(f"\n📚 Next Steps:")
    print("1. Update config/example_inactive_users.json with your AWS credentials")
    print("2. Run: python soc2_automation/inactive_users_detector.py --config config/example_inactive_users.json")
    print("3. Review the generated reports in the output directory")
    print("4. Configure multi-account setup if needed")
    print("5. Enable ticket creation for automated remediation")