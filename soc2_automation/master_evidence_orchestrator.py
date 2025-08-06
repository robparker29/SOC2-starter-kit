#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SOC 2 Master Evidence Orchestration Script
Coordinates all evidence collection and generates consolidated auditor report

This script coordinates the execution of all SOC 2 evidence collection scripts:
- Database Security Evidence Collector
- Network Security Configuration Collector  
- Vendor & Third-Party Access Auditor
- Generates consolidated auditor report with control mappings

Author: Parker Robertson
Purpose: Provide unified evidence collection orchestration for SOC 2 audits
"""

import argparse
import datetime
import json
import os
import sys
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any
import concurrent.futures
import csv

from lib.soc2_collectors import SystemDataCollector
from lib.soc2_models import (
    ConsolidatedEvidenceReport, DatabaseSecurityEvidence, 
    NetworkSecurityEvidence, VendorAccessEvidence, serialize_dataclass
)

# Enhanced error handling imports
try:
    import botocore.exceptions
except ImportError:
    botocore = None
from lib.soc2_utils import SOC2Utils


class MasterEvidenceOrchestrator(SystemDataCollector):
    """Master orchestrator for all SOC 2 evidence collection activities"""
    
    def __init__(self, config_path: str):
        """Initialize master evidence orchestrator"""
        self.config = SOC2Utils.load_json_config(config_path)
        super().__init__(self.config)
        
        # Orchestration configuration
        self.orchestrator_config = self.config.get('master_orchestrator', {})
        self.parallel_execution = self.orchestrator_config.get('parallel_execution', True)
        self.max_concurrent_collectors = self.orchestrator_config.get('max_concurrent_collectors', 3)
        self.timeout_minutes = self.orchestrator_config.get('timeout_minutes', 30)
        
        # Evidence collection configuration
        self.evidence_types = ['DATABASE_SECURITY', 'NETWORK_SECURITY', 'VENDOR_ACCESS', 'CHANGE_MANAGEMENT', 'INCIDENT_RESPONSE']
        self.collector_scripts = {
            'DATABASE_SECURITY': 'database_security_collector.py',
            'NETWORK_SECURITY': 'network_security_collector.py',
            'VENDOR_ACCESS': 'vendor_access_auditor.py',
            'CHANGE_MANAGEMENT': 'change_management_collector.py',
            'INCIDENT_RESPONSE': 'incident_response_collector.py'
        }
        
        # SOC 2 control mappings
        self.soc2_control_mappings = {
            'CC6.1': ['DATABASE_SECURITY', 'VENDOR_ACCESS'],
            'CC6.2': ['DATABASE_SECURITY', 'VENDOR_ACCESS'],
            'CC6.7': ['DATABASE_SECURITY', 'NETWORK_SECURITY'],
            'CC7.1': ['NETWORK_SECURITY'],
            'CC7.3': ['INCIDENT_RESPONSE'],
            'CC7.4': ['INCIDENT_RESPONSE'],
            'CC7.5': ['INCIDENT_RESPONSE'],
            'CC8.1': ['CHANGE_MANAGEMENT'],
            'CC9.1': ['VENDOR_ACCESS'],
            'CC9.2': ['VENDOR_ACCESS']
        }
        
        self.base_dir = Path(__file__).parent
        self.collection_date = datetime.datetime.now()
        self.evidence_data = {}
        self.collection_status = {}
        
    def orchestrate_evidence_collection(
        self, 
        environment: str = 'production',
        exclude_types: List[str] = None,
        cloud_providers: List[str] = None,
        output_dir: str = None
    ) -> ConsolidatedEvidenceReport:
        """
        Orchestrate comprehensive evidence collection across all collectors
        
        Args:
            environment: Target environment (production, staging, development)
            exclude_types: Evidence types to exclude from collection
            cloud_providers: Specific cloud providers to target
            output_dir: Custom output directory
            
        Returns:
            ConsolidatedEvidenceReport with all collected evidence
        """
        self.logger.info("🎯 Starting master evidence collection orchestration...")
        self.logger.info(f"Target environment: {environment}")
        
        # Determine evidence types to collect
        evidence_types_to_collect = [et for et in self.evidence_types if et not in (exclude_types or [])]
        self.logger.info(f"Evidence types to collect: {', '.join(evidence_types_to_collect)}")
        
        # Set up output directory
        output_dir = output_dir or self.config.get('global_settings', {}).get('output_directory', 'soc2_reports')
        os.makedirs(output_dir, exist_ok=True)
        
        # Execute evidence collection
        if self.parallel_execution:
            self._execute_collectors_parallel(evidence_types_to_collect, cloud_providers, output_dir)
        else:
            self._execute_collectors_sequential(evidence_types_to_collect, cloud_providers, output_dir)
        
        # Load collected evidence data
        self._load_evidence_data(output_dir)
        
        # Generate consolidated report
        consolidated_report = self._generate_consolidated_report(environment, output_dir)
        
        # Save consolidated report
        self._save_consolidated_report(consolidated_report, output_dir)
        
        self.logger.info("✅ Master evidence collection orchestration complete")
        return consolidated_report
    
    def _execute_collectors_parallel(
        self, 
        evidence_types: List[str], 
        cloud_providers: List[str], 
        output_dir: str
    ):
        """Execute evidence collectors in parallel"""
        self.logger.info("🚀 Executing evidence collectors in parallel...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_concurrent_collectors) as executor:
            futures = {}
            
            for evidence_type in evidence_types:
                if evidence_type in self.collector_scripts:
                    script_path = self.base_dir / self.collector_scripts[evidence_type]
                    cmd = self._build_collector_command(script_path, cloud_providers, output_dir)
                    
                    future = executor.submit(self._execute_collector_script, evidence_type, cmd)
                    futures[future] = evidence_type
            
            # Collect results
            for future in concurrent.futures.as_completed(futures, timeout=self.timeout_minutes * 60):
                evidence_type = futures[future]
                try:
                    success, output = future.result()
                    self.collection_status[evidence_type] = 'SUCCESS' if success else 'FAILED'
                    if success:
                        self.logger.info(f"✅ {evidence_type} collection completed successfully")
                    else:
                        self.logger.error(f"❌ {evidence_type} collection failed: {output}")
                except Exception as e:
                    self.logger.error(f"❌ {evidence_type} collection failed with exception: {str(e)}")
                    self.collection_status[evidence_type] = 'ERROR'
    
    def _execute_collectors_sequential(
        self, 
        evidence_types: List[str], 
        cloud_providers: List[str], 
        output_dir: str
    ):
        """Execute evidence collectors sequentially"""
        self.logger.info("📋 Executing evidence collectors sequentially...")
        
        for evidence_type in evidence_types:
            if evidence_type in self.collector_scripts:
                self.logger.info(f"Running {evidence_type} collector...")
                
                script_path = self.base_dir / self.collector_scripts[evidence_type]
                cmd = self._build_collector_command(script_path, cloud_providers, output_dir)
                
                success, output = self._execute_collector_script(evidence_type, cmd)
                self.collection_status[evidence_type] = 'SUCCESS' if success else 'FAILED'
                
                if success:
                    self.logger.info(f"✅ {evidence_type} collection completed")
                else:
                    self.logger.error(f"❌ {evidence_type} collection failed: {output}")
    
    def _build_collector_command(
        self, 
        script_path: Path, 
        cloud_providers: List[str], 
        output_dir: str
    ) -> List[str]:
        """Build command line for evidence collector script"""
        cmd = [
            sys.executable,
            str(script_path),
            '--config', str(Path(self.config.get('_config_path', 'config.json')).resolve())
        ]
        
        if output_dir:
            cmd.extend(['--output-dir', output_dir])
        
        if cloud_providers:
            cmd.extend(['--cloud-providers'] + cloud_providers)
        
        return cmd
    
    def _execute_collector_script(self, evidence_type: str, cmd: List[str]) -> tuple[bool, str]:
        """Execute individual collector script"""
        try:
            self.logger.debug(f"Executing command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_minutes * 60,
                check=False
            )
            
            success = result.returncode == 0
            output = result.stdout if success else result.stderr
            
            return success, output
            
        except subprocess.TimeoutExpired:
            error_msg = f"Collector timed out after {self.timeout_minutes} minutes"
            self.logger.error(f"{evidence_type}: {error_msg}")
            return False, error_msg
        except Exception as e:
            error_msg = f"Execution error: {str(e)}"
            self.logger.error(f"{evidence_type}: {error_msg}")
            return False, error_msg
    
    def _load_evidence_data(self, output_dir: str):
        """Load evidence data from collector output files"""
        self.logger.info("📂 Loading evidence data from collector outputs...")
        
        # Look for the most recent output files from each collector
        for evidence_type in self.evidence_types:
            try:
                evidence_files = self._find_latest_evidence_files(output_dir, evidence_type)
                if evidence_files:
                    self.evidence_data[evidence_type] = self._load_evidence_from_files(evidence_files)
                    self.logger.debug(f"Loaded {len(self.evidence_data[evidence_type])} {evidence_type} items")
                else:
                    self.logger.warning(f"No evidence files found for {evidence_type}")
                    self.evidence_data[evidence_type] = []
                    
            except Exception as e:
                self.logger.error(f"Error loading {evidence_type} evidence: {str(e)}")
                self.evidence_data[evidence_type] = []
    
    def _find_latest_evidence_files(self, output_dir: str, evidence_type: str) -> List[str]:
        """Find the latest evidence files for a given type"""
        evidence_files = []
        
        # Map evidence types to file patterns
        file_patterns = {
            'DATABASE_SECURITY': 'database_security_evidence_*.json',
            'NETWORK_SECURITY': 'network_security_evidence_*.json',
            'VENDOR_ACCESS': 'vendor_access_evidence_*.json'
        }
        
        if evidence_type in file_patterns:
            import glob
            pattern = os.path.join(output_dir, file_patterns[evidence_type])
            matching_files = glob.glob(pattern)
            
            if matching_files:
                # Get the most recent file
                latest_file = max(matching_files, key=os.path.getmtime)
                evidence_files.append(latest_file)
        
        return evidence_files
    
    def _load_evidence_from_files(self, file_paths: List[str]) -> List[Dict[str, Any]]:
        """Load evidence data from JSON files"""
        all_evidence = []
        
        for file_path in file_paths:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    evidence_data = json.load(f)
                    if isinstance(evidence_data, list):
                        all_evidence.extend(evidence_data)
                    else:
                        all_evidence.append(evidence_data)
            except Exception as e:
                self.logger.error(f"Error loading evidence from {file_path}: {str(e)}")
        
        return all_evidence
    
    def _generate_consolidated_report(self, environment: str, output_dir: str) -> ConsolidatedEvidenceReport:
        """Generate consolidated evidence report"""
        self.logger.info("📊 Generating consolidated evidence report...")
        
        # Calculate reporting period (last 30 days by default)
        reporting_period_end = self.collection_date
        reporting_period_start = reporting_period_end - datetime.timedelta(days=30)
        
        # Generate report ID
        report_id = f"SOC2_EVIDENCE_{self.collection_date.strftime('%Y%m%d_%H%M%S')}"
        
        # Count evidence items by type
        evidence_summary = {}
        for evidence_type, evidence_list in self.evidence_data.items():
            evidence_summary[evidence_type] = len(evidence_list)
        
        # Map evidence to SOC 2 controls
        soc2_control_coverage = {}
        for control, evidence_types in self.soc2_control_mappings.items():
            coverage = []
            for et in evidence_types:
                if et in self.evidence_data and self.evidence_data[et]:
                    coverage.append(et)
            soc2_control_coverage[control] = coverage
        
        # Identify compliance gaps
        compliance_gaps = self._identify_compliance_gaps()
        
        # Generate recommendations
        recommendations = self._generate_recommendations()
        
        # Calculate total evidence items
        total_evidence_items = sum(evidence_summary.values())
        
        # Determine report completeness
        report_completeness = self._assess_report_completeness()
        
        # Convert evidence data to proper data model objects (simplified for this implementation)
        database_evidence = []  # Would convert from self.evidence_data['DATABASE_SECURITY']
        network_evidence = []   # Would convert from self.evidence_data['NETWORK_SECURITY']  
        vendor_evidence = []    # Would convert from self.evidence_data['VENDOR_ACCESS']
        
        consolidated_report = ConsolidatedEvidenceReport(
            report_id=report_id,
            report_date=self.collection_date,
            reporting_period_start=reporting_period_start,
            reporting_period_end=reporting_period_end,
            organization_name=self.config.get('organization', {}).get('name', 'Unknown Organization'),
            environment=environment.upper(),
            evidence_summary=evidence_summary,
            database_evidence=database_evidence,
            network_evidence=network_evidence,
            vendor_evidence=vendor_evidence,
            soc2_control_coverage=soc2_control_coverage,
            compliance_gaps=compliance_gaps,
            recommendations=recommendations,
            evidence_collection_status=self.collection_status,
            total_evidence_items=total_evidence_items,
            report_completeness=report_completeness
        )
        
        return consolidated_report
    
    def _identify_compliance_gaps(self) -> List[str]:
        """Identify compliance gaps based on collected evidence"""
        gaps = []
        
        # Check for missing evidence types
        for evidence_type in self.evidence_types:
            if self.collection_status.get(evidence_type) != 'SUCCESS':
                gaps.append(f"Failed to collect {evidence_type} evidence")
            elif not self.evidence_data.get(evidence_type):
                gaps.append(f"No {evidence_type} evidence found")
        
        # Check for SOC 2 control coverage
        for control, evidence_types in self.soc2_control_mappings.items():
            covered_types = []
            for et in evidence_types:
                if et in self.evidence_data and self.evidence_data[et]:
                    covered_types.append(et)
            
            if not covered_types:
                gaps.append(f"No evidence collected for SOC 2 control {control}")
            elif len(covered_types) < len(evidence_types):
                missing_types = set(evidence_types) - set(covered_types)
                gaps.append(f"Incomplete evidence for {control}: missing {', '.join(missing_types)}")
        
        return gaps
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on evidence analysis"""
        recommendations = []
        
        # Analyze evidence for high-risk findings
        for evidence_type, evidence_list in self.evidence_data.items():
            if evidence_type == 'DATABASE_SECURITY':
                unencrypted_dbs = [item for item in evidence_list 
                                 if not item.get('encryption_at_rest', False)]
                if unencrypted_dbs:
                    recommendations.append(f"Enable encryption at rest for {len(unencrypted_dbs)} database(s)")
            
            elif evidence_type == 'NETWORK_SECURITY':
                high_risk_rules = [item for item in evidence_list 
                                 if item.get('compliance_risk_level') in ['HIGH', 'CRITICAL']]
                if high_risk_rules:
                    recommendations.append(f"Review and remediate {len(high_risk_rules)} high-risk network rules")
            
            elif evidence_type == 'VENDOR_ACCESS':
                non_compliant_vendors = [item for item in evidence_list 
                                       if item.get('compliance_status') == 'NON_COMPLIANT']
                if non_compliant_vendors:
                    recommendations.append(f"Address compliance issues for {len(non_compliant_vendors)} vendor(s)")
        
        # General recommendations
        if any(status != 'SUCCESS' for status in self.collection_status.values()):
            recommendations.append("Investigate and resolve evidence collection failures")
        
        if not recommendations:
            recommendations.append("All evidence collection completed successfully with no immediate actions required")
        
        return recommendations
    
    def _assess_report_completeness(self) -> str:
        """Assess overall report completeness"""
        successful_collections = sum(1 for status in self.collection_status.values() if status == 'SUCCESS')
        total_collections = len(self.collection_status)
        
        if successful_collections == total_collections:
            return 'COMPLETE'
        elif successful_collections >= total_collections * 0.7:
            return 'PARTIAL'
        else:
            return 'INCOMPLETE'
    
    def _save_consolidated_report(self, report: ConsolidatedEvidenceReport, output_dir: str):
        """Save consolidated report to files"""
        timestamp = self.collection_date.strftime('%Y%m%d_%H%M%S')
        
        # Save JSON report
        json_file = os.path.join(output_dir, f'consolidated_evidence_report_{timestamp}.json')
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(serialize_dataclass(report), f, indent=2, default=str)
        
        # Save CSV summary
        csv_file = os.path.join(output_dir, f'evidence_summary_{timestamp}.csv')
        with open(csv_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Report header
            writer.writerow(['SOC 2 Evidence Collection Summary'])
            writer.writerow(['Report ID', report.report_id])
            writer.writerow(['Organization', report.organization_name])
            writer.writerow(['Environment', report.environment])
            writer.writerow(['Report Date', report.report_date.isoformat()])
            writer.writerow(['Completeness', report.report_completeness])
            writer.writerow([])
            
            # Evidence summary
            writer.writerow(['Evidence Type', 'Items Collected', 'Collection Status'])
            for evidence_type, count in report.evidence_summary.items():
                status = self.collection_status.get(evidence_type, 'UNKNOWN')
                writer.writerow([evidence_type, count, status])
            writer.writerow([])
            
            # SOC 2 control coverage
            writer.writerow(['SOC 2 Control', 'Evidence Types Covering'])
            for control, evidence_types in report.soc2_control_coverage.items():
                writer.writerow([control, '; '.join(evidence_types)])
            writer.writerow([])
            
            # Compliance gaps
            if report.compliance_gaps:
                writer.writerow(['Compliance Gaps'])
                for gap in report.compliance_gaps:
                    writer.writerow([gap])
                writer.writerow([])
            
            # Recommendations
            writer.writerow(['Recommendations'])
            for recommendation in report.recommendations:
                writer.writerow([recommendation])
        
        self.logger.info(f"Consolidated report saved to: {json_file}")
        self.logger.info(f"Evidence summary saved to: {csv_file}")


def main():
    """Main entry point for master evidence orchestrator"""
    parser = argparse.ArgumentParser(
        description='SOC 2 Master Evidence Orchestrator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python master_evidence_orchestrator.py --config config.json
  python master_evidence_orchestrator.py --config config.json --environment staging --parallel
  python master_evidence_orchestrator.py --config config.json --exclude-types VENDOR_ACCESS
        """
    )
    
    parser.add_argument('--config', required=True,
                       help='Path to SOC 2 configuration file')
    parser.add_argument('--environment', 
                       choices=['production', 'staging', 'development'],
                       default='production',
                       help='Target environment for evidence collection')
    parser.add_argument('--output-dir',
                       help='Custom output directory for all reports')
    parser.add_argument('--exclude-types', nargs='*',
                       choices=['DATABASE_SECURITY', 'NETWORK_SECURITY', 'VENDOR_ACCESS'],
                       help='Evidence types to exclude from collection')
    parser.add_argument('--cloud-providers', nargs='*',
                       choices=['aws', 'azure', 'gcp'],
                       help='Specific cloud providers to target')
    parser.add_argument('--report-name',
                       help='Custom name for the consolidated report')
    parser.add_argument('--parallel', action='store_true',
                       help='Execute evidence collectors in parallel (default)')
    parser.add_argument('--sequential', action='store_true',
                       help='Execute evidence collectors sequentially')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Store config path for use in subprocesses
    config_dict = SOC2Utils.load_json_config(args.config)
    config_dict['_config_path'] = args.config
    
    # Initialize orchestrator
    orchestrator = MasterEvidenceOrchestrator(args.config)
    
    if args.verbose:
        orchestrator.logger.setLevel('DEBUG')
    
    # Override parallel execution setting
    if args.sequential:
        orchestrator.parallel_execution = False
    elif args.parallel:
        orchestrator.parallel_execution = True
    
    try:
        # Execute orchestrated evidence collection
        consolidated_report = orchestrator.orchestrate_evidence_collection(
            environment=args.environment,
            exclude_types=args.exclude_types,
            cloud_providers=args.cloud_providers,
            output_dir=args.output_dir
        )
        
        print(f"\\n🎯 Master Evidence Collection Orchestration Complete!")
        print(f"📊 Report ID: {consolidated_report.report_id}")
        print(f"🏢 Organization: {consolidated_report.organization_name}")
        print(f"🌍 Environment: {consolidated_report.environment}")
        print(f"📈 Completeness: {consolidated_report.report_completeness}")
        print(f"📋 Total Evidence Items: {consolidated_report.total_evidence_items}")
        
        print(f"\\n📊 Evidence Collection Summary:")
        for evidence_type, count in consolidated_report.evidence_summary.items():
            status = orchestrator.collection_status.get(evidence_type, 'UNKNOWN')
            status_icon = "✅" if status == 'SUCCESS' else "❌"
            print(f"  {status_icon} {evidence_type}: {count} items ({status})")
        
        print(f"\\n🎯 SOC 2 Control Coverage:")
        for control, evidence_types in consolidated_report.soc2_control_coverage.items():
            coverage_icon = "✅" if evidence_types else "❌"
            print(f"  {coverage_icon} {control}: {', '.join(evidence_types) if evidence_types else 'No evidence'}")
        
        if consolidated_report.compliance_gaps:
            print(f"\\n⚠️  Compliance Gaps ({len(consolidated_report.compliance_gaps)}):")
            for gap in consolidated_report.compliance_gaps[:5]:  # Show first 5
                print(f"  • {gap}")
            if len(consolidated_report.compliance_gaps) > 5:
                print(f"  ... and {len(consolidated_report.compliance_gaps) - 5} more")
        
        if consolidated_report.recommendations:
            print(f"\\n💡 Recommendations ({len(consolidated_report.recommendations)}):")
            for rec in consolidated_report.recommendations[:3]:  # Show first 3
                print(f"  • {rec}")
            if len(consolidated_report.recommendations) > 3:
                print(f"  ... and {len(consolidated_report.recommendations) - 3} more")
        
        return 0 if consolidated_report.report_completeness != 'INCOMPLETE' else 1
        
    except Exception as e:
        orchestrator.logger.error(f"Master evidence orchestration failed: {str(e)}")
        print(f"❌ Error: {str(e)}")
        return 1


if __name__ == "__main__":
    exit(main())