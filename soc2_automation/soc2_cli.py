#!/usr/bin/env python3
"""
SOC 2 Audit Automation CLI
Unified command-line interface for all SOC 2 compliance automation tools

This provides a single entry point for beginners to execute SOC 2 audit tasks:
- User access reviews and inactive user detection
- Evidence collection across systems
- Configuration drift detection
- Comprehensive audit reporting

Author: Parker Robertson
Purpose: Simplify SOC 2 audit execution with unified interface
"""

import argparse
import sys
import os
from pathlib import Path
import subprocess
import json

# Add the current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from lib.soc2_utils import SOC2Utils


class SOC2CLI:
    """Unified CLI for SOC 2 audit automation"""
    
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.logger = SOC2Utils.setup_logging()
    
    def create_parser(self):
        """Create the main argument parser with subcommands"""
        parser = argparse.ArgumentParser(
            prog='soc2-audit',
            description='SOC 2 Compliance Audit Automation Toolkit',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Available Commands:
  user-access-review    Run comprehensive user access review across systems
  inactive-users        Detect inactive users in AWS (legacy compatibility)
  evidence-collection   Collect audit evidence from configured systems
  config-drift          Detect configuration drift in infrastructure
  
Examples:
  soc2-audit user-access-review --config config.json --systems aws github
  soc2-audit evidence-collection --config config.json --controls CC6.1,CC6.2
  soc2-audit inactive-users --config config.json --accounts 123456789012
  soc2-audit config-drift --config config.json
            """
        )
        
        # Global arguments
        parser.add_argument('--version', action='version', version='SOC2 Audit CLI 1.0.0')
        parser.add_argument('--config', required=True, 
                           help='Path to SOC 2 configuration JSON file')
        parser.add_argument('--output-dir', 
                           help='Custom output directory for all reports')
        parser.add_argument('--verbose', '-v', action='store_true',
                           help='Enable verbose logging')
        
        # Create subparsers for different commands
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # User Access Review command
        self._add_user_access_review_parser(subparsers)
        
        # Inactive Users command (legacy compatibility)
        self._add_inactive_users_parser(subparsers)
        
        # Evidence Collection command
        self._add_evidence_collection_parser(subparsers)
        
        # Configuration Drift command
        self._add_config_drift_parser(subparsers)
        
        return parser
    
    def _add_user_access_review_parser(self, subparsers):
        """Add user access review subcommand"""
        parser = subparsers.add_parser(
            'user-access-review',
            help='Run comprehensive user access review',
            description='Analyze user access across AWS, Active Directory, and GitHub'
        )
        parser.add_argument('--systems', nargs='*', 
                          choices=['aws', 'active_directory', 'github'],
                          help='Systems to include in review (default: all configured)')
        parser.add_argument('--accounts', nargs='*',
                          help='Specific AWS account IDs to analyze')
        parser.add_argument('--console-threshold', type=int, default=90,
                          help='Console inactivity threshold in days (default: 90)')
        parser.add_argument('--access-key-threshold', type=int, default=180,
                          help='Access key inactivity threshold in days (default: 180)')
        parser.add_argument('--permission-threshold', type=int, default=10,
                          help='Excessive permissions threshold (default: 10)')
        parser.add_argument('--create-tickets', action='store_true',
                          help='Create remediation tickets for findings')
        parser.set_defaults(func=self._run_user_access_review)
    
    def _add_inactive_users_parser(self, subparsers):
        """Add inactive users subcommand (legacy compatibility)"""
        parser = subparsers.add_parser(
            'inactive-users',
            help='Detect inactive users in AWS (legacy mode)',
            description='AWS-focused inactive user detection for backward compatibility'
        )
        parser.add_argument('--accounts', nargs='*',
                          help='Specific AWS account IDs to analyze')
        parser.add_argument('--console-threshold', type=int, default=90,
                          help='Console inactivity threshold in days (default: 90)')
        parser.add_argument('--access-key-threshold', type=int, default=180,
                          help='Access key inactivity threshold in days (default: 180)')
        parser.add_argument('--create-tickets', action='store_true',
                          help='Create remediation tickets for findings')
        parser.set_defaults(func=self._run_inactive_users)
    
    def _add_evidence_collection_parser(self, subparsers):
        """Add evidence collection subcommand"""
        parser = subparsers.add_parser(
            'evidence-collection',
            help='Collect SOC 2 audit evidence',
            description='Gather evidence from systems for SOC 2 compliance'
        )
        parser.add_argument('--controls', nargs='*',
                          help='Specific SOC 2 controls to collect evidence for')
        parser.add_argument('--evidence-types', nargs='*',
                          choices=['ACCESS', 'CONFIG', 'MONITORING', 'CHANGE_MANAGEMENT'],
                          help='Types of evidence to collect')
        parser.set_defaults(func=self._run_evidence_collection)
    
    def _add_config_drift_parser(self, subparsers):
        """Add configuration drift subcommand"""
        parser = subparsers.add_parser(
            'config-drift',
            help='Detect configuration drift',
            description='Monitor infrastructure configuration changes'
        )
        parser.add_argument('--baseline-file',
                          help='Path to baseline configuration file')
        parser.add_argument('--systems', nargs='*',
                          choices=['aws', 'linux'],
                          help='Systems to check for drift')
        parser.set_defaults(func=self._run_config_drift)
    
    def _run_user_access_review(self, args):
        """Execute user access review"""
        self.logger.info("🔍 Running comprehensive user access review...")
        
        cmd = [
            sys.executable,
            str(self.base_dir / 'inactive_users_detector.py'),
            '--config', args.config,
            '--mode', 'comprehensive-review'
        ]
        
        if args.systems:
            cmd.extend(['--systems'] + args.systems)
        if args.accounts:
            cmd.extend(['--accounts'] + args.accounts)
        if args.output_dir:
            cmd.extend(['--output-dir', args.output_dir])
        if args.console_threshold:
            cmd.extend(['--console-threshold', str(args.console_threshold)])
        if args.access_key_threshold:
            cmd.extend(['--access-key-threshold', str(args.access_key_threshold)])
        if args.permission_threshold:
            cmd.extend(['--permission-threshold', str(args.permission_threshold)])
        if args.create_tickets:
            cmd.append('--create-tickets')
        
        return self._execute_command(cmd)
    
    def _run_inactive_users(self, args):
        """Execute inactive users detection (legacy mode)"""
        self.logger.info("🔍 Running AWS inactive users detection...")
        
        cmd = [
            sys.executable,
            str(self.base_dir / 'inactive_users_detector.py'),
            '--config', args.config,
            '--mode', 'inactive-users'
        ]
        
        if args.accounts:
            cmd.extend(['--accounts'] + args.accounts)
        if args.output_dir:
            cmd.extend(['--output-dir', args.output_dir])
        if args.console_threshold:
            cmd.extend(['--console-threshold', str(args.console_threshold)])
        if args.access_key_threshold:
            cmd.extend(['--access-key-threshold', str(args.access_key_threshold)])
        if args.create_tickets:
            cmd.append('--create-tickets')
        
        return self._execute_command(cmd)
    
    def _run_evidence_collection(self, args):
        """Execute evidence collection"""
        self.logger.info("📋 Running evidence collection...")
        
        cmd = [
            sys.executable,
            str(self.base_dir / 'evidence_collector.py'),
            '--config', args.config
        ]
        
        if args.controls:
            cmd.extend(['--controls'] + args.controls)
        if args.evidence_types:
            cmd.extend(['--evidence-types'] + args.evidence_types)
        if args.output_dir:
            cmd.extend(['--output-dir', args.output_dir])
        
        return self._execute_command(cmd)
    
    def _run_config_drift(self, args):
        """Execute configuration drift detection"""
        self.logger.info("⚙️  Running configuration drift detection...")
        
        cmd = [
            sys.executable,
            str(self.base_dir / 'config_drift_processor.py'),
            '--config', args.config
        ]
        
        if args.baseline_file:
            cmd.extend(['--baseline', args.baseline_file])
        if args.systems:
            cmd.extend(['--systems'] + args.systems)
        if args.output_dir:
            cmd.extend(['--output-dir', args.output_dir])
        
        return self._execute_command(cmd)
    
    def _execute_command(self, cmd):
        """Execute a command and handle the result"""
        try:
            self.logger.debug(f"Executing: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Print stdout and stderr
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print(result.stderr, file=sys.stderr)
            
            return result.returncode
            
        except Exception as e:
            self.logger.error(f"Failed to execute command: {str(e)}")
            return 1
    
    def _validate_config(self, config_path: str) -> bool:
        """Validate configuration file exists and is valid JSON"""
        try:
            if not os.path.exists(config_path):
                print(f"❌ Configuration file not found: {config_path}")
                return False
            
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            # Basic validation - ensure we have at least one system configured
            if not any(key in config for key in ['aws', 'active_directory', 'github']):
                print("❌ Configuration must include at least one system (aws, active_directory, github)")
                return False
            
            return True
            
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON in configuration file: {str(e)}")
            return False
        except Exception as e:
            print(f"❌ Error validating configuration: {str(e)}")
            return False
    
    def run(self):
        """Main CLI execution"""
        parser = self.create_parser()
        args = parser.parse_args()
        
        # Handle case where no command is provided
        if not args.command:
            parser.print_help()
            return 1
        
        # Set up verbose logging if requested
        if args.verbose:
            import logging
            logging.getLogger().setLevel(logging.DEBUG)
        
        # Validate configuration
        if not self._validate_config(args.config):
            return 1
        
        # Print header
        print("🛡️  SOC 2 Audit Automation Toolkit")
        print("=" * 50)
        
        # Execute the appropriate command
        try:
            return args.func(args)
        except Exception as e:
            self.logger.error(f"Command execution failed: {str(e)}")
            return 1


def main():
    """Entry point for the CLI"""
    cli = SOC2CLI()
    exit_code = cli.run()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()