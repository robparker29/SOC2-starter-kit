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
import logging
from logging.handlers import RotatingFileHandler
import concurrent.futures
from typing import List, Dict, Any, Tuple

# Add the current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from lib.soc2_utils import SOC2Utils
from lib.cloud_providers import CloudProviderFactory


class SecurityError(Exception):
    """Raised when security validation fails"""
    pass


class SOC2CLI:
    """Unified CLI for SOC 2 audit automation"""
    
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.logger = SOC2Utils.setup_logging()
        self.max_command_timeout = 300  # 5 minutes
        self.allowed_executables = [sys.executable, 'python', 'python3']
    
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
  soc2-audit user-access-review --config config.json --cloud-providers aws azure
  soc2-audit evidence-collection --config config.json --controls CC6.1,CC6.2 --cloud-providers gcp
  soc2-audit inactive-users --config config.json --accounts 123456789012 --cloud-providers aws
  soc2-audit multi-cloud-assessment --config config.json --parallel
  soc2-audit config-drift --config config.json --cloud-providers aws azure gcp
            """
        )
        
        # Global arguments
        parser.add_argument('--version', action='version', version='SOC2 Audit CLI 2.0.0 (Multi-Cloud)')
        parser.add_argument('--config', required=True, 
                           help='Path to SOC 2 configuration JSON file')
        parser.add_argument('--output-dir', 
                           help='Custom output directory for all reports')
        parser.add_argument('--cloud-providers', nargs='*', 
                           choices=['aws', 'azure', 'gcp'], 
                           help='Specific cloud providers to target (default: all configured)')
        parser.add_argument('--accounts', nargs='*',
                           help='Specific account/subscription/project IDs to analyze')
        parser.add_argument('--verbose', '-v', action='store_true',
                           help='Enable verbose logging')
        parser.add_argument('--parallel', action='store_true',
                           help='Execute operations across cloud providers in parallel')
        
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
        
        # Multi-Cloud Assessment command
        self._add_multi_cloud_assessment_parser(subparsers)
        
        # Cloud Connectivity Test command
        self._add_connectivity_test_parser(subparsers)
        
        # Master Evidence Orchestrator command
        self._add_master_orchestrator_parser(subparsers)
        
        return parser
    
    def _add_user_access_review_parser(self, subparsers):
        """Add user access review subcommand"""
        parser = subparsers.add_parser(
            'user-access-review',
            help='Run comprehensive user access review',
            description='Analyze user access across AWS, Active Directory, and GitHub'
        )
        parser.add_argument('--systems', nargs='*', 
                          choices=['aws', 'azure', 'gcp', 'active_directory', 'github'],
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
                          choices=['ACCESS', 'CONFIG', 'MONITORING', 'CHANGE_MANAGEMENT',
                                  'DATABASE_SECURITY', 'NETWORK_SECURITY', 'VENDOR_ACCESS'],
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
        if hasattr(args, 'aws_accounts') and args.aws_accounts:
            cmd.extend(['--accounts'] + args.aws_accounts)
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
        
        if hasattr(args, 'aws_accounts') and args.aws_accounts:
            cmd.extend(['--accounts'] + args.aws_accounts)
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
    
    def _add_multi_cloud_assessment_parser(self, subparsers):
        """Add multi-cloud assessment subcommand"""
        parser = subparsers.add_parser(
            'multi-cloud-assessment',
            help='Run comprehensive multi-cloud security assessment',
            description='Analyze security posture across AWS, Azure, and GCP simultaneously'
        )
        parser.add_argument('--assessment-types', nargs='*',
                          choices=['access_review', 'network_security', 'compliance_check', 'drift_detection'],
                          help='Types of assessments to run (default: all)')
        parser.add_argument('--generate-cross-cloud-report', action='store_true',
                          help='Generate unified report spanning all cloud providers')
        parser.set_defaults(func=self._run_multi_cloud_assessment)
    
    def _add_connectivity_test_parser(self, subparsers):
        """Add connectivity test subcommand"""
        parser = subparsers.add_parser(
            'test-connectivity',
            help='Test connectivity to all configured cloud providers',
            description='Validate authentication and API connectivity across cloud providers'
        )
        parser.set_defaults(func=self._run_connectivity_test)
    
    def _add_master_orchestrator_parser(self, subparsers):
        """Add master evidence orchestrator subcommand"""
        parser = subparsers.add_parser(
            'master-evidence-orchestrator',
            help='Run comprehensive evidence collection orchestration',
            description='Coordinate all evidence collection scripts and generate consolidated report'
        )
        parser.add_argument('--environment', 
                          choices=['production', 'staging', 'development'],
                          default='production',
                          help='Target environment for evidence collection')
        parser.add_argument('--exclude-types', nargs='*',
                          choices=['DATABASE_SECURITY', 'NETWORK_SECURITY', 'VENDOR_ACCESS'],
                          help='Evidence types to exclude from collection')
        parser.add_argument('--report-name',
                          help='Custom name for the consolidated report')
        parser.set_defaults(func=self._run_master_orchestrator)
    
    def _run_multi_cloud_assessment(self, _args):
        """Execute comprehensive multi-cloud assessment"""
        self.logger.info("🌐 Running multi-cloud security assessment...")
        
        # This would be implemented to use the cloud provider factory
        # and run assessments across all configured cloud providers
        print("Multi-cloud assessment functionality will be implemented with full cloud provider integration")
        return 0
    
    def _run_connectivity_test(self, args):
        """Test connectivity to cloud providers"""
        self.logger.info("🔗 Testing cloud provider connectivity...")
        
        try:
            config = SOC2Utils.load_json_config(args.config)
            providers = CloudProviderFactory.create_multi_cloud_session(config, self.logger)
            
            print(f"\n🌐 Cloud Provider Connectivity Test")
            print(f"=" * 50)
            
            for provider_name, provider in providers.items():
                print(f"\n{provider_name}:")
                connectivity_results = provider.validate_connectivity()
                
                for service, status in connectivity_results.items():
                    status_icon = "✅" if status else "❌"
                    print(f"  {status_icon} {service}: {'Connected' if status else 'Failed'}")
            
            # Print available providers
            available = CloudProviderFactory.get_available_providers()
            print(f"\n📦 Available Providers (SDKs installed): {', '.join(available)}")
            
            return 0
            
        except Exception as e:
            self.logger.error(f"Connectivity test failed: {str(e)}")
            return 1
    
    def _run_master_orchestrator(self, args):
        """Execute master evidence orchestrator"""
        self.logger.info("🎯 Running master evidence orchestration...")
        
        cmd = [
            sys.executable,
            str(self.base_dir / 'master_evidence_orchestrator.py'),
            '--config', args.config
        ]
        
        if args.environment:
            cmd.extend(['--environment', args.environment])
        if args.exclude_types:
            cmd.extend(['--exclude-types'] + args.exclude_types)
        if args.report_name:
            cmd.extend(['--report-name', args.report_name])
        if args.output_dir:
            cmd.extend(['--output-dir', args.output_dir])
        if args.cloud_providers:
            cmd.extend(['--cloud-providers'] + args.cloud_providers)
        if args.parallel:
            cmd.append('--parallel')
        
        return self._execute_command(cmd)
    
    def _execute_command(self, cmd: List[str]) -> int:
        """Execute a command and handle the result with security validation"""
        try:
            # Validate and sanitize command
            sanitized_cmd = self._sanitize_command(cmd)
            
            self.logger.debug(f"Executing: {' '.join(sanitized_cmd)}")
            result = subprocess.run(
                sanitized_cmd, 
                capture_output=True, 
                text=True,
                timeout=self.max_command_timeout,
                check=False
            )
            
            # Print stdout and stderr
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print(result.stderr, file=sys.stderr)
            
            return result.returncode
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"Command timed out after {self.max_command_timeout} seconds")
            print(f"❌ Command timed out after {self.max_command_timeout} seconds")
            return 1
        except (ValueError, SecurityError) as e:
            self.logger.error(f"Security validation failed: {str(e)}")
            print(f"❌ Security error: {str(e)}")
            return 1
        except Exception as e:
            self.logger.error(f"Failed to execute command: {str(e)}")
            print(f"❌ Command execution failed: {str(e)}")
            return 1
    
    def _validate_config(self, config_path: str) -> bool:
        """Validate configuration file exists and is valid JSON with multi-cloud support"""
        try:
            if not os.path.exists(config_path):
                print(f"❌ Configuration file not found: {config_path}")
                return False
            
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            # Enhanced validation for multi-cloud support
            cloud_providers = ['aws', 'azure', 'gcp']
            legacy_systems = ['active_directory', 'github']
            all_systems = cloud_providers + legacy_systems
            
            if not any(key in config for key in all_systems):
                print(f"❌ Configuration must include at least one system: {', '.join(all_systems)}")
                return False
            
            # Validate enabled cloud providers have required fields
            for provider in cloud_providers:
                if provider in config and config[provider].get('_enabled', True):
                    if not self._validate_provider_config(provider, config[provider]):
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
            self.logger.setLevel(logging.DEBUG)
            # Also set the root logger level for dependencies
            logging.getLogger().setLevel(logging.DEBUG)
        
        # Validate input arguments
        try:
            self._validate_threshold_args(args)
        except ValueError as e:
            print(f"❌ Invalid argument: {str(e)}")
            return 1
        
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


    def _setup_enhanced_logging(self) -> logging.Logger:
        """Setup enhanced logging with rotation and structured output"""
        logger = logging.getLogger('soc2_cli')
        logger.setLevel(logging.INFO)
        
        # Clear any existing handlers
        logger.handlers.clear()
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_format)
        logger.addHandler(console_handler)
        
        # File handler with rotation
        log_dir = self.base_dir / 'logs'
        log_dir.mkdir(exist_ok=True)
        
        file_handler = RotatingFileHandler(
            log_dir / 'soc2_cli.log',
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setFormatter(console_format)
        logger.addHandler(file_handler)
        
        return logger
    
    def _sanitize_command(self, cmd: List[str]) -> List[str]:
        """Sanitize command arguments to prevent injection attacks"""
        if not isinstance(cmd, list):
            raise ValueError("Command must be a list")
        
        if not cmd:
            raise ValueError("Command cannot be empty")
        
        # Validate command components
        sanitized_cmd = []
        for i, arg in enumerate(cmd):
            if not isinstance(arg, str):
                raise ValueError(f"Invalid command argument type at position {i}: {type(arg)}")
            
            # Check the executable (first argument)
            if i == 0:
                if arg not in self.allowed_executables:
                    raise SecurityError(f"Executable not allowed: {arg}")
            else:
                # Basic path traversal protection for other arguments
                if '..' in arg:
                    raise SecurityError(f"Path traversal attempt detected: {arg}")
                
                # Check for potentially dangerous characters in non-option arguments
                if not arg.startswith('--') and not arg.startswith('-'):
                    dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '<', '>']
                    if any(char in arg for char in dangerous_chars):
                        # Allow these characters only in known safe contexts (like file paths)
                        if not (os.path.isabs(arg) or arg.endswith('.json') or arg.endswith('.py')):
                            raise SecurityError(f"Potentially dangerous characters in argument: {arg}")
            
            sanitized_cmd.append(arg)
        
        return sanitized_cmd
    
    def _validate_provider_config(self, provider: str, config: Dict[str, Any]) -> bool:
        """Validate provider-specific configuration"""
        required_fields = {
            'aws': ['access_key', 'secret_key', 'region'],
            'azure': ['subscription_id', 'tenant_id'],
            'gcp': ['project_id']
        }
        
        if provider not in required_fields:
            return True  # Unknown provider, skip validation
        
        missing_fields = []
        for field in required_fields[provider]:
            if field not in config or not config[field]:
                # Allow alternative authentication methods
                if provider == 'aws' and field in ['access_key', 'secret_key'] and 'profile' in config:
                    continue  # AWS profile authentication
                if provider == 'azure' and field in ['tenant_id'] and config.get('use_managed_identity'):
                    continue  # Azure managed identity
                if provider == 'gcp' and field == 'project_id' and 'service_account_key_path' not in config:
                    missing_fields.append(field)
                elif provider != 'gcp':
                    missing_fields.append(field)
        
        if missing_fields:
            print(f"❌ {provider.upper()} configuration missing required fields: {', '.join(missing_fields)}")
            return False
        
        return True
    
    def _validate_threshold_args(self, args) -> None:
        """Validate threshold arguments are within reasonable ranges"""
        thresholds = {
            'console_threshold': (1, 365),
            'access_key_threshold': (1, 730),
            'permission_threshold': (1, 100)
        }
        
        for attr, (min_val, max_val) in thresholds.items():
            if hasattr(args, attr) and getattr(args, attr) is not None:
                value = getattr(args, attr)
                if not isinstance(value, int) or not (min_val <= value <= max_val):
                    raise ValueError(f"{attr} must be an integer between {min_val} and {max_val}")
    
    def _execute_parallel_commands(self, commands: List[List[str]], max_workers: int = 3) -> List[Tuple[List[str], int]]:
        """Execute multiple commands in parallel"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self._execute_command, cmd): cmd for cmd in commands}
            
            results = []
            for future in concurrent.futures.as_completed(futures):
                cmd = futures[future]
                try:
                    result = future.result()
                    results.append((cmd, result))
                except Exception as e:
                    self.logger.error(f"Parallel command failed: {cmd}, Error: {e}")
                    results.append((cmd, 1))
            
            return results


def main():
    """Entry point for the CLI"""
    cli = SOC2CLI()
    exit_code = cli.run()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()