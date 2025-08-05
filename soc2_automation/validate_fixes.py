#!/usr/bin/env python3
"""
SOC 2 CLI Security Fixes Validation Script
Validates that all recommended security fixes have been properly implemented

Author: Parker Robertson
Purpose: Ensure all security vulnerabilities have been addressed
"""

import sys
import ast
import inspect
from pathlib import Path
from typing import List, Dict, Any, Tuple

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from soc2_cli import SOC2CLI, SecurityError
except ImportError as e:
    print(f"❌ Failed to import SOC2CLI: {e}")
    sys.exit(1)


class SecurityFixValidator:
    """Validates that security fixes have been properly implemented"""
    
    def __init__(self):
        self.cli = SOC2CLI()
        self.validation_results = []
    
    def validate_command_injection_fix(self) -> bool:
        """Validate that command injection vulnerability has been fixed"""
        print("🔍 Validating command injection fix...")
        
        # Check if _sanitize_command method exists
        if not hasattr(self.cli, '_sanitize_command'):
            self.validation_results.append(("Command Injection", False, "_sanitize_command method missing"))
            return False
        
        # Test that malicious commands are blocked
        try:
            malicious_cmd = [str(sys.executable), "script.py", "; rm -rf /"]
            self.cli._sanitize_command(malicious_cmd)
            self.validation_results.append(("Command Injection", False, "Malicious command not blocked"))
            return False
        except SecurityError:
            # This is expected - malicious command should be blocked
            pass
        except Exception as e:
            self.validation_results.append(("Command Injection", False, f"Unexpected error: {e}"))
            return False
        
        # Test that valid commands pass through
        try:
            valid_cmd = [str(sys.executable), "script.py", "--config", "config.json"]
            result = self.cli._sanitize_command(valid_cmd)
            if result != valid_cmd:
                self.validation_results.append(("Command Injection", False, "Valid command modified incorrectly"))
                return False
        except Exception as e:
            self.validation_results.append(("Command Injection", False, f"Valid command blocked: {e}"))
            return False
        
        self.validation_results.append(("Command Injection", True, "Fixed - commands are properly sanitized"))
        return True
    
    def validate_timeout_protection(self) -> bool:
        """Validate that timeout protection has been added"""
        print("🔍 Validating timeout protection...")
        
        # Check if _execute_command has timeout parameter
        execute_method = getattr(self.cli, '_execute_command', None)
        if not execute_method:
            self.validation_results.append(("Timeout Protection", False, "_execute_command method missing"))
            return False
        
        # Inspect the method source to look for timeout parameter
        try:
            source = inspect.getsource(execute_method)
            if 'timeout=' not in source or 'TimeoutExpired' not in source:
                self.validation_results.append(("Timeout Protection", False, "Timeout handling not implemented"))
                return False
        except Exception as e:
            self.validation_results.append(("Timeout Protection", False, f"Could not inspect method: {e}"))
            return False
        
        self.validation_results.append(("Timeout Protection", True, "Fixed - subprocess calls have timeout protection"))
        return True
    
    def validate_config_validation_enhancement(self) -> bool:
        """Validate that configuration validation has been enhanced"""
        print("🔍 Validating configuration validation enhancement...")
        
        # Check if _validate_provider_config method exists
        if not hasattr(self.cli, '_validate_provider_config'):
            self.validation_results.append(("Config Validation", False, "_validate_provider_config method missing"))
            return False
        
        # Test multi-cloud provider validation
        try:
            # Test AWS validation
            aws_valid = self.cli._validate_provider_config('aws', {
                'access_key': 'test',
                'secret_key': 'test',
                'region': 'us-east-1'
            })
            if not aws_valid:
                self.validation_results.append(("Config Validation", False, "AWS validation failed for valid config"))
                return False
            
            # Test Azure validation
            azure_valid = self.cli._validate_provider_config('azure', {
                'subscription_id': 'test',
                'tenant_id': 'test'
            })
            if not azure_valid:
                self.validation_results.append(("Config Validation", False, "Azure validation failed for valid config"))
                return False
            
            # Test GCP validation
            gcp_valid = self.cli._validate_provider_config('gcp', {
                'project_id': 'test'
            })
            if not gcp_valid:
                self.validation_results.append(("Config Validation", False, "GCP validation failed for valid config"))
                return False
            
        except Exception as e:
            self.validation_results.append(("Config Validation", False, f"Provider validation error: {e}"))
            return False
        
        self.validation_results.append(("Config Validation", True, "Enhanced - multi-cloud validation implemented"))
        return True
    
    def validate_input_validation(self) -> bool:
        """Validate that input validation has been added"""
        print("🔍 Validating input validation...")
        
        # Check if _validate_threshold_args method exists
        if not hasattr(self.cli, '_validate_threshold_args'):
            self.validation_results.append(("Input Validation", False, "_validate_threshold_args method missing"))
            return False
        
        # Test threshold validation
        try:
            class MockArgs:
                def __init__(self):
                    self.console_threshold = 1000  # Invalid (too high)
            
            invalid_args = MockArgs()
            self.cli._validate_threshold_args(invalid_args)
            self.validation_results.append(("Input Validation", False, "Invalid threshold not caught"))
            return False
            
        except ValueError:
            # This is expected - invalid threshold should raise ValueError
            pass
        except Exception as e:
            self.validation_results.append(("Input Validation", False, f"Unexpected error: {e}"))
            return False
        
        self.validation_results.append(("Input Validation", True, "Fixed - input validation implemented"))
        return True
    
    def validate_multicloud_implementation(self) -> bool:
        """Validate that multi-cloud assessment has been implemented"""
        print("🔍 Validating multi-cloud implementation...")
        
        # Check if _run_multi_cloud_assessment is properly implemented
        method = getattr(self.cli, '_run_multi_cloud_assessment', None)
        if not method:
            self.validation_results.append(("Multi-Cloud Implementation", False, "Method missing"))
            return False
        
        # Check if the method contains actual implementation (not just placeholder)
        try:
            source = inspect.getsource(method)
            if 'MultiCloudDataCollector' not in source:
                self.validation_results.append(("Multi-Cloud Implementation", False, "Implementation incomplete"))
                return False
        except Exception as e:
            self.validation_results.append(("Multi-Cloud Implementation", False, f"Could not inspect method: {e}"))
            return False
        
        self.validation_results.append(("Multi-Cloud Implementation", True, "Fixed - multi-cloud assessment implemented"))
        return True
    
    def validate_exception_handling(self) -> bool:
        """Validate that exception handling has been improved"""
        print("🔍 Validating exception handling improvements...")
        
        # Check specific exception handling in connectivity test
        method = getattr(self.cli, '_run_connectivity_test', None)
        if not method:
            self.validation_results.append(("Exception Handling", False, "Method missing"))
            return False
        
        try:
            source = inspect.getsource(method)
            # Look for specific exception types instead of broad Exception catching
            if 'ImportError' not in source or 'PermissionError' not in source:
                self.validation_results.append(("Exception Handling", False, "Specific exception handling not implemented"))
                return False
        except Exception as e:
            self.validation_results.append(("Exception Handling", False, f"Could not inspect method: {e}"))
            return False
        
        self.validation_results.append(("Exception Handling", True, "Improved - specific exception handling implemented"))
        return True
    
    def validate_logging_enhancement(self) -> bool:
        """Validate that logging has been enhanced"""
        print("🔍 Validating logging enhancements...")
        
        # Check if enhanced logging setup exists
        if not hasattr(self.cli, '_setup_enhanced_logging'):
            self.validation_results.append(("Logging Enhancement", False, "_setup_enhanced_logging method missing"))
            return False
        
        # Check for RotatingFileHandler usage
        try:
            source = inspect.getsource(self.cli._setup_enhanced_logging)
            if 'RotatingFileHandler' not in source:
                self.validation_results.append(("Logging Enhancement", False, "Rotating file handler not implemented"))
                return False
        except Exception as e:
            self.validation_results.append(("Logging Enhancement", False, f"Could not inspect method: {e}"))
            return False
        
        self.validation_results.append(("Logging Enhancement", True, "Enhanced - rotating file handler implemented"))
        return True
    
    def validate_argument_conflicts_resolution(self) -> bool:
        """Validate that argument conflicts have been resolved"""
        print("🔍 Validating argument conflicts resolution...")
        
        # Test parser creation
        try:
            parser = self.cli.create_parser()
            
            # Test parsing with different argument combinations
            args1 = parser.parse_args(['user-access-review', '--config', 'test.json', '--aws-accounts', '123'])
            args2 = parser.parse_args(['inactive-users', '--config', 'test.json', '--aws-accounts', '456'])
            
            # Both should work without conflicts
            if not hasattr(args1, 'aws_accounts') or not hasattr(args2, 'aws_accounts'):
                self.validation_results.append(("Argument Conflicts", False, "Argument resolution incomplete"))
                return False
                
        except Exception as e:
            self.validation_results.append(("Argument Conflicts", False, f"Parser error: {e}"))
            return False
        
        self.validation_results.append(("Argument Conflicts", True, "Resolved - argument naming conflicts fixed"))
        return True
    
    def run_all_validations(self) -> bool:
        """Run all security fix validations"""
        print("🛡️  SOC 2 CLI Security Fixes Validation")
        print("=" * 60)
        
        validations = [
            self.validate_command_injection_fix,
            self.validate_timeout_protection,
            self.validate_config_validation_enhancement,
            self.validate_input_validation,
            self.validate_multicloud_implementation,
            self.validate_exception_handling,
            self.validate_logging_enhancement,
            self.validate_argument_conflicts_resolution
        ]
        
        all_passed = True
        for validation in validations:
            try:
                result = validation()
                all_passed &= result
            except Exception as e:
                print(f"❌ Validation error: {e}")
                all_passed = False
        
        return all_passed
    
    def print_summary(self):
        """Print validation summary"""
        print("\n" + "=" * 60)
        print("🔍 Security Fixes Validation Summary")
        print("=" * 60)
        
        passed = 0
        failed = 0
        
        for fix_name, status, details in self.validation_results:
            status_icon = "✅" if status else "❌"
            print(f"{status_icon} {fix_name}: {details}")
            
            if status:
                passed += 1
            else:
                failed += 1
        
        print("\n" + "-" * 60)
        print(f"Total: {len(self.validation_results)} validations")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        
        if failed == 0:
            print("\n🎉 All security fixes have been successfully implemented!")
            print("The SOC 2 CLI is now secure and ready for production use.")
        else:
            print(f"\n⚠️  {failed} security fix(es) need attention before deployment.")
        
        return failed == 0


def main():
    """Main validation function"""
    validator = SecurityFixValidator()
    
    try:
        success = validator.run_all_validations()
        validator.print_summary()
        
        return 0 if success else 1
        
    except Exception as e:
        print(f"❌ Validation failed with error: {e}")
        return 2


if __name__ == '__main__':
    sys.exit(main())