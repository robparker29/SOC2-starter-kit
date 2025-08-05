#!/usr/bin/env python3
"""
Unit Tests for SOC 2 CLI
Tests critical security and functionality aspects of the CLI

Author: Parker Robertson
Purpose: Ensure security and reliability of SOC 2 automation CLI
"""

import unittest
from unittest.mock import patch, MagicMock, mock_open
import tempfile
import json
import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from soc2_cli import SOC2CLI, SecurityError


class TestSOC2CLI(unittest.TestCase):
    """Test cases for SOC2CLI class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.cli = SOC2CLI()
        
        # Create a temporary config file for testing
        self.test_config = {
            "aws": {
                "_enabled": True,
                "access_key": "test_key",
                "secret_key": "test_secret",
                "region": "us-east-1"
            },
            "azure": {
                "_enabled": True,  
                "subscription_id": "test-subscription",
                "tenant_id": "test-tenant"
            },
            "gcp": {
                "_enabled": True,
                "project_id": "test-project"
            }
        }
    
    def tearDown(self):
        """Clean up test fixtures"""
        pass
    
    def test_validate_config_with_valid_multicloud_config(self):
        """Test configuration validation with valid multi-cloud setup"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(self.test_config, f)
            f.flush()
            
            try:
                result = self.cli._validate_config(f.name)
                self.assertTrue(result)
            finally:
                os.unlink(f.name)
    
    def test_validate_config_with_missing_file(self):
        """Test configuration validation with missing file"""
        result = self.cli._validate_config('/nonexistent/config.json')
        self.assertFalse(result)
    
    def test_validate_config_with_invalid_json(self):
        """Test configuration validation with invalid JSON"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{"invalid": json}')  # Invalid JSON
            f.flush()
            
            try:
                result = self.cli._validate_config(f.name)
                self.assertFalse(result)
            finally:
                os.unlink(f.name)
    
    def test_validate_config_with_no_systems(self):
        """Test configuration validation with no configured systems"""
        empty_config = {}
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(empty_config, f)
            f.flush()
            
            try:
                result = self.cli._validate_config(f.name)
                self.assertFalse(result)
            finally:
                os.unlink(f.name)
    
    def test_sanitize_command_with_valid_command(self):
        """Test command sanitization with valid command"""
        cmd = [str(sys.executable), "script.py", "--config", "config.json"]
        result = self.cli._sanitize_command(cmd)
        self.assertEqual(result, cmd)
    
    def test_sanitize_command_injection_prevention(self):
        """Test that command injection attempts are blocked"""
        malicious_commands = [
            [str(sys.executable), "script.py", "; rm -rf /"],
            [str(sys.executable), "script.py", "| cat /etc/passwd"],
            [str(sys.executable), "script.py", "&& malicious_command"],
            [str(sys.executable), "script.py", "`whoami`"],
            [str(sys.executable), "script.py", "$(evil_command)"]
        ]
        
        for cmd in malicious_commands:
            with self.assertRaises(SecurityError):
                self.cli._sanitize_command(cmd)
    
    def test_sanitize_command_path_traversal_prevention(self):
        """Test that path traversal attempts are blocked"""
        malicious_cmd = [str(sys.executable), "script.py", "../../../etc/passwd"]
        
        with self.assertRaises(SecurityError):
            self.cli._sanitize_command(malicious_cmd)
    
    def test_sanitize_command_invalid_executable(self):
        """Test that unauthorized executables are blocked"""
        malicious_cmd = ["/bin/sh", "-c", "evil_command"]
        
        with self.assertRaises(SecurityError):
            self.cli._sanitize_command(malicious_cmd)
    
    def test_sanitize_command_invalid_input_types(self):
        """Test command sanitization with invalid input types"""
        # Test non-list input
        with self.assertRaises(ValueError):
            self.cli._sanitize_command("not a list")
        
        # Test empty command
        with self.assertRaises(ValueError):
            self.cli._sanitize_command([])
        
        # Test non-string arguments
        with self.assertRaises(ValueError):
            self.cli._sanitize_command([str(sys.executable), 123, "arg"])
    
    def test_validate_provider_config_aws(self):
        """Test AWS provider configuration validation"""
        # Valid AWS config
        aws_config = {
            "access_key": "test_key",
            "secret_key": "test_secret", 
            "region": "us-east-1"
        }
        self.assertTrue(self.cli._validate_provider_config('aws', aws_config))
        
        # AWS config with profile (alternative auth)
        aws_config_profile = {
            "profile": "default",
            "region": "us-east-1"
        }
        self.assertTrue(self.cli._validate_provider_config('aws', aws_config_profile))
        
        # Invalid AWS config - missing required fields
        aws_config_invalid = {
            "region": "us-east-1"
        }
        self.assertFalse(self.cli._validate_provider_config('aws', aws_config_invalid))
    
    def test_validate_provider_config_azure(self):
        """Test Azure provider configuration validation"""
        # Valid Azure config
        azure_config = {
            "subscription_id": "test-subscription",
            "tenant_id": "test-tenant"
        }
        self.assertTrue(self.cli._validate_provider_config('azure', azure_config))
        
        # Azure config with managed identity
        azure_config_managed = {
            "subscription_id": "test-subscription",
            "use_managed_identity": True
        }
        self.assertTrue(self.cli._validate_provider_config('azure', azure_config_managed))
        
        # Invalid Azure config
        azure_config_invalid = {
            "tenant_id": "test-tenant"
        }
        self.assertFalse(self.cli._validate_provider_config('azure', azure_config_invalid))
    
    def test_validate_provider_config_gcp(self):
        """Test GCP provider configuration validation"""
        # Valid GCP config
        gcp_config = {
            "project_id": "test-project"
        }
        self.assertTrue(self.cli._validate_provider_config('gcp', gcp_config))
        
        # Invalid GCP config
        gcp_config_invalid = {}
        self.assertFalse(self.cli._validate_provider_config('gcp', gcp_config_invalid))
    
    def test_validate_threshold_args(self):
        """Test threshold argument validation"""
        # Mock args object with valid thresholds
        class MockArgs:
            def __init__(self):
                self.console_threshold = 90
                self.access_key_threshold = 180
                self.permission_threshold = 10
        
        # Valid args should not raise exception
        valid_args = MockArgs()
        try:
            self.cli._validate_threshold_args(valid_args)
        except ValueError:
            self.fail("_validate_threshold_args raised ValueError with valid arguments")
        
        # Invalid console threshold
        invalid_args = MockArgs()
        invalid_args.console_threshold = 1000  # Too high
        
        with self.assertRaises(ValueError):
            self.cli._validate_threshold_args(invalid_args)
        
        # Invalid access key threshold
        invalid_args2 = MockArgs()
        invalid_args2.access_key_threshold = 0  # Too low
        
        with self.assertRaises(ValueError):
            self.cli._validate_threshold_args(invalid_args2)
        
        # Non-integer threshold
        invalid_args3 = MockArgs()
        invalid_args3.permission_threshold = "not_an_int"
        
        with self.assertRaises(ValueError):
            self.cli._validate_threshold_args(invalid_args3)
    
    @patch('subprocess.run')
    def test_execute_command_timeout(self, mock_subprocess):
        """Test that subprocess calls have proper timeout"""
        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stdout = ""
        mock_subprocess.return_value.stderr = ""
        
        cmd = [str(sys.executable), "--version"]
        self.cli._execute_command(cmd)
        
        # Verify subprocess.run was called with timeout
        mock_subprocess.assert_called_once()
        call_args = mock_subprocess.call_args
        self.assertEqual(call_args[1]['timeout'], 300)  # 5 minutes
        self.assertTrue(call_args[1]['capture_output'])
        self.assertTrue(call_args[1]['text'])
        self.assertFalse(call_args[1]['check'])
    
    @patch('subprocess.run')
    def test_execute_command_timeout_expired(self, mock_subprocess):
        """Test command timeout handling"""
        import subprocess
        mock_subprocess.side_effect = subprocess.TimeoutExpired("test_cmd", 300)
        
        cmd = [str(sys.executable), "--version"]
        result = self.cli._execute_command(cmd)
        
        self.assertEqual(result, 1)  # Should return error code
    
    def test_create_parser_arguments(self):
        """Test argument parser creation"""
        parser = self.cli.create_parser()
        
        # Test that parser was created successfully
        self.assertIsNotNone(parser)
        
        # Test parsing valid arguments
        args = parser.parse_args(['user-access-review', '--config', 'test.json'])
        self.assertEqual(args.command, 'user-access-review')
        self.assertEqual(args.config, 'test.json')
        
        # Test cloud providers argument
        args = parser.parse_args(['user-access-review', '--config', 'test.json', 
                                 '--cloud-providers', 'aws', 'azure'])
        self.assertEqual(args.cloud_providers, ['aws', 'azure'])
    
    def test_enhanced_logging_setup(self):
        """Test enhanced logging configuration"""
        logger = self.cli._setup_enhanced_logging()
        
        # Verify logger was created
        self.assertIsNotNone(logger)
        self.assertEqual(logger.name, 'soc2_cli')
        
        # Verify handlers were added
        self.assertGreater(len(logger.handlers), 0)
        
        # Check that log directory was created
        log_dir = self.cli.base_dir / 'logs'
        self.assertTrue(log_dir.exists())
    
    @patch('builtins.print')
    def test_run_with_no_command(self, mock_print):
        """Test CLI behavior when no command is provided"""
        with patch('sys.argv', ['soc2-audit']):
            result = self.cli.run()
            self.assertEqual(result, 1)
    
    def test_run_with_invalid_threshold(self):
        """Test CLI behavior with invalid threshold arguments"""
        with patch('sys.argv', ['soc2-audit', 'user-access-review', 
                                '--config', 'test.json', '--console-threshold', '1000']):
            result = self.cli.run()
            self.assertEqual(result, 1)
    
    @patch('soc2_cli.SOC2Utils.load_json_config')
    @patch('soc2_cli.MultiCloudDataCollector')
    def test_multi_cloud_assessment_success(self, mock_collector_class, mock_load_config):
        """Test successful multi-cloud assessment execution"""
        # Mock configuration loading
        mock_load_config.return_value = self.test_config
        
        # Mock collector and report
        mock_collector = MagicMock()
        mock_collector_class.return_value = mock_collector
        
        mock_report = MagicMock()
        mock_report.summary_statistics = {'total_findings': 0}
        mock_report.findings_summary = {'CRITICAL': 0}
        mock_collector.run_cross_cloud_compliance_assessment.return_value = mock_report
        
        # Mock args
        class MockArgs:
            def __init__(self):
                self.config = 'test.json'
                self.assessment_types = ['access_review']
                self.generate_cross_cloud_report = False
                self.output_dir = None
        
        args = MockArgs()
        result = self.cli._run_multi_cloud_assessment(args)
        
        # Should return 0 for no findings
        self.assertEqual(result, 0)
        
        # Verify collector was called
        mock_collector.run_cross_cloud_compliance_assessment.assert_called_once()
    
    @patch('soc2_cli.SOC2Utils.load_json_config')
    def test_multi_cloud_assessment_missing_dependencies(self, mock_load_config):
        """Test multi-cloud assessment with missing dependencies"""
        mock_load_config.return_value = self.test_config
        
        # Mock missing MultiCloudDataCollector import
        with patch('builtins.__import__', side_effect=ImportError("No module named 'lib.multicloud_collectors'")):
            class MockArgs:
                def __init__(self):
                    self.config = 'test.json'
                    self.assessment_types = ['access_review']
                    self.generate_cross_cloud_report = False
                    self.output_dir = None
            
            args = MockArgs()
            result = self.cli._run_multi_cloud_assessment(args)
            
            # Should return 2 for dependency error
            self.assertEqual(result, 2)


class TestSecurityValidation(unittest.TestCase):
    """Additional security-focused test cases"""
    
    def setUp(self):
        self.cli = SOC2CLI()
    
    def test_security_various_injection_attempts(self):
        """Test various command injection scenarios"""
        injection_attempts = [
            # Shell metacharacters
            [str(sys.executable), "script.py", "arg; echo 'injected'"],
            [str(sys.executable), "script.py", "arg | cat"],
            [str(sys.executable), "script.py", "arg && echo"],
            [str(sys.executable), "script.py", "arg || echo"],
            
            # Command substitution
            [str(sys.executable), "script.py", "$(whoami)"],
            [str(sys.executable), "script.py", "`id`"],
            
            # Redirection attempts
            [str(sys.executable), "script.py", "arg > /tmp/output"],
            [str(sys.executable), "script.py", "arg < /etc/passwd"],
            
            # Process substitution
            [str(sys.executable), "script.py", "arg (echo test)"],
            [str(sys.executable), "script.py", "arg )echo test("],
        ]
        
        for cmd in injection_attempts:
            with self.subTest(cmd=cmd):
                with self.assertRaises(SecurityError):
                    self.cli._sanitize_command(cmd)
    
    def test_safe_file_paths_allowed(self):
        """Test that safe file paths are allowed"""
        safe_commands = [
            [str(sys.executable), "script.py", "--config", "/absolute/path/config.json"],
            [str(sys.executable), "script.py", "--output", "report.csv"],
            [str(sys.executable), "script.py", "--file", "data.json"],
            [str(sys.executable), "script.py", "--script", "analysis.py"],
        ]
        
        for cmd in safe_commands:
            with self.subTest(cmd=cmd):
                try:
                    result = self.cli._sanitize_command(cmd)
                    self.assertEqual(result, cmd)
                except SecurityError:
                    self.fail(f"Safe command was blocked: {cmd}")


if __name__ == '__main__':
    # Create test directory if it doesn't exist
    test_dir = Path(__file__).parent
    test_dir.mkdir(exist_ok=True)
    
    # Run tests
    unittest.main(verbosity=2)