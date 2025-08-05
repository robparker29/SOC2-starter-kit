#!/usr/bin/env python3
"""
Integration Tests for SOC 2 CLI
Tests end-to-end functionality with mocked cloud providers

Author: Parker Robertson
Purpose: Ensure complete workflow functionality
"""

import unittest
from unittest.mock import patch, MagicMock
import tempfile
import json
import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from soc2_cli import SOC2CLI


class TestSOC2CLIIntegration(unittest.TestCase):
    """Integration tests for SOC2CLI"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.cli = SOC2CLI()
        
        # Create comprehensive test configuration
        self.test_config = {
            "global_settings": {
                "default_cloud_providers": ["aws", "azure", "gcp"],
                "parallel_execution": True,
                "max_concurrent_clouds": 3
            },
            "aws": {
                "_enabled": True,
                "access_key": "AKIA_TEST_KEY",
                "secret_key": "test_secret_key_value",
                "region": "us-east-1",
                "accounts": [
                    {
                        "account_id": "123456789012",
                        "account_name": "Production",
                        "role_arn": "arn:aws:iam::123456789012:role/SOC2-CrossAccount-Role"
                    }
                ]
            },
            "azure": {
                "_enabled": True,
                "subscription_id": "test-subscription-id",
                "tenant_id": "test-tenant-id",
                "client_id": "test-client-id",
                "client_secret": "test-client-secret"
            },
            "gcp": {
                "_enabled": True,
                "project_id": "test-project-123",
                "service_account_key_path": "/path/to/service-account.json"
            },
            "user_access_review": {
                "console_threshold_days": 90,
                "access_key_threshold_days": 180,
                "excessive_permissions_threshold": 10
            },
            "evidence_collection": {
                "retention_days": 365,
                "output_format": ["csv", "json"]
            }
        }
        
        # Create temporary config file
        self.config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        json.dump(self.test_config, self.config_file)
        self.config_file.flush()
        self.config_file.close()
    
    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.config_file.name):
            os.unlink(self.config_file.name)
    
    @patch('subprocess.run')
    def test_user_access_review_command_execution(self, mock_subprocess):
        """Test user access review command execution"""
        # Mock successful subprocess execution
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "User access review completed successfully"
        mock_result.stderr = ""
        mock_subprocess.return_value = mock_result
        
        # Mock args
        class MockArgs:
            def __init__(self):
                self.config = self.config_file.name
                self.systems = ['aws', 'azure']
                self.aws_accounts = ['123456789012']
                self.output_dir = None
                self.console_threshold = 90
                self.access_key_threshold = 180
                self.permission_threshold = 10
                self.create_tickets = False
        
        args = MockArgs()
        result = self.cli._run_user_access_review(args)
        
        # Verify command was executed
        self.assertEqual(result, 0)
        mock_subprocess.assert_called_once()
        
        # Verify correct command structure
        call_args = mock_subprocess.call_args[0][0]
        self.assertIn('inactive_users_detector.py', call_args[1])
        self.assertIn('--config', call_args)
        self.assertIn('--mode', call_args)
        self.assertIn('comprehensive-review', call_args)
    
    @patch('subprocess.run')
    def test_evidence_collection_command_execution(self, mock_subprocess):
        """Test evidence collection command execution"""
        # Mock successful subprocess execution
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Evidence collection completed"
        mock_result.stderr = ""
        mock_subprocess.return_value = mock_result
        
        # Mock args
        class MockArgs:
            def __init__(self):
                self.config = self.config_file.name
                self.controls = ['CC6.1', 'CC6.2']
                self.evidence_types = ['ACCESS', 'CONFIG']
                self.output_dir = None
        
        args = MockArgs()
        result = self.cli._run_evidence_collection(args)
        
        # Verify command was executed
        self.assertEqual(result, 0)
        mock_subprocess.assert_called_once()
        
        # Verify correct command structure
        call_args = mock_subprocess.call_args[0][0]
        self.assertIn('evidence_collector.py', call_args[1])
        self.assertIn('--controls', call_args)
        self.assertIn('CC6.1', call_args)
    
    @patch('soc2_cli.CloudProviderFactory.create_multi_cloud_session')
    def test_connectivity_test_with_all_providers(self, mock_factory):
        """Test connectivity test with all cloud providers"""
        # Mock cloud providers
        mock_aws_provider = MagicMock()
        mock_aws_provider.validate_connectivity.return_value = {
            'sts': True,
            'iam': True,
            'ec2': True
        }
        
        mock_azure_provider = MagicMock()
        mock_azure_provider.validate_connectivity.return_value = {
            'resource_management': True,
            'network_management': True
        }
        
        mock_gcp_provider = MagicMock()
        mock_gcp_provider.validate_connectivity.return_value = {
            'resource_manager': True,
            'compute': True
        }
        
        mock_factory.return_value = {
            'AWS': mock_aws_provider,
            'AZURE': mock_azure_provider,
            'GCP': mock_gcp_provider
        }
        
        # Mock args
        class MockArgs:
            def __init__(self):
                self.config = self.config_file.name
        
        args = MockArgs()
        
        with patch('soc2_cli.CloudProviderFactory.get_available_providers', return_value=['AWS', 'AZURE', 'GCP']):
            result = self.cli._run_connectivity_test(args)
        
        # Verify successful execution
        self.assertEqual(result, 0)
        
        # Verify all providers were tested
        mock_aws_provider.validate_connectivity.assert_called_once()
        mock_azure_provider.validate_connectivity.assert_called_once()
        mock_gcp_provider.validate_connectivity.assert_called_once()
    
    @patch('soc2_cli.SOC2Utils.load_json_config')
    @patch('soc2_cli.MultiCloudDataCollector') 
    def test_multi_cloud_assessment_full_workflow(self, mock_collector_class, mock_load_config):
        """Test complete multi-cloud assessment workflow"""
        # Mock configuration loading
        mock_load_config.return_value = self.test_config
        
        # Mock collector and its methods
        mock_collector = MagicMock()
        mock_collector_class.return_value = mock_collector
        
        # Mock assessment report
        mock_report = MagicMock()
        mock_report.summary_statistics = {
            'total_findings': 5,
            'cloud_providers_assessed': 3
        }
        mock_report.findings_summary = {
            'CRITICAL': 1,
            'HIGH': 2,
            'MEDIUM': 2,
            'LOW': 0
        }
        
        mock_collector.run_cross_cloud_compliance_assessment.return_value = mock_report
        mock_collector.generate_cross_cloud_report.return_value = {
            'json': '/tmp/report.json',
            'csv': '/tmp/report.csv'
        }
        
        # Mock args
        class MockArgs:
            def __init__(self):
                self.config = self.config_file.name
                self.assessment_types = ['access_review', 'network_security']
                self.generate_cross_cloud_report = True
                self.output_dir = '/tmp/reports'
        
        args = MockArgs()
        result = self.cli._run_multi_cloud_assessment(args)
        
        # Should return 2 for critical findings
        self.assertEqual(result, 2)
        
        # Verify workflow execution
        mock_collector.run_cross_cloud_compliance_assessment.assert_called_once_with(
            assessment_types=['access_review', 'network_security'],
            soc2_controls=['CC6.1', 'CC6.2', 'CC6.3', 'CC7.1', 'CC7.2']
        )
        mock_collector.generate_cross_cloud_report.assert_called_once()
    
    def test_configuration_validation_comprehensive(self):
        """Test comprehensive configuration validation"""
        # Test valid configuration
        result = self.cli._validate_config(self.config_file.name)
        self.assertTrue(result)
        
        # Test configuration with only AWS
        aws_only_config = {"aws": {"_enabled": True, "access_key": "test", "secret_key": "test", "region": "us-east-1"}}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(aws_only_config, f)
            f.flush()
            
            try:
                result = self.cli._validate_config(f.name)
                self.assertTrue(result)
            finally:
                os.unlink(f.name)
        
        # Test configuration with legacy systems only
        legacy_config = {
            "active_directory": {"server": "ldap://dc.example.com"},
            "github": {"token": "test_token", "org_name": "test_org"}
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(legacy_config, f)
            f.flush()
            
            try:
                result = self.cli._validate_config(f.name)
                self.assertTrue(result)
            finally:
                os.unlink(f.name)
    
    def test_argument_parser_comprehensive(self):
        """Test argument parser with various command combinations"""
        parser = self.cli.create_parser()
        
        # Test user-access-review command
        args = parser.parse_args([
            'user-access-review', 
            '--config', 'test.json',
            '--systems', 'aws', 'azure',
            '--aws-accounts', '123456789012',
            '--console-threshold', '60',
            '--permission-threshold', '15',
            '--create-tickets'
        ])
        
        self.assertEqual(args.command, 'user-access-review')
        self.assertEqual(args.systems, ['aws', 'azure'])
        self.assertEqual(args.aws_accounts, ['123456789012'])
        self.assertEqual(args.console_threshold, 60)
        self.assertTrue(args.create_tickets)
        
        # Test multi-cloud-assessment command
        args = parser.parse_args([
            'multi-cloud-assessment',
            '--config', 'test.json',
            '--assessment-types', 'access_review', 'compliance_check',
            '--generate-cross-cloud-report'
        ])
        
        self.assertEqual(args.command, 'multi-cloud-assessment')
        self.assertEqual(args.assessment_types, ['access_review', 'compliance_check'])
        self.assertTrue(args.generate_cross_cloud_report)
        
        # Test evidence-collection command
        args = parser.parse_args([
            'evidence-collection',
            '--config', 'test.json',
            '--controls', 'CC6.1', 'CC6.2', 'CC7.1',
            '--evidence-types', 'ACCESS', 'CONFIG'
        ])
        
        self.assertEqual(args.command, 'evidence-collection')
        self.assertEqual(args.controls, ['CC6.1', 'CC6.2', 'CC7.1'])
        self.assertEqual(args.evidence_types, ['ACCESS', 'CONFIG'])
    
    def test_error_handling_scenarios(self):
        """Test various error handling scenarios"""
        # Test with invalid threshold values
        class MockArgsInvalidThreshold:
            def __init__(self):
                self.console_threshold = 1000  # Too high
                self.access_key_threshold = 180
                self.permission_threshold = 10
        
        args = MockArgsInvalidThreshold()
        with self.assertRaises(ValueError):
            self.cli._validate_threshold_args(args)
        
        # Test provider config validation with incomplete Azure config
        incomplete_azure_config = {
            "subscription_id": "test-sub"
            # Missing tenant_id
        }
        result = self.cli._validate_provider_config('azure', incomplete_azure_config)
        self.assertFalse(result)
        
        # Test provider config validation with unknown provider
        unknown_config = {"some_field": "some_value"}
        result = self.cli._validate_provider_config('unknown_provider', unknown_config)
        self.assertTrue(result)  # Should pass validation for unknown providers
    
    @patch('logging.getLogger')
    def test_logging_configuration(self, mock_get_logger):
        """Test logging configuration and rotation"""
        mock_logger = MagicMock()
        mock_get_logger.return_value = mock_logger
        
        # Test logger setup
        logger = self.cli._setup_enhanced_logging()
        
        # Verify logger configuration
        mock_logger.setLevel.assert_called()
        mock_logger.addHandler.assert_called()
        
        # Verify log directory creation
        log_dir = self.cli.base_dir / 'logs'
        self.assertTrue(log_dir.exists())


class TestPerformanceAndScalability(unittest.TestCase):
    """Performance and scalability tests"""
    
    def setUp(self):
        self.cli = SOC2CLI()
    
    def test_command_sanitization_performance(self):
        """Test command sanitization performance with large arguments"""
        import time
        
        # Create a command with many arguments
        large_cmd = [str(sys.executable), "script.py"]
        large_cmd.extend([f"--arg{i}" for i in range(100)])
        large_cmd.extend([f"value{i}" for i in range(100)])
        
        start_time = time.time()
        result = self.cli._sanitize_command(large_cmd)
        end_time = time.time()
        
        # Should complete quickly (less than 1 second)
        self.assertLess(end_time - start_time, 1.0)
        self.assertEqual(len(result), len(large_cmd))
    
    def test_configuration_validation_performance(self):
        """Test configuration validation performance with large configs"""
        import time
        
        # Create a large configuration
        large_config = {
            "aws": {
                "_enabled": True,
                "access_key": "test",
                "secret_key": "test", 
                "region": "us-east-1",
                "accounts": [
                    {
                        "account_id": f"12345678901{i}",
                        "account_name": f"Account_{i}",
                        "role_arn": f"arn:aws:iam::12345678901{i}:role/Role"
                    }
                    for i in range(50)  # 50 accounts
                ]
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(large_config, f)
            f.flush()
            
            try:
                start_time = time.time()
                result = self.cli._validate_config(f.name)
                end_time = time.time()
                
                # Should complete quickly and successfully
                self.assertTrue(result)
                self.assertLess(end_time - start_time, 2.0)
            finally:
                os.unlink(f.name)


if __name__ == '__main__':
    unittest.main(verbosity=2)