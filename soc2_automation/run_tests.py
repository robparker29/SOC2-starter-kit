#!/usr/bin/env python3
"""
Test Runner for SOC 2 Automation Framework
Runs all tests with coverage reporting and security checks

Author: Parker Robertson
Purpose: Comprehensive test execution for CI/CD and development
"""

import sys
import os
import unittest
import argparse
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))


def run_unit_tests(verbose=False):
    """Run unit tests"""
    print("🧪 Running Unit Tests...")
    print("=" * 50)
    
    # Discover and run unit tests
    loader = unittest.TestLoader()
    suite = loader.discover('tests', pattern='test_*.py')
    
    verbosity = 2 if verbose else 1
    runner = unittest.TextTestRunner(verbosity=verbosity, buffer=True)
    result = runner.run(suite)
    
    return result.wasSuccessful()


def run_security_tests(verbose=False):
    """Run security-specific tests"""
    print("\n🔒 Running Security Tests...")
    print("=" * 50)
    
    # Import and run security tests specifically
    from tests.test_soc2_cli import TestSecurityValidation
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestSecurityValidation)
    
    verbosity = 2 if verbose else 1
    runner = unittest.TextTestRunner(verbosity=verbosity, buffer=True)
    result = runner.run(suite)
    
    return result.wasSuccessful()


def run_integration_tests(verbose=False):
    """Run integration tests"""
    print("\n🔗 Running Integration Tests...")
    print("=" * 50)
    
    from tests.test_integration import TestSOC2CLIIntegration, TestPerformanceAndScalability
    
    loader = unittest.TestLoader()
    
    # Load integration test suites
    integration_suite = loader.loadTestsFromTestCase(TestSOC2CLIIntegration)
    performance_suite = loader.loadTestsFromTestCase(TestPerformanceAndScalability)
    
    # Combine suites
    combined_suite = unittest.TestSuite([integration_suite, performance_suite])
    
    verbosity = 2 if verbose else 1
    runner = unittest.TextTestRunner(verbosity=verbosity, buffer=True)
    result = runner.run(combined_suite)
    
    return result.wasSuccessful()


def run_coverage_analysis():
    """Run tests with coverage analysis"""
    try:
        import coverage
    except ImportError:
        print("❌ Coverage package not installed. Install with: pip install coverage")
        return False
    
    print("\n📊 Running Coverage Analysis...")
    print("=" * 50)
    
    # Initialize coverage
    cov = coverage.Coverage(source=['soc2_cli', 'lib'])
    cov.start()
    
    try:
        # Run all tests
        success = run_unit_tests(verbose=False)
        success &= run_integration_tests(verbose=False)
        
        # Stop coverage and generate report
        cov.stop()
        cov.save()
        
        print("\n📈 Coverage Report:")
        cov.report(show_missing=True)
        
        # Generate HTML coverage report
        html_dir = Path(__file__).parent / 'htmlcov'
        html_dir.mkdir(exist_ok=True)
        cov.html_report(directory=str(html_dir))
        print(f"\n📋 HTML coverage report generated: {html_dir}/index.html")
        
        return success
        
    except Exception as e:
        print(f"❌ Coverage analysis failed: {e}")
        return False


def run_static_analysis():
    """Run static code analysis"""
    print("\n🔍 Running Static Code Analysis...")
    print("=" * 50)
    
    # Check for common static analysis tools
    tools_to_run = []
    
    try:
        import pylint
        tools_to_run.append(('pylint', 'pylint soc2_cli.py lib/*.py'))
    except ImportError:
        pass
    
    try:
        import flake8
        tools_to_run.append(('flake8', 'flake8 soc2_cli.py lib/'))
    except ImportError:
        pass
    
    try:
        import bandit
        tools_to_run.append(('bandit', 'bandit -r soc2_cli.py lib/'))
    except ImportError:
        pass
    
    if not tools_to_run:
        print("⚠️  No static analysis tools found. Install with:")
        print("   pip install pylint flake8 bandit")
        return True
    
    success = True
    for tool_name, command in tools_to_run:
        print(f"\n🔧 Running {tool_name}...")
        result = os.system(command)
        if result != 0:
            print(f"⚠️  {tool_name} found issues")
            success = False
        else:
            print(f"✅ {tool_name} passed")
    
    return success


def validate_security_configuration():
    """Validate security configuration and dependencies"""
    print("\n🛡️  Validating Security Configuration...")
    print("=" * 50)
    
    security_checks = []
    
    # Check for insecure dependencies
    try:
        import safety
        print("🔍 Checking for known security vulnerabilities...")
        result = os.system('safety check')
        security_checks.append(('safety', result == 0))
    except ImportError:
        print("⚠️  Safety not installed. Install with: pip install safety")
        security_checks.append(('safety', None))
    
    # Check file permissions on sensitive files
    sensitive_files = ['soc2_cli.py', 'lib/soc2_utils.py', 'lib/cloud_providers.py']
    for file_path in sensitive_files:
        if os.path.exists(file_path):
            stat_info = os.stat(file_path)
            # Check if file is world-writable (security risk)
            if stat_info.st_mode & 0o002:
                print(f"⚠️  Security risk: {file_path} is world-writable")
                security_checks.append((f'permissions_{file_path}', False))
            else:
                security_checks.append((f'permissions_{file_path}', True))
    
    # Print security summary
    passed = sum(1 for check, result in security_checks if result is True)
    failed = sum(1 for check, result in security_checks if result is False)
    skipped = sum(1 for check, result in security_checks if result is None)
    
    print(f"\n🔒 Security Validation Summary:")
    print(f"  ✅ Passed: {passed}")
    print(f"  ❌ Failed: {failed}")
    print(f"  ⏭️  Skipped: {skipped}")
    
    return failed == 0


def main():
    """Main test runner"""
    parser = argparse.ArgumentParser(description='SOC 2 Automation Test Runner')
    parser.add_argument('--unit', action='store_true', help='Run unit tests only')
    parser.add_argument('--integration', action='store_true', help='Run integration tests only')
    parser.add_argument('--security', action='store_true', help='Run security tests only')
    parser.add_argument('--coverage', action='store_true', help='Run with coverage analysis')
    parser.add_argument('--static', action='store_true', help='Run static code analysis')
    parser.add_argument('--security-check', action='store_true', help='Run security configuration checks')
    parser.add_argument('--all', action='store_true', help='Run all tests and checks')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # If no specific tests selected, run all
    if not any([args.unit, args.integration, args.security, args.coverage, 
                args.static, args.security_check]):
        args.all = True
    
    print("🛡️  SOC 2 Automation Framework Test Suite")
    print("=" * 60)
    
    success = True
    
    if args.unit or args.all:
        success &= run_unit_tests(args.verbose)
    
    if args.security or args.all:
        success &= run_security_tests(args.verbose)
    
    if args.integration or args.all:
        success &= run_integration_tests(args.verbose)
    
    if args.coverage or args.all:
        success &= run_coverage_analysis()
    
    if args.static or args.all:
        success &= run_static_analysis()
    
    if args.security_check or args.all:
        success &= validate_security_configuration()
    
    # Print final summary
    print("\n" + "=" * 60)
    if success:
        print("✅ All tests passed! The SOC 2 automation framework is ready for deployment.")
        return 0
    else:
        print("❌ Some tests failed. Please review the output above and fix issues before deployment.")
        return 1


if __name__ == '__main__':
    sys.exit(main())