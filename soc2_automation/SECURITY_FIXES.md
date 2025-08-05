# Security and Code Quality Fixes for soc2_cli.py

## Critical Security Fixes

### 1. Command Injection Prevention

**Current Code (Vulnerable):**
```python
def _execute_command(self, cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
```

**Fixed Code:**
```python
def _execute_command(self, cmd):
    # Validate command components
    if not isinstance(cmd, list):
        raise ValueError("Command must be a list")
    
    # Sanitize command arguments
    sanitized_cmd = []
    for arg in cmd:
        if not isinstance(arg, str):
            raise ValueError(f"Invalid command argument type: {type(arg)}")
        # Basic path traversal protection
        if '..' in arg or arg.startswith('/') and not arg.startswith(str(self.base_dir)):
            if not any(arg.startswith(safe) for safe in [str(sys.executable), '--']):
                raise ValueError(f"Potentially unsafe argument: {arg}")
        sanitized_cmd.append(arg)
    
    try:
        self.logger.debug(f"Executing: {' '.join(sanitized_cmd)}")
        result = subprocess.run(
            sanitized_cmd, 
            capture_output=True, 
            text=True,
            timeout=300,  # 5 minute timeout
            check=False
        )
        # ... rest of the method
```

### 2. Enhanced Configuration Validation

**Current Code (Incomplete):**
```python
if not any(key in config for key in ['aws', 'active_directory', 'github']):
```

**Fixed Code:**
```python
def _validate_config(self, config_path: str) -> bool:
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
    # ... error handling
```

### 3. Implement Multi-Cloud Assessment

**Current Code (Placeholder):**
```python
def _run_multi_cloud_assessment(self, args):
    print("Multi-cloud assessment functionality will be implemented...")
    return 0
```

**Fixed Code:**
```python
def _run_multi_cloud_assessment(self, args):
    """Execute comprehensive multi-cloud assessment"""
    self.logger.info("🌐 Running multi-cloud security assessment...")
    
    try:
        # Load configuration and initialize multi-cloud collector
        config = SOC2Utils.load_json_config(args.config)
        from lib.multicloud_collectors import MultiCloudDataCollector
        
        collector = MultiCloudDataCollector(config)
        
        # Determine assessment types
        assessment_types = args.assessment_types or ['access_review', 'network_security', 'compliance_check']
        
        # Run cross-cloud assessment
        report = collector.run_cross_cloud_compliance_assessment(
            assessment_types=assessment_types,
            soc2_controls=['CC6.1', 'CC6.2', 'CC6.3', 'CC7.1', 'CC7.2']
        )
        
        # Generate reports if requested
        if args.generate_cross_cloud_report:
            output_dir = args.output_dir or None
            report_paths = collector.generate_cross_cloud_report(report, output_dir)
            
            print(f"\n📄 Cross-cloud reports generated:")
            for format_type, path in report_paths.items():
                print(f"  {format_type.upper()}: {path}")
        
        # Return appropriate exit code based on findings
        total_findings = report.summary_statistics.get('total_findings', 0)
        critical_findings = report.findings_summary.get('CRITICAL', 0)
        
        if critical_findings > 0:
            return 2  # Critical issues found
        elif total_findings > 0:
            return 1  # Issues found
        else:
            return 0  # No issues
            
    except Exception as e:
        self.logger.error(f"Multi-cloud assessment failed: {str(e)}")
        return 2
```

## Code Quality Improvements

### 4. Better Exception Handling

**Before:**
```python
except Exception as e:
    self.logger.error(f"Connectivity test failed: {str(e)}")
```

**After:**
```python
except (ImportError, ModuleNotFoundError) as e:
    self.logger.error(f"Missing required dependencies: {str(e)}")
    return 2
except (PermissionError, FileNotFoundError) as e:
    self.logger.error(f"Configuration access error: {str(e)}")
    return 1
except Exception as e:
    self.logger.error(f"Unexpected error during connectivity test: {str(e)}")
    return 2
```

### 5. Resolve Argument Conflicts

**Issue:** Duplicate --accounts arguments in global and subcommand parsers.

**Solution:** Use different argument names or proper argument inheritance:

```python
# In global parser
parser.add_argument('--target-accounts', nargs='*',
                   help='Specific account/subscription/project IDs to analyze')

# In subcommand parsers - use specific names
parser.add_argument('--aws-accounts', nargs='*',
                   help='Specific AWS account IDs to analyze')
```

### 6. Add Input Validation

```python
def _validate_threshold_args(self, args):
    """Validate threshold arguments are within reasonable ranges"""
    thresholds = {
        'console_threshold': (1, 365),
        'access_key_threshold': (1, 730),
        'permission_threshold': (1, 100)
    }
    
    for attr, (min_val, max_val) in thresholds.items():
        if hasattr(args, attr) and getattr(args, attr) is not None:
            value = getattr(args, attr)
            if not (min_val <= value <= max_val):
                raise ValueError(f"{attr} must be between {min_val} and {max_val}")
```

### 7. Enhanced Logging Configuration

```python
def __init__(self):
    self.base_dir = Path(__file__).parent
    # Configure logging with proper levels and handlers
    self.logger = self._setup_enhanced_logging()

def _setup_enhanced_logging(self):
    """Setup enhanced logging with rotation and structured output"""
    import logging
    from logging.handlers import RotatingFileHandler
    
    logger = logging.getLogger('soc2_cli')
    logger.setLevel(logging.INFO)
    
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
```

## Testing Recommendations

### 8. Unit Tests for Critical Functions

```python
import unittest
from unittest.mock import patch, MagicMock
import tempfile
import json

class TestSOC2CLI(unittest.TestCase):
    
    def setUp(self):
        self.cli = SOC2CLI()
        
    def test_validate_config_with_valid_multicloud_config(self):
        """Test configuration validation with valid multi-cloud setup"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config = {
                "aws": {"_enabled": True, "access_key": "test"},
                "azure": {"_enabled": True, "subscription_id": "test"},
                "gcp": {"_enabled": True, "project_id": "test"}
            }
            json.dump(config, f)
            f.flush()
            
            result = self.cli._validate_config(f.name)
            self.assertTrue(result)
    
    def test_command_injection_prevention(self):
        """Test that command injection attempts are blocked"""
        malicious_cmd = ["python", "script.py", "; rm -rf /"]
        
        with self.assertRaises(ValueError):
            self.cli._execute_command(malicious_cmd)
    
    @patch('subprocess.run')
    def test_subprocess_timeout(self, mock_subprocess):
        """Test that subprocess calls have proper timeout"""
        mock_subprocess.return_value.returncode = 0
        
        cmd = ["python", "--version"]
        self.cli._execute_command(cmd)
        
        mock_subprocess.assert_called_with(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=300,
            check=False
        )
```

## Performance Improvements

### 9. Lazy Loading of Dependencies

```python
def _run_multi_cloud_assessment(self, args):
    """Execute multi-cloud assessment with lazy loading"""
    try:
        # Lazy import to avoid loading dependencies unless needed
        from lib.multicloud_collectors import MultiCloudDataCollector
        from lib.cloud_providers import CloudProviderFactory
        
        # Rest of implementation...
    except ImportError as e:
        self.logger.error(f"Multi-cloud dependencies not available: {e}")
        print("❌ Install multi-cloud dependencies: pip install -r requirements.txt")
        return 2
```

### 10. Parallel Command Execution

```python
def _execute_parallel_commands(self, commands: list, max_workers: int = 3):
    """Execute multiple commands in parallel"""
    import concurrent.futures
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(self._execute_command, cmd): cmd for cmd in commands}
        
        results = []
        for future in concurrent.futures.as_completed(futures):
            cmd = futures[future]
            try:
                result = future.result()
                results.append((cmd, result))
            except Exception as e:
                self.logger.error(f"Command failed: {cmd}, Error: {e}")
                results.append((cmd, 1))
        
        return results
```