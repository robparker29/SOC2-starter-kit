# 🔧 Troubleshooting - Quick Reference

## Common Issues & Solutions

### 🔐 Authentication Problems

**AWS Permission Denied**
```bash
# Check credentials
aws sts get-caller-identity
# Fix: Update config.json with valid AWS keys
```

**Azure Authentication Failed**
```bash
# Test Azure CLI access
az account show
# Fix: Run 'az login' or update client credentials
```

**GCP Service Account Error**
```bash
# Verify service account
gcloud auth list
# Fix: Set GOOGLE_APPLICATION_CREDENTIALS path
```

### ⚠️ Configuration Errors

**Invalid JSON Configuration**
```bash
# Validate syntax
python -m json.tool config.json
# Fix: Check for missing commas, quotes, brackets
```

**Missing Required Fields**
```bash
# Example error: KeyError: 'aws'
# Fix: Ensure all required sections exist in config.json
```

**File Not Found**
```bash
# Error: FileNotFoundError: config.json
# Fix: Use absolute path or check working directory
```

### 🐍 Python Issues

**Module Not Found**
```bash
# Error: ModuleNotFoundError: No module named 'boto3'
pip install boto3 paramiko ldap3 PyGithub requests jira pandas
```

**Python Version Too Old**
```bash
# Check version (need 3.7+)
python --version
# Fix: Update Python or use virtual environment
```

### 📊 Report Generation Issues

**No Data in Reports**
```bash
# Check permissions and connectivity
./soc2-audit test-connectivity --config config.json
```

**Timeout Errors**
```bash
# Increase timeout in config or use --timeout flag
./soc2-audit user-access-review --config config.json --timeout 600
```

### 🌐 Network Issues

**Connection Timeout**
```bash
# Test network connectivity
curl -I https://aws.amazon.com
# Check firewall, proxy, VPN settings
```

**SSL Certificate Errors**
```bash
# Error: SSL verification failed
# Temporary fix: export PYTHONHTTPSVERIFY=0
# Better fix: Update certificates or configure proxy
```

## Quick Diagnostics

### Run Basic Health Check
```bash
# Test all systems
./soc2-audit test-connectivity --config config.json --verbose
```

### Check Configuration
```bash
# Validate without running
python -c "import json; print('Valid JSON' if json.load(open('config.json')) else 'Invalid')"
```

### Verify Dependencies
```bash
# Check all required packages
pip list | grep -E "(boto3|azure|google-cloud|paramiko|ldap3)"
```

## Error Code Reference

| Exit Code | Meaning | Action |
|-----------|---------|---------|
| 0 | Success, no findings | Continue normal operations |
| 1 | Findings detected | Review reports, address issues |
| 2 | Configuration error | Fix config.json, check credentials |
| 3 | Permission denied | Update IAM policies, check access |
| 4 | Network/timeout error | Check connectivity, increase timeouts |

## Log Locations

- **Application Logs**: `logs/soc2_cli.log`
- **Debug Logs**: `logs/debug.log` (with --verbose)
- **Error Logs**: Check console output
- **Report Status**: `soc2_reports/status.json`

## Getting Help

### Enable Verbose Logging
```bash
# Get detailed error information
./soc2-audit [command] --config config.json --verbose
```

### Check System Requirements
- Python 3.7+
- Network access to cloud APIs
- Valid cloud credentials
- Sufficient disk space for reports

### Contact Support
- **GitHub Issues**: [Report bugs](https://github.com/robparker29/SOC2-starter-kit/issues)
- **Discussions**: [Ask questions](https://github.com/robparker29/SOC2-starter-kit/discussions)
- **Documentation**: [Technical docs](../technical/)

## Emergency Fixes

### Can't Access Reports
```bash
# Check output directory permissions
ls -la soc2_reports/
chmod 755 soc2_reports/
```

### Script Won't Start
```bash
# Make executable
chmod +x soc2-audit
# Or run directly
python soc2_automation/soc2_cli.py --help
```

### Complete Reset
```bash
# Start fresh (saves config)
mv config/my_config.json /tmp/backup_config.json
rm -rf soc2_reports/ logs/
cp /tmp/backup_config.json config/my_config.json
```