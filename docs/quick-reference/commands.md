# 🚀 SOC 2 CLI Commands - Quick Reference

## Essential Commands

### User Access Review
```bash
# Basic access review
./soc2-audit user-access-review --config config.json

# Specific systems only
./soc2-audit user-access-review --config config.json --systems aws github

# Custom thresholds
./soc2-audit user-access-review --config config.json --console-threshold 60 --permission-threshold 5
```

### Evidence Collection
```bash
# Collect all evidence
./soc2-audit evidence-collection --config config.json

# Specific controls only
./soc2-audit evidence-collection --config config.json --controls CC6.1,CC6.2,CC7.1

# Specific evidence types
./soc2-audit evidence-collection --config config.json --evidence-types ACCESS,CONFIG
```

### Inactive Users Detection
```bash
# AWS inactive users
./soc2-audit inactive-users --config config.json

# Multiple accounts
./soc2-audit inactive-users --config config.json --accounts 123456789012 210987654321

# Create tickets for findings
./soc2-audit inactive-users --config config.json --create-tickets
```

### Configuration Drift
```bash
# Monitor infrastructure changes
./soc2-audit config-drift --config config.json --systems aws linux
```

## Multi-Cloud Commands

### Cross-Cloud Assessment
```bash
# All cloud providers
./soc2-audit multi-cloud-assessment --config config.json --parallel

# Specific providers
./soc2-audit user-access-review --config config.json --cloud-providers aws azure

# Generate comparison report
./soc2-audit multi-cloud-assessment --config config.json --generate-cross-cloud-report
```

## Common Flags

| Flag | Description | Example |
|------|-------------|---------|
| `--config` | Configuration file path | `--config config/prod.json` |
| `--parallel` | Enable parallel execution | `--parallel` |
| `--verbose` | Enable debug logging | `--verbose` |
| `--create-tickets` | Create JIRA tickets | `--create-tickets` |
| `--output-dir` | Custom output directory | `--output-dir /reports` |

## Exit Codes

- **0**: No findings (clean)
- **1**: Findings detected (review needed)
- **2**: Script error (investigate)

## Quick Troubleshooting

### Permission Errors
```bash
# Check AWS credentials
aws sts get-caller-identity

# Validate config syntax
python -m json.tool config.json
```

### Missing Dependencies
```bash
# Install all packages
pip install -r requirements.txt

# Check Python version (3.7+ required)
python --version
```

### Configuration Issues
```bash
# Test connectivity
./soc2-audit test-connectivity --config config.json

# Verbose mode for debugging
./soc2-audit user-access-review --config config.json --verbose
```

## File Locations

- **Reports**: `soc2_reports/` (default)
- **Logs**: `logs/soc2_cli.log`
- **Config**: `config/` directory
- **Templates**: `soc2_automation/config/`

## Need More Help?

- **Technical Details**: [docs/technical/](../technical/)
- **Multi-Cloud Setup**: [docs/advanced/multi-cloud-guide.md](../advanced/multi-cloud-guide.md)
- **Policy Implementation**: [Policies/README.md](../../Policies/README.md)