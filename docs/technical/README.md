# 📋 Technical Documentation

Detailed technical guides for SOC 2 automation implementation.

## Available Guides

### Core Automation
- **[Evidence Collection](evidence-collection.md)** - Comprehensive evidence gathering across multi-cloud environments
- **[Inactive Users Detection](inactive-users.md)** - AWS IAM user access review and compliance checking
- **[Implementation Summary](implementation-summary.md)** - Security fixes and functionality enhancements

### Advanced Features  
- **[Multi-Cloud Setup](../advanced/multi-cloud-guide.md)** - AWS, Azure, and GCP unified compliance automation

## Quick Navigation

**New to automation?** Start with [Evidence Collection](evidence-collection.md)

**Need AWS user reviews?** See [Inactive Users Detection](inactive-users.md)

**Multi-cloud environment?** Check [Multi-Cloud Setup](../advanced/multi-cloud-guide.md)

**Looking for fixes?** Review [Implementation Summary](implementation-summary.md)

## Integration Examples

### Python Integration
```python
from soc2_automation.inactive_users_detector import UserAccessReviewEngine

engine = UserAccessReviewEngine('config.json')
findings = engine.run_comprehensive_access_review()
```

### CI/CD Integration
```yaml
# GitHub Actions example
- name: SOC 2 Access Review
  run: |
    ./soc2-audit user-access-review --config config/prod_config.json
    if [ $? -eq 1 ]; then
      echo "::warning::Access review findings detected"
    fi
```

## Architecture Overview

```
SOC 2 CLI (soc2_cli.py)
├── Evidence Collection System
├── User Access Review Engine  
├── Multi-Cloud Data Collectors
└── Report Generation Framework
```

## Support

For implementation questions, see:
- **[Quick Reference](../quick-reference/commands.md)** - Common commands and flags
- **[Troubleshooting](../quick-reference/troubleshooting.md)** - Common issues and solutions