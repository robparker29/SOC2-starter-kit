# 🚀 SOC 2 Starter Kit - Quick Start

Get your first SOC 2 compliance check running in under 5 minutes.

## Prerequisites

- Python 3.7+
- AWS account (for cloud checks)

## Install

```bash
git clone https://github.com/robparker29/SOC2-starter-kit.git
cd SOC2-starter-kit
pip install boto3 paramiko ldap3 PyGithub requests jira pandas
```

## First Run

```bash
# Copy configuration template
cp soc2_automation/config/soc2_unified_config.json config/my_config.json

# Edit config/my_config.json - add your AWS credentials:
# "access_key": "YOUR_AWS_ACCESS_KEY"
# "secret_key": "YOUR_AWS_SECRET_KEY"

# Run your first compliance check
./soc2-audit user-access-review --config config/my_config.json
```

**Result:** You'll get a CSV report identifying inactive users and access issues, mapped to SOC 2 controls.

## What Just Happened?

You ran an automated SOC 2 access review that:
- ✅ Analyzed AWS IAM users for inactive access
- ✅ Generated audit-ready reports 
- ✅ Mapped findings to SOC 2 controls (CC6.1, CC6.2, CC6.3)

## Next Steps

**Need Policies?** → [Policy Templates](Policies/README.md)

**Want More Automation?** → [Technical Documentation](docs/technical/)

**Advanced Multi-Cloud?** → [Multi-Cloud Guide](docs/advanced/multi-cloud-guide.md)

**Need Help?** → [Quick Reference](docs/quick-reference/commands.md)

## All Available Commands

```bash
# User access review
./soc2-audit user-access-review --config config.json

# Evidence collection  
./soc2-audit evidence-collection --config config.json

# Inactive user detection
./soc2-audit inactive-users --config config.json

# Configuration drift monitoring
./soc2-audit config-drift --config config.json
```

**Time to first success: ~5 minutes** ⏱️