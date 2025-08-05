# 🛡️ SOC 2 Compliance Starter Kit for Startups

Welcome to the **SOC 2 Compliance Starter Kit** — a practical, open-source resource for startups and small security teams preparing for a SOC 2 audit. This project combines real-world audit experience with lightweight automation to help teams build a defensible security and compliance program without slowing down engineering.

---

## 🤓 About Me

I'm a GRC Security Analyst with a background in auditing and scripting. This project is an ongoing effort to make compliance more actionable, accessible, and automated. You can reach me via LinkedIn at linkedin.com/in/parker-w-robertson.

## 🔍 About This Project

SOC 2 compliance can be overwhelming, especially for startups with limited resources. This kit provides:

- ✅ **Unified Automation Framework**: Single command-line tool for all SOC 2 tasks
- 🔐 **Comprehensive Security Scripts**: Automated user access reviews, evidence collection, and configuration monitoring
- 📊 **Audit-Ready Reports**: CSV and JSON outputs mapped to SOC 2 controls
- 🎯 **Beginner-Friendly**: Clear workflows and consistent interfaces

Whether you're working toward SOC 2 Type I or II, this repository is designed to help you bridge the gap between policy and practice.

---

## 📁 What's Included

| Component | Description |
|-----------|-------------|
| **`soc2-audit` CLI** | Single command-line interface for all SOC 2 automation |
| **`soc2_automation/`** | Unified automation framework with modular components |
| **`controls/`** | SOC 2 Common Criteria matrix and implementation guides |
| **`requirements/`** | Detailed requirements and implementation documentation |

---

## 🚀 Quick Start

### 1. Clone and Setup
```bash
git clone https://github.com/robparker29/SOC2-starter-kit.git
cd SOC2-starter-kit

# Install Python dependencies
pip install boto3 paramiko ldap3 PyGithub requests jira pandas
```

### 2. Configure Your Environment
```bash
# Copy and customize the configuration template
cp soc2_automation/config/soc2_unified_config.json config/my_soc2_config.json

# Edit config/my_soc2_config.json with your system credentials
```

### 3. Run Your First Audit Task
```bash
# Check the CLI help
./soc2-audit --help

# Run a comprehensive user access review
./soc2-audit user-access-review --config config/my_soc2_config.json

# Collect evidence for specific SOC 2 controls
./soc2-audit evidence-collection --config config/my_soc2_config.json --controls CC6.1,CC6.2

# Detect inactive users in AWS
./soc2-audit inactive-users --config config/my_soc2_config.json
```

---

## 🎯 Available Commands

The `soc2-audit` CLI provides these commands:

### User Access Review
```bash
# Comprehensive review across all configured systems
./soc2-audit user-access-review --config config.json --systems aws github active_directory

# Focus on specific AWS accounts
./soc2-audit user-access-review --config config.json --accounts 123456789012 210987654321

# Customize thresholds
./soc2-audit user-access-review --config config.json --console-threshold 60 --permission-threshold 5
```

### Evidence Collection
```bash
# Collect all available evidence
./soc2-audit evidence-collection --config config.json

# Focus on specific controls
./soc2-audit evidence-collection --config config.json --controls CC6.1,CC7.1,CC7.2

# Collect specific evidence types
./soc2-audit evidence-collection --config config.json --evidence-types ACCESS,CONFIG
```

### Inactive Users Detection
```bash
# AWS-focused inactive user detection
./soc2-audit inactive-users --config config.json

# Multi-account analysis
./soc2-audit inactive-users --config config.json --accounts 123456789012 210987654321

# Create tickets for findings
./soc2-audit inactive-users --config config.json --create-tickets
```

### Configuration Drift
```bash
# Monitor infrastructure changes
./soc2-audit config-drift --config config.json --systems aws linux
```

---

## ⚙️ Configuration

### Basic Configuration Structure
```json
{
  "aws": {
    "access_key": "YOUR_AWS_ACCESS_KEY",
    "secret_key": "YOUR_AWS_SECRET_KEY",
    "region": "us-east-1",
    "accounts": [
      {
        "account_id": "123456789012",
        "role_arn": "arn:aws:iam::123456789012:role/SOC2-CrossAccount-Role"
      }
    ]
  },
  "active_directory": {
    "server": "ldap://dc.company.com",
    "user": "soc2-automation@company.com",
    "search_base": "dc=company,dc=com"
  },
  "github": {
    "token": "YOUR_GITHUB_TOKEN",
    "org_name": "your-organization"
  },
  "user_access_review": {
    "console_threshold_days": 90,
    "access_key_threshold_days": 180,
    "create_tickets": false
  }
}
```

### Required IAM Permissions
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:GetUser", 
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:ListAttachedUserPolicies",
        "iam:ListUserPolicies",
        "iam:GetGroupsForUser",
        "iam:ListUserTags",
        "iam:ListMFADevices",
        "ec2:DescribeSecurityGroups",
        "logs:DescribeLogGroups",
        "cloudtrail:LookupEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## 📊 Report Outputs

All commands generate consistent, audit-ready outputs:

### CSV Reports
- **Finding_ID**: Unique tracking identifier
- **SOC2_Control**: Mapped compliance control (CC6.1, CC6.2, etc.)
- **Severity**: Risk level (HIGH, MEDIUM, LOW)
- **Details**: Specific finding information
- **Remediation**: Recommended actions
- **Status**: Current remediation status

### JSON Reports
- Structured data for programmatic processing
- Complete metadata and configuration details
- Summary statistics and trends
- Integration-ready format

---

## 🏗️ Architecture

### Unified Framework Components
```
soc2_automation/
├── soc2_cli.py                 # Main CLI entry point
├── inactive_users_detector.py  # User access review engine
├── evidence_collector.py       # Evidence collection automation
├── config_drift_processor.py   # Configuration monitoring
├── lib/
│   ├── soc2_models.py          # Standardized data models
│   ├── soc2_collectors.py      # System data collection
│   └── soc2_utils.py           # Shared utilities
├── config/
│   └── soc2_unified_config.json # Configuration template
└── examples/
    └── *.py                    # Integration examples
```

### Key Benefits
- **Single Entry Point**: One command (`soc2-audit`) for all tasks
- **Consistent Data Models**: Unified structures across all tools
- **Standardized Configuration**: One config file for all systems
- **Audit-Ready Output**: Reports formatted for compliance teams
- **Extensible Framework**: Easy to add new systems and checks

---

## 🎯 SOC 2 Control Mapping

| SOC 2 Control | Automated Check | Command |
|---------------|-----------------|---------|
| **CC6.1** - Logical Access Controls | Inactive user detection, MFA validation | `user-access-review` |
| **CC6.2** - Least Privilege | Excessive permissions analysis | `user-access-review` |
| **CC6.3** - Access Review and Approval | Manager assignment validation | `user-access-review` |
| **CC7.1** - System Operations | Security group configurations | `evidence-collection` |
| **CC7.2** - Change Management | Configuration drift detection | `config-drift` |

---

## 🔧 Advanced Usage

### Scheduling Automated Reviews
```bash
# Monthly user access review (cron example)
0 9 1 * * /path/to/soc2-audit user-access-review --config /path/to/config.json

# Weekly evidence collection
0 6 * * 1 /path/to/soc2-audit evidence-collection --config /path/to/config.json
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

### Custom Reporting
```python
# Python integration example
from soc2_automation.inactive_users_detector import UserAccessReviewEngine

engine = UserAccessReviewEngine('config.json')
findings = engine.run_comprehensive_access_review()

# Process findings programmatically
for finding in findings:
    if finding.severity == 'HIGH':
        send_alert(finding)
```

---

## 🆘 Troubleshooting

### Common Issues

**Permission Errors**
```bash
# Ensure AWS credentials are configured
aws sts get-caller-identity

# Check IAM permissions against required policy
```

**Configuration Errors**
```bash
# Validate configuration syntax
python -m json.tool config/my_config.json

# Test connectivity to configured systems
./soc2-audit user-access-review --config config.json --verbose
```

**Missing Dependencies**
```bash
# Install all required packages
pip install -r requirements.txt

# Verify Python version (3.7+)
python --version
```

---

## 🤝 Contributing

This project welcomes contributions! Areas where help is needed:

- Additional system integrations (Okta, Azure AD, etc.)
- Enhanced reporting formats
- Additional SOC 2 control mappings
- Documentation improvements

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🔗 Additional Resources

- [SOC 2 Implementation Guide](controls/readme.md)
- [System Requirements](soc2_automation/README_inactive_users.md)
- [API Documentation](requirements/)
- [Best Practices Guide](https://github.com/robparker29/SOC2-starter-kit/wiki)

---

**Ready to streamline your SOC 2 compliance?** Get started with the unified `soc2-audit` command and automate your way to audit readiness! 🚀