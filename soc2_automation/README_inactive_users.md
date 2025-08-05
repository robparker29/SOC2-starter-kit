# AWS Inactive Users Detection Script

SOC 2 compliance script that identifies inactive AWS IAM users across single or multiple AWS accounts to support access review requirements and reduce security risk from dormant accounts.

## Features

- ✅ **Console Login Analysis**: Detects users inactive for 90+ days (configurable)
- ✅ **Access Key Analysis**: Identifies unused programmatic access (180+ days configurable)
- ✅ **Multi-Account Support**: Cross-account analysis using IAM roles
- ✅ **SOC 2 Integration**: Uses existing data models and reporting formats
- ✅ **Audit-Ready Reports**: CSV and JSON outputs with SOC 2 control mappings
- ✅ **Automated Tickets**: Optional Jira ticket creation for findings
- ✅ **Flexible Configuration**: Customizable thresholds and severity levels

## SOC 2 Control Mappings

- **CC6.1 - Logical Access Controls**: Inactive user identification and removal
- **CC6.2 - Least Privilege**: Detection of unused access patterns  
- **CC6.3 - Access Review and Approval**: Periodic validation of user access rights

## Installation

This script integrates with the existing SOC 2 automation framework:

```bash
# Ensure you're in the soc2-starter-kit directory
cd soc2-starter-kit

# Install required dependencies (if not already installed)
pip install boto3 paramiko ldap3 PyGithub

# Make the script executable
chmod +x soc2_automation/inactive_users_detector.py
```

## Configuration

### Single Account Setup

For analyzing a single AWS account, create `config/inactive_users_config.json`:

```json
{
  "aws": {
    "access_key": "YOUR_AWS_ACCESS_KEY",
    "secret_key": "YOUR_AWS_SECRET_KEY",
    "region": "us-east-1"
  },
  "inactive_users": {
    "console_threshold_days": 90,
    "access_key_threshold_days": 180,
    "create_tickets": false
  }
}
```

### Multi-Account Setup

For cross-account analysis, configure multiple accounts with IAM roles:

```json
{
  "aws": {
    "access_key": "YOUR_BASE_ACCESS_KEY",
    "secret_key": "YOUR_BASE_SECRET_KEY",
    "region": "us-east-1",
    "accounts": [
      {
        "account_id": "123456789012",
        "role_arn": "arn:aws:iam::123456789012:role/SOC2-CrossAccount-Role",
        "region": "us-east-1"
      },
      {
        "account_id": "210987654321", 
        "role_arn": "arn:aws:iam::210987654321:role/SOC2-CrossAccount-Role",
        "region": "us-west-2"
      }
    ]
  },
  "inactive_users": {
    "console_threshold_days": 90,
    "access_key_threshold_days": 180,
    "create_tickets": true
  },
  "jira": {
    "server": "https://your-company.atlassian.net",
    "username": "automation@yourcompany.com", 
    "api_token": "YOUR_JIRA_API_TOKEN",
    "project_key": "SEC"
  }
}
```

### Required IAM Permissions

The script requires these IAM permissions:

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
        "iam:ListMFADevices"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "sts:AssumeRole"
      ],
      "Resource": "arn:aws:iam::*:role/SOC2-CrossAccount-Role"
    }
  ]
}
```

## Usage

### Basic Usage

```bash
# Analyze current AWS account
python soc2_automation/inactive_users_detector.py --config config/inactive_users_config.json

# Analyze specific accounts only
python soc2_automation/inactive_users_detector.py --config config/inactive_users_config.json --accounts 123456789012 210987654321

# Custom output directory
python soc2_automation/inactive_users_detector.py --config config/inactive_users_config.json --output-dir /path/to/reports
```

### Advanced Options

```bash
# Override thresholds
python soc2_automation/inactive_users_detector.py \\
  --config config/inactive_users_config.json \\
  --console-threshold 60 \\
  --access-key-threshold 120

# Force ticket creation (overrides config)
python soc2_automation/inactive_users_detector.py \\
  --config config/inactive_users_config.json \\
  --create-tickets
```

### Integration with Existing Scripts

```python
from soc2_automation.inactive_users_detector import InactiveUsersDetector

# Initialize detector
detector = InactiveUsersDetector('config/inactive_users_config.json')

# Run analysis
findings = detector.analyze_inactive_users()

# Generate reports
report_paths = detector.generate_reports()

# Create tickets if enabled
if detector.create_tickets:
    detector.create_remediation_tickets()
```

## Output Reports

### CSV Report Format

The script generates audit-ready CSV reports with these columns:

- **Finding_ID**: Unique identifier for tracking
- **Account**: AWS account analyzed
- **Username**: IAM username
- **Email**: User email from tags
- **Finding_Type**: CONSOLE_INACTIVE, ACCESS_KEY_INACTIVE, etc.
- **Severity**: HIGH, MEDIUM, LOW
- **Details**: Specific inactivity information
- **SOC2_Control**: Related SOC 2 control (CC6.1, CC6.2, CC6.3)
- **Remediation**: Recommended actions
- **Department**: User department from tags
- **Manager**: User manager from tags
- **Created_Date**: Account creation date
- **Last_Login**: Most recent activity date
- **MFA_Enabled**: Multi-factor authentication status
- **Status**: Finding status (OPEN, RESOLVED)

### JSON Report Format

Structured JSON output includes:

```json
{
  "analysis_date": "2025-08-05T20:08:00Z",
  "accounts_analyzed": ["123456789012", "210987654321"],
  "configuration": {
    "console_threshold_days": 90,
    "access_key_threshold_days": 180
  },
  "summary": {
    "total_findings": 15,
    "high_severity": 8,
    "medium_severity": 7,
    "low_severity": 0
  },
  "findings": [...]
}
```

## Finding Types and Severities

| Finding Type | Severity | Description |
|--------------|----------|-------------|
| CONSOLE_INACTIVE | HIGH | Console login inactive for 90+ days |
| CONSOLE_NEVER_USED | HIGH | Console access never used since creation |
| ACCESS_KEY_INACTIVE | MEDIUM | Access keys unused for 180+ days |
| ACCESS_KEY_NEVER_USED | MEDIUM | Access keys created but never used |

## Automated Remediation

When ticket creation is enabled, the script creates Jira tickets for HIGH severity findings with:

- **Summary**: Clear identification of user and issue
- **Description**: Detailed user information and recommended actions
- **Priority**: High for security-related findings
- **Labels**: SOC2, InactiveUser, Security, AccessReview
- **SOC 2 Control**: Mapped to relevant compliance controls

## Scheduling and Automation

### Cron Example

Run monthly access reviews:

```bash
# Add to crontab for monthly execution
0 9 1 * * /usr/bin/python3 /path/to/soc2-starter-kit/soc2_automation/inactive_users_detector.py --config /path/to/config.json
```

### CI/CD Integration

Exit codes for automation:
- **0**: No findings (clean)
- **1**: Findings detected (review needed)  
- **2**: Script error (investigate)

```yaml
# GitHub Actions example
- name: Run Inactive Users Check
  run: |
    python soc2_automation/inactive_users_detector.py --config config/inactive_users_config.json
    if [ $? -eq 1 ]; then
      echo "::warning::Inactive users detected - review required"
    fi
```

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure IAM permissions are correctly configured
2. **Cross-Account Access Failed**: Verify role ARNs and trust relationships
3. **No Activity Data**: Some users may not have password or access key activity
4. **Rate Limiting**: Script includes retry logic for AWS API limits

### Debug Mode

Enable debug logging:

```json
{
  "logging": {
    "level": "DEBUG",
    "file": "logs/inactive_users_debug.log"
  }
}
```

### Validation

Test configuration without making changes:

```bash
# Dry run mode (add --dry-run flag in future version)
python soc2_automation/inactive_users_detector.py --config config/test_config.json --accounts 123456789012
```

## Security Considerations

- Store AWS credentials securely (use IAM roles when possible)
- Rotate access keys regularly
- Use cross-account roles instead of storing multiple credentials
- Review and validate findings before taking remediation actions
- Audit script execution logs regularly

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review logs in the configured log directory
3. Ensure all dependencies are installed and up to date
4. Verify AWS permissions and network connectivity