# Requirements Specification: AWS Inactive Users Detection Script

## Problem Statement
Create a SOC 2 compliance script that identifies inactive AWS IAM users across single or multiple AWS accounts to support access review requirements and reduce security risk from dormant accounts.

## Solution Overview
Extend the existing SOC 2 automation framework with a new inactive user detection capability that integrates with current data models, reporting formats, and remediation workflows.

## Functional Requirements

### F1: User Activity Analysis
- **F1.1**: Detect console login inactivity (threshold: 90 days)
- **F1.2**: Detect access key inactivity (threshold: 180 days for automation consideration)
- **F1.3**: Apply different severity levels based on inactivity type:
  - Console inactivity ≥90 days = HIGH severity
  - Access key inactivity ≥180 days = MEDIUM severity
- **F1.4**: Support configurable thresholds via configuration file

### F2: Multi-Account Support
- **F2.1**: Analyze users across multiple AWS accounts when configured
- **F2.2**: Use cross-account IAM roles for secure account access
- **F2.3**: Consolidate findings across all accounts in unified reports
- **F2.4**: Support single-account operation as default

### F3: Integration with SOC 2 Framework
- **F3.1**: Extend `SystemDataCollector` class with new `analyze_inactive_users()` method
- **F3.2**: Use existing `UserAccessRecord` model for user data consistency
- **F3.3**: Generate findings using `AccessReviewFinding` model structure
- **F3.4**: Leverage `SOC2Utils` for AWS client initialization and reporting

### F4: Reporting and Evidence
- **F4.1**: Generate audit-ready CSV reports with SOC 2 control mappings
- **F4.2**: Include findings summary with risk counts and recommendations
- **F4.3**: Create timestamped output directories following existing patterns
- **F4.4**: Support JSON output for programmatic processing

### F5: Automated Remediation
- **F5.1**: Create remediation tickets/notifications for findings
- **F5.2**: Provide configuration option to enable/disable ticket creation
- **F5.3**: Include detailed remediation recommendations in tickets
- **F5.4**: Follow existing Jira integration patterns from user access review script

## Technical Requirements

### T1: Architecture Integration
- **File Location**: `soc2_automation/inactive_users_detector.py`
- **Class Structure**: Extend `SystemDataCollector` at `soc2_automation/lib/soc2_collectors.py:18`
- **Method Addition**: `analyze_inactive_users(accounts: List[str] = None) -> List[AccessReviewFinding]`

### T2: Data Models
- **User Records**: Use `UserAccessRecord` from `soc2_automation/lib/soc2_models.py:12`
- **Findings**: Use `AccessReviewFinding` from `soc2_automation/lib/soc2_models.py:80`
- **Configuration**: Extend existing config structure for multi-account support

### T3: AWS Integration
- **Client Initialization**: Use `SOC2Utils.initialize_aws_client()`
- **Cross-Account Access**: Implement STS assume role for multi-account support
- **Permissions Required**: `iam:ListUsers`, `iam:GetAccessKeyLastUsed`, `iam:ListAccessKeys`

### T4: Configuration Structure
```json
{
  "aws": {
    "accounts": [
      {
        "account_id": "123456789012",
        "role_arn": "arn:aws:iam::123456789012:role/SOC2-CrossAccount-Role",
        "region": "us-east-1"
      }
    ]
  },
  "inactive_users": {
    "console_threshold_days": 90,
    "access_key_threshold_days": 180,
    "create_tickets": false,
    "severity_mapping": {
      "console_inactive": "HIGH",
      "access_key_inactive": "MEDIUM"
    }
  }
}
```

## Implementation Hints

### Key Methods to Implement
1. **`analyze_inactive_users()`** - Main analysis orchestrator
2. **`_check_console_activity()`** - Analyze console login patterns
3. **`_check_access_key_activity()`** - Analyze programmatic access patterns
4. **`_generate_inactive_user_findings()`** - Create structured findings
5. **`_assume_cross_account_role()`** - Handle multi-account access

### Integration Points
- **AWS User Collection**: Reuse `collect_aws_users()` method from existing collector
- **Report Generation**: Use `SOC2Utils.write_csv_report()` for consistent formatting
- **Logging**: Use `SOC2Utils.setup_logging()` for standardized log output
- **Ticket Creation**: Adapt existing Jira integration from `user_access_review.py:230`

### Error Handling Patterns
- Graceful handling of account access failures
- Detailed logging of permission issues
- Continuation of analysis if individual accounts fail
- Clear error messages for configuration issues

## Acceptance Criteria

### AC1: Core Functionality
- [ ] Script identifies users inactive for specified thresholds
- [ ] Console and access key activity analyzed separately
- [ ] Findings include user details, inactivity period, and recommendations
- [ ] Multi-account analysis works with cross-account roles

### AC2: Integration
- [ ] Extends existing `SystemDataCollector` class
- [ ] Uses standard SOC 2 data models consistently
- [ ] Generates reports in same format as other SOC 2 tools
- [ ] Logging follows established patterns

### AC3: Configuration
- [ ] Supports single and multi-account configurations
- [ ] Thresholds configurable via JSON config file
- [ ] Ticket creation can be enabled/disabled
- [ ] Cross-account role ARNs configurable per account

### AC4: Output
- [ ] CSV report with audit-ready format
- [ ] JSON output for programmatic processing
- [ ] Timestamped output directories
- [ ] Summary statistics and recommendations

### AC5: SOC 2 Compliance
- [ ] Findings mapped to SOC 2 controls (CC6.1, CC6.2, CC6.3)
- [ ] Evidence suitable for SOC 2 audit
- [ ] Remediation actions clearly documented
- [ ] Risk scoring follows established patterns

## Assumptions
- AWS accounts have necessary IAM permissions configured
- Cross-account roles follow standard naming convention
- Jira integration (if enabled) uses existing authentication
- Output directories are writable by automation user
- Network connectivity exists to all target AWS accounts

## SOC 2 Control Mappings
- **CC6.1 - Logical Access Controls**: Inactive user identification and removal
- **CC6.2 - Least Privilege**: Detection of unused access patterns
- **CC6.3 - Access Review and Approval**: Periodic validation of user access rights