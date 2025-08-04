# User Access Review Automation - Setup Guide

## Overview
This script automates SOC 2 user access reviews across Active Directory, AWS IAM, and GitHub. Before running, you'll need to configure system connections and customize the script for your environment.

## Prerequisites

### Required Python Packages
```bash
pip install boto3 PyGithub ldap3 requests
```

### System Access Requirements
- Active Directory: Read access to domain users
- AWS: IAM permissions for `ListUsers`, `GetAccessKeyLastUsed`, `ListAttachedUserPolicies`
- GitHub: Organization admin token with `read:org` and `repo` scopes
- Jira: API token for ticket creation (optional)

## Configuration Steps

### 1. Create Configuration File
Create `config/systems_config.json` in your project root:

```json
{
  "ad": {
    "server": "ldap://your-domain-controller.company.com",
    "user": "CN=service-account,OU=Users,DC=company,DC=com",
    "password": "your-service-account-password"
  },
  "aws": {
    "access_key": "AKIAIOSFODNN7EXAMPLE",
    "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "region": "us-east-1"
  },
  "github": {
    "token": "ghp_your-personal-access-token",
    "org_name": "your-organization-name"
  },
  "jira": {
    "url": "https://your-company.atlassian.net",
    "username": "your-email@company.com",
    "api_token": "your-jira-api-token",
    "project_key": "SEC"
  }
}
```

### 2. Script Customization Required

#### Active Directory Configuration (Lines 56-70)
**What to Change:**
- **Line 58**: Replace `'dc=company,dc=com'` with your domain DN
- **Line 69**: Update manager extraction logic if your AD schema differs
- **Line 70**: Modify department field name if different (`department` vs `ou`)

**Example:**
```python
# Line 58 - Replace with your domain
conn.search('dc=yourcompany,dc=local', '(objectClass=person)', attributes=['*'])

# Lines 69-70 - Adjust attribute names for your AD schema  
manager=str(entry.manager) if hasattr(entry, 'manager') else 'Unknown',
department=str(entry.departmentNumber) if hasattr(entry, 'departmentNumber') else 'Unknown',
```

#### AWS IAM Configuration (Lines 76-105)
**What to Change:**
- **Lines 88-90**: Modify tag extraction if you use different tag names
- **Lines 99-102**: Update tag names to match your AWS tagging strategy

**Example:**
```python
# Lines 88-90 - Replace with your AWS tag names
email=user.get('Tags', {}).get('EmailAddress', ''),  # If you use 'EmailAddress' instead of 'Email'
manager=user.get('Tags', {}).get('ManagerName', 'Unknown'),  # Your manager tag name
department=user.get('Tags', {}).get('CostCenter', 'Unknown'),  # Your department tag name
```

#### GitHub Configuration (Lines 107-128)
**What to Change:**
- **Line 112**: Replace organization name retrieval method if needed
- **Line 125**: Update department assumption or add logic to determine from teams

**Example:**
```python
# Line 112 - If you need to specify org differently
org = g.get_organization('your-actual-org-name')

# Line 125 - More sophisticated department detection
department=self._get_github_department(member),  # Custom function to determine dept
```

#### Risk Analysis Thresholds (Lines 143-185)
**What to Customize:**
- **Line 148**: Inactive user threshold (currently 90 days)
- **Line 156**: Excessive permissions threshold (currently 10)
- **Line 149**: High-risk inactive threshold (currently 180 days)

**Example:**
```python
# Line 148 - Adjust inactive threshold for your organization
if days_inactive > 60:  # Change from 90 to 60 days

# Line 156 - Adjust permission threshold based on your environment
if len(user.permissions) > 5:  # Change from 10 to 5 permissions
```

#### Output Customization (Lines 187-230)
**What to Change:**
- **Line 208**: Modify CSV field names to match your audit requirements
- **Lines 210-221**: Add/remove fields based on your reporting needs

### 3. Environment-Specific Helpers

#### For Different AD Schemas
If your Active Directory uses different attribute names, update the helper functions:

```python
# Lines 270-275 - Customize for your AD schema
def _extract_ad_groups(self, entry):
    """Extract group memberships - customize for your AD"""
    if hasattr(entry, 'memberOf'):
        return [group.split(',')[0].replace('CN=', '') for group in entry.memberOf.values]
    return ['Unknown']
```

#### For Different AWS Setups
If you use AWS Organizations or different IAM structures:

```python
# Add after line 84 - For AWS Organizations
def get_aws_accounts():
    org_client = boto3.client('organizations')
    accounts = org_client.list_accounts()
    return accounts['Accounts']
```

### 4. Security Considerations

#### Credential Management
**Never hardcode credentials in the script.** Use one of these methods:

1. **Environment Variables** (Recommended):
```bash
export AD_PASSWORD="your-password"
export AWS_ACCESS_KEY="your-key"
export GITHUB_TOKEN="your-token"
```

2. **AWS Secrets Manager**:
```python
# Replace lines 40-42 with secrets manager retrieval
import boto3
secrets_client = boto3.client('secretsmanager')
config = json.loads(secrets_client.get_secret_value(SecretId='soc2-config')['SecretString'])
```

3. **Azure Key Vault** or similar service for your environment

#### Network Security
- **Line 57**: Use LDAPS (secure LDAP) instead of LDAP
- Consider running from a bastion host or VPN-connected environment

### 5. Testing Your Configuration

#### Dry Run Mode
Add this parameter to test without creating tickets:

```python
# Line 35 - Add dry_run parameter
def __init__(self, config_path: str, dry_run: bool = False):
    self.dry_run = dry_run
    
# Line 253 - Check dry_run before creating tickets
if not self.dry_run:
    self.create_jira_tickets(findings)
```

#### Test Each System Individually
```python
# Test AD connection
python -c "from user_access_review import AccessReviewEngine; engine = AccessReviewEngine('config/systems_config.json'); print(len(engine.collect_ad_users()))"

# Test AWS connection  
python -c "from user_access_review import AccessReviewEngine; engine = AccessReviewEngine('config/systems_config.json'); print(len(engine.collect_aws_users()))"

# Test GitHub connection
python -c "from user_access_review import AccessReviewEngine; engine = AccessReviewEngine('config/systems_config.json'); print(len(engine.collect_github_users()))"
```

## Common Issues & Solutions

### Issue: "Server not available" (AD)
**Solution**: Update line 57 with correct domain controller FQDN or IP

### Issue: "AccessDenied" (AWS)
**Solution**: Verify IAM permissions and region in config

### Issue: "Bad credentials" (GitHub)
**Solution**: Regenerate token with correct scopes (`read:org`, `repo`)

### Issue: Empty results
**Solution**: Check search base DNs, organization names, and permissions

## Customization for Different Industries

### Healthcare (HIPAA)
Add PHI detection logic around line 160:
```python
# Check for PHI access
if 'PHI' in user.permissions or 'HIPAA' in user.permissions:
    findings.append({'type': 'PHI_ACCESS_REVIEW_REQUIRED', ...})
```

### Financial Services (SOX)
Add SOX-specific controls around line 165:
```python
# Check for financial system access
if any('FINANCIAL' in perm.upper() for perm in user.permissions):
    findings.append({'type': 'SOX_SEGREGATION_REVIEW', ...})
```

### PCI DSS Environments
Add cardholder data environment checks around line 170:
```python
# Check for CDE access
if user.system in ['PAYMENT_PROCESSOR', 'CARD_DB']:
    findings.append({'type': 'PCI_ACCESS_REVIEW', ...})
```

## Running the Script

### Manual Execution
```bash
python user_access_review.py
```

### Automated Quarterly Reviews
Add to crontab for quarterly execution:
```bash
# Run on the 1st of every quarter at 9 AM
0 9 1 1,4,7,10 * /usr/bin/python3 /path/to/user_access_review.py
```

### Integration with CI/CD
```yaml
# Example GitHub Action
name: SOC2 Access Review
on:
  schedule:
    - cron: '0 9 1 */3 *'  # Quarterly
jobs:
  access-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run Access Review
        run: python user_access_review.py
        env:
          CONFIG_PATH: ${{ secrets.SOC2_CONFIG }}
```

## Next Steps

1. **Test in non-production environment first**
2. **Validate output against manual access review**
3. **Customize risk thresholds based on your risk appetite**
4. **Integrate with your existing SIEM/compliance tools**
5. **Schedule regular automated runs**

## Support

For issues or customization help:
- Review the error logs generated in `/logs/` directory
- Check system connectivity and permissions
- Validate configuration file syntax with `python -m json.tool config/systems_config.json`
