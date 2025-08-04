# SOC 2 Evidence Collection Automation - Setup Guide

## Overview
This script automates the collection of audit evidence required for SOC 2 Type II compliance. It systematically gathers evidence from multiple sources including AWS, Active Directory, applications, and system configurations, then organizes everything in audit-ready formats.

## Prerequisites

### Required Python Packages
```bash
pip install boto3 paramiko pyyaml requests jira pandas ldap3 python-github
```

### System Access Requirements
- **AWS**: CloudTrail, IAM, and EC2 read permissions
- **Active Directory**: LDAP read access to user directory
- **Applications**: API tokens for GitHub, Jira, Salesforce, etc.
- **Linux Servers**: SSH access with sudo privileges for configuration reads
- **File System**: Write access for evidence storage and audit trail generation

## Configuration Steps

### 1. Create System Configuration File
Create `config/systems_config.json`:

```json
{
  "aws": {
    "access_key": "AKIAIOSFODNN7EXAMPLE",
    "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "region": "us-east-1"
  },
  "active_directory": {
    "server": "ldap://dc01.company.com",
    "user": "CN=soc2-service,OU=Service Accounts,DC=company,DC=com",
    "password": "service-account-password",
    "search_base": "DC=company,DC=com"
  },
  "jira": {
    "server": "https://company.atlassian.net",
    "username": "soc2-automation@company.com",
    "api_token": "your-jira-api-token",
    "project_key": "SEC"
  },
  "applications": [
    {
      "name": "GitHub",
      "type": "github",
      "token": "ghp_your-github-token",
      "org_name": "your-organization"
    },
    {
      "name": "Salesforce",
      "type": "salesforce",
      "username": "admin@company.com",
      "password": "salesforce-password",
      "security_token": "salesforce-security-token",
      "domain": "company"
    }
  ],
  "linux_servers": [
    {
      "hostname": "web-server-01.company.com",
      "username": "soc2-evidence",
      "key_file": "/home/evidence/.ssh/id_rsa",
      "password": null
    },
    {
      "hostname": "db-server-01.company.com",
      "username": "soc2-evidence", 
      "key_file": "/home/evidence/.ssh/id_rsa",
      "password": null
    }
  ]
}
```

### 2. Create Evidence Requirements Configuration
Create `config/evidence_requests.json`:

```json
[
  {
    "control_id": "CC6.1",
    "evidence_type": "ACCESS_LISTING",
    "source_system": "AWS IAM",
    "collection_method": "API",
    "file_format": "CSV",
    "retention_period": 2555,
    "collection_frequency": "DAILY",
    "validation_rules": [
      "security_events_captured",
      "administrative_actions_logged",
      "authentication_events_included"
    ]
  }
]
```

### 3. Script Customization Required

#### AWS Evidence Collection (Lines 180-250)
**What to Change:**
- **Line 185**: Update AWS region if different from us-east-1
- **Lines 200-220**: Customize IAM user data fields based on your requirements
- **Lines 230-240**: Modify privilege detection logic for your organization

**Example:**
```python
# Line 200 - Add custom user attributes
user_info = {
    'username': user['UserName'],
    'user_id': user['UserId'],
    'created_date': user['CreateDate'].strftime('%Y-%m-%d %H:%M:%S'),
    'cost_center': user.get('Tags', {}).get('CostCenter', ''),  # Add cost center tracking
    'employee_id': user.get('Tags', {}).get('EmployeeID', ''),  # Add employee ID
    'last_used': 'Never',
    'mfa_enabled': False,
    # ... rest of fields
}

# Line 235 - Customize privilege detection
privileged_keywords = ['admin', 'power', 'elevated', 'root', 'super']  # Add your privilege keywords
user_info['is_privileged'] = any(keyword in group.lower() for group in user_info['group_memberships'] for keyword in privileged_keywords)
```

#### Active Directory Integration (Lines 280-350)
**What to Customize:**
- **Line 285**: Update LDAP server and search base for your domain
- **Lines 295-300**: Modify AD attributes based on your schema
- **Lines 320-325**: Adjust group analysis for your AD structure

**Example:**
```python
# Line 295 - Customize AD attributes for your schema
attributes=['sAMAccountName', 'displayName', 'mail', 'department', 
           'title', 'manager', 'memberOf', 'lastLogon', 'userAccountControl',
           'whenCreated', 'pwdLastSet', 'employeeID', 'costCenter']  # Add your custom attributes

# Line 320 - Customize privileged group detection
privileged_groups = ['Domain Admins', 'Enterprise Admins', 'Schema Admins', 
                    'Backup Operators', 'Server Operators', 'IT Security']  # Your privileged groups
user_info['Privileged_Groups'] = '; '.join([g for g in groups if g in privileged_groups])
```

#### Application Integration (Lines 380-450)
**What to Add:**
- **Lines 390-400**: Add support for your specific applications
- **Lines 410-420**: Customize data collection for each application type

**Example:**
```python
# Add support for additional applications
def _collect_application_access(self, app_config: Dict) -> Optional[Dict[str, str]]:
    """Collect user access information from business applications"""
    if app_config['type'] == 'github':
        return self._collect_github_access(app_config)
    elif app_config['type'] == 'jira':
        return self._collect_jira_access(app_config)
    elif app_config['type'] == 'salesforce':
        return self._collect_salesforce_access(app_config)
    elif app_config['type'] == 'okta':          # Add Okta support
        return self._collect_okta_access(app_config)
    elif app_config['type'] == 'office365':    # Add Office 365 support
        return self._collect_office365_access(app_config)
    elif app_config['type'] == 'slack':        # Add Slack support
        return self._collect_slack_access(app_config)
    else:
        logging.warning(f"Unknown application type: {app_config['type']}")
        return None
```

#### Evidence Validation Rules (Lines 650-700)
**What to Customize:**
- **Lines 660-670**: Define validation rules specific to your compliance requirements
- **Lines 680-690**: Set thresholds based on your organization size and risk tolerance

**Example:**
```python
# Line 665 - Customize validation rules
def validate_evidence_completeness(self, evidence_items: List[EvidenceItem]) -> Dict[str, Any]:
    validation_rules = {
        'CC6.1': {
            'min_evidence_items': 3,  # Require at least 3 pieces of access evidence
            'required_sources': ['AWS IAM', 'Active Directory'],  # Must have these sources
            'max_age_days': 7  # Evidence must be less than 7 days old
        },
        'CC6.3': {
            'min_evidence_items': 1,
            'required_sources': ['Jira'],
            'max_age_days': 90,  # Quarterly reviews can be up to 90 days old
            'custom_validation': self._validate_access_reviews  # Custom validation function
        }
    }
```

### 4. Environment-Specific Customizations

#### For Multi-Cloud Environments
```python
# Add after line 50 - Support multiple cloud providers
def collect_azure_evidence(self) -> List[EvidenceItem]:
    """Collect evidence from Azure AD and Azure resources"""
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.authorization import AuthorizationManagementClient
    
    credential = DefaultAzureCredential()
    auth_client = AuthorizationManagementClient(credential, self.config['azure']['subscription_id'])
    
    # Collect Azure role assignments
    role_assignments = []
    for assignment in auth_client.role_assignments.list():
        role_assignments.append({
            'principal_id': assignment.principal_id,
            'role_definition_id': assignment.role_definition_id,
            'scope': assignment.scope
        })
    
    return self._save_azure_evidence(role_assignments)

def collect_gcp_evidence(self) -> List[EvidenceItem]:
    """Collect evidence from Google Cloud Platform"""
    from google.cloud import resource_manager
    from google.oauth2 import service_account
    
    credentials = service_account.Credentials.from_service_account_file(
        self.config['gcp']['service_account_file']
    )
    
    client = resource_manager.Client(credentials=credentials)
    # Collect GCP IAM policies and bindings
    return self._save_gcp_evidence(client)
```

#### For Compliance Frameworks Beyond SOC 2
```python
# Add framework-specific evidence collection
def collect_pci_evidence(self) -> List[EvidenceItem]:
    """Collect PCI DSS specific evidence"""
    evidence_items = []
    
    # PCI Requirement 8 - User identification and authentication
    pci_8_evidence = self._collect_cardholder_data_access()
    evidence_items.extend(pci_8_evidence)
    
    # PCI Requirement 10 - Logging and monitoring
    pci_10_evidence = self._collect_pci_logging_evidence()
    evidence_items.extend(pci_10_evidence)
    
    return evidence_items

def collect_hipaa_evidence(self) -> List[EvidenceItem]:
    """Collect HIPAA specific evidence"""
    evidence_items = []
    
    # HIPAA Security Rule - Administrative Safeguards
    hipaa_admin_evidence = self._collect_phi_access_evidence()
    evidence_items.extend(hipaa_admin_evidence)
    
    return evidence_items
```

#### For Container and Kubernetes Environments
```python
# Add container security evidence collection
def collect_container_evidence(self) -> List[EvidenceItem]:
    """Collect container and Kubernetes security evidence"""
    evidence_items = []
    
    try:
        from kubernetes import client, config
        
        # Load kubeconfig
        config.load_kube_config()
        v1 = client.CoreV1Api()
        
        # Collect service account information
        service_accounts = []
        for sa in v1.list_service_account_for_all_namespaces().items:
            sa_info = {
                'name': sa.metadata.name,
                'namespace': sa.metadata.namespace,
                'secrets': len(sa.secrets) if sa.secrets else 0,
                'image_pull_secrets': len(sa.image_pull_secrets) if sa.image_pull_secrets else 0
            }
            service_accounts.append(sa_info)
        
        # Save Kubernetes evidence
        output_file = f"{self.output_directory}/access_controls/k8s_service_accounts_{datetime.datetime.now().strftime('%Y%m%d')}.csv"
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            if service_accounts:
                fieldnames = service_accounts[0].keys()
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(service_accounts)
        
        # ... rest of Kubernetes evidence collection
        
    except Exception as e:
        logging.error(f"Kubernetes evidence collection failed: {str(e)}")
    
    return evidence_items
```

### 5. Security Considerations

#### Credential Management
**Never store credentials in configuration files.** Use these secure methods:

1. **Environment Variables** (Recommended):
```bash
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"  
export AD_SERVICE_PASSWORD="your-ad-password"
export JIRA_API_TOKEN="your-jira-token"
```

2. **AWS Secrets Manager Integration**:
```python
# Lines 40-50 - Add secrets manager integration
def load_credentials_from_secrets_manager(self):
    """Load credentials from AWS Secrets Manager"""
    import boto3
    
    secrets_client = boto3.client('secretsmanager', region_name='us-east-1')
    
    # Load different credential sets
    aws_creds = json.loads(secrets_client.get_secret_value(SecretId='soc2/aws-credentials')['SecretString'])
    ad_creds = json.loads(secrets_client.get_secret_value(SecretId='soc2/ad-credentials')['SecretString'])
    app_creds = json.loads(secrets_client.get_secret_value(SecretId='soc2/app-credentials')['SecretString'])
    
    # Update configuration with retrieved credentials
    self.config['aws'].update(aws_creds)
    self.config['active_directory'].update(ad_creds)
    # ... update other credentials
```

3. **HashiCorp Vault Integration**:
```python
# Alternative credential management with Vault
def load_credentials_from_vault(self):
    """Load credentials from HashiCorp Vault"""
    import hvac
    
    vault_client = hvac.Client(url=self.config['vault']['url'])
    vault_client.token = os.environ['VAULT_TOKEN']
    
    # Read secrets from different paths
    aws_secret = vault_client.secrets.kv.v2.read_secret_version(path='soc2/aws')
    ad_secret = vault_client.secrets.kv.v2.read_secret_version(path='soc2/activedirectory')
    
    # Update configuration
    self.config['aws'].update(aws_secret['data']['data'])
    self.config['active_directory'].update(ad_secret['data']['data'])
```

#### Audit Trail Security
```python
# Add after line 45 - Secure audit trail
def create_tamper_evident_audit_trail(self, evidence_items: List[EvidenceItem]):
    """Create cryptographically signed audit trail"""
    import hmac
    
    # Create audit trail data
    audit_data = {
        'session_id': self.collection_session_id,
        'collection_timestamp': datetime.datetime.now().isoformat(),
        'evidence_count': len(evidence_items),
        'evidence_hashes': [item.file_hash for item in evidence_items],
        'collection_user': os.environ.get('USER', 'unknown'),
        'collection_host': os.environ.get('HOSTNAME', 'unknown')
    }
    
    # Sign the audit data
    audit_string = json.dumps(audit_data, sort_keys=True)
    signature = hmac.new(
        self.config['audit_signing_key'].encode(),
        audit_string.encode(),
        hashlib.sha256
    ).hexdigest()
    
    # Save signed audit trail
    signed_audit = {
        'audit_data': audit_data,
        'signature': signature,
        'signing_algorithm': 'HMAC-SHA256'
    }
    
    audit_file = f"{self.output_directory}/audit_trail/signed_audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(audit_file, 'w') as f:
        json.dump(signed_audit, f, indent=2)
```

#### Data Encryption for Evidence Files
```python
# Add encryption for sensitive evidence
def encrypt_evidence_file(self, file_path: str) -> str:
    """Encrypt evidence file using AES encryption"""
    from cryptography.fernet import Fernet
    
    # Generate or load encryption key
    key = self.config.get('encryption_key', Fernet.generate_key())
    f = Fernet(key)
    
    # Read and encrypt file content
    with open(file_path, 'rb') as file:
        file_data = file.read()
    
    encrypted_data = f.encrypt(file_data)
    
    # Save encrypted file
    encrypted_file_path = f"{file_path}.encrypted"
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)
    
    # Remove original file
    os.remove(file_path)
    
    return encrypted_file_path
```

### 6. Testing and Validation

#### Dry Run Testing
```python
# Add dry run mode to constructor (line 35)
def __init__(self, config_path: str, evidence_requests_path: str, dry_run: bool = False):
    self.dry_run = dry_run
    # ... existing initialization
    
    if self.dry_run:
        logging.info("🧪 Running in DRY RUN mode - no evidence will be collected")

# Test connectivity without full collection
python -c "
from evidence_collection import SOC2EvidenceCollector
collector = SOC2EvidenceCollector('config/systems_config.json', 'config/evidence_requests.json', dry_run=True)

# Test AWS connectivity
try:
    import boto3
    iam = boto3.client('iam', **collector.config['aws'])
    response = iam.get_account_summary()
    print('✅ AWS connectivity: OK')
except Exception as e:
    print(f'❌ AWS connectivity: {str(e)}')

# Test AD connectivity  
try:
    import ldap3
    server = ldap3.Server(collector.config['active_directory']['server'])
    conn = ldap3.Connection(server, collector.config['active_directory']['user'], collector.config['active_directory']['password'])
    if conn.bind():
        print('✅ Active Directory connectivity: OK')
        conn.unbind()
    else:
        print('❌ Active Directory connectivity: Failed')
except Exception as e:
    print(f'❌ Active Directory connectivity: {str(e)}')
"
```

#### Evidence Quality Validation
```python
# Add evidence quality checks
def validate_evidence_quality(self, evidence_items: List[EvidenceItem]) -> Dict[str, Any]:
    """Validate quality and completeness of collected evidence"""
    quality_report = {
        'total_items': len(evidence_items),
        'quality_issues': [],
        'recommendations': []
    }
    
    for item in evidence_items:
        # Check file size (too small might indicate incomplete collection)
        if os.path.exists(item.file_path):
            file_size = os.path.getsize(item.file_path)
            if file_size < 100:  # Less than 100 bytes
                quality_report['quality_issues'].append({
                    'evidence_id': item.evidence_id,
                    'issue': 'File size too small',
                    'file_size': file_size
                })
        
        # Check if evidence is recent enough
        age_days = (datetime.datetime.now() - item.collection_date).days
        if age_days > 30:
            quality_report['quality_issues'].append({
                'evidence_id': item.evidence_id,
                'issue': 'Evidence is stale',
                'age_days': age_days
            })
        
        # Check for missing validation notes
        if not item.validation_notes:
            quality_report['quality_issues'].append({
                'evidence_id': item.evidence_id,
                'issue': 'Missing validation notes'
            })
    
    return quality_report
```

### 7. Deployment Strategies

#### Scheduled Evidence Collection
```bash
# Create systemd service for automated collection
sudo tee /etc/systemd/system/soc2-evidence.service > /dev/null <<EOF
[Unit]
Description=SOC 2 Evidence Collection
After=network.target

[Service]
Type=oneshot
User=soc2-evidence
WorkingDirectory=/opt/soc2-toolkit
ExecStart=/usr/bin/python3 evidence_collection.py
Environment=PYTHONPATH=/opt/soc2-toolkit
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Create systemd timer for weekly execution
sudo tee /etc/systemd/system/soc2-evidence.timer > /dev/null <<EOF
[Unit]
Description=Run SOC 2 Evidence Collection Weekly
Requires=soc2-evidence.service

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Enable and start the timer
sudo systemctl enable soc2-evidence.timer
sudo systemctl start soc2-evidence.timer
```

#### CI/CD Integration with GitHub Actions
```yaml
# .github/workflows/evidence-collection.yml
name: SOC 2 Evidence Collection
on:
  schedule:
    - cron: '0 6 * * 1'  # Every Monday at 6 AM
  workflow_dispatch:     # Manual trigger
  
jobs:
  collect-evidence:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
          
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
          
      - name: Run Evidence Collection
        run: python evidence_collection.py
        env:
          AD_SERVICE_PASSWORD: ${{ secrets.AD_SERVICE_PASSWORD }}
          JIRA_API_TOKEN: ${{ secrets.JIRA_API_TOKEN }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          
      - name: Upload Evidence Package
        uses: actions/upload-artifact@v3
        with:
          name: soc2-evidence-package
          path: evidence_collection_*/SOC2_Evidence_Package_*.zip
          retention-days: 90
          
      - name: Notify Security Team
        if: failure()
        uses: 8398a7/action-slack@v3
        with:
          status: failure
          channel: '#security-alerts'
          webhook_url: ${{ secrets.SLACK_WEBHOOK }}
```

#### Integration with Compliance Management Tools
```python
# Add integration with GRC platforms
def upload_to_grc_platform(self, evidence_items: List[EvidenceItem]):
    """Upload evidence to GRC/compliance management platform"""
    
    # Example: ServiceNow GRC integration
    if self.config.get('servicenow'):
        import requests
        
        for item in evidence_items:
            # Create evidence record in ServiceNow
            evidence_payload = {
                'control_id': item.soc2_control,
                'evidence_type': item.evidence_type,
                'collection_date': item.collection_date.isoformat(),
                'file_path': item.file_path,
                'description': item.description,
                'completeness_status': item.completeness_status
            }
            
            response = requests.post(
                f"{self.config['servicenow']['instance']}/api/now/table/u_soc2_evidence",
                auth=(self.config['servicenow']['username'], self.config['servicenow']['password']),
                headers={'Content-Type': 'application/json'},
                json=evidence_payload
            )
            
            if response.status_code == 201:
                logging.info(f"Evidence uploaded to ServiceNow: {item.evidence_id}")
            else:
                logging.error(f"Failed to upload evidence {item.evidence_id}: {response.text}")
    
    # Example: OneTrust integration
    if self.config.get('onetrust'):
        # Integration with OneTrust privacy and compliance platform
        pass
    
    # Example: MetricStream integration  
    if self.config.get('metricstream'):
        # Integration with MetricStream GRC platform
        pass
```

### 8. Troubleshooting Common Issues

#### Issue: "Permission denied" errors
**Solution**: Verify IAM permissions and service account privileges
```bash
# Test AWS permissions
aws iam get-account-summary --profile soc2-evidence

# Test AD connectivity
ldapsearch -x -H ldap://dc01.company.com -D "CN=soc2-service,OU=Service Accounts,DC=company,DC=com" -W -b "DC=company,DC=com" "(objectClass=user)" sAMAccountName

# Test Jira API
curl -u user@company.com:api-token -X GET "https://company.atlassian.net/rest/api/2/myself"
```

#### Issue: "SSL certificate verification failed"
**Solution**: Configure SSL settings for your environment
```python
# Lines 45-50 - Add SSL configuration
import ssl
import urllib3

# For development environments only - disable SSL warnings
if self.config.get('disable_ssl_verification', False):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    ssl._create_default_https_context = ssl._create_unverified_context
    
# For production - configure proper SSL verification
else:
    # Use custom CA bundle if needed
    os.environ['REQUESTS_CA_BUNDLE'] = '/path/to/your/ca-bundle.pem'
```

#### Issue: "Rate limiting" from APIs
**Solution**: Implement rate limiting and retry logic
```python
# Add retry logic with exponential backoff
import time
from functools import wraps

def retry_with_backoff(max_retries=3, backoff_factor=2):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if 'rate limit' in str(e).lower() and attempt < max_retries - 1:
                        wait_time = backoff_factor ** attempt
                        logging.warning(f"Rate limited, waiting {wait_time} seconds...")
                        time.sleep(wait_time)
                        continue
                    raise e
            return None
        return wrapper
    return decorator

# Apply to API calls
@retry_with_backoff()
def _collect_github_access(self, app_config: Dict) -> Optional[Dict[str, str]]:
    # ... existing implementation
```

### 9. Advanced Features

#### Incremental Evidence Collection
```python
# Add incremental collection capability
def collect_incremental_evidence(self, last_collection_timestamp: datetime.datetime) -> List[EvidenceItem]:
    """Collect only evidence that has changed since last collection"""
    evidence_items = []
    
    # Only collect AWS changes since last run
    aws_changes = self._get_aws_changes_since(last_collection_timestamp)
    if aws_changes:
        evidence_items.extend(self._collect_aws_incremental_evidence(aws_changes))
    
    # Only collect AD changes since last run
    ad_changes = self._get_ad_changes_since(last_collection_timestamp)
    if ad_changes:
        evidence_items.extend(self._collect_ad_incremental_evidence(ad_changes))
    
    return evidence_items
```

#### Evidence Correlation and Analysis
```python
# Add evidence correlation capabilities
def correlate_evidence_across_systems(self, evidence_items: List[EvidenceItem]) -> Dict[str, Any]:
    """Correlate evidence across different systems to identify gaps"""
    correlation_report = {
        'user_correlations': {},
        'access_gaps': [],
        'privilege_inconsistencies': []
    }
    
    # Group evidence by user
    aws_users = self._extract_users_from_evidence('AWS IAM', evidence_items)
    ad_users = self._extract_users_from_evidence('Active Directory', evidence_items)
    
    # Find users in one system but not the other
    aws_only = set(aws_users) - set(ad_users)
    ad_only = set(ad_users) - set(aws_users)
    
    if aws_only:
        correlation_report['access_gaps'].append({
            'type': 'AWS_ORPHANED_ACCOUNTS',
            'users': list(aws_only),
            'risk': 'Users with AWS access but no AD account'
        })
    
    if ad_only:
        correlation_report['access_gaps'].append({
            'type': 'AD_ORPHANED_ACCOUNTS', 
            'users': list(ad_only),
            'risk': 'Users with AD account but no AWS access'
        })
    
    return correlation_report
```

## Running the Script

### Initial Setup and Testing
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Create and configure files
mkdir -p config evidence_collection_$(date +%Y%m%d)
cp config/systems_config.json.template config/systems_config.json
cp config/evidence_requests.json.template config/evidence_requests.json

# 3. Edit configurations for your environment
vi config/systems_config.json
vi config/evidence_requests.json

# 4. Test connectivity (dry run)
python evidence_collection.py --dry-run

# 5. Run initial evidence collection
python evidence_collection.py

# 6. Review generated evidence package
ls -la evidence_collection_*/SOC2_Evidence_Package_*.zip
```

### Production Deployment
```bash
# Deploy to evidence collection server
sudo mkdir -p /opt/soc2-evidence-collector
sudo cp -r * /opt/soc2-evidence-collector/
sudo chown -R soc2-evidence:soc2-evidence /opt/soc2-evidence-collector/

# Set up secure file permissions
sudo chmod 600 /opt/soc2-evidence-collector/config/systems_config.json
sudo chmod 700 /opt/soc2-evidence-collector/evidence_collection_*

# Configure systemd service and timer (see deployment section above)
sudo systemctl enable soc2-evidence.timer
sudo systemctl start soc2-evidence.timer

# Monitor collection logs
sudo journalctl -u soc2-evidence.service -f
```

This comprehensive setup guide ensures your evidence collection automation can be deployed successfully across different enterprise environments while maintaining security and compliance requirements.
