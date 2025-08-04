# Configuration Drift Detection - Setup Guide

## Overview
This script monitors critical system configurations against approved baselines to detect unauthorized changes that could impact SOC 2 compliance. It scans AWS security groups, Linux servers, and network devices to identify configuration drift.

## Prerequisites

### Required Python Packages
```bash
pip install boto3 paramiko pyyaml requests
```

### System Access Requirements
- **AWS**: IAM permissions for EC2 security group read access
- **Linux Servers**: SSH access with sudo privileges for configuration reads
- **Network Devices**: SSH/console access to firewall/switch/router management interfaces
- **File System**: Write access for baseline storage and report generation

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
  "linux_servers": [
    {
      "hostname": "web-server-01.company.com",
      "username": "soc2-monitor",
      "key_file": "/home/monitor/.ssh/id_rsa",
      "password": null
    },
    {
      "hostname": "db-server-01.company.com", 
      "username": "soc2-monitor",
      "key_file": "/home/monitor/.ssh/id_rsa",
      "password": null
    }
  ],
  "network_devices": [
    {
      "ip": "192.168.1.1",
      "type": "cisco",
      "username": "admin",
      "password": "device-admin-password",
      "config_command": "show running-config"
    },
    {
      "ip": "192.168.1.2", 
      "type": "palo_alto",
      "username": "admin",
      "password": "device-admin-password",
      "config_command": "show config running"
    }
  ]
}
```

### 2. Create Baseline Configuration File
Create `baselines/approved_configs.yaml`:

```yaml
# AWS Security Group Baselines
aws_security_group:
  sg-12345abcde:
    baseline_hash: "a1b2c3d4e5f6789012345678901234567890abcdef"
    baseline_content:
      group_name: "web-servers-sg"
      description: "Web servers security group"
      inbound_rules:
        - protocol: "tcp"
          from_port: 443
          to_port: 443
          cidr_blocks: ["0.0.0.0/0"]
          security_groups: []
        - protocol: "tcp"
          from_port: 80
          to_port: 80
          cidr_blocks: ["0.0.0.0/0"] 
          security_groups: []
      outbound_rules:
        - protocol: "-1"
          from_port: ""
          to_port: ""
          cidr_blocks: ["0.0.0.0/0"]
          security_groups: []
    last_approved: "2024-01-15T10:30:00Z"
    approver: "security-team@company.com"
    compliance_controls: ["CC6.1", "CC6.7"]

# Linux Server Baselines  
linux_config:
  web-server-01.company.com_ssh_configuration:
    baseline_hash: "b2c3d4e5f6789012345678901234567890abcdef01"
    baseline_content: |
      PermitRootLogin no
      PasswordAuthentication no
      Port 22
    last_approved: "2024-01-15T10:30:00Z"
    approver: "infrastructure-team@company.com"
    compliance_controls: ["CC6.1", "CC6.7"]
    
  web-server-01.company.com_firewall_rules:
    baseline_hash: "c3d4e5f6789012345678901234567890abcdef0123"
    baseline_content: |
      Chain INPUT (policy DROP)
      target     prot opt source               destination
      ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:443
      ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:80
      ACCEPT     tcp  --  10.0.0.0/8           0.0.0.0/0            tcp dpt:22
    last_approved: "2024-01-15T10:30:00Z"
    approver: "infrastructure-team@company.com"
    compliance_controls: ["CC6.1", "CC6.7"]

# Network Device Baselines
network_device:
  192.168.1.1_cisco_config:
    baseline_hash: "d4e5f6789012345678901234567890abcdef012345"
    baseline_content: |
      interface GigabitEthernet0/1
       description LAN Interface
       ip address 192.168.1.1 255.255.255.0
       no shutdown
      !
      access-list 100 permit tcp any host 192.168.1.10 eq 443
      access-list 100 permit tcp any host 192.168.1.10 eq 80
      access-list 100 deny ip any any log
    last_approved: "2024-01-15T10:30:00Z"
    approver: "network-team@company.com"
    compliance_controls: ["CC6.1", "CC6.7", "CC6.8"]
```

### 3. Script Customization Required

#### AWS Security Group Monitoring (Lines 65-100)
**What to Change:**
- **Line 70**: Update AWS region if different from us-east-1
- **Lines 85-88**: Modify security group rule normalization if you use different rule structures
- **Lines 95-98**: Adjust SOC 2 control mappings based on your control framework

**Example:**
```python
# Line 70 - Update for your AWS region
region_name=self.config['aws']['region']  # Ensure this matches your primary region

# Line 87 - Add custom rule attributes if needed
'description': rule.get('Description', ''),  # If you use rule descriptions
'tags': rule.get('Tags', [])  # If you tag security group rules
```

#### Linux Server Configuration Checks (Lines 102-180)
**What to Customize:**
- **Lines 127-148**: Modify configuration checks based on your server hardening standards
- **Lines 135, 140, 145**: Update file paths if your configurations are in different locations
- **Line 165**: Adjust baseline key naming convention for your environment

**Example:**
```python
# Lines 127-148 - Customize for your environment
config_checks = [
    {
        'name': 'SSH Configuration',
        'command': 'sudo cat /etc/ssh/sshd_config | grep -E "(PermitRootLogin|PasswordAuthentication|Port|MaxAuthTries)"',
        'controls': ['CC6.1', 'CC6.7']
    },
    {
        'name': 'PAM Configuration',  # Add if you use PAM
        'command': 'sudo cat /etc/pam.d/common-auth | grep -v "^#"',
        'controls': ['CC6.1', 'CC6.2']
    },
    {
        'name': 'NTP Configuration',  # Add time sync monitoring
        'command': 'sudo cat /etc/ntp.conf | grep -E "^server"',
        'controls': ['CC6.8']
    }
]
```

#### Network Device Support (Lines 182-240)
**What to Change:**
- **Lines 200-206**: Add support for your specific network device types
- **Lines 201, 203, 205**: Update configuration dump commands for your devices
- **Line 215**: Modify baseline key format for your naming convention

**Example:**
```python
# Lines 200-206 - Add your device types
if device['type'] == 'cisco':
    command = 'show running-config'
elif device['type'] == 'palo_alto':
    command = 'show config running'
elif device['type'] == 'fortinet':  # Add FortiGate support
    command = 'show full-configuration'
elif device['type'] == 'juniper':   # Add Juniper support
    command = 'show configuration'
else:
    command = device.get('config_command', 'show config')
```

#### Risk Assessment Customization (Lines 445-495)
**What to Adjust:**
- **Lines 465-470**: Modify severity criteria based on your risk tolerance
- **Lines 475-485**: Update risk keywords for your environment
- **Lines 490-495**: Adjust remediation recommendations

**Example:**
```python
# Lines 465-470 - Customize severity assessment
def _assess_sg_drift_severity(self, change: Dict) -> str:
    # More restrictive assessment
    if '0.0.0.0/0' in change['current']:
        return 'CRITICAL'  # Any internet-facing rule is critical
    elif any(port in change['current'] for port in ['22', '3389', '5432']):
        return 'HIGH'  # Administrative/database ports are high risk
    elif change['type'] == 'NEW_INBOUND_RULE':
        return 'MEDIUM'  # Other new rules are medium risk
    return 'LOW'
```

### 4. Creating Initial Baselines

#### Method 1: Capture Current State (Initial Setup)
```bash
# Create baseline capture script
python create_baselines.py --capture-current --approve-all
```

#### Method 2: Manual Baseline Creation
For each system, manually create baseline entries:

```python
# Example baseline creation script
import hashlib
import json
import yaml

def create_sg_baseline(sg_id, sg_config):
    config_hash = hashlib.sha256(json.dumps(sg_config, sort_keys=True).encode()).hexdigest()
    return {
        'baseline_hash': config_hash,
        'baseline_content': sg_config,
        'last_approved': '2024-01-15T10:30:00Z',
        'approver': 'security-team@company.com',
        'compliance_controls': ['CC6.1', 'CC6.7']
    }
```

#### Method 3: Import from Configuration Management
If you use Ansible, Terraform, or similar tools:

```python
# Lines 50-55 - Add configuration management integration
def load_terraform_state(self):
    """Load baseline configurations from Terraform state"""
    import terraform
    tf = terraform.Terraform(working_dir='/path/to/terraform')
    state = tf.show(json=True)
    # Parse state and create baselines
```

### 5. Environment-Specific Customizations

#### For Multi-Account AWS Environments
```python
# Add after line 65 - Support multiple AWS accounts
def scan_all_aws_accounts(self):
    findings = []
    for account in self.config['aws_accounts']:
        session = boto3.Session(
            aws_access_key_id=account['access_key'],
            aws_secret_access_key=account['secret_key'],
            region_name=account['region']
        )
        ec2 = session.client('ec2')
        # Scan this account's security groups
    return findings
```

#### For Docker/Container Environments
```python
# Add container configuration monitoring
def scan_docker_configs(self):
    """Monitor Docker daemon and container configurations"""
    docker_checks = [
        {
            'name': 'Docker Daemon Config',
            'command': 'sudo cat /etc/docker/daemon.json',
            'controls': ['CC6.1', 'CC6.8']
        },
        {
            'name': 'Container Runtime Security',
            'command': 'docker info --format "{{json .SecurityOptions}}"',
            'controls': ['CC6.1']
        }
    ]
```

#### For Cloud-Native Environments
```python
# Add Kubernetes configuration monitoring
def scan_k8s_configs(self):
    """Monitor Kubernetes security configurations"""
    k8s_checks = [
        {
            'name': 'Pod Security Policies',
            'command': 'kubectl get psp -o yaml',
            'controls': ['CC6.1', 'CC6.2']
        },
        {
            'name': 'Network Policies', 
            'command': 'kubectl get networkpolicy --all-namespaces -o yaml',
            'controls': ['CC6.1', 'CC6.7']
        }
    ]
```

### 6. Security Considerations

#### Credential Management
**Never store credentials in configuration files.** Use one of these methods:

1. **AWS IAM Roles** (Recommended for AWS resources):
```json
{
  "aws": {
    "use_iam_role": true,
    "role_arn": "arn:aws:iam::123456789012:role/SOC2-ConfigMonitor",
    "region": "us-east-1"
  }
}
```

2. **HashiCorp Vault Integration**:
```python
# Lines 40-45 - Add Vault integration
import hvac
vault_client = hvac.Client(url='https://vault.company.com')
vault_client.token = os.environ['VAULT_TOKEN']
secrets = vault_client.secrets.kv.v2.read_secret_version(path='soc2/config-monitor')
```

3. **Environment Variables**:
```bash
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"
export LINUX_SSH_KEY_PATH="/path/to/key"
```

#### Network Security
- **Line 115**: Use SSH key-based authentication instead of passwords
- **Line 195**: Connect to network devices via management VLAN or VPN
- **Line 57**: Consider using bastion hosts for server access

#### Audit Trail Security
```python
# Add after line 245 - Secure audit trail
def secure_audit_trail(self, findings):
    """Create tamper-evident audit trail"""
    import hmac
    trail_data = json.dumps([asdict(f) for f in findings], sort_keys=True)
    signature = hmac.new(
        self.config['audit_key'].encode(),
        trail_data.encode(),
        hashlib.sha256
    ).hexdigest()
    
    with open(f'audit_trail_{int(self.scan_timestamp.timestamp())}.json', 'w') as f:
        json.dump({
            'findings': trail_data,
            'signature': signature,
            'timestamp': self.scan_timestamp.isoformat()
        }, f)
```

### 7. Testing Your Configuration

#### Dry Run Testing
```python
# Add dry run mode to constructor (line 35)
def __init__(self, config_path: str, baselines_path: str, dry_run: bool = False):
    self.dry_run = dry_run
    
# Test individual components
python -c "
from config_drift_detection import ConfigDriftDetector
detector = ConfigDriftDetector('config/systems_config.json', 'baselines/approved_configs.yaml', dry_run=True)
print('AWS SGs:', len(detector.scan_aws_security_groups()))
print('Linux:', len(detector.scan_linux_server_configs()))
"
```

#### Baseline Validation
```bash
# Validate baseline file syntax
python -c "import yaml; yaml.safe_load(open('baselines/approved_configs.yaml'))"

# Test configuration connectivity
python test_connectivity.py --config config/systems_config.json
```

#### Performance Testing
```python
# Add timing measurements
import time

def run_full_drift_scan(self):
    start_time = time.time()
    print("🚀 Starting SOC 2 Configuration Drift Detection...")
    
    # ... existing scan code ...
    
    end_time = time.time()
    print(f"⏱️  Scan completed in {end_time - start_time:.2f} seconds")
```

### 8. Deployment Strategies

#### Scheduled Execution
```bash
# Daily drift detection (crontab)
0 6 * * * cd /opt/soc2-toolkit && python config_drift_detection.py

# Hourly for critical systems
0 * * * * cd /opt/soc2-toolkit && python config_drift_detection.py --critical-only
```

#### CI/CD Integration
```yaml
# GitHub Actions example
name: Configuration Drift Detection
on:
  schedule:
    - cron: '0 6 * * *'  # Daily at 6 AM
  workflow_dispatch:     # Manual trigger

jobs:
  drift-detection:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'
          
      - name: Install dependencies
        run: pip install -r requirements.txt
        
      - name: Run Configuration Drift Detection
        run: python config_drift_detection.py
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          
      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: drift-report
          path: config_drift_report_*.md
```

#### Integration with SIEM
```python
# Add SIEM integration (after line 280)
def send_to_siem(self, findings):
    """Send high-severity findings to SIEM"""
    critical_findings = [f for f in findings if f.severity in ['CRITICAL', 'HIGH']]
    
    for finding in critical_findings:
        siem_event = {
            'timestamp': finding.detected_at.isoformat(),
            'event_type': 'configuration_drift',
            'severity': finding.severity,
            'source_system': finding.system_id,
            'description': f"Configuration drift detected: {finding.config_name}",
            'soc2_controls': finding.soc2_controls_affected
        }
        
        # Send to Splunk, ELK, or other SIEM
        self._send_to_splunk(siem_event)
```

### 9. Troubleshooting Common Issues

#### Issue: "Permission denied" on Linux servers
**Solution**: Update SSH key permissions and sudoers configuration
```bash
# Fix SSH key permissions
chmod 600 /path/to/ssh/key

# Add to sudoers for configuration reads
soc2-monitor ALL=(ALL) NOPASSWD: /bin/cat /etc/ssh/sshd_config, /usr/sbin/iptables
```

#### Issue: "Timeout" connecting to network devices
**Solution**: Update connection parameters and device access
```python
# Line 195 - Increase timeout for slow devices
ssh.connect(
    hostname=device['ip'],
    username=device['username'], 
    password=device['password'],
    timeout=60,  # Increase from 30 to 60 seconds
    banner_timeout=30
)
```

#### Issue: "Hash mismatch" on identical configurations
**Solution**: Ensure consistent data normalization
```python
# Add whitespace normalization
def _normalize_config_content(self, content):
    """Normalize configuration content for consistent comparison"""
    # Remove extra whitespace and sort lines
    lines = [line.strip() for line in content.split('\n') if line.strip()]
    return '\n'.join(sorted(lines))
```

### 10. Advanced Features

#### Baseline Auto-Update
```python
# Add baseline learning mode
def learn_baseline_updates(self, findings):
    """Automatically update baselines for approved changes"""
    for finding in findings:
        if finding.drift_type == 'APPROVED_CHANGE':
            self._update_baseline(finding.system_id, finding.current_value)
```

#### Integration with Change Management
```python
# Check against approved changes
def validate_against_change_requests(self, finding):
    """Check if drift corresponds to approved change request"""
    # Integration with ServiceNow, Jira, etc.
    change_requests = self._get_approved_changes(
        system=finding.system_id,
        timeframe=datetime.timedelta(days=7)
    )
    return any(cr.covers_change(finding) for cr in change_requests)
```

## Running the Script

### Initial Setup
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Create configuration files
cp config/systems_config.json.template config/systems_config.json
cp baselines/approved_configs.yaml.template baselines/approved_configs.yaml

# 3. Edit configurations for your environment
vi config/systems_config.json
vi baselines/approved_configs.yaml

# 4. Test connectivity
python test_connectivity.py

# 5. Create initial baselines
python create_baselines.py --capture-current

# 6. Run first scan
python config_drift_detection.py
```

### Production Deployment
```bash
# Deploy to monitoring server
sudo cp config_drift_detection.py /opt/soc2-toolkit/
sudo cp -r config/ /opt/soc2-toolkit/
sudo cp -r baselines/ /opt/soc2-toolkit/

# Set up service user
sudo useradd -r -s /bin/bash soc2-monitor
sudo chown -R soc2-monitor:soc2-monitor /opt/soc2-toolkit/

# Schedule regular execution
sudo crontab -u soc2-monitor -e
# Add: 0 6 * * * cd /opt/soc2-toolkit && python config_drift_detection.py
```

This comprehensive setup guide ensures the configuration drift detection script can be deployed successfully in diverse enterprise environments while maintaining security and compliance requirements.
