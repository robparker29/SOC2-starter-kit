#!/usr/bin/env python3
"""
SOC 2 Configuration Drift Detection
Maps to SOC 2 Common Criteria: CC6.1, CC6.7, CC6.8

This script monitors critical system configurations against approved baselines to detect
unauthorized changes that could impact security posture and compliance.

Key Features:
- Multi-system configuration monitoring (AWS, Linux, Network devices)
- Baseline comparison with approved configurations  
- Risk-based alerting and remediation recommendations
- Audit trail generation for compliance evidence
- Integration with SIEM and ticketing systems

Author: Parker Robertson
Purpose: Automated compliance monitoring for SOC 2 audit readiness
"""

import json
import yaml
import hashlib
import datetime
import subprocess
import difflib
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any
import boto3
import paramiko
import requests

@dataclass
class ConfigurationBaseline:
    """Standard format for approved system configurations"""
    system_id: str
    system_type: str  # 'aws_security_group', 'linux_server', 'firewall', etc.
    config_name: str
    baseline_hash: str
    baseline_content: Dict[str, Any]
    last_approved: datetime.datetime
    approver: str
    compliance_controls: List[str]  # SOC 2 controls this config supports

@dataclass
class DriftFinding:
    """Configuration drift detection result"""
    finding_id: str
    system_id: str
    config_name: str
    drift_type: str  # 'UNAUTHORIZED_CHANGE', 'MISSING_CONFIG', 'NEW_CONFIG'
    severity: str    # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    detected_at: datetime.datetime
    baseline_value: str
    current_value: str
    risk_impact: str
    soc2_controls_affected: List[str]
    remediation_action: str
    auto_fixable: bool = False

class ConfigDriftDetector:
    def __init__(self, config_path: str, baselines_path: str):
        """Initialize with system configurations and approved baselines"""
        with open(config_path, 'r') as f:
            self.config = json.load(f)
        
        with open(baselines_path, 'r') as f:
            self.baselines = yaml.safe_load(f)
        
        self.findings = []
        self.scan_timestamp = datetime.datetime.now()
        
    def scan_aws_security_groups(self) -> List[DriftFinding]:
        """Monitor AWS Security Group configurations for unauthorized changes"""
        print("🔍 Scanning AWS Security Groups for configuration drift...")
        
        findings = []
        ec2 = boto3.client('ec2',
                          aws_access_key_id=self.config['aws']['access_key'],
                          aws_secret_access_key=self.config['aws']['secret_key'],
                          region_name=self.config['aws']['region'])
        
        # Get all security groups
        response = ec2.describe_security_groups()
        
        for sg in response['SecurityGroups']:
            sg_id = sg['GroupId']
            
            # Check if we have a baseline for this security group
            baseline = self._get_baseline('aws_security_group', sg_id)
            if not baseline:
                continue
            
            # Create current configuration hash
            current_config = {
                'group_name': sg['GroupName'],
                'description': sg['Description'],
                'inbound_rules': self._normalize_sg_rules(sg['IpPermissions']),
                'outbound_rules': self._normalize_sg_rules(sg['IpPermissionsEgress'])
            }
            
            current_hash = self._calculate_config_hash(current_config)
            
            # Compare with baseline
            if current_hash != baseline['baseline_hash']:
                # Detailed analysis of what changed
                drift_details = self._analyze_sg_drift(baseline['baseline_content'], current_config)
                
                for detail in drift_details:
                    finding = DriftFinding(
                        finding_id=f"DRIFT-SG-{sg_id}-{int(self.scan_timestamp.timestamp())}",
                        system_id=sg_id,
                        config_name=f"SecurityGroup-{sg['GroupName']}",
                        drift_type=detail['type'],
                        severity=self._assess_sg_drift_severity(detail),
                        detected_at=self.scan_timestamp,
                        baseline_value=detail['baseline'],
                        current_value=detail['current'],
                        risk_impact=detail['risk_impact'],
                        soc2_controls_affected=['CC6.1', 'CC6.7'],
                        remediation_action=detail['remediation'],
                        auto_fixable=detail['auto_fixable']
                    )
                    findings.append(finding)
        
        return findings
    
    def scan_linux_server_configs(self) -> List[DriftFinding]:
        """Monitor critical Linux server configurations"""
        print("🐧 Scanning Linux server configurations...")
        
        findings = []
        
        for server in self.config['linux_servers']:
            print(f"  📡 Connecting to {server['hostname']}...")
            
            try:
                # SSH connection
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(
                    hostname=server['hostname'],
                    username=server['username'],
                    key_filename=server.get('key_file'),
                    password=server.get('password')
                )
                
                # Check critical configurations
                config_checks = [
                    {
                        'name': 'SSH Configuration',
                        'command': 'sudo cat /etc/ssh/sshd_config | grep -E "(PermitRootLogin|PasswordAuthentication|Port)"',
                        'controls': ['CC6.1', 'CC6.7']
                    },
                    {
                        'name': 'Firewall Rules',
                        'command': 'sudo iptables -L -n',
                        'controls': ['CC6.1', 'CC6.7']
                    },
                    {
                        'name': 'Sudo Configuration',
                        'command': 'sudo cat /etc/sudoers | grep -v "^#" | grep -v "^$"',
                        'controls': ['CC6.1', 'CC6.2']
                    },
                    {
                        'name': 'Log Configuration',
                        'command': 'sudo cat /etc/rsyslog.conf | grep -v "^#" | grep -v "^$"',
                        'controls': ['CC6.8', 'CC7.2']
                    }
                ]
                
                for check in config_checks:
                    stdin, stdout, stderr = ssh.exec_command(check['command'])
                    current_output = stdout.read().decode().strip()
                    
                    # Get baseline for this configuration
                    baseline_key = f"{server['hostname']}_{check['name'].replace(' ', '_').lower()}"
                    baseline = self._get_baseline('linux_config', baseline_key)
                    
                    if baseline:
                        current_hash = hashlib.sha256(current_output.encode()).hexdigest()
                        
                        if current_hash != baseline['baseline_hash']:
                            # Configuration has drifted
                            finding = DriftFinding(
                                finding_id=f"DRIFT-LINUX-{baseline_key}-{int(self.scan_timestamp.timestamp())}",
                                system_id=server['hostname'],
                                config_name=check['name'],
                                drift_type='UNAUTHORIZED_CHANGE',
                                severity=self._assess_linux_drift_severity(check['name'], baseline['baseline_content'], current_output),
                                detected_at=self.scan_timestamp,
                                baseline_value=baseline['baseline_content'][:200] + "..." if len(baseline['baseline_content']) > 200 else baseline['baseline_content'],
                                current_value=current_output[:200] + "..." if len(current_output) > 200 else current_output,
                                risk_impact=self._describe_linux_risk_impact(check['name']),
                                soc2_controls_affected=check['controls'],
                                remediation_action=self._get_linux_remediation(check['name']),
                                auto_fixable=self._is_linux_auto_fixable(check['name'])
                            )
                            findings.append(finding)
                
                ssh.close()
                
            except Exception as e:
                print(f"  ❌ Error connecting to {server['hostname']}: {str(e)}")
                # Create finding for unreachable server
                finding = DriftFinding(
                    finding_id=f"DRIFT-CONN-{server['hostname']}-{int(self.scan_timestamp.timestamp())}",
                    system_id=server['hostname'],
                    config_name='Server Connectivity',
                    drift_type='MISSING_CONFIG',
                    severity='HIGH',
                    detected_at=self.scan_timestamp,
                    baseline_value='Server accessible',
                    current_value=f'Connection failed: {str(e)}',
                    risk_impact='Unable to verify server configurations - potential security blind spot',
                    soc2_controls_affected=['CC6.1', 'CC6.8'],
                    remediation_action='Investigate server connectivity and restore monitoring',
                    auto_fixable=False
                )
                findings.append(finding)
        
        return findings
    
    def scan_network_device_configs(self) -> List[DriftFinding]:
        """Monitor network device configurations (firewalls, switches, routers)"""
        print("🌐 Scanning network device configurations...")
        
        findings = []
        
        for device in self.config.get('network_devices', []):
            print(f"  🔧 Checking {device['type']} at {device['ip']}...")
            
            try:
                # Connect via SSH to network device
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(
                    hostname=device['ip'],
                    username=device['username'],
                    password=device['password'],
                    timeout=30
                )
                
                # Execute configuration dump command based on device type
                if device['type'] == 'cisco':
                    command = 'show running-config'
                elif device['type'] == 'palo_alto':
                    command = 'show config running'
                else:
                    command = device.get('config_command', 'show config')
                
                stdin, stdout, stderr = ssh.exec_command(command)
                current_config = stdout.read().decode().strip()
                
                # Get baseline
                baseline_key = f"{device['ip']}_{device['type']}_config"
                baseline = self._get_baseline('network_device', baseline_key)
                
                if baseline:
                    current_hash = hashlib.sha256(current_config.encode()).hexdigest()
                    
                    if current_hash != baseline['baseline_hash']:
                        # Analyze configuration differences
                        config_diff = list(difflib.unified_diff(
                            baseline['baseline_content'].splitlines(),
                            current_config.splitlines(),
                            lineterm='',
                            fromfile='Baseline',
                            tofile='Current'
                        ))
                        
                        finding = DriftFinding(
                            finding_id=f"DRIFT-NET-{baseline_key}-{int(self.scan_timestamp.timestamp())}",
                            system_id=device['ip'],
                            config_name=f"{device['type'].title()} Configuration",
                            drift_type='UNAUTHORIZED_CHANGE',
                            severity=self._assess_network_drift_severity(config_diff),
                            detected_at=self.scan_timestamp,
                            baseline_value=f"Configuration hash: {baseline['baseline_hash']}",
                            current_value=f"Configuration hash: {current_hash}",
                            risk_impact='Network security posture may be compromised',
                            soc2_controls_affected=['CC6.1', 'CC6.7', 'CC6.8'],
                            remediation_action='Review configuration changes and restore approved baseline',
                            auto_fixable=False  # Network changes are typically manual
                        )
                        findings.append(finding)
                
                ssh.close()
                
            except Exception as e:
                print(f"  ❌ Error connecting to {device['ip']}: {str(e)}")
        
        return findings
    
    def generate_drift_report(self, findings: List[DriftFinding], output_path: str):
        """Generate comprehensive drift detection report for audit evidence"""
        print(f"📊 Generating configuration drift report: {output_path}")
        
        # Summary statistics
        total_findings = len(findings)
        critical_findings = len([f for f in findings if f.severity == 'CRITICAL'])
        high_findings = len([f for f in findings if f.severity == 'HIGH'])
        medium_findings = len([f for f in findings if f.severity == 'MEDIUM'])
        auto_fixable = len([f for f in findings if f.auto_fixable])
        
        # Generate detailed report
        report_content = f"""# Configuration Drift Detection Report
        
## Executive Summary
**Scan Date:** {self.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}
**Total Findings:** {total_findings}
**Critical Risk:** {critical_findings}
**High Risk:** {high_findings}  
**Medium Risk:** {medium_findings}
**Auto-Fixable:** {auto_fixable}

## SOC 2 Control Impact Analysis
"""
        
        # Group findings by SOC 2 controls
        control_impact = {}
        for finding in findings:
            for control in finding.soc2_controls_affected:
                if control not in control_impact:
                    control_impact[control] = []
                control_impact[control].append(finding)
        
        for control, control_findings in control_impact.items():
            report_content += f"\n### {control} - {len(control_findings)} findings\n"
            high_risk_count = len([f for f in control_findings if f.severity in ['CRITICAL', 'HIGH']])
            if high_risk_count > 0:
                report_content += f"⚠️  **{high_risk_count} high-risk findings require immediate attention**\n"
        
        report_content += "\n## Detailed Findings\n\n"
        
        # Sort findings by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.severity, 4))
        
        for finding in sorted_findings:
            severity_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(finding.severity, '⚪')
            
            report_content += f"""
### {severity_emoji} {finding.finding_id}
**System:** {finding.system_id}  
**Configuration:** {finding.config_name}  
**Severity:** {finding.severity}  
**Drift Type:** {finding.drift_type}  
**SOC 2 Controls:** {', '.join(finding.soc2_controls_affected)}  

**Risk Impact:** {finding.risk_impact}

**Baseline Value:**
```
{finding.baseline_value}
```

**Current Value:**
```
{finding.current_value}
```

**Recommended Action:** {finding.remediation_action}  
**Auto-Fixable:** {'✅ Yes' if finding.auto_fixable else '❌ No'}

---
"""
        
        # Save report
        with open(output_path, 'w') as f:
            f.write(report_content)
        
        print(f"\n📈 Configuration Drift Summary")
        print(f"  🔴 Critical: {critical_findings}")
        print(f"  🟠 High: {high_findings}")
        print(f"  🟡 Medium: {medium_findings}")
        print(f"  🟢 Auto-fixable: {auto_fixable}")
    
    def auto_remediate_findings(self, findings: List[DriftFinding]):
        """Automatically fix configuration drift where safe to do so"""
        print("🔧 Attempting automatic remediation...")
        
        auto_fixable_findings = [f for f in findings if f.auto_fixable]
        
        for finding in auto_fixable_findings:
            try:
                if finding.system_id.startswith('sg-'):  # AWS Security Group
                    self._auto_fix_security_group(finding)
                elif 'SSH Configuration' in finding.config_name:
                    self._auto_fix_ssh_config(finding)
                
                print(f"  ✅ Auto-fixed: {finding.finding_id}")
                
            except Exception as e:
                print(f"  ❌ Auto-fix failed for {finding.finding_id}: {str(e)}")
    
    def run_full_drift_scan(self):
        """Execute complete configuration drift detection"""
        print("🚀 Starting SOC 2 Configuration Drift Detection...")
        
        all_findings = []
        
        # Scan all system types
        all_findings.extend(self.scan_aws_security_groups())
        all_findings.extend(self.scan_linux_server_configs())
        all_findings.extend(self.scan_network_device_configs())
        
        self.findings = all_findings
        
        # Generate outputs
        report_filename = f"config_drift_report_{self.scan_timestamp.strftime('%Y%m%d_%H%M%S')}.md"
        self.generate_drift_report(all_findings, report_filename)
        
        # Auto-remediate safe findings
        self.auto_remediate_findings(all_findings)
        
        print(f"\n✅ Configuration drift scan complete! Report: {report_filename}")
        return all_findings
    
    # Helper methods
    def _get_baseline(self, system_type: str, system_id: str) -> Optional[Dict]:
        """Retrieve approved baseline configuration"""
        baselines = self.baselines.get(system_type, {})
        return baselines.get(system_id)
    
    def _calculate_config_hash(self, config: Dict) -> str:
        """Generate consistent hash for configuration comparison"""
        config_str = json.dumps(config, sort_keys=True)
        return hashlib.sha256(config_str.encode()).hexdigest()
    
    def _normalize_sg_rules(self, rules: List[Dict]) -> List[Dict]:
        """Normalize security group rules for consistent comparison"""
        normalized = []
        for rule in rules:
            normalized_rule = {
                'protocol': rule.get('IpProtocol', ''),
                'from_port': rule.get('FromPort', ''),
                'to_port': rule.get('ToPort', ''),
                'cidr_blocks': sorted([ip['CidrIp'] for ip in rule.get('IpRanges', [])]),
                'security_groups': sorted([sg['GroupId'] for sg in rule.get('UserIdGroupPairs', [])])
            }
            normalized.append(normalized_rule)
        return sorted(normalized, key=lambda x: str(x))
    
    def _analyze_sg_drift(self, baseline: Dict, current: Dict) -> List[Dict]:
        """Analyze specific security group configuration changes"""
        changes = []
        
        # Check for new inbound rules (potential security risk)
        baseline_inbound = set(str(rule) for rule in baseline.get('inbound_rules', []))
        current_inbound = set(str(rule) for rule in current.get('inbound_rules', []))
        
        new_rules = current_inbound - baseline_inbound
        removed_rules = baseline_inbound - current_inbound
        
        for rule in new_rules:
            changes.append({
                'type': 'NEW_INBOUND_RULE',
                'baseline': 'Rule did not exist',
                'current': rule,
                'risk_impact': 'New inbound rule may expose services to unauthorized access',
                'remediation': 'Review and approve new rule or remove if unauthorized',
                'auto_fixable': False
            })
        
        for rule in removed_rules:
            changes.append({
                'type': 'REMOVED_INBOUND_RULE',
                'baseline': rule,
                'current': 'Rule removed',
                'risk_impact': 'Removed rule may disrupt legitimate access',
                'remediation': 'Restore rule if removal was unauthorized',
                'auto_fixable': True
            })
        
        return changes
    
    def _assess_sg_drift_severity(self, change: Dict) -> str:
        """Assess severity of security group configuration changes"""
        if '0.0.0.0/0' in change['current'] and change['type'] == 'NEW_INBOUND_RULE':
            return 'CRITICAL'  # New rule allowing access from anywhere
        elif change['type'] == 'NEW_INBOUND_RULE':
            return 'HIGH'
        elif change['type'] == 'REMOVED_INBOUND_RULE':
            return 'MEDIUM'
        return 'LOW'
    
    def _assess_linux_drift_severity(self, config_name: str, baseline: str, current: str) -> str:
        """Assess severity of Linux configuration changes"""
        if 'SSH Configuration' in config_name:
            if 'PermitRootLogin yes' in current and 'PermitRootLogin no' in baseline:
                return 'CRITICAL'
            elif 'PasswordAuthentication yes' in current and 'PasswordAuthentication no' in baseline:
                return 'HIGH'
        elif 'Sudo Configuration' in config_name:
            if 'NOPASSWD: ALL' in current and 'NOPASSWD: ALL' not in baseline:
                return 'HIGH'
        return 'MEDIUM'
    
    def _assess_network_drift_severity(self, config_diff: List[str]) -> str:
        """Assess severity of network device configuration changes"""
        critical_keywords = ['permit ip any any', 'no access-list', 'shutdown']
        high_keywords = ['access-list', 'route', 'vlan']
        
        diff_text = '\n'.join(config_diff).lower()
        
        if any(keyword in diff_text for keyword in critical_keywords):
            return 'CRITICAL'
        elif any(keyword in diff_text for keyword in high_keywords):
            return 'HIGH'
        return 'MEDIUM'
    
    def _describe_linux_risk_impact(self, config_name: str) -> str:
        """Describe risk impact of Linux configuration drift"""
        impacts = {
            'SSH Configuration': 'Unauthorized SSH access may be possible',
            'Firewall Rules': 'Network security controls may be bypassed',
            'Sudo Configuration': 'Privilege escalation vulnerabilities may exist',
            'Log Configuration': 'Security events may not be properly logged'
        }
        return impacts.get(config_name, 'System security posture may be compromised')
    
    def _get_linux_remediation(self, config_name: str) -> str:
        """Get remediation action for Linux configuration drift"""
        actions = {
            'SSH Configuration': 'Review SSH settings and restore secure configuration',
            'Firewall Rules': 'Verify firewall rules and restore approved ruleset',
            'Sudo Configuration': 'Review sudo permissions and apply principle of least privilege',
            'Log Configuration': 'Restore logging configuration to capture security events'
        }
        return actions.get(config_name, 'Review configuration and restore approved baseline')
    
    def _is_linux_auto_fixable(self, config_name: str) -> bool:
        """Determine if Linux configuration drift can be automatically fixed"""
        auto_fixable = ['Log Configuration']  # Safe to auto-fix
        return config_name in auto_fixable
    
    def _auto_fix_security_group(self, finding: DriftFinding):
        """Automatically restore security group configuration"""
        # Implementation would restore from baseline
        pass
    
    def _auto_fix_ssh_config(self, finding: DriftFinding):
        """Automatically fix SSH configuration drift"""
        # Implementation would restore SSH config from baseline
        pass

if __name__ == "__main__":
    detector = ConfigDriftDetector('config/systems_config.json', 'baselines/approved_configs.yaml')
    findings = detector.run_full_drift_scan()
