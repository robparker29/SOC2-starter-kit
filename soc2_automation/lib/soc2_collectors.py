#!/usr/bin/env python3
"""
SOC 2 System Data Collector
Centralized data collection for all SOC 2 automation tasks
"""

import datetime
import json
from typing import Dict, List, Optional, Any
import boto3
import paramiko
import ldap3
from github import Github

from .soc2_models import UserAccessRecord, SystemConfiguration, AccessReviewFinding
from .soc2_utils import SOC2Utils

class SystemDataCollector:
    """Centralized data collection for all SOC 2 automation"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize collector with system configuration"""
        self.config = config
        self.logger = SOC2Utils.setup_logging()
        
    # =============================================================================
    # USER ACCESS COLLECTION METHODS
    # =============================================================================
    
    def collect_aws_users(self, include_permissions: bool = True, include_activity: bool = True) -> List[UserAccessRecord]:
        """
        Collect AWS IAM user information
        
        Args:
            include_permissions: Whether to collect detailed permission information
            include_activity: Whether to collect last login/activity information
            
        Returns:
            List of UserAccessRecord objects for AWS users
        """
        self.logger.info("Collecting AWS IAM users...")
        
        try:
            iam = SOC2Utils.initialize_aws_client('iam', self.config)
            users = []
            
            # Get all IAM users
            paginator = iam.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    user_record = self._process_aws_user(user, iam, include_permissions, include_activity)
                    users.append(user_record)
            
            self.logger.info(f"Collected {len(users)} AWS users")
            return users
            
        except Exception as e:
            self.logger.error(f"Failed to collect AWS users: {str(e)}")
            raise
    
    def _process_aws_user(self, user: Dict, iam_client, include_permissions: bool, include_activity: bool) -> UserAccessRecord:
        """Process individual AWS user data"""
        username = user['UserName']
        
        # Get basic user info
        last_login = None
        if include_activity:
            last_login = self._get_aws_user_last_activity(username, iam_client)
        
        # Get permissions
        permissions = []
        group_memberships = []
        if include_permissions:
            permissions, group_memberships = self._get_aws_user_permissions(username, iam_client)
        
        # Get MFA status
        mfa_enabled = self._get_aws_user_mfa_status(username, iam_client)
        
        # Get user tags for additional metadata
        tags = self._get_aws_user_tags(username, iam_client)
        
        return UserAccessRecord(
            username=username,
            email=tags.get('Email', ''),
            system='AWS IAM',
            user_id=user['UserId'],
            last_login=last_login,
            permissions=permissions,
            manager=tags.get('Manager', 'Unknown'),
            department=tags.get('Department', 'Unknown'),
            status='Active',
            created_date=user.get('CreateDate'),
            mfa_enabled=mfa_enabled,
            group_memberships=group_memberships
        )
    
    def _get_aws_user_last_activity(self, username: str, iam_client) -> Optional[datetime.datetime]:
        """Get AWS user's last activity"""
        try:
            # Get access keys and check last used
            access_keys = iam_client.list_access_keys(UserName=username)
            latest_activity = None
            
            for key in access_keys['AccessKeyMetadata']:
                try:
                    last_used = iam_client.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                    if 'AccessKeyLastUsed' in last_used and 'LastUsedDate' in last_used['AccessKeyLastUsed']:
                        activity_date = last_used['AccessKeyLastUsed']['LastUsedDate']
                        if latest_activity is None or activity_date > latest_activity:
                            latest_activity = activity_date
                except:
                    continue
            
            return latest_activity
        except:
            return None
    
    def _get_aws_user_permissions(self, username: str, iam_client) -> tuple:
        """Get AWS user's permissions and group memberships"""
        permissions = []
        group_memberships = []
        
        try:
            # Get attached policies
            attached_policies = iam_client.list_attached_user_policies(UserName=username)
            for policy in attached_policies['AttachedPolicies']:
                permissions.append(f"Policy: {policy['PolicyName']}")
            
            # Get inline policies
            inline_policies = iam_client.list_user_policies(UserName=username)
            for policy_name in inline_policies['PolicyNames']:
                permissions.append(f"Inline: {policy_name}")
            
            # Get group memberships
            groups = iam_client.get_groups_for_user(UserName=username)
            for group in groups['Groups']:
                group_memberships.append(group['GroupName'])
                permissions.append(f"Group: {group['GroupName']}")
                
        except Exception as e:
            self.logger.warning(f"Could not get permissions for user {username}: {str(e)}")
        
        return permissions, group_memberships
    
    def _get_aws_user_mfa_status(self, username: str, iam_client) -> bool:
        """Check if AWS user has MFA enabled"""
        try:
            mfa_devices = iam_client.list_mfa_devices(UserName=username)
            return len(mfa_devices['MFADevices']) > 0
        except:
            return False
    
    def _get_aws_user_tags(self, username: str, iam_client) -> Dict[str, str]:
        """Get AWS user tags"""
        try:
            tags_response = iam_client.list_user_tags(UserName=username)
            return {tag['Key']: tag['Value'] for tag in tags_response['Tags']}
        except:
            return {}
    
    def collect_ad_users(self, include_groups: bool = True, include_last_login: bool = True) -> List[UserAccessRecord]:
        """
        Collect Active Directory user information
        
        Args:
            include_groups: Whether to collect group membership information
            include_last_login: Whether to collect last login information
            
        Returns:
            List of UserAccessRecord objects for AD users
        """
        self.logger.info("Collecting Active Directory users...")
        
        try:
            # Connect to Active Directory
            server = ldap3.Server(self.config['active_directory']['server'])
            conn = ldap3.Connection(
                server,
                user=self.config['active_directory']['user'],
                password=self.config['active_directory']['password']
            )
            
            if not conn.bind():
                raise ConnectionError(f"Failed to bind to AD: {conn.last_error}")
            
            # Search for users
            search_base = self.config['active_directory']['search_base']
            conn.search(
                search_base,
                '(&(objectClass=person)(!(objectClass=computer)))',
                attributes=['sAMAccountName', 'displayName', 'mail', 'department',
                           'title', 'manager', 'memberOf', 'lastLogon', 'userAccountControl',
                           'whenCreated', 'pwdLastSet']
            )
            
            users = []
            for entry in conn.entries:
                user_record = self._process_ad_user(entry, include_groups, include_last_login)
                users.append(user_record)
            
            conn.unbind()
            self.logger.info(f"Collected {len(users)} AD users")
            return users
            
        except Exception as e:
            self.logger.error(f"Failed to collect AD users: {str(e)}")
            raise
    
    def _process_ad_user(self, entry, include_groups: bool, include_last_login: bool) -> UserAccessRecord:
        """Process individual AD user entry"""
        username = str(entry.sAMAccountName) if hasattr(entry, 'sAMAccountName') else 'Unknown'
        
        # Parse account status
        account_disabled = False
        if hasattr(entry, 'userAccountControl'):
            account_disabled = bool(entry.userAccountControl.value & 2)
        
        # Parse last logon
        last_login = None
        if include_last_login and hasattr(entry, 'lastLogon') and entry.lastLogon.value:
            last_login = SOC2Utils.parse_windows_timestamp(entry.lastLogon.value)
        
        # Parse group memberships
        group_memberships = []
        permissions = []
        if include_groups and hasattr(entry, 'memberOf'):
            for dn in entry.memberOf.values:
                group_name = SOC2Utils.extract_cn_from_dn(dn)
                group_memberships.append(group_name)
                permissions.append(f"Group: {group_name}")
        
        return UserAccessRecord(
            username=username,
            email=str(entry.mail) if hasattr(entry, 'mail') else '',
            system='Active Directory',
            user_id=username,  # AD uses username as ID
            last_login=last_login,
            permissions=permissions,
            manager=SOC2Utils.extract_cn_from_dn(str(entry.manager)) if hasattr(entry, 'manager') else 'Unknown',
            department=str(entry.department) if hasattr(entry, 'department') else 'Unknown',
            status='Disabled' if account_disabled else 'Active',
            created_date=entry.whenCreated.value if hasattr(entry, 'whenCreated') else None,
            group_memberships=group_memberships
        )
    
    def collect_github_users(self, include_repos: bool = True) -> List[UserAccessRecord]:
        """
        Collect GitHub organization user information
        
        Args:
            include_repos: Whether to collect repository access information
            
        Returns:
            List of UserAccessRecord objects for GitHub users
        """
        self.logger.info("Collecting GitHub organization users...")
        
        try:
            g = Github(self.config['github']['token'])
            org = g.get_organization(self.config['github']['org_name'])
            
            users = []
            for member in org.get_members():
                user_record = self._process_github_user(member, org, include_repos)
                users.append(user_record)
            
            self.logger.info(f"Collected {len(users)} GitHub users")
            return users
            
        except Exception as e:
            self.logger.error(f"Failed to collect GitHub users: {str(e)}")
            raise
    
    def _process_github_user(self, member, org, include_repos: bool) -> UserAccessRecord:
        """Process individual GitHub user"""
        permissions = []
        
        # Get organization role
        try:
            membership = org.get_membership(member)
            permissions.append(f"Org Role: {membership.role}")
        except:
            permissions.append("Org Role: Member")
        
        # Get repository access (limited to avoid rate limits)
        if include_repos:
            try:
                repos = list(member.get_repos())[:5]  # Limit to first 5 repos
                for repo in repos:
                    permissions.append(f"Repo: {repo.name}")
            except:
                pass
        
        return UserAccessRecord(
            username=member.login,
            email=member.email or '',
            system='GitHub',
            user_id=str(member.id),
            last_login=None,  # GitHub API doesn't provide last login
            permissions=permissions,
            manager='Unknown',
            department='Engineering',  # Default assumption
            status='Active',
            created_date=member.created_at,
            group_memberships=[]
        )
    
    # =============================================================================
    # SYSTEM CONFIGURATION COLLECTION METHODS
    # =============================================================================
    
    def collect_aws_security_groups(self, detailed_analysis: bool = False) -> List[SystemConfiguration]:
        """
        Collect AWS Security Group configurations
        
        Args:
            detailed_analysis: Whether to include detailed rule analysis
            
        Returns:
            List of SystemConfiguration objects for security groups
        """
        self.logger.info("Collecting AWS Security Groups...")
        
        try:
            ec2 = SOC2Utils.initialize_aws_client('ec2', self.config)
            response = ec2.describe_security_groups()
            
            configurations = []
            for sg in response['SecurityGroups']:
                config = self._process_aws_security_group(sg, detailed_analysis)
                configurations.append(config)
            
            self.logger.info(f"Collected {len(configurations)} security groups")
            return configurations
            
        except Exception as e:
            self.logger.error(f"Failed to collect AWS security groups: {str(e)}")
            raise
    
    def _process_aws_security_group(self, sg: Dict, detailed_analysis: bool) -> SystemConfiguration:
        """Process individual security group"""
        config_data = {
            'group_name': sg['GroupName'],
            'description': sg['Description'],
            'vpc_id': sg.get('VpcId', 'EC2-Classic'),
            'inbound_rules_count': len(sg['IpPermissions']),
            'outbound_rules_count': len(sg['IpPermissionsEgress']),
            'tags': {tag['Key']: tag['Value'] for tag in sg.get('Tags', [])}
        }
        
        if detailed_analysis:
            config_data.update({
                'inbound_rules': self._normalize_sg_rules(sg['IpPermissions']),
                'outbound_rules': self._normalize_sg_rules(sg['IpPermissionsEgress']),
                'open_to_internet': any('0.0.0.0/0' in str(rule) for rule in sg['IpPermissions']),
                'ssh_access': any('22' in str(rule) for rule in sg['IpPermissions']),
                'rdp_access': any('3389' in str(rule) for rule in sg['IpPermissions'])
            })
        
        config_hash = SOC2Utils.calculate_file_hash(json.dumps(config_data, sort_keys=True).encode())
        
        return SystemConfiguration(
            system_id=sg['GroupId'],
            system_type='aws_security_group',
            config_name=f"SecurityGroup-{sg['GroupName']}",
            config_data=config_data,
            collection_date=datetime.datetime.now(),
            config_hash=config_hash
        )
    
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
    
    def collect_linux_configs(self, servers: List[Dict] = None, config_types: List[str] = None) -> List[SystemConfiguration]:
        """
        Collect Linux server configurations
        
        Args:
            servers: List of server configurations (if None, uses config file)
            config_types: Types of configs to collect ['ssh', 'firewall', 'sudo', 'logging']
            
        Returns:
            List of SystemConfiguration objects for Linux servers
        """
        if servers is None:
            servers = self.config.get('linux_servers', [])
        
        if config_types is None:
            config_types = ['ssh', 'firewall', 'sudo', 'logging']
        
        self.logger.info(f"Collecting Linux configurations for {len(servers)} servers...")
        
        configurations = []
        for server_config in servers:
            try:
                server_configs = self._collect_server_configs(server_config, config_types)
                configurations.extend(server_configs)
            except Exception as e:
                self.logger.error(f"Failed to collect configs from {server_config['hostname']}: {str(e)}")
        
        self.logger.info(f"Collected {len(configurations)} Linux configurations")
        return configurations
    
    def _collect_server_configs(self, server_config: Dict, config_types: List[str]) -> List[SystemConfiguration]:
        """Collect configurations from a single Linux server"""
        configs = []
        
        # SSH connection
        ssh = SOC2Utils.create_ssh_connection(server_config)
        
        try:
            # Define configuration collection commands
            config_commands = {
                'ssh': {
                    'command': 'sudo cat /etc/ssh/sshd_config | grep -E "(PermitRootLogin|PasswordAuthentication|Port|MaxAuthTries)"',
                    'name': 'SSH Configuration'
                },
                'firewall': {
                    'command': 'sudo iptables -L -n || sudo ufw status verbose',
                    'name': 'Firewall Configuration'
                },
                'sudo': {
                    'command': 'sudo cat /etc/sudoers | grep -v "^#" | grep -v "^$"',
                    'name': 'Sudo Configuration'
                },
                'logging': {
                    'command': 'sudo cat /etc/rsyslog.conf | grep -v "^#" | grep -v "^$"',
                    'name': 'Logging Configuration'
                }
            }
            
            for config_type in config_types:
                if config_type in config_commands:
                    cmd_info = config_commands[config_type]
                    result = SOC2Utils.safe_execute_ssh_command(ssh, cmd_info['command'])
                    
                    if result['success']:
                        config_data = {
                            'configuration_output': result['output'],
                            'collection_command': cmd_info['command'],
                            'server_hostname': server_config['hostname'],
                            'config_type': config_type
                        }
                        
                        config_hash = hashlib.sha256(result['output'].encode()).hexdigest()
                        
                        config = SystemConfiguration(
                            system_id=f"{server_config['hostname']}_{config_type}",
                            system_type='linux_config',
                            config_name=f"{server_config['hostname']} - {cmd_info['name']}",
                            config_data=config_data,
                            collection_date=datetime.datetime.now(),
                            config_hash=config_hash
                        )
                        configs.append(config)
                    else:
                        self.logger.warning(f"Failed to collect {config_type} from {server_config['hostname']}: {result['error']}")
        
        finally:
            ssh.close()
        
        return configs
    
    def collect_network_configs(self, devices: List[Dict] = None, device_types: List[str] = None) -> List[SystemConfiguration]:
        """
        Collect network device configurations
        
        Args:
            devices: List of network device configurations
            device_types: Types of devices to collect from
            
        Returns:
            List of SystemConfiguration objects for network devices
        """
        if devices is None:
            devices = self.config.get('network_devices', [])
        
        if device_types is None:
            device_types = ['cisco', 'palo_alto', 'fortinet']
        
        self.logger.info(f"Collecting network configurations for {len(devices)} devices...")
        
        configurations = []
        for device_config in devices:
            if device_config.get('type') in device_types:
                try:
                    config = self._collect_network_device_config(device_config)
                    if config:
                        configurations.append(config)
                except Exception as e:
                    self.logger.error(f"Failed to collect config from {device_config['ip']}: {str(e)}")
        
        self.logger.info(f"Collected {len(configurations)} network configurations")
        return configurations
    
    def _collect_network_device_config(self, device_config: Dict) -> Optional[SystemConfiguration]:
        """Collect configuration from a single network device"""
        ssh = None
        try:
            # Connect to device
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=device_config['ip'],
                username=device_config['username'],
                password=device_config['password'],
                timeout=30
            )
            
            # Determine config command based on device type
            command_map = {
                'cisco': 'show running-config',
                'palo_alto': 'show config running',
                'fortinet': 'show full-configuration'
            }
            
            command = command_map.get(device_config['type'], device_config.get('config_command', 'show config'))
            
            # Execute command
            stdin, stdout, stderr = ssh.exec_command(command)
            config_output = stdout.read().decode().strip()
            
            if config_output:
                config_data = {
                    'device_type': device_config['type'],
                    'device_ip': device_config['ip'],
                    'configuration_output': config_output,
                    'collection_command': command
                }
                
                config_hash = hashlib.sha256(config_output.encode()).hexdigest()
                
                return SystemConfiguration(
                    system_id=f"{device_config['ip']}_{device_config['type']}",
                    system_type='network_device',
                    config_name=f"{device_config['type'].title()} - {device_config['ip']}",
                    config_data=config_data,
                    collection_date=datetime.datetime.now(),
                    config_hash=config_hash
                )
        
        finally:
            if ssh:
                ssh.close()
        
        return None
    
    # =============================================================================
    # MONITORING & LOGGING COLLECTION METHODS
    # =============================================================================
    
    def collect_cloudtrail_events(self, event_types: List[str], time_range: int = 7) -> List[Dict]:
        """
        Collect AWS CloudTrail events
        
        Args:
            event_types: List of event types to collect
            time_range: Number of days to look back
            
        Returns:
            List of CloudTrail events
        """
        self.logger.info(f"Collecting CloudTrail events for {time_range} days...")
        
        try:
            cloudtrail = SOC2Utils.initialize_aws_client('cloudtrail', self.config)
            
            end_time = datetime.datetime.now()
            start_time = end_time - datetime.timedelta(days=time_range)
            
            all_events = []
            for event_type in event_types:
                try:
                    response = cloudtrail.lookup_events(
                        LookupAttributes=[{
                            'AttributeKey': 'EventName',
                            'AttributeValue': event_type
                        }],
                        StartTime=start_time,
                        EndTime=end_time
                    )
                    
                    for event in response.get('Events', []):
                        event_data = {
                            'event_time': event['EventTime'].isoformat(),
                            'event_name': event['EventName'],
                            'username': event.get('Username', 'Unknown'),
                            'source_ip': event.get('SourceIPAddress', 'Unknown'),
                            'user_agent': event.get('UserAgent', 'Unknown'),
                            'aws_region': event.get('AwsRegion', 'Unknown'),
                            'event_source': event.get('EventSource', 'Unknown'),
                            'error_code': event.get('ErrorCode', ''),
                            'error_message': event.get('ErrorMessage', '')
                        }
                        all_events.append(event_data)
                        
                except Exception as e:
                    self.logger.warning(f"Could not collect {event_type} events: {str(e)}")
            
            self.logger.info(f"Collected {len(all_events)} CloudTrail events")
            return all_events
            
        except Exception as e:
            self.logger.error(f"Failed to collect CloudTrail events: {str(e)}")
            raise
    
    def collect_security_logs(self, sources: List[str], time_range: int = 7) -> List[Dict]:
        """
        Collect security logs from various sources
        
        Args:
            sources: List of log sources to collect from
            time_range: Number of days to look back
            
        Returns:
            List of security log events
        """
        self.logger.info(f"Collecting security logs from {len(sources)} sources...")
        
        all_logs = []
        
        for source in sources:
            if source == 'cloudtrail':
                # Collect security-relevant CloudTrail events
                security_events = [
                    'ConsoleLogin', 'AssumeRole', 'CreateUser', 'DeleteUser',
                    'CreateAccessKey', 'DeleteAccessKey', 'PutBucketPolicy'
                ]
                events = self.collect_cloudtrail_events(security_events, time_range)
                all_logs.extend(events)
            
            # Add other log source implementations here
            # elif source == 'syslog':
            #     logs = self._collect_syslog_events(time_range)
            #     all_logs.extend(logs)
        
        return all_logs
    
    # =============================================================================
    # INACTIVE USERS ANALYSIS METHODS
    # =============================================================================
    
    def analyze_inactive_users(self, console_threshold: int = 90, access_key_threshold: int = 180) -> List[AccessReviewFinding]:
        """
        Analyze AWS users for inactivity patterns
        
        Args:
            console_threshold: Days of console inactivity to flag (default: 90)
            access_key_threshold: Days of access key inactivity to flag (default: 180)
            
        Returns:
            List of AccessReviewFinding objects for inactive users
        """
        self.logger.info("Analyzing AWS users for inactivity patterns...")
        
        try:
            # Collect all AWS users with activity information
            users = self.collect_aws_users(include_permissions=True, include_activity=True)
            
            findings = []
            current_date = datetime.datetime.now(datetime.timezone.utc)
            
            iam = SOC2Utils.initialize_aws_client('iam', self.config)
            
            for user in users:
                user_findings = self._analyze_user_inactivity(
                    user, iam, current_date, console_threshold, access_key_threshold
                )
                findings.extend(user_findings)
            
            self.logger.info(f"Found {len(findings)} inactive user findings")
            return findings
            
        except Exception as e:
            self.logger.error(f"Failed to analyze inactive users: {str(e)}")
            raise
    
    def _analyze_user_inactivity(self, user: UserAccessRecord, iam_client, 
                                current_date: datetime.datetime, console_threshold: int, 
                                access_key_threshold: int) -> List[AccessReviewFinding]:
        """Analyze individual user for inactivity patterns"""
        findings = []
        
        # Get detailed activity information
        console_last_login = self._get_user_console_activity(user.username, iam_client)
        access_key_last_activity = self._get_user_access_key_activity(user.username, iam_client)
        
        # Check console inactivity
        if console_last_login:
            if console_last_login.tzinfo is None:
                console_last_login = console_last_login.replace(tzinfo=datetime.timezone.utc)
            days_inactive = (current_date - console_last_login).days
            
            if days_inactive >= console_threshold:
                findings.append(self._create_inactivity_finding(
                    user, 'CONSOLE_INACTIVE', 'HIGH',
                    f'Console login inactive for {days_inactive} days',
                    'CC6.1 - Logical Access Controls',
                    'Review user necessity and disable console access if no longer needed'
                ))
        else:
            # No console activity - check if account is old enough to be concerning
            if user.created_date:
                if user.created_date.tzinfo is None:
                    created_date = user.created_date.replace(tzinfo=datetime.timezone.utc)
                else:
                    created_date = user.created_date
                    
                account_age = (current_date - created_date).days
                if account_age >= console_threshold:
                    findings.append(self._create_inactivity_finding(
                        user, 'CONSOLE_NEVER_USED', 'HIGH',
                        f'Console access never used in {account_age} days since creation',
                        'CC6.1 - Logical Access Controls',
                        'Consider removing console permissions if not needed'
                    ))
        
        # Check access key inactivity
        if access_key_last_activity:
            if access_key_last_activity.tzinfo is None:
                access_key_last_activity = access_key_last_activity.replace(tzinfo=datetime.timezone.utc)
            days_inactive = (current_date - access_key_last_activity).days
            
            if days_inactive >= access_key_threshold:
                findings.append(self._create_inactivity_finding(
                    user, 'ACCESS_KEY_INACTIVE', 'MEDIUM',
                    f'Access keys inactive for {days_inactive} days',
                    'CC6.2 - Least Privilege',
                    'Review programmatic access necessity and rotate or delete unused keys'
                ))
        
        return findings
    
    def _get_user_console_activity(self, username: str, iam_client) -> Optional[datetime.datetime]:
        """Get user's last console login activity"""
        try:
            user_info = iam_client.get_user(UserName=username)
            return user_info['User'].get('PasswordLastUsed')
        except Exception:
            return None
    
    def _get_user_access_key_activity(self, username: str, iam_client) -> Optional[datetime.datetime]:
        """Get user's last access key activity"""
        try:
            access_keys = iam_client.list_access_keys(UserName=username)
            latest_activity = None
            
            for key in access_keys['AccessKeyMetadata']:
                if key['Status'] == 'Active':
                    try:
                        last_used = iam_client.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                        if 'AccessKeyLastUsed' in last_used and 'LastUsedDate' in last_used['AccessKeyLastUsed']:
                            activity_date = last_used['AccessKeyLastUsed']['LastUsedDate']
                            if latest_activity is None or activity_date > latest_activity:
                                latest_activity = activity_date
                    except Exception:
                        continue
            
            return latest_activity
        except Exception:
            return None
    
    def _create_inactivity_finding(self, user: UserAccessRecord, finding_type: str, 
                                  severity: str, details: str, control: str, 
                                  remediation: str) -> AccessReviewFinding:
        """Create standardized inactivity finding"""
        finding_id = f"IAU-{user.username}-{finding_type}-{datetime.datetime.now().strftime('%Y%m%d')}"
        
        return AccessReviewFinding(
            finding_id=finding_id,
            finding_type=finding_type,
            severity=severity,
            user_record=user,
            details=details,
            soc2_control=control,
            remediation_action=remediation,
            created_date=datetime.datetime.now(),
            status='OPEN'
        )
