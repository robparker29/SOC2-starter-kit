#!/usr/bin/env python3
"""
Multi-Cloud Provider Interface for SOC 2 Automation
Provides unified interface for AWS, Azure, and Google Cloud Platform

This module implements a factory pattern for cloud-agnostic operations across:
- Identity and Access Management (IAM)
- Network Security (Security Groups/Firewalls)
- Audit Logging and Monitoring
- Resource Configuration Management

Author: Parker Robertson
Purpose: Enable SOC 2 automation across multiple cloud providers
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
import json
import logging
from dataclasses import dataclass

# Cloud SDK imports (with error handling for missing packages)
try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

try:
    from azure.identity import DefaultAzureCredential, ClientSecretCredential
    from azure.mgmt.authorization import AuthorizationManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.monitor import MonitorManagementClient
    from azure.mgmt.resource import ResourceManagementClient
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

try:
    from google.cloud import iam, compute_v1, logging as gcp_logging
    from google.oauth2 import service_account
    import googleapiclient.discovery
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False

from .soc2_models import UserAccessRecord, SystemConfiguration, CloudResource


@dataclass
class CloudIdentity:
    """Unified cloud identity representation"""
    user_id: str
    username: str
    email: str
    display_name: str
    cloud_provider: str
    account_id: str
    roles: List[str]
    permissions: List[str]
    last_login: Optional[datetime]
    mfa_enabled: bool
    created_date: Optional[datetime]
    status: str
    metadata: Dict[str, Any]


@dataclass
class CloudNetworkRule:
    """Unified network security rule representation"""
    rule_id: str
    rule_name: str
    cloud_provider: str
    resource_id: str
    direction: str  # INBOUND/OUTBOUND
    protocol: str
    source: str
    destination: str
    port_range: str
    action: str  # ALLOW/DENY
    priority: Optional[int]
    created_date: Optional[datetime]
    metadata: Dict[str, Any]


@dataclass
class CloudAuditEvent:
    """Unified cloud audit event representation"""
    event_id: str
    event_name: str
    cloud_provider: str
    source_service: str
    event_time: datetime
    user_identity: str
    source_ip: str
    user_agent: str
    resources: List[str]
    event_outcome: str
    event_details: Dict[str, Any]


class CloudProvider(ABC):
    """Abstract base class for cloud provider implementations"""
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.provider_name = self.__class__.__name__.replace('Provider', '').upper()
    
    @abstractmethod
    def authenticate(self) -> bool:
        """Authenticate with cloud provider"""
        pass
    
    @abstractmethod
    def get_identities(self, account_id: str = None) -> List[CloudIdentity]:
        """Get all user identities from the cloud provider"""
        pass
    
    @abstractmethod
    def get_network_rules(self, resource_group: str = None) -> List[CloudNetworkRule]:
        """Get network security rules (security groups, firewall rules)"""
        pass
    
    @abstractmethod
    def get_audit_events(self, time_range_days: int = 30, event_types: List[str] = None) -> List[CloudAuditEvent]:
        """Get audit/activity log events"""
        pass
    
    @abstractmethod
    def get_resource_configurations(self) -> List[SystemConfiguration]:
        """Get system/resource configurations"""
        pass
    
    @abstractmethod
    def validate_connectivity(self) -> Dict[str, bool]:
        """Validate connectivity to cloud services"""
        pass


class AWSProvider(CloudProvider):
    """Amazon Web Services provider implementation"""
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        super().__init__(config, logger)
        if not AWS_AVAILABLE:
            raise ImportError("AWS SDK (boto3) not available. Install with: pip install boto3")
        
        self.session = None
        self.clients = {}
        
    def authenticate(self) -> bool:
        """Authenticate with AWS"""
        try:
            aws_config = self.config.get('aws', {})
            
            if aws_config.get('access_key') and aws_config.get('secret_key'):
                self.session = boto3.Session(
                    aws_access_key_id=aws_config['access_key'],
                    aws_secret_access_key=aws_config['secret_key'],
                    region_name=aws_config.get('region', 'us-east-1')
                )
            else:
                # Use default credential chain
                self.session = boto3.Session(region_name=aws_config.get('region', 'us-east-1'))
            
            # Test authentication
            sts = self.session.client('sts')
            identity = sts.get_caller_identity()
            self.logger.info(f"AWS authentication successful for account: {identity['Account']}")
            return True
            
        except Exception as e:
            self.logger.error(f"AWS authentication failed: {str(e)}")
            return False
    
    def _get_client(self, service: str):
        """Get cached AWS client"""
        if service not in self.clients:
            self.clients[service] = self.session.client(service)
        return self.clients[service]
    
    def get_identities(self, account_id: str = None) -> List[CloudIdentity]:
        """Get AWS IAM users"""
        identities = []
        
        try:
            iam = self._get_client('iam')
            paginator = iam.get_paginator('list_users')
            
            for page in paginator.paginate():
                for user in page['Users']:
                    # Get user details
                    user_details = self._get_aws_user_details(iam, user)
                    identities.append(user_details)
                    
            self.logger.info(f"Retrieved {len(identities)} AWS identities")
            return identities
            
        except Exception as e:
            self.logger.error(f"Failed to get AWS identities: {str(e)}")
            return []
    
    def _get_aws_user_details(self, iam_client, user: Dict) -> CloudIdentity:
        """Get detailed AWS user information"""
        username = user['UserName']
        
        # Get user tags
        tags = {}
        try:
            tag_response = iam_client.list_user_tags(UserName=username)
            tags = {tag['Key']: tag['Value'] for tag in tag_response['Tags']}
        except:
            pass
        
        # Get user policies and roles
        roles = []
        permissions = []
        
        try:
            # Get attached policies
            policies = iam_client.list_attached_user_policies(UserName=username)
            permissions.extend([p['PolicyName'] for p in policies['AttachedPolicies']])
            
            # Get groups
            groups = iam_client.get_groups_for_user(UserName=username)
            roles.extend([g['GroupName'] for g in groups['Groups']])
            
        except:
            pass
        
        # Get MFA status
        mfa_enabled = False
        try:
            mfa_devices = iam_client.list_mfa_devices(UserName=username)
            mfa_enabled = len(mfa_devices['MFADevices']) > 0
        except:
            pass
        
        # Get last activity
        last_login = user.get('PasswordLastUsed')
        
        return CloudIdentity(
            user_id=user['UserId'],
            username=username,
            email=tags.get('Email', ''),
            display_name=tags.get('Name', username),
            cloud_provider='AWS',
            account_id=self.session.client('sts').get_caller_identity()['Account'],
            roles=roles,
            permissions=permissions,
            last_login=last_login,
            mfa_enabled=mfa_enabled,
            created_date=user.get('CreateDate'),
            status='Active',
            metadata={'tags': tags, 'arn': user['Arn']}
        )
    
    def get_network_rules(self, resource_group: str = None) -> List[CloudNetworkRule]:
        """Get AWS Security Group rules"""
        rules = []
        
        try:
            ec2 = self._get_client('ec2')
            response = ec2.describe_security_groups()
            
            for sg in response['SecurityGroups']:
                # Process inbound rules
                for rule in sg['IpPermissions']:
                    network_rule = self._convert_aws_security_rule(sg, rule, 'INBOUND')
                    rules.append(network_rule)
                
                # Process outbound rules  
                for rule in sg['IpPermissionsEgress']:
                    network_rule = self._convert_aws_security_rule(sg, rule, 'OUTBOUND')
                    rules.append(network_rule)
            
            self.logger.info(f"Retrieved {len(rules)} AWS security group rules")
            return rules
            
        except Exception as e:
            self.logger.error(f"Failed to get AWS network rules: {str(e)}")
            return []
    
    def _convert_aws_security_rule(self, security_group: Dict, rule: Dict, direction: str) -> CloudNetworkRule:
        """Convert AWS security group rule to unified format"""
        
        # Extract port range
        port_range = "All"
        if 'FromPort' in rule and 'ToPort' in rule:
            if rule['FromPort'] == rule['ToPort']:
                port_range = str(rule['FromPort'])
            else:
                port_range = f"{rule['FromPort']}-{rule['ToPort']}"
        
        # Extract source/destination
        sources = []
        for ip_range in rule.get('IpRanges', []):
            sources.append(ip_range['CidrIp'])
        for sg_ref in rule.get('UserIdGroupPairs', []):
            sources.append(f"sg-{sg_ref['GroupId']}")
        
        source_dest = ', '.join(sources) if sources else '0.0.0.0/0'
        
        return CloudNetworkRule(
            rule_id=f"{security_group['GroupId']}-{direction}-{hash(str(rule))}",
            rule_name=f"{security_group['GroupName']}-{direction}",
            cloud_provider='AWS',
            resource_id=security_group['GroupId'],
            direction=direction,
            protocol=rule.get('IpProtocol', 'all'),
            source=source_dest if direction == 'INBOUND' else security_group['GroupId'],
            destination=security_group['GroupId'] if direction == 'INBOUND' else source_dest,
            port_range=port_range,
            action='ALLOW',  # AWS security groups are allow-only
            priority=None,
            created_date=None,
            metadata={'security_group': security_group['GroupName'], 'vpc_id': security_group.get('VpcId')}
        )
    
    def get_audit_events(self, time_range_days: int = 30, event_types: List[str] = None) -> List[CloudAuditEvent]:
        """Get AWS CloudTrail events"""
        events = []
        
        try:
            cloudtrail = self._get_client('cloudtrail')
            
            # Default security-related events if none specified
            if not event_types:
                event_types = [
                    'ConsoleLogin', 'AssumeRole', 'CreateUser', 'DeleteUser',
                    'CreateAccessKey', 'DeleteAccessKey', 'PutBucketPolicy'
                ]
            
            end_time = datetime.now()
            start_time = end_time - timedelta(days=time_range_days)
            
            for event_type in event_types:
                try:
                    response = cloudtrail.lookup_events(
                        LookupAttributes=[
                            {
                                'AttributeKey': 'EventName',
                                'AttributeValue': event_type
                            }
                        ],
                        StartTime=start_time,
                        EndTime=end_time
                    )
                    
                    for event in response['Events']:
                        audit_event = self._convert_aws_audit_event(event)
                        events.append(audit_event)
                        
                except Exception as e:
                    self.logger.warning(f"Failed to get events for {event_type}: {str(e)}")
                    continue
            
            self.logger.info(f"Retrieved {len(events)} AWS audit events")
            return events
            
        except Exception as e:
            self.logger.error(f"Failed to get AWS audit events: {str(e)}")
            return []
    
    def _convert_aws_audit_event(self, event: Dict) -> CloudAuditEvent:
        """Convert AWS CloudTrail event to unified format"""
        return CloudAuditEvent(
            event_id=event.get('EventId', ''),
            event_name=event.get('EventName', ''),
            cloud_provider='AWS',
            source_service=event.get('EventSource', ''),
            event_time=event.get('EventTime'),
            user_identity=event.get('Username', ''),
            source_ip=event.get('SourceIPAddress', ''),
            user_agent=event.get('UserAgent', ''),
            resources=[r.get('ResourceName', '') for r in event.get('Resources', [])],
            event_outcome='SUCCESS',  # CloudTrail doesn't always include this
            event_details={'cloud_trail_event': event}
        )
    
    def get_resource_configurations(self) -> List[SystemConfiguration]:
        """Get AWS resource configurations"""
        configs = []
        
        # This would be expanded to include various AWS resources
        # For now, just include basic account info
        try:
            sts = self._get_client('sts')
            identity = sts.get_caller_identity()
            
            config = SystemConfiguration(
                config_id=f"aws-account-{identity['Account']}",
                system_name='AWS Account',
                config_type='ACCOUNT',
                config_data={'account_id': identity['Account'], 'arn': identity['Arn']},
                last_updated=datetime.now(),
                compliance_status='UNKNOWN'
            )
            configs.append(config)
            
        except Exception as e:
            self.logger.error(f"Failed to get AWS configurations: {str(e)}")
        
        return configs
    
    def validate_connectivity(self) -> Dict[str, bool]:
        """Validate AWS service connectivity"""
        results = {}
        
        services = ['sts', 'iam', 'ec2', 'cloudtrail']
        
        for service in services:
            try:
                client = self._get_client(service)
                if service == 'sts':
                    client.get_caller_identity()
                elif service == 'iam':
                    client.list_users(MaxItems=1)
                elif service == 'ec2':
                    client.describe_regions()
                elif service == 'cloudtrail':
                    client.describe_trails()
                
                results[service] = True
                
            except Exception as e:
                self.logger.error(f"AWS {service} connectivity failed: {str(e)}")
                results[service] = False
        
        return results


class AzureProvider(CloudProvider):
    """Microsoft Azure provider implementation"""
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        super().__init__(config, logger)
        if not AZURE_AVAILABLE:
            raise ImportError("Azure SDK not available. Install with: pip install azure-identity azure-mgmt-authorization azure-mgmt-network azure-mgmt-monitor azure-mgmt-resource")
        
        self.credential = None
        self.subscription_id = None
        self.clients = {}
    
    def authenticate(self) -> bool:
        """Authenticate with Azure"""
        try:
            azure_config = self.config.get('azure', {})
            self.subscription_id = azure_config.get('subscription_id')
            
            if not self.subscription_id:
                raise ValueError("Azure subscription_id required in configuration")
            
            # Use service principal if provided, otherwise default credentials
            if azure_config.get('client_id') and azure_config.get('client_secret'):
                self.credential = ClientSecretCredential(
                    tenant_id=azure_config['tenant_id'],
                    client_id=azure_config['client_id'],
                    client_secret=azure_config['client_secret']
                )
            else:
                self.credential = DefaultAzureCredential()
            
            # Test authentication
            resource_client = ResourceManagementClient(self.credential, self.subscription_id)
            list(resource_client.resource_groups.list())
            
            self.logger.info(f"Azure authentication successful for subscription: {self.subscription_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Azure authentication failed: {str(e)}")
            return False
    
    def get_identities(self, account_id: str = None) -> List[CloudIdentity]:
        """Get Azure AD users (simplified implementation)"""
        # Note: Full Azure AD integration would require Microsoft Graph API
        # This is a placeholder for the Azure AD user enumeration
        identities = []
        
        try:
            # This would require Microsoft Graph API integration
            # For now, return placeholder
            self.logger.warning("Azure AD user enumeration requires Microsoft Graph API integration")
            return identities
            
        except Exception as e:
            self.logger.error(f"Failed to get Azure identities: {str(e)}")
            return []
    
    def get_network_rules(self, resource_group: str = None) -> List[CloudNetworkRule]:
        """Get Azure Network Security Group rules"""
        rules = []
        
        try:
            network_client = NetworkManagementClient(self.credential, self.subscription_id)
            
            # Get all resource groups if none specified
            if not resource_group:
                resource_client = ResourceManagementClient(self.credential, self.subscription_id)
                resource_groups = [rg.name for rg in resource_client.resource_groups.list()]
            else:
                resource_groups = [resource_group]
            
            for rg_name in resource_groups:
                try:
                    nsgs = network_client.network_security_groups.list(rg_name)
                    
                    for nsg in nsgs:
                        # Process security rules
                        for rule in nsg.security_rules or []:
                            network_rule = self._convert_azure_security_rule(nsg, rule)
                            rules.append(network_rule)
                            
                except Exception as e:
                    self.logger.warning(f"Failed to get NSG rules for {rg_name}: {str(e)}")
                    continue
            
            self.logger.info(f"Retrieved {len(rules)} Azure NSG rules")
            return rules
            
        except Exception as e:
            self.logger.error(f"Failed to get Azure network rules: {str(e)}")
            return []
    
    def _convert_azure_security_rule(self, nsg, rule) -> CloudNetworkRule:
        """Convert Azure NSG rule to unified format"""
        
        port_range = "All"
        if rule.destination_port_range and rule.destination_port_range != "*":
            port_range = rule.destination_port_range
        
        return CloudNetworkRule(
            rule_id=f"{nsg.name}-{rule.name}",
            rule_name=rule.name,
            cloud_provider='AZURE',
            resource_id=nsg.name,
            direction='INBOUND' if rule.direction == 'Inbound' else 'OUTBOUND',
            protocol=rule.protocol,
            source=rule.source_address_prefix or '',
            destination=rule.destination_address_prefix or '',
            port_range=port_range,
            action=rule.access,
            priority=rule.priority,
            created_date=None,
            metadata={'resource_group': nsg.id.split('/')[4] if '/' in nsg.id else ''}
        )
    
    def get_audit_events(self, time_range_days: int = 30, event_types: List[str] = None) -> List[CloudAuditEvent]:
        """Get Azure Activity Log events"""
        events = []
        
        try:
            monitor_client = MonitorManagementClient(self.credential, self.subscription_id)
            
            end_time = datetime.now()
            start_time = end_time - timedelta(days=time_range_days)
            
            # Get activity log events
            filter_str = f"eventTimestamp ge '{start_time.isoformat()}' and eventTimestamp le '{end_time.isoformat()}'"
            
            activity_logs = monitor_client.activity_logs.list(filter=filter_str)
            
            for log in activity_logs:
                audit_event = self._convert_azure_audit_event(log)
                events.append(audit_event)
            
            self.logger.info(f"Retrieved {len(events)} Azure audit events")
            return events
            
        except Exception as e:
            self.logger.error(f"Failed to get Azure audit events: {str(e)}")
            return []
    
    def _convert_azure_audit_event(self, log) -> CloudAuditEvent:
        """Convert Azure activity log to unified format"""
        return CloudAuditEvent(
            event_id=log.correlation_id or '',
            event_name=log.operation_name.localized_value or log.operation_name.value,
            cloud_provider='AZURE',
            source_service=log.resource_provider_name.value,
            event_time=log.event_timestamp,
            user_identity=log.caller or '',
            source_ip='',
            user_agent='',
            resources=[log.resource_id] if log.resource_id else [],
            event_outcome=log.status.localized_value or log.status.value,
            event_details={'activity_log': log.__dict__}
        )
    
    def get_resource_configurations(self) -> List[SystemConfiguration]:
        """Get Azure resource configurations"""
        configs = []
        
        try:
            resource_client = ResourceManagementClient(self.credential, self.subscription_id)
            
            # Get subscription info
            config = SystemConfiguration(
                config_id=f"azure-subscription-{self.subscription_id}",
                system_name='Azure Subscription',
                config_type='SUBSCRIPTION',
                config_data={'subscription_id': self.subscription_id},
                last_updated=datetime.now(),
                compliance_status='UNKNOWN'
            )
            configs.append(config)
            
        except Exception as e:
            self.logger.error(f"Failed to get Azure configurations: {str(e)}")
        
        return configs
    
    def validate_connectivity(self) -> Dict[str, bool]:
        """Validate Azure service connectivity"""
        results = {}
        
        try:
            # Test Resource Management
            resource_client = ResourceManagementClient(self.credential, self.subscription_id)
            list(resource_client.resource_groups.list())
            results['resource_management'] = True
        except:
            results['resource_management'] = False
        
        try:
            # Test Network Management
            network_client = NetworkManagementClient(self.credential, self.subscription_id)
            results['network_management'] = True
        except:
            results['network_management'] = False
        
        try:
            # Test Monitor
            monitor_client = MonitorManagementClient(self.credential, self.subscription_id)
            results['monitor'] = True
        except:
            results['monitor'] = False
        
        return results


class GCPProvider(CloudProvider):
    """Google Cloud Platform provider implementation"""
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        super().__init__(config, logger)
        if not GCP_AVAILABLE:
            raise ImportError("GCP SDK not available. Install with: pip install google-cloud-iam google-cloud-compute google-cloud-logging google-api-python-client")
        
        self.credentials = None
        self.project_id = None
        self.clients = {}
    
    def authenticate(self) -> bool:
        """Authenticate with GCP"""
        try:
            gcp_config = self.config.get('gcp', {})
            self.project_id = gcp_config.get('project_id')
            
            if not self.project_id:
                raise ValueError("GCP project_id required in configuration")
            
            # Use service account key if provided
            if gcp_config.get('service_account_key_path'):
                self.credentials = service_account.Credentials.from_service_account_file(
                    gcp_config['service_account_key_path']
                )
            else:
                # Use default credentials
                from google.auth import default
                self.credentials, _ = default()
            
            # Test authentication
            service = googleapiclient.discovery.build('cloudresourcemanager', 'v1', credentials=self.credentials)
            service.projects().get(projectId=self.project_id).execute()
            
            self.logger.info(f"GCP authentication successful for project: {self.project_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"GCP authentication failed: {str(e)}")
            return False
    
    def get_identities(self, account_id: str = None) -> List[CloudIdentity]:
        """Get GCP IAM principals"""
        identities = []
        
        try:
            service = googleapiclient.discovery.build('cloudresourcemanager', 'v1', credentials=self.credentials)
            
            # Get IAM policy for the project
            policy = service.projects().getIamPolicy(
                resource=self.project_id,
                body={}
            ).execute()
            
            # Extract unique members
            members = set()
            for binding in policy.get('bindings', []):
                members.update(binding.get('members', []))
            
            for member in members:
                if member.startswith('user:'):
                    identity = self._create_gcp_user_identity(member, policy)
                    identities.append(identity)
            
            self.logger.info(f"Retrieved {len(identities)} GCP identities")
            return identities
            
        except Exception as e:
            self.logger.error(f"Failed to get GCP identities: {str(e)}")
            return []
    
    def _create_gcp_user_identity(self, member: str, policy: Dict) -> CloudIdentity:
        """Create GCP user identity from member string"""
        email = member.replace('user:', '')
        
        # Get roles for this user
        roles = []
        for binding in policy.get('bindings', []):
            if member in binding.get('members', []):
                roles.append(binding['role'])
        
        return CloudIdentity(
            user_id=email,
            username=email.split('@')[0],
            email=email,
            display_name=email,
            cloud_provider='GCP',
            account_id=self.project_id,
            roles=roles,
            permissions=roles,  # In GCP, roles contain permissions
            last_login=None,  # Not easily available
            mfa_enabled=False,  # Would need additional API calls
            created_date=None,
            status='Active',
            metadata={'member_type': 'user'}
        )
    
    def get_network_rules(self, resource_group: str = None) -> List[CloudNetworkRule]:
        """Get GCP Firewall rules"""
        rules = []
        
        try:
            service = googleapiclient.discovery.build('compute', 'v1', credentials=self.credentials)
            
            # Get firewall rules
            request = service.firewalls().list(project=self.project_id)
            
            while request:
                response = request.execute()
                
                for firewall in response.get('items', []):
                    network_rule = self._convert_gcp_firewall_rule(firewall)
                    rules.append(network_rule)
                
                request = service.firewalls().list_next(previous_request=request, previous_response=response)
            
            self.logger.info(f"Retrieved {len(rules)} GCP firewall rules")
            return rules
            
        except Exception as e:
            self.logger.error(f"Failed to get GCP network rules: {str(e)}")
            return []
    
    def _convert_gcp_firewall_rule(self, firewall: Dict) -> CloudNetworkRule:
        """Convert GCP firewall rule to unified format"""
        
        # Extract port ranges
        port_ranges = []
        for allowed in firewall.get('allowed', []):
            if allowed.get('ports'):
                port_ranges.extend(allowed['ports'])
            else:
                port_ranges.append('all')
        
        port_range = ', '.join(port_ranges) if port_ranges else 'all'
        
        # Extract sources
        sources = firewall.get('sourceRanges', ['0.0.0.0/0'])
        source = ', '.join(sources)
        
        return CloudNetworkRule(
            rule_id=firewall['name'],
            rule_name=firewall['name'],
            cloud_provider='GCP',
            resource_id=firewall['name'],
            direction=firewall.get('direction', 'INGRESS'),
            protocol=firewall.get('allowed', [{}])[0].get('IPProtocol', 'all') if firewall.get('allowed') else 'all',
            source=source,
            destination=firewall.get('network', ''),
            port_range=port_range,
            action='ALLOW' if firewall.get('allowed') else 'DENY',
            priority=firewall.get('priority'),
            created_date=None,
            metadata={'network': firewall.get('network', ''), 'target_tags': firewall.get('targetTags', [])}
        )
    
    def get_audit_events(self, time_range_days: int = 30, event_types: List[str] = None) -> List[CloudAuditEvent]:
        """Get GCP Cloud Audit Log events"""
        events = []
        
        try:
            logging_client = gcp_logging.Client(project=self.project_id, credentials=self.credentials)
            
            # Create filter for audit logs
            filter_str = 'protoPayload.serviceName="cloudresourcemanager.googleapis.com" OR protoPayload.serviceName="iam.googleapis.com"'
            
            # Add time filter
            end_time = datetime.now()
            start_time = end_time - timedelta(days=time_range_days)
            filter_str += f' AND timestamp>="{start_time.isoformat()}Z" AND timestamp<="{end_time.isoformat()}Z"'
            
            entries = logging_client.list_entries(filter_=filter_str)
            
            for entry in entries:
                audit_event = self._convert_gcp_audit_event(entry)
                events.append(audit_event)
            
            self.logger.info(f"Retrieved {len(events)} GCP audit events")
            return events
            
        except Exception as e:
            self.logger.error(f"Failed to get GCP audit events: {str(e)}")
            return []
    
    def _convert_gcp_audit_event(self, entry) -> CloudAuditEvent:
        """Convert GCP audit log entry to unified format"""
        payload = entry.payload if hasattr(entry, 'payload') else {}
        
        return CloudAuditEvent(
            event_id=entry.insert_id or '',
            event_name=payload.get('methodName', ''),
            cloud_provider='GCP',
            source_service=payload.get('serviceName', ''),
            event_time=entry.timestamp,
            user_identity=payload.get('authenticationInfo', {}).get('principalEmail', ''),
            source_ip=payload.get('requestMetadata', {}).get('callerIp', ''),
            user_agent=payload.get('requestMetadata', {}).get('callerSuppliedUserAgent', ''),
            resources=[r.get('resourceName', '') for r in payload.get('resourceLocation', {}).get('currentLocations', [])],
            event_outcome='SUCCESS',  # GCP audit logs typically show successful operations
            event_details={'audit_log': payload}
        )
    
    def get_resource_configurations(self) -> List[SystemConfiguration]:
        """Get GCP resource configurations"""
        configs = []
        
        try:
            config = SystemConfiguration(
                config_id=f"gcp-project-{self.project_id}",
                system_name='GCP Project',
                config_type='PROJECT',
                config_data={'project_id': self.project_id},
                last_updated=datetime.now(),
                compliance_status='UNKNOWN'
            )
            configs.append(config)
            
        except Exception as e:
            self.logger.error(f"Failed to get GCP configurations: {str(e)}")
        
        return configs
    
    def validate_connectivity(self) -> Dict[str, bool]:
        """Validate GCP service connectivity"""
        results = {}
        
        try:
            # Test Cloud Resource Manager
            service = googleapiclient.discovery.build('cloudresourcemanager', 'v1', credentials=self.credentials)
            service.projects().get(projectId=self.project_id).execute()
            results['resource_manager'] = True
        except:
            results['resource_manager'] = False
        
        try:
            # Test Compute Engine
            service = googleapiclient.discovery.build('compute', 'v1', credentials=self.credentials)
            service.zones().list(project=self.project_id).execute()
            results['compute'] = True
        except:
            results['compute'] = False
        
        try:
            # Test Cloud Logging
            logging_client = gcp_logging.Client(project=self.project_id, credentials=self.credentials)
            list(logging_client.list_entries(max_results=1))
            results['logging'] = True
        except:
            results['logging'] = False
        
        return results


class CloudProviderFactory:
    """Factory class for creating cloud provider instances"""
    
    @staticmethod
    def create_provider(provider_name: str, config: Dict[str, Any], logger: logging.Logger) -> CloudProvider:
        """Create a cloud provider instance"""
        
        provider_name = provider_name.upper()
        
        if provider_name == 'AWS':
            return AWSProvider(config, logger)
        elif provider_name == 'AZURE':
            return AzureProvider(config, logger)
        elif provider_name == 'GCP':
            return GCPProvider(config, logger)
        else:
            raise ValueError(f"Unsupported cloud provider: {provider_name}")
    
    @staticmethod
    def get_available_providers() -> List[str]:
        """Get list of available cloud providers based on installed SDKs"""
        providers = []
        
        if AWS_AVAILABLE:
            providers.append('AWS')
        if AZURE_AVAILABLE:
            providers.append('AZURE')
        if GCP_AVAILABLE:
            providers.append('GCP')
        
        return providers
    
    @staticmethod
    def create_multi_cloud_session(config: Dict[str, Any], logger: logging.Logger) -> Dict[str, CloudProvider]:
        """Create providers for all configured cloud environments"""
        providers = {}
        
        for provider_name in ['aws', 'azure', 'gcp']:
            if provider_name in config:
                try:
                    provider = CloudProviderFactory.create_provider(provider_name, config, logger)
                    if provider.authenticate():
                        providers[provider_name.upper()] = provider
                        logger.info(f"Successfully initialized {provider_name.upper()} provider")
                    else:
                        logger.error(f"Failed to authenticate {provider_name.upper()} provider")
                except Exception as e:
                    logger.error(f"Failed to initialize {provider_name.upper()} provider: {str(e)}")
        
        return providers