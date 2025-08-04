#!/usr/bin/env python3
"""
SOC 2 Shared Utilities
Common utility functions used across all SOC 2 automation scripts
"""

import os
import json
import csv
import hashlib
import logging
import datetime
from typing import Dict, List, Any, Optional
import boto3
import paramiko
from pathlib import Path

class SOC2Utils:
    """Shared utility functions for SOC 2 automation"""
    
    @staticmethod
    def setup_logging(log_file: str = "soc2_automation.log", log_level: str = "INFO") -> logging.Logger:
        """Setup standardized logging for SOC 2 scripts"""
        
        # Create logs directory if it doesn't exist
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Configure logging
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format=log_format,
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        return logging.getLogger('SOC2Automation')
    
    @staticmethod
    def load_json_config(config_path: str) -> Dict[str, Any]:
        """Load and validate JSON configuration file"""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            return config
        except FileNotFoundError:
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in configuration file {config_path}: {str(e)}")
    
    @staticmethod
    def calculate_file_hash(file_path: str) -> str:
        """Calculate SHA256 hash of a file for integrity verification"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found for hashing: {file_path}")
            
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    @staticmethod
    def create_ssh_connection(host_config: Dict[str, str]) -> paramiko.SSHClient:
        """Create standardized SSH connection"""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # Support both key-based and password authentication
            if 'key_file' in host_config:
                ssh.connect(
                    hostname=host_config['hostname'],
                    username=host_config['username'],
                    key_filename=host_config['key_file'],
                    timeout=30
                )
            else:
                ssh.connect(
                    hostname=host_config['hostname'],
                    username=host_config['username'],
                    password=host_config['password'],
                    timeout=30
                )
            return ssh
        except Exception as e:
            ssh.close()
            raise ConnectionError(f"Failed to connect to {host_config['hostname']}: {str(e)}")
    
    @staticmethod
    def initialize_aws_client(service: str, config: Dict[str, str]):
        """Initialize AWS client with standardized configuration"""
        try:
            client = boto3.client(
                service,
                aws_access_key_id=config['aws']['access_key'],
                aws_secret_access_key=config['aws']['secret_key'],
                region_name=config['aws'].get('region', 'us-east-1')
            )
            return client
        except Exception as e:
            raise ConnectionError(f"Failed to initialize AWS {service} client: {str(e)}")
    
    @staticmethod
    def write_csv_report(data: List[Dict], output_path: str, fieldnames: Optional[List[str]] = None) -> str:
        """Write data to CSV file with standardized formatting"""
        if not data:
            raise ValueError("No data provided for CSV report")
        
        # Create output directory if it doesn't exist
        output_dir = Path(output_path).parent
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Use first record's keys if fieldnames not provided
        if fieldnames is None:
            fieldnames = list(data[0].keys())
        
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        
        return output_path
    
    @staticmethod
    def write_json_report(data: Any, output_path: str) -> str:
        """Write data to JSON file with standardized formatting"""
        # Create output directory if it doesn't exist
        output_dir = Path(output_path).parent
        output_dir.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)  # default=str handles datetime objects
        
        return output_path
    
    @staticmethod
    def create_output_directory(base_name: str) -> str:
        """Create timestamped output directory"""
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = f"output/{base_name}_{timestamp}"
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        return output_dir
    
    @staticmethod
    def parse_windows_timestamp(timestamp: int) -> datetime.datetime:
        """Convert Windows FILETIME timestamp to datetime object"""
        try:
            # Windows FILETIME epoch starts at 1601-01-01
            epoch = datetime.datetime(1601, 1, 1)
            return epoch + datetime.timedelta(microseconds=timestamp/10)
        except:
            return datetime.datetime.min
    
    @staticmethod
    def extract_cn_from_dn(dn: str) -> str:
        """Extract Common Name from LDAP Distinguished Name"""
        try:
            # Extract CN= part from DN string
            cn_parts = [part.strip() for part in dn.split(',') if part.strip().startswith('CN=')]
            if cn_parts:
                return cn_parts[0].replace('CN=', '').strip()
            return dn
        except:
            return dn
    
    @staticmethod
    def validate_config_completeness(config: Dict, required_sections: List[str]) -> List[str]:
        """Validate that configuration contains all required sections"""
        missing_sections = []
        for section in required_sections:
            if section not in config:
                missing_sections.append(section)
        return missing_sections
    
    @staticmethod
    def safe_execute_ssh_command(ssh: paramiko.SSHClient, command: str, timeout: int = 30) -> Dict[str, str]:
        """Safely execute SSH command and return results"""
        try:
            stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
            output = stdout.read().decode('utf-8', errors='ignore').strip()
            error = stderr.read().decode('utf-8', errors='ignore').strip()
            exit_code = stdout.channel.recv_exit_status()
            
            return {
                'success': exit_code == 0,
                'output': output,
                'error': error,
                'exit_code': exit_code
            }
        except Exception as e:
            return {
                'success': False,
                'output': '',
                'error': str(e),
                'exit_code': -1
            }
