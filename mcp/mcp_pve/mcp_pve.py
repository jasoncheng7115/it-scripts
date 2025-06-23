#!/usr/bin/env python3
"""
Proxmox VE MCP Server - Enhanced Edition with Batch Operations
Provides comprehensive Proxmox VE management functionality including batch data collection

Author: Jason Cheng (Jason Tools)
Version: 1.2.1
License: MIT
Repository: https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/mcp/mcp_pve/mcp_pve.py
"""

import asyncio
import json
import logging
import base64
import os
import sys
import ssl
import struct
import io
import time
from typing import Any, Dict, List, Optional, Union
from urllib.parse import quote, urlencode

import httpx
import websockets
from PIL import Image
from mcp.server.models import InitializationOptions
from mcp.server import NotificationOptions, Server
from mcp.types import (
    Resource, Tool, TextContent, ImageContent, EmbeddedResource
)
from pydantic import AnyUrl
import mcp.types as types

# Version information
__version__ = "1.2.1"
__author__ = "Jason Cheng"
__email__ = "jason@jason.tools"
__license__ = "MIT"

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("pve-mcp-server")

class ProxmoxVEError(Exception):
    """Custom exception for Proxmox VE related errors"""
    pass

class ProxmoxVEClient:
    """Proxmox VE API Client with improved error handling and connection management"""
    
    def __init__(self, host: str, username: str = None, password: str = None, 
                 api_token_id: str = None, api_token_secret: str = None, 
                 verify_ssl: bool = False, timeout: float = 30.0):
        self.host = host.rstrip('/')
        self.username = username
        self.password = password
        self.api_token_id = api_token_id
        self.api_token_secret = api_token_secret
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = None
        self.ticket = None
        self.csrf_token = None
        self._authenticated = False
        self._use_api_token = bool(api_token_id and api_token_secret)
        
    async def __aenter__(self):
        self.session = httpx.AsyncClient(
            verify=self.verify_ssl, 
            timeout=httpx.Timeout(self.timeout),
            headers={
                'User-Agent': f'PVE-MCP-Server/{__version__}',
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        )
        if not self._use_api_token:
            await self.authenticate()
        else:
            await self.setup_api_token_auth()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.aclose()
            
    async def setup_api_token_auth(self):
        """Setup API token authentication"""
        try:
            logger.info(f"Setting up API token authentication for {self.api_token_id}")
            
            # Set authorization header for API token
            self.session.headers.update({
                'Authorization': f'PVEAPIToken={self.api_token_id}={self.api_token_secret}'
            })
            
            # Test the token by making a simple API call
            test_result = await self.session.get(f"{self.host}/api2/json/version")
            
            if test_result.status_code == 401:
                raise ProxmoxVEError("API token authentication failed: Invalid token ID or secret")
            elif test_result.status_code == 403:
                raise ProxmoxVEError("API token authentication failed: Insufficient permissions")
            elif test_result.status_code >= 400:
                raise ProxmoxVEError(f"API token authentication failed: HTTP {test_result.status_code}")
            
            test_result.raise_for_status()
            self._authenticated = True
            logger.info("API token authentication successful")
            
        except httpx.RequestError as e:
            raise ProxmoxVEError(f"Network error during API token setup: {e}")
        except Exception as e:
            if isinstance(e, ProxmoxVEError):
                raise
            logger.error(f"API token setup error: {e}")
            raise ProxmoxVEError(f"API token authentication failed: {e}")
            
    async def authenticate(self):
        """Authenticate and get ticket with improved error handling"""
        if self._authenticated:
            return
        
        if self._use_api_token:
            await self.setup_api_token_auth()
            return
            
        if not self.username or not self.password:
            raise ProxmoxVEError("Username and password are required for ticket authentication")
            
        auth_data = {
            'username': self.username,
            'password': self.password
        }
        
        try:
            logger.info(f"Authenticating to Proxmox VE at {self.host}")
            response = await self.session.post(
                f"{self.host}/api2/json/access/ticket",
                data=auth_data
            )
            
            if response.status_code == 401:
                raise ProxmoxVEError("Authentication failed: Invalid username or password")
            elif response.status_code == 403:
                raise ProxmoxVEError("Authentication failed: Access denied")
            elif response.status_code >= 400:
                raise ProxmoxVEError(f"Authentication failed: HTTP {response.status_code}")
                
            response.raise_for_status()
            result = response.json()
            
            if not result.get('data'):
                raise ProxmoxVEError("Authentication failed: No ticket received")
                
            self.ticket = result['data']['ticket']
            self.csrf_token = result['data']['CSRFPreventionToken']
            
            # Update session headers with authentication
            self.session.headers.update({
                'Cookie': f'PVEAuthCookie={self.ticket}',
                'CSRFPreventionToken': self.csrf_token
            })
            
            self._authenticated = True
            logger.info("Ticket authentication successful")
            
        except httpx.RequestError as e:
            raise ProxmoxVEError(f"Network error during authentication: {e}")
        except Exception as e:
            if isinstance(e, ProxmoxVEError):
                raise
            logger.error(f"Authentication error: {e}")
            raise ProxmoxVEError(f"Authentication failed: {e}")
            
    async def _make_request(self, method: str, path: str, params: Optional[Dict] = None, data: Optional[Dict] = None) -> Dict:
        """Make HTTP request with improved error handling and retry logic"""
        if not self._authenticated:
            await self.authenticate()
            
        url = f"{self.host}/api2/json{path}"
        
        try:
            if method.upper() == 'GET':
                response = await self.session.get(url, params=params)
            elif method.upper() == 'POST':
                response = await self.session.post(url, data=data, params=params)
            elif method.upper() == 'PUT':
                response = await self.session.put(url, data=data, params=params)
            elif method.upper() == 'DELETE':
                response = await self.session.delete(url, params=params)
            else:
                raise ProxmoxVEError(f"Unsupported HTTP method: {method}")
            
            # Handle authentication errors
            if response.status_code == 401:
                if self._use_api_token:
                    # API token doesn't expire, so this is likely a permission issue
                    raise ProxmoxVEError("API token authentication failed: Invalid token or insufficient permissions")
                else:
                    # For ticket auth, try re-authenticating
                    logger.warning("Ticket expired, re-authenticating...")
                    self._authenticated = False
                    await self.authenticate()
                    # Retry the request once
                    return await self._make_request(method, path, params, data)
            
            # Handle other HTTP errors
            if response.status_code >= 400:
                try:
                    error_data = response.json()
                    error_msg = error_data.get('errors', {}).get('detail', f"HTTP {response.status_code}")
                except:
                    error_msg = f"HTTP {response.status_code}: {response.text}"
                raise ProxmoxVEError(f"API request failed: {error_msg}")
            
            response.raise_for_status()
            return response.json()
            
        except httpx.RequestError as e:
            raise ProxmoxVEError(f"Network error: {e}")
        except Exception as e:
            if isinstance(e, ProxmoxVEError):
                raise
            logger.error(f"{method} request error {path}: {e}")
            raise ProxmoxVEError(f"Request failed: {e}")
            
    async def get(self, path: str, params: Optional[Dict] = None) -> Dict:
        """Send GET request"""
        return await self._make_request('GET', path, params=params)
            
    async def post(self, path: str, data: Optional[Dict] = None, params: Optional[Dict] = None) -> Dict:
        """Send POST request"""
        return await self._make_request('POST', path, params=params, data=data)

    async def put(self, path: str, data: Optional[Dict] = None, params: Optional[Dict] = None) -> Dict:
        """Send PUT request"""
        return await self._make_request('PUT', path, params=params, data=data)

    async def delete(self, path: str, params: Optional[Dict] = None) -> Dict:
        """Send DELETE request"""
        return await self._make_request('DELETE', path, params=params)

# Global client instance and config
pve_config = None

def get_pve_client():
    """Get PVE client from global config"""
    global pve_config
    
    if pve_config is None:
        raise ProxmoxVEError("PVE configuration not available")
    
    return ProxmoxVEClient(
        host=pve_config['host'],
        username=pve_config['username'],
        password=pve_config['password'],
        api_token_id=pve_config['api_token_id'],
        api_token_secret=pve_config['api_token_secret'],
        verify_ssl=pve_config['verify_ssl'],
        timeout=pve_config['timeout']
    )

# Create MCP server
server = Server("proxmox-ve-mcp")

@server.list_tools()
async def handle_list_tools() -> List[Tool]:
    """List all available tools with comprehensive descriptions"""
    return [
        # NEW: Batch Operations for Data Collection
        Tool(
            name="get_all_vm_firewall_rules",
            description="Get firewall rules and firewall options for all VMs and containers across all nodes",
            inputSchema={
                "type": "object",
                "properties": {
                    "include_containers": {"type": "boolean", "description": "Include LXC containers (default: True)", "default": True},
                    "include_disabled": {"type": "boolean", "description": "Include disabled firewall rules (default: True)", "default": True}
                },
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_all_vm_status_history",
            description="Get power state change history for all VMs and containers",
            inputSchema={
                "type": "object",
                "properties": {
                    "include_containers": {"type": "boolean", "description": "Include LXC containers (default: True)", "default": True},
                    "limit_per_vm": {"type": "integer", "description": "Limit number of history entries per VM/CT", "default": 50, "minimum": 1, "maximum": 500}
                },
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_all_operation_logs",
            description="Get comprehensive operation logs from all nodes, VMs, and containers",
            inputSchema={
                "type": "object",
                "properties": {
                    "include_node_logs": {"type": "boolean", "description": "Include node-level logs (default: True)", "default": True},
                    "include_vm_logs": {"type": "boolean", "description": "Include VM-specific logs (default: True)", "default": True},
                    "include_container_logs": {"type": "boolean", "description": "Include container-specific logs (default: True)", "default": True},
                    "limit_per_source": {"type": "integer", "description": "Limit number of log entries per source", "default": 100, "minimum": 1, "maximum": 1000},
                    "since_hours": {"type": "integer", "description": "Only get logs from last N hours (default: 24)", "default": 24, "minimum": 1}
                },
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_all_snapshots",
            description="Get snapshot information for all VMs and containers across all nodes",
            inputSchema={
                "type": "object",
                "properties": {
                    "include_containers": {"type": "boolean", "description": "Include LXC containers (default: True)", "default": True},
                    "include_details": {"type": "boolean", "description": "Include detailed snapshot information (default: False)", "default": False}
                },
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_all_vm_configs",
            description="Get configuration details for all VMs and containers",
            inputSchema={
                "type": "object",
                "properties": {
                    "include_containers": {"type": "boolean", "description": "Include LXC containers (default: True)", "default": True},
                    "include_hardware_info": {"type": "boolean", "description": "Include hardware configuration details (default: True)", "default": True}
                },
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_all_backup_status",
            description="Get backup status and history for all VMs and containers",
            inputSchema={
                "type": "object",
                "properties": {
                    "include_containers": {"type": "boolean", "description": "Include LXC containers (default: True)", "default": True},
                    "include_job_history": {"type": "boolean", "description": "Include backup job execution history (default: True)", "default": True}
                },
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_all_performance_stats",
            description="Get performance statistics for all nodes, VMs, and containers",
            inputSchema={
                "type": "object",
                "properties": {
                    "include_containers": {"type": "boolean", "description": "Include LXC containers (default: True)", "default": True},
                    "timeframe": {"type": "string", "description": "Time range for statistics", "enum": ["hour", "day", "week"], "default": "hour"},
                    "include_node_stats": {"type": "boolean", "description": "Include node-level statistics (default: True)", "default": True}
                },
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_cluster_overview",
            description="Get comprehensive cluster overview including all resources, status, and health metrics",
            inputSchema={
                "type": "object",
                "properties": {
                    "include_detailed_stats": {"type": "boolean", "description": "Include detailed performance statistics (default: False)", "default": False},
                    "include_logs": {"type": "boolean", "description": "Include recent cluster logs (default: True)", "default": True}
                },
                "additionalProperties": False
            }
        ),
        
        # Cluster and Node Management
        Tool(
            name="get_cluster_status",
            description="Get Proxmox VE cluster overall status including node health and cluster information",
            inputSchema={
                "type": "object",
                "properties": {},
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_cluster_nodes",
            description="Get detailed information about all nodes in the cluster",
            inputSchema={
                "type": "object",
                "properties": {},
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_node_status",
            description="Get detailed status of a specific node including CPU, memory, and system information",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"}
                },
                "required": ["node"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_node_resources",
            description="Get node resource usage including VMs, containers, and storage",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"}
                },
                "required": ["node"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_node_tasks",
            description="Get node task execution status and history",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"},
                    "limit": {"type": "integer", "description": "Limit number of tasks returned", "default": 50, "minimum": 1, "maximum": 1000}
                },
                "required": ["node"],
                "additionalProperties": False
            }
        ),
        
        # Virtual Machine Management
        Tool(
            name="list_vms",
            description="List all virtual machines across all nodes or on a specific node",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name (optional - if not provided, lists VMs from all nodes)"}
                },
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_vm_status",
            description="Get virtual machine current status and runtime information",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name where VM is located"},
                    "vmid": {"type": "integer", "description": "Virtual machine ID", "minimum": 100}
                },
                "required": ["node", "vmid"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_vm_config",
            description="Get virtual machine configuration details including hardware settings",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name where VM is located"},
                    "vmid": {"type": "integer", "description": "Virtual machine ID", "minimum": 100}
                },
                "required": ["node", "vmid"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_vm_snapshots",
            description="Get virtual machine snapshot information and tree structure",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name where VM is located"},
                    "vmid": {"type": "integer", "description": "Virtual machine ID", "minimum": 100}
                },
                "required": ["node", "vmid"],
                "additionalProperties": False
            }
        ),
        
        # VM Creation and Configuration
        Tool(
            name="create_vm",
            description="Create new virtual machine with comprehensive hardware configuration (requires confirmation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name where VM will be created"},
                    "vmid": {"type": "integer", "description": "Virtual machine ID (must be unique)", "minimum": 100},
                    "name": {"type": "string", "description": "VM name", "maxLength": 64},
                    
                    # Basic Settings
                    "ostype": {"type": "string", "description": "OS type", "enum": ["l24", "l26", "win11", "win10", "win8", "win7", "winxp", "w2k19", "w2k16", "w2k12", "w2k8", "wvista", "other"], "default": "l26"},
                    "machine": {"type": "string", "description": "Machine type", "enum": ["pc", "pc-i440fx", "q35", "pc-q35"], "default": "pc"},
                    "bios": {"type": "string", "description": "BIOS type", "enum": ["seabios", "ovmf"], "default": "seabios"},
                    
                    # CPU Configuration
                    "cores": {"type": "integer", "description": "Number of CPU cores", "minimum": 1, "maximum": 128, "default": 1},
                    "sockets": {"type": "integer", "description": "Number of CPU sockets", "minimum": 1, "maximum": 4, "default": 1},
                    "cpu": {"type": "string", "description": "CPU type", "enum": ["host", "kvm64", "qemu64", "x86-64-v2", "x86-64-v3", "x86-64-v4"], "default": "kvm64"},
                    "vcpus": {"type": "integer", "description": "Number of vCPUs (optional)", "minimum": 1, "maximum": 512},
                    
                    # Memory Configuration
                    "memory": {"type": "integer", "description": "Memory in MB", "minimum": 16, "maximum": 4194304, "default": 512},
                    "balloon": {"type": "integer", "description": "Memory balloon device size in MB (0 to disable)", "minimum": 0, "default": 0},
                    
                    # Storage Configuration
                    "scsi0": {"type": "string", "description": "Primary disk (format: storage:size,format=raw/qcow2)", "default": "local-lvm:32,format=raw"},
                    "scsihw": {"type": "string", "description": "SCSI controller type", "enum": ["lsi", "lsi53c810", "virtio-scsi-pci", "virtio-scsi-single", "megasas", "pvscsi"], "default": "virtio-scsi-pci"},
                    "bootdisk": {"type": "string", "description": "Boot disk", "default": "scsi0"},
                    
                    # Network Configuration
                    "net0": {"type": "string", "description": "Network interface (format: model=virtio,bridge=vmbr0)", "default": "virtio,bridge=vmbr0"},
                    
                    # Boot Configuration
                    "boot": {"type": "string", "description": "Boot order", "default": "order=scsi0;ide2;net0"},
                    
                    # Advanced Options
                    "agent": {"type": "integer", "description": "Enable QEMU guest agent (1=enable, 0=disable)", "enum": [0, 1], "default": 1},
                    "protection": {"type": "integer", "description": "Prevent accidental removal (1=enable, 0=disable)", "enum": [0, 1], "default": 0},
                    "tablet": {"type": "integer", "description": "Enable tablet device (1=enable, 0=disable)", "enum": [0, 1], "default": 1},
                    "onboot": {"type": "integer", "description": "Start VM on boot (1=enable, 0=disable)", "enum": [0, 1], "default": 0},
                    
                    # ISO/CDROM
                    "ide2": {"type": "string", "description": "ISO image or CDROM (format: storage:iso/filename.iso,media=cdrom)"},
                    
                    # Description
                    "description": {"type": "string", "description": "VM description", "maxLength": 8192},
                    
                    # Tags
                    "tags": {"type": "string", "description": "Tags separated by semicolons"},
                    
                    # Start after creation
                    "start": {"type": "boolean", "description": "Start VM after creation", "default": False},
                    
                    # Confirmation
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "required": ["node", "vmid"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="clone_vm",
            description="Clone existing virtual machine with new ID (requires confirmation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Source node name where VM is located"},
                    "vmid": {"type": "integer", "description": "Source VM ID to clone", "minimum": 100},
                    "newid": {"type": "integer", "description": "New VM ID for clone", "minimum": 100},
                    "name": {"type": "string", "description": "New VM name"},
                    "description": {"type": "string", "description": "New VM description"},
                    "target": {"type": "string", "description": "Target node (if different from source)"},
                    "storage": {"type": "string", "description": "Target storage for clone"},
                    "format": {"type": "string", "description": "Storage format", "enum": ["raw", "qcow2", "vmdk"], "default": "raw"},
                    "full": {"type": "boolean", "description": "Create full clone (not linked clone)", "default": True},
                    "pool": {"type": "string", "description": "Resource pool"},
                    "snapname": {"type": "string", "description": "Snapshot name to clone from"},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "required": ["node", "vmid", "newid"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="update_vm_config",
            description="Update virtual machine configuration (requires confirmation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name where VM is located"},
                    "vmid": {"type": "integer", "description": "Virtual machine ID", "minimum": 100},
                    "name": {"type": "string", "description": "VM name"},
                    "description": {"type": "string", "description": "VM description"},
                    "cores": {"type": "integer", "description": "Number of CPU cores", "minimum": 1, "maximum": 128},
                    "memory": {"type": "integer", "description": "Memory in MB", "minimum": 16, "maximum": 4194304},
                    "balloon": {"type": "integer", "description": "Memory balloon device size in MB", "minimum": 0},
                    "onboot": {"type": "integer", "description": "Start VM on boot", "enum": [0, 1]},
                    "agent": {"type": "integer", "description": "Enable QEMU guest agent", "enum": [0, 1]},
                    "protection": {"type": "integer", "description": "Prevent accidental removal", "enum": [0, 1]},
                    "tags": {"type": "string", "description": "Tags separated by semicolons"},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "required": ["node", "vmid"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="delete_vm",
            description="Delete virtual machine permanently (requires confirmation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name where VM is located"},
                    "vmid": {"type": "integer", "description": "Virtual machine ID", "minimum": 100},
                    "purge": {"type": "boolean", "description": "Remove VM from all clusters and configs", "default": False},
                    "destroy_unreferenced_disks": {"type": "boolean", "description": "Destroy unreferenced disks", "default": True},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "required": ["node", "vmid"],
                "additionalProperties": False
            }
        ),
        
        # Container Creation and Configuration
        Tool(
            name="create_container",
            description="Create new LXC container with comprehensive configuration (requires confirmation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name where container will be created"},
                    "vmid": {"type": "integer", "description": "Container ID (must be unique)", "minimum": 100},
                    "hostname": {"type": "string", "description": "Container hostname", "maxLength": 64},
                    
                    # Template and OS
                    "ostemplate": {"type": "string", "description": "OS template (format: storage:template.tar.gz)", "default": "local:vztmpl/ubuntu-22.04-standard_22.04-1_amd64.tar.zst"},
                    
                    # CPU Configuration
                    "cores": {"type": "integer", "description": "Number of CPU cores", "minimum": 1, "maximum": 128, "default": 1},
                    "cpulimit": {"type": "number", "description": "CPU limit (floating point)", "minimum": 0, "maximum": 128},
                    "cpuunits": {"type": "integer", "description": "CPU weight", "minimum": 8, "maximum": 500000, "default": 1024},
                    
                    # Memory Configuration
                    "memory": {"type": "integer", "description": "Memory in MB", "minimum": 16, "maximum": 4194304, "default": 512},
                    "swap": {"type": "integer", "description": "Swap in MB", "minimum": 0, "maximum": 4194304, "default": 512},
                    
                    # Storage Configuration
                    "rootfs": {"type": "string", "description": "Root filesystem (format: storage:size)", "default": "local-lvm:8"},
                    "storage": {"type": "string", "description": "Default storage for container", "default": "local-lvm"},
                    
                    # Network Configuration
                    "net0": {"type": "string", "description": "Network interface (format: name=eth0,bridge=vmbr0,ip=dhcp)", "default": "name=eth0,bridge=vmbr0,ip=dhcp"},
                    
                    # Security
                    "unprivileged": {"type": "integer", "description": "Unprivileged container (1=unprivileged, 0=privileged)", "enum": [0, 1], "default": 1},
                    "protection": {"type": "integer", "description": "Prevent accidental removal", "enum": [0, 1], "default": 0},
                    
                    # Boot Configuration
                    "onboot": {"type": "integer", "description": "Start container on boot", "enum": [0, 1], "default": 0},
                    "startup": {"type": "string", "description": "Startup order (format: order=1,up=30,down=60)"},
                    
                    # SSH Keys and Password
                    "password": {"type": "string", "description": "Root password"},
                    "ssh_public_keys": {"type": "string", "description": "SSH public keys (newline separated)"},
                    
                    # DNS Configuration
                    "nameserver": {"type": "string", "description": "DNS nameserver (space separated)"},
                    "searchdomain": {"type": "string", "description": "DNS search domain"},
                    
                    # Features
                    "features": {"type": "string", "description": "Container features (format: nesting=1,keyctl=1)"},
                    
                    # Console
                    "console": {"type": "integer", "description": "Enable console access", "enum": [0, 1], "default": 1},
                    "tty": {"type": "integer", "description": "Number of TTYs", "minimum": 0, "maximum": 6, "default": 2},
                    
                    # Resource Pool
                    "pool": {"type": "string", "description": "Resource pool"},
                    
                    # Description and Tags
                    "description": {"type": "string", "description": "Container description"},
                    "tags": {"type": "string", "description": "Tags separated by semicolons"},
                    
                    # Start after creation
                    "start": {"type": "boolean", "description": "Start container after creation", "default": False},
                    
                    # Confirmation
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "required": ["node", "vmid", "ostemplate"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="clone_container",
            description="Clone existing LXC container with new ID (requires confirmation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Source node name where container is located"},
                    "vmid": {"type": "integer", "description": "Source container ID to clone", "minimum": 100},
                    "newid": {"type": "integer", "description": "New container ID for clone", "minimum": 100},
                    "hostname": {"type": "string", "description": "New container hostname"},
                    "description": {"type": "string", "description": "New container description"},
                    "target": {"type": "string", "description": "Target node (if different from source)"},
                    "storage": {"type": "string", "description": "Target storage for clone"},
                    "pool": {"type": "string", "description": "Resource pool"},
                    "snapname": {"type": "string", "description": "Snapshot name to clone from"},
                    "full": {"type": "boolean", "description": "Create full clone", "default": False},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "required": ["node", "vmid", "newid"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="update_container_config",
            description="Update LXC container configuration (requires confirmation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name where container is located"},
                    "vmid": {"type": "integer", "description": "Container ID", "minimum": 100},
                    "hostname": {"type": "string", "description": "Container hostname"},
                    "description": {"type": "string", "description": "Container description"},
                    "cores": {"type": "integer", "description": "Number of CPU cores", "minimum": 1, "maximum": 128},
                    "memory": {"type": "integer", "description": "Memory in MB", "minimum": 16, "maximum": 4194304},
                    "swap": {"type": "integer", "description": "Swap in MB", "minimum": 0, "maximum": 4194304},
                    "onboot": {"type": "integer", "description": "Start container on boot", "enum": [0, 1]},
                    "protection": {"type": "integer", "description": "Prevent accidental removal", "enum": [0, 1]},
                    "tags": {"type": "string", "description": "Tags separated by semicolons"},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "required": ["node", "vmid"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="delete_container",
            description="Delete LXC container permanently (requires confirmation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name where container is located"},
                    "vmid": {"type": "integer", "description": "Container ID", "minimum": 100},
                    "purge": {"type": "boolean", "description": "Remove container from all clusters and configs", "default": False},
                    "destroy_unreferenced_disks": {"type": "boolean", "description": "Destroy unreferenced disks", "default": True},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "required": ["node", "vmid"],
                "additionalProperties": False
            }
        ),
        
        # Resource Management
        Tool(
            name="list_iso_images",
            description="List available ISO images for VM installation",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"},
                    "storage": {"type": "string", "description": "Storage name (optional)"}
                },
                "required": ["node"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="list_templates",
            description="List available container templates",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"},
                    "storage": {"type": "string", "description": "Storage name (optional)"}
                },
                "required": ["node"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_next_vmid",
            description="Get next available VM/Container ID",
            inputSchema={
                "type": "object",
                "properties": {},
                "additionalProperties": False
            }
        ),
        
        # Configuration Options Query
        Tool(
            name="get_vm_config_options",
            description="Get available configuration options for VM creation (CPU types, network types, etc.)",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name to query options from"}
                },
                "required": ["node"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_network_bridges",
            description="Get available network bridges and their configuration",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"}
                },
                "required": ["node"],
                "additionalProperties": False
            }
        ),
        
        # VM Control Operations (requires confirmation)
        Tool(
            name="vm_start",
            description="Start virtual machine (requires confirmation to prevent accidental operations)",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name where VM is located"},
                    "vmid": {"type": "integer", "description": "Virtual machine ID", "minimum": 100},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "required": ["node", "vmid"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="vm_shutdown",
            description="Shutdown virtual machine gracefully using ACPI (requires confirmation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name where VM is located"},
                    "vmid": {"type": "integer", "description": "Virtual machine ID", "minimum": 100},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "required": ["node", "vmid"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="vm_stop",
            description="Stop virtual machine forcefully (equivalent to power off - requires confirmation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name where VM is located"},
                    "vmid": {"type": "integer", "description": "Virtual machine ID", "minimum": 100},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "required": ["node", "vmid"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="vm_reboot",
            description="Reboot virtual machine gracefully (requires confirmation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name where VM is located"},
                    "vmid": {"type": "integer", "description": "Virtual machine ID", "minimum": 100},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "required": ["node", "vmid"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="vm_reset",
            description="Reset virtual machine forcefully (equivalent to hardware reset - requires confirmation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name where VM is located"},
                    "vmid": {"type": "integer", "description": "Virtual machine ID", "minimum": 100},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "required": ["node", "vmid"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="vm_migrate",
            description="Migrate virtual machine to another node (requires confirmation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Source node name where VM is currently located"},
                    "vmid": {"type": "integer", "description": "Virtual machine ID", "minimum": 100},
                    "target": {"type": "string", "description": "Target node name where VM will be migrated"},
                    "online": {"type": "boolean", "description": "Online migration (live migration)", "default": True},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "required": ["node", "vmid", "target"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="vm_backup",
            description="Create backup of virtual machine (requires confirmation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name where VM is located"},
                    "vmid": {"type": "integer", "description": "Virtual machine ID", "minimum": 100},
                    "storage": {"type": "string", "description": "Backup storage name"},
                    "mode": {"type": "string", "description": "Backup mode", "enum": ["snapshot", "suspend", "stop"], "default": "snapshot"},
                    "compress": {"type": "string", "description": "Compression method", "enum": ["0", "1", "gzip", "lzo", "zstd"], "default": "zstd"},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "required": ["node", "vmid", "storage"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="vm_snapshot",
            description="Create snapshot of virtual machine (requires confirmation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name where VM is located"},
                    "vmid": {"type": "integer", "description": "Virtual machine ID", "minimum": 100},
                    "snapname": {"type": "string", "description": "Snapshot name (must be unique)"},
                    "description": {"type": "string", "description": "Snapshot description", "default": ""},
                    "vmstate": {"type": "boolean", "description": "Include VM memory state in snapshot", "default": False},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "required": ["node", "vmid", "snapname"],
                "additionalProperties": False
            }
        ),
        
        # Container Control Operations (requires confirmation)
        Tool(
            name="ct_start",
            description="Start LXC container (requires confirmation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name where container is located"},
                    "vmid": {"type": "integer", "description": "Container ID", "minimum": 100},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "required": ["node", "vmid"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="ct_shutdown",
            description="Shutdown LXC container gracefully (requires confirmation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name where container is located"},
                    "vmid": {"type": "integer", "description": "Container ID", "minimum": 100},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "required": ["node", "vmid"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="ct_stop",
            description="Stop LXC container forcefully (requires confirmation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name where container is located"},
                    "vmid": {"type": "integer", "description": "Container ID", "minimum": 100},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "required": ["node", "vmid"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="ct_reboot",
            description="Reboot LXC container (requires confirmation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name where container is located"},
                    "vmid": {"type": "integer", "description": "Container ID", "minimum": 100},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "required": ["node", "vmid"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="ct_migrate",
            description="Migrate LXC container to another node (requires confirmation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Source node name where container is currently located"},
                    "vmid": {"type": "integer", "description": "Container ID", "minimum": 100},
                    "target": {"type": "string", "description": "Target node name where container will be migrated"},
                    "online": {"type": "boolean", "description": "Online migration", "default": True},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "required": ["node", "vmid", "target"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="ct_backup",
            description="Create backup of LXC container (requires confirmation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name where container is located"},
                    "vmid": {"type": "integer", "description": "Container ID", "minimum": 100},
                    "storage": {"type": "string", "description": "Backup storage name"},
                    "mode": {"type": "string", "description": "Backup mode", "enum": ["snapshot", "suspend", "stop"], "default": "snapshot"},
                    "compress": {"type": "string", "description": "Compression method", "enum": ["0", "1", "gzip", "lzo", "zstd"], "default": "zstd"},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "required": ["node", "vmid", "storage"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="ct_snapshot",
            description="Create snapshot of LXC container (requires confirmation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name where container is located"},
                    "vmid": {"type": "integer", "description": "Container ID", "minimum": 100},
                    "snapname": {"type": "string", "description": "Snapshot name (must be unique)"},
                    "description": {"type": "string", "description": "Snapshot description", "default": ""},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "required": ["node", "vmid", "snapname"],
                "additionalProperties": False
            }
        ),
        
        # Container Management
        Tool(
            name="list_containers",
            description="List all LXC containers across all nodes or on a specific node",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name (optional - if not provided, lists containers from all nodes)"}
                },
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_container_status",
            description="Get LXC container current status and runtime information",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name where container is located"},
                    "vmid": {"type": "integer", "description": "Container ID", "minimum": 100}
                },
                "required": ["node", "vmid"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_container_config",
            description="Get LXC container configuration details",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name where container is located"},
                    "vmid": {"type": "integer", "description": "Container ID", "minimum": 100}
                },
                "required": ["node", "vmid"],
                "additionalProperties": False
            }
        ),
        
        # Storage Management
        Tool(
            name="get_storage_status",
            description="Get storage status and usage information",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name (optional - if not provided, lists all storage)"}
                },
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_storage_content",
            description="Get storage content list including VMs, templates, and ISOs",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"},
                    "storage": {"type": "string", "description": "Storage name"}
                },
                "required": ["node", "storage"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_zfs_pools",
            description="Get ZFS pool status and information",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"}
                },
                "required": ["node"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_ceph_status",
            description="Get Ceph cluster status and health information",
            inputSchema={
                "type": "object",
                "properties": {},
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_ceph_osds",
            description="Get Ceph OSD (Object Storage Daemon) status",
            inputSchema={
                "type": "object",
                "properties": {},
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_ceph_pools",
            description="Get Ceph pool information and statistics",
            inputSchema={
                "type": "object",
                "properties": {},
                "additionalProperties": False
            }
        ),
        
        # Network Management
        Tool(
            name="get_network_interfaces",
            description="Get network interface status and configuration",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"}
                },
                "required": ["node"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_firewall_rules",
            description="Get firewall rules for cluster, node, or specific VM/container",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name (optional)"},
                    "vmid": {"type": "integer", "description": "VM/Container ID (optional)", "minimum": 100}
                },
                "additionalProperties": False
            }
        ),
        
        # Hardware Monitoring
        Tool(
            name="get_hardware_info",
            description="Get hardware information including PCI devices",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"}
                },
                "required": ["node"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_cpu_info",
            description="Get detailed CPU information and capabilities",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"}
                },
                "required": ["node"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_disk_info",
            description="Get disk information including SMART data",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"}
                },
                "required": ["node"],
                "additionalProperties": False
            }
        ),
        
        # Performance Monitoring
        Tool(
            name="get_performance_stats",
            description="Get node performance statistics",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"},
                    "timeframe": {"type": "string", "description": "Time range for statistics", "enum": ["hour", "day", "week", "month", "year"], "default": "hour"}
                },
                "required": ["node"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_vm_performance",
            description="Get virtual machine performance statistics",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name where VM is located"},
                    "vmid": {"type": "integer", "description": "Virtual machine ID", "minimum": 100},
                    "timeframe": {"type": "string", "description": "Time range for statistics", "enum": ["hour", "day", "week", "month", "year"], "default": "hour"}
                },
                "required": ["node", "vmid"],
                "additionalProperties": False
            }
        ),
        
        # Log Monitoring
        Tool(
            name="get_system_logs",
            description="Get system logs from journal or syslog",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"},
                    "limit": {"type": "integer", "description": "Limit number of log entries", "default": 100, "minimum": 1, "maximum": 1000},
                    "start": {"type": "integer", "description": "Start offset for log entries", "default": 0},
                    "service": {"type": "string", "description": "Filter by systemd service name (optional)"}
                },
                "required": ["node"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_cluster_logs",
            description="Get cluster-wide task and event logs",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "Limit number of log entries", "default": 100, "minimum": 1, "maximum": 1000}
                },
                "additionalProperties": False
            }
        ),
        
        # Backup and Restore
        Tool(
            name="get_backup_jobs",
            description="Get backup job status and schedules",
            inputSchema={
                "type": "object",
                "properties": {},
                "additionalProperties": False
            }
        ),
        Tool(
            name="list_backups",
            description="List backup files in specified storage",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"},
                    "storage": {"type": "string", "description": "Storage name where backups are stored"}
                },
                "required": ["node", "storage"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="create_backup_job",
            description="Create immediate backup job for specified VMs/containers (requires confirmation)",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"},
                    "vmid": {"type": "string", "description": "VM/Container IDs (comma-separated, e.g., '100,101,102')"},
                    "storage": {"type": "string", "description": "Backup storage name"},
                    "mode": {"type": "string", "description": "Backup mode", "enum": ["snapshot", "suspend", "stop"], "default": "snapshot"},
                    "compress": {"type": "string", "description": "Compression method", "enum": ["0", "1", "gzip", "lzo", "zstd"], "default": "zstd"},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "required": ["node", "vmid", "storage"],
                "additionalProperties": False
            }
        ),
        
        # High Availability
        Tool(
            name="get_ha_status",
            description="Get High Availability cluster status",
            inputSchema={
                "type": "object",
                "properties": {},
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_ha_resources",
            description="Get High Availability resource status and configuration",
            inputSchema={
                "type": "object",
                "properties": {},
                "additionalProperties": False
            }
        )
    ]

@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> List[Union[types.TextContent, types.ImageContent]]:
    """Handle tool calls with comprehensive error handling"""
    try:
        result = await execute_tool(name, arguments)
        
        # Pretty print JSON output
        if isinstance(result, dict):
            json_output = json.dumps(result, indent=2, ensure_ascii=False)
        else:
            json_output = str(result)
            
        return [types.TextContent(type="text", text=json_output)]
        
    except ProxmoxVEError as e:
        error_msg = f"Proxmox VE Error: {str(e)}"
        logger.error(error_msg)
        return [types.TextContent(type="text", text=error_msg)]
    except Exception as e:
        error_msg = f"Unexpected error executing tool '{name}': {str(e)}"
        logger.error(error_msg)
        return [types.TextContent(type="text", text=error_msg)]

async def execute_tool(name: str, arguments: dict) -> Union[dict, str]:
    """Execute specific tool operations with enhanced validation and error handling"""
    
    # Validate VM/Container IDs
    if 'vmid' in arguments:
        vmid = arguments['vmid']
        if isinstance(vmid, int) and vmid < 100:
            raise ProxmoxVEError(f"Invalid VM/Container ID: {vmid}. ID must be >= 100")
    
    # Control operations that require confirmation
    control_operations = [
        "vm_start", "vm_shutdown", "vm_stop", "vm_reboot", "vm_reset", "vm_migrate", "vm_backup", "vm_snapshot",
        "ct_start", "ct_shutdown", "ct_stop", "ct_reboot", "ct_migrate", "ct_backup", "ct_snapshot",
        "create_backup_job", "create_vm", "clone_vm", "update_vm_config", "delete_vm",
        "create_container", "clone_container", "update_container_config", "delete_container"
    ]
    
    if name in control_operations:
        if not arguments.get("confirm", False):
            return {
                "status": "confirmation_required",
                "message": f"This operation ({name}) requires confirmation for safety. Please set 'confirm': true to proceed.",
                "operation": name,
                "arguments": arguments,
                "warning": "This operation will modify system state. Please ensure you understand the consequences."
            }
    
    # Get client and execute operations
    client = get_pve_client()
    
    async with client:
        # NEW: Enhanced Batch Operations for Data Collection with Firewall Options
        if name == "get_all_vm_firewall_rules":
            include_containers = arguments.get("include_containers", True)
            include_disabled = arguments.get("include_disabled", True)
            
            # Get all nodes
            nodes_result = await client.get("/nodes")
            all_firewall_rules = []
            
            for node_info in nodes_result.get("data", []):
                node = node_info["node"]
                
                # Get VMs firewall rules
                try:
                    vms_result = await client.get(f"/nodes/{node}/qemu")
                    for vm in vms_result.get("data", []):
                        vmid = vm["vmid"]
                        try:
                            # Get firewall rules
                            firewall_result = await client.get(f"/nodes/{node}/qemu/{vmid}/firewall/rules")
                            
                            # Get firewall options
                            firewall_options = {}
                            try:
                                options_result = await client.get(f"/nodes/{node}/qemu/{vmid}/firewall/options")
                                firewall_options = options_result.get("data", {})
                            except Exception as e:
                                logger.warning(f"Cannot get firewall options for VM {vmid} on node {node}: {e}")
                                firewall_options = {"error": str(e)}
                            
                            if firewall_result.get("data"):
                                rules = firewall_result["data"]
                                if not include_disabled:
                                    rules = [rule for rule in rules if rule.get("enable", 1) == 1]
                                
                                if rules or firewall_options:  # Add if there are rules or options
                                    all_firewall_rules.append({
                                        "node": node,
                                        "vmid": vmid,
                                        "name": vm.get("name", f"VM-{vmid}"),
                                        "type": "qemu",
                                        "status": vm.get("status", "unknown"),
                                        "firewall_rules": rules,
                                        "firewall_options": firewall_options,
                                        "rule_count": len(rules)
                                    })
                        except Exception as e:
                            logger.warning(f"Cannot get firewall rules for VM {vmid} on node {node}: {e}")
                except Exception as e:
                    logger.warning(f"Cannot get VMs from node {node}: {e}")
                
                # Get containers firewall rules
                if include_containers:
                    try:
                        containers_result = await client.get(f"/nodes/{node}/lxc")
                        for container in containers_result.get("data", []):
                            vmid = container["vmid"]
                            try:
                                # Get firewall rules
                                firewall_result = await client.get(f"/nodes/{node}/lxc/{vmid}/firewall/rules")
                                
                                # Get firewall options
                                firewall_options = {}
                                try:
                                    options_result = await client.get(f"/nodes/{node}/lxc/{vmid}/firewall/options")
                                    firewall_options = options_result.get("data", {})
                                except Exception as e:
                                    logger.warning(f"Cannot get firewall options for container {vmid} on node {node}: {e}")
                                    firewall_options = {"error": str(e)}
                                
                                if firewall_result.get("data"):
                                    rules = firewall_result["data"]
                                    if not include_disabled:
                                        rules = [rule for rule in rules if rule.get("enable", 1) == 1]
                                    
                                    if rules or firewall_options:  # Add if there are rules or options
                                        all_firewall_rules.append({
                                            "node": node,
                                            "vmid": vmid,
                                            "name": container.get("name", f"CT-{vmid}"),
                                            "type": "lxc",
                                            "status": container.get("status", "unknown"),
                                            "firewall_rules": rules,
                                            "firewall_options": firewall_options,
                                            "rule_count": len(rules)
                                        })
                            except Exception as e:
                                logger.warning(f"Cannot get firewall rules for container {vmid} on node {node}: {e}")
                    except Exception as e:
                        logger.warning(f"Cannot get containers from node {node}: {e}")
            
            return {
                "data": all_firewall_rules,
                "summary": {
                    "total_entries": len(all_firewall_rules),
                    "nodes_scanned": len(nodes_result.get("data", [])),
                    "include_containers": include_containers,
                    "include_disabled": include_disabled
                }
            }
        
        elif name == "get_all_vm_status_history":
            include_containers = arguments.get("include_containers", True)
            limit_per_vm = arguments.get("limit_per_vm", 50)
            
            # Get all nodes
            nodes_result = await client.get("/nodes")
            all_status_history = []
            
            for node_info in nodes_result.get("data", []):
                node = node_info["node"]
                
                # Get VM status history
                try:
                    vms_result = await client.get(f"/nodes/{node}/qemu")
                    for vm in vms_result.get("data", []):
                        vmid = vm["vmid"]
                        try:
                            # Get task history for this VM (includes start/stop operations)
                            tasks_result = await client.get(f"/nodes/{node}/tasks", {
                                "limit": limit_per_vm,
                                "vmid": vmid
                            })
                            
                            power_operations = []
                            for task in tasks_result.get("data", []):
                                task_type = task.get("type", "")
                                if task_type in ["qmstart", "qmstop", "qmshutdown", "qmreboot", "qmreset"]:
                                    power_operations.append({
                                        "operation": task_type,
                                        "status": task.get("status", "unknown"),
                                        "starttime": task.get("starttime"),
                                        "endtime": task.get("endtime"),
                                        "user": task.get("user", ""),
                                        "upid": task.get("upid", "")
                                    })
                            
                            if power_operations:
                                all_status_history.append({
                                    "node": node,
                                    "vmid": vmid,
                                    "name": vm.get("name", f"VM-{vmid}"),
                                    "type": "qemu",
                                    "current_status": vm.get("status", "unknown"),
                                    "power_operations": power_operations,
                                    "operation_count": len(power_operations)
                                })
                        except Exception as e:
                            logger.warning(f"Cannot get status history for VM {vmid} on node {node}: {e}")
                except Exception as e:
                    logger.warning(f"Cannot get VMs from node {node}: {e}")
                
                # Get container status history
                if include_containers:
                    try:
                        containers_result = await client.get(f"/nodes/{node}/lxc")
                        for container in containers_result.get("data", []):
                            vmid = container["vmid"]
                            try:
                                tasks_result = await client.get(f"/nodes/{node}/tasks", {
                                    "limit": limit_per_vm,
                                    "vmid": vmid
                                })
                                
                                power_operations = []
                                for task in tasks_result.get("data", []):
                                    task_type = task.get("type", "")
                                    if task_type in ["vzstart", "vzstop", "vzshutdown", "vzreboot"]:
                                        power_operations.append({
                                            "operation": task_type,
                                            "status": task.get("status", "unknown"),
                                            "starttime": task.get("starttime"),
                                            "endtime": task.get("endtime"),
                                            "user": task.get("user", ""),
                                            "upid": task.get("upid", "")
                                        })
                                
                                if power_operations:
                                    all_status_history.append({
                                        "node": node,
                                        "vmid": vmid,
                                        "name": container.get("name", f"CT-{vmid}"),
                                        "type": "lxc",
                                        "current_status": container.get("status", "unknown"),
                                        "power_operations": power_operations,
                                        "operation_count": len(power_operations)
                                    })
                            except Exception as e:
                                logger.warning(f"Cannot get status history for container {vmid} on node {node}: {e}")
                    except Exception as e:
                        logger.warning(f"Cannot get containers from node {node}: {e}")
            
            return {
                "data": all_status_history,
                "summary": {
                    "total_entries": len(all_status_history),
                    "nodes_scanned": len(nodes_result.get("data", [])),
                    "include_containers": include_containers,
                    "limit_per_vm": limit_per_vm
                }
            }
        
        elif name == "get_all_operation_logs":
            include_node_logs = arguments.get("include_node_logs", True)
            include_vm_logs = arguments.get("include_vm_logs", True)
            include_container_logs = arguments.get("include_container_logs", True)
            limit_per_source = arguments.get("limit_per_source", 100)
            since_hours = arguments.get("since_hours", 24)
            
            since_timestamp = int(time.time()) - (since_hours * 3600)
            
            # Get all nodes
            nodes_result = await client.get("/nodes")
            all_operation_logs = []
            
            for node_info in nodes_result.get("data", []):
                node = node_info["node"]
                
                # Get node-level logs
                if include_node_logs:
                    try:
                        node_tasks = await client.get(f"/nodes/{node}/tasks", {
                            "limit": limit_per_source,
                            "since": since_timestamp
                        })
                        
                        for task in node_tasks.get("data", []):
                            if task.get("starttime", 0) >= since_timestamp:
                                all_operation_logs.append({
                                    "source_type": "node",
                                    "source_name": node,
                                    "node": node,
                                    "vmid": task.get("id"),
                                    "operation": task.get("type", ""),
                                    "status": task.get("status", "unknown"),
                                    "starttime": task.get("starttime"),
                                    "endtime": task.get("endtime"),
                                    "user": task.get("user", ""),
                                    "upid": task.get("upid", ""),
                                    "log_entry": task
                                })
                    except Exception as e:
                        logger.warning(f"Cannot get node logs from {node}: {e}")
                
                # Get VM-specific logs
                if include_vm_logs:
                    try:
                        vms_result = await client.get(f"/nodes/{node}/qemu")
                        for vm in vms_result.get("data", []):
                            vmid = vm["vmid"]
                            try:
                                vm_tasks = await client.get(f"/nodes/{node}/tasks", {
                                    "limit": limit_per_source // 10,
                                    "vmid": vmid,
                                    "since": since_timestamp
                                })
                                
                                for task in vm_tasks.get("data", []):
                                    if task.get("starttime", 0) >= since_timestamp:
                                        all_operation_logs.append({
                                            "source_type": "vm",
                                            "source_name": vm.get("name", f"VM-{vmid}"),
                                            "node": node,
                                            "vmid": vmid,
                                            "operation": task.get("type", ""),
                                            "status": task.get("status", "unknown"),
                                            "starttime": task.get("starttime"),
                                            "endtime": task.get("endtime"),
                                            "user": task.get("user", ""),
                                            "upid": task.get("upid", ""),
                                            "log_entry": task
                                        })
                            except Exception as e:
                                logger.warning(f"Cannot get logs for VM {vmid} on node {node}: {e}")
                    except Exception as e:
                        logger.warning(f"Cannot get VMs from node {node}: {e}")
                
                # Get container-specific logs
                if include_container_logs:
                    try:
                        containers_result = await client.get(f"/nodes/{node}/lxc")
                        for container in containers_result.get("data", []):
                            vmid = container["vmid"]
                            try:
                                ct_tasks = await client.get(f"/nodes/{node}/tasks", {
                                    "limit": limit_per_source // 10,
                                    "vmid": vmid,
                                    "since": since_timestamp
                                })
                                
                                for task in ct_tasks.get("data", []):
                                    if task.get("starttime", 0) >= since_timestamp:
                                        all_operation_logs.append({
                                            "source_type": "container",
                                            "source_name": container.get("name", f"CT-{vmid}"),
                                            "node": node,
                                            "vmid": vmid,
                                            "operation": task.get("type", ""),
                                            "status": task.get("status", "unknown"),
                                            "starttime": task.get("starttime"),
                                            "endtime": task.get("endtime"),
                                            "user": task.get("user", ""),
                                            "upid": task.get("upid", ""),
                                            "log_entry": task
                                        })
                            except Exception as e:
                                logger.warning(f"Cannot get logs for container {vmid} on node {node}: {e}")
                    except Exception as e:
                        logger.warning(f"Cannot get containers from node {node}: {e}")
            
            # Sort by starttime (newest first)
            all_operation_logs.sort(key=lambda x: x.get("starttime", 0), reverse=True)
            
            return {
                "data": all_operation_logs,
                "summary": {
                    "total_entries": len(all_operation_logs),
                    "nodes_scanned": len(nodes_result.get("data", [])),
                    "since_hours": since_hours,
                    "include_node_logs": include_node_logs,
                    "include_vm_logs": include_vm_logs,
                    "include_container_logs": include_container_logs
                }
            }
        
        elif name == "get_all_snapshots":
            include_containers = arguments.get("include_containers", True)
            include_details = arguments.get("include_details", False)
            
            # Get all nodes
            nodes_result = await client.get("/nodes")
            all_snapshots = []
            
            for node_info in nodes_result.get("data", []):
                node = node_info["node"]
                
                # Get VM snapshots
                try:
                    vms_result = await client.get(f"/nodes/{node}/qemu")
                    for vm in vms_result.get("data", []):
                        vmid = vm["vmid"]
                        try:
                            snapshots_result = await client.get(f"/nodes/{node}/qemu/{vmid}/snapshot")
                            snapshots = snapshots_result.get("data", [])
                            
                            if snapshots:
                                snapshot_info = {
                                    "node": node,
                                    "vmid": vmid,
                                    "name": vm.get("name", f"VM-{vmid}"),
                                    "type": "qemu",
                                    "status": vm.get("status", "unknown"),
                                    "snapshot_count": len(snapshots),
                                    "snapshots": []
                                }
                                
                                for snapshot in snapshots:
                                    snap_data = {
                                        "name": snapshot.get("name", ""),
                                        "description": snapshot.get("description", ""),
                                        "snaptime": snapshot.get("snaptime")
                                    }
                                    
                                    if include_details:
                                        snap_data.update({
                                            "vmstate": snapshot.get("vmstate", 0),
                                            "parent": snapshot.get("parent", ""),
                                            "running": snapshot.get("running", 0)
                                        })
                                    
                                    snapshot_info["snapshots"].append(snap_data)
                                
                                all_snapshots.append(snapshot_info)
                        except Exception as e:
                            logger.warning(f"Cannot get snapshots for VM {vmid} on node {node}: {e}")
                except Exception as e:
                    logger.warning(f"Cannot get VMs from node {node}: {e}")
                
                # Get container snapshots
                if include_containers:
                    try:
                        containers_result = await client.get(f"/nodes/{node}/lxc")
                        for container in containers_result.get("data", []):
                            vmid = container["vmid"]
                            try:
                                snapshots_result = await client.get(f"/nodes/{node}/lxc/{vmid}/snapshot")
                                snapshots = snapshots_result.get("data", [])
                                
                                if snapshots:
                                    snapshot_info = {
                                        "node": node,
                                        "vmid": vmid,
                                        "name": container.get("name", f"CT-{vmid}"),
                                        "type": "lxc",
                                        "status": container.get("status", "unknown"),
                                        "snapshot_count": len(snapshots),
                                        "snapshots": []
                                    }
                                    
                                    for snapshot in snapshots:
                                        snap_data = {
                                            "name": snapshot.get("name", ""),
                                            "description": snapshot.get("description", ""),
                                            "snaptime": snapshot.get("snaptime")
                                        }
                                        
                                        if include_details:
                                            snap_data.update({
                                                "parent": snapshot.get("parent", "")
                                            })
                                        
                                        snapshot_info["snapshots"].append(snap_data)
                                    
                                    all_snapshots.append(snapshot_info)
                            except Exception as e:
                                logger.warning(f"Cannot get snapshots for container {vmid} on node {node}: {e}")
                    except Exception as e:
                        logger.warning(f"Cannot get containers from node {node}: {e}")
            
            total_snapshots = sum(item["snapshot_count"] for item in all_snapshots)
            
            return {
                "data": all_snapshots,
                "summary": {
                    "total_vms_with_snapshots": len(all_snapshots),
                    "total_snapshots": total_snapshots,
                    "nodes_scanned": len(nodes_result.get("data", [])),
                    "include_containers": include_containers,
                    "include_details": include_details
                }
            }
        
        elif name == "get_all_vm_configs":
            include_containers = arguments.get("include_containers", True)
            include_hardware_info = arguments.get("include_hardware_info", True)
            
            # Get all nodes
            nodes_result = await client.get("/nodes")
            all_configs = []
            
            for node_info in nodes_result.get("data", []):
                node = node_info["node"]
                
                # Get VM configurations
                try:
                    vms_result = await client.get(f"/nodes/{node}/qemu")
                    for vm in vms_result.get("data", []):
                        vmid = vm["vmid"]
                        try:
                            config_result = await client.get(f"/nodes/{node}/qemu/{vmid}/config")
                            config_data = config_result.get("data", {})
                            
                            vm_config = {
                                "node": node,
                                "vmid": vmid,
                                "name": vm.get("name", config_data.get("name", f"VM-{vmid}")),
                                "type": "qemu",
                                "status": vm.get("status", "unknown"),
                                "configuration": config_data
                            }
                            
                            if include_hardware_info:
                                vm_config["hardware_summary"] = {
                                    "cores": config_data.get("cores", 1),
                                    "memory": config_data.get("memory", 512),
                                    "sockets": config_data.get("sockets", 1),
                                    "cpu": config_data.get("cpu", "kvm64"),
                                    "ostype": config_data.get("ostype", "l26"),
                                    "machine": config_data.get("machine", "pc"),
                                    "bios": config_data.get("bios", "seabios"),
                                    "balloon": config_data.get("balloon", 0),
                                    "boot": config_data.get("boot", ""),
                                    "agent": config_data.get("agent", 0),
                                    "protection": config_data.get("protection", 0)
                                }
                                
                                # Extract storage information
                                storage_devices = {}
                                for key, value in config_data.items():
                                    if key.startswith(('scsi', 'ide', 'sata', 'virtio')):
                                        storage_devices[key] = value
                                vm_config["storage_devices"] = storage_devices
                                
                                # Extract network information
                                network_devices = {}
                                for key, value in config_data.items():
                                    if key.startswith('net'):
                                        network_devices[key] = value
                                vm_config["network_devices"] = network_devices
                            
                            all_configs.append(vm_config)
                        except Exception as e:
                            logger.warning(f"Cannot get config for VM {vmid} on node {node}: {e}")
                except Exception as e:
                    logger.warning(f"Cannot get VMs from node {node}: {e}")
                
                # Get container configurations
                if include_containers:
                    try:
                        containers_result = await client.get(f"/nodes/{node}/lxc")
                        for container in containers_result.get("data", []):
                            vmid = container["vmid"]
                            try:
                                config_result = await client.get(f"/nodes/{node}/lxc/{vmid}/config")
                                config_data = config_result.get("data", {})
                                
                                ct_config = {
                                    "node": node,
                                    "vmid": vmid,
                                    "name": container.get("name", config_data.get("hostname", f"CT-{vmid}")),
                                    "type": "lxc",
                                    "status": container.get("status", "unknown"),
                                    "configuration": config_data
                                }
                                
                                if include_hardware_info:
                                    ct_config["hardware_summary"] = {
                                        "cores": config_data.get("cores", 1),
                                        "memory": config_data.get("memory", 512),
                                        "swap": config_data.get("swap", 512),
                                        "hostname": config_data.get("hostname", ""),
                                        "ostype": config_data.get("ostype", ""),
                                        "arch": config_data.get("arch", "amd64"),
                                        "unprivileged": config_data.get("unprivileged", 1),
                                        "protection": config_data.get("protection", 0),
                                        "onboot": config_data.get("onboot", 0)
                                    }
                                    
                                    # Extract storage information
                                    storage_devices = {}
                                    for key, value in config_data.items():
                                        if key.startswith(('rootfs', 'mp')):
                                            storage_devices[key] = value
                                    ct_config["storage_devices"] = storage_devices
                                    
                                    # Extract network information
                                    network_devices = {}
                                    for key, value in config_data.items():
                                        if key.startswith('net'):
                                            network_devices[key] = value
                                    ct_config["network_devices"] = network_devices
                                
                                all_configs.append(ct_config)
                            except Exception as e:
                                logger.warning(f"Cannot get config for container {vmid} on node {node}: {e}")
                    except Exception as e:
                        logger.warning(f"Cannot get containers from node {node}: {e}")
            
            return {
                "data": all_configs,
                "summary": {
                    "total_entries": len(all_configs),
                    "nodes_scanned": len(nodes_result.get("data", [])),
                    "include_containers": include_containers,
                    "include_hardware_info": include_hardware_info,
                    "vm_count": len([c for c in all_configs if c["type"] == "qemu"]),
                    "container_count": len([c for c in all_configs if c["type"] == "lxc"])
                }
            }
        
        elif name == "get_all_backup_status":
            include_containers = arguments.get("include_containers", True)
            include_job_history = arguments.get("include_job_history", True)
            
            # Get all nodes
            nodes_result = await client.get("/nodes")
            all_backup_status = []
            
            # Get backup jobs configuration
            backup_jobs = {}
            try:
                jobs_result = await client.get("/cluster/backup")
                for job in jobs_result.get("data", []):
                    job_id = job.get("id", "")
                    backup_jobs[job_id] = job
            except Exception as e:
                logger.warning(f"Cannot get backup jobs: {e}")
            
            for node_info in nodes_result.get("data", []):
                node = node_info["node"]
                
                # Get storage information to find backup storages
                backup_storages = []
                try:
                    storage_result = await client.get(f"/nodes/{node}/storage")
                    for storage in storage_result.get("data", []):
                        content = storage.get("content", "")
                        if "backup" in content.split(","):
                            backup_storages.append(storage["storage"])
                except Exception as e:
                    logger.warning(f"Cannot get storage info from node {node}: {e}")
                
                # Get VM backup status
                try:
                    vms_result = await client.get(f"/nodes/{node}/qemu")
                    for vm in vms_result.get("data", []):
                        vmid = vm["vmid"]
                        
                        vm_backup_info = {
                            "node": node,
                            "vmid": vmid,
                            "name": vm.get("name", f"VM-{vmid}"),
                            "type": "qemu",
                            "status": vm.get("status", "unknown"),
                            "backup_files": [],
                            "backup_jobs": [],
                            "last_backup": None
                        }
                        
                        # Check backup files in each backup storage
                        for storage in backup_storages:
                            try:
                                backups_result = await client.get(f"/nodes/{node}/storage/{storage}/content", {
                                    "content": "backup",
                                    "vmid": vmid
                                })
                                
                                for backup in backups_result.get("data", []):
                                    vm_backup_info["backup_files"].append({
                                        "storage": storage,
                                        "filename": backup.get("volid", ""),
                                        "size": backup.get("size", 0),
                                        "format": backup.get("format", ""),
                                        "ctime": backup.get("ctime", 0)
                                    })
                            except Exception as e:
                                logger.warning(f"Cannot get backups for VM {vmid} from storage {storage}: {e}")
                        
                        # Sort backup files by creation time
                        if vm_backup_info["backup_files"]:
                            vm_backup_info["backup_files"].sort(key=lambda x: x.get("ctime", 0), reverse=True)
                            vm_backup_info["last_backup"] = vm_backup_info["backup_files"][0]
                        
                        # Find applicable backup jobs
                        for job_id, job in backup_jobs.items():
                            job_vmids = job.get("vmid", "").split(",")
                            if str(vmid) in job_vmids or "all" in job_vmids:
                                vm_backup_info["backup_jobs"].append({
                                    "job_id": job_id,
                                    "enabled": job.get("enabled", 1),
                                    "schedule": job.get("schedule", ""),
                                    "storage": job.get("storage", ""),
                                    "mode": job.get("mode", "snapshot")
                                })
                        
                        if vm_backup_info["backup_files"] or vm_backup_info["backup_jobs"]:
                            all_backup_status.append(vm_backup_info)
                except Exception as e:
                    logger.warning(f"Cannot get VMs from node {node}: {e}")
                
                # Get container backup status
                if include_containers:
                    try:
                        containers_result = await client.get(f"/nodes/{node}/lxc")
                        for container in containers_result.get("data", []):
                            vmid = container["vmid"]
                            
                            ct_backup_info = {
                                "node": node,
                                "vmid": vmid,
                                "name": container.get("name", f"CT-{vmid}"),
                                "type": "lxc",
                                "status": container.get("status", "unknown"),
                                "backup_files": [],
                                "backup_jobs": [],
                                "last_backup": None
                            }
                            
                            # Check backup files in each backup storage
                            for storage in backup_storages:
                                try:
                                    backups_result = await client.get(f"/nodes/{node}/storage/{storage}/content", {
                                        "content": "backup",
                                        "vmid": vmid
                                    })
                                    
                                    for backup in backups_result.get("data", []):
                                        ct_backup_info["backup_files"].append({
                                            "storage": storage,
                                            "filename": backup.get("volid", ""),
                                            "size": backup.get("size", 0),
                                            "format": backup.get("format", ""),
                                            "ctime": backup.get("ctime", 0)
                                        })
                                except Exception as e:
                                    logger.warning(f"Cannot get backups for container {vmid} from storage {storage}: {e}")
                            
                            # Sort backup files by creation time
                            if ct_backup_info["backup_files"]:
                                ct_backup_info["backup_files"].sort(key=lambda x: x.get("ctime", 0), reverse=True)
                                ct_backup_info["last_backup"] = ct_backup_info["backup_files"][0]
                            
                            # Find applicable backup jobs
                            for job_id, job in backup_jobs.items():
                                job_vmids = job.get("vmid", "").split(",")
                                if str(vmid) in job_vmids or "all" in job_vmids:
                                    ct_backup_info["backup_jobs"].append({
                                        "job_id": job_id,
                                        "enabled": job.get("enabled", 1),
                                        "schedule": job.get("schedule", ""),
                                        "storage": job.get("storage", ""),
                                        "mode": job.get("mode", "snapshot")
                                    })
                            
                            if ct_backup_info["backup_files"] or ct_backup_info["backup_jobs"]:
                                all_backup_status.append(ct_backup_info)
                    except Exception as e:
                        logger.warning(f"Cannot get containers from node {node}: {e}")
            
            # Calculate summary statistics
            total_backup_files = sum(len(item["backup_files"]) for item in all_backup_status)
            vms_with_backups = len([item for item in all_backup_status if item["type"] == "qemu" and item["backup_files"]])
            containers_with_backups = len([item for item in all_backup_status if item["type"] == "lxc" and item["backup_files"]])
            
            return {
                "data": all_backup_status,
                "backup_jobs": list(backup_jobs.values()) if include_job_history else [],
                "summary": {
                    "total_entries": len(all_backup_status),
                    "total_backup_files": total_backup_files,
                    "vms_with_backups": vms_with_backups,
                    "containers_with_backups": containers_with_backups,
                    "backup_jobs_count": len(backup_jobs),
                    "nodes_scanned": len(nodes_result.get("data", [])),
                    "include_containers": include_containers,
                    "include_job_history": include_job_history
                }
            }
        
        elif name == "get_all_performance_stats":
            include_containers = arguments.get("include_containers", True)
            timeframe = arguments.get("timeframe", "hour")
            include_node_stats = arguments.get("include_node_stats", True)
            
            # Get all nodes
            nodes_result = await client.get("/nodes")
            all_performance_stats = []
            
            for node_info in nodes_result.get("data", []):
                node = node_info["node"]
                
                # Get node performance stats
                if include_node_stats:
                    try:
                        node_stats = await client.get(f"/nodes/{node}/rrddata", {"timeframe": timeframe})
                        all_performance_stats.append({
                            "source_type": "node",
                            "source_name": node,
                            "node": node,
                            "vmid": None,
                            "performance_data": node_stats.get("data", []),
                            "data_points": len(node_stats.get("data", [])),
                            "timeframe": timeframe
                        })
                    except Exception as e:
                        logger.warning(f"Cannot get performance stats for node {node}: {e}")
                
                # Get VM performance stats
                try:
                    vms_result = await client.get(f"/nodes/{node}/qemu")
                    for vm in vms_result.get("data", []):
                        vmid = vm["vmid"]
                        try:
                            vm_stats = await client.get(f"/nodes/{node}/qemu/{vmid}/rrddata", {"timeframe": timeframe})
                            all_performance_stats.append({
                                "source_type": "vm",
                                "source_name": vm.get("name", f"VM-{vmid}"),
                                "node": node,
                                "vmid": vmid,
                                "performance_data": vm_stats.get("data", []),
                                "data_points": len(vm_stats.get("data", [])),
                                "timeframe": timeframe
                            })
                        except Exception as e:
                            logger.warning(f"Cannot get performance stats for VM {vmid} on node {node}: {e}")
                except Exception as e:
                    logger.warning(f"Cannot get VMs from node {node}: {e}")
                
                # Get container performance stats
                if include_containers:
                    try:
                        containers_result = await client.get(f"/nodes/{node}/lxc")
                        for container in containers_result.get("data", []):
                            vmid = container["vmid"]
                            try:
                                ct_stats = await client.get(f"/nodes/{node}/lxc/{vmid}/rrddata", {"timeframe": timeframe})
                                all_performance_stats.append({
                                    "source_type": "container",
                                    "source_name": container.get("name", f"CT-{vmid}"),
                                    "node": node,
                                    "vmid": vmid,
                                    "performance_data": ct_stats.get("data", []),
                                    "data_points": len(ct_stats.get("data", [])),
                                    "timeframe": timeframe
                                })
                            except Exception as e:
                                logger.warning(f"Cannot get performance stats for container {vmid} on node {node}: {e}")
                    except Exception as e:
                        logger.warning(f"Cannot get containers from node {node}: {e}")
            
            total_data_points = sum(item["data_points"] for item in all_performance_stats)
            node_stats_count = len([item for item in all_performance_stats if item["source_type"] == "node"])
            vm_stats_count = len([item for item in all_performance_stats if item["source_type"] == "vm"])
            container_stats_count = len([item for item in all_performance_stats if item["source_type"] == "container"])
            
            return {
                "data": all_performance_stats,
                "summary": {
                    "total_sources": len(all_performance_stats),
                    "total_data_points": total_data_points,
                    "node_stats_count": node_stats_count,
                    "vm_stats_count": vm_stats_count,
                    "container_stats_count": container_stats_count,
                    "timeframe": timeframe,
                    "nodes_scanned": len(nodes_result.get("data", [])),
                    "include_containers": include_containers,
                    "include_node_stats": include_node_stats
                }
            }
        
        elif name == "get_cluster_overview":
            include_detailed_stats = arguments.get("include_detailed_stats", False)
            include_logs = arguments.get("include_logs", True)
            
            cluster_overview = {}
            
            # Get cluster status
            try:
                cluster_status = await client.get("/cluster/status")
                cluster_overview["cluster_status"] = cluster_status.get("data", [])
            except Exception as e:
                cluster_overview["cluster_status_error"] = str(e)
            
            # Get all nodes
            try:
                nodes_result = await client.get("/nodes")
                cluster_overview["nodes"] = []
                
                total_memory = 0
                total_memory_used = 0
                total_cpu_cores = 0
                total_cpu_usage = 0.0
                total_vms = 0
                total_containers = 0
                
                for node_info in nodes_result.get("data", []):
                    node = node_info["node"]
                    
                    # Get detailed node status
                    try:
                        node_status = await client.get(f"/nodes/{node}/status")
                        node_data = node_status.get("data", {})
                        
                        # Calculate totals
                        memory = node_data.get("memory", {})
                        total_memory += memory.get("total", 0)
                        total_memory_used += memory.get("used", 0)
                        
                        cpu_info = node_data.get("cpu", 0)
                        cpuinfo = node_data.get("cpuinfo", {})
                        cores = cpuinfo.get("cores", 1)
                        total_cpu_cores += cores
                        total_cpu_usage += cpu_info * cores
                        
                        # Get VMs and containers count
                        try:
                            vms_result = await client.get(f"/nodes/{node}/qemu")
                            node_vms = len(vms_result.get("data", []))
                            total_vms += node_vms
                        except:
                            node_vms = 0
                        
                        try:
                            containers_result = await client.get(f"/nodes/{node}/lxc")
                            node_containers = len(containers_result.get("data", []))
                            total_containers += node_containers
                        except:
                            node_containers = 0
                        
                        node_overview = {
                            "node": node,
                            "status": node_data.get("pveversion", "unknown"),
                            "uptime": node_data.get("uptime", 0),
                            "cpu_usage": cpu_info,
                            "cpu_cores": cores,
                            "memory_total": memory.get("total", 0),
                            "memory_used": memory.get("used", 0),
                            "memory_percentage": (memory.get("used", 0) / memory.get("total", 1)) * 100,
                            "vm_count": node_vms,
                            "container_count": node_containers,
                            "loadavg": node_data.get("loadavg", [])
                        }
                        
                        if include_detailed_stats:
                            # Get storage info
                            try:
                                storage_result = await client.get(f"/nodes/{node}/storage")
                                node_overview["storage"] = storage_result.get("data", [])
                            except:
                                node_overview["storage"] = []
                            
                            # Get network interfaces
                            try:
                                network_result = await client.get(f"/nodes/{node}/network")
                                node_overview["network_interfaces"] = network_result.get("data", [])
                            except:
                                node_overview["network_interfaces"] = []
                        
                        cluster_overview["nodes"].append(node_overview)
                    except Exception as e:
                        cluster_overview["nodes"].append({
                            "node": node,
                            "error": str(e)
                        })
                
                # Calculate cluster-wide statistics
                cluster_overview["cluster_summary"] = {
                    "total_nodes": len(nodes_result.get("data", [])),
                    "total_vms": total_vms,
                    "total_containers": total_containers,
                    "total_memory_gb": round(total_memory / (1024**3), 2),
                    "total_memory_used_gb": round(total_memory_used / (1024**3), 2),
                    "memory_usage_percentage": round((total_memory_used / total_memory) * 100, 2) if total_memory > 0 else 0,
                    "total_cpu_cores": total_cpu_cores,
                    "average_cpu_usage": round(total_cpu_usage / total_cpu_cores, 2) if total_cpu_cores > 0 else 0
                }
                
            except Exception as e:
                cluster_overview["nodes_error"] = str(e)
            
            # Get cluster logs
            if include_logs:
                try:
                    logs_result = await client.get("/cluster/tasks", {"limit": 50})
                    cluster_overview["recent_tasks"] = logs_result.get("data", [])
                except Exception as e:
                    cluster_overview["logs_error"] = str(e)
            
            # Get backup jobs
            try:
                backup_jobs = await client.get("/cluster/backup")
                cluster_overview["backup_jobs"] = backup_jobs.get("data", [])
            except Exception as e:
                cluster_overview["backup_jobs_error"] = str(e)
            
            # Get HA status
            try:
                ha_status = await client.get("/cluster/ha/status/current")
                cluster_overview["ha_status"] = ha_status.get("data", [])
            except Exception as e:
                cluster_overview["ha_status_error"] = str(e)
            
            return {
                "data": cluster_overview,
                "summary": {
                    "include_detailed_stats": include_detailed_stats,
                    "include_logs": include_logs,
                    "generation_time": int(time.time())
                }
            }
        
        # Cluster and Node Management
        elif name == "get_cluster_status":
            return await client.get("/cluster/status")
        
        elif name == "get_cluster_nodes":
            return await client.get("/nodes")
        
        elif name == "get_node_status":
            node = arguments["node"]
            return await client.get(f"/nodes/{node}/status")
        
        elif name == "get_node_resources":
            node = arguments["node"]
            return await client.get(f"/nodes/{node}/resources")
        
        elif name == "get_node_tasks":
            node = arguments["node"]
            limit = arguments.get("limit", 50)
            return await client.get(f"/nodes/{node}/tasks", {"limit": limit})
        
        # Virtual Machine Management
        elif name == "list_vms":
            if "node" in arguments:
                node = arguments["node"]
                return await client.get(f"/nodes/{node}/qemu")
            else:
                nodes_result = await client.get("/nodes")
                all_vms = []
                for node_info in nodes_result.get("data", []):
                    node = node_info["node"]
                    try:
                        vms_result = await client.get(f"/nodes/{node}/qemu")
                        if vms_result.get("data"):
                            for vm in vms_result["data"]:
                                vm["node"] = node
                            all_vms.extend(vms_result["data"])
                    except Exception as e:
                        logger.warning(f"Cannot get VMs from node {node}: {e}")
                return {"data": all_vms}
        
        elif name == "get_vm_status":
            node = arguments["node"]
            vmid = arguments["vmid"]
            return await client.get(f"/nodes/{node}/qemu/{vmid}/status/current")
        
        elif name == "get_vm_config":
            node = arguments["node"]
            vmid = arguments["vmid"]
            return await client.get(f"/nodes/{node}/qemu/{vmid}/config")
        
        elif name == "get_vm_snapshots":
            node = arguments["node"]
            vmid = arguments["vmid"]
            return await client.get(f"/nodes/{node}/qemu/{vmid}/snapshot")
        
        # VM Control Operations
        elif name == "vm_start":
            node = arguments["node"]
            vmid = arguments["vmid"]
            return await client.post(f"/nodes/{node}/qemu/{vmid}/status/start")
        
        elif name == "vm_shutdown":
            node = arguments["node"]
            vmid = arguments["vmid"]
            return await client.post(f"/nodes/{node}/qemu/{vmid}/status/shutdown")
        
        elif name == "vm_stop":
            node = arguments["node"]
            vmid = arguments["vmid"]
            return await client.post(f"/nodes/{node}/qemu/{vmid}/status/stop")
        
        elif name == "vm_reboot":
            node = arguments["node"]
            vmid = arguments["vmid"]
            return await client.post(f"/nodes/{node}/qemu/{vmid}/status/reboot")
        
        elif name == "vm_reset":
            node = arguments["node"]
            vmid = arguments["vmid"]
            return await client.post(f"/nodes/{node}/qemu/{vmid}/status/reset")
        
        # **修正：添加 vm_migrate 的實作**
        elif name == "vm_migrate":
            node = arguments["node"]
            vmid = arguments["vmid"]
            target = arguments["target"]
            online = arguments.get("online", True)
            
            migrate_data = {
                "target": target,
                "online": 1 if online else 0
            }
            
            return await client.post(f"/nodes/{node}/qemu/{vmid}/migrate", data=migrate_data)
        
        elif name == "vm_backup":
            node = arguments["node"]
            vmid = arguments["vmid"]
            storage = arguments["storage"]
            mode = arguments.get("mode", "snapshot")
            compress = arguments.get("compress", "zstd")
            
            backup_data = {
                "storage": storage,
                "mode": mode,
                "compress": compress
            }
            
            return await client.post(f"/nodes/{node}/qemu/{vmid}/backup", data=backup_data)
        
        elif name == "vm_snapshot":
            node = arguments["node"]
            vmid = arguments["vmid"]
            snapname = arguments["snapname"]
            description = arguments.get("description", "")
            vmstate = arguments.get("vmstate", False)
            
            snapshot_data = {
                "snapname": snapname,
                "description": description,
                "vmstate": 1 if vmstate else 0
            }
            
            return await client.post(f"/nodes/{node}/qemu/{vmid}/snapshot", data=snapshot_data)
        
        # Container Management
        elif name == "list_containers":
            if "node" in arguments:
                node = arguments["node"]
                return await client.get(f"/nodes/{node}/lxc")
            else:
                nodes_result = await client.get("/nodes")
                all_containers = []
                for node_info in nodes_result.get("data", []):
                    node = node_info["node"]
                    try:
                        containers_result = await client.get(f"/nodes/{node}/lxc")
                        if containers_result.get("data"):
                            for container in containers_result["data"]:
                                container["node"] = node
                            all_containers.extend(containers_result["data"])
                    except Exception as e:
                        logger.warning(f"Cannot get containers from node {node}: {e}")
                return {"data": all_containers}
        
        elif name == "get_container_status":
            node = arguments["node"]
            vmid = arguments["vmid"]
            return await client.get(f"/nodes/{node}/lxc/{vmid}/status/current")
        
        elif name == "get_container_config":
            node = arguments["node"]
            vmid = arguments["vmid"]
            return await client.get(f"/nodes/{node}/lxc/{vmid}/config")
        
        # Container Control Operations
        elif name == "ct_start":
            node = arguments["node"]
            vmid = arguments["vmid"]
            return await client.post(f"/nodes/{node}/lxc/{vmid}/status/start")
        
        elif name == "ct_shutdown":
            node = arguments["node"]
            vmid = arguments["vmid"]
            return await client.post(f"/nodes/{node}/lxc/{vmid}/status/shutdown")
        
        elif name == "ct_stop":
            node = arguments["node"]
            vmid = arguments["vmid"]
            return await client.post(f"/nodes/{node}/lxc/{vmid}/status/stop")
        
        elif name == "ct_reboot":
            node = arguments["node"]
            vmid = arguments["vmid"]
            return await client.post(f"/nodes/{node}/lxc/{vmid}/status/reboot")
        
        elif name == "ct_migrate":
            node = arguments["node"]
            vmid = arguments["vmid"]
            target = arguments["target"]
            online = arguments.get("online", True)
            
            migrate_data = {
                "target": target,
                "online": 1 if online else 0
            }
            
            return await client.post(f"/nodes/{node}/lxc/{vmid}/migrate", data=migrate_data)
        
        elif name == "ct_backup":
            node = arguments["node"]
            vmid = arguments["vmid"]
            storage = arguments["storage"]
            mode = arguments.get("mode", "snapshot")
            compress = arguments.get("compress", "zstd")
            
            backup_data = {
                "storage": storage,
                "mode": mode,
                "compress": compress
            }
            
            return await client.post(f"/nodes/{node}/lxc/{vmid}/backup", data=backup_data)
        
        elif name == "ct_snapshot":
            node = arguments["node"]
            vmid = arguments["vmid"]
            snapname = arguments["snapname"]
            description = arguments.get("description", "")
            
            snapshot_data = {
                "snapname": snapname,
                "description": description
            }
            
            return await client.post(f"/nodes/{node}/lxc/{vmid}/snapshot", data=snapshot_data)
        
        # Storage Management
        elif name == "get_storage_status":
            if "node" in arguments:
                node = arguments["node"]
                return await client.get(f"/nodes/{node}/storage")
            else:
                nodes_result = await client.get("/nodes")
                all_storage = []
                for node_info in nodes_result.get("data", []):
                    node = node_info["node"]
                    try:
                        storage_result = await client.get(f"/nodes/{node}/storage")
                        if storage_result.get("data"):
                            for storage in storage_result["data"]:
                                storage["node"] = node
                            all_storage.extend(storage_result["data"])
                    except Exception as e:
                        logger.warning(f"Cannot get storage from node {node}: {e}")
                return {"data": all_storage}
        
        elif name == "get_storage_content":
            node = arguments["node"]
            storage = arguments["storage"]
            return await client.get(f"/nodes/{node}/storage/{storage}/content")
        
        elif name == "get_zfs_pools":
            node = arguments["node"]
            return await client.get(f"/nodes/{node}/disks/zfs")
        
        elif name == "get_ceph_status":
            return await client.get("/cluster/ceph/status")
        
        elif name == "get_ceph_osds":
            return await client.get("/cluster/ceph/osd")
        
        elif name == "get_ceph_pools":
            return await client.get("/cluster/ceph/pool")
        
        # Network Management
        elif name == "get_network_interfaces":
            node = arguments["node"]
            return await client.get(f"/nodes/{node}/network")
        
        elif name == "get_network_bridges":
            node = arguments["node"]
            network_result = await client.get(f"/nodes/{node}/network")
            bridges = []
            for interface in network_result.get("data", []):
                if interface.get("type") == "bridge":
                    bridges.append(interface)
            return {"data": bridges}
        
        elif name == "get_firewall_rules":
            if "vmid" in arguments and "node" in arguments:
                node = arguments["node"]
                vmid = arguments["vmid"]
                try:
                    # Try VM first
                    return await client.get(f"/nodes/{node}/qemu/{vmid}/firewall/rules")
                except:
                    # Try container
                    return await client.get(f"/nodes/{node}/lxc/{vmid}/firewall/rules")
            elif "node" in arguments:
                node = arguments["node"]
                return await client.get(f"/nodes/{node}/firewall/rules")
            else:
                return await client.get("/cluster/firewall/groups")
        
        # Hardware and Performance Monitoring
        elif name == "get_hardware_info":
            node = arguments["node"]
            return await client.get(f"/nodes/{node}/hardware/pci")
        
        elif name == "get_cpu_info":
            node = arguments["node"]
            return await client.get(f"/nodes/{node}/hardware/cpu")
        
        elif name == "get_disk_info":
            node = arguments["node"]
            return await client.get(f"/nodes/{node}/disks/list")
        
        elif name == "get_performance_stats":
            node = arguments["node"]
            timeframe = arguments.get("timeframe", "hour")
            return await client.get(f"/nodes/{node}/rrddata", {"timeframe": timeframe})
        
        elif name == "get_vm_performance":
            node = arguments["node"]
            vmid = arguments["vmid"]
            timeframe = arguments.get("timeframe", "hour")
            return await client.get(f"/nodes/{node}/qemu/{vmid}/rrddata", {"timeframe": timeframe})
        
        # Log Management
        elif name == "get_system_logs":
            node = arguments["node"]
            limit = arguments.get("limit", 100)
            start = arguments.get("start", 0)
            service = arguments.get("service")
            
            params = {"limit": limit, "start": start}
            if service:
                params["service"] = service
            
            return await client.get(f"/nodes/{node}/journal", params)
        
        elif name == "get_cluster_logs":
            limit = arguments.get("limit", 100)
            return await client.get("/cluster/tasks", {"limit": limit})
        
        # Backup Management
        elif name == "get_backup_jobs":
            return await client.get("/cluster/backup")
        
        elif name == "list_backups":
            node = arguments["node"]
            storage = arguments["storage"]
            return await client.get(f"/nodes/{node}/storage/{storage}/content", {"content": "backup"})
        
        elif name == "create_backup_job":
            node = arguments["node"]
            vmid = arguments["vmid"]
            storage = arguments["storage"]
            mode = arguments.get("mode", "snapshot")
            compress = arguments.get("compress", "zstd")
            
            backup_data = {
                "vmid": vmid,
                "storage": storage,
                "mode": mode,
                "compress": compress
            }
            
            return await client.post("/cluster/backup", data=backup_data)
        
        # High Availability
        elif name == "get_ha_status":
            return await client.get("/cluster/ha/status/current")
        
        elif name == "get_ha_resources":
            return await client.get("/cluster/ha/resources")
        
        # Resource Management
        elif name == "list_iso_images":
            node = arguments["node"]
            storage = arguments.get("storage")
            
            if storage:
                return await client.get(f"/nodes/{node}/storage/{storage}/content", {"content": "iso"})
            else:
                # List all ISO images across all storages
                storage_result = await client.get(f"/nodes/{node}/storage")
                all_isos = []
                for storage_info in storage_result.get("data", []):
                    storage_name = storage_info["storage"]
                    content = storage_info.get("content", "")
                    if "iso" in content.split(","):
                        try:
                            iso_result = await client.get(f"/nodes/{node}/storage/{storage_name}/content", {"content": "iso"})
                            if iso_result.get("data"):
                                for iso in iso_result["data"]:
                                    iso["storage"] = storage_name
                                all_isos.extend(iso_result["data"])
                        except Exception as e:
                            logger.warning(f"Cannot get ISOs from storage {storage_name}: {e}")
                return {"data": all_isos}
        
        elif name == "list_templates":
            node = arguments["node"]
            storage = arguments.get("storage")
            
            if storage:
                return await client.get(f"/nodes/{node}/storage/{storage}/content", {"content": "vztmpl"})
            else:
                # List all templates across all storages
                storage_result = await client.get(f"/nodes/{node}/storage")
                all_templates = []
                for storage_info in storage_result.get("data", []):
                    storage_name = storage_info["storage"]
                    content = storage_info.get("content", "")
                    if "vztmpl" in content.split(","):
                        try:
                            template_result = await client.get(f"/nodes/{node}/storage/{storage_name}/content", {"content": "vztmpl"})
                            if template_result.get("data"):
                                for template in template_result["data"]:
                                    template["storage"] = storage_name
                                all_templates.extend(template_result["data"])
                        except Exception as e:
                            logger.warning(f"Cannot get templates from storage {storage_name}: {e}")
                return {"data": all_templates}
        
        elif name == "get_next_vmid":
            return await client.get("/cluster/nextid")
        
        elif name == "get_vm_config_options":
            node = arguments["node"]
            return await client.get(f"/nodes/{node}/capabilities/qemu")
        
        # VM Creation and Management Operations
        elif name == "create_vm":
            node = arguments["node"]
            vmid = arguments["vmid"]
            
            # Build creation data from arguments
            vm_data = {"vmid": vmid}
            
            # Copy all supported parameters
            supported_params = [
                "name", "ostype", "machine", "bios", "cores", "sockets", "cpu", "vcpus",
                "memory", "balloon", "scsi0", "scsihw", "bootdisk", "net0", "boot",
                "agent", "protection", "tablet", "onboot", "ide2", "description", "tags"
            ]
            
            for param in supported_params:
                if param in arguments:
                    vm_data[param] = arguments[param]
            
            # Convert boolean start to actual start operation
            start_after_create = arguments.get("start", False)
            
            # Create the VM
            result = await client.post(f"/nodes/{node}/qemu", data=vm_data)
            
            # Start VM if requested
            if start_after_create and result:
                try:
                    start_result = await client.post(f"/nodes/{node}/qemu/{vmid}/status/start")
                    result["start_result"] = start_result
                except Exception as e:
                    result["start_error"] = str(e)
            
            return result
        
        elif name == "clone_vm":
            node = arguments["node"]
            vmid = arguments["vmid"]
            newid = arguments["newid"]
            
            clone_data = {"newid": newid}
            
            # Copy supported clone parameters
            supported_params = ["name", "description", "target", "storage", "format", "full", "pool", "snapname"]
            for param in supported_params:
                if param in arguments:
                    clone_data[param] = arguments[param]
            
            return await client.post(f"/nodes/{node}/qemu/{vmid}/clone", data=clone_data)
        
        elif name == "update_vm_config":
            node = arguments["node"]
            vmid = arguments["vmid"]
            
            update_data = {}
            supported_params = ["name", "description", "cores", "memory", "balloon", "onboot", "agent", "protection", "tags"]
            for param in supported_params:
                if param in arguments:
                    update_data[param] = arguments[param]
            
            return await client.put(f"/nodes/{node}/qemu/{vmid}/config", data=update_data)
        
        elif name == "delete_vm":
            node = arguments["node"]
            vmid = arguments["vmid"]
            
            delete_params = {}
            if arguments.get("purge", False):
                delete_params["purge"] = 1
            if arguments.get("destroy_unreferenced_disks", True):
                delete_params["destroy-unreferenced-disks"] = 1
            
            return await client.delete(f"/nodes/{node}/qemu/{vmid}", params=delete_params)
        
        # Container Creation and Management Operations
        elif name == "create_container":
            node = arguments["node"]
            vmid = arguments["vmid"]
            ostemplate = arguments["ostemplate"]
            
            # Build creation data from arguments
            ct_data = {"vmid": vmid, "ostemplate": ostemplate}
            
            # Copy all supported parameters
            supported_params = [
                "hostname", "cores", "cpulimit", "cpuunits", "memory", "swap", "rootfs", "storage",
                "net0", "unprivileged", "protection", "onboot", "startup", "password", "ssh-public-keys",
                "nameserver", "searchdomain", "features", "console", "tty", "pool", "description", "tags"
            ]
            
            for param in supported_params:
                if param in arguments:
                    if param == "ssh_public_keys":
                        ct_data["ssh-public-keys"] = arguments[param]
                    else:
                        ct_data[param] = arguments[param]
            
            # Convert boolean start to actual start operation
            start_after_create = arguments.get("start", False)
            
            # Create the container
            result = await client.post(f"/nodes/{node}/lxc", data=ct_data)
            
            # Start container if requested
            if start_after_create and result:
                try:
                    start_result = await client.post(f"/nodes/{node}/lxc/{vmid}/status/start")
                    result["start_result"] = start_result
                except Exception as e:
                    result["start_error"] = str(e)
            
            return result
        
        elif name == "clone_container":
            node = arguments["node"]
            vmid = arguments["vmid"]
            newid = arguments["newid"]
            
            clone_data = {"newid": newid}
            
            # Copy supported clone parameters
            supported_params = ["hostname", "description", "target", "storage", "pool", "snapname", "full"]
            for param in supported_params:
                if param in arguments:
                    clone_data[param] = arguments[param]
            
            return await client.post(f"/nodes/{node}/lxc/{vmid}/clone", data=clone_data)
        
        elif name == "update_container_config":
            node = arguments["node"]
            vmid = arguments["vmid"]
            
            update_data = {}
            supported_params = ["hostname", "description", "cores", "memory", "swap", "onboot", "protection", "tags"]
            for param in supported_params:
                if param in arguments:
                    update_data[param] = arguments[param]
            
            return await client.put(f"/nodes/{node}/lxc/{vmid}/config", data=update_data)
        
        elif name == "delete_container":
            node = arguments["node"]
            vmid = arguments["vmid"]
            
            delete_params = {}
            if arguments.get("purge", False):
                delete_params["purge"] = 1
            if arguments.get("destroy_unreferenced_disks", True):
                delete_params["destroy-unreferenced-disks"] = 1
            
            return await client.delete(f"/nodes/{node}/lxc/{vmid}", params=delete_params)
        
        else:
            raise ProxmoxVEError(f"Tool '{name}' is not implemented. This should not happen as all tools are now implemented.")
    """Execute specific tool operations with enhanced validation and error handling"""
    
    # Validate VM/Container IDs
    if 'vmid' in arguments:
        vmid = arguments['vmid']
        if isinstance(vmid, int) and vmid < 100:
            raise ProxmoxVEError(f"Invalid VM/Container ID: {vmid}. ID must be >= 100")
    
    # Control operations that require confirmation
    control_operations = [
        "vm_start", "vm_shutdown", "vm_stop", "vm_reboot", "vm_reset", "vm_migrate", "vm_backup", "vm_snapshot",
        "ct_start", "ct_shutdown", "ct_stop", "ct_reboot", "ct_migrate", "ct_backup", "ct_snapshot",
        "create_backup_job", "create_vm", "clone_vm", "update_vm_config", "delete_vm",
        "create_container", "clone_container", "update_container_config", "delete_container"
    ]
    
    if name in control_operations:
        if not arguments.get("confirm", False):
            return {
                "status": "confirmation_required",
                "message": f"This operation ({name}) requires confirmation for safety. Please set 'confirm': true to proceed.",
                "operation": name,
                "arguments": arguments,
                "warning": "This operation will modify system state. Please ensure you understand the consequences."
            }
    
    # Get client and execute operations
    client = get_pve_client()
    
    async with client:
        # NEW: Enhanced Batch Operations for Data Collection with Firewall Options
        if name == "get_all_vm_firewall_rules":
            include_containers = arguments.get("include_containers", True)
            include_disabled = arguments.get("include_disabled", True)
            
            # Get all nodes
            nodes_result = await client.get("/nodes")
            all_firewall_rules = []
            
            for node_info in nodes_result.get("data", []):
                node = node_info["node"]
                
                # Get VMs firewall rules
                try:
                    vms_result = await client.get(f"/nodes/{node}/qemu")
                    for vm in vms_result.get("data", []):
                        vmid = vm["vmid"]
                        try:
                            # Get firewall rules
                            firewall_result = await client.get(f"/nodes/{node}/qemu/{vmid}/firewall/rules")
                            
                            # Get firewall options
                            firewall_options = {}
                            try:
                                options_result = await client.get(f"/nodes/{node}/qemu/{vmid}/firewall/options")
                                firewall_options = options_result.get("data", {})
                            except Exception as e:
                                logger.warning(f"Cannot get firewall options for VM {vmid} on node {node}: {e}")
                                firewall_options = {"error": str(e)}
                            
                            if firewall_result.get("data"):
                                rules = firewall_result["data"]
                                if not include_disabled:
                                    rules = [rule for rule in rules if rule.get("enable", 1) == 1]
                                
                                if rules or firewall_options:  # Add if there are rules or options
                                    all_firewall_rules.append({
                                        "node": node,
                                        "vmid": vmid,
                                        "name": vm.get("name", f"VM-{vmid}"),
                                        "type": "qemu",
                                        "status": vm.get("status", "unknown"),
                                        "firewall_rules": rules,
                                        "firewall_options": firewall_options,
                                        "rule_count": len(rules)
                                    })
                        except Exception as e:
                            logger.warning(f"Cannot get firewall rules for VM {vmid} on node {node}: {e}")
                except Exception as e:
                    logger.warning(f"Cannot get VMs from node {node}: {e}")
                
                # Get containers firewall rules
                if include_containers:
                    try:
                        containers_result = await client.get(f"/nodes/{node}/lxc")
                        for container in containers_result.get("data", []):
                            vmid = container["vmid"]
                            try:
                                # Get firewall rules
                                firewall_result = await client.get(f"/nodes/{node}/lxc/{vmid}/firewall/rules")
                                
                                # Get firewall options
                                firewall_options = {}
                                try:
                                    options_result = await client.get(f"/nodes/{node}/lxc/{vmid}/firewall/options")
                                    firewall_options = options_result.get("data", {})
                                except Exception as e:
                                    logger.warning(f"Cannot get firewall options for container {vmid} on node {node}: {e}")
                                    firewall_options = {"error": str(e)}
                                
                                if firewall_result.get("data"):
                                    rules = firewall_result["data"]
                                    if not include_disabled:
                                        rules = [rule for rule in rules if rule.get("enable", 1) == 1]
                                    
                                    if rules or firewall_options:  # Add if there are rules or options
                                        all_firewall_rules.append({
                                            "node": node,
                                            "vmid": vmid,
                                            "name": container.get("name", f"CT-{vmid}"),
                                            "type": "lxc",
                                            "status": container.get("status", "unknown"),
                                            "firewall_rules": rules,
                                            "firewall_options": firewall_options,
                                            "rule_count": len(rules)
                                        })
                            except Exception as e:
                                logger.warning(f"Cannot get firewall rules for container {vmid} on node {node}: {e}")
                    except Exception as e:
                        logger.warning(f"Cannot get containers from node {node}: {e}")
            
            return {
                "data": all_firewall_rules,
                "summary": {
                    "total_entries": len(all_firewall_rules),
                    "nodes_scanned": len(nodes_result.get("data", [])),
                    "include_containers": include_containers,
                    "include_disabled": include_disabled
                }
            }
        
        elif name == "get_all_vm_status_history":
            include_containers = arguments.get("include_containers", True)
            limit_per_vm = arguments.get("limit_per_vm", 50)
            
            # Get all nodes
            nodes_result = await client.get("/nodes")
            all_status_history = []
            
            for node_info in nodes_result.get("data", []):
                node = node_info["node"]
                
                # Get VM status history
                try:
                    vms_result = await client.get(f"/nodes/{node}/qemu")
                    for vm in vms_result.get("data", []):
                        vmid = vm["vmid"]
                        try:
                            # Get task history for this VM (includes start/stop operations)
                            tasks_result = await client.get(f"/nodes/{node}/tasks", {
                                "limit": limit_per_vm,
                                "vmid": vmid
                            })
                            
                            power_operations = []
                            for task in tasks_result.get("data", []):
                                task_type = task.get("type", "")
                                if task_type in ["qmstart", "qmstop", "qmshutdown", "qmreboot", "qmreset"]:
                                    power_operations.append({
                                        "operation": task_type,
                                        "status": task.get("status", "unknown"),
                                        "starttime": task.get("starttime"),
                                        "endtime": task.get("endtime"),
                                        "user": task.get("user", ""),
                                        "upid": task.get("upid", "")
                                    })
                            
                            if power_operations:
                                all_status_history.append({
                                    "node": node,
                                    "vmid": vmid,
                                    "name": vm.get("name", f"VM-{vmid}"),
                                    "type": "qemu",
                                    "current_status": vm.get("status", "unknown"),
                                    "power_operations": power_operations,
                                    "operation_count": len(power_operations)
                                })
                        except Exception as e:
                            logger.warning(f"Cannot get status history for VM {vmid} on node {node}: {e}")
                except Exception as e:
                    logger.warning(f"Cannot get VMs from node {node}: {e}")
                
                # Get container status history
                if include_containers:
                    try:
                        containers_result = await client.get(f"/nodes/{node}/lxc")
                        for container in containers_result.get("data", []):
                            vmid = container["vmid"]
                            try:
                                tasks_result = await client.get(f"/nodes/{node}/tasks", {
                                    "limit": limit_per_vm,
                                    "vmid": vmid
                                })
                                
                                power_operations = []
                                for task in tasks_result.get("data", []):
                                    task_type = task.get("type", "")
                                    if task_type in ["vzstart", "vzstop", "vzshutdown", "vzreboot"]:
                                        power_operations.append({
                                            "operation": task_type,
                                            "status": task.get("status", "unknown"),
                                            "starttime": task.get("starttime"),
                                            "endtime": task.get("endtime"),
                                            "user": task.get("user", ""),
                                            "upid": task.get("upid", "")
                                        })
                                
                                if power_operations:
                                    all_status_history.append({
                                        "node": node,
                                        "vmid": vmid,
                                        "name": container.get("name", f"CT-{vmid}"),
                                        "type": "lxc",
                                        "current_status": container.get("status", "unknown"),
                                        "power_operations": power_operations,
                                        "operation_count": len(power_operations)
                                    })
                            except Exception as e:
                                logger.warning(f"Cannot get status history for container {vmid} on node {node}: {e}")
                    except Exception as e:
                        logger.warning(f"Cannot get containers from node {node}: {e}")
            
            return {
                "data": all_status_history,
                "summary": {
                    "total_entries": len(all_status_history),
                    "nodes_scanned": len(nodes_result.get("data", [])),
                    "include_containers": include_containers,
                    "limit_per_vm": limit_per_vm
                }
            }
        
        elif name == "get_all_operation_logs":
            include_node_logs = arguments.get("include_node_logs", True)
            include_vm_logs = arguments.get("include_vm_logs", True)
            include_container_logs = arguments.get("include_container_logs", True)
            limit_per_source = arguments.get("limit_per_source", 100)
            since_hours = arguments.get("since_hours", 24)
            
            since_timestamp = int(time.time()) - (since_hours * 3600)
            
            # Get all nodes
            nodes_result = await client.get("/nodes")
            all_operation_logs = []
            
            for node_info in nodes_result.get("data", []):
                node = node_info["node"]
                
                # Get node-level logs
                if include_node_logs:
                    try:
                        node_tasks = await client.get(f"/nodes/{node}/tasks", {
                            "limit": limit_per_source,
                            "since": since_timestamp
                        })
                        
                        for task in node_tasks.get("data", []):
                            if task.get("starttime", 0) >= since_timestamp:
                                all_operation_logs.append({
                                    "source_type": "node",
                                    "source_name": node,
                                    "node": node,
                                    "vmid": task.get("id"),
                                    "operation": task.get("type", ""),
                                    "status": task.get("status", "unknown"),
                                    "starttime": task.get("starttime"),
                                    "endtime": task.get("endtime"),
                                    "user": task.get("user", ""),
                                    "upid": task.get("upid", ""),
                                    "log_entry": task
                                })
                    except Exception as e:
                        logger.warning(f"Cannot get node logs from {node}: {e}")
                
                # Get VM-specific logs
                if include_vm_logs:
                    try:
                        vms_result = await client.get(f"/nodes/{node}/qemu")
                        for vm in vms_result.get("data", []):
                            vmid = vm["vmid"]
                            try:
                                vm_tasks = await client.get(f"/nodes/{node}/tasks", {
                                    "limit": limit_per_source // 10,
                                    "vmid": vmid,
                                    "since": since_timestamp
                                })
                                
                                for task in vm_tasks.get("data", []):
                                    if task.get("starttime", 0) >= since_timestamp:
                                        all_operation_logs.append({
                                            "source_type": "vm",
                                            "source_name": vm.get("name", f"VM-{vmid}"),
                                            "node": node,
                                            "vmid": vmid,
                                            "operation": task.get("type", ""),
                                            "status": task.get("status", "unknown"),
                                            "starttime": task.get("starttime"),
                                            "endtime": task.get("endtime"),
                                            "user": task.get("user", ""),
                                            "upid": task.get("upid", ""),
                                            "log_entry": task
                                        })
                            except Exception as e:
                                logger.warning(f"Cannot get logs for VM {vmid} on node {node}: {e}")
                    except Exception as e:
                        logger.warning(f"Cannot get VMs from node {node}: {e}")
                
                # Get container-specific logs
                if include_container_logs:
                    try:
                        containers_result = await client.get(f"/nodes/{node}/lxc")
                        for container in containers_result.get("data", []):
                            vmid = container["vmid"]
                            try:
                                ct_tasks = await client.get(f"/nodes/{node}/tasks", {
                                    "limit": limit_per_source // 10,
                                    "vmid": vmid,
                                    "since": since_timestamp
                                })
                                
                                for task in ct_tasks.get("data", []):
                                    if task.get("starttime", 0) >= since_timestamp:
                                        all_operation_logs.append({
                                            "source_type": "container",
                                            "source_name": container.get("name", f"CT-{vmid}"),
                                            "node": node,
                                            "vmid": vmid,
                                            "operation": task.get("type", ""),
                                            "status": task.get("status", "unknown"),
                                            "starttime": task.get("starttime"),
                                            "endtime": task.get("endtime"),
                                            "user": task.get("user", ""),
                                            "upid": task.get("upid", ""),
                                            "log_entry": task
                                        })
                            except Exception as e:
                                logger.warning(f"Cannot get logs for container {vmid} on node {node}: {e}")
                    except Exception as e:
                        logger.warning(f"Cannot get containers from node {node}: {e}")
            
            # Sort by starttime (newest first)
            all_operation_logs.sort(key=lambda x: x.get("starttime", 0), reverse=True)
            
            return {
                "data": all_operation_logs,
                "summary": {
                    "total_entries": len(all_operation_logs),
                    "nodes_scanned": len(nodes_result.get("data", [])),
                    "since_hours": since_hours,
                    "include_node_logs": include_node_logs,
                    "include_vm_logs": include_vm_logs,
                    "include_container_logs": include_container_logs
                }
            }
        
        elif name == "get_all_snapshots":
            include_containers = arguments.get("include_containers", True)
            include_details = arguments.get("include_details", False)
            
            # Get all nodes
            nodes_result = await client.get("/nodes")
            all_snapshots = []
            
            for node_info in nodes_result.get("data", []):
                node = node_info["node"]
                
                # Get VM snapshots
                try:
                    vms_result = await client.get(f"/nodes/{node}/qemu")
                    for vm in vms_result.get("data", []):
                        vmid = vm["vmid"]
                        try:
                            snapshots_result = await client.get(f"/nodes/{node}/qemu/{vmid}/snapshot")
                            snapshots = snapshots_result.get("data", [])
                            
                            if snapshots:
                                snapshot_info = {
                                    "node": node,
                                    "vmid": vmid,
                                    "name": vm.get("name", f"VM-{vmid}"),
                                    "type": "qemu",
                                    "status": vm.get("status", "unknown"),
                                    "snapshot_count": len(snapshots),
                                    "snapshots": []
                                }
                                
                                for snapshot in snapshots:
                                    snap_data = {
                                        "name": snapshot.get("name", ""),
                                        "description": snapshot.get("description", ""),
                                        "snaptime": snapshot.get("snaptime")
                                    }
                                    
                                    if include_details:
                                        snap_data.update({
                                            "vmstate": snapshot.get("vmstate", 0),
                                            "parent": snapshot.get("parent", ""),
                                            "running": snapshot.get("running", 0)
                                        })
                                    
                                    snapshot_info["snapshots"].append(snap_data)
                                
                                all_snapshots.append(snapshot_info)
                        except Exception as e:
                            logger.warning(f"Cannot get snapshots for VM {vmid} on node {node}: {e}")
                except Exception as e:
                    logger.warning(f"Cannot get VMs from node {node}: {e}")
                
                # Get container snapshots
                if include_containers:
                    try:
                        containers_result = await client.get(f"/nodes/{node}/lxc")
                        for container in containers_result.get("data", []):
                            vmid = container["vmid"]
                            try:
                                snapshots_result = await client.get(f"/nodes/{node}/lxc/{vmid}/snapshot")
                                snapshots = snapshots_result.get("data", [])
                                
                                if snapshots:
                                    snapshot_info = {
                                        "node": node,
                                        "vmid": vmid,
                                        "name": container.get("name", f"CT-{vmid}"),
                                        "type": "lxc",
                                        "status": container.get("status", "unknown"),
                                        "snapshot_count": len(snapshots),
                                        "snapshots": []
                                    }
                                    
                                    for snapshot in snapshots:
                                        snap_data = {
                                            "name": snapshot.get("name", ""),
                                            "description": snapshot.get("description", ""),
                                            "snaptime": snapshot.get("snaptime")
                                        }
                                        
                                        if include_details:
                                            snap_data.update({
                                                "parent": snapshot.get("parent", "")
                                            })
                                        
                                        snapshot_info["snapshots"].append(snap_data)
                                    
                                    all_snapshots.append(snapshot_info)
                            except Exception as e:
                                logger.warning(f"Cannot get snapshots for container {vmid} on node {node}: {e}")
                    except Exception as e:
                        logger.warning(f"Cannot get containers from node {node}: {e}")
            
            total_snapshots = sum(item["snapshot_count"] for item in all_snapshots)
            
            return {
                "data": all_snapshots,
                "summary": {
                    "total_vms_with_snapshots": len(all_snapshots),
                    "total_snapshots": total_snapshots,
                    "nodes_scanned": len(nodes_result.get("data", [])),
                    "include_containers": include_containers,
                    "include_details": include_details
                }
            }
        
        elif name == "get_all_vm_configs":
            include_containers = arguments.get("include_containers", True)
            include_hardware_info = arguments.get("include_hardware_info", True)
            
            # Get all nodes
            nodes_result = await client.get("/nodes")
            all_configs = []
            
            for node_info in nodes_result.get("data", []):
                node = node_info["node"]
                
                # Get VM configurations
                try:
                    vms_result = await client.get(f"/nodes/{node}/qemu")
                    for vm in vms_result.get("data", []):
                        vmid = vm["vmid"]
                        try:
                            config_result = await client.get(f"/nodes/{node}/qemu/{vmid}/config")
                            config_data = config_result.get("data", {})
                            
                            vm_config = {
                                "node": node,
                                "vmid": vmid,
                                "name": vm.get("name", config_data.get("name", f"VM-{vmid}")),
                                "type": "qemu",
                                "status": vm.get("status", "unknown"),
                                "configuration": config_data
                            }
                            
                            if include_hardware_info:
                                vm_config["hardware_summary"] = {
                                    "cores": config_data.get("cores", 1),
                                    "memory": config_data.get("memory", 512),
                                    "sockets": config_data.get("sockets", 1),
                                    "cpu": config_data.get("cpu", "kvm64"),
                                    "ostype": config_data.get("ostype", "l26"),
                                    "machine": config_data.get("machine", "pc"),
                                    "bios": config_data.get("bios", "seabios"),
                                    "balloon": config_data.get("balloon", 0),
                                    "boot": config_data.get("boot", ""),
                                    "agent": config_data.get("agent", 0),
                                    "protection": config_data.get("protection", 0)
                                }
                                
                                # Extract storage information
                                storage_devices = {}
                                for key, value in config_data.items():
                                    if key.startswith(('scsi', 'ide', 'sata', 'virtio')):
                                        storage_devices[key] = value
                                vm_config["storage_devices"] = storage_devices
                                
                                # Extract network information
                                network_devices = {}
                                for key, value in config_data.items():
                                    if key.startswith('net'):
                                        network_devices[key] = value
                                vm_config["network_devices"] = network_devices
                            
                            all_configs.append(vm_config)
                        except Exception as e:
                            logger.warning(f"Cannot get config for VM {vmid} on node {node}: {e}")
                except Exception as e:
                    logger.warning(f"Cannot get VMs from node {node}: {e}")
                
                # Get container configurations
                if include_containers:
                    try:
                        containers_result = await client.get(f"/nodes/{node}/lxc")
                        for container in containers_result.get("data", []):
                            vmid = container["vmid"]
                            try:
                                config_result = await client.get(f"/nodes/{node}/lxc/{vmid}/config")
                                config_data = config_result.get("data", {})
                                
                                ct_config = {
                                    "node": node,
                                    "vmid": vmid,
                                    "name": container.get("name", config_data.get("hostname", f"CT-{vmid}")),
                                    "type": "lxc",
                                    "status": container.get("status", "unknown"),
                                    "configuration": config_data
                                }
                                
                                if include_hardware_info:
                                    ct_config["hardware_summary"] = {
                                        "cores": config_data.get("cores", 1),
                                        "memory": config_data.get("memory", 512),
                                        "swap": config_data.get("swap", 512),
                                        "hostname": config_data.get("hostname", ""),
                                        "ostype": config_data.get("ostype", ""),
                                        "arch": config_data.get("arch", "amd64"),
                                        "unprivileged": config_data.get("unprivileged", 1),
                                        "protection": config_data.get("protection", 0),
                                        "onboot": config_data.get("onboot", 0)
                                    }
                                    
                                    # Extract storage information
                                    storage_devices = {}
                                    for key, value in config_data.items():
                                        if key.startswith(('rootfs', 'mp')):
                                            storage_devices[key] = value
                                    ct_config["storage_devices"] = storage_devices
                                    
                                    # Extract network information
                                    network_devices = {}
                                    for key, value in config_data.items():
                                        if key.startswith('net'):
                                            network_devices[key] = value
                                    ct_config["network_devices"] = network_devices
                                
                                all_configs.append(ct_config)
                            except Exception as e:
                                logger.warning(f"Cannot get config for container {vmid} on node {node}: {e}")
                    except Exception as e:
                        logger.warning(f"Cannot get containers from node {node}: {e}")
            
            return {
                "data": all_configs,
                "summary": {
                    "total_entries": len(all_configs),
                    "nodes_scanned": len(nodes_result.get("data", [])),
                    "include_containers": include_containers,
                    "include_hardware_info": include_hardware_info,
                    "vm_count": len([c for c in all_configs if c["type"] == "qemu"]),
                    "container_count": len([c for c in all_configs if c["type"] == "lxc"])
                }
            }
        
        elif name == "get_all_backup_status":
            include_containers = arguments.get("include_containers", True)
            include_job_history = arguments.get("include_job_history", True)
            
            # Get all nodes
            nodes_result = await client.get("/nodes")
            all_backup_status = []
            
            # Get backup jobs configuration
            backup_jobs = {}
            try:
                jobs_result = await client.get("/cluster/backup")
                for job in jobs_result.get("data", []):
                    job_id = job.get("id", "")
                    backup_jobs[job_id] = job
            except Exception as e:
                logger.warning(f"Cannot get backup jobs: {e}")
            
            for node_info in nodes_result.get("data", []):
                node = node_info["node"]
                
                # Get storage information to find backup storages
                backup_storages = []
                try:
                    storage_result = await client.get(f"/nodes/{node}/storage")
                    for storage in storage_result.get("data", []):
                        content = storage.get("content", "")
                        if "backup" in content.split(","):
                            backup_storages.append(storage["storage"])
                except Exception as e:
                    logger.warning(f"Cannot get storage info from node {node}: {e}")
                
                # Get VM backup status
                try:
                    vms_result = await client.get(f"/nodes/{node}/qemu")
                    for vm in vms_result.get("data", []):
                        vmid = vm["vmid"]
                        
                        vm_backup_info = {
                            "node": node,
                            "vmid": vmid,
                            "name": vm.get("name", f"VM-{vmid}"),
                            "type": "qemu",
                            "status": vm.get("status", "unknown"),
                            "backup_files": [],
                            "backup_jobs": [],
                            "last_backup": None
                        }
                        
                        # Check backup files in each backup storage
                        for storage in backup_storages:
                            try:
                                backups_result = await client.get(f"/nodes/{node}/storage/{storage}/content", {
                                    "content": "backup",
                                    "vmid": vmid
                                })
                                
                                for backup in backups_result.get("data", []):
                                    vm_backup_info["backup_files"].append({
                                        "storage": storage,
                                        "filename": backup.get("volid", ""),
                                        "size": backup.get("size", 0),
                                        "format": backup.get("format", ""),
                                        "ctime": backup.get("ctime", 0)
                                    })
                            except Exception as e:
                                logger.warning(f"Cannot get backups for VM {vmid} from storage {storage}: {e}")
                        
                        # Sort backup files by creation time
                        if vm_backup_info["backup_files"]:
                            vm_backup_info["backup_files"].sort(key=lambda x: x.get("ctime", 0), reverse=True)
                            vm_backup_info["last_backup"] = vm_backup_info["backup_files"][0]
                        
                        # Find applicable backup jobs
                        for job_id, job in backup_jobs.items():
                            job_vmids = job.get("vmid", "").split(",")
                            if str(vmid) in job_vmids or "all" in job_vmids:
                                vm_backup_info["backup_jobs"].append({
                                    "job_id": job_id,
                                    "enabled": job.get("enabled", 1),
                                    "schedule": job.get("schedule", ""),
                                    "storage": job.get("storage", ""),
                                    "mode": job.get("mode", "snapshot")
                                })
                        
                        if vm_backup_info["backup_files"] or vm_backup_info["backup_jobs"]:
                            all_backup_status.append(vm_backup_info)
                except Exception as e:
                    logger.warning(f"Cannot get VMs from node {node}: {e}")
                
                # Get container backup status
                if include_containers:
                    try:
                        containers_result = await client.get(f"/nodes/{node}/lxc")
                        for container in containers_result.get("data", []):
                            vmid = container["vmid"]
                            
                            ct_backup_info = {
                                "node": node,
                                "vmid": vmid,
                                "name": container.get("name", f"CT-{vmid}"),
                                "type": "lxc",
                                "status": container.get("status", "unknown"),
                                "backup_files": [],
                                "backup_jobs": [],
                                "last_backup": None
                            }
                            
                            # Check backup files in each backup storage
                            for storage in backup_storages:
                                try:
                                    backups_result = await client.get(f"/nodes/{node}/storage/{storage}/content", {
                                        "content": "backup",
                                        "vmid": vmid
                                    })
                                    
                                    for backup in backups_result.get("data", []):
                                        ct_backup_info["backup_files"].append({
                                            "storage": storage,
                                            "filename": backup.get("volid", ""),
                                            "size": backup.get("size", 0),
                                            "format": backup.get("format", ""),
                                            "ctime": backup.get("ctime", 0)
                                        })
                                except Exception as e:
                                    logger.warning(f"Cannot get backups for container {vmid} from storage {storage}: {e}")
                            
                            # Sort backup files by creation time
                            if ct_backup_info["backup_files"]:
                                ct_backup_info["backup_files"].sort(key=lambda x: x.get("ctime", 0), reverse=True)
                                ct_backup_info["last_backup"] = ct_backup_info["backup_files"][0]
                            
                            # Find applicable backup jobs
                            for job_id, job in backup_jobs.items():
                                job_vmids = job.get("vmid", "").split(",")
                                if str(vmid) in job_vmids or "all" in job_vmids:
                                    ct_backup_info["backup_jobs"].append({
                                        "job_id": job_id,
                                        "enabled": job.get("enabled", 1),
                                        "schedule": job.get("schedule", ""),
                                        "storage": job.get("storage", ""),
                                        "mode": job.get("mode", "snapshot")
                                    })
                            
                            if ct_backup_info["backup_files"] or ct_backup_info["backup_jobs"]:
                                all_backup_status.append(ct_backup_info)
                    except Exception as e:
                        logger.warning(f"Cannot get containers from node {node}: {e}")
            
            # Calculate summary statistics
            total_backup_files = sum(len(item["backup_files"]) for item in all_backup_status)
            vms_with_backups = len([item for item in all_backup_status if item["type"] == "qemu" and item["backup_files"]])
            containers_with_backups = len([item for item in all_backup_status if item["type"] == "lxc" and item["backup_files"]])
            
            return {
                "data": all_backup_status,
                "backup_jobs": list(backup_jobs.values()) if include_job_history else [],
                "summary": {
                    "total_entries": len(all_backup_status),
                    "total_backup_files": total_backup_files,
                    "vms_with_backups": vms_with_backups,
                    "containers_with_backups": containers_with_backups,
                    "backup_jobs_count": len(backup_jobs),
                    "nodes_scanned": len(nodes_result.get("data", [])),
                    "include_containers": include_containers,
                    "include_job_history": include_job_history
                }
            }
        
        elif name == "get_all_performance_stats":
            include_containers = arguments.get("include_containers", True)
            timeframe = arguments.get("timeframe", "hour")
            include_node_stats = arguments.get("include_node_stats", True)
            
            # Get all nodes
            nodes_result = await client.get("/nodes")
            all_performance_stats = []
            
            for node_info in nodes_result.get("data", []):
                node = node_info["node"]
                
                # Get node performance stats
                if include_node_stats:
                    try:
                        node_stats = await client.get(f"/nodes/{node}/rrddata", {"timeframe": timeframe})
                        all_performance_stats.append({
                            "source_type": "node",
                            "source_name": node,
                            "node": node,
                            "vmid": None,
                            "performance_data": node_stats.get("data", []),
                            "data_points": len(node_stats.get("data", [])),
                            "timeframe": timeframe
                        })
                    except Exception as e:
                        logger.warning(f"Cannot get performance stats for node {node}: {e}")
                
                # Get VM performance stats
                try:
                    vms_result = await client.get(f"/nodes/{node}/qemu")
                    for vm in vms_result.get("data", []):
                        vmid = vm["vmid"]
                        try:
                            vm_stats = await client.get(f"/nodes/{node}/qemu/{vmid}/rrddata", {"timeframe": timeframe})
                            all_performance_stats.append({
                                "source_type": "vm",
                                "source_name": vm.get("name", f"VM-{vmid}"),
                                "node": node,
                                "vmid": vmid,
                                "performance_data": vm_stats.get("data", []),
                                "data_points": len(vm_stats.get("data", [])),
                                "timeframe": timeframe
                            })
                        except Exception as e:
                            logger.warning(f"Cannot get performance stats for VM {vmid} on node {node}: {e}")
                except Exception as e:
                    logger.warning(f"Cannot get VMs from node {node}: {e}")
                
                # Get container performance stats
                if include_containers:
                    try:
                        containers_result = await client.get(f"/nodes/{node}/lxc")
                        for container in containers_result.get("data", []):
                            vmid = container["vmid"]
                            try:
                                ct_stats = await client.get(f"/nodes/{node}/lxc/{vmid}/rrddata", {"timeframe": timeframe})
                                all_performance_stats.append({
                                    "source_type": "container",
                                    "source_name": container.get("name", f"CT-{vmid}"),
                                    "node": node,
                                    "vmid": vmid,
                                    "performance_data": ct_stats.get("data", []),
                                    "data_points": len(ct_stats.get("data", [])),
                                    "timeframe": timeframe
                                })
                            except Exception as e:
                                logger.warning(f"Cannot get performance stats for container {vmid} on node {node}: {e}")
                    except Exception as e:
                        logger.warning(f"Cannot get containers from node {node}: {e}")
            
            total_data_points = sum(item["data_points"] for item in all_performance_stats)
            node_stats_count = len([item for item in all_performance_stats if item["source_type"] == "node"])
            vm_stats_count = len([item for item in all_performance_stats if item["source_type"] == "vm"])
            container_stats_count = len([item for item in all_performance_stats if item["source_type"] == "container"])
            
            return {
                "data": all_performance_stats,
                "summary": {
                    "total_sources": len(all_performance_stats),
                    "total_data_points": total_data_points,
                    "node_stats_count": node_stats_count,
                    "vm_stats_count": vm_stats_count,
                    "container_stats_count": container_stats_count,
                    "timeframe": timeframe,
                    "nodes_scanned": len(nodes_result.get("data", [])),
                    "include_containers": include_containers,
                    "include_node_stats": include_node_stats
                }
            }
        
        elif name == "get_cluster_overview":
            include_detailed_stats = arguments.get("include_detailed_stats", False)
            include_logs = arguments.get("include_logs", True)
            
            cluster_overview = {}
            
            # Get cluster status
            try:
                cluster_status = await client.get("/cluster/status")
                cluster_overview["cluster_status"] = cluster_status.get("data", [])
            except Exception as e:
                cluster_overview["cluster_status_error"] = str(e)
            
            # Get all nodes
            try:
                nodes_result = await client.get("/nodes")
                cluster_overview["nodes"] = []
                
                total_memory = 0
                total_memory_used = 0
                total_cpu_cores = 0
                total_cpu_usage = 0.0
                total_vms = 0
                total_containers = 0
                
                for node_info in nodes_result.get("data", []):
                    node = node_info["node"]
                    
                    # Get detailed node status
                    try:
                        node_status = await client.get(f"/nodes/{node}/status")
                        node_data = node_status.get("data", {})
                        
                        # Calculate totals
                        memory = node_data.get("memory", {})
                        total_memory += memory.get("total", 0)
                        total_memory_used += memory.get("used", 0)
                        
                        cpu_info = node_data.get("cpu", 0)
                        cpuinfo = node_data.get("cpuinfo", {})
                        cores = cpuinfo.get("cores", 1)
                        total_cpu_cores += cores
                        total_cpu_usage += cpu_info * cores
                        
                        # Get VMs and containers count
                        try:
                            vms_result = await client.get(f"/nodes/{node}/qemu")
                            node_vms = len(vms_result.get("data", []))
                            total_vms += node_vms
                        except:
                            node_vms = 0
                        
                        try:
                            containers_result = await client.get(f"/nodes/{node}/lxc")
                            node_containers = len(containers_result.get("data", []))
                            total_containers += node_containers
                        except:
                            node_containers = 0
                        
                        node_overview = {
                            "node": node,
                            "status": node_data.get("pveversion", "unknown"),
                            "uptime": node_data.get("uptime", 0),
                            "cpu_usage": cpu_info,
                            "cpu_cores": cores,
                            "memory_total": memory.get("total", 0),
                            "memory_used": memory.get("used", 0),
                            "memory_percentage": (memory.get("used", 0) / memory.get("total", 1)) * 100,
                            "vm_count": node_vms,
                            "container_count": node_containers,
                            "loadavg": node_data.get("loadavg", [])
                        }
                        
                        if include_detailed_stats:
                            # Get storage info
                            try:
                                storage_result = await client.get(f"/nodes/{node}/storage")
                                node_overview["storage"] = storage_result.get("data", [])
                            except:
                                node_overview["storage"] = []
                            
                            # Get network interfaces
                            try:
                                network_result = await client.get(f"/nodes/{node}/network")
                                node_overview["network_interfaces"] = network_result.get("data", [])
                            except:
                                node_overview["network_interfaces"] = []
                        
                        cluster_overview["nodes"].append(node_overview)
                    except Exception as e:
                        cluster_overview["nodes"].append({
                            "node": node,
                            "error": str(e)
                        })
                
                # Calculate cluster-wide statistics
                cluster_overview["cluster_summary"] = {
                    "total_nodes": len(nodes_result.get("data", [])),
                    "total_vms": total_vms,
                    "total_containers": total_containers,
                    "total_memory_gb": round(total_memory / (1024**3), 2),
                    "total_memory_used_gb": round(total_memory_used / (1024**3), 2),
                    "memory_usage_percentage": round((total_memory_used / total_memory) * 100, 2) if total_memory > 0 else 0,
                    "total_cpu_cores": total_cpu_cores,
                    "average_cpu_usage": round(total_cpu_usage / total_cpu_cores, 2) if total_cpu_cores > 0 else 0
                }
                
            except Exception as e:
                cluster_overview["nodes_error"] = str(e)
            
            # Get cluster logs
            if include_logs:
                try:
                    logs_result = await client.get("/cluster/tasks", {"limit": 50})
                    cluster_overview["recent_tasks"] = logs_result.get("data", [])
                except Exception as e:
                    cluster_overview["logs_error"] = str(e)
            
            # Get backup jobs
            try:
                backup_jobs = await client.get("/cluster/backup")
                cluster_overview["backup_jobs"] = backup_jobs.get("data", [])
            except Exception as e:
                cluster_overview["backup_jobs_error"] = str(e)
            
            # Get HA status
            try:
                ha_status = await client.get("/cluster/ha/status/current")
                cluster_overview["ha_status"] = ha_status.get("data", [])
            except Exception as e:
                cluster_overview["ha_status_error"] = str(e)
            
            return {
                "data": cluster_overview,
                "summary": {
                    "include_detailed_stats": include_detailed_stats,
                    "include_logs": include_logs,
                    "generation_time": int(time.time())
                }
            }
        elif name == "get_cluster_status":
            return await client.get("/cluster/status")
        
        elif name == "get_cluster_nodes":
            return await client.get("/nodes")
        
        elif name == "get_node_status":
            node = arguments["node"]
            return await client.get(f"/nodes/{node}/status")
        
        elif name == "get_node_resources":
            node = arguments["node"]
            return await client.get(f"/nodes/{node}/resources")
        
        elif name == "get_node_tasks":
            node = arguments["node"]
            limit = arguments.get("limit", 50)
            return await client.get(f"/nodes/{node}/tasks", {"limit": limit})
        
        elif name == "list_vms":
            if "node" in arguments:
                node = arguments["node"]
                return await client.get(f"/nodes/{node}/qemu")
            else:
                nodes_result = await client.get("/nodes")
                all_vms = []
                for node_info in nodes_result.get("data", []):
                    node = node_info["node"]
                    try:
                        vms_result = await client.get(f"/nodes/{node}/qemu")
                        if vms_result.get("data"):
                            for vm in vms_result["data"]:
                                vm["node"] = node
                            all_vms.extend(vms_result["data"])
                    except Exception as e:
                        logger.warning(f"Cannot get VMs from node {node}: {e}")
                return {"data": all_vms}
        
        elif name == "get_vm_status":
            node = arguments["node"]
            vmid = arguments["vmid"]
            return await client.get(f"/nodes/{node}/qemu/{vmid}/status/current")
        
        elif name == "get_vm_config":
            node = arguments["node"]
            vmid = arguments["vmid"]
            return await client.get(f"/nodes/{node}/qemu/{vmid}/config")
        
        elif name == "get_vm_snapshots":
            node = arguments["node"]
            vmid = arguments["vmid"]
            return await client.get(f"/nodes/{node}/qemu/{vmid}/snapshot")
        
        else:
            raise ProxmoxVEError(f"Tool '{name}' is not implemented. This should not happen as all tools are now implemented.")

def parse_args():
    """Parse command line arguments with enhanced validation"""
    args = sys.argv[1:]
    config = {
        'host': os.getenv("PVE_HOST", ""),
        'username': os.getenv("PVE_USERNAME", ""),
        'password': os.getenv("PVE_PASSWORD", ""),
        'api_token_id': os.getenv("PVE_API_TOKEN_ID", ""),
        'api_token_secret': os.getenv("PVE_API_TOKEN_SECRET", ""),
        'verify_ssl': os.getenv("PVE_VERIFY_SSL", "false").lower() in ("true", "1", "yes"),
        'timeout': float(os.getenv("PVE_TIMEOUT", "30")),
        'test': False,
        'help': False
    }
    
    i = 0
    while i < len(args):
        arg = args[i]
        
        if arg in ['-h', '--help']:
            config['help'] = True
        elif arg == '--host' and i + 1 < len(args):
            config['host'] = args[i + 1]
            i += 1
        elif arg == '--username' and i + 1 < len(args):
            config['username'] = args[i + 1]
            i += 1
        elif arg == '--password' and i + 1 < len(args):
            config['password'] = args[i + 1]
            i += 1
        elif arg == '--api-token-id' and i + 1 < len(args):
            config['api_token_id'] = args[i + 1]
            i += 1
        elif arg == '--api-token-secret' and i + 1 < len(args):
            config['api_token_secret'] = args[i + 1]
            i += 1
        elif arg == '--verify-ssl':
            config['verify_ssl'] = True
        elif arg == '--test':
            config['test'] = True
        
        i += 1
    
    return config

async def main():
    """Main function with enhanced error handling and logging"""
    try:
        global pve_config
        
        # Parse command line arguments
        config = parse_args()
        
        # Show help message
        if config['help']:
            print("Proxmox VE MCP Server - Enhanced Edition v1.2.1")
            print("Use environment variables PVE_HOST, PVE_USERNAME, PVE_PASSWORD")
            print("or PVE_API_TOKEN_ID, PVE_API_TOKEN_SECRET for authentication")
            return
        
        # Validate required settings
        if not config['host']:
            print("Error: PVE_HOST environment variable or --host parameter is required", file=sys.stderr)
            sys.exit(1)
        
        # Check authentication method
        has_credentials = config['username'] and config['password']
        has_api_token = config['api_token_id'] and config['api_token_secret']
        
        if not has_credentials and not has_api_token:
            print("Error: Authentication required (username/password or API token)", file=sys.stderr)
            sys.exit(1)
        
        # If using username/password but username is empty, set default
        if config['password'] and not config['username']:
            config['username'] = 'root@pam'
        
        # Validate host format
        if not config['host'].startswith(('http://', 'https://')):
            print("Error: Host must include protocol (http:// or https://)", file=sys.stderr)
            sys.exit(1)
        
        # Store config globally
        pve_config = config
        
        # Show startup information
        auth_method = "API Token" if (config['api_token_id'] and config['api_token_secret']) else "Username/Password"
        print(f"🚀 Proxmox VE MCP Server v{__version__} - Enhanced Edition starting...", file=sys.stderr)
        print(f"🔗 Host: {config['host']}", file=sys.stderr)
        print(f"🔐 Auth: {auth_method}", file=sys.stderr)
        print(f"🆕 Features: {len(await handle_list_tools())} tools available", file=sys.stderr)
        print("✅ Enhanced MCP Server ready for connections", file=sys.stderr)
        
        # Run MCP server
        from mcp.server.stdio import stdio_server
        
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="proxmox-ve-mcp",
                    server_version=__version__,
                    capabilities=server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    )
                )
            )
            
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
