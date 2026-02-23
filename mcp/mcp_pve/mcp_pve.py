#!/usr/bin/env python3
"""
Proxmox VE MCP Server - Enhanced Edition with Batch Operations and Pagination
Provides comprehensive Proxmox VE management functionality including batch data collection

Author: Jason Cheng (jason@jason.tools)
Version: 1.5.0
Last Updated: 2026-02-10
License: MIT
Repository: https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/mcp/mcp_pve/mcp_pve.py

Changelog:
v1.5.0 (2026-02-10) - MAJOR: Consolidate 28 VM/CT tools into 15 unified tools
         - Merged 14 pairs of VM/CT tools (get_vm_status+get_container_status, vm_start+ct_start, etc.)
         - New unified tools: get_status, get_config, get_snapshots, start, shutdown, stop, reboot,
           reset, migrate, backup, snapshot, clone, update_config, delete, get_performance
         - Auto-detect VM vs container type via resolver (_resolved_type from cluster/resources)
         - Added _resolve_type_with_fallback() helper for qemu/lxc API path selection
         - Feature toggles now checked per-type after identity resolution
         - Removed ~1050 lines of dead/duplicate code
         - Tool count reduced from 49 to 36 (27% reduction, saves LLM tokens)

v1.3.3 (2025-11-29) - Enhancement: Improved get_ceph_osd_details
         - Added node-specific endpoint /nodes/{node}/ceph/osd as primary method when node is specified
         - Improved API endpoint fallback strategy for better compatibility
         - Enhanced error diagnostics with 4 methods instead of 3
         - Fixed: Added type checking and better error handling for API responses
         - Fixed: Properly handle tree structure from /nodes/{node}/ceph/osd endpoint
         - Fixed: Added recursive tree traversal to find OSDs for specific host
         - Fixed: Support Proxmox API key-value pairs format: {"data": [{"key": "root", "value": {...}}]}
         - Fixed: Support multiple response formats (key-value pairs, tree with "root", flat list)
         - Fixed: Support querying all OSDs from all nodes when no node parameter specified
         - Added find_all_osds() helper to extract all OSDs from tree without filtering

v1.3.2 (2025-11-29) - SECURITY FIX: Implement feature toggles
         - CRITICAL: Fixed feature toggles not being enforced (security issue)
         - Added permission checking in handle_list_tools() - tools are filtered based on ENABLE_* flags
         - Added permission checking in execute_tool() - operations blocked if disabled
         - Dangerous operations now properly require ENABLE_* flags to be True
         - Clear error messages when trying to use disabled operations

v1.3.1 (2025-11-29) - Bug fixes and enhancements
         - Fixed get_ceph_osd_details error handling (improved fallback on all errors, not just 501/404)
         - Added enhanced diagnostics to get_ceph_osd_details (detailed error reporting)
         - Fixed get_storage_content HTTP 500 error (added content parameter)
         - Added filter functionality to list_vms (filter_id, filter_name, filter_status)
         - Added filter functionality to list_containers (filter_id, filter_name, filter_status)
         - Removed all Chinese text from output (English only)
         - Removed all emojis from output and startup messages
         - Documentation: Created 9 comprehensive markdown files for fixes and features

v1.3.0 - MAJOR IMPROVEMENT: Added pagination and feature toggles
         - Added feature toggle system for dangerous operations (create/modify/delete)
         - All batch operations now support pagination (limit/offset)
         - Added display_message to show pagination status
         - Enhanced tool descriptions with detailed parameter explanations
         - Added create_pagination_message() helper function
         - Prevents context overflow by limiting result sizes

v1.2.2 - Fixed get_node_resources and get_ceph_osds functions
         - get_node_resources: Now uses /cluster/resources with node filtering
         - get_ceph_osds: Enhanced with multiple endpoint fallbacks and OSD tree parsing
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
__version__ = "1.5.0"
__last_updated__ = "2026-02-10"
__author__ = "Jason Cheng"
__email__ = "jason@jason.tools"
__license__ = "MIT"

# ============================================================================
# FEATURE TOGGLES - Control which operations are available via MCP
# ============================================================================
# SAFETY: Modification operations are DISABLED by default to prevent accidents
# Set to True to enable these operations (use with caution!)

# VM/Container Creation Operations
ENABLE_VM_CREATE = False        # Allow creating new VMs
ENABLE_CT_CREATE = False        # Allow creating new containers
ENABLE_VM_CLONE = False         # Allow cloning VMs
ENABLE_CT_CLONE = False         # Allow cloning containers

# VM/Container Modification Operations
ENABLE_VM_UPDATE = False        # Allow updating VM configurations
ENABLE_CT_UPDATE = False        # Allow updating container configurations
ENABLE_VM_DELETE = False        # Allow deleting VMs
ENABLE_CT_DELETE = False        # Allow deleting containers

# VM/Container Control Operations
ENABLE_VM_START = False         # Allow starting VMs
ENABLE_VM_STOP = False          # Allow stopping VMs
ENABLE_VM_SHUTDOWN = False      # Allow shutting down VMs
ENABLE_VM_REBOOT = False        # Allow rebooting VMs
ENABLE_VM_RESET = False         # Allow resetting VMs
ENABLE_CT_START = False         # Allow starting containers
ENABLE_CT_STOP = False          # Allow stopping containers
ENABLE_CT_SHUTDOWN = False      # Allow shutting down containers
ENABLE_CT_REBOOT = False        # Allow rebooting containers

# Advanced Operations
ENABLE_VM_MIGRATE = False       # Allow migrating VMs between nodes
ENABLE_CT_MIGRATE = False       # Allow migrating containers between nodes
ENABLE_VM_BACKUP = True         # Allow creating VM backups
ENABLE_CT_BACKUP = True         # Allow creating container backups
ENABLE_VM_SNAPSHOT = True       # Allow creating VM snapshots
ENABLE_CT_SNAPSHOT = True       # Allow creating container snapshots
ENABLE_BACKUP_JOB = False       # Allow creating backup jobs

# Default pagination limits (prevent context overflow)
DEFAULT_BATCH_LIMIT = 100       # Default limit for batch operations
MAX_BATCH_LIMIT = 500          # Maximum allowed limit for batch operations
DEFAULT_LOG_LIMIT = 50         # Default limit for log entries
MAX_LOG_LIMIT = 200            # Maximum allowed limit for log entries

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("pve-mcp-server")

class ProxmoxVEError(Exception):
    """Custom exception for Proxmox VE related errors"""
    pass

# Tools that support auto-resolution of VM/container identity
# (vmid-only → auto-detect node, vmname → search by name)
TOOLS_WITH_VM_IDENTITY = {
    "get_status", "get_config", "get_snapshots",
    "start", "shutdown", "stop", "reboot", "reset",
    "migrate", "backup", "snapshot",
    "clone", "update_config", "delete",
    "get_performance", "get_firewall_rules",
}

# ============================================================================
# Helper Functions
# ============================================================================

def create_pagination_message(returned_count: int, total_count: int, has_more: bool,
                              item_type: str = "items", limit: int = None, offset: int = 0) -> str:
    """
    Create clear pagination display message for users

    Args:
        returned_count: Number of items in current response
        total_count: Total number of items available (or estimated)
        has_more: Whether more items are available
        item_type: Type of items (e.g., "VMs", "containers", "logs")
        limit: Requested limit
        offset: Current offset

    Returns:
        Human-readable pagination message in English

    Examples:
        "Showing first 100 VMs (250 total, 150 remaining)"
        "Showing items 101-200 of 500 containers"
        "Showing all 15 logs (complete)"
    """
    if offset == 0:
        if not has_more:
            return f"Showing all {returned_count} {item_type} (complete)"
        remaining = total_count - returned_count if total_count > returned_count else "unknown"
        return f"Showing first {returned_count} {item_type} ({total_count} total, {remaining} remaining)"
    else:
        start = offset + 1
        end = offset + returned_count
        if not has_more:
            return f"Showing items {start}-{end} of {total_count} {item_type} (complete)"
        return f"Showing items {start}-{end} of {total_count} {item_type} (more available)"

def validate_pagination_params(limit: Optional[int], offset: Optional[int],
                               default_limit: int, max_limit: int) -> tuple:
    """
    Validate and normalize pagination parameters

    Args:
        limit: Requested limit (or None)
        offset: Requested offset (or None)
        default_limit: Default limit if not specified
        max_limit: Maximum allowed limit

    Returns:
        Tuple of (validated_limit, validated_offset)
    """
    # Validate limit
    if limit is None:
        limit = default_limit
    elif limit < 1:
        limit = default_limit
    elif limit > max_limit:
        logger.warning(f"Requested limit {limit} exceeds maximum {max_limit}, using {max_limit}")
        limit = max_limit

    # Validate offset
    if offset is None or offset < 0:
        offset = 0

    return int(limit), int(offset)

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
        # Use proxy from environment if available (required by Claude Desktop sandbox)
        self.session = httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=httpx.Timeout(self.timeout),
            trust_env=True,  # Read proxy settings from environment
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
        import socket

        try:
            logger.info(f"Setting up API token authentication for {self.api_token_id}")

            # Network diagnostic before connection attempt
            try:
                from urllib.parse import urlparse
                parsed = urlparse(self.host)
                hostname = parsed.hostname
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)

                logger.info(f"Network diagnostic - Target: {hostname}:{port}")

                # DNS resolution test
                try:
                    ip = socket.gethostbyname(hostname)
                    logger.info(f"DNS resolved: {hostname} -> {ip}")
                except socket.gaierror as dns_err:
                    logger.error(f"DNS resolution failed for {hostname}: {dns_err}")
                    raise ProxmoxVEError(f"DNS resolution failed for {hostname}: {dns_err}")

                # TCP connection test (non-fatal, may fail in sandboxed environments)
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5.0)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    if result == 0:
                        logger.info(f"TCP connection test: {ip}:{port} - SUCCESS")
                    else:
                        logger.warning(f"TCP connection test: {ip}:{port} - FAILED (errno={result}), will try httpx anyway")
                except socket.timeout:
                    logger.warning(f"TCP connection test: {ip}:{port} - TIMEOUT, will try httpx anyway")
                except socket.error as sock_err:
                    logger.warning(f"TCP connection test failed: {sock_err}, will try httpx anyway")

            except ProxmoxVEError:
                raise
            except Exception as diag_err:
                logger.warning(f"Network diagnostic error (non-fatal): {diag_err}")

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

        except httpx.ConnectError as e:
            # Provide more detailed connection error message
            logger.error(f"Connection error details: {type(e).__name__}: {e}")
            raise ProxmoxVEError(f"Connection failed to {self.host}: {e}. Check if the host is reachable and the port is open.")
        except httpx.TimeoutException as e:
            logger.error(f"Timeout error: {e}")
            raise ProxmoxVEError(f"Connection timeout to {self.host}: {e}")
        except httpx.RequestError as e:
            logger.error(f"Request error details: {type(e).__name__}: {e}")
            raise ProxmoxVEError(f"Network error during API token setup: {e}")
        except Exception as e:
            if isinstance(e, ProxmoxVEError):
                raise
            logger.error(f"API token setup error: {type(e).__name__}: {e}")
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
server = Server("Proxmox_VE")

@server.list_tools()
async def handle_list_tools() -> List[Tool]:
    """List all available tools with comprehensive descriptions"""

    # Define tool permissions mapping for feature toggles
    # A unified tool is enabled if EITHER the VM or CT toggle is on
    tool_permissions = {
        # Creation (not unified)
        "create_vm": ENABLE_VM_CREATE,
        "create_container": ENABLE_CT_CREATE,

        # Unified tools — enabled if either VM or CT toggle is on
        "start": ENABLE_VM_START or ENABLE_CT_START,
        "shutdown": ENABLE_VM_SHUTDOWN or ENABLE_CT_SHUTDOWN,
        "stop": ENABLE_VM_STOP or ENABLE_CT_STOP,
        "reboot": ENABLE_VM_REBOOT or ENABLE_CT_REBOOT,
        "reset": ENABLE_VM_RESET,  # VM only
        "migrate": ENABLE_VM_MIGRATE or ENABLE_CT_MIGRATE,
        "backup": ENABLE_VM_BACKUP or ENABLE_CT_BACKUP,
        "snapshot": ENABLE_VM_SNAPSHOT or ENABLE_CT_SNAPSHOT,
        "clone": ENABLE_VM_CLONE or ENABLE_CT_CLONE,
        "update_config": ENABLE_VM_UPDATE or ENABLE_CT_UPDATE,
        "delete": ENABLE_VM_DELETE or ENABLE_CT_DELETE,
        "create_backup_job": ENABLE_BACKUP_JOB,
    }

    # Build complete tool list
    all_tools = [
        # NEW: Batch Operations for Data Collection
        Tool(
            name="get_all_vm_firewall_rules",
            description="Get firewall rules for all VMs and containers across all nodes. Supports pagination with limit/offset.",
            inputSchema={
                "type": "object",
                "properties": {
                    "include_containers": {"type": "boolean", "description": "Include LXC containers", "default": True},
                    "include_disabled": {"type": "boolean", "description": "Include disabled firewall rules", "default": True},
                    "limit": {"type": "integer", "description": "Maximum number of items to return (default: 100, max: 500)", "default": 100, "minimum": 1, "maximum": 500},
                    "offset": {"type": "integer", "description": "Number of items to skip for pagination", "default": 0, "minimum": 0}
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
            description="Get node resource usage including VMs, containers, and storage from cluster resources filtered by node",
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
            description="List virtual machines with optional filtering and pagination. Returns vmid, name, status, node. Use filter_name, filter_id, or filter_status to narrow results.",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name (optional - lists from all nodes if not provided)"},
                    "summary_only": {"type": "boolean", "description": "Return only essential info to prevent overflow", "default": True},
                    "limit": {"type": "integer", "description": "Maximum number of VMs to return", "default": 100, "minimum": 1, "maximum": 500},
                    "offset": {"type": "integer", "description": "Number of VMs to skip for pagination", "default": 0, "minimum": 0},
                    "filter_id": {"type": "string", "description": "Filter by VM ID (single or comma-separated, e.g., '100,101,102')"},
                    "filter_name": {"type": "string", "description": "Filter by VM name (case-insensitive partial match)"},
                    "filter_status": {"type": "string", "description": "Filter by VM status", "enum": ["running", "stopped", "paused"]}
                },
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_status",
            description="Get VM or container status. Provide node+vmid, or just vmid, or vmname.",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"},
                    "vmid": {"type": "integer", "description": "VM/container ID", "minimum": 100},
                    "vmname": {"type": "string", "description": "VM/container name (partial match, alternative to vmid)"}
                },
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_config",
            description="Get VM or container configuration. Provide node+vmid, or just vmid, or vmname.",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"},
                    "vmid": {"type": "integer", "description": "VM/container ID", "minimum": 100},
                    "vmname": {"type": "string", "description": "VM/container name (partial match, alternative to vmid)"}
                },
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_snapshots",
            description="Get VM or container snapshots. Provide node+vmid, or just vmid, or vmname.",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"},
                    "vmid": {"type": "integer", "description": "VM/container ID", "minimum": 100},
                    "vmname": {"type": "string", "description": "VM/container name (partial match, alternative to vmid)"}
                },
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
            name="clone",
            description="Clone a VM or container. Provide node+vmid, or just vmid, or vmname. Requires newid and confirm=true.",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Source node name"},
                    "vmid": {"type": "integer", "description": "Source VM/container ID", "minimum": 100},
                    "vmname": {"type": "string", "description": "VM/container name (partial match, alternative to vmid)"},
                    "newid": {"type": "integer", "description": "New ID for clone", "minimum": 100},
                    "name": {"type": "string", "description": "New name (VMs) or hostname (containers)"},
                    "description": {"type": "string", "description": "New description"},
                    "target": {"type": "string", "description": "Target node (if different from source)"},
                    "storage": {"type": "string", "description": "Target storage for clone"},
                    "format": {"type": "string", "description": "Storage format (VMs only)", "enum": ["raw", "qcow2", "vmdk"], "default": "raw"},
                    "full": {"type": "boolean", "description": "Create full clone (not linked clone)", "default": True},
                    "pool": {"type": "string", "description": "Resource pool"},
                    "snapname": {"type": "string", "description": "Snapshot name to clone from"},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "required": ["newid"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="update_config",
            description="Update VM or container configuration. Provide node+vmid, or just vmid, or vmname. Set confirm=true.",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"},
                    "vmid": {"type": "integer", "description": "VM/container ID", "minimum": 100},
                    "vmname": {"type": "string", "description": "VM/container name (partial match, alternative to vmid)"},
                    "name": {"type": "string", "description": "VM name (VMs only)"},
                    "hostname": {"type": "string", "description": "Container hostname (containers only)"},
                    "description": {"type": "string", "description": "Description"},
                    "cores": {"type": "integer", "description": "Number of CPU cores", "minimum": 1, "maximum": 128},
                    "memory": {"type": "integer", "description": "Memory in MB", "minimum": 16, "maximum": 4194304},
                    "balloon": {"type": "integer", "description": "Memory balloon in MB (VMs only)", "minimum": 0},
                    "swap": {"type": "integer", "description": "Swap in MB (containers only)", "minimum": 0, "maximum": 4194304},
                    "onboot": {"type": "integer", "description": "Start on boot", "enum": [0, 1]},
                    "agent": {"type": "integer", "description": "Enable QEMU guest agent (VMs only)", "enum": [0, 1]},
                    "protection": {"type": "integer", "description": "Prevent accidental removal", "enum": [0, 1]},
                    "tags": {"type": "string", "description": "Tags separated by semicolons"},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "additionalProperties": False
            }
        ),
        Tool(
            name="delete",
            description="Delete a VM or container permanently. Provide node+vmid, or just vmid, or vmname. Set confirm=true.",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"},
                    "vmid": {"type": "integer", "description": "VM/container ID", "minimum": 100},
                    "vmname": {"type": "string", "description": "VM/container name (partial match, alternative to vmid)"},
                    "purge": {"type": "boolean", "description": "Remove from all clusters and configs", "default": False},
                    "destroy_unreferenced_disks": {"type": "boolean", "description": "Destroy unreferenced disks", "default": True},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
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
        # clone_container, update_container_config, delete_container — unified into clone, update_config, delete
        
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
        
        # Unified VM/Container Control Operations (requires confirmation)
        Tool(
            name="start",
            description="Start a VM or container. Provide node+vmid, or just vmid, or vmname. Set confirm=true.",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"},
                    "vmid": {"type": "integer", "description": "VM/container ID", "minimum": 100},
                    "vmname": {"type": "string", "description": "VM/container name (partial match, alternative to vmid)"},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "additionalProperties": False
            }
        ),
        Tool(
            name="shutdown",
            description="Gracefully shutdown a VM or container. Provide node+vmid, or just vmid, or vmname. Set confirm=true. Prefer over stop.",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"},
                    "vmid": {"type": "integer", "description": "VM/container ID", "minimum": 100},
                    "vmname": {"type": "string", "description": "VM/container name (partial match, alternative to vmid)"},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "additionalProperties": False
            }
        ),
        Tool(
            name="stop",
            description="Force stop a VM or container (may cause data loss). Provide node+vmid, or just vmid, or vmname. Set confirm=true.",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"},
                    "vmid": {"type": "integer", "description": "VM/container ID", "minimum": 100},
                    "vmname": {"type": "string", "description": "VM/container name (partial match, alternative to vmid)"},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "additionalProperties": False
            }
        ),
        Tool(
            name="reboot",
            description="Reboot a VM or container gracefully. Provide node+vmid, or just vmid, or vmname. Set confirm=true.",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"},
                    "vmid": {"type": "integer", "description": "VM/container ID", "minimum": 100},
                    "vmname": {"type": "string", "description": "VM/container name (partial match, alternative to vmid)"},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "additionalProperties": False
            }
        ),
        Tool(
            name="reset",
            description="Reset VM forcefully via hardware reset (VMs only). Provide node+vmid, or just vmid, or vmname. Set confirm=true.",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"},
                    "vmid": {"type": "integer", "description": "VM ID", "minimum": 100},
                    "vmname": {"type": "string", "description": "VM name (partial match, alternative to vmid)"},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "additionalProperties": False
            }
        ),
        Tool(
            name="migrate",
            description="Migrate VM or container to another node. Provide node+vmid, or just vmid, or vmname. Set confirm=true.",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Source node name"},
                    "vmid": {"type": "integer", "description": "VM/container ID", "minimum": 100},
                    "vmname": {"type": "string", "description": "VM/container name (partial match, alternative to vmid)"},
                    "target": {"type": "string", "description": "Target node name"},
                    "online": {"type": "boolean", "description": "Online/live migration", "default": True},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "required": ["target"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="backup",
            description="Backup a VM or container. Provide node+vmid, or just vmid, or vmname. Requires storage and confirm=true.",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"},
                    "vmid": {"type": "integer", "description": "VM/container ID", "minimum": 100},
                    "vmname": {"type": "string", "description": "VM/container name (partial match, alternative to vmid)"},
                    "storage": {"type": "string", "description": "Backup storage name"},
                    "mode": {"type": "string", "description": "Backup mode", "enum": ["snapshot", "suspend", "stop"], "default": "snapshot"},
                    "compress": {"type": "string", "description": "Compression method", "enum": ["0", "1", "gzip", "lzo", "zstd"], "default": "zstd"},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute", "default": False}
                },
                "required": ["storage"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="snapshot",
            description="Create snapshot for a VM or container. Provide node+vmid, or just vmid, or vmname. Requires snapname and confirm=true.",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"},
                    "vmid": {"type": "integer", "description": "VM/container ID", "minimum": 100},
                    "vmname": {"type": "string", "description": "VM/container name (partial match, alternative to vmid)"},
                    "snapname": {"type": "string", "description": "Snapshot name (must be unique)"},
                    "description": {"type": "string", "description": "Snapshot description", "default": ""},
                    "vmstate": {"type": "boolean", "description": "Include VM memory state (VMs only)", "default": False},
                    "confirm": {"type": "boolean", "description": "Confirmation flag - must be true to execute"}
                },
                "required": ["snapname", "confirm"],
                "additionalProperties": False
            }
        ),
        
        # ct_start..ct_snapshot — unified into start, shutdown, stop, reboot, migrate, backup, snapshot

        # Container Management
        Tool(
            name="list_containers",
            description="List LXC containers with optional filtering and pagination. Returns vmid, name, status, node. Use filter_name, filter_id, or filter_status to narrow results.",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name (optional - lists from all nodes if not provided)"},
                    "summary_only": {"type": "boolean", "description": "Return only essential info to prevent overflow", "default": True},
                    "limit": {"type": "integer", "description": "Maximum number of containers to return", "default": 100, "minimum": 1, "maximum": 500},
                    "offset": {"type": "integer", "description": "Number of containers to skip for pagination", "default": 0, "minimum": 0},
                    "filter_id": {"type": "string", "description": "Filter by container ID (single or comma-separated, e.g., '100,101,102')"},
                    "filter_name": {"type": "string", "description": "Filter by container name (case-insensitive partial match)"},
                    "filter_status": {"type": "string", "description": "Filter by container status", "enum": ["running", "stopped", "paused"]}
                },
                "additionalProperties": False
            }
        ),
        # get_container_status, get_container_config — unified into get_status, get_config
        
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
            description="Get storage content list. Specify content type to filter results.",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"},
                    "storage": {"type": "string", "description": "Storage name"},
                    "content": {"type": "string", "description": "Content type filter", "enum": ["images", "iso", "vztmpl", "backup", "rootdir", "snippets"]}
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
            description="Get Ceph cluster health status. Set summary_only=false for full details.",
            inputSchema={
                "type": "object",
                "properties": {
                    "summary_only": {
                        "type": "boolean",
                        "description": "Return only essential health summary (default: True, safest)",
                        "default": True
                    },
                    "include_details": {
                        "type": "boolean",
                        "description": "Include full raw Ceph status (may overflow context)",
                        "default": False
                    }
                },
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_ceph_osds",
            description="Get Ceph OSD (Object Storage Daemon) status from all nodes in the cluster",
            inputSchema={
                "type": "object",
                "properties": {},
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_ceph_osd_details",
            description="Get detailed information for specific Ceph OSD(s). Specify osd_id for a single OSD or omit for all.",
            inputSchema={
                "type": "object",
                "properties": {
                    "osd_id": {"type": "integer", "description": "Specific OSD ID to query (optional - if not provided, shows all OSDs)", "minimum": 0},
                    "node": {"type": "string", "description": "Filter by node name (optional)"},
                    "include_metadata": {"type": "boolean", "description": "Include device metadata", "default": True}
                },
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
            description="Get firewall rules for cluster, node, or specific VM/container. Provide node+vmid, or just vmid, or vmname.",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name (optional)"},
                    "vmid": {"type": "integer", "description": "VM/Container ID (optional)", "minimum": 100},
                    "vmname": {"type": "string", "description": "VM/container name to search (partial match, alternative to vmid)"}
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
            description="Get CPU information and capabilities for a node.",
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
            description="Get disk information including SMART health and wearout data.",
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
            name="get_performance",
            description="Get VM or container performance statistics. Provide node+vmid, or just vmid, or vmname.",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"},
                    "vmid": {"type": "integer", "description": "VM/container ID", "minimum": 100},
                    "vmname": {"type": "string", "description": "VM/container name (partial match, alternative to vmid)"},
                    "timeframe": {"type": "string", "description": "Time range for statistics", "enum": ["hour", "day", "week", "month", "year"], "default": "hour"}
                },
                "additionalProperties": False
            }
        ),
        
        # Log Monitoring
        Tool(
            name="get_system_logs",
            description="Get system logs from a node. Optionally filter by service name.",
            inputSchema={
                "type": "object",
                "properties": {
                    "node": {"type": "string", "description": "Node name"},
                    "limit": {"type": "integer", "description": "Maximum number of log entries to return", "default": 100, "minimum": 1, "maximum": 1000},
                    "start": {"type": "integer", "description": "Start offset (for future use)", "default": 0, "minimum": 0},
                    "service": {"type": "string", "description": "Filter by systemd service name (e.g., 'pveproxy', 'pvedaemon')"}
                },
                "required": ["node"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_cluster_logs",
            description="Get cluster-wide logs and task history. Supports filtering by errors and vmid.",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "Maximum number of entries to return", "default": 100, "minimum": 1, "maximum": 1000},
                    "start": {"type": "integer", "description": "Offset for pagination", "default": 0, "minimum": 0},
                    "errors": {"type": "boolean", "description": "Only show tasks with errors", "default": False},
                    "vmid": {"type": "integer", "description": "Only show tasks for this VM ID", "minimum": 100}
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

    # Filter tools based on feature toggles
    # Added in v1.3.2 (2025-11-29): Enforce feature toggles for dangerous operations
    enabled_tools = []
    for tool in all_tools:
        tool_name = tool.name
        # Check if this tool requires permission
        if tool_name in tool_permissions:
            # Only include if permission is enabled
            if tool_permissions[tool_name]:
                enabled_tools.append(tool)
        else:
            # Always include tools not in permission map (read-only operations)
            enabled_tools.append(tool)

    return enabled_tools

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
        
    except KeyError as e:
        error_result = {
            "error": f"Missing required parameter: {e.args[0]}",
            "tool": name,
            "hint": "Check the tool schema for required parameters."
        }
        json_output = json.dumps(error_result, indent=2, ensure_ascii=False)
        logger.error(f"Missing required parameter for tool '{name}': {e.args[0]}")
        return [types.TextContent(type="text", text=json_output)]
    except ProxmoxVEError as e:
        error_msg = f"Proxmox VE Error: {str(e)}"
        logger.error(error_msg)
        return [types.TextContent(type="text", text=error_msg)]
    except Exception as e:
        error_msg = f"Unexpected error executing tool '{name}': {str(e)}"
        logger.error(error_msg)
        return [types.TextContent(type="text", text=error_msg)]

def normalize_arguments(name: str, arguments: dict) -> dict:
    """Normalize arguments to handle common LLM mistakes."""
    args = dict(arguments)

    # --- Parameter name aliases (common model mistakes) ---
    aliases = {
        "snapshot_name": "snapname",
        "snapshotname": "snapname",
        "snap_name": "snapname",
        "vm_id": "vmid",
        "vmId": "vmid",
        "vm_name": "name",
        "host_name": "hostname",
        "new_id": "newid",
        "newId": "newid",
        "target_node": "target",
        "node_name": "node",
        "storage_name": "storage",
        "filter_by_id": "filter_id",
        "filter_by_name": "filter_name",
        "filter_by_status": "filter_status",
        "vmName": "vmname",
        "container_name": "vmname",
        "ct_name": "vmname",
    }
    for wrong, correct in aliases.items():
        if wrong in args and correct not in args:
            args[correct] = args.pop(wrong)

    # --- Type coercion ---
    # vmid: must be int
    if "vmid" in args:
        v = args["vmid"]
        if isinstance(v, str):
            args["vmid"] = int(v)
        elif isinstance(v, float):
            args["vmid"] = int(v)

    # newid: must be int
    if "newid" in args:
        v = args["newid"]
        if isinstance(v, str):
            args["newid"] = int(v)

    # osd_id: must be int
    if "osd_id" in args:
        v = args["osd_id"]
        if isinstance(v, str):
            args["osd_id"] = int(v)

    # Integer fields
    for key in ("cores", "sockets", "memory", "balloon", "swap",
                "limit", "offset", "limit_per_vm", "limit_per_source",
                "since_hours", "http_port", "tty", "cpuunits", "vcpus"):
        if key in args and isinstance(args[key], str):
            args[key] = int(args[key])

    # Float fields
    if "cpulimit" in args and isinstance(args["cpulimit"], str):
        args["cpulimit"] = float(args["cpulimit"])

    # Boolean fields
    bool_keys = ("confirm", "summary_only", "include_containers",
                 "include_disabled", "include_details", "include_hardware_info",
                 "include_job_history", "include_node_stats", "include_node_logs",
                 "include_vm_logs", "include_container_logs", "include_metadata",
                 "include_detailed_stats", "include_logs",
                 "online", "full", "purge", "destroy_unreferenced_disks",
                 "vmstate", "errors", "start", "protection")
    for key in bool_keys:
        if key in args:
            v = args[key]
            if isinstance(v, str):
                args[key] = v.lower() in ("true", "1", "yes")
            elif isinstance(v, int):
                args[key] = bool(v)

    # onboot, agent, unprivileged, console — Proxmox expects 0/1 int
    for key in ("onboot", "agent", "unprivileged", "console"):
        if key in args:
            v = args[key]
            if isinstance(v, bool):
                args[key] = 1 if v else 0
            elif isinstance(v, str):
                args[key] = 1 if v.lower() in ("true", "1", "yes") else 0

    # filter_status: normalize to lowercase
    if "filter_status" in args and isinstance(args["filter_status"], str):
        args["filter_status"] = args["filter_status"].lower().strip()

    return args


async def resolve_vm_identity(client, arguments: dict, tool_name: str) -> dict:
    """Resolve VM/container identity from vmid-only or vmname to node+vmid.

    - node + vmid both present → return immediately (zero API calls)
    - vmid only → GET /cluster/resources to find node
    - vmname only → GET /cluster/resources, partial name match (case-insensitive)
    - Neither → return as-is (downstream will raise KeyError)
    """
    args = dict(arguments)
    has_node = bool(args.get("node"))
    has_vmid = "vmid" in args and args["vmid"] is not None
    vmname = args.pop("vmname", None)

    # Fast path: both provided, nothing to resolve
    if has_node and has_vmid:
        return args

    # Nothing to resolve with
    if not has_vmid and not vmname:
        return args

    # Fetch cluster resources (single API call)
    result = await client.get("/cluster/resources", params={"type": "vm"})
    resources = result.get("data", [])

    if has_vmid:
        # Resolve node from vmid
        vmid = int(args["vmid"])
        for r in resources:
            if r.get("vmid") == vmid:
                args["node"] = r["node"]
                args["_resolved_name"] = r.get("name", "")
                args["_resolved_type"] = r.get("type", "")
                return args
        raise ProxmoxVEError(
            f"VM/Container with ID {vmid} not found on any node. "
            f"Use list_vms or list_containers to see available IDs."
        )

    # Resolve from vmname (partial, case-insensitive)
    search = vmname.lower()
    matches = [r for r in resources if search in r.get("name", "").lower()]

    if not matches:
        raise ProxmoxVEError(
            f"No VM or container found matching name '{vmname}'. "
            f"Use list_vms or list_containers to see available names."
        )

    if len(matches) == 1:
        m = matches[0]
        args["node"] = m["node"]
        args["vmid"] = m["vmid"]
        args["_resolved_name"] = m.get("name", "")
        args["_resolved_type"] = m.get("type", "")
        return args

    # Multiple matches — check for exact name match
    exact = [r for r in matches if r.get("name", "").lower() == search]
    if len(exact) == 1:
        m = exact[0]
        args["node"] = m["node"]
        args["vmid"] = m["vmid"]
        args["_resolved_name"] = m.get("name", "")
        args["_resolved_type"] = m.get("type", "")
        return args

    # Ambiguous — list all matches
    lines = [f"Multiple VMs/containers match name '{vmname}'. Specify vmid to disambiguate:"]
    for r in matches:
        lines.append(
            f"  vmid={r.get('vmid')} name='{r.get('name', '')}' "
            f"node={r.get('node', '')} type={r.get('type', '')} status={r.get('status', '')}"
        )
    raise ProxmoxVEError("\n".join(lines))


async def _resolve_type_with_fallback(client, node, vmid, resolved_type, path_suffix, method="get", **kwargs):
    """Auto-detect qemu/lxc when type unknown. Try qemu first, fallback to lxc."""
    if resolved_type:
        prefix = "qemu" if resolved_type == "qemu" else "lxc"
        return await getattr(client, method)(f"/nodes/{node}/{prefix}/{vmid}{path_suffix}", **kwargs)
    # Unknown type (fast path: node+vmid both given, no API lookup) — try qemu first
    try:
        return await getattr(client, method)(f"/nodes/{node}/qemu/{vmid}{path_suffix}", **kwargs)
    except Exception:
        return await getattr(client, method)(f"/nodes/{node}/lxc/{vmid}{path_suffix}", **kwargs)


async def execute_tool(name: str, arguments: dict) -> Union[dict, str]:
    """Execute specific tool operations with enhanced validation and error handling"""

    # Normalize arguments to handle common LLM mistakes
    arguments = normalize_arguments(name, arguments)

    # Non-unified operations — checked before resolver (no _resolved_type needed)
    static_permissions = {
        "create_vm": ("ENABLE_VM_CREATE", ENABLE_VM_CREATE),
        "create_container": ("ENABLE_CT_CREATE", ENABLE_CT_CREATE),
        "create_backup_job": ("ENABLE_BACKUP_JOB", ENABLE_BACKUP_JOB),
    }
    if name in static_permissions:
        flag_name, flag_value = static_permissions[name]
        if not flag_value:
            raise ProxmoxVEError(
                f"Operation '{name}' is disabled. "
                f"Set {flag_name} = True to enable. Safety feature."
            )

    # Unified permissions — checked AFTER resolver (need _resolved_type)
    # Defined here, enforced after resolve_vm_identity
    unified_permissions = {
        "start":         {"qemu": ("ENABLE_VM_START", ENABLE_VM_START),       "lxc": ("ENABLE_CT_START", ENABLE_CT_START)},
        "shutdown":      {"qemu": ("ENABLE_VM_SHUTDOWN", ENABLE_VM_SHUTDOWN), "lxc": ("ENABLE_CT_SHUTDOWN", ENABLE_CT_SHUTDOWN)},
        "stop":          {"qemu": ("ENABLE_VM_STOP", ENABLE_VM_STOP),         "lxc": ("ENABLE_CT_STOP", ENABLE_CT_STOP)},
        "reboot":        {"qemu": ("ENABLE_VM_REBOOT", ENABLE_VM_REBOOT),     "lxc": ("ENABLE_CT_REBOOT", ENABLE_CT_REBOOT)},
        "reset":         {"qemu": ("ENABLE_VM_RESET", ENABLE_VM_RESET)},
        "migrate":       {"qemu": ("ENABLE_VM_MIGRATE", ENABLE_VM_MIGRATE),   "lxc": ("ENABLE_CT_MIGRATE", ENABLE_CT_MIGRATE)},
        "backup":        {"qemu": ("ENABLE_VM_BACKUP", ENABLE_VM_BACKUP),     "lxc": ("ENABLE_CT_BACKUP", ENABLE_CT_BACKUP)},
        "snapshot":      {"qemu": ("ENABLE_VM_SNAPSHOT", ENABLE_VM_SNAPSHOT), "lxc": ("ENABLE_CT_SNAPSHOT", ENABLE_CT_SNAPSHOT)},
        "clone":         {"qemu": ("ENABLE_VM_CLONE", ENABLE_VM_CLONE),       "lxc": ("ENABLE_CT_CLONE", ENABLE_CT_CLONE)},
        "update_config": {"qemu": ("ENABLE_VM_UPDATE", ENABLE_VM_UPDATE),     "lxc": ("ENABLE_CT_UPDATE", ENABLE_CT_UPDATE)},
        "delete":        {"qemu": ("ENABLE_VM_DELETE", ENABLE_VM_DELETE),     "lxc": ("ENABLE_CT_DELETE", ENABLE_CT_DELETE)},
    }

    # Validate VM/Container IDs
    if 'vmid' in arguments:
        vmid = arguments['vmid']
        if isinstance(vmid, int) and vmid < 100:
            raise ProxmoxVEError(f"Invalid VM/Container ID: {vmid}. ID must be >= 100")

    # Control operations that require confirmation
    control_operations = [
        "start", "shutdown", "stop", "reboot", "reset",
        "migrate", "backup", "snapshot",
        "clone", "update_config", "delete",
        "create_backup_job", "create_vm", "create_container",
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
        # Auto-resolve VM/container identity (vmid-only or vmname lookup)
        if name in TOOLS_WITH_VM_IDENTITY:
            arguments = await resolve_vm_identity(client, arguments, name)

        # Extract resolver metadata before dispatch
        resolved_type = arguments.pop("_resolved_type", None)
        resolved_name = arguments.pop("_resolved_name", None)

        # Unified permission check (needs _resolved_type from resolver)
        if name in unified_permissions:
            perm_map = unified_permissions[name]
            check_type = resolved_type
            if not check_type:
                if not any(v[1] for v in perm_map.values()):
                    first_flag = next(iter(perm_map.values()))[0]
                    raise ProxmoxVEError(
                        f"Operation '{name}' is disabled. "
                        f"Set {first_flag} = True to enable. Safety feature."
                    )
            else:
                if check_type not in perm_map:
                    raise ProxmoxVEError(
                        f"Operation '{name}' is not supported for type '{check_type}'."
                    )
                flag_name, flag_value = perm_map[check_type]
                if not flag_value:
                    raise ProxmoxVEError(
                        f"Operation '{name}' is disabled for {check_type}. "
                        f"Set {flag_name} = True to enable. Safety feature."
                    )

        # ================================================================
        # Unified VM/Container dispatch
        # ================================================================
        if name == "get_status":
            node = arguments["node"]
            vmid = arguments["vmid"]
            return await _resolve_type_with_fallback(client, node, vmid, resolved_type, "/status/current")

        elif name == "get_config":
            node = arguments["node"]
            vmid = arguments["vmid"]
            return await _resolve_type_with_fallback(client, node, vmid, resolved_type, "/config")

        elif name == "get_snapshots":
            node = arguments["node"]
            vmid = arguments["vmid"]
            return await _resolve_type_with_fallback(client, node, vmid, resolved_type, "/snapshot")

        elif name == "start":
            node = arguments["node"]
            vmid = arguments["vmid"]
            return await _resolve_type_with_fallback(client, node, vmid, resolved_type, "/status/start", method="post")

        elif name == "shutdown":
            node = arguments["node"]
            vmid = arguments["vmid"]
            return await _resolve_type_with_fallback(client, node, vmid, resolved_type, "/status/shutdown", method="post")

        elif name == "stop":
            node = arguments["node"]
            vmid = arguments["vmid"]
            return await _resolve_type_with_fallback(client, node, vmid, resolved_type, "/status/stop", method="post")

        elif name == "reboot":
            node = arguments["node"]
            vmid = arguments["vmid"]
            return await _resolve_type_with_fallback(client, node, vmid, resolved_type, "/status/reboot", method="post")

        elif name == "reset":
            node = arguments["node"]
            vmid = arguments["vmid"]
            if resolved_type == "lxc":
                raise ProxmoxVEError("reset is only supported for VMs, not containers.")
            return await client.post(f"/nodes/{node}/qemu/{vmid}/status/reset")

        elif name == "migrate":
            node = arguments["node"]
            vmid = arguments["vmid"]
            target = arguments["target"]
            online = arguments.get("online", True)
            migrate_data = {
                "target": target,
                "online": 1 if online else 0
            }
            return await _resolve_type_with_fallback(client, node, vmid, resolved_type, "/migrate", method="post", data=migrate_data)

        elif name == "backup":
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
            return await _resolve_type_with_fallback(client, node, vmid, resolved_type, "/backup", method="post", data=backup_data)

        elif name == "snapshot":
            node = arguments["node"]
            vmid = arguments["vmid"]
            snapname = arguments["snapname"]
            description = arguments.get("description", "")
            snapshot_data = {
                "snapname": snapname,
                "description": description
            }
            if resolved_type != "lxc":
                vmstate = arguments.get("vmstate", False)
                snapshot_data["vmstate"] = 1 if vmstate else 0
            return await _resolve_type_with_fallback(client, node, vmid, resolved_type, "/snapshot", method="post", data=snapshot_data)

        elif name == "clone":
            node = arguments["node"]
            vmid = arguments["vmid"]
            newid = arguments["newid"]
            clone_data = {"newid": newid}
            if resolved_type == "lxc":
                supported_params = ["description", "target", "storage", "pool", "snapname", "full"]
                for param in supported_params:
                    if param in arguments:
                        clone_data[param] = arguments[param]
                if "name" in arguments:
                    clone_data["hostname"] = arguments["name"]
                return await client.post(f"/nodes/{node}/lxc/{vmid}/clone", data=clone_data)
            else:
                supported_params = ["name", "description", "target", "storage", "format", "full", "pool", "snapname"]
                for param in supported_params:
                    if param in arguments:
                        clone_data[param] = arguments[param]
                return await _resolve_type_with_fallback(client, node, vmid, resolved_type, "/clone", method="post", data=clone_data)

        elif name == "update_config":
            node = arguments["node"]
            vmid = arguments["vmid"]
            update_data = {}
            if resolved_type == "lxc":
                supported_params = ["hostname", "description", "cores", "memory", "swap", "onboot", "protection", "tags"]
                for param in supported_params:
                    if param in arguments:
                        update_data[param] = arguments[param]
                if "name" in arguments and "hostname" not in arguments:
                    update_data["hostname"] = arguments["name"]
                return await client.put(f"/nodes/{node}/lxc/{vmid}/config", data=update_data)
            else:
                supported_params = ["name", "description", "cores", "memory", "balloon", "onboot", "agent", "protection", "tags"]
                for param in supported_params:
                    if param in arguments:
                        update_data[param] = arguments[param]
                return await _resolve_type_with_fallback(client, node, vmid, resolved_type, "/config", method="put", data=update_data)

        elif name == "delete":
            node = arguments["node"]
            vmid = arguments["vmid"]
            delete_params = {}
            if arguments.get("purge", False):
                delete_params["purge"] = 1
            if arguments.get("destroy_unreferenced_disks", True):
                delete_params["destroy-unreferenced-disks"] = 1
            if resolved_type == "lxc":
                return await client.delete(f"/nodes/{node}/lxc/{vmid}", params=delete_params)
            elif resolved_type == "qemu":
                return await client.delete(f"/nodes/{node}/qemu/{vmid}", params=delete_params)
            else:
                try:
                    return await client.delete(f"/nodes/{node}/qemu/{vmid}", params=delete_params)
                except Exception:
                    return await client.delete(f"/nodes/{node}/lxc/{vmid}", params=delete_params)

        elif name == "get_performance":
            node = arguments["node"]
            vmid = arguments["vmid"]
            timeframe = arguments.get("timeframe", "hour")
            return await _resolve_type_with_fallback(client, node, vmid, resolved_type, "/rrddata", params={"timeframe": timeframe})

        # NEW: Enhanced Batch Operations for Data Collection with Firewall Options
        elif name == "get_all_vm_firewall_rules":
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
            # Get cluster resources filtered by node
            cluster_resources = await client.get("/cluster/resources")
            node_resources = []
            
            # Filter resources for the specific node
            for resource in cluster_resources.get("data", []):
                if resource.get("node") == node:
                    node_resources.append(resource)
            
            # Also get node-specific information
            node_status = await client.get(f"/nodes/{node}/status")
            
            return {
                "data": {
                    "resources": node_resources,
                    "node_status": node_status.get("data", {}),
                    "summary": {
                        "total_resources": len(node_resources),
                        "vms": len([r for r in node_resources if r.get("type") == "qemu"]),
                        "containers": len([r for r in node_resources if r.get("type") == "lxc"]),
                        "storage": len([r for r in node_resources if r.get("type") == "storage"])
                    }
                }
            }
        
        elif name == "get_node_tasks":
            node = arguments["node"]
            limit = arguments.get("limit", 50)
            return await client.get(f"/nodes/{node}/tasks", {"limit": limit})
        
        # Virtual Machine Management
        elif name == "list_vms":
            # Enhanced in v1.3.1 (2025-11-29):
            # - Added filter_id: filter by VM ID (single or comma-separated)
            # - Added filter_name: filter by name (case-insensitive partial match)
            # - Added filter_status: filter by status (running, stopped, paused)
            # - Filters applied before pagination with AND logic
            node = arguments.get("node")
            summary_only = arguments.get("summary_only", True)
            limit = arguments.get("limit", 100)
            offset = arguments.get("offset", 0)
            filter_id = arguments.get("filter_id")
            filter_name = arguments.get("filter_name")
            filter_status = arguments.get("filter_status")

            # Handle filter_id sent as bare integer
            if isinstance(filter_id, (int, float)):
                filter_id = str(int(filter_id))

            # Validate pagination parameters
            limit, offset = validate_pagination_params(limit, offset, DEFAULT_BATCH_LIMIT, MAX_BATCH_LIMIT)

            # Collect all VMs
            all_vms = []

            if node:
                # Get VMs from specific node
                try:
                    vms_result = await client.get(f"/nodes/{node}/qemu")
                    if vms_result.get("data"):
                        for vm in vms_result["data"]:
                            vm["node"] = node
                        all_vms = vms_result["data"]
                except Exception as e:
                    logger.error(f"Cannot get VMs from node {node}: {e}")
                    raise ProxmoxVEError(f"Failed to get VMs from node {node}: {e}")
            else:
                # Get VMs from all nodes
                nodes_result = await client.get("/nodes")
                for node_info in nodes_result.get("data", []):
                    node_name = node_info["node"]
                    try:
                        vms_result = await client.get(f"/nodes/{node_name}/qemu")
                        if vms_result.get("data"):
                            for vm in vms_result["data"]:
                                vm["node"] = node_name
                            all_vms.extend(vms_result["data"])
                    except Exception as e:
                        logger.warning(f"Cannot get VMs from node {node_name}: {e}")

            # Apply filters before pagination
            filtered_vms = all_vms
            filter_info = {}

            # Filter by ID
            if filter_id:
                # Support comma-separated IDs
                id_list = [int(x.strip()) for x in filter_id.split(",") if x.strip().isdigit()]
                if id_list:
                    filtered_vms = [vm for vm in filtered_vms if vm.get("vmid") in id_list]
                    filter_info["filter_id"] = filter_id

            # Filter by name (case-insensitive partial match)
            if filter_name:
                filter_name_lower = filter_name.lower()
                filtered_vms = [vm for vm in filtered_vms if filter_name_lower in vm.get("name", "").lower()]
                filter_info["filter_name"] = filter_name

            # Filter by status
            if filter_status:
                filter_status_lower = filter_status.lower()
                filtered_vms = [vm for vm in filtered_vms if vm.get("status", "").lower() == filter_status_lower]
                filter_info["filter_status"] = filter_status

            # Total count after filtering but before pagination
            total_count = len(filtered_vms)

            # Apply pagination
            paginated_vms = filtered_vms[offset:offset + limit]
            returned_count = len(paginated_vms)
            has_more = (offset + returned_count) < total_count

            # Apply summary filter if requested
            if summary_only:
                summary_vms = []
                for vm in paginated_vms:
                    summary_vms.append({
                        "vmid": vm.get("vmid"),
                        "name": vm.get("name"),
                        "status": vm.get("status"),
                        "node": vm.get("node")
                    })
                paginated_vms = summary_vms

            # Create pagination message
            display_msg = create_pagination_message(
                returned_count=returned_count,
                total_count=total_count,
                has_more=has_more,
                item_type="VMs",
                limit=limit,
                offset=offset
            )

            # Add filter info to summary if filters were applied
            summary_dict = {
                "total_count": total_count,
                "returned_count": returned_count,
                "offset": offset,
                "limit": limit,
                "has_more": has_more,
                "next_offset": offset + returned_count if has_more else None,
                "summary_only": summary_only
            }
            if filter_info:
                summary_dict["filters_applied"] = filter_info

            return {
                "data": paginated_vms,
                "summary": summary_dict,
                "display_message": display_msg
            }
        
        # Container Management
        elif name == "list_containers":
            # Enhanced in v1.3.1 (2025-11-29):
            # - Added filter_id: filter by container ID (single or comma-separated)
            # - Added filter_name: filter by name (case-insensitive partial match)
            # - Added filter_status: filter by status (running, stopped, paused)
            # - Filters applied before pagination with AND logic
            node = arguments.get("node")
            summary_only = arguments.get("summary_only", True)
            limit = arguments.get("limit", 100)
            offset = arguments.get("offset", 0)
            filter_id = arguments.get("filter_id")
            filter_name = arguments.get("filter_name")
            filter_status = arguments.get("filter_status")

            # Handle filter_id sent as bare integer
            if isinstance(filter_id, (int, float)):
                filter_id = str(int(filter_id))

            # Validate pagination parameters
            limit, offset = validate_pagination_params(limit, offset, DEFAULT_BATCH_LIMIT, MAX_BATCH_LIMIT)

            # Collect all containers
            all_containers = []

            if node:
                # Get containers from specific node
                try:
                    containers_result = await client.get(f"/nodes/{node}/lxc")
                    if containers_result.get("data"):
                        for container in containers_result["data"]:
                            container["node"] = node
                        all_containers = containers_result["data"]
                except Exception as e:
                    logger.error(f"Cannot get containers from node {node}: {e}")
                    raise ProxmoxVEError(f"Failed to get containers from node {node}: {e}")
            else:
                # Get containers from all nodes
                nodes_result = await client.get("/nodes")
                for node_info in nodes_result.get("data", []):
                    node_name = node_info["node"]
                    try:
                        containers_result = await client.get(f"/nodes/{node_name}/lxc")
                        if containers_result.get("data"):
                            for container in containers_result["data"]:
                                container["node"] = node_name
                            all_containers.extend(containers_result["data"])
                    except Exception as e:
                        logger.warning(f"Cannot get containers from node {node_name}: {e}")

            # Apply filters before pagination
            filtered_containers = all_containers
            filter_info = {}

            # Filter by ID
            if filter_id:
                # Support comma-separated IDs
                id_list = [int(x.strip()) for x in filter_id.split(",") if x.strip().isdigit()]
                if id_list:
                    filtered_containers = [ct for ct in filtered_containers if ct.get("vmid") in id_list]
                    filter_info["filter_id"] = filter_id

            # Filter by name (case-insensitive partial match)
            if filter_name:
                filter_name_lower = filter_name.lower()
                filtered_containers = [ct for ct in filtered_containers if filter_name_lower in ct.get("name", "").lower()]
                filter_info["filter_name"] = filter_name

            # Filter by status
            if filter_status:
                filter_status_lower = filter_status.lower()
                filtered_containers = [ct for ct in filtered_containers if ct.get("status", "").lower() == filter_status_lower]
                filter_info["filter_status"] = filter_status

            # Total count after filtering but before pagination
            total_count = len(filtered_containers)

            # Apply pagination
            paginated_containers = filtered_containers[offset:offset + limit]
            returned_count = len(paginated_containers)
            has_more = (offset + returned_count) < total_count

            # Apply summary filter if requested
            if summary_only:
                summary_containers = []
                for container in paginated_containers:
                    summary_containers.append({
                        "vmid": container.get("vmid"),
                        "name": container.get("name"),
                        "status": container.get("status"),
                        "node": container.get("node")
                    })
                paginated_containers = summary_containers

            # Create pagination message
            display_msg = create_pagination_message(
                returned_count=returned_count,
                total_count=total_count,
                has_more=has_more,
                item_type="containers",
                limit=limit,
                offset=offset
            )

            # Add filter info to summary if filters were applied
            summary_dict = {
                "total_count": total_count,
                "returned_count": returned_count,
                "offset": offset,
                "limit": limit,
                "has_more": has_more,
                "next_offset": offset + returned_count if has_more else None,
                "summary_only": summary_only
            }
            if filter_info:
                summary_dict["filters_applied"] = filter_info

            return {
                "data": paginated_containers,
                "summary": summary_dict,
                "display_message": display_msg
            }
        
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
            # Fixed in v1.3.1 (2025-11-29):
            # - Added content parameter to fix HTTP 500 errors
            # - Enhanced error messages with helpful suggestions
            # - Added _content_type field to response
            node = arguments["node"]
            storage = arguments["storage"]
            content = arguments.get("content")

            # Build parameters
            params = {}
            if content:
                params["content"] = content

            # Try to get storage content
            try:
                result = await client.get(f"/nodes/{node}/storage/{storage}/content", params if params else None)

                # Add information about what was queried
                if isinstance(result, dict):
                    if "data" not in result:
                        result = {"data": result}
                    if content:
                        result["_content_type"] = content
                    else:
                        result["_content_type"] = "all"

                return result

            except ProxmoxVEError as e:
                # If query failed and no content type was specified, provide helpful error
                if not content and "500" in str(e):
                    raise ProxmoxVEError(
                        f"Failed to get storage content: {e}. "
                        f"This storage may require a 'content' parameter. "
                        f"Try specifying content type: images, iso, vztmpl, backup, rootdir, or snippets"
                    )
                else:
                    raise
        
        elif name == "get_zfs_pools":
            node = arguments["node"]
            return await client.get(f"/nodes/{node}/disks/zfs")
        
        elif name == "get_ceph_status":
            summary_only = arguments.get("summary_only", True)
            include_details = arguments.get("include_details", False)

            # Get full Ceph status
            full_status = await client.get("/cluster/ceph/status")
            ceph_data = full_status.get("data", {})

            # If full details requested, return raw data (may overflow context)
            if include_details:
                logger.warning("Returning full Ceph details - may cause context overflow!")
                return {
                    "full_details": ceph_data,
                    "display_message": "Returning full Ceph details (may cause context overflow)",
                    "warning": "Full details included - may cause context overflow in large clusters"
                }

            # Extract core health information
            health = ceph_data.get("health", {})
            health_status = health.get("status", "UNKNOWN")

            # Extract health check summary (key information only)
            health_checks = health.get("checks", {})
            health_summary = []
            for check_name, check_data in health_checks.items():
                check_info = {
                    "check": check_name,
                    "severity": check_data.get("severity", "INFO"),
                    "summary": check_data.get("summary", {}).get("message", "")
                }

                # Extract detailed information (especially for MON_DOWN, OSD_DOWN, etc.)
                detail_list = check_data.get("detail", [])
                if detail_list:
                    check_info["details"] = detail_list

                health_summary.append(check_info)

            # If summary-only mode, return health status only
            if summary_only:
                display_msg = f"Ceph cluster health: {health_status}"
                if health_summary:
                    display_msg += f" ({len(health_summary)} checks)"

                return {
                    "health_status": health_status,
                    "health_checks_count": len(health_summary),
                    "health_issues": health_summary if health_status != "HEALTH_OK" else [],
                    "display_message": display_msg,
                    "recommendation": "Use summary_only=false for more details, include_details=true for full output"
                }

            # Standard mode: return key metrics without detailed data
            mon_status = ceph_data.get("monmap", {})
            osd_status = ceph_data.get("osdmap", {}).get("osdmap", {})
            pg_status = ceph_data.get("pgmap", {})

            # Extract OSD key information
            osd_summary = {
                "total": osd_status.get("num_osds", 0),
                "up": osd_status.get("num_up_osds", 0),
                "in": osd_status.get("num_in_osds", 0),
                "full": osd_status.get("full", False),
                "nearfull": osd_status.get("nearfull", False)
            }

            # Extract Monitor key information
            all_mons = mon_status.get("mons", [])
            quorum_ranks = mon_status.get("quorum", [])

            mon_summary = {
                "total": len(all_mons),
                "quorum": quorum_ranks,
                "quorum_count": len(quorum_ranks),
                "monitors_up": [m.get("name") for m in all_mons if m.get("rank") in quorum_ranks],
                "monitors_down": [m.get("name") for m in all_mons if m.get("rank") not in quorum_ranks]
            }

            # Extract PG key information
            pg_summary = {
                "total": pg_status.get("num_pgs", 0),
                "active_clean": 0,
                "degraded": 0,
                "states": {}
            }

            # Simplify PG states (counts only, no detailed lists)
            pgs_by_state = pg_status.get("pgs_by_state", [])
            for pg_state in pgs_by_state:
                state_name = pg_state.get("state_name", "unknown")
                count = pg_state.get("count", 0)
                pg_summary["states"][state_name] = count
                if "active+clean" in state_name:
                    pg_summary["active_clean"] += count
                if "degraded" in state_name:
                    pg_summary["degraded"] += count

            # Extract storage usage information
            storage_summary = {
                "total_bytes": pg_status.get("bytes_total", 0),
                "used_bytes": pg_status.get("bytes_used", 0),
                "available_bytes": pg_status.get("bytes_avail", 0),
                "percent_used": round(pg_status.get("bytes_used", 0) / max(pg_status.get("bytes_total", 1), 1) * 100, 2)
            }

            # Create status message
            display_msg = f"Ceph cluster status: {health_status} | "

            # If monitors are down, show them first
            if mon_summary["monitors_down"]:
                display_msg += f"Monitor DOWN: {', '.join(mon_summary['monitors_down'])} | "
                display_msg += f"Monitor: {mon_summary['quorum_count']}/{mon_summary['total']} up | "
            else:
                display_msg += f"Monitor: {mon_summary['quorum_count']}/{mon_summary['total']} up | "

            display_msg += f"OSD: {osd_summary['up']}/{osd_summary['total']} up | "
            display_msg += f"PG: {pg_summary['active_clean']}/{pg_summary['total']} active+clean | "
            display_msg += f"Storage used: {storage_summary['percent_used']}%"

            if health_summary:
                display_msg += f" | {len(health_summary)} health checks"

            return {
                "health_status": health_status,
                "health_checks": health_summary,
                "monitors": mon_summary,
                "osds": osd_summary,
                "placement_groups": pg_summary,
                "storage": storage_summary,
                "display_message": display_msg,
                "summary_mode": "standard",
                "recommendation": "Use include_details=true for full Ceph status output (may cause context overflow)"
            }
        
        elif name == "get_ceph_osds":
            # First, try the cluster-wide endpoint
            all_osds = []
            osd_tree = None
            ceph_status = None
            nodes_with_osds = set()
            
            try:
                # Try cluster-wide OSD endpoint first
                logger.info("Trying cluster-wide Ceph OSD endpoint")
                osd_result = await client.get("/cluster/ceph/osd")
                all_osds = osd_result.get("data", [])
                logger.info(f"Found {len(all_osds)} OSDs from cluster endpoint")
            except Exception as e:
                logger.warning(f"Cluster OSD endpoint failed: {e}, trying per-node approach")
                
                # If cluster endpoint fails, try per-node approach
                nodes_result = await client.get("/nodes")
                
                for node_info in nodes_result.get("data", []):
                    node = node_info["node"]
                    try:
                        # Try multiple possible endpoints
                        endpoints = [
                            f"/nodes/{node}/ceph/osd",
                            f"/nodes/{node}/ceph/osds"
                        ]
                        
                        for endpoint in endpoints:
                            try:
                                logger.debug(f"Trying endpoint: {endpoint}")
                                osds_result = await client.get(endpoint)
                                node_osds = osds_result.get("data", [])
                                
                                if node_osds:
                                    logger.info(f"Found {len(node_osds)} OSDs on node {node}")
                                    for osd in node_osds:
                                        # Ensure we have consistent data structure
                                        if "node" not in osd:
                                            osd["node"] = node
                                        all_osds.append(osd)
                                        nodes_with_osds.add(node)
                                    break  # Success, no need to try other endpoints
                            except Exception as endpoint_error:
                                logger.debug(f"Endpoint {endpoint} failed: {endpoint_error}")
                                continue
                    except Exception as node_error:
                        logger.debug(f"Cannot get Ceph OSDs from node {node}: {node_error}")
            
            # Try to get OSD tree for additional information
            try:
                logger.info("Getting OSD tree information")
                osd_tree_result = await client.get("/cluster/ceph/osd/tree")
                osd_tree = osd_tree_result.get("data", {})
                
                # If we didn't get OSDs from previous methods, try to extract from tree
                if not all_osds and osd_tree:
                    logger.info("Extracting OSD information from OSD tree")
                    tree_nodes = osd_tree.get("nodes", [])
                    for node in tree_nodes:
                        if node.get("type") == "osd":
                            osd_info = {
                                "id": node.get("id"),
                                "name": node.get("name", f"osd.{node.get('id')}"),
                                "status": "up" if node.get("status") == "up" else "down",
                                "in": node.get("in", 0) == 1,
                                "up": node.get("status") == "up",
                                "reweight": node.get("reweight", 1.0),
                                "primary_affinity": node.get("primary_affinity", 1.0),
                                "host": node.get("host", "unknown")
                            }
                            all_osds.append(osd_info)
            except Exception as e:
                logger.debug(f"Cannot get OSD tree: {e}")
            
            # Get cluster-wide Ceph status for summary
            try:
                ceph_status_result = await client.get("/cluster/ceph/status")
                ceph_status = ceph_status_result.get("data", {})
            except Exception as e:
                logger.debug(f"Cannot get cluster Ceph status: {e}")
            
            # If still no OSDs found but Ceph status shows OSDs exist, log error
            if not all_osds and ceph_status:
                osdmap = ceph_status.get("osdmap", {})
                num_osds = osdmap.get("num_osds", 0)
                if num_osds > 0:
                    logger.error(f"Ceph status shows {num_osds} OSDs but unable to retrieve OSD details")
            
            # Build comprehensive summary
            summary = {
                "total_osds": len(all_osds),
                "nodes_checked": len(nodes_result.get("data", [])) if 'nodes_result' in locals() else 0,
                "nodes_with_osds": len(nodes_with_osds) if nodes_with_osds else 0
            }
            
            # Add status information if available
            if ceph_status:
                osdmap = ceph_status.get("osdmap", {})
                summary.update({
                    "cluster_osd_count": osdmap.get("num_osds", 0),
                    "up_osds": osdmap.get("num_up_osds", 0),
                    "in_osds": osdmap.get("num_in_osds", 0),
                    "ceph_healthy": ceph_status.get("health", {}).get("status") == "HEALTH_OK"
                })
            
            # Validate and enrich OSD data
            for osd in all_osds:
                # Ensure consistent data structure
                if "id" in osd and isinstance(osd["id"], str) and osd["id"].startswith("osd."):
                    osd["id"] = int(osd["id"].replace("osd.", ""))
                elif "osd" in osd and "id" not in osd:
                    osd["id"] = osd["osd"]
                
                # Add missing fields with defaults
                osd.setdefault("in", True)
                osd.setdefault("up", True)
                osd.setdefault("status", "up" if osd.get("up", True) else "down")
            
            return {
                "data": all_osds,
                "summary": summary
            }
        
        elif name == "get_ceph_osd_details":
            # Enhanced in v1.3.1 (2025-11-29):
            # - Improved error handling: fallback on any error, not just 501/404
            # - Added detailed diagnostics: tracks all failed methods with specific errors
            # - Better error messages: includes possible causes and diagnostic steps
            osd_id = arguments.get("osd_id")
            node = arguments.get("node")
            include_metadata = arguments.get("include_metadata", True)

            osd_details = []

            # If specific OSD ID provided, get details for that OSD only
            if osd_id is not None:
                try:
                    # Try to get detailed OSD information
                    osd_info = await client.get(f"/cluster/ceph/osd/{osd_id}")

                    if osd_info.get("data"):
                        osd_data = osd_info["data"]
                        osd_data["osd_id"] = osd_id

                        # Try to get additional metadata if requested
                        if include_metadata:
                            try:
                                metadata = await client.get(f"/cluster/ceph/osd/{osd_id}/metadata")
                                if metadata.get("data"):
                                    osd_data["metadata"] = metadata["data"]
                            except ProxmoxVEError:
                                logger.debug(f"Metadata not available for OSD {osd_id}")

                        osd_details.append(osd_data)

                except ProxmoxVEError as e:
                    raise ProxmoxVEError(f"Failed to get details for OSD {osd_id}: {e}")

            else:
                # Get details for all OSDs
                # Try multiple methods to get OSD list
                # v1.3.3 enhancement: Added node-specific endpoint as primary method when node is specified
                osd_list = []
                use_tree = False
                failed_methods = []  # Track which methods failed and why

                # Method 1: Try node-specific endpoint to get full tree
                # Added in v1.3.3: Use /nodes/{node}/ceph/osd endpoint
                # Note: This endpoint returns a tree structure with ALL OSDs from ALL nodes
                # We can use any node to get the tree, then filter by target node if specified

                # Try to get a node name (use specified node, or get first available node)
                query_node = node
                if not query_node:
                    # Get first available node to query the tree
                    try:
                        nodes_result = await client.get("/nodes")
                        nodes_data = nodes_result.get("data", [])
                        if nodes_data and len(nodes_data) > 0:
                            query_node = nodes_data[0].get("node")
                            logger.info(f"No node specified, using '{query_node}' to get full OSD tree")
                    except Exception as e:
                        logger.warning(f"Could not get nodes list: {e}")

                if query_node:
                    try:
                        logger.info(f"Trying node-specific OSD endpoint using node '{query_node}'")
                        node_osd_result = await client.get(f"/nodes/{query_node}/ceph/osd")

                        # Helper function to recursively find OSDs for a specific host in tree structure
                        def find_host_osds(tree_node, target_host):
                            """Recursively search tree for OSDs belonging to target_host"""
                            osds = []

                            if not isinstance(tree_node, dict):
                                return osds

                            node_type = tree_node.get("type")
                            node_name = tree_node.get("name")

                            # Check if this node is a host node matching our target
                            if node_type == "host" and node_name == target_host:
                                # This is our target host, extract its OSD children
                                children = tree_node.get("children", [])
                                for child in children:
                                    if isinstance(child, dict) and child.get("type") == "osd":
                                        osds.append(child)
                                return osds

                            # Otherwise, recursively search children
                            children = tree_node.get("children", [])
                            for child in children:
                                osds.extend(find_host_osds(child, target_host))

                            return osds

                        # Helper function to extract all OSDs from tree (no host filtering)
                        def find_all_osds(tree_node):
                            """Recursively extract all OSDs from entire tree"""
                            osds = []

                            if not isinstance(tree_node, dict):
                                return osds

                            # If this is an OSD node, add it
                            if tree_node.get("type") == "osd":
                                osds.append(tree_node)

                            # Recursively search children
                            children = tree_node.get("children", [])
                            for child in children:
                                osds.extend(find_all_osds(child))

                            return osds

                        # Parse the tree structure
                        # Format: {"flags": "...", "root": {"children": [...]}}
                        osd_list = []

                        if isinstance(node_osd_result, dict):
                            # Check if response has "data" key first (most common)
                            if "data" in node_osd_result:
                                data = node_osd_result["data"]

                                # Check if data is a list of key-value pairs
                                if isinstance(data, list) and len(data) > 0:
                                    # Format: {"data": [{"key": "flags", "value": "..."}, {"key": "root", "value": {...}}]}
                                    root_item = None
                                    for item in data:
                                        if isinstance(item, dict) and item.get("key") == "root":
                                            root_item = item.get("value")
                                            break

                                    if root_item:
                                        # Found root in key-value pairs
                                        # Use appropriate function based on whether we're filtering by node
                                        if node:
                                            osd_items = find_host_osds(root_item, node)
                                        else:
                                            osd_items = find_all_osds(root_item)

                                        # Convert to consistent structure
                                        for osd in osd_items:
                                            osd_id = osd.get("id")
                                            if osd_id is None:
                                                continue

                                            osd_list.append({
                                                "id": int(osd_id),
                                                "name": osd.get("name", f"osd.{osd_id}"),
                                                "host": osd.get("host", node if node else osd.get("host")),
                                                "status": osd.get("status"),
                                                "in": osd.get("in"),
                                                "crush_weight": osd.get("crush_weight"),
                                                "reweight": osd.get("reweight"),
                                                "percent_used": osd.get("percent_used"),
                                                "pgs": osd.get("pgs")
                                            })
                                    else:
                                        # data is a list but not key-value pairs, might be direct OSD list
                                        for osd in data:
                                            if not isinstance(osd, dict):
                                                continue
                                            osd_name = osd.get("name", "")
                                            if not osd_name or not osd_name.startswith("osd."):
                                                continue
                                            osd_id = osd_name.replace("osd.", "")
                                            if osd_id and osd_id.isdigit():
                                                osd_list.append({
                                                    "id": int(osd_id),
                                                    "name": osd_name,
                                                    "host": node,
                                                    "status": osd.get("status", osd.get("state"))
                                                })

                                # Check if data is a dict with "root" key
                                elif isinstance(data, dict) and "root" in data:
                                    # Format: {"data": {"flags": "...", "root": {...}}}
                                    root = data["root"]
                                    # Use appropriate function based on whether we're filtering by node
                                    if node:
                                        osd_items = find_host_osds(root, node)
                                    else:
                                        osd_items = find_all_osds(root)

                                    for osd in osd_items:
                                        osd_id = osd.get("id")
                                        if osd_id is None:
                                            continue

                                        osd_list.append({
                                            "id": int(osd_id),
                                            "name": osd.get("name", f"osd.{osd_id}"),
                                            "host": osd.get("host", node if node else osd.get("host")),
                                            "status": osd.get("status"),
                                            "in": osd.get("in"),
                                            "crush_weight": osd.get("crush_weight"),
                                            "reweight": osd.get("reweight"),
                                            "percent_used": osd.get("percent_used"),
                                            "pgs": osd.get("pgs")
                                        })

                            # Check if response directly has "root" key (no "data" wrapper)
                            elif "root" in node_osd_result:
                                root = node_osd_result["root"]
                                # Use appropriate function based on whether we're filtering by node
                                if node:
                                    osd_items = find_host_osds(root, node)
                                else:
                                    osd_items = find_all_osds(root)

                                for osd in osd_items:
                                    osd_id = osd.get("id")
                                    if osd_id is None:
                                        continue

                                    osd_list.append({
                                        "id": int(osd_id),
                                        "name": osd.get("name", f"osd.{osd_id}"),
                                        "host": osd.get("host", node if node else osd.get("host")),
                                        "status": osd.get("status"),
                                        "in": osd.get("in"),
                                        "crush_weight": osd.get("crush_weight"),
                                        "reweight": osd.get("reweight"),
                                        "percent_used": osd.get("percent_used"),
                                        "pgs": osd.get("pgs")
                                    })

                        elif isinstance(node_osd_result, list):
                            # Direct list format
                            for osd in node_osd_result:
                                if not isinstance(osd, dict):
                                    continue
                                osd_name = osd.get("name", "")
                                if not osd_name or not osd_name.startswith("osd."):
                                    continue
                                osd_id = osd_name.replace("osd.", "")
                                if osd_id and osd_id.isdigit():
                                    osd_list.append({
                                        "id": int(osd_id),
                                        "name": osd_name,
                                        "host": node,
                                        "status": osd.get("status", osd.get("state"))
                                    })

                        if osd_list:
                            use_tree = True  # Mark that we got data from tree
                            if node:
                                logger.info(f"Got {len(osd_list)} OSDs for node '{node}' from node-specific endpoint")
                            else:
                                logger.info(f"Got {len(osd_list)} OSDs from all nodes using node '{query_node}' endpoint")
                        else:
                            # Build detailed diagnostic message
                            diag = []
                            if node:
                                diag.append(f"Method 1 returned 0 OSDs for node '{node}'")
                            else:
                                diag.append(f"Method 1 returned 0 OSDs (queried via node '{query_node}')")

                            if isinstance(node_osd_result, dict):
                                diag.append(f"Response type: dict with keys {list(node_osd_result.keys())}")

                                if "root" in node_osd_result:
                                    root = node_osd_result["root"]
                                    diag.append(f"Root type: {type(root)}")

                                    if isinstance(root, dict):
                                        diag.append(f"Root keys: {list(root.keys())}")
                                        if "children" in root:
                                            children = root.get("children", [])
                                            diag.append(f"Root has {len(children)} children")

                                            # Check what's in the first level
                                            if children and isinstance(children, list) and len(children) > 0:
                                                first_child = children[0]
                                                if isinstance(first_child, dict):
                                                    diag.append(f"First child type: {first_child.get('type')}, name: {first_child.get('name')}")
                                                    if "children" in first_child:
                                                        diag.append(f"First child has {len(first_child.get('children', []))} children")

                                                        # List host names found
                                                        host_names = []
                                                        for child in first_child.get("children", []):
                                                            if isinstance(child, dict) and child.get("type") == "host":
                                                                host_names.append(child.get("name"))
                                                        diag.append(f"Hosts found in tree: {host_names}")
                                                        diag.append(f"Target node: '{node}' (looking for exact match)")

                                elif "data" in node_osd_result:
                                    diag.append(f"Has 'data' key with {len(node_osd_result['data'])} items")
                            else:
                                diag.append(f"Response type: {type(node_osd_result)}")

                            failed_methods.append(f"Method 1 (/nodes/{node}/ceph/osd): " + " | ".join(diag))

                    except ProxmoxVEError as e:
                        error_msg = str(e)
                        failed_methods.append(f"Method 1 (/nodes/{node}/ceph/osd): {error_msg}")
                        logger.info(f"Node-specific OSD endpoint not available ({error_msg}), trying fallback methods")
                    except Exception as e:
                        error_msg = f"Unexpected error: {type(e).__name__}: {str(e)}"
                        failed_methods.append(f"Method 1 (/nodes/{node}/ceph/osd): {error_msg}")
                        logger.warning(f"Node-specific OSD endpoint failed unexpectedly: {error_msg}")

                # Method 2: Try to get OSD tree (best for cluster-wide - includes host info)
                if not osd_list:
                    try:
                        logger.info("Trying to get OSD tree")
                        tree_result = await client.get("/cluster/ceph/osd/tree")
                        tree_data = tree_result.get("data", {})
                        tree_nodes = tree_data.get("nodes", [])

                        # Filter to get only OSD nodes
                        osd_nodes = [n for n in tree_nodes if n.get("type") == "osd"]

                        # Filter by node if specified
                        if node:
                            osd_nodes = [n for n in osd_nodes if n.get("host") == node]

                        osd_list = osd_nodes
                        use_tree = True
                        logger.info(f"Got {len(osd_list)} OSDs from tree")

                    except ProxmoxVEError as e:
                        # Try fallback methods for any error (not just 501/404)
                        error_msg = str(e)
                        failed_methods.append(f"Method 2 (/cluster/ceph/osd/tree): {error_msg}")
                        logger.info(f"OSD tree not available ({error_msg}), trying fallback methods")

                # Method 3: If tree failed, try cluster OSD list
                if not osd_list:
                    try:
                        logger.info("Trying cluster OSD list endpoint")
                        osd_result = await client.get("/cluster/ceph/osd")
                        osd_data = osd_result.get("data", [])

                        # Convert to node-like structure
                        osd_list = [{"id": osd.get("name", "").replace("osd.", ""), "name": osd.get("name")}
                                   for osd in osd_data if osd.get("name", "").startswith("osd.")]

                        logger.info(f"Got {len(osd_list)} OSDs from cluster endpoint")

                        # Node filtering not available without tree
                        if node:
                            logger.warning(f"Node filtering requested but OSD tree not available - returning all OSDs")

                    except ProxmoxVEError as e:
                        error_msg = str(e)
                        failed_methods.append(f"Method 3 (/cluster/ceph/osd): {error_msg}")
                        logger.warning(f"Cluster OSD endpoint failed: {error_msg}")

                # Method 4: If still no OSDs, try getting from Ceph status
                if not osd_list:
                    try:
                        logger.info("Trying to extract OSD list from Ceph status")
                        status_result = await client.get("/cluster/ceph/status")
                        status_data = status_result.get("data", {})
                        osdmap = status_data.get("osdmap", {}).get("osdmap", {})

                        num_osds = osdmap.get("num_osds", 0)
                        if num_osds > 0:
                            # Generate OSD list based on count
                            osd_list = [{"id": i, "name": f"osd.{i}"} for i in range(num_osds)]
                            logger.info(f"Generated list of {len(osd_list)} OSDs from status")

                            if node:
                                logger.warning(f"Node filtering requested but OSD tree not available - returning all OSDs")
                        else:
                            failed_methods.append(f"Method 4 (/cluster/ceph/status): Ceph status shows 0 OSDs")

                    except ProxmoxVEError as e:
                        error_msg = str(e)
                        failed_methods.append(f"Method 4 (/cluster/ceph/status): {error_msg}")
                        logger.warning(f"Could not extract OSD list from status: {error_msg}")

                # If we still don't have OSDs, raise detailed error
                if not osd_list:
                    error_details = "\n  ".join(failed_methods) if failed_methods else "All methods failed with unknown errors"

                    # Build helpful diagnostic message
                    diagnostic_msg = (
                        f"Unable to retrieve OSD list. Tried {len(failed_methods)} methods:\n  {error_details}\n\n"
                        f"Possible causes:\n"
                        f"  - Ceph is not configured on this cluster\n"
                        f"  - Ceph service is not running\n"
                        f"  - API permissions issue\n"
                    )

                    if node:
                        diagnostic_msg += (
                            f"  - Node '{node}' has no OSDs\n"
                            f"  - Node-specific endpoint /nodes/{node}/ceph/osd not available\n\n"
                            f"To diagnose:\n"
                            f"  1. Check if Ceph is configured: pveceph status\n"
                            f"  2. Check Ceph service on node: ssh {node} 'systemctl status ceph.target'\n"
                            f"  3. Check OSDs on node: ssh {node} 'pveceph osd tree'\n"
                            f"  4. Try without node filter: get_ceph_osd_details()\n"
                            f"  5. Verify node name is correct (case-sensitive)"
                        )
                    else:
                        diagnostic_msg += (
                            f"  - Cluster-wide Ceph endpoints not available\n\n"
                            f"To diagnose:\n"
                            f"  1. Check if Ceph is configured: pveceph status\n"
                            f"  2. Check Ceph service: systemctl status ceph.target\n"
                            f"  3. Try with specific node: get_ceph_osd_details(node='your-node-name')\n"
                            f"  4. Check API user permissions for Ceph access"
                        )

                    raise ProxmoxVEError(diagnostic_msg)

                # Get detailed info for each OSD
                for osd_item in osd_list:
                    osd_num = osd_item.get("id")
                    if osd_num is None:
                        continue

                    # Convert to int if it's a string
                    try:
                        osd_num = int(osd_num)
                    except (ValueError, TypeError):
                        logger.warning(f"Invalid OSD ID: {osd_num}")
                        continue

                    # Check if we already have all the data from tree (Method 1)
                    # Tree data from node-specific endpoint already contains detailed info
                    if use_tree and "crush_weight" in osd_item:
                        # We have detailed data from tree, use it directly
                        osd_data = {
                            "osd_id": osd_num,
                            "name": osd_item.get("name", f"osd.{osd_num}"),
                            "host": osd_item.get("host"),
                            "in": osd_item.get("in"),
                            "up": 1 if osd_item.get("status") == "up" else 0,
                            "status": osd_item.get("status"),
                            "crush_weight": osd_item.get("crush_weight"),
                            "reweight": osd_item.get("reweight"),
                            "percent_used": osd_item.get("percent_used"),
                            "pgs": osd_item.get("pgs"),
                            "bytes_used": osd_item.get("bytes_used"),
                            "total_space": osd_item.get("total_space"),
                            "apply_latency_ms": osd_item.get("apply_latency_ms"),
                            "commit_latency_ms": osd_item.get("commit_latency_ms"),
                            "device_class": osd_item.get("device_class"),
                            "osdtype": osd_item.get("osdtype"),
                            "ceph_version": osd_item.get("ceph_version"),
                            "ceph_version_short": osd_item.get("ceph_version_short"),
                            "tree_info": {
                                "name": osd_item.get("name"),
                                "host": osd_item.get("host"),
                                "status": osd_item.get("status"),
                                "crush_weight": osd_item.get("crush_weight"),
                                "reweight": osd_item.get("reweight")
                            }
                        }

                        # Try to get metadata if requested
                        if include_metadata:
                            try:
                                metadata = await client.get(f"/cluster/ceph/osd/{osd_num}/metadata")
                                if metadata.get("data"):
                                    osd_data["metadata"] = metadata["data"]
                            except ProxmoxVEError:
                                logger.debug(f"Metadata not available for OSD {osd_num}")

                        osd_details.append(osd_data)

                    else:
                        # Need to fetch OSD details from API
                        try:
                            # Get OSD details
                            osd_info = await client.get(f"/cluster/ceph/osd/{osd_num}")

                            if osd_info.get("data"):
                                osd_data = osd_info["data"]
                                osd_data["osd_id"] = osd_num

                                # Add tree information if we got it from tree
                                if use_tree:
                                    osd_data["tree_info"] = {
                                        "name": osd_item.get("name"),
                                        "host": osd_item.get("host"),
                                        "status": osd_item.get("status"),
                                        "reweight": osd_item.get("reweight"),
                                        "primary_affinity": osd_item.get("primary_affinity"),
                                        "crush_weight": osd_item.get("crush_weight")
                                    }
                                else:
                                    # Basic tree info without host
                                    osd_data["tree_info"] = {
                                        "name": osd_item.get("name", f"osd.{osd_num}"),
                                        "host": "unknown (tree not available)"
                                    }

                                # Try to get metadata if requested
                                if include_metadata:
                                    try:
                                        metadata = await client.get(f"/cluster/ceph/osd/{osd_num}/metadata")
                                        if metadata.get("data"):
                                            osd_data["metadata"] = metadata["data"]
                                            # If we didn't get host from tree, try to get from metadata
                                            if not use_tree and "hostname" in metadata["data"]:
                                                osd_data["tree_info"]["host"] = metadata["data"]["hostname"]
                                    except ProxmoxVEError:
                                        logger.debug(f"Metadata not available for OSD {osd_num}")

                                osd_details.append(osd_data)

                        except ProxmoxVEError as e:
                            logger.warning(f"Failed to get details for OSD {osd_num}: {e}")
                            continue

            # Create summary
            total_osds = len(osd_details)
            up_osds = sum(1 for osd in osd_details if osd.get("in") and osd.get("up"))

            return {
                "data": osd_details,
                "summary": {
                    "total_osds": total_osds,
                    "up_and_in": up_osds,
                    "queried_osd_id": osd_id,
                    "filtered_by_node": node,
                    "metadata_included": include_metadata
                },
                "display_message": f"Retrieved details for {total_osds} OSD(s)" + (f" on node {node}" if node else "")
            }

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
                return await _resolve_type_with_fallback(client, node, vmid, resolved_type, "/firewall/rules")
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

            # Try multiple endpoints as API varies by version
            # 1. Try hardware/cpu endpoint (newer versions)
            try:
                result = await client.get(f"/nodes/{node}/hardware/cpu")
                result["_source"] = "hardware/cpu"
                return result
            except ProxmoxVEError as e:
                if "501" not in str(e) and "404" not in str(e):
                    # If not "not implemented" or "not found", raise the error
                    raise

            # 2. Try to get CPU info from node status (fallback)
            try:
                status = await client.get(f"/nodes/{node}/status")
                if status.get("data"):
                    node_data = status["data"]
                    cpu_info = {
                        "model": node_data.get("cpuinfo", {}).get("model", "Unknown"),
                        "cpus": node_data.get("cpuinfo", {}).get("cpus", 0),
                        "sockets": node_data.get("cpuinfo", {}).get("sockets", 0),
                        "cores": node_data.get("cpuinfo", {}).get("cores", 0),
                        "usage": node_data.get("cpu", 0),
                        "flags": node_data.get("cpuinfo", {}).get("flags", ""),
                        "_source": "node/status",
                        "_note": "CPU details extracted from node status (hardware/cpu endpoint not available)"
                    }
                    return {"data": cpu_info}
            except ProxmoxVEError:
                pass

            # 3. Final fallback: Try to get basic info from cluster resources
            try:
                resources = await client.get("/cluster/resources", {"type": "node"})
                for resource in resources.get("data", []):
                    if resource.get("node") == node:
                        cpu_info = {
                            "model": "Unknown (use get_node_status for details)",
                            "cpus": resource.get("maxcpu", 0),
                            "usage_percent": round(resource.get("cpu", 0) * 100, 2) if resource.get("cpu") else 0,
                            "_source": "cluster/resources",
                            "_note": "Limited CPU info from cluster resources (hardware/cpu endpoint not available)"
                        }
                        return {"data": cpu_info}
            except ProxmoxVEError:
                pass

            # If all attempts failed
            raise ProxmoxVEError(f"Unable to retrieve CPU information for node {node}. Try using get_node_status instead.")
        
        elif name == "get_disk_info":
            node = arguments["node"]
            result = await client.get(f"/nodes/{node}/disks/list")

            # Process disk data to fix wearout display
            if result.get("data"):
                for disk in result["data"]:
                    # Fix wearout percentage
                    # Proxmox API returns remaining life percentage (100 = healthy, 0 = worn out)
                    # We need to convert it to wearout percentage (0 = new, 100 = worn out)
                    if "wearout" in disk:
                        wearout_value = disk.get("wearout")
                        if wearout_value is not None:
                            # Convert: API value of 100 (100% remaining) -> 0% wearout
                            #          API value of 0 (0% remaining) -> 100% wearout
                            try:
                                remaining_pct = float(wearout_value)
                                disk["wearout"] = 100 - remaining_pct
                                disk["wearout_display"] = f"{disk['wearout']:.0f}%"
                                disk["remaining_life"] = f"{remaining_pct:.0f}%"
                            except (ValueError, TypeError):
                                # If conversion fails, keep original value
                                disk["wearout_display"] = str(wearout_value)

            return result
        
        elif name == "get_performance_stats":
            node = arguments["node"]
            timeframe = arguments.get("timeframe", "hour")
            return await client.get(f"/nodes/{node}/rrddata", {"timeframe": timeframe})
        
        # get_vm_performance — unified into get_performance above

        # Log Management
        elif name == "get_system_logs":
            node = arguments["node"]
            limit = arguments.get("limit", 100)
            start = arguments.get("start", 0)
            service = arguments.get("service")

            # Try different parameter combinations as API varies by version
            param_combinations = [
                {"lastentries": limit},  # Most common: get last N entries
                {"lines": limit},        # Alternative parameter name
                {},                      # No params - get recent logs
            ]

            last_error = None
            for params in param_combinations:
                try:
                    # Add optional service filter if specified
                    if service:
                        params["service"] = service

                    # Try the request
                    result = await client.get(f"/nodes/{node}/journal", params if params else None)

                    # Success - return with params info
                    if isinstance(result, dict):
                        result["_params_used"] = params
                        return result
                    else:
                        return {
                            "data": result if isinstance(result, list) else [result],
                            "_params_used": params
                        }

                except ProxmoxVEError as e:
                    last_error = e
                    logger.warning(f"Failed to get system logs with params {params}: {e}")
                    continue

            # If all attempts failed, try syslog as fallback
            try:
                result = await client.get(f"/nodes/{node}/syslog", {"limit": limit})
                result["_endpoint_used"] = "syslog"
                return result
            except ProxmoxVEError:
                pass

            # If everything failed, raise the last error
            if last_error:
                raise last_error
            else:
                raise ProxmoxVEError(f"Failed to retrieve system logs from node {node}")
        
        elif name == "get_cluster_logs":
            limit = arguments.get("limit", 100)
            start = arguments.get("start", 0)
            errors = arguments.get("errors", False)
            vmid = arguments.get("vmid")

            # Try different endpoints as Proxmox VE API varies by version
            endpoints_to_try = [
                ("/cluster/log", {"max": limit}),  # Cluster event log
                ("/cluster/tasks", None),           # Task history (no params)
            ]

            last_error = None
            for endpoint, default_params in endpoints_to_try:
                try:
                    # Build params for this endpoint
                    if default_params:
                        params = default_params.copy()
                    else:
                        params = {}

                    # Add optional filters if supported
                    if vmid and endpoint == "/cluster/tasks":
                        params["vmid"] = vmid

                    if errors and endpoint == "/cluster/tasks":
                        params["errors"] = 1

                    if start > 0 and endpoint == "/cluster/tasks":
                        params["start"] = start

                    # Try the request
                    result = await client.get(endpoint, params if params else None)

                    # Success - return with endpoint info
                    if isinstance(result, dict) and "data" in result:
                        result["_endpoint_used"] = endpoint
                        return result
                    else:
                        return {
                            "data": result if isinstance(result, list) else [result],
                            "_endpoint_used": endpoint
                        }

                except ProxmoxVEError as e:
                    last_error = e
                    logger.warning(f"Failed to get logs from {endpoint}: {e}")
                    continue

            # If all endpoints failed, raise the last error
            if last_error:
                raise last_error
            else:
                raise ProxmoxVEError("Failed to retrieve cluster logs from any endpoint")
        
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
        
        # clone_vm, update_vm_config, delete_vm — unified into clone, update_config, delete above

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
        
        # clone_container, update_container_config, delete_container — unified above

        else:
            raise ProxmoxVEError(f"Tool '{name}' is not implemented. This should not happen as all tools are now implemented.")


# Dead code block removed in v1.5.0 (was unreachable duplicate of execute_tool)

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
        'transport': os.getenv("MCP_TRANSPORT", "stdio"),
        'http_host': os.getenv("MCP_HTTP_HOST", "0.0.0.0"),
        'http_port': int(os.getenv("MCP_HTTP_PORT", "8000")),
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
        elif arg == '--transport' and i + 1 < len(args):
            config['transport'] = args[i + 1]
            i += 1
        elif arg == '--http-host' and i + 1 < len(args):
            config['http_host'] = args[i + 1]
            i += 1
        elif arg == '--http-port' and i + 1 < len(args):
            config['http_port'] = int(args[i + 1])
            i += 1
        elif arg == '--test':
            config['test'] = True

        i += 1

    # Validate transport value
    valid_transports = ('stdio', 'streamable-http')
    if config['transport'] not in valid_transports:
        print(f"Error: --transport must be one of: {', '.join(valid_transports)} (got '{config['transport']}')", file=sys.stderr)
        sys.exit(1)

    return config

async def main():
    """Main function with enhanced error handling and logging"""
    try:
        global pve_config

        # ============================================================================
        # NETWORK DIAGNOSTICS - Added to debug Claude Desktop network issues
        # ============================================================================
        import socket

        print("=" * 60, file=sys.stderr)
        print("NETWORK DIAGNOSTICS - MCP Startup Debug Info", file=sys.stderr)
        print("=" * 60, file=sys.stderr)

        # 1. Output proxy-related environment variables
        proxy_vars = ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy',
                      'ALL_PROXY', 'all_proxy', 'NO_PROXY', 'no_proxy',
                      'SOCKS_PROXY', 'socks_proxy']
        print("\n[Proxy Environment Variables]", file=sys.stderr)
        proxy_found = False
        for var in proxy_vars:
            value = os.environ.get(var)
            if value:
                print(f"  {var}: {value}", file=sys.stderr)
                proxy_found = True
        if not proxy_found:
            print("  (No proxy variables set)", file=sys.stderr)

        # 2. Output PVE-related environment variables
        print("\n[PVE Environment Variables]", file=sys.stderr)
        pve_vars = ['PVE_HOST', 'PVE_API_TOKEN_ID', 'PVE_VERIFY_SSL', 'PVE_TIMEOUT']
        for var in pve_vars:
            value = os.environ.get(var, "(not set)")
            # Mask sensitive values
            if 'SECRET' in var or 'PASSWORD' in var:
                value = "***REDACTED***" if value and value != "(not set)" else "(not set)"
            print(f"  {var}: {value}", file=sys.stderr)

        # 3. Keep proxy variables - Claude Desktop sandbox requires proxy for network access
        print(f"\n[Proxy Variables] (kept for Claude Desktop sandbox compatibility)", file=sys.stderr)
        if proxy_found:
            print(f"  Proxy will be used for connections", file=sys.stderr)
        else:
            print(f"  No proxy configured", file=sys.stderr)

        # 4. DNS resolution test
        pve_host_env = os.environ.get('PVE_HOST', '')
        if pve_host_env:
            try:
                # Extract hostname from URL
                from urllib.parse import urlparse
                parsed = urlparse(pve_host_env)
                hostname = parsed.hostname or parsed.path.split(':')[0]
                print(f"\n[DNS Resolution Test]", file=sys.stderr)
                print(f"  Target hostname: {hostname}", file=sys.stderr)
                ip = socket.gethostbyname(hostname)
                print(f"  Resolved IP: {ip}", file=sys.stderr)
            except socket.gaierror as e:
                print(f"  DNS resolution FAILED: {e}", file=sys.stderr)
            except Exception as e:
                print(f"  DNS test error: {e}", file=sys.stderr)

        # 5. Network interface info
        print(f"\n[Network Info]", file=sys.stderr)
        try:
            local_hostname = socket.gethostname()
            print(f"  Local hostname: {local_hostname}", file=sys.stderr)
            # Try to get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.1)
            try:
                # Connect to a public IP to determine local interface
                s.connect(('8.8.8.8', 80))
                local_ip = s.getsockname()[0]
                print(f"  Local IP (outbound): {local_ip}", file=sys.stderr)
            except:
                print(f"  Local IP: Unable to determine", file=sys.stderr)
            finally:
                s.close()
        except Exception as e:
            print(f"  Network info error: {e}", file=sys.stderr)

        print("=" * 60, file=sys.stderr)
        print("END NETWORK DIAGNOSTICS", file=sys.stderr)
        print("=" * 60 + "\n", file=sys.stderr)
        # ============================================================================

        # Parse command line arguments
        config = parse_args()
        
        # Show help message
        if config['help']:
            print(f"Proxmox VE MCP Server - Enhanced Edition v{__version__}")
            print()
            print("Usage: python mcp_pve.py [OPTIONS]")
            print()
            print("Proxmox VE connection:")
            print("  --host HOST               PVE host URL (env: PVE_HOST)")
            print("  --username USER            PVE username (env: PVE_USERNAME)")
            print("  --password PASS            PVE password (env: PVE_PASSWORD)")
            print("  --api-token-id ID          PVE API token ID (env: PVE_API_TOKEN_ID)")
            print("  --api-token-secret SECRET  PVE API token secret (env: PVE_API_TOKEN_SECRET)")
            print("  --verify-ssl               Enable SSL verification (env: PVE_VERIFY_SSL)")
            print()
            print("Transport:")
            print("  --transport TYPE           Transport type: stdio | streamable-http (env: MCP_TRANSPORT, default: stdio)")
            print("  --http-host HOST           HTTP listen address (env: MCP_HTTP_HOST, default: 0.0.0.0)")
            print("  --http-port PORT           HTTP listen port (env: MCP_HTTP_PORT, default: 8000)")
            print()
            print("Other:")
            print("  --test                     Run in test mode")
            print("  -h, --help                 Show this help message")
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
        transport = config['transport']
        print(f"Proxmox VE MCP Server v{__version__} - Enhanced Edition starting...", file=sys.stderr)
        print(f"Host: {config['host']}", file=sys.stderr)
        print(f"Auth: {auth_method}", file=sys.stderr)
        print(f"Transport: {transport}", file=sys.stderr)
        print(f"Features: {len(await handle_list_tools())} tools available", file=sys.stderr)
        print("Enhanced MCP Server ready for connections", file=sys.stderr)

        # Run MCP server
        if transport == "stdio":
            from mcp.server.stdio import stdio_server

            async with stdio_server() as (read_stream, write_stream):
                await server.run(
                    read_stream,
                    write_stream,
                    InitializationOptions(
                        server_name="Proxmox_VE",
                        server_version=__version__,
                        capabilities=server.get_capabilities(
                            notification_options=NotificationOptions(),
                            experimental_capabilities={},
                        )
                    )
                )

        elif transport == "streamable-http":
            from contextlib import asynccontextmanager
            from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
            from starlette.applications import Starlette
            from starlette.routing import Mount
            import uvicorn

            session_manager = StreamableHTTPSessionManager(
                app=server,
                json_response=True,
            )

            @asynccontextmanager
            async def lifespan(app):
                async with session_manager.run():
                    yield

            starlette_app = Starlette(
                debug=False,
                routes=[
                    Mount("/mcp", app=session_manager.handle_request),
                ],
                lifespan=lifespan,
            )

            http_host = config['http_host']
            http_port = config['http_port']
            print(f"Streamable HTTP server listening on http://{http_host}:{http_port}/mcp", file=sys.stderr)

            uvicorn_config = uvicorn.Config(
                starlette_app,
                host=http_host,
                port=http_port,
                log_level="info",
            )
            uvicorn_server = uvicorn.Server(uvicorn_config)
            await uvicorn_server.serve()

    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
