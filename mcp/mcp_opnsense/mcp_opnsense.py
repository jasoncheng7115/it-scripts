#!/usr/bin/env python3
"""
OPNsense MCP Server
A Model Context Protocol server for OPNsense firewall management

Author: Jason Cheng (Jason Tools)
Version: 1.0.0
License: MIT
Created: 2025-06-25

This MCP server provides comprehensive OPNsense firewall management capabilities
including firewall rules, NAT rules, aliases, interfaces, and batch operations.
"""

import asyncio
import json
import logging
import os
import ssl
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import aiohttp
from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import (
    Resource,
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
    LoggingLevel,
    ServerCapabilities,
    ToolsCapability
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("opnsense-mcp")

__version__ = "1.0.0"
__author__ = "Jason Cheng (Jason Tools)"

class OPNsenseClient:
    """OPNsense API client"""
    
    def __init__(self):
        self.host = os.getenv("OPNSENSE_HOST", "https://192.168.1.1")
        self.api_key = os.getenv("OPNSENSE_API_KEY", "")
        self.api_secret = os.getenv("OPNSENSE_API_SECRET", "")
        self.verify_ssl = os.getenv("OPNSENSE_VERIFY_SSL", "false").lower() == "true"
        self.timeout = int(os.getenv("OPNSENSE_TIMEOUT", "30"))
        
        if not self.host.startswith(('http://', 'https://')):
            self.host = f"https://{self.host}"
            
        self.session = None
        self._ssl_context = self._create_ssl_context()
    
    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context"""
        if self.verify_ssl:
            return ssl.create_default_context()
        else:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            return context
    
    async def __aenter__(self):
        """Async context manager entry"""
        connector = aiohttp.TCPConnector(ssl=self._ssl_context)
        auth = aiohttp.BasicAuth(self.api_key, self.api_secret)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            auth=auth,
            timeout=timeout
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def _request(self, method: str, endpoint: str, data: Dict = None, params: Dict = None) -> Dict:
        """Send API request"""
        url = urljoin(self.host, endpoint)
        
        try:
            kwargs = {}
            if data:
                kwargs['json'] = data
            if params:
                kwargs['params'] = params
                
            async with self.session.request(method, url, **kwargs) as response:
                response_text = await response.text()
                
                if response.status == 200:
                    try:
                        return json.loads(response_text)
                    except json.JSONDecodeError:
                        return {"raw_response": response_text}
                else:
                    logger.error(f"API request failed: {response.status} - {response_text}")
                    raise Exception(f"API error {response.status}: {response_text}")
                    
        except Exception as e:
            logger.error(f"API request exception: {str(e)}")
            raise
    
    # === Firewall Rules Management ===
    
    async def search_firewall_rules(self, search_phrase: str = "", current: int = 1, 
                                  row_count: int = 100) -> Dict:
        """Search firewall rules"""
        params = {
            "current": current,
            "rowCount": row_count,
            "searchPhrase": search_phrase
        }
        return await self._request("GET", "/api/firewall/filter/searchRule", params=params)
    
    async def get_firewall_rule(self, uuid: str) -> Dict:
        """Get specific firewall rule"""
        return await self._request("GET", f"/api/firewall/filter/getRule/{uuid}")
    
    async def add_firewall_rule(self, rule_data: Dict) -> Dict:
        """Add firewall rule"""
        data = {"rule": rule_data}
        return await self._request("POST", "/api/firewall/filter/addRule", data=data)
    
    async def update_firewall_rule(self, uuid: str, rule_data: Dict) -> Dict:
        """Update firewall rule"""
        data = {"rule": rule_data}
        return await self._request("POST", f"/api/firewall/filter/setRule/{uuid}", data=data)
    
    async def delete_firewall_rule(self, uuid: str) -> Dict:
        """Delete firewall rule"""
        return await self._request("POST", f"/api/firewall/filter/delRule/{uuid}")
    
    async def toggle_firewall_rule(self, uuid: str, enabled: bool) -> Dict:
        """Enable/disable firewall rule"""
        enabled_value = "1" if enabled else "0"
        return await self._request("POST", f"/api/firewall/filter/toggleRule/{uuid}/{enabled_value}")
    
    async def get_all_firewall_rules(self) -> List[Dict]:
        """Get all firewall rules with pagination"""
        all_rules = []
        current_page = 1
        row_count = 100
        
        while True:
            result = await self.search_firewall_rules(current=current_page, row_count=row_count)
            
            if 'rows' in result and result['rows']:
                all_rules.extend(result['rows'])
                
                if len(result['rows']) < row_count:
                    break
                current_page += 1
            else:
                break
        
        return all_rules
    
    # === NAT Rules Management ===
    
    async def search_nat_rules(self, nat_type: str = "source_nat", search_phrase: str = "",
                              current: int = 1, row_count: int = 100) -> Dict:
        """Search NAT rules"""
        params = {
            "current": current,
            "rowCount": row_count,
            "searchPhrase": search_phrase
        }
        return await self._request("GET", f"/api/firewall/{nat_type}/searchRule", params=params)
    
    async def get_nat_rule(self, nat_type: str, uuid: str) -> Dict:
        """Get specific NAT rule"""
        return await self._request("GET", f"/api/firewall/{nat_type}/getRule/{uuid}")
    
    async def add_nat_rule(self, nat_type: str, rule_data: Dict) -> Dict:
        """Add NAT rule"""
        data = {"rule": rule_data}
        return await self._request("POST", f"/api/firewall/{nat_type}/addRule", data=data)
    
    # === Alias Management ===
    
    async def search_aliases(self, search_phrase: str = "", current: int = 1, 
                            row_count: int = 100) -> Dict:
        """Search aliases"""
        params = {
            "current": current,
            "rowCount": row_count,
            "searchPhrase": search_phrase
        }
        return await self._request("GET", "/api/firewall/alias/searchItem", params=params)
    
    async def get_alias(self, uuid: str) -> Dict:
        """Get specific alias"""
        return await self._request("GET", f"/api/firewall/alias/getItem/{uuid}")
    
    async def add_alias(self, alias_data: Dict) -> Dict:
        """Add alias"""
        data = {"alias": alias_data}
        return await self._request("POST", "/api/firewall/alias/addItem", data=data)
    
    async def update_alias(self, uuid: str, alias_data: Dict) -> Dict:
        """Update alias"""
        data = {"alias": alias_data}
        return await self._request("POST", f"/api/firewall/alias/setItem/{uuid}", data=data)
    
    async def delete_alias(self, uuid: str) -> Dict:
        """Delete alias"""
        return await self._request("POST", f"/api/firewall/alias/delItem/{uuid}")
    
    async def get_all_aliases(self) -> List[Dict]:
        """Get all aliases with pagination"""
        all_aliases = []
        current_page = 1
        row_count = 100
        
        while True:
            result = await self.search_aliases(current=current_page, row_count=row_count)
            
            if 'rows' in result and result['rows']:
                all_aliases.extend(result['rows'])
                
                if len(result['rows']) < row_count:
                    break
                current_page += 1
            else:
                break
        
        return all_aliases
    
    # === Alias Utility Functions ===
    
    async def list_alias_content(self, alias_name: str) -> Dict:
        """List alias content"""
        return await self._request("GET", f"/api/firewall/alias_util/list/{alias_name}")
    
    async def add_to_alias(self, alias_name: str, address: str) -> Dict:
        """Add address to alias"""
        data = {"address": address}
        return await self._request("POST", f"/api/firewall/alias_util/add/{alias_name}", data=data)
    
    async def remove_from_alias(self, alias_name: str, address: str) -> Dict:
        """Remove address from alias"""
        data = {"address": address}
        return await self._request("POST", f"/api/firewall/alias_util/delete/{alias_name}", data=data)
    
    # === Interface Management ===
    
    async def get_interface_overview(self) -> Dict:
        """Get interface overview - try multiple endpoints"""
        # Try different possible endpoints
        endpoints = [
            "/api/diagnostics/interface/getInterfaceNames",
            "/api/core/interface/search",
            "/api/interfaces/overview/export",
            "/api/diagnostics/interface/getInterface"
        ]
        
        for endpoint in endpoints:
            try:
                result = await self._request("GET", endpoint)
                if result:
                    return {"endpoint_used": endpoint, "data": result}
            except Exception as e:
                continue
        
        raise Exception("No working interface endpoint found")
    
    async def get_interface_config(self, interface: str) -> Dict:
        """Get interface configuration - try multiple endpoints"""
        endpoints = [
            f"/api/diagnostics/interface/getInterfaceConfig/{interface}",
            f"/api/interfaces/{interface}/get",
            f"/api/core/interface/{interface}"
        ]
        
        for endpoint in endpoints:
            try:
                return await self._request("GET", endpoint)
            except Exception as e:
                continue
        
        raise Exception(f"No working interface config endpoint found for {interface}")
    
    async def get_interface_status(self, interface: str) -> Dict:
        """Get interface status"""
        try:
            return await self._request("GET", f"/api/diagnostics/interface/getInterfaceConfig/{interface}")
        except Exception:
            # Fallback: try to get from interface names
            try:
                names = await self.get_interface_names()
                return {"interface": interface, "names_data": names}
            except Exception as e:
                raise Exception(f"Cannot get status for interface {interface}: {str(e)}")
    
    async def get_all_interfaces(self) -> List[Dict]:
        """Get all interfaces using available methods"""
        try:
            # Try to get interface overview first
            overview = await self.get_interface_overview()
            
            if 'data' in overview and isinstance(overview['data'], dict):
                # Convert dict to list format
                interfaces = []
                for key, value in overview['data'].items():
                    if isinstance(value, dict):
                        interface_data = value.copy()
                        interface_data['name'] = key
                        interfaces.append(interface_data)
                    else:
                        interfaces.append({"name": key, "data": value})
                
                return interfaces
            elif 'data' in overview and isinstance(overview['data'], list):
                return overview['data']
            else:
                return [overview]
                
        except Exception as e:
            # Fallback: return basic interface names
            try:
                names = await self.get_interface_names()
                interfaces = []
                for key, value in names.items():
                    interfaces.append({"name": key, "description": value})
                return interfaces
            except Exception:
                raise Exception(f"Cannot retrieve interfaces: {str(e)}")
    
    async def get_interface_statistics(self) -> Dict:
        """Get interface statistics"""
        endpoints = [
            "/api/diagnostics/interface/getInterfaceStatistics",
            "/api/diagnostics/interface/getStats",
            "/api/core/interface/statistics"
        ]
        
        for endpoint in endpoints:
            try:
                return await self._request("GET", endpoint)
            except Exception:
                continue
        
        raise Exception("No working interface statistics endpoint found")
    
    async def get_interface_names(self) -> Dict:
        """Get interface names mapping"""
        try:
            return await self._request("GET", "/api/diagnostics/interface/getInterfaceNames")
        except Exception as e:
            raise Exception(f"Cannot get interface names: {str(e)}")
    
    async def get_arp_table(self) -> Dict:
        """Get ARP table"""
        try:
            return await self._request("GET", "/api/diagnostics/interface/getArp")
        except Exception as e:
            raise Exception(f"Cannot get ARP table: {str(e)}")
    
    async def get_ndp_table(self) -> Dict:
        """Get NDP table (IPv6 neighbor discovery)"""
        try:
            return await self._request("GET", "/api/diagnostics/interface/getNdp")
        except Exception as e:
            raise Exception(f"Cannot get NDP table: {str(e)}")
    
    async def get_routes(self) -> Dict:
        """Get routing table"""
        endpoints = [
            "/api/routes/routes/searchRoute",
            "/api/diagnostics/interface/getRoutes",
            "/api/routes/routes/search"
        ]
        
        for endpoint in endpoints:
            try:
                result = await self._request("GET", endpoint)
                if result:
                    return result
            except Exception:
                continue
        
        raise Exception("No working routes endpoint found")
    
    # === Configuration Management ===
    
    async def create_savepoint(self) -> Dict:
        """Create configuration savepoint"""
        return await self._request("POST", "/api/firewall/filter/savepoint", data={})
    
    async def apply_changes(self, rollback_revision: str = None) -> Dict:
        """Apply changes"""
        endpoint = "/api/firewall/filter/apply"
        if rollback_revision:
            endpoint += f"/{rollback_revision}"
        return await self._request("POST", endpoint, data={})
    
    async def cancel_rollback(self, rollback_revision: str) -> Dict:
        """Cancel automatic rollback"""
        return await self._request("POST", f"/api/firewall/filter/cancelRollback/{rollback_revision}", data={})
    
    async def reconfigure_aliases(self) -> Dict:
        """Reconfigure aliases"""
        return await self._request("POST", "/api/firewall/alias/reconfigure", data={})

# Initialize the MCP server
server = Server("opnsense-mcp")

@server.list_tools()
async def handle_list_tools() -> List[Tool]:
    """List available tools"""
    return [
        Tool(
            name="get_firewall_rules",
            description="Get all firewall rules or search with filters",
            inputSchema={
                "type": "object",
                "properties": {
                    "search_phrase": {
                        "type": "string",
                        "description": "Search phrase to filter rules"
                    },
                    "interface": {
                        "type": "string",
                        "description": "Filter by interface (e.g., WAN, LAN)"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of rules to return",
                        "default": 100
                    }
                }
            }
        ),
        Tool(
            name="get_wan_public_rules",
            description="Get all WAN interface public-facing firewall rules",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="create_firewall_rule",
            description="Create a new firewall rule",
            inputSchema={
                "type": "object",
                "properties": {
                    "description": {
                        "type": "string",
                        "description": "Rule description"
                    },
                    "interface": {
                        "type": "string",
                        "description": "Interface (e.g., WAN, LAN)",
                        "default": "LAN"
                    },
                    "source_net": {
                        "type": "string",
                        "description": "Source network",
                        "default": "any"
                    },
                    "destination_net": {
                        "type": "string",
                        "description": "Destination network",
                        "default": "any"
                    },
                    "destination_port": {
                        "type": "string",
                        "description": "Destination port"
                    },
                    "protocol": {
                        "type": "string",
                        "description": "Protocol (TCP, UDP, any)",
                        "default": "any"
                    },
                    "action": {
                        "type": "string",
                        "description": "Action (pass, block)",
                        "default": "pass"
                    },
                    "enabled": {
                        "type": "boolean",
                        "description": "Enable rule",
                        "default": True
                    },
                    "apply_changes": {
                        "type": "boolean",
                        "description": "Apply changes after creation",
                        "default": True
                    },
                    "confirm": {
                        "type": "boolean",
                        "description": "Confirmation to proceed with the operation (required for safety)",
                        "default": False
                    }
                },
                "required": ["description"]
            }
        ),
        Tool(
            name="update_firewall_rule",
            description="Update an existing firewall rule",
            inputSchema={
                "type": "object",
                "properties": {
                    "uuid": {
                        "type": "string",
                        "description": "Rule UUID"
                    },
                    "description": {
                        "type": "string",
                        "description": "Rule description"
                    },
                    "interface": {
                        "type": "string",
                        "description": "Interface"
                    },
                    "source_net": {
                        "type": "string",
                        "description": "Source network"
                    },
                    "destination_net": {
                        "type": "string",
                        "description": "Destination network"
                    },
                    "destination_port": {
                        "type": "string",
                        "description": "Destination port"
                    },
                    "protocol": {
                        "type": "string",
                        "description": "Protocol"
                    },
                    "action": {
                        "type": "string",
                        "description": "Action"
                    },
                    "enabled": {
                        "type": "boolean",
                        "description": "Enable rule"
                    },
                    "apply_changes": {
                        "type": "boolean",
                        "description": "Apply changes after update",
                        "default": True
                    },
                    "confirm": {
                        "type": "boolean",
                        "description": "Confirmation to proceed with the operation (required for safety)",
                        "default": False
                    }
                },
                "required": ["uuid"]
            }
        ),
        Tool(
            name="delete_firewall_rule",
            description="Delete a firewall rule",
            inputSchema={
                "type": "object",
                "properties": {
                    "uuid": {
                        "type": "string",
                        "description": "Rule UUID"
                    },
                    "apply_changes": {
                        "type": "boolean",
                        "description": "Apply changes after deletion",
                        "default": True
                    },
                    "confirm": {
                        "type": "boolean",
                        "description": "Confirmation to proceed with the operation (required for safety)",
                        "default": False
                    }
                },
                "required": ["uuid"]
            }
        ),
        Tool(
            name="toggle_firewall_rule",
            description="Enable or disable a firewall rule",
            inputSchema={
                "type": "object",
                "properties": {
                    "uuid": {
                        "type": "string",
                        "description": "Rule UUID"
                    },
                    "enabled": {
                        "type": "boolean",
                        "description": "Enable or disable the rule"
                    },
                    "apply_changes": {
                        "type": "boolean",
                        "description": "Apply changes after toggle",
                        "default": True
                    },
                    "confirm": {
                        "type": "boolean",
                        "description": "Confirmation to proceed with the operation (required for safety)",
                        "default": False
                    }
                },
                "required": ["uuid", "enabled"]
            }
        ),
        Tool(
            name="get_aliases",
            description="Get all aliases or search with filters",
            inputSchema={
                "type": "object",
                "properties": {
                    "search_phrase": {
                        "type": "string",
                        "description": "Search phrase to filter aliases"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of aliases to return",
                        "default": 100
                    }
                }
            }
        ),
        Tool(
            name="create_alias",
            description="Create a new alias",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Alias name"
                    },
                    "type": {
                        "type": "string",
                        "description": "Alias type (host, network, port)",
                        "default": "host"
                    },
                    "content": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Alias content (IPs, networks, ports)"
                    },
                    "description": {
                        "type": "string",
                        "description": "Alias description"
                    },
                    "enabled": {
                        "type": "boolean",
                        "description": "Enable alias",
                        "default": True
                    },
                    "apply_changes": {
                        "type": "boolean",
                        "description": "Apply changes after creation",
                        "default": True
                    },
                    "confirm": {
                        "type": "boolean",
                        "description": "Confirmation to proceed with the operation (required for safety)",
                        "default": False
                    }
                },
                "required": ["name", "content"]
            }
        ),
        Tool(
            name="update_alias",
            description="Update an existing alias",
            inputSchema={
                "type": "object",
                "properties": {
                    "uuid": {
                        "type": "string",
                        "description": "Alias UUID"
                    },
                    "name": {
                        "type": "string",
                        "description": "Alias name"
                    },
                    "type": {
                        "type": "string",
                        "description": "Alias type"
                    },
                    "content": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Alias content"
                    },
                    "description": {
                        "type": "string",
                        "description": "Alias description"
                    },
                    "enabled": {
                        "type": "boolean",
                        "description": "Enable alias"
                    },
                    "apply_changes": {
                        "type": "boolean",
                        "description": "Apply changes after update",
                        "default": True
                    },
                    "confirm": {
                        "type": "boolean",
                        "description": "Confirmation to proceed with the operation (required for safety)",
                        "default": False
                    }
                },
                "required": ["uuid"]
            }
        ),
        Tool(
            name="delete_alias",
            description="Delete an alias",
            inputSchema={
                "type": "object",
                "properties": {
                    "uuid": {
                        "type": "string",
                        "description": "Alias UUID"
                    },
                    "apply_changes": {
                        "type": "boolean",
                        "description": "Apply changes after deletion",
                        "default": True
                    },
                    "confirm": {
                        "type": "boolean",
                        "description": "Confirmation to proceed with the operation (required for safety)",
                        "default": False
                    }
                },
                "required": ["uuid"]
            }
        ),
        Tool(
            name="manage_alias_content",
            description="Add or remove items from an alias",
            inputSchema={
                "type": "object",
                "properties": {
                    "alias_name": {
                        "type": "string",
                        "description": "Alias name"
                    },
                    "action": {
                        "type": "string",
                        "description": "Action to perform (add, remove, list)",
                        "enum": ["add", "remove", "list"]
                    },
                    "address": {
                        "type": "string",
                        "description": "Address to add or remove (required for add/remove)"
                    },
                    "apply_changes": {
                        "type": "boolean",
                        "description": "Apply changes after modification",
                        "default": True
                    },
                    "confirm": {
                        "type": "boolean",
                        "description": "Confirmation to proceed with the operation (required for safety)",
                        "default": False
                    }
                },
                "required": ["alias_name", "action"]
            }
        ),
        Tool(
            name="get_interfaces",
            description="Get all network interfaces information",
            inputSchema={
                "type": "object",
                "properties": {
                    "interface": {
                        "type": "string",
                        "description": "Specific interface name (optional)"
                    },
                    "include_status": {
                        "type": "boolean",
                        "description": "Include interface status information",
                        "default": True
                    },
                    "include_statistics": {
                        "type": "boolean",
                        "description": "Include interface statistics",
                        "default": False
                    }
                }
            }
        ),
        Tool(
            name="get_interface_config",
            description="Get configuration for a specific interface",
            inputSchema={
                "type": "object",
                "properties": {
                    "interface": {
                        "type": "string",
                        "description": "Interface name (e.g., wan, lan, opt1)"
                    }
                },
                "required": ["interface"]
            }
        ),
        Tool(
            name="get_interface_status",
            description="Get status information for a specific interface",
            inputSchema={
                "type": "object",
                "properties": {
                    "interface": {
                        "type": "string",
                        "description": "Interface name (e.g., wan, lan, opt1)"
                    }
                },
                "required": ["interface"]
            }
        ),
        Tool(
            name="get_interface_statistics",
            description="Get network interface statistics",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="get_arp_table",
            description="Get ARP table (IPv4 address to MAC mapping)",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="get_ndp_table",
            description="Get NDP table (IPv6 neighbor discovery)",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="get_routes",
            description="Get routing table information",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="get_network_overview",
            description="Get comprehensive network overview including interfaces, routes, and neighbor tables",
            inputSchema={
                "type": "object",
                "properties": {
                    "include_statistics": {
                        "type": "boolean",
                        "description": "Include detailed interface statistics",
                        "default": False
                    },
                    "include_neighbors": {
                        "type": "boolean",
                        "description": "Include ARP and NDP tables",
                        "default": True
                    },
                    "include_routes": {
                        "type": "boolean",
                        "description": "Include routing table",
                        "default": True
                    }
                }
            }
        ),
        Tool(
            name="get_nat_rules",
            description="Get NAT rules (Source NAT or One-to-One NAT)",
            inputSchema={
                "type": "object",
                "properties": {
                    "nat_type": {
                        "type": "string",
                        "description": "NAT type (source_nat, one_to_one)",
                        "enum": ["source_nat", "one_to_one"],
                        "default": "source_nat"
                    },
                    "search_phrase": {
                        "type": "string",
                        "description": "Search phrase to filter rules"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of rules to return",
                        "default": 100
                    }
                }
            }
        ),
        Tool(
            name="backup_configuration",
            description="Backup all OPNsense configuration to JSON",
            inputSchema={
                "type": "object",
                "properties": {
                    "include_rules": {
                        "type": "boolean",
                        "description": "Include firewall rules",
                        "default": True
                    },
                    "include_aliases": {
                        "type": "boolean",
                        "description": "Include aliases",
                        "default": True
                    },
                    "include_nat": {
                        "type": "boolean",
                        "description": "Include NAT rules",
                        "default": True
                    },
                    "include_interfaces": {
                        "type": "boolean",
                        "description": "Include interface information",
                        "default": True
                    }
                }
            }
        ),
        Tool(
            name="batch_create_rules",
            description="Batch create multiple firewall rules",
            inputSchema={
                "type": "object",
                "properties": {
                    "rules": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "description": {"type": "string"},
                                "interface": {"type": "string", "default": "LAN"},
                                "source_net": {"type": "string", "default": "any"},
                                "destination_net": {"type": "string", "default": "any"},
                                "destination_port": {"type": "string"},
                                "protocol": {"type": "string", "default": "any"},
                                "action": {"type": "string", "default": "pass"},
                                "enabled": {"type": "boolean", "default": True}
                            },
                            "required": ["description"]
                        },
                        "description": "Array of firewall rules to create"
                    },
                    "apply_changes": {
                        "type": "boolean",
                        "description": "Apply changes after creation",
                        "default": True
                    },
                    "use_savepoint": {
                        "type": "boolean",
                        "description": "Use savepoint for rollback protection",
                        "default": True
                    },
                    "confirm": {
                        "type": "boolean",
                        "description": "Confirmation to proceed with the batch operation (required for safety)",
                        "default": False
                    }
                },
                "required": ["rules"]
            }
        )
    ]

def requires_confirmation(tool_name: str, arguments: Dict[str, Any]) -> bool:
    """Check if tool requires user confirmation before execution"""
    # Tools that modify OPNsense configuration
    modification_tools = {
        "create_firewall_rule",
        "update_firewall_rule", 
        "delete_firewall_rule",
        "toggle_firewall_rule",
        "create_alias",
        "update_alias",
        "delete_alias",
        "batch_create_rules"
    }
    
    # Special case: manage_alias_content only requires confirmation for add/remove, not list
    if tool_name == "manage_alias_content":
        action = arguments.get("action", "")
        return action in ["add", "remove"]
    
    return tool_name in modification_tools

def generate_confirmation_message(tool_name: str, arguments: Dict[str, Any]) -> str:
    """Generate confirmation message for the tool"""
    
    if tool_name == "create_firewall_rule":
        return f"""⚠️  CONFIRMATION REQUIRED ⚠️

You are about to CREATE a new firewall rule:
- Description: {arguments.get('description', 'N/A')}
- Interface: {arguments.get('interface', 'LAN')}
- Source: {arguments.get('source_net', 'any')}
- Destination: {arguments.get('destination_net', 'any')}
- Port: {arguments.get('destination_port', 'any')}
- Protocol: {arguments.get('protocol', 'any')}
- Action: {arguments.get('action', 'pass')}
- Apply changes: {arguments.get('apply_changes', True)}

This will modify your OPNsense firewall configuration.
Please confirm if you want to proceed with this operation."""

    elif tool_name == "update_firewall_rule":
        return f"""⚠️  CONFIRMATION REQUIRED ⚠️

You are about to UPDATE firewall rule:
- Rule UUID: {arguments.get('uuid', 'N/A')}
- Apply changes: {arguments.get('apply_changes', True)}

This will modify your OPNsense firewall configuration.
Please confirm if you want to proceed with this operation."""

    elif tool_name == "delete_firewall_rule":
        return f"""⚠️  CONFIRMATION REQUIRED ⚠️

You are about to DELETE firewall rule:
- Rule UUID: {arguments.get('uuid', 'N/A')}
- Apply changes: {arguments.get('apply_changes', True)}

This will permanently remove the rule from your OPNsense firewall.
Please confirm if you want to proceed with this operation."""

    elif tool_name == "toggle_firewall_rule":
        action = "ENABLE" if arguments.get('enabled', False) else "DISABLE"
        return f"""⚠️  CONFIRMATION REQUIRED ⚠️

You are about to {action} firewall rule:
- Rule UUID: {arguments.get('uuid', 'N/A')}
- Apply changes: {arguments.get('apply_changes', True)}

This will modify your OPNsense firewall configuration.
Please confirm if you want to proceed with this operation."""

    elif tool_name == "create_alias":
        content_preview = arguments.get('content', [])[:5]  # Show first 5 items
        content_str = ', '.join(content_preview)
        if len(arguments.get('content', [])) > 5:
            content_str += f" ... (and {len(arguments.get('content', [])) - 5} more)"
            
        return f"""⚠️  CONFIRMATION REQUIRED ⚠️

You are about to CREATE a new alias:
- Name: {arguments.get('name', 'N/A')}
- Type: {arguments.get('type', 'host')}
- Content: {content_str}
- Description: {arguments.get('description', 'N/A')}
- Apply changes: {arguments.get('apply_changes', True)}

This will modify your OPNsense alias configuration.
Please confirm if you want to proceed with this operation."""

    elif tool_name == "update_alias":
        return f"""⚠️  CONFIRMATION REQUIRED ⚠️

You are about to UPDATE alias:
- Alias UUID: {arguments.get('uuid', 'N/A')}
- Apply changes: {arguments.get('apply_changes', True)}

This will modify your OPNsense alias configuration.
Please confirm if you want to proceed with this operation."""

    elif tool_name == "delete_alias":
        return f"""⚠️  CONFIRMATION REQUIRED ⚠️

You are about to DELETE alias:
- Alias UUID: {arguments.get('uuid', 'N/A')}
- Apply changes: {arguments.get('apply_changes', True)}

This will permanently remove the alias from your OPNsense configuration.
Please confirm if you want to proceed with this operation."""

    elif tool_name == "manage_alias_content":
        action = arguments.get('action', 'N/A').upper()
        return f"""⚠️  CONFIRMATION REQUIRED ⚠️

You are about to {action} alias content:
- Alias name: {arguments.get('alias_name', 'N/A')}
- Action: {action}
- Address: {arguments.get('address', 'N/A')}
- Apply changes: {arguments.get('apply_changes', True)}

This will modify your OPNsense alias configuration.
Please confirm if you want to proceed with this operation."""

    elif tool_name == "batch_create_rules":
        rules_count = len(arguments.get('rules', []))
        rules_preview = []
        for i, rule in enumerate(arguments.get('rules', [])[:3]):
            rules_preview.append(f"  {i+1}. {rule.get('description', 'N/A')}")
        
        preview_text = '\n'.join(rules_preview)
        if rules_count > 3:
            preview_text += f"\n  ... (and {rules_count - 3} more rules)"
            
        return f"""⚠️  CONFIRMATION REQUIRED ⚠️

You are about to BATCH CREATE {rules_count} firewall rules:
{preview_text}

Settings:
- Apply changes: {arguments.get('apply_changes', True)}
- Use savepoint: {arguments.get('use_savepoint', True)}

This will modify your OPNsense firewall configuration significantly.
Please confirm if you want to proceed with this batch operation."""

    else:
        return f"""⚠️  CONFIRMATION REQUIRED ⚠️

You are about to perform operation: {tool_name}
This will modify your OPNsense configuration.
Please confirm if you want to proceed with this operation."""

@server.call_tool()
async def handle_call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Handle tool calls"""
    
    # Check if tool requires confirmation
    if requires_confirmation(name, arguments):
        # Check if user has provided confirmation
        user_confirmed = arguments.get("confirm", False)
        
        if not user_confirmed:
            confirmation_msg = generate_confirmation_message(name, arguments)
            return [TextContent(
                type="text",
                text=f"{confirmation_msg}\n\n" +
                     "To proceed, please call this tool again with 'confirm': true in the parameters.\n\n" +
                     "Example: Use the same parameters but add '\"confirm\": true'"
            )]
    
    try:
        async with OPNsenseClient() as client:
            
            if name == "get_firewall_rules":
                search_phrase = arguments.get("search_phrase", "")
                interface_filter = arguments.get("interface", "")
                limit = arguments.get("limit", 100)
                
                rules = await client.get_all_firewall_rules()
                
                # Apply filters
                if interface_filter:
                    rules = [r for r in rules if r.get('interface', '').upper() == interface_filter.upper()]
                
                if search_phrase:
                    rules = [r for r in rules if search_phrase.lower() in r.get('description', '').lower()]
                
                # Apply limit
                if limit and limit > 0:
                    rules = rules[:limit]
                
                result = {
                    "total_rules": len(rules),
                    "rules": rules
                }
                
                return [TextContent(
                    type="text",
                    text=f"Retrieved {len(rules)} firewall rules:\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "get_wan_public_rules":
                all_rules = await client.get_all_firewall_rules()
                wan_rules = [
                    rule for rule in all_rules 
                    if (rule.get('interface', '').upper() == 'WAN' and 
                        rule.get('action', '') == 'pass' and
                        rule.get('direction', '') == 'in')
                ]
                
                result = {
                    "total_wan_rules": len(wan_rules),
                    "wan_public_rules": wan_rules
                }
                
                return [TextContent(
                    type="text",
                    text=f"Found {len(wan_rules)} WAN public-facing rules:\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "create_firewall_rule":
                rule_data = {
                    "description": arguments["description"],
                    "interface": arguments.get("interface", "LAN"),
                    "source_net": arguments.get("source_net", "any"),
                    "destination_net": arguments.get("destination_net", "any"),
                    "protocol": arguments.get("protocol", "any"),
                    "action": arguments.get("action", "pass"),
                    "direction": "in",
                    "enabled": "1" if arguments.get("enabled", True) else "0"
                }
                
                if arguments.get("destination_port"):
                    rule_data["destination_port"] = arguments["destination_port"]
                
                result = await client.add_firewall_rule(rule_data)
                
                if arguments.get("apply_changes", True):
                    await client.apply_changes()
                    result["changes_applied"] = True
                
                return [TextContent(
                    type="text",
                    text=f"Firewall rule created successfully:\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "update_firewall_rule":
                uuid = arguments["uuid"]
                rule_data = {}
                
                # Only include provided fields
                for field in ["description", "interface", "source_net", "destination_net", 
                             "destination_port", "protocol", "action"]:
                    if field in arguments:
                        rule_data[field] = arguments[field]
                
                if "enabled" in arguments:
                    rule_data["enabled"] = "1" if arguments["enabled"] else "0"
                
                result = await client.update_firewall_rule(uuid, rule_data)
                
                if arguments.get("apply_changes", True):
                    await client.apply_changes()
                    result["changes_applied"] = True
                
                return [TextContent(
                    type="text",
                    text=f"Firewall rule updated successfully:\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "delete_firewall_rule":
                uuid = arguments["uuid"]
                result = await client.delete_firewall_rule(uuid)
                
                if arguments.get("apply_changes", True):
                    await client.apply_changes()
                    result["changes_applied"] = True
                
                return [TextContent(
                    type="text",
                    text=f"Firewall rule deleted successfully:\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "toggle_firewall_rule":
                uuid = arguments["uuid"]
                enabled = arguments["enabled"]
                
                result = await client.toggle_firewall_rule(uuid, enabled)
                
                if arguments.get("apply_changes", True):
                    await client.apply_changes()
                    result["changes_applied"] = True
                
                action = "enabled" if enabled else "disabled"
                return [TextContent(
                    type="text",
                    text=f"Firewall rule {action} successfully:\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "get_aliases":
                search_phrase = arguments.get("search_phrase", "")
                limit = arguments.get("limit", 100)
                
                aliases = await client.get_all_aliases()
                
                # Apply search filter
                if search_phrase:
                    aliases = [a for a in aliases if search_phrase.lower() in a.get('name', '').lower()]
                
                # Apply limit
                if limit and limit > 0:
                    aliases = aliases[:limit]
                
                result = {
                    "total_aliases": len(aliases),
                    "aliases": aliases
                }
                
                return [TextContent(
                    type="text",
                    text=f"Retrieved {len(aliases)} aliases:\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "create_alias":
                alias_data = {
                    "name": arguments["name"],
                    "type": arguments.get("type", "host"),
                    "content": "\n".join(arguments["content"]),
                    "description": arguments.get("description", ""),
                    "enabled": "1" if arguments.get("enabled", True) else "0"
                }
                
                result = await client.add_alias(alias_data)
                
                if arguments.get("apply_changes", True):
                    await client.reconfigure_aliases()
                    result["changes_applied"] = True
                
                return [TextContent(
                    type="text",
                    text=f"Alias created successfully:\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "update_alias":
                uuid = arguments["uuid"]
                alias_data = {}
                
                # Only include provided fields
                for field in ["name", "type", "description"]:
                    if field in arguments:
                        alias_data[field] = arguments[field]
                
                if "content" in arguments:
                    alias_data["content"] = "\n".join(arguments["content"])
                
                if "enabled" in arguments:
                    alias_data["enabled"] = "1" if arguments["enabled"] else "0"
                
                result = await client.update_alias(uuid, alias_data)
                
                if arguments.get("apply_changes", True):
                    await client.reconfigure_aliases()
                    result["changes_applied"] = True
                
                return [TextContent(
                    type="text",
                    text=f"Alias updated successfully:\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "delete_alias":
                uuid = arguments["uuid"]
                result = await client.delete_alias(uuid)
                
                if arguments.get("apply_changes", True):
                    await client.reconfigure_aliases()
                    result["changes_applied"] = True
                
                return [TextContent(
                    type="text",
                    text=f"Alias deleted successfully:\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "manage_alias_content":
                alias_name = arguments["alias_name"]
                action = arguments["action"]
                
                if action == "list":
                    # List operation doesn't require confirmation
                    result = await client.list_alias_content(alias_name)
                elif action == "add":
                    address = arguments["address"]
                    result = await client.add_to_alias(alias_name, address)
                    if arguments.get("apply_changes", True):
                        await client.reconfigure_aliases()
                        result["changes_applied"] = True
                elif action == "remove":
                    address = arguments["address"]
                    result = await client.remove_from_alias(alias_name, address)
                    if arguments.get("apply_changes", True):
                        await client.reconfigure_aliases()
                        result["changes_applied"] = True
                
                return [TextContent(
                    type="text",
                    text=f"Alias {action} operation completed:\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "get_interfaces":
                interface = arguments.get("interface")
                include_status = arguments.get("include_status", True)
                include_statistics = arguments.get("include_statistics", False)
                
                if interface:
                    # Get specific interface
                    interface_data = {}
                    try:
                        interface_data["config"] = await client.get_interface_config(interface)
                    except Exception as e:
                        interface_data["config_error"] = str(e)
                    
                    if include_status:
                        try:
                            interface_data["status"] = await client.get_interface_status(interface)
                        except Exception as e:
                            interface_data["status_error"] = str(e)
                    
                    result = {
                        "interface": interface,
                        "data": interface_data
                    }
                else:
                    # Get all interfaces
                    interfaces = await client.get_all_interfaces()
                    
                    # Get interface names mapping
                    try:
                        names_mapping = await client.get_interface_names()
                    except Exception as e:
                        names_mapping = {"error": str(e)}
                    
                    result = {
                        "total_interfaces": len(interfaces),
                        "interfaces": interfaces,
                        "interface_names": names_mapping
                    }
                    
                    if include_statistics:
                        try:
                            result["statistics"] = await client.get_interface_statistics()
                        except Exception as e:
                            result["statistics_error"] = str(e)
                
                return [TextContent(
                    type="text",
                    text=f"Interface information retrieved:\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "get_interface_config":
                interface = arguments["interface"]
                result = await client.get_interface_config(interface)
                
                return [TextContent(
                    type="text",
                    text=f"Configuration for interface {interface}:\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "get_interface_status":
                interface = arguments["interface"]
                result = await client.get_interface_status(interface)
                
                return [TextContent(
                    type="text",
                    text=f"Status for interface {interface}:\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "get_interface_statistics":
                result = await client.get_interface_statistics()
                
                return [TextContent(
                    type="text",
                    text="Interface statistics:\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "get_arp_table":
                result = await client.get_arp_table()
                
                return [TextContent(
                    type="text",
                    text="ARP table:\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "get_ndp_table":
                result = await client.get_ndp_table()
                
                return [TextContent(
                    type="text",
                    text="NDP table (IPv6 neighbors):\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "get_routes":
                result = await client.get_routes()
                
                return [TextContent(
                    type="text",
                    text="Routing table:\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "get_network_overview":
                include_statistics = arguments.get("include_statistics", False)
                include_neighbors = arguments.get("include_neighbors", True)
                include_routes = arguments.get("include_routes", True)
                
                overview = {
                    "timestamp": datetime.now().isoformat(),
                    "overview_type": "network_comprehensive"
                }
                
                # Get interfaces
                try:
                    overview["interfaces"] = await client.get_all_interfaces()
                    overview["interface_names"] = await client.get_interface_names()
                except Exception as e:
                    overview["interfaces_error"] = str(e)
                
                # Get statistics if requested
                if include_statistics:
                    try:
                        overview["interface_statistics"] = await client.get_interface_statistics()
                    except Exception as e:
                        overview["statistics_error"] = str(e)
                
                # Get neighbor tables if requested
                if include_neighbors:
                    try:
                        overview["arp_table"] = await client.get_arp_table()
                        overview["ndp_table"] = await client.get_ndp_table()
                    except Exception as e:
                        overview["neighbors_error"] = str(e)
                
                # Get routes if requested
                if include_routes:
                    try:
                        overview["routes"] = await client.get_routes()
                    except Exception as e:
                        overview["routes_error"] = str(e)
                
                return [TextContent(
                    type="text",
                    text="Comprehensive network overview:\n\n" + 
                         json.dumps(overview, indent=2, ensure_ascii=False)
                )]
            
            elif name == "get_nat_rules":
                nat_type = arguments.get("nat_type", "source_nat")
                search_phrase = arguments.get("search_phrase", "")
                limit = arguments.get("limit", 100)
                
                result = await client.search_nat_rules(nat_type, search_phrase, row_count=limit)
                
                return [TextContent(
                    type="text",
                    text=f"Retrieved {nat_type} rules:\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "backup_configuration":
                include_rules = arguments.get("include_rules", True)
                include_aliases = arguments.get("include_aliases", True)
                include_nat = arguments.get("include_nat", True)
                include_interfaces = arguments.get("include_interfaces", True)
                
                backup_data = {
                    "timestamp": datetime.now().isoformat(),
                    "version": __version__
                }
                
                if include_rules:
                    backup_data["firewall_rules"] = await client.get_all_firewall_rules()
                
                if include_aliases:
                    backup_data["aliases"] = await client.get_all_aliases()
                
                if include_nat:
                    source_nat = await client.search_nat_rules("source_nat", row_count=1000)
                    one_to_one = await client.search_nat_rules("one_to_one", row_count=1000)
                    backup_data["source_nat_rules"] = source_nat.get('rows', [])
                    backup_data["one_to_one_rules"] = one_to_one.get('rows', [])
                
                if include_interfaces:
                    try:
                        backup_data["interfaces"] = await client.get_all_interfaces()
                        backup_data["interface_names"] = await client.get_interface_names()
                        backup_data["arp_table"] = await client.get_arp_table()
                        backup_data["routes"] = await client.get_routes()
                    except Exception as e:
                        backup_data["interfaces_error"] = str(e)
                
                return [TextContent(
                    type="text",
                    text=f"Configuration backup completed:\n\n" + 
                         json.dumps(backup_data, indent=2, ensure_ascii=False)
                )]
            
            elif name == "batch_create_rules":
                rules = arguments["rules"]
                apply_changes = arguments.get("apply_changes", True)
                use_savepoint = arguments.get("use_savepoint", True)
                
                results = []
                savepoint_data = None
                
                try:
                    if use_savepoint:
                        savepoint_data = await client.create_savepoint()
                    
                    for i, rule in enumerate(rules):
                        try:
                            rule_data = {
                                "description": rule["description"],
                                "interface": rule.get("interface", "LAN"),
                                "source_net": rule.get("source_net", "any"),
                                "destination_net": rule.get("destination_net", "any"),
                                "protocol": rule.get("protocol", "any"),
                                "action": rule.get("action", "pass"),
                                "direction": "in",
                                "enabled": "1" if rule.get("enabled", True) else "0"
                            }
                            
                            if rule.get("destination_port"):
                                rule_data["destination_port"] = rule["destination_port"]
                            
                            result = await client.add_firewall_rule(rule_data)
                            results.append({
                                "index": i,
                                "rule_description": rule["description"],
                                "status": "success",
                                "uuid": result.get("uuid")
                            })
                            
                        except Exception as e:
                            results.append({
                                "index": i,
                                "rule_description": rule["description"],
                                "status": "error",
                                "error": str(e)
                            })
                    
                    if apply_changes:
                        await client.apply_changes(savepoint_data.get('revision') if savepoint_data else None)
                        
                        if use_savepoint and savepoint_data:
                            # Wait 5 seconds then cancel rollback
                            await asyncio.sleep(5)
                            await client.cancel_rollback(savepoint_data.get('revision'))
                    
                    batch_result = {
                        "total_rules": len(rules),
                        "successful": len([r for r in results if r['status'] == 'success']),
                        "failed": len([r for r in results if r['status'] == 'error']),
                        "results": results,
                        "savepoint": savepoint_data.get('revision') if savepoint_data else None,
                        "changes_applied": apply_changes
                    }
                    
                    return [TextContent(
                        type="text",
                        text=f"Batch rule creation completed:\n\n" + 
                             json.dumps(batch_result, indent=2, ensure_ascii=False)
                    )]
                    
                except Exception as e:
                    if savepoint_data and use_savepoint:
                        error_msg = f"Batch operation failed, will auto-rollback in 60 seconds: {str(e)}"
                    else:
                        error_msg = f"Batch operation failed: {str(e)}"
                    
                    return [TextContent(
                        type="text",
                        text=error_msg
                    )]
            
            else:
                return [TextContent(
                    type="text",
                    text=f"Unknown tool: {name}"
                )]
                
    except Exception as e:
        logger.error(f"Tool execution error: {str(e)}")
        return [TextContent(
            type="text",
            text=f"Error executing tool {name}: {str(e)}"
        )]

async def main():
    """Main function to run the MCP server"""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="opnsense-mcp",
                server_version=__version__,
                capabilities=ServerCapabilities(
                    tools=ToolsCapability()
                ),
            ),
        )

if __name__ == "__main__":
    asyncio.run(main())
