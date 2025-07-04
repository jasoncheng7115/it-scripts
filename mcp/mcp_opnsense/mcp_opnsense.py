#!/usr/bin/env python3
"""
OPNsense MCP Server - Config.xml Based (Fixed Version)
A Model Context Protocol server for OPNsense firewall management (read-only)

Author: Jason Cheng (Jason Tools)
Version: 1.4.2
License: MIT
Created: 2025-06-25
Updated: 2025-07-04 - Fixed disabled/enabled rule detection logic

This MCP server provides OPNsense firewall rule reading capabilities
by parsing config.xml directly (read-only operations only).

Fixed Issues:
- Corrected disabled/enabled rule detection to properly check for <disabled>1</disabled> tags
- Improved XML parsing logic for various rule types
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
import requests
import urllib3
from requests.auth import HTTPBasicAuth
from defusedxml import ElementTree as ET
from xml.etree.ElementTree import Element  # For type hints only
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

__version__ = "1.4.1"
__author__ = "Jason Cheng (Jason Tools)"

class OPNsenseClient:
    """OPNsense API client for config.xml reading"""
    
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
        
        # Disable SSL warnings if verification is disabled
        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
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
    
    async def download_config_xml(self) -> Element:
        """Download config.xml using synchronous request (as XML parsing is sync)"""
        try:
            # Use synchronous requests for XML download as it's simpler
            url = f"{self.host}/api/core/backup/download/this"
            response = requests.get(
                url, 
                auth=HTTPBasicAuth(self.api_key, self.api_secret), 
                verify=self.verify_ssl, 
                timeout=self.timeout
            )
            
            if response.status_code == 404:
                raise RuntimeError(
                    "Could not find /api/core/backup/download/this endpoint. "
                    "Requires OPNsense ≥ 23.7.8 or os-api-backup plugin"
                )
            
            response.raise_for_status()
            
            # Check if response is JSON (error response)
            if response.headers.get("content-type", "").startswith("application/json"):
                raise RuntimeError(f"API returned error: {response.text}")
            
            try:
                return ET.fromstring(response.content)
            except ET.ParseError as exc:
                raise RuntimeError(f"config.xml parsing failed: {exc}") from exc
                
        except Exception as e:
            logger.error(f"Config XML download failed: {str(e)}")
            raise
    
    def _is_disabled(self, elem: Optional[Element]) -> bool:
        """
        Check if an element is disabled based on the <disabled> tag
        
        Args:
            elem: XML element to check for disabled status
            
        Returns:
            True if disabled (has <disabled>1</disabled> or <disabled>yes</disabled>)
            False if enabled (no disabled tag or disabled tag is not "1"/"yes")
        """
        if elem is None:
            return False
            
        disabled_elem = elem.find("disabled")
        if disabled_elem is None:
            return False
            
        disabled_value = disabled_elem.text
        if disabled_value is None:
            return False
            
        disabled_value = disabled_value.strip().lower()
        return disabled_value in ("1", "yes", "true")
    
    def _parse_firewall_rules_from_xml(self, root: Element) -> List[Dict[str, Any]]:
        """Parse firewall rules from config.xml root element"""
        def txt(elem: Optional[Element], default="") -> str:
            return elem.text.strip() if elem is not None and elem.text else default
        
        # Build alias index for reference detection
        alias_names = {txt(a.find("name")) for a in root.findall("./aliases/alias")}
        
        rules: List[Dict[str, Any]] = []
        for node in root.findall("./filter/rule"):
            src_addr = txt(node.find("source/address"))
            dst_addr = txt(node.find("destination/address"))
            
            # Extract additional fields that might be useful
            rule_data = {
                "tracker": txt(node.find("tracker")),
                "description": txt(node.find("descr")),
                "interface": txt(node.find("interface")),
                "action": txt(node.find("type")),
                "protocol": txt(node.find("protocol")),
                "src_addr": src_addr,
                "src_port": txt(node.find("source/port")),
                "dst_addr": dst_addr,
                "dst_port": txt(node.find("destination/port")),
                "src_alias": src_addr if src_addr in alias_names else "",
                "dst_alias": dst_addr if dst_addr in alias_names else "",
                "enabled": not self._is_disabled(node),  # Fixed: Use proper disabled check
                "direction": txt(node.find("direction"), "in"),
                "ipprotocol": txt(node.find("ipprotocol"), "inet"),
                "statetype": txt(node.find("statetype")),
                "created": txt(node.find("created")),
                "updated": txt(node.find("updated"))
            }
            
            # Add gateway information if present
            gateway = txt(node.find("gateway"))
            if gateway:
                rule_data["gateway"] = gateway
            
            # Check if log is enabled (tag exists = enabled, regardless of content)
            log_elem = node.find("log")
            rule_data["log"] = log_elem is not None

            # Check if quick is enabled (tag exists = enabled, regardless of content)  
            quick_elem = node.find("quick")
            rule_data["quick"] = quick_elem is not None

            rules.append(rule_data)
        
        return rules
    
    def _parse_aliases_from_xml(self, root: Element) -> List[Dict[str, Any]]:
        """
        Parse aliases from config.xml root element
        Enhanced version based on test_alias2.py with fixed disabled logic
        """
        def txt(elem: Optional[Element], default="") -> str:
            return elem.text.strip() if elem is not None and elem.text else default
        
        aliases: List[Dict[str, Any]] = []
        
        # Use findall(".//alias") to capture all hierarchy levels of alias
        for node in root.findall(".//alias"):
            name = txt(node.find("name"))
            if not name:  # Skip if no name
                continue
                
            alias_type = txt(node.find("type"))
            
            # content/address/url three choices, prioritize content
            content = txt(node.find("content")) or txt(node.find("address")) or txt(node.find("url"))
            # Convert newlines to comma-separated
            content = content.replace("\n", ", ").strip()
            
            # Try both description and descr
            description = txt(node.find("description")) or txt(node.find("descr"))
            
            alias_data = {
                "name": name,
                "type": alias_type,
                "content": content,
                "description": description,
                "enabled": not self._is_disabled(node)  # Fixed: Use proper disabled check
            }
            
            # Parse content into list if it contains multiple entries
            if content:
                if ", " in content:
                    alias_data["content_list"] = [item.strip() for item in content.split(", ") if item.strip()]
                elif "\n" in content:
                    alias_data["content_list"] = [item.strip() for item in content.split("\n") if item.strip()]
                else:
                    alias_data["content_list"] = [content.strip()] if content.strip() else []
                alias_data["content_count"] = len(alias_data["content_list"])
            else:
                alias_data["content_list"] = []
                alias_data["content_count"] = 0
            
            aliases.append(alias_data)
        
        return aliases
    
    def _parse_nat_rules_from_xml(self, root: Element, rule_type: str) -> List[Dict[str, Any]]:
        """
        Parse NAT rules from config.xml root element
        Enhanced version based on test_nat.py with fixed disabled logic
        
        Args:
            root: XML root element
            rule_type: One of 'forward', 'outbound', 'source', 'one_to_one', 'filter'
        """
        def txt(elem: Optional[Element], default: str = "") -> str:
            return elem.text.strip() if elem is not None and elem.text else default

        rules: List[Dict[str, Any]] = []

        if rule_type == "forward":
            for node in root.findall("./nat/rule"):
                nat_ip = txt(node.find("target"))
                nat_port = txt(node.find("local-port"))
                rules.append({
                    "uuid": txt(node.find("uuid")),
                    "description": txt(node.find("descr")),
                    "interface": txt(node.find("interface")),
                    "protocol": txt(node.find("protocol")),
                    "source": txt(node.find("source/address")),
                    "src_port": txt(node.find("source/port")),
                    "destination": txt(node.find("destination/address")),
                    "dst_port": txt(node.find("destination/port")),
                    "nat_ip": nat_ip,
                    "nat_port": nat_port,
                    "enabled": not self._is_disabled(node),  # Fixed: Use proper disabled check
                })

        elif rule_type == "outbound":
            for node in root.findall("./nat/outbound/rule"):
                rules.append({
                    "uuid": txt(node.find("uuid")),
                    "description": txt(node.find("descr")),
                    "source": txt(node.find("source/network")),
                    "src_port": txt(node.find("source/port")),
                    "destination": txt(node.find("destination/network")),
                    "dst_port": txt(node.find("destination/port")),
                    "translation": txt(node.find("translation/address")),
                    "interface": txt(node.find("interface")),
                    "proto": txt(node.find("protocol")),
                    "enabled": not self._is_disabled(node),  # Fixed: Use proper disabled check
                })

        elif rule_type == "source":
            for node in root.findall("./nat/advancedoutbound/rule") + root.findall("./nat/source/rule"):
                rules.append({
                    "uuid": txt(node.find("uuid")),
                    "description": txt(node.find("descr")),
                    "source": txt(node.find("source/network")),
                    "translation": txt(node.find("translation/address")),
                    "interface": txt(node.find("interface")),
                    "proto": txt(node.find("protocol")),
                    "enabled": not self._is_disabled(node),  # Fixed: Use proper disabled check
                })

        elif rule_type == "one_to_one":
            for node in root.findall("./nat/onetoone/rule"):
                rules.append({
                    "uuid": txt(node.find("uuid")),
                    "description": txt(node.find("descr")),
                    "external": txt(node.find("external")),
                    "internal": txt(node.find("internal")),
                    "interface": txt(node.find("interface")),
                    "proto": txt(node.find("protocol")),
                    "enabled": not self._is_disabled(node),  # Fixed: Use proper disabled check
                })

        elif rule_type == "filter":
            for node in root.findall("./filter/rule"):
                rules.append({
                    "uuid": txt(node.find("uuid")),
                    "description": txt(node.find("descr")),
                    "interface": txt(node.find("interface")),
                    "proto": txt(node.find("protocol")),
                    "source": txt(node.find("source/network")),
                    "destination": txt(node.find("destination/network")),
                    "action": txt(node.find("type")),
                    "enabled": not self._is_disabled(node),  # Fixed: Use proper disabled check
                })

        return rules
    
    def _parse_interfaces_from_xml(self, root: Element) -> List[Dict[str, Any]]:
        """Parse interfaces from config.xml root element"""
        def txt(elem: Optional[Element], default="") -> str:
            return elem.text.strip() if elem is not None and elem.text else default
        
        interfaces: List[Dict[str, Any]] = []
        
        # Parse physical interfaces
        for node in root.findall("./interfaces/*"):
            if_name = node.tag
            interface_data = {
                "name": if_name,
                "type": "physical",
                "if": txt(node.find("if")),
                "descr": txt(node.find("descr")),
                "enable": txt(node.find("enable")) == "1",
                "ipaddr": txt(node.find("ipaddr")),
                "subnet": txt(node.find("subnet")),
                "gateway": txt(node.find("gateway")),
                "mtu": txt(node.find("mtu")),
                "media": txt(node.find("media")),
                "mediaopt": txt(node.find("mediaopt"))
            }
            interfaces.append(interface_data)
        
        return interfaces
    
    async def get_config_xml_summary(self) -> Dict[str, Any]:
        """Get comprehensive summary from config.xml"""
        try:
            root = await self.download_config_xml()
            
            # Parse different sections
            fw_rules = self._parse_firewall_rules_from_xml(root)
            aliases = self._parse_aliases_from_xml(root)
            interfaces = self._parse_interfaces_from_xml(root)
            
            # Parse NAT rules for summary
            nat_forward = self._parse_nat_rules_from_xml(root, "forward")
            nat_outbound = self._parse_nat_rules_from_xml(root, "outbound")
            nat_source = self._parse_nat_rules_from_xml(root, "source")
            nat_one_to_one = self._parse_nat_rules_from_xml(root, "one_to_one")
            
            # Extract system information
            def txt(elem: Optional[Element], default="") -> str:
                return elem.text.strip() if elem is not None and elem.text else default
            
            system_info = {}
            system_node = root.find("./system")
            if system_node is not None:
                system_info = {
                    "hostname": txt(system_node.find("hostname")),
                    "domain": txt(system_node.find("domain")),
                    "timezone": txt(system_node.find("timezone")),
                    "language": txt(system_node.find("language")),
                    "version": txt(system_node.find("version"))
                }
            
            summary = {
                "timestamp": datetime.now().isoformat(),
                "source": "config.xml",
                "system_info": system_info,
                "statistics": {
                    "firewall_rules": len(fw_rules),
                    "aliases": len(aliases),
                    "interfaces": len(interfaces),
                    "nat_forward_rules": len(nat_forward),
                    "nat_outbound_rules": len(nat_outbound),
                    "nat_source_rules": len(nat_source),
                    "nat_one_to_one_rules": len(nat_one_to_one),
                    "enabled_rules": len([r for r in fw_rules if r["enabled"]]),
                    "disabled_rules": len([r for r in fw_rules if not r["enabled"]]),
                    "enabled_aliases": len([a for a in aliases if a["enabled"]]),
                    "disabled_aliases": len([a for a in aliases if not a["enabled"]])
                },
                "firewall_rules": fw_rules,
                "aliases": aliases,
                "interfaces": interfaces,
                "nat_rules": {
                    "forward": nat_forward,
                    "outbound": nat_outbound,
                    "source": nat_source,
                    "one_to_one": nat_one_to_one
                }
            }
            
            return summary
            
        except Exception as e:
            logger.error(f"Config XML summary failed: {str(e)}")
            raise
    
    async def get_aliases_from_config(self, 
                                    alias_type: str = None,
                                    enabled_only: bool = None,
                                    name_filter: str = None) -> List[Dict[str, Any]]:
        """Get aliases from config.xml with filtering options"""
        try:
            root = await self.download_config_xml()
            aliases = self._parse_aliases_from_xml(root)
            
            # Apply filters
            if alias_type:
                aliases = [a for a in aliases if a["type"].lower() == alias_type.lower()]
            
            if enabled_only is not None:
                aliases = [a for a in aliases if a["enabled"] == enabled_only]
            
            if name_filter:
                aliases = [a for a in aliases if name_filter.lower() in a["name"].lower()]
            
            return aliases
            
        except Exception as e:
            logger.error(f"Getting aliases from config failed: {str(e)}")
            raise
    
    async def get_firewall_rules_from_config(self, 
                                           interface_filter: str = None,
                                           action_filter: str = None,
                                           enabled_only: bool = None,
                                           with_aliases_only: bool = False) -> List[Dict[str, Any]]:
        """Get firewall rules from config.xml with filtering options"""
        try:
            root = await self.download_config_xml()
            rules = self._parse_firewall_rules_from_xml(root)
            
            # Apply filters
            if interface_filter:
                rules = [r for r in rules if r["interface"].lower() == interface_filter.lower()]
            
            if action_filter:
                rules = [r for r in rules if r["action"].lower() == action_filter.lower()]
            
            if enabled_only is not None:
                rules = [r for r in rules if r["enabled"] == enabled_only]
            
            if with_aliases_only:
                rules = [r for r in rules if r["src_alias"] or r["dst_alias"]]
            
            return rules
            
        except Exception as e:
            logger.error(f"Getting firewall rules from config failed: {str(e)}")
            raise
    
    async def get_nat_rules_from_config(self, 
                                      rule_type: str = "forward",
                                      enabled_only: bool = None,
                                      search_phrase: str = None) -> List[Dict[str, Any]]:
        """Get NAT rules from config.xml with filtering options"""
        valid_types = ["forward", "outbound", "source", "one_to_one", "filter"]
        if rule_type not in valid_types:
            raise ValueError(f"Invalid rule_type. Must be one of: {valid_types}")
        
        try:
            root = await self.download_config_xml()
            rules = self._parse_nat_rules_from_xml(root, rule_type)
            
            # Apply filters
            if enabled_only is not None:
                rules = [r for r in rules if r["enabled"] == enabled_only]
            
            if search_phrase:
                rules = [r for r in rules if search_phrase.lower() in r.get("description", "").lower()]
            
            return rules
            
        except Exception as e:
            logger.error(f"Getting NAT rules from config failed: {str(e)}")
            raise
    
    # === DHCP Management (Read-only) ===
    
    async def search_dhcp_leases(self, search_phrase: str = "", current: int = 1, 
                                row_count: int = 100) -> Dict:
        """Search DHCP leases"""
        params = {
            "current": current,
            "rowCount": row_count,
            "searchPhrase": search_phrase
        }
        return await self._request("GET", "/api/dhcpv4/leases/searchlease", params=params)
    
    async def get_dhcp_service_status(self) -> Dict:
        """Get DHCP service status"""
        return await self._request("GET", "/api/dhcpv4/service/status")
    
    async def get_dhcp_settings(self) -> Dict:
        """Get global DHCP settings"""
        return await self._request("GET", "/api/dhcpv4/settings/get")
    
    async def get_dhcp_interface_settings(self, interface: str) -> Dict:
        """Get DHCP settings for specific interface"""
        return await self._request("GET", f"/api/dhcpv4/settings/getdhcp/{interface}")
    
    async def get_all_dhcp_leases(self) -> List[Dict]:
        """Get all DHCP leases with pagination"""
        all_leases = []
        current_page = 1
        row_count = 100
        
        while True:
            result = await self.search_dhcp_leases(current=current_page, row_count=row_count)
            
            if 'rows' in result and result['rows']:
                all_leases.extend(result['rows'])
                
                # Check if we have total count
                total_count = result.get('total', 0)
                current_count = len(all_leases)
                
                # If we have total count, use it to determine if we need more pages
                if total_count > 0 and current_count >= total_count:
                    break
                
                # If no total count, check if we got less than requested (end of data)
                if len(result['rows']) < row_count:
                    break
                    
                current_page += 1
            else:
                break
        
        return all_leases
    
    # === Interface Management (Read-only) ===
    
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
    
    # === NAT Rules Management (Read-only) ===
    
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
    
    # === Alias Management (Read-only) ===
    
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
    
    async def get_all_aliases(self) -> List[Dict]:
        """Get all aliases with pagination"""
        all_aliases = []
        current_page = 1
        row_count = 100
        
        while True:
            result = await self.search_aliases(current=current_page, row_count=row_count)
            
            if 'rows' in result and result['rows']:
                all_aliases.extend(result['rows'])
                
                # Check if we have total count
                total_count = result.get('total', 0)
                current_count = len(all_aliases)
                
                # If we have total count, use it to determine if we need more pages
                if total_count > 0 and current_count >= total_count:
                    break
                
                # If no total count, check if we got less than requested (end of data)
                if len(result['rows']) < row_count:
                    break
                    
                current_page += 1
            else:
                break
        
        return all_aliases
    
    async def list_alias_content(self, alias_name: str) -> Dict:
        """List alias content"""
        return await self._request("GET", f"/api/firewall/alias_util/list/{alias_name}")

# Initialize the MCP server
server = Server("opnsense-mcp")

@server.list_tools()
async def handle_list_tools() -> List[Tool]:
    """List available tools"""
    return [
        Tool(
            name="get_config_xml_summary",
            description="Download and parse OPNsense config.xml to get comprehensive configuration summary",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="get_firewall_rules_from_config",
            description="Get firewall rules directly from config.xml with detailed information including tracker IDs and alias references",
            inputSchema={
                "type": "object",
                "properties": {
                    "interface_filter": {
                        "type": "string",
                        "description": "Filter by interface (e.g., WAN, LAN, OPT1)"
                    },
                    "action_filter": {
                        "type": "string",
                        "description": "Filter by action (pass, block, reject)"
                    },
                    "enabled_only": {
                        "type": "boolean",
                        "description": "Show only enabled rules (true) or only disabled rules (false), or all rules (null)"
                    },
                    "with_aliases_only": {
                        "type": "boolean",
                        "description": "Show only rules that use aliases",
                        "default": False
                    },
                    "format": {
                        "type": "string",
                        "description": "Output format",
                        "enum": ["detailed", "summary", "table"],
                        "default": "detailed"
                    }
                }
            }
        ),
        Tool(
            name="get_aliases_from_config",
            description="Get aliases directly from config.xml with enhanced parsing (based on test_alias2.py logic)",
            inputSchema={
                "type": "object",
                "properties": {
                    "alias_type": {
                        "type": "string",
                        "description": "Filter by alias type (e.g., host, network, port)"
                    },
                    "enabled_only": {
                        "type": "boolean",
                        "description": "Show only enabled aliases (true) or only disabled aliases (false), or all aliases (null)"
                    },
                    "name_filter": {
                        "type": "string",
                        "description": "Filter by name (case-insensitive partial match)"
                    },
                    "format": {
                        "type": "string",
                        "description": "Output format",
                        "enum": ["detailed", "summary", "table"],
                        "default": "detailed"
                    }
                }
            }
        ),
        Tool(
            name="get_nat_rules_from_config",
            description="Get NAT rules directly from config.xml with detailed information (forward, outbound, source, one_to_one, filter)",
            inputSchema={
                "type": "object",
                "properties": {
                    "rule_type": {
                        "type": "string",
                        "description": "NAT rule type",
                        "enum": ["forward", "outbound", "source", "one_to_one", "filter"],
                        "default": "forward"
                    },
                    "enabled_only": {
                        "type": "boolean",
                        "description": "Show only enabled rules (true) or only disabled rules (false), or all rules (null)"
                    },
                    "search_phrase": {
                        "type": "string",
                        "description": "Search phrase to filter rules by description"
                    },
                    "format": {
                        "type": "string",
                        "description": "Output format",
                        "enum": ["detailed", "summary", "table"],
                        "default": "detailed"
                    }
                }
            }
        ),
        Tool(
            name="download_config_xml",
            description="Download the complete OPNsense config.xml file (requires OPNsense ≥ 23.7.8 or os-api-backup plugin)",
            inputSchema={
                "type": "object",
                "properties": {
                    "parse": {
                        "type": "boolean",
                        "description": "Parse the XML and return structured data",
                        "default": True
                    }
                }
            }
        ),
        # === DHCP Tools ===
        Tool(
            name="get_dhcp_leases",
            description="Get all DHCP leases or search with filters",
            inputSchema={
                "type": "object",
                "properties": {
                    "search_phrase": {
                        "type": "string",
                        "description": "Search phrase to filter leases by IP, MAC, or hostname"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of leases to return",
                        "default": 100
                    }
                }
            }
        ),
        Tool(
            name="get_dhcp_service_status",
            description="Get DHCP service status and information",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="get_dhcp_settings",
            description="Get global DHCP configuration settings",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="get_dhcp_interface_settings",
            description="Get DHCP settings for a specific interface",
            inputSchema={
                "type": "object",
                "properties": {
                    "interface": {
                        "type": "string",
                        "description": "Interface name (e.g., lan, opt1)"
                    }
                },
                "required": ["interface"]
            }
        ),
        # === Interface Tools ===
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
                    },
                    "include_dhcp": {
                        "type": "boolean",
                        "description": "Include DHCP leases and service status",
                        "default": False
                    }
                }
            }
        ),
        # === NAT Rules Tools ===
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
        # === Alias Tools ===
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
            name="get_alias_content",
            description="Get specific alias content",
            inputSchema={
                "type": "object",
                "properties": {
                    "alias_name": {
                        "type": "string",
                        "description": "Alias name to get content for"
                    }
                },
                "required": ["alias_name"]
            }
        )
    ]

def _format_table_output(rows: List[Dict[str, Any]], title: str = "") -> str:
    """Format data as table similar to test_alias2.py and test_nat.py"""
    if not rows:
        return f"({title}: No data)" if title else "(No data)"
    
    # Detect data type and choose appropriate columns
    if rows and "name" in rows[0] and "type" in rows[0] and "content" in rows[0]:
        # Alias table format
        cols = ["name", "type", "content", "description"]
        cols = [c for c in cols if c in rows[0]]
    elif rows and "nat_ip" in rows[0]:
        # NAT forward rules table format
        nat_cols = ["uuid", "description", "interface", "protocol", "source", "dst_port", "nat_ip", "nat_port", "enabled"]
        cols = [c for c in nat_cols if c in rows[0]]
    elif rows and "translation" in rows[0]:
        # NAT outbound/source rules table format
        nat_cols = ["uuid", "description", "interface", "source", "destination", "translation", "enabled"]
        cols = [c for c in nat_cols if c in rows[0]]
    elif rows and "external" in rows[0] and "internal" in rows[0]:
        # NAT one-to-one rules table format
        nat_cols = ["uuid", "description", "interface", "external", "internal", "enabled"]
        cols = [c for c in nat_cols if c in rows[0]]
    else:
        # Common columns for firewall rules or generic format
        common_cols = [
            "tracker", "description", "interface", "action", "protocol", 
            "src_addr", "src_port", "dst_addr", "dst_port", "src_alias", "dst_alias", "enabled"
        ]
        
        # Use only columns that exist in the data
        available_cols = list(rows[0].keys())
        cols = [c for c in common_cols if c in available_cols]
        
        # Add any remaining columns
        remaining_cols = [c for c in available_cols if c not in cols]
        cols.extend(remaining_cols[:5])  # Limit total columns for readability

    # Calculate dynamic column widths
    width = {}
    for c in cols:
        col_values = [str(r.get(c, '')) for r in rows]
        width[c] = max(len(c), max(len(v) for v in col_values) if col_values else 0)

    def format_row(r: Dict[str, Any]) -> str:
        return "  ".join(f"{str(r.get(c, '')):<{width[c]}}" for c in cols)

    # Build table
    header = format_row({c: c.upper() for c in cols})
    separator = "-+-".join("-" * width[c] for c in cols)
    data_rows = [format_row(r) for r in rows]
    
    lines = [header, separator] + data_rows
    
    if title:
        lines.insert(0, f"\n=== {title} ===")
        lines.append(f"\nTotal: {len(rows)} records")
    
    return "\n".join(lines)

@server.call_tool()
async def handle_call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Handle tool calls"""
    
    try:
        async with OPNsenseClient() as client:
            
            if name == "get_config_xml_summary":
                result = await client.get_config_xml_summary()
                
                return [TextContent(
                    type="text",
                    text=f"OPNsense Configuration Summary (Source: config.xml):\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "get_firewall_rules_from_config":
                interface_filter = arguments.get("interface_filter")
                action_filter = arguments.get("action_filter")
                enabled_only = arguments.get("enabled_only")
                with_aliases_only = arguments.get("with_aliases_only", False)
                format_type = arguments.get("format", "detailed")
                
                rules = await client.get_firewall_rules_from_config(
                    interface_filter=interface_filter,
                    action_filter=action_filter,
                    enabled_only=enabled_only,
                    with_aliases_only=with_aliases_only
                )
                
                filter_info = []
                if interface_filter:
                    filter_info.append(f"Interface: {interface_filter}")
                if action_filter:
                    filter_info.append(f"Action: {action_filter}")
                if enabled_only is not None:
                    filter_info.append(f"Status: {'Enabled' if enabled_only else 'Disabled'}")
                if with_aliases_only:
                    filter_info.append("Only rules using aliases")
                
                filter_str = f" (Filters: {', '.join(filter_info)})" if filter_info else ""
                
                if format_type == "table":
                    response_text = f"Firewall Rules{filter_str}:\n"
                    response_text += _format_table_output(rules, "Firewall Rules")
                elif format_type == "summary":
                    summary = {
                        "Total": len(rules),
                        "Enabled": len([r for r in rules if r.get("enabled", True)]),
                        "Disabled": len([r for r in rules if not r.get("enabled", True)]),
                        "Using aliases": len([r for r in rules if r.get("src_alias") or r.get("dst_alias")]),
                        "Filters applied": filter_info if filter_info else ["None"]
                    }
                    response_text = f"Firewall Rules Summary{filter_str}:\n\n" + json.dumps(summary, indent=2, ensure_ascii=False)
                else:  # detailed
                    result = {
                        "Source": "config.xml",
                        "Total count": len(rules),
                        "Filters applied": filter_info if filter_info else [],
                        "Rules": rules
                    }
                    response_text = f"Firewall Rules Detailed Information{filter_str}:\n\n" + json.dumps(result, indent=2, ensure_ascii=False)
                
                return [TextContent(
                    type="text",
                    text=response_text
                )]
            
            elif name == "get_aliases_from_config":
                alias_type = arguments.get("alias_type")
                enabled_only = arguments.get("enabled_only")
                name_filter = arguments.get("name_filter")
                format_type = arguments.get("format", "detailed")
                
                aliases = await client.get_aliases_from_config(
                    alias_type=alias_type,
                    enabled_only=enabled_only,
                    name_filter=name_filter
                )
                
                filter_info = []
                if alias_type:
                    filter_info.append(f"Type: {alias_type}")
                if enabled_only is not None:
                    filter_info.append(f"Status: {'Enabled' if enabled_only else 'Disabled'}")
                if name_filter:
                    filter_info.append(f"Name contains: {name_filter}")
                
                filter_str = f" (Filters: {', '.join(filter_info)})" if filter_info else ""
                
                if format_type == "table":
                    response_text = f"Aliases List{filter_str}:\n"
                    response_text += _format_table_output(aliases, "Aliases")
                elif format_type == "summary":
                    type_counts = {}
                    for alias in aliases:
                        alias_type = alias.get("type", "unknown")
                        type_counts[alias_type] = type_counts.get(alias_type, 0) + 1
                    
                    summary = {
                        "Total": len(aliases),
                        "Enabled": len([a for a in aliases if a.get("enabled", True)]),
                        "Disabled": len([a for a in aliases if not a.get("enabled", True)]),
                        "Type statistics": type_counts,
                        "Filters applied": filter_info if filter_info else ["None"]
                    }
                    response_text = f"Aliases Summary{filter_str}:\n\n" + json.dumps(summary, indent=2, ensure_ascii=False)
                else:  # detailed
                    result = {
                        "Source": "config.xml",
                        "Total count": len(aliases),
                        "Filters applied": filter_info if filter_info else [],
                        "Aliases": aliases
                    }
                    response_text = f"Aliases Detailed Information{filter_str}:\n\n" + json.dumps(result, indent=2, ensure_ascii=False)
                
                return [TextContent(
                    type="text",
                    text=response_text
                )]
            
            elif name == "get_nat_rules_from_config":
                rule_type = arguments.get("rule_type", "forward")
                enabled_only = arguments.get("enabled_only")
                search_phrase = arguments.get("search_phrase")
                format_type = arguments.get("format", "detailed")
                
                rules = await client.get_nat_rules_from_config(
                    rule_type=rule_type,
                    enabled_only=enabled_only,
                    search_phrase=search_phrase
                )
                
                filter_info = []
                filter_info.append(f"Type: {rule_type}")
                if enabled_only is not None:
                    filter_info.append(f"Status: {'Enabled' if enabled_only else 'Disabled'}")
                if search_phrase:
                    filter_info.append(f"Search: {search_phrase}")
                
                filter_str = f" (Filters: {', '.join(filter_info)})"
                
                if format_type == "table":
                    response_text = f"NAT Rules{filter_str}:\n"
                    response_text += _format_table_output(rules, f"NAT Rules ({rule_type})")
                elif format_type == "summary":
                    summary = {
                        "Total": len(rules),
                        "Rule type": rule_type,
                        "Enabled": len([r for r in rules if r.get("enabled", True)]),
                        "Disabled": len([r for r in rules if not r.get("enabled", True)]),
                        "Filters applied": filter_info
                    }
                    response_text = f"NAT Rules Summary{filter_str}:\n\n" + json.dumps(summary, indent=2, ensure_ascii=False)
                else:  # detailed
                    result = {
                        "Source": "config.xml",
                        "Rule type": rule_type,
                        "Total count": len(rules),
                        "Filters applied": filter_info,
                        "Rules": rules
                    }
                    response_text = f"NAT Rules Detailed Information{filter_str}:\n\n" + json.dumps(result, indent=2, ensure_ascii=False)
                
                return [TextContent(
                    type="text",
                    text=response_text
                )]
            
            elif name == "download_config_xml":
                parse_xml = arguments.get("parse", True)
                
                if parse_xml:
                    # Download and parse
                    root = await client.download_config_xml()
                    
                    # Extract key information
                    def txt(elem, default=""):
                        return elem.text.strip() if elem is not None and elem.text else default
                    
                    system_node = root.find("./system")
                    system_info = {}
                    if system_node is not None:
                        system_info = {
                            "Hostname": txt(system_node.find("hostname")),
                            "Domain": txt(system_node.find("domain")),
                            "Timezone": txt(system_node.find("timezone")),
                            "Language": txt(system_node.find("language")),
                            "Version": txt(system_node.find("version"))
                        }
                    
                    # Count major sections including NAT rules
                    counts = {
                        "Firewall rules": len(root.findall("./filter/rule")),
                        "Aliases": len(root.findall(".//alias")),  # Use .//alias to capture all hierarchy levels
                        "Interfaces": len(root.findall("./interfaces/*")),
                        "NAT Forward rules": len(root.findall("./nat/rule")),
                        "NAT Outbound rules": len(root.findall("./nat/outbound/rule")),
                        "NAT Source rules": len(root.findall("./nat/advancedoutbound/rule")) + len(root.findall("./nat/source/rule")),
                        "NAT One-to-One rules": len(root.findall("./nat/onetoone/rule"))
                    }
                    
                    result = {
                        "Download time": datetime.now().isoformat(),
                        "System information": system_info,
                        "Configuration statistics": counts,
                        "Status": "config.xml downloaded and parsed successfully"
                    }
                    
                    return [TextContent(
                        type="text",
                        text=f"config.xml downloaded successfully:\n\n" + 
                             json.dumps(result, indent=2, ensure_ascii=False)
                    )]
                else:
                    # Just download without parsing
                    await client.download_config_xml()  # This will raise exception if fails
                    return [TextContent(
                        type="text",
                        text="config.xml downloaded successfully (not parsed)"
                    )]
            
            # === DHCP Management Tools ===
            elif name == "get_dhcp_leases":
                search_phrase = arguments.get("search_phrase", "")
                limit = arguments.get("limit", 100)
                
                # Get the data using pagination
                all_leases = []
                current_page = 1
                
                while len(all_leases) < limit:
                    result = await client.search_dhcp_leases(
                        search_phrase=search_phrase, 
                        current=current_page, 
                        row_count=min(100, limit - len(all_leases))
                    )
                    
                    if 'rows' in result and result['rows']:
                        all_leases.extend(result['rows'])
                        
                        # Check if we have all data or reached the limit
                        if len(result['rows']) < 100 or len(all_leases) >= limit:
                            break
                            
                        current_page += 1
                    else:
                        break
                
                final_result = {
                    "total_found": result.get('total', len(all_leases)),
                    "returned_count": len(all_leases),
                    "search_phrase": search_phrase,
                    "dhcp_leases": all_leases
                }
                
                return [TextContent(
                    type="text",
                    text=f"DHCP Leases List:\n\n" + 
                         json.dumps(final_result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "get_dhcp_service_status":
                result = await client.get_dhcp_service_status()
                
                return [TextContent(
                    type="text",
                    text="DHCP Service Status:\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "get_dhcp_settings":
                result = await client.get_dhcp_settings()
                
                return [TextContent(
                    type="text",
                    text="Global DHCP Settings:\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "get_dhcp_interface_settings":
                interface = arguments["interface"]
                result = await client.get_dhcp_interface_settings(interface)
                
                return [TextContent(
                    type="text",
                    text=f"DHCP Settings for Interface {interface}:\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            # === Interface Tools ===
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
                    text=f"Interface Information:\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "get_interface_config":
                interface = arguments["interface"]
                result = await client.get_interface_config(interface)
                
                return [TextContent(
                    type="text",
                    text=f"Interface {interface} Configuration:\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "get_interface_status":
                interface = arguments["interface"]
                result = await client.get_interface_status(interface)
                
                return [TextContent(
                    type="text",
                    text=f"Interface {interface} Status:\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "get_interface_statistics":
                result = await client.get_interface_statistics()
                
                return [TextContent(
                    type="text",
                    text="Interface Statistics:\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "get_arp_table":
                result = await client.get_arp_table()
                
                return [TextContent(
                    type="text",
                    text="ARP Table:\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "get_ndp_table":
                result = await client.get_ndp_table()
                
                return [TextContent(
                    type="text",
                    text="NDP Table (IPv6 Neighbors):\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "get_routes":
                result = await client.get_routes()
                
                return [TextContent(
                    type="text",
                    text="Routing Table:\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "get_network_overview":
                include_statistics = arguments.get("include_statistics", False)
                include_neighbors = arguments.get("include_neighbors", True)
                include_routes = arguments.get("include_routes", True)
                include_dhcp = arguments.get("include_dhcp", False)
                
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
                
                # Get DHCP information if requested
                if include_dhcp:
                    try:
                        overview["dhcp_service_status"] = await client.get_dhcp_service_status()
                        overview["dhcp_leases"] = await client.get_all_dhcp_leases()
                        overview["dhcp_settings"] = await client.get_dhcp_settings()
                    except Exception as e:
                        overview["dhcp_error"] = str(e)
                
                return [TextContent(
                    type="text",
                    text="Network Comprehensive Overview:\n\n" + 
                         json.dumps(overview, indent=2, ensure_ascii=False)
                )]
            
            # === NAT Rules Tools ===
            elif name == "get_nat_rules":
                nat_type = arguments.get("nat_type", "source_nat")
                search_phrase = arguments.get("search_phrase", "")
                limit = arguments.get("limit", 100)
                
                result = await client.search_nat_rules(nat_type, search_phrase, row_count=limit)
                
                return [TextContent(
                    type="text",
                    text=f"NAT Rules ({nat_type}):\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
                )]
            
            # === Alias Tools ===
            elif name == "get_aliases":
                search_phrase = arguments.get("search_phrase", "")
                limit = arguments.get("limit", 100)
                
                # Get the data using pagination
                all_aliases = []
                current_page = 1
                
                while len(all_aliases) < limit:
                    result = await client.search_aliases(
                        search_phrase=search_phrase, 
                        current=current_page, 
                        row_count=min(100, limit - len(all_aliases))
                    )
                    
                    if 'rows' in result and result['rows']:
                        all_aliases.extend(result['rows'])
                        
                        # Check if we have all data or reached the limit
                        if len(result['rows']) < 100 or len(all_aliases) >= limit:
                            break
                            
                        current_page += 1
                    else:
                        break
                
                final_result = {
                    "total_found": result.get('total', len(all_aliases)),
                    "returned_count": len(all_aliases),
                    "search_phrase": search_phrase,
                    "aliases": all_aliases
                }
                
                return [TextContent(
                    type="text",
                    text=f"Aliases List:\n\n" + 
                         json.dumps(final_result, indent=2, ensure_ascii=False)
                )]
            
            elif name == "get_alias_content":
                alias_name = arguments["alias_name"]
                result = await client.list_alias_content(alias_name)
                
                return [TextContent(
                    type="text",
                    text=f"Alias {alias_name} Content:\n\n" + 
                         json.dumps(result, indent=2, ensure_ascii=False)
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
