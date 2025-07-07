#!/usr/bin/env python3
"""
MCP server for LibreNMS API – v3.5 Enhanced with ARP Table and IP-to-MAC Support
===============================================================================
Author: Jason Cheng (Jason Tools) - Enhanced by Claude
Created: 2025-06-24
Updated: 2025-07-07
License: MIT

FastMCP-based LibreNMS integration with comprehensive batch operations,
improved error handling, caching, SLA analytics, FDB table management,
and ARP table/IP-to-MAC address resolution.

Features:
- Comprehensive alert history access including resolved alerts
- Batch operations for devices, services, and alerts
- Intelligent caching to reduce API load
- Enhanced error handling and retry logic
- Accurate SLA calculation based on real alert data
- Performance monitoring and statistics
- Configuration validation and health checks
- UNLIMITED device retrieval capabilities
- FDB table search and management
- MAC address tracking and location discovery
- ARP table queries and IP-to-MAC resolution
- Network layer 2/3 correlation and analysis

Installation:
pip install mcp requests

Environment Variables:
LIBRENMS_URL - LibreNMS base URL (e.g., https://librenms.example.com/api/v0)
LIBRENMS_TOKEN - LibreNMS API token
LIBRENMS_CACHE_TTL - Cache TTL in seconds (default: 300)
LIBRENMS_TIMEOUT - API timeout in seconds (default: 30)

Run steps:
chmod +x mcp_librenms.py
/path/to/python mcp_librenms.py
"""
import json
import os
import sys
import time
from typing import Optional, Dict, Any, List, Union
from datetime import datetime, timedelta
from functools import wraps
import logging
import hashlib
import re
import ipaddress

import requests
from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('mcp-librenms')

# Environment configuration with validation
class Config:
    def __init__(self):
        self.BASE_URL = os.getenv("LIBRENMS_URL")
        self.TOKEN = os.getenv("LIBRENMS_TOKEN")
        self.CACHE_TTL = int(os.getenv("LIBRENMS_CACHE_TTL", "300"))
        self.TIMEOUT = int(os.getenv("LIBRENMS_TIMEOUT", "30"))
        self.MAX_RETRIES = int(os.getenv("LIBRENMS_MAX_RETRIES", "3"))
        self.BATCH_SIZE = int(os.getenv("LIBRENMS_BATCH_SIZE", "200"))  # 增加預設批次大小
        
        self.validate()
    
    def validate(self):
        if not self.BASE_URL or not self.TOKEN:
            logger.error("LIBRENMS_URL or LIBRENMS_TOKEN environment variables not set")
            sys.exit(1)
        
        # Clean up BASE_URL
        self.BASE_URL = self.BASE_URL.rstrip('/')
        if not self.BASE_URL.endswith('/api/v0'):
            self.BASE_URL += '/api/v0'
        
        logger.info(f"LibreNMS URL: {self.BASE_URL}")
        logger.info(f"Cache TTL: {self.CACHE_TTL}s, Timeout: {self.TIMEOUT}s")

config = Config()

# Improved JSON encoder for datetime objects
class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super(DateTimeEncoder, self).default(obj)

# Simple in-memory cache with improved key generation
class SimpleCache:
    def __init__(self, ttl: int = 300):
        self.cache = {}
        self.ttl = ttl
    
    def _generate_key(self, key_data: str) -> str:
        """Generate a safe cache key"""
        return hashlib.md5(key_data.encode('utf-8')).hexdigest()
    
    def get(self, key: str) -> Optional[Any]:
        safe_key = self._generate_key(key)
        if safe_key in self.cache:
            data, timestamp = self.cache[safe_key]
            if time.time() - timestamp < self.ttl:
                return data
            else:
                del self.cache[safe_key]
        return None
    
    def set(self, key: str, value: Any):
        safe_key = self._generate_key(key)
        self.cache[safe_key] = (value, time.time())
    
    def clear(self):
        self.cache.clear()
    
    def stats(self) -> Dict[str, int]:
        current_time = time.time()
        active_keys = 0
        for _, (_, timestamp) in self.cache.items():
            if current_time - timestamp < self.ttl:
                active_keys += 1
        return {
            "total_keys": len(self.cache),
            "active_keys": active_keys,
            "ttl_seconds": self.ttl
        }

cache = SimpleCache(config.CACHE_TTL)

# Initialize requests session with retry logic
session = requests.Session()
session.headers.update({
    "X-Auth-Token": config.TOKEN,
    "User-Agent": "mcp-librenms/3.4-arp",
    "Accept": "application/json",
    "Content-Type": "application/json"
})

# Create FastMCP server
mcp = FastMCP("LibreNMS")

# ───────────────────────── Helper Functions ─────────────────────────

def retry_on_failure(max_retries: int = 3, delay: float = 1.0):
    """Decorator for retry logic with exponential backoff"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        wait_time = delay * (2 ** attempt)
                        logger.warning(f"Attempt {attempt + 1} failed: {e}, retrying in {wait_time}s")
                        time.sleep(wait_time)
                    else:
                        logger.error(f"All {max_retries} attempts failed")
            raise last_exception
        return wrapper
    return decorator

@retry_on_failure(max_retries=config.MAX_RETRIES)
def _api_request(method: str, endpoint: str, params: Optional[Dict[str, Any]] = None,
                 json_body: Optional[Dict[str, Any]] = None, use_cache: bool = True) -> Dict[str, Any]:
    """Send API request to LibreNMS with caching and retry logic"""
    
    # Create cache key with better serialization
    cache_key = f"{method}:{endpoint}:{json.dumps(params, sort_keys=True)}:{json.dumps(json_body, sort_keys=True)}" if use_cache else None
    
    # Check cache first
    if cache_key and method.upper() == 'GET':
        cached_result = cache.get(cache_key)
        if cached_result:
            logger.debug(f"Cache hit for {endpoint}")
            return cached_result
    
    url = f"{config.BASE_URL}/{endpoint.lstrip('/')}"
    logger.debug(f"API request: {method} {url} params={params}")
    
    try:
        response = session.request(
            method.upper(), 
            url, 
            params=params, 
            json=json_body, 
            timeout=config.TIMEOUT
        )
        response.raise_for_status()
        
        result = response.json()
        
        # Cache successful GET requests
        if cache_key and method.upper() == 'GET' and response.status_code == 200:
            cache.set(cache_key, result)
        
        return result
        
    except requests.exceptions.RequestException as e:
        logger.error(f"API request failed: {method} {url} - {e}")
        raise Exception(f"LibreNMS API error: {str(e)}")

def _safe_parse_datetime(timestamp_str: Any) -> Optional[datetime]:
    """Safely parse datetime string with multiple format support"""
    if not timestamp_str or timestamp_str == '0000-00-00 00:00:00':
        return None
    
    # Convert to string if not already
    timestamp_str = str(timestamp_str)
    
    # Common datetime patterns
    patterns = [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%S.%f',
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%dT%H:%M:%S.%fZ',
        '%Y-%m-%d %H:%M:%S.%f',
    ]
    
    for pattern in patterns:
        try:
            return datetime.strptime(timestamp_str, pattern)
        except ValueError:
            continue
    
    # Try ISO format parsing
    try:
        if 'T' in timestamp_str:
            # Remove timezone info if present
            clean_timestamp = timestamp_str.replace('Z', '').split('+')[0].split('-')[0:3]
            clean_timestamp = '-'.join(clean_timestamp[0:3]) + 'T' + timestamp_str.split('T')[1].replace('Z', '').split('+')[0]
            return datetime.fromisoformat(clean_timestamp)
    except Exception:
        pass
    
    logger.warning(f"Could not parse datetime: {timestamp_str}")
    return None

def _format_timestamp(timestamp_str: str) -> str:
    """Format timestamp for display"""
    dt = _safe_parse_datetime(timestamp_str)
    if dt:
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    return str(timestamp_str) if timestamp_str else "N/A"

def _normalize_mac_address(mac: str) -> str:
    """Normalize MAC address format for API compatibility - FIXED REGEX"""
    if not mac:
        return ""
    
    # Remove any separators and convert to lowercase - FIXED: Escape the dash
    mac_clean = re.sub(r'[:\-.]', '', mac.lower())
    
    # Ensure it's 12 characters
    if len(mac_clean) != 12:
        raise ValueError(f"Invalid MAC address format: {mac}")
    
    # Return in format expected by LibreNMS API (usually without separators)
    return mac_clean

def _format_mac_address(mac: str, format_type: str = "colon") -> str:
    """Format MAC address for display - FIXED REGEX"""
    if not mac:
        return ""
    
    # Clean the MAC address - FIXED: Escape the dash
    mac_clean = re.sub(r'[:\-.]', '', mac.lower())
    
    if len(mac_clean) != 12:
        return mac  # Return original if can't parse
    
    if format_type == "colon":
        return ':'.join(mac_clean[i:i+2] for i in range(0, 12, 2))
    elif format_type == "dash":
        return '-'.join(mac_clean[i:i+2] for i in range(0, 12, 2))
    elif format_type == "dot":
        return '.'.join(mac_clean[i:i+4] for i in range(0, 12, 4))
    else:
        return mac_clean

def _validate_ip_address(ip_str: str) -> bool:
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def _validate_network_cidr(network_str: str) -> bool:
    """Validate network CIDR format"""
    try:
        ipaddress.ip_network(network_str, strict=False)
        return True
    except ValueError:
        return False

def _extract_data_from_response(result: Any, expected_keys: List[str] = None) -> List[Dict[str, Any]]:
    """Extract data array from API response with enhanced flexible key detection"""
    if expected_keys is None:
        expected_keys = ['devices', 'services', 'alerts', 'data', 'results', 'eventlog', 'alertlog', 'ports_fdb', 'fdb', 'ports_nac', 'ports', 'arp', 'ip_arp']
    
    logger.debug(f"Extracting data from response type: {type(result)}")
    
    if isinstance(result, list):
        logger.debug(f"Result is list with {len(result)} items")
        return result
    
    if isinstance(result, dict):
        logger.debug(f"Result is dict with keys: {list(result.keys())}")
        
        # 首先嘗試預期的鍵
        for key in expected_keys:
            if key in result:
                value = result[key]
                if isinstance(value, list):
                    logger.debug(f"Found data in key '{key}' with {len(value)} items")
                    return value
                elif isinstance(value, dict) and 'data' in value:
                    # 處理巢狀結構
                    nested_data = value['data']
                    if isinstance(nested_data, list):
                        logger.debug(f"Found nested data in '{key}.data' with {len(nested_data)} items")
                        return nested_data
        
        # 如果沒有找到預期的鍵，尋找任何包含陣列的鍵
        for key, value in result.items():
            if isinstance(value, list) and len(value) > 0:
                # 檢查陣列內容是否看起來像設備資料
                first_item = value[0]
                if isinstance(first_item, dict):
                    # 檢查是否有常見的設備欄位
                    device_fields = ['device_id', 'hostname', 'ip', 'status', 'type', 'id']
                    service_fields = ['service_id', 'service_type', 'service_status']
                    alert_fields = ['alert_id', 'severity', 'timestamp', 'message']
                    fdb_fields = ['ports_fdb_id', 'port_id', 'mac_address', 'vlan_id']
                    port_fields = ['port_id', 'ifName', 'ifDescr', 'ifIndex']
                    arp_fields = ['ipv4_address', 'mac_address', 'device_id', 'port_id', 'context_name']
                    
                    if any(field in first_item for field in device_fields + service_fields + alert_fields + fdb_fields + port_fields + arp_fields):
                        logger.debug(f"Found data-like content in key '{key}' with {len(value)} items")
                        return value
        
        # 如果還是沒找到，返回所有陣列
        for key, value in result.items():
            if isinstance(value, list):
                logger.debug(f"Returning list from key '{key}' with {len(value)} items")
                return value
        
        # 最後，如果是單一項目結果，包裝成陣列
        if result and not any(isinstance(v, list) for v in result.values()):
            logger.debug("Wrapping single item in list")
            return [result]
    
    logger.debug("No data found, returning empty list")
    return []

def _paginate_request_optimized(endpoint: str, params: Optional[Dict[str, Any]] = None, 
                               max_items: Optional[int] = None) -> List[Dict[str, Any]]:
    """Optimized paginated API requests with smaller batch sizes for large datasets"""
    all_items = []
    offset = 0
    # 使用較小的批次大小避免超時
    limit = min(config.BATCH_SIZE, 100) if max_items and max_items > 1000 else min(config.BATCH_SIZE, 200)
    consecutive_empty = 0
    total_processed = 0
    
    if params is None:
        params = {}
    
    logger.info(f"Starting optimized pagination for {endpoint}, max_items={max_items}, batch_size={limit}")
    
    # 設定更嚴格的安全限制
    max_iterations = 50 if max_items and max_items > 5000 else 25
    iteration_count = 0
    
    while consecutive_empty < 2 and iteration_count < max_iterations:
        current_params = params.copy()
        current_params.update({"limit": limit, "offset": offset})
        
        try:
            logger.debug(f"Optimized request {endpoint} with offset={offset}, limit={limit}")
            result = _api_request("GET", endpoint, params=current_params)
            
            items = _extract_data_from_response(result)
            
            if not items:
                consecutive_empty += 1
                logger.debug(f"Empty response at offset {offset}, consecutive empty: {consecutive_empty}")
                offset += limit
                iteration_count += 1
                continue
            
            consecutive_empty = 0
            items_count = len(items)
            all_items.extend(items)
            total_processed += items_count
            
            logger.info(f"Retrieved {items_count} items at offset {offset}, total so far: {total_processed}")
            
            # 檢查是否達到最大限制
            if max_items and len(all_items) >= max_items:
                all_items = all_items[:max_items]
                logger.info(f"Reached max_items limit: {max_items}")
                break
            
            # 如果取得的項目少於請求的數量，可能已到末尾
            if items_count < limit:
                logger.info(f"Got {items_count} < {limit}, assuming end of data")
                break
            
            offset += limit
            iteration_count += 1
            
            # 每 10 次迭代短暫暫停，避免 API 限制
            if iteration_count % 10 == 0:
                time.sleep(0.1)
            
        except Exception as e:
            logger.warning(f"Optimized pagination failed at offset {offset}: {e}")
            consecutive_empty += 1
            if consecutive_empty >= 2:
                logger.error("Too many consecutive failures, stopping optimized pagination")
                break
            offset += limit
            iteration_count += 1
    
    if iteration_count >= max_iterations:
        logger.warning(f"Reached maximum iteration limit ({max_iterations}), stopping pagination")
    
    logger.info(f"Optimized pagination complete for {endpoint}: {len(all_items)} total items retrieved")
    return all_items

def _paginate_request(endpoint: str, params: Optional[Dict[str, Any]] = None, 
                     max_items: Optional[int] = None) -> List[Dict[str, Any]]:
    """Handle paginated API requests to get all data with improved error handling and multiple fallback methods"""
    all_items = []
    offset = 0
    limit = min(config.BATCH_SIZE, 200)  # 增加批次大小到 200
    consecutive_empty = 0
    total_processed = 0
    
    if params is None:
        params = {}
    
    logger.info(f"Starting pagination for {endpoint}, max_items={max_items}")
    
    # 方法 1: 標準分頁
    while consecutive_empty < 2:  # 減少到 2 次連續空響應就停止
        current_params = params.copy()
        current_params.update({"limit": limit, "offset": offset})
        
        try:
            logger.debug(f"Requesting {endpoint} with offset={offset}, limit={limit}")
            result = _api_request("GET", endpoint, params=current_params)
            
            # 嘗試多種方式提取資料
            items = _extract_data_from_response(result)
            
            # 如果沒有 items，但有 result 且 result 是字典，檢查是否有特殊格式
            if not items and isinstance(result, dict):
                # 直接檢查所有可能的鍵
                for possible_key in ['devices', 'data', 'results', 'services', 'alerts', 'ports_fdb', 'fdb', 'ports', 'arp', 'ip_arp']:
                    if possible_key in result:
                        potential_items = result[possible_key]
                        if isinstance(potential_items, list):
                            items = potential_items
                            logger.debug(f"Found items in {possible_key}")
                            break
                        elif isinstance(potential_items, dict) and 'data' in potential_items:
                            items = potential_items['data']
                            logger.debug(f"Found items in {possible_key}.data")
                            break
            
            if not items:
                consecutive_empty += 1
                logger.debug(f"Empty response at offset {offset}, consecutive empty: {consecutive_empty}")
                
                # 如果是第一次請求就空的，可能是 API 格式問題
                if offset == 0:
                    logger.info("First request empty, trying alternative methods...")
                    break
                
                offset += limit
                continue
            
            consecutive_empty = 0  # Reset counter
            items_count = len(items)
            all_items.extend(items)
            total_processed += items_count
            
            logger.info(f"Retrieved {items_count} items at offset {offset}, total so far: {total_processed}")
            
            # Check if we've reached the maximum
            if max_items and len(all_items) >= max_items:
                all_items = all_items[:max_items]
                logger.info(f"Reached max_items limit: {max_items}")
                break
            
            # If we got fewer items than requested, we're probably at the end
            if items_count < limit:
                logger.info(f"Got {items_count} < {limit}, assuming end of data")
                break
            
            offset += limit
            
            # Safety break to prevent infinite loops - 增加到 50000
            if offset > 50000:
                logger.warning(f"Pagination safety break at offset {offset}")
                break
            
        except Exception as e:
            logger.warning(f"Pagination failed at offset {offset}: {e}")
            consecutive_empty += 1
            if consecutive_empty >= 2:
                logger.error("Too many consecutive failures, stopping pagination")
                break
            offset += limit
    
    # 方法 2: 如果標準分頁沒有結果，嘗試大量請求
    if not all_items:
        logger.info("Standard pagination failed, trying large limit request...")
        try:
            large_params = params.copy()
            large_params.update({"limit": 10000})
            large_result = _api_request("GET", endpoint, params=large_params)
            large_items = _extract_data_from_response(large_result)
            if large_items:
                all_items.extend(large_items)
                logger.info(f"Large limit request succeeded: {len(large_items)} items")
        except Exception as e:
            logger.warning(f"Large request method failed: {e}")
    
    # 方法 3: 如果還是沒有結果，嘗試無參數請求
    if not all_items:
        logger.info("Large limit failed, trying simple request...")
        try:
            simple_result = _api_request("GET", endpoint, params=params)
            if isinstance(simple_result, list):
                all_items.extend(simple_result)
                logger.info(f"Simple request returned list: {len(simple_result)} items")
            elif isinstance(simple_result, dict):
                simple_items = _extract_data_from_response(simple_result)
                if simple_items:
                    all_items.extend(simple_items)
                    logger.info(f"Simple request extracted items: {len(simple_items)} items")
        except Exception as e:
            logger.warning(f"Simple request failed: {e}")
    
    logger.info(f"Pagination complete for {endpoint}: {len(all_items)} total items retrieved")
    return all_items

# ───────────────────────── Core MCP Tools ─────────────────────────

@mcp.tool()
def librenms_api(method: str, endpoint: str, params: Optional[Dict[str, Any]] = None,
                 json_body: Optional[Dict[str, Any]] = None) -> str:
    """Execute raw request to any LibreNMS REST API endpoint
    
    Args:
        method: HTTP method (GET, POST, PUT, DELETE)
        endpoint: API endpoint path
        params: Query parameters (optional)
        json_body: JSON request body (optional)
    
    Returns:
        JSON string of API response
    """
    logger.info(f"Raw API call: {method} {endpoint}")
    
    try:
        result = _api_request(method, endpoint, params, json_body, use_cache=False)
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def health_check() -> str:
    """Perform health check on LibreNMS API and cache system
    
    Returns:
        JSON string with health status and performance metrics
    """
    logger.info("Performing health check")
    
    try:
        start_time = time.time()
        
        # Test basic API connectivity
        api_result = _api_request("GET", "devices", params={"limit": 1}, use_cache=False)
        api_response_time = time.time() - start_time
        
        # Get cache statistics
        cache_stats = cache.stats()
        
        # Test authentication
        auth_status = "OK" if api_result else "FAILED"
        
        result = {
            "status": "healthy" if auth_status == "OK" else "unhealthy",
            "timestamp": datetime.now().isoformat(),
            "api": {
                "status": auth_status,
                "response_time_ms": round(api_response_time * 1000, 2),
                "endpoint": config.BASE_URL
            },
            "cache": cache_stats,
            "configuration": {
                "timeout": config.TIMEOUT,
                "max_retries": config.MAX_RETRIES,
                "batch_size": config.BATCH_SIZE
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        return json.dumps({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }, indent=2, ensure_ascii=False)

# ───────────────────────── NEW: ARP Table and IP-to-MAC Management ─────────────────────────

@mcp.tool()
def search_ip_to_mac(ip_address: str, detailed: bool = True, prefer_arp_vlan: bool = True) -> str:
    """Search ARP table to find MAC address for specific IP address - FIXED VLAN MAPPING
    
    Args:
        ip_address: IP address to search for (e.g., "192.168.1.200")
        detailed: Include detailed device and port information (default: True)
        prefer_arp_vlan: Prefer VLAN information from ARP table rather than FDB table (default: True)
        
    Returns:
        JSON string with IP-to-MAC mapping and device details with CORRECT VLAN tags
    """
    logger.info(f"VLAN FIXED: Searching ARP table for IP: {ip_address}")
    
    try:
        # Validate IP address format
        if not _validate_ip_address(ip_address):
            return json.dumps({
                "error": f"Invalid IP address format: {ip_address}",
                "timestamp": datetime.now().isoformat()
            }, indent=2, ensure_ascii=False)
        
        arp_entries = []
        
        # Method 1: Direct ARP lookup
        try:
            logger.info(f"Direct ARP lookup for IP: {ip_address}")
            direct_result = _api_request("GET", f"resources/ip/arp/{ip_address}")
            direct_data = _extract_data_from_response(direct_result, ['arp', 'ip_arp'])
            
            for entry in direct_data:
                entry["debug_info"] = {
                    "query_method": "direct_arp_lookup"
                }
                arp_entries.append(entry)
            
            logger.info(f"Direct lookup found {len(direct_data)} entries")
            
        except Exception as e:
            logger.warning(f"Direct ARP lookup failed: {e}")
        
        # Method 2: Device-specific lookup if direct failed
        if not arp_entries:
            try:
                logger.info(f"Device-specific ARP lookup for IP: {ip_address}")
                
                devices_result = _api_request("GET", "devices", params={"limit": 5})
                devices_data = _extract_data_from_response(devices_result, ['devices'])
                
                for device in devices_data:
                    device_id = device.get('device_id')
                    hostname = device.get('hostname', f'device_{device_id}')
                    
                    if device_id:
                        try:
                            device_arp_result = _api_request("GET", f"devices/{device_id}/arp")
                            device_arp_data = _extract_data_from_response(device_arp_result, ['arp', 'ip_arp'])
                            
                            for entry in device_arp_data:
                                entry_ip = entry.get("ipv4_address") or entry.get("ip_address")
                                if entry_ip == ip_address:
                                    entry["debug_info"] = {
                                        "source_device_id": device_id,
                                        "source_hostname": hostname,
                                        "query_method": "device_specific_arp"
                                    }
                                    arp_entries.append(entry)
                                    break
                            
                            if arp_entries:
                                break
                                
                        except Exception as e:
                            logger.debug(f"Device {device_id} query failed: {e}")
                
                logger.info(f"Device-specific search found {len(arp_entries)} entries")
                
            except Exception as e:
                logger.warning(f"Device-specific search failed: {e}")
        
        # Remove duplicates
        unique_entries = []
        seen_combinations = set()
        
        for entry in arp_entries:
            if not isinstance(entry, dict):
                continue
                
            mac_address = entry.get("mac_address", "")
            device_id = entry.get("device_id", "")
            combination_key = f"{ip_address}_{mac_address}_{device_id}"
            
            if combination_key not in seen_combinations:
                seen_combinations.add(combination_key)
                unique_entries.append(entry)
        
        # **CRITICAL FIX: Map vlan_id to actual VLAN tag using vlans table**
        enriched_entries = []
        vlan_mapping_cache = {}
        
        for entry in unique_entries:
            enriched_entry = entry.copy()
            
            # Format MAC address
            if "mac_address" in enriched_entry:
                try:
                    enriched_entry["mac_address_formatted"] = _format_mac_address(
                        enriched_entry["mac_address"], "colon"
                    )
                except Exception as e:
                    enriched_entry["mac_address_formatted"] = enriched_entry["mac_address"]
            
            # Format timestamps
            enriched_entry["created_at_formatted"] = _format_timestamp(
                enriched_entry.get("created_at", "")
            )
            enriched_entry["updated_at_formatted"] = _format_timestamp(
                enriched_entry.get("updated_at", "")
            )
            
            # **CRITICAL FIX: Get correct VLAN tag from vlans table**
            arp_vlan_id = enriched_entry.get("vlan_id")  # This is the database ID, NOT the VLAN tag!
            actual_vlan_tag = None
            vlan_mapping_error = None
            
            if arp_vlan_id:
                # Check if we already have this mapping cached
                if arp_vlan_id not in vlan_mapping_cache:
                    try:
                        # Query vlans table to get actual VLAN tag
                        vlans_result = _api_request("GET", "resources/vlans")
                        vlans_data = _extract_data_from_response(vlans_result, ['vlans'])
                        
                        # Build mapping cache for all VLANs
                        for vlan_entry in vlans_data:
                            vlan_db_id = str(vlan_entry.get("vlan_id", ""))
                            vlan_tag = vlan_entry.get("vlan_vlan")  # This is the actual VLAN tag!
                            vlan_name = vlan_entry.get("vlan_name", "")
                            device_id = vlan_entry.get("device_id", "")
                            
                            if vlan_db_id and vlan_tag:
                                vlan_mapping_cache[vlan_db_id] = {
                                    "vlan_tag": vlan_tag,
                                    "vlan_name": vlan_name,
                                    "device_id": device_id
                                }
                        
                        logger.info(f"Built VLAN mapping cache with {len(vlan_mapping_cache)} entries")
                        
                    except Exception as e:
                        vlan_mapping_error = str(e)
                        logger.warning(f"Failed to build VLAN mapping cache: {e}")
                
                # Get the actual VLAN tag
                vlan_mapping = vlan_mapping_cache.get(str(arp_vlan_id))
                if vlan_mapping:
                    actual_vlan_tag = vlan_mapping["vlan_tag"]
                    enriched_entry["vlan_info"] = {
                        "vlan_tag": actual_vlan_tag,  # CORRECT VLAN tag
                        "vlan_name": vlan_mapping["vlan_name"],
                        "vlan_db_id": arp_vlan_id,   # Database ID (for reference)
                        "source": "vlans_table_mapping",
                        "mapping_device_id": vlan_mapping["device_id"]
                    }
                else:
                    enriched_entry["vlan_info"] = {
                        "vlan_tag": "unknown",
                        "vlan_db_id": arp_vlan_id,
                        "error": f"No VLAN mapping found for vlan_id {arp_vlan_id}",
                        "source": "vlans_table_mapping_failed"
                    }
            else:
                enriched_entry["vlan_info"] = {
                    "vlan_tag": "not_specified",
                    "source": "no_vlan_in_arp_entry"
                }
            
            # Add mapping debug info
            enriched_entry["vlan_mapping_debug"] = {
                "original_vlan_id_field": arp_vlan_id,
                "mapped_vlan_tag": actual_vlan_tag,
                "mapping_cache_size": len(vlan_mapping_cache),
                "mapping_error": vlan_mapping_error
            }
            
            # Get device information if detailed
            if detailed:
                device_id = enriched_entry.get("device_id")
                if device_id:
                    try:
                        device_result = _api_request("GET", f"devices/{device_id}")
                        if "devices" in device_result and device_result["devices"]:
                            device_info = device_result["devices"][0]
                            enriched_entry["device_info"] = {
                                "hostname": device_info.get("hostname"),
                                "sysName": device_info.get("sysName"),
                                "ip": device_info.get("ip"),
                                "type": device_info.get("type")
                            }
                    except Exception as e:
                        enriched_entry["device_info_error"] = str(e)
                
                # Get port information
                port_id = enriched_entry.get("port_id")
                if port_id:
                    try:
                        port_result = _api_request("GET", f"ports/{port_id}")
                        if "ports" in port_result and port_result["ports"]:
                            port_info = port_result["ports"][0]
                            enriched_entry["port_info"] = {
                                "ifName": port_info.get("ifName"),
                                "ifDescr": port_info.get("ifDescr"),
                                "ifOperStatus": port_info.get("ifOperStatus"),
                                "ifSpeed": port_info.get("ifSpeed")
                            }
                    except Exception as e:
                        enriched_entry["port_info_error"] = str(e)
            
            enriched_entries.append(enriched_entry)
        
        # Calculate summary with correct VLAN tags
        if enriched_entries:
            devices_found = set(str(entry.get("device_id", "")) for entry in enriched_entries)
            mac_addresses = set(entry.get("mac_address", "") for entry in enriched_entries)
            vlan_tags_found = set()
            for entry in enriched_entries:
                vlan_info = entry.get("vlan_info", {})
                vlan_tag = vlan_info.get("vlan_tag")
                if vlan_tag and vlan_tag not in ["unknown", "not_specified"]:
                    vlan_tags_found.add(str(vlan_tag))
            
            search_summary = {
                "ip_address_searched": ip_address,
                "total_arp_entries_found": len(enriched_entries),
                "unique_mac_addresses": len(mac_addresses),
                "devices_with_this_ip": sorted(list(devices_found)),
                "mac_addresses_found": sorted(list(mac_addresses)),
                "vlan_tags_found": sorted(list(vlan_tags_found)),  # CORRECT VLAN tags
                "data_source": "arp_with_correct_vlan_mapping"
            }
        else:
            search_summary = {
                "ip_address_searched": ip_address,
                "total_arp_entries_found": 0,
                "message": "IP address not found in ARP tables"
            }
        
        result = {
            "search_summary": search_summary,
            "arp_entries": enriched_entries,
            "vlan_mapping_info": {
                "explanation": "VLAN tags are now correctly mapped from vlans table",
                "vlan_db_ids_vs_tags": "vlan_id field is database ID, vlan_vlan field is actual VLAN tag",
                "mapping_cache_entries": len(vlan_mapping_cache)
            },
            "query_info": {
                "ip_address_input": ip_address,
                "detailed_search": detailed,
                "timestamp": datetime.now().isoformat(),
                "note": "VLAN MAPPING FIXED - Now shows correct VLAN tags from vlans.vlan_vlan field"
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
        
    except Exception as e:
        logger.error(f"Error in search_ip_to_mac (vlan fixed): {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def search_fdb_by_mac(mac_address: str, detailed: bool = True) -> str:
    """Search FDB table for specific MAC address with CORRECT VLAN mapping
    
    Args:
        mac_address: MAC address to search for (various formats accepted)
        detailed: Include detailed device and port information (default: True)
        
    Returns:
        JSON string with MAC address location and CORRECT VLAN tags
    """
    logger.info(f"VLAN FIXED: Searching FDB for MAC: {mac_address}")
    
    try:
        # Normalize MAC address
        try:
            normalized_mac = _normalize_mac_address(mac_address)
            logger.debug(f"Normalized MAC: {normalized_mac}")
        except Exception as e:
            logger.warning(f"MAC normalization failed: {e}, using original format")
            normalized_mac = mac_address
        
        # Try different search methods
        fdb_results = []
        
        # Method 1: Direct FDB search
        try:
            fdb_result = _api_request("GET", f"resources/fdb/{normalized_mac}")
            fdb_data = _extract_data_from_response(fdb_result, ['ports_fdb'])
            fdb_results.extend(fdb_data)
            logger.debug(f"Direct search found {len(fdb_data)} entries")
        except Exception as e:
            logger.warning(f"Direct FDB search failed: {e}")
        
        # Method 2: Search using list_fdb_entries if direct failed
        if not fdb_results:
            try:
                logger.info("Trying FDB table search...")
                filter_result = list_fdb_entries(limit=1000, mac_filter=mac_address)
                filter_data = json.loads(filter_result)
                
                if "fdb_entries" in filter_data:
                    fdb_results.extend(filter_data["fdb_entries"])
                    logger.debug(f"Filter search found {len(filter_data['fdb_entries'])} entries")
                
            except Exception as e:
                logger.warning(f"Filter search failed: {e}")
        
        # Remove duplicates
        unique_results = []
        seen_ids = set()
        
        for result in fdb_results:
            if not isinstance(result, dict):
                continue
                
            result_id = result.get("ports_fdb_id") or result.get("id") or str(result)
            if result_id not in seen_ids:
                seen_ids.add(result_id)
                unique_results.append(result)
        
        # **CRITICAL FIX: Build VLAN mapping cache for FDB entries**
        vlan_mapping_cache = {}
        try:
            vlans_result = _api_request("GET", "resources/vlans")
            vlans_data = _extract_data_from_response(vlans_result, ['vlans'])
            
            for vlan_entry in vlans_data:
                vlan_db_id = str(vlan_entry.get("vlan_id", ""))
                vlan_tag = vlan_entry.get("vlan_vlan")  # Actual VLAN tag
                vlan_name = vlan_entry.get("vlan_name", "")
                device_id = vlan_entry.get("device_id", "")
                
                if vlan_db_id and vlan_tag:
                    vlan_mapping_cache[vlan_db_id] = {
                        "vlan_tag": vlan_tag,
                        "vlan_name": vlan_name,
                        "device_id": device_id
                    }
            
            logger.info(f"Built VLAN mapping cache with {len(vlan_mapping_cache)} entries for FDB")
            
        except Exception as e:
            logger.warning(f"Failed to build VLAN mapping cache for FDB: {e}")
        
        # Enrich results with correct VLAN mapping
        enriched_results = []
        device_info_cache = {}
        port_info_cache = {}
        
        for entry in unique_results:
            enriched_entry = entry.copy()
            
            # Format MAC address
            if "mac_address" in enriched_entry:
                try:
                    enriched_entry["mac_address_formatted"] = _format_mac_address(
                        enriched_entry["mac_address"], "colon"
                    )
                except Exception as e:
                    logger.warning(f"MAC formatting failed: {e}")
                    enriched_entry["mac_address_formatted"] = enriched_entry["mac_address"]
            
            # Format timestamps
            enriched_entry["created_at_formatted"] = _format_timestamp(
                enriched_entry.get("created_at", "")
            )
            enriched_entry["updated_at_formatted"] = _format_timestamp(
                enriched_entry.get("updated_at", "")
            )
            
            # **CRITICAL FIX: Map FDB vlan_id to actual VLAN tag**
            fdb_vlan_id = enriched_entry.get("vlan_id")  # This is database ID, NOT VLAN tag!
            actual_vlan_tag = None
            
            if fdb_vlan_id:
                vlan_mapping = vlan_mapping_cache.get(str(fdb_vlan_id))
                if vlan_mapping:
                    actual_vlan_tag = vlan_mapping["vlan_tag"]
                    enriched_entry["vlan_info"] = {
                        "vlan_tag": actual_vlan_tag,  # CORRECT VLAN tag
                        "vlan_name": vlan_mapping["vlan_name"],
                        "vlan_db_id": fdb_vlan_id,   # Database ID (for reference)
                        "source": "fdb_vlans_table_mapping",
                        "mapping_device_id": vlan_mapping["device_id"]
                    }
                else:
                    enriched_entry["vlan_info"] = {
                        "vlan_tag": "unknown",
                        "vlan_db_id": fdb_vlan_id,
                        "error": f"No VLAN mapping found for vlan_id {fdb_vlan_id}",
                        "source": "fdb_vlans_table_mapping_failed"
                    }
            else:
                enriched_entry["vlan_info"] = {
                    "vlan_tag": "not_specified",
                    "source": "no_vlan_in_fdb_entry"
                }
            
            # Add FDB-specific debug info
            enriched_entry["fdb_vlan_mapping_debug"] = {
                "original_vlan_id_field": fdb_vlan_id,
                "mapped_vlan_tag": actual_vlan_tag,
                "mapping_source": "vlans_table"
            }
            
            # Get device information if detailed
            if detailed:
                device_id = enriched_entry.get("device_id")
                if device_id:
                    if device_id not in device_info_cache:
                        try:
                            device_result = _api_request("GET", f"devices/{device_id}")
                            if "devices" in device_result and device_result["devices"]:
                                device_info_cache[device_id] = device_result["devices"][0]
                            else:
                                device_info_cache[device_id] = None
                        except Exception as e:
                            logger.warning(f"Failed to get device info for {device_id}: {e}")
                            device_info_cache[device_id] = None
                    
                    device_info = device_info_cache.get(device_id)
                    if device_info:
                        enriched_entry["device_info"] = {
                            "hostname": device_info.get("hostname"),
                            "sysName": device_info.get("sysName"),
                            "ip": device_info.get("ip"),
                            "type": device_info.get("type"),
                            "location": device_info.get("location")
                        }
                
                # Get port information
                port_id = enriched_entry.get("port_id")
                if port_id:
                    if port_id not in port_info_cache:
                        try:
                            port_result = _api_request("GET", f"ports/{port_id}")
                            if "ports" in port_result and port_result["ports"]:
                                port_info_cache[port_id] = port_result["ports"][0]
                            else:
                                port_info_cache[port_id] = None
                        except Exception as e:
                            logger.warning(f"Failed to get port info for {port_id}: {e}")
                            port_info_cache[port_id] = None
                    
                    port_info = port_info_cache.get(port_id)
                    if port_info:
                        enriched_entry["port_info"] = {
                            "ifName": port_info.get("ifName"),
                            "ifAlias": port_info.get("ifAlias"),
                            "ifDescr": port_info.get("ifDescr"),
                            "ifOperStatus": port_info.get("ifOperStatus"),
                            "ifSpeed": port_info.get("ifSpeed"),
                            "ifType": port_info.get("ifType")
                        }
            
            enriched_results.append(enriched_entry)
        
        # Calculate search statistics with correct VLAN tags
        if enriched_results:
            vlans_found = set()
            devices_found = set(str(entry.get("device_id", "")) for entry in enriched_results)
            ports_found = set(str(entry.get("port_id", "")) for entry in enriched_results)
            
            for entry in enriched_results:
                vlan_info = entry.get("vlan_info", {})
                vlan_tag = vlan_info.get("vlan_tag")
                if vlan_tag and vlan_tag not in ["unknown", "not_specified"]:
                    vlans_found.add(str(vlan_tag))
            
            search_summary = {
                "mac_address_searched": mac_address,
                "mac_address_normalized": normalized_mac,
                "total_entries_found": len(enriched_results),
                "vlan_tags_found": sorted(list(vlans_found)),  # CORRECT VLAN tags
                "devices_found": sorted(list(devices_found)),
                "ports_found": sorted(list(ports_found)),
                "vlan_mapping_applied": True
            }
        else:
            search_summary = {
                "mac_address_searched": mac_address,
                "mac_address_normalized": normalized_mac,
                "total_entries_found": 0,
                "message": "MAC address not found in FDB table"
            }
        
        result = {
            "search_summary": search_summary,
            "fdb_entries": enriched_results,
            "vlan_mapping_info": {
                "explanation": "FDB VLAN tags are now correctly mapped from vlans table",
                "mapping_cache_entries": len(vlan_mapping_cache)
            },
            "query_info": {
                "mac_address_input": mac_address,
                "detailed_search": detailed,
                "timestamp": datetime.now().isoformat(),
                "note": "FDB VLAN MAPPING FIXED - Now shows correct VLAN tags from vlans.vlan_vlan field"
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Error in search_fdb_by_mac (vlan fixed): {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def test_vlan_mapping() -> str:
    """Test the VLAN mapping to understand the difference between vlan_id and vlan_vlan
    
    Returns:
        JSON string showing VLAN mapping analysis
    """
    logger.info("Testing VLAN mapping")
    
    try:
        # Get all VLANs to understand the mapping
        vlans_result = _api_request("GET", "resources/vlans")
        vlans_data = _extract_data_from_response(vlans_result, ['vlans'])
        
        mapping_analysis = {
            "total_vlans_found": len(vlans_data),
            "vlan_mappings": [],
            "explanation": {
                "vlan_id": "Database primary key (NOT the VLAN tag)",
                "vlan_vlan": "Actual VLAN tag number",
                "vlan_name": "VLAN name",
                "device_id": "Device this VLAN belongs to"
            }
        }
        
        for vlan in vlans_data:
            mapping_entry = {
                "vlan_id": vlan.get("vlan_id"),           # Database ID
                "vlan_vlan": vlan.get("vlan_vlan"),       # Actual VLAN tag
                "vlan_name": vlan.get("vlan_name"),
                "device_id": vlan.get("device_id"),
                "vlan_domain": vlan.get("vlan_domain")
            }
            mapping_analysis["vlan_mappings"].append(mapping_entry)
        
        # Sort by device_id for easier reading
        mapping_analysis["vlan_mappings"].sort(key=lambda x: (x.get("device_id", 0), x.get("vlan_vlan", 0)))
        
        return json.dumps(mapping_analysis, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
        
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def compare_arp_sources(ip_address: str) -> str:
    """Compare ARP data from different LibreNMS API sources to find discrepancy
    
    Args:
        ip_address: IP address to compare across sources
        
    Returns:
        JSON string comparing all possible data sources
    """
    logger.info(f"Comparing ARP sources for IP: {ip_address}")
    
    try:
        comparison_results = {
            "ip_address": ip_address,
            "sources": {}
        }
        
        # Source 1: Direct ARP endpoint
        try:
            direct_result = _api_request("GET", f"resources/ip/arp/{ip_address}")
            direct_entries = _extract_data_from_response(direct_result, ['arp', 'ip_arp'])
            
            comparison_results["sources"]["direct_arp_endpoint"] = {
                "method": "GET /resources/ip/arp/{ip}",
                "entries_found": len(direct_entries),
                "entries": direct_entries,
                "vlans_found": [str(entry.get("vlan_id") or entry.get("vlan", "")) for entry in direct_entries if (entry.get("vlan_id") or entry.get("vlan"))]
            }
        except Exception as e:
            comparison_results["sources"]["direct_arp_endpoint"] = {"error": str(e)}
        
        # Source 2: Device-specific ARP tables
        try:
            devices_result = _api_request("GET", "devices", params={"limit": 10})
            devices_data = _extract_data_from_response(devices_result, ['devices'])
            
            device_results = {}
            for device in devices_data:
                device_id = device.get('device_id')
                hostname = device.get('hostname', f'device_{device_id}')
                
                try:
                    device_arp_result = _api_request("GET", f"devices/{device_id}/arp")
                    device_arp_data = _extract_data_from_response(device_arp_result, ['arp', 'ip_arp'])
                    
                    matching_entries = []
                    for entry in device_arp_data:
                        entry_ip = entry.get("ipv4_address") or entry.get("ip_address")
                        if entry_ip == ip_address:
                            matching_entries.append(entry)
                    
                    if matching_entries:
                        device_results[hostname] = {
                            "device_id": device_id,
                            "method": f"GET /devices/{device_id}/arp",
                            "matching_entries": matching_entries,
                            "vlans_found": [str(entry.get("vlan_id") or entry.get("vlan", "")) for entry in matching_entries if (entry.get("vlan_id") or entry.get("vlan"))]
                        }
                        
                except Exception as e:
                    device_results[hostname] = {"error": str(e)}
            
            comparison_results["sources"]["device_specific_arp"] = device_results
            
        except Exception as e:
            comparison_results["sources"]["device_specific_arp"] = {"error": str(e)}
        
        # Source 3: General ARP table search
        try:
            general_result = _paginate_request("resources/ip/arp", params={}, max_items=1000)
            
            matching_general = []
            for entry in general_result:
                entry_ip = entry.get("ipv4_address") or entry.get("ip_address")
                if entry_ip == ip_address:
                    matching_general.append(entry)
            
            comparison_results["sources"]["general_arp_search"] = {
                "method": "GET /resources/ip/arp (filtered)",
                "entries_found": len(matching_general),
                "entries": matching_general,
                "vlans_found": [str(entry.get("vlan_id") or entry.get("vlan", "")) for entry in matching_general if (entry.get("vlan_id") or entry.get("vlan"))]
            }
            
        except Exception as e:
            comparison_results["sources"]["general_arp_search"] = {"error": str(e)}
        
        # Source 4: FDB cross-reference (to see if this is causing confusion)
        try:
            # First get MAC addresses from ARP sources
            all_macs = set()
            for source_name, source_data in comparison_results["sources"].items():
                if isinstance(source_data, dict):
                    if "entries" in source_data:
                        for entry in source_data["entries"]:
                            mac = entry.get("mac_address")
                            if mac:
                                all_macs.add(mac)
                    elif source_name == "device_specific_arp":
                        for device_data in source_data.values():
                            if isinstance(device_data, dict) and "matching_entries" in device_data:
                                for entry in device_data["matching_entries"]:
                                    mac = entry.get("mac_address")
                                    if mac:
                                        all_macs.add(mac)
            
            fdb_results = {}
            for mac in all_macs:
                try:
                    fdb_result = search_fdb_by_mac(mac, detailed=False)
                    fdb_data = json.loads(fdb_result)
                    if "fdb_entries" in fdb_data and fdb_data["fdb_entries"]:
                        fdb_vlans = [str(entry.get("vlan_id", "")) for entry in fdb_data["fdb_entries"] if entry.get("vlan_id")]
                        fdb_results[mac] = {
                            "fdb_vlans": fdb_vlans,
                            "fdb_entries": len(fdb_data["fdb_entries"])
                        }
                except Exception as e:
                    fdb_results[mac] = {"error": str(e)}
            
            comparison_results["sources"]["fdb_cross_reference"] = fdb_results
            
        except Exception as e:
            comparison_results["sources"]["fdb_cross_reference"] = {"error": str(e)}
        
        # Analysis
        all_vlans_found = set()
        source_vlan_summary = {}
        
        for source_name, source_data in comparison_results["sources"].items():
            source_vlans = set()
            
            if isinstance(source_data, dict):
                if "vlans_found" in source_data:
                    source_vlans.update(source_data["vlans_found"])
                elif source_name == "device_specific_arp":
                    for device_data in source_data.values():
                        if isinstance(device_data, dict) and "vlans_found" in device_data:
                            source_vlans.update(device_data["vlans_found"])
                elif source_name == "fdb_cross_reference":
                    for mac_data in source_data.values():
                        if isinstance(mac_data, dict) and "fdb_vlans" in mac_data:
                            source_vlans.update(mac_data["fdb_vlans"])
            
            source_vlan_summary[source_name] = list(source_vlans)
            all_vlans_found.update(source_vlans)
        
        comparison_results["analysis"] = {
            "all_vlans_found": sorted(list(all_vlans_found)),
            "source_vlan_summary": source_vlan_summary,
            "discrepancy_detected": len(all_vlans_found) > 1,
            "potential_issue": "FDB cross-reference may be introducing wrong VLAN data" if len(all_vlans_found) > 1 else None
        }
        
        return json.dumps(comparison_results, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
        
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# Diagnostic function: Compare results from different API endpoints
@mcp.tool() 
def diagnose_ip_vlan_discrepancy(ip_address: str) -> str:
    """Diagnose VLAN information discrepancy for an IP address
    
    Args:
        ip_address: IP address to diagnose
        
    Returns:
        JSON string with VLAN information comparison from different sources
    """
    logger.info(f"Diagnosing VLAN discrepancy for IP {ip_address}")
    
    try:
        results = {
            "ip_address": ip_address,
            "sources": {},
            "analysis": {}
        }
        
        # 1. Check different ARP API endpoints
        arp_endpoints = [
            f"resources/ip/arp/{ip_address}",
            f"devices/arp/{ip_address}", 
            f"arp/{ip_address}"
        ]
        
        for endpoint in arp_endpoints:
            try:
                arp_result = _api_request("GET", endpoint)
                arp_data = _extract_data_from_response(arp_result, ['arp', 'ip_arp'])
                
                vlans_from_endpoint = []
                for entry in arp_data:
                    if entry.get("ipv4_address") == ip_address or entry.get("ip_address") == ip_address:
                        vlan = entry.get("vlan_id") or entry.get("vlan")
                        if vlan:
                            vlans_from_endpoint.append(str(vlan))
                
                endpoint_name = endpoint.split('/')[-2] if '/' in endpoint else endpoint
                results["sources"][f"arp_endpoint_{endpoint_name}"] = {
                    "vlans_found": vlans_from_endpoint,
                    "entry_count": len(arp_data)
                }
                
            except Exception as e:
                endpoint_name = endpoint.split('/')[-2] if '/' in endpoint else endpoint
                results["sources"][f"arp_endpoint_{endpoint_name}"] = {
                    "error": str(e)
                }
        
        # 2. Check device-specific ARP tables
        try:
            devices_result = _api_request("GET", "devices", params={"limit": 10})
            devices_data = _extract_data_from_response(devices_result, ['devices'])
            
            device_arp_vlans = {}
            
            for device in devices_data:
                device_id = device.get('device_id')
                hostname = device.get('hostname', f'device_{device_id}')
                
                try:
                    device_arp_result = _api_request("GET", f"devices/{device_id}/arp")
                    device_arp_data = _extract_data_from_response(device_arp_result, ['arp', 'ip_arp'])
                    
                    for entry in device_arp_data:
                        if entry.get("ipv4_address") == ip_address or entry.get("ip_address") == ip_address:
                            vlan = entry.get("vlan_id") or entry.get("vlan")
                            mac = entry.get("mac_address")
                            device_arp_vlans[hostname] = {
                                "vlan": str(vlan) if vlan else None,
                                "mac": mac,
                                "device_id": device_id
                            }
                            
                except Exception as e:
                    device_arp_vlans[hostname] = {"error": str(e)}
            
            results["sources"]["device_specific_arp"] = device_arp_vlans
            
        except Exception as e:
            results["sources"]["device_specific_arp"] = {"error": str(e)}
        
        # 3. Check FDB lookup through MAC addresses
        try:
            # First get MAC addresses from ARP
            mac_addresses = set()
            for source_data in results["sources"].values():
                if isinstance(source_data, dict):
                    if "vlans_found" in source_data:  # ARP endpoint data
                        continue
                    else:  # Device specific data  
                        for device_info in source_data.values():
                            if isinstance(device_info, dict) and "mac" in device_info:
                                if device_info["mac"]:
                                    mac_addresses.add(device_info["mac"])
            
            fdb_vlans = {}
            for mac in mac_addresses:
                if mac:
                    try:
                        fdb_result = search_fdb_by_mac(mac, detailed=False)
                        fdb_data = json.loads(fdb_result)
                        if "fdb_entries" in fdb_data:
                            vlans = [str(entry.get("vlan_id")) for entry in fdb_data["fdb_entries"] if entry.get("vlan_id")]
                            fdb_vlans[mac] = vlans
                    except Exception as e:
                        fdb_vlans[mac] = {"error": str(e)}
            
            results["sources"]["fdb_lookup"] = fdb_vlans
            
        except Exception as e:
            results["sources"]["fdb_lookup"] = {"error": str(e)}
        
        # 4. Analyze discrepancies
        all_vlans = set()
        source_summary = {}
        
        for source_name, source_data in results["sources"].items():
            vlans_in_source = set()
            
            if isinstance(source_data, dict):
                if "vlans_found" in source_data:
                    vlans_in_source.update(source_data["vlans_found"])
                elif source_name == "device_specific_arp":
                    for device_info in source_data.values():
                        if isinstance(device_info, dict) and "vlan" in device_info:
                            if device_info["vlan"]:
                                vlans_in_source.add(device_info["vlan"])
                elif source_name == "fdb_lookup":
                    for vlans_list in source_data.values():
                        if isinstance(vlans_list, list):
                            vlans_in_source.update(vlans_list)
            
            source_summary[source_name] = list(vlans_in_source)
            all_vlans.update(vlans_in_source)
        
        results["analysis"] = {
            "all_vlans_found": sorted(list(all_vlans)),
            "vlan_consistency": len(all_vlans) <= 1,
            "source_summary": source_summary,
            "discrepancy_detected": len(all_vlans) > 1,
            "recommendation": "Use device-specific ARP queries for most accurate VLAN information" if len(all_vlans) > 1 else "VLAN information is consistent across sources"
        }
        
        return json.dumps(results, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
        
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def get_network_arp_table(network_cidr: str, detailed: bool = False) -> str:
    """Get ARP table entries for a specific network segment with CORRECT VLAN mapping
    
    Args:
        network_cidr: Network in CIDR format (e.g., "192.168.1.0/24")
        detailed: Include detailed device information (default: False)
        
    Returns:
        JSON string with network ARP table and statistics with CORRECT VLAN tags
    """
    logger.info(f"VLAN FIXED: Getting ARP table for network: {network_cidr}")
    
    try:
        # Validate network CIDR format
        if not _validate_network_cidr(network_cidr):
            return json.dumps({
                "error": f"Invalid network CIDR format: {network_cidr}",
                "timestamp": datetime.now().isoformat()
            }, indent=2, ensure_ascii=False)
        
        # Build VLAN mapping cache
        vlan_mapping_cache = _build_vlan_mapping_cache()
        
        arp_entries = []
        
        # Filter all ARP entries by network
        try:
            logger.info("Filtering all ARP entries by network...")
            all_arp_result = _paginate_request("resources/ip/arp", params={}, max_items=5000)
            
            if all_arp_result:
                network = ipaddress.ip_network(network_cidr, strict=False)
                
                for entry in all_arp_result:
                    ip_str = entry.get("ipv4_address") or entry.get("ip_address")
                    if ip_str:
                        try:
                            ip_addr = ipaddress.ip_address(ip_str)
                            if ip_addr in network:
                                arp_entries.append(entry)
                        except ValueError:
                            continue
                
                logger.info(f"Network filtering found {len(arp_entries)} entries in {network_cidr}")
            
        except Exception as e:
            logger.warning(f"Network filtering failed: {e}")
        
        # Sort by IP address
        def ip_sort_key(entry):
            ip_str = entry.get("ipv4_address") or entry.get("ip_address") or "0.0.0.0"
            try:
                return ipaddress.ip_address(ip_str)
            except:
                return ipaddress.ip_address("0.0.0.0")
        
        try:
            arp_entries.sort(key=ip_sort_key)
        except Exception as e:
            logger.warning(f"Could not sort by IP: {e}")
        
        # Apply VLAN mapping to all entries
        enriched_entries = []
        for entry in arp_entries:
            enriched_entry = entry.copy()
            
            # Format MAC address
            if "mac_address" in enriched_entry:
                try:
                    enriched_entry["mac_address_formatted"] = _format_mac_address(
                        enriched_entry["mac_address"], "colon"
                    )
                except Exception as e:
                    enriched_entry["mac_address_formatted"] = enriched_entry["mac_address"]
            
            # Apply VLAN mapping
            enriched_entry = _apply_vlan_mapping(enriched_entry, vlan_mapping_cache, "arp")
            
            enriched_entries.append(enriched_entry)
        
        # Calculate network statistics with correct VLAN tags
        ip_count = len(set(entry.get("ipv4_address") or entry.get("ip_address") for entry in enriched_entries))
        mac_count = len(set(entry.get("mac_address") for entry in enriched_entries))
        device_count = len(set(str(entry.get("device_id")) for entry in enriched_entries))
        
        vlan_counts = {}
        for entry in enriched_entries:
            vlan_info = entry.get("vlan_info", {})
            vlan_tag = vlan_info.get("vlan_tag")
            if vlan_tag and vlan_tag not in ["unknown", "not_specified"]:
                vlan_counts[str(vlan_tag)] = vlan_counts.get(str(vlan_tag), 0) + 1
        
        # Analyze network usage
        try:
            network = ipaddress.ip_network(network_cidr, strict=False)
            total_addresses = network.num_addresses
            if network.prefixlen >= 24:
                usable_addresses = total_addresses - 2
            else:
                usable_addresses = total_addresses
            utilization_percentage = (ip_count / max(usable_addresses, 1)) * 100
        except Exception as e:
            logger.warning(f"Network analysis failed: {e}")
            total_addresses = 0
            usable_addresses = 0
            utilization_percentage = 0
        
        result = {
            "network_info": {
                "network_cidr": network_cidr,
                "total_addresses": total_addresses,
                "usable_addresses": usable_addresses,
                "discovered_ip_addresses": ip_count,
                "utilization_percentage": round(utilization_percentage, 2)
            },
            "statistics": {
                "unique_ip_addresses": ip_count,
                "unique_mac_addresses": mac_count,
                "monitoring_devices": device_count,
                "total_arp_entries": len(enriched_entries),
                "vlan_breakdown": dict(sorted(vlan_counts.items(), key=lambda x: x[1], reverse=True))
            },
            "arp_entries": enriched_entries,
            "query_info": {
                "network_input": network_cidr,
                "detailed_search": detailed,
                "entries_enriched": len(enriched_entries),
                "vlan_mapping_applied": True,
                "timestamp": datetime.now().isoformat(),
                "note": "VLAN MAPPING FIXED - Shows correct VLAN tags"
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
        
    except Exception as e:
        logger.error(f"Error in get_network_arp_table (vlan fixed): {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def analyze_network_layer2_layer3(network_cidr: Optional[str] = None, device_id: Optional[int] = None) -> str:
    """Analyze correlation between layer 2 (FDB) and layer 3 (ARP) with CORRECT VLAN mapping
    
    Args:
        network_cidr: Network to analyze (optional, e.g., "192.168.1.0/24")
        device_id: Specific device to analyze (optional)
        
    Returns:
        JSON string with comprehensive layer 2/3 network analysis with CORRECT VLAN tags
    """
    logger.info(f"VLAN FIXED: Analyzing L2/L3 correlation: network={network_cidr}, device={device_id}")
    
    try:
        # Build VLAN mapping cache
        vlan_mapping_cache = _build_vlan_mapping_cache()
        
        # Get ARP data
        arp_data = []
        if network_cidr:
            arp_result = get_network_arp_table(network_cidr, detailed=False)
            arp_response = json.loads(arp_result)
            if "arp_entries" in arp_response:
                arp_data = arp_response["arp_entries"]
        elif device_id:
            try:
                device_arp_result = _api_request("GET", f"devices/{device_id}/arp")
                device_arp_data = _extract_data_from_response(device_arp_result, ['arp', 'ip_arp'])
                # Apply VLAN mapping to device ARP data
                for entry in device_arp_data:
                    _apply_vlan_mapping(entry, vlan_mapping_cache, "arp")
                arp_data = device_arp_data
            except Exception as e:
                logger.warning(f"Device ARP lookup failed: {e}")
                arp_data = []
        else:
            try:
                arp_sample = _paginate_request("resources/ip/arp", params={}, max_items=1000)
                # Apply VLAN mapping to sample data
                for entry in arp_sample:
                    _apply_vlan_mapping(entry, vlan_mapping_cache, "arp")
                arp_data = arp_sample
            except Exception as e:
                logger.warning(f"General ARP lookup failed: {e}")
                arp_data = []
        
        # Get FDB data
        fdb_data = []
        if device_id:
            fdb_result = get_device_fdb_table(device_id, limit=0)
            fdb_response = json.loads(fdb_result)
            if "fdb_entries" in fdb_response:
                fdb_data = fdb_response["fdb_entries"]
        else:
            fdb_result = list_fdb_entries(limit=1000)
            fdb_response = json.loads(fdb_result)
            if "fdb_entries" in fdb_response:
                fdb_data = fdb_response["fdb_entries"]
        
        # Create MAC address mappings with CORRECT VLAN tags
        arp_mac_to_ip = {}
        arp_ip_to_mac = {}
        arp_mac_to_vlans = {}
        
        for entry in arp_data:
            if not isinstance(entry, dict):
                continue
                
            mac = entry.get("mac_address", "")
            ip = entry.get("ipv4_address") or entry.get("ip_address", "")
            vlan_info = entry.get("vlan_info", {})
            vlan_tag = vlan_info.get("vlan_tag")
            
            if mac and ip:
                if mac not in arp_mac_to_ip:
                    arp_mac_to_ip[mac] = []
                arp_mac_to_ip[mac].append(ip)
                arp_ip_to_mac[ip] = mac
                
                if vlan_tag and vlan_tag not in ["unknown", "not_specified"]:
                    if mac not in arp_mac_to_vlans:
                        arp_mac_to_vlans[mac] = set()
                    arp_mac_to_vlans[mac].add(str(vlan_tag))
        
        # Create FDB mappings with CORRECT VLAN tags
        fdb_mac_to_devices = {}
        fdb_mac_to_vlans = {}
        fdb_mac_to_ports = {}
        
        for entry in fdb_data:
            if not isinstance(entry, dict):
                continue
                
            mac = entry.get("mac_address", "")
            device_id_entry = entry.get("device_id")
            port_id = entry.get("port_id")
            vlan_info = entry.get("vlan_info", {})
            vlan_tag = vlan_info.get("vlan_tag")
            
            if mac:
                if mac not in fdb_mac_to_devices:
                    fdb_mac_to_devices[mac] = set()
                if device_id_entry:
                    fdb_mac_to_devices[mac].add(str(device_id_entry))
                
                if vlan_tag and vlan_tag not in ["unknown", "not_specified"]:
                    if mac not in fdb_mac_to_vlans:
                        fdb_mac_to_vlans[mac] = set()
                    fdb_mac_to_vlans[mac].add(str(vlan_tag))
                
                if mac not in fdb_mac_to_ports:
                    fdb_mac_to_ports[mac] = set()
                if port_id:
                    fdb_mac_to_ports[mac].add(str(port_id))
        
        # Find correlations
        correlated_macs = set(arp_mac_to_ip.keys()) & set(fdb_mac_to_devices.keys())
        arp_only_macs = set(arp_mac_to_ip.keys()) - set(fdb_mac_to_devices.keys())
        fdb_only_macs = set(fdb_mac_to_devices.keys()) - set(arp_mac_to_ip.keys())
        
        # Analyze correlations with CORRECT VLAN tags
        correlation_details = []
        vlan_consistency_issues = []
        
        for mac in correlated_macs:
            arp_vlans = list(arp_mac_to_vlans.get(mac, set()))
            fdb_vlans = list(fdb_mac_to_vlans.get(mac, set()))
            
            correlation_entry = {
                "mac_address": mac,
                "mac_address_formatted": _format_mac_address(mac, "colon"),
                "ip_addresses": arp_mac_to_ip.get(mac, []),
                "arp_vlans": arp_vlans,  # CORRECT VLAN tags
                "fdb_vlans": fdb_vlans,  # CORRECT VLAN tags
                "ports": list(fdb_mac_to_ports.get(mac, set())),
                "vlan_consistency": set(arp_vlans) == set(fdb_vlans)
            }
            
            if not correlation_entry["vlan_consistency"]:
                vlan_consistency_issues.append({
                    "mac": mac,
                    "arp_vlans": arp_vlans,
                    "fdb_vlans": fdb_vlans,
                    "issue": "VLAN mismatch between ARP and FDB"
                })
            
            correlation_details.append(correlation_entry)
        
        # Calculate statistics with CORRECT VLAN tags
        total_arp_macs = len(arp_mac_to_ip)
        total_fdb_macs = len(fdb_mac_to_devices)
        correlation_percentage = (len(correlated_macs) / max(total_arp_macs, 1)) * 100
        
        # Identify potential issues
        issues = []
        
        if len(arp_only_macs) > total_arp_macs * 0.1:
            issues.append(f"High number of MAC addresses in ARP but not FDB: {len(arp_only_macs)}")
        
        if len(fdb_only_macs) > total_fdb_macs * 0.2:
            issues.append(f"High number of MAC addresses in FDB but not ARP: {len(fdb_only_macs)}")
        
        if len(vlan_consistency_issues) > 0:
            issues.append(f"VLAN consistency issues detected: {len(vlan_consistency_issues)} MAC addresses")
        
        result = {
            "analysis_summary": {
                "total_arp_mac_addresses": total_arp_macs,
                "total_fdb_mac_addresses": total_fdb_macs,
                "correlated_mac_addresses": len(correlated_macs),
                "correlation_percentage": round(correlation_percentage, 2),
                "arp_only_macs": len(arp_only_macs),
                "fdb_only_macs": len(fdb_only_macs),
                "vlan_consistency_issues": len(vlan_consistency_issues)
            },
            "correlation_details": correlation_details[:100],
            "vlan_consistency_issues": vlan_consistency_issues[:20],
            "health_assessment": {
                "overall_health": "good" if not issues else "attention_needed",
                "potential_issues": issues,
                "recommendations": [
                    "Investigate ARP-only MAC addresses for security concerns",
                    "Review FDB-only MAC addresses for inactive devices",
                    "Monitor VLAN consistency across network layers",
                    "Validate VLAN configurations and IP assignments"
                ]
            },
            "query_info": {
                "network_filter": network_cidr,
                "device_filter": device_id,
                "arp_entries_analyzed": len(arp_data),
                "fdb_entries_analyzed": len(fdb_data),
                "vlan_mapping_applied": True,
                "analysis_timestamp": datetime.now().isoformat(),
                "note": "VLAN MAPPING FIXED - Analysis uses correct VLAN tags"
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
        
    except Exception as e:
        logger.error(f"Error in analyze_network_layer2_layer3 (vlan fixed): {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)


# ───────────────────────── FDB Table Management - FIXED ─────────────────────────

@mcp.tool()
def get_fdb_summary() -> str:
    """Get FDB table summary without retrieving all entries - FAST
    
    Returns:
        JSON string with FDB summary statistics
    """
    logger.info("Getting FDB summary (fast mode)")
    
    try:
        # 嘗試從 API 獲取計數資訊
        summary_info = {}
        
        # Method 1: 嘗試獲取總計數
        try:
            count_result = _api_request("GET", "resources/fdb", params={"limit": 1})
            if isinstance(count_result, dict) and "count" in count_result:
                summary_info["total_fdb_entries"] = count_result["count"]
            else:
                summary_info["total_fdb_entries"] = "Unknown (API doesn't provide count)"
        except Exception as e:
            logger.warning(f"Count query failed: {e}")
            summary_info["total_fdb_entries"] = "Unknown"
        
        # Method 2: 快速樣本分析 (只取 1000 筆進行分析)
        try:
            sample_result = _api_request("GET", "resources/fdb", params={"limit": 1000})
            sample_data = _extract_data_from_response(sample_result, ['ports_fdb', 'fdb'])
            
            if sample_data:
                # 分析樣本資料
                vlan_sample = {}
                device_sample = {}
                vendor_sample = {}
                
                for entry in sample_data:
                    if not isinstance(entry, dict):
                        continue
                    
                    # VLAN 分析
                    vlan = entry.get("vlan_id", "unknown")
                    vlan_sample[str(vlan)] = vlan_sample.get(str(vlan), 0) + 1
                    
                    # 設備分析
                    device = entry.get("device_id", "unknown")
                    device_sample[str(device)] = device_sample.get(str(device), 0) + 1
                    
                    # Vendor 分析
                    mac = entry.get("mac_address", "")
                    if len(mac) >= 6:
                        oui = re.sub(r'[:\-.]', '', mac)[:6].upper()
                        vendor_sample[oui] = vendor_sample.get(oui, 0) + 1
                
                summary_info["sample_analysis"] = {
                    "sample_size": len(sample_data),
                    "unique_vlans_in_sample": len(vlan_sample),
                    "unique_devices_in_sample": len(device_sample),
                    "unique_vendors_in_sample": len(vendor_sample),
                    "top_vlans": dict(sorted(vlan_sample.items(), key=lambda x: x[1], reverse=True)[:10]),
                    "top_devices": dict(sorted(device_sample.items(), key=lambda x: x[1], reverse=True)[:10]),
                    "top_vendors": dict(sorted(vendor_sample.items(), key=lambda x: x[1], reverse=True)[:10])
                }
            else:
                summary_info["sample_analysis"] = "No sample data available"
                
        except Exception as e:
            logger.warning(f"Sample analysis failed: {e}")
            summary_info["sample_analysis"] = f"Failed: {str(e)}"
        
        # Method 3: 獲取設備列表來估計 FDB 大小
        try:
            devices_result = _api_request("GET", "devices", params={"limit": 20})
            devices_data = _extract_data_from_response(devices_result, ['devices'])
            
            if devices_data:
                summary_info["network_overview"] = {
                    "sample_devices": len(devices_data),
                    "estimated_total_devices": summary_info.get("total_devices", "Unknown")
                }
        except Exception as e:
            logger.debug(f"Device overview failed: {e}")
        
        # 建議的查詢策略
        recommendations = [
            "Use device_id filter to query specific devices",
            "Use vlan_id filter to query specific VLANs", 
            "Set reasonable limits (100-1000) for interactive queries",
            "Use search_fdb_by_mac() for specific MAC lookups",
            "Use analyze_fdb_statistics() for detailed analysis with sampling"
        ]
        
        if isinstance(summary_info.get("total_fdb_entries"), int):
            if summary_info["total_fdb_entries"] > 100000:
                recommendations.insert(0, "⚠️  Large FDB table detected - always use filters!")
        
        result = {
            "fdb_summary": summary_info,
            "performance_recommendations": recommendations,
            "query_options": {
                "list_fdb_entries": "Get filtered FDB entries (use filters!)",
                "search_fdb_by_mac": "Search for specific MAC address",
                "get_device_fdb_table": "Get FDB for specific device",
                "analyze_fdb_statistics": "Statistical analysis with sampling"
            },
            "timestamp": datetime.now().isoformat()
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
        
    except Exception as e:
        logger.error(f"Error in get_fdb_summary: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)


# ═══════════════════════════════════════════════════════════════
# VLAN MAPPING HELPER FUNCTION
# ═══════════════════════════════════════════════════════════════

def _build_vlan_mapping_cache():
    """Build VLAN mapping cache from vlans table - SHARED HELPER
    
    Returns:
        dict: Mapping from vlan_id (database ID) to actual VLAN tag and info
    """
    vlan_mapping_cache = {}
    
    try:
        vlans_result = _api_request("GET", "resources/vlans")
        vlans_data = _extract_data_from_response(vlans_result, ['vlans'])
        
        for vlan_entry in vlans_data:
            vlan_db_id = str(vlan_entry.get("vlan_id", ""))
            vlan_tag = vlan_entry.get("vlan_vlan")  # Actual VLAN tag
            vlan_name = vlan_entry.get("vlan_name", "")
            device_id = vlan_entry.get("device_id", "")
            
            if vlan_db_id and vlan_tag is not None:
                vlan_mapping_cache[vlan_db_id] = {
                    "vlan_tag": vlan_tag,
                    "vlan_name": vlan_name,
                    "device_id": device_id
                }
        
        logger.debug(f"Built VLAN mapping cache with {len(vlan_mapping_cache)} entries")
        
    except Exception as e:
        logger.warning(f"Failed to build VLAN mapping cache: {e}")
    
    return vlan_mapping_cache

def _apply_vlan_mapping(entry, vlan_mapping_cache, source_prefix=""):
    """Apply VLAN mapping to an entry - SHARED HELPER
    
    Args:
        entry: Dictionary entry containing vlan_id field
        vlan_mapping_cache: VLAN mapping cache from _build_vlan_mapping_cache()
        source_prefix: Prefix for source field (e.g., "arp", "fdb")
        
    Returns:
        dict: Entry with vlan_info field added
    """
    vlan_id = entry.get("vlan_id")
    
    if vlan_id:
        vlan_mapping = vlan_mapping_cache.get(str(vlan_id))
        if vlan_mapping:
            entry["vlan_info"] = {
                "vlan_tag": vlan_mapping["vlan_tag"],  # CORRECT VLAN tag
                "vlan_name": vlan_mapping["vlan_name"],
                "vlan_db_id": vlan_id,   # Database ID (for reference)
                "source": f"{source_prefix}_vlans_table_mapping",
                "mapping_device_id": vlan_mapping["device_id"]
            }
        else:
            entry["vlan_info"] = {
                "vlan_tag": "unknown",
                "vlan_db_id": vlan_id,
                "error": f"No VLAN mapping found for vlan_id {vlan_id}",
                "source": f"{source_prefix}_vlans_table_mapping_failed"
            }
    else:
        entry["vlan_info"] = {
            "vlan_tag": "not_specified",
            "source": f"no_vlan_in_{source_prefix}_entry"
        }
    
    return entry

# ═══════════════════════════════════════════════════════════════
# FIXED FUNCTIONS
# ═══════════════════════════════════════════════════════════════

@mcp.tool()
def search_mac_to_ip(mac_address: str, detailed: bool = True) -> str:
    """Search ARP table to find IP addresses for specific MAC address - VLAN FIXED
    
    Args:
        mac_address: MAC address to search for (various formats accepted)
        detailed: Include detailed device and port information (default: True)
        
    Returns:
        JSON string with MAC-to-IP mapping and device details with CORRECT VLAN tags
    """
    logger.info(f"VLAN FIXED: Searching ARP table for MAC: {mac_address}")
    
    try:
        # Build VLAN mapping cache
        vlan_mapping_cache = _build_vlan_mapping_cache()
        
        # Normalize MAC address
        try:
            normalized_mac = _normalize_mac_address(mac_address)
        except Exception as e:
            logger.warning(f"MAC normalization failed: {e}, using original format")
            normalized_mac = mac_address
        
        arp_entries = []
        
        # Search methods...
        try:
            all_arp_result = _paginate_request("resources/ip/arp", params={}, max_items=5000)
            
            if all_arp_result:
                for entry in all_arp_result:
                    entry_mac = entry.get("mac_address", "")
                    if (entry_mac.lower() == mac_address.lower() or 
                        entry_mac.lower() == normalized_mac.lower() or
                        mac_address.lower() in entry_mac.lower()):
                        arp_entries.append(entry)
        except Exception as e:
            logger.warning(f"ARP table search failed: {e}")
        
        # Apply VLAN mapping to all entries
        enriched_entries = []
        for entry in arp_entries:
            enriched_entry = entry.copy()
            
            # Format MAC address
            if "mac_address" in enriched_entry:
                try:
                    enriched_entry["mac_address_formatted"] = _format_mac_address(
                        enriched_entry["mac_address"], "colon"
                    )
                except Exception as e:
                    enriched_entry["mac_address_formatted"] = enriched_entry["mac_address"]
            
            # Apply VLAN mapping
            enriched_entry = _apply_vlan_mapping(enriched_entry, vlan_mapping_cache, "arp")
            
            enriched_entries.append(enriched_entry)
        
        # Calculate summary with correct VLAN tags
        if enriched_entries:
            ip_addresses = [entry.get("ipv4_address") or entry.get("ip_address") for entry in enriched_entries]
            vlan_tags_found = set()
            for entry in enriched_entries:
                vlan_info = entry.get("vlan_info", {})
                vlan_tag = vlan_info.get("vlan_tag")
                if vlan_tag and vlan_tag not in ["unknown", "not_specified"]:
                    vlan_tags_found.add(str(vlan_tag))
            
            search_summary = {
                "mac_address_searched": mac_address,
                "total_ip_addresses_found": len(ip_addresses),
                "ip_addresses": sorted([ip for ip in ip_addresses if ip]),
                "vlan_tags_found": sorted(list(vlan_tags_found)),  # CORRECT VLAN tags
                "vlan_mapping_applied": True
            }
        else:
            search_summary = {
                "mac_address_searched": mac_address,
                "total_ip_addresses_found": 0,
                "message": "MAC address not found in ARP tables"
            }
        
        result = {
            "search_summary": search_summary,
            "arp_entries": enriched_entries,
            "query_info": {
                "mac_address_input": mac_address,
                "detailed_search": detailed,
                "timestamp": datetime.now().isoformat(),
                "note": "VLAN MAPPING FIXED - Shows correct VLAN tags"
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
        
    except Exception as e:
        logger.error(f"Error in search_mac_to_ip (vlan fixed): {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def list_fdb_entries(limit: int = 100, vlan_id: Optional[int] = None, 
                     device_id: Optional[int] = None, mac_filter: Optional[str] = None) -> str:
    """List FDB entries with CORRECT VLAN mapping
    
    Args:
        limit: Maximum number of FDB entries to return (default: 100)
        vlan_id: Filter by VLAN database ID (optional) - NOTE: This is database ID, not VLAN tag
        device_id: Filter by device ID (optional)
        mac_filter: Filter by partial MAC address (optional)
        
    Returns:
        JSON string of FDB entries with CORRECT VLAN tags
    """
    logger.info(f"VLAN FIXED: Listing FDB entries with correct VLAN mapping")
    
    try:
        # Build VLAN mapping cache
        vlan_mapping_cache = _build_vlan_mapping_cache()
        
        # Get FDB entries using existing logic...
        params = {}
        if vlan_id is not None:
            params["vlan"] = vlan_id
        if device_id is not None:
            params["device_id"] = device_id
            
        fdb_entries = _paginate_request_optimized("resources/fdb", params, max_items=limit)
        
        # Apply MAC filter if specified
        if mac_filter and fdb_entries:
            try:
                normalized_filter = _normalize_mac_address(mac_filter)
                fdb_entries = [entry for entry in fdb_entries 
                              if normalized_filter in entry.get("mac_address", "")]
            except Exception:
                fdb_entries = [entry for entry in fdb_entries 
                              if mac_filter.lower() in entry.get("mac_address", "").lower()]
        
        # Apply VLAN mapping to all entries
        enriched_entries = []
        for entry in fdb_entries[:min(len(fdb_entries), limit)]:
            enriched_entry = entry.copy()
            
            # Format MAC address
            if "mac_address" in enriched_entry:
                try:
                    enriched_entry["mac_address_formatted"] = _format_mac_address(
                        enriched_entry["mac_address"], "colon"
                    )
                except Exception as e:
                    enriched_entry["mac_address_formatted"] = enriched_entry["mac_address"]
            
            # Apply VLAN mapping
            enriched_entry = _apply_vlan_mapping(enriched_entry, vlan_mapping_cache, "fdb")
            
            enriched_entries.append(enriched_entry)
        
        # Calculate statistics with correct VLAN tags
        vlan_counts = {}
        device_counts = {}
        
        for entry in enriched_entries:
            if not isinstance(entry, dict):
                continue
                
            # VLAN statistics using correct tags
            vlan_info = entry.get("vlan_info", {})
            vlan_tag = vlan_info.get("vlan_tag")
            if vlan_tag and vlan_tag not in ["unknown", "not_specified"]:
                vlan_counts[str(vlan_tag)] = vlan_counts.get(str(vlan_tag), 0) + 1
            
            # Device statistics
            device = entry.get("device_id", "unknown")
            device_counts[str(device)] = device_counts.get(str(device), 0) + 1
        
        result = {
            "fdb_entries": enriched_entries,
            "count": len(enriched_entries),
            "statistics": {
                "vlan_breakdown": dict(sorted(vlan_counts.items(), key=lambda x: x[1], reverse=True)[:20]),
                "device_breakdown": dict(sorted(device_counts.items(), key=lambda x: x[1], reverse=True)[:20])
            },
            "query_info": {
                "limit_requested": limit,
                "vlan_filter": vlan_id,
                "device_filter": device_id,
                "mac_filter": mac_filter,
                "total_found": len(enriched_entries),
                "vlan_mapping_applied": True,
                "timestamp": datetime.now().isoformat(),
                "note": "VLAN MAPPING FIXED - Shows correct VLAN tags from vlans.vlan_vlan field"
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Error in list_fdb_entries (vlan fixed): {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def get_device_fdb_table(device_id: int, limit: int = 100) -> str:
    """Get FDB table for a specific device with CORRECT VLAN mapping
    
    Args:
        device_id: Device ID to get FDB table for
        limit: Maximum number of entries to return (default: 100, 0 = all)
        
    Returns:
        JSON string with device FDB table and CORRECT VLAN tags
    """
    logger.info(f"VLAN FIXED: Getting FDB table for device {device_id}")
    
    try:
        # Build VLAN mapping cache
        vlan_mapping_cache = _build_vlan_mapping_cache()
        
        # Get device information
        device_result = _api_request("GET", f"devices/{device_id}")
        device_info = None
        
        if "devices" in device_result and device_result["devices"]:
            device_info = device_result["devices"][0]
        
        # Get FDB entries using existing methods...
        fdb_entries = []
        
        try:
            filter_result = list_fdb_entries(limit=0, device_id=device_id)
            filter_data = json.loads(filter_result)
            
            if "fdb_entries" in filter_data:
                fdb_entries = filter_data["fdb_entries"]
        except Exception as e:
            logger.warning(f"FDB collection failed: {e}")
        
        # Limit results if specified
        if limit > 0:
            fdb_entries = fdb_entries[:limit]
        
        # Re-apply VLAN mapping (in case list_fdb_entries didn't apply it)
        for entry in fdb_entries:
            if "vlan_info" not in entry:
                _apply_vlan_mapping(entry, vlan_mapping_cache, "fdb")
        
        # Calculate statistics with correct VLAN tags
        vlan_counts = {}
        port_counts = {}
        
        for entry in fdb_entries:
            if not isinstance(entry, dict):
                continue
                
            # VLAN statistics using correct tags
            vlan_info = entry.get("vlan_info", {})
            vlan_tag = vlan_info.get("vlan_tag")
            if vlan_tag and vlan_tag not in ["unknown", "not_specified"]:
                vlan_counts[str(vlan_tag)] = vlan_counts.get(str(vlan_tag), 0) + 1
            
            # Port statistics
            port = entry.get("port_id", "unknown")
            port_counts[str(port)] = port_counts.get(str(port), 0) + 1
        
        result = {
            "device_info": {
                "device_id": device_id,
                "hostname": device_info.get("hostname") if device_info else "Unknown",
                "sysName": device_info.get("sysName") if device_info else "Unknown",
                "ip": device_info.get("ip") if device_info else "Unknown",
                "type": device_info.get("type") if device_info else "Unknown"
            } if device_info else {"device_id": device_id, "error": "Device not found"},
            "fdb_entries": fdb_entries,
            "count": len(fdb_entries),
            "statistics": {
                "total_mac_addresses": len(fdb_entries),
                "vlan_breakdown": dict(sorted(vlan_counts.items(), key=lambda x: x[1], reverse=True)),
                "port_breakdown": dict(sorted(port_counts.items(), key=lambda x: x[1], reverse=True))
            },
            "query_info": {
                "device_id": device_id,
                "limit_requested": limit,
                "total_found": len(fdb_entries),
                "vlan_mapping_applied": True,
                "timestamp": datetime.now().isoformat(),
                "note": "VLAN MAPPING FIXED - Shows correct VLAN tags"
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Error in get_device_fdb_table (vlan fixed): {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def analyze_fdb_statistics(days: int = 7) -> str:
    """Analyze FDB table statistics and patterns with CORRECT VLAN mapping
    
    Args:
        days: Number of days to analyze (default: 7)
        
    Returns:
        JSON string with comprehensive FDB analysis with CORRECT VLAN tags
    """
    logger.info(f"VLAN FIXED: Analyzing FDB statistics for {days} days")
    
    try:
        # Build VLAN mapping cache
        vlan_mapping_cache = _build_vlan_mapping_cache()
        
        # Get comprehensive FDB data
        all_fdb_result = list_fdb_entries(limit=0)
        all_fdb_data = json.loads(all_fdb_result)
        
        if "error" in all_fdb_data:
            return json.dumps({
                "error": f"Failed to get FDB data: {all_fdb_data['error']}",
                "timestamp": datetime.now().isoformat()
            }, indent=2, ensure_ascii=False)
        
        all_fdb = all_fdb_data.get("fdb_entries", [])
        
        if not all_fdb:
            return json.dumps({
                "error": "No FDB data available",
                "timestamp": datetime.now().isoformat()
            }, indent=2, ensure_ascii=False)
        
        # Ensure all entries have VLAN mapping applied
        for entry in all_fdb:
            if "vlan_info" not in entry:
                _apply_vlan_mapping(entry, vlan_mapping_cache, "fdb")
        
        # Calculate time window
        end_time = datetime.now()
        start_time = end_time - timedelta(days=days)
        
        # Initialize analysis containers
        device_stats = {}
        vlan_stats = {}  # Using CORRECT VLAN tags
        port_stats = {}
        mac_age_distribution = {}
        activity_patterns = {}
        vendor_analysis = {}
        
        active_entries = 0
        stale_entries = 0
        
        for entry in all_fdb:
            if not isinstance(entry, dict):
                continue
            
            device_id = entry.get("device_id")
            port_id = entry.get("port_id")
            mac_address = entry.get("mac_address", "")
            updated_at = entry.get("updated_at")
            created_at = entry.get("created_at")
            
            # Get CORRECT VLAN tag
            vlan_info = entry.get("vlan_info", {})
            vlan_tag = vlan_info.get("vlan_tag")
            
            # Device statistics
            if device_id:
                if device_id not in device_stats:
                    device_stats[device_id] = {
                        "total_macs": 0,
                        "active_macs": 0,
                        "vlans": set(),
                        "ports": set()
                    }
                device_stats[device_id]["total_macs"] += 1
                if vlan_tag and vlan_tag not in ["unknown", "not_specified"]:
                    device_stats[device_id]["vlans"].add(str(vlan_tag))
                if port_id:
                    device_stats[device_id]["ports"].add(port_id)
            
            # VLAN statistics using CORRECT tags
            if vlan_tag and vlan_tag not in ["unknown", "not_specified"]:
                vlan_stats[str(vlan_tag)] = vlan_stats.get(str(vlan_tag), 0) + 1
            
            # Port statistics
            if port_id:
                port_stats[port_id] = port_stats.get(port_id, 0) + 1
            
            # Age analysis
            if updated_at:
                updated_time = _safe_parse_datetime(updated_at)
                if updated_time:
                    age_hours = (end_time - updated_time).total_seconds() / 3600
                    
                    if updated_time >= start_time:
                        active_entries += 1
                        if device_id:
                            device_stats[device_id]["active_macs"] += 1
                    else:
                        stale_entries += 1
                    
                    # Age distribution
                    if age_hours < 1:
                        age_category = "< 1 hour"
                    elif age_hours < 24:
                        age_category = "< 1 day"
                    elif age_hours < 168:  # 7 days
                        age_category = "< 1 week"
                    elif age_hours < 720:  # 30 days
                        age_category = "< 1 month"
                    else:
                        age_category = "> 1 month"
                    
                    mac_age_distribution[age_category] = mac_age_distribution.get(age_category, 0) + 1
                    
                    # Activity patterns (by hour of day)
                    hour = updated_time.hour
                    activity_patterns[hour] = activity_patterns.get(hour, 0) + 1
            
            # Vendor analysis (OUI)
            if len(mac_address) >= 6:
                try:
                    clean_mac = re.sub(r'[:\-.]', '', mac_address)
                    if len(clean_mac) >= 6:
                        oui = clean_mac[:6].upper()
                        vendor_analysis[oui] = vendor_analysis.get(oui, 0) + 1
                except Exception as e:
                    logger.debug(f"OUI extraction failed for {mac_address}: {e}")
        
        # Convert sets to counts for device stats
        for device_id in device_stats:
            device_stats[device_id]["unique_vlans"] = len(device_stats[device_id]["vlans"])
            device_stats[device_id]["unique_ports"] = len(device_stats[device_id]["ports"])
            del device_stats[device_id]["vlans"]
            del device_stats[device_id]["ports"]
        
        # Calculate health metrics
        total_entries = len(all_fdb)
        activity_rate = (active_entries / max(total_entries, 1)) * 100
        
        # Identify potential issues
        issues = []
        
        stale_percentage = (stale_entries / max(total_entries, 1)) * 100
        if stale_percentage > 30:
            issues.append(f"High percentage of stale entries: {stale_percentage:.1f}%")
        
        if port_stats:
            max_port_macs = max(port_stats.values())
            if max_port_macs > 100:
                issues.append(f"Port with excessive MAC addresses: {max_port_macs}")
        
        if len(vlan_stats) < 2:
            issues.append("Very few VLANs in use - possible configuration issue")
        
        result = {
            "analysis_summary": {
                "total_fdb_entries": total_entries,
                "active_entries_last_n_days": active_entries,
                "stale_entries": stale_entries,
                "activity_rate_percentage": round(activity_rate, 2),
                "unique_devices": len(device_stats),
                "unique_vlans": len(vlan_stats),
                "unique_ports": len(port_stats),
                "unique_mac_vendors": len(vendor_analysis)
            },
            "device_analysis": {
                "top_devices_by_mac_count": dict(sorted(
                    [(dev, stats["total_macs"]) for dev, stats in device_stats.items()],
                    key=lambda x: x[1], reverse=True
                )[:20]),
                "devices_with_most_vlans": dict(sorted(
                    [(dev, stats["unique_vlans"]) for dev, stats in device_stats.items()],
                    key=lambda x: x[1], reverse=True
                )[:10])
            },
            "network_distribution": {
                "vlan_breakdown": dict(sorted(vlan_stats.items(), key=lambda x: x[1], reverse=True)[:20]),  # CORRECT VLAN tags
                "port_concentration": dict(sorted(port_stats.items(), key=lambda x: x[1], reverse=True)[:20])
            },
            "temporal_analysis": {
                "mac_age_distribution": mac_age_distribution,
                "hourly_activity_pattern": dict(sorted(activity_patterns.items())),
                "analysis_window_days": days
            },
            "vendor_analysis": {
                "top_mac_vendors_by_oui": dict(sorted(vendor_analysis.items(), key=lambda x: x[1], reverse=True)[:15])
            },
            "health_assessment": {
                "overall_health": "good" if not issues else "attention_needed",
                "potential_issues": issues,
                "recommendations": [
                    "Monitor devices with high MAC counts",
                    "Review stale FDB entries periodically",
                    "Ensure proper VLAN segmentation"
                ]
            },
            "query_info": {
                "analysis_period_days": days,
                "analysis_timestamp": datetime.now().isoformat(),
                "total_entries_analyzed": total_entries,
                "vlan_mapping_applied": True,
                "note": "VLAN MAPPING FIXED - Analysis uses correct VLAN tags from vlans.vlan_vlan field"
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Error in analyze_fdb_statistics (vlan fixed): {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# ───────────────────────── Enhanced Device Management ─────────────────────────

@mcp.tool()
def list_devices(limit: int = 0, status: Optional[str] = None, 
                type_filter: Optional[str] = None, location: Optional[str] = None) -> str:
    """List devices with enhanced filtering options
    
    Args:
        limit: Maximum number of devices to return (default: 0 = all devices)
        status: Filter by device status (up, down, disabled) (optional)
        type_filter: Filter by device type (optional)
        location: Filter by location (optional)
        
    Returns:
        JSON string of devices list with metadata
    """
    logger.info(f"Listing devices: limit={limit}, status={status}, type={type_filter}")
    
    try:
        params = {}
        if status:
            # Convert status to numeric if needed
            status_map = {"up": "1", "down": "0", "disabled": "2"}
            params["status"] = status_map.get(status.lower(), status)
        if type_filter:
            params["type"] = type_filter
        if location:
            params["location"] = location
        
        # 如果 limit 為 0，則撈取所有設備
        max_items = None if limit == 0 else limit
        
        devices = _paginate_request("devices", params, max_items=max_items)
        
        # Calculate statistics with safe access
        total_devices = len(devices)
        status_counts = {}
        type_counts = {}
        
        for device in devices:
            # Ensure device is a dictionary before using .get()
            if not isinstance(device, dict):
                logger.warning(f"Device is not a dictionary: {type(device)} - {device}")
                continue
                
            device_status_val = device.get("status")
            if device_status_val == 1 or device_status_val == "1":
                device_status = "up"
            elif device_status_val == 0 or device_status_val == "0":
                device_status = "down"
            else:
                device_status = "unknown"
            
            device_type = device.get("type", "unknown")
            
            status_counts[device_status] = status_counts.get(device_status, 0) + 1
            type_counts[device_type] = type_counts.get(device_type, 0) + 1
        
        result = {
            "devices": devices,
            "count": total_devices,
            "statistics": {
                "status_breakdown": status_counts,
                "type_breakdown": type_counts
            },
            "query_info": {
                "limit_requested": limit,
                "actual_count": total_devices,
                "filters": {
                    "status": status,
                    "type": type_filter,
                    "location": location
                },
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Error in list_devices: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def get_all_devices() -> str:
    """Get ALL devices without any limit
    
    Returns:
        JSON string of all devices with complete statistics
    """
    logger.info("Getting ALL devices (no limit)")
    
    try:
        # 使用多種方法嘗試獲取所有設備
        all_devices = []
        
        # 方法 1: 使用改進的分頁
        try:
            devices_paginated = _paginate_request("devices", max_items=None)
            all_devices.extend(devices_paginated)
            logger.info(f"Method 1 (pagination): Got {len(devices_paginated)} devices")
        except Exception as e:
            logger.warning(f"Pagination method failed: {e}")
        
        # 方法 2: 如果分頁沒有結果，嘗試單次大量請求
        if not all_devices:
            try:
                large_request = _api_request("GET", "devices", params={"limit": 10000})
                devices_large = _extract_data_from_response(large_request)
                all_devices.extend(devices_large)
                logger.info(f"Method 2 (large request): Got {len(devices_large)} devices")
            except Exception as e:
                logger.warning(f"Large request method failed: {e}")
        
        # 方法 3: 嘗試不帶參數的請求
        if not all_devices:
            try:
                simple_request = _api_request("GET", "devices")
                devices_simple = _extract_data_from_response(simple_request)
                all_devices.extend(devices_simple)
                logger.info(f"Method 3 (simple): Got {len(devices_simple)} devices")
            except Exception as e:
                logger.warning(f"Simple request method failed: {e}")
        
        # 去重複（基於 device_id）
        unique_devices = []
        seen_ids = set()
        
        for device in all_devices:
            if isinstance(device, dict):
                device_id = device.get('device_id') or device.get('id')
                if device_id and device_id not in seen_ids:
                    seen_ids.add(device_id)
                    unique_devices.append(device)
                elif not device_id:
                    # 如果沒有 ID，直接加入（可能是錯誤的資料結構）
                    unique_devices.append(device)
        
        # 計算詳細統計
        total_devices = len(unique_devices)
        status_counts = {"up": 0, "down": 0, "disabled": 0, "unknown": 0}
        type_counts = {}
        location_counts = {}
        os_counts = {}
        
        for device in unique_devices:
            if not isinstance(device, dict):
                continue
                
            # 狀態統計
            device_status_val = device.get("status")
            if device_status_val == 1 or device_status_val == "1":
                status_counts["up"] += 1
            elif device_status_val == 0 or device_status_val == "0":
                status_counts["down"] += 1
            elif device_status_val == 2 or device_status_val == "2":
                status_counts["disabled"] += 1
            else:
                status_counts["unknown"] += 1
            
            # 類型統計
            device_type = device.get("type", "unknown")
            type_counts[device_type] = type_counts.get(device_type, 0) + 1
            
            # 位置統計
            location = device.get("location", "unknown")
            location_counts[location] = location_counts.get(location, 0) + 1
            
            # 作業系統統計
            os_name = device.get("os", "unknown")
            os_counts[os_name] = os_counts.get(os_name, 0) + 1
        
        result = {
            "devices": unique_devices,
            "total_count": total_devices,
            "statistics": {
                "status_breakdown": status_counts,
                "type_breakdown": dict(sorted(type_counts.items(), key=lambda x: x[1], reverse=True)),
                "location_breakdown": dict(sorted(location_counts.items(), key=lambda x: x[1], reverse=True)[:20]),
                "os_breakdown": dict(sorted(os_counts.items(), key=lambda x: x[1], reverse=True)[:20])
            },
            "query_info": {
                "method": "get_all_devices",
                "no_limits_applied": True,
                "deduplication_applied": True,
                "unique_device_ids": len(seen_ids),
                "timestamp": datetime.now().isoformat()
            }
        }
        
        logger.info(f"Successfully retrieved {total_devices} unique devices")
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
        
    except Exception as e:
        logger.error(f"Error in get_all_devices: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def check_device_count() -> str:
    """Check device count using different API methods
    
    Returns:
        JSON string with device count from different methods
    """
    logger.info("Checking device count using different methods")
    
    try:
        results = {}
        
        # 方法 1: 獲取第一頁看看總數
        try:
            first_page = _api_request("GET", "devices", params={"limit": 1, "offset": 0})
            if isinstance(first_page, dict) and "count" in first_page:
                results["method_1_api_count"] = first_page["count"]
            else:
                results["method_1_api_count"] = "Not available"
                results["method_1_response_keys"] = list(first_page.keys()) if isinstance(first_page, dict) else "Not a dict"
        except Exception as e:
            results["method_1_error"] = str(e)
        
        # 方法 2: 嘗試大數字限制
        try:
            large_limit = _api_request("GET", "devices", params={"limit": 99999})
            devices_large = _extract_data_from_response(large_limit)
            results["method_2_large_limit"] = len(devices_large)
        except Exception as e:
            results["method_2_error"] = str(e)
        
        # 方法 3: 不帶參數
        try:
            no_params = _api_request("GET", "devices")
            devices_no_params = _extract_data_from_response(no_params)
            results["method_3_no_params"] = len(devices_no_params)
        except Exception as e:
            results["method_3_error"] = str(e)
        
        # 方法 4: 使用分頁計算
        try:
            paginated = _paginate_request("devices", max_items=None)
            results["method_4_pagination"] = len(paginated)
        except Exception as e:
            results["method_4_error"] = str(e)
        
        # 方法 5: 嘗試不同的端點
        try:
            devices_count_endpoint = _api_request("GET", "devices/count")
            results["method_5_count_endpoint"] = devices_count_endpoint
        except Exception as e:
            results["method_5_error"] = str(e)
        
        return json.dumps({
            "device_count_methods": results,
            "recommendation": "使用 get_all_devices() 函數獲取所有設備",
            "timestamp": datetime.now().isoformat()
        }, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
        
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def batch_device_info(device_ids: str, include_services: bool = True, 
                     include_alerts: bool = True) -> str:
    """Get detailed information for multiple devices in batch
    
    Args:
        device_ids: Comma-separated list of device IDs (e.g., "1,2,3")
        include_services: Include services information (default: True)
        include_alerts: Include recent alerts (default: True)
        
    Returns:
        JSON string with batch device information
    """
    logger.info(f"Batch device info: device_ids={device_ids}")
    
    try:
        device_id_list = []
        for id_str in device_ids.split(","):
            try:
                device_id_list.append(int(id_str.strip()))
            except ValueError:
                logger.warning(f"Invalid device ID: {id_str}")
        
        device_results = {}
        
        for device_id in device_id_list:
            try:
                # Get device details
                device_info = _api_request("GET", f"devices/{device_id}")
                
                result = {
                    "device_info": device_info,
                    "services": [],
                    "recent_alerts": [],
                    "status": "success"
                }
                
                # Get services if requested
                if include_services:
                    try:
                        services_result = _api_request("GET", f"devices/{device_id}/services")
                        services_data = _extract_data_from_response(services_result, ['services'])
                        result["services"] = services_data
                    except Exception as e:
                        result["services_error"] = str(e)
                
                # Get recent alerts if requested
                if include_alerts:
                    try:
                        alerts_result = _api_request("GET", "alerts", params={
                            "device_id": device_id,
                            "limit": 10
                        })
                        alerts_data = _extract_data_from_response(alerts_result, ['alerts'])
                        result["recent_alerts"] = alerts_data
                    except Exception as e:
                        result["alerts_error"] = str(e)
                
                device_results[str(device_id)] = result
                
            except Exception as e:
                device_results[str(device_id)] = {
                    "status": "error",
                    "error": str(e)
                }
        
        summary = {
            "total_requested": len(device_id_list),
            "successful": len([r for r in device_results.values() if r.get("status") == "success"]),
            "failed": len([r for r in device_results.values() if r.get("status") == "error"]),
            "timestamp": datetime.now().isoformat()
        }
        
        result = {
            "devices": device_results,
            "summary": summary
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Error in batch_device_info: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# ───────────────────────── Enhanced Service Management ─────────────────────────

@mcp.tool()
def list_all_services(state: Optional[str] = None, limit: int = 100, 
                     service_type: Optional[str] = None) -> str:
    """List all services with enhanced filtering and statistics
    
    Args:
        state: Service state filter (0=OK, 1=Warning, 2=Critical) (optional)
        limit: Maximum number of services to return (default: 100)
        service_type: Filter by service type (optional)
        
    Returns:
        JSON string of services list with statistics
    """
    logger.info(f"Listing services: state={state}, limit={limit}, type={service_type}")
    
    try:
        params = {}
        if state is not None:
            params["state"] = state
        if service_type:
            params["type"] = service_type
        
        services = _paginate_request("services", params, max_items=limit)
        
        # Calculate statistics with safe access
        state_counts = {"0": 0, "1": 0, "2": 0, "unknown": 0}
        type_counts = {}
        device_counts = {}
        
        for service in services:
            # Ensure service is a dictionary before using .get()
            if not isinstance(service, dict):
                logger.warning(f"Service is not a dictionary: {type(service)} - {service}")
                continue
                
            service_state = str(service.get("service_status", "unknown"))
            service_type_name = service.get("service_type", "unknown")
            device_id = str(service.get("device_id", "unknown"))
            
            if service_state in state_counts:
                state_counts[service_state] += 1
            else:
                state_counts["unknown"] += 1
                
            type_counts[service_type_name] = type_counts.get(service_type_name, 0) + 1
            device_counts[device_id] = device_counts.get(device_id, 0) + 1
        
        result = {
            "services": services,
            "count": len(services),
            "statistics": {
                "state_breakdown": {
                    "ok": state_counts.get("0", 0),
                    "warning": state_counts.get("1", 0),
                    "critical": state_counts.get("2", 0),
                    "unknown": state_counts.get("unknown", 0)
                },
                "type_breakdown": type_counts,
                "devices_with_services": len(device_counts),
                "top_service_devices": dict(sorted(device_counts.items(), 
                                                 key=lambda x: x[1], reverse=True)[:10])
            },
            "query_info": {
                "state_filter": state,
                "type_filter": service_type,
                "limit": limit,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Error in list_all_services: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def get_services_summary() -> str:
    """Get comprehensive summary of services status with performance metrics
    
    Returns:
        JSON string of detailed services summary
    """
    logger.info("Getting services summary")
    
    try:
        # Get services by state using batch requests
        summary_data = {}
        total_services = 0
        
        # Try to get total count first
        try:
            all_services_result = _api_request("GET", "services", params={"limit": 1})
            if "count" in all_services_result:
                total_services = all_services_result["count"]
            else:
                # Fallback: get actual services to count
                services = _paginate_request("services", max_items=1000)
                total_services = len(services)
        except Exception as e:
            logger.warning(f"Could not get total service count: {e}")
        
        for state in ["0", "1", "2"]:
            try:
                services_result = _api_request("GET", "services", params={
                    "state": state,
                    "limit": 1
                })
                count = services_result.get("count", 0)
                summary_data[state] = count
            except Exception as e:
                logger.warning(f"Failed to get services for state {state}: {e}")
                summary_data[state] = 0
        
        # Get additional statistics
        type_distribution = {}
        device_distribution = {}
        
        try:
            sample_services_result = _api_request("GET", "services", params={"limit": 100})
            services_list = _extract_data_from_response(sample_services_result, ['services'])
            
            # Calculate additional metrics
            for service in services_list:
                service_type = service.get("service_type", "unknown")
                device_id = str(service.get("device_id", "unknown"))
                
                type_distribution[service_type] = type_distribution.get(service_type, 0) + 1
                device_distribution[device_id] = device_distribution.get(device_id, 0) + 1
            
        except Exception as e:
            logger.warning(f"Failed to get detailed service stats: {e}")
        
        # Recalculate total if we didn't get it from API
        if total_services == 0:
            total_services = sum(summary_data.values())
        
        # Calculate health percentage
        ok_count = summary_data.get("0", 0)
        health_percentage = (ok_count / max(total_services, 1)) * 100
        
        result = {
            "summary": {
                "ok_count": summary_data.get("0", 0),
                "warning_count": summary_data.get("1", 0),
                "critical_count": summary_data.get("2", 0),
                "total_count": total_services,
                "health_percentage": round(health_percentage, 2)
            },
            "detailed_stats": {
                "service_types": type_distribution,
                "top_devices_by_service_count": dict(sorted(device_distribution.items(), 
                                                          key=lambda x: x[1], reverse=True)[:10])
            },
            "timestamp": datetime.now().isoformat()
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Error in get_services_summary: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# ───────────────────────── Enhanced Alert Management ─────────────────────────

@mcp.tool()
def get_comprehensive_alert_history(days: int = 30, limit: int = 1000, 
                                  include_resolved: bool = True, 
                                  severity: Optional[str] = None) -> str:
    """Get comprehensive alert history with multiple data sources
    
    Args:
        days: Number of days to look back (default: 30)
        limit: Maximum number of alerts to return (default: 1000)
        include_resolved: Include resolved/closed alerts (default: True)
        severity: Filter by severity (critical, warning, etc.) (optional)
        
    Returns:
        JSON string of comprehensive alert history
    """
    logger.info(f"Getting comprehensive alert history: days={days}, limit={limit}")
    
    try:
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        all_alerts = []
        
        # Strategy 1: Get active/current alerts
        try:
            params = {"limit": min(limit, 500)}
            if severity:
                params["severity"] = severity
            
            active_alerts_result = _api_request("GET", "alerts", params=params)
            active_alerts = _extract_data_from_response(active_alerts_result, ['alerts'])
            
            if active_alerts:
                all_alerts.extend(active_alerts)
                logger.info(f"Retrieved {len(active_alerts)} active alerts")
        except Exception as e:
            logger.warning(f"Failed to get active alerts: {e}")
        
        # Strategy 2: Try different endpoints for historical data
        if include_resolved:
            # Try alertlog endpoint
            try:
                alertlog_params = {"limit": min(300, limit)}
                alertlog_result = _api_request("GET", "alertlog", params=alertlog_params)
                alertlog_data = _extract_data_from_response(alertlog_result, ['alertlog'])
                
                # Convert alertlog to alert format
                for log_entry in alertlog_data:
                    alert_entry = {
                        "id": f"alertlog_{log_entry.get('id', '')}",
                        "timestamp": log_entry.get("datetime") or log_entry.get("time_logged"),
                        "device_id": log_entry.get("device_id"),
                        "message": log_entry.get("details", ""),
                        "severity": log_entry.get("severity", "info"),
                        "type": "alertlog",
                        "rule": log_entry.get("rule", ""),
                        "state": log_entry.get("state", 0)
                    }
                    all_alerts.append(alert_entry)
                logger.info(f"Added {len(alertlog_data)} alertlog entries")
            except Exception as e:
                logger.warning(f"Failed to get alertlog: {e}")
            
            # Try eventlog endpoint
            try:
                eventlog_params = {"limit": min(300, limit)}
                eventlog_result = _api_request("GET", "eventlog", params=eventlog_params)
                eventlog_data = _extract_data_from_response(eventlog_result, ['eventlog'])
                
                # Convert eventlog entries to alert format
                for event in eventlog_data:
                    event_message = event.get("message", "").lower()
                    if any(keyword in event_message for keyword in ["alert", "down", "up", "critical", "warning"]):
                        alert_entry = {
                            "id": f"event_{event.get('eventlog_id', '')}",
                            "timestamp": event.get("datetime"),
                            "device_id": event.get("device_id"),
                            "message": event.get("message", ""),
                            "severity": event.get("severity", "info"),
                            "type": "eventlog",
                            "rule": event.get("type", "")
                        }
                        all_alerts.append(alert_entry)
                logger.info(f"Added {len([e for e in eventlog_data if any(k in e.get('message', '').lower() for k in ['alert', 'down', 'up', 'critical', 'warning'])])} relevant eventlog entries")
            except Exception as e:
                logger.warning(f"Failed to get eventlog: {e}")
        
        # Filter by date range and severity
        filtered_alerts = []
        for alert in all_alerts:
            # Date filtering
            alert_time_str = alert.get("timestamp") or alert.get("datetime")
            if alert_time_str:
                alert_time = _safe_parse_datetime(alert_time_str)
                if alert_time and not (start_date <= alert_time <= end_date):
                    continue
            
            # Severity filtering
            if severity:
                alert_severity = alert.get("severity", "").lower()
                if alert_severity != severity.lower():
                    continue
            
            filtered_alerts.append(alert)
        
        # Remove duplicates and sort
        unique_alerts = []
        seen_ids = set()
        
        for alert in filtered_alerts:
            alert_id = alert.get("id") or f"{alert.get('device_id', '')}_{alert.get('timestamp', '')}"
            if alert_id not in seen_ids:
                seen_ids.add(alert_id)
                unique_alerts.append(alert)
        
        # Sort by timestamp (newest first)
        def sort_key(alert):
            timestamp = alert.get("timestamp") or alert.get("datetime") or ""
            dt = _safe_parse_datetime(timestamp)
            return dt if dt else datetime.min
        
        try:
            unique_alerts.sort(key=sort_key, reverse=True)
        except Exception as e:
            logger.warning(f"Could not sort alerts by timestamp: {e}")
        
        # Limit results
        unique_alerts = unique_alerts[:limit]
        
        # Calculate statistics
        severity_counts = {}
        device_counts = {}
        hourly_distribution = {}
        
        for alert in unique_alerts:
            # Ensure alert is a dictionary before using .get()
            if not isinstance(alert, dict):
                logger.warning(f"Alert is not a dictionary: {type(alert)} - {alert}")
                continue
                
            # Severity stats
            alert_severity = alert.get("severity", "unknown")
            severity_counts[alert_severity] = severity_counts.get(alert_severity, 0) + 1
            
            # Device stats
            device_id = str(alert.get("device_id", "unknown"))
            device_counts[device_id] = device_counts.get(device_id, 0) + 1
            
            # Time distribution
            timestamp = alert.get("timestamp") or alert.get("datetime")
            if timestamp:
                dt = _safe_parse_datetime(timestamp)
                if dt:
                    hour_key = dt.strftime("%Y-%m-%d %H:00")
                    hourly_distribution[hour_key] = hourly_distribution.get(hour_key, 0) + 1
        
        result = {
            "query_info": {
                "period_days": days,
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "requested_limit": limit,
                "include_resolved": include_resolved,
                "severity_filter": severity
            },
            "statistics": {
                "total_alerts_found": len(unique_alerts),
                "severity_breakdown": severity_counts,
                "device_breakdown": dict(sorted(device_counts.items(), 
                                              key=lambda x: x[1], reverse=True)[:20]),
                "alerts_per_day": round(len(unique_alerts) / max(days, 1), 2)
            },
            "time_analysis": {
                "hourly_distribution": dict(sorted(hourly_distribution.items())[-24:])  # Last 24 hours
            },
            "alerts": unique_alerts,
            "data_sources": ["alerts", "alertlog", "eventlog"],
            "timestamp": datetime.now().isoformat()
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Error in get_comprehensive_alert_history: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def get_recent_alerts(limit: int = 10, severity: Optional[str] = None, days: int = 7) -> str:
    """Get recent active alerts"""
    logger.info(f"Getting recent alerts: limit={limit}, severity={severity}")
    
    try:
        params = {"limit": limit}
        if severity:
            params["severity"] = severity
            
        result = _api_request("GET", "alerts", params=params)
        
        # Ensure we have the right structure
        alerts_data = _extract_data_from_response(result, ['alerts'])
        
        formatted_result = {
            "alerts": alerts_data,
            "count": len(alerts_data),
            "query_info": {
                "period_days": days,
                "severity_filter": severity,
                "limit": limit,
                "note": "Shows only current active/open alerts"
            },
            "timestamp": datetime.now().isoformat()
        }
        
        return json.dumps(formatted_result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Error in get_recent_alerts: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# ───────────────────────── Cache Management ─────────────────────────

@mcp.tool()
def clear_cache() -> str:
    """Clear the internal cache
    
    Returns:
        JSON string with cache clear status
    """
    logger.info("Clearing cache")
    
    try:
        cache.clear()
        return json.dumps({
            "status": "success",
            "message": "Cache cleared successfully",
            "timestamp": datetime.now().isoformat()
        }, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def cache_stats() -> str:
    """Get cache statistics
    
    Returns:
        JSON string with cache statistics
    """
    logger.info("Getting cache stats")
    
    try:
        stats = cache.stats()
        stats["timestamp"] = datetime.now().isoformat()
        return json.dumps(stats, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# ───────────────────────── Main Entry Point ─────────────────────────

if __name__ == "__main__":
    logger.info("=" * 80)
    logger.info("LibreNMS FastMCP Server v3.5 - Enhanced with ARP Table and IP-to-MAC Support")
    logger.info("=" * 80)
    logger.info("Core Features:")
    logger.info("  ✓ Comprehensive alert history with multiple data sources")
    logger.info("  ✓ Batch operations for devices, services, and alerts")
    logger.info("  ✓ Intelligent caching with configurable TTL")
    logger.info("  ✓ Enhanced error handling and retry logic")
    logger.info("  ✓ Performance monitoring and health checks")
    logger.info("  ✓ UNLIMITED device retrieval capabilities")
    logger.info("  ✓ FDB table search and management (FIXED)")
    logger.info("  ✓ MAC address tracking and location discovery (FIXED)")
    logger.info("  ✓ ARP table queries and IP-to-MAC resolution (NEW)")
    logger.info("  ✓ Network layer 2/3 correlation and analysis (NEW)")
    logger.info("=" * 80)
    logger.info("Available Tools:")
    logger.info("  • librenms_api() - Raw API calls")
    logger.info("  • health_check() - API connectivity test")
    logger.info("  • search_ip_to_mac() - IP to MAC address resolution")
    logger.info("  • search_mac_to_ip() - MAC to IP address lookup")
    logger.info("  • get_network_arp_table() - Network ARP table")
    logger.info("  • analyze_network_layer2_layer3() - L2/L3 correlation")
    logger.info("  • list_fdb_entries() - List FDB entries")
    logger.info("  • search_fdb_by_mac() - Search MAC addresses")
    logger.info("  • get_device_fdb_table() - Device FDB table")
    logger.info("  • analyze_fdb_statistics() - FDB analysis")
    logger.info("  • list_devices() - List devices")
    logger.info("  • get_all_devices() - Get ALL devices")
    logger.info("  • check_device_count() - Device count diagnostics")
    logger.info("  • batch_device_info() - Batch device info")
    logger.info("  • list_all_services() - List services")
    logger.info("  • get_services_summary() - Services summary")
    logger.info("  • get_comprehensive_alert_history() - Alert history")
    logger.info("  • get_recent_alerts() - Recent alerts")
    logger.info("  • clear_cache() - Clear cache")
    logger.info("  • cache_stats() - Cache statistics")
    logger.info("=" * 80)
    logger.info(f"Configuration: Cache TTL={config.CACHE_TTL}s, Timeout={config.TIMEOUT}s")
    logger.info(f"Enhanced Batch Size={config.BATCH_SIZE}, Max Retries={config.MAX_RETRIES}")
    logger.info("=" * 80)
    
    mcp.run()
