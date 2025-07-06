#!/usr/bin/env python3
"""
MCP server for LibreNMS API – v3.4 Enhanced with ARP Table and IP-to-MAC Support
===============================================================================
Author: Jason Cheng (Jason Tools) - Enhanced by Claude
Created: 2025-06-24
Updated: 2025-07-07
License: MIT

FastMCP-based LibreNMS integration with comprehensive batch operations,
improved error handling, caching, SLA analytics, FDB table management,
and ARP table/IP-to-MAC address resolution.

NEW in v3.4:
- Added comprehensive ARP table management
- IP address to MAC address resolution  
- MAC address to IP address lookup
- Network segment ARP scanning
- Enhanced network discovery with ARP integration
- Cross-referencing between FDB and ARP tables
- Network troubleshooting with layer 2/3 correlation

FIXED Issues in previous version:
- Fixed regex pattern in _normalize_mac_address function
- Fixed _format_mac_address function regex pattern
- Updated FDB endpoints to use correct LibreNMS API paths
- Enhanced error handling for FDB operations

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
def search_ip_to_mac(ip_address: str, detailed: bool = True) -> str:
    """Search ARP table to find MAC address for specific IP address
    
    Args:
        ip_address: IP address to search for (e.g., "192.168.1.118")
        detailed: Include detailed device and port information (default: True)
        
    Returns:
        JSON string with IP-to-MAC mapping and device details
    """
    logger.info(f"Searching ARP table for IP: {ip_address}")
    
    try:
        # Validate IP address format
        if not _validate_ip_address(ip_address):
            return json.dumps({
                "error": f"Invalid IP address format: {ip_address}",
                "timestamp": datetime.now().isoformat()
            }, indent=2, ensure_ascii=False)
        
        arp_entries = []
        
        # Method 1: Direct IP ARP lookup
        try:
            logger.info(f"Direct ARP lookup for IP: {ip_address}")
            arp_result = _api_request("GET", f"resources/ip/arp/{ip_address}")
            arp_data = _extract_data_from_response(arp_result, ['arp', 'ip_arp'])
            if arp_data:
                arp_entries.extend(arp_data)
                logger.info(f"Direct lookup found {len(arp_data)} ARP entries")
        except Exception as e:
            logger.warning(f"Direct ARP lookup failed: {e}")
        
        # Method 2: Search all ARP entries if direct lookup fails
        if not arp_entries:
            try:
                logger.info("Searching all ARP entries...")
                all_arp_result = get_arp_table_entries(limit=0, ip_filter=ip_address)
                all_arp_data = json.loads(all_arp_result)
                
                if "arp_entries" in all_arp_data and all_arp_data["arp_entries"]:
                    # Filter for exact IP match
                    for entry in all_arp_data["arp_entries"]:
                        entry_ip = entry.get("ipv4_address") or entry.get("ip_address")
                        if entry_ip == ip_address:
                            arp_entries.append(entry)
                    logger.info(f"Filtered search found {len(arp_entries)} matching entries")
                
            except Exception as e:
                logger.warning(f"ARP table search failed: {e}")
        
        # Remove duplicates based on MAC address and device
        unique_entries = []
        seen_combinations = set()
        
        for entry in arp_entries:
            if not isinstance(entry, dict):
                continue
                
            mac_address = entry.get("mac_address", "")
            device_id = entry.get("device_id", "")
            combination_key = f"{mac_address}_{device_id}"
            
            if combination_key not in seen_combinations:
                seen_combinations.add(combination_key)
                unique_entries.append(entry)
        
        # Enrich entries with additional information
        enriched_entries = []
        device_info_cache = {}
        port_info_cache = {}
        
        for entry in unique_entries:
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
            
            # Get device information
            device_id = enriched_entry.get("device_id")
            if device_id and detailed:
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
            if port_id and detailed:
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
            
            enriched_entries.append(enriched_entry)
        
        # Cross-reference with FDB table for additional context
        fdb_cross_reference = []
        if enriched_entries and detailed:
            try:
                for entry in enriched_entries:
                    mac_address = entry.get("mac_address")
                    if mac_address:
                        fdb_result = search_fdb_by_mac(mac_address, detailed=False)
                        fdb_data = json.loads(fdb_result)
                        if "fdb_entries" in fdb_data and fdb_data["fdb_entries"]:
                            fdb_cross_reference.extend(fdb_data["fdb_entries"])
            except Exception as e:
                logger.warning(f"FDB cross-reference failed: {e}")
        
        # Calculate summary
        if enriched_entries:
            devices_found = set(str(entry.get("device_id", "")) for entry in enriched_entries)
            mac_addresses = set(entry.get("mac_address", "") for entry in enriched_entries)
            
            search_summary = {
                "ip_address_searched": ip_address,
                "total_arp_entries_found": len(enriched_entries),
                "unique_mac_addresses": len(mac_addresses),
                "devices_with_this_ip": sorted(list(devices_found)),
                "mac_addresses_found": sorted(list(mac_addresses)),
                "has_fdb_cross_reference": len(fdb_cross_reference) > 0
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
            "fdb_cross_reference": fdb_cross_reference,
            "query_info": {
                "ip_address_input": ip_address,
                "detailed_search": detailed,
                "search_methods_used": ["direct_arp_lookup", "arp_table_search", "fdb_cross_reference"],
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
        
    except Exception as e:
        logger.error(f"Error in search_ip_to_mac: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def search_mac_to_ip(mac_address: str, detailed: bool = True) -> str:
    """Search ARP table to find IP addresses for specific MAC address
    
    Args:
        mac_address: MAC address to search for (various formats accepted)
        detailed: Include detailed device and port information (default: True)
        
    Returns:
        JSON string with MAC-to-IP mapping and device details
    """
    logger.info(f"Searching ARP table for MAC: {mac_address}")
    
    try:
        # Normalize MAC address
        try:
            normalized_mac = _normalize_mac_address(mac_address)
            logger.debug(f"Normalized MAC: {normalized_mac}")
        except Exception as e:
            logger.warning(f"MAC normalization failed: {e}, using original format")
            normalized_mac = mac_address
        
        arp_entries = []
        
        # Method 1: Direct MAC ARP lookup
        try:
            logger.info(f"Direct ARP lookup for MAC: {mac_address}")
            arp_result = _api_request("GET", f"resources/ip/arp/{mac_address}")
            arp_data = _extract_data_from_response(arp_result, ['arp', 'ip_arp'])
            if arp_data:
                arp_entries.extend(arp_data)
                logger.info(f"Direct lookup found {len(arp_data)} ARP entries")
        except Exception as e:
            logger.warning(f"Direct MAC ARP lookup failed: {e}")
        
        # Method 2: Try normalized MAC format
        if not arp_entries and normalized_mac != mac_address:
            try:
                logger.info(f"Trying normalized MAC: {normalized_mac}")
                arp_result = _api_request("GET", f"resources/ip/arp/{normalized_mac}")
                arp_data = _extract_data_from_response(arp_result, ['arp', 'ip_arp'])
                if arp_data:
                    arp_entries.extend(arp_data)
                    logger.info(f"Normalized MAC lookup found {len(arp_data)} ARP entries")
            except Exception as e:
                logger.warning(f"Normalized MAC lookup failed: {e}")
        
        # Method 3: Search all ARP entries if direct lookup fails
        if not arp_entries:
            try:
                logger.info("Searching all ARP entries...")
                all_arp_result = get_arp_table_entries(limit=0, mac_filter=mac_address)
                all_arp_data = json.loads(all_arp_result)
                
                if "arp_entries" in all_arp_data and all_arp_data["arp_entries"]:
                    arp_entries.extend(all_arp_data["arp_entries"])
                    logger.info(f"ARP table search found {len(all_arp_data['arp_entries'])} matching entries")
                
            except Exception as e:
                logger.warning(f"ARP table search failed: {e}")
        
        # Remove duplicates and sort by IP
        unique_entries = []
        seen_ips = set()
        
        for entry in arp_entries:
            if not isinstance(entry, dict):
                continue
                
            ip_address = entry.get("ipv4_address") or entry.get("ip_address")
            if ip_address and ip_address not in seen_ips:
                seen_ips.add(ip_address)
                unique_entries.append(entry)
        
        # Sort by IP address
        def ip_sort_key(entry):
            ip_str = entry.get("ipv4_address") or entry.get("ip_address") or "0.0.0.0"
            try:
                return ipaddress.ip_address(ip_str)
            except:
                return ipaddress.ip_address("0.0.0.0")
        
        try:
            unique_entries.sort(key=ip_sort_key)
        except Exception as e:
            logger.warning(f"Could not sort by IP: {e}")
        
        # Enrich entries with additional information
        enriched_entries = []
        device_info_cache = {}
        
        for entry in unique_entries:
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
            
            # Get device information
            device_id = enriched_entry.get("device_id")
            if device_id and detailed:
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
            
            enriched_entries.append(enriched_entry)
        
        # Cross-reference with FDB table
        fdb_cross_reference = []
        if detailed:
            try:
                fdb_result = search_fdb_by_mac(mac_address, detailed=False)
                fdb_data = json.loads(fdb_result)
                if "fdb_entries" in fdb_data and fdb_data["fdb_entries"]:
                    fdb_cross_reference = fdb_data["fdb_entries"]
            except Exception as e:
                logger.warning(f"FDB cross-reference failed: {e}")
        
        # Calculate summary
        if enriched_entries:
            ip_addresses = [entry.get("ipv4_address") or entry.get("ip_address") for entry in enriched_entries]
            devices_found = set(str(entry.get("device_id", "")) for entry in enriched_entries)
            
            search_summary = {
                "mac_address_searched": mac_address,
                "mac_address_normalized": normalized_mac,
                "total_ip_addresses_found": len(ip_addresses),
                "ip_addresses": sorted(ip_addresses),
                "devices_with_this_mac": sorted(list(devices_found)),
                "has_fdb_cross_reference": len(fdb_cross_reference) > 0
            }
        else:
            search_summary = {
                "mac_address_searched": mac_address,
                "mac_address_normalized": normalized_mac,
                "total_ip_addresses_found": 0,
                "message": "MAC address not found in ARP tables"
            }
        
        result = {
            "search_summary": search_summary,
            "arp_entries": enriched_entries,
            "fdb_cross_reference": fdb_cross_reference,
            "query_info": {
                "mac_address_input": mac_address,
                "detailed_search": detailed,
                "search_methods_used": ["direct_arp_lookup", "normalized_mac_lookup", "arp_table_search", "fdb_cross_reference"],
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
        
    except Exception as e:
        logger.error(f"Error in search_mac_to_ip: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def get_network_arp_table(network_cidr: str, detailed: bool = False) -> str:
    """Get ARP table entries for a specific network segment
    
    Args:
        network_cidr: Network in CIDR format (e.g., "192.168.1.0/24")
        detailed: Include detailed device information (default: False)
        
    Returns:
        JSON string with network ARP table and statistics
    """
    logger.info(f"Getting ARP table for network: {network_cidr}")
    
    try:
        # Validate network CIDR format
        if not _validate_network_cidr(network_cidr):
            return json.dumps({
                "error": f"Invalid network CIDR format: {network_cidr}",
                "timestamp": datetime.now().isoformat()
            }, indent=2, ensure_ascii=False)
        
        arp_entries = []
        
        # Method 1: Direct network ARP lookup
        try:
            logger.info(f"Direct ARP lookup for network: {network_cidr}")
            arp_result = _api_request("GET", f"resources/ip/arp/{network_cidr}")
            arp_data = _extract_data_from_response(arp_result, ['arp', 'ip_arp'])
            if arp_data:
                arp_entries.extend(arp_data)
                logger.info(f"Direct network lookup found {len(arp_data)} ARP entries")
        except Exception as e:
            logger.warning(f"Direct network ARP lookup failed: {e}")
        
        # Method 2: Filter all ARP entries by network
        if not arp_entries:
            try:
                logger.info("Filtering all ARP entries by network...")
                all_arp_result = get_arp_table_entries(limit=0)
                all_arp_data = json.loads(all_arp_result)
                
                if "arp_entries" in all_arp_data and all_arp_data["arp_entries"]:
                    network = ipaddress.ip_network(network_cidr, strict=False)
                    
                    for entry in all_arp_data["arp_entries"]:
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
        
        # Calculate network statistics
        ip_count = len(set(entry.get("ipv4_address") or entry.get("ip_address") for entry in arp_entries))
        mac_count = len(set(entry.get("mac_address") for entry in arp_entries))
        device_count = len(set(str(entry.get("device_id")) for entry in arp_entries))
        
        # Analyze network usage
        try:
            network = ipaddress.ip_network(network_cidr, strict=False)
            total_addresses = network.num_addresses
            # Exclude network and broadcast addresses for /24 and smaller
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
        
        # Enrich with device information if requested
        enriched_entries = arp_entries
        if detailed and arp_entries:
            enriched_entries = []
            device_info_cache = {}
            
            for entry in arp_entries[:100]:  # Limit to 100 for performance
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
                
                # Get device information
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
                
                enriched_entries.append(enriched_entry)
        
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
                "total_arp_entries": len(arp_entries)
            },
            "arp_entries": enriched_entries,
            "query_info": {
                "network_input": network_cidr,
                "detailed_search": detailed,
                "entries_enriched": len(enriched_entries) if detailed else 0,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
        
    except Exception as e:
        logger.error(f"Error in get_network_arp_table: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def get_arp_table_entries(limit: int = 100, device_id: Optional[int] = None, 
                         ip_filter: Optional[str] = None, mac_filter: Optional[str] = None) -> str:
    """List ARP table entries with filtering options
    
    Args:
        limit: Maximum number of ARP entries to return (default: 100, 0 = all)
        device_id: Filter by device ID (optional)
        ip_filter: Filter by IP address (partial match) (optional)
        mac_filter: Filter by MAC address (partial match) (optional)
        
    Returns:
        JSON string of ARP entries with statistics
    """
    logger.info(f"Listing ARP entries: limit={limit}, device={device_id}, ip={ip_filter}, mac={mac_filter}")
    
    try:
        # Performance limit
        if limit == 0:
            logger.warning("Unlimited query requested, setting safety limit to 10000")
            limit = 10000
        elif limit > 50000:
            logger.warning(f"Large limit {limit} requested, setting safety limit to 50000")
            limit = 50000
        
        arp_entries = []
        
        # Method 1: Device-specific query if device_id provided
        if device_id is not None:
            try:
                logger.info(f"Using device-specific ARP query for device {device_id}")
                device_arp_result = _api_request("GET", f"devices/{device_id}/arp")
                arp_entries = _extract_data_from_response(device_arp_result, ['arp', 'ip_arp'])
                logger.info(f"Device-specific method found {len(arp_entries)} ARP entries")
            except Exception as e:
                logger.warning(f"Device-specific ARP query failed: {e}")
        
        # Method 2: General ARP table query
        if not arp_entries:
            endpoints_to_try = ["resources/ip/arp", "arp"]
            
            for endpoint in endpoints_to_try:
                try:
                    logger.info(f"Trying ARP endpoint: {endpoint}")
                    params = {"limit": limit}
                    
                    if device_id is not None:
                        params["device_id"] = device_id
                    
                    arp_result = _paginate_request_optimized(endpoint, params, max_items=limit)
                    
                    if arp_result:
                        arp_entries = arp_result
                        logger.info(f"Successfully got {len(arp_entries)} entries from {endpoint}")
                        break
                    
                except Exception as e:
                    logger.warning(f"ARP endpoint {endpoint} failed: {e}")
                    continue
        
        # Client-side filtering
        if ip_filter and arp_entries:
            logger.info(f"Applying IP filter: {ip_filter}")
            original_count = len(arp_entries)
            arp_entries = [entry for entry in arp_entries 
                          if ip_filter in (entry.get("ipv4_address", "") or entry.get("ip_address", ""))]
            logger.info(f"IP filter reduced entries from {original_count} to {len(arp_entries)}")
        
        if mac_filter and arp_entries:
            logger.info(f"Applying MAC filter: {mac_filter}")
            original_count = len(arp_entries)
            try:
                normalized_filter = _normalize_mac_address(mac_filter)
                arp_entries = [entry for entry in arp_entries 
                              if normalized_filter in entry.get("mac_address", "")]
            except Exception as e:
                logger.warning(f"MAC normalization failed: {e}, using string filter")
                arp_entries = [entry for entry in arp_entries 
                              if mac_filter.lower() in entry.get("mac_address", "").lower()]
            logger.info(f"MAC filter reduced entries from {original_count} to {len(arp_entries)}")
        
        # Final limit
        if len(arp_entries) > limit:
            arp_entries = arp_entries[:limit]
        
        # Calculate statistics (sample-based for performance)
        sample_size = min(len(arp_entries), 1000)
        sample_entries = arp_entries[:sample_size]
        
        total_entries = len(arp_entries)
        device_counts = {}
        ip_networks = {}
        mac_vendors = {}
        
        for entry in sample_entries:
            if not isinstance(entry, dict):
                continue
            
            # Device statistics
            device = entry.get("device_id", "unknown")
            device_counts[str(device)] = device_counts.get(str(device), 0) + 1
            
            # Network statistics
            ip_addr = entry.get("ipv4_address") or entry.get("ip_address")
            if ip_addr:
                try:
                    ip = ipaddress.ip_address(ip_addr)
                    if ip.is_private:
                        # Determine network class
                        if str(ip).startswith("192.168."):
                            network_class = "192.168.x.x"
                        elif str(ip).startswith("10."):
                            network_class = "10.x.x.x"
                        elif str(ip).startswith("172."):
                            network_class = "172.16-31.x.x"
                        else:
                            network_class = "other_private"
                    else:
                        network_class = "public"
                    ip_networks[network_class] = ip_networks.get(network_class, 0) + 1
                except Exception:
                    ip_networks["invalid"] = ip_networks.get("invalid", 0) + 1
            
            # MAC vendor statistics
            mac = entry.get("mac_address", "")
            if len(mac) >= 6:
                try:
                    clean_mac = re.sub(r'[:\-.]', '', mac)
                    if len(clean_mac) >= 6:
                        oui = clean_mac[:6].upper()
                        mac_vendors[oui] = mac_vendors.get(oui, 0) + 1
                except Exception as e:
                    logger.debug(f"OUI extraction failed for {mac}: {e}")
        
        # Format entries for display (limit to first 500 for performance)
        display_limit = min(len(arp_entries), 500)
        formatted_entries = []
        
        for i, entry in enumerate(arp_entries[:display_limit]):
            formatted_entry = entry.copy()
            if "mac_address" in formatted_entry:
                try:
                    formatted_entry["mac_address_formatted"] = _format_mac_address(
                        formatted_entry["mac_address"], "colon"
                    )
                except Exception as e:
                    formatted_entry["mac_address_formatted"] = formatted_entry["mac_address"]
                    
                formatted_entry["created_at_formatted"] = _format_timestamp(
                    formatted_entry.get("created_at", "")
                )
                formatted_entry["updated_at_formatted"] = _format_timestamp(
                    formatted_entry.get("updated_at", "")
                )
            formatted_entries.append(formatted_entry)
        
        result = {
            "arp_entries": formatted_entries,
            "count": total_entries,
            "statistics": {
                "device_breakdown": dict(sorted(device_counts.items(), key=lambda x: x[1], reverse=True)[:20]),
                "network_distribution": dict(sorted(ip_networks.items(), key=lambda x: x[1], reverse=True)),
                "top_mac_vendors": dict(sorted(mac_vendors.items(), key=lambda x: x[1], reverse=True)[:10])
            },
            "query_info": {
                "limit_requested": limit,
                "device_filter": device_id,
                "ip_filter": ip_filter,
                "mac_filter": mac_filter,
                "total_found": total_entries,
                "displayed_entries": len(formatted_entries),
                "statistics_sample_size": sample_size,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
        
    except Exception as e:
        logger.error(f"Error in get_arp_table_entries: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def analyze_network_layer2_layer3(network_cidr: Optional[str] = None, device_id: Optional[int] = None) -> str:
    """Analyze correlation between layer 2 (FDB) and layer 3 (ARP) network information
    
    Args:
        network_cidr: Network to analyze (optional, e.g., "192.168.1.0/24")
        device_id: Specific device to analyze (optional)
        
    Returns:
        JSON string with comprehensive layer 2/3 network analysis
    """
    logger.info(f"Analyzing L2/L3 correlation: network={network_cidr}, device={device_id}")
    
    try:
        # Get ARP data
        arp_data = []
        if network_cidr:
            arp_result = get_network_arp_table(network_cidr, detailed=False)
            arp_response = json.loads(arp_result)
            if "arp_entries" in arp_response:
                arp_data = arp_response["arp_entries"]
        elif device_id:
            arp_result = get_arp_table_entries(limit=0, device_id=device_id)
            arp_response = json.loads(arp_result)
            if "arp_entries" in arp_response:
                arp_data = arp_response["arp_entries"]
        else:
            # Get sample of ARP data
            arp_result = get_arp_table_entries(limit=1000)
            arp_response = json.loads(arp_result)
            if "arp_entries" in arp_response:
                arp_data = arp_response["arp_entries"]
        
        # Get FDB data
        fdb_data = []
        if device_id:
            fdb_result = get_device_fdb_table(device_id, limit=0)
            fdb_response = json.loads(fdb_result)
            if "fdb_entries" in fdb_response:
                fdb_data = fdb_response["fdb_entries"]
        else:
            # Get sample of FDB data
            fdb_result = list_fdb_entries(limit=1000)
            fdb_response = json.loads(fdb_result)
            if "fdb_entries" in fdb_response:
                fdb_data = fdb_response["fdb_entries"]
        
        # Create MAC address mappings
        arp_mac_to_ip = {}
        arp_ip_to_mac = {}
        arp_mac_to_devices = {}
        
        for entry in arp_data:
            if not isinstance(entry, dict):
                continue
                
            mac = entry.get("mac_address", "")
            ip = entry.get("ipv4_address") or entry.get("ip_address", "")
            device_id_entry = entry.get("device_id")
            
            if mac and ip:
                if mac not in arp_mac_to_ip:
                    arp_mac_to_ip[mac] = []
                arp_mac_to_ip[mac].append(ip)
                arp_ip_to_mac[ip] = mac
                
                if mac not in arp_mac_to_devices:
                    arp_mac_to_devices[mac] = set()
                if device_id_entry:
                    arp_mac_to_devices[mac].add(str(device_id_entry))
        
        # Create FDB mappings
        fdb_mac_to_devices = {}
        fdb_mac_to_vlans = {}
        fdb_mac_to_ports = {}
        
        for entry in fdb_data:
            if not isinstance(entry, dict):
                continue
                
            mac = entry.get("mac_address", "")
            device_id_entry = entry.get("device_id")
            vlan_id = entry.get("vlan_id")
            port_id = entry.get("port_id")
            
            if mac:
                if mac not in fdb_mac_to_devices:
                    fdb_mac_to_devices[mac] = set()
                if device_id_entry:
                    fdb_mac_to_devices[mac].add(str(device_id_entry))
                
                if mac not in fdb_mac_to_vlans:
                    fdb_mac_to_vlans[mac] = set()
                if vlan_id:
                    fdb_mac_to_vlans[mac].add(str(vlan_id))
                
                if mac not in fdb_mac_to_ports:
                    fdb_mac_to_ports[mac] = set()
                if port_id:
                    fdb_mac_to_ports[mac].add(str(port_id))
        
        # Find correlations
        correlated_macs = set(arp_mac_to_ip.keys()) & set(fdb_mac_to_devices.keys())
        arp_only_macs = set(arp_mac_to_ip.keys()) - set(fdb_mac_to_devices.keys())
        fdb_only_macs = set(fdb_mac_to_devices.keys()) - set(arp_mac_to_ip.keys())
        
        # Analyze correlations
        correlation_details = []
        device_correlation = {}
        vlan_ip_correlation = {}
        
        for mac in correlated_macs:
            correlation_entry = {
                "mac_address": mac,
                "mac_address_formatted": _format_mac_address(mac, "colon"),
                "ip_addresses": arp_mac_to_ip.get(mac, []),
                "arp_devices": list(arp_mac_to_devices.get(mac, set())),
                "fdb_devices": list(fdb_mac_to_devices.get(mac, set())),
                "vlans": list(fdb_mac_to_vlans.get(mac, set())),
                "ports": list(fdb_mac_to_ports.get(mac, set())),
                "device_consistency": list(arp_mac_to_devices.get(mac, set())) == list(fdb_mac_to_devices.get(mac, set()))
            }
            correlation_details.append(correlation_entry)
            
            # Device correlation analysis
            for device in correlation_entry["arp_devices"]:
                if device not in device_correlation:
                    device_correlation[device] = {"arp_macs": 0, "fdb_macs": 0, "correlated_macs": 0}
                device_correlation[device]["correlated_macs"] += 1
            
            # VLAN-IP correlation
            for vlan in correlation_entry["vlans"]:
                if vlan not in vlan_ip_correlation:
                    vlan_ip_correlation[vlan] = {"unique_ips": set(), "unique_macs": set()}
                vlan_ip_correlation[vlan]["unique_macs"].add(mac)
                for ip in correlation_entry["ip_addresses"]:
                    vlan_ip_correlation[vlan]["unique_ips"].add(ip)
        
        # Count individual table entries
        for mac in arp_only_macs:
            for device in arp_mac_to_devices.get(mac, set()):
                if device not in device_correlation:
                    device_correlation[device] = {"arp_macs": 0, "fdb_macs": 0, "correlated_macs": 0}
                device_correlation[device]["arp_macs"] += 1
        
        for mac in fdb_only_macs:
            for device in fdb_mac_to_devices.get(mac, set()):
                if device not in device_correlation:
                    device_correlation[device] = {"arp_macs": 0, "fdb_macs": 0, "correlated_macs": 0}
                device_correlation[device]["fdb_macs"] += 1
        
        # Convert VLAN correlation sets to counts
        vlan_summary = {}
        for vlan, data in vlan_ip_correlation.items():
            vlan_summary[vlan] = {
                "unique_ip_count": len(data["unique_ips"]),
                "unique_mac_count": len(data["unique_macs"]),
                "sample_ips": sorted(list(data["unique_ips"]))[:10]  # Show first 10 IPs
            }
        
        # Calculate statistics
        total_arp_macs = len(arp_mac_to_ip)
        total_fdb_macs = len(fdb_mac_to_devices)
        correlation_percentage = (len(correlated_macs) / max(total_arp_macs, 1)) * 100
        
        # Identify potential issues
        issues = []
        
        # Check for MAC addresses in ARP but not FDB (possible security concern)
        if len(arp_only_macs) > total_arp_macs * 0.1:  # More than 10%
            issues.append(f"High number of MAC addresses in ARP but not FDB: {len(arp_only_macs)}")
        
        # Check for MAC addresses in FDB but not ARP (possible inactive devices)
        if len(fdb_only_macs) > total_fdb_macs * 0.2:  # More than 20%
            issues.append(f"High number of MAC addresses in FDB but not ARP: {len(fdb_only_macs)}")
        
        # Check for device inconsistencies
        inconsistent_devices = sum(1 for entry in correlation_details if not entry["device_consistency"])
        if inconsistent_devices > len(correlation_details) * 0.05:  # More than 5%
            issues.append(f"Device inconsistencies detected: {inconsistent_devices} MAC addresses")
        
        result = {
            "analysis_summary": {
                "total_arp_mac_addresses": total_arp_macs,
                "total_fdb_mac_addresses": total_fdb_macs,
                "correlated_mac_addresses": len(correlated_macs),
                "correlation_percentage": round(correlation_percentage, 2),
                "arp_only_macs": len(arp_only_macs),
                "fdb_only_macs": len(fdb_only_macs),
                "unique_devices_analyzed": len(device_correlation),
                "unique_vlans_found": len(vlan_summary)
            },
            "correlation_details": correlation_details[:100],  # Limit for performance
            "device_analysis": dict(sorted(device_correlation.items(), 
                                         key=lambda x: x[1]["correlated_macs"], reverse=True)[:20]),
            "vlan_ip_correlation": dict(sorted(vlan_summary.items(), 
                                             key=lambda x: x[1]["unique_ip_count"], reverse=True)[:20]),
            "discrepancies": {
                "arp_only_samples": [{"mac": mac, "ips": arp_mac_to_ip.get(mac, [])} 
                                   for mac in list(arp_only_macs)[:10]],
                "fdb_only_samples": [{"mac": mac, "vlans": list(fdb_mac_to_vlans.get(mac, set()))} 
                                   for mac in list(fdb_only_macs)[:10]]
            },
            "health_assessment": {
                "overall_health": "good" if not issues else "attention_needed",
                "potential_issues": issues,
                "recommendations": [
                    "Investigate ARP-only MAC addresses for security concerns",
                    "Review FDB-only MAC addresses for inactive devices",
                    "Monitor device consistency across network layers",
                    "Validate VLAN configurations and IP assignments"
                ]
            },
            "query_info": {
                "network_filter": network_cidr,
                "device_filter": device_id,
                "arp_entries_analyzed": len(arp_data),
                "fdb_entries_analyzed": len(fdb_data),
                "analysis_timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
        
    except Exception as e:
        logger.error(f"Error in analyze_network_layer2_layer3: {e}")
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

@mcp.tool()
def list_fdb_entries(limit: int = 100, vlan_id: Optional[int] = None, 
                     device_id: Optional[int] = None, mac_filter: Optional[str] = None) -> str:
    """List FDB (Forwarding Database) entries with filtering options - OPTIMIZED
    
    Args:
        limit: Maximum number of FDB entries to return (default: 100, max: 10000 for performance)
        vlan_id: Filter by VLAN ID (optional)
        device_id: Filter by device ID (optional)
        mac_filter: Filter by partial MAC address (optional)
        
    Returns:
        JSON string of FDB entries with statistics
    """
    logger.info(f"Listing FDB entries: limit={limit}, vlan={vlan_id}, device={device_id}")
    
    try:
        # 效能限制：避免記憶體問題
        if limit == 0:
            logger.warning("Unlimited query requested, setting safety limit to 10000")
            limit = 10000
        elif limit > 50000:
            logger.warning(f"Large limit {limit} requested, setting safety limit to 50000")
            limit = 50000
        
        fdb_entries = []
        
        # 優先策略：如果有特定篩選條件，使用更有效的方法
        if device_id is not None:
            # Method 1: Device-specific query (最有效)
            try:
                logger.info(f"Using optimized device-specific query for device {device_id}")
                params = {"limit": limit}
                if vlan_id is not None:
                    params["vlan"] = vlan_id
                
                # 嘗試直接的設備 FDB 端點
                device_fdb_result = _api_request("GET", f"devices/{device_id}/fdb", params=params)
                fdb_entries = _extract_data_from_response(device_fdb_result, ['ports_fdb', 'fdb'])
                
                if not fdb_entries:
                    # 回退到埠口方法，但限制埠口數量
                    ports_result = _api_request("GET", f"devices/{device_id}/ports", params={"limit": 20})
                    ports_data = _extract_data_from_response(ports_result, ['ports'])
                    
                    for port in ports_data[:20]:  # 限制最多 20 個埠口
                        port_id = port.get('port_id')
                        if port_id:
                            try:
                                port_params = {"limit": min(limit // len(ports_data), 1000)}
                                if vlan_id is not None:
                                    port_params["vlan"] = vlan_id
                                    
                                port_fdb_result = _api_request("GET", f"ports/{port_id}/fdb", params=port_params)
                                port_fdb_data = _extract_data_from_response(port_fdb_result, ['ports_fdb', 'fdb'])
                                fdb_entries.extend(port_fdb_data)
                                
                                if len(fdb_entries) >= limit:
                                    break
                            except Exception as e:
                                logger.debug(f"Port {port_id} FDB query failed: {e}")
                
                logger.info(f"Device-specific method found {len(fdb_entries)} FDB entries")
                
            except Exception as e:
                logger.warning(f"Device-specific method failed: {e}")
        
        # Method 2: 如果沒有設備篩選，或者設備方法失敗，使用一般端點但加強篩選
        if not fdb_entries:
            endpoints_to_try = ["resources/fdb", "fdb"]
            
            for endpoint in endpoints_to_try:
                try:
                    logger.info(f"Trying optimized FDB endpoint: {endpoint}")
                    params = {"limit": limit}
                    
                    # 伺服器端篩選 (更有效)
                    if vlan_id is not None:
                        params["vlan"] = vlan_id
                    if device_id is not None:
                        params["device_id"] = device_id
                        
                    # 使用修改過的分頁，限制批次大小
                    fdb_result = _paginate_request_optimized(endpoint, params, max_items=limit)
                    
                    if fdb_result:
                        fdb_entries = fdb_result
                        logger.info(f"Successfully got {len(fdb_entries)} entries from {endpoint}")
                        break
                    
                except Exception as e:
                    logger.warning(f"FDB endpoint {endpoint} failed: {e}")
                    continue
        
        # 客戶端篩選 (只在必要時進行)
        if mac_filter and fdb_entries:
            logger.info(f"Applying MAC filter: {mac_filter}")
            original_count = len(fdb_entries)
            try:
                normalized_filter = _normalize_mac_address(mac_filter)
                fdb_entries = [entry for entry in fdb_entries 
                              if normalized_filter in entry.get("mac_address", "")]
            except Exception as e:
                logger.warning(f"MAC normalization failed: {e}, using string filter")
                fdb_entries = [entry for entry in fdb_entries 
                              if mac_filter.lower() in entry.get("mac_address", "").lower()]
            logger.info(f"MAC filter reduced entries from {original_count} to {len(fdb_entries)}")
        
        # 最終限制
        if len(fdb_entries) > limit:
            fdb_entries = fdb_entries[:limit]
        
        # 快速統計計算 (只計算前 1000 筆以提高效能)
        sample_size = min(len(fdb_entries), 1000)
        sample_entries = fdb_entries[:sample_size]
        
        total_entries = len(fdb_entries)
        vlan_counts = {}
        device_counts = {}
        mac_vendors = {}
        
        for entry in sample_entries:
            if not isinstance(entry, dict):
                continue
                
            # VLAN statistics
            vlan = entry.get("vlan_id", "unknown")
            vlan_counts[str(vlan)] = vlan_counts.get(str(vlan), 0) + 1
            
            # Device statistics
            device = entry.get("device_id", "unknown")
            device_counts[str(device)] = device_counts.get(str(device), 0) + 1
            
            # MAC vendor statistics (simplified)
            mac = entry.get("mac_address", "")
            if len(mac) >= 6:
                oui = mac[:6].upper()
                mac_vendors[oui] = mac_vendors.get(oui, 0) + 1
        
        # 只格式化顯示的條目 (提高效能)
        display_limit = min(len(fdb_entries), 500)  # 只格式化前 500 筆
        formatted_entries = []
        
        for i, entry in enumerate(fdb_entries[:display_limit]):
            formatted_entry = entry.copy()
            if "mac_address" in formatted_entry:
                try:
                    formatted_entry["mac_address_formatted"] = _format_mac_address(
                        formatted_entry["mac_address"], "colon"
                    )
                except Exception as e:
                    formatted_entry["mac_address_formatted"] = formatted_entry["mac_address"]
                    
                formatted_entry["created_at_formatted"] = _format_timestamp(
                    formatted_entry.get("created_at", "")
                )
                formatted_entry["updated_at_formatted"] = _format_timestamp(
                    formatted_entry.get("updated_at", "")
                )
            formatted_entries.append(formatted_entry)
        
        # 建立回應
        result = {
            "fdb_entries": formatted_entries,
            "count": total_entries,
            "statistics": {
                "vlan_breakdown": dict(sorted(vlan_counts.items(), key=lambda x: x[1], reverse=True)[:20]),
                "device_breakdown": dict(sorted(device_counts.items(), key=lambda x: x[1], reverse=True)[:20]),
                "top_mac_vendors": dict(sorted(mac_vendors.items(), key=lambda x: x[1], reverse=True)[:10])
            },
            "query_info": {
                "limit_requested": limit,
                "vlan_filter": vlan_id,
                "device_filter": device_id,
                "mac_filter": mac_filter,
                "total_found": total_entries,
                "displayed_entries": len(formatted_entries),
                "statistics_sample_size": sample_size,
                "performance_optimizations": [
                    "Limited batch size",
                    "Server-side filtering when possible",
                    "Reduced formatting overhead",
                    "Sample-based statistics"
                ],
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Error in list_fdb_entries: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def search_fdb_by_mac(mac_address: str, detailed: bool = True) -> str:
    """Search FDB table for specific MAC address with detailed information - FIXED
    
    Args:
        mac_address: MAC address to search for (various formats accepted)
        detailed: Include detailed device and port information (default: True)
        
    Returns:
        JSON string with MAC address location and details
    """
    logger.info(f"Searching FDB for MAC: {mac_address}")
    
    try:
        # Normalize MAC address for API
        try:
            normalized_mac = _normalize_mac_address(mac_address)
            logger.debug(f"Normalized MAC: {normalized_mac}")
        except Exception as e:
            logger.warning(f"MAC normalization failed: {e}, using original format")
            normalized_mac = mac_address
        
        # Try different search methods
        fdb_results = []
        
        # Method 1: Direct FDB search with normalized MAC
        try:
            fdb_result = _api_request("GET", f"resources/fdb/{normalized_mac}")
            fdb_data = _extract_data_from_response(fdb_result, ['ports_fdb'])
            fdb_results.extend(fdb_data)
            logger.debug(f"Direct search found {len(fdb_data)} entries")
        except Exception as e:
            logger.warning(f"Direct FDB search failed: {e}")
        
        # Method 2: Search using mac_filter in list_fdb_entries
        if not fdb_results:
            try:
                logger.info("Trying MAC filter search...")
                filter_result = list_fdb_entries(limit=1000, mac_filter=mac_address)
                filter_data = json.loads(filter_result)
                
                if "fdb_entries" in filter_data:
                    fdb_results.extend(filter_data["fdb_entries"])
                    logger.debug(f"Filter search found {len(filter_data['fdb_entries'])} entries")
                
            except Exception as e:
                logger.warning(f"Filter search failed: {e}")
        
        # Method 3: Try different MAC formats
        if not fdb_results:
            mac_formats = [
                mac_address.replace(":", "").replace("-", "").replace(".", "").lower(),
                mac_address.replace(":", "").replace("-", "").replace(".", "").upper(),
                mac_address.lower(),
                mac_address.upper()
            ]
            
            for mac_format in mac_formats:
                try:
                    endpoint = f"resources/fdb/{mac_format}"
                    search_result = _api_request("GET", endpoint)
                    search_data = _extract_data_from_response(search_result, ['ports_fdb', 'fdb'])
                    if search_data:
                        fdb_results.extend(search_data)
                        logger.debug(f"Format search with {mac_format} found {len(search_data)} entries")
                        break
                except Exception as e:
                    logger.debug(f"Search with format {mac_format} failed: {e}")
        
        # Method 4: Comprehensive search if still no results
        if not fdb_results:
            logger.info("No direct results, trying comprehensive search...")
            try:
                all_fdb_result = list_fdb_entries(limit=0)
                all_fdb_data = json.loads(all_fdb_result)
                
                if "fdb_entries" in all_fdb_data:
                    all_entries = all_fdb_data["fdb_entries"]
                    
                    # Search for MAC in various formats
                    search_terms = [
                        mac_address.lower(),
                        mac_address.upper(),
                        mac_address.replace(":", "").replace("-", "").replace(".", "").lower(),
                        mac_address.replace(":", "").replace("-", "").replace(".", "").upper()
                    ]
                    
                    for entry in all_entries:
                        entry_mac = entry.get("mac_address", "")
                        if any(term in entry_mac.lower() for term in search_terms):
                            fdb_results.append(entry)
                    
                    logger.debug(f"Comprehensive search found {len(fdb_results)} entries")
                
            except Exception as e:
                logger.warning(f"Comprehensive search failed: {e}")
        
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
        
        # Enrich results with additional information
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
            
            # Get device information
            device_id = enriched_entry.get("device_id")
            if device_id and detailed:
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
            if port_id and detailed:
                if port_id not in port_info_cache:
                    try:
                        port_result = _api_request("GET", f"ports/{port_id}")
                        if "port" in port_result and port_result["port"]:
                            port_info_cache[port_id] = port_result["port"][0]
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
        
        # Calculate search statistics
        if enriched_results:
            vlans_found = set(str(entry.get("vlan_id", "")) for entry in enriched_results)
            devices_found = set(str(entry.get("device_id", "")) for entry in enriched_results)
            ports_found = set(str(entry.get("port_id", "")) for entry in enriched_results)
            
            # Determine MAC vendor (OUI lookup)
            try:
                mac_oui = normalized_mac[:6].upper() if len(normalized_mac) >= 6 else ""
            except:
                mac_oui = ""
            
            search_summary = {
                "mac_address_searched": mac_address,
                "mac_address_normalized": normalized_mac,
                "mac_oui": mac_oui,
                "total_entries_found": len(enriched_results),
                "vlans_found": sorted(list(vlans_found)),
                "devices_found": sorted(list(devices_found)),
                "ports_found": sorted(list(ports_found)),
                "search_methods_used": ["direct_fdb_search", "filter_search", "format_search", "comprehensive_search"]
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
            "query_info": {
                "mac_address_input": mac_address,
                "detailed_search": detailed,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Error in search_fdb_by_mac: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def get_device_fdb_table(device_id: int, limit: int = 100) -> str:
    """Get FDB table for a specific device - FIXED
    
    Args:
        device_id: Device ID to get FDB table for
        limit: Maximum number of entries to return (default: 100, 0 = all)
        
    Returns:
        JSON string with device FDB table and statistics
    """
    logger.info(f"Getting FDB table for device {device_id}")
    
    try:
        # Get device information first
        device_result = _api_request("GET", f"devices/{device_id}")
        device_info = None
        
        if "devices" in device_result and device_result["devices"]:
            device_info = device_result["devices"][0]
        
        # Try multiple methods to get FDB data for this device
        fdb_entries = []
        
        # Method 1: Try device-specific FDB endpoint
        try:
            device_fdb_result = _api_request("GET", f"devices/{device_id}/fdb")
            fdb_entries = _extract_data_from_response(device_fdb_result, ['ports_fdb', 'fdb'])
            logger.debug(f"Device FDB endpoint returned {len(fdb_entries)} entries")
        except Exception as e:
            logger.warning(f"Device FDB endpoint failed: {e}")
        
        # Method 2: Try getting ports and then FDB for each port
        if not fdb_entries:
            try:
                logger.info("Trying port-based FDB collection...")
                ports_result = _api_request("GET", f"devices/{device_id}/ports")
                ports_data = _extract_data_from_response(ports_result, ['ports'])
                
                for port in ports_data:
                    port_id = port.get('port_id')
                    if port_id:
                        try:
                            port_fdb_result = _api_request("GET", f"ports/{port_id}/fdb")
                            port_fdb_data = _extract_data_from_response(port_fdb_result, ['ports_fdb', 'fdb'])
                            fdb_entries.extend(port_fdb_data)
                        except Exception as e:
                            logger.debug(f"Port {port_id} FDB failed: {e}")
                
                logger.debug(f"Port-based collection found {len(fdb_entries)} entries")
                
            except Exception as e:
                logger.warning(f"Port-based FDB collection failed: {e}")
        
        # Method 3: Use list_fdb_entries with device filter
        if not fdb_entries:
            try:
                logger.info("Using list_fdb_entries with device filter...")
                filter_result = list_fdb_entries(limit=0, device_id=device_id)
                filter_data = json.loads(filter_result)
                
                if "fdb_entries" in filter_data:
                    fdb_entries = filter_data["fdb_entries"]
                    logger.debug(f"Filter method found {len(fdb_entries)} entries")
                
            except Exception as e:
                logger.warning(f"Filter method failed: {e}")
        
        # Limit results if specified
        if limit > 0:
            fdb_entries = fdb_entries[:limit]
        
        # Calculate statistics
        vlan_counts = {}
        port_counts = {}
        mac_age_analysis = {}
        
        for entry in fdb_entries:
            if not isinstance(entry, dict):
                continue
                
            # VLAN statistics
            vlan = entry.get("vlan_id", "unknown")
            vlan_counts[str(vlan)] = vlan_counts.get(str(vlan), 0) + 1
            
            # Port statistics
            port = entry.get("port_id", "unknown")
            port_counts[str(port)] = port_counts.get(str(port), 0) + 1
            
            # Age analysis
            updated_at = entry.get("updated_at")
            
            if updated_at:
                updated_time = _safe_parse_datetime(updated_at)
                if updated_time:
                    age_hours = (datetime.now() - updated_time).total_seconds() / 3600
                    if age_hours < 1:
                        age_category = "< 1 hour"
                    elif age_hours < 24:
                        age_category = "< 1 day"
                    elif age_hours < 168:  # 7 days
                        age_category = "< 1 week"
                    else:
                        age_category = "> 1 week"
                    
                    mac_age_analysis[age_category] = mac_age_analysis.get(age_category, 0) + 1
        
        # Format entries for display
        formatted_entries = []
        for entry in fdb_entries:
            formatted_entry = entry.copy()
            if "mac_address" in formatted_entry:
                try:
                    formatted_entry["mac_address_formatted"] = _format_mac_address(
                        formatted_entry["mac_address"], "colon"
                    )
                except Exception as e:
                    logger.warning(f"MAC formatting failed: {e}")
                    formatted_entry["mac_address_formatted"] = formatted_entry["mac_address"]
                    
            formatted_entry["created_at_formatted"] = _format_timestamp(
                formatted_entry.get("created_at", "")
            )
            formatted_entry["updated_at_formatted"] = _format_timestamp(
                formatted_entry.get("updated_at", "")
            )
            formatted_entries.append(formatted_entry)
        
        result = {
            "device_info": {
                "device_id": device_id,
                "hostname": device_info.get("hostname") if device_info else "Unknown",
                "sysName": device_info.get("sysName") if device_info else "Unknown",
                "ip": device_info.get("ip") if device_info else "Unknown",
                "type": device_info.get("type") if device_info else "Unknown"
            } if device_info else {"device_id": device_id, "error": "Device not found"},
            "fdb_entries": formatted_entries,
            "count": len(formatted_entries),
            "statistics": {
                "total_mac_addresses": len(formatted_entries),
                "vlan_breakdown": dict(sorted(vlan_counts.items(), key=lambda x: x[1], reverse=True)),
                "port_breakdown": dict(sorted(port_counts.items(), key=lambda x: x[1], reverse=True)),
                "mac_age_analysis": mac_age_analysis
            },
            "query_info": {
                "device_id": device_id,
                "limit_requested": limit,
                "total_found": len(fdb_entries),
                "timestamp": datetime.now().isoformat(),
                "collection_methods": ["device_fdb_endpoint", "port_based_collection", "filter_method"]
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Error in get_device_fdb_table: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def analyze_fdb_statistics(days: int = 7) -> str:
    """Analyze FDB table statistics and patterns - FIXED
    
    Args:
        days: Number of days to analyze (default: 7)
        
    Returns:
        JSON string with comprehensive FDB analysis
    """
    logger.info(f"Analyzing FDB statistics for {days} days")
    
    try:
        # Get comprehensive FDB data using our fixed function
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
        
        # Calculate time window
        end_time = datetime.now()
        start_time = end_time - timedelta(days=days)
        
        # Initialize analysis containers
        device_stats = {}
        vlan_stats = {}
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
            vlan_id = entry.get("vlan_id")
            port_id = entry.get("port_id")
            mac_address = entry.get("mac_address", "")
            updated_at = entry.get("updated_at")
            created_at = entry.get("created_at")
            
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
                if vlan_id:
                    device_stats[device_id]["vlans"].add(vlan_id)
                if port_id:
                    device_stats[device_id]["ports"].add(port_id)
            
            # VLAN statistics
            if vlan_id:
                vlan_stats[vlan_id] = vlan_stats.get(vlan_id, 0) + 1
            
            # Port statistics
            if port_id:
                port_stats[port_id] = port_stats.get(port_id, 0) + 1
            
            # Age analysis
            if updated_at:
                updated_time = _safe_parse_datetime(updated_at)
                if updated_time:
                    age_hours = (end_time - updated_time).total_seconds() / 3600
                    
                    # Check if within analysis window
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
                    # Remove separators for consistent processing
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
        
        # Check for stale entries
        stale_percentage = (stale_entries / max(total_entries, 1)) * 100
        if stale_percentage > 30:
            issues.append(f"High percentage of stale entries: {stale_percentage:.1f}%")
        
        # Check for port concentration
        if port_stats:
            max_port_macs = max(port_stats.values())
            if max_port_macs > 100:
                issues.append(f"Port with excessive MAC addresses: {max_port_macs}")
        
        # Check for VLAN distribution
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
                "vlan_breakdown": dict(sorted(vlan_stats.items(), key=lambda x: x[1], reverse=True)[:20]),
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
                "total_entries_analyzed": total_entries
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Error in analyze_fdb_statistics: {e}")
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
    logger.info("LibreNMS FastMCP Server v3.4 - Enhanced with ARP Table and IP-to-MAC Support")
    logger.info("=" * 80)
    logger.info("NEW in v3.4:")
    logger.info("  ✨ COMPREHENSIVE ARP TABLE MANAGEMENT")
    logger.info("  ✨ IP address to MAC address resolution")
    logger.info("  ✨ MAC address to IP address lookup")
    logger.info("  ✨ Network segment ARP scanning")
    logger.info("  ✨ Enhanced network discovery with ARP integration")
    logger.info("  ✨ Cross-referencing between FDB and ARP tables")
    logger.info("  ✨ Network troubleshooting with layer 2/3 correlation")
    logger.info("=" * 80)
    logger.info("FIXED in v3.3:")
    logger.info("  🔧 FIXED regex pattern in _normalize_mac_address function")
    logger.info("  🔧 FIXED _format_mac_address function regex pattern")
    logger.info("  🔧 Updated FDB endpoints to use correct LibreNMS API paths")
    logger.info("  🔧 Enhanced error handling for FDB operations")
    logger.info("  🔧 Multiple fallback methods for FDB data retrieval")
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
    logger.info("  • get_arp_table_entries() - List ARP entries")
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
