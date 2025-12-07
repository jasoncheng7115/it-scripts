#!/usr/bin/env python3
"""
MCP server for LibreNMS API – v3.10.2 Emoji-Free Docstrings
===============================================================================
Author: Jason Cheng (Jason Tools) - Enhanced by Claude
Created: 2025-06-24
Updated: 2025-11-22
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

Configuration Methods (Priority: CLI Args > Environment Variables > Defaults):

1. Command Line Arguments (Recommended):
   uvx --with mcp python3 mcp_librenms.py --url "http://192.168.1.68" --token "your_token"

   Available arguments:
   --url, --host         LibreNMS base URL (e.g., http://192.168.1.68)
   --token, --api-token  LibreNMS API token
   --verify-ssl          Verify SSL certificates (true/false, default: true)
   --cache-ttl           Cache TTL in seconds (default: 300)
   --timeout             API timeout in seconds (default: 30)
   --max-retries         Max retries for failed requests (default: 3)
   --batch-size          Batch size for paginated requests (default: 200)

2. Environment Variables:
   LIBRENMS_URL          LibreNMS base URL
   LIBRENMS_TOKEN        LibreNMS API token
   LIBRENMS_VERIFY_SSL   Verify SSL (true/false, default: true)
   LIBRENMS_CACHE_TTL    Cache TTL in seconds (default: 300)
   LIBRENMS_TIMEOUT      API timeout in seconds (default: 30)
   LIBRENMS_MAX_RETRIES  Max retries (default: 3)
   LIBRENMS_BATCH_SIZE   Batch size (default: 200)

3. Mixed Configuration:
   LIBRENMS_URL="http://192.168.1.68" python3 mcp_librenms.py --token "your_token" --cache-ttl 600

Run steps:
chmod +x mcp_librenms.py
python3 mcp_librenms.py --help  # Show all available options
"""
import json
import os
import sys
import time
import argparse
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
    def __init__(self, args=None):
        """Initialize config from command line args (priority) or environment variables (fallback)

        Args:
            args: Parsed argparse.Namespace object with command line arguments
        """
        # Priority: Command line args > Environment variables > Defaults
        if args:
            self.BASE_URL = args.url or os.getenv("LIBRENMS_URL")
            self.TOKEN = args.token or os.getenv("LIBRENMS_TOKEN")
            self.CACHE_TTL = args.cache_ttl if args.cache_ttl is not None else int(os.getenv("LIBRENMS_CACHE_TTL", "300"))
            self.TIMEOUT = args.timeout if args.timeout is not None else int(os.getenv("LIBRENMS_TIMEOUT", "30"))
            self.MAX_RETRIES = args.max_retries if args.max_retries is not None else int(os.getenv("LIBRENMS_MAX_RETRIES", "3"))
            self.BATCH_SIZE = args.batch_size if args.batch_size is not None else int(os.getenv("LIBRENMS_BATCH_SIZE", "200"))
            self.VERIFY_SSL = args.verify_ssl if args.verify_ssl is not None else True
        else:
            # Fallback to environment variables only
            self.BASE_URL = os.getenv("LIBRENMS_URL")
            self.TOKEN = os.getenv("LIBRENMS_TOKEN")
            self.CACHE_TTL = int(os.getenv("LIBRENMS_CACHE_TTL", "300"))
            self.TIMEOUT = int(os.getenv("LIBRENMS_TIMEOUT", "30"))
            self.MAX_RETRIES = int(os.getenv("LIBRENMS_MAX_RETRIES", "3"))
            self.BATCH_SIZE = int(os.getenv("LIBRENMS_BATCH_SIZE", "200"))
            self.VERIFY_SSL = os.getenv("LIBRENMS_VERIFY_SSL", "true").lower() in ("true", "1", "yes")

        self.validate()

    def validate(self):
        if not self.BASE_URL or not self.TOKEN:
            logger.error("LibreNMS URL and API Token are required!")
            logger.error("Provide via command line arguments or environment variables:")
            logger.error("  Command line: --url <URL> --token <TOKEN>")
            logger.error("  Environment:  LIBRENMS_URL=<URL> LIBRENMS_TOKEN=<TOKEN>")
            sys.exit(1)

        # Clean up BASE_URL
        self.BASE_URL = self.BASE_URL.rstrip('/')
        if not self.BASE_URL.endswith('/api/v0'):
            self.BASE_URL += '/api/v0'

        logger.info(f"LibreNMS URL: {self.BASE_URL}")
        logger.info(f"Cache TTL: {self.CACHE_TTL}s, Timeout: {self.TIMEOUT}s")
        logger.info(f"SSL Verification: {self.VERIFY_SSL}")

# Config will be initialized in main() after parsing command line args
config = None

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

# Cache and session will be initialized after config is created
cache = None
session = None

# Create FastMCP server
mcp = FastMCP("LibreNMS")

def initialize_session():
    """Initialize session with config values"""
    global session
    session = requests.Session()
    session.headers.update({
        "X-Auth-Token": config.TOKEN,
        "User-Agent": "mcp-librenms/3.6.2",
        "Accept": "application/json",
        "Content-Type": "application/json"
    })
    session.verify = config.VERIFY_SSL

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

    # Retry logic with exponential backoff
    max_retries = config.MAX_RETRIES if config else 3
    last_exception = None

    for attempt in range(max_retries):
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
            last_exception = e
            if attempt < max_retries - 1:
                wait_time = 1.0 * (2 ** attempt)
                logger.warning(f"API request attempt {attempt + 1} failed: {e}, retrying in {wait_time}s")
                time.sleep(wait_time)
            else:
                logger.error(f"All {max_retries} attempts failed for {method} {url}")

    raise Exception(f"LibreNMS API error: {str(last_exception)}")

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

    [INTENT] USER INTENT MATCHING:
    [YES] Use this when user asks:
       - "What's the MAC address for IP 192.168.1.100?"
       - "Find MAC for this IP"
       - "這個 IP 的 MAC address 是什麼？"
       - "IP 對應的 MAC 是？"
       - "從 IP 找 MAC"

    [NO] DO NOT use when user asks:
       - "Find device/switch for this IP" → use search_fdb_by_mac() after getting MAC
       - "Which port is this IP on?" → use search_fdb_by_mac() after getting MAC
       - "Find IP for this MAC" → use search_mac_to_ip()

    [NOTE] TYPICAL WORKFLOW:
       1. search_ip_to_mac() to get MAC from IP
       2. search_fdb_by_mac() to find device/port location

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
                    sysname = device.get('sysName', hostname)

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
                                        "source_sysName": sysname,
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

    [INTENT] USER INTENT MATCHING:
    [YES] Use this when user asks:
       - "Which switch/device is this MAC on?"
       - "Find port for MAC address aa:bb:cc:dd:ee:ff"
       - "這個 MAC 在哪個交換機？"
       - "MAC 在哪個 port？"
       - "從 MAC 找設備位置"
       - "Where is this device connected?" (after getting MAC from IP)

    [NO] DO NOT use when user asks:
       - "Find MAC for this IP" → use search_ip_to_mac()
       - "Find IP for this MAC" → use search_mac_to_ip()

    [NOTE] TYPICAL WORKFLOW:
       1. (Optional) search_ip_to_mac() to get MAC from IP
       2. search_fdb_by_mac() to find switch/port location
       3. Results show: device_id, hostname, port_id, ifName, VLAN

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
                sysname = device.get('sysName', hostname)

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
                            "hostname": hostname,
                            "sysName": sysname,
                            "method": f"GET /devices/{device_id}/arp",
                            "matching_entries": matching_entries,
                            "vlans_found": [str(entry.get("vlan_id") or entry.get("vlan", "")) for entry in matching_entries if (entry.get("vlan_id") or entry.get("vlan"))]
                        }

                except Exception as e:
                    device_results[hostname] = {"error": str(e), "hostname": hostname, "sysName": sysname}
            
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
                sysname = device.get('sysName', hostname)

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
                                "device_id": device_id,
                                "hostname": hostname,
                                "sysName": sysname
                            }

                except Exception as e:
                    device_arp_vlans[hostname] = {"error": str(e), "hostname": hostname, "sysName": sysname}
            
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
def get_network_arp_table(network_cidr: str, detailed: bool = False, limit: int = 1000) -> str:
    """Get ARP table entries for a specific network segment with CORRECT VLAN mapping

    [WARNING] SAFETY: Default limit is 1000 entries to prevent memory issues.

    Args:
        network_cidr: Network in CIDR format (e.g., "192.168.1.0/24")
        detailed: Include detailed device information (default: False)
        limit: Maximum number of ARP entries to retrieve (default: 1000)

    Returns:
        JSON string with network ARP table and statistics with CORRECT VLAN tags
    """
    logger.info(f"VLAN FIXED: Getting ARP table for network: {network_cidr}, limit={limit}")

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
            all_arp_result = _paginate_request("resources/ip/arp", params={}, max_items=limit)
            
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
                recommendations.insert(0, "[WARNING]  Large FDB table detected - always use filters!")
        
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

    [INTENT] USER INTENT MATCHING:
    [YES] Use this when user asks:
       - "What's the IP for this MAC?"
       - "Find IP address for MAC aa:bb:cc:dd:ee:ff"
       - "這個 MAC 的 IP 是什麼？"
       - "MAC 對應的 IP 是？"
       - "從 MAC 找 IP"
       - "Reverse ARP lookup"

    [NO] DO NOT use when user asks:
       - "Find MAC for this IP" → use search_ip_to_mac()
       - "Find device/switch for this MAC" → use search_fdb_by_mac()

    [NOTE] NOTE:
       - A single MAC can have multiple IPs (common for routers, servers)
       - Results include VLAN information and device context

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
    """List devices ONLY (without ports) - Use get_devices_with_ports() for devices+ports

    [INTENT] USER INTENT MATCHING:
    [YES] Use this when user asks:
       - "Show me all devices"
       - "List all network devices"
       - "給我看所有設備"
       - "Show proxmox devices" (use type_filter="proxmox")
       - "Which devices are down?" (use status="down")
       - "List devices in datacenter1" (use location="datacenter1")
       - "How many devices do we have?"
       - "Get device list by OS/status/location"

    [NO] DO NOT use when user asks:
       - "Get devices and their ports" → use get_devices_with_ports()
       - "Show devices WITH ports" → use get_devices_with_ports()
       - "Query devices then get ports for each" → use get_devices_with_ports()
       - "List proxmox devices and show their ifOperStatus" → use get_devices_with_ports()
       - "For each device, retrieve port information" → use get_devices_with_ports()
       - "Show device details for device 123" → use get_device_info()

    [WARNING] IMPORTANT:
       This function returns ONLY device information (hostname, IP, status, etc.)
       It does NOT return port/interface information.

       If you need BOTH devices AND their ports in one query,
       use get_devices_with_ports() instead!

    [NOTE] FILTERING OPTIONS:
       - status: "up", "down", "disabled"
       - type_filter: "proxmox", "linux", "ios", etc.
       - location: any location string
       - limit: 0 = all devices (default)

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
def get_all_devices(limit: int = 100) -> str:
    """Get devices with optional limit (default: 100 for safety)

    [WARNING] SAFETY: Default limit is 100 devices to prevent memory issues.
    For large deployments, use list_devices() with filters instead.

    Args:
        limit: Maximum number of devices to return (default: 100)
               Set to a higher value if needed, but be cautious with large deployments

    Returns:
        JSON string of devices with complete statistics
    """
    logger.info(f"Getting devices with limit={limit}")

    try:
        # 使用多種方法嘗試獲取所有設備
        all_devices = []

        # 方法 1: 使用改進的分頁
        try:
            devices_paginated = _paginate_request("devices", max_items=limit)
            all_devices.extend(devices_paginated)
            logger.info(f"Method 1 (pagination): Got {len(devices_paginated)} devices")
        except Exception as e:
            logger.warning(f"Pagination method failed: {e}")
        
        # 方法 2: 如果分頁沒有結果，嘗試單次請求（使用指定的 limit）
        if not all_devices:
            try:
                large_request = _api_request("GET", "devices", params={"limit": limit})
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
                "limit_applied": limit,
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

def _normalize_port_status(status_value) -> str:
    """Normalize port operational status to lowercase string

    LibreNMS API may return ifOperStatus as:
    - String: 'up', 'down', 'adminDown', etc.
    - Integer: 1 (up), 2 (down), 3 (testing), etc.
    - None or missing

    Args:
        status_value: Raw ifOperStatus value from API

    Returns:
        Normalized lowercase status string ('up', 'down', 'admindown', 'unknown', etc.)
    """
    if status_value is None:
        return 'unknown'

    # If it's already a string, normalize it
    if isinstance(status_value, str):
        return status_value.lower().strip()

    # If it's an integer, map SNMP ifOperStatus values
    # Per RFC 2863: 1=up, 2=down, 3=testing, 4=unknown, 5=dormant, 6=notPresent, 7=lowerLayerDown
    if isinstance(status_value, int):
        status_map = {
            1: 'up',
            2: 'down',
            3: 'testing',
            4: 'unknown',
            5: 'dormant',
            6: 'notpresent',
            7: 'lowerlayerdown'
        }
        return status_map.get(status_value, 'unknown')

    # Fallback: convert to string
    return str(status_value).lower().strip()


# ═══════════════════════════════════════════════════════════════
# DEVICE TYPE-AWARE LOGIC (v3.10.0)
# ═══════════════════════════════════════════════════════════════

def _get_port_filter_strategy(device_os: str) -> dict:
    """Get device-type-aware port filtering strategy

    Different device types have different SNMP capabilities:
    - Virtual devices (Proxmox, KVM): Often lack ifOperStatus
    - Network devices (Cisco, Juniper): Full SNMP support
    - Linux servers: May have limited ifOperStatus

    Args:
        device_os: Device OS type (e.g., 'proxmox', 'ios', 'linux')

    Returns:
        Dictionary with filtering strategy and recommendations
    """
    device_os_lower = (device_os or "unknown").lower()

    # Strategy database
    strategies = {
        "proxmox": {
            "name": "Proxmox VE (Virtualization)",
            "default_filter": None,  # Don't filter by default
            "primary_status_field": "ifAdminStatus",  # Use admin status if available
            "fallback_filter": "enabled",  # Filter by enabled/disabled
            "confidence": "low",
            "recommendations": [
                "Proxmox devices often lack ifOperStatus data",
                "Use port_status=None to get all ports",
                "Consider filtering by ifAdminStatus or port name patterns"
            ],
            "typical_issues": [
                "ifOperStatus is usually null",
                "Virtual interfaces may not report status correctly",
                "Bridge interfaces (vmbr*) may appear down even when functional"
            ]
        },
        "kvm": {
            "name": "KVM (Kernel-based Virtual Machine)",
            "default_filter": None,
            "primary_status_field": "ifAdminStatus",
            "fallback_filter": "enabled",
            "confidence": "low",
            "recommendations": [
                "KVM hypervisors have similar limitations to Proxmox",
                "Virtual interfaces may not provide reliable status",
                "Focus on ifName patterns for meaningful ports"
            ]
        },
        "linux": {
            "name": "Linux Server",
            "default_filter": "up",
            "primary_status_field": "ifOperStatus",
            "fallback_filter": "ifAdminStatus",
            "confidence": "medium",
            "recommendations": [
                "Most Linux servers provide basic ifOperStatus",
                "Status reliability depends on kernel version and drivers",
                "Physical interfaces usually more reliable than virtual ones"
            ],
            "typical_issues": [
                "Virtual interfaces (docker*, veth*) may have inconsistent status",
                "Some network card drivers don't report status correctly"
            ]
        },
        "ios": {
            "name": "Cisco IOS",
            "default_filter": "up",
            "primary_status_field": "ifOperStatus",
            "fallback_filter": "ifAdminStatus",
            "confidence": "high",
            "recommendations": [
                "Cisco IOS provides full SNMP support",
                "ifOperStatus is highly reliable",
                "Both layer 2 and layer 3 status are accurate"
            ],
            "typical_issues": []
        },
        "iosxe": {
            "name": "Cisco IOS XE",
            "default_filter": "up",
            "primary_status_field": "ifOperStatus",
            "fallback_filter": "ifAdminStatus",
            "confidence": "high",
            "recommendations": [
                "IOS XE has excellent SNMP support",
                "All interface types report accurate status"
            ]
        },
        "nxos": {
            "name": "Cisco NX-OS",
            "default_filter": "up",
            "primary_status_field": "ifOperStatus",
            "confidence": "high",
            "recommendations": [
                "NX-OS provides comprehensive interface monitoring",
                "Datacenter-grade status reporting"
            ]
        },
        "junos": {
            "name": "Juniper Junos",
            "default_filter": "up",
            "primary_status_field": "ifOperStatus",
            "confidence": "high",
            "recommendations": [
                "Junos has excellent SNMP implementation",
                "Logical interfaces (*.unit) also report accurately"
            ]
        },
        "routeros": {
            "name": "MikroTik RouterOS",
            "default_filter": "up",
            "primary_status_field": "ifOperStatus",
            "confidence": "high",
            "recommendations": [
                "RouterOS SNMP is reliable for physical ports",
                "Virtual interfaces (VLAN, bridge) may need careful filtering"
            ]
        },
        "vyos": {
            "name": "VyOS",
            "default_filter": "up",
            "primary_status_field": "ifOperStatus",
            "confidence": "medium",
            "recommendations": [
                "VyOS based on Linux kernel",
                "Physical ports reliable, virtual ports may vary"
            ]
        },
        "pfsense": {
            "name": "pfSense",
            "default_filter": None,
            "primary_status_field": "ifAdminStatus",
            "confidence": "medium",
            "recommendations": [
                "FreeBSD-based, status reporting varies",
                "Virtual VLANs may not report status correctly"
            ]
        },
        "opnsense": {
            "name": "OPNsense",
            "default_filter": None,
            "primary_status_field": "ifAdminStatus",
            "confidence": "medium",
            "recommendations": [
                "Similar to pfSense, FreeBSD-based",
                "Physical interfaces more reliable than VLANs"
            ]
        }
    }

    # Match device OS to strategy
    for os_key, strategy in strategies.items():
        if os_key in device_os_lower:
            return {
                "matched": True,
                "os_key": os_key,
                **strategy
            }

    # Default strategy for unknown devices
    return {
        "matched": False,
        "os_key": "unknown",
        "name": f"Unknown ({device_os or 'N/A'})",
        "default_filter": "up",
        "primary_status_field": "ifOperStatus",
        "fallback_filter": "ifAdminStatus",
        "confidence": "medium",
        "recommendations": [
            f"No specific strategy for '{device_os}'",
            "Using standard SNMP ifOperStatus filtering",
            "If results are unexpected, try port_status=None"
        ],
        "typical_issues": [
            "Unknown device type - results may vary"
        ]
    }

def _evaluate_port_data_quality(ports: list, device_os: str = None) -> dict:
    """Evaluate the quality of port data and provide suggestions

    Args:
        ports: List of port dictionaries
        device_os: Device OS type (e.g., 'proxmox', 'ios')

    Returns:
        Dictionary with quality metrics and suggestions
    """
    if not ports:
        return {
            "confidence": "none",
            "has_ifOperStatus": False,
            "has_ifAdminStatus": False,
            "complete_ports": 0,
            "incomplete_ports": 0,
            "suggestions": ["No ports data available"]
        }

    total_ports = len(ports)
    has_oper_status = 0
    has_admin_status = 0
    has_ifname = 0

    for port in ports:
        if port.get('ifOperStatus') is not None:
            has_oper_status += 1
        if port.get('ifAdminStatus') is not None:
            has_admin_status += 1
        if port.get('ifName'):
            has_ifname += 1

    # Calculate confidence
    if has_oper_status == total_ports:
        confidence = "high"
    elif has_oper_status > total_ports * 0.5:
        confidence = "medium"
    elif has_admin_status > total_ports * 0.5:
        confidence = "medium"
    elif has_ifname > total_ports * 0.8:
        confidence = "low"
    else:
        confidence = "very_low"

    # Generate suggestions
    suggestions = []
    if has_oper_status == 0:
        suggestions.append(f"[WARNING]  設備類型 '{device_os or 'unknown'}' 沒有 ifOperStatus 數據")
        if has_admin_status > 0:
            suggestions.append("[NOTE] 建議使用 ifAdminStatus 判斷 port 狀態")
        else:
            suggestions.append("[NOTE] 建議使用 port_status=None 獲取所有 port，手動篩選")
            suggestions.append("[NOTE] 或使用 debug_port_fields() 查看原始數據")

    if has_oper_status < total_ports and has_oper_status > 0:
        suggestions.append(f"[WARNING]  只有 {has_oper_status}/{total_ports} 個 port 有 ifOperStatus")

    return {
        "confidence": confidence,
        "has_ifOperStatus": has_oper_status > 0,
        "has_ifAdminStatus": has_admin_status > 0,
        "complete_ports": has_oper_status,
        "incomplete_ports": total_ports - has_oper_status,
        "total_ports": total_ports,
        "suggestions": suggestions if suggestions else ["數據質量良好"]
    }


# ───────────────────────── Port Management ─────────────────────────

@mcp.tool()
def debug_port_fields(device_id: int, limit: int = 3) -> str:
    """DEBUG TOOL: Show raw port data structure from LibreNMS API

    Use this to diagnose port filtering issues by showing the actual field names
    and values returned by LibreNMS for a specific device.

    Args:
        device_id: Device ID to inspect
        limit: Number of ports to show (default: 3)

    Returns:
        JSON with raw port data showing all available fields
    """
    logger.info(f"DEBUG: Inspecting raw port data for device {device_id}")

    try:
        # Get device info
        device_result = _api_request("GET", f"devices/{device_id}")
        device_info = device_result.get("devices", [{}])[0] if "devices" in device_result else {}

        # Get ports
        ports_result = _api_request("GET", f"devices/{device_id}/ports")
        all_ports = _extract_data_from_response(ports_result, ['ports'])

        # Show only first N ports with ALL fields
        sample_ports = all_ports[:limit]

        # Analyze available status fields
        status_fields = {}
        for port in all_ports:
            for field in port.keys():
                if 'status' in field.lower() or 'state' in field.lower() or 'oper' in field.lower():
                    if field not in status_fields:
                        status_fields[field] = []
                    value = port.get(field)
                    if value not in status_fields[field]:
                        status_fields[field].append(value)

        result = {
            "device_info": {
                "device_id": device_id,
                "hostname": device_info.get("hostname"),
                "sysName": device_info.get("sysName"),
                "os": device_info.get("os")
            },
            "total_ports": len(all_ports),
            "sample_ports_full_data": sample_ports,
            "status_related_fields_analysis": status_fields,
            "recommendations": [
                "Check 'status_related_fields_analysis' to find the correct status field",
                "If ifOperStatus is null, try ifAdminStatus or other status fields",
                "Some devices (like Proxmox VMs) may not provide SNMP ifOperStatus"
            ],
            "timestamp": datetime.now().isoformat()
        }

        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)

    except Exception as e:
        logger.error(f"Error in debug_port_fields: {e}")
        return json.dumps({"error": str(e), "device_id": device_id}, indent=2, ensure_ascii=False)


@mcp.tool()
def get_device_ports(device_id: int, status_filter: Optional[str] = None) -> str:
    """Get all network ports/interfaces for a specific device

    [INTENT] USER INTENT MATCHING:
    [YES] Use this when user asks:
       - "Show me all ports for device 123"
       - "Which ports are up on this device?"
       - "List the network interfaces"
       - "給我看這台設備的所有 port"

    [NO] DO NOT use when user asks:
       - "Show ports for ALL proxmox devices" → use get_devices_with_ports()
       - "Which devices have down ports?" → use get_devices_with_ports()

    [INFO] DATA QUALITY NOTE:
    - For standard network devices (Cisco, Juniper): ifOperStatus is reliable
    - For virtual devices (Proxmox, KVM): ifOperStatus may be null
    - When ifOperStatus is null, filtering by status may return incomplete results
    - Recommendation: Use status_filter=None for devices with poor SNMP support

    Args:
        device_id: Device ID to get ports for
        status_filter: Filter by port status - 'up', 'down', 'admin_down' (optional)
                      Set to None to get all ports regardless of status

    Returns:
        JSON with:
        - ports: List of port objects
        - statistics: Count by status
        - metadata: Data quality information and suggestions
        - device_info: Device hostname and sysName
    """
    logger.info(f"Getting ports for device {device_id}, status_filter={status_filter}")

    try:
        # Get device info first
        device_result = _api_request("GET", f"devices/{device_id}")
        device_info = None
        device_os = None
        if "devices" in device_result and device_result["devices"]:
            device_info = device_result["devices"][0]
            device_os = device_info.get("os")

        # Get ALL ports from API
        ports_result = _api_request("GET", f"devices/{device_id}/ports")
        all_ports = _extract_data_from_response(ports_result, ['ports'])

        # Evaluate data quality BEFORE filtering
        data_quality = _evaluate_port_data_quality(all_ports, device_os)

        # Simple, honest filtering
        if status_filter and data_quality["has_ifOperStatus"]:
            # Only filter if we have reliable ifOperStatus data
            status_filter_lower = status_filter.lower()
            filtered_ports = []
            for port in all_ports:
                port_status = _normalize_port_status(port.get('ifOperStatus'))

                # Simple exact matching
                if status_filter_lower == 'up' and port_status == 'up':
                    filtered_ports.append(port)
                elif status_filter_lower == 'down' and port_status == 'down':
                    filtered_ports.append(port)
                elif status_filter_lower == 'admin_down' and port_status == 'admindown':
                    filtered_ports.append(port)

            ports_data = filtered_ports
        elif status_filter and not data_quality["has_ifOperStatus"]:
            # No reliable status data - return all non-disabled ports with warning
            logger.warning(f"Device {device_id} has no ifOperStatus, returning all non-disabled ports")
            ports_data = [p for p in all_ports if not p.get('disabled', 0) and not p.get('deleted', 0)]
        else:
            # No filter requested - return all ports
            ports_data = all_ports

        # Calculate statistics
        stats = {'up': 0, 'down': 0, 'admin_down': 0, 'unknown': 0}
        for port in ports_data:
            status = _normalize_port_status(port.get('ifOperStatus'))
            stats[status] = stats.get(status, 0) + 1

        result = {
            "device_id": device_id,
            "device_info": {
                "hostname": device_info.get("hostname") if device_info else "Unknown",
                "sysName": device_info.get("sysName") if device_info else "Unknown",
                "os": device_os,
                "ip": device_info.get("ip") if device_info else "Unknown"
            } if device_info else None,
            "ports": ports_data,
            "statistics": stats,
            "total_ports": len(ports_data),
            "filter_applied": status_filter,
            "metadata": {
                "data_quality": data_quality,
                "filtering_note": "Filtering skipped - no ifOperStatus data" if (status_filter and not data_quality["has_ifOperStatus"]) else None
            },
            "timestamp": datetime.now().isoformat()
        }

        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Error getting device ports: {e}")
        return json.dumps({"error": str(e), "device_id": device_id}, indent=2, ensure_ascii=False)


@mcp.tool()
def get_devices_with_ports(os_filter: Optional[str] = None,
                          device_status: Optional[str] = None,
                          port_status: Optional[str] = None,
                          limit: int = 10) -> str:
    """Get devices and their network ports - ONE-STOP batch query function

    [INTENT] USER INTENT MATCHING:
    [YES] Use this when user asks:
       - "Get proxmox devices with status up, then for each device get ports where ifOperStatus is up"
       - "Query devices with os=proxmox and status=up, then get their ports"
       - "Show me all proxmox devices and their ports"
       - "List devices with their network interfaces"
       - "Which Linux servers have ports?"
       - "給我看 proxmox 的裝置和它們的 port"
       - "用表格呈現裝置的 port 資訊"
       - "I need devices filtered by OS and status, with their ports"
       - "Batch query: devices + ports in one call"

    [NO] DO NOT use when user asks:
       - "Show ports for device 123" → use get_device_ports()
       - "What's the port status for one device?" → use get_device_ports()

    [NOTE] WHY USE THIS FUNCTION:
       This is a ONE-STOP function designed to avoid multiple API calls.
       Instead of calling get_devices() then get_device_ports() for each device,
       this function does it all in ONE call with proper filtering and data quality checks.

    [INFO] DATA QUALITY WARNING:
    - For Proxmox/KVM devices: ifOperStatus is often null
    - Recommendation: Use port_status=None for virtual devices
    - The function will automatically handle missing data and provide suggestions

    [INFO] PARAMETERS GUIDE:
       - os_filter: "proxmox", "linux", "ios", etc.
       - device_status: "up", "down" (filters which devices to include)
       - port_status: "up", "down", None (filters which ports to show)
         [WARNING] Use port_status=None for Proxmox/virtual devices!
       - limit: how many devices to return

    Args:
        os_filter: Filter devices by OS (e.g., "proxmox", "linux", "ios") (optional)
        device_status: Filter devices by status - 'up', 'down' (optional, default: all)
        port_status: Filter ports by status - 'up', 'down', 'admin_down', or None for all ports
                    [WARNING]  Changed default from 'up' to None for better compatibility
        limit: Maximum number of devices to return (default: 10)

    Returns:
        JSON with:
        - devices: List of devices with ports
        - metadata: Data quality per device
        - summary: Statistics
        - optimized_for_table: true
    """
    logger.info(f"Getting devices with ports: os={os_filter}, device_status={device_status}, port_status={port_status}")

    try:
        # Get devices with filtering
        params = {}
        if device_status:
            status_map = {"up": "1", "down": "0"}
            params["status"] = status_map.get(device_status.lower(), device_status)

        # Get all devices first, then filter by OS in code
        devices_result = _api_request("GET", "devices", params={**params, "limit": limit * 2})  # Get more to filter by OS
        devices_data = _extract_data_from_response(devices_result, ['devices'])

        # Filter by OS if specified
        if os_filter:
            devices_data = [d for d in devices_data if os_filter.lower() in d.get('os', '').lower()]

        # Limit after OS filtering
        devices_data = devices_data[:limit]

        # For each device, get ports
        result_devices = []
        total_ports = 0
        port_stats = {'up': 0, 'down': 0, 'admin_down': 0, 'unknown': 0}
        overall_data_quality = []

        for device in devices_data:
            device_id = device.get('device_id')
            device_os = device.get('os')
            if not device_id:
                continue

            try:
                # Get ALL ports for this device
                ports_result = _api_request("GET", f"devices/{device_id}/ports")
                all_ports = _extract_data_from_response(ports_result, ['ports'])

                # Evaluate data quality
                data_quality = _evaluate_port_data_quality(all_ports, device_os)
                overall_data_quality.append(data_quality)

                # Simple, honest filtering
                if port_status and data_quality["has_ifOperStatus"]:
                    # Only filter if we have reliable data
                    status_lower = port_status.lower()
                    filtered_ports = []
                    for port in all_ports:
                        port_op_status = _normalize_port_status(port.get('ifOperStatus'))
                        if status_lower == 'up' and port_op_status == 'up':
                            filtered_ports.append(port)
                        elif status_lower == 'down' and port_op_status == 'down':
                            filtered_ports.append(port)
                        elif status_lower == 'admin_down' and port_op_status == 'admindown':
                            filtered_ports.append(port)
                    ports_data = filtered_ports
                elif port_status and not data_quality["has_ifOperStatus"]:
                    # No reliable data - return all non-disabled ports
                    logger.warning(f"Device {device_id} ({device_os}) has no ifOperStatus, returning all non-disabled ports")
                    ports_data = [p for p in all_ports if not p.get('disabled', 0) and not p.get('deleted', 0)]
                else:
                    # No filter - return all ports
                    ports_data = all_ports

                # Update statistics
                for port in ports_data:
                    total_ports += 1
                    status = _normalize_port_status(port.get('ifOperStatus'))
                    port_stats[status] = port_stats.get(status, 0) + 1

                # Simplify port data for table display
                simple_ports = []
                for port in ports_data:
                    simple_ports.append({
                        'port_id': port.get('port_id'),
                        'ifName': port.get('ifName'),
                        'ifDescr': port.get('ifDescr'),
                        'ifAlias': port.get('ifAlias'),
                        'ifOperStatus': port.get('ifOperStatus'),
                        'ifSpeed': port.get('ifSpeed'),
                        'ifType': port.get('ifType')
                    })

                result_devices.append({
                    'device_id': device_id,
                    'hostname': device.get('hostname'),
                    'sysName': device.get('sysName'),
                    'os': device_os,
                    'status': 'up' if device.get('status') == 1 or device.get('status') == '1' else 'down',
                    'ip': device.get('ip'),
                    'ports': simple_ports,
                    'port_count': len(simple_ports),
                    'data_quality': data_quality
                })

            except Exception as e:
                logger.warning(f"Failed to get ports for device {device_id}: {e}")
                result_devices.append({
                    'device_id': device_id,
                    'hostname': device.get('hostname'),
                    'sysName': device.get('sysName'),
                    'os': device_os,
                    'error': str(e),
                    'ports': [],
                    'port_count': 0
                })

        # Calculate overall data quality
        devices_with_good_data = sum(1 for q in overall_data_quality if q["confidence"] in ["high", "medium"])
        devices_with_poor_data = len(overall_data_quality) - devices_with_good_data

        # Generate suggestions
        suggestions = []
        if devices_with_poor_data > 0:
            suggestions.append(f"[WARNING]  {devices_with_poor_data}/{len(overall_data_quality)} 個設備缺少 ifOperStatus 數據")
            if os_filter and os_filter.lower() in ['proxmox', 'kvm', 'qemu']:
                suggestions.append("[NOTE] 虛擬化設備通常沒有完整的 SNMP 數據，這是正常的")
            suggestions.append("[NOTE] 建議使用 debug_port_fields() 檢查原始數據")

        if devices_with_good_data == len(overall_data_quality):
            suggestions.append("[YES] 所有設備的數據質量良好")

        result = {
            "devices": result_devices,
            "summary": {
                "total_devices": len(result_devices),
                "total_ports": total_ports,
                "port_statistics": port_stats,
                "filters_applied": {
                    "os": os_filter,
                    "device_status": device_status,
                    "port_status": port_status
                }
            },
            "metadata": {
                "overall_data_quality": {
                    "devices_with_good_data": devices_with_good_data,
                    "devices_with_poor_data": devices_with_poor_data
                },
                "suggestions": suggestions
            },
            "optimized_for_table": True,
            "timestamp": datetime.now().isoformat()
        }

        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Error getting devices with ports: {e}")
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
def get_comprehensive_alert_history(days: int = 30, limit: int = 100,
                                  include_resolved: bool = True,
                                  severity: Optional[str] = None) -> str:
    """Get comprehensive alert history with multiple data sources

    [INTENT] USER INTENT MATCHING:
    [YES] Use this when user asks:
       - "Show alert history from last week"
       - "過去一個月的告警記錄"
       - "給我看已解決的告警"
       - "Alert history" or "告警歷史"
       - "How many alerts happened in the past 7 days?"
       - "Show both active and resolved alerts"

    [NO] DO NOT use when user asks:
       - "What alerts are firing NOW?" → use get_recent_alerts()
       - "現在有哪些告警？" → use get_recent_alerts()
       - "Current active alerts" → use get_recent_alerts()

    [NOTE] KEY DIFFERENCE:
       - get_recent_alerts(): ACTIVE alerts only (what's happening now)
       - get_comprehensive_alert_history(): HISTORICAL alerts (what happened in past X days)

    [WARNING] SAFETY: Default limit reduced to 100 for better performance.
    Increase limit parameter if you need more alerts.

    Args:
        days: Number of days to look back (default: 30)
        limit: Maximum number of alerts to return (default: 100, was 1000 in v3.6)
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
    """Get current ACTIVE alerts with device information

    [INTENT] USER INTENT MATCHING:
    [YES] Use this when user asks:
       - "What alerts are firing now?"
       - "Show me current active alerts"
       - "現在有哪些告警？"
       - "目前活躍的 alerts"
       - "當前的警報"

    [NO] DO NOT use when user asks:
       - "Show alerts from last week" → use get_comprehensive_alert_history()
       - "已解決的告警" → use get_comprehensive_alert_history()
       - "Alert history" → use get_comprehensive_alert_history()

    [INFO] CONFIDENCE: High - Returns only currently active alerts
    """
    logger.info(f"Getting recent alerts: limit={limit}, severity={severity}")

    try:
        params = {"limit": limit}
        if severity:
            params["severity"] = severity

        result = _api_request("GET", "alerts", params=params)

        # Ensure we have the right structure
        alerts_data = _extract_data_from_response(result, ['alerts'])

        # Enrich alerts with device information
        device_ids = set()
        for alert in alerts_data:
            device_id = alert.get('device_id')
            if device_id:
                device_ids.add(device_id)

        # Batch fetch device information
        device_info_cache = {}
        if device_ids:
            logger.info(f"Fetching device info for {len(device_ids)} devices")
            for device_id in device_ids:
                try:
                    device_result = _api_request("GET", f"devices/{device_id}")
                    if "devices" in device_result and device_result["devices"]:
                        device_info_cache[device_id] = device_result["devices"][0]
                except Exception as e:
                    logger.warning(f"Failed to fetch device {device_id}: {e}")

        # Add device info to each alert
        for alert in alerts_data:
            device_id = alert.get('device_id')
            if device_id and device_id in device_info_cache:
                device_info = device_info_cache[device_id]
                alert['device_info'] = {
                    'hostname': device_info.get('hostname'),
                    'sysName': device_info.get('sysName'),
                    'display': device_info.get('display') or device_info.get('sysName') or device_info.get('hostname'),
                    'ip': device_info.get('ip'),
                    'type': device_info.get('type'),
                    'location': device_info.get('location')
                }

        formatted_result = {
            "alerts": alerts_data,
            "count": len(alerts_data),
            "query_info": {
                "period_days": days,
                "severity_filter": severity,
                "limit": limit,
                "note": "Shows only current active/open alerts with device information"
            },
            "timestamp": datetime.now().isoformat()
        }

        return json.dumps(formatted_result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Error in get_recent_alerts: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# ═══════════════════════════════════════════════════════════════
# HIGH-LEVEL QUERY FUNCTIONS (v3.9.0)
# ═══════════════════════════════════════════════════════════════

@mcp.tool()
def troubleshoot_ip(ip_address: str) -> str:
    """ Comprehensive IP troubleshooting - One-stop network investigation

    [INTENT] USER INTENT MATCHING:
    [YES] Use this when user asks:
       - "這個 IP 在哪台交換機？"
       - "Find everything about IP 192.168.1.100"
       - "Where is this IP connected?"
       - "幫我找出這個 IP 的完整資訊"
       - "Trace IP to switch port"
       - "IP 在哪個 port？"

    [NO] DO NOT use when user asks:
       - "Just find MAC for this IP" → use search_ip_to_mac()
       - "Just find switch for this MAC" → use search_fdb_by_mac()

    [NOTE] WHAT THIS DOES:
       This is a ONE-STOP investigation that automatically:
       1. Searches ARP table → Finds MAC address
       2. Searches FDB table → Finds switch/port location
       3. Retrieves VLAN information
       4. Gets device details (hostname, sysName, location)
       5. Provides connection path and troubleshooting insights

    [INFO] TYPICAL OUTPUT:
       - IP address and MAC address
       - Connected to: switch hostname, port name
       - VLAN: tag and name
       - Device details: type, location, status
       - Troubleshooting suggestions

    Args:
        ip_address: IP address to investigate (e.g., "192.168.1.100")

    Returns:
        JSON string with comprehensive IP investigation results
    """
    logger.info(f" Starting comprehensive IP troubleshooting for: {ip_address}")

    try:
        investigation = {
            "ip_address": ip_address,
            "timestamp": datetime.now().isoformat(),
            "investigation_steps": []
        }

        # Step 1: Find MAC address from ARP table
        logger.info("Step 1: Searching ARP table for MAC address...")
        investigation["investigation_steps"].append("Step 1: Searching ARP table")

        arp_result = search_ip_to_mac(ip_address, detailed=True, prefer_arp_vlan=True)
        arp_data = json.loads(arp_result)

        if "error" in arp_data:
            investigation["status"] = "failed"
            investigation["failure_point"] = "arp_lookup"
            investigation["error"] = arp_data["error"]
            investigation["suggestions"] = [
                "[NO] IP address not found in ARP table",
                "[NOTE] Possible reasons:",
                "   - Device is offline or not responding",
                "   - IP address is incorrect",
                "   - Device is outside monitored network",
                "   - ARP entry has expired (typical TTL: 5-20 minutes)"
            ]
            return json.dumps(investigation, indent=2, ensure_ascii=False, cls=DateTimeEncoder)

        # Extract MAC address
        arp_entries = arp_data.get("arp_entries", [])
        if not arp_entries:
            investigation["status"] = "not_found"
            investigation["failure_point"] = "arp_lookup"
            investigation["suggestions"] = [
                "[NO] No ARP entry found for this IP",
                "[NOTE] Try:",
                "   - Ping the IP first to populate ARP table",
                "   - Verify IP is in the correct subnet",
                "   - Check if device is online"
            ]
            return json.dumps(investigation, indent=2, ensure_ascii=False, cls=DateTimeEncoder)

        # Use first ARP entry
        arp_entry = arp_entries[0]
        mac_address = arp_entry.get("mac_address")

        investigation["mac_address"] = mac_address
        investigation["arp_info"] = {
            "mac_address": mac_address,
            "context_device_id": arp_entry.get("device_id"),
            "context_port_id": arp_entry.get("port_id"),
            "vlan_info": arp_entry.get("vlan_info", {})
        }
        investigation["investigation_steps"].append(f"[YES] Found MAC: {mac_address}")

        # Step 2: Find switch/port location from FDB table
        logger.info(f"Step 2: Searching FDB table for MAC {mac_address}...")
        investigation["investigation_steps"].append("Step 2: Searching FDB table for device location")

        fdb_result = search_fdb_by_mac(mac_address, detailed=True)
        fdb_data = json.loads(fdb_result)

        if "error" in fdb_data:
            investigation["status"] = "partial"
            investigation["mac_found"] = True
            investigation["switch_found"] = False
            investigation["fdb_error"] = fdb_data["error"]
            investigation["suggestions"] = [
                f"[YES] Found MAC address: {mac_address}",
                "[WARNING] Could not locate switch port in FDB table",
                "[NOTE] Possible reasons:",
                "   - Device is directly connected to a router (not a switch)",
                "   - FDB table hasn't learned this MAC yet",
                "   - Device is on a different network segment"
            ]
            return json.dumps(investigation, indent=2, ensure_ascii=False, cls=DateTimeEncoder)

        fdb_entries = fdb_data.get("fdb_entries", [])
        if not fdb_entries:
            investigation["status"] = "partial"
            investigation["mac_found"] = True
            investigation["switch_found"] = False
            investigation["suggestions"] = [
                f"[YES] Found MAC address: {mac_address}",
                "[WARNING] MAC not found in any switch FDB table",
                "[NOTE] This typically means:",
                "   - Device is connected to a router, not a switch",
                "   - Device is on a virtual/overlay network"
            ]
            return json.dumps(investigation, indent=2, ensure_ascii=False, cls=DateTimeEncoder)

        # Use first FDB entry (most relevant)
        fdb_entry = fdb_entries[0]

        investigation["location"] = {
            "switch_device_id": fdb_entry.get("device_id"),
            "switch_hostname": fdb_entry.get("device_hostname"),
            "switch_sysName": fdb_entry.get("device_sysName"),
            "switch_ip": fdb_entry.get("device_ip"),
            "port_id": fdb_entry.get("port_id"),
            "port_name": fdb_entry.get("ifName"),
            "port_description": fdb_entry.get("ifDescr"),
            "vlan_info": fdb_entry.get("vlan_info", {})
        }
        investigation["investigation_steps"].append(
            f"[YES] Found location: {fdb_entry.get('device_hostname')} port {fdb_entry.get('ifName')}"
        )

        # Step 3: Get detailed device information
        device_id = fdb_entry.get("device_id")
        if device_id:
            logger.info(f"Step 3: Getting device details for device {device_id}...")
            investigation["investigation_steps"].append("Step 3: Retrieving device details")

            try:
                device_result = _api_request("GET", f"devices/{device_id}")
                if "devices" in device_result and device_result["devices"]:
                    device_info = device_result["devices"][0]
                    investigation["switch_details"] = {
                        "hostname": device_info.get("hostname"),
                        "sysName": device_info.get("sysName"),
                        "ip": device_info.get("ip"),
                        "type": device_info.get("type"),
                        "os": device_info.get("os"),
                        "version": device_info.get("version"),
                        "hardware": device_info.get("hardware"),
                        "location": device_info.get("location"),
                        "status": "up" if device_info.get("status") == 1 else "down",
                        "uptime": device_info.get("uptime")
                    }
                    investigation["investigation_steps"].append("[YES] Retrieved switch details")
            except Exception as e:
                logger.warning(f"Could not get device details: {e}")
                investigation["investigation_steps"].append("[WARNING] Could not retrieve full device details")

        # Build final summary
        investigation["status"] = "success"
        investigation["summary"] = {
            "ip_address": ip_address,
            "mac_address": mac_address,
            "connected_to": f"{fdb_entry.get('device_hostname')} ({fdb_entry.get('device_ip')})",
            "port": f"{fdb_entry.get('ifName')} - {fdb_entry.get('ifDescr', 'N/A')}",
            "vlan": fdb_entry.get("vlan_info", {}).get("vlan_tag", "unknown"),
            "vlan_name": fdb_entry.get("vlan_info", {}).get("vlan_name", "N/A")
        }

        investigation["troubleshooting_insights"] = []

        # Add insights based on data
        if fdb_entry.get("vlan_info", {}).get("vlan_tag") == "unknown":
            investigation["troubleshooting_insights"].append(
                "[WARNING] VLAN information unavailable - may need manual verification"
            )

        if len(fdb_entries) > 1:
            investigation["troubleshooting_insights"].append(
                f"ℹ️ MAC found on {len(fdb_entries)} ports (possible port mirroring or MAC flapping)"
            )
            investigation["all_locations"] = [
                {
                    "device": entry.get("device_hostname"),
                    "port": entry.get("ifName")
                } for entry in fdb_entries
            ]

        investigation["troubleshooting_insights"].append(
            "[YES] Investigation complete - Device location identified"
        )

        return json.dumps(investigation, indent=2, ensure_ascii=False, cls=DateTimeEncoder)

    except Exception as e:
        logger.error(f"Error in troubleshoot_ip: {e}")
        return json.dumps({
            "status": "error",
            "ip_address": ip_address,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }, indent=2, ensure_ascii=False)

@mcp.tool()
def network_health_overview(location: Optional[str] = None, device_type: Optional[str] = None) -> str:
    """ Network health overview - Quick network status dashboard

    [INTENT] USER INTENT MATCHING:
    [YES] Use this when user asks:
       - "網路狀況如何？"
       - "Show me network health"
       - "What's the overall network status?"
       - "給我一個總覽"
       - "Are there any problems?"
       - "Network dashboard"
       - "有哪些問題設備？"

    [NO] DO NOT use when user asks:
       - "Show specific device details" → use get_device_info()
       - "List all devices" → use list_devices()
       - "Show current alerts" → use get_recent_alerts()

    [NOTE] WHAT THIS DOES:
       Provides a comprehensive network health dashboard with:
       1. Device statistics (up/down/disabled counts)
       2. Alert summary (critical/warning counts)
       3. Service health statistics
       4. Problem devices list with reasons
       5. Health score and recommendations

    [INFO] TYPICAL OUTPUT:
       - Overall health score (0-100)
       - Device status breakdown
       - Alert severity breakdown
       - Top problem devices
       - Actionable recommendations

    Args:
        location: Filter by location (optional)
        device_type: Filter by device type/OS (optional)

    Returns:
        JSON string with comprehensive network health overview
    """
    logger.info(f" Generating network health overview (location={location}, type={device_type})")

    try:
        health_report = {
            "timestamp": datetime.now().isoformat(),
            "filters": {
                "location": location,
                "device_type": device_type
            },
            "health_score": 0,
            "status": "analyzing"
        }

        # Step 1: Get device statistics
        logger.info("Step 1: Gathering device statistics...")
        devices_result = list_devices(limit=0, location=location, type_filter=device_type)
        devices_data = json.loads(devices_result)

        if "error" in devices_data:
            health_report["status"] = "error"
            health_report["error"] = devices_data["error"]
            return json.dumps(health_report, indent=2, ensure_ascii=False, cls=DateTimeEncoder)

        devices = devices_data.get("devices", [])
        total_devices = len(devices)

        # Calculate device statistics
        device_stats = {
            "total": total_devices,
            "up": 0,
            "down": 0,
            "disabled": 0,
            "unknown": 0
        }

        devices_by_type = {}
        problem_devices = []

        for device in devices:
            if not isinstance(device, dict):
                continue

            # Device status
            status_val = device.get("status")
            if status_val == 1 or status_val == "1":
                device_stats["up"] += 1
            elif status_val == 0 or status_val == "0":
                device_stats["down"] += 1
                problem_devices.append({
                    "device_id": device.get("device_id"),
                    "hostname": device.get("hostname"),
                    "ip": device.get("ip"),
                    "reason": "Device is DOWN",
                    "severity": "critical"
                })
            elif status_val == 2 or status_val == "2":
                device_stats["disabled"] += 1
            else:
                device_stats["unknown"] += 1

            # Device type distribution
            device_os = device.get("os", "unknown")
            devices_by_type[device_os] = devices_by_type.get(device_os, 0) + 1

        health_report["device_statistics"] = device_stats
        health_report["device_type_distribution"] = dict(sorted(
            devices_by_type.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10])  # Top 10 device types

        # Step 2: Get active alerts
        logger.info("Step 2: Gathering active alerts...")
        alerts_result = get_recent_alerts(limit=100)
        alerts_data = json.loads(alerts_result)

        alert_stats = {
            "total_active": 0,
            "critical": 0,
            "warning": 0,
            "info": 0,
            "unknown": 0
        }

        devices_with_alerts = set()

        if "alerts" in alerts_data:
            alerts = alerts_data["alerts"]
            alert_stats["total_active"] = len(alerts)

            for alert in alerts:
                if not isinstance(alert, dict):
                    continue

                severity = str(alert.get("severity", "")).lower()
                device_id = alert.get("device_id")

                if device_id:
                    devices_with_alerts.add(device_id)

                # Count by severity
                if "crit" in severity or severity == "5":
                    alert_stats["critical"] += 1
                elif "warn" in severity or severity == "4":
                    alert_stats["warning"] += 1
                elif "info" in severity:
                    alert_stats["info"] += 1
                else:
                    alert_stats["unknown"] += 1

        health_report["alert_statistics"] = alert_stats
        health_report["devices_with_active_alerts"] = len(devices_with_alerts)

        # Step 3: Calculate health score
        # Health score based on:
        # - 60% device uptime (up vs total)
        # - 40% alert severity (less critical alerts = better)

        if total_devices > 0:
            device_health = (device_stats["up"] / total_devices) * 60
        else:
            device_health = 0

        # Alert health: penalize critical alerts more
        if total_devices > 0:
            alert_penalty = (
                (alert_stats["critical"] * 5) +
                (alert_stats["warning"] * 2) +
                (alert_stats["info"] * 0.5)
            ) / total_devices
            alert_health = max(0, 40 - alert_penalty)
        else:
            alert_health = 40

        health_score = round(device_health + alert_health, 1)
        health_report["health_score"] = health_score

        # Determine overall status
        if health_score >= 90:
            health_report["status"] = "excellent"
            health_report["status_emoji"] = "[YES]"
        elif health_score >= 75:
            health_report["status"] = "good"
            health_report["status_emoji"] = "👍"
        elif health_score >= 50:
            health_report["status"] = "fair"
            health_report["status_emoji"] = "[WARNING]"
        else:
            health_report["status"] = "poor"
            health_report["status_emoji"] = "🔴"

        # Step 4: Build problem devices list
        # Add devices with critical alerts
        for alert in alerts_data.get("alerts", []):
            if not isinstance(alert, dict):
                continue

            severity = str(alert.get("severity", "")).lower()
            if "crit" in severity or severity == "5":
                device_info = alert.get("device_info", {})
                device_id = alert.get("device_id")

                # Avoid duplicates
                if not any(d.get("device_id") == device_id for d in problem_devices):
                    problem_devices.append({
                        "device_id": device_id,
                        "hostname": device_info.get("hostname", alert.get("hostname")),
                        "ip": device_info.get("ip"),
                        "reason": f"Critical alert: {alert.get('rule', alert.get('name', 'Unknown'))}",
                        "severity": "critical"
                    })

        # Sort by severity
        problem_devices.sort(key=lambda x: 0 if x["severity"] == "critical" else 1)

        health_report["problem_devices"] = problem_devices[:10]  # Top 10 problems
        health_report["total_problem_devices"] = len(problem_devices)

        # Step 5: Generate recommendations
        recommendations = []

        if device_stats["down"] > 0:
            recommendations.append(
                f"🔴 URGENT: {device_stats['down']} device(s) are DOWN - investigate immediately"
            )

        if alert_stats["critical"] > 0:
            recommendations.append(
                f"[WARNING] HIGH PRIORITY: {alert_stats['critical']} critical alert(s) require attention"
            )

        if alert_stats["warning"] > 5:
            recommendations.append(
                f"[WARNING] MEDIUM PRIORITY: {alert_stats['warning']} warning alert(s) detected"
            )

        if device_stats["up"] > 0 and total_devices > 0:
            uptime_pct = round((device_stats["up"] / total_devices) * 100, 1)
            recommendations.append(
                f"[YES] Network uptime: {uptime_pct}% ({device_stats['up']}/{total_devices} devices up)"
            )

        if health_score >= 90:
            recommendations.append("🎉 Network health is excellent - no major issues detected")
        elif health_score >= 75:
            recommendations.append("👍 Network health is good - minor issues present")
        elif health_score >= 50:
            recommendations.append("[WARNING] Network health is fair - several issues need attention")
        else:
            recommendations.append("🔴 Network health is poor - immediate action required")

        health_report["recommendations"] = recommendations

        # Summary for quick viewing
        health_report["summary"] = {
            "health_score": health_score,
            "status": health_report["status"],
            "total_devices": total_devices,
            "devices_up": device_stats["up"],
            "devices_down": device_stats["down"],
            "active_alerts": alert_stats["total_active"],
            "critical_alerts": alert_stats["critical"],
            "problem_devices_count": len(problem_devices)
        }

        return json.dumps(health_report, indent=2, ensure_ascii=False, cls=DateTimeEncoder)

    except Exception as e:
        logger.error(f"Error in network_health_overview: {e}")
        return json.dumps({
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }, indent=2, ensure_ascii=False)

@mcp.tool()
def find_device_by_criteria(
    hostname: Optional[str] = None,
    ip_address: Optional[str] = None,
    mac_address: Optional[str] = None,
    location: Optional[str] = None,
    device_type: Optional[str] = None,
    fuzzy_search: bool = True
) -> str:
    """ Smart device finder - Search devices by multiple criteria

    [INTENT] USER INTENT MATCHING:
    [YES] Use this when user asks:
       - "Find device by hostname/IP/MAC"
       - "尋找設備 xyz"
       - "Search for device with IP 192.168.1.x"
       - "哪台設備的 hostname 包含 'router'？"
       - "Find all devices in datacenter1"
       - "Show me proxmox servers"

    [NO] DO NOT use when user asks:
       - "List ALL devices" → use list_devices()
       - "Show device details for device_id 123" → use get_device_info()
       - "Where is IP X.X.X.X?" → use troubleshoot_ip()

    [NOTE] WHAT THIS DOES:
       Smart multi-criteria device search with:
       1. Multiple search criteria (hostname, IP, MAC, location, type)
       2. Fuzzy matching for partial searches
       3. Automatic search across different LibreNMS tables
       4. Ranked results based on match quality
       5. Enriched device information

    [INFO] SEARCH STRATEGIES:
       - hostname: Partial match in hostname/sysName
       - ip_address: Exact or subnet match
       - mac_address: Search via ARP/FDB tables
       - location: Partial match in location field
       - device_type: Match OS/type field
       - fuzzy_search: Enable partial/contains matching

    Args:
        hostname: Device hostname or sysName (partial match)
        ip_address: Device IP address
        mac_address: MAC address (searches ARP/FDB)
        location: Device location
        device_type: Device type/OS
        fuzzy_search: Enable fuzzy/partial matching (default: True)

    Returns:
        JSON string with matching devices and search metadata
    """
    logger.info(f" Smart device search: hostname={hostname}, ip={ip_address}, mac={mac_address}, location={location}, type={device_type}")

    try:
        search_criteria = {
            "hostname": hostname,
            "ip_address": ip_address,
            "mac_address": mac_address,
            "location": location,
            "device_type": device_type,
            "fuzzy_search": fuzzy_search
        }

        # Remove None values
        active_criteria = {k: v for k, v in search_criteria.items() if v is not None and k != "fuzzy_search"}

        if not active_criteria:
            return json.dumps({
                "status": "error",
                "error": "No search criteria provided",
                "hint": "Provide at least one search criterion: hostname, ip_address, mac_address, location, or device_type",
                "timestamp": datetime.now().isoformat()
            }, indent=2, ensure_ascii=False)

        results = {
            "search_criteria": search_criteria,
            "matches": [],
            "search_methods_used": [],
            "timestamp": datetime.now().isoformat()
        }

        candidate_devices = []

        # Strategy 1: Search by MAC address (if provided)
        if mac_address:
            logger.info(f"Strategy 1: Searching by MAC address: {mac_address}")
            results["search_methods_used"].append("mac_address_lookup")

            # Try ARP table first
            try:
                arp_result = search_mac_to_ip(mac_address, detailed=True)
                arp_data = json.loads(arp_result)

                if "arp_entries" in arp_data and arp_data["arp_entries"]:
                    for arp_entry in arp_data["arp_entries"]:
                        device_id = arp_entry.get("device_id")
                        if device_id:
                            candidate_devices.append({
                                "device_id": device_id,
                                "match_method": "arp_table",
                                "confidence": "high",
                                "ip_from_arp": arp_entry.get("ipv4_address")
                            })
            except Exception as e:
                logger.warning(f"ARP search failed: {e}")

            # Try FDB table
            try:
                fdb_result = search_fdb_by_mac(mac_address, detailed=True)
                fdb_data = json.loads(fdb_result)

                if "fdb_entries" in fdb_data and fdb_data["fdb_entries"]:
                    for fdb_entry in fdb_data["fdb_entries"]:
                        device_id = fdb_entry.get("device_id")
                        if device_id:
                            candidate_devices.append({
                                "device_id": device_id,
                                "match_method": "fdb_table",
                                "confidence": "medium",
                                "port_name": fdb_entry.get("ifName")
                            })
            except Exception as e:
                logger.warning(f"FDB search failed: {e}")

        # Strategy 2: Get all devices and filter
        logger.info("Strategy 2: Fetching devices with filters...")
        results["search_methods_used"].append("device_list_filter")

        try:
            devices_result = list_devices(
                limit=0,
                location=location if not fuzzy_search else None,
                type_filter=device_type if not fuzzy_search else None
            )
            devices_data = json.loads(devices_result)

            if "devices" in devices_data:
                all_devices = devices_data["devices"]

                for device in all_devices:
                    if not isinstance(device, dict):
                        continue

                    device_id = device.get("device_id")
                    device_hostname = str(device.get("hostname", "")).lower()
                    device_sysname = str(device.get("sysName", "")).lower()
                    device_ip = device.get("ip", "")
                    device_location = str(device.get("location", "")).lower()
                    device_os = str(device.get("os", "")).lower()

                    match_score = 0
                    match_reasons = []

                    # Hostname matching
                    if hostname:
                        search_hostname = hostname.lower()
                        if fuzzy_search:
                            if search_hostname in device_hostname or search_hostname in device_sysname:
                                match_score += 10
                                match_reasons.append(f"hostname_contains_{hostname}")
                        else:
                            if device_hostname == search_hostname or device_sysname == search_hostname:
                                match_score += 15
                                match_reasons.append(f"hostname_exact_{hostname}")

                    # IP matching
                    if ip_address:
                        if fuzzy_search:
                            if ip_address in device_ip:
                                match_score += 10
                                match_reasons.append(f"ip_contains_{ip_address}")
                        else:
                            if device_ip == ip_address:
                                match_score += 15
                                match_reasons.append(f"ip_exact_{ip_address}")

                    # Location matching
                    if location and not location in search_criteria.get("location", ""):
                        search_location = location.lower()
                        if fuzzy_search:
                            if search_location in device_location:
                                match_score += 5
                                match_reasons.append(f"location_contains_{location}")
                        else:
                            if device_location == search_location:
                                match_score += 10
                                match_reasons.append(f"location_exact_{location}")

                    # Device type matching
                    if device_type and not device_type in search_criteria.get("device_type", ""):
                        search_type = device_type.lower()
                        if fuzzy_search:
                            if search_type in device_os:
                                match_score += 5
                                match_reasons.append(f"type_contains_{device_type}")
                        else:
                            if device_os == search_type:
                                match_score += 10
                                match_reasons.append(f"type_exact_{device_type}")

                    # If device matches any criteria, add to candidates
                    if match_score > 0:
                        candidate_devices.append({
                            "device_id": device_id,
                            "match_method": "device_list",
                            "confidence": "high" if match_score >= 15 else "medium" if match_score >= 10 else "low",
                            "match_score": match_score,
                            "match_reasons": match_reasons
                        })

        except Exception as e:
            logger.error(f"Device list search failed: {e}")

        # Remove duplicates and enrich device information
        seen_device_ids = set()
        enriched_matches = []

        # Sort candidates by match score (if available)
        candidate_devices.sort(key=lambda x: x.get("match_score", 0), reverse=True)

        for candidate in candidate_devices:
            device_id = candidate.get("device_id")

            if device_id in seen_device_ids:
                continue

            seen_device_ids.add(device_id)

            # Get full device information
            try:
                device_result = _api_request("GET", f"devices/{device_id}")
                if "devices" in device_result and device_result["devices"]:
                    device_info = device_result["devices"][0]

                    enriched_match = {
                        "device_id": device_id,
                        "hostname": device_info.get("hostname"),
                        "sysName": device_info.get("sysName"),
                        "ip": device_info.get("ip"),
                        "type": device_info.get("type"),
                        "os": device_info.get("os"),
                        "version": device_info.get("version"),
                        "hardware": device_info.get("hardware"),
                        "location": device_info.get("location"),
                        "status": "up" if device_info.get("status") == 1 else "down" if device_info.get("status") == 0 else "unknown",
                        "uptime": device_info.get("uptime"),
                        "match_metadata": {
                            "method": candidate.get("match_method"),
                            "confidence": candidate.get("confidence"),
                            "score": candidate.get("match_score", 0),
                            "reasons": candidate.get("match_reasons", [])
                        }
                    }

                    enriched_matches.append(enriched_match)

            except Exception as e:
                logger.warning(f"Could not enrich device {device_id}: {e}")

        results["matches"] = enriched_matches
        results["total_matches"] = len(enriched_matches)

        # Add search insights
        if len(enriched_matches) == 0:
            results["status"] = "no_matches"
            results["suggestions"] = [
                "[NO] No devices found matching the criteria",
                "[NOTE] Try:",
                "   - Enable fuzzy_search for partial matching",
                "   - Use broader search criteria",
                "   - Check if search values are correct"
            ]
        elif len(enriched_matches) == 1:
            results["status"] = "exact_match"
            results["suggestions"] = [
                "[YES] Found exactly 1 matching device"
            ]
        else:
            results["status"] = "multiple_matches"
            results["suggestions"] = [
                f"[YES] Found {len(enriched_matches)} matching devices",
                "[NOTE] Results are sorted by match quality (highest first)"
            ]

        return json.dumps(results, indent=2, ensure_ascii=False, cls=DateTimeEncoder)

    except Exception as e:
        logger.error(f"Error in find_device_by_criteria: {e}")
        return json.dumps({
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }, indent=2, ensure_ascii=False)

@mcp.tool()
def get_device_type_info(device_os: str) -> str:
    """ Get device type-specific filtering strategy and recommendations

    [INTENT] USER INTENT MATCHING:
    [YES] Use this when user asks:
       - "How should I query Proxmox devices?"
       - "What's the best way to get ports from Cisco devices?"
       - "為什麼 Proxmox 的 port 查詢結果是空的？"
       - "Show me device type strategy for linux"

    [NO] DO NOT use when user asks:
       - "Get ports for device 123" → use get_device_ports()
       - "List all devices" → use list_devices()

    [NOTE] WHAT THIS DOES:
       Provides device-type-specific information including:
       1. Recommended default port filter strategy
       2. Primary and fallback status fields to use
       3. Known issues and limitations
       4. Confidence level for SNMP data
       5. Best practices for this device type

    [INFO] SUPPORTED DEVICE TYPES:
       - proxmox, kvm (Virtual platforms)
       - linux (Linux servers)
       - ios, iosxe, nxos (Cisco)
       - junos (Juniper)
       - routeros (MikroTik)
       - vyos, pfsense, opnsense (Open source routers/firewalls)

    Args:
        device_os: Device OS type (e.g., "proxmox", "ios", "linux")

    Returns:
        JSON string with device type strategy information
    """
    logger.info(f" Looking up device type strategy for: {device_os}")

    try:
        strategy = _get_port_filter_strategy(device_os)

        result = {
            "device_os": device_os,
            "strategy": strategy,
            "usage_examples": {},
            "timestamp": datetime.now().isoformat()
        }

        # Add specific usage examples based on device type
        if strategy["default_filter"] is None:
            result["usage_examples"] = {
                "recommended": f"get_devices_with_ports(os_filter='{device_os}', port_status=None)",
                "explanation": "Use port_status=None because this device type often lacks ifOperStatus",
                "alternatives": [
                    f"get_device_ports(device_id=123, status_filter=None)",
                    "Filter results manually based on ifName patterns"
                ]
            }
        else:
            result["usage_examples"] = {
                "recommended": f"get_devices_with_ports(os_filter='{device_os}', port_status='up')",
                "explanation": f"This device type has reliable {strategy['primary_status_field']}",
                "alternatives": [
                    f"get_device_ports(device_id=123, status_filter='up')",
                    f"Use status_filter=None to get all ports"
                ]
            }

        # Add summary
        result["summary"] = {
            "device_type": strategy["name"],
            "matched_strategy": strategy["matched"],
            "confidence_level": strategy["confidence"],
            "recommended_filter": strategy["default_filter"] or "None (get all ports)",
            "primary_field": strategy["primary_status_field"],
            "known_issues_count": len(strategy.get("typical_issues", []))
        }

        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)

    except Exception as e:
        logger.error(f"Error in get_device_type_info: {e}")
        return json.dumps({
            "status": "error",
            "device_os": device_os,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }, indent=2, ensure_ascii=False)

@mcp.tool()
def diagnose_device(device_id: int, include_ports: bool = True, include_alerts: bool = True) -> str:
    """ Comprehensive device diagnostics - One-stop device health check

    [INTENT] USER INTENT MATCHING:
    [YES] Use this when user asks:
       - "Diagnose device 123"
       - "Check health of this device"
       - "這台設備有什麼問題？"
       - "為什麼設備 X 不正常？"
       - "Run full diagnostics on device"

    [NO] DO NOT use when user asks:
       - "Just show device info" → use get_device_info()
       - "List all devices" → use list_devices()
       - "Network overview" → use network_health_overview()

    [NOTE] WHAT THIS DOES:
       Comprehensive device diagnostic report including:
       1. Basic device information (hostname, IP, type, status)
       2. Device type-specific strategy and recommendations
       3. Port analysis with data quality assessment
       4. Active alerts and their severity
       5. Health score (0-100)
       6. Actionable recommendations

    [INFO] HEALTH SCORE:
       - 90-100: Excellent [YES]
       - 75-89: Good [YES]
       - 50-74: Fair [WARNING]
       - 0-49: Poor [NO]

    Args:
        device_id: Device ID to diagnose
        include_ports: Include port analysis (default: True)
        include_alerts: Include alert analysis (default: True)

    Returns:
        JSON string with comprehensive diagnostic report
    """
    logger.info(f" Running comprehensive diagnostics for device {device_id}")

    try:
        diagnostic = {
            "device_id": device_id,
            "timestamp": datetime.now().isoformat(),
            "diagnostic_steps": [],
            "health_score": 0,
            "status": "analyzing"
        }

        # Step 1: Get device basic information
        logger.info("Step 1: Fetching device information...")
        diagnostic["diagnostic_steps"].append("Step 1: Fetching basic device information")

        try:
            device_result = _api_request("GET", f"devices/{device_id}")
            if "devices" not in device_result or not device_result["devices"]:
                return json.dumps({
                    "status": "error",
                    "device_id": device_id,
                    "error": "Device not found",
                    "timestamp": datetime.now().isoformat()
                }, indent=2, ensure_ascii=False)

            device_info = device_result["devices"][0]
            diagnostic["device_info"] = {
                "hostname": device_info.get("hostname"),
                "sysName": device_info.get("sysName"),
                "ip": device_info.get("ip"),
                "type": device_info.get("type"),
                "os": device_info.get("os"),
                "version": device_info.get("version"),
                "hardware": device_info.get("hardware"),
                "location": device_info.get("location"),
                "status": "up" if device_info.get("status") == 1 else "down" if device_info.get("status") == 0 else "unknown",
                "status_raw": device_info.get("status"),
                "uptime": device_info.get("uptime"),
                "uptime_short": device_info.get("uptime_short")
            }
            diagnostic["diagnostic_steps"].append("[YES] Device information retrieved")
        except Exception as e:
            diagnostic["status"] = "error"
            diagnostic["error"] = f"Failed to get device info: {str(e)}"
            return json.dumps(diagnostic, indent=2, ensure_ascii=False, cls=DateTimeEncoder)

        # Step 2: Get device type strategy
        device_os = device_info.get("os", "unknown")
        logger.info(f"Step 2: Analyzing device type strategy for '{device_os}'...")
        diagnostic["diagnostic_steps"].append(f"Step 2: Analyzing device type ({device_os})")

        strategy = _get_port_filter_strategy(device_os)
        diagnostic["device_type_strategy"] = {
            "os": device_os,
            "strategy_matched": strategy["matched"],
            "device_type_name": strategy["name"],
            "confidence": strategy["confidence"],
            "recommendations": strategy["recommendations"],
            "typical_issues": strategy.get("typical_issues", [])
        }
        diagnostic["diagnostic_steps"].append(f"[YES] Device type: {strategy['name']}")

        # Step 3: Port analysis (if requested)
        port_health_score = 50  # Default neutral score
        if include_ports:
            logger.info("Step 3: Analyzing ports...")
            diagnostic["diagnostic_steps"].append("Step 3: Analyzing ports")

            try:
                ports_result = _api_request("GET", f"devices/{device_id}/ports")
                all_ports = _extract_data_from_response(ports_result, ['ports'])

                # Filter out ignored/disabled ports
                active_ports = [p for p in all_ports if not p.get('ignore') and not p.get('disabled')]

                # Evaluate port data quality
                quality = _evaluate_port_data_quality(active_ports, device_os)

                # Count port statuses
                port_status_counts = {"up": 0, "down": 0, "unknown": 0, "other": 0}
                for port in active_ports:
                    status = _normalize_port_status(port.get('ifOperStatus'))
                    if status == 'up':
                        port_status_counts["up"] += 1
                    elif status == 'down':
                        port_status_counts["down"] += 1
                    elif status == 'unknown':
                        port_status_counts["unknown"] += 1
                    else:
                        port_status_counts["other"] += 1

                diagnostic["port_analysis"] = {
                    "total_ports": len(all_ports),
                    "active_ports": len(active_ports),
                    "ignored_disabled_ports": len(all_ports) - len(active_ports),
                    "port_status_counts": port_status_counts,
                    "data_quality": quality
                }

                # Calculate port health score
                if len(active_ports) > 0:
                    up_ratio = port_status_counts["up"] / len(active_ports)
                    port_health_score = round(up_ratio * 100, 1)
                else:
                    port_health_score = 100  # No ports = no problems

                diagnostic["diagnostic_steps"].append(f"[YES] Port analysis complete: {len(active_ports)} active ports")
            except Exception as e:
                diagnostic["port_analysis"] = {"error": str(e)}
                diagnostic["diagnostic_steps"].append(f"[WARNING] Port analysis failed: {str(e)}")
                port_health_score = 50  # Neutral score if port analysis fails

        # Step 4: Alert analysis (if requested)
        alert_health_score = 100  # Default perfect score
        if include_alerts:
            logger.info("Step 4: Analyzing alerts...")
            diagnostic["diagnostic_steps"].append("Step 4: Analyzing active alerts")

            try:
                alerts_result = _api_request("GET", "alerts", params={"device_id": device_id})
                alerts = _extract_data_from_response(alerts_result, ['alerts'])

                # Count by severity
                alert_severity_counts = {"critical": 0, "warning": 0, "info": 0, "other": 0}
                for alert in alerts:
                    severity = str(alert.get("severity", "")).lower()
                    if "crit" in severity or severity == "5":
                        alert_severity_counts["critical"] += 1
                    elif "warn" in severity or severity == "4":
                        alert_severity_counts["warning"] += 1
                    elif "info" in severity:
                        alert_severity_counts["info"] += 1
                    else:
                        alert_severity_counts["other"] += 1

                diagnostic["alert_analysis"] = {
                    "total_active_alerts": len(alerts),
                    "severity_counts": alert_severity_counts,
                    "recent_alerts": alerts[:5]  # Top 5 recent alerts
                }

                # Calculate alert health score (penalize critical more)
                alert_penalty = (
                    (alert_severity_counts["critical"] * 30) +
                    (alert_severity_counts["warning"] * 10) +
                    (alert_severity_counts["info"] * 2)
                )
                alert_health_score = max(0, 100 - alert_penalty)

                diagnostic["diagnostic_steps"].append(f"[YES] Alert analysis complete: {len(alerts)} active alerts")
            except Exception as e:
                diagnostic["alert_analysis"] = {"error": str(e)}
                diagnostic["diagnostic_steps"].append(f"[WARNING] Alert analysis failed: {str(e)}")
                alert_health_score = 100  # Assume no alerts if analysis fails

        # Step 5: Calculate overall health score
        device_status_score = 100 if diagnostic["device_info"]["status"] == "up" else 0

        # Weighted average: Device status (40%), Ports (30%), Alerts (30%)
        overall_health = round(
            (device_status_score * 0.4) +
            (port_health_score * 0.3) +
            (alert_health_score * 0.3),
            1
        )

        diagnostic["health_score"] = overall_health

        # Determine overall status
        if overall_health >= 90:
            diagnostic["status"] = "excellent"
            diagnostic["status_emoji"] = "[YES]"
        elif overall_health >= 75:
            diagnostic["status"] = "good"
            diagnostic["status_emoji"] = "👍"
        elif overall_health >= 50:
            diagnostic["status"] = "fair"
            diagnostic["status_emoji"] = "[WARNING]"
        else:
            diagnostic["status"] = "poor"
            diagnostic["status_emoji"] = "🔴"

        # Step 6: Generate recommendations
        recommendations = []

        if diagnostic["device_info"]["status"] == "down":
            recommendations.append("🔴 CRITICAL: Device is DOWN - check physical connectivity and power")

        if include_alerts and diagnostic.get("alert_analysis", {}).get("severity_counts", {}).get("critical", 0) > 0:
            critical_count = diagnostic["alert_analysis"]["severity_counts"]["critical"]
            recommendations.append(f"[WARNING] HIGH PRIORITY: {critical_count} critical alert(s) on this device")

        if include_ports:
            port_analysis = diagnostic.get("port_analysis", {})
            if port_analysis.get("port_status_counts", {}).get("down", 0) > 0:
                down_count = port_analysis["port_status_counts"]["down"]
                recommendations.append(f"[WARNING] ATTENTION: {down_count} port(s) are DOWN")

            data_quality = port_analysis.get("data_quality", {})
            if data_quality.get("confidence") in ["low", "very_low"]:
                recommendations.append(f"[NOTE] Data quality is {data_quality['confidence']} - see device_type_strategy for guidance")

        # Add device-type-specific recommendations
        if not strategy["matched"]:
            recommendations.append(f"ℹ️ Unknown device type '{device_os}' - using default strategy")

        if overall_health >= 90:
            recommendations.append("[YES] Device health is excellent - no issues detected")
        elif overall_health >= 75:
            recommendations.append("👍 Device health is good - minor issues present")
        elif overall_health >= 50:
            recommendations.append("[WARNING] Device health is fair - several issues need attention")
        else:
            recommendations.append("🔴 Device health is poor - immediate action required")

        diagnostic["recommendations"] = recommendations

        # Summary
        diagnostic["summary"] = {
            "device_id": device_id,
            "hostname": diagnostic["device_info"]["hostname"],
            "health_score": overall_health,
            "status": diagnostic["status"],
            "device_up": diagnostic["device_info"]["status"] == "up",
            "active_alerts": diagnostic.get("alert_analysis", {}).get("total_active_alerts", 0) if include_alerts else "not_analyzed",
            "active_ports": diagnostic.get("port_analysis", {}).get("active_ports", 0) if include_ports else "not_analyzed"
        }

        diagnostic["diagnostic_steps"].append("[YES] Diagnostic complete")

        return json.dumps(diagnostic, indent=2, ensure_ascii=False, cls=DateTimeEncoder)

    except Exception as e:
        logger.error(f"Error in diagnose_device: {e}")
        return json.dumps({
            "status": "error",
            "device_id": device_id,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }, indent=2, ensure_ascii=False)

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

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="LibreNMS FastMCP Server v3.10.2 - Emoji-Free Docstrings",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Using command line arguments:
  uvx --with mcp python3 mcp_librenms.py --url "http://192.168.1.68" --token "your_api_token"

  # Using environment variables:
  LIBRENMS_URL="http://192.168.1.68" LIBRENMS_TOKEN="your_token" python3 mcp_librenms.py

  # Mixed (command line takes priority):
  LIBRENMS_URL="http://192.168.1.68" python3 mcp_librenms.py --token "your_token" --cache-ttl 600

Configuration Priority: Command Line Args > Environment Variables > Defaults
        """
    )

    # Connection settings
    parser.add_argument('--url', '--host',
                        dest='url',
                        help='LibreNMS base URL (e.g., http://192.168.1.68 or https://librenms.example.com)')
    parser.add_argument('--token', '--api-token',
                        dest='token',
                        help='LibreNMS API token')

    # SSL/TLS settings
    parser.add_argument('--verify-ssl',
                        type=lambda x: x.lower() in ('true', '1', 'yes'),
                        default=None,
                        help='Verify SSL certificates (true/false, default: true)')

    # Performance settings
    parser.add_argument('--cache-ttl',
                        type=int,
                        default=None,
                        help='Cache TTL in seconds (default: 300)')
    parser.add_argument('--timeout',
                        type=int,
                        default=None,
                        help='API request timeout in seconds (default: 30)')
    parser.add_argument('--max-retries',
                        type=int,
                        default=None,
                        help='Maximum number of retries for failed requests (default: 3)')
    parser.add_argument('--batch-size',
                        type=int,
                        default=None,
                        help='Batch size for paginated requests (default: 200)')

    return parser.parse_args()

if __name__ == "__main__":
    # Parse command line arguments
    args = parse_arguments()

    # Initialize configuration with command line args
    config = Config(args)

    # Initialize cache and session with config values
    cache = SimpleCache(config.CACHE_TTL)
    initialize_session()

    # Display startup information
    logger.info("=" * 80)
    logger.info("LibreNMS FastMCP Server v3.10.2 - Emoji-Free Docstrings")
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
    logger.info("  ✓ Command line argument support (NEW)")
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
    logger.info(f"SSL Verification: {config.VERIFY_SSL}")
    logger.info("=" * 80)

    mcp.run()
