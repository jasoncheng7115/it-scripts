#!/usr/bin/env python3
"""
MCP Server for phpIPAM API – v1.2
===================================================
Author: Jason Cheng (Jason Tools)
Created: 2025-06-28
Modified: 2025-06-29
License: MIT

FastMCP-based phpIPAM integration with comprehensive IP management operations,
advanced search, and network resource tracking.
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

import requests
import urllib3
from mcp.server.fastmcp import FastMCP

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('phpipam')

class Config:
    def __init__(self):
        # All configuration from environment variables only
        base_url = os.getenv("PHPIPAM_URL")
        if not base_url:
            logger.error("PHPIPAM_URL environment variable not set")
            sys.exit(1)
        
        # Remove possible /api suffix
        if base_url.endswith('/api'):
            base_url = base_url[:-4]
        self.BASE_URL = base_url.rstrip('/')
        
        self.TOKEN = os.getenv("PHPIPAM_TOKEN")
        if not self.TOKEN:
            logger.error("PHPIPAM_TOKEN environment variable not set")
            sys.exit(1)
            
        self.APP_ID = os.getenv("PHPIPAM_APP_ID")
        if not self.APP_ID:
            logger.error("PHPIPAM_APP_ID environment variable not set")
            sys.exit(1)
            
        self.CACHE_TTL = int(os.getenv("PHPIPAM_CACHE_TTL", "300"))
        self.TIMEOUT = int(os.getenv("PHPIPAM_TIMEOUT", "10"))
        self.VERIFY_SSL = os.getenv("PHPIPAM_VERIFY_SSL", "false").lower() == "true"
        self.MAX_RETRIES = 3
        self.BATCH_SIZE = 500  # Set batch size to 500 as requested
        
        self.validate()
    
    def validate(self):
        logger.info(f"phpIPAM Base URL: {self.BASE_URL} (without /api)")
        logger.info(f"Full API URL will be: {self.BASE_URL}/api/{self.APP_ID}")
        logger.info(f"App ID: {self.APP_ID}")
        logger.info(f"Cache TTL: {self.CACHE_TTL}s, Timeout: {self.TIMEOUT}s")
        logger.info(f"Batch Size: {self.BATCH_SIZE} records")
        logger.info(f"SSL Verification: {'Enabled' if self.VERIFY_SSL else 'Disabled'}")

config = Config()

# Cache implementation
class SimpleCache:
    def __init__(self, ttl: int = 300):
        self.cache = {}
        self.ttl = ttl
    
    def _generate_key(self, key_data: str) -> str:
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

# Initialize requests session
session = requests.Session()
session.headers.update({
    "token": config.TOKEN,
    "User-Agent": "mcp-phpipam/1.2",
    "Accept": "application/json",
    "Content-Type": "application/json"
})

# Create FastMCP server
mcp = FastMCP("phpIPAM")

# Retry decorator
def retry_on_failure(max_retries: int = 3, delay: float = 1.0):
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
def _api_request(method: str, path: str, params: Optional[Dict[str, Any]] = None,
                 json_body: Optional[Dict[str, Any]] = None, use_cache: bool = True) -> Dict[str, Any]:
    """Execute a request to phpIPAM API with simplified error handling."""
    
    # Build URL exactly like the working example
    url = f"{config.BASE_URL}/api/{config.APP_ID}/{path.lstrip('/')}"
    
    # Generate cache key
    cache_key = f"{method}:{url}:{json.dumps(params or {}, sort_keys=True)}:{json.dumps(json_body or {}, sort_keys=True)}" if use_cache else None
    
    # Check cache first for GET requests
    if cache_key and method.upper() == 'GET':
        cached_result = cache.get(cache_key)
        if cached_result:
            logger.debug(f"Cache hit for {path}")
            return cached_result
    
    # Detailed logging
    logger.info(f"API Request: {method} {url}")
    if params:
        logger.info(f"  Params: {params}")
    
    try:
        # Execute the request
        response = session.request(
            method.upper(), 
            url, 
            params=params, 
            json=json_body, 
            timeout=config.TIMEOUT,
            verify=config.VERIFY_SSL
        )
        
        # Log response details
        logger.info(f"Response Status: {response.status_code}")
        
        # Raise exception for bad HTTP status
        response.raise_for_status()
        
        # Parse JSON response
        response_data = response.json()
        
        # Extract data field like the working example
        if isinstance(response_data, dict) and "data" in response_data:
            result_data = response_data["data"]
        else:
            result_data = response_data
        
        # Cache result for GET requests
        if cache_key and method.upper() == 'GET':
            cache.set(cache_key, result_data)
        
        logger.info(f"API request successful, returned {len(result_data) if isinstance(result_data, list) else 1} items")
        return result_data
        
    except requests.exceptions.RequestException as request_error:
        logger.error(f"API Request Error: {request_error}")
        raise Exception(f"phpIPAM API request failed: {request_error}")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise

def _fetch_all_with_pagination(path: str, limit: int = 0) -> List[Dict[str, Any]]:
    """
    Fetch all records with pagination support.
    First gets total count, then fetches in batches of 500.
    """
    try:
        # First, get total count by fetching first record
        first_batch = _api_request("GET", path, params={"limit": 1}, use_cache=False)
        
        if not isinstance(first_batch, list):
            first_batch = [first_batch] if first_batch else []
        
        if len(first_batch) == 0:
            logger.info(f"No records found for path: {path}")
            return []
        
        # Try to get total count from headers or estimate
        # Since phpIPAM API might not provide total count easily,
        # we'll fetch in batches until we get less than batch_size
        all_records = []
        offset = 0
        batch_size = config.BATCH_SIZE
        
        logger.info(f"Starting batch fetch for {path} with batch size {batch_size}")
        
        while True:
            logger.info(f"Fetching batch: offset {offset}, limit {batch_size}")
            
            batch = _api_request("GET", path, params={
                "offset": offset,
                "limit": batch_size
            })
            
            if not isinstance(batch, list):
                batch = [batch] if batch else []
            
            if len(batch) == 0:
                logger.info(f"No more records found at offset {offset}")
                break
            
            all_records.extend(batch)
            logger.info(f"Fetched {len(batch)} records, total so far: {len(all_records)}")
            
            # If we got less than batch_size, we've reached the end
            if len(batch) < batch_size:
                logger.info(f"Reached end of records (got {len(batch)} < {batch_size})")
                break
            
            offset += batch_size
            
            # Apply user-specified limit if provided
            if limit > 0 and len(all_records) >= limit:
                all_records = all_records[:limit]
                logger.info(f"Applied user limit: returning {len(all_records)} records")
                break
        
        logger.info(f"Total records fetched for {path}: {len(all_records)}")
        return all_records
        
    except Exception as e:
        logger.error(f"Error in batch fetch for {path}: {e}")
        # Fallback to single request
        logger.info("Falling back to single request")
        try:
            result = _api_request("GET", path)
            if not isinstance(result, list):
                result = [result] if result else []
            return result[:limit] if limit > 0 else result
        except Exception as fallback_error:
            logger.error(f"Fallback also failed: {fallback_error}")
            return []

# MCP Tools for Folders
@mcp.tool()
def list_folders(limit: int = 0) -> str:
    """List all folders in phpIPAM with batch fetching"""
    logger.info(f"Listing folders: limit {limit}")
    
    try:
        folders = _fetch_all_with_pagination("folders/", limit)
        
        result = {
            "folders": folders,
            "count": len(folders),
            "query_info": {
                "limit_requested": limit,
                "batch_size_used": config.BATCH_SIZE,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error listing folders: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def get_folder(folder_id: int) -> str:
    """Get specific folder details"""
    logger.info(f"Getting folder details for ID: {folder_id}")
    
    try:
        folder = _api_request("GET", f"folders/{folder_id}/")
        
        result = {
            "folder_id": folder_id,
            "folder": folder,
            "timestamp": datetime.now().isoformat()
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error getting folder: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def list_folder_sections(folder_id: int, limit: int = 0) -> str:
    """List sections within a specific folder with batch fetching"""
    logger.info(f"Listing sections in folder {folder_id}, limit {limit}")
    
    try:
        sections = _fetch_all_with_pagination(f"folders/{folder_id}/sections/", limit)
        
        result = {
            "folder_id": folder_id,
            "sections": sections,
            "count": len(sections),
            "query_info": {
                "limit_requested": limit,
                "batch_size_used": config.BATCH_SIZE,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error listing folder sections: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# MCP Tools for Sections
@mcp.tool()
def list_sections(limit: int = 0) -> str:
    """List all sections in phpIPAM with batch fetching"""
    logger.info(f"Listing sections: limit {limit}")
    
    try:
        sections = _fetch_all_with_pagination("sections/", limit)
        
        result = {
            "sections": sections,
            "count": len(sections),
            "query_info": {
                "limit_requested": limit,
                "batch_size_used": config.BATCH_SIZE,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error listing sections: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def get_section(section_id: int) -> str:
    """Get specific section details"""
    logger.info(f"Getting section details for ID: {section_id}")
    
    try:
        section = _api_request("GET", f"sections/{section_id}/")
        
        result = {
            "section_id": section_id,
            "section": section,
            "timestamp": datetime.now().isoformat()
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error getting section: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def list_section_subnets(section_id: int, limit: int = 0) -> str:
    """List subnets within a specific section with batch fetching"""
    logger.info(f"Listing subnets in section {section_id}, limit {limit}")
    
    try:
        subnets = _fetch_all_with_pagination(f"sections/{section_id}/subnets/", limit)
        
        result = {
            "section_id": section_id,
            "subnets": subnets,
            "count": len(subnets),
            "query_info": {
                "limit_requested": limit,
                "batch_size_used": config.BATCH_SIZE,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error listing section subnets: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# MCP Tools for Subnets
@mcp.tool()
def list_subnets(section_id: Optional[int] = None, limit: int = 0) -> str:
    """List subnets, optionally filtered by section with batch fetching"""
    logger.info(f"Listing subnets: section_id {section_id}, limit {limit}")
    
    try:
        if section_id is not None:
            path = f"sections/{section_id}/subnets/"
        else:
            path = "subnets/"
        
        subnets = _fetch_all_with_pagination(path, limit)
        
        result = {
            "subnets": subnets,
            "count": len(subnets),
            "query_info": {
                "section_id": section_id,
                "limit_requested": limit,
                "batch_size_used": config.BATCH_SIZE,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error listing subnets: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def get_subnet(subnet_id: int) -> str:
    """Get specific subnet details"""
    logger.info(f"Getting subnet details for ID: {subnet_id}")
    
    try:
        subnet = _api_request("GET", f"subnets/{subnet_id}/")
        
        result = {
            "subnet_id": subnet_id,
            "subnet": subnet,
            "timestamp": datetime.now().isoformat()
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error getting subnet: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def get_subnet_usage(subnet_id: int) -> str:
    """Get subnet usage statistics"""
    logger.info(f"Getting subnet usage for ID: {subnet_id}")
    
    try:
        usage = _api_request("GET", f"subnets/{subnet_id}/usage/")
        
        result = {
            "subnet_id": subnet_id,
            "usage": usage,
            "timestamp": datetime.now().isoformat()
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error getting subnet usage: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def search_subnet(subnet: str) -> str:
    """Search for subnets by CIDR or partial match"""
    logger.info(f"Searching subnet: {subnet}")
    
    try:
        search_result = _api_request("GET", f"subnets/search/{subnet}/")
        
        # Ensure response is a list
        if not isinstance(search_result, list):
            search_result = [search_result] if search_result else []
        
        result = {
            "search_term": subnet,
            "subnets": search_result,
            "count": len(search_result),
            "timestamp": datetime.now().isoformat()
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error searching subnet: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def get_free_address(subnet_id: int) -> str:
    """Get the first free IP address in a subnet"""
    logger.info(f"Getting first free address in subnet: {subnet_id}")
    
    try:
        free_address = _api_request("GET", f"subnets/{subnet_id}/first_free/")
        
        result = {
            "subnet_id": subnet_id,
            "free_address": free_address,
            "timestamp": datetime.now().isoformat()
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error getting free address: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def list_subnet_addresses(subnet_id: int, limit: int = 0) -> str:
    """List all addresses in a specific subnet with batch fetching"""
    logger.info(f"Listing addresses in subnet {subnet_id}, limit {limit}")
    
    try:
        addresses = _fetch_all_with_pagination(f"subnets/{subnet_id}/addresses/", limit)
        
        result = {
            "subnet_id": subnet_id,
            "addresses": addresses,
            "count": len(addresses),
            "query_info": {
                "limit_requested": limit,
                "batch_size_used": config.BATCH_SIZE,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error listing subnet addresses: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# MCP Tools for Addresses
@mcp.tool()
def search_ip_address(ip_address: str) -> str:
    """Search for a specific IP address"""
    logger.info(f"Searching IP address: {ip_address}")
    
    try:
        search_result = _api_request("GET", f"addresses/search/{ip_address}/")
        
        # Ensure response is a list
        if not isinstance(search_result, list):
            search_result = [search_result] if search_result else []
        
        result = {
            "ip_address": ip_address,
            "matches": search_result,
            "count": len(search_result),
            "timestamp": datetime.now().isoformat()
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error searching IP address: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def search_hostname(hostname: str) -> str:
    """Search for addresses by hostname"""
    logger.info(f"Searching addresses for hostname: {hostname}")
    
    try:
        search_result = _api_request("GET", f"addresses/search_hostname/{hostname}/")
        
        # Ensure response is a list
        if not isinstance(search_result, list):
            search_result = [search_result] if search_result else []
        
        result = {
            "hostname": hostname,
            "addresses": search_result,
            "count": len(search_result),
            "timestamp": datetime.now().isoformat()
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error searching hostname: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# MCP Tools for VLANs
@mcp.tool()
def list_vlans(limit: int = 0) -> str:
    """List VLANs with batch fetching"""
    logger.info(f"Listing VLANs: limit {limit}")
    
    try:
        vlans = _fetch_all_with_pagination("vlan/", limit)
        
        result = {
            "vlans": vlans,
            "count": len(vlans),
            "query_info": {
                "limit_requested": limit,
                "batch_size_used": config.BATCH_SIZE,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error listing VLANs: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def get_vlan(vlan_id: int) -> str:
    """Get specific VLAN details"""
    logger.info(f"Getting VLAN details for ID: {vlan_id}")
    
    try:
        vlan = _api_request("GET", f"vlan/{vlan_id}/")
        
        result = {
            "vlan_id": vlan_id,
            "vlan": vlan,
            "timestamp": datetime.now().isoformat()
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error getting VLAN: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# MCP Tools for Racks
@mcp.tool()
def list_racks(limit: int = 0) -> str:
    """List all racks in phpIPAM with batch fetching"""
    logger.info(f"Listing racks: limit {limit}")
    
    try:
        racks = _fetch_all_with_pagination("tools/racks/", limit)
        
        result = {
            "racks": racks,
            "count": len(racks),
            "query_info": {
                "limit_requested": limit,
                "batch_size_used": config.BATCH_SIZE,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error listing racks: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def get_rack(rack_id: int) -> str:
    """Get specific rack details with configuration"""
    logger.info(f"Getting rack details for ID: {rack_id}")
    
    try:
        rack = _api_request("GET", f"tools/racks/{rack_id}/")
        
        # Properly parse rack numbering direction
        # Check different possible field names for numbering direction
        numbering_top_down = True  # Default assumption
        
        # Check various possible field names for rack orientation/direction
        if rack.get("hasBack") is not None:
            # hasBack seems to be related to rear mounting support
            has_rear_support = rack.get("hasBack") == "1"
        else:
            has_rear_support = False
        
        # Look for numbering direction fields
        if rack.get("numberDirection") is not None:
            # Possible field name for numbering direction
            numbering_top_down = rack.get("numberDirection") == "0"
        elif rack.get("numbering_direction") is not None:
            numbering_top_down = rack.get("numbering_direction") == "top_to_bottom"
        elif rack.get("orientation") is not None:
            numbering_top_down = rack.get("orientation") == "0"
        
        result = {
            "rack_id": rack_id,
            "rack": rack,
            "configuration": {
                "name": rack.get("name"),
                "size_units": int(rack.get("size", 42)),
                "numbering_direction": "top_to_bottom" if numbering_top_down else "bottom_to_top",
                "first_u_at_top": numbering_top_down,
                "rear_mounting_support": has_rear_support,
                "location": rack.get("location"),
                "description": rack.get("description"),
                "customer": rack.get("customer")
            },
            "raw_fields": {
                "hasBack": rack.get("hasBack"),
                "numberDirection": rack.get("numberDirection"),
                "numbering_direction": rack.get("numbering_direction"),
                "orientation": rack.get("orientation")
            },
            "timestamp": datetime.now().isoformat()
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error getting rack: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def get_rack_devices(rack_id: int) -> str:
    """Get all devices in a specific rack with position information"""
    logger.info(f"Getting devices in rack: {rack_id}")
    
    try:
        devices = _api_request("GET", f"tools/racks/{rack_id}/devices/")
        
        # Ensure response is a list
        if not isinstance(devices, list):
            devices = [devices] if devices else []
        
        # Get rack info for context
        rack_info = _api_request("GET", f"tools/racks/{rack_id}/")
        
        # Determine rack numbering direction
        numbering_top_down = True  # Default
        if rack_info.get("numberDirection") is not None:
            numbering_top_down = rack_info.get("numberDirection") == "0"
        elif rack_info.get("numbering_direction") is not None:
            numbering_top_down = rack_info.get("numbering_direction") == "top_to_bottom"
        elif rack_info.get("orientation") is not None:
            numbering_top_down = rack_info.get("orientation") == "0"
        
        rack_size = int(rack_info.get("size", 42))
        
        # Sort devices by rack position for proper visualization
        # If numbering is top-to-bottom, sort ascending; if bottom-to-top, sort descending
        if numbering_top_down:
            sorted_devices = sorted(devices, key=lambda x: int(x.get("rack_start", 0)))
        else:
            sorted_devices = sorted(devices, key=lambda x: int(x.get("rack_start", 0)), reverse=True)
        
        result = {
            "rack_id": rack_id,
            "rack_info": {
                "name": rack_info.get("name"),
                "size_units": rack_size,
                "numbering_direction": "top_to_bottom" if numbering_top_down else "bottom_to_top",
                "first_u_at_top": numbering_top_down,
                "rear_mounting_support": rack_info.get("hasBack") == "1",
                "location": rack_info.get("location"),
                "customer": rack_info.get("customer")
            },
            "devices": sorted_devices,
            "device_count": len(sorted_devices),
            "timestamp": datetime.now().isoformat()
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error getting rack devices: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def get_rack_layout(rack_id: int) -> str:
    """Get detailed rack layout with visual positioning information"""
    logger.info(f"Getting rack layout for ID: {rack_id}")
    
    try:
        # Get rack configuration
        rack_info = _api_request("GET", f"tools/racks/{rack_id}/")
        
        # Get devices in rack
        devices = _api_request("GET", f"tools/racks/{rack_id}/devices/")
        
        if not isinstance(devices, list):
            devices = [devices] if devices else []
        
        rack_size = int(rack_info.get("size", 42))
        has_rear = rack_info.get("hasBack") == "1"
        
        # Determine rack numbering direction properly
        numbering_top_down = True  # Default
        if rack_info.get("numberDirection") is not None:
            numbering_top_down = rack_info.get("numberDirection") == "0"
        elif rack_info.get("numbering_direction") is not None:
            numbering_top_down = rack_info.get("numbering_direction") == "top_to_bottom"
        elif rack_info.get("orientation") is not None:
            numbering_top_down = rack_info.get("orientation") == "0"
        
        # Initialize rack layout
        layout = {
            "rack_info": {
                "id": rack_id,
                "name": rack_info.get("name"),
                "size_units": rack_size,
                "has_rear_mounting": has_rear,
                "numbering_direction": "top_to_bottom" if numbering_top_down else "bottom_to_top",
                "first_u_at_top": numbering_top_down,
                "location": rack_info.get("location"),
                "description": rack_info.get("description"),
                "customer": rack_info.get("customer")
            },
            "occupied_units": {},
            "free_units": [],
            "devices": [],
            "visual_layout": {}
        }
        
        # Track occupied units
        occupied = set()
        
        # Process each device
        for device in devices:
            start_unit = int(device.get("rack_start", 0))
            device_size = int(device.get("rack_size", 1))
            is_rear = device.get("rack_side") == "1"
            
            # Calculate visual position based on numbering direction
            if numbering_top_down:
                visual_start = start_unit
                visual_end = start_unit + device_size - 1
            else:
                # If bottom-to-top, flip the positions
                visual_start = rack_size - start_unit - device_size + 1
                visual_end = rack_size - start_unit
            
            device_info = {
                "id": device.get("id"),
                "hostname": device.get("hostname"),
                "type": device.get("type"),
                "start_unit": start_unit,  # Logical position in database
                "end_unit": start_unit + device_size - 1,  # Logical end position
                "visual_start_unit": visual_start,  # Visual position for display
                "visual_end_unit": visual_end,  # Visual end position
                "size_units": device_size,
                "side": "rear" if is_rear else "front",
                "description": device.get("description")
            }
            
            layout["devices"].append(device_info)
            
            # Mark logical units as occupied
            for unit in range(start_unit, start_unit + device_size):
                occupied.add(unit)
                layout["occupied_units"][unit] = {
                    "device_id": device.get("id"),
                    "device_name": device.get("hostname"),
                    "side": "rear" if is_rear else "front",
                    "visual_unit": rack_size - unit + 1 if not numbering_top_down else unit
                }
        
        # Calculate free units (logical positions)
        layout["free_units"] = [unit for unit in range(1, rack_size + 1) if unit not in occupied]
        
        # Create visual layout grid for easy visualization
        layout["visual_layout"] = {}
        for visual_unit in range(1, rack_size + 1):
            if numbering_top_down:
                logical_unit = visual_unit
            else:
                logical_unit = rack_size - visual_unit + 1
            
            layout["visual_layout"][visual_unit] = {
                "logical_unit": logical_unit,
                "front_occupied": False,
                "rear_occupied": False,
                "front_device": None,
                "rear_device": None
            }
            
            if logical_unit in occupied:
                for device in layout["devices"]:
                    if device["start_unit"] <= logical_unit <= device["end_unit"]:
                        if device["side"] == "front":
                            layout["visual_layout"][visual_unit]["front_occupied"] = True
                            layout["visual_layout"][visual_unit]["front_device"] = device["hostname"]
                        else:
                            layout["visual_layout"][visual_unit]["rear_occupied"] = True
                            layout["visual_layout"][visual_unit]["rear_device"] = device["hostname"]
        
        layout["utilization"] = {
            "total_units": rack_size,
            "occupied_units": len(occupied),
            "free_units": len(layout["free_units"]),
            "utilization_percentage": round((len(occupied) / rack_size) * 100, 2)
        }
        
        return json.dumps(layout, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error getting rack layout: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# MCP Tools for Devices
@mcp.tool()
def list_devices(limit: int = 0) -> str:
    """List network devices with batch fetching"""
    logger.info(f"Listing devices: limit {limit}")
    
    try:
        devices = _fetch_all_with_pagination("devices/", limit)
        
        result = {
            "devices": devices,
            "count": len(devices),
            "query_info": {
                "limit_requested": limit,
                "batch_size_used": config.BATCH_SIZE,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error listing devices: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def get_device(device_id: int) -> str:
    """Get specific device details"""
    logger.info(f"Getting device details for ID: {device_id}")
    
    try:
        device = _api_request("GET", f"devices/{device_id}/")
        
        result = {
            "device_id": device_id,
            "device": device,
            "timestamp": datetime.now().isoformat()
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error getting device: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def list_devices_with_rack_info(limit: int = 0) -> str:
    """List devices with their rack positioning information using batch fetching"""
    logger.info(f"Listing devices with rack info: limit {limit}")
    
    try:
        devices = _fetch_all_with_pagination("devices/", limit)
        
        # Rack cache for efficiency
        rack_cache = {}
        
        # Enrich devices with rack information
        enriched_devices = []
        for device in devices:
            enriched_device = device.copy()
            
            if device.get("rack"):
                rack_id = int(device["rack"])
                if rack_id not in rack_cache:
                    try:
                        rack_info = _api_request("GET", f"tools/racks/{rack_id}/")
                        rack_cache[rack_id] = rack_info
                    except Exception as e:
                        logger.warning(f"Could not fetch rack {rack_id}: {e}")
                        rack_cache[rack_id] = None
                
                if rack_cache[rack_id]:
                    rack = rack_cache[rack_id]
                    enriched_device["rack_info"] = {
                        "id": rack_id,
                        "name": rack.get("name"),
                        "size_units": rack.get("size"),
                        "has_rear": rack.get("hasBack") == "1",
                        "location": rack.get("location"),
                        "position": {
                            "start_unit": device.get("rack_start"),
                            "size_units": device.get("rack_size"),
                            "side": "rear" if device.get("rack_side") == "1" else "front"
                        }
                    }
            
            enriched_devices.append(enriched_device)
        
        result = {
            "devices": enriched_devices,
            "count": len(enriched_devices),
            "rack_cache_hits": len(rack_cache),
            "query_info": {
                "limit_requested": limit,
                "batch_size_used": config.BATCH_SIZE,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error listing devices with rack info: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# Other MCP Tools
@mcp.tool()
def list_address_tags() -> str:
    """List all address tags"""
    logger.info("Listing address tags")
    
    try:
        tags = _api_request("GET", "addresses/tags/")
        
        # Ensure response is a list
        if not isinstance(tags, list):
            tags = [tags] if tags else []
        
        result = {
            "tags": tags,
            "count": len(tags),
            "timestamp": datetime.now().isoformat()
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error listing address tags: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def list_subnets_with_vlan(section_id: Optional[int] = None, limit: int = 0) -> str:
    """List subnets with VLAN information using batch fetching"""
    logger.info(f"Listing subnets with VLAN info: section_id {section_id}, limit {limit}")
    
    try:
        # Get subnets using batch fetching
        if section_id is not None:
            path = f"sections/{section_id}/subnets/"
        else:
            path = "subnets/"
        
        subnets = _fetch_all_with_pagination(path, limit)
        
        # VLAN cache for efficiency
        vlan_cache = {}
        
        # Enrich with VLAN info
        enriched_subnets = []
        for subnet in subnets:
            enriched_subnet = subnet.copy()
            
            if subnet.get("vlanId"):
                vlan_id = int(subnet["vlanId"])
                if vlan_id not in vlan_cache:
                    try:
                        vlan_info = _api_request("GET", f"vlan/{vlan_id}/")
                        vlan_cache[vlan_id] = vlan_info
                    except Exception as e:
                        logger.warning(f"Could not fetch VLAN {vlan_id}: {e}")
                        vlan_cache[vlan_id] = None
                
                if vlan_cache[vlan_id]:
                    vlan = vlan_cache[vlan_id]
                    enriched_subnet["vlan_info"] = {
                        "number": vlan.get("number"),
                        "name": vlan.get("name"),
                        "description": vlan.get("description")
                    }
            
            enriched_subnets.append(enriched_subnet)
        
        result = {
            "subnets": enriched_subnets,
            "count": len(enriched_subnets),
            "vlan_cache_hits": len(vlan_cache),
            "query_info": {
                "section_id": section_id,
                "limit_requested": limit,
                "batch_size_used": config.BATCH_SIZE,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Error listing subnets with VLAN: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# System Tools
@mcp.tool()
def health_check() -> str:
    """Perform phpIPAM API health check"""
    logger.info("Performing phpIPAM API health check")
    
    try:
        start_time = time.time()
        
        # Test basic API connectivity
        test_result = _api_request("GET", "sections/", use_cache=False)
        api_response_time = time.time() - start_time
        
        # Get cache statistics
        cache_stats = cache.stats()
        
        result = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "api": {
                "response_time_ms": round(api_response_time * 1000, 2),
                "endpoint": f"{config.BASE_URL}/api/{config.APP_ID}",
                "test_result_count": len(test_result) if isinstance(test_result, list) else 1
            },
            "cache": cache_stats,
            "configuration": {
                "timeout": config.TIMEOUT,
                "max_retries": config.MAX_RETRIES,
                "batch_size": config.BATCH_SIZE,
                "ssl_verification": config.VERIFY_SSL
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return json.dumps({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }, indent=2, ensure_ascii=False)

@mcp.tool()
def clear_cache() -> str:
    """Clear the internal cache"""
    logger.info("Clearing cache")
    
    try:
        cache.clear()
        return json.dumps({
            "status": "success",
            "message": "Cache cleared successfully",
            "timestamp": datetime.now().isoformat()
        }, indent=2, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def cache_stats() -> str:
    """Get cache statistics"""
    logger.info("Getting cache stats")
    
    try:
        stats = cache.stats()
        stats["timestamp"] = datetime.now().isoformat()
        return json.dumps(stats, indent=2, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# Main entry point
if __name__ == "__main__":
    logger.info("=" * 80)
    logger.info("phpIPAM FastMCP Server v1.2")
    logger.info("=" * 80)
    logger.info("Configuration Details:")
    logger.info(f"  URL: {config.BASE_URL}")
    logger.info(f"  App ID: {config.APP_ID}")
    logger.info(f"  SSL Verification: {'Enabled' if config.VERIFY_SSL else 'Disabled'}")
    logger.info(f"  Cache TTL: {config.CACHE_TTL}s")
    logger.info(f"  Timeout: {config.TIMEOUT}s")
    logger.info("=" * 80)
    
    mcp.run()
