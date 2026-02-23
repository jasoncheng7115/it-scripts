#!/usr/bin/env python3
"""
MCP server for Wazuh SIEM API - v1.2.0
===============================================================================
Author: Jason Cheng (co-created with Claude Code)
Created: 2025-01-23
License: MIT

Reference:
This implementation is inspired by and references the design patterns from:
- mcp-server-wazuh (Rust implementation) by Gianluca Brigandi
  Repository: https://github.com/gbrigandi/mcp-server-wazuh
- mcp_librenms_sample.py architecture by Jason Cheng

FastMCP-based Wazuh SIEM integration providing comprehensive security monitoring
and analysis capabilities through natural language interactions.

Features:
- Real-time security alert monitoring and analysis
- Comprehensive vulnerability assessment across all agents
- Agent lifecycle management and health monitoring
- Security rule configuration and compliance tracking
- Detailed system statistics and performance insights
- Advanced log analysis and forensic capabilities
- Cluster health monitoring and node management
- Multi-framework compliance support (GDPR, HIPAA, PCI DSS, NIST)

Installation:
pip install mcp requests urllib3

Configuration Methods (Priority: CLI Args > Environment Variables > Defaults):

1. Command Line Arguments (Recommended):
   python3 mcp_wazuh.py \\
     --manager-host "192.168.1.100" \\
     --manager-user "wazuh" \\
     --manager-pass "wazuh" \\
     --indexer-host "192.168.1.100" \\
     --indexer-user "admin" \\
     --indexer-pass "admin"

   Available arguments:
   --manager-host          Wazuh Manager API hostname/IP
   --manager-port          Wazuh Manager API port (default: 55000)
   --manager-user          Wazuh Manager API username
   --manager-pass          Wazuh Manager API password
   --indexer-host          Wazuh Indexer hostname/IP
   --indexer-port          Wazuh Indexer port (default: 9200)
   --indexer-user          Wazuh Indexer username
   --indexer-pass          Wazuh Indexer password
   --use-ssl               Enable SSL/TLS (true/false, default: false)
   --protocol              Connection protocol (http/https, default: https)
   --cache-duration        Cache duration in seconds (default: 300)
   --request-timeout       Request timeout in seconds (default: 30)
   --retry-attempts        Retry attempts for failed requests (default: 3)
   --transport             MCP transport: stdio or streamable-http (default: stdio)
   --host                  HTTP server host for streamable-http (default: 0.0.0.0)
   --port                  HTTP server port for streamable-http (default: 8000)

2. Environment Variables:
   WAZUH_API_HOST          Manager hostname
   WAZUH_API_PORT          Manager port
   WAZUH_API_USERNAME      Manager username
   WAZUH_API_PASSWORD      Manager password
   WAZUH_INDEXER_HOST      Indexer hostname
   WAZUH_INDEXER_PORT      Indexer port
   WAZUH_INDEXER_USERNAME  Indexer username
   WAZUH_INDEXER_PASSWORD  Indexer password
   WAZUH_VERIFY_SSL        Enable SSL verification
   WAZUH_TEST_PROTOCOL     Connection protocol
   WAZUH_CACHE_TTL         Cache TTL
   WAZUH_TIMEOUT           Request timeout
   WAZUH_MAX_RETRIES       Retry attempts

Usage:
chmod +x mcp_wazuh.py

# stdio mode (default, for Claude Desktop / CLI integration):
python3 mcp_wazuh.py --manager-host ... --indexer-host ...

# streamable-http mode (for network-based / multi-client access):
python3 mcp_wazuh.py --transport streamable-http --host 0.0.0.0 --port 8000 \
  --manager-host ... --indexer-host ...

python3 mcp_wazuh.py --help

Changelog:
  v1.2.0 - Token optimization
    - Added _compact_json() helper: compact JSON output + strip None values (~30-40% token saving)
    - Trimmed all tool docstrings for 120B model compatibility
    - Removed redundant tools: get_wazuh_critical_vulnerabilities
      (use get_wazuh_vulnerability_summary with severity_filter="Critical")
      and get_wazuh_manager_error_logs
      (use search_wazuh_manager_logs with level_filter="error")
    - Deduplicated aggregation query in get_wazuh_agents_with_alerts
    - 19 tools → 17 tools
  v1.1.0 - Transport support
    - Added --transport flag: stdio (default) and streamable-http
    - Added --host / --port flags for streamable-http mode
  v1.0.0 - Initial release
    - 19 MCP tools covering alerts, vulnerabilities, agents, rules, logs, cluster, cache
    - Dual API architecture: Manager (JWT) + Indexer (Basic Auth)
    - In-memory TTL cache, exponential backoff retry, module-level arg parsing
"""

import json
import os
import sys
import time
import argparse
import base64
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from functools import wraps
import logging
import hashlib
import urllib3

import requests
from mcp.server.fastmcp import FastMCP

# Suppress SSL warnings when verification is disabled
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('wazuh-mcp-server')

# ═══════════════════════ Configuration Management ═══════════════════════

class WazuhConfig:
    """Configuration manager for Wazuh MCP Server with CLI and environment variable support"""

    def __init__(self, cli_args=None):
        """Initialize configuration with priority: CLI > ENV > Defaults"""
        # Manager configuration
        self.manager_host = self._get_value(cli_args, 'manager_host', 'WAZUH_API_HOST')
        self.manager_port = self._get_int_value(cli_args, 'manager_port', 'WAZUH_API_PORT', 55000)
        self.manager_user = self._get_value(cli_args, 'manager_user', 'WAZUH_API_USERNAME')
        self.manager_pass = self._get_value(cli_args, 'manager_pass', 'WAZUH_API_PASSWORD')

        # Indexer configuration
        self.indexer_host = self._get_value(cli_args, 'indexer_host', 'WAZUH_INDEXER_HOST')
        self.indexer_port = self._get_int_value(cli_args, 'indexer_port', 'WAZUH_INDEXER_PORT', 9200)
        self.indexer_user = self._get_value(cli_args, 'indexer_user', 'WAZUH_INDEXER_USERNAME')
        self.indexer_pass = self._get_value(cli_args, 'indexer_pass', 'WAZUH_INDEXER_PASSWORD')

        # Connection settings
        self.use_ssl = self._get_bool_value(cli_args, 'use_ssl', 'WAZUH_VERIFY_SSL', False)
        self.protocol = self._get_value(cli_args, 'protocol', 'WAZUH_TEST_PROTOCOL', 'https')

        # Performance settings
        self.cache_duration = self._get_int_value(cli_args, 'cache_duration', 'WAZUH_CACHE_TTL', 300)
        self.request_timeout = self._get_int_value(cli_args, 'request_timeout', 'WAZUH_TIMEOUT', 30)
        self.retry_attempts = self._get_int_value(cli_args, 'retry_attempts', 'WAZUH_MAX_RETRIES', 3)

        self._validate_config()

    def _get_value(self, cli_args, cli_attr, env_var, default=None):
        """Get configuration value with priority: CLI > ENV > Default"""
        if cli_args and hasattr(cli_args, cli_attr):
            value = getattr(cli_args, cli_attr)
            if value is not None:
                return value
        return os.getenv(env_var, default)

    def _get_int_value(self, cli_args, cli_attr, env_var, default):
        """Get integer configuration value"""
        value = self._get_value(cli_args, cli_attr, env_var)
        return int(value) if value is not None else default

    def _get_bool_value(self, cli_args, cli_attr, env_var, default):
        """Get boolean configuration value"""
        value = self._get_value(cli_args, cli_attr, env_var)
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        return str(value).lower() in ('true', '1', 'yes', 'on')

    def _validate_config(self):
        """Validate required configuration parameters"""
        errors = []

        if not all([self.manager_host, self.manager_user, self.manager_pass]):
            errors.append("Manager configuration incomplete (host, username, password required)")

        if not all([self.indexer_host, self.indexer_user, self.indexer_pass]):
            errors.append("Indexer configuration incomplete (host, username, password required)")

        if errors:
            logger.error("Configuration validation failed:")
            for error in errors:
                logger.error(f"  - {error}")
            logger.error("\nProvide configuration via:")
            logger.error("  CLI: --manager-host <HOST> --manager-user <USER> --manager-pass <PASS>")
            logger.error("  ENV: WAZUH_API_HOST=<HOST> WAZUH_API_USERNAME=<USER> WAZUH_API_PASSWORD=<PASS> ...")
            sys.exit(1)

        logger.info(f"Manager: {self.protocol}://{self.manager_host}:{self.manager_port}")
        logger.info(f"Indexer: {self.protocol}://{self.indexer_host}:{self.indexer_port}")
        logger.info(f"Cache: {self.cache_duration}s | Timeout: {self.request_timeout}s | SSL: {self.use_ssl}")

# Global configuration instance
# Parse CLI arguments at module level (for uvx/mcpo compatibility)
_cli_args = None
if len(sys.argv) > 1:  # If arguments provided, parse them
    def _parse_args():
        parser = argparse.ArgumentParser(add_help=False)  # Disable default help to avoid conflicts
        parser.add_argument('--manager-host', help='Manager hostname or IP')
        parser.add_argument('--manager-port', type=int, help='Manager port')
        parser.add_argument('--manager-user', help='Manager username')
        parser.add_argument('--manager-pass', help='Manager password')
        parser.add_argument('--indexer-host', help='Indexer hostname or IP')
        parser.add_argument('--indexer-port', type=int, help='Indexer port')
        parser.add_argument('--indexer-user', help='Indexer username')
        parser.add_argument('--indexer-pass', help='Indexer password')
        parser.add_argument('--use-ssl', type=lambda x: x.lower() in ('true', '1', 'yes'), help='Enable SSL verification')
        parser.add_argument('--protocol', choices=['http', 'https'], help='Connection protocol')
        parser.add_argument('--cache-duration', type=int, help='Cache duration in seconds')
        parser.add_argument('--request-timeout', type=int, help='Request timeout in seconds')
        parser.add_argument('--retry-attempts', type=int, help='Retry attempts')
        parser.add_argument('--transport', choices=['stdio', 'streamable-http'], default='stdio', help='MCP transport type')
        parser.add_argument('--host', default='0.0.0.0', help='HTTP server host (for streamable-http)')
        parser.add_argument('--port', type=int, default=8000, help='HTTP server port (for streamable-http)')
        args, _ = parser.parse_known_args()  # Use parse_known_args to ignore unknown arguments
        return args
    _cli_args = _parse_args()

wazuh_config = WazuhConfig(cli_args=_cli_args)

# ═══════════════════════ JSON Serialization ═══════════════════════

class DateTimeJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder for datetime objects"""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

def _strip_none(obj):
    """Recursively remove keys with None values from dicts"""
    if isinstance(obj, dict):
        return {k: _strip_none(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_strip_none(i) for i in obj]
    return obj

def _compact_json(data: dict) -> str:
    """Serialize to compact JSON, stripping None values"""
    return json.dumps(_strip_none(data), ensure_ascii=False, cls=DateTimeJSONEncoder, separators=(',',':'))

# ═══════════════════════ Caching System ═══════════════════════

class MemoryCache:
    """Simple in-memory cache with TTL support"""

    def __init__(self, ttl_seconds: int = 300):
        self._storage = {}
        self._ttl = ttl_seconds

    def _compute_key(self, key_string: str) -> str:
        """Generate MD5 hash for cache key"""
        return hashlib.md5(key_string.encode('utf-8')).hexdigest()

    def retrieve(self, key: str) -> Optional[Any]:
        """Retrieve value from cache if not expired"""
        hashed_key = self._compute_key(key)
        if hashed_key in self._storage:
            cached_value, cached_time = self._storage[hashed_key]
            if time.time() - cached_time < self._ttl:
                return cached_value
            del self._storage[hashed_key]
        return None

    def store(self, key: str, value: Any):
        """Store value in cache with current timestamp"""
        hashed_key = self._compute_key(key)
        self._storage[hashed_key] = (value, time.time())

    def invalidate_all(self):
        """Clear all cached entries"""
        self._storage.clear()

    def get_statistics(self) -> Dict[str, int]:
        """Get cache statistics"""
        current_ts = time.time()
        valid_entries = sum(
            1 for _, ts in self._storage.values()
            if current_ts - ts < self._ttl
        )
        return {
            "total_entries": len(self._storage),
            "valid_entries": valid_entries,
            "ttl_seconds": self._ttl
        }

# Global cache instance (will be initialized after config)
memory_cache = None

# ═══════════════════════ HTTP Session Management ═══════════════════════

# Global session instances (will be initialized after config)
manager_http_session = None
indexer_http_session = None
manager_jwt_token = None
manager_token_expiry = None

def get_manager_jwt_token() -> str:
    """Obtain JWT token from Wazuh Manager API"""
    global manager_jwt_token, manager_token_expiry

    # Check if we have a valid token
    if manager_jwt_token and manager_token_expiry:
        if datetime.now() < manager_token_expiry:
            return manager_jwt_token

    # Get new token
    auth_url = f"{wazuh_config.protocol}://{wazuh_config.manager_host}:{wazuh_config.manager_port}/security/user/authenticate"
    auth_string = f"{wazuh_config.manager_user}:{wazuh_config.manager_pass}"
    encoded_auth = base64.b64encode(auth_string.encode()).decode()

    try:
        response = requests.get(
            auth_url,
            headers={
                "Authorization": f"Basic {encoded_auth}",
                "Content-Type": "application/json"
            },
            verify=wazuh_config.use_ssl,
            timeout=wazuh_config.request_timeout
        )
        response.raise_for_status()

        token_data = response.json()
        manager_jwt_token = token_data.get("data", {}).get("token")

        if not manager_jwt_token:
            raise Exception("No token in authentication response")

        # Token expires in 15 minutes, refresh 1 minute before
        manager_token_expiry = datetime.now() + timedelta(minutes=14)

        logger.debug("Successfully obtained JWT token")
        return manager_jwt_token

    except Exception as e:
        logger.error(f"Failed to obtain JWT token: {e}")
        raise Exception(f"Authentication failed: {str(e)}")

def setup_http_sessions():
    """Initialize HTTP sessions for Manager and Indexer"""
    global manager_http_session, indexer_http_session

    # Manager session (JWT token will be added on each request)
    manager_http_session = requests.Session()
    manager_http_session.headers.update({
        "Content-Type": "application/json",
        "User-Agent": "wazuh-mcp-server/1.2.0"
    })
    manager_http_session.verify = wazuh_config.use_ssl

    # Indexer session with Basic Authentication
    indexer_http_session = requests.Session()
    indexer_http_session.auth = (wazuh_config.indexer_user, wazuh_config.indexer_pass)
    indexer_http_session.headers.update({
        "Content-Type": "application/json",
        "User-Agent": "wazuh-mcp-server/1.2.0"
    })
    indexer_http_session.verify = wazuh_config.use_ssl

# Create FastMCP server instance
mcp_server = FastMCP("Wazuh")

# Initialize cache and HTTP sessions (for module import)
memory_cache = MemoryCache(wazuh_config.cache_duration)
setup_http_sessions()

# ═══════════════════════ Utility Functions ═══════════════════════

def exponential_backoff_retry(max_attempts: int = 3, initial_delay: float = 1.0):
    """Decorator implementing exponential backoff retry logic"""
    def decorator_func(func):
        @wraps(func)
        def wrapper_func(*args, **kwargs):
            last_error = None
            for attempt_num in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as error:
                    last_error = error
                    if attempt_num < max_attempts - 1:
                        delay = initial_delay * (2 ** attempt_num)
                        logger.warning(f"Attempt {attempt_num + 1}/{max_attempts} failed: {error}")
                        logger.warning(f"Retrying in {delay}s...")
                        time.sleep(delay)
            logger.error(f"All {max_attempts} attempts exhausted")
            raise last_error
        return wrapper_func
    return decorator_func

def query_manager_api(endpoint: str, query_params: Optional[Dict] = None,
                     http_method: str = "GET", request_body: Optional[Dict] = None,
                     enable_cache: bool = True) -> Dict[str, Any]:
    """Execute API request to Wazuh Manager with caching and JWT authentication"""

    # Generate cache key
    cache_identifier = f"mgr:{http_method}:{endpoint}:{json.dumps(query_params, sort_keys=True)}:{json.dumps(request_body, sort_keys=True)}"

    # Check cache for GET requests
    if enable_cache and http_method.upper() == 'GET':
        cached_response = memory_cache.retrieve(cache_identifier)
        if cached_response:
            logger.debug(f"Cache hit: {endpoint}")
            return cached_response

    # Build full URL
    full_url = f"{wazuh_config.protocol}://{wazuh_config.manager_host}:{wazuh_config.manager_port}{endpoint}"
    logger.debug(f"Manager API: {http_method} {full_url}")

    # Retry logic
    for attempt in range(wazuh_config.retry_attempts):
        try:
            # Get JWT token
            jwt_token = get_manager_jwt_token()

            # Make request with JWT token
            http_response = manager_http_session.request(
                http_method.upper(),
                full_url,
                params=query_params,
                json=request_body,
                headers={"Authorization": f"Bearer {jwt_token}"},
                timeout=wazuh_config.request_timeout
            )
            http_response.raise_for_status()

            response_data = http_response.json()

            # Cache successful GET requests
            if enable_cache and http_method.upper() == 'GET':
                memory_cache.store(cache_identifier, response_data)

            return response_data

        except requests.exceptions.RequestException as req_error:
            # If 401, invalidate token and retry
            if hasattr(req_error, 'response') and req_error.response and req_error.response.status_code == 401:
                global manager_jwt_token, manager_token_expiry
                manager_jwt_token = None
                manager_token_expiry = None
                logger.warning("Token expired or invalid, will get new token on retry")

            if attempt < wazuh_config.retry_attempts - 1:
                backoff_delay = 1.0 * (2 ** attempt)
                logger.warning(f"Request failed (attempt {attempt + 1}): {req_error}")
                logger.warning(f"Retrying after {backoff_delay}s...")
                time.sleep(backoff_delay)
            else:
                logger.error(f"Manager API request failed after {wazuh_config.retry_attempts} attempts")
                raise Exception(f"Wazuh Manager API error: {str(req_error)}")

def query_indexer_api(endpoint: str, query_params: Optional[Dict] = None,
                     http_method: str = "GET", request_body: Optional[Dict] = None,
                     enable_cache: bool = True) -> Dict[str, Any]:
    """Execute API request to Wazuh Indexer with caching"""

    # Generate cache key
    cache_identifier = f"idx:{http_method}:{endpoint}:{json.dumps(query_params, sort_keys=True)}:{json.dumps(request_body, sort_keys=True)}"

    # Check cache for GET requests
    if enable_cache and http_method.upper() == 'GET':
        cached_response = memory_cache.retrieve(cache_identifier)
        if cached_response:
            logger.debug(f"Cache hit: {endpoint}")
            return cached_response

    # Build full URL
    full_url = f"{wazuh_config.protocol}://{wazuh_config.indexer_host}:{wazuh_config.indexer_port}{endpoint}"
    logger.debug(f"Indexer API: {http_method} {full_url}")

    # Retry logic
    for attempt in range(wazuh_config.retry_attempts):
        try:
            http_response = indexer_http_session.request(
                http_method.upper(),
                full_url,
                params=query_params,
                json=request_body,
                timeout=wazuh_config.request_timeout
            )
            http_response.raise_for_status()

            response_data = http_response.json()

            # Cache successful GET/POST requests
            if enable_cache and http_method.upper() in ['GET', 'POST']:
                memory_cache.store(cache_identifier, response_data)

            return response_data

        except requests.exceptions.RequestException as req_error:
            if attempt < wazuh_config.retry_attempts - 1:
                backoff_delay = 1.0 * (2 ** attempt)
                logger.warning(f"Request failed (attempt {attempt + 1}): {req_error}")
                logger.warning(f"Retrying after {backoff_delay}s...")
                time.sleep(backoff_delay)
            else:
                logger.error(f"Indexer API request failed after {wazuh_config.retry_attempts} attempts")
                raise Exception(f"Wazuh Indexer API error: {str(req_error)}")

def normalize_agent_identifier(agent_id_input: str) -> str:
    """Convert agent ID to zero-padded 3-digit format"""
    try:
        agent_number = int(agent_id_input)
        if agent_number > 999:
            raise ValueError(f"Agent ID '{agent_id_input}' exceeds maximum (999)")
        return f"{agent_number:03d}"
    except ValueError:
        if len(agent_id_input) == 3 and agent_id_input.isdigit():
            return agent_id_input
        raise ValueError(
            f"Invalid agent ID format: '{agent_id_input}'. "
            "Expected: number (1-999) or 3-digit string (001-999)"
        )

# ═══════════════════════ MCP Tool Implementations ═══════════════════════

# ─────────────────── Alert Monitoring Tools ───────────────────

@mcp_server.tool()
def get_wazuh_alert_summary(max_results: int = 300,
                           offset: int = 0,
                           min_level: Optional[int] = None,
                           max_level: Optional[int] = None,
                           time_range_hours: Optional[int] = None,
                           agent_name: Optional[str] = None,
                           agent_id: Optional[str] = None,
                           agent_ip: Optional[str] = None,
                           rule_id: Optional[str] = None,
                           rule_group: Optional[str] = None,
                           rule_description: Optional[str] = None,
                           mitre_technique: Optional[str] = None,
                           mitre_tactic: Optional[str] = None,
                           min_cvss_score: Optional[float] = None,
                           cve_id: Optional[str] = None,
                           source_ip: Optional[str] = None,
                           destination_ip: Optional[str] = None,
                           user: Optional[str] = None,
                           process_name: Optional[str] = None,
                           file_path: Optional[str] = None) -> str:
    """Retrieve security alerts with filtering, pagination, and IoC extraction.

    Supports filtering by severity, time, agent, rule, MITRE ATT&CK, CVE, network, and system fields.
    Use pagination (offset/max_results) when has_more=true in response.
    For statistics only (no alert details), prefer get_wazuh_alert_statistics instead.

    Args:
        max_results: Alerts per page (default 300, max 10000).
        offset: Skip N alerts for pagination (default 0). Use response pagination.next_offset.
        min_level: Min alert level 0-15. Levels: 0-3=low, 4-7=medium, 8-11=high, 12-15=critical.
        max_level: Max alert level 0-15.
        time_range_hours: Look back N hours (e.g. 24, 72, 168).
        agent_name: Filter by agent hostname.
        agent_id: Filter by agent ID (e.g. "001").
        agent_ip: Filter by agent IP.
        rule_id: Exact rule ID (e.g. "5710").
        rule_group: Partial match, case-insensitive (e.g. "authentication", "jason" finds "jason_tools_ioc").
        rule_description: Partial match, case-insensitive (e.g. "IoC", "brute force").
        mitre_technique: MITRE technique ID (e.g. "T1078").
        mitre_tactic: MITRE tactic (e.g. "Initial Access").
        min_cvss_score: Min CVSS score (e.g. 7.0).
        cve_id: CVE ID (e.g. "CVE-2021-44228").
        source_ip: Source IP filter.
        destination_ip: Destination IP filter.
        user: Username filter.
        process_name: Process name filter.
        file_path: File path filter.

    Returns:
        JSON: {status, pagination:{offset,page_size,returned_count,total_matches,has_more,next_offset},
        alerts:[{alert_id,timestamp,agent_name,agent_id,severity_level,rule_id,rule_groups,description,
        ioc:{source_ip,destination_ip,md5_hash,sha256_hash,url,domain,process_name,mitre_attack,...}}]}
    """
    logger.info(f"Fetching alert summary (max={max_results}, offset={offset}, filters={{level:{min_level}-{max_level}, "
                f"time:{time_range_hours}h, agent:{agent_name or agent_id}, rule:{rule_id or rule_group}, cvss:{min_cvss_score}}})")

    try:
        # Build Elasticsearch query with filters
        must_clauses = []

        # Time range filter
        if time_range_hours:
            time_filter = {
                "range": {
                    "timestamp": {
                        "gte": f"now-{time_range_hours}h",
                        "lte": "now"
                    }
                }
            }
            must_clauses.append(time_filter)

        # Alert level filter (range)
        if min_level is not None or max_level is not None:
            level_range = {}
            if min_level is not None:
                level_range["gte"] = min_level
            if max_level is not None:
                level_range["lte"] = max_level
            level_filter = {
                "range": {
                    "rule.level": level_range
                }
            }
            must_clauses.append(level_filter)

        # Agent filters
        if agent_name:
            must_clauses.append({"match": {"agent.name": agent_name}})
        if agent_id:
            must_clauses.append({"match": {"agent.id": agent_id}})
        if agent_ip:
            must_clauses.append({"match": {"agent.ip": agent_ip}})

        # Rule filters
        if rule_id:
            must_clauses.append({"term": {"rule.id": rule_id}})
        if rule_group:
            # Use wildcard query for partial matching in rule groups
            # This allows searching "jason" to find "jason_tools_ioc" or "ioc" to find any group with "ioc"
            must_clauses.append({
                "wildcard": {
                    "rule.groups": {
                        "value": f"*{rule_group}*",
                        "case_insensitive": True
                    }
                }
            })
        if rule_description:
            # Use wildcard query for true partial matching (works with both text and keyword fields)
            # This ensures we can find "IOC" in "Jason Tools IOC: Malicious..." regardless of field mapping
            must_clauses.append({
                "wildcard": {
                    "rule.description": {
                        "value": f"*{rule_description}*",
                        "case_insensitive": True
                    }
                }
            })

        # MITRE ATT&CK filters
        if mitre_technique:
            must_clauses.append({"match": {"rule.mitre.technique": mitre_technique}})
        if mitre_tactic:
            must_clauses.append({"match": {"rule.mitre.tactic": mitre_tactic}})

        # Network/System event filters
        if source_ip:
            must_clauses.append({"match": {"data.srcip": source_ip}})
        if destination_ip:
            must_clauses.append({"match": {"data.dstip": destination_ip}})
        if user:
            must_clauses.append({"match": {"data.dstuser": user}})
        if process_name:
            must_clauses.append({"match": {"data.process.name": process_name}})
        if file_path:
            must_clauses.append({"match_phrase": {"syscheck.path": file_path}})

        # Vulnerability filters
        if cve_id:
            must_clauses.append({"match": {"data.vulnerability.cve": cve_id}})

        # CVSS score filter (for vulnerability-related alerts)
        if min_cvss_score is not None:
            # Try to match CVSS3 or CVSS2 scores
            # Wazuh vulnerability alerts store CVSS in data.vulnerability.cvss
            cvss_filter = {
                "bool": {
                    "should": [
                        {
                            "range": {
                                "data.vulnerability.cvss.cvss3.base_score": {
                                    "gte": min_cvss_score
                                }
                            }
                        },
                        {
                            "range": {
                                "data.vulnerability.cvss.cvss2.base_score": {
                                    "gte": min_cvss_score
                                }
                            }
                        }
                    ],
                    "minimum_should_match": 1
                }
            }
            must_clauses.append(cvss_filter)

        # Build final query with pagination
        if must_clauses:
            search_query = {
                "size": max_results,
                "from": offset,
                "sort": [{"timestamp": {"order": "desc"}}],
                "query": {
                    "bool": {
                        "must": must_clauses
                    }
                }
            }
        else:
            search_query = {
                "size": max_results,
                "from": offset,
                "sort": [{"timestamp": {"order": "desc"}}],
                "query": {"match_all": {}}
            }

        api_response = query_indexer_api(
            "/wazuh-alerts-*/_search",
            http_method="POST",
            request_body=search_query
        )

        hits_data = api_response.get("hits", {})
        alert_hits = hits_data.get("hits", [])
        total_hits = hits_data.get("total", {})

        # Extract total count (Elasticsearch 7.x format)
        if isinstance(total_hits, dict):
            total_count = total_hits.get("value", 0)
        else:
            total_count = total_hits

        if not alert_hits:
            return _compact_json({
                "status": "success",
                "message": "No security alerts found matching the criteria",
                "pagination": {
                    "offset": offset,
                    "page_size": max_results,
                    "returned_count": 0,
                    "total_matches": total_count
                },
                "alerts": []
            })

        processed_alerts = []
        for hit_entry in alert_hits:
            alert_source = hit_entry.get("_source", {})

            # Extract alert details
            alert_identifier = alert_source.get("id") or hit_entry.get("_id", "N/A")
            event_timestamp = alert_source.get("timestamp", "N/A")

            rule_details = alert_source.get("rule", {})
            event_description = rule_details.get("description", "No description")
            severity_level = rule_details.get("level", 0)

            agent_details = alert_source.get("agent", {})
            agent_identifier = agent_details.get("name", "N/A")

            # Extract IoC (Indicators of Compromise) information
            alert_data = alert_source.get("data", {})
            ioc_info = {}

            # IP addresses (malicious IPs)
            if "srcip" in alert_data:
                ioc_info["source_ip"] = alert_data["srcip"]
            if "dstip" in alert_data:
                ioc_info["destination_ip"] = alert_data["dstip"]

            # File hashes (malware indicators)
            if "md5" in alert_data:
                ioc_info["md5_hash"] = alert_data["md5"]
            if "sha1" in alert_data:
                ioc_info["sha1_hash"] = alert_data["sha1"]
            if "sha256" in alert_data:
                ioc_info["sha256_hash"] = alert_data["sha256"]

            # URLs (malicious links)
            if "url" in alert_data:
                ioc_info["url"] = alert_data["url"]

            # Domain names
            if "domain" in alert_data:
                ioc_info["domain"] = alert_data["domain"]

            # Process information (suspicious processes)
            if "process" in alert_data:
                process_data = alert_data["process"]
                if isinstance(process_data, dict):
                    ioc_info["process_name"] = process_data.get("name")
                    ioc_info["process_path"] = process_data.get("path")
                    ioc_info["process_cmdline"] = process_data.get("cmdline")
                else:
                    ioc_info["process_name"] = process_data

            # File paths
            if "file" in alert_data:
                ioc_info["file_path"] = alert_data["file"]

            # Username (suspicious account activity)
            if "dstuser" in alert_data:
                ioc_info["username"] = alert_data["dstuser"]
            elif "srcuser" in alert_data:
                ioc_info["username"] = alert_data["srcuser"]

            # Port information
            if "dstport" in alert_data:
                ioc_info["destination_port"] = alert_data["dstport"]
            if "srcport" in alert_data:
                ioc_info["source_port"] = alert_data["srcport"]

            # MITRE ATT&CK mapping
            mitre_data = rule_details.get("mitre", {})
            if mitre_data:
                mitre_info = {}
                if "technique" in mitre_data and mitre_data["technique"]:
                    mitre_info["techniques"] = mitre_data["technique"]
                if "tactic" in mitre_data and mitre_data["tactic"]:
                    mitre_info["tactics"] = mitre_data["tactic"]
                if mitre_info:
                    ioc_info["mitre_attack"] = mitre_info

            # Threat intelligence (VirusTotal, etc.)
            if "virustotal" in alert_data:
                vt_data = alert_data["virustotal"]
                ioc_info["virustotal"] = {
                    "positives": vt_data.get("positives"),
                    "total": vt_data.get("total"),
                    "permalink": vt_data.get("permalink")
                }

            # Build alert entry
            alert_entry = {
                "alert_id": alert_identifier,
                "timestamp": event_timestamp,
                "agent_name": agent_identifier,
                "agent_id": agent_details.get("id", "N/A"),
                "severity_level": severity_level,
                "rule_id": rule_details.get("id", "N/A"),
                "rule_groups": rule_details.get("groups", []),
                "description": event_description
            }

            # Only include IoC section if we found IoC data
            if ioc_info:
                alert_entry["ioc"] = ioc_info

            processed_alerts.append(alert_entry)

        # Calculate pagination info
        returned_count = len(processed_alerts)
        has_more = (offset + returned_count) < total_count

        return _compact_json({
            "status": "success",
            "pagination": {
                "offset": offset,
                "page_size": max_results,
                "returned_count": returned_count,
                "total_matches": total_count,
                "has_more": has_more,
                "next_offset": offset + returned_count if has_more else None
            },
            "alerts": processed_alerts
        })

    except Exception as error:
        logger.error(f"Alert retrieval failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve alerts: {str(error)}"
        })

@mcp_server.tool()
def get_wazuh_alert_statistics(time_range_hours: Optional[int] = 24,
                               agent_name: Optional[str] = None,
                               agent_id: Optional[str] = None,
                               rule_group: Optional[str] = None,
                               rule_id: Optional[str] = None,
                               rule_description: Optional[str] = None) -> str:
    """Lightweight alert statistics (counts/distribution only, no alert details). Use this before get_wazuh_alert_summary to check volume.

    Args:
        time_range_hours: Hours to look back (default 24). E.g. 72=3 days, 168=week.
        agent_name: Filter by agent hostname.
        agent_id: Filter by agent ID (e.g. "031"). Auto-padded to 3 digits.
        rule_group: Partial match, case-insensitive (e.g. "jason" finds "jason_tools_ioc").
        rule_id: Exact rule ID (e.g. "5715").
        rule_description: Partial match, case-insensitive (e.g. "IoC", "brute force").

    Returns:
        JSON: {status, time_range_hours, total_alerts, severity_distribution:{critical_emergency_12_15,high_8_11,medium_4_7,low_0_3},
        top_agents:[{agent_name,alert_count}], top_rules:[{rule_id,description,trigger_count}]}
    """
    logger.info(f"Fetching alert statistics (time={time_range_hours}h, agent_name={agent_name}, agent_id={agent_id}, "
                f"rule_group={rule_group}, rule_id={rule_id}, rule_description={rule_description})")

    try:
        # Build Elasticsearch aggregation query
        must_clauses = []

        # Time range filter
        if time_range_hours:
            must_clauses.append({
                "range": {
                    "timestamp": {
                        "gte": f"now-{time_range_hours}h",
                        "lte": "now"
                    }
                }
            })

        # Agent filters
        if agent_name:
            must_clauses.append({"match": {"agent.name": agent_name}})
        if agent_id:
            normalized_agent = normalize_agent_identifier(agent_id)
            must_clauses.append({"term": {"agent.id": normalized_agent}})

        # Rule filters
        if rule_id:
            must_clauses.append({"term": {"rule.id": rule_id}})
        if rule_group:
            # Use wildcard query for partial matching in rule groups
            # This allows searching "jason" to find "jason_tools_ioc" or "ioc" to find any group with "ioc"
            must_clauses.append({
                "wildcard": {
                    "rule.groups": {
                        "value": f"*{rule_group}*",
                        "case_insensitive": True
                    }
                }
            })
        if rule_description:
            # Use wildcard query for true partial matching (works with both text and keyword fields)
            # This ensures we can find "IOC" in "Jason Tools IOC: Malicious..." regardless of field mapping
            must_clauses.append({
                "wildcard": {
                    "rule.description": {
                        "value": f"*{rule_description}*",
                        "case_insensitive": True
                    }
                }
            })

        # Build aggregation query for statistics
        agg_query = {
            "size": 0,  # Don't return actual documents, only aggregations
            "track_total_hits": True,  # Get accurate total count (not limited to 10,000)
            "query": {
                "bool": {
                    "must": must_clauses if must_clauses else [{"match_all": {}}]
                }
            },
            "aggs": {
                # Severity level distribution
                "severity_stats": {
                    "range": {
                        "field": "rule.level",
                        "ranges": [
                            {"key": "low", "from": 0, "to": 4},
                            {"key": "medium", "from": 4, "to": 8},
                            {"key": "high", "from": 8, "to": 12},
                            {"key": "critical_emergency", "from": 12, "to": 16}
                        ]
                    }
                },
                # Top agents by alert count
                "top_agents": {
                    "terms": {
                        "field": "agent.name",
                        "size": 10,
                        "order": {"_count": "desc"}
                    }
                },
                # Top rules
                "top_rules": {
                    "terms": {
                        "field": "rule.id",
                        "size": 10,
                        "order": {"_count": "desc"}
                    },
                    "aggs": {
                        "rule_description": {
                            "top_hits": {
                                "size": 1,
                                "_source": ["rule.description"]
                            }
                        }
                    }
                }
            }
        }

        api_response = query_indexer_api(
            "/wazuh-alerts-*/_search",
            http_method="POST",
            request_body=agg_query
        )

        # Extract total count from hits
        total_hits = api_response.get("hits", {}).get("total", {})
        total_count = total_hits.get("value", 0) if isinstance(total_hits, dict) else total_hits

        # Extract severity distribution
        severity_buckets = api_response.get("aggregations", {}).get("severity_stats", {}).get("buckets", [])

        # Calculate actual total from aggregations (more accurate than hits.total)
        agg_total = sum(bucket.get("doc_count", 0) for bucket in severity_buckets)

        # Use aggregation total if it's more accurate (handles cases where total_count was capped at 10,000)
        accurate_total = agg_total if agg_total > total_count else total_count

        severity_dist = {}
        for bucket in severity_buckets:
            key = bucket.get("key", "unknown")
            count = bucket.get("doc_count", 0)
            percentage = round((count / accurate_total * 100), 2) if accurate_total > 0 else 0
            severity_dist[key] = {
                "count": count,
                "percentage": percentage
            }

        # Extract top agents
        agent_buckets = api_response.get("aggregations", {}).get("top_agents", {}).get("buckets", [])
        top_agents = [
            {
                "agent_name": bucket.get("key", "Unknown"),
                "alert_count": bucket.get("doc_count", 0)
            }
            for bucket in agent_buckets
        ]

        # Extract top rules
        rule_buckets = api_response.get("aggregations", {}).get("top_rules", {}).get("buckets", [])
        top_rules = []
        for bucket in rule_buckets:
            rule_hits = bucket.get("rule_description", {}).get("hits", {}).get("hits", [])
            description = "N/A"
            if rule_hits:
                description = rule_hits[0].get("_source", {}).get("rule", {}).get("description", "N/A")

            top_rules.append({
                "rule_id": bucket.get("key", "N/A"),
                "description": description,
                "trigger_count": bucket.get("doc_count", 0)
            })

        return _compact_json({
            "status": "success",
            "time_range_hours": time_range_hours,
            "filters": {
                "agent_name": agent_name,
                "agent_id": agent_id,
                "rule_group": rule_group,
                "rule_id": rule_id,
                "rule_description": rule_description
            },
            "total_alerts": accurate_total,
            "severity_distribution": {
                "critical_emergency_12_15": severity_dist.get("critical_emergency", {"count": 0, "percentage": 0}),
                "high_8_11": severity_dist.get("high", {"count": 0, "percentage": 0}),
                "medium_4_7": severity_dist.get("medium", {"count": 0, "percentage": 0}),
                "low_0_3": severity_dist.get("low", {"count": 0, "percentage": 0})
            },
            "top_agents": top_agents if not (agent_name or agent_id) else [],
            "top_rules": top_rules
        })

    except Exception as error:
        logger.error(f"Alert statistics retrieval failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve alert statistics: {str(error)}"
        })

@mcp_server.tool()
def get_wazuh_agents_with_alerts(min_level: Optional[int] = None,
                                time_range_hours: Optional[int] = None,
                                max_agents: int = 100) -> str:
    """List agents grouped by alert count, with severity and most recent alert info.

    Args:
        min_level: Min alert level 0-15. Levels: 0-3=low, 4-7=medium, 8-11=high, 12-15=critical.
        time_range_hours: Hours to look back (e.g. 24, 72, 168). Omit for all history.
        max_agents: Max agents to return (default 100), sorted by alert count desc.

    Returns:
        JSON: {status, total_agents, agents:[{agent_name, agent_id, alert_count, max_severity_level,
        most_recent_alert:{timestamp, description, level}}]}
    """
    logger.info(f"Analyzing agents with alerts (min_level={min_level}, "
                f"time_range={time_range_hours}h)")

    try:
        # Build Elasticsearch aggregation query
        must_clauses = []

        # Time range filter
        if time_range_hours:
            time_filter = {
                "range": {
                    "timestamp": {
                        "gte": f"now-{time_range_hours}h",
                        "lte": "now"
                    }
                }
            }
            must_clauses.append(time_filter)

        # Alert level filter
        if min_level is not None:
            level_filter = {
                "range": {
                    "rule.level": {
                        "gte": min_level
                    }
                }
            }
            must_clauses.append(level_filter)

        # Build aggregation query
        agg_query = {
            "size": 0,
            "query": {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}},
            "aggs": {
                "agents": {
                    "terms": {
                        "field": "agent.name",
                        "size": max_agents,
                        "order": {"_count": "desc"}
                    },
                    "aggs": {
                        "agent_id": {
                            "terms": {"field": "agent.id", "size": 1}
                        },
                        "max_level": {
                            "max": {"field": "rule.level"}
                        },
                        "recent_alert": {
                            "top_hits": {
                                "size": 1,
                                "sort": [{"timestamp": {"order": "desc"}}],
                                "_source": ["timestamp", "rule.description", "rule.level"]
                            }
                        }
                    }
                }
            }
        }

        api_response = query_indexer_api(
            "/wazuh-alerts-*/_search",
            http_method="POST",
            request_body=agg_query
        )

        agent_buckets = api_response.get("aggregations", {}).get("agents", {}).get("buckets", [])

        if not agent_buckets:
            return _compact_json({
                "status": "success",
                "message": "No agents found with alerts matching the criteria",
                "total_agents": 0,
                "agents": []
            })

        processed_agents = []
        for bucket in agent_buckets:
            agent_name = bucket.get("key", "Unknown")
            alert_count = bucket.get("doc_count", 0)
            max_severity = int(bucket.get("max_level", {}).get("value", 0))

            # Extract agent ID
            agent_id_buckets = bucket.get("agent_id", {}).get("buckets", [])
            agent_id = agent_id_buckets[0].get("key", "N/A") if agent_id_buckets else "N/A"

            # Extract most recent alert
            recent_hits = bucket.get("recent_alert", {}).get("hits", {}).get("hits", [])
            recent_alert_info = {}
            if recent_hits:
                recent_source = recent_hits[0].get("_source", {})
                recent_alert_info = {
                    "timestamp": recent_source.get("timestamp", "N/A"),
                    "description": recent_source.get("rule", {}).get("description", "N/A"),
                    "level": recent_source.get("rule", {}).get("level", 0)
                }

            processed_agents.append({
                "agent_name": agent_name,
                "agent_id": agent_id,
                "alert_count": alert_count,
                "max_severity_level": max_severity,
                "most_recent_alert": recent_alert_info
            })

        return _compact_json({
            "status": "success",
            "total_agents": len(processed_agents),
            "filter_criteria": {
                "min_level": min_level,
                "time_range_hours": time_range_hours
            },
            "agents": processed_agents
        })

    except Exception as error:
        logger.error(f"Agent alert analysis failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to analyze agents: {str(error)}"
        })

# ─────────────────── Security Rules Tools ───────────────────

@mcp_server.tool()
def get_wazuh_rules_summary(max_results: int = 300,
                           offset: int = 0,
                           min_level: Optional[int] = None,
                           rule_group: Optional[str] = None,
                           rule_file: Optional[str] = None) -> str:
    """Search Wazuh detection rules. Supports pagination. Includes compliance mappings (GDPR, HIPAA, PCI-DSS, NIST).

    Args:
        max_results: Rules per page (default 300).
        offset: Pagination offset (default 0).
        min_level: Min severity level 0-15. Levels: 0-3=low, 4-7=medium, 8-11=high, 12-15=critical.
        rule_group: Exact group name filter (e.g. "authentication", "web", "syscheck", "vulnerability-detector", "firewall").
        rule_file: Filter by rule filename (e.g. "0095-sshd_rules.xml").

    Returns:
        JSON: {status, pagination:{offset,page_size,returned_count,total_matches,has_more,next_offset},
        rules:[{rule_id, severity_level, severity_category, description, groups, filename, status, compliance}]}
    """
    logger.info(f"Fetching rules (max={max_results}, offset={offset}, level={min_level}, group={rule_group})")

    try:
        # Build query parameters
        api_params = {"limit": max_results, "offset": offset}
        if min_level is not None:
            api_params["level"] = min_level
        if rule_group:
            api_params["group"] = rule_group
        if rule_file:
            api_params["filename"] = rule_file

        api_response = query_manager_api("/rules", query_params=api_params)

        data_section = api_response.get("data", {})
        rule_items = data_section.get("affected_items", [])
        total_items = data_section.get("total_affected_items", 0)

        if not rule_items:
            return _compact_json({
                "status": "success",
                "message": "No rules match the specified criteria",
                "pagination": {
                    "offset": offset,
                    "page_size": max_results,
                    "returned_count": 0,
                    "total_matches": total_items
                },
                "rules": []
            })

        processed_rules = []
        for rule_entry in rule_items:
            rule_identifier = rule_entry.get("id", "N/A")
            severity_level = rule_entry.get("level", 0)
            rule_description = rule_entry.get("description", "No description")
            rule_groups = rule_entry.get("groups", [])
            source_file = rule_entry.get("filename", "N/A")
            rule_status = rule_entry.get("status", "unknown")

            # Calculate severity category
            if severity_level <= 3:
                severity_category = "Low"
            elif severity_level <= 7:
                severity_category = "Medium"
            elif severity_level <= 12:
                severity_category = "High"
            else:
                severity_category = "Critical"

            # Extract compliance mappings
            compliance_mappings = {}
            for compliance_type in ["gdpr", "hipaa", "pci_dss", "nist_800_53"]:
                if compliance_type in rule_entry and rule_entry[compliance_type]:
                    compliance_mappings[compliance_type.upper().replace("_", " ")] = rule_entry[compliance_type]

            processed_rules.append({
                "rule_id": rule_identifier,
                "severity_level": severity_level,
                "severity_category": severity_category,
                "description": rule_description,
                "groups": rule_groups,
                "filename": source_file,
                "status": rule_status,
                "compliance": compliance_mappings or None
            })

        # Calculate pagination info
        returned_count = len(processed_rules)
        has_more = (offset + returned_count) < total_items

        return _compact_json({
            "status": "success",
            "pagination": {
                "offset": offset,
                "page_size": max_results,
                "returned_count": returned_count,
                "total_matches": total_items,
                "has_more": has_more,
                "next_offset": offset + returned_count if has_more else None
            },
            "rules": processed_rules
        })

    except Exception as error:
        logger.error(f"Rule retrieval failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve rules: {str(error)}"
        })

# ─────────────────── Vulnerability Assessment Tools ───────────────────

@mcp_server.tool()
def get_wazuh_vulnerability_summary(agent_identifier: str,
                                   max_results: int = 500,
                                   offset: int = 0,
                                   severity_filter: Optional[str] = None,
                                   cve_filter: Optional[str] = None) -> str:
    """Get vulnerability scan results (CVEs) for a specific agent. Supports pagination. Use severity_filter="Critical" for critical-only.

    Args:
        agent_identifier: Agent ID (REQUIRED). Format: "0"=Manager, "1" or "001". Auto-padded to 3 digits.
        max_results: Vulnerabilities per page (default 500).
        offset: Pagination offset (default 0).
        severity_filter: Exact match: "Low", "Medium", "High", or "Critical" (case-sensitive).
        cve_filter: CVE ID search (e.g. "CVE-2021-44228"). Partial match supported.

    Returns:
        JSON: {status, agent_id, pagination:{offset,page_size,returned_count,total_matches,has_more,next_offset},
        vulnerabilities:[{cve_id, severity, title, description, published_date, cvss_scores, package_name, package_version}]}
    """
    logger.info(f"Fetching vulnerabilities for agent {agent_identifier} (max={max_results}, offset={offset})")

    try:
        # Normalize agent ID
        normalized_id = normalize_agent_identifier(agent_identifier)

        # Build Elasticsearch query for vulnerability alerts
        must_clauses = [
            {"exists": {"field": "data.vulnerability"}},
            {"term": {"agent.id": normalized_id}}
        ]

        # Apply severity filter if provided
        if severity_filter:
            must_clauses.append({"term": {"data.vulnerability.severity": severity_filter}})

        # Apply CVE filter if provided
        if cve_filter:
            must_clauses.append({"match": {"data.vulnerability.cve": cve_filter}})

        # Build Elasticsearch query with collapse to get unique CVEs
        search_query = {
            "size": max_results,
            "from": offset,
            "query": {
                "bool": {
                    "must": must_clauses
                }
            },
            "collapse": {
                "field": "data.vulnerability.cve"
            },
            "sort": [{"timestamp": {"order": "desc"}}],
            "_source": ["data.vulnerability", "timestamp", "agent.name"]
        }

        api_response = query_indexer_api(
            "/wazuh-alerts-*/_search",
            http_method="POST",
            request_body=search_query
        )

        hits_data = api_response.get("hits", {})
        vuln_hits = hits_data.get("hits", [])
        total_hits = hits_data.get("total", {})

        # Extract total count
        if isinstance(total_hits, dict):
            total_items = total_hits.get("value", 0)
        else:
            total_items = total_hits

        vuln_items = []
        for hit in vuln_hits:
            alert_source = hit.get("_source", {})
            vuln_data = alert_source.get("data", {}).get("vulnerability", {})
            if vuln_data:
                vuln_items.append(vuln_data)

        if not vuln_items:
            return _compact_json({
                "status": "success",
                "message": f"No vulnerabilities found for agent {normalized_id}",
                "agent_id": normalized_id,
                "pagination": {
                    "offset": offset,
                    "page_size": max_results,
                    "returned_count": 0,
                    "total_matches": total_items
                },
                "vulnerabilities": []
            })

        processed_vulns = []
        for vuln_data in vuln_items:
            severity_rating = vuln_data.get("severity", "Unknown")

            # Map severity to display format
            severity_map = {
                "Critical": "CRITICAL",
                "High": "HIGH",
                "Medium": "MEDIUM",
                "Low": "LOW"
            }
            display_severity = severity_map.get(severity_rating, severity_rating)

            # Extract CVSS scores
            cvss_data = {}
            if "cvss" in vuln_data:
                cvss_info = vuln_data["cvss"]
                if "cvss2" in cvss_info and cvss_info.get("cvss2", {}).get("base_score"):
                    cvss_data["CVSS2_Score"] = float(cvss_info["cvss2"]["base_score"])
                if "cvss3" in cvss_info and cvss_info.get("cvss3", {}).get("base_score"):
                    cvss_data["CVSS3_Score"] = float(cvss_info["cvss3"]["base_score"])

            # Extract package information
            package_data = vuln_data.get("package", {})
            package_name = package_data.get("name", "N/A")
            package_version = package_data.get("version", "N/A")

            processed_vulns.append({
                "cve_id": vuln_data.get("cve", "N/A"),
                "severity": display_severity,
                "title": vuln_data.get("title", package_name),  # Use package name if no title
                "description": f"Vulnerability in {package_name} {package_version}" if package_name != "N/A" else "No description",
                "published_date": vuln_data.get("published"),
                "updated_date": vuln_data.get("updated"),
                "detected_at": vuln_data.get("detection_time"),
                "cvss_scores": cvss_data or None,
                "reference_url": vuln_data.get("reference"),
                "package_name": package_name,
                "package_version": package_version
            })

        # Calculate pagination info
        returned_count = len(processed_vulns)
        has_more = (offset + returned_count) < total_items

        return _compact_json({
            "status": "success",
            "agent_id": normalized_id,
            "pagination": {
                "offset": offset,
                "page_size": max_results,
                "returned_count": returned_count,
                "total_matches": total_items,
                "has_more": has_more,
                "next_offset": offset + returned_count if has_more else None
            },
            "vulnerabilities": processed_vulns
        })

    except Exception as error:
        logger.error(f"Vulnerability retrieval failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve vulnerabilities: {str(error)}"
        })

# ─────────────────── Agent Management Tools ───────────────────

@mcp_server.tool()
def get_wazuh_agents(max_results: int = 300, status_filter: str = "active",
                    name_filter: Optional[str] = None, ip_filter: Optional[str] = None,
                    group_filter: Optional[str] = None, os_filter: Optional[str] = None,
                    version_filter: Optional[str] = None) -> str:
    """List Wazuh monitored agents/servers. Use this first to get agent_id for other agent-specific tools. Agent "000" is always the Manager.

    Args:
        max_results: Max agents (default 300).
        status_filter: "active" (default), "disconnected", "pending", "never_connected", or "all".
        name_filter: Partial hostname match (e.g. "web" matches "web-server-01").
        ip_filter: Exact IP match (e.g. "192.168.1.100").
        group_filter: Exact group name (e.g. "production").
        os_filter: OS platform partial match (e.g. "ubuntu", "windows", "centos").
        version_filter: Wazuh agent version (e.g. "4.7.0").

    Returns:
        JSON: {status, total_count, agents:[{agent_id, agent_name, status, ip_address, os_info, agent_version,
        groups, last_keepalive, node}]}
    """
    logger.info(f"Fetching agents (max={max_results}, status={status_filter})")

    try:
        # Build query parameters
        api_params = {"limit": max_results, "offset": 0, "status": status_filter}
        if name_filter:
            api_params["name"] = name_filter
        if ip_filter:
            api_params["ip"] = ip_filter
        if group_filter:
            api_params["group"] = group_filter
        if os_filter:
            api_params["os.platform"] = os_filter
        if version_filter:
            api_params["version"] = version_filter

        api_response = query_manager_api("/agents", query_params=api_params)

        agent_items = api_response.get("data", {}).get("affected_items", [])

        if not agent_items:
            return _compact_json({
                "status": "success",
                "message": f"No agents found (status filter: {status_filter})",
                "total_count": 0,
                "agents": []
            })

        processed_agents = []
        for agent_entry in agent_items:
            agent_id = agent_entry.get("id", "N/A")
            agent_status = agent_entry.get("status", "unknown")

            # Map status to display format
            status_map = {
                "active": "ACTIVE",
                "disconnected": "DISCONNECTED",
                "pending": "PENDING",
                "never_connected": "NEVER_CONNECTED"
            }
            display_status = status_map.get(agent_status.lower(), agent_status.upper())

            # Extract OS information
            os_details = {}
            if "os" in agent_entry:
                os_data = agent_entry["os"]
                os_details = {
                    "name": os_data.get("name"),
                    "version": os_data.get("version"),
                    "architecture": os_data.get("arch")
                }

            # Format agent ID display
            agent_id_display = f"{agent_id} (Manager)" if agent_id == "000" else agent_id

            processed_agents.append({
                "agent_id": agent_id_display,
                "agent_name": agent_entry.get("name", "N/A"),
                "status": display_status,
                "ip_address": agent_entry.get("ip"),
                "registration_ip": agent_entry.get("registerIP"),
                "os_info": os_details or None,
                "agent_version": agent_entry.get("version"),
                "groups": agent_entry.get("group"),
                "last_keepalive": agent_entry.get("lastKeepAlive"),
                "registration_date": agent_entry.get("dateAdd"),
                "node": agent_entry.get("node_name"),
                "config_status": agent_entry.get("group_config_status")
            })

        return _compact_json({
            "status": "success",
            "total_count": len(processed_agents),
            "agents": processed_agents
        })

    except Exception as error:
        logger.error(f"Agent retrieval failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve agents: {str(error)}"
        })

@mcp_server.tool()
def get_wazuh_agent_processes(agent_identifier: str, max_results: int = 300,
                              search_filter: Optional[str] = None) -> str:
    """Get running processes on an agent via Syscollector.

    Args:
        agent_identifier: Agent ID (e.g. "1", "001"). Auto-padded to 3 digits.
        max_results: Max processes (default 300).
        search_filter: Filter by process name or command.

    Returns:
        JSON: {status, agent_id, total_count, processes:[{process_id, process_name, state, username, command_line, memory_resident_kb}]}
    """
    logger.info(f"Fetching processes for agent {agent_identifier}")

    try:
        # Normalize agent ID
        normalized_id = normalize_agent_identifier(agent_identifier)

        api_params = {"limit": max_results, "offset": 0}
        if search_filter:
            api_params["search"] = search_filter

        api_response = query_manager_api(
            f"/syscollector/{normalized_id}/processes",
            query_params=api_params
        )

        process_items = api_response.get("data", {}).get("affected_items", [])

        if not process_items:
            return _compact_json({
                "status": "success",
                "message": f"No process data available for agent {normalized_id}",
                "agent_id": normalized_id,
                "total_count": 0,
                "processes": []
            })

        processed_procs = []
        for proc_entry in process_items:
            # Convert memory values from bytes to KB
            resident_mem = proc_entry.get("resident")
            vm_mem = proc_entry.get("vm_size")

            processed_procs.append({
                "process_id": proc_entry.get("pid", "N/A"),
                "process_name": proc_entry.get("name", "N/A"),
                "state": proc_entry.get("state"),
                "parent_pid": proc_entry.get("ppid"),
                "username": proc_entry.get("euser"),
                "command_line": proc_entry.get("cmd"),
                "start_time": proc_entry.get("start_time"),
                "memory_resident_kb": resident_mem // 1024 if resident_mem else None,
                "memory_virtual_kb": vm_mem // 1024 if vm_mem else None
            })

        return _compact_json({
            "status": "success",
            "agent_id": normalized_id,
            "total_count": len(processed_procs),
            "processes": processed_procs
        })

    except Exception as error:
        logger.error(f"Process retrieval failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve processes: {str(error)}"
        })

@mcp_server.tool()
def get_wazuh_agent_ports(agent_identifier: str, max_results: int = 300,
                         protocol_filter: str = "", state_filter: str = "") -> str:
    """Get network ports on an agent via Syscollector.

    Args:
        agent_identifier: Agent ID (e.g. "001"). Auto-padded to 3 digits.
        max_results: Max ports (default 300).
        protocol_filter: "tcp" or "udp".
        state_filter: "LISTENING" or "ESTABLISHED".

    Returns:
        JSON: {status, agent_id, total_count, ports:[{protocol, local_address, remote_address, state, process_name, process_id}]}
    """
    logger.info(f"Fetching network ports for agent {agent_identifier}")

    try:
        # Normalize agent ID
        normalized_id = normalize_agent_identifier(agent_identifier)

        # Fetch extra results for client-side filtering
        api_params = {"limit": max_results * 2, "offset": 0}
        if protocol_filter:
            api_params["protocol"] = protocol_filter

        api_response = query_manager_api(
            f"/syscollector/{normalized_id}/ports",
            query_params=api_params
        )

        port_items = api_response.get("data", {}).get("affected_items", [])

        # Apply client-side state filtering (matching Rust logic)
        if state_filter:
            is_listening_filter = state_filter.strip().lower() == "listening"
            filtered_ports = []

            for port_entry in port_items:
                port_state = port_entry.get("state", "").strip()

                if not port_state:
                    # Include entries without state only for non-listening filter
                    if not is_listening_filter:
                        filtered_ports.append(port_entry)
                elif is_listening_filter:
                    # For LISTENING filter: only include LISTENING state
                    if port_state.lower() == "listening":
                        filtered_ports.append(port_entry)
                else:
                    # For non-LISTENING filter: exclude LISTENING state
                    if port_state.lower() != "listening":
                        filtered_ports.append(port_entry)

            port_items = filtered_ports[:max_results]
        else:
            port_items = port_items[:max_results]

        if not port_items:
            return _compact_json({
                "status": "success",
                "message": f"No network port data for agent {normalized_id}",
                "agent_id": normalized_id,
                "total_count": 0,
                "ports": []
            })

        processed_ports = []
        for port_entry in port_items:
            local_info = port_entry.get("local", {})
            local_addr = f"{local_info.get('ip', 'N/A')}:{local_info.get('port', 'N/A')}"

            remote_info = port_entry.get("remote", {})
            remote_addr = None
            if remote_info:
                remote_addr = f"{remote_info.get('ip', 'N/A')}:{remote_info.get('port', 'N/A')}"

            processed_ports.append({
                "protocol": port_entry.get("protocol", "N/A"),
                "local_address": local_addr,
                "remote_address": remote_addr,
                "state": port_entry.get("state"),
                "process_name": port_entry.get("process"),
                "process_id": port_entry.get("pid"),
                "inode": port_entry.get("inode"),
                "tx_queue": port_entry.get("tx_queue"),
                "rx_queue": port_entry.get("rx_queue")
            })

        return _compact_json({
            "status": "success",
            "agent_id": normalized_id,
            "total_count": len(processed_ports),
            "ports": processed_ports
        })

    except Exception as error:
        logger.error(f"Port retrieval failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve ports: {str(error)}"
        })

# ─────────────────── Statistics & Monitoring Tools ───────────────────

@mcp_server.tool()
def search_wazuh_manager_logs(max_results: int = 300, skip_count: int = 0,
                             level_filter: str = "", tag_filter: Optional[str] = None,
                             keyword_search: Optional[str] = None) -> str:
    """Search Wazuh manager logs. Use level_filter="error" for error-only logs.

    Args:
        max_results: Max log entries (default 300).
        skip_count: Entries to skip (default 0).
        level_filter: "error", "warning", or "info".
        tag_filter: Filter by log tag.
        keyword_search: Search term in log description.

    Returns:
        JSON: {status, total_count, logs:[{timestamp, tag, level, description}]}
    """
    logger.info(f"Searching manager logs (max={max_results}, level={level_filter})")

    try:
        api_params = {"limit": max_results, "offset": skip_count}
        if level_filter:
            api_params["level"] = level_filter
        if tag_filter:
            api_params["tag"] = tag_filter
        if keyword_search:
            api_params["search"] = keyword_search

        api_response = query_manager_api("/manager/logs", query_params=api_params)

        log_items = api_response.get("data", {}).get("affected_items", [])

        if not log_items:
            return _compact_json({
                "status": "success",
                "message": "No log entries match the search criteria",
                "total_count": 0,
                "logs": []
            })

        processed_logs = []
        for log_entry in log_items:
            processed_logs.append({
                "timestamp": log_entry.get("timestamp", "N/A"),
                "tag": log_entry.get("tag", "N/A"),
                "level": log_entry.get("level", "N/A"),
                "description": log_entry.get("description", "No description")
            })

        return _compact_json({
            "status": "success",
            "total_count": len(processed_logs),
            "logs": processed_logs
        })

    except Exception as error:
        logger.error(f"Log search failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to search logs: {str(error)}"
        })

@mcp_server.tool()
def get_wazuh_log_collector_stats(agent_identifier: str) -> str:
    """Get log collector stats (events, bytes, per-file metrics) for an agent.

    Args:
        agent_identifier: Agent ID (e.g. "1", "001"). Auto-padded to 3 digits.

    Returns:
        JSON: {status, statistics:{agent_id, global_period, interval_period}}
    """
    logger.info(f"Fetching log collector stats for agent {agent_identifier}")

    try:
        # Normalize agent ID
        normalized_id = normalize_agent_identifier(agent_identifier)

        api_response = query_manager_api(
            f"/agents/{normalized_id}/stats/logcollector"
        )

        stats_items = api_response.get("data", {}).get("affected_items", [])

        if not stats_items:
            return _compact_json({
                "status": "success",
                "message": f"No log collector stats for agent {normalized_id}",
                "agent_id": normalized_id
            })

        stats_data = stats_items[0]

        def extract_period_stats(period_info):
            """Extract statistics for a time period"""
            if not period_info:
                return None

            file_stats = []
            for file_data in period_info.get("files", []):
                target_stats = []
                for target_data in file_data.get("targets", []):
                    target_stats.append({
                        "name": target_data.get("name"),
                        "drops": target_data.get("drops")
                    })

                file_stats.append({
                    "file_path": file_data.get("location"),
                    "events_count": file_data.get("events"),
                    "bytes_count": file_data.get("bytes"),
                    "targets": target_stats
                })

            return {
                "period_start": period_info.get("start"),
                "period_end": period_info.get("end"),
                "files": file_stats
            }

        collector_stats = {
            "agent_id": normalized_id,
            "global_period": extract_period_stats(stats_data.get("global")),
            "interval_period": extract_period_stats(stats_data.get("interval"))
        }

        return _compact_json({
            "status": "success",
            "statistics": collector_stats
        })

    except Exception as error:
        logger.error(f"Log collector stats retrieval failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve log collector stats: {str(error)}"
        })

@mcp_server.tool()
def get_wazuh_remoted_stats() -> str:
    """Get remoted daemon stats (queue sizes, TCP sessions, message counts, traffic).

    Returns:
        JSON: {status, statistics:{queue_size, total_queue_size, tcp_sessions, sent_bytes, recv_bytes}}
    """
    logger.info("Fetching remoted daemon statistics")

    try:
        api_response = query_manager_api("/manager/stats/remoted")

        stats_items = api_response.get("data", {}).get("affected_items", [])

        if not stats_items:
            return _compact_json({
                "status": "error",
                "message": "Remoted statistics unavailable"
            })

        stats_data = stats_items[0]

        remoted_metrics = {
            "queue_size": stats_data.get("queue_size"),
            "total_queue_size": stats_data.get("total_queue_size"),
            "tcp_sessions": stats_data.get("tcp_sessions"),
            "ctrl_msg_count": stats_data.get("ctrl_msg_count"),
            "discarded_count": stats_data.get("discarded_count"),
            "sent_bytes": stats_data.get("sent_bytes"),
            "recv_bytes": stats_data.get("recv_bytes"),
            "dequeued_after_close": stats_data.get("dequeued_after_close")
        }

        return _compact_json({
            "status": "success",
            "statistics": remoted_metrics
        })

    except Exception as error:
        logger.error(f"Remoted stats retrieval failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve remoted stats: {str(error)}"
        })

@mcp_server.tool()
def get_wazuh_weekly_stats() -> str:
    """Get weekly aggregated performance statistics from the manager.

    Returns:
        JSON: {status, statistics:{...weekly metrics}}
    """
    logger.info("Fetching weekly statistics")

    try:
        api_response = query_manager_api("/manager/stats/weekly")

        return _compact_json({
            "status": "success",
            "statistics": api_response.get("data", {})
        })

    except Exception as error:
        logger.error(f"Weekly stats retrieval failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve weekly stats: {str(error)}"
        })

@mcp_server.tool()
def get_wazuh_cluster_health() -> str:
    """Check Wazuh cluster health (enabled, running, connected nodes).

    Returns:
        JSON: {status, cluster_health:{is_healthy, enabled, running, connected_nodes}}
    """
    logger.info("Checking cluster health")

    try:
        # Retrieve cluster status
        status_response = query_manager_api("/cluster/status")
        status_items = status_response.get("data", {}).get("affected_items", [])

        if not status_items:
            return _compact_json({
                "status": "error",
                "message": "Unable to retrieve cluster status"
            })

        status_info = status_items[0]
        cluster_enabled = status_info.get("enabled", "no").lower() == "yes"
        cluster_running = status_info.get("running", "no").lower() == "yes"

        health_assessment = {
            "is_healthy": cluster_enabled and cluster_running,
            "enabled": cluster_enabled,
            "running": cluster_running
        }

        # Check node connectivity if cluster is operational
        if cluster_enabled and cluster_running:
            try:
                health_response = query_manager_api("/cluster/healthcheck")
                health_items = health_response.get("data", {}).get("affected_items", [])
                if health_items:
                    connected_count = health_items[0].get("n_connected_nodes", 0)
                    health_assessment["connected_nodes"] = connected_count
                    if connected_count == 0:
                        health_assessment["is_healthy"] = False
                        health_assessment["health_issue"] = "No nodes connected"
            except Exception:
                pass
        elif not cluster_enabled:
            health_assessment["health_issue"] = "Cluster not enabled"
        elif not cluster_running:
            health_assessment["health_issue"] = "Cluster not running"

        return _compact_json({
            "status": "success",
            "cluster_health": health_assessment
        })

    except Exception as error:
        logger.error(f"Cluster health check failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to check cluster health: {str(error)}"
        })

@mcp_server.tool()
def get_wazuh_cluster_nodes(max_results: Optional[int] = None, skip_count: int = 0,
                           node_type_filter: Optional[str] = None) -> str:
    """List Wazuh cluster nodes with type, version, IP, and status.

    Args:
        max_results: Max nodes (API default 500).
        skip_count: Nodes to skip (default 0).
        node_type_filter: "master" or "worker".

    Returns:
        JSON: {status, total_count, nodes:[{node_name, node_type, version, ip_address, status}]}
    """
    logger.info(f"Fetching cluster nodes (max={max_results}, type={node_type_filter})")

    try:
        api_params = {"offset": skip_count}
        if max_results is not None:
            api_params["limit"] = max_results
        if node_type_filter:
            api_params["type"] = node_type_filter

        api_response = query_manager_api("/cluster/nodes", query_params=api_params)

        node_items = api_response.get("data", {}).get("affected_items", [])

        if not node_items:
            return _compact_json({
                "status": "success",
                "message": "No cluster nodes found",
                "total_count": 0,
                "nodes": []
            })

        processed_nodes = []
        for node_entry in node_items:
            node_status = node_entry.get("status", "unknown")

            # Map status to display format
            status_map = {
                "connected": "CONNECTED",
                "active": "CONNECTED",
                "disconnected": "DISCONNECTED"
            }
            display_status = status_map.get(node_status.lower(), node_status.upper())

            processed_nodes.append({
                "node_name": node_entry.get("name", "N/A"),
                "node_type": node_entry.get("type", "N/A"),
                "version": node_entry.get("version", "N/A"),
                "ip_address": node_entry.get("ip", "N/A"),
                "status": display_status
            })

        return _compact_json({
            "status": "success",
            "total_count": len(processed_nodes),
            "nodes": processed_nodes
        })

    except Exception as error:
        logger.error(f"Cluster node retrieval failed: {error}")
        return _compact_json({
            "status": "error",
            "message": f"Failed to retrieve cluster nodes: {str(error)}"
        })

# ─────────────────── Utility Tools ───────────────────

@mcp_server.tool()
def health_check() -> str:
    """Test connectivity to Wazuh Manager and Indexer. Returns response times, cache stats, and config.

    Returns:
        JSON: {overall_status, timestamp, manager_api:{status,response_time_ms}, indexer_api:{status,response_time_ms}, cache, configuration}
    """
    logger.info("Executing health check")

    try:
        # Test Manager API
        manager_start = time.time()
        query_manager_api("/", enable_cache=False)
        manager_latency = time.time() - manager_start

        # Test Indexer API
        indexer_start = time.time()
        query_indexer_api("/", enable_cache=False)
        indexer_latency = time.time() - indexer_start

        # Get cache metrics
        cache_metrics = memory_cache.get_statistics()

        health_report = {
            "overall_status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "manager_api": {
                "status": "operational",
                "response_time_ms": round(manager_latency * 1000, 2),
                "endpoint": f"{wazuh_config.protocol}://{wazuh_config.manager_host}:{wazuh_config.manager_port}"
            },
            "indexer_api": {
                "status": "operational",
                "response_time_ms": round(indexer_latency * 1000, 2),
                "endpoint": f"{wazuh_config.protocol}://{wazuh_config.indexer_host}:{wazuh_config.indexer_port}"
            },
            "cache": cache_metrics,
            "configuration": {
                "request_timeout": wazuh_config.request_timeout,
                "retry_attempts": wazuh_config.retry_attempts,
                "ssl_verification": wazuh_config.use_ssl
            }
        }

        return _compact_json(health_report)

    except Exception as error:
        return _compact_json({
            "overall_status": "unhealthy",
            "error": str(error),
            "timestamp": datetime.now().isoformat()
        })

@mcp_server.tool()
def clear_cache() -> str:
    """Clear all cached API responses. Forces fresh data on next request.

    Returns:
        JSON: {status, message}
    """
    logger.info("Clearing cache")
    memory_cache.invalidate_all()
    return _compact_json({
        "status": "success",
        "message": "Cache cleared successfully"
    })

@mcp_server.tool()
def cache_stats() -> str:
    """Get cache usage info (total entries, valid entries, TTL).

    Returns:
        JSON: {status, cache_statistics:{total_entries, valid_entries, ttl_seconds}}
    """
    logger.info("Retrieving cache statistics")
    cache_metrics = memory_cache.get_statistics()
    return _compact_json({
        "status": "success",
        "cache_statistics": cache_metrics
    })

# ═══════════════════════ CLI Argument Parser ═══════════════════════

def parse_cli_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Wazuh SIEM MCP Server - FastMCP Integration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage Examples:

  Command Line Configuration:
    python3 mcp_wazuh.py \\
      --manager-host 192.168.1.100 --manager-user wazuh --manager-pass wazuh \\
      --indexer-host 192.168.1.100 --indexer-user admin --indexer-pass admin

  Environment Variables:
    export WAZUH_MANAGER_HOST=192.168.1.100
    export WAZUH_MANAGER_USER=wazuh
    export WAZUH_MANAGER_PASS=wazuh
    python3 mcp_wazuh.py

  Mixed Configuration:
    WAZUH_MANAGER_HOST=192.168.1.100 python3 mcp_wazuh.py \\
      --manager-user wazuh --manager-pass wazuh

  Streamable HTTP Transport (network-based / multi-client):
    python3 mcp_wazuh.py --transport streamable-http --host 0.0.0.0 --port 8000 \\
      --manager-host 192.168.1.100 --manager-user wazuh --manager-pass wazuh \\
      --indexer-host 192.168.1.100 --indexer-user admin --indexer-pass admin
        """
    )

    # Manager configuration
    mgr_group = parser.add_argument_group('Wazuh Manager API Configuration')
    mgr_group.add_argument('--manager-host', help='Manager hostname or IP')
    mgr_group.add_argument('--manager-port', type=int, help='Manager port (default: 55000)')
    mgr_group.add_argument('--manager-user', help='Manager username')
    mgr_group.add_argument('--manager-pass', help='Manager password')

    # Indexer configuration
    idx_group = parser.add_argument_group('Wazuh Indexer Configuration')
    idx_group.add_argument('--indexer-host', help='Indexer hostname or IP')
    idx_group.add_argument('--indexer-port', type=int, help='Indexer port (default: 9200)')
    idx_group.add_argument('--indexer-user', help='Indexer username')
    idx_group.add_argument('--indexer-pass', help='Indexer password')

    # Connection settings
    conn_group = parser.add_argument_group('Connection Settings')
    conn_group.add_argument('--use-ssl', type=lambda x: x.lower() in ('true', '1', 'yes'),
                           help='Enable SSL verification (default: false)')
    conn_group.add_argument('--protocol', choices=['http', 'https'],
                           help='Connection protocol (default: https)')

    # Performance settings
    perf_group = parser.add_argument_group('Performance Settings')
    perf_group.add_argument('--cache-duration', type=int,
                           help='Cache duration in seconds (default: 300)')
    perf_group.add_argument('--request-timeout', type=int,
                           help='Request timeout in seconds (default: 30)')
    perf_group.add_argument('--retry-attempts', type=int,
                           help='Retry attempts for failed requests (default: 3)')

    # Transport settings
    transport_group = parser.add_argument_group('MCP Transport Settings')
    transport_group.add_argument('--transport', choices=['stdio', 'streamable-http'],
                                default='stdio',
                                help='MCP transport type (default: stdio)')
    transport_group.add_argument('--host', default='0.0.0.0',
                                help='HTTP server host for streamable-http (default: 0.0.0.0)')
    transport_group.add_argument('--port', type=int, default=8000,
                                help='HTTP server port for streamable-http (default: 8000)')

    return parser.parse_args()

# ═══════════════════════ Main Entry Point ═══════════════════════

if __name__ == "__main__":
    # Parse CLI arguments
    cli_args = parse_cli_arguments()

    # Initialize configuration
    wazuh_config = WazuhConfig(cli_args)

    # Initialize cache and HTTP sessions
    memory_cache = MemoryCache(wazuh_config.cache_duration)
    setup_http_sessions()

    # Display startup banner
    logger.info("=" * 80)
    logger.info("Wazuh SIEM MCP Server v1.2.0")
    logger.info("=" * 80)
    logger.info("Reference: Inspired by mcp-server-wazuh (Rust) by Gianluca Brigandi")
    logger.info("=" * 80)
    logger.info("Core Capabilities:")
    logger.info("  ✓ Real-time security alert monitoring")
    logger.info("  ✓ Comprehensive vulnerability assessment")
    logger.info("  ✓ Agent lifecycle management")
    logger.info("  ✓ Security rule configuration and compliance")
    logger.info("  ✓ System statistics and performance monitoring")
    logger.info("  ✓ Advanced log analysis and forensics")
    logger.info("  ✓ Cluster health monitoring")
    logger.info("  ✓ Multi-framework compliance (GDPR, HIPAA, PCI DSS, NIST)")
    logger.info("=" * 80)
    logger.info("Available Tools (17 total):")
    logger.info("  • health_check() - Connectivity diagnostics")
    logger.info("  • get_wazuh_alert_summary() - Security alerts")
    logger.info("  • get_wazuh_alert_statistics() - Alert statistics")
    logger.info("  • get_wazuh_agents_with_alerts() - Agents with alerts")
    logger.info("  • get_wazuh_rules_summary() - Detection rules")
    logger.info("  • get_wazuh_vulnerability_summary() - Vulnerability assessment")
    logger.info("  • get_wazuh_agents() - Agent inventory")
    logger.info("  • get_wazuh_agent_processes() - Process monitoring")
    logger.info("  • get_wazuh_agent_ports() - Network port analysis")
    logger.info("  • search_wazuh_manager_logs() - Log search")
    logger.info("  • get_wazuh_log_collector_stats() - Collection metrics")
    logger.info("  • get_wazuh_remoted_stats() - Daemon statistics")
    logger.info("  • get_wazuh_weekly_stats() - Weekly aggregates")
    logger.info("  • get_wazuh_cluster_health() - Cluster status")
    logger.info("  • get_wazuh_cluster_nodes() - Node inventory")
    logger.info("  • clear_cache() / cache_stats() - Cache management")
    logger.info("=" * 80)
    logger.info(f"Configuration:")
    logger.info(f"  Cache: {wazuh_config.cache_duration}s | Timeout: {wazuh_config.request_timeout}s")
    logger.info(f"  Retries: {wazuh_config.retry_attempts} | SSL: {wazuh_config.use_ssl}")
    logger.info(f"  Transport: {cli_args.transport}")
    if cli_args.transport == "streamable-http":
        logger.info(f"  HTTP endpoint: http://{cli_args.host}:{cli_args.port}/mcp")
    logger.info("=" * 80)

    # Start MCP server with selected transport
    if cli_args.transport == "streamable-http":
        mcp_server.run(
            transport="streamable-http",
            host=cli_args.host,
            port=cli_args.port,
        )
    else:
        mcp_server.run(transport="stdio")
