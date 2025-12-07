#!/usr/bin/env python3
"""
MCP server for Wazuh SIEM API - v1.0.0
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
python3 mcp_wazuh.py --help
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
        "User-Agent": "wazuh-mcp-server/1.0.0"
    })
    manager_http_session.verify = wazuh_config.use_ssl

    # Indexer session with Basic Authentication
    indexer_http_session = requests.Session()
    indexer_http_session.auth = (wazuh_config.indexer_user, wazuh_config.indexer_pass)
    indexer_http_session.headers.update({
        "Content-Type": "application/json",
        "User-Agent": "wazuh-mcp-server/1.0.0"
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
    """Retrieve security alerts from Wazuh Indexer with comprehensive filtering and pagination

    Fetches recent security alerts with support for extensive filtering including severity,
    time range, agent info, rules, MITRE ATT&CK, vulnerabilities, and network/system events.
    Includes IoC (Indicators of Compromise) extraction for threat intelligence.

    **IMPORTANT - Pagination Support:**
    This function returns a limited number of results per call. Use pagination to retrieve
    large datasets in multiple requests. The response includes:
    - pagination.total_matches: Total alerts matching your filters
    - pagination.returned_count: Alerts in this response
    - pagination.has_more: Boolean - are there more results?
    - pagination.next_offset: Value to use for next request

    **How to use pagination:**
    1. First request: get_wazuh_alert_summary(max_results=300, offset=0, ...)
    2. Check response.pagination.has_more
    3. If true, next request: get_wazuh_alert_summary(max_results=300, offset=300, ...)
    4. Repeat until has_more = false

    Args:
        max_results: Maximum number of alerts to fetch per page (default: 300, max: 10000)
            - Recommended: 100-500 for better performance
            - Elasticsearch hard limit: 10000 per request
            - For large queries, use multiple paginated requests

        offset: Number of alerts to skip for pagination (default: 0)
            - Page 1: offset=0
            - Page 2: offset=300 (if max_results=300)
            - Page 3: offset=600, etc.
            - Use pagination.next_offset from previous response
        min_level: Minimum alert level to filter (optional)
            **Wazuh Alert Level Classification (0-15):**
            - Level 0-3: Low severity (informational events)
            - Level 4-7: Medium severity (events requiring attention)
            - Level 8-11: High severity (important events)
            - Level 12-15: Critical/Emergency (requires immediate action)

            Examples: min_level=12 for critical alerts, min_level=8 for high+ alerts
        max_level: Maximum alert level to filter (e.g., 15) (optional)
        time_range_hours: Time range in hours to look back (e.g., 72 for 3 days) (optional)
        agent_name: Filter by agent name (optional)
        agent_id: Filter by agent ID (optional)
        agent_ip: Filter by agent IP address (optional)
        rule_id: Filter by specific rule ID (e.g., "5710") (optional)
        rule_group: Filter by rule group - **supports partial matching** (optional)
            - Examples: "authentication", "web", "syscheck", "jason_tools_ioc"
            - Searching "jason" will find "jason_tools_ioc" group
            - Case-insensitive
        rule_description: Search in rule description - **supports partial matching** (optional)
            - Searching "IoC" will find "Jason Tools IOC: Malicious..."
            - Case-insensitive
        mitre_technique: Filter by MITRE ATT&CK technique ID (e.g., "T1078") (optional)
        mitre_tactic: Filter by MITRE ATT&CK tactic (e.g., "Initial Access") (optional)
        min_cvss_score: Minimum CVSS score for vulnerability alerts (e.g., 7.0) (optional)
        cve_id: Filter by specific CVE ID (e.g., "CVE-2021-44228") (optional)
        source_ip: Filter by source IP address (optional)
        destination_ip: Filter by destination IP address (optional)
        user: Filter by username (optional)
        process_name: Filter by process name (optional)
        file_path: Filter by file path (optional)

    Returns:
        JSON object with:
        - status: "success" or "error"
        - pagination: Object with pagination info:
            - offset: Current offset value
            - page_size: Requested max_results
            - returned_count: Number of alerts in this response
            - total_matches: Total alerts matching filters (across all pages)
            - has_more: Boolean - true if more pages available
            - next_offset: Offset value for next page (if has_more=true)
        - alerts: Array of alert objects, each containing:
            - alert_id: Unique alert identifier
            - timestamp: When the alert occurred
            - agent_name: Name of the agent that generated alert
            - agent_id: Agent identifier (e.g., "031")
            - severity_level: Alert level (0-15, higher=more critical)
            - rule_id: Wazuh rule ID that triggered
            - rule_groups: Array of rule group classifications
            - description: Human-readable alert description
            - ioc: (Optional) IoC data if alert contains threat indicators:
                - source_ip, destination_ip: IP addresses
                - md5_hash, sha1_hash, sha256_hash: File hashes
                - url, domain: Web-based threats
                - process_name, process_path, process_cmdline: Process info
                - file_path: File system paths
                - username: User account names
                - destination_port, source_port: Network ports
                - mitre_attack: MITRE ATT&CK techniques and tactics
                - virustotal: VirusTotal scan results (positives, total, permalink)

    **Examples:**

    1. Get first page of critical alerts (last 24 hours):
       get_wazuh_alert_summary(min_level=12, time_range_hours=24, max_results=100)

    2. Pagination example - getting all authentication alerts:
       # First page
       response1 = get_wazuh_alert_summary(rule_group="authentication", max_results=300, offset=0)
       # If response1.pagination.has_more is true:
       response2 = get_wazuh_alert_summary(rule_group="authentication", max_results=300, offset=300)
       # Continue until has_more = false

    3. Find alerts with IoC data (malicious IPs, hashes, etc.):
       get_wazuh_alert_summary(min_level=8, rule_group="threat-detection", time_range_hours=168)

    4. Complex filter - SSH authentication failures from specific IP:
       get_wazuh_alert_summary(
           rule_group="authentication",
           source_ip="192.168.1.100",
           time_range_hours=24,
           min_level=4
       )

    5. Vulnerability alerts with high CVSS scores:
       get_wazuh_alert_summary(cve_id="CVE-2021-44228", min_cvss_score=7.0)
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
            return json.dumps({
                "status": "success",
                "message": "No security alerts found matching the criteria",
                "pagination": {
                    "offset": offset,
                    "page_size": max_results,
                    "returned_count": 0,
                    "total_matches": total_count
                },
                "alerts": []
            }, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

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

        return json.dumps({
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
        }, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

    except Exception as error:
        logger.error(f"Alert retrieval failed: {error}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to retrieve alerts: {str(error)}"
        }, indent=2, ensure_ascii=False)

@mcp_server.tool()
def get_wazuh_alert_statistics(time_range_hours: Optional[int] = 24,
                               agent_name: Optional[str] = None,
                               agent_id: Optional[str] = None,
                               rule_group: Optional[str] = None,
                               rule_id: Optional[str] = None,
                               rule_description: Optional[str] = None) -> str:
    """Get alert statistics summary without detailed alert data (lightweight, token-efficient)

    **Primary Use Cases:**
    - Quick overview of alert volume and severity distribution
    - Check overall security posture without loading detailed alert data
    - Efficient way to get total counts before fetching detailed alerts
    - Ideal for dashboards and periodic status checks

    **When to Use This Tool:**
    - User asks "how many alerts in the last 24 hours?"
    - User wants "alert statistics" or "alert distribution"
    - Before loading detailed alerts, check if there are many alerts
    - When you need statistics only (saves tokens vs get_wazuh_alert_summary)

    **Advantages over get_wazuh_alert_summary:**
    - Much lighter response (only statistics, no alert details)
    - Uses significantly fewer tokens
    - Faster execution (uses Elasticsearch aggregations)
    - Perfect for getting counts before deciding to fetch details

    Args:
        time_range_hours: Time window to analyze in hours (default: 24)
            - Examples: 24 (last day), 72 (3 days), 168 (week)
            - If omitted, defaults to 24 hours

        agent_name: Filter by agent name (optional)
            - Example: "ubuntu22-pro", "host-114", "mail1"
            - If omitted, includes all agents
            - Can use with agent_id for precise filtering

        agent_id: Filter by agent ID (optional)
            - Example: "031", "001"
            - If omitted, includes all agents
            - Can use with agent_name for precise filtering

        rule_group: Filter by rule group (optional)
            - Examples: "authentication", "web", "syscheck", "threat-detection", "jason_tools_ioc"
            - **Supports partial matching** - searching "jason" will find "jason_tools_ioc"
            - Case-insensitive matching
            - If omitted, includes all rule groups
            - Very useful when user doesn't know exact group name

        rule_id: Filter by specific rule ID (optional)
            - Example: "5715", "5503"
            - If omitted, includes all rules
            - Exact match only

        rule_description: Filter by rule description keywords (optional)
            - Example: "IoC", "threat", "malicious", "brute force"
            - **Supports partial matching** - searches for keyword within description
            - Case-insensitive matching
            - If omitted, includes all rule descriptions
            - Very useful when user doesn't know exact rule name

    Returns:
        JSON object with:
        - status: "success" or "error"
        - time_range_hours: Time window analyzed
        - total_alerts: Total number of alerts in time range
        - severity_distribution: Statistics by alert level:
            - critical_emergency (12-15): count and percentage
            - high (8-11): count and percentage
            - medium (4-7): count and percentage
            - low (0-3): count and percentage
        - top_agents: Top 10 agents by alert count (if not filtered by agent)
        - top_rules: Top 10 triggered rules

    **Examples:**

    1. Quick 24h overview:
       get_wazuh_alert_statistics()

    2. Last week statistics:
       get_wazuh_alert_statistics(time_range_hours=168)

    3. Specific agent statistics by name:
       get_wazuh_alert_statistics(agent_name="host-114", time_range_hours=24)

    4. Specific agent statistics by ID:
       get_wazuh_alert_statistics(agent_id="031", time_range_hours=24)

    5. Authentication alerts statistics:
       get_wazuh_alert_statistics(rule_group="authentication", time_range_hours=72)

    6. IoC-related alerts for specific agent:
       get_wazuh_alert_statistics(agent_name="ubuntu22-pro", rule_group="threat-detection", time_range_hours=24)

    7. Search by partial rule group name (finds "jason_tools_ioc" group):
       get_wazuh_alert_statistics(rule_group="jason", time_range_hours=24)

    8. Alerts containing "IoC" in rule description:
       get_wazuh_alert_statistics(rule_description="IoC", time_range_hours=24)

    9. Specific rule statistics:
       get_wazuh_alert_statistics(rule_id="5715", time_range_hours=168)

    10. Brute force attack statistics:
        get_wazuh_alert_statistics(rule_description="brute force", time_range_hours=24)

    11. Combined filters - IoC alerts from specific agent:
        get_wazuh_alert_statistics(agent_name="host-114", rule_description="threat", time_range_hours=24)

    **Workflow Example:**
    Step 1: get_wazuh_alert_statistics(rule_description="IoC", time_range_hours=24)
            → See there are 50 alerts with "IoC" in description, top agent is "host-114"
    Step 2: get_wazuh_alert_statistics(agent_name="host-114", rule_description="IoC", time_range_hours=24)
            → See detailed statistics for IoC alerts from this specific agent
    Step 3: get_wazuh_alert_summary(agent_name="host-114", rule_description="IoC", time_range_hours=24, max_results=15)
            → Get detailed information with actual IoC data (IPs, hashes, etc.)
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

        return json.dumps({
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
        }, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

    except Exception as error:
        logger.error(f"Alert statistics retrieval failed: {error}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to retrieve alert statistics: {str(error)}"
        }, indent=2, ensure_ascii=False)

@mcp_server.tool()
def get_wazuh_agents_with_alerts(min_level: Optional[int] = None,
                                time_range_hours: Optional[int] = None,
                                max_agents: int = 100) -> str:
    """Aggregate and list agents that have security alerts matching specified criteria

    **Primary Use Cases:**
    - Identify which agents are experiencing security events
    - Find agents with high-severity alerts requiring immediate attention
    - Analyze alert distribution across your infrastructure
    - Quickly answer questions like "which servers had critical alerts in the last 24 hours?"

    **When to Use This Tool:**
    - User asks "which agents/servers/hosts have alerts?"
    - User wants to know "what systems are affected by X severity alerts?"
    - User asks to "list machines with problems"
    - Before diving into detailed alerts, get an overview of affected systems

    **How It Works:**
    This tool performs Elasticsearch aggregation on Wazuh alerts, grouping by agent
    and returning statistics per agent including alert count, highest severity level,
    and most recent alert. Much more efficient than fetching all alerts.

    Args:
        min_level: Minimum alert level to filter (optional)
            **Wazuh Alert Level Classification (0-15):**
            - Level 0-3: Low severity (informational events)
            - Level 4-7: Medium severity (events requiring attention)
            - Level 8-11: High severity (important events)
            - Level 12-15: Critical/Emergency (requires immediate action)

            Examples:
            - min_level=12: Returns only agents with critical/emergency alerts
            - min_level=8: Returns agents with high severity or above
            - If omitted, includes alerts of all severity levels

        time_range_hours: Time window to analyze in hours (optional)
            - Examples: 24 (last day), 72 (last 3 days), 168 (last week)
            - If omitted, searches all available alert history
            - Recommended to specify for better performance

        max_agents: Maximum number of agents to return (default: 100)
            - Results ordered by alert count (descending)
            - Returns agents with most alerts first

    Returns:
        JSON object containing:
        - status: "success" or "error"
        - total_agents: Number of agents found
        - filter_criteria: Applied filters for reference
        - agents: Array of agent objects, each with:
            - agent_name: Agent hostname
            - agent_id: Agent identifier
            - alert_count: Total matching alerts for this agent
            - max_severity_level: Highest alert level seen
            - most_recent_alert: Details of the latest alert (timestamp, description, level)

    **Examples:**

    1. Find agents with critical/emergency alerts in last 3 days:
       get_wazuh_agents_with_alerts(min_level=12, time_range_hours=72)

    2. Get all agents with any alerts in last 24 hours:
       get_wazuh_agents_with_alerts(time_range_hours=24)

    3. Find top 10 agents with high severity+ events (level 8+):
       get_wazuh_agents_with_alerts(min_level=8, max_agents=10)

    4. Find agents with medium severity+ alerts in last week:
       get_wazuh_agents_with_alerts(min_level=4, time_range_hours=168)
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
        if must_clauses:
            agg_query = {
                "size": 0,  # We only need aggregation results
                "query": {
                    "bool": {
                        "must": must_clauses
                    }
                },
                "aggs": {
                    "agents": {
                        "terms": {
                            "field": "agent.name",
                            "size": max_agents,
                            "order": {"_count": "desc"}
                        },
                        "aggs": {
                            "agent_id": {
                                "terms": {
                                    "field": "agent.id",
                                    "size": 1
                                }
                            },
                            "max_level": {
                                "max": {
                                    "field": "rule.level"
                                }
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
        else:
            agg_query = {
                "size": 0,
                "query": {"match_all": {}},
                "aggs": {
                    "agents": {
                        "terms": {
                            "field": "agent.name",
                            "size": max_agents,
                            "order": {"_count": "desc"}
                        },
                        "aggs": {
                            "agent_id": {
                                "terms": {
                                    "field": "agent.id",
                                    "size": 1
                                }
                            },
                            "max_level": {
                                "max": {
                                    "field": "rule.level"
                                }
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
            return json.dumps({
                "status": "success",
                "message": "No agents found with alerts matching the criteria",
                "total_agents": 0,
                "agents": []
            }, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

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

        return json.dumps({
            "status": "success",
            "total_agents": len(processed_agents),
            "filter_criteria": {
                "min_level": min_level,
                "time_range_hours": time_range_hours
            },
            "agents": processed_agents
        }, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

    except Exception as error:
        logger.error(f"Agent alert analysis failed: {error}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to analyze agents: {str(error)}"
        }, indent=2, ensure_ascii=False)

# ─────────────────── Security Rules Tools ───────────────────

@mcp_server.tool()
def get_wazuh_rules_summary(max_results: int = 300,
                           offset: int = 0,
                           min_level: Optional[int] = None,
                           rule_group: Optional[str] = None,
                           rule_file: Optional[str] = None) -> str:
    """Retrieve and search Wazuh security detection rules configuration

    **Primary Use Cases:**
    - Understand what security detections are configured in Wazuh
    - Search for specific rules by ID, group, or severity
    - Review compliance mappings (GDPR, HIPAA, PCI-DSS, NIST)
    - Audit active detection rules
    - Find rules related to specific attack types or compliance requirements

    **When to Use This Tool:**
    - User asks "what rules are configured?"
    - User wants to know "show me authentication rules"
    - User asks "what rules detect SQL injection?"
    - User needs compliance audit information
    - Before creating custom rules, check existing ones

    **Rule Groups (Common Values):**
    - "authentication" - Login/authentication events
    - "web" - Web attacks (SQL injection, XSS, etc.)
    - "syscheck" - File integrity monitoring
    - "vulnerability-detector" - Vulnerability scanning
    - "firewall" - Firewall events
    - "ids" - Intrusion detection
    - "malware" - Malware detection
    - "pci_dss" - PCI-DSS compliance
    - "gdpr" - GDPR compliance

    Args:
        max_results: Maximum rules per page (default: 300, recommended: 100-500)
            - Wazuh has thousands of rules, use pagination
            - Use filters to narrow down results

        offset: Pagination offset (default: 0)
            - Skip this many rules for next page
            - Example: offset=300 gets rules 301-600

        min_level: Minimum severity level filter (optional)
            **Wazuh Alert Level Classification (0-15):**
            - Level 0-3: Low severity (informational events)
            - Level 4-7: Medium severity (events requiring attention)
            - Level 8-11: High severity (important events)
            - Level 12-15: Critical/Emergency (requires immediate action)

            Examples:
            - min_level=12: Shows only critical/emergency rules
            - min_level=8: Shows high severity and above rules

        rule_group: Filter by rule group name (optional)
            - Exact match on group name
            - Examples: "authentication", "web", "syscheck"
            - See "Rule Groups" section above for common values

        rule_file: Filter by rule filename (optional)
            - Examples: "0010-rules_config.xml", "0095-sshd_rules.xml"
            - Useful for finding rules in specific rule files

    Returns:
        JSON object with:
        - status: "success" or "error"
        - pagination: offset, page_size, returned_count, total_matches, has_more
        - rules: Array of rule objects with:
            - rule_id: Unique rule identifier (e.g., "5710")
            - severity_level: Numeric level (0-15)
            - severity_category: "Low", "Medium", "High", or "Critical"
            - description: What the rule detects
            - groups: Array of group classifications
            - filename: Source rule file
            - status: "enabled" or "disabled"
            - compliance: GDPR, HIPAA, PCI-DSS, NIST mappings (if applicable)

    **Examples:**

    1. Find all authentication-related rules:
       get_wazuh_rules_summary(rule_group="authentication", max_results=100)

    2. Get critical severity rules:
       get_wazuh_rules_summary(min_level=13, max_results=50)

    3. Find web attack detection rules:
       get_wazuh_rules_summary(rule_group="web")

    4. Browse all rules with pagination:
       get_wazuh_rules_summary(max_results=100, offset=0)  # First page
       get_wazuh_rules_summary(max_results=100, offset=100)  # Second page
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
            return json.dumps({
                "status": "success",
                "message": "No rules match the specified criteria",
                "pagination": {
                    "offset": offset,
                    "page_size": max_results,
                    "returned_count": 0,
                    "total_matches": total_items
                },
                "rules": []
            }, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

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

        return json.dumps({
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
        }, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

    except Exception as error:
        logger.error(f"Rule retrieval failed: {error}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to retrieve rules: {str(error)}"
        }, indent=2, ensure_ascii=False)

# ─────────────────── Vulnerability Assessment Tools ───────────────────

@mcp_server.tool()
def get_wazuh_vulnerability_summary(agent_identifier: str,
                                   max_results: int = 500,
                                   offset: int = 0,
                                   severity_filter: Optional[str] = None,
                                   cve_filter: Optional[str] = None) -> str:
    """Get complete vulnerability scan results for a specific agent/server

    **Primary Use Cases:**
    - Security vulnerability assessment for a specific server/agent
    - Identify all CVEs affecting a particular system
    - Prioritize patching based on CVSS scores and severity
    - Compliance reporting (track vulnerability remediation)
    - Answer "what vulnerabilities does server X have?"

    **When to Use This Tool:**
    - User asks "what vulnerabilities are on server X?"
    - User wants CVE details for a specific agent
    - User asks "does server X have CVE-YYYY-NNNNN?"
    - User wants to prioritize patching for a specific system
    - Security audit or compliance check required

    **Important Notes:**
    - Requires Wazuh vulnerability detector module enabled
    - Results based on installed packages vs. NVD database
    - CVSS scores from NVD (National Vulnerability Database)
    - Detection happens periodically (not real-time)

    Args:
        agent_identifier: Agent ID to check (REQUIRED)
            - Format: "0" (Manager), "1", "001", etc.
            - Single-digit numbers auto-padded: "1" becomes "001"
            - Get agent IDs using get_wazuh_agents() first
            - Example: "005" for agent 5

        max_results: Vulnerabilities per page (default: 500, max recommended: 1000)
            - Servers may have hundreds/thousands of vulnerabilities
            - Use pagination for large results
            - Combine with severity_filter to reduce results

        offset: Pagination offset (default: 0)
            - Skip this many vulnerabilities
            - Example: offset=500 gets vulnerabilities 501-1000

        severity_filter: Filter by severity level (optional)
            - Valid values: "Low", "Medium", "High", "Critical"
            - Case-sensitive exact match
            - Examples:
                - severity_filter="Critical" - Only critical CVEs
                - severity_filter="High" - Only high severity
            - Use this to focus on most important vulnerabilities first

        cve_filter: Search for specific CVE ID (optional)
            - Format: "CVE-YYYY-NNNNN"
            - Example: "CVE-2021-44228" (Log4Shell)
            - Partial match supported
            - Use to check if specific vulnerability exists

    Returns:
        JSON object with:
        - status: "success" or "error"
        - agent_id: Queried agent identifier
        - pagination: offset, page_size, returned_count, total_matches, has_more
        - vulnerabilities: Array of vulnerability objects with:
            - cve_id: CVE identifier (e.g., "CVE-2021-44228")
            - severity: CRITICAL/HIGH/MEDIUM/LOW
            - title: Brief vulnerability description
            - description: Detailed description
            - published_date: When CVE was published
            - updated_date: Last CVE update
            - detected_at: When Wazuh detected it
            - cvss_scores: CVSS2_Score and/or CVSS3_Score (if available)
            - reference_url: Link to more information

    **Examples:**

    1. Check all vulnerabilities on web server (agent 5):
       get_wazuh_vulnerability_summary(agent_identifier="5")

    2. Get only critical vulnerabilities:
       get_wazuh_vulnerability_summary(agent_identifier="10", severity_filter="Critical")

    3. Check if Log4Shell affects server:
       get_wazuh_vulnerability_summary(agent_identifier="5", cve_filter="CVE-2021-44228")

    4. Get high-severity vulnerabilities with pagination:
       get_wazuh_vulnerability_summary(agent_identifier="3", severity_filter="High", max_results=100, offset=0)

    5. Check Wazuh Manager itself (agent 0):
       get_wazuh_vulnerability_summary(agent_identifier="0")
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
            return json.dumps({
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
            }, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

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

        return json.dumps({
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
        }, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

    except Exception as error:
        logger.error(f"Vulnerability retrieval failed: {error}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to retrieve vulnerabilities: {str(error)}"
        }, indent=2, ensure_ascii=False)

@mcp_server.tool()
def get_wazuh_critical_vulnerabilities(agent_identifier: str,
                                      max_results: int = 300,
                                      offset: int = 0) -> str:
    """Get ONLY critical-severity vulnerabilities requiring immediate attention

    **Primary Use Cases:**
    - Emergency response - identify critical CVEs needing immediate patching
    - Security triage - focus on highest-priority vulnerabilities first
    - Compliance - track critical vulnerability remediation
    - Quick critical CVE check without noise from lower severity issues

    **When to Use This Tool:**
    - User asks "what critical vulnerabilities does server X have?"
    - User wants only the most severe CVEs
    - Emergency: Check if server has any critical security issues
    - Monthly security review - prioritize critical vulns first
    - Use THIS instead of get_wazuh_vulnerability_summary when only interested in critical severity

    **Difference from get_wazuh_vulnerability_summary:**
    - THIS tool: Only returns CRITICAL severity vulnerabilities
    - get_wazuh_vulnerability_summary: Returns ALL severities (can filter)
    - Use this for faster, focused critical CVE analysis

    Args:
        agent_identifier: Agent ID to check (REQUIRED)
            - Format: "0" (Manager), "1", "001", etc.
            - Single-digit auto-padded: "5" → "005"
            - Get agent IDs using get_wazuh_agents() first

        max_results: Critical vulnerabilities per page (default: 300)
            - Most systems have fewer critical CVEs than total CVEs
            - 300 is usually sufficient for single server
            - Use pagination if server has 300+ critical CVEs

        offset: Pagination offset (default: 0)
            - Skip this many critical vulnerabilities
            - Example: offset=300 gets CVEs 301-600

    Returns:
        JSON object with:
        - status: "success" or "error"
        - agent_id: Queried agent identifier
        - pagination: offset, page_size, returned_count, total_matches, has_more
        - vulnerabilities: Array of CRITICAL vulnerability objects with:
            - severity: Always "CRITICAL"
            - cve_id: CVE identifier
            - title: Brief description
            - description: Detailed vulnerability info
            - published_date: CVE publication date
            - updated_date: Last CVE update
            - detected_at: When Wazuh detected it
            - cvss_scores: CVSS2/CVSS3 base scores (typically 9.0-10.0)
            - reference_url: Link to CVE details

    **Examples:**

    1. Emergency check - any critical CVEs on production server:
       get_wazuh_critical_vulnerabilities(agent_identifier="5")

    2. Check Wazuh Manager for critical vulnerabilities:
       get_wazuh_critical_vulnerabilities(agent_identifier="0")

    3. Get critical CVEs with pagination (if many):
       get_wazuh_critical_vulnerabilities(agent_identifier="10", max_results=100, offset=0)

    **Response Interpretation:**
    - If returned_count > 0: URGENT patching required
    - If returned_count = 0: No critical vulnerabilities (good!)
    - Check cvss_scores: 10.0 = maximum severity
    - Prioritize by published_date (older = more likely exploited)
    """
    logger.info(f"Fetching critical vulnerabilities for agent {agent_identifier} (max={max_results}, offset={offset})")

    try:
        # Normalize agent ID
        normalized_id = normalize_agent_identifier(agent_identifier)

        # Build Elasticsearch query for CRITICAL vulnerability alerts only
        search_query = {
            "size": max_results,
            "from": offset,
            "query": {
                "bool": {
                    "must": [
                        {"exists": {"field": "data.vulnerability"}},
                        {"term": {"agent.id": normalized_id}},
                        {"term": {"data.vulnerability.severity": "Critical"}}
                    ]
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
            return json.dumps({
                "status": "success",
                "message": f"No critical vulnerabilities found for agent {normalized_id}",
                "agent_id": normalized_id,
                "pagination": {
                    "offset": offset,
                    "page_size": max_results,
                    "returned_count": 0,
                    "total_matches": total_items
                },
                "vulnerabilities": []
            }, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

        processed_vulns = []
        for vuln_data in vuln_items:
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
                "severity": "CRITICAL",
                "cve_id": vuln_data.get("cve", "N/A"),
                "title": vuln_data.get("title", package_name),
                "description": f"Critical vulnerability in {package_name} {package_version}" if package_name != "N/A" else "No description",
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

        return json.dumps({
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
        }, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

    except Exception as error:
        logger.error(f"Critical vulnerability retrieval failed: {error}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to retrieve critical vulnerabilities: {str(error)}"
        }, indent=2, ensure_ascii=False)

# ─────────────────── Agent Management Tools ───────────────────

@mcp_server.tool()
def get_wazuh_agents(max_results: int = 300, status_filter: str = "active",
                    name_filter: Optional[str] = None, ip_filter: Optional[str] = None,
                    group_filter: Optional[str] = None, os_filter: Optional[str] = None,
                    version_filter: Optional[str] = None) -> str:
    """List and discover all Wazuh monitored agents/servers in your infrastructure

    **Primary Use Cases:**
    - Inventory management - see all monitored systems
    - Health monitoring - identify disconnected or problematic agents
    - Get agent IDs for use in other tools (vulnerabilities, alerts, etc.)
    - Find specific servers by name, IP, or OS
    - Audit agent versions and operating systems

    **When to Use This Tool:**
    - User asks "what servers/agents are monitored?"
    - User wants to "list all Linux servers"
    - User asks "is server X being monitored?"
    - User wants "show me disconnected agents"
    - PREREQUISITE: Use this first to get agent_id before calling other agent-specific tools
    - Infrastructure inventory audit

    **Important Notes:**
    - Agent ID "000" is always the Wazuh Manager itself
    - Active agents are healthy and reporting
    - Disconnected agents may indicate network issues or agent problems
    - Pending agents need manual approval to join

    Args:
        max_results: Maximum agents to return (default: 300)
            - Most environments have < 1000 agents
            - Increase if you have large infrastructure
            - Use filters to narrow results

        status_filter: Connection status filter (default: "active")
            - "active" - Currently connected and reporting (recommended default)
            - "disconnected" - Known agents not currently connected
            - "pending" - New agents waiting for approval
            - "never_connected" - Registered but never connected
            - "all" - All agents regardless of status

        name_filter: Filter by agent hostname (optional)
            - Partial match supported
            - Example: name_filter="web" matches "web-server-01", "web-server-02"
            - Case-sensitive

        ip_filter: Filter by IP address (optional)
            - Exact match required
            - Example: ip_filter="192.168.1.100"
            - Use for finding specific server by IP

        group_filter: Filter by agent group (optional)
            - Agents can be organized into groups
            - Example groups: "production", "development", "webservers"
            - Exact match required

        os_filter: Filter by operating system platform (optional)
            - Common values: "ubuntu", "centos", "windows", "darwin" (macOS)
            - Partial match supported
            - Example: os_filter="ubuntu" finds all Ubuntu systems

        version_filter: Filter by Wazuh agent version (optional)
            - Example: version_filter="4.7.0"
            - Useful for upgrade planning

    Returns:
        JSON object with:
        - status: "success" or "error"
        - total_agents: Number of agents found
        - agents: Array of agent objects with:
            - agent_id: Unique identifier (use this for other API calls)
            - agent_name: Hostname
            - ip_address: IP address
            - status: active/disconnected/pending/never_connected
            - os_platform: Operating system
            - os_version: OS version details
            - agent_version: Wazuh agent version
            - last_keepalive: Last communication time (ISO 8601)
            - groups: Array of group memberships
            - node_name: Wazuh cluster node managing this agent

    **Examples:**

    1. List all active (healthy) agents:
       get_wazuh_agents()

    2. Find disconnected agents requiring attention:
       get_wazuh_agents(status_filter="disconnected")

    3. Find specific server by name:
       get_wazuh_agents(name_filter="web-server")

    4. List all Windows servers:
       get_wazuh_agents(os_filter="windows")

    5. Find agent by IP address:
       get_wazuh_agents(ip_filter="192.168.1.100")

    6. List all agents (including disconnected):
       get_wazuh_agents(status_filter="all", max_results=1000)

    **Common Workflow:**
    1. Use get_wazuh_agents() to find server and get its agent_id
    2. Use agent_id in:
       - get_wazuh_vulnerability_summary(agent_id)
       - get_wazuh_alert_summary(agent_id=agent_id)
       - get_wazuh_agent_processes(agent_id)
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
            return json.dumps({
                "status": "success",
                "message": f"No agents found (status filter: {status_filter})",
                "total_count": 0,
                "agents": []
            }, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

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

        return json.dumps({
            "status": "success",
            "total_count": len(processed_agents),
            "agents": processed_agents
        }, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

    except Exception as error:
        logger.error(f"Agent retrieval failed: {error}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to retrieve agents: {str(error)}"
        }, indent=2, ensure_ascii=False)

@mcp_server.tool()
def get_wazuh_agent_processes(agent_identifier: str, max_results: int = 300,
                              search_filter: Optional[str] = None) -> str:
    """Retrieve running processes on specific agent

    Fetches process information via Syscollector including PIDs, process names,
    states, users, command lines, start times, and memory usage.

    Args:
        agent_identifier: Agent ID (e.g., "0", "1", "001")
        max_results: Maximum processes to retrieve (default: 300)
        search_filter: Filter by process name or command (optional)

    Returns:
        JSON formatted process list
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
            return json.dumps({
                "status": "success",
                "message": f"No process data available for agent {normalized_id}",
                "agent_id": normalized_id,
                "total_count": 0,
                "processes": []
            }, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

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

        return json.dumps({
            "status": "success",
            "agent_id": normalized_id,
            "total_count": len(processed_procs),
            "processes": processed_procs
        }, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

    except Exception as error:
        logger.error(f"Process retrieval failed: {error}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to retrieve processes: {str(error)}"
        }, indent=2, ensure_ascii=False)

@mcp_server.tool()
def get_wazuh_agent_ports(agent_identifier: str, max_results: int = 300,
                         protocol_filter: str = "", state_filter: str = "") -> str:
    """Retrieve network port information for specific agent

    Fetches network port details via Syscollector including local/remote addresses,
    ports, protocols, connection states, and associated processes.

    Args:
        agent_identifier: Agent ID (e.g., "001", "002", "003")
        max_results: Maximum ports to retrieve (default: 300)
        protocol_filter: Filter by protocol (tcp/udp) (optional)
        state_filter: Filter by state (LISTENING/ESTABLISHED) (optional)

    Returns:
        JSON formatted port list
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
            return json.dumps({
                "status": "success",
                "message": f"No network port data for agent {normalized_id}",
                "agent_id": normalized_id,
                "total_count": 0,
                "ports": []
            }, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

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

        return json.dumps({
            "status": "success",
            "agent_id": normalized_id,
            "total_count": len(processed_ports),
            "ports": processed_ports
        }, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

    except Exception as error:
        logger.error(f"Port retrieval failed: {error}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to retrieve ports: {str(error)}"
        }, indent=2, ensure_ascii=False)

# ─────────────────── Statistics & Monitoring Tools ───────────────────

@mcp_server.tool()
def search_wazuh_manager_logs(max_results: int = 300, skip_count: int = 0,
                             level_filter: str = "", tag_filter: Optional[str] = None,
                             keyword_search: Optional[str] = None) -> str:
    """Search Wazuh manager logs with filtering

    Retrieves manager log entries including timestamps, tags, severity levels,
    and descriptions for operational monitoring.

    Args:
        max_results: Maximum log entries to retrieve (default: 300)
        skip_count: Number of entries to skip (default: 0)
        level_filter: Filter by log level (error/warning/info) (optional)
        tag_filter: Filter by log tag (optional)
        keyword_search: Search term for descriptions (optional)

    Returns:
        JSON formatted log entries
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
            return json.dumps({
                "status": "success",
                "message": "No log entries match the search criteria",
                "total_count": 0,
                "logs": []
            }, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

        processed_logs = []
        for log_entry in log_items:
            processed_logs.append({
                "timestamp": log_entry.get("timestamp", "N/A"),
                "tag": log_entry.get("tag", "N/A"),
                "level": log_entry.get("level", "N/A"),
                "description": log_entry.get("description", "No description")
            })

        return json.dumps({
            "status": "success",
            "total_count": len(processed_logs),
            "logs": processed_logs
        }, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

    except Exception as error:
        logger.error(f"Log search failed: {error}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to search logs: {str(error)}"
        }, indent=2, ensure_ascii=False)

@mcp_server.tool()
def get_wazuh_manager_error_logs(max_results: int = 300) -> str:
    """Retrieve error-level manager logs

    Returns error-severity log entries for troubleshooting.

    Args:
        max_results: Maximum error log entries (default: 300)

    Returns:
        JSON formatted error logs
    """
    logger.info(f"Fetching error logs (max={max_results})")

    try:
        api_response = query_manager_api(
            "/manager/logs",
            query_params={"limit": max_results, "offset": 0, "level": "error"}
        )

        log_items = api_response.get("data", {}).get("affected_items", [])

        if not log_items:
            return json.dumps({
                "status": "success",
                "message": "No error logs found",
                "total_count": 0,
                "logs": []
            }, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

        processed_logs = []
        for log_entry in log_items:
            processed_logs.append({
                "timestamp": log_entry.get("timestamp", "N/A"),
                "tag": log_entry.get("tag", "N/A"),
                "level": "error",
                "description": log_entry.get("description", "No description")
            })

        return json.dumps({
            "status": "success",
            "total_count": len(processed_logs),
            "logs": processed_logs
        }, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

    except Exception as error:
        logger.error(f"Error log retrieval failed: {error}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to retrieve error logs: {str(error)}"
        }, indent=2, ensure_ascii=False)

@mcp_server.tool()
def get_wazuh_log_collector_stats(agent_identifier: str) -> str:
    """Retrieve log collector statistics for agent

    Provides detailed log collection statistics including events processed,
    bytes collected, and per-file metrics for global and interval periods.

    Args:
        agent_identifier: Agent ID (e.g., "0", "1", "001")

    Returns:
        JSON formatted log collector statistics
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
            return json.dumps({
                "status": "success",
                "message": f"No log collector stats for agent {normalized_id}",
                "agent_id": normalized_id
            }, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

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

        return json.dumps({
            "status": "success",
            "statistics": collector_stats
        }, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

    except Exception as error:
        logger.error(f"Log collector stats retrieval failed: {error}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to retrieve log collector stats: {str(error)}"
        }, indent=2, ensure_ascii=False)

@mcp_server.tool()
def get_wazuh_remoted_stats() -> str:
    """Retrieve remoted daemon statistics

    Provides manager-wide remoted daemon metrics including queue sizes,
    TCP sessions, message counts, and traffic statistics.

    Returns:
        JSON formatted remoted statistics
    """
    logger.info("Fetching remoted daemon statistics")

    try:
        api_response = query_manager_api("/manager/stats/remoted")

        stats_items = api_response.get("data", {}).get("affected_items", [])

        if not stats_items:
            return json.dumps({
                "status": "error",
                "message": "Remoted statistics unavailable"
            }, indent=2, ensure_ascii=False)

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

        return json.dumps({
            "status": "success",
            "statistics": remoted_metrics
        }, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

    except Exception as error:
        logger.error(f"Remoted stats retrieval failed: {error}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to retrieve remoted stats: {str(error)}"
        }, indent=2, ensure_ascii=False)

@mcp_server.tool()
def get_wazuh_weekly_stats() -> str:
    """Retrieve weekly aggregated statistics

    Provides comprehensive weekly metrics from the manager covering
    various performance indicators.

    Returns:
        JSON formatted weekly statistics
    """
    logger.info("Fetching weekly statistics")

    try:
        api_response = query_manager_api("/manager/stats/weekly")

        return json.dumps({
            "status": "success",
            "statistics": api_response.get("data", {})
        }, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

    except Exception as error:
        logger.error(f"Weekly stats retrieval failed: {error}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to retrieve weekly stats: {str(error)}"
        }, indent=2, ensure_ascii=False)

@mcp_server.tool()
def get_wazuh_cluster_health() -> str:
    """Check Wazuh cluster health status

    Returns cluster health assessment including enabled status,
    running state, and node connectivity.

    Returns:
        JSON formatted cluster health status
    """
    logger.info("Checking cluster health")

    try:
        # Retrieve cluster status
        status_response = query_manager_api("/cluster/status")
        status_items = status_response.get("data", {}).get("affected_items", [])

        if not status_items:
            return json.dumps({
                "status": "error",
                "message": "Unable to retrieve cluster status"
            }, indent=2, ensure_ascii=False)

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

        return json.dumps({
            "status": "success",
            "cluster_health": health_assessment
        }, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

    except Exception as error:
        logger.error(f"Cluster health check failed: {error}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to check cluster health: {str(error)}"
        }, indent=2, ensure_ascii=False)

@mcp_server.tool()
def get_wazuh_cluster_nodes(max_results: Optional[int] = None, skip_count: int = 0,
                           node_type_filter: Optional[str] = None) -> str:
    """List Wazuh cluster nodes

    Retrieves cluster node information including names, types, versions,
    IP addresses, and connection status.

    Args:
        max_results: Maximum nodes to retrieve (API default: 500)
        skip_count: Number of nodes to skip (default: 0)
        node_type_filter: Filter by node type (master/worker) (optional)

    Returns:
        JSON formatted cluster node list
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
            return json.dumps({
                "status": "success",
                "message": "No cluster nodes found",
                "total_count": 0,
                "nodes": []
            }, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

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

        return json.dumps({
            "status": "success",
            "total_count": len(processed_nodes),
            "nodes": processed_nodes
        }, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

    except Exception as error:
        logger.error(f"Cluster node retrieval failed: {error}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to retrieve cluster nodes: {str(error)}"
        }, indent=2, ensure_ascii=False)

# ─────────────────── Utility Tools ───────────────────

@mcp_server.tool()
def health_check() -> str:
    """Perform comprehensive health check

    Tests connectivity to Wazuh Manager and Indexer, provides response times,
    cache statistics, and configuration details.

    Returns:
        JSON formatted health status
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

        return json.dumps(health_report, indent=2, ensure_ascii=False, cls=DateTimeJSONEncoder)

    except Exception as error:
        return json.dumps({
            "overall_status": "unhealthy",
            "error": str(error),
            "timestamp": datetime.now().isoformat()
        }, indent=2, ensure_ascii=False)

@mcp_server.tool()
def clear_cache() -> str:
    """Clear all cached data

    Removes all cached API responses, forcing fresh data retrieval.

    Returns:
        JSON formatted cache clear confirmation
    """
    logger.info("Clearing cache")
    memory_cache.invalidate_all()
    return json.dumps({
        "status": "success",
        "message": "Cache cleared successfully"
    }, indent=2, ensure_ascii=False)

@mcp_server.tool()
def cache_stats() -> str:
    """Retrieve cache statistics

    Provides cache usage information including total entries,
    valid entries, and TTL settings.

    Returns:
        JSON formatted cache statistics
    """
    logger.info("Retrieving cache statistics")
    cache_metrics = memory_cache.get_statistics()
    return json.dumps({
        "status": "success",
        "cache_statistics": cache_metrics
    }, indent=2, ensure_ascii=False)

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
    logger.info("Wazuh SIEM MCP Server v1.0.0")
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
    logger.info("  • get_wazuh_rules_summary() - Detection rules")
    logger.info("  • get_wazuh_vulnerability_summary() - Vulnerability assessment")
    logger.info("  • get_wazuh_critical_vulnerabilities() - Critical CVEs")
    logger.info("  • get_wazuh_agents() - Agent inventory")
    logger.info("  • get_wazuh_agent_processes() - Process monitoring")
    logger.info("  • get_wazuh_agent_ports() - Network port analysis")
    logger.info("  • search_wazuh_manager_logs() - Log search")
    logger.info("  • get_wazuh_manager_error_logs() - Error diagnostics")
    logger.info("  • get_wazuh_log_collector_stats() - Collection metrics")
    logger.info("  • get_wazuh_remoted_stats() - Daemon statistics")
    logger.info("  • get_wazuh_weekly_stats() - Weekly aggregates")
    logger.info("  • get_wazuh_cluster_health() - Cluster status")
    logger.info("  • get_wazuh_cluster_nodes() - Node inventory")
    logger.info("  • clear_cache() - Cache management")
    logger.info("  • cache_stats() - Cache metrics")
    logger.info("=" * 80)
    logger.info(f"Configuration:")
    logger.info(f"  Cache: {wazuh_config.cache_duration}s | Timeout: {wazuh_config.request_timeout}s")
    logger.info(f"  Retries: {wazuh_config.retry_attempts} | SSL: {wazuh_config.use_ssl}")
    logger.info("=" * 80)

    # Start MCP server
    mcp_server.run()
