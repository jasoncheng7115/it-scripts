#!/usr/bin/env python3
"""
MCP server for Zimbra Collaboration Suite - v1.8.4
===============================================================================
Author: Jason Cheng (co-created with Claude Code)
Created: 2025-01-27
Updated: 2026-02-13
License: MIT

Reference:
This implementation follows design patterns from mcp_wazuh_sample.py
architecture by Jason Cheng.

FastMCP-based Zimbra integration providing comprehensive email system monitoring
and analysis capabilities through natural language interactions.

Version History:
- v1.8.4 (2026-02-13): ROBUSTNESS - Input validation guards for weaker LLM compatibility
                       - All msg_id/conversation_id params validated before SOAP calls
                       - Empty or missing IDs return clear error with correct usage example
                       - searchMail response includes usage_hint showing how to use result IDs
                       - Docstring ID examples updated to realistic format (was "12345")
                       - Prevents gpt-oss:120b empty-param errors via early guard returns
- v1.8.3 (2026-02-12): ENHANCEMENT - saveDraft auto-quotes original message on reply/forward
                       - Reply: appends "On {date}, {from} wrote:" + quoted original body
                       - Forward: appends "Forwarded message" header + original body
                       - LLM only provides reply text; quoting handled automatically
                       - Docstring clarified: body = your reply only, original is auto-appended
- v1.8.2 (2026-02-12): FIX - JSON output now uses ensure_ascii=False globally
                       - CJK characters output as readable text instead of \\uXXXX escapes
                       - Prevents LLM misreading similar-looking Chinese characters
                       - Affects all 115 json.dumps calls via global default override
- v1.8.1 (2026-02-12): BUG FIX - searchMail date range was exclusive (off-by-one)
                       - FIX: date_from/date_to now inclusive (after:-1day, before:+1day)
                       - Zimbra after:/before: are exclusive; adjusted boundaries automatically
                       - "today's mail" queries now return correct results
- v1.8.0 (2026-02-11): NEW FEATURE - Dual authentication mode (Admin + User)
                       - User mode: authenticate with regular account credentials
                       - User mode provides 18 tools for personal mailbox access
                       - Admin mode: unchanged, all 49 tools available
                       - NEW CONFIG: ZIMBRA_USER_EMAIL, ZIMBRA_USER_PASS for user mode
                       - Conditional tool registration via admin_only_tool() decorator
                       - Total tools: 49 (admin) / 18 (user)
- v1.7.0 (2026-02-11): NEW FEATURE - Mail search, contacts, drafts, folder management
                       - NEW TOOL: searchMail() - Search mailbox by subject/sender/recipient/body/date
                       - NEW TOOL: getMailDetail() - Get full message with body, headers, attachments
                       - NEW TOOL: getConversation() - Get all messages in a conversation thread
                       - NEW TOOL: getMailAttachment() - Download attachment to local file via REST
                       - NEW TOOL: listFolders() - List mailbox folders with fuzzy name matching
                       - NEW TOOL: saveDraft() - Save new email or reply/forward as draft
                       - NEW TOOL: searchContacts() - Search user's personal address book
                       - NEW HELPER: query_zimbra_mail_api() - Admin-delegated mail namespace SOAP
                       - NEW CONFIG: ZIMBRA_MAIL_URL - Web client URL for REST operations
                       - Total tools: 49
- v1.6.0 (2026-02-09): NEW FEATURE - Bulk audit tools (LDAP-based, single-call)
                       - NEW TOOL: getAllDelegations() - List all sendAs/sendOnBehalfOf rights
                       - NEW TOOL: getAllForwardings() - List all mail forwarding rules
                       - NEW TOOL: getAllOutOfOffice() - List all auto-reply enabled accounts
                       - NEW TOOL: getInactiveAccounts() - List accounts inactive for N+ days
                       - NEW TOOL: searchByAttribute() - Generic LDAP filter search
                       - FIX: getGrants without target_name no longer sends invalid <target> element
                       - Total tools: 42
- v1.5.0 (2026-02-09): COMPATIBILITY - gpt-oss:120b model compatibility improvements
                       - REMOVED: getTopMailboxesBySize (deprecated, use getQuotaUsage)
                       - FIX: getAccountQuota now uses UUID for GetMailboxRequest (was 500 error)
                       - FIX: unlockAccount handles both "locked" and "lockout" states with fresh query
                       - FIX: getQueueList/searchMailQueue sender field uses full address (was domain-only)
                       - FIX: searchMailQueue searches all 5 queues when queue_name not specified
                       - FIX: getGrants default target_type changed to "account"
                       - RENAME: max_results → limit in 5 tools for consistent naming
                       - REWRITE: All 37 tool docstrings with proper Args format for LLM compatibility
                       - Total tools: 37
- v1.3.0 (2025-11-27): NEW FEATURE - Added getActiveSessions() for real-time session monitoring
                       - NEW TOOL: getActiveSessions() - Query currently logged-in users
                       - Shows SOAP (web), IMAP, POP3, and admin sessions
                       - Supports detailed session list or summary counts
                       - Real-time data (no caching) for accurate session monitoring
                       - Total tools increased from 31 to 32
- v1.2.6 (2025-11-27): UX IMPROVEMENT - Added display_message to all pagination functions
                       - NEW: create_pagination_message() helper function
                       - getAllAccounts: Added display_message (e.g., "Showing first 100 items (250 total, 150 remaining)")
                       - getAllDistributionLists: Added display_message + fixed same 'more' bug
                       - getDLMembers: Added display_message
                       - getQuotaUsage: Added display_message
                       - Users now clearly see if viewing partial results!
- v1.2.5 (2025-11-27): BUG FIX - Fixed getAccountCount() returning incorrect count
                       - getAllAccounts: Fixed total_matches calculation (was using 'more' as count!)
                       - getAccountCount: Now uses accurate counting with full iteration fallback
                       - Added counting_method to show how count was determined
                       - Bug discovered: getAccountCount showed 1 when actually 10 accounts exist
- v1.2.4 (2025-11-27): SAFETY - Enhanced getCOSInfo() with safe-by-default behavior
                       - Without attr_filter: Returns only ~30 common attributes (SAFE)
                       - With attr_filter: Returns filtered attributes (TARGETED)
                       - Use attr_filter=".*" to get all attributes (with warning)
                       - Prevents context overflow when querying COS without filter
                       - Response includes suggestions for common filter patterns
- v1.2.3 (2025-11-27): NEW TOOL - Added getCOSInfo() with attribute filtering
                       - Query specific COS by name with regex attribute filtering
                       - Solves context overflow issue when querying COS settings
                       - Use attr_filter="password" to get only password-related settings
                       - Total tools increased from 30 to 31
- v1.2.2 (2025-11-27): PERFORMANCE - Added getQuotaUsage() for fast account storage ranking
                       - NEW TOOL: getQuotaUsage() - Single API call, up to 1000x faster!
                       - Uses Zimbra's GetQuotaUsageRequest API (optimized for bulk queries)
                       - Supports sorting by totalUsed, percentUsed, quotaLimit
                       - Supports pagination (limit, offset) for large systems
                       - getTopMailboxesBySize() now uses getQuotaUsage internally (backward compatible)
                       - Total tools increased from 29 to 30
- v1.2.1 (2025-11-27): Fixed dynamic distribution list support
                       - getAllDistributionLists now queries both static DLs and dynamic groups
                       - getDLInfo now handles dynamic groups correctly
                       - getDLMembers now handles dynamic groups correctly
                       - Added proper element type detection (<dl> vs <dynamicGroup>)
- v1.2.0 (2025-11-27): Added jt_zmmsgtrace integration
                       - 6 new tools for mail tracing via jt_zmmsgtrace API
                       - Search by sender, recipient, message ID, host, time
                       - Comprehensive mail delivery path tracking
                       - Support for regex patterns in searches
                       - Total tools increased from 23 to 29
- v1.1.7 (2025-11-27): Fixed getAllDistributionLists() memberCount issue
                       - Added include_member_count parameter (default: False)
                       - When True: Queries actual member count per DL (slower but accurate)
                       - When False: Returns null for memberCount (faster)
                       - Fixed incorrect attribute usage (was using wrong Zimbra attribute)
- v1.1.6 (2025-11-27): Added getAllDistributionLists() function
                       - List all distribution lists with domain filtering
                       - Pagination support (limit, offset)
                       - Returns DL details: name, displayName, dynamic, description, memberCount
                       - Total tools increased from 22 to 23
- v1.1.5 (2025-11-27): MAJOR FIX - Completely rewrote parse_server_status()
                       - Discovered actual Zimbra XML format: <status service="X">1</status>
                       - Fixed incorrect XML parsing (was looking for <service> elements)
                       - Now correctly parses flat <status> elements with service attribute
                       - Confirmed: "1"=running, "0"=stopped (not reversed!)
                       - Timestamp conversion to ISO format
                       - Services now show correct running/stopped status
- v1.1.4 (2025-11-27): Attempted status normalization (incomplete - wrong XML structure assumed)
- v1.1.3 (2025-11-27): Enhanced unlockAccount with status validation
                       - Now only unlocks accounts in 'locked' status
                       - Returns 'skipped' status for non-locked accounts
                       - Added comprehensive logging and safety checks
                       - Prevents accidental status modification
- v1.1.2 (2025-11-27): Fixed service status parsing - now checks attributes AND text
                       - Added extract_status() helper to check multiple locations
                       - Status now correctly parsed from text, attributes, or child elements
                       - Enhanced debug logging with 1500 chars of XML response
- v1.1.1 (2025-11-27): Fixed getServerStatus function with improved XML parsing
                       - Added multiple SOAP request format fallback strategies
                       - Enhanced XML parsing with 3 different parsing strategies
                       - Added detailed debug logging for troubleshooting
                       - Improved compatibility with Zimbra 10.x FOSS edition
- v1.1.0 (2025-01-27): Added account unlock, mail queue search, mailbox statistics,
                       storage usage rankings, and enhanced queue monitoring
- v1.0.0 (2025-01-27): Initial release with basic account, DL, server, and queue tools

Features (49 tools admin / 18 tools user):
- Account management: info, quota, aliases, unlock, listing, counting
- Distribution list: info, members, listing all DLs (static & dynamic)
- Mail queue monitoring: statistics, listing, searching
- Mail tracing (jt_zmmsgtrace): delivery path tracking, search by various criteria
- Quota usage analysis: FAST bulk quota queries with sorting
- Mailbox statistics and storage usage analysis
- System status and health checks
- Server inventory and service monitoring
- Active session monitoring: Real-time logged-in users tracking (NEW in v1.3.0)
- Domain and COS (Class of Service) information with attribute filtering
- Comprehensive caching and retry mechanisms
- Real-time queue analysis for bounce/delivery troubleshooting

Installation:
pip install mcp requests urllib3

Configuration Methods (Priority: CLI Args > Environment Variables > Defaults):

1. Command Line Arguments (Recommended):
   python3 mcp_zimbra.py \\
     --admin-url "https://mail.example.com:7071/service/admin/soap" \\
     --admin-user "admin@example.com" \\
     --admin-pass "password"

   Available arguments:
   --admin-url             Zimbra Admin SOAP API URL
   --admin-user            Zimbra admin username
   --admin-pass            Zimbra admin password
   --use-ssl               Enable SSL/TLS (true/false, default: true)
   --cache-duration        Cache duration in seconds (default: 300)
   --request-timeout       Request timeout in seconds (default: 30)
   --retry-attempts        Retry attempts for failed requests (default: 3)
   --jt-zmmsgtrace-url     jt_zmmsgtrace base URL (default: http://localhost)
   --jt-zmmsgtrace-port    jt_zmmsgtrace port (default: 8989)
   --jt-zmmsgtrace-api-key jt_zmmsgtrace API key (required for mail tracing)
   --transport             Transport mode: stdio (default) or streamable-http
   --host                  HTTP listen host for streamable-http (default: 127.0.0.1)
   --port                  HTTP listen port for streamable-http (default: 8000)

2. Environment Variables:
   Zimbra Configuration (Required):
   ZIMBRA_ADMIN_URL        Admin SOAP API URL
   ZIMBRA_ADMIN_USER       Admin username
   ZIMBRA_ADMIN_PASS       Admin password
   ZIMBRA_VERIFY_SSL       Enable SSL verification
   ZIMBRA_CACHE_TTL        Cache TTL
   ZIMBRA_TIMEOUT          Request timeout
   ZIMBRA_MAX_RETRIES      Retry attempts

   jt_zmmsgtrace Configuration (Optional - for mail tracing):
   JT_ZMMSGTRACE_URL       jt_zmmsgtrace base URL (default: http://localhost)
   JT_ZMMSGTRACE_PORT      jt_zmmsgtrace port (default: 8989)
   JT_ZMMSGTRACE_API_KEY   API key for authentication (required for mail tracing)

   Note: If JT_ZMMSGTRACE_API_KEY is not set, mail tracing tools will not be available.

Usage:
chmod +x mcp_zimbra.py
python3 mcp_zimbra.py --help
"""

import json
# Override json.dumps default: output CJK characters as-is (not \uXXXX escapes)
# so LLMs can read them directly without decoding errors
_json_dumps_original = json.dumps
json.dumps = lambda *args, **kwargs: _json_dumps_original(*args, **{**{'ensure_ascii': False}, **kwargs})

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
import re
import urllib3
from urllib.parse import urlparse, unquote
import xml.etree.ElementTree as ET

import requests
from mcp.server.fastmcp import FastMCP

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('zimbra-mcp-server')

# ======================= Configuration Management =======================

class ZimbraConfig:
    """Configuration manager for Zimbra MCP Server with CLI and environment variable support"""

    def __init__(self, cli_args=None):
        """Initialize configuration with priority: CLI > ENV > Defaults"""
        # Zimbra configuration
        self.admin_url = self._get_value(cli_args, 'admin_url', 'ZIMBRA_ADMIN_URL')
        self.admin_user = self._get_value(cli_args, 'admin_user', 'ZIMBRA_ADMIN_USER')
        self.admin_pass = self._get_value(cli_args, 'admin_pass', 'ZIMBRA_ADMIN_PASS')

        self.mail_url = self._get_value(cli_args, 'mail_url', 'ZIMBRA_MAIL_URL', '')

        # User mode configuration
        self.user_email = self._get_value(cli_args, 'user_email', 'ZIMBRA_USER_EMAIL', '')
        self.user_pass = self._get_value(cli_args, 'user_pass', 'ZIMBRA_USER_PASS', '')

        self.use_ssl = self._get_bool_value(cli_args, 'use_ssl', 'ZIMBRA_VERIFY_SSL', True)

        self.cache_duration = self._get_int_value(cli_args, 'cache_duration', 'ZIMBRA_CACHE_TTL', 300)
        self.request_timeout = self._get_int_value(cli_args, 'request_timeout', 'ZIMBRA_TIMEOUT', 30)
        self.retry_attempts = self._get_int_value(cli_args, 'retry_attempts', 'ZIMBRA_MAX_RETRIES', 3)

        # jt_zmmsgtrace configuration (optional)
        self.jt_zmmsgtrace_url = self._get_value(cli_args, 'jt_zmmsgtrace_url', 'JT_ZMMSGTRACE_URL', 'http://localhost')
        self.jt_zmmsgtrace_port = self._get_int_value(cli_args, 'jt_zmmsgtrace_port', 'JT_ZMMSGTRACE_PORT', 8989)
        self.jt_zmmsgtrace_api_key = self._get_value(cli_args, 'jt_zmmsgtrace_api_key', 'JT_ZMMSGTRACE_API_KEY', '')

        # Build full jt_zmmsgtrace base URL
        if self.jt_zmmsgtrace_url and self.jt_zmmsgtrace_port:
            # Remove trailing slash from URL
            base_url = self.jt_zmmsgtrace_url.rstrip('/')
            self.jt_zmmsgtrace_base_url = f"{base_url}:{self.jt_zmmsgtrace_port}"
        else:
            self.jt_zmmsgtrace_base_url = None

        # Determine authentication mode
        has_admin = all([self.admin_url, self.admin_user, self.admin_pass])
        has_user = all([self.mail_url, self.user_email, self.user_pass])
        if has_admin:
            self.auth_mode = "admin"
        elif has_user:
            self.auth_mode = "user"
        else:
            self.auth_mode = None  # Will trigger validation error

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
        if self.auth_mode == "admin":
            logger.info(f"Auth mode: admin")
            logger.info(f"Admin API: {self.admin_url}")
            logger.info(f"Cache: {self.cache_duration}s | Timeout: {self.request_timeout}s | SSL: {self.use_ssl}")

            # Log jt_zmmsgtrace configuration if available
            if self.jt_zmmsgtrace_base_url and self.jt_zmmsgtrace_api_key:
                logger.info(f"jt_zmmsgtrace: {self.jt_zmmsgtrace_base_url} (API Key configured)")
            else:
                logger.info("jt_zmmsgtrace: Not configured (mail tracing tools will not be available)")

        elif self.auth_mode == "user":
            logger.info(f"Auth mode: user ({self.user_email})")
            logger.info(f"Mail URL: {self.mail_url}")
            logger.info(f"Cache: {self.cache_duration}s | Timeout: {self.request_timeout}s | SSL: {self.use_ssl}")

        else:
            logger.error("Configuration validation failed:")
            logger.error("  No valid authentication configuration found.")
            logger.error("")
            logger.error("  Admin mode (full access, 49 tools):")
            logger.error("    CLI: --admin-url <URL> --admin-user <USER> --admin-pass <PASS>")
            logger.error("    ENV: ZIMBRA_ADMIN_URL, ZIMBRA_ADMIN_USER, ZIMBRA_ADMIN_PASS")
            logger.error("")
            logger.error("  User mode (personal mailbox, 18 tools):")
            logger.error("    CLI: --mail-url <URL> --user-email <EMAIL> --user-pass <PASS>")
            logger.error("    ENV: ZIMBRA_MAIL_URL, ZIMBRA_USER_EMAIL, ZIMBRA_USER_PASS")
            sys.exit(1)

_cli_args = None
if len(sys.argv) > 1:
    def _parse_args():
        parser = argparse.ArgumentParser(add_help=False)
        # Zimbra configuration
        parser.add_argument('--admin-url', help='Zimbra Admin SOAP API URL')
        parser.add_argument('--admin-user', help='Admin username')
        parser.add_argument('--admin-pass', help='Admin password')
        parser.add_argument('--mail-url', help='Zimbra web client base URL for REST API')
        parser.add_argument('--user-email', help='User email for user mode authentication')
        parser.add_argument('--user-pass', help='User password for user mode authentication')
        parser.add_argument('--use-ssl', type=lambda x: x.lower() in ('true', '1', 'yes'), help='Enable SSL verification')
        parser.add_argument('--cache-duration', type=int, help='Cache duration in seconds')
        parser.add_argument('--request-timeout', type=int, help='Request timeout in seconds')
        parser.add_argument('--retry-attempts', type=int, help='Retry attempts')
        # jt_zmmsgtrace configuration
        parser.add_argument('--jt-zmmsgtrace-url', help='jt_zmmsgtrace base URL (default: http://localhost)')
        parser.add_argument('--jt-zmmsgtrace-port', type=int, help='jt_zmmsgtrace port (default: 8989)')
        parser.add_argument('--jt-zmmsgtrace-api-key', help='jt_zmmsgtrace API key')
        # Transport configuration (consumed later in __main__)
        parser.add_argument('--transport', help='Transport mode')
        parser.add_argument('--host', help='HTTP host')
        parser.add_argument('--port', type=int, help='HTTP port')
        args, _ = parser.parse_known_args()
        return args
    _cli_args = _parse_args()

zimbra_config = ZimbraConfig(cli_args=_cli_args)

# ======================= JSON Serialization =======================

class DateTimeJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder for datetime objects"""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

# ======================= Caching System =======================

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

memory_cache = None

# ======================= HTTP Session Management =======================

http_session = None
auth_token = None
token_expiry = None
user_auth_token = None
user_token_expiry = None

def get_auth_token() -> str:
    """Obtain authentication token from Zimbra Admin API"""
    global auth_token, token_expiry

    if auth_token and token_expiry:
        if datetime.now() < token_expiry:
            return auth_token

    soap_request = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
    <soap:Header>
        <context xmlns="urn:zimbra"/>
    </soap:Header>
    <soap:Body>
        <AuthRequest xmlns="urn:zimbraAdmin">
            <name>{zimbra_config.admin_user}</name>
            <password>{zimbra_config.admin_pass}</password>
        </AuthRequest>
    </soap:Body>
</soap:Envelope>"""

    try:
        response = requests.post(
            zimbra_config.admin_url,
            data=soap_request,
            headers={"Content-Type": "application/soap+xml"},
            verify=zimbra_config.use_ssl,
            timeout=zimbra_config.request_timeout
        )
        response.raise_for_status()

        root = ET.fromstring(response.text)
        ns = {'soap': 'http://www.w3.org/2003/05/soap-envelope', 'zimbra': 'urn:zimbraAdmin'}

        auth_token_elem = root.find('.//zimbra:authToken', ns)
        if auth_token_elem is None or not auth_token_elem.text:
            raise Exception("No authToken in authentication response")

        auth_token = auth_token_elem.text
        token_expiry = datetime.now() + timedelta(hours=12)

        logger.debug("Successfully obtained auth token")
        return auth_token

    except Exception as e:
        logger.error(f"Failed to obtain auth token: {e}")
        raise Exception(f"Authentication failed: {str(e)}")

def setup_http_session():
    """Initialize HTTP session"""
    global http_session

    http_session = requests.Session()
    http_session.headers.update({
        "Content-Type": "application/soap+xml",
        "User-Agent": "zimbra-mcp-server/1.8.3"
    })
    http_session.verify = zimbra_config.use_ssl

def get_user_auth_token() -> str:
    """Obtain authentication token from Zimbra Account API (user mode)"""
    global user_auth_token, user_token_expiry

    if user_auth_token and user_token_expiry:
        if datetime.now() < user_token_expiry:
            return user_auth_token

    soap_url = f"{zimbra_config.mail_url.rstrip('/')}/service/soap"

    soap_request = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
    <soap:Header>
        <context xmlns="urn:zimbra"/>
    </soap:Header>
    <soap:Body>
        <AuthRequest xmlns="urn:zimbraAccount">
            <account by="name">{zimbra_config.user_email}</account>
            <password>{zimbra_config.user_pass}</password>
        </AuthRequest>
    </soap:Body>
</soap:Envelope>"""

    try:
        response = requests.post(
            soap_url,
            data=soap_request,
            headers={"Content-Type": "application/soap+xml"},
            verify=zimbra_config.use_ssl,
            timeout=zimbra_config.request_timeout
        )
        response.raise_for_status()

        root = ET.fromstring(response.text)
        ns = {'soap': 'http://www.w3.org/2003/05/soap-envelope', 'zimbra': 'urn:zimbraAccount'}

        auth_token_elem = root.find('.//zimbra:authToken', ns)
        if auth_token_elem is None or not auth_token_elem.text:
            raise Exception("No authToken in user authentication response")

        user_auth_token = auth_token_elem.text
        user_token_expiry = datetime.now() + timedelta(hours=12)

        logger.debug("Successfully obtained user auth token")
        return user_auth_token

    except Exception as e:
        logger.error(f"User authentication failed: {e}")
        raise Exception(f"User authentication failed: {str(e)}")

def _query_user_soap(soap_body: str) -> ET.Element:
    """Execute SOAP request using user mode authentication (no <account> header)"""
    global user_auth_token, user_token_expiry

    token = get_user_auth_token()
    soap_url = f"{zimbra_config.mail_url.rstrip('/')}/service/soap"

    soap_request = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
    <soap:Header>
        <context xmlns="urn:zimbra">
            <authToken>{token}</authToken>
        </context>
    </soap:Header>
    <soap:Body>
        {soap_body}
    </soap:Body>
</soap:Envelope>"""

    for attempt in range(zimbra_config.retry_attempts):
        try:
            response = http_session.post(
                soap_url,
                data=soap_request,
                timeout=zimbra_config.request_timeout
            )
            response.raise_for_status()
            return ET.fromstring(response.text)

        except requests.exceptions.RequestException as req_error:
            if hasattr(req_error, 'response') and req_error.response and req_error.response.status_code == 401:
                user_auth_token = None
                user_token_expiry = None
                logger.warning("User token expired, will refresh on retry")

            if attempt < zimbra_config.retry_attempts - 1:
                backoff_delay = 1.0 * (2 ** attempt)
                logger.warning(f"User SOAP request failed (attempt {attempt + 1}): {req_error}")
                time.sleep(backoff_delay)
            else:
                logger.error(f"User SOAP request failed after {zimbra_config.retry_attempts} attempts")
                raise Exception(f"User SOAP error: {str(req_error)}")

mcp_server = FastMCP("Zimbra")

def admin_only_tool():
    """Decorator factory: registers tool only in admin mode, skips in user mode."""
    def decorator(func):
        if zimbra_config.auth_mode == "admin":
            return mcp_server.tool()(func)
        return func  # user mode: don't register
    return decorator

memory_cache = MemoryCache(zimbra_config.cache_duration)
setup_http_session()

# ======================= Utility Functions =======================

def query_zimbra_api(soap_body: str, enable_cache: bool = True) -> ET.Element:
    """Execute SOAP API request to Zimbra with caching and authentication"""

    cache_identifier = f"zimbra:{hashlib.md5(soap_body.encode()).hexdigest()}"

    if enable_cache:
        cached_response = memory_cache.retrieve(cache_identifier)
        if cached_response:
            logger.debug("Cache hit")
            return cached_response

    token = get_auth_token()

    soap_request = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
    <soap:Header>
        <context xmlns="urn:zimbra">
            <authToken>{token}</authToken>
        </context>
    </soap:Header>
    <soap:Body>
        {soap_body}
    </soap:Body>
</soap:Envelope>"""

    for attempt in range(zimbra_config.retry_attempts):
        try:
            response = http_session.post(
                zimbra_config.admin_url,
                data=soap_request,
                timeout=zimbra_config.request_timeout
            )
            response.raise_for_status()

            root = ET.fromstring(response.text)

            if enable_cache:
                memory_cache.store(cache_identifier, root)

            return root

        except requests.exceptions.RequestException as req_error:
            if hasattr(req_error, 'response') and req_error.response and req_error.response.status_code == 401:
                global auth_token, token_expiry
                auth_token = None
                token_expiry = None
                logger.warning("Token expired or invalid, will get new token on retry")

            if attempt < zimbra_config.retry_attempts - 1:
                backoff_delay = 1.0 * (2 ** attempt)
                logger.warning(f"Request failed (attempt {attempt + 1}): {req_error}")
                logger.warning(f"Retrying after {backoff_delay}s...")
                time.sleep(backoff_delay)
            else:
                logger.error(f"Zimbra API request failed after {zimbra_config.retry_attempts} attempts")
                raise Exception(f"Zimbra API error: {str(req_error)}")

def _query_mail_api_user_mode(soap_body: str, target_account: str) -> ET.Element:
    """Execute mail-namespace SOAP using user mode authentication.
    Only allows access to the authenticated user's own mailbox.
    """
    if target_account and target_account.lower() != zimbra_config.user_email.lower():
        raise Exception(
            f"User mode: cannot access mailbox of '{target_account}'. "
            f"Only '{zimbra_config.user_email}' is accessible in user mode."
        )
    return _query_user_soap(soap_body)

def query_zimbra_mail_api(soap_body: str, target_account: str) -> ET.Element:
    """Execute mail-namespace SOAP request targeting a specific user's mailbox.

    Uses admin auth token with <account> header to access the user's mailbox
    without needing DelegateAuth. In user mode, uses user token directly.
    """
    if zimbra_config.auth_mode == "user":
        return _query_mail_api_user_mode(soap_body, target_account)

    # === ADMIN MODE: original code below ===
    token = get_auth_token()

    soap_request = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
    <soap:Header>
        <context xmlns="urn:zimbra">
            <authToken>{token}</authToken>
            <account by="name">{target_account}</account>
        </context>
    </soap:Header>
    <soap:Body>
        {soap_body}
    </soap:Body>
</soap:Envelope>"""

    for attempt in range(zimbra_config.retry_attempts):
        try:
            response = http_session.post(
                zimbra_config.admin_url,
                data=soap_request,
                timeout=zimbra_config.request_timeout
            )
            response.raise_for_status()
            return ET.fromstring(response.text)

        except requests.exceptions.RequestException as req_error:
            if hasattr(req_error, 'response') and req_error.response and req_error.response.status_code == 401:
                global auth_token, token_expiry
                auth_token = None
                token_expiry = None
                logger.warning("Token expired, will refresh on retry")

            if attempt < zimbra_config.retry_attempts - 1:
                backoff_delay = 1.0 * (2 ** attempt)
                logger.warning(f"Mail API request failed (attempt {attempt + 1}): {req_error}")
                time.sleep(backoff_delay)
            else:
                logger.error(f"Zimbra Mail API request failed after {zimbra_config.retry_attempts} attempts")
                raise Exception(f"Zimbra Mail API error: {str(req_error)}")

def parse_zimbra_response(root: ET.Element, namespace: str = "urn:zimbraAdmin") -> Dict[str, Any]:
    """Parse Zimbra SOAP response into dictionary"""
    ns = {'soap': 'http://www.w3.org/2003/05/soap-envelope', 'zimbra': namespace}

    fault = root.find('.//soap:Fault', ns)
    if fault is not None:
        reason = fault.find('.//soap:Reason/soap:Text', ns)
        error_msg = reason.text if reason is not None else "Unknown error"
        raise Exception(f"Zimbra API error: {error_msg}")

    return root

def parse_attributes(element: ET.Element) -> Dict[str, Any]:
    """Parse Zimbra attribute elements into dictionary"""
    attrs = {}
    for attr in element.findall('.//{urn:zimbraAdmin}a'):
        name = attr.get('n')
        value = attr.text
        if name:
            attrs[name] = value
    return attrs

_mail_base_url_cache = None

def get_mail_base_url() -> str:
    """Get Zimbra web client base URL for REST API (e.g. attachment download).

    Priority: ZIMBRA_MAIL_URL config > auto-detect from server config.
    Result is cached for the session.
    """
    global _mail_base_url_cache

    if _mail_base_url_cache:
        return _mail_base_url_cache

    # 1. Use explicit config if set
    if zimbra_config.mail_url:
        _mail_base_url_cache = zimbra_config.mail_url.rstrip('/')
        logger.info(f"Using configured mail URL: {_mail_base_url_cache}")
        return _mail_base_url_cache

    # User mode requires explicit ZIMBRA_MAIL_URL (no admin API for auto-detect)
    if zimbra_config.auth_mode == "user":
        raise Exception(
            "User mode requires ZIMBRA_MAIL_URL to be set. "
            "Auto-detection is not available without admin credentials."
        )

    # 2. Auto-detect from Zimbra server config (admin mode only)
    try:
        parsed = urlparse(zimbra_config.admin_url)
        hostname = parsed.hostname

        # GetServerRequest to query web client settings
        soap_body = f"""
        <GetServerRequest xmlns="urn:zimbraAdmin">
            <server by="name">{hostname}</server>
        </GetServerRequest>
        """
        root = query_zimbra_api(soap_body)
        parse_zimbra_response(root)

        ns = {'zimbra': 'urn:zimbraAdmin'}
        server_elem = root.find('.//zimbra:server', ns)

        if server_elem is not None:
            attrs = parse_attributes(server_elem)

            # Try zimbraPublicService* first (most reliable for external access)
            pub_host = attrs.get('zimbraPublicServiceHostname', '')
            pub_port = attrs.get('zimbraPublicServicePort', '')
            pub_proto = attrs.get('zimbraPublicServiceProtocol', '')

            if pub_host:
                proto = pub_proto or 'https'
                if pub_port and pub_port not in ('443', '80'):
                    _mail_base_url_cache = f"{proto}://{pub_host}:{pub_port}"
                else:
                    _mail_base_url_cache = f"{proto}://{pub_host}"
                logger.info(f"Auto-detected mail URL (public service): {_mail_base_url_cache}")
                return _mail_base_url_cache

            # Fallback: use zimbraMailSSLPort on same hostname
            ssl_port = attrs.get('zimbraMailSSLPort', '443')
            if ssl_port and ssl_port != '443':
                _mail_base_url_cache = f"https://{hostname}:{ssl_port}"
            else:
                _mail_base_url_cache = f"https://{hostname}"
            logger.info(f"Auto-detected mail URL (SSL port): {_mail_base_url_cache}")
            return _mail_base_url_cache

    except Exception as e:
        logger.warning(f"Failed to auto-detect mail URL: {e}")

    # 3. Last resort: same hostname, default HTTPS
    parsed = urlparse(zimbra_config.admin_url)
    _mail_base_url_cache = f"https://{parsed.hostname}"
    logger.warning(f"Using fallback mail URL: {_mail_base_url_cache}")
    return _mail_base_url_cache

def create_pagination_message(returned_count: int, total_count: int, has_more: bool,
                              item_name: str = "items") -> str:
    """Create clear pagination display message for users

    Args:
        returned_count: Number of items in current response
        total_count: Total number of items available
        has_more: Whether there are more items available
        item_name: Name of items being displayed (default: "items")

    Returns:
        Clear message explaining what is being shown

    Examples:
        - "Showing 10 items (10 total, all displayed)"
        - "Showing first 100 items (250 total, 150 remaining)"
        - "Showing first 100 items (total unknown, more available)"
    """
    if returned_count == total_count and not has_more:
        # All items shown
        return f"Showing {returned_count} {item_name} ({total_count} total, all displayed)"
    elif total_count > returned_count:
        # Know total, showing partial
        remaining = total_count - returned_count
        return f"Showing first {returned_count} {item_name} ({total_count} total, {remaining} remaining)"
    elif has_more:
        # Don't know total, but there are more
        return f"Showing first {returned_count} {item_name} (total unknown, more available)"
    else:
        # Fallback
        return f"Showing {returned_count} {item_name}"

def query_jt_zmmsgtrace_api(params: Dict[str, Any]) -> Dict[str, Any]:
    """Execute API request to jt_zmmsgtrace service

    Args:
        params: Query parameters for the API request
            - sender: Sender email pattern (regex supported)
            - recipient: Recipient email pattern (regex supported)
            - message_id: Message-ID pattern (regex supported)
            - srchost: Source host pattern (regex supported)
            - desthost: Destination host pattern (regex supported)
            - time: Time range in format YYYYMMDD,YYYYMMDD
            - limit: Maximum results (default: 100, max: 1000)
            - offset: Pagination offset (default: 0)

    Returns:
        Dictionary with API response data or error information

    Raises:
        Exception: If jt_zmmsgtrace is not configured or API request fails
    """

    # Check if jt_zmmsgtrace is configured
    if not zimbra_config.jt_zmmsgtrace_base_url:
        raise Exception("jt_zmmsgtrace is not configured. Please set JT_ZMMSGTRACE_URL and JT_ZMMSGTRACE_PORT")

    if not zimbra_config.jt_zmmsgtrace_api_key:
        raise Exception("jt_zmmsgtrace API key is not configured. Please set JT_ZMMSGTRACE_API_KEY")

    # Build API URL
    api_url = f"{zimbra_config.jt_zmmsgtrace_base_url}/api/search"

    # Prepare headers with API key (using Authorization Bearer format)
    headers = {
        "Authorization": f"Bearer {zimbra_config.jt_zmmsgtrace_api_key}",
        "Accept": "application/json",
        "User-Agent": "zimbra-mcp-server/1.8.3"
    }

    # Clean up params - remove None values
    clean_params = {k: v for k, v in params.items() if v is not None}

    logger.debug(f"Querying jt_zmmsgtrace API: {api_url}")
    logger.debug(f"Parameters: {clean_params}")

    for attempt in range(zimbra_config.retry_attempts):
        try:
            response = http_session.get(
                api_url,
                params=clean_params,
                headers=headers,
                timeout=zimbra_config.request_timeout
            )

            # Check HTTP status code
            if response.status_code == 401:
                raise Exception("jt_zmmsgtrace API authentication failed. Check your API key.")
            elif response.status_code == 400:
                # Bad request - try to get error message from response
                try:
                    error_data = response.json()
                    error_msg = error_data.get('message', 'Bad request')
                    raise Exception(f"jt_zmmsgtrace API error: {error_msg}")
                except json.JSONDecodeError:
                    raise Exception(f"jt_zmmsgtrace API bad request: {response.text}")

            response.raise_for_status()

            # Parse JSON response
            data = response.json()

            # Check if API returned success
            if not data.get('success', False):
                error_msg = data.get('message', 'Unknown error')
                raise Exception(f"jt_zmmsgtrace API returned error: {error_msg}")

            logger.debug(f"Successfully retrieved {len(data.get('data', {}).get('messages', []))} messages")

            return data

        except requests.exceptions.RequestException as req_error:
            if attempt < zimbra_config.retry_attempts - 1:
                backoff_delay = 1.0 * (2 ** attempt)
                logger.warning(f"jt_zmmsgtrace API request failed (attempt {attempt + 1}): {req_error}")
                logger.warning(f"Retrying after {backoff_delay}s...")
                time.sleep(backoff_delay)
            else:
                logger.error(f"jt_zmmsgtrace API request failed after {zimbra_config.retry_attempts} attempts")
                raise Exception(f"jt_zmmsgtrace API error: {str(req_error)}")

def format_jt_zmmsgtrace_result(api_response: Dict[str, Any]) -> str:
    """Format jt_zmmsgtrace API response into user-friendly JSON

    Args:
        api_response: Raw API response from jt_zmmsgtrace

    Returns:
        Formatted JSON string with human-readable structure
    """

    if not api_response.get('success', False):
        return json.dumps({
            "status": "error",
            "message": api_response.get('message', 'Unknown error')
        }, indent=2)

    data = api_response.get('data', {})

    result = {
        "status": "success",
        "query": data.get('query', {}),
        "pagination": data.get('pagination', {}),
        "messages": []
    }

    # Format messages for better readability
    for msg in data.get('messages', []):
        formatted_msg = {
            "message_id": msg.get('message_id'),
            "sender": msg.get('sender'),
            "subject": msg.get('subject'),
            "source_file": msg.get('source_file'),
            "queue_ids": msg.get('queue_ids', []),
            "recipient_count": len(msg.get('recipients', [])),
            "recipients": []
        }

        for recip in msg.get('recipients', []):
            formatted_recip = {
                "address": recip.get('address'),
                "orig_recip": recip.get('orig_recip'),
                "from_amavis_only": recip.get('from_amavis_only', False),
                "delivery_stages": len(recip.get('delivery_path', [])),
                "delivery_path": []
            }

            for stage in recip.get('delivery_path', []):
                formatted_stage = {
                    "time": stage.get('arrive_time'),
                    "from": {
                        "host": stage.get('prev_host'),
                        "ip": stage.get('prev_ip')
                    },
                    "to": {
                        "host": stage.get('next_host'),
                        "ip": stage.get('next_ip')
                    },
                    "status": stage.get('status'),
                    "status_msg": stage.get('status_msg'),
                    "queue_id": stage.get('queue_id')
                }

                # Add amavis info if present
                if stage.get('amavis'):
                    formatted_stage['amavis'] = stage['amavis']

                formatted_recip['delivery_path'].append(formatted_stage)

            formatted_msg['recipients'].append(formatted_recip)

        result['messages'].append(formatted_msg)

    return json.dumps(result, indent=2, cls=DateTimeJSONEncoder)

# ======================= MCP Tool Implementations =======================

# ------------------- Account Management -------------------

@admin_only_tool()
def getAccountInfo(email: str) -> str:
    """Get all attributes and settings for an email account.

    Args:
        email: Account email address. Example: "user@example.com". Case-insensitive.
    """
    logger.info(f"Getting account info for {email}")

    try:
        soap_body = f"""
        <GetAccountRequest xmlns="urn:zimbraAdmin">
            <account by="name">{email}</account>
        </GetAccountRequest>
        """

        root = query_zimbra_api(soap_body)
        parse_zimbra_response(root)

        ns = {'zimbra': 'urn:zimbraAdmin'}
        account_elem = root.find('.//zimbra:account', ns)

        if account_elem is None:
            return json.dumps({
                "status": "error",
                "message": f"Account not found: {email}"
            }, indent=2)

        account_info = {
            "id": account_elem.get('id'),
            "name": account_elem.get('name'),
            "attributes": parse_attributes(account_elem)
        }

        return json.dumps({
            "status": "success",
            "account": account_info
        }, indent=2, cls=DateTimeJSONEncoder)

    except Exception as e:
        logger.error(f"Failed to get account info: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to get account info: {str(e)}"
        }, indent=2)

@admin_only_tool()
def getAccountQuota(email: str) -> str:
    """Get mailbox quota limit and current storage usage for an account.

    Args:
        email: Account email address. Example: "user@example.com". Case-insensitive.
    """
    logger.info(f"Getting account quota for {email}")

    try:
        # Step 1: Get account UUID and quota attribute via GetAccountRequest
        acct_soap = f"""
        <GetAccountRequest xmlns="urn:zimbraAdmin">
            <account by="name">{email}</account>
        </GetAccountRequest>
        """

        acct_root = query_zimbra_api(acct_soap)
        parse_zimbra_response(acct_root)

        ns = {'zimbra': 'urn:zimbraAdmin'}
        account_elem = acct_root.find('.//zimbra:account', ns)

        if account_elem is None:
            return json.dumps({
                "status": "error",
                "message": f"Account not found: {email}"
            }, indent=2)

        account_id = account_elem.get('id')
        attrs = parse_attributes(account_elem)
        limit_str = attrs.get('zimbraMailQuota', '0')
        limit = int(limit_str) if limit_str else 0

        # Step 2: Get mailbox size using UUID (GetMailboxRequest expects UUID, not email)
        mbox_soap = f"""
        <GetMailboxRequest xmlns="urn:zimbraAdmin">
            <mbox id="{account_id}"/>
        </GetMailboxRequest>
        """

        mbox_root = query_zimbra_api(mbox_soap)
        parse_zimbra_response(mbox_root)

        mbox_elem = mbox_root.find('.//zimbra:mbox', ns)

        if mbox_elem is None:
            return json.dumps({
                "status": "error",
                "message": f"Mailbox not found: {email}"
            }, indent=2)

        used = int(mbox_elem.get('s', 0))

        percentage = 0
        available = 0
        if limit > 0:
            percentage = round((used / limit) * 100, 2)
            available = max(0, limit - used)

        return json.dumps({
            "status": "success",
            "email": email,
            "quota": {
                "used_bytes": used,
                "limit_bytes": limit,
                "percentage_used": percentage,
                "available_bytes": available,
                "unlimited": limit == 0
            }
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to get account quota: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to get account quota: {str(e)}"
        }, indent=2)

@admin_only_tool()
def getAccountAliases(email: str) -> str:
    """List all email aliases configured for an account.

    Args:
        email: Primary account email address. Example: "user@example.com". Case-insensitive.
    """
    logger.info(f"Getting aliases for {email}")

    try:
        account_info = getAccountInfo(email)
        account_data = json.loads(account_info)

        if account_data.get('status') != 'success':
            return account_info

        attrs = account_data.get('account', {}).get('attributes', {})

        aliases = []
        for key, value in attrs.items():
            if key == 'zimbraMailAlias':
                if isinstance(value, list):
                    aliases.extend(value)
                else:
                    aliases.append(value)

        return json.dumps({
            "status": "success",
            "email": email,
            "aliases": aliases,
            "count": len(aliases)
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to get account aliases: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to get account aliases: {str(e)}"
        }, indent=2)

@admin_only_tool()
def unlockAccount(email: str) -> str:
    """Unlock a locked or lockout account and restore it to active status.

    Args:
        email: Account email address. Example: "user@example.com". Case-insensitive.
    """
    logger.info(f"Attempting to unlock account {email}")

    try:
        # Get current account status with fresh SOAP query (no cache)
        acct_soap = f"""
        <GetAccountRequest xmlns="urn:zimbraAdmin">
            <account by="name">{email}</account>
        </GetAccountRequest>
        """

        acct_root = query_zimbra_api(acct_soap, enable_cache=False)
        parse_zimbra_response(acct_root)

        ns = {'zimbra': 'urn:zimbraAdmin'}
        account_elem = acct_root.find('.//zimbra:account', ns)

        if account_elem is None:
            return json.dumps({
                "status": "error",
                "message": f"Account not found: {email}"
            }, indent=2)

        account_id = account_elem.get('id')
        attrs = parse_attributes(account_elem)
        current_status = attrs.get('zimbraAccountStatus', 'unknown')

        logger.info(f"Account {email} current status: {current_status}")

        # Check if account is locked or lockout
        if current_status.lower() not in ('locked', 'lockout'):
            logger.warning(f"Account {email} is not locked (status: {current_status}), skipping unlock operation")
            return json.dumps({
                "status": "skipped",
                "email": email,
                "current_status": current_status,
                "message": f"Account unlock skipped: account status is '{current_status}', not 'locked' or 'lockout'. Only locked/lockout accounts can be unlocked.",
                "hint": "If you need to change the account status, use a different operation or manually modify the account."
            }, indent=2)

        # Account is locked/lockout, proceed with unlock
        logger.info(f"Account {email} is {current_status}, proceeding with unlock operation")

        # Build modify attributes: set status to active
        modify_attrs = '<a n="zimbraAccountStatus">active</a>'

        # For lockout status, also clear lockout-related attributes
        if current_status.lower() == 'lockout':
            modify_attrs += '\n            <a n="zimbraPasswordLockoutFailureTime"></a>'
            modify_attrs += '\n            <a n="zimbraPasswordLockoutLockedTime"></a>'

        soap_body = f"""
        <ModifyAccountRequest xmlns="urn:zimbraAdmin">
            <id>{account_id}</id>
            {modify_attrs}
        </ModifyAccountRequest>
        """

        root = query_zimbra_api(soap_body, enable_cache=False)
        parse_zimbra_response(root)

        logger.info(f"Successfully unlocked account {email}")

        return json.dumps({
            "status": "success",
            "email": email,
            "previous_status": current_status,
            "current_status": "active",
            "message": f"Account {email} has been unlocked successfully (status changed from '{current_status}' to 'active')"
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to unlock account: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to unlock account: {str(e)}"
        }, indent=2)

@admin_only_tool()
def getAllAccounts(domain: Optional[str] = None,
                   limit: int = 100,
                   offset: int = 0,
                   status_filter: Optional[str] = None) -> str:
    """List email accounts with optional domain and status filtering.

    Args:
        domain: Filter by domain. Example: "example.com" or "a.com,b.com". Default: all domains.
        limit: Max results per page. Default: 100. Range: 1-1000.
        offset: Starting position for pagination. Default: 0. Use offset=limit for page 2.
        status_filter: Filter by status. Values: "active", "closed", "locked", "lockout", "maintenance", "pending". Default: all.
    """
    logger.info(f"Getting all accounts (domain={domain}, status={status_filter}, limit={limit}, offset={offset})")

    try:
        domain_query = ""
        if domain:
            domains = [d.strip() for d in domain.split(',')]
            if len(domains) == 1:
                domain_query = f'<domain by="name">{domains[0]}</domain>'
            else:
                for d in domains:
                    domain_query += f'<domain by="name">{d}</domain>'

        soap_body = f"""
        <SearchDirectoryRequest xmlns="urn:zimbraAdmin"
                                limit="{limit}"
                                offset="{offset}"
                                types="accounts">
            {domain_query}
        </SearchDirectoryRequest>
        """

        root = query_zimbra_api(soap_body)
        parse_zimbra_response(root)

        ns = {'zimbra': 'urn:zimbraAdmin'}
        account_elems = root.findall('.//zimbra:account', ns)

        accounts = []
        for account_elem in account_elems:
            attrs = parse_attributes(account_elem)

            account_status = attrs.get('zimbraAccountStatus', 'unknown')

            if status_filter and account_status != status_filter:
                continue

            account_info = {
                "id": account_elem.get('id'),
                "name": account_elem.get('name'),
                "displayName": attrs.get('displayName', ''),
                "accountStatus": account_status,
                "created": attrs.get('zimbraCreateTimestamp', ''),
                "mailHost": attrs.get('zimbraMailHost', ''),
                "cosId": attrs.get('zimbraCOSId', '')
            }
            accounts.append(account_info)

        # Parse pagination information from SearchDirectoryResponse
        search_response = root.find('.//{urn:zimbraAdmin}SearchDirectoryResponse')

        returned_count = len(accounts)
        has_more = False
        total_matches = returned_count  # Default fallback

        if search_response is not None:
            # Check for searchTotal attribute (most accurate)
            if search_response.get('searchTotal'):
                total_matches = int(search_response.get('searchTotal'))

            # Check for 'more' attribute (indicates if there are more results)
            has_more = search_response.get('more') == '1'

            # If we have 'more' flag but no searchTotal, we need to estimate
            # This happens when Zimbra doesn't return searchTotal
            if not search_response.get('searchTotal'):
                if has_more:
                    # There are more results, but we don't know the total
                    # Return a conservative estimate: at least offset + returned + 1
                    total_matches = offset + returned_count + 1
                    logger.warning(f"SearchDirectoryResponse missing searchTotal attribute, estimating total_matches as {total_matches}+")
                else:
                    # No more results, total is offset + what we got
                    total_matches = offset + returned_count

        # Create display message for user clarity
        display_msg = create_pagination_message(returned_count, total_matches, has_more, "accounts")

        return json.dumps({
            "status": "success",
            "display_message": display_msg,
            "filters": {
                "domain": domain,
                "account_status": status_filter
            },
            "pagination": {
                "offset": offset,
                "page_size": limit,
                "returned_count": returned_count,
                "total_matches": total_matches,
                "has_more": has_more,
                "next_offset": offset + returned_count if has_more else None
            },
            "accounts": accounts
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to get all accounts: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to get all accounts: {str(e)}"
        }, indent=2)

@admin_only_tool()
def getAccountCount(domain: Optional[str] = None, status_filter: Optional[str] = None) -> str:
    """Get total account count with optional domain and status filtering.

    Args:
        domain: Filter by domain. Example: "example.com" or "a.com,b.com". Default: all domains.
        status_filter: Filter by status. Values: "active", "closed", "locked", "lockout", "maintenance", "pending". Default: all.
    """
    logger.info(f"Getting account count (domain={domain}, status={status_filter})")

    try:
        # First, try to get count from pagination with a small query
        result = getAllAccounts(domain=domain, limit=100, offset=0, status_filter=status_filter)
        result_data = json.loads(result)

        if result_data.get('status') != 'success':
            return result

        pagination = result_data.get('pagination', {})
        total_matches = pagination.get('total_matches', 0)
        has_more = pagination.get('has_more', False)

        # If Zimbra provided searchTotal, use it (most accurate)
        if total_matches > 0 and not has_more:
            # We got all results in one query
            counting_method = "complete_query"
        elif total_matches > pagination.get('returned_count', 0):
            # Zimbra provided searchTotal
            counting_method = "zimbra_searchTotal"
        else:
            # Need to count by iterating (Zimbra didn't provide searchTotal)
            logger.info("Zimbra didn't provide searchTotal, counting all accounts...")
            total_count = 0
            offset = 0
            page_size = 1000  # Large page size for efficiency

            while True:
                result = getAllAccounts(domain=domain, limit=page_size, offset=offset, status_filter=status_filter)
                result_data = json.loads(result)

                if result_data.get('status') != 'success':
                    return result

                page_pagination = result_data.get('pagination', {})
                returned = page_pagination.get('returned_count', 0)
                total_count += returned

                if not page_pagination.get('has_more', False):
                    break

                offset += returned

            total_matches = total_count
            counting_method = "full_iteration"

        return json.dumps({
            "status": "success",
            "filters": {
                "domain": domain,
                "account_status": status_filter
            },
            "total_count": total_matches,
            "counting_method": counting_method
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to get account count: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to get account count: {str(e)}"
        }, indent=2)

# ------------------- Distribution List -------------------

@admin_only_tool()
def getDLInfo(dl_email: str) -> str:
    """Get distribution list (DL) information and settings. Supports both static DLs and dynamic groups.

    Args:
        dl_email: Distribution list email address. Example: "group@example.com". Case-insensitive.
    """
    logger.info(f"Getting DL info for {dl_email}")

    try:
        soap_body = f"""
        <GetDistributionListRequest xmlns="urn:zimbraAdmin">
            <dl by="name">{dl_email}</dl>
        </GetDistributionListRequest>
        """

        root = query_zimbra_api(soap_body)
        parse_zimbra_response(root)

        ns = {'zimbra': 'urn:zimbraAdmin'}

        # Look for both static DL and dynamic group
        dl_elem = root.find('.//zimbra:dl', ns)
        is_dynamic = False

        if dl_elem is None:
            dl_elem = root.find('.//zimbra:dynamicGroup', ns)
            is_dynamic = True

        if dl_elem is None:
            return json.dumps({
                "status": "error",
                "message": f"Distribution list not found: {dl_email}"
            }, indent=2)

        # Determine dynamic status from element type, attribute, or memberURL
        attrs = parse_attributes(dl_elem)
        if not is_dynamic:
            is_dynamic = (
                dl_elem.get('dynamic', 'false') in ('true', '1') or
                'memberURL' in attrs or
                'zimbraMemberURL' in attrs
            )

        dl_info = {
            "id": dl_elem.get('id'),
            "name": dl_elem.get('name'),
            "dynamic": is_dynamic,
            "attributes": attrs
        }

        logger.debug(f"Retrieved {'dynamic group' if is_dynamic else 'DL'} info for {dl_email}")

        return json.dumps({
            "status": "success",
            "dl": dl_info
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to get DL info: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to get DL info: {str(e)}"
        }, indent=2)

@admin_only_tool()
def getDLMembers(dl_email: str, limit: int = 100, offset: int = 0) -> str:
    """List members of a distribution list with pagination.

    Args:
        dl_email: Distribution list email address. Example: "group@example.com". Case-insensitive.
        limit: Max results per page. Default: 100. Range: 1-1000.
        offset: Starting position for pagination. Default: 0.
    """
    logger.info(f"Getting DL members for {dl_email} (limit={limit}, offset={offset})")

    try:
        soap_body = f"""
        <GetDistributionListRequest xmlns="urn:zimbraAdmin" limit="{limit}" offset="{offset}">
            <dl by="name">{dl_email}</dl>
        </GetDistributionListRequest>
        """

        root = query_zimbra_api(soap_body)
        parse_zimbra_response(root)

        ns = {'zimbra': 'urn:zimbraAdmin'}

        # Look for both static DL and dynamic group
        dl_elem = root.find('.//zimbra:dl', ns)
        is_dynamic = False

        if dl_elem is None:
            dl_elem = root.find('.//zimbra:dynamicGroup', ns)
            is_dynamic = True

        if dl_elem is None:
            return json.dumps({
                "status": "error",
                "message": f"Distribution list not found: {dl_email}"
            }, indent=2)

        members = []
        for member_elem in dl_elem.findall('.//zimbra:dlm', ns):
            members.append(member_elem.text)

        logger.debug(f"Found {len(members)} members in {'dynamic group' if is_dynamic else 'DL'} {dl_email}")

        total_members = int(dl_elem.get('total', len(members)))
        returned_count = len(members)
        has_more = (offset + returned_count) < total_members

        # Create display message for user clarity
        display_msg = create_pagination_message(returned_count, total_members, has_more, "members")

        return json.dumps({
            "status": "success",
            "dl_email": dl_email,
            "display_message": display_msg,
            "pagination": {
                "offset": offset,
                "page_size": limit,
                "returned_count": returned_count,
                "total_members": total_members,
                "has_more": has_more,
                "next_offset": offset + returned_count if has_more else None
            },
            "members": members
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to get DL members: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to get DL members: {str(e)}"
        }, indent=2)

@admin_only_tool()
def getAllDistributionLists(domain: Optional[str] = None, limit: int = 100, offset: int = 0, include_member_count: bool = False) -> str:
    """List all distribution lists (static and dynamic) with optional domain filtering.

    Args:
        domain: Filter by domain. Example: "example.com" or "a.com,b.com". Default: all domains.
        limit: Max results per page. Default: 100. Range: 1-1000.
        offset: Starting position for pagination. Default: 0.
        include_member_count: Include accurate member count per DL. Default: false. Warning: slow for many DLs.
    """
    logger.info(f"Getting all distribution lists (domain={domain}, limit={limit}, offset={offset}, include_member_count={include_member_count})")

    try:
        domain_query = ""
        if domain:
            domains = [d.strip() for d in domain.split(',')]
            if len(domains) == 1:
                domain_query = f'<domain by="name">{domains[0]}</domain>'
            else:
                for d in domains:
                    domain_query += f'<domain by="name">{d}</domain>'

        soap_body = f"""
        <SearchDirectoryRequest xmlns="urn:zimbraAdmin"
                                limit="{limit}"
                                offset="{offset}"
                                sortBy="name"
                                types="distributionlists,dynamicgroups">
            {domain_query}
        </SearchDirectoryRequest>
        """

        root = query_zimbra_api(soap_body)
        parse_zimbra_response(root)

        # Debug logging to see actual response
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"SearchDirectoryRequest XML response:\n{ET.tostring(root, encoding='unicode')}")

        ns = {'zimbra': 'urn:zimbraAdmin'}

        # Query both static DLs (<dl>) and dynamic groups (<dynamicGroup>)
        dl_elems = root.findall('.//zimbra:dl', ns)
        dynamic_elems = root.findall('.//zimbra:dynamicGroup', ns)

        # Combine both types
        all_elems = list(dl_elems) + list(dynamic_elems)

        logger.debug(f"Found {len(dl_elems)} static DLs and {len(dynamic_elems)} dynamic groups")

        distribution_lists = []
        for dl_elem in all_elems:
            attrs = parse_attributes(dl_elem)
            dl_name = dl_elem.get('name')

            # Determine if this is a dynamic group
            # Dynamic groups have memberURL attribute (LDAP query for members)
            # Static DLs have static member list
            is_dynamic = (
                dl_elem.tag.endswith('dynamicGroup') or
                dl_elem.get('dynamic', 'false') in ('true', '1') or
                'memberURL' in attrs or
                'zimbraMemberURL' in attrs
            )

            # Get member count if requested (requires additional API call per DL)
            member_count = None
            if include_member_count and dl_name:
                try:
                    # Query this DL/dynamic group to get member count
                    dl_soap = f"""
                    <GetDistributionListRequest xmlns="urn:zimbraAdmin">
                        <dl by="name">{dl_name}</dl>
                    </GetDistributionListRequest>
                    """
                    dl_root = query_zimbra_api(dl_soap, enable_cache=False)
                    parse_zimbra_response(dl_root)

                    # Look for both <dl> and <dynamicGroup> elements
                    dl_detail = dl_root.find('.//zimbra:dl', ns)
                    if dl_detail is None:
                        dl_detail = dl_root.find('.//zimbra:dynamicGroup', ns)

                    if dl_detail is not None:
                        # Get total attribute from DL/dynamicGroup element
                        member_count = int(dl_detail.get('total', '0'))
                        logger.debug(f"{'Dynamic group' if is_dynamic else 'DL'} {dl_name} has {member_count} members")
                except Exception as e:
                    logger.warning(f"Failed to get member count for {dl_name}: {e}")
                    member_count = None

            dl_info = {
                "id": dl_elem.get('id'),
                "name": dl_name,
                "displayName": attrs.get('displayName', ''),
                "dynamic": is_dynamic,
                "description": attrs.get('description', ''),
                "memberCount": member_count
            }
            distribution_lists.append(dl_info)

        # Parse pagination information from SearchDirectoryResponse
        search_response = root.find('.//{urn:zimbraAdmin}SearchDirectoryResponse')

        returned_count = len(distribution_lists)
        has_more = False
        total_matches = returned_count  # Default fallback

        if search_response is not None:
            # Check for searchTotal attribute (most accurate)
            if search_response.get('searchTotal'):
                total_matches = int(search_response.get('searchTotal'))

            # Check for 'more' attribute (indicates if there are more results)
            has_more = search_response.get('more') == '1'

            # If we have 'more' flag but no searchTotal
            if not search_response.get('searchTotal'):
                if has_more:
                    total_matches = offset + returned_count + 1
                    logger.warning(f"SearchDirectoryResponse missing searchTotal attribute, estimating total_matches as {total_matches}+")
                else:
                    total_matches = offset + returned_count

        # Create display message for user clarity
        display_msg = create_pagination_message(returned_count, total_matches, has_more, "distribution lists")

        return json.dumps({
            "status": "success",
            "display_message": display_msg,
            "filters": {
                "domain": domain
            },
            "pagination": {
                "offset": offset,
                "page_size": limit,
                "returned_count": returned_count,
                "total_matches": total_matches,
                "has_more": has_more,
                "next_offset": offset + returned_count if has_more else None
            },
            "distribution_lists": distribution_lists
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to get all distribution lists: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to get all distribution lists: {str(e)}"
        }, indent=2)

# ------------------- System Status -------------------

@admin_only_tool()
def getServerList(attrs: str = "minimal") -> str:
    """List all Zimbra servers in the deployment with configurable detail level.

    Args:
        attrs: Detail level. Values: "minimal" (id+name only, recommended), "essential" (adds services+version), "full" (all attributes, may overflow). Default: "minimal".
    """
    logger.info("Getting server list")

    try:
        soap_body = """
        <GetAllServersRequest xmlns="urn:zimbraAdmin"/>
        """

        root = query_zimbra_api(soap_body)
        parse_zimbra_response(root)

        ns = {
            'soap': 'http://www.w3.org/2003/05/soap-envelope',
            'zimbra': 'urn:zimbraAdmin'
        }

        response_elem = root.find('.//zimbra:GetAllServersResponse', ns)
        if response_elem is None:
            response_elem = root.find('.//{urn:zimbraAdmin}GetAllServersResponse')

        if response_elem is not None:
            server_elems = response_elem.findall('zimbra:server', ns)
            if not server_elems:
                server_elems = response_elem.findall('{urn:zimbraAdmin}server')
        else:
            server_elems = root.findall('.//zimbra:server', ns)
            if not server_elems:
                server_elems = root.findall('.//{urn:zimbraAdmin}server')

        logger.debug(f"Found {len(server_elems)} servers")

        # Define essential attributes (minimal set for essential mode)
        ESSENTIAL_ATTRS = [
            'zimbraServiceEnabled',
            'zimbraServerVersion',
            'cn'
        ]

        servers = []
        for server_elem in server_elems:
            server_id = server_elem.get('id')
            server_name = server_elem.get('name')

            logger.debug(f"Processing server: {server_name} (ID: {server_id})")

            server_info = {
                "id": server_id,
                "name": server_name
            }

            # Add attributes based on mode
            if attrs == "minimal":
                # Minimal mode: Only id and name, no attributes at all
                pass  # server_info already has id and name only

            elif attrs == "essential":
                # Essential mode: Parse and return only essential attributes
                all_attributes = parse_attributes(server_elem)
                attributes = {
                    key: all_attributes[key]
                    for key in ESSENTIAL_ATTRS
                    if key in all_attributes
                }
                server_info["attributes"] = attributes

            elif attrs == "full":
                # Full mode: Return all attributes (may cause overflow!)
                all_attributes = parse_attributes(server_elem)
                server_info["attributes"] = all_attributes

            else:
                # Invalid mode, default to minimal
                logger.warning(f"Invalid attrs mode '{attrs}', using minimal")

            servers.append(server_info)

        if not servers:
            logger.warning("No servers found in response")

        # Create display message based on mode
        if attrs == "minimal":
            mode_desc = "names only"
        elif attrs == "essential":
            mode_desc = "essential attributes"
        elif attrs == "full":
            mode_desc = "full attributes"
        else:
            mode_desc = "names only"
            attrs = "minimal"  # Normalize invalid mode

        display_msg = f"Found {len(servers)} servers ({mode_desc})"

        return json.dumps({
            "status": "success",
            "servers": servers,
            "count": len(servers),
            "display_message": display_msg,
            "mode": attrs
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to get server list: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to get server list: {str(e)}"
        }, indent=2)

@admin_only_tool()
def getServerStatus(server_name: Optional[str] = None) -> str:
    """Get real-time service health status (running/stopped) for Zimbra servers.

    Args:
        server_name: Server hostname. Example: "mail.example.com". Default: all servers.
    """
    logger.info(f"Getting server status for {server_name or 'all servers'}")

    def parse_server_status(root: ET.Element, expected_server: str = None) -> List[Dict[str, Any]]:
        """Parse server status from XML response

        Zimbra GetServiceStatusResponse format:
        <status server="mail.example.com" t="1234567890" service="mailbox">1</status>

        Where:
        - server attribute: server hostname
        - service attribute: service name
        - text content: "1" = running, "0" = stopped
        - t attribute: timestamp
        """

        # Debug: Log the raw XML response
        xml_string = ET.tostring(root, encoding='unicode')
        logger.debug(f"Raw XML response (first 1500 chars): {xml_string[:1500]}")

        def normalize_status(value: str) -> str:
            """Convert numeric status codes to text"""
            if not value:
                return "unknown"

            value_stripped = value.strip()

            # Zimbra numeric status codes (confirmed from actual API response):
            # 1 = running
            # 0 = stopped
            if value_stripped == "1":
                return "running"
            elif value_stripped == "0":
                return "stopped"

            # Handle text formats (case-insensitive)
            value_lower = value_stripped.lower()
            if value_lower in ["running", "started", "up", "active"]:
                return "running"
            elif value_lower in ["stopped", "down", "inactive"]:
                return "stopped"

            # Return original value if not recognized
            return value_stripped

        # Parse the actual Zimbra response format
        # Format: <status server="X" service="Y" t="Z">1</status>
        status_elems = root.findall('.//{urn:zimbraAdmin}status')

        logger.debug(f"Found {len(status_elems)} status elements")

        if not status_elems:
            logger.warning("No status elements found in response")
            return []

        # Group services by server
        servers_dict = {}

        for status_elem in status_elems:
            server_name = status_elem.get('server', expected_server or 'unknown')
            service_name = status_elem.get('service', 'unknown')
            timestamp = status_elem.get('t')
            status_value = status_elem.text or 'unknown'

            # Convert timestamp to datetime if present
            time_value = None
            if timestamp:
                try:
                    from datetime import datetime
                    time_value = datetime.fromtimestamp(int(timestamp)).isoformat()
                except:
                    time_value = timestamp

            # Normalize status value
            normalized_status = normalize_status(status_value)

            logger.debug(f"Parsed: server={server_name}, service={service_name}, "
                        f"raw_status={status_value}, normalized={normalized_status}")

            # Add to server's services list
            if server_name not in servers_dict:
                servers_dict[server_name] = []

            servers_dict[server_name].append({
                "name": service_name,
                "status": normalized_status,
                "time": time_value
            })

        # Convert dict to list format
        servers_status = []
        for server_name, services in servers_dict.items():
            servers_status.append({
                "server": server_name,
                "services": services,
                "service_count": len(services)
            })

        return servers_status

    try:
        if not server_name:
            # Query all servers
            servers_list_result = getServerList()
            servers_list_data = json.loads(servers_list_result)

            if servers_list_data.get('status') != 'success':
                return servers_list_result

            all_servers_status = []
            for server in servers_list_data.get('servers', []):
                server_hostname = server.get('name')
                if not server_hostname:
                    continue

                # Try multiple SOAP request formats
                soap_formats = [
                    f'<GetServiceStatusRequest xmlns="urn:zimbraAdmin"/>',  # No server specified
                    f'<GetServiceStatusRequest xmlns="urn:zimbraAdmin"><hostname>{server_hostname}</hostname></GetServiceStatusRequest>',
                ]

                server_status_found = False
                for soap_body in soap_formats:
                    try:
                        logger.debug(f"Trying SOAP format for {server_hostname}: {soap_body[:100]}")
                        root = query_zimbra_api(soap_body, enable_cache=False)
                        parse_zimbra_response(root)

                        servers_status = parse_server_status(root, server_hostname)

                        if servers_status:
                            all_servers_status.extend(servers_status)
                            server_status_found = True
                            logger.debug(f"Successfully got status for {server_hostname}")
                            break
                    except Exception as format_error:
                        logger.debug(f"SOAP format failed for {server_hostname}: {format_error}")
                        continue

                if not server_status_found:
                    logger.warning(f"Could not get status for {server_hostname}")
                    all_servers_status.append({
                        "server": server_hostname,
                        "error": "Could not retrieve service status",
                        "services": []
                    })

            return json.dumps({
                "status": "success",
                "total_servers": len(all_servers_status),
                "servers": all_servers_status
            }, indent=2)

        else:
            # Query specific server - try multiple formats
            soap_formats = [
                f'<GetServiceStatusRequest xmlns="urn:zimbraAdmin"/>',  # Format 1: No server (gets all)
                f'<GetServiceStatusRequest xmlns="urn:zimbraAdmin"><hostname>{server_name}</hostname></GetServiceStatusRequest>',  # Format 2: hostname
            ]

            last_error = None
            for i, soap_body in enumerate(soap_formats):
                try:
                    logger.debug(f"Attempting SOAP format {i+1} for {server_name}")
                    root = query_zimbra_api(soap_body, enable_cache=False)
                    parse_zimbra_response(root)

                    servers_status = parse_server_status(root, server_name)

                    if servers_status:
                        logger.info(f"Successfully retrieved status for {server_name} using format {i+1}")
                        return json.dumps({
                            "status": "success",
                            "servers": servers_status
                        }, indent=2)
                    else:
                        logger.debug(f"Format {i+1} returned no servers")

                except Exception as e:
                    last_error = str(e)
                    logger.debug(f"Format {i+1} failed: {e}")
                    continue

            # If all formats failed
            logger.error(f"All SOAP formats failed for {server_name}")
            return json.dumps({
                "status": "error",
                "message": f"Could not retrieve service status for {server_name}",
                "last_error": last_error,
                "hint": "The server exists but service status could not be retrieved. This may be a permissions issue or API compatibility issue."
            }, indent=2)

    except Exception as e:
        logger.error(f"Failed to get server status: {e}")
        import traceback
        logger.debug(traceback.format_exc())
        return json.dumps({
            "status": "error",
            "message": f"Failed to get server status: {str(e)}"
        }, indent=2)

@admin_only_tool()
def getActiveSessions(list_sessions: bool = False, group_by_account: bool = False) -> str:
    """Get currently active user sessions (SOAP, IMAP, POP3, admin) for monitoring.

    Args:
        list_sessions: Return detailed session list. Default: false (counts only, faster).
        group_by_account: Group sessions by user account. Default: false.
    """
    logger.info(f"Getting active sessions (list={list_sessions}, group={group_by_account})")

    try:
        # Build SOAP request
        list_attr = 'listSessions="1"' if list_sessions else ''
        group_attr = 'groupByAccount="1"' if group_by_account else ''

        soap_body = f"""
        <DumpSessionsRequest xmlns="urn:zimbraAdmin" {list_attr} {group_attr}/>
        """

        root = query_zimbra_api(soap_body, enable_cache=False)  # Don't cache - real-time data
        parse_zimbra_response(root)

        ns = {'zimbra': 'urn:zimbraAdmin'}

        # Parse session counts
        response_elem = root.find('.//zimbra:DumpSessionsResponse', ns)

        summary = {
            "total_sessions": 0,
            "soap_sessions": 0,
            "imap_sessions": 0,
            "pop3_sessions": 0,
            "admin_sessions": 0
        }

        if response_elem is not None:
            # Parse different session types
            for session_type in ['soap', 'imap', 'pop3', 'admin']:
                elem = response_elem.find(f'.//zimbra:{session_type}Session', ns)
                if elem is not None:
                    count = int(elem.get('activeAccounts', 0))
                    summary[f"{session_type}_sessions"] = count
                    summary["total_sessions"] += count
                    logger.debug(f"{session_type} sessions: {count}")

        result = {
            "status": "success",
            "summary": summary
        }

        # Parse detailed session list if requested
        if list_sessions:
            sessions = []

            # Parse SOAP sessions
            for soap_elem in root.findall('.//zimbra:soapSession/zimbra:zid', ns):
                session = {
                    "account": soap_elem.get('name', 'N/A'),
                    "protocol": "SOAP",
                    "session_count": int(soap_elem.get('activeCount', 1))
                }
                sessions.append(session)

            # Parse IMAP sessions
            for imap_elem in root.findall('.//zimbra:imapSession/zimbra:zid', ns):
                session = {
                    "account": imap_elem.get('name', 'N/A'),
                    "protocol": "IMAP",
                    "session_count": int(imap_elem.get('activeCount', 1))
                }
                sessions.append(session)

            # Parse Admin sessions
            for admin_elem in root.findall('.//zimbra:adminSession/zimbra:zid', ns):
                session = {
                    "account": admin_elem.get('name', 'N/A'),
                    "protocol": "Admin",
                    "session_count": int(admin_elem.get('activeCount', 1))
                }
                sessions.append(session)

            result["sessions"] = sessions
            result["session_detail_count"] = len(sessions)

            # Create display message
            if sessions:
                display_msg = f"Showing {len(sessions)} active users ({summary['total_sessions']} total sessions)"
            else:
                display_msg = "No active sessions currently"

            result["display_message"] = display_msg

        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error(f"Failed to get active sessions: {e}")
        import traceback
        logger.debug(traceback.format_exc())
        return json.dumps({
            "status": "error",
            "message": f"Failed to get active sessions: {str(e)}"
        }, indent=2)

# ------------------- Domain & COS -------------------

@admin_only_tool()
def getDomainList(limit: int = 50,
                  offset: int = 0,
                  include_attrs: bool = False) -> str:
    """List all email domains configured in Zimbra with pagination.

    Args:
        limit: Max results per page. Default: 50. Recommended: 20-50 with attrs, 100-200 without.
        offset: Starting position for pagination. Default: 0.
        include_attrs: Include full domain attributes. Default: false (names only, recommended).
    """
    logger.info(f"Getting domain list: limit={limit}, offset={offset}, include_attrs={include_attrs}")

    try:
        # Validate limit
        if limit > 1000:
            limit = 1000
            logger.warning(f"Limit exceeds maximum (1000), using 1000")

        soap_body = """
        <GetAllDomainsRequest xmlns="urn:zimbraAdmin"/>
        """

        root = query_zimbra_api(soap_body)
        parse_zimbra_response(root)

        ns = {'zimbra': 'urn:zimbraAdmin'}
        domain_elems = root.findall('.//zimbra:domain', ns)

        # Get total count
        total_domains = len(domain_elems)

        # Apply pagination
        paginated_elems = domain_elems[offset:offset + limit]
        returned_count = len(paginated_elems)

        domains = []
        for domain_elem in paginated_elems:
            if include_attrs:
                # Include full attributes
                domain_info = {
                    "id": domain_elem.get('id'),
                    "name": domain_elem.get('name'),
                    "attributes": parse_attributes(domain_elem)
                }
            else:
                # Names and IDs only (RECOMMENDED)
                domain_info = {
                    "id": domain_elem.get('id'),
                    "name": domain_elem.get('name')
                }
            domains.append(domain_info)

        # Calculate pagination info
        has_more = (offset + returned_count) < total_domains
        next_offset = offset + returned_count if has_more else None

        # Create display message
        mode = "with full attributes" if include_attrs else "names only"
        if has_more:
            display_msg = f"Showing domains {offset + 1}-{offset + returned_count} ({mode}), {total_domains} total, more available"
        else:
            display_msg = f"Showing {returned_count} domains ({mode}), {total_domains} total"

        return json.dumps({
            "status": "success",
            "domains": domains,
            "pagination": {
                "offset": offset,
                "limit": limit,
                "returned_count": returned_count,
                "total_domains": total_domains,
                "has_more": has_more,
                "next_offset": next_offset
            },
            "display_message": display_msg
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to get domain list: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to get domain list: {str(e)}"
        }, indent=2)

@admin_only_tool()
def getDomainInfo(domain_name: str) -> str:
    """Get detailed configuration and all attributes for a specific domain.

    Args:
        domain_name: Domain name. Example: "example.com". Case-insensitive.
    """
    logger.info(f"Getting domain info for {domain_name}")

    try:
        soap_body = f"""
        <GetDomainRequest xmlns="urn:zimbraAdmin">
            <domain by="name">{domain_name}</domain>
        </GetDomainRequest>
        """

        root = query_zimbra_api(soap_body)
        parse_zimbra_response(root)

        ns = {'zimbra': 'urn:zimbraAdmin'}
        domain_elem = root.find('.//zimbra:domain', ns)

        if domain_elem is None:
            return json.dumps({
                "status": "error",
                "message": f"Domain not found: {domain_name}"
            }, indent=2)

        domain_info = {
            "id": domain_elem.get('id'),
            "name": domain_elem.get('name'),
            "attributes": parse_attributes(domain_elem)
        }

        return json.dumps({
            "status": "success",
            "domain": domain_info
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to get domain info: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to get domain info: {str(e)}"
        }, indent=2)

@admin_only_tool()
def getCOSList(limit: int = 20,
               offset: int = 0,
               include_attrs: bool = False) -> str:
    """List all Class of Service (COS) definitions with pagination.

    Args:
        limit: Max results per page. Default: 20. Max: 100.
        offset: Starting position for pagination. Default: 0.
        include_attrs: Include full COS attributes. Default: false (names only, recommended).
    """
    logger.info(f"Getting COS list: limit={limit}, offset={offset}, include_attrs={include_attrs}")

    try:
        # Validate limit
        if limit > 100:
            limit = 100
            logger.warning(f"Limit exceeds maximum (100), using 100")

        soap_body = """
        <GetAllCosRequest xmlns="urn:zimbraAdmin"/>
        """

        root = query_zimbra_api(soap_body)
        parse_zimbra_response(root)

        ns = {'zimbra': 'urn:zimbraAdmin'}
        cos_elems = root.findall('.//zimbra:cos', ns)

        # Get total count
        total_cos = len(cos_elems)

        # Apply pagination
        paginated_elems = cos_elems[offset:offset + limit]
        returned_count = len(paginated_elems)

        cos_list = []
        for cos_elem in paginated_elems:
            if include_attrs:
                # Include full attributes
                cos_info = {
                    "id": cos_elem.get('id'),
                    "name": cos_elem.get('name'),
                    "attributes": parse_attributes(cos_elem)
                }
            else:
                # Names and IDs only (RECOMMENDED)
                cos_info = {
                    "id": cos_elem.get('id'),
                    "name": cos_elem.get('name')
                }
            cos_list.append(cos_info)

        # Calculate pagination info
        has_more = (offset + returned_count) < total_cos
        next_offset = offset + returned_count if has_more else None

        # Create display message
        mode = "with full attributes" if include_attrs else "names only"
        if has_more:
            display_msg = f"Showing COS {offset + 1}-{offset + returned_count} ({mode}), {total_cos} total, more available"
        else:
            display_msg = f"Showing {returned_count} COS ({mode}), {total_cos} total"

        return json.dumps({
            "status": "success",
            "cos_list": cos_list,
            "pagination": {
                "offset": offset,
                "limit": limit,
                "returned_count": returned_count,
                "total_cos": total_cos,
                "has_more": has_more,
                "next_offset": next_offset
            },
            "display_message": display_msg
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to get COS list: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to get COS list: {str(e)}"
        }, indent=2)

@admin_only_tool()
def getCOSInfo(cos_name: str,
               attr_filter: Optional[str] = None,
               limit: int = 0,
               offset: int = 0) -> str:
    """Get detailed COS settings with optional regex attribute filtering.

    Args:
        cos_name: COS name. Example: "default", "premium". Case-sensitive.
        attr_filter: Regex to filter attributes. Example: "password", "quota|limit", ".*" (all). Default: common attributes only.
        limit: Max attributes to return. Default: 0 (unlimited).
        offset: Starting position in attribute list. Default: 0.
    """
    logger.info(f"Getting COS info for '{cos_name}' with filter: {attr_filter or 'common-only'}")

    # Define commonly-used attributes to return when no filter is specified
    COMMON_ATTRIBUTES = [
        # Identity
        'zimbraId', 'cn', 'description',
        # Quota
        'zimbraMailQuota', 'zimbraAttachmentMaxSize', 'zimbraFileUploadMaxSize',
        # Password policy
        'zimbraPasswordMinLength', 'zimbraPasswordMaxLength',
        'zimbraPasswordMinUpperCaseChars', 'zimbraPasswordMinLowerCaseChars',
        'zimbraPasswordMinPunctuationChars', 'zimbraPasswordMinNumericChars',
        'zimbraPasswordMinAge', 'zimbraPasswordMaxAge',
        'zimbraPasswordEnforceHistory', 'zimbraPasswordLocked',
        # Mail features
        'zimbraFeatureMailEnabled', 'zimbraFeatureIMAPEnabled',
        'zimbraFeaturePOP3Enabled', 'zimbraFeatureWebClientEnabled',
        'zimbraFeatureMobileSyncEnabled', 'zimbraFeatureCalendarEnabled',
        # Limits
        'zimbraMailMessageLifetime', 'zimbraMailTrashLifetime',
        'zimbraMailSpamLifetime', 'zimbraMailItemsPerPage',
        # Other important
        'zimbraMailHost', 'zimbraMailTransport', 'zimbraMailStatus'
    ]

    try:
        # Query COS by name
        soap_body = f"""
        <GetCosRequest xmlns="urn:zimbraAdmin">
            <cos by="name">{cos_name}</cos>
        </GetCosRequest>
        """

        root = query_zimbra_api(soap_body)
        parse_zimbra_response(root)

        ns = {'zimbra': 'urn:zimbraAdmin'}
        cos_elem = root.find('.//zimbra:cos', ns)

        if cos_elem is None:
            return json.dumps({
                "status": "error",
                "message": f"COS '{cos_name}' not found"
            }, indent=2)

        cos_id = cos_elem.get('id')
        cos_name_result = cos_elem.get('name')

        # Parse all attributes
        all_attributes = parse_attributes(cos_elem)
        total_attrs = len(all_attributes)

        # Determine mode and select attributes
        if attr_filter:
            import re
            try:
                pattern = re.compile(attr_filter, re.IGNORECASE)
                selected_attrs = {
                    key: value
                    for key, value in all_attributes.items()
                    if pattern.search(key)
                }
                mode = "filtered"
                filter_pattern = attr_filter

            except re.error as e:
                return json.dumps({
                    "status": "error",
                    "message": f"Invalid regex pattern '{attr_filter}': {str(e)}"
                }, indent=2)
        else:
            # No filter - return only common attributes to prevent overflow
            selected_attrs = {
                key: all_attributes[key]
                for key in COMMON_ATTRIBUTES
                if key in all_attributes
            }
            mode = "common"
            filter_pattern = None

        # Apply pagination to selected attributes
        matched_count = len(selected_attrs)

        # Sort attributes alphabetically for consistent pagination
        sorted_keys = sorted(selected_attrs.keys())

        # Apply offset and limit
        if limit > 0:
            paginated_keys = sorted_keys[offset:offset + limit]
        else:
            # limit = 0 means unlimited
            paginated_keys = sorted_keys[offset:]

        paginated_attrs = {key: selected_attrs[key] for key in paginated_keys}
        returned_count = len(paginated_attrs)

        # Create display message
        has_more = (offset + returned_count) < matched_count
        display_msg = create_pagination_message(returned_count, matched_count, has_more, "attributes")

        # Build result
        result = {
            "status": "success",
            "cos_id": cos_id,
            "cos_name": cos_name_result,
            "mode": mode,
            "total_attributes": total_attrs,
            "matched_attributes": matched_count,
            "returned_attributes": returned_count,
            "attributes": paginated_attrs,
            "display_message": display_msg
        }

        # Add filter pattern if used
        if filter_pattern:
            result["filter_pattern"] = filter_pattern

            # Add warning if using ".*" pattern without limit
            if filter_pattern in [".*", ".+", ".*.*"] and limit == 0:
                result["warning"] = "Returning ALL attributes - this may cause context overflow! Consider using limit parameter."
        else:
            # Add suggestions for common mode
            result["note"] = "Showing commonly-used attributes only. Use attr_filter to get specific settings."
            result["suggestions"] = {
                "password_settings": "attr_filter='password'",
                "quota_settings": "attr_filter='quota|limit'",
                "mail_features": "attr_filter='feature.*mail|mail.*feature'",
                "all_attributes": "attr_filter='.*', limit=50 (get first 50 of all attributes)"
            }

        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error(f"Failed to get COS info: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to get COS info: {str(e)}"
        }, indent=2)

# ------------------- Mail Queue -------------------

@admin_only_tool()
def getQueueStat(server_name: str) -> str:
    """Get mail queue message counts (deferred, active, incoming, corrupt, hold) for an MTA server.

    Args:
        server_name: MTA server hostname. Example: "mail.example.com".
    """
    logger.info(f"Getting queue stats for {server_name}")

    try:
        soap_body = f"""
        <GetMailQueueInfoRequest xmlns="urn:zimbraAdmin">
            <server name="{server_name}"/>
        </GetMailQueueInfoRequest>
        """

        root = query_zimbra_api(soap_body, enable_cache=False)
        parse_zimbra_response(root)

        ns = {'zimbra': 'urn:zimbraAdmin'}
        server_elem = root.find('.//zimbra:server', ns)

        if server_elem is None:
            return json.dumps({
                "status": "error",
                "message": f"Queue info not found for server: {server_name}"
            }, indent=2)

        queues = {}
        for queue_elem in server_elem.findall('.//zimbra:queue', ns):
            queue_name = queue_elem.get('name')
            queue_count = int(queue_elem.get('n', 0))
            queues[queue_name] = queue_count

        return json.dumps({
            "status": "success",
            "server": server_name,
            "queues": queues,
            "total": sum(queues.values())
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to get queue stats: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to get queue stats: {str(e)}"
        }, indent=2)

@admin_only_tool()
def getQueueList(server_name: str,
                 queue_name: str = "deferred",
                 limit: int = 100,
                 offset: int = 0) -> str:
    """List individual messages in an MTA mail queue (undelivered/pending) with sender, recipients, and failure reasons.

    Args:
        server_name: MTA server hostname. Example: "mail.example.com".
        queue_name: Queue to list. Values: "deferred", "active", "incoming", "corrupt", "hold". Default: "deferred".
        limit: Max results per page. Default: 100. Range: 1-1000.
        offset: Starting position for pagination. Default: 0.
    """
    logger.info(f"Getting queue list for {server_name} queue {queue_name}")

    try:
        soap_body = f"""
        <GetMailQueueRequest xmlns="urn:zimbraAdmin">
            <server name="{server_name}"/>
            <queue name="{queue_name}" scan="1"/>
        </GetMailQueueRequest>
        """

        root = query_zimbra_api(soap_body, enable_cache=False)
        parse_zimbra_response(root)

        ns = {'zimbra': 'urn:zimbraAdmin'}
        queue_elem = root.find('.//zimbra:queue', ns)

        all_messages = []
        if queue_elem is not None:
            for qi_elem in queue_elem.findall('.//zimbra:qi', ns):
                message_info = {
                    "id": qi_elem.get('id', 'N/A'),
                    "size": int(qi_elem.get('size', 0)),
                    "time": qi_elem.get('time', 'N/A'),
                    "sender": qi_elem.get('from', 'N/A'),
                    "sender_domain": qi_elem.get('fromdomain', 'N/A'),
                    "recipients": []
                }

                for recipient_elem in qi_elem.findall('.//zimbra:recipient', ns):
                    recipient_info = {
                        "address": recipient_elem.get('addr', 'N/A'),
                        "reason": recipient_elem.text or 'N/A'
                    }
                    message_info["recipients"].append(recipient_info)

                all_messages.append(message_info)

        # Apply pagination on client side since API doesn't support it directly
        total = len(all_messages)
        start_idx = min(offset, total)
        end_idx = min(offset + limit, total)
        messages = all_messages[start_idx:end_idx]
        returned_count = len(messages)
        has_more = end_idx < total

        return json.dumps({
            "status": "success",
            "server": server_name,
            "queue_name": queue_name,
            "pagination": {
                "offset": offset,
                "page_size": limit,
                "returned_count": returned_count,
                "total_messages": total,
                "has_more": has_more,
                "next_offset": offset + returned_count if has_more else None
            },
            "messages": messages
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to get queue list: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to get queue list: {str(e)}"
        }, indent=2)

@admin_only_tool()
def searchMailQueue(server_name: str,
                    search_query: str,
                    queue_name: Optional[str] = None,
                    limit: int = 100) -> str:
    """Search MTA mail queues (undelivered/pending messages) for messages matching sender, recipient, or domain. Not for mailbox content — use searchMail instead.

    Args:
        server_name: MTA server hostname. Example: "mail.example.com".
        search_query: Search text to match against sender/recipient. Example: "user@example.com", "example.com".
        queue_name: Specific queue to search. Values: "deferred", "active", "incoming", "corrupt", "hold". Default: all queues.
        limit: Max results to return. Default: 100.
    """
    logger.info(f"Searching mail queue on {server_name} for: {search_query}")

    try:
        # Determine which queues to search
        if queue_name:
            queues_to_search = [queue_name]
        else:
            queues_to_search = ["deferred", "active", "incoming", "corrupt", "hold"]

        ns = {'zimbra': 'urn:zimbraAdmin'}
        all_messages = []

        for q_name in queues_to_search:
            try:
                soap_body = f"""
                <GetMailQueueRequest xmlns="urn:zimbraAdmin">
                    <server name="{server_name}"/>
                    <queue name="{q_name}" scan="1"/>
                </GetMailQueueRequest>
                """

                root = query_zimbra_api(soap_body, enable_cache=False)
                parse_zimbra_response(root)

                # Parse all messages from this queue
                for qi_elem in root.findall('.//zimbra:qi', ns):
                    message_info = {
                        "queue_id": qi_elem.get('id', 'N/A'),
                        "queue_name": q_name,
                        "size_bytes": int(qi_elem.get('size', 0)),
                        "time_in_queue": qi_elem.get('time', 'N/A'),
                        "sender": qi_elem.get('from', 'N/A'),
                        "sender_domain": qi_elem.get('fromdomain', 'N/A'),
                        "recipients": []
                    }

                    for recipient_elem in qi_elem.findall('.//zimbra:recipient', ns):
                        message_info["recipients"].append({
                            "address": recipient_elem.get('addr', 'N/A'),
                            "error": recipient_elem.text or 'N/A'
                        })

                    all_messages.append(message_info)

            except Exception as q_error:
                logger.warning(f"Failed to query queue '{q_name}': {q_error}")

        # Filter messages on client side based on search query
        matches = []
        search_lower = search_query.lower()
        for msg in all_messages:
            # Check if search query matches sender
            if search_lower in msg['sender'].lower():
                matches.append(msg)
                continue

            # Check if search query matches sender domain
            if search_lower in msg['sender_domain'].lower():
                matches.append(msg)
                continue

            # Check if search query matches any recipient
            for recip in msg['recipients']:
                if search_lower in recip['address'].lower():
                    matches.append(msg)
                    break

        # Apply limit
        matches = matches[:limit]

        return json.dumps({
            "status": "success",
            "server": server_name,
            "search_query": search_query,
            "queue_name": queue_name or "all",
            "queues_searched": queues_to_search,
            "match_count": len(matches),
            "matches": matches
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to search mail queue: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to search mail queue: {str(e)}"
        }, indent=2)

# ------------------- Mail Statistics -------------------

@admin_only_tool()
def getMailboxStats(server_name: Optional[str] = None) -> str:
    """Get aggregate mailbox count and total storage per server for capacity planning.

    Args:
        server_name: Mailbox server hostname. Example: "mail.example.com". Default: all servers.
    """
    logger.info(f"Getting mailbox stats for {server_name or 'all servers'}")

    try:
        if server_name:
            soap_body = f"""
            <GetMailboxStatsRequest xmlns="urn:zimbraAdmin">
                <hostname>{server_name}</hostname>
            </GetMailboxStatsRequest>
            """
        else:
            soap_body = """
            <GetMailboxStatsRequest xmlns="urn:zimbraAdmin"/>
            """

        root = query_zimbra_api(soap_body)
        parse_zimbra_response(root)

        ns = {'zimbra': 'urn:zimbraAdmin'}
        stats_elems = root.findall('.//zimbra:stats', ns)

        servers_stats = []
        for stats_elem in stats_elems:
            server_stat = {
                "name": stats_elem.get('name', 'N/A'),
                "mailbox_count": int(stats_elem.get('numMboxes', 0)),
                "total_size_bytes": int(stats_elem.get('totalSize', 0))
            }
            servers_stats.append(server_stat)

        return json.dumps({
            "status": "success",
            "servers": servers_stats,
            "total_servers": len(servers_stats)
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to get mailbox stats: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to get mailbox stats: {str(e)}"
        }, indent=2)
@admin_only_tool()
def getQuotaUsage(domain: Optional[str] = None,
                  limit: int = 100,
                  offset: int = 0,
                  sort_by: str = "totalUsed",
                  sort_ascending: bool = False) -> str:
    """Get ranked account quota usage for storage management (FAST, recommended).

    Args:
        domain: Filter by domain. Example: "example.com". Default: all domains.
        limit: Max results per page. Default: 100. Range: 1-1000.
        offset: Starting position for pagination. Default: 0.
        sort_by: Sort field. Values: "totalUsed", "percentUsed", "quotaLimit". Default: "totalUsed".
        sort_ascending: Sort direction. Default: false (largest first).
    """
    logger.info(f"Getting quota usage: domain={domain or 'all'}, limit={limit}, sort_by={sort_by}")

    try:
        # Build SOAP request
        domain_attr = f'domain="{domain}"' if domain else 'allServers="1"'
        sort_dir = "1" if sort_ascending else "0"

        soap_body = f"""
        <GetQuotaUsageRequest xmlns="urn:zimbraAdmin" {domain_attr}
                             limit="{limit}" offset="{offset}"
                             sortBy="{sort_by}" sortAscending="{sort_dir}"/>
        """

        root = query_zimbra_api(soap_body)
        parse_zimbra_response(root)

        ns = {'zimbra': 'urn:zimbraAdmin'}
        account_elems = root.findall('.//zimbra:account', ns)

        accounts = []
        for acc_elem in account_elems:
            used_bytes = int(acc_elem.get('used', 0))
            quota_bytes = int(acc_elem.get('limit', 0))

            # Calculate percentage
            if quota_bytes > 0:
                percentage = round((used_bytes / quota_bytes) * 100, 2)
            else:
                percentage = 0  # Unlimited quota

            accounts.append({
                "email": acc_elem.get('name', 'N/A'),
                "account_id": acc_elem.get('id', 'N/A'),
                "used_bytes": used_bytes,
                "used_mb": round(used_bytes / (1024 * 1024), 2),
                "used_gb": round(used_bytes / (1024 * 1024 * 1024), 3),
                "quota_bytes": quota_bytes,
                "quota_mb": round(quota_bytes / (1024 * 1024), 2) if quota_bytes > 0 else 0,
                "quota_gb": round(quota_bytes / (1024 * 1024 * 1024), 2) if quota_bytes > 0 else 0,
                "percentage_used": percentage
            })

        # Check if there might be more results
        returned_count = len(accounts)
        # GetQuotaUsageRequest returns up to 'limit' accounts
        # If we got exactly 'limit', there might be more
        has_more = returned_count == limit

        # Create display message for user clarity
        display_msg = create_pagination_message(returned_count, returned_count, has_more, "accounts")

        return json.dumps({
            "status": "success",
            "display_message": display_msg,
            "domain": domain or "all",
            "sort_by": sort_by,
            "sort_ascending": sort_ascending,
            "limit": limit,
            "offset": offset,
            "total_accounts": returned_count,
            "accounts": accounts
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to get quota usage: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to get quota usage: {str(e)}"
        }, indent=2)

# ------------------- Mail Tracing (jt_zmmsgtrace) -------------------

@mcp_server.tool()
def jt_zmmsgtrace_search_by_sender(sender: str,
                                    limit: int = 100,
                                    offset: int = 0) -> str:
    """Search mail delivery traces by sender email address. Supports regex.

    Args:
        sender: Sender email or regex pattern. Example: "user@example.com", "^admin@", "@example.com$".
        limit: Max results. Default: 100.
        offset: Pagination offset. Default: 0.
    """
    logger.info(f"Searching mail traces by sender: {sender}")

    try:
        params = {
            "sender": sender,
            "limit": limit,
            "offset": offset
        }

        api_response = query_jt_zmmsgtrace_api(params)
        return format_jt_zmmsgtrace_result(api_response)

    except Exception as e:
        logger.error(f"Failed to search by sender: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to search by sender: {str(e)}"
        }, indent=2)

@mcp_server.tool()
def jt_zmmsgtrace_search_by_recipient(recipient: str,
                                       limit: int = 100,
                                       offset: int = 0) -> str:
    """Search mail delivery traces by recipient email address. Supports regex.

    Args:
        recipient: Recipient email or regex pattern. Example: "user@example.com", "@example.com$".
        limit: Max results. Default: 100.
        offset: Pagination offset. Default: 0.
    """
    logger.info(f"Searching mail traces by recipient: {recipient}")

    try:
        params = {
            "recipient": recipient,
            "limit": limit,
            "offset": offset
        }

        api_response = query_jt_zmmsgtrace_api(params)
        return format_jt_zmmsgtrace_result(api_response)

    except Exception as e:
        logger.error(f"Failed to search by recipient: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to search by recipient: {str(e)}"
        }, indent=2)

@mcp_server.tool()
def jt_zmmsgtrace_search_by_message_id(message_id: str,
                                        limit: int = 100,
                                        offset: int = 0) -> str:
    """Search mail delivery traces by Message-ID header. Supports regex.

    Args:
        message_id: Message-ID or regex pattern. Example: "ABC123@mail.example.com".
        limit: Max results. Default: 100.
        offset: Pagination offset. Default: 0.
    """
    logger.info(f"Searching mail traces by message ID: {message_id}")

    try:
        params = {
            "message_id": message_id,
            "limit": limit,
            "offset": offset
        }

        api_response = query_jt_zmmsgtrace_api(params)
        return format_jt_zmmsgtrace_result(api_response)

    except Exception as e:
        logger.error(f"Failed to search by message ID: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to search by message ID: {str(e)}"
        }, indent=2)

@mcp_server.tool()
def jt_zmmsgtrace_search_by_host(srchost: Optional[str] = None,
                                  desthost: Optional[str] = None,
                                  limit: int = 100,
                                  offset: int = 0) -> str:
    """Search mail delivery traces by source or destination host. At least one required.

    Args:
        srchost: Source host or regex. Example: "mail.example.com", "^10\\.".
        desthost: Destination host or regex. Example: "relay.example.com".
        limit: Max results. Default: 100.
        offset: Pagination offset. Default: 0.
    """
    logger.info(f"Searching mail traces by host (src: {srchost}, dest: {desthost})")

    try:
        if not srchost and not desthost:
            return json.dumps({
                "status": "error",
                "message": "At least one of srchost or desthost must be provided"
            }, indent=2)

        params = {
            "srchost": srchost,
            "desthost": desthost,
            "limit": limit,
            "offset": offset
        }

        api_response = query_jt_zmmsgtrace_api(params)
        return format_jt_zmmsgtrace_result(api_response)

    except Exception as e:
        logger.error(f"Failed to search by host: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to search by host: {str(e)}"
        }, indent=2)

@mcp_server.tool()
def jt_zmmsgtrace_search_by_time(time_range: str,
                                  sender: Optional[str] = None,
                                  recipient: Optional[str] = None,
                                  limit: int = 100,
                                  offset: int = 0) -> str:
    """Search mail delivery traces within a time range, optionally filtered by sender/recipient.

    Args:
        time_range: Time range. Format: "YYYYMMDD,YYYYMMDD". Example: "20251101,20251130". Open-ended: "20251101," or ",20251130".
        sender: Optional sender filter (regex supported). Example: "user@example.com".
        recipient: Optional recipient filter (regex supported). Example: "@example.com$".
        limit: Max results. Default: 100.
        offset: Pagination offset. Default: 0.
    """
    logger.info(f"Searching mail traces by time range: {time_range}")

    try:
        params = {
            "time": time_range,
            "sender": sender,
            "recipient": recipient,
            "limit": limit,
            "offset": offset
        }

        api_response = query_jt_zmmsgtrace_api(params)
        return format_jt_zmmsgtrace_result(api_response)

    except Exception as e:
        logger.error(f"Failed to search by time: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to search by time: {str(e)}"
        }, indent=2)

@mcp_server.tool()
def jt_zmmsgtrace_search(sender: Optional[str] = None,
                          recipient: Optional[str] = None,
                          message_id: Optional[str] = None,
                          srchost: Optional[str] = None,
                          desthost: Optional[str] = None,
                          time_range: Optional[str] = None,
                          limit: int = 100,
                          offset: int = 0) -> str:
    """Comprehensive mail delivery trace search combining multiple criteria. At least one parameter required.

    Args:
        sender: Sender email or regex. Example: "user@example.com".
        recipient: Recipient email or regex. Example: "@example.com$".
        message_id: Message-ID or regex. Example: "ABC123@mail.example.com".
        srchost: Source host or regex. Example: "mail.example.com".
        desthost: Destination host or regex. Example: "relay.example.com".
        time_range: Time range. Format: "YYYYMMDD,YYYYMMDD". Example: "20251101,20251130".
        limit: Max results. Default: 100.
        offset: Pagination offset. Default: 0.
    """
    logger.info(f"Comprehensive mail trace search")

    try:
        # Validate at least one search parameter is provided
        if not any([sender, recipient, message_id, srchost, desthost, time_range]):
            return json.dumps({
                "status": "error",
                "message": "At least one search parameter is required (sender, recipient, message_id, srchost, desthost, or time_range)"
            }, indent=2)

        params = {
            "sender": sender,
            "recipient": recipient,
            "message_id": message_id,
            "srchost": srchost,
            "desthost": desthost,
            "time": time_range,
            "limit": limit,
            "offset": offset
        }

        api_response = query_jt_zmmsgtrace_api(params)
        return format_jt_zmmsgtrace_result(api_response)

    except Exception as e:
        logger.error(f"Failed comprehensive search: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed comprehensive search: {str(e)}"
        }, indent=2)

# ------------------- Health Check & Utilities -------------------

def _health_check_user_mode() -> str:
    """Simplified health check for user mode: tests auth + mailbox connectivity."""
    try:
        start_time = time.time()

        soap_body = '<GetFolderRequest xmlns="urn:zimbraMail"/>'
        root = _query_user_soap(soap_body)
        parse_zimbra_response(root, namespace="urn:zimbraMail")

        latency = time.time() - start_time
        cache_metrics = memory_cache.get_statistics()

        return json.dumps({
            "overall_status": "healthy",
            "auth_mode": "user",
            "user_email": zimbra_config.user_email,
            "timestamp": datetime.now().isoformat(),
            "mail_api": {
                "status": "operational",
                "response_time_ms": round(latency * 1000, 2),
                "endpoint": zimbra_config.mail_url
            },
            "cache": cache_metrics,
            "note": "User mode: server-level health data unavailable"
        }, indent=2, cls=DateTimeJSONEncoder)

    except Exception as error:
        logger.error(f"User mode health check failed: {error}")
        return json.dumps({
            "overall_status": "unhealthy",
            "auth_mode": "user",
            "timestamp": datetime.now().isoformat(),
            "error": str(error),
            "mail_api": {
                "status": "unreachable",
                "endpoint": zimbra_config.mail_url
            }
        }, indent=2, cls=DateTimeJSONEncoder)

@mcp_server.tool()
def health_check() -> str:
    """Perform comprehensive health check on Zimbra infrastructure including API connectivity and all services."""
    logger.info("Executing comprehensive health check")

    if zimbra_config.auth_mode == "user":
        return _health_check_user_mode()

    # === ADMIN MODE: original code below ===
    try:
        start_time = time.time()

        soap_body = """
        <GetVersionInfoRequest xmlns="urn:zimbraAdmin"/>
        """

        root = query_zimbra_api(soap_body, enable_cache=False)
        parse_zimbra_response(root)

        latency = time.time() - start_time

        ns = {'zimbra': 'urn:zimbraAdmin'}
        info_elem = root.find('.//zimbra:info', ns)
        version = info_elem.get('version') if info_elem is not None else "unknown"

        cache_metrics = memory_cache.get_statistics()

        logger.info("Checking all server services status")

        servers_health = {
            "total_servers": 0,
            "healthy_servers": 0,
            "degraded_servers": 0,
            "total_services": 0,
            "running_services": 0,
            "stopped_services": 0,
            "servers": []
        }

        overall_status = "healthy"

        try:
            server_status_result = getServerStatus()
            server_status_data = json.loads(server_status_result)

            logger.debug(f"Server status result: {server_status_data.get('status')}")
            logger.debug(f"Number of servers: {server_status_data.get('total_servers', 0)}")

            if server_status_data.get('status') != 'success':
                logger.warning(f"getServerStatus failed: {server_status_data.get('message', 'Unknown error')}")
                overall_status = "degraded"
        except Exception as e:
            logger.error(f"Failed to get server status: {e}")
            overall_status = "degraded"
            server_status_data = {"status": "error", "servers": []}

        if server_status_data.get('status') == 'success':
            servers_list = server_status_data.get('servers', [])
            servers_health["total_servers"] = len(servers_list)

            logger.info(f"Processing {len(servers_list)} servers for health check")

            for server in servers_list:
                services = server.get('services', [])
                running = 0
                stopped = 0

                for service in services:
                    service_status = service.get('status', 'unknown')
                    if service_status == 'running':
                        running += 1
                    else:
                        stopped += 1

                servers_health["total_services"] += len(services)
                servers_health["running_services"] += running
                servers_health["stopped_services"] += stopped

                server_health = "healthy" if stopped == 0 else "degraded"
                if server_health == "healthy":
                    servers_health["healthy_servers"] += 1
                else:
                    servers_health["degraded_servers"] += 1

                servers_health["servers"].append({
                    "server": server.get('server', 'unknown'),
                    "health": server_health,
                    "total_services": len(services),
                    "running": running,
                    "stopped": stopped,
                    "services": services
                })

            if servers_health["stopped_services"] > 0:
                critical_services_down = any(
                    service.get('name') in ['mailboxd', 'mta', 'ldap']
                    and service.get('status') != 'running'
                    for server in servers_health["servers"]
                    for service in server.get('services', [])
                )

                if critical_services_down:
                    overall_status = "unhealthy"
                else:
                    overall_status = "degraded"

        health_report = {
            "overall_status": overall_status,
            "timestamp": datetime.now().isoformat(),
            "admin_api": {
                "status": "operational",
                "response_time_ms": round(latency * 1000, 2),
                "endpoint": zimbra_config.admin_url,
                "version": version
            },
            "servers_health": servers_health,
            "cache": cache_metrics,
            "configuration": {
                "request_timeout": zimbra_config.request_timeout,
                "retry_attempts": zimbra_config.retry_attempts,
                "ssl_verification": zimbra_config.use_ssl
            }
        }

        return json.dumps(health_report, indent=2, cls=DateTimeJSONEncoder)

    except Exception as error:
        logger.error(f"Health check failed: {error}")
        return json.dumps({
            "overall_status": "unhealthy",
            "timestamp": datetime.now().isoformat(),
            "error": str(error),
            "admin_api": {
                "status": "unreachable",
                "endpoint": zimbra_config.admin_url
            }
        }, indent=2, cls=DateTimeJSONEncoder)

@mcp_server.tool()
def clear_cache() -> str:
    """Clear all cached API responses to force fresh data retrieval."""
    logger.info("Clearing cache")
    memory_cache.invalidate_all()
    return json.dumps({
        "status": "success",
        "message": "Cache cleared successfully"
    }, indent=2)

@mcp_server.tool()
def cache_stats() -> str:
    """Get cache performance statistics including entry counts and TTL configuration."""
    logger.info("Retrieving cache statistics")
    cache_metrics = memory_cache.get_statistics()
    return json.dumps({
        "status": "success",
        "cache_statistics": cache_metrics
    }, indent=2)

# ------------------- Rights & Permissions -------------------

@admin_only_tool()
def getGrants(target_type: str = "account",
              target_name: Optional[str] = None,
              grantee_type: Optional[str] = None,
              grantee_name: Optional[str] = None) -> str:
    """Get permission grants (ACLs) for access control auditing.

    Args:
        target_type: Resource type. Values: "account", "domain", "dl", "cos", "server", "config", "calresource". Default: "account".
        target_name: Resource name. Example: "user@example.com" (account), "example.com" (domain). Default: all of target_type.
        grantee_type: Grantee type filter. Values: "usr", "grp", "dom", "all", "pub", "guest". Default: none.
        grantee_name: Grantee name filter. Example: "admin@example.com". Default: none.
    """
    logger.info(f"Getting grants for target_type={target_type}, target={target_name}")

    try:
        # Build target specification (target_name is required for a valid target element)
        if target_name:
            target_spec = f'<target type="{target_type}" by="name">{target_name}</target>'
        else:
            target_spec = ""

        # Build grantee specification if provided
        grantee_spec = ""
        if grantee_name and grantee_type:
            grantee_spec = f'<grantee type="{grantee_type}" by="name">{grantee_name}</grantee>'
        elif grantee_type:
            grantee_spec = f'<grantee type="{grantee_type}"/>'

        soap_body = f"""
        <GetGrantsRequest xmlns="urn:zimbraAdmin">
            {target_spec}
            {grantee_spec}
        </GetGrantsRequest>
        """

        root = query_zimbra_api(soap_body)
        parse_zimbra_response(root)

        ns = {'zimbra': 'urn:zimbraAdmin'}

        # Try different possible element names (ace or grant)
        grant_elems = root.findall('.//zimbra:ace', ns)
        if not grant_elems:
            grant_elems = root.findall('.//zimbra:grant', ns)

        # Log raw XML for debugging if no grants found
        if not grant_elems:
            logger.warning("No grant/ace elements found in response")
            import xml.etree.ElementTree as ET
            response_xml = ET.tostring(root, encoding='unicode')
            logger.debug(f"Response XML: {response_xml}")

        grants = []
        for grant_elem in grant_elems:
            # Parse target information (may be from request context, not in response)
            target_elem = grant_elem.find('.//zimbra:target', ns)
            if target_elem is not None:
                target_info = {
                    "type": target_elem.get('type'),
                    "id": target_elem.get('id'),
                    "name": target_elem.get('name') or target_elem.text
                }
            else:
                # Try direct attributes (multiple possible names)
                target_info = {
                    "type": grant_elem.get('targetType') or grant_elem.get('tt'),
                    "id": grant_elem.get('targetId'),
                    "name": grant_elem.get('targetName') or grant_elem.get('dn')
                }
                # If still no target info, use from request parameters
                if not any(target_info.values()) and target_name:
                    target_info = {
                        "type": target_type,
                        "id": None,
                        "name": target_name
                    }

            # Parse grantee information (this is usually what's returned)
            grantee_elem = grant_elem.find('.//zimbra:grantee', ns)
            if grantee_elem is not None:
                grantee_info = {
                    "type": grantee_elem.get('type'),
                    "id": grantee_elem.get('id'),
                    "name": grantee_elem.get('name') or grantee_elem.text
                }
            else:
                # Common ACE attribute names: gt (grantee type), d (display name), zid (zimbra id)
                grantee_type = grant_elem.get('granteeType') or grant_elem.get('gt')
                grantee_id = grant_elem.get('granteeId') or grant_elem.get('zid')
                grantee_name = grant_elem.get('granteeName') or grant_elem.get('d')

                grantee_info = {
                    "type": grantee_type,
                    "id": grantee_id,
                    "name": grantee_name
                }

            # Parse right (permission name)
            right_elem = grant_elem.find('.//zimbra:right', ns)
            if right_elem is not None:
                right_value = right_elem.text
            else:
                # Try as direct attribute
                right_value = grant_elem.get('right') or grant_elem.get('perm')

            # Parse deny flag
            deny_attr = grant_elem.get('deny', '0')
            deny_value = deny_attr in ['true', '1', 'TRUE']

            grant_info = {
                "target": target_info,
                "grantee": grantee_info,
                "right": right_value,
                "deny": deny_value
            }

            # Add raw attributes for debugging if parsing seems incomplete
            if not right_value or not any(target_info.values()) or not any(grantee_info.values()):
                grant_info["raw_attributes"] = dict(grant_elem.attrib)
                grant_info["debug_note"] = "Some fields are empty, includes raw attributes for debugging"

            grants.append(grant_info)

        result = {
            "status": "success",
            "grants": grants,
            "count": len(grants),
            "display_message": f"Found {len(grants)} permission grants"
        }

        # Add debug info if no grants found but elements existed
        if len(grants) == 0 and len(grant_elems) > 0:
            result["debug"] = {
                "message": "Found grant elements but unable to parse content, possibly API response format mismatch",
                "element_count": len(grant_elems),
                "suggestion": "Please contact administrator to verify Zimbra version and API format"
            }

        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error(f"Failed to get grants: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to get grants: {str(e)}"
        }, indent=2)

@admin_only_tool()
def checkRight(target_type: str,
               target_name: str,
               grantee_name: str,
               right: str) -> str:
    """Check if a user has a specific permission on a target resource.

    Args:
        target_type: Resource type. Values: "account", "domain", "dl", "calresource", "cos", "server".
        target_name: Resource name. Example: "user@example.com" (account), "example.com" (domain).
        grantee_name: User or group to check. Example: "admin@example.com".
        right: Permission name to verify. Example: "sendAs", "viewFreeBusy".
    """
    logger.info(f"Checking right '{right}' for {grantee_name} on {target_type}:{target_name}")

    try:
        soap_body = f"""
        <CheckRightRequest xmlns="urn:zimbraAdmin">
            <target type="{target_type}" by="name">{target_name}</target>
            <grantee by="name">{grantee_name}</grantee>
            <right>{right}</right>
        </CheckRightRequest>
        """

        root = query_zimbra_api(soap_body)
        parse_zimbra_response(root)

        ns = {'zimbra': 'urn:zimbraAdmin'}
        response_elem = root.find('.//zimbra:CheckRightResponse', ns)

        has_right = response_elem.get('allow', '0') == '1' if response_elem is not None else False

        return json.dumps({
            "status": "success",
            "has_right": has_right,
            "target": {
                "type": target_type,
                "name": target_name
            },
            "grantee": grantee_name,
            "right": right,
            "display_message": f"{'Has permission' if has_right else 'No permission'}: {grantee_name} {'has' if has_right else 'does not have'} {right} permission on {target_name}"
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to check right: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to check right: {str(e)}"
        }, indent=2)

# ------------------- Delegation -------------------

@admin_only_tool()
def getDelegates(account: str) -> str:
    """Get email addresses that an account is permitted to send from (delegated sender identities). To find who CAN send as this account, use getGrants with target_name instead.

    Args:
        account: Account email address. Example: "user@example.com".
    """
    logger.info(f"Getting delegates for account: {account}")

    try:
        # Get account information including delegate settings
        soap_body = f"""
        <GetAccountRequest xmlns="urn:zimbraAdmin" applyCos="0">
            <account by="name">{account}</account>
        </GetAccountRequest>
        """

        root = query_zimbra_api(soap_body)
        parse_zimbra_response(root)

        ns = {'zimbra': 'urn:zimbraAdmin'}
        account_elem = root.find('.//zimbra:account', ns)

        if account_elem is None:
            return json.dumps({
                "status": "error",
                "message": f"Account '{account}' not found"
            }, indent=2)

        # Parse zimbraPrefAllowAddressForDelegatedSender attribute
        delegates = []
        for attr_elem in account_elem.findall('.//zimbra:a[@n="zimbraPrefAllowAddressForDelegatedSender"]', ns):
            delegate_email = attr_elem.text
            if delegate_email:
                delegates.append(delegate_email)

        return json.dumps({
            "status": "success",
            "account": account,
            "delegates": delegates,
            "count": len(delegates),
            "display_message": f"Account {account} has {len(delegates)} delegates"
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to get delegates: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to get delegates: {str(e)}"
        }, indent=2)


@admin_only_tool()
def getAllDelegations(domain: Optional[str] = None,
                     limit: int = 500,
                     offset: int = 0) -> str:
    """List all accounts with sendAs or sendOnBehalfOf delegation rights in one bulk query.

    Args:
        domain: Filter by domain. Example: "example.com". Default: all domains.
        limit: Max results. Default: 500. Range: 1-2000.
        offset: Starting position for pagination. Default: 0.
    """
    logger.info(f"Getting all delegations (domain={domain}, limit={limit}, offset={offset})")

    try:
        domain_query = ""
        if domain:
            domain_query = f'<domain by="name">{domain}</domain>'

        ldap_filter = "(|(zimbraACE=*sendAs*)(zimbraACE=*sendOnBehalfOf*)(zimbraPrefAllowAddressForDelegatedSender=*))"

        soap_body = f"""
        <SearchDirectoryRequest xmlns="urn:zimbraAdmin"
                                limit="{limit}"
                                offset="{offset}"
                                types="accounts">
            {domain_query}
            <query>{ldap_filter}</query>
        </SearchDirectoryRequest>
        """

        root = query_zimbra_api(soap_body)
        parse_zimbra_response(root)

        ns = {'zimbra': 'urn:zimbraAdmin'}
        account_elems = root.findall('.//zimbra:account', ns)

        grantee_uuids = set()
        accounts_data = []

        for account_elem in account_elems:
            account_name = account_elem.get('name')
            account_id = account_elem.get('id')

            # Parse multi-valued attributes (parse_attributes only keeps last value)
            aces = []
            delegated_senders = []
            for attr_elem in account_elem.findall('.//{urn:zimbraAdmin}a'):
                attr_name = attr_elem.get('n')
                attr_value = attr_elem.text or ''
                if attr_name == 'zimbraACE':
                    aces.append(attr_value)
                elif attr_name == 'zimbraPrefAllowAddressForDelegatedSender':
                    delegated_senders.append(attr_value)

            # Filter ACEs for delegation rights only
            delegations = []
            for ace in aces:
                parts = ace.split()
                if len(parts) >= 3:
                    grantee_id, grantee_type, right = parts[0], parts[1], parts[2]
                    if right in ('sendAs', 'sendOnBehalfOf', 'sendOnBehalfOfDistList'):
                        delegations.append({
                            "grantee_id": grantee_id,
                            "grantee_type": grantee_type,
                            "right": right
                        })
                        grantee_uuids.add(grantee_id)

            if delegations or delegated_senders:
                accounts_data.append({
                    "account": account_name,
                    "account_id": account_id,
                    "aces": delegations,
                    "delegated_senders": delegated_senders
                })

        # Batch resolve grantee UUIDs to names
        uuid_to_name = {}
        if grantee_uuids:
            uuid_list = list(grantee_uuids)
            for i in range(0, len(uuid_list), 50):
                chunk = uuid_list[i:i + 50]
                or_filter = ''.join(f'(zimbraId={uid})' for uid in chunk)
                resolve_filter = f'(|{or_filter})' if len(chunk) > 1 else or_filter

                resolve_soap = f"""
                <SearchDirectoryRequest xmlns="urn:zimbraAdmin"
                                        limit="{len(chunk)}"
                                        types="accounts,distributionlists">
                    <query>{resolve_filter}</query>
                </SearchDirectoryRequest>
                """
                try:
                    resolve_root = query_zimbra_api(resolve_soap)
                    parse_zimbra_response(resolve_root)
                    for elem in resolve_root.findall('.//{urn:zimbraAdmin}account'):
                        uuid_to_name[elem.get('id')] = elem.get('name')
                    for elem in resolve_root.findall('.//{urn:zimbraAdmin}dl'):
                        uuid_to_name[elem.get('id')] = elem.get('name')
                except Exception as e:
                    logger.warning(f"Failed to resolve grantee UUIDs: {e}")

        # Enrich ACEs with resolved grantee names
        for account_data in accounts_data:
            for ace in account_data["aces"]:
                grantee_id = ace["grantee_id"]
                resolved = uuid_to_name.get(grantee_id)
                if resolved:
                    ace["grantee_name"] = resolved

        # Parse pagination
        search_response = root.find('.//{urn:zimbraAdmin}SearchDirectoryResponse')
        has_more = False
        total_matches = len(accounts_data)
        if search_response is not None:
            if search_response.get('searchTotal'):
                total_matches = int(search_response.get('searchTotal'))
            has_more = search_response.get('more') == '1'

        return json.dumps({
            "status": "success",
            "accounts": accounts_data,
            "count": len(accounts_data),
            "total": total_matches,
            "has_more": has_more,
            "offset": offset,
            "limit": limit,
            "display_message": f"Found {len(accounts_data)} accounts with delegation settings"
                              + (f" (domain: {domain})" if domain else "")
                              + (f" - more results available, use offset={offset + limit}" if has_more else "")
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to get all delegations: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to get all delegations: {str(e)}"
        }, indent=2)

# ------------------- Bulk Audit -------------------

@admin_only_tool()
def getAllForwardings(domain: Optional[str] = None,
                     limit: int = 500,
                     offset: int = 0) -> str:
    """List all accounts with mail forwarding rules configured for security auditing.

    Args:
        domain: Filter by domain. Example: "example.com". Default: all domains.
        limit: Max results. Default: 500. Range: 1-2000.
        offset: Starting position for pagination. Default: 0.
    """
    logger.info(f"Getting all forwardings (domain={domain}, limit={limit}, offset={offset})")

    try:
        domain_query = ""
        if domain:
            domain_query = f'<domain by="name">{domain}</domain>'

        ldap_filter = "(|(zimbraMailForwardingAddress=*)(zimbraPrefMailForwardingAddress=*))"

        soap_body = f"""
        <SearchDirectoryRequest xmlns="urn:zimbraAdmin"
                                limit="{limit}"
                                offset="{offset}"
                                types="accounts">
            {domain_query}
            <query>{ldap_filter}</query>
        </SearchDirectoryRequest>
        """

        root = query_zimbra_api(soap_body)
        parse_zimbra_response(root)

        ns = {'zimbra': 'urn:zimbraAdmin'}
        account_elems = root.findall('.//zimbra:account', ns)

        accounts_data = []
        for account_elem in account_elems:
            account_name = account_elem.get('name')

            # Parse multi-valued forwarding attributes
            admin_forwards = []
            user_forwards = []
            local_delivery_disabled = False

            for attr_elem in account_elem.findall('.//{urn:zimbraAdmin}a'):
                attr_name = attr_elem.get('n')
                attr_value = attr_elem.text or ''
                if attr_name == 'zimbraMailForwardingAddress':
                    admin_forwards.append(attr_value)
                elif attr_name == 'zimbraPrefMailForwardingAddress':
                    user_forwards.append(attr_value)
                elif attr_name == 'zimbraPrefMailLocalDeliveryDisabled' and attr_value.upper() == 'TRUE':
                    local_delivery_disabled = True

            if admin_forwards or user_forwards:
                accounts_data.append({
                    "account": account_name,
                    "admin_forwards": admin_forwards,
                    "user_forwards": user_forwards,
                    "local_delivery_disabled": local_delivery_disabled
                })

        # Parse pagination
        search_response = root.find('.//{urn:zimbraAdmin}SearchDirectoryResponse')
        has_more = False
        total_matches = len(accounts_data)
        if search_response is not None:
            if search_response.get('searchTotal'):
                total_matches = int(search_response.get('searchTotal'))
            has_more = search_response.get('more') == '1'

        return json.dumps({
            "status": "success",
            "accounts": accounts_data,
            "count": len(accounts_data),
            "total": total_matches,
            "has_more": has_more,
            "offset": offset,
            "limit": limit,
            "display_message": f"Found {len(accounts_data)} accounts with forwarding rules"
                              + (f" (domain: {domain})" if domain else "")
                              + (f" - more results available, use offset={offset + limit}" if has_more else "")
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to get all forwardings: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to get all forwardings: {str(e)}"
        }, indent=2)


@admin_only_tool()
def getAllOutOfOffice(domain: Optional[str] = None,
                     limit: int = 500,
                     offset: int = 0) -> str:
    """List all accounts with out-of-office auto-reply currently enabled.

    Args:
        domain: Filter by domain. Example: "example.com". Default: all domains.
        limit: Max results. Default: 500. Range: 1-2000.
        offset: Starting position for pagination. Default: 0.
    """
    logger.info(f"Getting all out-of-office accounts (domain={domain}, limit={limit}, offset={offset})")

    try:
        domain_query = ""
        if domain:
            domain_query = f'<domain by="name">{domain}</domain>'

        ldap_filter = "(zimbraPrefOutOfOfficeReplyEnabled=TRUE)"

        soap_body = f"""
        <SearchDirectoryRequest xmlns="urn:zimbraAdmin"
                                limit="{limit}"
                                offset="{offset}"
                                types="accounts">
            {domain_query}
            <query>{ldap_filter}</query>
        </SearchDirectoryRequest>
        """

        root = query_zimbra_api(soap_body)
        parse_zimbra_response(root)

        ns = {'zimbra': 'urn:zimbraAdmin'}
        account_elems = root.findall('.//zimbra:account', ns)

        accounts_data = []
        for account_elem in account_elems:
            account_name = account_elem.get('name')
            attrs = parse_attributes(account_elem)

            accounts_data.append({
                "account": account_name,
                "from_date": attrs.get('zimbraPrefOutOfOfficeFromDate', ''),
                "until_date": attrs.get('zimbraPrefOutOfOfficeUntilDate', ''),
                "reply_preview": (attrs.get('zimbraPrefOutOfOfficeReply', '') or '')[:200]
            })

        # Parse pagination
        search_response = root.find('.//{urn:zimbraAdmin}SearchDirectoryResponse')
        has_more = False
        total_matches = len(accounts_data)
        if search_response is not None:
            if search_response.get('searchTotal'):
                total_matches = int(search_response.get('searchTotal'))
            has_more = search_response.get('more') == '1'

        return json.dumps({
            "status": "success",
            "accounts": accounts_data,
            "count": len(accounts_data),
            "total": total_matches,
            "has_more": has_more,
            "offset": offset,
            "limit": limit,
            "display_message": f"Found {len(accounts_data)} accounts with out-of-office enabled"
                              + (f" (domain: {domain})" if domain else "")
                              + (f" - more results available, use offset={offset + limit}" if has_more else "")
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to get out-of-office accounts: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to get out-of-office accounts: {str(e)}"
        }, indent=2)


@admin_only_tool()
def getInactiveAccounts(days: int = 90,
                        domain: Optional[str] = None,
                        limit: int = 500,
                        offset: int = 0) -> str:
    """List active accounts that have not logged in for a specified number of days.

    Args:
        days: Inactivity threshold in days. Example: 90. Default: 90.
        domain: Filter by domain. Example: "example.com". Default: all domains.
        limit: Max results. Default: 500. Range: 1-2000.
        offset: Starting position for pagination. Default: 0.
    """
    logger.info(f"Getting inactive accounts (days={days}, domain={domain}, limit={limit}, offset={offset})")

    try:
        from datetime import datetime, timedelta
        cutoff_dt = datetime.utcnow() - timedelta(days=days)
        cutoff = cutoff_dt.strftime('%Y%m%d%H%M%SZ')

        domain_query = ""
        if domain:
            domain_query = f'<domain by="name">{domain}</domain>'

        # LDAP: active accounts with no login ever OR last login before cutoff
        # CDATA needed because LDAP & and <= break XML parsing
        soap_body = f"""
        <SearchDirectoryRequest xmlns="urn:zimbraAdmin"
                                limit="{limit}"
                                offset="{offset}"
                                types="accounts">
            {domain_query}
            <query><![CDATA[(&(zimbraAccountStatus=active)(|(!(zimbraLastLogonTimestamp=*))(zimbraLastLogonTimestamp<={cutoff})))]]></query>
        </SearchDirectoryRequest>
        """

        root = query_zimbra_api(soap_body)
        parse_zimbra_response(root)

        ns = {'zimbra': 'urn:zimbraAdmin'}
        account_elems = root.findall('.//zimbra:account', ns)

        accounts_data = []
        now = datetime.utcnow()

        for account_elem in account_elems:
            account_name = account_elem.get('name')
            attrs = parse_attributes(account_elem)

            last_logon = attrs.get('zimbraLastLogonTimestamp', '')
            days_inactive = None

            if last_logon:
                try:
                    logon_dt = datetime.strptime(last_logon[:14], '%Y%m%d%H%M%S')
                    days_inactive = (now - logon_dt).days
                except (ValueError, IndexError):
                    pass

            accounts_data.append({
                "account": account_name,
                "displayName": attrs.get('displayName', ''),
                "last_logon": last_logon or "never",
                "days_inactive": days_inactive if days_inactive is not None else "never",
                "mailHost": attrs.get('zimbraMailHost', '')
            })

        # Sort: never logged in first, then most inactive
        accounts_data.sort(key=lambda x: float('inf') if x["days_inactive"] == "never" else -x["days_inactive"], reverse=True)

        # Parse pagination
        search_response = root.find('.//{urn:zimbraAdmin}SearchDirectoryResponse')
        has_more = False
        total_matches = len(accounts_data)
        if search_response is not None:
            if search_response.get('searchTotal'):
                total_matches = int(search_response.get('searchTotal'))
            has_more = search_response.get('more') == '1'

        return json.dumps({
            "status": "success",
            "accounts": accounts_data,
            "count": len(accounts_data),
            "total": total_matches,
            "has_more": has_more,
            "offset": offset,
            "limit": limit,
            "threshold_days": days,
            "cutoff_date": cutoff,
            "display_message": f"Found {len(accounts_data)} accounts inactive for {days}+ days"
                              + (f" (domain: {domain})" if domain else "")
                              + (f" - more results available, use offset={offset + limit}" if has_more else "")
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to get inactive accounts: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to get inactive accounts: {str(e)}"
        }, indent=2)


@admin_only_tool()
def searchByAttribute(query: str,
                      domain: Optional[str] = None,
                      search_type: str = "accounts",
                      limit: int = 500,
                      offset: int = 0) -> str:
    """Search directory using custom LDAP filter to find accounts or groups matching specific attribute conditions.

    Args:
        query: LDAP filter expression. Examples: "(zimbraAccountStatus=locked)", "(|(zimbraAccountStatus=locked)(zimbraAccountStatus=lockout))", "(zimbraMailHost=mail1.example.com)", "(zimbraMailTransport=*relay*)".
        domain: Filter by domain. Example: "example.com". Default: all domains.
        search_type: Entry type. Values: "accounts", "distributionlists", "aliases", "resources", "all". Default: "accounts".
        limit: Max results. Default: 500. Range: 1-2000.
        offset: Starting position for pagination. Default: 0.
    """
    logger.info(f"Searching by attribute: query={query}, domain={domain}, type={search_type}, limit={limit}")

    try:
        type_map = {
            "accounts": "accounts",
            "distributionlists": "distributionlists",
            "aliases": "aliases",
            "resources": "resources",
            "all": "accounts,distributionlists,aliases,resources"
        }
        zimbra_types = type_map.get(search_type, "accounts")

        domain_query = ""
        if domain:
            domain_query = f'<domain by="name">{domain}</domain>'

        # CDATA safely passes any LDAP filter characters (& < > etc.)
        soap_body = f"""
        <SearchDirectoryRequest xmlns="urn:zimbraAdmin"
                                limit="{limit}"
                                offset="{offset}"
                                types="{zimbra_types}">
            {domain_query}
            <query><![CDATA[{query}]]></query>
        </SearchDirectoryRequest>
        """

        root = query_zimbra_api(soap_body)
        parse_zimbra_response(root)

        ns = {'zimbra': 'urn:zimbraAdmin'}

        results = []

        # Parse accounts
        for elem in root.findall('.//zimbra:account', ns):
            attrs = parse_attributes(elem)
            results.append({
                "type": "account",
                "name": elem.get('name'),
                "id": elem.get('id'),
                "displayName": attrs.get('displayName', ''),
                "status": attrs.get('zimbraAccountStatus', ''),
                "mailHost": attrs.get('zimbraMailHost', ''),
                "cosId": attrs.get('zimbraCOSId', '')
            })

        # Parse distribution lists
        for elem in root.findall('.//zimbra:dl', ns):
            attrs = parse_attributes(elem)
            results.append({
                "type": "distributionlist",
                "name": elem.get('name'),
                "id": elem.get('id'),
                "displayName": attrs.get('displayName', ''),
                "isDynamic": attrs.get('zimbraIsDynamic', 'FALSE')
            })

        # Parse aliases
        for elem in root.findall('.//zimbra:alias', ns):
            attrs = parse_attributes(elem)
            results.append({
                "type": "alias",
                "name": elem.get('name'),
                "id": elem.get('id'),
                "targetName": attrs.get('zimbraAliasTargetId', '')
            })

        # Parse pagination
        search_response = root.find('.//{urn:zimbraAdmin}SearchDirectoryResponse')
        has_more = False
        total_matches = len(results)
        if search_response is not None:
            if search_response.get('searchTotal'):
                total_matches = int(search_response.get('searchTotal'))
            has_more = search_response.get('more') == '1'

        return json.dumps({
            "status": "success",
            "results": results,
            "count": len(results),
            "total": total_matches,
            "has_more": has_more,
            "offset": offset,
            "limit": limit,
            "query": query,
            "display_message": f"Found {len(results)} results for LDAP filter: {query}"
                              + (f" (domain: {domain})" if domain else "")
                              + (f" - more results available, use offset={offset + limit}" if has_more else "")
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to search by attribute: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to search by attribute: {str(e)}"
        }, indent=2)

# ------------------- Mail Search -------------------

def _get_account_folders(account: str) -> list:
    """Get all folders for an account (flat list). Returns list of dicts with id, name, path, count, unread."""
    soap_body = """
    <GetFolderRequest xmlns="urn:zimbraMail">
        <folder l="1"/>
    </GetFolderRequest>
    """
    root = query_zimbra_mail_api(soap_body, account)
    parse_zimbra_response(root, namespace="urn:zimbraMail")

    ns_mail = 'urn:zimbraMail'
    folders = []

    def walk_folders(parent_elem, parent_path=""):
        for folder_elem in parent_elem.findall(f'{{{ns_mail}}}folder'):
            name = folder_elem.get('name', '')
            folder_id = folder_elem.get('id', '')
            count = folder_elem.get('n', '0')
            unread = folder_elem.get('u', '0')
            view = folder_elem.get('view', '')

            path = f"{parent_path}/{name}" if parent_path else name

            folders.append({
                "id": folder_id,
                "name": name,
                "path": path,
                "count": int(count) if count else 0,
                "unread": int(unread) if unread else 0,
                "view": view
            })
            walk_folders(folder_elem, path)

    # Walk from root
    root_folder = root.find(f'.//{{{ns_mail}}}folder')
    if root_folder is not None:
        walk_folders(root_folder)

    return folders


def _fuzzy_match_folders(folders: list, keyword: str) -> list:
    """Find folders whose name contains the keyword (case-insensitive)."""
    keyword_lower = keyword.lower()
    return [f for f in folders if keyword_lower in f["name"].lower()]


@mcp_server.tool()
def listFolders(account: str,
                keyword: Optional[str] = None) -> str:
    """List all mailbox folders for an account, optionally filtered by keyword. Use to discover folder names for searchMail's folder parameter.

    Args:
        account: Account email. Example: "user@example.com".
        keyword: Filter folders by name containing this text (fuzzy). Example: "華電" matches "中華電信". Default: show all folders.
    """
    logger.info(f"Listing folders for account={account}, keyword={keyword}")

    try:
        folders = _get_account_folders(account)

        if keyword:
            matched = _fuzzy_match_folders(folders, keyword)
        else:
            matched = folders

        return json.dumps({
            "status": "success",
            "account": account,
            "folders": matched,
            "count": len(matched),
            "total_folders": len(folders),
            "display_message": f"{len(matched)} folders"
                              + (f" matching '{keyword}'" if keyword else "")
                              + f" in {account}"
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to list folders: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to list folders: {str(e)}"
        }, indent=2)


@mcp_server.tool()
def searchMail(account: str,
               query: Optional[str] = None,
               subject: Optional[str] = None,
               sender: Optional[str] = None,
               recipient: Optional[str] = None,
               cc: Optional[str] = None,
               content: Optional[str] = None,
               folder: Optional[str] = None,
               date_from: Optional[str] = None,
               date_to: Optional[str] = None,
               has_attachment: bool = False,
               limit: int = 50,
               offset: int = 0) -> str:
    """Search an account's mailbox by subject, sender, recipient, body content, date range, and more.

    Args:
        account: Target account email. Example: "user@example.com".
        query: Raw Zimbra search query (advanced). Example: "subject:meeting from:boss". Overrides other filters if provided.
        subject: Search in subject line. Example: "meeting invitation".
        sender: Search by sender email (From). Example: "boss@example.com".
        recipient: Search by recipient email (To). Example: "team@example.com".
        cc: Search by CC recipient email. Example: "manager@example.com".
        content: Search in message body text. Example: "quarterly report".
        folder: Limit to folder. Supports fuzzy match — e.g. "華電" matches "中華電信" and "華電聯網". Example: "inbox", "sent", "華電". Default: all folders.
        date_from: Start date inclusive. Format: "YYYY/MM/DD". Example: "2025/01/01".
        date_to: End date inclusive. Format: "YYYY/MM/DD". Example: "2025/12/31".
        has_attachment: Only messages with attachments. Default: false.
        limit: Max results. Default: 50. Range: 1-500.
        offset: Starting position for pagination. Default: 0.
    """
    logger.info(f"Searching mail for account={account}, subject={subject}, sender={sender}, limit={limit}")

    try:
        # Build search query from structured parameters
        if query:
            search_query = query
        else:
            parts = []
            if subject:
                parts.append(f'subject:("{subject}")')
            if sender:
                parts.append(f'from:({sender})')
            if recipient:
                parts.append(f'to:({recipient})')
            if cc:
                parts.append(f'cc:({cc})')
            if content:
                parts.append(f'content:("{content}")')
            if folder:
                # Check if it's an exact system folder name
                system_folders = ('inbox', 'sent', 'drafts', 'junk', 'trash')
                if folder.lower() in system_folders:
                    parts.append(f'in:"{folder}"')
                else:
                    # Fuzzy match against account's folder list
                    try:
                        all_folders = _get_account_folders(account)
                        matched = _fuzzy_match_folders(all_folders, folder)
                        if matched:
                            if len(matched) == 1:
                                parts.append(f'in:"{matched[0]["path"]}"')
                            else:
                                or_parts = ' OR '.join(f'in:"{m["path"]}"' for m in matched)
                                parts.append(f'({or_parts})')
                        else:
                            # No match found, use as-is (let Zimbra handle it)
                            parts.append(f'in:"{folder}"')
                    except Exception:
                        parts.append(f'in:"{folder}"')
            if date_from:
                # Zimbra after: is exclusive, subtract 1 day to make inclusive
                try:
                    df = datetime.strptime(date_from, "%Y/%m/%d") - timedelta(days=1)
                    parts.append(f'after:{df.strftime("%Y/%m/%d")}')
                except ValueError:
                    parts.append(f'after:{date_from}')
            if date_to:
                # Zimbra before: is exclusive, add 1 day to make inclusive
                try:
                    dt = datetime.strptime(date_to, "%Y/%m/%d") + timedelta(days=1)
                    parts.append(f'before:{dt.strftime("%Y/%m/%d")}')
                except ValueError:
                    parts.append(f'before:{date_to}')
            if has_attachment:
                parts.append('has:attachment')
            search_query = ' '.join(parts) if parts else 'in:inbox'

        soap_body = f"""
        <SearchRequest xmlns="urn:zimbraMail"
                       types="message"
                       sortBy="dateDesc"
                       limit="{limit}"
                       offset="{offset}">
            <query><![CDATA[{search_query}]]></query>
        </SearchRequest>
        """

        root = query_zimbra_mail_api(soap_body, account)
        parse_zimbra_response(root, namespace="urn:zimbraMail")

        ns_mail = 'urn:zimbraMail'

        messages = []
        for msg_elem in root.findall(f'.//{{{ns_mail}}}m'):
            msg_id = msg_elem.get('id', '')
            size = msg_elem.get('s', '0')
            date_ms = msg_elem.get('d', '')
            flags = msg_elem.get('f', '')
            conv_id = msg_elem.get('cid', '')

            # Subject
            su_elem = msg_elem.find(f'{{{ns_mail}}}su')
            msg_subject = su_elem.text if su_elem is not None and su_elem.text else ''

            # Fragment (preview)
            fr_elem = msg_elem.find(f'{{{ns_mail}}}fr')
            fragment = fr_elem.text if fr_elem is not None and fr_elem.text else ''

            # Email addresses
            from_addrs = []
            to_addrs = []
            cc_addrs = []
            for e_elem in msg_elem.findall(f'{{{ns_mail}}}e'):
                addr_type = e_elem.get('t', '')
                addr = e_elem.get('a', '')
                display = e_elem.get('p') or e_elem.get('d', '')
                entry = f"{display} <{addr}>" if display else addr
                if addr_type == 'f':
                    from_addrs.append(entry)
                elif addr_type == 't':
                    to_addrs.append(entry)
                elif addr_type == 'c':
                    cc_addrs.append(entry)

            # Convert epoch ms to readable date
            date_str = ''
            if date_ms:
                try:
                    dt = datetime.fromtimestamp(int(date_ms) / 1000)
                    date_str = dt.strftime('%Y-%m-%d %H:%M:%S')
                except (ValueError, OSError):
                    date_str = date_ms

            messages.append({
                "id": msg_id,
                "conversation_id": conv_id,
                "subject": msg_subject,
                "from": from_addrs,
                "to": to_addrs,
                "cc": cc_addrs if cc_addrs else None,
                "date": date_str,
                "fragment": fragment,
                "size_bytes": int(size) if size else 0,
                "unread": 'u' in flags,
                "flagged": 'f' in flags,
                "has_attachment": 'a' in flags,
                "replied": 'r' in flags,
                "forwarded": 'w' in flags
            })

        # Parse pagination from SearchResponse
        search_response = root.find(f'.//{{{ns_mail}}}SearchResponse')
        has_more = False
        total_matches = len(messages)
        if search_response is not None:
            if search_response.get('total'):
                total_matches = int(search_response.get('total'))
            has_more = search_response.get('more') == '1'

        return json.dumps({
            "status": "success",
            "account": account,
            "query_used": search_query,
            "messages": messages,
            "count": len(messages),
            "total": total_matches,
            "has_more": has_more,
            "offset": offset,
            "limit": limit,
            "display_message": f"Found {total_matches} messages in {account}"
                              + (f", showing {len(messages)}" if len(messages) < total_matches else "")
                              + (f" - more results available, use offset={offset + limit}" if has_more else ""),
            "usage_hint": "To read a message, call getMailDetail with the 'id' value from a message above. To get conversation thread, use the 'conversation_id' value."
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to search mail: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to search mail for {account}: {str(e)}"
        }, indent=2)


@mcp_server.tool()
def getMailDetail(account: str,
                  msg_id: str) -> str:
    """Get full detail of a specific email message including complete headers, body text, and attachment list.

    Args:
        account: Account email address. Example: "user@example.com".
        msg_id: Message ID from searchMail "id" field. Must be non-empty. Example: "894727" or "4ef3bd6d-e227-4986-8993-98443101a169:894727".
    """
    logger.info(f"Getting mail detail for account={account}, msg_id={msg_id}")

    if not msg_id or not str(msg_id).strip():
        return json.dumps({
            "status": "error",
            "message": "msg_id is required and cannot be empty. Use the 'id' field from searchMail results. Example: call searchMail first, then pass the 'id' value from a message in the results."
        }, indent=2)

    try:
        soap_body = f"""
        <GetMsgRequest xmlns="urn:zimbraMail">
            <m id="{msg_id}" html="0" needExp="1"/>
        </GetMsgRequest>
        """

        root = query_zimbra_mail_api(soap_body, account)
        parse_zimbra_response(root, namespace="urn:zimbraMail")

        ns_mail = 'urn:zimbraMail'
        msg_elem = root.find(f'.//{{{ns_mail}}}m')

        if msg_elem is None:
            return json.dumps({
                "status": "error",
                "message": f"Message {msg_id} not found in {account}"
            }, indent=2)

        msg_id_val = msg_elem.get('id', '')
        size = msg_elem.get('s', '0')
        date_ms = msg_elem.get('d', '')
        flags = msg_elem.get('f', '')
        conv_id = msg_elem.get('cid', '')
        folder_id = msg_elem.get('l', '')

        # Subject
        su_elem = msg_elem.find(f'{{{ns_mail}}}su')
        msg_subject = su_elem.text if su_elem is not None and su_elem.text else ''

        # Fragment
        fr_elem = msg_elem.find(f'{{{ns_mail}}}fr')
        fragment = fr_elem.text if fr_elem is not None and fr_elem.text else ''

        # Email addresses
        from_addrs = []
        to_addrs = []
        cc_addrs = []
        bcc_addrs = []
        reply_to = []
        for e_elem in msg_elem.findall(f'{{{ns_mail}}}e'):
            addr_type = e_elem.get('t', '')
            addr = e_elem.get('a', '')
            display = e_elem.get('p') or e_elem.get('d', '')
            entry = {"address": addr, "display": display}
            if addr_type == 'f':
                from_addrs.append(entry)
            elif addr_type == 't':
                to_addrs.append(entry)
            elif addr_type == 'c':
                cc_addrs.append(entry)
            elif addr_type == 'b':
                bcc_addrs.append(entry)
            elif addr_type == 'r':
                reply_to.append(entry)

        # Parse body content from mime parts
        body_text = ''
        attachments = []

        def parse_mime_parts(parent_elem):
            nonlocal body_text
            for mp_elem in parent_elem.findall(f'{{{ns_mail}}}mp'):
                content_type = mp_elem.get('ct', '')
                filename = mp_elem.get('filename', '')
                part_id = mp_elem.get('part', '')
                part_size = mp_elem.get('s', '0')

                # Get body text (prefer text/plain)
                if content_type == 'text/plain' and not body_text:
                    content_elem = mp_elem.find(f'{{{ns_mail}}}content')
                    if content_elem is not None and content_elem.text:
                        body_text = content_elem.text

                # Collect attachments
                if filename:
                    attachments.append({
                        "filename": filename,
                        "content_type": content_type,
                        "size_bytes": int(part_size) if part_size else 0,
                        "part_id": part_id
                    })

                # Recurse into nested mime parts (multipart/*)
                parse_mime_parts(mp_elem)

        parse_mime_parts(msg_elem)

        # If no text/plain, try text/html
        if not body_text:
            for mp_elem in msg_elem.findall(f'.//{{{ns_mail}}}mp'):
                if mp_elem.get('ct') == 'text/html':
                    content_elem = mp_elem.find(f'{{{ns_mail}}}content')
                    if content_elem is not None and content_elem.text:
                        body_text = f"[HTML content]\n{content_elem.text[:2000]}"
                        break

        # Convert date
        date_str = ''
        if date_ms:
            try:
                dt = datetime.fromtimestamp(int(date_ms) / 1000)
                date_str = dt.strftime('%Y-%m-%d %H:%M:%S')
            except (ValueError, OSError):
                date_str = date_ms

        # Parse headers
        headers = {}
        for hdr in msg_elem.findall(f'.//{{{ns_mail}}}header'):
            hdr_name = hdr.get('n', '')
            if hdr_name and hdr.text:
                headers[hdr_name] = hdr.text

        return json.dumps({
            "status": "success",
            "account": account,
            "message": {
                "id": msg_id_val,
                "conversation_id": conv_id,
                "folder_id": folder_id,
                "subject": msg_subject,
                "from": from_addrs,
                "to": to_addrs,
                "cc": cc_addrs if cc_addrs else None,
                "bcc": bcc_addrs if bcc_addrs else None,
                "reply_to": reply_to if reply_to else None,
                "date": date_str,
                "size_bytes": int(size) if size else 0,
                "unread": 'u' in flags,
                "flagged": 'f' in flags,
                "has_attachment": 'a' in flags,
                "body": body_text[:5000] if body_text else '',
                "attachments": attachments if attachments else None,
                "headers": headers if headers else None,
                "fragment": fragment
            }
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to get mail detail: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to get mail detail: {str(e)}"
        }, indent=2)


@mcp_server.tool()
def getConversation(account: str,
                    conversation_id: str) -> str:
    """Get all messages in an email conversation thread. Use conversation_id from searchMail results.

    Args:
        account: Account email. Example: "user@example.com".
        conversation_id: Conversation ID from searchMail "conversation_id" field. Must be non-empty. Example: "-12345".
    """
    logger.info(f"Getting conversation: account={account}, conv_id={conversation_id}")

    if not conversation_id or not str(conversation_id).strip():
        return json.dumps({
            "status": "error",
            "message": "conversation_id is required and cannot be empty. Use the 'conversation_id' field from searchMail results."
        }, indent=2)

    try:
        soap_body = f"""
        <GetConvRequest xmlns="urn:zimbraMail">
            <c id="{conversation_id}" fetch="all" html="0"/>
        </GetConvRequest>
        """

        root = query_zimbra_mail_api(soap_body, account)
        parse_zimbra_response(root, namespace="urn:zimbraMail")

        ns_mail = 'urn:zimbraMail'

        conv_elem = root.find(f'.//{{{ns_mail}}}c')
        if conv_elem is None:
            return json.dumps({
                "status": "error",
                "message": f"Conversation {conversation_id} not found in {account}"
            }, indent=2)

        conv_subject = ''
        su_elem = conv_elem.find(f'{{{ns_mail}}}su')
        if su_elem is not None and su_elem.text:
            conv_subject = su_elem.text

        num_messages = conv_elem.get('n', '0')

        messages = []
        for msg_elem in conv_elem.findall(f'{{{ns_mail}}}m'):
            msg_id = msg_elem.get('id', '')
            size = msg_elem.get('s', '0')
            date_ms = msg_elem.get('d', '')
            flags = msg_elem.get('f', '')
            folder_id = msg_elem.get('l', '')

            # Subject
            msg_su = msg_elem.find(f'{{{ns_mail}}}su')
            msg_subject = msg_su.text if msg_su is not None and msg_su.text else ''

            # Fragment
            fr_elem = msg_elem.find(f'{{{ns_mail}}}fr')
            fragment = fr_elem.text if fr_elem is not None and fr_elem.text else ''

            # Body text from mime parts
            body_text = ''
            for mp_elem in msg_elem.findall(f'.//{{{ns_mail}}}mp'):
                if mp_elem.get('ct') == 'text/plain':
                    content_elem = mp_elem.find(f'{{{ns_mail}}}content')
                    if content_elem is not None and content_elem.text:
                        body_text = content_elem.text
                        break

            # Email addresses
            from_addrs = []
            to_addrs = []
            cc_addrs = []
            for e_elem in msg_elem.findall(f'{{{ns_mail}}}e'):
                addr_type = e_elem.get('t', '')
                addr = e_elem.get('a', '')
                display = e_elem.get('p') or e_elem.get('d', '')
                entry = f"{display} <{addr}>" if display else addr
                if addr_type == 'f':
                    from_addrs.append(entry)
                elif addr_type == 't':
                    to_addrs.append(entry)
                elif addr_type == 'c':
                    cc_addrs.append(entry)

            # Date
            date_str = ''
            if date_ms:
                try:
                    dt = datetime.fromtimestamp(int(date_ms) / 1000)
                    date_str = dt.strftime('%Y-%m-%d %H:%M:%S')
                except (ValueError, OSError):
                    date_str = date_ms

            messages.append({
                "id": msg_id,
                "subject": msg_subject,
                "from": from_addrs,
                "to": to_addrs,
                "cc": cc_addrs if cc_addrs else None,
                "date": date_str,
                "body": body_text[:3000] if body_text else fragment,
                "size_bytes": int(size) if size else 0,
                "folder_id": folder_id,
                "unread": 'u' in flags,
                "has_attachment": 'a' in flags
            })

        # Sort by date ascending (oldest first = conversation order)
        messages.sort(key=lambda x: x["date"])

        return json.dumps({
            "status": "success",
            "account": account,
            "conversation_id": conversation_id,
            "subject": conv_subject,
            "message_count": int(num_messages) if num_messages else len(messages),
            "messages": messages,
            "display_message": f"Conversation '{conv_subject}' - {len(messages)} messages"
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to get conversation: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to get conversation: {str(e)}"
        }, indent=2)


@mcp_server.tool()
def getMailAttachment(account: str,
                      msg_id: str,
                      part_id: str,
                      save_dir: str = "~/Downloads") -> str:
    """Download an email attachment to a local file. Use getMailDetail first to find part_id values.

    Args:
        account: Account email. Example: "user@example.com".
        msg_id: Message ID from searchMail "id" field. Must be non-empty. Example: "894727" or "4ef3bd6d-e227-4986-8993-98443101a169:894727".
        part_id: Attachment part ID from getMailDetail results. Must be non-empty. Example: "2", "1.2".
        save_dir: Directory to save the file. Default: "~/Downloads".
    """
    logger.info(f"Downloading attachment: account={account}, msg_id={msg_id}, part={part_id}")

    if not msg_id or not str(msg_id).strip():
        return json.dumps({
            "status": "error",
            "message": "msg_id is required and cannot be empty. Use the 'id' field from searchMail results."
        }, indent=2)
    if not part_id or not str(part_id).strip():
        return json.dumps({
            "status": "error",
            "message": "part_id is required and cannot be empty. Use getMailDetail first to find attachment part_id values."
        }, indent=2)

    try:
        if zimbra_config.auth_mode == "user":
            # User mode: use user auth token directly, no DelegateAuth
            if account.lower() != zimbra_config.user_email.lower():
                raise Exception(
                    f"User mode: cannot access attachments of '{account}'. "
                    f"Only '{zimbra_config.user_email}' is accessible."
                )
            delegate_token = get_user_auth_token()
            base_url = zimbra_config.mail_url.rstrip('/')
        else:
            # === ADMIN MODE: DelegateAuth flow ===
            delegate_soap = f"""
            <DelegateAuthRequest xmlns="urn:zimbraAdmin">
                <account by="name">{account}</account>
            </DelegateAuthRequest>
            """
            root = query_zimbra_api(delegate_soap, enable_cache=False)
            parse_zimbra_response(root)

            ns = {'zimbra': 'urn:zimbraAdmin'}
            token_elem = root.find('.//zimbra:authToken', ns)
            if token_elem is None or not token_elem.text:
                raise Exception(f"Failed to get delegated auth token for {account}")
            delegate_token = token_elem.text

            base_url = get_mail_base_url()

        download_url = (
            f"{base_url}/service/home/~/"
            f"?auth=qp&zauthtoken={delegate_token}"
            f"&id={msg_id}&part={part_id}"
        )

        # Step 3: Download attachment via streaming
        response = http_session.get(
            download_url,
            timeout=zimbra_config.request_timeout * 3,
            stream=True
        )
        response.raise_for_status()

        # Step 4: Determine filename
        filename = None
        content_disp = response.headers.get('Content-Disposition', '')

        # Try RFC 5987 encoded filename (filename*=UTF-8''...)
        match = re.search(r"filename\*=(?:UTF-8|utf-8)''(.+?)(?:;|$)", content_disp)
        if match:
            filename = unquote(match.group(1).strip())

        # Try regular filename
        if not filename:
            match = re.search(r'filename="?([^";\n]+)"?', content_disp)
            if match:
                filename = match.group(1).strip()

        # Fallback with extension from content type
        if not filename:
            content_type = response.headers.get('Content-Type', '')
            ext_map = {
                'application/pdf': '.pdf', 'image/png': '.png',
                'image/jpeg': '.jpg', 'image/gif': '.gif',
                'application/zip': '.zip', 'application/x-zip-compressed': '.zip',
                'text/plain': '.txt', 'text/html': '.html', 'text/csv': '.csv',
                'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '.xlsx',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
                'application/vnd.openxmlformats-officedocument.presentationml.presentation': '.pptx',
                'application/vnd.ms-excel': '.xls', 'application/msword': '.doc',
                'message/rfc822': '.eml',
            }
            ext = ext_map.get(content_type.split(';')[0].strip(), '')
            filename = f"attachment_{msg_id}_{part_id}{ext}"

        # Sanitize filename to prevent path traversal
        filename = os.path.basename(filename)

        # Step 5: Save to file (expand ~ to home directory)
        save_dir = os.path.expanduser(save_dir)
        os.makedirs(save_dir, exist_ok=True)
        filepath = os.path.join(save_dir, filename)

        total_size = 0
        with open(filepath, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
                total_size += len(chunk)

        content_type = response.headers.get('Content-Type', 'unknown').split(';')[0].strip()

        logger.info(f"Saved attachment: {filepath} ({total_size} bytes)")

        return json.dumps({
            "status": "success",
            "account": account,
            "msg_id": msg_id,
            "part_id": part_id,
            "filename": filename,
            "filepath": filepath,
            "size_bytes": total_size,
            "content_type": content_type,
            "display_message": f"Saved '{filename}' ({total_size:,} bytes) to {filepath}"
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to download attachment: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to download attachment: {str(e)}"
        }, indent=2)


@mcp_server.tool()
def saveDraft(account: str,
              to: str,
              subject: str,
              body: str,
              cc: Optional[str] = None,
              bcc: Optional[str] = None,
              reply_to_msg_id: Optional[str] = None,
              is_forward: bool = False) -> str:
    """Save a new email or a reply/forward as draft. When replying, original message is auto-quoted.

    Args:
        account: Sender account email. Example: "user@example.com".
        to: Recipient email(s), comma-separated. Example: "a@example.com" or "a@example.com,b@example.com".
        subject: Email subject. For replies, add "Re: " prefix. Example: "Re: Meeting Tomorrow".
        body: Your reply/new message text only. Do NOT include quoted original — it is auto-appended for replies.
        cc: CC recipient(s), comma-separated. Example: "manager@example.com". Default: none.
        bcc: BCC recipient(s), comma-separated. Example: "archive@example.com". Default: none.
        reply_to_msg_id: Original message ID to reply to (from searchMail "id" field). Original message auto-quoted. Example: "894727". Default: none (new email).
        is_forward: Set true if forwarding instead of replying. Only used with reply_to_msg_id. Default: false.
    """
    logger.info(f"Saving draft: account={account}, to={to}, subject={subject}, reply_to={reply_to_msg_id}")

    try:
        # Build recipient elements
        recipients = ""
        for addr in to.split(','):
            addr = addr.strip()
            if addr:
                recipients += f'<e t="t" a="{addr}"/>\n'

        if cc:
            for addr in cc.split(','):
                addr = addr.strip()
                if addr:
                    recipients += f'<e t="c" a="{addr}"/>\n'

        if bcc:
            for addr in bcc.split(','):
                addr = addr.strip()
                if addr:
                    recipients += f'<e t="b" a="{addr}"/>\n'

        # From address
        recipients += f'<e t="f" a="{account}"/>'

        # Build message attributes for reply/forward
        msg_attrs = ""
        if reply_to_msg_id:
            reply_type = "w" if is_forward else "r"
            msg_attrs = f'origid="{reply_to_msg_id}" rt="{reply_type}"'

            # Auto-quote original message for reply/forward
            try:
                orig_detail = json.loads(getMailDetail(account, reply_to_msg_id))
                if orig_detail.get("status") == "success":
                    orig_msg = orig_detail.get("message", {})
                    orig_from = ""
                    from_list = orig_msg.get("from", [])
                    if from_list:
                        f = from_list[0]
                        orig_from = f.get("display", f.get("address", ""))
                        if f.get("address"):
                            orig_from = f"{f.get('display', '')} <{f['address']}>".strip()
                    orig_date = orig_msg.get("date", "")
                    orig_subject = orig_msg.get("subject", "")
                    orig_body = orig_msg.get("body_text", "")

                    # Build quoted text
                    quoted_lines = orig_body.split('\n')
                    quoted_text = '\n'.join(f'> {line}' for line in quoted_lines)

                    if is_forward:
                        separator = (
                            f"\n\n---------- Forwarded message ----------\n"
                            f"From: {orig_from}\n"
                            f"Date: {orig_date}\n"
                            f"Subject: {orig_subject}\n\n"
                            f"{orig_body}"
                        )
                    else:
                        separator = (
                            f"\n\nOn {orig_date}, {orig_from} wrote:\n"
                            f"{quoted_text}"
                        )

                    body = body + separator
            except Exception as quote_err:
                logger.warning(f"Failed to auto-quote original message: {quote_err}")
                # Continue without quote — still save the draft

        # Escape XML special characters in body and subject
        body_escaped = (body.replace('&', '&amp;').replace('<', '&lt;')
                           .replace('>', '&gt;'))
        subject_escaped = (subject.replace('&', '&amp;').replace('<', '&lt;')
                                  .replace('>', '&gt;'))

        soap_body = f"""
        <SaveDraftRequest xmlns="urn:zimbraMail">
            <m {msg_attrs}>
                {recipients}
                <su>{subject_escaped}</su>
                <mp ct="text/plain">
                    <content>{body_escaped}</content>
                </mp>
            </m>
        </SaveDraftRequest>
        """

        root = query_zimbra_mail_api(soap_body, account)
        parse_zimbra_response(root, namespace="urn:zimbraMail")

        ns_mail = 'urn:zimbraMail'
        msg_elem = root.find(f'.//{{{ns_mail}}}m')

        draft_id = msg_elem.get('id', '') if msg_elem is not None else ''

        draft_type = "reply draft" if reply_to_msg_id and not is_forward else \
                     "forward draft" if reply_to_msg_id and is_forward else \
                     "new draft"

        result = {
            "status": "success",
            "account": account,
            "draft_id": draft_id,
            "draft_type": draft_type,
            "to": to,
            "cc": cc,
            "bcc": bcc,
            "subject": subject,
            "reply_to_msg_id": reply_to_msg_id,
            "display_message": f"Saved {draft_type} in {account}'s Drafts folder (ID: {draft_id})"
        }
        if reply_to_msg_id:
            result["note"] = "Original message was auto-quoted in the draft body. No need to include it separately."

        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error(f"Failed to save draft: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to save draft: {str(e)}"
        }, indent=2)

# ------------------- Directory Search -------------------

def _searchGal_user_mode(query: str, search_type: str, limit: int) -> str:
    """SearchGalRequest via user mode (urn:zimbraAccount)"""
    type_map = {
        "accounts": "account",
        "groups": "group",
        "resources": "resource",
        "all": "all"
    }
    gal_type = type_map.get(search_type, "account")

    soap_body = f"""
    <SearchGalRequest xmlns="urn:zimbraAccount" type="{gal_type}" limit="{limit}">
        <name>{query}</name>
    </SearchGalRequest>
    """

    root = _query_user_soap(soap_body)
    parse_zimbra_response(root, namespace="urn:zimbraAccount")

    ns_acct = {'zimbra': 'urn:zimbraAccount'}
    results = []

    for cn_elem in root.findall('.//zimbra:cn', ns_acct):
        entry = {
            "type": None,
            "id": cn_elem.get('id'),
            "name": None,
            "display_name": None,
            "attributes": {}
        }
        for attr_elem in cn_elem.findall('.//zimbra:a', ns_acct):
            attr_name = attr_elem.get('n')
            attr_value = attr_elem.text
            if attr_name == 'email':
                entry["name"] = attr_value
            elif attr_name == 'fullName' or attr_name == 'displayName':
                entry["display_name"] = attr_value
            elif attr_name == 'type':
                entry["type"] = attr_value
            elif attr_name in ['zimbraAccountStatus', 'zimbraMailHost']:
                entry["attributes"][attr_name] = attr_value

        if not entry["type"]:
            entry["type"] = "account"
        results.append(entry)

    returned_count = len(results)
    has_more = returned_count == limit
    if has_more:
        display_msg = f"GAL search '{query}' showing first {returned_count} results (more may exist, narrow search)"
    else:
        display_msg = f"GAL search '{query}' found {returned_count} results (all displayed)"

    return json.dumps({
        "status": "success",
        "results": results,
        "count": returned_count,
        "search_query": query,
        "limit": limit,
        "has_more": has_more,
        "auth_mode": "user",
        "display_message": display_msg
    }, indent=2)

@mcp_server.tool()
def searchGal(query: str,
              domain: Optional[str] = None,
              search_type: str = "accounts",
              limit: int = 100) -> str:
    """Search Global Address List (GAL) — the company-wide directory — for accounts, groups, or resources by name or email. For personal address book, use searchContacts instead.

    Args:
        query: Search text. Matches cn, mail, displayName fields. Example: "john", "sales". Case-insensitive partial match.
        domain: Filter by domain. Example: "example.com". Default: all domains (user mode ignores this).
        search_type: Entry type. Values: "accounts", "groups", "resources", "all". Default: "accounts".
        limit: Max results. Default: 100. Range: 1-1000.
    """
    logger.info(f"Searching directory for '{query}' in domain={domain}, type={search_type}")

    if zimbra_config.auth_mode == "user":
        return _searchGal_user_mode(query, search_type, limit)

    # === ADMIN MODE: original code below ===
    try:
        # Map search_type to Zimbra types
        type_map = {
            "accounts": "accounts",
            "groups": "distributionlists",
            "resources": "resources",
            "all": "accounts,distributionlists,resources"
        }
        zimbra_types = type_map.get(search_type, "accounts")

        # Build domain element (not attribute!)
        domain_element = ""
        if domain:
            domain_element = f'<domain by="name">{domain}</domain>'

        # Build LDAP-style search query
        # Search in common name, mail, and display name fields
        search_query = f"(|(cn=*{query}*)(mail=*{query}*)(displayName=*{query}*))"

        soap_body = f"""
        <SearchDirectoryRequest xmlns="urn:zimbraAdmin"
                                types="{zimbra_types}"
                                limit="{limit}">
            {domain_element}
            <query>{search_query}</query>
        </SearchDirectoryRequest>
        """

        root = query_zimbra_api(soap_body)
        parse_zimbra_response(root)

        ns = {'zimbra': 'urn:zimbraAdmin'}

        results = []

        # Parse accounts
        for account_elem in root.findall('.//zimbra:account', ns):
            entry = {
                "type": "account",
                "id": account_elem.get('id'),
                "name": account_elem.get('name'),
                "display_name": None,
                "attributes": {}
            }

            # Parse attributes
            for attr_elem in account_elem.findall('.//zimbra:a', ns):
                attr_name = attr_elem.get('n')
                attr_value = attr_elem.text

                if attr_name == 'displayName':
                    entry["display_name"] = attr_value
                elif attr_name in ['zimbraAccountStatus', 'zimbraMailHost']:
                    entry["attributes"][attr_name] = attr_value

            results.append(entry)

        # Parse distribution lists
        for dl_elem in root.findall('.//zimbra:dl', ns):
            entry = {
                "type": "distributionlist",
                "id": dl_elem.get('id'),
                "name": dl_elem.get('name'),
                "display_name": dl_elem.get('d'),
                "attributes": {}
            }
            results.append(entry)

        # Parse calendar resources
        for resource_elem in root.findall('.//zimbra:calresource', ns):
            entry = {
                "type": "resource",
                "id": resource_elem.get('id'),
                "name": resource_elem.get('name'),
                "display_name": None,
                "attributes": {}
            }

            for attr_elem in resource_elem.findall('.//zimbra:a', ns):
                attr_name = attr_elem.get('n')
                attr_value = attr_elem.text
                if attr_name == 'displayName':
                    entry["display_name"] = attr_value

            results.append(entry)

        # Create display message with pagination info
        returned_count = len(results)
        has_more = returned_count == limit

        if has_more:
            display_msg = f"GAL search '{query}' showing first {returned_count} results (more may exist, narrow search)"
        else:
            display_msg = f"GAL search '{query}' found {returned_count} results (all displayed)"

        return json.dumps({
            "status": "success",
            "results": results,
            "count": returned_count,
            "search_query": query,
            "limit": limit,
            "has_more": has_more,
            "display_message": display_msg
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to search GAL: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to search GAL: {str(e)}"
        }, indent=2)

@mcp_server.tool()
def searchContacts(account: str,
                   query: str = "",
                   folder: str = "Contacts",
                   limit: int = 100,
                   offset: int = 0) -> str:
    """Search a user's personal address book / contacts by name, email, or phone number. For company-wide directory, use searchGal instead.

    Args:
        account: Account email to search contacts in. Example: "user@example.com".
        query: Search text. Matches name, email, phone, company fields. Example: "john", "0912". Default: "" (all contacts).
        folder: Contact folder name. Example: "Contacts", "Emailed Contacts". Default: "Contacts".
        limit: Max results. Default: 100. Range: 1-1000.
        offset: Starting position for pagination. Default: 0.
    """
    logger.info(f"Searching contacts: account={account}, query='{query}', folder={folder}")

    try:
        # Build search query
        search_query = f'in:"{folder}"'
        if query:
            search_query += f" {query}"

        soap_body = f"""
        <SearchRequest xmlns="urn:zimbraMail"
                       types="contact"
                       limit="{limit}"
                       offset="{offset}"
                       sortBy="nameAsc">
            <query>{search_query}</query>
        </SearchRequest>
        """

        root = query_zimbra_mail_api(soap_body, account)
        parse_zimbra_response(root, namespace="urn:zimbraMail")

        ns_mail = 'urn:zimbraMail'
        contacts = []

        for cn_elem in root.iter(f'{{{ns_mail}}}cn'):
            contact = {
                "id": cn_elem.get('id', ''),
                "file_as": cn_elem.get('fileAsStr', ''),
                "attributes": {}
            }

            # Parse contact attributes
            for attr_elem in cn_elem.iter(f'{{{ns_mail}}}a'):
                attr_name = attr_elem.get('n', '')
                attr_value = attr_elem.text or ''
                if attr_name:
                    contact["attributes"][attr_name] = attr_value

            # Extract common fields for convenience
            attrs = contact["attributes"]
            contact["display_name"] = attrs.get('fullName', attrs.get('firstName', '') + ' ' + attrs.get('lastName', '')).strip()
            contact["email"] = attrs.get('email', '')
            contact["company"] = attrs.get('company', '')
            contact["phone"] = attrs.get('workPhone', attrs.get('mobilePhone', attrs.get('homePhone', '')))
            contact["job_title"] = attrs.get('jobTitle', '')

            contacts.append(contact)

        # Pagination info
        search_resp = root.find(f'.//{{{ns_mail}}}SearchResponse')
        total = int(search_resp.get('total', len(contacts))) if search_resp is not None else len(contacts)
        has_more = search_resp.get('more', 'false') == '1' if search_resp is not None else False

        display_msg = (f"Found {len(contacts)} contacts in {account}'s '{folder}' "
                      f"(total: {total}, showing offset {offset})")
        if has_more:
            display_msg += f" — more results available, use offset={offset + limit}"

        return json.dumps({
            "status": "success",
            "account": account,
            "contacts": contacts,
            "count": len(contacts),
            "total": total,
            "has_more": has_more,
            "offset": offset,
            "limit": limit,
            "display_message": display_msg
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to search contacts: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to search contacts: {str(e)}"
        }, indent=2)

# ------------------- COS Statistics -------------------

@admin_only_tool()
def countAccountByCOS(cos_name: Optional[str] = None) -> str:
    """Count accounts per COS (Class of Service) for license auditing and capacity planning.

    Args:
        cos_name: COS name to filter. Example: "default", "premium". Case-sensitive. Default: all COS.
    """
    logger.info(f"Counting accounts by COS{f': {cos_name}' if cos_name else ''}")

    try:
        # Step 1: Get all COS definitions
        soap_body = """
        <GetAllCosRequest xmlns="urn:zimbraAdmin"/>
        """

        root = query_zimbra_api(soap_body)
        parse_zimbra_response(root)

        ns = {'zimbra': 'urn:zimbraAdmin'}
        cos_elems = root.findall('.//zimbra:cos', ns)

        # Build COS map (id -> name)
        cos_map = {}
        for cos_elem in cos_elems:
            cos_id = cos_elem.get('id')
            name = cos_elem.get('name')
            cos_map[cos_id] = name

        # Step 2: Get ALL accounts and count by their actual COS
        # Important: We fetch all accounts and read their zimbraCOSId attribute
        # This works for both explicitly-set and inherited/default COS
        all_accounts_soap = """
        <SearchDirectoryRequest xmlns="urn:zimbraAdmin" types="accounts" limit="0">
        </SearchDirectoryRequest>
        """

        accounts_root = query_zimbra_api(all_accounts_soap)
        parse_zimbra_response(accounts_root)

        # Get total from response attribute
        search_response = accounts_root.find('.//zimbra:SearchDirectoryResponse', ns)
        total_accounts_in_system = 0
        if search_response is not None:
            total_accounts_in_system = int(search_response.get('searchTotal', 0))

        # Step 3: Now fetch accounts with attributes to count by COS
        # We need to fetch actual account data to read zimbraCOSId
        accounts_with_attrs_soap = f"""
        <SearchDirectoryRequest xmlns="urn:zimbraAdmin" types="accounts" limit="{total_accounts_in_system}">
        </SearchDirectoryRequest>
        """

        full_accounts_root = query_zimbra_api(accounts_with_attrs_soap)
        parse_zimbra_response(full_accounts_root)

        # Count accounts by their actual COS
        cos_count = {}
        account_elems = full_accounts_root.findall('.//zimbra:account', ns)

        for account_elem in account_elems:
            attrs = parse_attributes(account_elem)
            # zimbraCOSId will contain the ACTUAL COS being used
            # (whether explicitly set or inherited from domain/system default)
            actual_cos_id = attrs.get('zimbraCOSId')

            if actual_cos_id:
                cos_count[actual_cos_id] = cos_count.get(actual_cos_id, 0) + 1

        # Step 4: Build statistics
        cos_statistics = []
        total_accounts = 0

        for cos_id, cos_name_val in cos_map.items():
            # Skip if filtering by name and doesn't match
            if cos_name and cos_name_val != cos_name:
                continue

            count = cos_count.get(cos_id, 0)
            cos_statistics.append({
                "cos_id": cos_id,
                "cos_name": cos_name_val,
                "account_count": count
            })
            total_accounts += count

        # Sort by account count descending
        cos_statistics.sort(key=lambda x: x['account_count'], reverse=True)

        return json.dumps({
            "status": "success",
            "cos_statistics": cos_statistics,
            "total_accounts": total_accounts,
            "display_message": f"{len(cos_statistics)} COS total, {total_accounts} accounts total"
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to count accounts by COS: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to count accounts by COS: {str(e)}"
        }, indent=2)

# ------------------- DL Nested Relations -------------------

@admin_only_tool()
def getDLMembership(email: str) -> str:
    """Get all distribution lists that an account or DL belongs to, including nested membership.

    Args:
        email: Account or DL email address. Example: "user@example.com" or "group@example.com".
    """
    logger.info(f"Getting DL membership for {email}")

    try:
        soap_body = f"""
        <GetAccountMembershipRequest xmlns="urn:zimbraAdmin">
            <account by="name">{email}</account>
        </GetAccountMembershipRequest>
        """

        root = query_zimbra_api(soap_body)
        parse_zimbra_response(root)

        ns = {'zimbra': 'urn:zimbraAdmin'}
        dl_elems = root.findall('.//zimbra:dl', ns)

        member_of = []
        for dl_elem in dl_elems:
            dl_info = {
                "id": dl_elem.get('id'),
                "name": dl_elem.get('name'),
                "display_name": dl_elem.get('d'),
                "via": dl_elem.get('via')  # If member via another DL
            }
            member_of.append(dl_info)

        return json.dumps({
            "status": "success",
            "email": email,
            "member_of": member_of,
            "count": len(member_of),
            "display_message": f"{email} belongs to {len(member_of)} distribution lists"
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to get DL membership: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to get DL membership: {str(e)}"
        }, indent=2)

# ------------------- System Information -------------------

@mcp_server.tool()
def getVersionInfo() -> str:
    """Get Zimbra server version, build, and release information."""
    logger.info("Getting Zimbra version information")

    if zimbra_config.auth_mode == "user":
        # User mode: use GetInfoRequest to get version
        try:
            soap_body = '<GetInfoRequest xmlns="urn:zimbraAccount" sections="mbox"/>'
            root = _query_user_soap(soap_body)
            parse_zimbra_response(root, namespace="urn:zimbraAccount")

            ns = {'zimbra': 'urn:zimbraAccount'}
            info_elem = root.find('.//zimbra:GetInfoResponse', ns)

            version_info = {}
            if info_elem is not None:
                version_info["version"] = info_elem.get('version')

            return json.dumps({
                "status": "success",
                "auth_mode": "user",
                "version_info": version_info,
                "display_message": f"Zimbra {version_info.get('version', 'Unknown')} (user mode)"
            }, indent=2)

        except Exception as e:
            logger.error(f"Failed to get version info (user mode): {e}")
            return json.dumps({
                "status": "error",
                "message": f"Failed to get version info: {str(e)}"
            }, indent=2)

    # === ADMIN MODE: original code below ===
    try:
        soap_body = """
        <GetVersionInfoRequest xmlns="urn:zimbraAdmin"/>
        """

        root = query_zimbra_api(soap_body)
        parse_zimbra_response(root)

        ns = {'zimbra': 'urn:zimbraAdmin'}
        info_elem = root.find('.//zimbra:info', ns)

        version_info = {}
        if info_elem is not None:
            version_info = {
                "version": info_elem.get('version'),
                "release": info_elem.get('release'),
                "build_date": info_elem.get('buildDate'),
                "host": info_elem.get('host'),
                "platform": info_elem.get('platform'),
                "major_version": info_elem.get('majorversion'),
                "minor_version": info_elem.get('minorversion'),
                "micro_version": info_elem.get('microversion')
            }

        return json.dumps({
            "status": "success",
            "version_info": version_info,
            "display_message": f"Zimbra {version_info.get('version', 'Unknown')} ({version_info.get('release', 'Unknown')})"
        }, indent=2)

    except Exception as e:
        logger.error(f"Failed to get version info: {e}")
        return json.dumps({
            "status": "error",
            "message": f"Failed to get version info: {str(e)}"
        }, indent=2)

# ======================= CLI Argument Parser =======================

def parse_cli_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Zimbra Collaboration MCP Server - FastMCP Integration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage Examples:

  Admin Mode (full access, 49 tools):
    python3 mcp_zimbra.py \\
      --admin-url https://mail.example.com:7071/service/admin/soap \\
      --admin-user admin@example.com \\
      --admin-pass password

  User Mode (personal mailbox, 18 tools):
    python3 mcp_zimbra.py \\
      --mail-url https://mail.example.com \\
      --user-email user@example.com \\
      --user-pass password

  Environment Variables:
    Admin: ZIMBRA_ADMIN_URL, ZIMBRA_ADMIN_USER, ZIMBRA_ADMIN_PASS
    User:  ZIMBRA_MAIL_URL, ZIMBRA_USER_EMAIL, ZIMBRA_USER_PASS
        """
    )

    admin_group = parser.add_argument_group('Zimbra Admin API Configuration')
    admin_group.add_argument('--admin-url', help='Admin SOAP API URL')
    admin_group.add_argument('--admin-user', help='Admin username')
    admin_group.add_argument('--admin-pass', help='Admin password')
    admin_group.add_argument('--mail-url',
                             help='Web client base URL for REST API (e.g. https://mail.example.com). Auto-detected if not set.')

    user_group = parser.add_argument_group('User Mode Configuration')
    user_group.add_argument('--user-email', help='User email for user mode authentication')
    user_group.add_argument('--user-pass', help='User password for user mode authentication')

    conn_group = parser.add_argument_group('Connection Settings')
    conn_group.add_argument('--use-ssl', type=lambda x: x.lower() in ('true', '1', 'yes'),
                           help='Enable SSL verification (default: true)')

    perf_group = parser.add_argument_group('Performance Settings')
    perf_group.add_argument('--cache-duration', type=int,
                           help='Cache duration in seconds (default: 300)')
    perf_group.add_argument('--request-timeout', type=int,
                           help='Request timeout in seconds (default: 30)')
    perf_group.add_argument('--retry-attempts', type=int,
                           help='Retry attempts for failed requests (default: 3)')

    trace_group = parser.add_argument_group('Mail Tracing (jt_zmmsgtrace) Configuration')
    trace_group.add_argument('--jt-zmmsgtrace-url',
                            help='jt_zmmsgtrace base URL (default: http://localhost)')
    trace_group.add_argument('--jt-zmmsgtrace-port', type=int,
                            help='jt_zmmsgtrace port (default: 8989)')
    trace_group.add_argument('--jt-zmmsgtrace-api-key',
                            help='jt_zmmsgtrace API key (required for mail tracing)')

    transport_group = parser.add_argument_group('MCP Transport Settings')
    transport_group.add_argument('--transport', choices=['stdio', 'streamable-http'],
                                default='stdio',
                                help='Transport mode (default: stdio)')
    transport_group.add_argument('--host', default='127.0.0.1',
                                help='HTTP listen host for streamable-http (default: 127.0.0.1)')
    transport_group.add_argument('--port', type=int, default=8000,
                                help='HTTP listen port for streamable-http (default: 8000)')

    return parser.parse_args()

# ======================= Main Entry Point =======================

if __name__ == "__main__":
    cli_args = parse_cli_arguments()

    zimbra_config = ZimbraConfig(cli_args)

    memory_cache = MemoryCache(zimbra_config.cache_duration)
    setup_http_session()

    logger.info("=" * 80)
    logger.info("Zimbra Collaboration MCP Server v1.8.3")
    logger.info("=" * 80)

    if zimbra_config.auth_mode == "user":
        logger.info(f"Available Tools (18 total, user mode: {zimbra_config.user_email}):")
        logger.info("  Mail: searchMail, getMailDetail, getConversation,")
        logger.info("        getMailAttachment, listFolders, saveDraft, searchContacts")
        logger.info("  Directory: searchGal")
        logger.info("  Trace: jt_zmmsgtrace_search_by_sender/recipient/message_id/")
        logger.info("         host/time, jt_zmmsgtrace_search")
        logger.info("  System: health_check, clear_cache, cache_stats, getVersionInfo")
    else:
        logger.info("Available Tools (49 total, admin mode):")
        logger.info("  Account: getAccountInfo, getAccountQuota, getAccountAliases,")
        logger.info("           unlockAccount, getAllAccounts, getAccountCount")
        logger.info("  DL: getDLInfo, getDLMembers, getAllDistributionLists,")
        logger.info("      getDLMembership")
        logger.info("  Queue: getQueueStat, getQueueList, searchMailQueue")
        logger.info("  Stats: getMailboxStats, getQuotaUsage")
        logger.info("  Server: getServerList, getServerStatus, getActiveSessions")
        logger.info("  Domain/COS: getDomainList, getDomainInfo, getCOSList,")
        logger.info("              getCOSInfo, countAccountByCOS")
        logger.info("  Rights: getGrants, checkRight, getDelegates")
        logger.info("  Bulk Audit: getAllDelegations, getAllForwardings,")
        logger.info("              getAllOutOfOffice, getInactiveAccounts, searchByAttribute")
        logger.info("  Mail: searchMail, getMailDetail, getConversation,")
        logger.info("        getMailAttachment, listFolders, saveDraft, searchContacts")
        logger.info("  Directory: searchGal")
        logger.info("  Trace: jt_zmmsgtrace_search_by_sender/recipient/message_id/")
        logger.info("         host/time, jt_zmmsgtrace_search")
        logger.info("  System: health_check, clear_cache, cache_stats, getVersionInfo")
    logger.info("=" * 80)
    # Transport configuration
    transport_mode = getattr(cli_args, 'transport', 'stdio') or 'stdio'
    http_host = getattr(cli_args, 'host', '127.0.0.1') or '127.0.0.1'
    http_port = getattr(cli_args, 'port', 8000) or 8000

    if transport_mode == 'streamable-http':
        mcp_server.settings.host = http_host
        mcp_server.settings.port = http_port

    logger.info(f"Configuration:")
    logger.info(f"  Cache: {zimbra_config.cache_duration}s | Timeout: {zimbra_config.request_timeout}s")
    logger.info(f"  Retries: {zimbra_config.retry_attempts} | SSL: {zimbra_config.use_ssl}")
    logger.info(f"  Transport: {transport_mode}" +
                (f" ({http_host}:{http_port})" if transport_mode == 'streamable-http' else ''))
    logger.info("=" * 80)

    mcp_server.run(transport=transport_mode)
