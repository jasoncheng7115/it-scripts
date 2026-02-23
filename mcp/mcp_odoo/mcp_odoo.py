#!/usr/bin/env python3
"""
MCP server for Odoo API – v1.7.0 Token-Saving Output Controls
===============================================================================
Author: Jason Cheng (Jason Tools)
Created: 2025-07-14
Updated: 2026-02-10
Version: 1.7.0
License: MIT
Tested: Odoo 13 Community Edition

FastMCP-based Odoo integration with comprehensive business management capabilities.

NEW in v1.7.0:
- Token-saving output controls for ALL search functions:
  - count_only=True: Return only count, no data (minimal tokens)
  - compact=True: Return minimal essential fields only
  - include_lines/include_moves=False: Skip line item details
- Added product_keywords to search_purchase_orders and search_delivery_orders
- Added keywords parameter to search_products for multi-keyword search
- Added get_quotation_stats function for quick statistics
- Optimized for gpt-oss:120b compatibility with clear docstrings

NEW in v1.6.0:
- Added product_keywords parameter to search_quotations:
  - Find products whose name contains ALL specified keywords
  - Example: product_keywords=["proxmox", "訓練"] finds "Proxmox VE 教育訓練課程"
  - Different from product_names which finds multiple different products
- Added docstring reminder: DO NOT translate user keywords

NEW in v1.5.9:
- Added exclude_only_products parameter to search_quotations:
  - Exclude quotations where ALL line items match the exclude keywords
  - Keeps quotations that have training + subscription, excludes subscription-only

NEW in v1.5.8:
- Added product_match_mode parameter to search_quotations:
  - "all" (default): AND logic - quotation must contain ALL products
  - "any": OR logic - quotation must contain ANY of the products

NEW in v1.5.7:
- Enhanced search_quotations with advanced filtering:
  - product_names: Search quotations containing specified products
  - min_amount/max_amount: Filter by total amount range
  - Single API call for complex queries

NEW in v1.5.6:
- Added pagination support (offset parameter) to all search functions:
  - search_quotations, search_purchase_orders, search_delivery_orders
  - search_products, search_partners
  - Use offset to get next batch of results (e.g., offset=10 for 2nd page)
- Dual transport mode support:
  - stdio (default): For Claude Desktop MCP integration
  - streamable-http: For MCPO/OpenAI gateway integration
  - Usage: python mcp_odoo.py --transport streamable-http --port 8001

NEW in v1.5.5:
- Added VAT/Tax ID (統一編號) support to partner management functions
  - create_or_get_partner: Now supports vat parameter
  - create_partner_with_contacts: Now supports vat parameter for company
- VAT number is stored in Odoo's standard 'vat' field
- Added quotation update functions
  - update_quotation: Update quotation header and lines in one operation
  - update_quotation_lines: Dedicated function for line management
- Supports updating customer, addresses, dates, notes, and all line details

NEW in v1.5.4:
- Added partner hierarchy management using parent_id relationship
  - create_partner_with_contacts: Create company with multiple contacts in one operation
  - add_contact_to_partner: Add new contacts to existing companies
- Supports contact types: 'contact', 'invoice', 'delivery', 'other'
- Automatically establishes parent-child relationships between company and contacts

NEW in v1.5.3:
- Added quotation copy functionality with customer replacement
  - create_or_get_partner: Create new partners or retrieve existing ones
  - preview_quotation_copy: Preview the copy before creation with text replacements
  - copy_quotation: Copy quotation to new customer with automatic text replacement
- Safety feature: Requires preview and confirmation before actual copy
- Automatically replaces old customer name in product descriptions and notes

NEW in v1.5.2:
- Fixed multiple quotation numbers search to return all matching results
  - No longer limited by the limit parameter when searching specific quotation numbers
  - Automatically adjusts search limit based on number of quotations requested
  - Added debug logging for domain and search parameters

NEW in v1.5.1:
- Added support for multiple quotation numbers search in search_quotations
  - New parameter: quotation_numbers (List[str]) for efficient bulk search
  - Backward compatible with single quotation_number parameter
  - Uses 'in' operator for exact matches when multiple numbers provided

NEW in v1.5.0:
- Major version milestone with complete multi-language support
- All functions now use consistent product name handling
- Enhanced language context handling across all API calls

NEW in v1.4.9:
- Enhanced _cached_odoo_call to automatically include language context
- Fixed ALL order/delivery functions to use line description (name field) as product name:
  - search_quotations: Now shows quotation line descriptions
  - get_quotation_details: Now shows quotation line descriptions
  - search_purchase_orders: Now shows purchase line descriptions
  - get_purchase_order_details: Now shows purchase line descriptions
  - search_delivery_orders: Now shows stock move descriptions
  - get_delivery_order_details: Now shows stock move descriptions
- Product names now show the actual line text (first line of description)
- All API calls now respect ODOO_DEFAULT_LANGUAGE setting
- Consistent behavior across all functions

NEW in v1.4.8:
- Added default language configuration support
- Can set ODOO_DEFAULT_LANGUAGE in MCP config or environment
- Overrides user's Odoo language preference when set
- Supports configuration in Claude Desktop MCP settings
- Enhanced language detection priority: Config > User Preference > Default

NEW in v1.4.7:
- Added multi-language product search support
- Automatically detects user language from res.users
- Searches both original names and translations (ir.translation)
- Returns product names in user's preferred language
- Supports zh_TW (繁體中文) and en_US (English)

NEW in v1.4.6:
- Added investigate_product_264 to debug specific product naming issues
- Added check_product_variants to examine product variant confusion
- Discovered critical issue: Product ID 264 shows different names in API vs WebUI
- Enhanced investigation tools for product data inconsistencies

NEW in v1.4.5:
- Added search_products_v2 with improved search logic
- Added diagnose_product_search for comprehensive troubleshooting
- Added verify_product_search to validate search functionality
- Fixed domain construction to properly find all products
- Added pagination support with offset parameter
- Direct API calls without cache for accurate results
- Enhanced logging for better debugging

NEW in v1.4.4:
- Fixed product name display to use 'name' field instead of 'display_name'
- Removed "(副本)" or "(copy)" text from product names
- Added check_product_names debug function to analyze name differences
- Preserved original display_name in original_display_name field

NEW in v1.4.3:
- Simplified domain construction for product search
- Removed complex OR logic that was causing search failures
- Added search_products_debug function for troubleshooting
- Added domain logging for better debugging
- Increased search limit multiplier from 3x to 5x

NEW in v1.4.2:
- Enhanced product search to find all matching products
- Added skip_cache parameter for fresh search results
- Automatically skip cache when searching by name
- Increased internal search limit to prevent missing results
- Added total_found vs displayed_count in results

NEW in v1.4.1:
- Fixed search_products name search to properly use ilike operator
- Corrected domain syntax for OR operations in product search
- Now correctly finds products with case-insensitive partial matching

NEW in v1.4.0:
- Complete Product management functions
- search_products: Search products with filters (name, category, type, etc.)
- get_product_details: Get detailed product information including variants
- get_product_stock: Get real-time stock levels across warehouses
- Support for product variants and attributes
- Multi-warehouse stock visibility

NEW in v1.3.1:
- Fixed partner name search to support partial matching
- Enhanced search to include both 'name' and 'display_name' fields
- Improved search results for government agencies and organizations
- Fixed domain syntax errors in OR operations

NEW in v1.3.0:
- Complete Delivery Orders management
- Complete Purchase Orders management
- Enhanced URL generation for all new modules
- Multi-language support for new features
- Comprehensive search and filtering capabilities

Features:
- Complete quotation management with all fields
- Complete delivery orders management (NEW)
- Complete purchase orders management (NEW)
- Direct URL links to all records in Odoo
- Multi-language support (English/Chinese) based on settings
- Multi-currency support with proper currency display
- Enhanced contact/customer/supplier management
- Intelligent caching to reduce API load
- Enhanced error handling and retry logic
- Performance monitoring and statistics
- Configuration validation and health checks

Installation:
pip install mcp requests

Configuration Options:

Option 1 - Claude Desktop MCP Configuration (Recommended):
Add to your Claude Desktop config file (~/.claude/config.json or %APPDATA%\\Claude\\config.json):

{
  "mcpServers": {
    "odoo": {
      "command": "python",
      "args": [
        "/path/to/mcp_odoo.py"
      ],
      "env": {
        "ODOO_URL": "http://localhost:8069",
        "ODOO_DATABASE": "your_db",
        "ODOO_USERNAME": "admin",
        "ODOO_PASSWORD": "your_password",
        "ODOO_DEFAULT_LANGUAGE": "zh_TW"
      }
    }
  }
}

Option 2 - Environment Variables:
ODOO_URL - Odoo base URL (e.g., http://localhost:8069)
ODOO_DATABASE - Odoo database name
ODOO_USERNAME - Odoo username
ODOO_PASSWORD - Odoo password
ODOO_DEFAULT_LANGUAGE - Default language for searches (e.g., zh_TW, en_US) (optional)
ODOO_CACHE_TTL - Cache TTL in seconds (default: 300)
ODOO_TIMEOUT - API timeout in seconds (default: 30)

Run steps:
chmod +x mcp_odoo.py
/path/to/python mcp_odoo.py
"""
import json
import os
import sys
import time
import argparse
import xmlrpc.client
import http.client
import socket
import ssl
from urllib.parse import urlparse
from typing import Optional, Dict, Any, List, Union
from datetime import datetime, timedelta
from functools import wraps
import logging
import hashlib
import re
import traceback


# Custom Transport class for proxy support via HTTP CONNECT tunnel
class ProxiedTransport(xmlrpc.client.SafeTransport):
    """Transport class that supports HTTPS proxy via CONNECT tunnel for XML-RPC"""

    def __init__(self, proxy_host, proxy_port, use_datetime=False, use_builtin_types=False):
        super().__init__(use_datetime=use_datetime, use_builtin_types=use_builtin_types)
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port

    def make_connection(self, host):
        # Parse host:port
        if ':' in host:
            target_host, target_port = host.split(':')
            target_port = int(target_port)
        else:
            target_host = host
            target_port = 443

        # Create socket connection to proxy
        sock = socket.create_connection((self.proxy_host, self.proxy_port), timeout=30)

        # Send CONNECT request
        connect_req = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n\r\n"
        sock.sendall(connect_req.encode('utf-8'))

        # Read proxy response
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(1024)
            if not chunk:
                raise Exception("Proxy connection closed")
            response += chunk

        # Check if proxy accepted the connection
        status_line = response.split(b"\r\n")[0].decode('utf-8')
        if "200" not in status_line:
            raise Exception(f"Proxy CONNECT failed: {status_line}")

        # Wrap socket with SSL
        context = ssl.create_default_context()
        ssl_sock = context.wrap_socket(sock, server_hostname=target_host)

        # Create HTTPS connection using the tunneled socket
        connection = http.client.HTTPSConnection(target_host, target_port)
        connection.sock = ssl_sock

        # Store as tuple (host, connection) for parent class close() method
        self._connection = (host, connection)

        return connection


class ProxiedHTTPTransport(xmlrpc.client.Transport):
    """Transport class that supports HTTP proxy for non-SSL XML-RPC connections"""

    def __init__(self, proxy_host, proxy_port, use_datetime=False, use_builtin_types=False):
        super().__init__(use_datetime=use_datetime, use_builtin_types=use_builtin_types)
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port

    def make_connection(self, host):
        # For HTTP, connect directly through proxy
        return http.client.HTTPConnection(self.proxy_host, self.proxy_port)

from mcp.server.fastmcp import FastMCP

# Version information
__version__ = "1.7.0"
__author__ = "Jason Cheng (Jason Tools)"

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('mcp-odoo')

# Configuration loader with MCP settings support
def load_mcp_config():
    """Load configuration from MCP server arguments or environment variables"""
    config_data = {}
    
    # Try to read from MCP server arguments first
    if len(sys.argv) > 1:
        try:
            # MCP servers can receive configuration as JSON arguments
            mcp_args = json.loads(sys.argv[1]) if sys.argv[1].startswith('{') else {}
            
            # Extract Odoo configuration from MCP args
            if 'odoo_url' in mcp_args:
                config_data['ODOO_URL'] = mcp_args['odoo_url']
            if 'odoo_database' in mcp_args:
                config_data['DATABASE'] = mcp_args['odoo_database']
            if 'odoo_username' in mcp_args:
                config_data['USERNAME'] = mcp_args['odoo_username']
            if 'odoo_password' in mcp_args:
                config_data['PASSWORD'] = mcp_args['odoo_password']
            if 'cache_ttl' in mcp_args:
                config_data['CACHE_TTL'] = int(mcp_args['cache_ttl'])
            if 'timeout' in mcp_args:
                config_data['TIMEOUT'] = int(mcp_args['timeout'])
            if 'max_retries' in mcp_args:
                config_data['MAX_RETRIES'] = int(mcp_args['max_retries'])
            if 'default_language' in mcp_args:
                config_data['DEFAULT_LANGUAGE'] = mcp_args['default_language']
                
            logger.info("Configuration loaded from MCP arguments")
            
        except (json.JSONDecodeError, ValueError, IndexError) as e:
            logger.debug(f"Could not parse MCP arguments: {e}, falling back to environment variables")
    
    # Fall back to environment variables
    if not config_data.get('ODOO_URL'):
        config_data['ODOO_URL'] = os.getenv("ODOO_URL")
    if not config_data.get('DATABASE'):
        config_data['DATABASE'] = os.getenv("ODOO_DATABASE")
    if not config_data.get('USERNAME'):
        config_data['USERNAME'] = os.getenv("ODOO_USERNAME")
    if not config_data.get('PASSWORD'):
        config_data['PASSWORD'] = os.getenv("ODOO_PASSWORD")
    if not config_data.get('CACHE_TTL'):
        config_data['CACHE_TTL'] = int(os.getenv("ODOO_CACHE_TTL", "300"))
    if not config_data.get('TIMEOUT'):
        config_data['TIMEOUT'] = int(os.getenv("ODOO_TIMEOUT", "30"))
    if not config_data.get('MAX_RETRIES'):
        config_data['MAX_RETRIES'] = int(os.getenv("ODOO_MAX_RETRIES", "3"))
    if not config_data.get('DEFAULT_LANGUAGE'):
        config_data['DEFAULT_LANGUAGE'] = os.getenv("ODOO_DEFAULT_LANGUAGE", None)
    
    return config_data

class Config:
    def __init__(self):
        # Load configuration from MCP or environment
        config_data = load_mcp_config()
        
        self.ODOO_URL = config_data.get('ODOO_URL')
        self.DATABASE = config_data.get('DATABASE')
        self.USERNAME = config_data.get('USERNAME')
        self.PASSWORD = config_data.get('PASSWORD')
        self.CACHE_TTL = config_data.get('CACHE_TTL', 300)
        self.TIMEOUT = config_data.get('TIMEOUT', 30)
        self.MAX_RETRIES = config_data.get('MAX_RETRIES', 3)
        self.DEFAULT_LANGUAGE = config_data.get('DEFAULT_LANGUAGE', None)
        
        self.validate()
    
    def validate(self):
        # Skip validation if showing help
        if '--help' in sys.argv or '-h' in sys.argv:
            return

        required_vars = [self.ODOO_URL, self.DATABASE, self.USERNAME, self.PASSWORD]
        if not all(required_vars):
            logger.error("Missing required configuration: ODOO_URL, DATABASE, USERNAME, PASSWORD")
            logger.error("Please set these in your Claude Desktop MCP configuration or environment variables")
            logger.error("Example MCP config:")
            logger.error('  "args": ["/path/to/mcp_odoo.py"]')
            logger.error('  "env": {')
            logger.error('    "ODOO_URL": "http://localhost:8069",')
            logger.error('    "ODOO_DATABASE": "mydb",')
            logger.error('    "ODOO_USERNAME": "admin",')
            logger.error('    "ODOO_PASSWORD": "admin"')
            logger.error('  }')
            sys.exit(1)
        
        # Clean up URL
        self.ODOO_URL = self.ODOO_URL.rstrip('/')
        
        logger.info(f"Odoo URL: {self.ODOO_URL}")
        logger.info(f"Database: {self.DATABASE}")
        logger.info(f"Username: {self.USERNAME}")
        logger.info(f"Cache TTL: {self.CACHE_TTL}s, Timeout: {self.TIMEOUT}s")
        if self.DEFAULT_LANGUAGE:
            logger.info(f"Default Language: {self.DEFAULT_LANGUAGE}")

config = Config()

# JSON encoder for datetime objects
class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super(DateTimeEncoder, self).default(obj)

# Simple in-memory cache
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

# Odoo connection manager with version detection and field validation
class OdooConnection:
    def __init__(self):
        self.url = config.ODOO_URL
        self.db = config.DATABASE
        self.username = config.USERNAME
        self.password = config.PASSWORD
        self.uid = None
        self.models = None
        self.connected = False
        self.version_info = {}
        self.model_fields_cache = {}
        self.user_lang = None  # Store user language

        # Get proxy URL from environment (for Claude Desktop sandbox bypass)
        self.proxy_url = os.environ.get('HTTPS_PROXY') or os.environ.get('HTTP_PROXY')
        self.proxy_host = None
        self.proxy_port = None
        if self.proxy_url:
            parsed = urlparse(self.proxy_url)
            self.proxy_host = parsed.hostname
            self.proxy_port = parsed.port or 8080
            logger.info(f"Using proxy: {self.proxy_host}:{self.proxy_port}")

        self._connect()
        self._detect_version()
        self._initialize_field_cache()
        self._get_user_language()  # Get user language after connection

    def _get_transport(self):
        """Get appropriate transport based on URL scheme and proxy settings"""
        if not self.proxy_host:
            # No proxy, use default transport
            return None
        if self.url.startswith('https://'):
            return ProxiedTransport(self.proxy_host, self.proxy_port)
        else:
            return ProxiedHTTPTransport(self.proxy_host, self.proxy_port)

    def _connect(self):
        """Establish connection to Odoo"""
        try:
            # Get transport with proxy support
            transport = self._get_transport()

            # Authentication
            common = xmlrpc.client.ServerProxy(f'{self.url}/xmlrpc/2/common', transport=transport)
            self.uid = common.authenticate(self.db, self.username, self.password, {})

            if not self.uid:
                raise Exception("Authentication failed")

            # Model connection
            self.models = xmlrpc.client.ServerProxy(f'{self.url}/xmlrpc/2/object', transport=transport)
            self.connected = True

            logger.info(f"Successfully connected to Odoo as UID: {self.uid}")

        except Exception as e:
            logger.error(f"Failed to connect to Odoo: {e}")
            raise e

    def _detect_version(self):
        """Detect Odoo version and capabilities"""
        try:
            transport = self._get_transport()
            common = xmlrpc.client.ServerProxy(f'{self.url}/xmlrpc/2/common', transport=transport)
            version_info = common.version()
            
            self.version_info = {
                'server_version': version_info.get('server_version', 'Unknown'),
                'server_serie': version_info.get('server_serie', 'Unknown'),
                'server_version_info': version_info.get('server_version_info', []),
                'protocol_version': version_info.get('protocol_version', 1)
            }
            
            # Extract major version
            if self.version_info['server_version_info']:
                self.version_info['major_version'] = self.version_info['server_version_info'][0]
            else:
                # Fallback: extract from server_version string
                version_str = self.version_info['server_version']
                if version_str and version_str != 'Unknown':
                    try:
                        major_version = int(version_str.split('.')[0])
                        self.version_info['major_version'] = major_version
                    except:
                        self.version_info['major_version'] = 13  # Default to Odoo 13 (tested version)
                else:
                    self.version_info['major_version'] = 13  # Default to Odoo 13 (tested version)
            
            logger.info(f"Detected Odoo version: {self.version_info['server_version']} (v{self.version_info['major_version']})")
            
        except Exception as e:
            logger.warning(f"Could not detect Odoo version: {e}")
            self.version_info = {
                'server_version': 'Unknown',
                'major_version': 13,  # Default to Odoo 13 (tested version)
                'detection_error': str(e)
            }
    
    def _initialize_field_cache(self):
        """Initialize field cache for critical models"""
        critical_models = [
            'sale.order', 'sale.order.line', 'res.partner', 
            'purchase.order', 'purchase.order.line',
            'stock.picking', 'stock.move', 'stock.move.line',
            'account.move', 'product.product', 'product.template',
            'product.category', 'stock.quant'
        ]
        
        for model in critical_models:
            try:
                self._cache_model_fields(model)
                logger.info(f"Cached fields for model: {model}")
            except Exception as e:
                logger.warning(f"Could not cache fields for {model}: {e}")
                self.model_fields_cache[model] = {}
    
    def _cache_model_fields(self, model_name):
        """Cache available fields for a specific model"""
        try:
            fields = self.execute_kw(model_name, 'fields_get', [], {})
            self.model_fields_cache[model_name] = list(fields.keys())
            return self.model_fields_cache[model_name]
        except Exception as e:
            logger.error(f"Failed to get fields for {model_name}: {e}")
            self.model_fields_cache[model_name] = []
            return []
    
    def get_available_fields(self, model_name, requested_fields):
        """Get list of available fields from requested fields list"""
        if model_name not in self.model_fields_cache:
            self._cache_model_fields(model_name)
        
        available_fields = self.model_fields_cache.get(model_name, [])
        
        # Filter requested fields to only include available ones
        valid_fields = []
        invalid_fields = []
        
        for field in requested_fields:
            if field in available_fields:
                valid_fields.append(field)
            else:
                invalid_fields.append(field)
        
        if invalid_fields:
            logger.debug(f"Model {model_name} - Invalid fields filtered out: {invalid_fields}")
        
        return valid_fields
    
    def get_version_compatible_fields(self, model_name, field_set_name):
        """Get version-compatible field sets for different models"""
        
        # Define field sets based on Odoo version and model
        field_sets = {
            'sale.order': {
                'basic': [
                    'name', 'partner_id', 'date_order', 'state',
                    'amount_untaxed', 'amount_tax', 'amount_total', 'currency_id',
                    'create_date', 'write_date'
                ],
                'standard': [
                    'name', 'partner_id', 'date_order', 'validity_date', 'state',
                    'amount_untaxed', 'amount_tax', 'amount_total', 'currency_id',
                    'payment_term_id', 'pricelist_id', 'user_id', 'team_id',
                    'note', 'client_order_ref', 'origin', 'create_date', 'write_date'
                ],
                'extended': [
                    'name', 'partner_id', 'date_order', 'validity_date', 'state',
                    'amount_untaxed', 'amount_tax', 'amount_total', 'currency_id',
                    'payment_term_id', 'pricelist_id', 'fiscal_position_id',
                    'user_id', 'team_id', 'company_id', 'note', 'client_order_ref',
                    'origin', 'partner_invoice_id', 'partner_shipping_id',
                    'invoice_status', 'warehouse_id', 'carrier_id', 'incoterm',
                    'picking_policy', 'confirmation_date', 'commitment_date',
                    'delivery_status', 'create_date', 'write_date'
                ]
            },
            'sale.order.line': {
                'basic': [
                    'sequence', 'product_id', 'name', 'product_uom_qty',
                    'product_uom', 'price_unit', 'price_subtotal', 'price_total'
                ],
                'standard': [
                    'sequence', 'product_id', 'name', 'product_uom_qty',
                    'product_uom', 'price_unit', 'price_subtotal', 'price_total',
                    'discount', 'tax_id', 'price_reduce', 'price_reduce_taxinc'
                ]
            },
            'purchase.order': {
                'basic': [
                    'name', 'partner_id', 'date_order', 'state',
                    'amount_untaxed', 'amount_tax', 'amount_total', 'currency_id',
                    'create_date', 'write_date'
                ],
                'standard': [
                    'name', 'partner_id', 'date_order', 'date_planned', 'state',
                    'amount_untaxed', 'amount_tax', 'amount_total', 'currency_id',
                    'payment_term_id', 'user_id', 'company_id', 'notes',
                    'partner_ref', 'origin', 'invoice_status', 'receipt_reminder_email',
                    'reminder_date_before_receipt', 'create_date', 'write_date'
                ],
                'extended': [
                    'name', 'partner_id', 'date_order', 'date_planned', 'state',
                    'amount_untaxed', 'amount_tax', 'amount_total', 'currency_id',
                    'payment_term_id', 'fiscal_position_id', 'user_id', 'company_id',
                    'notes', 'partner_ref', 'origin', 'invoice_status',
                    'receipt_reminder_email', 'reminder_date_before_receipt',
                    'picking_type_id', 'dest_address_id', 'default_location_dest_id',
                    'incoterm_id', 'create_date', 'write_date'
                ]
            },
            'purchase.order.line': {
                'basic': [
                    'sequence', 'product_id', 'name', 'product_qty',
                    'product_uom', 'price_unit', 'price_subtotal', 'price_total'
                ],
                'standard': [
                    'sequence', 'product_id', 'name', 'product_qty', 'qty_received',
                    'qty_invoiced', 'product_uom', 'price_unit', 'price_subtotal',
                    'price_total', 'taxes_id', 'date_planned'
                ]
            },
            'stock.picking': {
                'basic': [
                    'name', 'partner_id', 'picking_type_id', 'state',
                    'scheduled_date', 'date_done', 'create_date', 'write_date'
                ],
                'standard': [
                    'name', 'partner_id', 'picking_type_id', 'state', 'priority',
                    'scheduled_date', 'date_done', 'location_id', 'location_dest_id',
                    'origin', 'note', 'company_id', 'user_id', 'carrier_id',
                    'create_date', 'write_date'
                ],
                'extended': [
                    'name', 'partner_id', 'picking_type_id', 'state', 'priority',
                    'scheduled_date', 'date_done', 'location_id', 'location_dest_id',
                    'origin', 'note', 'company_id', 'user_id', 'carrier_id',
                    'carrier_tracking_ref', 'carrier_tracking_url', 'weight',
                    'shipping_weight', 'sale_id', 'purchase_id', 'backorder_id',
                    'group_id', 'create_date', 'write_date'
                ]
            },
            'stock.move': {
                'basic': [
                    'name', 'product_id', 'product_uom_qty', 'quantity_done',
                    'product_uom', 'state', 'location_id', 'location_dest_id'
                ],
                'standard': [
                    'name', 'product_id', 'product_uom_qty', 'quantity_done',
                    'product_uom', 'state', 'location_id', 'location_dest_id',
                    'date', 'date_deadline', 'origin', 'partner_id', 'picking_id',
                    'sale_line_id', 'purchase_line_id'
                ]
            },
            'res.partner': {
                'basic': [
                    'name', 'email', 'phone', 'is_company', 'customer_rank', 'supplier_rank'
                ],
                'standard': [
                    'name', 'display_name', 'email', 'phone', 'mobile',
                    'street', 'city', 'country_id', 'vat', 'lang', 'tz',
                    'is_company', 'customer_rank', 'supplier_rank',
                    'property_payment_term_id', 'property_product_pricelist'
                ]
            },
            'product.product': {
                'basic': [
                    'name', 'display_name', 'default_code', 'barcode', 'type',
                    'categ_id', 'list_price', 'standard_price', 'qty_available',
                    'active'
                ],
                'standard': [
                    'name', 'display_name', 'default_code', 'barcode', 'type',
                    'categ_id', 'list_price', 'standard_price', 'qty_available',
                    'virtual_available', 'uom_id', 'uom_po_id', 'active',
                    'sale_ok', 'purchase_ok', 'description', 'description_sale',
                    'product_tmpl_id', 'attribute_value_ids', 'taxes_id',
                    'supplier_taxes_id', 'company_id'
                ]
            },
            'product.template': {
                'basic': [
                    'name', 'default_code', 'type', 'categ_id', 'list_price',
                    'standard_price', 'active'
                ],
                'standard': [
                    'name', 'default_code', 'type', 'categ_id', 'list_price',
                    'standard_price', 'active', 'sale_ok', 'purchase_ok',
                    'uom_id', 'uom_po_id', 'description', 'description_sale',
                    'description_purchase', 'attribute_line_ids', 'company_id'
                ]
            }
        }
        
        # Get requested field set
        model_fields = field_sets.get(model_name, {})
        requested_fields = model_fields.get(field_set_name, model_fields.get('basic', []))
        
        # Filter by available fields
        return self.get_available_fields(model_name, requested_fields)
    
    def _get_user_language(self):
        """Get the language setting of the connected user"""
        # First check if there's a configured default language
        if config.DEFAULT_LANGUAGE:
            self.user_lang = config.DEFAULT_LANGUAGE
            logger.info(f"Using configured default language: {self.user_lang}")
            return
            
        # Otherwise, get user's language from Odoo
        try:
            # Get user information
            user_data = self.execute_kw(
                'res.users', 'read', [self.uid], 
                {'fields': ['lang', 'name']}
            )
            if user_data:
                self.user_lang = user_data[0].get('lang', 'en_US')
                logger.info(f"User {user_data[0].get('name')} language: {self.user_lang}")
            else:
                self.user_lang = 'en_US'
                logger.warning("Could not get user language, defaulting to en_US")
        except Exception as e:
            logger.warning(f"Failed to get user language: {e}, defaulting to en_US")
            self.user_lang = 'en_US'
    
    def execute_kw(self, model: str, method: str, args: List = None, kwargs: Dict = None):
        """Execute Odoo model method"""
        if not self.connected:
            self._connect()
        
        if args is None:
            args = []
        if kwargs is None:
            kwargs = {}
        
        try:
            return self.models.execute_kw(
                self.db, self.uid, self.password,
                model, method, args, kwargs
            )
        except Exception as e:
            logger.error(f"Odoo API call failed: {model}.{method} - {e}")
            raise e

# Global Odoo connection (skip if showing help)
odoo = None
if '--help' not in sys.argv and '-h' not in sys.argv:
    odoo = OdooConnection()

# Create FastMCP server
mcp = FastMCP("Odoo")

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
def _cached_odoo_call(model: str, method: str, args: List = None, kwargs: Dict = None, use_cache: bool = True) -> Any:
    """Cached Odoo API call with automatic language context
    
    v1.4.9: Automatically adds user language context to all API calls
    """
    
    # Ensure args and kwargs are not None
    if args is None:
        args = []
    if kwargs is None:
        kwargs = {}
    
    # Add language context if available
    if odoo.user_lang and 'context' not in kwargs:
        kwargs['context'] = {'lang': odoo.user_lang}
    elif odoo.user_lang and 'context' in kwargs and 'lang' not in kwargs['context']:
        kwargs['context']['lang'] = odoo.user_lang
    
    # Create cache key
    cache_key = f"{model}:{method}:{json.dumps(args, sort_keys=True)}:{json.dumps(kwargs, sort_keys=True)}" if use_cache else None
    
    # Check cache first for read operations
    if cache_key and method in ['search_read', 'read', 'search', 'name_get']:
        cached_result = cache.get(cache_key)
        if cached_result:
            logger.debug(f"Cache hit for {model}.{method}")
            return cached_result
    
    logger.debug(f"Odoo API call: {model}.{method} args={args} kwargs={kwargs}")
    
    try:
        result = odoo.execute_kw(model, method, args, kwargs)
        
        # Cache successful read operations
        if cache_key and method in ['search_read', 'read', 'search', 'name_get']:
            cache.set(cache_key, result)
        
        return result
        
    except Exception as e:
        logger.error(f"Odoo API call failed: {model}.{method} - {e}")
        raise Exception(f"Odoo API error: {str(e)}")

def _format_datetime(dt_str: str) -> str:
    """Format datetime for display"""
    if not dt_str:
        return "N/A"
    try:
        dt = datetime.fromisoformat(dt_str.replace('Z', ''))
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return str(dt_str)

def _is_english_customer(partner_lang: str) -> bool:
    """Determine if customer uses English"""
    return partner_lang and partner_lang.startswith('en')

def _get_currency_code(currency_tuple: List) -> str:
    """Extract currency code from Odoo currency tuple"""
    if not currency_tuple or len(currency_tuple) < 2:
        return ""
    
    currency_name = currency_tuple[1]
    # Extract currency code (usually in parentheses)
    if '(' in currency_name and ')' in currency_name:
        return currency_name.split('(')[1].split(')')[0]
    return currency_name

def _get_partner_details(partner_id: int) -> Dict:
    """Get detailed partner information including language and currency settings"""
    try:
        partner_data = _cached_odoo_call(
            'res.partner', 'read', [partner_id],
            {'fields': ['name', 'lang', 'country_id', 'tz', 'property_product_pricelist', 'vat']}
        )
        
        if partner_data:
            partner = partner_data[0]
            
            # Get pricelist currency if available
            pricelist_currency = None
            if partner.get('property_product_pricelist'):
                try:
                    pricelist_data = _cached_odoo_call(
                        'product.pricelist', 'read', [partner['property_product_pricelist'][0]],
                        {'fields': ['currency_id']}
                    )
                    if pricelist_data and pricelist_data[0].get('currency_id'):
                        pricelist_currency = pricelist_data[0]['currency_id']
                except Exception as e:
                    logger.warning(f"Failed to get pricelist currency: {e}")
            
            return {
                'name': partner.get('name', ''),
                'lang': partner.get('lang', 'zh_TW'),
                'country': partner.get('country_id', [None, 'Not Set'])[1] if partner.get('country_id') else 'Not Set',
                'timezone': partner.get('tz', 'Not Set'),
                'vat': partner.get('vat', ''),
                'pricelist': partner.get('property_product_pricelist', [None, 'Default'])[1] if partner.get('property_product_pricelist') else 'Default',
                'pricelist_currency': pricelist_currency
            }
    except Exception as e:
        logger.warning(f"Failed to get partner details for {partner_id}: {e}")
    
    return {}

def _generate_record_url(record_id: int, model_name: str) -> str:
    """Generate URL to access any record in Odoo web interface
    
    Args:
        record_id: The ID of the record
        model_name: The Odoo model name (e.g., 'sale.order', 'stock.picking')
        
    Returns:
        Complete URL to the record page
    """
    base_url = config.ODOO_URL
    
    # Standard Odoo web client URL pattern
    url = f"{base_url}/web#id={record_id}&model={model_name}&view_type=form"
    
    return url

def _generate_quotation_url(quotation_id: int) -> str:
    """Generate URL to access quotation in Odoo web interface"""
    return _generate_record_url(quotation_id, 'sale.order')

def _generate_partner_url(partner_id: int) -> str:
    """Generate URL to access partner in Odoo web interface"""
    return _generate_record_url(partner_id, 'res.partner')

def _generate_purchase_order_url(po_id: int) -> str:
    """Generate URL to access purchase order in Odoo web interface"""
    return _generate_record_url(po_id, 'purchase.order')

def _generate_delivery_order_url(delivery_id: int) -> str:
    """Generate URL to access delivery order in Odoo web interface"""
    return _generate_record_url(delivery_id, 'stock.picking')

def _generate_product_url(product_id: int) -> str:
    """Generate URL to access product in Odoo web interface"""
    return _generate_record_url(product_id, 'product.product')

def _translate_delivery_state(state: str, is_english: bool = False) -> str:
    """Translate delivery order state to Chinese or English"""
    states_translation = {
        'draft': {'zh': '草稿', 'en': 'Draft'},
        'waiting': {'zh': '等待中', 'en': 'Waiting'},
        'confirmed': {'zh': '已確認', 'en': 'Confirmed'},
        'assigned': {'zh': '已分配', 'en': 'Assigned'},
        'done': {'zh': '已完成', 'en': 'Done'},
        'cancel': {'zh': '已取消', 'en': 'Cancelled'}
    }
    
    lang = 'en' if is_english else 'zh'
    return states_translation.get(state, {}).get(lang, state)

def _translate_purchase_state(state: str, is_english: bool = False) -> str:
    """Translate purchase order state to Chinese or English"""
    states_translation = {
        'draft': {'zh': '報價需求', 'en': 'RFQ'},
        'sent': {'zh': '已發送報價需求', 'en': 'RFQ Sent'},
        'to approve': {'zh': '待審核', 'en': 'To Approve'},
        'purchase': {'zh': '採購單', 'en': 'Purchase Order'},
        'done': {'zh': '已完成', 'en': 'Done'},
        'cancel': {'zh': '已取消', 'en': 'Cancelled'}
    }
    
    lang = 'en' if is_english else 'zh'
    return states_translation.get(state, {}).get(lang, state)

# ───────────────────────── Core MCP Tools ─────────────────────────

@mcp.tool()
def get_odoo_system_info() -> str:
    """Get Odoo system information including version, connection status, and server capabilities.

    Returns:
        JSON with: server_version, database, connected_user, cached_models, mcp_version
    """
    logger.info("Getting Odoo system information")
    
    try:
        result = {
            "mcp_server_info": {
                "name": "Odoo MCP Server",
                "version": __version__,
                "author": __author__,
                "new_features_v1_3": [
                    "Complete Delivery Orders (出貨單) management",
                    "Complete Purchase Orders (採購單) management",
                    "Enhanced URL generation for all modules",
                    "Multi-language support for new features"
                ]
            },
            "connection_status": "connected" if odoo.connected else "disconnected",
            "version_info": odoo.version_info,
            "database": config.DATABASE,
            "user_id": odoo.uid,
            "base_url": config.ODOO_URL,
            "cached_models": list(odoo.model_fields_cache.keys()),
            "model_field_counts": {
                model: len(fields) for model, fields in odoo.model_fields_cache.items()
            },
            "url_generation": {
                "quotation_url_pattern": f"{config.ODOO_URL}/web#id={{ID}}&model=sale.order&view_type=form",
                "partner_url_pattern": f"{config.ODOO_URL}/web#id={{ID}}&model=res.partner&view_type=form",
                "purchase_order_url_pattern": f"{config.ODOO_URL}/web#id={{ID}}&model=purchase.order&view_type=form",
                "delivery_order_url_pattern": f"{config.ODOO_URL}/web#id={{ID}}&model=stock.picking&view_type=form"
            },
            "supported_modules": {
                "sales": ["quotations", "sales_orders", "customers"],
                "purchase": ["purchase_orders", "rfq", "suppliers"],
                "inventory": ["delivery_orders", "stock_picking", "stock_moves"],
                "contacts": ["partners", "customers", "suppliers"]
            },
            "timestamp": datetime.now().isoformat()
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# @mcp.tool()  # Disabled to reduce tool count
def get_sale_order_fields() -> str:
    """Get available fields for sale.order model to check compatibility
    
    Returns:
        JSON string with all available fields in sale.order model
    """
    logger.info("Getting sale.order model fields")
    
    try:
        fields = _cached_odoo_call('sale.order', 'fields_get', [], {})
        
        # Extract field names and types
        field_summary = {}
        for field_name, field_info in fields.items():
            field_summary[field_name] = {
                "type": field_info.get('type'),
                "string": field_info.get('string'),
                "required": field_info.get('required', False),
                "readonly": field_info.get('readonly', False)
            }
        
        result = {
            "model": "sale.order",
            "total_fields": len(field_summary),
            "fields": field_summary,
            "timestamp": datetime.now().isoformat()
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Error getting sale.order fields: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# @mcp.tool()  # Disabled to reduce tool count
def health_check() -> str:
    """Perform health check on Odoo connection and cache system
    
    Returns:
        JSON string with health status and performance metrics
    """
    logger.info("Performing health check")
    
    try:
        start_time = time.time()
        
        # Test basic connection
        test_result = _cached_odoo_call('res.partner', 'search', [[]], {'limit': 1}, use_cache=False)
        api_response_time = time.time() - start_time
        
        # Get cache statistics
        cache_stats = cache.stats()
        
        # Test authentication
        auth_status = "OK" if test_result is not None else "FAILED"
        
        result = {
            "status": "healthy" if auth_status == "OK" else "unhealthy",
            "timestamp": datetime.now().isoformat(),
            "mcp_server_info": {
                "version": __version__,
                "author": __author__
            },
            "odoo_connection": {
                "status": auth_status,
                "response_time_ms": round(api_response_time * 1000, 2),
                "url": config.ODOO_URL,
                "database": config.DATABASE,
                "username": config.USERNAME,
                "user_id": odoo.uid,
                "version": odoo.version_info.get('server_version', 'Unknown'),
                "major_version": odoo.version_info.get('major_version', 'Unknown')
            },
            "cache": cache_stats,
            "field_cache": {
                "cached_models": list(odoo.model_fields_cache.keys()),
                "total_cached_fields": sum(len(fields) for fields in odoo.model_fields_cache.values())
            },
            "configuration": {
                "timeout": config.TIMEOUT,
                "max_retries": config.MAX_RETRIES
            },
            "url_generation": {
                "enabled": True,
                "base_url": config.ODOO_URL,
                "sample_quotation_url": _generate_quotation_url(1),
                "sample_partner_url": _generate_partner_url(1),
                "sample_purchase_order_url": _generate_purchase_order_url(1),
                "sample_delivery_order_url": _generate_delivery_order_url(1)
            },
            "new_capabilities_v1_3": {
                "delivery_orders": True,
                "purchase_orders": True,
                "enhanced_url_generation": True,
                "multi_language_support": True
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        return json.dumps({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }, indent=2, ensure_ascii=False)

# @mcp.tool()  # Disabled to reduce tool count
def odoo_raw_call(model: str, method: str, args: Optional[List] = None, kwargs: Optional[Dict] = None) -> str:
    """Execute raw Odoo API call
    
    Args:
        model: Odoo model name (e.g., 'sale.order', 'res.partner')
        method: Method name (e.g., 'search_read', 'create', 'write')
        args: Arguments list (optional)
        kwargs: Keyword arguments (optional)
    
    Returns:
        JSON string of API response
    """
    logger.info(f"Raw Odoo call: {model}.{method}")
    
    try:
        if args is None:
            args = []
        if kwargs is None:
            kwargs = {}
            
        result = _cached_odoo_call(model, method, args, kwargs, use_cache=False)
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# ───────────────────────── Quotation Management ─────────────────────────

@mcp.tool()
def search_quotations(partner_name: Optional[str] = None, quotation_number: Optional[str] = None,
                     quotation_numbers: Optional[List[str]] = None,
                     state: Optional[str] = None, date_from: Optional[str] = None,
                     date_to: Optional[str] = None, product_name: Optional[str] = None,
                     product_keywords: Optional[List[str]] = None,
                     product_names: Optional[List[str]] = None,
                     product_match_mode: str = "all",
                     exclude_only_products: Optional[List[str]] = None,
                     min_amount: Optional[float] = None, max_amount: Optional[float] = None,
                     description_contains: Optional[str] = None, global_search: Optional[str] = None,
                     limit: int = 10, offset: int = 0,
                     compact: bool = False, include_lines: bool = True, count_only: bool = False) -> str:
    """Search Odoo quotations/sales orders with flexible filters.

    IMPORTANT: Use the EXACT keywords from user input. DO NOT translate.
    If user says "教育訓練", use "教育訓練" not "training".
    If user says "proxmox 訓練", use ["proxmox", "訓練"] not ["proxmox", "training"].

    WHEN TO USE THIS FUNCTION:
    - Finding quotations by customer, product, amount, date, or any combination
    - Finding products whose name contains multiple keywords (e.g., "Proxmox 教育訓練")
    - Complex queries like "quotations with training but not only subscriptions"
    - Amount-based filtering like "quotations over 100,000"

    OUTPUT CONTROL (use these to reduce response size):
    - count_only=True: Only return count, no data (fastest, minimal tokens)
    - compact=True: Return minimal fields only (id, name, customer, amount, state, date)
    - include_lines=False: Skip line items detail (saves ~50% tokens)

    Args:
        partner_name: Customer name (partial match supported)
        quotation_number: Single quotation number (e.g., 'S00123')
        quotation_numbers: List of quotation numbers for bulk search
        state: Filter by state - draft/sent/sale/done/cancel
        date_from: Start date filter (YYYY-MM-DD)
        date_to: End date filter (YYYY-MM-DD)
        product_name: Filter by single product/service name in lines (single keyword)
        product_keywords: Find products whose name contains ALL these keywords.
                          Example: ["proxmox", "訓練"] finds "Proxmox VE 教育訓練課程"
        product_names: Find quotations containing multiple DIFFERENT products.
                       Use with product_match_mode. Example: ["graylog", "librenms"]
        product_match_mode: How to match product_names - "all" (AND) or "any" (OR).
        exclude_only_products: Exclude quotations where ALL lines match these keywords.
        min_amount: Minimum total amount filter
        max_amount: Maximum total amount filter
        description_contains: Search in quotation notes
        global_search: Search across all fields
        limit: Max results (default: 10)
        offset: Skip first N results for pagination (default: 0)
        compact: Return minimal fields only (default: False)
        include_lines: Include line items detail (default: True, set False to save tokens)
        count_only: Only return count, no quotation data (default: False)

    Returns:
        JSON with quotations list (or count if count_only=True)

    EXAMPLES:
        # Quick count of matching quotations
        search_quotations(product_keywords=["proxmox", "訓練"], count_only=True)

        # Compact list without line details (saves tokens)
        search_quotations(partner_name="ABC", compact=True, include_lines=False)

        # Full details for specific quotations
        search_quotations(quotation_numbers=["S00123", "S00124"])
    """
    logger.info(f"Searching quotations: partner={partner_name}, product={product_name}, keywords={product_keywords}, products={product_names}, min_amount={min_amount}, max_amount={max_amount}, global={global_search}")

    try:
        # Build domain filters
        domain = []

        if partner_name:
            # Use OR to search in both name and display_name for better matching
            domain.extend(['|', ['partner_id.name', 'ilike', partner_name], ['partner_id.display_name', 'ilike', partner_name]])

        # Handle quotation number(s) search
        if quotation_numbers:
            # Multiple quotation numbers provided
            if len(quotation_numbers) == 1:
                # Single item in list
                domain.append(['name', 'ilike', quotation_numbers[0]])
            else:
                # Multiple items - use 'in' operator for exact matches
                domain.append(['name', 'in', quotation_numbers])
                logger.info(f"Searching for {len(quotation_numbers)} specific quotation numbers: {quotation_numbers[:5]}... (showing first 5)")
        elif quotation_number:
            # Single quotation number provided (backward compatibility)
            domain.append(['name', 'ilike', quotation_number])
        if state:
            domain.append(['state', '=', state])
        if date_from:
            domain.append(['date_order', '>=', date_from])
        if date_to:
            domain.append(['date_order', '<=', date_to])
        if description_contains:
            domain.append(['note', 'ilike', description_contains])

        # Amount filtering
        if min_amount is not None:
            domain.append(['amount_total', '>=', min_amount])
            logger.info(f"Filtering by min_amount >= {min_amount}")
        if max_amount is not None:
            domain.append(['amount_total', '<=', max_amount])
            logger.info(f"Filtering by max_amount <= {max_amount}")
        
        # Global search across multiple fields (simplified approach)
        quotation_ids_from_global = []
        if global_search:
            try:
                # Search each field separately and combine results
                search_domains = [
                    [['name', 'ilike', global_search]],
                    [['note', 'ilike', global_search]],
                    [['client_order_ref', 'ilike', global_search]],
                    [['origin', 'ilike', global_search]],
                    ['|', ['partner_id.name', 'ilike', global_search], ['partner_id.display_name', 'ilike', global_search]]
                ]
                
                # Try to search user_id.name if field exists
                try:
                    user_search = [['user_id.name', 'ilike', global_search]]
                    search_domains.append(user_search)
                except:
                    pass  # Skip if user_id.name field doesn't exist
                
                for search_domain in search_domains:
                    try:
                        results = _cached_odoo_call(
                            'sale.order', 'search', search_domain,
                            {'limit': 1000}
                        )
                        if results:
                            quotation_ids_from_global.extend(results)
                    except Exception as e:
                        logger.debug(f"Search domain {search_domain} failed: {e}")
                        continue
                
                # Remove duplicates
                quotation_ids_from_global = list(set(quotation_ids_from_global))
                logger.info(f"Global search found {len(quotation_ids_from_global)} quotations")
                
            except Exception as e:
                logger.warning(f"Global search failed: {e}")
        
        # If searching by product_keywords (single product with multiple keywords in name)
        quotation_ids_from_keywords = None  # None means not filtered, [] means no results
        if product_keywords and len(product_keywords) > 0:
            try:
                logger.info(f"Searching for products containing ALL keywords: {product_keywords}")

                # Get all lines first, then filter in Python for multi-keyword match
                # Start with the first keyword to narrow down
                first_keyword = product_keywords[0]
                line_domain = [
                    '|',
                    ['product_id.name', 'ilike', first_keyword],
                    ['name', 'ilike', first_keyword]
                ]
                matching_lines = _cached_odoo_call(
                    'sale.order.line', 'search_read', [line_domain],
                    {'fields': ['order_id', 'name', 'product_id'], 'limit': 5000}
                )

                # Filter lines where ALL keywords are present
                quotation_ids_from_keywords = set()
                for line in matching_lines:
                    line_name = (line.get('name') or '').lower()
                    product_name_str = ''
                    if line.get('product_id'):
                        product_name_str = (line['product_id'][1] if isinstance(line['product_id'], list) else '').lower()

                    combined_text = f"{line_name} {product_name_str}"

                    # Check if ALL keywords are present
                    if all(kw.lower() in combined_text for kw in product_keywords):
                        if line.get('order_id'):
                            quotation_ids_from_keywords.add(line['order_id'][0])

                quotation_ids_from_keywords = list(quotation_ids_from_keywords)
                logger.info(f"Found {len(quotation_ids_from_keywords)} quotations with products matching ALL keywords: {product_keywords}")

            except Exception as e:
                logger.warning(f"Error searching product keywords: {e}")
                quotation_ids_from_keywords = []

        # If searching by multiple product names, find intersection (AND) or union (OR)
        quotation_ids_from_multi_products = None  # None means not filtered, [] means no results
        if product_names and len(product_names) > 0:
            try:
                match_mode = product_match_mode.lower() if product_match_mode else "all"
                if match_mode not in ("all", "any"):
                    match_mode = "all"

                logger.info(f"Searching for quotations containing {match_mode.upper()} of products: {product_names}")
                product_id_sets = []

                for pname in product_names:
                    line_domain = [
                        '|',
                        ['product_id.name', 'ilike', pname],
                        ['name', 'ilike', pname]
                    ]
                    matching_lines = _cached_odoo_call(
                        'sale.order.line', 'search_read', [line_domain],
                        {'fields': ['order_id'], 'limit': 5000}
                    )
                    order_ids = set([line['order_id'][0] for line in matching_lines if line.get('order_id')])
                    logger.info(f"  - Product '{pname}': found in {len(order_ids)} quotations")
                    product_id_sets.append(order_ids)

                if product_id_sets:
                    if match_mode == "all":
                        # AND logic: intersection of all sets
                        quotation_ids_from_multi_products = list(set.intersection(*product_id_sets))
                        logger.info(f"Intersection (AND): {len(quotation_ids_from_multi_products)} quotations contain ALL products")
                    else:
                        # OR logic: union of all sets
                        quotation_ids_from_multi_products = list(set.union(*product_id_sets))
                        logger.info(f"Union (OR): {len(quotation_ids_from_multi_products)} quotations contain ANY product")
                else:
                    quotation_ids_from_multi_products = []

            except Exception as e:
                logger.warning(f"Error searching multiple products: {e}")
                quotation_ids_from_multi_products = []

        # If searching by single product/service name, we need to search in quotation lines first
        quotation_ids_from_lines = []
        if product_name or global_search:
            try:
                # Search in sale.order.line for products matching the criteria
                line_domain = []
                if product_name:
                    line_domain = [
                        '|',
                        ['product_id.name', 'ilike', product_name],
                        ['name', 'ilike', product_name]  # This includes service descriptions
                    ]
                elif global_search:
                    line_domain = [
                        '|',
                        ['product_id.name', 'ilike', global_search],
                        ['name', 'ilike', global_search]  # This includes service descriptions
                    ]

                if line_domain:
                    line_fields = ['order_id', 'product_id', 'name']
                    matching_lines = _cached_odoo_call(
                        'sale.order.line', 'search_read', [line_domain],
                        {'fields': line_fields, 'limit': 1000}  # Get more lines to find all matching orders
                    )

                    # Extract unique order IDs
                    quotation_ids_from_lines = list(set([line['order_id'][0] for line in matching_lines if line.get('order_id')]))
                    search_term = product_name or global_search
                    logger.info(f"Found {len(quotation_ids_from_lines)} quotations with product/service: {search_term}")

            except Exception as e:
                logger.warning(f"Error searching quotation lines: {e}")

        # Combine all found quotation IDs (priority: keywords > multi-products > global > single)
        all_found_ids = []
        if quotation_ids_from_keywords is not None:
            # Product keywords search takes highest priority
            all_found_ids = quotation_ids_from_keywords
        elif quotation_ids_from_multi_products is not None:
            # Multi-product AND/OR search
            all_found_ids = quotation_ids_from_multi_products
        elif global_search:
            all_found_ids.extend(quotation_ids_from_global)
            all_found_ids.extend(quotation_ids_from_lines)
            all_found_ids = list(set(all_found_ids))  # Remove duplicates
        elif product_name:
            all_found_ids = quotation_ids_from_lines

        # Add ID filter to domain if we found specific quotations
        if all_found_ids:
            domain.append(['id', 'in', all_found_ids])
        elif product_keywords and len(product_keywords) > 0:
            # No quotations found with products matching all keywords
            logger.info(f"No quotations found with products matching ALL keywords: {product_keywords}")
            return json.dumps({
                "quotations": [],
                "summary": {
                    "total_found": 0,
                    "message": f"No quotations found with products containing ALL of: {', '.join(product_keywords)}"
                },
                "query_info": {
                    "product_keywords_filter": product_keywords,
                    "search_method": "product_keywords_search",
                    "timestamp": datetime.now().isoformat()
                }
            }, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
        elif product_names and len(product_names) > 0:
            # No quotations found containing ALL specified products
            logger.info(f"No quotations found containing ALL products: {product_names}")
            return json.dumps({
                "quotations": [],
                "summary": {
                    "total_found": 0,
                    "message": f"No quotations found containing ALL of: {', '.join(product_names)}"
                },
                "query_info": {
                    "product_names_filter": product_names,
                    "search_method": "multi_product_and_search",
                    "timestamp": datetime.now().isoformat()
                }
            }, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
        elif product_name and not global_search:
            # No matching products found for specific product search, return empty result
            logger.info(f"No quotations found containing product/service: {product_name}")
            return json.dumps({
                "quotations": [],
                "summary": {
                    "total_found": 0,
                    "message": f"No quotations found containing '{product_name}'"
                },
                "query_info": {
                    "product_name_filter": product_name,
                    "search_method": "product_line_search",
                    "timestamp": datetime.now().isoformat()
                }
            }, indent=2, ensure_ascii=False, cls=DateTimeEncoder)

        # Log the final domain for debugging
        logger.info(f"Final search domain: {domain}")

        # Get quotations using version-compatible fields
        available_fields = odoo.get_version_compatible_fields('sale.order', 'standard')

        # Increase limit if we're doing a product/global search or multiple quotation numbers search
        # For multiple quotation numbers, we want to get ALL matching results
        if quotation_numbers and len(quotation_numbers) > 1:
            search_limit = len(quotation_numbers) * 2  # Allow some buffer for potential duplicates
        else:
            # Increase limit more if we need to filter by exclude_only_products
            multiplier = 20 if exclude_only_products else 10
            search_limit = min(limit * multiplier, 2000) if (product_name or product_keywords or product_names or global_search or exclude_only_products) else limit

        quotations = _cached_odoo_call(
            'sale.order', 'search_read', [domain],
            {
                'fields': available_fields,
                'limit': search_limit,
                'order': 'date_order desc'
            }
        )

        # Apply exclude_only_products filter: remove quotations where ALL lines match exclude keywords
        if exclude_only_products and len(exclude_only_products) > 0:
            logger.info(f"Applying exclude_only_products filter: {exclude_only_products}")
            filtered_quotations = []
            excluded_count = 0

            for quote in quotations:
                try:
                    # Get all lines for this quotation
                    quote_lines = _cached_odoo_call(
                        'sale.order.line', 'search_read',
                        [[['order_id', '=', quote['id']]]],
                        {'fields': ['name', 'product_id'], 'limit': 100}
                    )

                    if not quote_lines:
                        # No lines, keep the quotation
                        filtered_quotations.append(quote)
                        continue

                    # Check if ALL lines match any of the exclude keywords
                    all_lines_match_exclude = True
                    for line in quote_lines:
                        line_name = (line.get('name') or '').lower()
                        product_name_str = ''
                        if line.get('product_id'):
                            product_name_str = (line['product_id'][1] if isinstance(line['product_id'], list) else '').lower()

                        line_text = f"{line_name} {product_name_str}"

                        # Check if this line matches any exclude keyword
                        line_matches_exclude = any(
                            excl.lower() in line_text
                            for excl in exclude_only_products
                        )

                        if not line_matches_exclude:
                            # This line does NOT match any exclude keyword
                            # So the quotation has at least one non-excluded product
                            all_lines_match_exclude = False
                            break

                    if all_lines_match_exclude:
                        # All lines match exclude keywords, skip this quotation
                        excluded_count += 1
                    else:
                        # At least one line is not in exclude list, keep this quotation
                        filtered_quotations.append(quote)

                except Exception as e:
                    logger.warning(f"Error checking lines for quotation {quote['id']}: {e}")
                    filtered_quotations.append(quote)  # Keep on error

            logger.info(f"Excluded {excluded_count} quotations that only contained excluded products")
            quotations = filtered_quotations

        # Apply offset and limit for pagination
        # But don't paginate if we're searching for specific quotation numbers
        if not (quotation_numbers and len(quotation_numbers) > 1):
            quotations = quotations[offset:offset + limit]

        # Handle count_only mode - return just the count
        if count_only:
            return json.dumps({
                "count": len(quotations),
                "query_info": {
                    "mode": "count_only",
                    "filters_applied": {
                        "partner_name": partner_name,
                        "product_keywords": product_keywords,
                        "product_names": product_names,
                        "min_amount": min_amount,
                        "max_amount": max_amount,
                        "state": state,
                        "date_from": date_from,
                        "date_to": date_to
                    },
                    "timestamp": datetime.now().isoformat()
                }
            }, indent=2, ensure_ascii=False, cls=DateTimeEncoder)

        # Enrich each quotation
        enriched_quotations = []

        for quote in quotations:
            # Compact mode: minimal fields only
            if compact:
                enriched_quote = {
                    'id': quote.get('id'),
                    'name': quote.get('name'),
                    'customer': quote.get('partner_id', [None, ''])[1] if quote.get('partner_id') else '',
                    'amount_total': quote.get('amount_total', 0),
                    'state': quote.get('state'),
                    'date': quote.get('date_order', '')[:10] if quote.get('date_order') else '',
                    'odoo_url': _generate_quotation_url(quote['id'])
                }
            else:
                # Full mode
                enriched_quote = quote.copy()
                enriched_quote['odoo_url'] = _generate_quotation_url(quote['id'])
                enriched_quote['url_description'] = f"點擊直接開啟報價單 {quote.get('name', quote['id'])}"

                if quote.get('partner_id'):
                    partner_details = _get_partner_details(quote['partner_id'][0])
                    enriched_quote['customer_details'] = partner_details
                    enriched_quote['customer_url'] = _generate_partner_url(quote['partner_id'][0])

                    currency_code = _get_currency_code(quote.get('currency_id', []))
                    enriched_quote['currency_code'] = currency_code

                    for field in ['amount_untaxed', 'amount_tax', 'amount_total']:
                        if quote.get(field) is not None:
                            enriched_quote[f'{field}_formatted'] = f"{quote[field]} {currency_code}"

            # Get quotation lines (skip if include_lines=False)
            if include_lines and not compact:
                try:
                    line_fields = odoo.get_version_compatible_fields('sale.order.line', 'standard')
                    quote_lines = _cached_odoo_call(
                        'sale.order.line', 'search_read',
                        [[['order_id', '=', quote['id']]]],
                        {'fields': line_fields, 'order': 'sequence'}
                    )

                    services_products = []
                    for line in quote_lines:
                        line_product_name = line.get('name', '')
                        if line_product_name:
                            line_product_name = line_product_name.split('\n')[0].strip()

                        line_info = {
                            'product_name': line_product_name,
                            'quantity': line.get('product_uom_qty', 1),
                            'unit_price': line.get('price_unit', 0),
                            'subtotal': line.get('price_subtotal', 0)
                        }
                        services_products.append(line_info)

                    enriched_quote['lines'] = services_products
                    enriched_quote['line_count'] = len(services_products)

                except Exception as e:
                    logger.warning(f"Failed to get lines for quotation {quote['id']}: {e}")
                    enriched_quote['lines'] = []
                    enriched_quote['line_count'] = 0
            elif not compact:
                enriched_quote['line_count'] = 0
                enriched_quote['lines_skipped'] = True

            enriched_quotations.append(enriched_quote)
        
        # Build result based on compact mode
        total_found = len(enriched_quotations)

        if compact:
            # Compact result - minimal metadata
            result = {
                "quotations": enriched_quotations,
                "total": total_found,
                "mode": "compact"
            }
        else:
            # Full result with statistics
            state_breakdown = {}
            for quote in enriched_quotations:
                st = quote.get('state', 'unknown')
                state_breakdown[st] = state_breakdown.get(st, 0) + 1

            result = {
                "quotations": enriched_quotations,
                "summary": {
                    "total_found": total_found,
                    "state_breakdown": state_breakdown,
                    "include_lines": include_lines
                },
                "query_info": {
                    "product_keywords": product_keywords,
                    "product_names": product_names,
                    "min_amount": min_amount,
                    "max_amount": max_amount,
                    "exclude_only_products": exclude_only_products,
                    "timestamp": datetime.now().isoformat()
                }
            }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Error searching quotations: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def get_quotation_stats(date_from: Optional[str] = None, date_to: Optional[str] = None,
                        partner_name: Optional[str] = None, state: Optional[str] = None) -> str:
    """Get statistical summary of quotations/sales orders.

    Use this for quick statistics without fetching full quotation data.
    Much faster and uses fewer tokens than search_quotations.

    Args:
        date_from: Start date filter (YYYY-MM-DD)
        date_to: End date filter (YYYY-MM-DD)
        partner_name: Filter by customer name
        state: Filter by state - draft/sent/sale/done/cancel

    Returns:
        JSON with statistics: count by state, total amounts, date range summary
    """
    logger.info(f"Getting quotation stats: date_from={date_from}, date_to={date_to}")

    try:
        # Build domain filters
        domain = []

        if partner_name:
            domain.extend(['|', ['partner_id.name', 'ilike', partner_name],
                          ['partner_id.display_name', 'ilike', partner_name]])
        if state:
            domain.append(['state', '=', state])
        if date_from:
            domain.append(['date_order', '>=', date_from])
        if date_to:
            domain.append(['date_order', '<=', date_to])

        # Fetch minimal fields needed for statistics
        quotations = _cached_odoo_call(
            'sale.order', 'search_read', [domain],
            {'fields': ['id', 'state', 'amount_total', 'currency_id', 'date_order'],
             'limit': 10000, 'order': 'date_order desc'}
        )

        # Calculate statistics
        state_counts = {}
        state_amounts = {}
        currency_totals = {}
        dates = []

        for q in quotations:
            st = q.get('state', 'unknown')
            state_counts[st] = state_counts.get(st, 0) + 1
            state_amounts[st] = state_amounts.get(st, 0) + (q.get('amount_total', 0) or 0)

            currency = q.get('currency_id', [None, 'TWD'])[1] if q.get('currency_id') else 'TWD'
            if currency not in currency_totals:
                currency_totals[currency] = {'count': 0, 'total': 0}
            currency_totals[currency]['count'] += 1
            currency_totals[currency]['total'] += (q.get('amount_total', 0) or 0)

            if q.get('date_order'):
                dates.append(q['date_order'][:10])

        # State translations
        state_names = {
            'draft': '報價單 (Draft)',
            'sent': '已發送報價 (Sent)',
            'sale': '銷售訂單 (Sales Order)',
            'done': '已完成 (Done)',
            'cancel': '已取消 (Cancelled)'
        }

        result = {
            "statistics": {
                "total_count": len(quotations),
                "by_state": {state_names.get(k, k): {'count': v, 'total_amount': state_amounts.get(k, 0)}
                            for k, v in state_counts.items()},
                "by_currency": currency_totals,
                "date_range": {
                    "earliest": min(dates) if dates else None,
                    "latest": max(dates) if dates else None
                }
            },
            "query_info": {
                "date_from": date_from,
                "date_to": date_to,
                "partner_name": partner_name,
                "state": state,
                "timestamp": datetime.now().isoformat()
            }
        }

        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)

    except Exception as e:
        logger.error(f"Error getting quotation stats: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def get_quotation_details(quotation_id: int, include_lines: bool = True) -> str:
    """Get detailed quotation/sales order information by ID.

    Args:
        quotation_id: The quotation ID (integer)
        include_lines: Include line items with product details (default: True)

    Returns:
        JSON with: header info, customer details, line items (product, qty, price, subtotal),
        totals, currency, payment terms, and direct Odoo URL
    """
    logger.info(f"Getting quotation details for ID: {quotation_id}")
    
    try:
        # Get quotation header using compatible fields
        available_fields = odoo.get_version_compatible_fields('sale.order', 'standard')
        
        quotation = _cached_odoo_call(
            'sale.order', 'read', [quotation_id],
            {'fields': available_fields}
        )
        
        if not quotation:
            return json.dumps({"error": "Quotation not found"}, indent=2, ensure_ascii=False)
        
        quote_data = quotation[0]
        
        # Get customer details for language/currency settings
        customer_details = {}
        is_english = False
        customer_url = None
        if quote_data.get('partner_id'):
            customer_details = _get_partner_details(quote_data['partner_id'][0])
            is_english = _is_english_customer(customer_details.get('lang', ''))
            customer_url = _generate_partner_url(quote_data['partner_id'][0])
        
        # Get currency code
        currency_code = _get_currency_code(quote_data.get('currency_id', []))
        
        # Generate quotation URL
        quotation_url = _generate_quotation_url(quotation_id)
        
        # Get quotation lines if requested
        quotation_lines = []
        if include_lines:
            line_fields = odoo.get_version_compatible_fields('sale.order.line', 'standard')
            
            lines = _cached_odoo_call(
                'sale.order.line', 'search_read',
                [[['order_id', '=', quotation_id]]],
                {
                    'fields': line_fields,
                    'order': 'sequence'
                }
            )
            
            
            # Format line items with currency and language
            for line in lines:
                formatted_line = line.copy()
                
                # Format prices with currency
                price_fields = ['price_unit', 'price_subtotal', 'price_total', 'price_reduce', 'price_reduce_taxinc']
                for field in price_fields:
                    if line.get(field) is not None:
                        formatted_line[f'{field}_formatted'] = f"{line[field]} {currency_code}"
                
                # Format product information using the line description
                # Use the 'name' field which contains the actual line description
                product_name = line.get('name', '')
                if product_name:
                    # Get first line of description if multi-line
                    formatted_line['product_name'] = product_name.split('\n')[0].strip()
                else:
                    formatted_line['product_name'] = line.get('product_id', [None, 'Service'])[1] if line.get('product_id') else 'Service'
                
                # Keep product reference information
                if line.get('product_id'):
                    formatted_line['product_ref'] = line['product_id'][1]
                    formatted_line['product_id'] = line['product_id'][0]
                
                if line.get('product_uom'):
                    formatted_line['uom_name'] = line['product_uom'][1]
                
                if line.get('tax_id'):
                    tax_names = [tax[1] for tax in line['tax_id']]
                    formatted_line['tax_names'] = tax_names
                
                quotation_lines.append(formatted_line)
        
        # Format the complete quotation data with URLs
        result = {
            "quotation_header": {
                "id": quotation_id,
                "name": quote_data.get('name'),
                "odoo_url": quotation_url,
                "url_description": f"點擊直接開啟報價單 {quote_data.get('name', quotation_id)}",
                "customer": {
                    "id": quote_data.get('partner_id', [None])[0] if quote_data.get('partner_id') else None,
                    "name": quote_data.get('partner_id', [None, 'Unknown'])[1] if quote_data.get('partner_id') else 'Unknown',
                    "odoo_url": customer_url,
                    "url_description": f"點擊直接開啟客戶 {quote_data.get('partner_id', [None, 'Unknown'])[1] if quote_data.get('partner_id') else 'Unknown'}",
                    "language": customer_details.get('lang', 'zh_TW'),
                    "country": customer_details.get('country', 'Not Set'),
                    "timezone": customer_details.get('timezone', 'Not Set'),
                    "vat": customer_details.get('vat', ''),
                    "pricelist": customer_details.get('pricelist', 'Default')
                },
                "dates": {
                    "order_date": _format_datetime(quote_data.get('date_order', '')),
                    "validity_date": _format_datetime(quote_data.get('validity_date', ''))
                },
                "amounts": {
                    "untaxed": f"{quote_data.get('amount_untaxed', 0)} {currency_code}",
                    "tax": f"{quote_data.get('amount_tax', 0)} {currency_code}",
                    "total": f"{quote_data.get('amount_total', 0)} {currency_code}",
                    "currency": quote_data.get('currency_id', [None, 'Unknown'])[1] if quote_data.get('currency_id') else 'Unknown',
                    "currency_code": currency_code
                },
                "status": {
                    "state": quote_data.get('state')
                },
                "references": {
                    "client_order_ref": quote_data.get('client_order_ref'),
                    "origin": quote_data.get('origin'),
                    "note": quote_data.get('note')
                },
                "sales_info": {
                    "salesperson": quote_data.get('user_id', [None, 'Unknown'])[1] if quote_data.get('user_id') else 'Unknown',
                    "sales_team": quote_data.get('team_id', [None, 'Unknown'])[1] if quote_data.get('team_id') else 'Unknown',
                    "pricelist": quote_data.get('pricelist_id', [None, 'Default'])[1] if quote_data.get('pricelist_id') else 'Default',
                    "payment_terms": quote_data.get('payment_term_id', [None, 'None'])[1] if quote_data.get('payment_term_id') else 'None'
                }
            },
            "quotation_lines": quotation_lines,
            "line_count": len(quotation_lines),
            "display_settings": {
                "language": "english" if is_english else "chinese",
                "is_english_customer": is_english,
                "currency_code": currency_code
            },
            "url_info": {
                "quotation_url": quotation_url,
                "customer_url": customer_url,
                "base_odoo_url": config.ODOO_URL
            },
            "query_info": {
                "quotation_id": quotation_id,
                "include_lines": include_lines,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Error getting quotation details: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# ───────────────────────── NEW: Purchase Orders Management ─────────────────────────

@mcp.tool()
def search_purchase_orders(partner_name: Optional[str] = None, po_number: Optional[str] = None,
                          state: Optional[str] = None, date_from: Optional[str] = None,
                          date_to: Optional[str] = None, product_name: Optional[str] = None,
                          product_keywords: Optional[List[str]] = None,
                          min_amount: Optional[float] = None, max_amount: Optional[float] = None,
                          notes_contains: Optional[str] = None, global_search: Optional[str] = None,
                          limit: int = 10, offset: int = 0,
                          compact: bool = False, include_lines: bool = True, count_only: bool = False) -> str:
    """Search Odoo purchase orders with flexible filters.

    IMPORTANT: Use the EXACT keywords from user input. DO NOT translate.

    OUTPUT CONTROL (use these to reduce response size):
    - count_only=True: Only return count, no data
    - compact=True: Return minimal fields only
    - include_lines=False: Skip line items detail

    Args:
        partner_name: Supplier/vendor name (partial match supported)
        po_number: Purchase order number (e.g., 'P00123')
        state: Filter by state - draft/sent/to approve/purchase/done/cancel
        date_from: Start date filter (YYYY-MM-DD)
        date_to: End date filter (YYYY-MM-DD)
        product_name: Filter by single product name in lines
        product_keywords: Find products whose name contains ALL these keywords
        min_amount: Minimum total amount filter
        max_amount: Maximum total amount filter
        notes_contains: Search in PO notes
        global_search: Search across all fields
        limit: Max results (default: 10)
        offset: Skip first N results for pagination (default: 0)
        compact: Return minimal fields only (default: False)
        include_lines: Include line items detail (default: True)
        count_only: Only return count (default: False)

    Returns:
        JSON with purchase orders list (or count if count_only=True)
    """
    logger.info(f"Searching purchase orders: partner={partner_name}, product={product_name}, global={global_search}")
    
    try:
        # Build domain filters
        domain = []
        
        if partner_name:
            # Use OR to search in both name and display_name for better matching
            domain.extend(['|', ['partner_id.name', 'ilike', partner_name], ['partner_id.display_name', 'ilike', partner_name]])
        if po_number:
            domain.append(['name', 'ilike', po_number])
        if state:
            domain.append(['state', '=', state])
        if date_from:
            domain.append(['date_order', '>=', date_from])
        if date_to:
            domain.append(['date_order', '<=', date_to])
        if notes_contains:
            domain.append(['notes', 'ilike', notes_contains])

        # Amount filtering
        if min_amount is not None:
            domain.append(['amount_total', '>=', min_amount])
        if max_amount is not None:
            domain.append(['amount_total', '<=', max_amount])

        # Global search across multiple fields
        po_ids_from_global = []
        if global_search:
            try:
                search_domains = [
                    [['name', 'ilike', global_search]],
                    [['notes', 'ilike', global_search]],
                    [['partner_ref', 'ilike', global_search]],
                    [['origin', 'ilike', global_search]],
                    ['|', ['partner_id.name', 'ilike', global_search], ['partner_id.display_name', 'ilike', global_search]]
                ]
                
                # Try to search user_id.name if field exists
                try:
                    user_search = [['user_id.name', 'ilike', global_search]]
                    search_domains.append(user_search)
                except:
                    pass
                
                for search_domain in search_domains:
                    try:
                        results = _cached_odoo_call(
                            'purchase.order', 'search', search_domain,
                            {'limit': 1000}
                        )
                        if results:
                            po_ids_from_global.extend(results)
                    except Exception as e:
                        logger.debug(f"Search domain {search_domain} failed: {e}")
                        continue
                
                # Remove duplicates
                po_ids_from_global = list(set(po_ids_from_global))
                logger.info(f"Global search found {len(po_ids_from_global)} purchase orders")
                
            except Exception as e:
                logger.warning(f"Global search failed: {e}")
        
        # Search by product_keywords (single product with multiple keywords)
        po_ids_from_keywords = None
        if product_keywords and len(product_keywords) > 0:
            try:
                first_keyword = product_keywords[0]
                line_domain = [
                    '|',
                    ['product_id.name', 'ilike', first_keyword],
                    ['name', 'ilike', first_keyword]
                ]
                matching_lines = _cached_odoo_call(
                    'purchase.order.line', 'search_read', [line_domain],
                    {'fields': ['order_id', 'name', 'product_id'], 'limit': 5000}
                )
                po_ids_from_keywords = set()
                for line in matching_lines:
                    line_name = (line.get('name') or '').lower()
                    product_name_str = (line['product_id'][1] if line.get('product_id') and isinstance(line['product_id'], list) else '').lower()
                    combined_text = f"{line_name} {product_name_str}"
                    if all(kw.lower() in combined_text for kw in product_keywords):
                        if line.get('order_id'):
                            po_ids_from_keywords.add(line['order_id'][0])
                po_ids_from_keywords = list(po_ids_from_keywords)
                logger.info(f"Found {len(po_ids_from_keywords)} POs with products matching keywords: {product_keywords}")
            except Exception as e:
                logger.warning(f"Error searching product keywords: {e}")
                po_ids_from_keywords = []

        # Search by product name in purchase order lines
        po_ids_from_lines = []
        if product_name or global_search:
            try:
                line_domain = []
                if product_name:
                    line_domain = [
                        '|',
                        ['product_id.name', 'ilike', product_name],
                        ['name', 'ilike', product_name]
                    ]
                elif global_search:
                    line_domain = [
                        '|',
                        ['product_id.name', 'ilike', global_search],
                        ['name', 'ilike', global_search]
                    ]

                if line_domain:
                    line_fields = ['order_id', 'product_id', 'name']
                    matching_lines = _cached_odoo_call(
                        'purchase.order.line', 'search_read', [line_domain],
                        {'fields': line_fields, 'limit': 1000}
                    )
                    po_ids_from_lines = list(set([line['order_id'][0] for line in matching_lines if line.get('order_id')]))
                    search_term = product_name or global_search
                    logger.info(f"Found {len(po_ids_from_lines)} purchase orders with product: {search_term}")

            except Exception as e:
                logger.warning(f"Error searching purchase order lines: {e}")

        # Combine all found PO IDs
        all_found_ids = []
        if po_ids_from_keywords is not None:
            all_found_ids = po_ids_from_keywords
        elif global_search:
            all_found_ids.extend(po_ids_from_global)
            all_found_ids.extend(po_ids_from_lines)
            all_found_ids = list(set(all_found_ids))
        elif product_name:
            all_found_ids = po_ids_from_lines
        
        # Add ID filter to domain if we found specific purchase orders
        if all_found_ids:
            domain.append(['id', 'in', all_found_ids])
        elif product_name and not global_search:
            logger.info(f"No purchase orders found containing product: {product_name}")
            return json.dumps({
                "purchase_orders": [],
                "summary": {
                    "total_found": 0,
                    "message": f"No purchase orders found containing '{product_name}'"
                },
                "query_info": {
                    "product_name_filter": product_name,
                    "search_method": "product_line_search",
                    "timestamp": datetime.now().isoformat()
                }
            }, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
        
        # Get purchase orders using version-compatible fields
        available_fields = odoo.get_version_compatible_fields('purchase.order', 'standard')
        
        # Increase limit if we're doing a product/global search
        search_limit = min(limit * 10, 1000) if (product_name or global_search) else limit
        
        purchase_orders = _cached_odoo_call(
            'purchase.order', 'search_read', [domain],
            {
                'fields': available_fields,
                'limit': search_limit,
                'order': 'date_order desc'
            }
        )
        
        # Apply offset and limit for pagination
        purchase_orders = purchase_orders[offset:offset + limit]

        # Handle count_only mode
        if count_only:
            return json.dumps({
                "count": len(purchase_orders),
                "query_info": {"mode": "count_only", "timestamp": datetime.now().isoformat()}
            }, indent=2, ensure_ascii=False, cls=DateTimeEncoder)

        # Enrich each purchase order
        enriched_pos = []

        for po in purchase_orders:
            if compact:
                enriched_po = {
                    'id': po.get('id'),
                    'name': po.get('name'),
                    'supplier': po.get('partner_id', [None, ''])[1] if po.get('partner_id') else '',
                    'amount_total': po.get('amount_total', 0),
                    'state': po.get('state'),
                    'date': po.get('date_order', '')[:10] if po.get('date_order') else '',
                    'odoo_url': _generate_purchase_order_url(po['id'])
                }
            else:
                enriched_po = po.copy()
                enriched_po['odoo_url'] = _generate_purchase_order_url(po['id'])

                if po.get('partner_id'):
                    partner_details = _get_partner_details(po['partner_id'][0])
                    enriched_po['supplier_details'] = partner_details
                    currency_code = _get_currency_code(po.get('currency_id', []))
                    enriched_po['currency_code'] = currency_code

            # Get purchase order lines (skip if include_lines=False or compact)
            if include_lines and not compact:
                try:
                    line_fields = odoo.get_version_compatible_fields('purchase.order.line', 'standard')
                    po_lines = _cached_odoo_call(
                        'purchase.order.line', 'search_read',
                        [[['order_id', '=', po['id']]]],
                        {'fields': line_fields, 'order': 'sequence'}
                    )

                    products = []
                    for line in po_lines:
                        line_product_name = line.get('name', '')
                        if line_product_name:
                            line_product_name = line_product_name.split('\n')[0].strip()

                        line_info = {
                            'product_name': line_product_name,
                            'quantity': line.get('product_qty', 1),
                            'unit_price': line.get('price_unit', 0),
                            'subtotal': line.get('price_subtotal', 0)
                        }
                        products.append(line_info)

                    enriched_po['products'] = products
                    enriched_po['line_count'] = len(products)

                except Exception as e:
                    logger.warning(f"Failed to get lines for purchase order {po['id']}: {e}")
                    enriched_po['products'] = []
                    enriched_po['line_count'] = 0
            
            # Format dates
            date_fields = ['date_order', 'date_planned', 'create_date', 'write_date']
            for field in date_fields:
                if po.get(field):
                    enriched_po[f'{field}_formatted'] = _format_datetime(po[field])
            
            enriched_pos.append(enriched_po)
        
        # Calculate summary statistics
        total_found = len(enriched_pos)
        currency_breakdown = {}
        state_breakdown = {}
        supplier_breakdown = {}
        
        for po in enriched_pos:
            # Currency statistics
            currency = po.get('currency_code', 'Unknown')
            currency_breakdown[currency] = currency_breakdown.get(currency, 0) + 1
            
            # State statistics
            state = po.get('state', 'unknown')
            state_breakdown[state] = state_breakdown.get(state, 0) + 1
            
            # Supplier statistics
            supplier = po.get('partner_id', [None, 'Unknown'])[1] if po.get('partner_id') else 'Unknown'
            supplier_breakdown[supplier] = supplier_breakdown.get(supplier, 0) + 1
        
        # Search scope message
        search_scope_parts = []
        if global_search:
            search_scope_parts.append(f"Global search for '{global_search}' across all purchase order fields and line items")
        if product_name:
            search_scope_parts.append(f"Product search for '{product_name}'")
        if notes_contains:
            search_scope_parts.append(f"Notes search for '{notes_contains}'")
        if not any([global_search, product_name, notes_contains]):
            search_scope_parts.append("Standard purchase order search")
        
        result = {
            "purchase_orders": enriched_pos,
            "summary": {
                "total_found": total_found,
                "currency_breakdown": currency_breakdown,
                "state_breakdown": state_breakdown,
                "top_suppliers": dict(list(supplier_breakdown.items())[:5]),
                "search_scope": " + ".join(search_scope_parts),
                "urls_included": True,
                "url_base": config.ODOO_URL
            },
            "search_fields_covered": {
                "purchase_order_header": [
                    "name (PO number)",
                    "notes (description)", 
                    "partner_ref (supplier reference)",
                    "origin (source document)",
                    "partner_id.name (supplier name)",
                    "user_id.name (buyer)"
                ] if global_search else ["Limited to specific filters"],
                "purchase_order_lines": [
                    "product_id.name (product name)",
                    "name (line description)"
                ] if (product_name or global_search) else ["Not searched"]
            },
            "query_info": {
                "partner_name_filter": partner_name,
                "po_number_filter": po_number,
                "state_filter": state,
                "date_from": date_from,
                "date_to": date_to,
                "product_name_filter": product_name,
                "notes_filter": notes_contains,
                "global_search_filter": global_search,
                "limit": limit,
                "actual_search_limit": search_limit if (product_name or global_search) else limit,
                "odoo_version": odoo.version_info.get('major_version', 'Unknown'),
                "fields_used": len(available_fields),
                "search_method": "global_search" if global_search else ("product_line_search" if product_name else "standard_search"),
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Error searching purchase orders: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def get_purchase_order_details(po_id: int, include_lines: bool = True) -> str:
    """Get detailed purchase order information by ID.

    Args:
        po_id: The purchase order ID (integer)
        include_lines: Include line items with product details (default: True)

    Returns:
        JSON with: header info, supplier details, line items (product, qty, price, subtotal),
        totals, currency, expected delivery date, and direct Odoo URL
    """
    logger.info(f"Getting purchase order details for ID: {po_id}")
    
    try:
        # Get purchase order header using compatible fields
        available_fields = odoo.get_version_compatible_fields('purchase.order', 'standard')
        
        purchase_order = _cached_odoo_call(
            'purchase.order', 'read', [po_id],
            {'fields': available_fields}
        )
        
        if not purchase_order:
            return json.dumps({"error": "Purchase order not found"}, indent=2, ensure_ascii=False)
        
        po_data = purchase_order[0]
        
        # Get supplier details
        supplier_details = {}
        is_english = False
        supplier_url = None
        if po_data.get('partner_id'):
            supplier_details = _get_partner_details(po_data['partner_id'][0])
            is_english = _is_english_customer(supplier_details.get('lang', ''))
            supplier_url = _generate_partner_url(po_data['partner_id'][0])
        
        # Get currency code
        currency_code = _get_currency_code(po_data.get('currency_id', []))
        
        # Generate purchase order URL
        po_url = _generate_purchase_order_url(po_id)
        
        # Get purchase order lines if requested
        po_lines = []
        if include_lines:
            line_fields = odoo.get_version_compatible_fields('purchase.order.line', 'standard')
            
            lines = _cached_odoo_call(
                'purchase.order.line', 'search_read',
                [[['order_id', '=', po_id]]],
                {
                    'fields': line_fields,
                    'order': 'sequence'
                }
            )
            
            # Format line items with currency
            for line in lines:
                formatted_line = line.copy()
                
                # Format prices with currency
                price_fields = ['price_unit', 'price_subtotal', 'price_total']
                for field in price_fields:
                    if line.get(field) is not None:
                        formatted_line[f'{field}_formatted'] = f"{line[field]} {currency_code}"
                
                # Format product information using the line description
                # Use the 'name' field which contains the actual line description
                product_name = line.get('name', '')
                if product_name:
                    # Get first line of description if multi-line
                    formatted_line['product_name'] = product_name.split('\n')[0].strip()
                else:
                    formatted_line['product_name'] = line.get('product_id', [None, 'Product'])[1] if line.get('product_id') else 'Product'
                
                # Keep product reference information
                if line.get('product_id'):
                    formatted_line['product_ref'] = line['product_id'][1]
                    formatted_line['product_id'] = line['product_id'][0]
                
                if line.get('product_uom'):
                    formatted_line['uom_name'] = line['product_uom'][1]
                
                if line.get('taxes_id'):
                    tax_names = [tax[1] for tax in line['taxes_id']]
                    formatted_line['tax_names'] = tax_names
                
                # Format dates
                if line.get('date_planned'):
                    formatted_line['date_planned_formatted'] = _format_datetime(line['date_planned'])
                
                po_lines.append(formatted_line)
        
        # Format the complete purchase order data with URLs
        result = {
            "purchase_order_header": {
                "id": po_id,
                "name": po_data.get('name'),
                "odoo_url": po_url,
                "url_description": f"點擊直接開啟採購單 {po_data.get('name', po_id)}",
                "supplier": {
                    "id": po_data.get('partner_id', [None])[0] if po_data.get('partner_id') else None,
                    "name": po_data.get('partner_id', [None, 'Unknown'])[1] if po_data.get('partner_id') else 'Unknown',
                    "odoo_url": supplier_url,
                    "url_description": f"點擊直接開啟供應商 {po_data.get('partner_id', [None, 'Unknown'])[1] if po_data.get('partner_id') else 'Unknown'}",
                    "language": supplier_details.get('lang', 'zh_TW'),
                    "country": supplier_details.get('country', 'Not Set'),
                    "vat": supplier_details.get('vat', ''),
                    "pricelist": supplier_details.get('pricelist', 'Default')
                },
                "dates": {
                    "order_date": _format_datetime(po_data.get('date_order', '')),
                    "planned_date": _format_datetime(po_data.get('date_planned', ''))
                },
                "amounts": {
                    "untaxed": f"{po_data.get('amount_untaxed', 0)} {currency_code}",
                    "tax": f"{po_data.get('amount_tax', 0)} {currency_code}",
                    "total": f"{po_data.get('amount_total', 0)} {currency_code}",
                    "currency": po_data.get('currency_id', [None, 'Unknown'])[1] if po_data.get('currency_id') else 'Unknown',
                    "currency_code": currency_code
                },
                "status": {
                    "state": po_data.get('state'),
                    "state_translated": _translate_purchase_state(po_data.get('state', ''), is_english),
                    "invoice_status": po_data.get('invoice_status')
                },
                "references": {
                    "partner_ref": po_data.get('partner_ref'),
                    "origin": po_data.get('origin'),
                    "notes": po_data.get('notes')
                },
                "purchase_info": {
                    "buyer": po_data.get('user_id', [None, 'Unknown'])[1] if po_data.get('user_id') else 'Unknown',
                    "company": po_data.get('company_id', [None, 'Unknown'])[1] if po_data.get('company_id') else 'Unknown',
                    "payment_terms": po_data.get('payment_term_id', [None, 'None'])[1] if po_data.get('payment_term_id') else 'None'
                }
            },
            "purchase_order_lines": po_lines,
            "line_count": len(po_lines),
            "display_settings": {
                "language": "english" if is_english else "chinese",
                "is_english_supplier": is_english,
                "currency_code": currency_code
            },
            "url_info": {
                "purchase_order_url": po_url,
                "supplier_url": supplier_url,
                "base_odoo_url": config.ODOO_URL
            },
            "query_info": {
                "purchase_order_id": po_id,
                "include_lines": include_lines,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Error getting purchase order details: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# ───────────────────────── NEW: Delivery Orders Management ─────────────────────────

@mcp.tool()
def search_delivery_orders(partner_name: Optional[str] = None, delivery_number: Optional[str] = None,
                          state: Optional[str] = None, picking_type: Optional[str] = None,
                          date_from: Optional[str] = None, date_to: Optional[str] = None,
                          product_name: Optional[str] = None,
                          product_keywords: Optional[List[str]] = None,
                          origin_filter: Optional[str] = None,
                          global_search: Optional[str] = None, limit: int = 10, offset: int = 0,
                          compact: bool = False, include_moves: bool = True, count_only: bool = False) -> str:
    """Search Odoo delivery orders (stock pickings) with flexible filters.

    IMPORTANT: Use the EXACT keywords from user input. DO NOT translate.

    OUTPUT CONTROL (use these to reduce response size):
    - count_only=True: Only return count, no data
    - compact=True: Return minimal fields only
    - include_moves=False: Skip stock moves detail

    Args:
        partner_name: Customer/partner name (partial match supported)
        delivery_number: Delivery order number (e.g., 'WH/OUT/00123')
        state: Filter by state - draft/waiting/confirmed/assigned/done/cancel
        picking_type: Filter by type - 'Delivery Orders', 'Receipts', etc.
        date_from: Start date filter (YYYY-MM-DD)
        date_to: End date filter (YYYY-MM-DD)
        product_name: Filter by single product name in moves
        product_keywords: Find products whose name contains ALL these keywords
        origin_filter: Filter by source document (e.g., 'S00123', 'P00456')
        global_search: Search across all fields
        limit: Max results (default: 10)
        offset: Skip first N results for pagination (default: 0)
        compact: Return minimal fields only (default: False)
        include_moves: Include stock moves detail (default: True)
        count_only: Only return count (default: False)

    Returns:
        JSON with delivery orders list (or count if count_only=True)
    """
    logger.info(f"Searching delivery orders: partner={partner_name}, product={product_name}, global={global_search}")
    
    try:
        # Build domain filters
        domain = []
        
        if partner_name:
            # Use OR to search in both name and display_name for better matching
            domain.extend(['|', ['partner_id.name', 'ilike', partner_name], ['partner_id.display_name', 'ilike', partner_name]])
        if delivery_number:
            domain.append(['name', 'ilike', delivery_number])
        if state:
            domain.append(['state', '=', state])
        if picking_type:
            domain.append(['picking_type_id.name', 'ilike', picking_type])
        if date_from:
            domain.append(['scheduled_date', '>=', date_from])
        if date_to:
            domain.append(['scheduled_date', '<=', date_to])
        if origin_filter:
            domain.append(['origin', 'ilike', origin_filter])
        
        # Global search across multiple fields
        delivery_ids_from_global = []
        if global_search:
            try:
                search_domains = [
                    [['name', 'ilike', global_search]],
                    [['note', 'ilike', global_search]],
                    [['origin', 'ilike', global_search]],
                    [['carrier_tracking_ref', 'ilike', global_search]],
                    ['|', ['partner_id.name', 'ilike', global_search], ['partner_id.display_name', 'ilike', global_search]]
                ]
                
                for search_domain in search_domains:
                    try:
                        results = _cached_odoo_call(
                            'stock.picking', 'search', search_domain,
                            {'limit': 1000}
                        )
                        if results:
                            delivery_ids_from_global.extend(results)
                    except Exception as e:
                        logger.debug(f"Search domain {search_domain} failed: {e}")
                        continue
                
                # Remove duplicates
                delivery_ids_from_global = list(set(delivery_ids_from_global))
                logger.info(f"Global search found {len(delivery_ids_from_global)} delivery orders")
                
            except Exception as e:
                logger.warning(f"Global search failed: {e}")
        
        # Search by product_keywords (single product with multiple keywords)
        delivery_ids_from_keywords = None
        if product_keywords and len(product_keywords) > 0:
            try:
                first_keyword = product_keywords[0]
                move_domain = [
                    '|',
                    ['product_id.name', 'ilike', first_keyword],
                    ['name', 'ilike', first_keyword]
                ]
                matching_moves = _cached_odoo_call(
                    'stock.move', 'search_read', [move_domain],
                    {'fields': ['picking_id', 'name', 'product_id'], 'limit': 5000}
                )
                delivery_ids_from_keywords = set()
                for move in matching_moves:
                    move_name = (move.get('name') or '').lower()
                    product_name_str = (move['product_id'][1] if move.get('product_id') and isinstance(move['product_id'], list) else '').lower()
                    combined_text = f"{move_name} {product_name_str}"
                    if all(kw.lower() in combined_text for kw in product_keywords):
                        if move.get('picking_id'):
                            delivery_ids_from_keywords.add(move['picking_id'][0])
                delivery_ids_from_keywords = list(delivery_ids_from_keywords)
                logger.info(f"Found {len(delivery_ids_from_keywords)} deliveries with products matching keywords: {product_keywords}")
            except Exception as e:
                logger.warning(f"Error searching product keywords: {e}")
                delivery_ids_from_keywords = []

        # Search by product name in stock moves
        delivery_ids_from_moves = []
        if product_name or global_search:
            try:
                move_domain = []
                if product_name:
                    move_domain = [
                        '|', 
                        ['product_id.name', 'ilike', product_name],
                        ['name', 'ilike', product_name]
                    ]
                elif global_search:
                    move_domain = [
                        '|', 
                        ['product_id.name', 'ilike', global_search],
                        ['name', 'ilike', global_search]
                    ]
                
                if move_domain:
                    move_fields = ['picking_id', 'product_id', 'name']
                    matching_moves = _cached_odoo_call(
                        'stock.move', 'search_read', [move_domain],
                        {'fields': move_fields, 'limit': 1000}
                    )
                    
                    # Extract unique picking IDs
                    delivery_ids_from_moves = list(set([move['picking_id'][0] for move in matching_moves if move.get('picking_id')]))
                    search_term = product_name or global_search
                    logger.info(f"Found {len(delivery_ids_from_moves)} delivery orders with product: {search_term}")
                        
            except Exception as e:
                logger.warning(f"Error searching stock moves: {e}")
        
        # Combine all found delivery IDs
        all_found_ids = []
        if delivery_ids_from_keywords is not None:
            all_found_ids = delivery_ids_from_keywords
        elif global_search:
            all_found_ids.extend(delivery_ids_from_global)
            all_found_ids.extend(delivery_ids_from_moves)
            all_found_ids = list(set(all_found_ids))
        elif product_name:
            all_found_ids = delivery_ids_from_moves
        
        # Add ID filter to domain if we found specific deliveries
        if all_found_ids:
            domain.append(['id', 'in', all_found_ids])
        elif product_name and not global_search:
            logger.info(f"No delivery orders found containing product: {product_name}")
            return json.dumps({
                "delivery_orders": [],
                "summary": {
                    "total_found": 0,
                    "message": f"No delivery orders found containing '{product_name}'"
                },
                "query_info": {
                    "product_name_filter": product_name,
                    "search_method": "product_move_search",
                    "timestamp": datetime.now().isoformat()
                }
            }, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
        
        # Get delivery orders using version-compatible fields
        available_fields = odoo.get_version_compatible_fields('stock.picking', 'standard')
        
        # Increase limit if we're doing a product/global search
        search_limit = min(limit * 10, 1000) if (product_name or global_search) else limit
        
        delivery_orders = _cached_odoo_call(
            'stock.picking', 'search_read', [domain],
            {
                'fields': available_fields,
                'limit': search_limit,
                'order': 'scheduled_date desc'
            }
        )
        
        # Apply offset and limit for pagination
        delivery_orders = delivery_orders[offset:offset + limit]

        # Handle count_only mode
        if count_only:
            return json.dumps({
                "count": len(delivery_orders),
                "query_info": {"mode": "count_only", "timestamp": datetime.now().isoformat()}
            }, indent=2, ensure_ascii=False, cls=DateTimeEncoder)

        # Enrich each delivery order with partner details and URLs
        enriched_deliveries = []

        for delivery in delivery_orders:
            if compact:
                enriched_delivery = {
                    'id': delivery.get('id'),
                    'name': delivery.get('name'),
                    'partner': delivery.get('partner_id', [None, ''])[1] if delivery.get('partner_id') else '',
                    'state': delivery.get('state'),
                    'picking_type': delivery.get('picking_type_id', [None, ''])[1] if delivery.get('picking_type_id') else '',
                    'scheduled_date': delivery.get('scheduled_date', '')[:10] if delivery.get('scheduled_date') else '',
                    'origin': delivery.get('origin', ''),
                    'odoo_url': _generate_delivery_order_url(delivery['id'])
                }
            else:
                enriched_delivery = delivery.copy()
            
            # Skip detailed enrichment for compact mode
            if not compact:
                # Generate direct URL to delivery order
                enriched_delivery['odoo_url'] = _generate_delivery_order_url(delivery['id'])
                enriched_delivery['url_description'] = f"點擊直接開啟出貨單 {delivery.get('name', delivery['id'])}"

                # Get partner details
                if delivery.get('partner_id'):
                    partner_details = _get_partner_details(delivery['partner_id'][0])
                    enriched_delivery['partner_details'] = partner_details

                    # Add partner URL
                    enriched_delivery['partner_url'] = _generate_partner_url(delivery['partner_id'][0])
                    enriched_delivery['partner_url_description'] = f"點擊直接開啟客戶 {delivery['partner_id'][1]}"

                    # Determine display language
                    is_english = _is_english_customer(partner_details.get('lang', ''))
                    enriched_delivery['display_language'] = 'en' if is_english else 'zh'

                    # Translate state
                    enriched_delivery['state_translated'] = _translate_delivery_state(delivery.get('state', ''), is_english)

                # Get picking type details
                if delivery.get('picking_type_id'):
                    enriched_delivery['picking_type_name'] = delivery['picking_type_id'][1]

                # Get location details
                if delivery.get('location_id'):
                    enriched_delivery['source_location'] = delivery['location_id'][1]
                if delivery.get('location_dest_id'):
                    enriched_delivery['destination_location'] = delivery['location_dest_id'][1]

                # Get related sale order or purchase order URLs
                if delivery.get('origin'):
                    origin = delivery['origin']
                    # Try to detect if it's a sale order or purchase order
                    if origin.startswith('SO') or 'sale' in origin.lower():
                        try:
                            # Search for related sale order
                            so_search = _cached_odoo_call(
                                'sale.order', 'search', [['name', '=', origin]], {'limit': 1}
                            )
                            if so_search:
                                enriched_delivery['related_sale_order_url'] = _generate_quotation_url(so_search[0])
                        except:
                            pass
                    elif origin.startswith('PO') or 'purchase' in origin.lower():
                        try:
                            # Search for related purchase order
                            po_search = _cached_odoo_call(
                                'purchase.order', 'search', [['name', '=', origin]], {'limit': 1}
                            )
                            if po_search:
                                enriched_delivery['related_purchase_order_url'] = _generate_purchase_order_url(po_search[0])
                        except:
                            pass

            # Get stock moves for product details (skip if include_moves=False or compact)
            if include_moves and not compact:
                try:
                    move_fields = odoo.get_version_compatible_fields('stock.move', 'standard')
                    stock_moves = _cached_odoo_call(
                        'stock.move', 'search_read',
                        [[['picking_id', '=', delivery['id']]]],
                        {'fields': move_fields, 'order': 'name'}
                    )

                    # Format move information
                    products_moved = []
                    for move in stock_moves:
                        # Use the 'name' field which contains the product description/move name
                        move_product_name = move.get('name', '')
                        if move_product_name:
                            # Get first line of description if multi-line
                            move_product_name = move_product_name.split('\n')[0].strip()

                        move_info = {
                            'product_name': move_product_name,
                            'description': move.get('name', ''),
                            'product_id': move.get('product_id', [None, ''])[0] if move.get('product_id') else None,
                            'product_ref': move.get('product_id', [None, ''])[1] if move.get('product_id') else '',
                            'quantity_expected': move.get('product_uom_qty', 0),
                            'quantity_done': move.get('quantity_done', 0),
                            'unit_of_measure': move.get('product_uom', [None, 'Unit'])[1] if move.get('product_uom') else 'Unit',
                            'state': move.get('state', ''),
                            'date_expected': _format_datetime(move.get('date', '')),
                            'date_deadline': _format_datetime(move.get('date_deadline', ''))
                        }
                        products_moved.append(move_info)

                    enriched_delivery['products_moved'] = products_moved
                    enriched_delivery['move_count'] = len(products_moved)

                except Exception as e:
                    logger.warning(f"Failed to get moves for delivery {delivery['id']}: {e}")
                    enriched_delivery['products_moved'] = []
                    enriched_delivery['move_count'] = 0

            # Format dates (skip for compact mode)
            if not compact:
                date_fields = ['scheduled_date', 'date_done', 'create_date', 'write_date']
                for field in date_fields:
                    if delivery.get(field):
                        enriched_delivery[f'{field}_formatted'] = _format_datetime(delivery[field])
            
            enriched_deliveries.append(enriched_delivery)
        
        # Calculate summary statistics
        total_found = len(enriched_deliveries)
        state_breakdown = {}
        picking_type_breakdown = {}
        partner_breakdown = {}
        
        for delivery in enriched_deliveries:
            # State statistics
            state = delivery.get('state', 'unknown')
            state_breakdown[state] = state_breakdown.get(state, 0) + 1
            
            # Picking type statistics
            picking_type = delivery.get('picking_type_name', 'Unknown')
            picking_type_breakdown[picking_type] = picking_type_breakdown.get(picking_type, 0) + 1
            
            # Partner statistics
            partner = delivery.get('partner_id', [None, 'Unknown'])[1] if delivery.get('partner_id') else 'Unknown'
            partner_breakdown[partner] = partner_breakdown.get(partner, 0) + 1
        
        # Search scope message
        search_scope_parts = []
        if global_search:
            search_scope_parts.append(f"Global search for '{global_search}' across all delivery order fields and stock moves")
        if product_name:
            search_scope_parts.append(f"Product search for '{product_name}'")
        if origin_filter:
            search_scope_parts.append(f"Origin document search for '{origin_filter}'")
        if not any([global_search, product_name, origin_filter]):
            search_scope_parts.append("Standard delivery order search")
        
        result = {
            "delivery_orders": enriched_deliveries,
            "summary": {
                "total_found": total_found,
                "state_breakdown": state_breakdown,
                "picking_type_breakdown": picking_type_breakdown,
                "top_partners": dict(list(partner_breakdown.items())[:5]),
                "search_scope": " + ".join(search_scope_parts),
                "urls_included": True,
                "url_base": config.ODOO_URL
            },
            "search_fields_covered": {
                "delivery_order_header": [
                    "name (delivery number)",
                    "note (description)", 
                    "origin (source document)",
                    "carrier_tracking_ref (tracking reference)",
                    "partner_id.name (partner name)"
                ] if global_search else ["Limited to specific filters"],
                "stock_moves": [
                    "product_id.name (product name)",
                    "name (move description)"
                ] if (product_name or global_search) else ["Not searched"]
            },
            "query_info": {
                "partner_name_filter": partner_name,
                "delivery_number_filter": delivery_number,
                "state_filter": state,
                "picking_type_filter": picking_type,
                "date_from": date_from,
                "date_to": date_to,
                "product_name_filter": product_name,
                "origin_filter": origin_filter,
                "global_search_filter": global_search,
                "limit": limit,
                "actual_search_limit": search_limit if (product_name or global_search) else limit,
                "odoo_version": odoo.version_info.get('major_version', 'Unknown'),
                "fields_used": len(available_fields),
                "search_method": "global_search" if global_search else ("product_move_search" if product_name else "standard_search"),
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Error searching delivery orders: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def get_delivery_order_details(delivery_id: int, include_moves: bool = True) -> str:
    """Get detailed delivery order (stock picking) information by ID.

    Args:
        delivery_id: The delivery order ID (integer)
        include_moves: Include stock move details (default: True)

    Returns:
        JSON with: header info, partner details, stock moves (product, qty demanded/done),
        tracking info, scheduled date, and direct Odoo URL
    """
    logger.info(f"Getting delivery order details for ID: {delivery_id}")
    
    try:
        # Get delivery order header using compatible fields
        available_fields = odoo.get_version_compatible_fields('stock.picking', 'extended')
        
        delivery_order = _cached_odoo_call(
            'stock.picking', 'read', [delivery_id],
            {'fields': available_fields}
        )
        
        if not delivery_order:
            return json.dumps({"error": "Delivery order not found"}, indent=2, ensure_ascii=False)
        
        delivery_data = delivery_order[0]
        
        # Get partner details
        partner_details = {}
        is_english = False
        partner_url = None
        if delivery_data.get('partner_id'):
            partner_details = _get_partner_details(delivery_data['partner_id'][0])
            is_english = _is_english_customer(partner_details.get('lang', ''))
            partner_url = _generate_partner_url(delivery_data['partner_id'][0])
        
        # Generate delivery order URL
        delivery_url = _generate_delivery_order_url(delivery_id)
        
        # Get related sale order or purchase order details
        related_order_info = {}
        if delivery_data.get('sale_id'):
            related_order_info['sale_order'] = {
                'id': delivery_data['sale_id'][0],
                'name': delivery_data['sale_id'][1],
                'url': _generate_quotation_url(delivery_data['sale_id'][0])
            }
        elif delivery_data.get('purchase_id'):
            related_order_info['purchase_order'] = {
                'id': delivery_data['purchase_id'][0],
                'name': delivery_data['purchase_id'][1],
                'url': _generate_purchase_order_url(delivery_data['purchase_id'][0])
            }
        
        # Get stock moves if requested
        stock_moves = []
        if include_moves:
            move_fields = odoo.get_version_compatible_fields('stock.move', 'standard')
            
            moves = _cached_odoo_call(
                'stock.move', 'search_read',
                [[['picking_id', '=', delivery_id]]],
                {
                    'fields': move_fields,
                    'order': 'name'
                }
            )
            
            # Format move items
            for move in moves:
                formatted_move = move.copy()
                
                # Format product information using the move name/description
                # Use the 'name' field which contains the actual move description
                product_name = move.get('name', '')
                if product_name:
                    # Get first line of description if multi-line
                    formatted_move['product_name'] = product_name.split('\n')[0].strip()
                else:
                    formatted_move['product_name'] = move.get('product_id', [None, 'Product'])[1] if move.get('product_id') else 'Product'
                
                # Keep product reference information
                if move.get('product_id'):
                    formatted_move['product_ref'] = move['product_id'][1]
                    formatted_move['product_id'] = move['product_id'][0]
                
                if move.get('product_uom'):
                    formatted_move['uom_name'] = move['product_uom'][1]
                
                # Format locations
                if move.get('location_id'):
                    formatted_move['source_location_name'] = move['location_id'][1]
                
                if move.get('location_dest_id'):
                    formatted_move['destination_location_name'] = move['location_dest_id'][1]
                
                # Format dates
                date_fields = ['date', 'date_deadline']
                for field in date_fields:
                    if move.get(field):
                        formatted_move[f'{field}_formatted'] = _format_datetime(move[field])
                
                # Calculate completion percentage
                expected_qty = move.get('product_uom_qty', 0)
                done_qty = move.get('quantity_done', 0)
                if expected_qty > 0:
                    formatted_move['completion_percentage'] = round((done_qty / expected_qty) * 100, 2)
                else:
                    formatted_move['completion_percentage'] = 0
                
                stock_moves.append(formatted_move)
        
        # Format the complete delivery order data with URLs
        result = {
            "delivery_order_header": {
                "id": delivery_id,
                "name": delivery_data.get('name'),
                "odoo_url": delivery_url,
                "url_description": f"點擊直接開啟出貨單 {delivery_data.get('name', delivery_id)}",
                "partner": {
                    "id": delivery_data.get('partner_id', [None])[0] if delivery_data.get('partner_id') else None,
                    "name": delivery_data.get('partner_id', [None, 'Unknown'])[1] if delivery_data.get('partner_id') else 'Unknown',
                    "odoo_url": partner_url,
                    "url_description": f"點擊直接開啟客戶 {delivery_data.get('partner_id', [None, 'Unknown'])[1] if delivery_data.get('partner_id') else 'Unknown'}",
                    "language": partner_details.get('lang', 'zh_TW'),
                    "country": partner_details.get('country', 'Not Set')
                },
                "dates": {
                    "scheduled_date": _format_datetime(delivery_data.get('scheduled_date', '')),
                    "date_done": _format_datetime(delivery_data.get('date_done', ''))
                },
                "status": {
                    "state": delivery_data.get('state'),
                    "state_translated": _translate_delivery_state(delivery_data.get('state', ''), is_english),
                    "priority": delivery_data.get('priority', 'Normal')
                },
                "logistics": {
                    "picking_type": delivery_data.get('picking_type_id', [None, 'Unknown'])[1] if delivery_data.get('picking_type_id') else 'Unknown',
                    "source_location": delivery_data.get('location_id', [None, 'Unknown'])[1] if delivery_data.get('location_id') else 'Unknown',
                    "destination_location": delivery_data.get('location_dest_id', [None, 'Unknown'])[1] if delivery_data.get('location_dest_id') else 'Unknown',
                    "carrier": delivery_data.get('carrier_id', [None, 'Not Set'])[1] if delivery_data.get('carrier_id') else 'Not Set',
                    "tracking_reference": delivery_data.get('carrier_tracking_ref', ''),
                    "tracking_url": delivery_data.get('carrier_tracking_url', ''),
                    "weight": delivery_data.get('weight', 0),
                    "shipping_weight": delivery_data.get('shipping_weight', 0)
                },
                "references": {
                    "origin": delivery_data.get('origin'),
                    "note": delivery_data.get('note'),
                    "backorder": delivery_data.get('backorder_id', [None, 'None'])[1] if delivery_data.get('backorder_id') else 'None'
                },
                "responsible": {
                    "user": delivery_data.get('user_id', [None, 'Unknown'])[1] if delivery_data.get('user_id') else 'Unknown',
                    "company": delivery_data.get('company_id', [None, 'Unknown'])[1] if delivery_data.get('company_id') else 'Unknown'
                }
            },
            "related_orders": related_order_info,
            "stock_moves": stock_moves,
            "move_count": len(stock_moves),
            "display_settings": {
                "language": "english" if is_english else "chinese",
                "is_english_partner": is_english
            },
            "url_info": {
                "delivery_order_url": delivery_url,
                "partner_url": partner_url,
                "base_odoo_url": config.ODOO_URL
            },
            "query_info": {
                "delivery_order_id": delivery_id,
                "include_moves": include_moves,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Error getting delivery order details: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)


# ───────────────────────── NEW: Product Management ─────────────────────────










# @mcp.tool()  # Disabled - duplicate of search_products
def search_products_v2(name: Optional[str] = None, category_name: Optional[str] = None,
                      product_type: Optional[str] = None, default_code: Optional[str] = None,
                      barcode: Optional[str] = None, active_only: bool = True,
                      sale_ok: Optional[bool] = None, purchase_ok: Optional[bool] = None,
                      min_price: Optional[float] = None, max_price: Optional[float] = None,
                      limit: int = 100, offset: int = 0) -> str:
    """Improved product search with better coverage and accuracy
    
    v1.4.5: Enhanced search function that finds all products correctly
    v1.4.7: Added multi-language search support
    
    Args:
        name: Product name filter (partial matching supported)
        category_name: Product category name filter
        product_type: Product type filter ('consu', 'service', 'product')
        default_code: Internal reference/SKU filter
        barcode: Barcode filter
        active_only: Only show active products (default: True)
        sale_ok: Filter products that can be sold
        purchase_ok: Filter products that can be purchased
        min_price: Minimum sale price filter
        max_price: Maximum sale price filter
        limit: Maximum number of products to return (default: 100)
        offset: Number of records to skip (for pagination)
    
    Returns:
        JSON string with product data including all matching products
    """
    logger.info(f"search_products_v2: name={name}, limit={limit}, offset={offset}, user_lang={odoo.user_lang}")
    
    try:
        # Build domain with proper syntax
        domain = []
        
        # Name search - enhanced with multi-language support
        if name:
            # First, search for products in the default way
            name_conditions = [
                ['name', 'ilike', name],
                ['default_code', 'ilike', name],
            ]
            
            # If user language is not English, also search in translations
            if odoo.user_lang and odoo.user_lang != 'en_US':
                # Search for product IDs that have matching translations
                try:
                    translation_domain = [
                        ['name', '=', 'product.product,name'],
                        ['lang', '=', odoo.user_lang],
                        ['value', 'ilike', name],
                        ['type', '=', 'model']
                    ]
                    
                    translations = odoo.execute_kw(
                        'ir.translation', 'search_read',
                        [translation_domain],
                        {'fields': ['res_id'], 'limit': 1000}
                    )
                    
                    if translations:
                        product_ids_from_translation = [t['res_id'] for t in translations if t.get('res_id')]
                        if product_ids_from_translation:
                            logger.info(f"Found {len(product_ids_from_translation)} products with matching translations")
                            name_conditions.append(['id', 'in', product_ids_from_translation])
                except Exception as e:
                    logger.warning(f"Failed to search translations: {e}")
            
            # Use proper OR syntax
            if len(name_conditions) > 1:
                or_domain = ['|'] * (len(name_conditions) - 1)
                or_domain.extend(name_conditions)
                domain.extend(or_domain)
            else:
                domain.extend(name_conditions)
        
        # Other filters (these are ANDed with name search)
        if category_name:
            domain.append(['categ_id.name', 'ilike', category_name])
        
        if product_type:
            domain.append(['type', '=', product_type])
        
        if default_code and not name:  # Don't double filter if name already searches default_code
            domain.append(['default_code', 'ilike', default_code])
        
        if barcode:
            domain.append(['barcode', '=', barcode])
        
        if active_only:
            domain.append(['active', '=', True])
        
        if sale_ok is not None:
            domain.append(['sale_ok', '=', sale_ok])
        
        if purchase_ok is not None:
            domain.append(['purchase_ok', '=', purchase_ok])
        
        if min_price is not None:
            domain.append(['list_price', '>=', min_price])
        
        if max_price is not None:
            domain.append(['list_price', '<=', max_price])
        
        logger.info(f"Final search domain: {domain}")
        
        # First, get total count
        total_count = odoo.execute_kw(
            'product.product', 'search_count', [domain]
        )
        logger.info(f"Total products matching criteria: {total_count}")
        
        # Get products directly without cache
        fields_to_fetch = [
            'id', 'name', 'display_name', 'default_code', 'barcode',
            'type', 'categ_id', 'list_price', 'standard_price',
            'qty_available', 'virtual_available', 'uom_id', 'active',
            'sale_ok', 'purchase_ok', 'description', 'description_sale'
        ]
        
        # Set context with user language for proper translation
        context = {}
        if odoo.user_lang:
            context['lang'] = odoo.user_lang
            
        products = odoo.execute_kw(
            'product.product', 'search_read', [domain],
            {
                'fields': fields_to_fetch,
                'limit': limit,
                'offset': offset,
                'order': 'name',
                'context': context  # Add context with language
            }
        )
        
        logger.info(f"Retrieved {len(products)} products")
        
        # Get translations if user language is not English
        product_translations = {}
        if odoo.user_lang and odoo.user_lang != 'en_US' and products:
            try:
                product_ids = [p['id'] for p in products]
                translation_domain = [
                    ['name', '=', 'product.product,name'],
                    ['lang', '=', odoo.user_lang],
                    ['res_id', 'in', product_ids],
                    ['type', '=', 'model']
                ]
                
                translations = odoo.execute_kw(
                    'ir.translation', 'search_read',
                    [translation_domain],
                    {'fields': ['res_id', 'value']}
                )
                
                for trans in translations:
                    if trans.get('res_id') and trans.get('value'):
                        product_translations[trans['res_id']] = trans['value']
                        
                logger.info(f"Found translations for {len(product_translations)} products")
            except Exception as e:
                logger.warning(f"Failed to get product translations: {e}")
        
        # Process products
        processed_products = []
        for product in products:
            # Use translated name if available, otherwise use original name
            product_name = product_translations.get(product['id'], product.get('name', ''))
            
            processed = {
                'id': product['id'],
                'name': product_name,  # Use translated name
                'display_name': product_name,  # Use translated name
                'original_name': product.get('name', ''),  # Keep original name
                'default_code': product.get('default_code', ''),
                'barcode': product.get('barcode', ''),
                'type': product.get('type', 'consu'),
                'active': product.get('active', True),
                'sale_ok': product.get('sale_ok', False),
                'purchase_ok': product.get('purchase_ok', False),
                'list_price': product.get('list_price', 0),
                'standard_price': product.get('standard_price', 0),
                'qty_available': product.get('qty_available', 0),
                'virtual_available': product.get('virtual_available', 0),
                'description': product.get('description', ''),
                'description_sale': product.get('description_sale', ''),
                'odoo_url': _generate_product_url(product['id'])
            }
            
            # Process category
            if product.get('categ_id'):
                processed['category_id'] = product['categ_id'][0]
                processed['category_name'] = product['categ_id'][1]
            
            # Process UOM
            if product.get('uom_id'):
                processed['uom_id'] = product['uom_id'][0]
                processed['uom_name'] = product['uom_id'][1]
            
            # Type translation
            type_map = {
                'consu': 'Consumable',
                'service': 'Service',
                'product': 'Storable Product'
            }
            processed['type_display'] = type_map.get(product.get('type', 'consu'), 'Unknown')
            
            processed_products.append(processed)
        
        # Build result
        result = {
            "success": True,
            "products": processed_products,
            "pagination": {
                "total_count": total_count,
                "limit": limit,
                "offset": offset,
                "returned_count": len(processed_products),
                "has_more": (offset + len(processed_products)) < total_count
            },
            "search_params": {
                "name": name,
                "category_name": category_name,
                "active_only": active_only,
                "domain": str(domain),
                "user_language": odoo.user_lang
            },
            "timestamp": datetime.now().isoformat()
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
        
    except Exception as e:
        logger.error(f"Error in search_products_v2: {e}", exc_info=True)
        return json.dumps({
            "success": False,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }, indent=2, ensure_ascii=False)

@mcp.tool()
def search_products(name: Optional[str] = None, category_name: Optional[str] = None,
                   keywords: Optional[List[str]] = None,
                   product_type: Optional[str] = None, default_code: Optional[str] = None,
                   barcode: Optional[str] = None, active_only: bool = True,
                   sale_ok: Optional[bool] = None, purchase_ok: Optional[bool] = None,
                   min_price: Optional[float] = None, max_price: Optional[float] = None,
                   limit: int = 20, offset: int = 0, skip_cache: bool = False,
                   compact: bool = False, count_only: bool = False) -> str:
    """Search Odoo products with comprehensive filters.

    IMPORTANT: Use the EXACT keywords from user input. DO NOT translate.

    OUTPUT CONTROL (use these to reduce response size):
    - count_only=True: Only return count, no data
    - compact=True: Return minimal fields only

    Args:
        name: Product name (partial match, case-insensitive)
        category_name: Product category name filter
        keywords: Find products whose name contains ALL these keywords (AND logic)
        product_type: Type filter - 'consu' (consumable), 'service', 'product' (storable)
        default_code: Internal reference/SKU filter
        barcode: Barcode filter
        active_only: Only active products (default: True)
        sale_ok: Filter products that can be sold
        purchase_ok: Filter products that can be purchased
        min_price: Minimum sale price filter
        max_price: Maximum sale price filter
        limit: Max results (default: 20)
        offset: Skip first N results for pagination (default: 0)
        skip_cache: Force fresh data from Odoo (default: False)
        compact: Return minimal fields only (default: False)
        count_only: Only return count (default: False)

    Returns:
        JSON with products list (or count if count_only=True)
    """
    logger.info(f"Searching products: name={name}, category={category_name}, type={product_type}")
    
    try:
        # Build domain filters
        # v1.4.3: Simplified domain construction - just use simple list format
        domain = []
        
        if name:
            # Just search in name field with ilike
            domain.append(['name', 'ilike', name])
        
        if category_name:
            domain.append(['categ_id.name', 'ilike', category_name])
        
        if product_type:
            domain.append(['type', '=', product_type])
        
        if default_code:
            domain.append(['default_code', 'ilike', default_code])
        
        if barcode:
            domain.append(['barcode', '=', barcode])
        
        if active_only:
            domain.append(['active', '=', True])
        
        if sale_ok is not None:
            domain.append(['sale_ok', '=', sale_ok])
        
        if purchase_ok is not None:
            domain.append(['purchase_ok', '=', purchase_ok])
        
        if min_price is not None:
            domain.append(['list_price', '>=', min_price])
        
        if max_price is not None:
            domain.append(['list_price', '<=', max_price])

        # Handle keywords search (find products whose name contains ALL keywords)
        product_ids_from_keywords = None
        if keywords and len(keywords) > 0:
            try:
                first_keyword = keywords[0]
                keyword_domain = [['name', 'ilike', first_keyword]]
                if active_only:
                    keyword_domain.append(['active', '=', True])
                matching_products = _cached_odoo_call(
                    'product.product', 'search_read', [keyword_domain],
                    {'fields': ['id', 'name'], 'limit': 5000}
                )
                product_ids_from_keywords = []
                for prod in matching_products:
                    prod_name = (prod.get('name') or '').lower()
                    if all(kw.lower() in prod_name for kw in keywords):
                        product_ids_from_keywords.append(prod['id'])
                logger.info(f"Found {len(product_ids_from_keywords)} products matching keywords: {keywords}")
                if product_ids_from_keywords:
                    domain.append(['id', 'in', product_ids_from_keywords])
                else:
                    # No products match all keywords
                    return json.dumps({
                        "products": [],
                        "count": 0,
                        "summary": {"message": f"No products found matching all keywords: {keywords}"},
                        "query_info": {"keywords": keywords, "timestamp": datetime.now().isoformat()}
                    }, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
            except Exception as e:
                logger.warning(f"Error searching keywords: {e}")

        # Get products using version-compatible fields
        available_fields = odoo.get_version_compatible_fields('product.product', 'standard')
        
        # v1.4.3: Log the domain for debugging
        logger.info(f"Search domain: {domain}")
        
        # v1.4.2: Use skip_cache parameter and increase internal search limit
        # First, search with a higher limit to ensure we get all matching products
        search_limit = limit * 5 if name else limit  # Increase limit when searching by name
        
        if skip_cache or name:  # Always skip cache for name searches to ensure fresh results
            # Direct API call without cache
            products = odoo.execute_kw(
                'product.product', 'search_read', [domain],
                {
                    'fields': available_fields,
                    'limit': search_limit,
                    'order': 'name'
                }
            )
        else:
            products = _cached_odoo_call(
                'product.product', 'search_read', [domain],
                {
                    'fields': available_fields,
                    'limit': search_limit,
                    'order': 'name'
                }
            )
        
        # Log the actual number of products found
        logger.info(f"Found {len(products)} products matching criteria")

        # Apply offset and limit for pagination early
        total_found = len(products)
        products = products[offset:offset + limit]

        # Handle count_only mode
        if count_only:
            return json.dumps({
                "count": total_found,
                "query_info": {"mode": "count_only", "timestamp": datetime.now().isoformat()}
            }, indent=2, ensure_ascii=False, cls=DateTimeEncoder)

        # Enrich product data
        enriched_products = []

        for product in products:
            if compact:
                enriched_product = {
                    'id': product.get('id'),
                    'name': product.get('name'),
                    'default_code': product.get('default_code', ''),
                    'type': product.get('type'),
                    'list_price': product.get('list_price', 0),
                    'category': product.get('categ_id', [None, ''])[1] if product.get('categ_id') else '',
                    'qty_available': product.get('qty_available', 0),
                    'odoo_url': _generate_product_url(product['id'])
                }
                enriched_products.append(enriched_product)
                continue

            enriched_product = product.copy()
            
            # v1.4.4: Use 'name' field instead of 'display_name' to avoid variant/copy text
            # Keep the clean product name
            if 'display_name' in enriched_product and 'name' in enriched_product:
                # Log the transformation for debugging
                if '副本' in enriched_product['display_name']:
                    logger.debug(f"Cleaning product name: {enriched_product['display_name']} -> {enriched_product['name']}")
                
                enriched_product['original_display_name'] = enriched_product['display_name']
                # Override display_name with clean name to avoid "副本" text
                enriched_product['display_name'] = enriched_product['name']
                # Also add a specific clean_name field to be extra clear
                enriched_product['clean_name'] = enriched_product['name']
                # Ensure the main 'name' field is also clean
                enriched_product['name'] = enriched_product['name']  # Redundant but ensures it's clean
            elif 'name' in enriched_product:
                enriched_product['clean_name'] = enriched_product['name']
                enriched_product['display_name'] = enriched_product['name']
            
            # Generate direct URL to product
            enriched_product['odoo_url'] = _generate_product_url(product['id'])
            
            # Format category
            if product.get('categ_id'):
                enriched_product['category_name'] = product['categ_id'][1]
            
            # Format UOM
            if product.get('uom_id'):
                enriched_product['unit_of_measure'] = product['uom_id'][1]
            
            # Product type translation
            type_translations = {
                'consu': '消耗品 (Consumable)',
                'service': '服務 (Service)',
                'product': '可庫存產品 (Storable Product)'
            }
            enriched_product['type_display'] = type_translations.get(
                product.get('type', 'consu'),
                product.get('type', 'Unknown')
            )
            
            # Stock information
            enriched_product['stock_info'] = {
                'qty_on_hand': product.get('qty_available', 0),
                'qty_forecasted': product.get('virtual_available', 0),
                'uom': enriched_product.get('unit_of_measure', 'Unit')
            }
            
            enriched_products.append(enriched_product)

        # Calculate summary
        displayed_count = len(enriched_products)  # Count after limiting
        category_breakdown = {}
        type_breakdown = {}
        
        for product in enriched_products:
            # Category statistics
            category = product.get('category_name', 'Uncategorized')
            category_breakdown[category] = category_breakdown.get(category, 0) + 1
            
            # Type statistics
            ptype = product.get('type', 'unknown')
            type_breakdown[ptype] = type_breakdown.get(ptype, 0) + 1
        
        result = {
            "products": enriched_products,
            "summary": {
                "total_found": total_found,
                "displayed_count": displayed_count,
                "category_breakdown": category_breakdown,
                "type_breakdown": type_breakdown,
                "search_criteria": {
                    "name": name,
                    "category": category_name,
                    "type": product_type,
                    "active_only": active_only
                },
                "more_available": total_found > displayed_count
            },
            "query_info": {
                "limit": limit,
                "actual_search_limit": search_limit,
                "skip_cache": skip_cache or bool(name),
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
        
    except Exception as e:
        logger.error(f"Error searching products: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def get_product_details(product_id: int, include_stock_by_location: bool = False) -> str:
    """Get detailed product information by ID.

    Args:
        product_id: The product ID (integer)
        include_stock_by_location: Include stock levels breakdown by warehouse/location (default: False)

    Returns:
        JSON with: product info (name, code, type, category), prices (sale/cost),
        stock quantities, unit of measure, variants info, and direct Odoo URL
    """
    logger.info(f"Getting product details for ID: {product_id}")
    
    try:
        # Get all available fields for the product
        available_fields = odoo.get_version_compatible_fields('product.product', 'standard')
        
        # Add variant-specific fields if available
        variant_fields = ['product_template_attribute_value_ids', 'product_variant_count']
        for field in variant_fields:
            if field not in available_fields:
                try:
                    # Test if field exists
                    test = _cached_odoo_call(
                        'product.product', 'search_read',
                        [[['id', '=', product_id]]],
                        {'fields': [field], 'limit': 1}
                    )
                    if test:
                        available_fields.append(field)
                except:
                    pass
        
        # Get product details
        products = _cached_odoo_call(
            'product.product', 'search_read',
            [[['id', '=', product_id]]],
            {'fields': available_fields, 'limit': 1}
        )
        
        if not products:
            return json.dumps({
                "error": f"Product with ID {product_id} not found"
            }, indent=2, ensure_ascii=False)
        
        product = products[0]
        
        # Enrich product data
        enriched_product = product.copy()
        
        # Generate URL
        enriched_product['odoo_url'] = _generate_product_url(product_id)
        
        # Format fields
        if product.get('categ_id'):
            enriched_product['category_name'] = product['categ_id'][1]
            enriched_product['category_id_raw'] = product['categ_id'][0]
        
        if product.get('uom_id'):
            enriched_product['unit_of_measure'] = product['uom_id'][1]
        
        if product.get('uom_po_id'):
            enriched_product['purchase_unit_of_measure'] = product['uom_po_id'][1]
        
        # Product type translation
        type_translations = {
            'consu': '消耗品 (Consumable)',
            'service': '服務 (Service)',
            'product': '可庫存產品 (Storable Product)'
        }
        enriched_product['type_display'] = type_translations.get(
            product.get('type', 'consu'),
            product.get('type', 'Unknown')
        )
        
        # Get product template information if available
        if product.get('product_tmpl_id'):
            template_id = product['product_tmpl_id'][0]
            try:
                template_fields = odoo.get_version_compatible_fields('product.template', 'standard')
                templates = _cached_odoo_call(
                    'product.template', 'search_read',
                    [[['id', '=', template_id]]],
                    {'fields': template_fields, 'limit': 1}
                )
                if templates:
                    enriched_product['template_info'] = templates[0]
            except Exception as e:
                logger.warning(f"Could not get template info: {e}")
        
        # Stock information
        stock_info = {
            'qty_on_hand': product.get('qty_available', 0),
            'qty_forecasted': product.get('virtual_available', 0),
            'incoming_qty': product.get('incoming_qty', 0),
            'outgoing_qty': product.get('outgoing_qty', 0),
            'uom': enriched_product.get('unit_of_measure', 'Unit')
        }
        
        # Get stock by location if requested
        if include_stock_by_location and product.get('type') == 'product':
            try:
                # Search for stock quants
                quants = _cached_odoo_call(
                    'stock.quant', 'search_read',
                    [[['product_id', '=', product_id], ['location_id.usage', '=', 'internal']]],
                    {
                        'fields': ['location_id', 'quantity', 'reserved_quantity', 'available_quantity'],
                        'limit': 100
                    }
                )
                
                location_stock = []
                for quant in quants:
                    if quant.get('quantity', 0) > 0:
                        location_stock.append({
                            'location': quant['location_id'][1] if quant.get('location_id') else 'Unknown',
                            'location_id': quant['location_id'][0] if quant.get('location_id') else None,
                            'quantity': quant.get('quantity', 0),
                            'reserved': quant.get('reserved_quantity', 0),
                            'available': quant.get('available_quantity', 0)
                        })
                
                stock_info['by_location'] = location_stock
                
            except Exception as e:
                logger.warning(f"Could not get stock by location: {e}")
        
        enriched_product['stock_info'] = stock_info
        
        # Pricing information
        enriched_product['pricing_info'] = {
            'sale_price': product.get('list_price', 0),
            'cost': product.get('standard_price', 0),
            'currency': 'TWD'  # Default, should get from company
        }
        
        # Vendor information (if available)
        try:
            if product.get('seller_ids'):
                # Get supplier info
                vendor_info = _cached_odoo_call(
                    'product.supplierinfo', 'search_read',
                    [[['product_id', '=', product_id]]],
                    {
                        'fields': ['name', 'price', 'min_qty', 'delay', 'product_code'],
                        'limit': 5
                    }
                )
                
                vendors = []
                for vendor in vendor_info:
                    vendors.append({
                        'supplier': vendor['name'][1] if vendor.get('name') else 'Unknown',
                        'supplier_id': vendor['name'][0] if vendor.get('name') else None,
                        'price': vendor.get('price', 0),
                        'min_qty': vendor.get('min_qty', 1),
                        'lead_time_days': vendor.get('delay', 0),
                        'supplier_product_code': vendor.get('product_code', '')
                    })
                
                enriched_product['vendor_info'] = vendors
                
        except Exception as e:
            logger.debug(f"Could not get vendor info: {e}")
        
        result = {
            "product": enriched_product,
            "query_info": {
                "product_id": product_id,
                "include_stock_by_location": include_stock_by_location,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
        
    except Exception as e:
        logger.error(f"Error getting product details: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def get_product_stock(product_id: Optional[int] = None, product_name: Optional[str] = None,
                     warehouse_id: Optional[int] = None, location_id: Optional[int] = None) -> str:
    """Get real-time stock levels for products.

    Args:
        product_id: Specific product ID (optional, use this OR product_name)
        product_name: Product name to search (optional, returns multiple matches)
        warehouse_id: Filter by specific warehouse ID (optional)
        location_id: Filter by specific stock location ID (optional)

    Returns:
        JSON with: product info, total stock quantity, reserved quantity,
        available quantity, and breakdown by location/warehouse if applicable
    """
    logger.info(f"Getting product stock: id={product_id}, name={product_name}")
    
    try:
        # First, find the product if searching by name
        if product_name and not product_id:
            products = _cached_odoo_call(
                'product.product', 'search_read',
                [[['name', 'ilike', product_name]]],
                {'fields': ['id', 'name', 'display_name'], 'limit': 10}
            )
            
            if not products:
                return json.dumps({
                    "error": f"No products found matching '{product_name}'"
                }, indent=2, ensure_ascii=False)
            
            if len(products) > 1:
                # Return list of matching products
                return json.dumps({
                    "error": "Multiple products found",
                    "products": [
                        {
                            "id": p['id'],
                            "name": p.get('display_name', p.get('name', 'Unknown'))
                        } for p in products
                    ],
                    "message": "Please specify product_id for exact match"
                }, indent=2, ensure_ascii=False)
            
            product_id = products[0]['id']
            product_info = products[0]
        else:
            # Get product info
            products = _cached_odoo_call(
                'product.product', 'search_read',
                [[['id', '=', product_id]]],
                {'fields': ['id', 'name', 'display_name', 'type', 'uom_id'], 'limit': 1}
            )
            
            if not products:
                return json.dumps({
                    "error": f"Product with ID {product_id} not found"
                }, indent=2, ensure_ascii=False)
            
            product_info = products[0]
        
        # Check if product is stockable
        if product_info.get('type') not in ['product', None]:
            return json.dumps({
                "product": {
                    "id": product_info['id'],
                    "name": product_info.get('display_name', product_info.get('name', 'Unknown')),
                    "type": product_info.get('type', 'unknown')
                },
                "message": "This product is not stockable (type: " + product_info.get('type', 'unknown') + ")",
                "stock_info": {
                    "is_stockable": False
                }
            }, indent=2, ensure_ascii=False)
        
        # Build domain for stock search
        domain = [['product_id', '=', product_id]]
        
        # Add location filters
        if warehouse_id:
            # Get warehouse locations
            warehouses = _cached_odoo_call(
                'stock.warehouse', 'search_read',
                [[['id', '=', warehouse_id]]],
                {'fields': ['lot_stock_id'], 'limit': 1}
            )
            if warehouses and warehouses[0].get('lot_stock_id'):
                domain.append(['location_id', 'child_of', warehouses[0]['lot_stock_id'][0]])
        elif location_id:
            domain.append(['location_id', '=', location_id])
        else:
            # Only internal locations by default
            domain.append(['location_id.usage', '=', 'internal'])
        
        # Get stock quants
        quants = _cached_odoo_call(
            'stock.quant', 'search_read',
            [domain],
            {
                'fields': ['location_id', 'quantity', 'reserved_quantity', 'available_quantity'],
                'limit': 1000
            }
        )
        
        # Aggregate stock by location
        location_stock = {}
        total_qty = 0
        total_reserved = 0
        total_available = 0
        
        for quant in quants:
            loc_id = quant['location_id'][0] if quant.get('location_id') else 0
            loc_name = quant['location_id'][1] if quant.get('location_id') else 'Unknown'
            
            if loc_id not in location_stock:
                location_stock[loc_id] = {
                    'location_id': loc_id,
                    'location_name': loc_name,
                    'quantity': 0,
                    'reserved': 0,
                    'available': 0
                }
            
            qty = quant.get('quantity', 0)
            reserved = quant.get('reserved_quantity', 0)
            available = quant.get('available_quantity', 0)
            
            location_stock[loc_id]['quantity'] += qty
            location_stock[loc_id]['reserved'] += reserved
            location_stock[loc_id]['available'] += available
            
            total_qty += qty
            total_reserved += reserved
            total_available += available
        
        # Get product stock info from product itself for verification
        product_stock = _cached_odoo_call(
            'product.product', 'search_read',
            [[['id', '=', product_id]]],
            {
                'fields': ['qty_available', 'virtual_available', 'incoming_qty', 'outgoing_qty'],
                'limit': 1
            }
        )
        
        result = {
            "product": {
                "id": product_info['id'],
                "name": product_info.get('display_name', product_info.get('name', 'Unknown')),
                "uom": product_info['uom_id'][1] if product_info.get('uom_id') else 'Unit',
                "odoo_url": _generate_product_url(product_info['id'])
            },
            "stock_summary": {
                "total_on_hand": total_qty,
                "total_reserved": total_reserved,
                "total_available": total_available,
                "system_on_hand": product_stock[0].get('qty_available', 0) if product_stock else 0,
                "system_forecasted": product_stock[0].get('virtual_available', 0) if product_stock else 0,
                "incoming": product_stock[0].get('incoming_qty', 0) if product_stock else 0,
                "outgoing": product_stock[0].get('outgoing_qty', 0) if product_stock else 0
            },
            "stock_by_location": list(location_stock.values()),
            "query_info": {
                "product_id": product_id,
                "warehouse_filter": warehouse_id,
                "location_filter": location_id,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
        
    except Exception as e:
        logger.error(f"Error getting product stock: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# ───────────────────────── Enhanced Contact/Partner Management ─────────────────────────

@mcp.tool()
def search_partners(name: Optional[str] = None, is_customer: Optional[bool] = None,
                   is_supplier: Optional[bool] = None, email: Optional[str] = None,
                   phone: Optional[str] = None, limit: int = 20, offset: int = 0,
                   compact: bool = False, count_only: bool = False) -> str:
    """Search Odoo contacts/customers/suppliers (res.partner).

    IMPORTANT: Use the EXACT keywords from user input. DO NOT translate.

    OUTPUT CONTROL (use these to reduce response size):
    - count_only=True: Only return count, no data
    - compact=True: Return minimal fields only

    Args:
        name: Partner name (partial match, searches both name and display_name)
        is_customer: Filter customers only (True) or exclude (False), None=all
        is_supplier: Filter suppliers only (True) or exclude (False), None=all
        email: Email address filter (partial match)
        phone: Phone/mobile number filter (partial match)
        limit: Max results (default: 20, use 0 for unlimited)
        offset: Skip first N results for pagination (default: 0)
        compact: Return minimal fields only (default: False)
        count_only: Only return count (default: False)

    Returns:
        JSON with partners list (or count if count_only=True)
    """
    logger.info(f"Searching partners: name={name}, customer={is_customer}, supplier={is_supplier}, limit={limit}")
    
    try:
        # Build domain filters - FIXED: Only add customer/supplier filters when explicitly requested
        domain = []
        
        if name:
            # Use OR to search in both name and display_name for better matching
            domain.extend(['|', ['name', 'ilike', name], ['display_name', 'ilike', name]])
        if email:
            domain.append(['email', 'ilike', email])
        if phone:
            domain.append(['|', ['phone', 'ilike', phone], ['mobile', 'ilike', phone]])
        
        # FIXED: Only filter by customer_rank/supplier_rank when explicitly requested
        if is_customer is True:
            domain.append(['customer_rank', '>', 0])
        if is_supplier is True:
            domain.append(['supplier_rank', '>', 0])
        
        # Get partners using compatible fields
        partner_fields = odoo.get_version_compatible_fields('res.partner', 'standard')
        
        # Set search kwargs with pagination support
        search_kwargs = {'fields': partner_fields}
        if limit > 0:
            search_kwargs['limit'] = limit
        if offset > 0:
            search_kwargs['offset'] = offset

        partners = _cached_odoo_call(
            'res.partner', 'search_read', [domain], search_kwargs
        )

        # Handle count_only mode
        if count_only:
            return json.dumps({
                "count": len(partners),
                "query_info": {"mode": "count_only", "timestamp": datetime.now().isoformat()}
            }, indent=2, ensure_ascii=False, cls=DateTimeEncoder)

        # Enrich partner data with URLs
        enriched_partners = []

        for partner in partners:
            if compact:
                enriched_partner = {
                    'id': partner.get('id'),
                    'name': partner.get('name'),
                    'email': partner.get('email', ''),
                    'phone': partner.get('phone', ''),
                    'is_company': partner.get('is_company', False),
                    'customer_rank': partner.get('customer_rank', 0),
                    'supplier_rank': partner.get('supplier_rank', 0),
                    'odoo_url': _generate_partner_url(partner['id'])
                }
                enriched_partners.append(enriched_partner)
                continue

            enriched_partner = partner.copy()

            # Generate partner URL
            enriched_partner['odoo_url'] = _generate_partner_url(partner['id'])
            enriched_partner['url_description'] = f"點擊直接開啟聯絡人 {partner.get('name', partner['id'])}"

            # Format address
            address_parts = []
            if partner.get('street'):
                address_parts.append(partner['street'])
            if partner.get('city'):
                address_parts.append(partner['city'])
            if partner.get('country_id'):
                address_parts.append(partner['country_id'][1])

            enriched_partner['formatted_address'] = ', '.join(address_parts) if address_parts else 'No address'

            # Language and currency settings
            partner_lang = partner.get('lang', 'zh_TW')
            enriched_partner['is_english_customer'] = _is_english_customer(partner_lang)

            enriched_partners.append(enriched_partner)
        
        # Calculate statistics
        total_found = len(enriched_partners)
        customer_count = len([p for p in enriched_partners if p.get('customer_rank', 0) > 0])
        supplier_count = len([p for p in enriched_partners if p.get('supplier_rank', 0) > 0])
        company_count = len([p for p in enriched_partners if p.get('is_company', False)])
        individual_count = total_found - company_count
        
        result = {
            "partners": enriched_partners,
            "summary": {
                "total_found": total_found,
                "customers": customer_count,
                "suppliers": supplier_count,
                "companies": company_count,
                "individuals": individual_count,
                "urls_included": True,
                "url_base": config.ODOO_URL
            },
            "query_info": {
                "name_filter": name,
                "is_customer": is_customer,
                "is_supplier": is_supplier,
                "email_filter": email,
                "phone_filter": phone,
                "limit": limit,
                "search_type": "all_partners" if is_customer is None and is_supplier is None else "filtered_partners",
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Error searching partners: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# @mcp.tool()  # Disabled - use search_partners instead
def get_all_partners(limit: int = 0, include_companies: bool = True, 
                    include_individuals: bool = True) -> str:
    """Get all partners/contacts in the system
    
    Args:
        limit: Maximum number of partners to return (default: 0 = all)
        include_companies: Include company records (default: True)
        include_individuals: Include individual contact records (default: True)
    
    Returns:
        JSON string with all partner data including URLs
    """
    logger.info(f"Getting all partners: limit={limit}, companies={include_companies}, individuals={include_individuals}")
    
    try:
        domain = []
        
        # Filter by record type if specified
        if include_companies and not include_individuals:
            domain.append(['is_company', '=', True])
        elif include_individuals and not include_companies:
            domain.append(['is_company', '=', False])
        # If both are True or both are False, no filter needed
        
        partner_fields = odoo.get_version_compatible_fields('res.partner', 'standard')
        
        search_kwargs = {'fields': partner_fields}
        if limit > 0:
            search_kwargs['limit'] = limit
        
        partners = _cached_odoo_call(
            'res.partner', 'search_read', [domain], search_kwargs
        )
        
        # Enhanced partner information with URLs
        enriched_partners = []
        
        for partner in partners:
            enriched_partner = partner.copy()
            
            # Generate partner URL
            enriched_partner['odoo_url'] = _generate_partner_url(partner['id'])
            enriched_partner['url_description'] = f"點擊直接開啟聯絡人 {partner.get('name', partner['id'])}"
            
            # Format address
            address_parts = []
            if partner.get('street'):
                address_parts.append(partner['street'])
            if partner.get('city'):
                address_parts.append(partner['city'])
            if partner.get('country_id'):
                address_parts.append(partner['country_id'][1])
            
            enriched_partner['formatted_address'] = ', '.join(address_parts) if address_parts else 'No address'
            
            # Classification
            enriched_partner['is_customer'] = partner.get('customer_rank', 0) > 0
            enriched_partner['is_supplier'] = partner.get('supplier_rank', 0) > 0
            enriched_partner['is_english_customer'] = _is_english_customer(partner.get('lang', 'zh_TW'))
            
            # Contact type
            enriched_partner['contact_type'] = 'Company' if partner.get('is_company') else 'Individual'
            
            enriched_partners.append(enriched_partner)
        
        # Detailed statistics
        total_found = len(enriched_partners)
        stats = {
            "total_records": total_found,
            "companies": len([p for p in enriched_partners if p.get('is_company', False)]),
            "individuals": len([p for p in enriched_partners if not p.get('is_company', False)]),
            "customers": len([p for p in enriched_partners if p.get('customer_rank', 0) > 0]),
            "suppliers": len([p for p in enriched_partners if p.get('supplier_rank', 0) > 0]),
            "with_email": len([p for p in enriched_partners if p.get('email')]),
            "with_phone": len([p for p in enriched_partners if p.get('phone') or p.get('mobile')]),
            "english_customers": len([p for p in enriched_partners if p.get('is_english_customer')]),
            "chinese_customers": len([p for p in enriched_partners if not p.get('is_english_customer')]),
            "urls_included": True,
            "url_base": config.ODOO_URL
        }
        
        result = {
            "partners": enriched_partners,
            "statistics": stats,
            "query_info": {
                "limit": limit,
                "include_companies": include_companies,
                "include_individuals": include_individuals,
                "total_available": total_found,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Error getting all partners: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# @mcp.tool()  # Disabled to reduce tool count
def get_partner_statistics() -> str:
    """Get comprehensive partner statistics and counts
    
    Returns:
        JSON string with detailed partner statistics
    """
    logger.info("Getting partner statistics")
    
    try:
        # Get total counts using search_count for efficiency
        total_partners = _cached_odoo_call('res.partner', 'search_count', [[]], {})
        total_customers = _cached_odoo_call('res.partner', 'search_count', [[['customer_rank', '>', 0]]], {})
        total_suppliers = _cached_odoo_call('res.partner', 'search_count', [[['supplier_rank', '>', 0]]], {})
        total_companies = _cached_odoo_call('res.partner', 'search_count', [[['is_company', '=', True]]], {})
        total_individuals = _cached_odoo_call('res.partner', 'search_count', [[['is_company', '=', False]]], {})
        
        # Get partners with email/phone
        with_email = _cached_odoo_call('res.partner', 'search_count', [[['email', '!=', False]]], {})
        with_phone = _cached_odoo_call('res.partner', 'search_count', [['|', ['phone', '!=', False], ['mobile', '!=', False]]], {})
        
        # Get language distribution (sample for performance)
        language_sample = _cached_odoo_call(
            'res.partner', 'search_read', 
            [[['lang', '!=', False]]], 
            {'fields': ['lang'], 'limit': 1000}
        )
        
        language_counts = {}
        for partner in language_sample:
            lang = partner.get('lang', 'Not Set')
            language_counts[lang] = language_counts.get(lang, 0) + 1
        
        result = {
            "overview": {
                "total_partners": total_partners,
                "customers": total_customers,
                "suppliers": total_suppliers,
                "companies": total_companies,
                "individuals": total_individuals,
                "with_email": with_email,
                "with_phone": with_phone
            },
            "percentages": {
                "customer_percentage": round((total_customers / total_partners * 100), 2) if total_partners > 0 else 0,
                "supplier_percentage": round((total_suppliers / total_partners * 100), 2) if total_partners > 0 else 0,
                "company_percentage": round((total_companies / total_partners * 100), 2) if total_partners > 0 else 0,
                "email_coverage": round((with_email / total_partners * 100), 2) if total_partners > 0 else 0,
                "phone_coverage": round((with_phone / total_partners * 100), 2) if total_partners > 0 else 0
            },
            "language_distribution": language_counts,
            "query_info": {
                "language_sample_size": len(language_sample),
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Error getting partner statistics: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# @mcp.tool()  # Disabled to reduce tool count
def get_partner_language_currency(partner_id: int) -> str:
    """Get detailed language and currency settings for a specific partner
    
    Args:
        partner_id: Partner ID
    
    Returns:
        JSON string with language and currency configuration including URL
    """
    logger.info(f"Getting language/currency settings for partner: {partner_id}")
    
    try:
        # Get partner basic info
        partner = _cached_odoo_call(
            'res.partner', 'read', [partner_id],
            {
                'fields': [
                    'name', 'lang', 'country_id', 'tz', 'vat', 'is_company',
                    'property_product_pricelist', 'property_payment_term_id',
                    'customer_rank', 'supplier_rank'
                ]
            }
        )
        
        if not partner:
            return json.dumps({"error": "Partner not found"}, indent=2, ensure_ascii=False)
        
        partner_data = partner[0]
        partner_lang = partner_data.get('lang', 'zh_TW')
        is_english = _is_english_customer(partner_lang)
        
        # Generate partner URL
        partner_url = _generate_partner_url(partner_id)
        
        result = {
            "partner_info": {
                "id": partner_id,
                "name": partner_data.get('name'),
                "type": "Company" if partner_data.get('is_company') else "Individual",
                "language": partner_lang,
                "is_english_customer": is_english,
                "country": partner_data.get('country_id', [None, 'Not Set'])[1] if partner_data.get('country_id') else 'Not Set',
                "timezone": partner_data.get('tz', 'Not Set'),
                "vat_number": partner_data.get('vat', 'None'),
                "odoo_url": partner_url,
                "url_description": f"點擊直接開啟聯絡人 {partner_data.get('name', partner_id)}"
            },
            "classification": {
                "is_customer": partner_data.get('customer_rank', 0) > 0,
                "is_supplier": partner_data.get('supplier_rank', 0) > 0,
                "customer_rank": partner_data.get('customer_rank', 0),
                "supplier_rank": partner_data.get('supplier_rank', 0)
            },
            "url_info": {
                "partner_url": partner_url,
                "base_odoo_url": config.ODOO_URL
            },
            "query_info": {
                "partner_id": partner_id,
                "timestamp": datetime.now().isoformat()
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        logger.error(f"Error getting partner language/currency: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# ───────────────────────── User Language Management ─────────────────────────

# @mcp.tool()  # Disabled to reduce tool count
def get_current_user_language() -> str:
    """Get the current MCP user's language setting
    
    Returns:
        JSON string with user language information
    """
    logger.info("Getting current user language setting")
    
    try:
        # Get fresh user data
        user_data = odoo.execute_kw(
            'res.users', 'read', [odoo.uid], 
            {'fields': ['name', 'lang', 'tz', 'company_id']}
        )
        
        if user_data:
            user_info = user_data[0]
            result = {
                "user": {
                    "id": odoo.uid,
                    "name": user_info.get('name', 'Unknown'),
                    "language": user_info.get('lang', 'en_US'),
                    "language_name": {
                        'zh_TW': '繁體中文',
                        'zh_CN': '简体中文',
                        'en_US': 'English (US)',
                        'en_GB': 'English (UK)'
                    }.get(user_info.get('lang', 'en_US'), user_info.get('lang', 'en_US')),
                    "timezone": user_info.get('tz', 'UTC'),
                    "company": user_info.get('company_id', [None, 'Unknown'])[1] if user_info.get('company_id') else 'Unknown'
                },
                "cached_language": odoo.user_lang,
                "configured_default_language": config.DEFAULT_LANGUAGE,
                "language_source": "configured_default" if config.DEFAULT_LANGUAGE else "user_preference",
                "multi_language_search_enabled": True,
                "supported_languages": ['zh_TW', 'zh_CN', 'en_US', 'en_GB'],
                "timestamp": datetime.now().isoformat()
            }
        else:
            result = {
                "error": "Could not retrieve user information",
                "cached_language": odoo.user_lang,
                "timestamp": datetime.now().isoformat()
            }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
        
    except Exception as e:
        logger.error(f"Error getting user language: {e}")
        return json.dumps({
            "error": str(e),
            "cached_language": odoo.user_lang,
            "timestamp": datetime.now().isoformat()
        }, indent=2, ensure_ascii=False)

# ───────────────────────── Partner Management ─────────────────────────

@mcp.tool()
def create_or_get_partner(partner_name: str, is_company: bool = True,
                         is_customer: bool = True, is_supplier: bool = False,
                         vat: Optional[str] = None, phone: Optional[str] = None,
                         email: Optional[str] = None, street: Optional[str] = None,
                         city: Optional[str] = None, country_code: Optional[str] = "TW") -> str:
    """Create a new partner or retrieve existing one by exact name match.

    Args:
        partner_name: Partner/company name (required, exact match for lookup)
        is_company: True for company, False for individual (default: True)
        is_customer: Mark as customer (default: True)
        is_supplier: Mark as supplier (default: False)
        vat: VAT/Tax ID number - 統一編號 for Taiwan (optional)
        phone: Phone number (optional)
        email: Email address (optional)
        street: Street address (optional)
        city: City name (optional)
        country_code: ISO country code (default: "TW" for Taiwan)

    Returns:
        JSON with: status ('existing' or 'created'), partner ID, name, and details
    """
    logger.info(f"Creating or getting partner: {partner_name}")
    
    try:
        # First, search for existing partner with exact name
        existing_partners = _cached_odoo_call(
            'res.partner', 'search_read',
            [[['name', '=', partner_name]]],
            {'fields': ['id', 'name', 'is_company', 'customer_rank', 'supplier_rank'], 'limit': 1}
        )
        
        if existing_partners:
            # Partner already exists
            partner = existing_partners[0]
            logger.info(f"Found existing partner: {partner['id']} - {partner['name']}")
            
            return json.dumps({
                "status": "existing",
                "partner": {
                    "id": partner['id'],
                    "name": partner['name'],
                    "is_company": partner.get('is_company', False),
                    "is_customer": partner.get('customer_rank', 0) > 0,
                    "is_supplier": partner.get('supplier_rank', 0) > 0
                },
                "message": f"Partner '{partner_name}' already exists"
            }, indent=2, ensure_ascii=False)
        
        # Create new partner
        partner_data = {
            'name': partner_name,
            'is_company': is_company,
            'customer_rank': 1 if is_customer else 0,
            'supplier_rank': 1 if is_supplier else 0,
        }
        
        # Add optional fields
        if vat:
            partner_data['vat'] = vat
        if phone:
            partner_data['phone'] = phone
        if email:
            partner_data['email'] = email
        if street:
            partner_data['street'] = street
        if city:
            partner_data['city'] = city
            
        # Get country ID
        if country_code:
            countries = _cached_odoo_call(
                'res.country', 'search_read',
                [[['code', '=', country_code.upper()]]],
                {'fields': ['id'], 'limit': 1}
            )
            if countries:
                partner_data['country_id'] = countries[0]['id']
        
        # Create the partner
        partner_id = odoo.execute_kw(
            'res.partner', 'create', [partner_data]
        )
        
        logger.info(f"Created new partner: {partner_id} - {partner_name}")
        
        # Clear cache to ensure fresh data
        cache.clear()
        
        return json.dumps({
            "status": "created",
            "partner": {
                "id": partner_id,
                "name": partner_name,
                "is_company": is_company,
                "is_customer": is_customer,
                "is_supplier": is_supplier,
                "url": _generate_partner_url(partner_id)
            },
            "message": f"Successfully created new partner '{partner_name}'"
        }, indent=2, ensure_ascii=False)
        
    except Exception as e:
        logger.error(f"Error creating/getting partner: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# @mcp.tool()  # Disabled - use create_or_get_partner instead
def create_partner_with_contacts(company_name: str, contacts: List[Dict[str, str]], 
                                 is_customer: bool = True, is_supplier: bool = False,
                                 vat: Optional[str] = None, company_phone: Optional[str] = None, 
                                 company_email: Optional[str] = None, company_street: Optional[str] = None, 
                                 company_city: Optional[str] = None, country_code: Optional[str] = "TW") -> str:
    """Create a new company partner with multiple contacts
    
    v1.5.4: New function to create company with contacts in one operation
    
    Args:
        company_name: Company name (required)
        contacts: List of contacts, each with 'name' (required), 'function', 'phone', 'mobile', 'email'
        is_customer: Whether this is a customer (default: True)
        is_supplier: Whether this is a supplier (default: False)
        vat: VAT/Tax ID number (統一編號) (optional)
        company_phone: Company main phone (optional)
        company_email: Company main email (optional)
        company_street: Company street address (optional)
        company_city: Company city (optional)
        country_code: Country code (default: "TW" for Taiwan)
    
    Returns:
        JSON string with created company and contacts information
        
    Example contacts parameter:
    [
        {"name": "John Doe", "function": "CEO", "email": "john@company.com", "phone": "123456"},
        {"name": "Jane Smith", "function": "Sales Manager", "email": "jane@company.com", "mobile": "098765"}
    ]
    """
    logger.info(f"Creating company with contacts: {company_name}")
    
    try:
        # First check if company already exists
        existing_companies = _cached_odoo_call(
            'res.partner', 'search_read',
            [[['name', '=', company_name], ['is_company', '=', True]]],
            {'fields': ['id', 'name'], 'limit': 1}
        )
        
        if existing_companies:
            return json.dumps({
                "error": "Company already exists",
                "existing_company": {
                    "id": existing_companies[0]['id'],
                    "name": existing_companies[0]['name']
                },
                "message": f"Company '{company_name}' already exists. Use add_contact_to_partner to add new contacts."
            }, indent=2, ensure_ascii=False)
        
        # Create the company
        company_data = {
            'name': company_name,
            'is_company': True,
            'customer_rank': 1 if is_customer else 0,
            'supplier_rank': 1 if is_supplier else 0,
        }
        
        # Add optional company fields
        if vat:
            company_data['vat'] = vat
        if company_phone:
            company_data['phone'] = company_phone
        if company_email:
            company_data['email'] = company_email
        if company_street:
            company_data['street'] = company_street
        if company_city:
            company_data['city'] = company_city
            
        # Get country ID
        if country_code:
            countries = _cached_odoo_call(
                'res.country', 'search_read',
                [[['code', '=', country_code.upper()]]],
                {'fields': ['id'], 'limit': 1}
            )
            if countries:
                company_data['country_id'] = countries[0]['id']
        
        # Create the company
        company_id = odoo.execute_kw(
            'res.partner', 'create', [company_data]
        )
        
        logger.info(f"Created company: {company_id} - {company_name}")
        
        # Create contacts
        created_contacts = []
        for contact in contacts:
            if not contact.get('name'):
                logger.warning(f"Skipping contact without name")
                continue
                
            contact_data = {
                'name': contact['name'],
                'parent_id': company_id,  # This establishes the parent-child relationship
                'is_company': False,
                'type': 'contact',  # Type can be 'contact', 'invoice', 'delivery', 'other'
            }
            
            # Add optional contact fields
            if contact.get('function'):
                contact_data['function'] = contact['function']  # Job position
            if contact.get('email'):
                contact_data['email'] = contact['email']
            if contact.get('phone'):
                contact_data['phone'] = contact['phone']
            if contact.get('mobile'):
                contact_data['mobile'] = contact['mobile']
            
            # Inherit some fields from parent if not specified
            if country_code and 'country_id' in company_data:
                contact_data['country_id'] = company_data['country_id']
            
            # Create the contact
            contact_id = odoo.execute_kw(
                'res.partner', 'create', [contact_data]
            )
            
            created_contacts.append({
                'id': contact_id,
                'name': contact['name'],
                'function': contact.get('function', ''),
                'email': contact.get('email', ''),
                'phone': contact.get('phone', ''),
                'mobile': contact.get('mobile', ''),
                'url': _generate_partner_url(contact_id)
            })
            
            logger.info(f"Created contact: {contact_id} - {contact['name']}")
        
        # Clear cache
        cache.clear()
        
        result = {
            "status": "success",
            "company": {
                "id": company_id,
                "name": company_name,
                "is_customer": is_customer,
                "is_supplier": is_supplier,
                "url": _generate_partner_url(company_id)
            },
            "contacts": created_contacts,
            "summary": {
                "total_contacts_created": len(created_contacts),
                "message": f"Successfully created company '{company_name}' with {len(created_contacts)} contact(s)"
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
        
    except Exception as e:
        logger.error(f"Error creating company with contacts: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# @mcp.tool()  # Disabled to reduce tool count
def add_contact_to_partner(parent_partner_id: int, contact_name: str,
                          function: Optional[str] = None, email: Optional[str] = None,
                          phone: Optional[str] = None, mobile: Optional[str] = None,
                          contact_type: str = "contact") -> str:
    """Add a contact to an existing partner (company)
    
    v1.5.4: New function to add contacts to existing partners
    
    Args:
        parent_partner_id: ID of the parent partner (company)
        contact_name: Contact person's name (required)
        function: Job position/function (optional)
        email: Contact email (optional)
        phone: Contact phone (optional)
        mobile: Contact mobile (optional)
        contact_type: Type of contact - 'contact', 'invoice', 'delivery', 'other' (default: 'contact')
    
    Returns:
        JSON string with created contact information
    """
    logger.info(f"Adding contact to partner {parent_partner_id}: {contact_name}")
    
    try:
        # First verify the parent partner exists and is a company
        parent_partner = _cached_odoo_call(
            'res.partner', 'read', [parent_partner_id],
            {'fields': ['id', 'name', 'is_company']}
        )
        
        if not parent_partner:
            return json.dumps({
                "error": "Parent partner not found",
                "parent_partner_id": parent_partner_id
            }, indent=2, ensure_ascii=False)
        
        parent_data = parent_partner[0]
        
        # Check if contact already exists
        existing_contacts = _cached_odoo_call(
            'res.partner', 'search_read',
            [[['name', '=', contact_name], ['parent_id', '=', parent_partner_id]]],
            {'fields': ['id', 'name'], 'limit': 1}
        )
        
        if existing_contacts:
            return json.dumps({
                "error": "Contact already exists",
                "existing_contact": {
                    "id": existing_contacts[0]['id'],
                    "name": existing_contacts[0]['name'],
                    "parent_company": parent_data['name']
                }
            }, indent=2, ensure_ascii=False)
        
        # Create the contact
        contact_data = {
            'name': contact_name,
            'parent_id': parent_partner_id,
            'is_company': False,
            'type': contact_type,
        }
        
        # Add optional fields
        if function:
            contact_data['function'] = function
        if email:
            contact_data['email'] = email
        if phone:
            contact_data['phone'] = phone
        if mobile:
            contact_data['mobile'] = mobile
        
        # Create the contact
        contact_id = odoo.execute_kw(
            'res.partner', 'create', [contact_data]
        )
        
        logger.info(f"Created contact: {contact_id} - {contact_name} under company {parent_data['name']}")
        
        # Clear cache
        cache.clear()
        
        # Get all contacts of this company for summary
        all_contacts = _cached_odoo_call(
            'res.partner', 'search_read',
            [[['parent_id', '=', parent_partner_id]]],
            {'fields': ['id', 'name', 'function', 'email', 'phone', 'mobile'], 'limit': 100}
        )
        
        result = {
            "status": "success",
            "parent_company": {
                "id": parent_partner_id,
                "name": parent_data['name'],
                "is_company": parent_data.get('is_company', False),
                "url": _generate_partner_url(parent_partner_id)
            },
            "new_contact": {
                "id": contact_id,
                "name": contact_name,
                "function": function or "",
                "email": email or "",
                "phone": phone or "",
                "mobile": mobile or "",
                "type": contact_type,
                "url": _generate_partner_url(contact_id)
            },
            "all_company_contacts": [
                {
                    "id": c['id'],
                    "name": c['name'],
                    "function": c.get('function', ''),
                    "email": c.get('email', ''),
                    "phone": c.get('phone', ''),
                    "mobile": c.get('mobile', '')
                } for c in all_contacts
            ],
            "summary": {
                "total_contacts": len(all_contacts),
                "message": f"Successfully added contact '{contact_name}' to company '{parent_data['name']}'"
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
        
    except Exception as e:
        logger.error(f"Error adding contact to partner: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# @mcp.tool()  # Disabled to reduce tool count
def preview_quotation_copy(source_quotation_id: int, new_partner_name: str,
                          replace_customer_name_in_text: bool = True) -> str:
    """Preview what a quotation copy would look like with a new customer
    
    v1.5.3: New function to preview quotation copy before creation
    
    Args:
        source_quotation_id: ID of the quotation to copy
        new_partner_name: Name of the new customer
        replace_customer_name_in_text: Whether to replace old customer name in text fields (default: True)
    
    Returns:
        JSON string with preview of the quotation copy
    """
    logger.info(f"Previewing quotation copy: {source_quotation_id} -> {new_partner_name}")
    
    try:
        # Get source quotation details
        source_quote = _cached_odoo_call(
            'sale.order', 'read', [source_quotation_id],
            {}
        )
        
        if not source_quote:
            return json.dumps({"error": "Source quotation not found"}, indent=2, ensure_ascii=False)
        
        source_data = source_quote[0]
        
        # Get original customer name
        original_customer_name = source_data.get('partner_id', [None, 'Unknown'])[1] if source_data.get('partner_id') else 'Unknown'
        
        # Check if new partner exists
        new_partners = _cached_odoo_call(
            'res.partner', 'search_read',
            [[['name', '=', new_partner_name]]],
            {'fields': ['id', 'name'], 'limit': 1}
        )
        
        new_partner_exists = len(new_partners) > 0
        new_partner_id = new_partners[0]['id'] if new_partner_exists else None
        
        # Get quotation lines
        lines = _cached_odoo_call(
            'sale.order.line', 'search_read',
            [[['order_id', '=', source_quotation_id]]],
            {'order': 'sequence'}
        )
        
        # Preview data
        preview_data = {
            "source_quotation": {
                "id": source_quotation_id,
                "name": source_data.get('name', ''),
                "original_customer": original_customer_name,
                "date_order": source_data.get('date_order', ''),
                "amount_total": source_data.get('amount_total', 0),
                "currency": source_data.get('currency_id', [None, 'TWD'])[1] if source_data.get('currency_id') else 'TWD'
            },
            "new_quotation_preview": {
                "name": "[TO BE GENERATED]",
                "new_customer": new_partner_name,
                "customer_exists": new_partner_exists,
                "customer_id": new_partner_id,
                "date_order": datetime.now().strftime('%Y-%m-%d'),
                "validity_date": source_data.get('validity_date', ''),
                "payment_term": source_data.get('payment_term_id', [None, ''])[1] if source_data.get('payment_term_id') else '',
                "notes": source_data.get('note', ''),
                "amount_total": source_data.get('amount_total', 0),
                "currency": source_data.get('currency_id', [None, 'TWD'])[1] if source_data.get('currency_id') else 'TWD'
            },
            "lines_preview": [],
            "text_replacements": []
        }
        
        # Process lines
        for line in lines:
            line_preview = {
                "sequence": line.get('sequence', 0),
                "product": line.get('product_id', [None, ''])[1] if line.get('product_id') else 'Service',
                "description": line.get('name', ''),
                "quantity": line.get('product_uom_qty', 0),
                "unit_price": line.get('price_unit', 0),
                "subtotal": line.get('price_subtotal', 0)
            }
            
            # Check if description contains customer name
            if replace_customer_name_in_text and line.get('name', '') and original_customer_name in line['name']:
                new_description = line['name'].replace(original_customer_name, new_partner_name)
                line_preview['new_description'] = new_description
                preview_data['text_replacements'].append({
                    "field": f"Line {line.get('sequence', 0)} description",
                    "original": line['name'][:100] + "..." if len(line['name']) > 100 else line['name'],
                    "new": new_description[:100] + "..." if len(new_description) > 100 else new_description
                })
            
            preview_data['lines_preview'].append(line_preview)
        
        # Check notes field
        if replace_customer_name_in_text and source_data.get('note') and original_customer_name in source_data['note']:
            new_note = source_data['note'].replace(original_customer_name, new_partner_name)
            preview_data['new_quotation_preview']['new_notes'] = new_note
            preview_data['text_replacements'].append({
                "field": "Quotation notes",
                "original": source_data['note'][:100] + "..." if len(source_data['note']) > 100 else source_data['note'],
                "new": new_note[:100] + "..." if len(new_note) > 100 else new_note
            })
        
        # Summary
        preview_data['summary'] = {
            "action_required": "not_exists" if not new_partner_exists else "exists",
            "customer_action": f"Will create new customer '{new_partner_name}'" if not new_partner_exists else f"Will use existing customer '{new_partner_name}'",
            "total_lines": len(lines),
            "text_replacements_count": len(preview_data['text_replacements']),
            "confirmation_required": True,
            "instructions": "Review the preview above. Use copy_quotation with confirm=True to create the copy."
        }
        
        return json.dumps(preview_data, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
        
    except Exception as e:
        logger.error(f"Error previewing quotation copy: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# @mcp.tool()  # Disabled to reduce tool count
def copy_quotation(source_quotation_id: int, new_partner_name: str,
                  replace_customer_name_in_text: bool = True,
                  confirm: bool = False) -> str:
    """Copy a quotation to a new customer
    
    v1.5.3: New function to copy quotations with customer replacement
    
    Args:
        source_quotation_id: ID of the quotation to copy
        new_partner_name: Name of the new customer
        replace_customer_name_in_text: Whether to replace old customer name in text fields (default: True)
        confirm: Must be True to actually create the copy (safety check)
    
    Returns:
        JSON string with the new quotation information
    """
    logger.info(f"Copying quotation: {source_quotation_id} -> {new_partner_name} (confirm={confirm})")
    
    if not confirm:
        return json.dumps({
            "error": "Confirmation required",
            "message": "Please preview the copy first with preview_quotation_copy, then set confirm=True to create the copy"
        }, indent=2, ensure_ascii=False)
    
    try:
        # Get source quotation
        source_quote = _cached_odoo_call(
            'sale.order', 'read', [source_quotation_id],
            {}
        )
        
        if not source_quote:
            return json.dumps({"error": "Source quotation not found"}, indent=2, ensure_ascii=False)
        
        source_data = source_quote[0]
        original_customer_name = source_data.get('partner_id', [None, 'Unknown'])[1] if source_data.get('partner_id') else 'Unknown'
        
        # Get or create partner
        partner_result = json.loads(create_or_get_partner(new_partner_name))
        if 'error' in partner_result:
            return json.dumps(partner_result, indent=2, ensure_ascii=False)
        
        new_partner_id = partner_result['partner']['id']
        
        # Use Odoo's copy method
        new_quote_id = odoo.execute_kw(
            'sale.order', 'copy', [source_quotation_id],
            {'default': {'partner_id': new_partner_id}}
        )
        
        logger.info(f"Created quotation copy: {new_quote_id}")
        
        # If we need to replace customer names in text
        if replace_customer_name_in_text:
            # Get the new quotation's lines
            new_lines = odoo.execute_kw(
                'sale.order.line', 'search_read',
                [[['order_id', '=', new_quote_id]]],
                {'fields': ['id', 'name']}
            )
            
            # Update line descriptions
            for line in new_lines:
                if line.get('name') and original_customer_name in line['name']:
                    new_description = line['name'].replace(original_customer_name, new_partner_name)
                    odoo.execute_kw(
                        'sale.order.line', 'write',
                        [[line['id']], {'name': new_description}]
                    )
                    logger.info(f"Updated line {line['id']} description")
            
            # Update notes if needed
            new_quote_data = odoo.execute_kw(
                'sale.order', 'read', [new_quote_id],
                {'fields': ['note']}
            )
            
            if new_quote_data and new_quote_data[0].get('note') and original_customer_name in new_quote_data[0]['note']:
                new_note = new_quote_data[0]['note'].replace(original_customer_name, new_partner_name)
                odoo.execute_kw(
                    'sale.order', 'write',
                    [[new_quote_id], {'note': new_note}]
                )
                logger.info("Updated quotation notes")
        
        # Clear cache
        cache.clear()
        
        # Get final quotation details
        final_quote = odoo.execute_kw(
            'sale.order', 'read', [new_quote_id],
            {}
        )
        
        if final_quote:
            result = {
                "status": "success",
                "original_quotation": {
                    "id": source_quotation_id,
                    "name": source_data.get('name', ''),
                    "customer": original_customer_name
                },
                "new_quotation": {
                    "id": new_quote_id,
                    "name": final_quote[0].get('name', ''),
                    "customer": new_partner_name,
                    "customer_id": new_partner_id,
                    "state": final_quote[0].get('state', 'draft'),
                    "date_order": final_quote[0].get('date_order', ''),
                    "amount_total": final_quote[0].get('amount_total', 0),
                    "currency": final_quote[0].get('currency_id', [None, 'TWD'])[1] if final_quote[0].get('currency_id') else 'TWD',
                    "url": _generate_quotation_url(new_quote_id)
                },
                "message": f"Successfully copied quotation to new customer '{new_partner_name}'"
            }
            
            return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
        else:
            return json.dumps({
                "error": "Failed to retrieve new quotation details",
                "new_quotation_id": new_quote_id
            }, indent=2, ensure_ascii=False)
            
    except Exception as e:
        logger.error(f"Error copying quotation: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# @mcp.tool()  # Disabled to reduce tool count
def update_quotation(quotation_id: int, 
                    partner_id: Optional[int] = None,
                    partner_invoice_id: Optional[int] = None,
                    partner_shipping_id: Optional[int] = None,
                    validity_date: Optional[str] = None,
                    date_order: Optional[str] = None,
                    note: Optional[str] = None,
                    payment_term_id: Optional[int] = None,
                    user_id: Optional[int] = None,
                    team_id: Optional[int] = None,
                    client_order_ref: Optional[str] = None,
                    fiscal_position_id: Optional[int] = None,
                    update_lines: Optional[List[Dict]] = None) -> str:
    """Update quotation header and optionally its lines
    
    v1.5.5: New function to update quotations
    
    Args:
        quotation_id: ID of the quotation to update (required)
        partner_id: Customer ID (optional)
        partner_invoice_id: Invoice address ID (optional)
        partner_shipping_id: Delivery address ID (optional)
        validity_date: Expiration date YYYY-MM-DD (optional)
        date_order: Order date YYYY-MM-DD (optional)
        note: Internal notes (optional)
        payment_term_id: Payment terms ID (optional)
        user_id: Salesperson ID (optional)
        team_id: Sales team ID (optional)
        client_order_ref: Customer reference (optional)
        fiscal_position_id: Fiscal position ID (optional)
        update_lines: List of line updates (optional)
            Each line dict can contain:
            - line_id: ID of line to update (required for update)
            - action: 'update', 'create', or 'delete'
            - product_id: Product ID
            - name: Description
            - product_uom_qty: Quantity
            - price_unit: Unit price
            - discount: Discount percentage
            - tax_id: List of tax IDs
    
    Returns:
        JSON string with update result
    """
    logger.info(f"Updating quotation: {quotation_id}")
    
    try:
        # First check if quotation exists
        quotations = _cached_odoo_call(
            'sale.order', 'search_read',
            [[['id', '=', quotation_id]]],
            {'fields': ['id', 'name', 'state'], 'limit': 1}
        )
        
        if not quotations:
            return json.dumps({
                "error": "Quotation not found",
                "quotation_id": quotation_id
            }, indent=2, ensure_ascii=False)
        
        quotation = quotations[0]
        
        # Check if quotation is in editable state
        if quotation.get('state') not in ['draft', 'sent']:
            return json.dumps({
                "error": "Cannot modify quotation",
                "reason": f"Quotation is in '{quotation.get('state')}' state. Only 'draft' and 'sent' quotations can be modified.",
                "quotation_id": quotation_id,
                "quotation_name": quotation.get('name')
            }, indent=2, ensure_ascii=False)
        
        # Prepare update data for header
        update_data = {}
        
        if partner_id is not None:
            update_data['partner_id'] = partner_id
        if partner_invoice_id is not None:
            update_data['partner_invoice_id'] = partner_invoice_id
        if partner_shipping_id is not None:
            update_data['partner_shipping_id'] = partner_shipping_id
        if validity_date is not None:
            update_data['validity_date'] = validity_date
        if date_order is not None:
            update_data['date_order'] = date_order
        if note is not None:
            update_data['note'] = note
        if payment_term_id is not None:
            update_data['payment_term_id'] = payment_term_id
        if user_id is not None:
            update_data['user_id'] = user_id
        if team_id is not None:
            update_data['team_id'] = team_id
        if client_order_ref is not None:
            update_data['client_order_ref'] = client_order_ref
        if fiscal_position_id is not None:
            update_data['fiscal_position_id'] = fiscal_position_id
        
        # Update quotation header if there's data to update
        if update_data:
            odoo.execute_kw(
                'sale.order', 'write',
                [[quotation_id], update_data]
            )
            logger.info(f"Updated quotation header: {update_data}")
        
        # Handle line updates
        line_results = []
        if update_lines:
            for line_update in update_lines:
                action = line_update.get('action', 'update')
                
                if action == 'delete' and line_update.get('line_id'):
                    # Delete line
                    try:
                        odoo.execute_kw(
                            'sale.order.line', 'unlink',
                            [[line_update['line_id']]]
                        )
                        line_results.append({
                            'action': 'deleted',
                            'line_id': line_update['line_id'],
                            'status': 'success'
                        })
                    except Exception as e:
                        line_results.append({
                            'action': 'delete',
                            'line_id': line_update['line_id'],
                            'status': 'error',
                            'error': str(e)
                        })
                        
                elif action == 'create':
                    # Create new line
                    line_data = {
                        'order_id': quotation_id,
                        'product_id': line_update.get('product_id'),
                        'name': line_update.get('name', ''),
                        'product_uom_qty': line_update.get('product_uom_qty', 1),
                        'price_unit': line_update.get('price_unit', 0),
                    }
                    
                    if 'discount' in line_update:
                        line_data['discount'] = line_update['discount']
                    if 'tax_id' in line_update:
                        line_data['tax_id'] = [(6, 0, line_update['tax_id'])]
                    
                    try:
                        new_line_id = odoo.execute_kw(
                            'sale.order.line', 'create',
                            [line_data]
                        )
                        line_results.append({
                            'action': 'created',
                            'line_id': new_line_id,
                            'status': 'success'
                        })
                    except Exception as e:
                        line_results.append({
                            'action': 'create',
                            'status': 'error',
                            'error': str(e)
                        })
                        
                elif action == 'update' and line_update.get('line_id'):
                    # Update existing line
                    line_data = {}
                    
                    if 'product_id' in line_update:
                        line_data['product_id'] = line_update['product_id']
                    if 'name' in line_update:
                        line_data['name'] = line_update['name']
                    if 'product_uom_qty' in line_update:
                        line_data['product_uom_qty'] = line_update['product_uom_qty']
                    if 'price_unit' in line_update:
                        line_data['price_unit'] = line_update['price_unit']
                    if 'discount' in line_update:
                        line_data['discount'] = line_update['discount']
                    if 'tax_id' in line_update:
                        line_data['tax_id'] = [(6, 0, line_update['tax_id'])]
                    
                    if line_data:
                        try:
                            odoo.execute_kw(
                                'sale.order.line', 'write',
                                [[line_update['line_id']], line_data]
                            )
                            line_results.append({
                                'action': 'updated',
                                'line_id': line_update['line_id'],
                                'status': 'success',
                                'updated_fields': list(line_data.keys())
                            })
                        except Exception as e:
                            line_results.append({
                                'action': 'update',
                                'line_id': line_update['line_id'],
                                'status': 'error',
                                'error': str(e)
                            })
        
        # Clear cache
        cache.clear()
        
        # Get updated quotation details
        updated_quote = odoo.execute_kw(
            'sale.order', 'read', [quotation_id],
            {}
        )
        
        if updated_quote:
            result = {
                "status": "success",
                "quotation": {
                    "id": quotation_id,
                    "name": updated_quote[0].get('name'),
                    "state": updated_quote[0].get('state'),
                    "partner_id": updated_quote[0].get('partner_id'),
                    "amount_total": updated_quote[0].get('amount_total'),
                    "url": _generate_quotation_url(quotation_id)
                },
                "updates": {
                    "header_fields_updated": list(update_data.keys()) if update_data else [],
                    "lines_updated": line_results
                },
                "message": f"Successfully updated quotation {updated_quote[0].get('name')}"
            }
            
            return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
        else:
            return json.dumps({
                "status": "partial_success",
                "message": "Updates applied but could not retrieve final quotation state",
                "updates": {
                    "header_fields_updated": list(update_data.keys()) if update_data else [],
                    "lines_updated": line_results
                }
            }, indent=2, ensure_ascii=False)
            
    except Exception as e:
        logger.error(f"Error updating quotation: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# @mcp.tool()  # Disabled to reduce tool count
def update_quotation_lines(quotation_id: int, line_updates: List[Dict]) -> str:
    """Update, create or delete quotation lines
    
    v1.5.5: Dedicated function for managing quotation lines
    
    Args:
        quotation_id: ID of the quotation (required)
        line_updates: List of line operations (required)
            Each dict must contain:
            - action: 'create', 'update', or 'delete'
            - For 'update' and 'delete': line_id (required)
            - For 'create' and 'update': 
                - product_id: Product ID
                - name: Line description
                - product_uom_qty: Quantity
                - price_unit: Unit price
                - discount: Discount percentage (optional)
                - sequence: Line sequence (optional)
    
    Returns:
        JSON string with update results
        
    Example:
    [
        {"action": "update", "line_id": 123, "product_uom_qty": 5, "price_unit": 100},
        {"action": "create", "product_id": 456, "name": "New Product", "product_uom_qty": 2, "price_unit": 50},
        {"action": "delete", "line_id": 789}
    ]
    """
    logger.info(f"Updating quotation lines for: {quotation_id}")
    
    try:
        # Verify quotation exists and is editable
        quotations = _cached_odoo_call(
            'sale.order', 'search_read',
            [[['id', '=', quotation_id]]],
            {'fields': ['id', 'name', 'state'], 'limit': 1}
        )
        
        if not quotations:
            return json.dumps({
                "error": "Quotation not found",
                "quotation_id": quotation_id
            }, indent=2, ensure_ascii=False)
        
        quotation = quotations[0]
        
        if quotation.get('state') not in ['draft', 'sent']:
            return json.dumps({
                "error": "Cannot modify quotation lines",
                "reason": f"Quotation is in '{quotation.get('state')}' state",
                "quotation_id": quotation_id
            }, indent=2, ensure_ascii=False)
        
        # Process line updates
        results = []
        for line_update in line_updates:
            action = line_update.get('action')
            
            if action == 'delete':
                line_id = line_update.get('line_id')
                if not line_id:
                    results.append({
                        'action': 'delete',
                        'status': 'error',
                        'error': 'line_id is required for delete action'
                    })
                    continue
                    
                try:
                    odoo.execute_kw(
                        'sale.order.line', 'unlink',
                        [[line_id]]
                    )
                    results.append({
                        'action': 'deleted',
                        'line_id': line_id,
                        'status': 'success'
                    })
                except Exception as e:
                    results.append({
                        'action': 'delete',
                        'line_id': line_id,
                        'status': 'error',
                        'error': str(e)
                    })
                    
            elif action == 'create':
                line_data = {
                    'order_id': quotation_id,
                    'product_id': line_update.get('product_id'),
                    'name': line_update.get('name', ''),
                    'product_uom_qty': line_update.get('product_uom_qty', 1),
                    'price_unit': line_update.get('price_unit', 0),
                }
                
                if 'discount' in line_update:
                    line_data['discount'] = line_update['discount']
                if 'sequence' in line_update:
                    line_data['sequence'] = line_update['sequence']
                
                try:
                    new_line_id = odoo.execute_kw(
                        'sale.order.line', 'create',
                        [line_data]
                    )
                    results.append({
                        'action': 'created',
                        'line_id': new_line_id,
                        'status': 'success'
                    })
                except Exception as e:
                    results.append({
                        'action': 'create',
                        'status': 'error',
                        'error': str(e),
                        'data': line_data
                    })
                    
            elif action == 'update':
                line_id = line_update.get('line_id')
                if not line_id:
                    results.append({
                        'action': 'update',
                        'status': 'error',
                        'error': 'line_id is required for update action'
                    })
                    continue
                
                line_data = {}
                if 'product_id' in line_update:
                    line_data['product_id'] = line_update['product_id']
                if 'name' in line_update:
                    line_data['name'] = line_update['name']
                if 'product_uom_qty' in line_update:
                    line_data['product_uom_qty'] = line_update['product_uom_qty']
                if 'price_unit' in line_update:
                    line_data['price_unit'] = line_update['price_unit']
                if 'discount' in line_update:
                    line_data['discount'] = line_update['discount']
                if 'sequence' in line_update:
                    line_data['sequence'] = line_update['sequence']
                
                if line_data:
                    try:
                        odoo.execute_kw(
                            'sale.order.line', 'write',
                            [[line_id], line_data]
                        )
                        results.append({
                            'action': 'updated',
                            'line_id': line_id,
                            'status': 'success',
                            'updated_fields': list(line_data.keys())
                        })
                    except Exception as e:
                        results.append({
                            'action': 'update',
                            'line_id': line_id,
                            'status': 'error',
                            'error': str(e)
                        })
                else:
                    results.append({
                        'action': 'update',
                        'line_id': line_id,
                        'status': 'skipped',
                        'reason': 'No fields to update'
                    })
                    
            else:
                results.append({
                    'action': action,
                    'status': 'error',
                    'error': f"Unknown action: {action}. Use 'create', 'update', or 'delete'"
                })
        
        # Clear cache
        cache.clear()
        
        # Get updated quotation totals
        updated_quote = odoo.execute_kw(
            'sale.order', 'read', [quotation_id],
            {'fields': ['name', 'amount_untaxed', 'amount_tax', 'amount_total']}
        )
        
        if updated_quote:
            summary = {
                "quotation_id": quotation_id,
                "quotation_name": updated_quote[0].get('name'),
                "new_totals": {
                    "untaxed": updated_quote[0].get('amount_untaxed', 0),
                    "tax": updated_quote[0].get('amount_tax', 0),
                    "total": updated_quote[0].get('amount_total', 0)
                }
            }
        else:
            summary = {"quotation_id": quotation_id}
        
        # Count results
        success_count = len([r for r in results if r['status'] == 'success'])
        error_count = len([r for r in results if r['status'] == 'error'])
        
        return json.dumps({
            "status": "completed",
            "summary": summary,
            "statistics": {
                "total_operations": len(results),
                "successful": success_count,
                "errors": error_count
            },
            "results": results,
            "message": f"Processed {len(results)} line operations: {success_count} successful, {error_count} errors"
        }, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
        
    except Exception as e:
        logger.error(f"Error updating quotation lines: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

# ───────────────────────── Cache Management ─────────────────────────

# @mcp.tool()  # Disabled - debug tool
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

# @mcp.tool()  # Disabled - debug tool
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

def print_startup_info():
    """Print startup information and available features"""
    logger.info("=" * 80)
    logger.info(f"Odoo FastMCP Server v{__version__} - Multi-language Support - Tested on Odoo 13 Community Edition")
    logger.info(f"Author: {__author__}")
    logger.info("=" * 80)
    logger.info("Configuration Methods:")
    logger.info("  ✓ Claude Desktop MCP config (recommended)")
    logger.info("  ✓ Environment variables (fallback)")
    logger.info("=" * 80)
    logger.info("Core Features:")
    logger.info("  ✓ Complete quotation management with all fields")
    logger.info("  ✓ Complete purchase order management")
    logger.info("  ✓ Complete delivery order management")
    logger.info("  ✓ Direct URL links to all record pages")
    logger.info("  ✓ Multi-language support (English/Chinese)")
    logger.info("  ✓ Multi-currency support with proper currency display")
    logger.info("  ✓ Enhanced contact/customer/supplier management")
    logger.info("  ✓ Comprehensive search and filtering with pagination")
    logger.info("  ✓ Intelligent caching with configurable TTL")
    logger.info("=" * 80)
    logger.info(f"Configuration: Cache TTL={config.CACHE_TTL}s, Timeout={config.TIMEOUT}s")
    logger.info(f"Base URL for links: {config.ODOO_URL}")
    logger.info("=" * 80)


if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description='Odoo MCP Server - supports stdio and streamable-http transports',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with stdio (default, for Claude Desktop)
  python mcp_odoo.py

  # Run with streamable-http (for MCPO/OpenAI gateway)
  python mcp_odoo.py --transport streamable-http --port 8001

  # Run HTTP on custom host/port
  python mcp_odoo.py --transport streamable-http --host 0.0.0.0 --port 9000
        """
    )
    parser.add_argument(
        '--transport', '-t',
        choices=['stdio', 'streamable-http'],
        default='stdio',
        help='Transport mode: stdio (default) or streamable-http'
    )
    parser.add_argument(
        '--host', '-H',
        default='127.0.0.1',
        help='Host to bind for streamable-http (default: 127.0.0.1)'
    )
    parser.add_argument(
        '--port', '-p',
        type=int,
        default=8001,
        help='Port to bind for streamable-http (default: 8001)'
    )

    args = parser.parse_args()

    # Print startup info
    print_startup_info()

    # Run with selected transport
    if args.transport == 'stdio':
        logger.info("Transport: stdio (for Claude Desktop)")
        logger.info("Ready to serve MCP requests!")
        logger.info("=" * 80)
        mcp.run()
    else:
        logger.info(f"Transport: streamable-http")
        logger.info(f"Listening on: http://{args.host}:{args.port}")
        logger.info("Ready to serve MCP requests!")
        logger.info("=" * 80)
        mcp.run(transport='streamable-http', host=args.host, port=args.port)
