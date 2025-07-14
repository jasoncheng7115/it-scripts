#!/usr/bin/env python3
"""
MCP server for Odoo API – v1.2 Complete Implementation with Enhanced Partner Management and URL Generation
=============================================================================================================
Author: Jason Cheng (Jason Tools)
Created: 2025-07-14
Updated: 2025-07-14
Version: 1.2.0
License: MIT

FastMCP-based Odoo integration with comprehensive quotation, sales, purchase,
and contact management capabilities with multi-language and multi-currency support.

Features:
- Complete quotation management with all fields
- Direct URL links to quotation pages in Odoo (NEW in v1.2)
- Multi-language support (English/Chinese) based on customer settings
- Multi-currency support with proper currency display
- Enhanced contact/customer/supplier management with proper filtering
- Purchase order handling
- Invoice management (sales/purchase)
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
        "ODOO_PASSWORD": "your_password"
      }
    }
  }
}

Option 2 - Environment Variables:
ODOO_URL - Odoo base URL (e.g., http://localhost:8069)
ODOO_DATABASE - Odoo database name
ODOO_USERNAME - Odoo username
ODOO_PASSWORD - Odoo password
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
import xmlrpc.client
from typing import Optional, Dict, Any, List, Union
from datetime import datetime, timedelta
from functools import wraps
import logging
import hashlib
import re

from mcp.server.fastmcp import FastMCP

# Version information
__version__ = "1.2.0"
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
            import json
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
        
        self.validate()
    
    def validate(self):
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
        
        self._connect()
        self._detect_version()
        self._initialize_field_cache()
    
    def _connect(self):
        """Establish connection to Odoo"""
        try:
            # Authentication
            common = xmlrpc.client.ServerProxy(f'{self.url}/xmlrpc/2/common')
            self.uid = common.authenticate(self.db, self.username, self.password, {})
            
            if not self.uid:
                raise Exception("Authentication failed")
            
            # Model connection
            self.models = xmlrpc.client.ServerProxy(f'{self.url}/xmlrpc/2/object')
            self.connected = True
            
            logger.info(f"Successfully connected to Odoo as UID: {self.uid}")
            
        except Exception as e:
            logger.error(f"Failed to connect to Odoo: {e}")
            raise e
    
    def _detect_version(self):
        """Detect Odoo version and capabilities"""
        try:
            common = xmlrpc.client.ServerProxy(f'{self.url}/xmlrpc/2/common')
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
                        self.version_info['major_version'] = 13  # Default assumption
                else:
                    self.version_info['major_version'] = 13
            
            logger.info(f"Detected Odoo version: {self.version_info['server_version']} (v{self.version_info['major_version']})")
            
        except Exception as e:
            logger.warning(f"Could not detect Odoo version: {e}")
            self.version_info = {
                'server_version': 'Unknown',
                'major_version': 13,  # Safe default
                'detection_error': str(e)
            }
    
    def _initialize_field_cache(self):
        """Initialize field cache for critical models"""
        critical_models = ['sale.order', 'sale.order.line', 'res.partner', 'purchase.order', 'account.move']
        
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
            }
        }
        
        # Get requested field set
        model_fields = field_sets.get(model_name, {})
        requested_fields = model_fields.get(field_set_name, model_fields.get('basic', []))
        
        # Filter by available fields
        return self.get_available_fields(model_name, requested_fields)
    
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

# Global Odoo connection
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
    """Cached Odoo API call"""
    
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

def _generate_quotation_url(quotation_id: int) -> str:
    """Generate URL to access quotation in Odoo web interface
    
    Args:
        quotation_id: The ID of the quotation
        
    Returns:
        Complete URL to the quotation page
    """
    base_url = config.ODOO_URL
    database = config.DATABASE
    
    # Standard Odoo web client URL pattern for sale.order
    url = f"{base_url}/web#id={quotation_id}&model=sale.order&view_type=form"
    
    # Add database parameter if needed (some Odoo instances require it)
    # url += f"&db={database}"
    
    return url

def _generate_partner_url(partner_id: int) -> str:
    """Generate URL to access partner in Odoo web interface
    
    Args:
        partner_id: The ID of the partner
        
    Returns:
        Complete URL to the partner page
    """
    base_url = config.ODOO_URL
    database = config.DATABASE
    
    # Standard Odoo web client URL pattern for res.partner
    url = f"{base_url}/web#id={partner_id}&model=res.partner&view_type=form"
    
    return url

# ───────────────────────── Core MCP Tools ─────────────────────────

@mcp.tool()
def get_odoo_system_info() -> str:
    """Get Odoo system information including version and capabilities
    
    Returns:
        JSON string with Odoo system information
    """
    logger.info("Getting Odoo system information")
    
    try:
        result = {
            "mcp_server_info": {
                "name": "Odoo MCP Server",
                "version": __version__,
                "author": __author__
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
                "partner_url_pattern": f"{config.ODOO_URL}/web#id={{ID}}&model=res.partner&view_type=form"
            },
            "timestamp": datetime.now().isoformat()
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
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

@mcp.tool()
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
                "sample_partner_url": _generate_partner_url(1)
            }
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False, cls=DateTimeEncoder)
    except Exception as e:
        return json.dumps({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }, indent=2, ensure_ascii=False)

@mcp.tool()
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
                     state: Optional[str] = None, date_from: Optional[str] = None,
                     date_to: Optional[str] = None, product_name: Optional[str] = None,
                     description_contains: Optional[str] = None, global_search: Optional[str] = None,
                     limit: int = 10) -> str:
    """Search quotations with complete field information and language/currency support
    
    Args:
        partner_name: Customer name filter (optional)
        quotation_number: Quotation number filter (optional)
        state: State filter (draft, sent, sale, done, cancel) (optional)
        date_from: Start date filter (YYYY-MM-DD) (optional)
        date_to: End date filter (YYYY-MM-DD) (optional)
        product_name: Product/service name filter (searches in quotation lines) (optional)
        description_contains: Search in quotation notes/descriptions (optional)
        global_search: Search across ALL quotation fields including client_order_ref, origin, etc. (optional)
        limit: Maximum number of quotations to return (default: 10)
    
    Returns:
        JSON string with quotation data including customer language/currency settings and direct URLs
    """
    logger.info(f"Searching quotations: partner={partner_name}, product={product_name}, global={global_search}")
    
    try:
        # Build domain filters
        domain = []
        
        if partner_name:
            domain.append(['partner_id.name', 'ilike', partner_name])
        if quotation_number:
            domain.append(['name', 'ilike', quotation_number])
        if state:
            domain.append(['state', '=', state])
        if date_from:
            domain.append(['date_order', '>=', date_from])
        if date_to:
            domain.append(['date_order', '<=', date_to])
        if description_contains:
            domain.append(['note', 'ilike', description_contains])
        
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
                    [['partner_id.name', 'ilike', global_search]]
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
        
        # If searching by product/service name, we need to search in quotation lines first
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
        
        # Combine all found quotation IDs
        all_found_ids = []
        if global_search:
            all_found_ids.extend(quotation_ids_from_global)
            all_found_ids.extend(quotation_ids_from_lines)
            all_found_ids = list(set(all_found_ids))  # Remove duplicates
        elif product_name:
            all_found_ids = quotation_ids_from_lines
        
        # Add ID filter to domain if we found specific quotations
        if all_found_ids:
            domain.append(['id', 'in', all_found_ids])
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
        
        # Get quotations using version-compatible fields
        available_fields = odoo.get_version_compatible_fields('sale.order', 'standard')
        
        # Increase limit if we're doing a product/global search to ensure we get all relevant results
        search_limit = min(limit * 10, 1000) if (product_name or global_search) else limit
        
        quotations = _cached_odoo_call(
            'sale.order', 'search_read', [domain],
            {
                'fields': available_fields,
                'limit': search_limit,
                'order': 'date_order desc'
            }
        )
        
        # If we searched by product/global and got more results than requested, limit them
        if (product_name or global_search) and len(quotations) > limit:
            quotations = quotations[:limit]
        
        # Enrich each quotation with customer language/currency details, line items, and URLs
        enriched_quotations = []
        
        for quote in quotations:
            enriched_quote = quote.copy()
            
            # Generate direct URL to quotation
            enriched_quote['odoo_url'] = _generate_quotation_url(quote['id'])
            enriched_quote['url_description'] = f"點擊直接開啟報價單 {quote.get('name', quote['id'])}"
            
            # Get customer details
            if quote.get('partner_id'):
                partner_details = _get_partner_details(quote['partner_id'][0])
                enriched_quote['customer_details'] = partner_details
                
                # Add customer URL
                enriched_quote['customer_url'] = _generate_partner_url(quote['partner_id'][0])
                enriched_quote['customer_url_description'] = f"點擊直接開啟客戶 {quote['partner_id'][1]}"
                
                # Determine display language
                is_english = _is_english_customer(partner_details.get('lang', ''))
                enriched_quote['display_language'] = 'en' if is_english else 'zh'
                
                # Get currency information
                currency_code = _get_currency_code(quote.get('currency_id', []))
                enriched_quote['currency_code'] = currency_code
                
                # Format amounts with currency
                amount_fields = ['amount_untaxed', 'amount_tax', 'amount_total']
                for field in amount_fields:
                    if quote.get(field) is not None:
                        enriched_quote[f'{field}_formatted'] = f"{quote[field]} {currency_code}"
            
            # Get quotation lines for service/product details (always include for better analysis)
            try:
                line_fields = odoo.get_version_compatible_fields('sale.order.line', 'standard')
                quote_lines = _cached_odoo_call(
                    'sale.order.line', 'search_read',
                    [[['order_id', '=', quote['id']]]],
                    {'fields': line_fields, 'order': 'sequence'}
                )
                
                # Format line information
                services_products = []
                for line in quote_lines:
                    line_info = {
                        'sequence': line.get('sequence', 0),
                        'product_name': line.get('product_id', [None, 'Service'])[1] if line.get('product_id') else 'Service',
                        'description': line.get('name', ''),
                        'quantity': line.get('product_uom_qty', 1),
                        'unit_price': line.get('price_unit', 0),
                        'subtotal': line.get('price_subtotal', 0)
                    }
                    services_products.append(line_info)
                
                enriched_quote['services_products'] = services_products
                enriched_quote['line_count'] = len(services_products)
                
            except Exception as e:
                logger.warning(f"Failed to get lines for quotation {quote['id']}: {e}")
                enriched_quote['services_products'] = []
                enriched_quote['line_count'] = 0
            
            # Format dates (only include fields that exist)
            date_fields = ['date_order', 'validity_date', 'create_date', 'write_date']
            for field in date_fields:
                if quote.get(field):
                    enriched_quote[f'{field}_formatted'] = _format_datetime(quote[field])
            
            enriched_quotations.append(enriched_quote)
        
        # Calculate summary statistics
        total_found = len(enriched_quotations)
        currency_breakdown = {}
        state_breakdown = {}
        
        for quote in enriched_quotations:
            # Currency statistics
            currency = quote.get('currency_code', 'Unknown')
            currency_breakdown[currency] = currency_breakdown.get(currency, 0) + 1
            
            # State statistics
            state = quote.get('state', 'unknown')
            state_breakdown[state] = state_breakdown.get(state, 0) + 1
        
        # Determine search scope message
        search_scope_parts = []
        if global_search:
            search_scope_parts.append(f"Global search for '{global_search}' across all quotation fields and line items")
        if product_name:
            search_scope_parts.append(f"Product/service search for '{product_name}'")
        if description_contains:
            search_scope_parts.append(f"Description search for '{description_contains}'")
        if not any([global_search, product_name, description_contains]):
            search_scope_parts.append("Standard quotation search")
        
        result = {
            "quotations": enriched_quotations,
            "summary": {
                "total_found": total_found,
                "currency_breakdown": currency_breakdown,
                "state_breakdown": state_breakdown,
                "search_scope": " + ".join(search_scope_parts),
                "urls_included": True,
                "url_base": config.ODOO_URL
            },
            "search_fields_covered": {
                "quotation_header": [
                    "name (quotation number)",
                    "note (description)", 
                    "client_order_ref (customer order ref)",
                    "origin (source document)",
                    "partner_id.name (customer name)",
                    "user_id.name (salesperson)"
                ] if global_search else ["Limited to specific filters"],
                "quotation_lines": [
                    "product_id.name (product name)",
                    "name (line description/service details)"
                ] if (product_name or global_search) else ["Not searched"]
            },
            "query_info": {
                "partner_name_filter": partner_name,
                "quotation_number_filter": quotation_number,
                "state_filter": state,
                "date_from": date_from,
                "date_to": date_to,
                "product_name_filter": product_name,
                "description_filter": description_contains,
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
        logger.error(f"Error searching quotations: {e}")
        return json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

@mcp.tool()
def get_quotation_details(quotation_id: int, include_lines: bool = True) -> str:
    """Get detailed quotation information with line items and customer language settings
    
    Args:
        quotation_id: Quotation ID
        include_lines: Include quotation line items (default: True)
    
    Returns:
        JSON string with complete quotation details including direct URL
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
                
                # Format product information
                if line.get('product_id'):
                    formatted_line['product_name'] = line['product_id'][1]
                
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

# ───────────────────────── Enhanced Contact/Partner Management ─────────────────────────

@mcp.tool()
def search_partners(name: Optional[str] = None, is_customer: Optional[bool] = None,
                   is_supplier: Optional[bool] = None, email: Optional[str] = None,
                   phone: Optional[str] = None, limit: int = 100) -> str:
    """Search contacts/customers/suppliers with complete information
    
    Args:
        name: Contact name filter (optional)
        is_customer: Filter for customers only (optional) - if None, includes all
        is_supplier: Filter for suppliers only (optional) - if None, includes all
        email: Email filter (optional)
        phone: Phone number filter (optional)
        limit: Maximum number of contacts to return (default: 100, 0 = all)
    
    Returns:
        JSON string with contact data including language/currency settings and URLs
    """
    logger.info(f"Searching partners: name={name}, customer={is_customer}, supplier={is_supplier}, limit={limit}")
    
    try:
        # Build domain filters - FIXED: Only add customer/supplier filters when explicitly requested
        domain = []
        
        if name:
            domain.append(['name', 'ilike', name])
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
        
        # Set search kwargs
        search_kwargs = {'fields': partner_fields}
        if limit > 0:
            search_kwargs['limit'] = limit
        
        partners = _cached_odoo_call(
            'res.partner', 'search_read', [domain], search_kwargs
        )
        
        # Enrich partner data with URLs
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

@mcp.tool()
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

@mcp.tool()
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

@mcp.tool()
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
    logger.info(f"Odoo FastMCP Server v{__version__} - Complete Business Management Integration")
    logger.info(f"Author: {__author__}")
    logger.info("=" * 80)
    logger.info("Configuration Methods:")
    logger.info("  ✓ Claude Desktop MCP config (recommended)")
    logger.info("  ✓ Environment variables (fallback)")
    logger.info("=" * 80)
    logger.info("Core Features:")
    logger.info("  ✓ Complete quotation management with all fields")
    logger.info("  ✓ Direct URL links to quotation and partner pages (NEW in v1.2)")
    logger.info("  ✓ Multi-language support (English/Chinese) based on customer settings")
    logger.info("  ✓ Multi-currency support with proper currency display")
    logger.info("  ✓ Enhanced contact/customer/supplier management (FIXED)")
    logger.info("  ✓ Comprehensive partner statistics and analytics")
    logger.info("  ✓ Intelligent caching with configurable TTL")
    logger.info("  ✓ Enhanced error handling and retry logic")
    logger.info("  ✓ Performance monitoring and health checks")
    logger.info("=" * 80)
    logger.info("Available Tools:")
    logger.info("  • get_odoo_system_info() - Odoo system and version information")
    logger.info("  • get_sale_order_fields() - Check available sale.order fields")
    logger.info("  • health_check() - Odoo connectivity and system status")
    logger.info("  • odoo_raw_call() - Raw Odoo API calls")
    logger.info("  • search_quotations() - Search quotations with URLs and language/currency support")
    logger.info("  • get_quotation_details() - Complete quotation details with URLs and line items")
    logger.info("  • search_partners() - Search contacts/customers/suppliers with URLs (FIXED)")
    logger.info("  • get_all_partners() - Get all partners in the system with URLs (ENHANCED)")
    logger.info("  • get_partner_statistics() - Comprehensive partner statistics (NEW)")
    logger.info("  • get_partner_language_currency() - Customer language/currency settings with URL")
    logger.info("  • clear_cache() - Clear internal cache")
    logger.info("  • cache_stats() - Cache statistics")
    logger.info("=" * 80)
    logger.info(f"Configuration: Cache TTL={config.CACHE_TTL}s, Timeout={config.TIMEOUT}s")
    logger.info(f"Max Retries={config.MAX_RETRIES}")
    logger.info(f"Base URL for links: {config.ODOO_URL}")
    logger.info("=" * 80)
    logger.info("New Features in v1.2.0:")
    logger.info("  ✓ Added direct URL links to quotations and partners")
    logger.info("  ✓ URL generation functions for web interface access")
    logger.info("  ✓ Enhanced search results with clickable links")
    logger.info("  ✓ Bilingual URL descriptions (Chinese)")
    logger.info("  ✓ URL information in all relevant API responses")
    logger.info("=" * 80)
    logger.info("URL Patterns:")
    logger.info(f"  • Quotations: {config.ODOO_URL}/web#id={{ID}}&model=sale.order&view_type=form")
    logger.info(f"  • Partners: {config.ODOO_URL}/web#id={{ID}}&model=res.partner&view_type=form")
    logger.info("=" * 80)
    logger.info("MCP Configuration Example:")
    logger.info('  "odoo": {')
    logger.info('    "command": "python",')
    logger.info('    "args": ["/path/to/mcp_odoo.py"],')
    logger.info('    "env": {')
    logger.info('      "ODOO_URL": "http://localhost:8069",')
    logger.info('      "ODOO_DATABASE": "mydb",')
    logger.info('      "ODOO_USERNAME": "admin",')
    logger.info('      "ODOO_PASSWORD": "password"')
    logger.info('    }')
    logger.info('  }')
    logger.info("=" * 80)
    
    mcp.run()
