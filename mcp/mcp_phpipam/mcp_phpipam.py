#!/usr/bin/env python3
"""
MCP Server for phpIPAM API – v2.1
===================================================
Author: Jason Cheng (Jason Tools)
Created: 2025-06-28
Modified: 2026-02-09
License: MIT

FastMCP-based phpIPAM integration with comprehensive IP management operations,
advanced search, and network resource tracking.

Optimized for compatibility with smaller LLMs (e.g. gpt-oss:120b):
- Clear, distinct tool descriptions with usage guidance
- Explicit parameter descriptions in docstring Args
- Consistent page/page_size pagination on every list endpoint
- No redundant/overlapping tools
- Token-efficient plain-text output (pipe-table for lists, key:value for details)
"""

import argparse
import json
import os
import sys
import time
from typing import Optional, Dict, Any, List
from functools import wraps
import logging
import hashlib

import requests
import urllib3
from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("phpipam")


# ---------------------------------------------------------------------------
# Configuration (environment variables only)
# ---------------------------------------------------------------------------
class Config:
    def __init__(self):
        base_url = os.getenv("PHPIPAM_URL")
        if not base_url:
            logger.error("PHPIPAM_URL environment variable not set")
            sys.exit(1)
        if base_url.endswith("/api"):
            base_url = base_url[:-4]
        self.BASE_URL = base_url.rstrip("/")

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

        logger.info(f"phpIPAM API: {self.BASE_URL}/api/{self.APP_ID}")
        logger.info(f"Cache TTL: {self.CACHE_TTL}s | Timeout: {self.TIMEOUT}s | SSL: {self.VERIFY_SSL}")


config = Config()


# ---------------------------------------------------------------------------
# Simple TTL cache
# ---------------------------------------------------------------------------
class SimpleCache:
    def __init__(self, ttl: int = 300):
        self._store: Dict[str, tuple] = {}
        self.ttl = ttl

    def _key(self, raw: str) -> str:
        return hashlib.md5(raw.encode()).hexdigest()

    def get(self, key: str) -> Optional[Any]:
        k = self._key(key)
        if k in self._store:
            data, ts = self._store[k]
            if time.time() - ts < self.ttl:
                return data
            del self._store[k]
        return None

    def set(self, key: str, value: Any):
        self._store[self._key(key)] = (value, time.time())

    def clear(self):
        self._store.clear()

    def stats(self) -> Dict[str, int]:
        now = time.time()
        active = sum(1 for _, (_, ts) in self._store.items() if now - ts < self.ttl)
        return {"total_keys": len(self._store), "active_keys": active, "ttl_seconds": self.ttl}


cache = SimpleCache(config.CACHE_TTL)


# ---------------------------------------------------------------------------
# HTTP session
# ---------------------------------------------------------------------------
session = requests.Session()
session.headers.update({
    "token": config.TOKEN,
    "User-Agent": "mcp-phpipam/2.1",
    "Accept": "application/json",
    "Content-Type": "application/json",
})


# ---------------------------------------------------------------------------
# FastMCP server
# ---------------------------------------------------------------------------
mcp = FastMCP(
    "phpIPAM",
    host=os.getenv("FASTMCP_HOST", "0.0.0.0"),
    port=int(os.getenv("FASTMCP_PORT", "8000")),
)


# ---------------------------------------------------------------------------
# Retry decorator
# ---------------------------------------------------------------------------
def retry_on_failure(max_retries: int = 3, delay: float = 1.0):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exc = e
                    if attempt < max_retries - 1:
                        wait = delay * (2 ** attempt)
                        logger.warning(f"Attempt {attempt + 1} failed: {e}, retry in {wait}s")
                        time.sleep(wait)
            raise last_exc
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Core API helpers
# ---------------------------------------------------------------------------
@retry_on_failure(max_retries=config.MAX_RETRIES)
def _api_request(
    method: str,
    path: str,
    params: Optional[Dict[str, Any]] = None,
    json_body: Optional[Dict[str, Any]] = None,
    use_cache: bool = True,
) -> Any:
    """Low-level phpIPAM API call with cache + retry."""
    url = f"{config.BASE_URL}/api/{config.APP_ID}/{path.lstrip('/')}"
    cache_key = f"{method}:{url}:{json.dumps(params or {}, sort_keys=True)}"

    if use_cache and method.upper() == "GET":
        hit = cache.get(cache_key)
        if hit is not None:
            return hit

    logger.info(f"API {method} {url} params={params}")
    resp = session.request(
        method.upper(), url,
        params=params, json=json_body,
        timeout=config.TIMEOUT, verify=config.VERIFY_SSL,
    )
    resp.raise_for_status()
    body = resp.json()
    data = body.get("data", body) if isinstance(body, dict) else body

    if use_cache and method.upper() == "GET":
        cache.set(cache_key, data)
    return data


def _ensure_list(data: Any) -> List:
    """Normalise API response to a list."""
    if isinstance(data, list):
        return data
    return [data] if data else []


# ---------------------------------------------------------------------------
# Column definitions for LIST views (pipe-table)
#   (api_field_key, display_header)
# ---------------------------------------------------------------------------
COLS_SECTION = [("id", "ID"), ("name", "Name"), ("description", "Desc"), ("masterSection", "Parent")]
COLS_SUBNET = [("id", "ID"), ("subnet", "Subnet"), ("mask", "Mask"), ("description", "Desc"), ("sectionId", "SectID"), ("vlanId", "VLAN")]
COLS_ADDRESS = [("id", "ID"), ("ip", "IP"), ("hostname", "Hostname"), ("description", "Desc"), ("mac", "MAC"), ("tag", "Tag")]
COLS_VLAN = [("id", "ID"), ("number", "Number"), ("name", "Name"), ("description", "Desc")]
COLS_DEVICE = [("id", "ID"), ("hostname", "Hostname"), ("ip_addr", "IP"), ("type", "Type"), ("vendor", "Vendor"), ("model", "Model")]
COLS_RACK = [("id", "ID"), ("name", "Name"), ("size", "Size(U)"), ("location", "Location"), ("description", "Desc")]
COLS_RACK_DEVICE = [("hostname", "Hostname"), ("type", "Type"), ("start_u", "StartU"), ("size_u", "SizeU"), ("side", "Side")]
COLS_FOLDER = [("id", "ID"), ("name", "Name"), ("description", "Desc")]
COLS_TAG = [("id", "ID"), ("type", "Type"), ("showtag", "Show"), ("bgcolor", "Color")]

# ---------------------------------------------------------------------------
# Field definitions for DETAIL views (key:value, allowlist only)
#   (api_field_key, display_label)
# ---------------------------------------------------------------------------
DETAIL_SECTION = [
    ("id", "id"), ("name", "name"), ("description", "description"),
    ("masterSection", "parentSection"), ("subnetNum", "subnetCount"),
    ("showVLAN", "showVLAN"), ("showVRF", "showVRF"),
]
DETAIL_SUBNET = [
    ("id", "id"), ("subnet", "subnet"), ("mask", "mask"),
    ("description", "description"), ("sectionId", "sectionId"),
    ("vlanId", "vlanId"), ("vrfId", "vrfId"), ("gateway", "gateway"),
    ("nameserverId", "nameserverId"), ("location", "location"),
    ("isPool", "isPool"), ("isFull", "isFull"), ("tag", "tag"),
]
DETAIL_VLAN = [
    ("id", "id"), ("number", "number"), ("name", "name"),
    ("description", "description"), ("domainId", "domainId"),
]
DETAIL_DEVICE = [
    ("id", "id"), ("hostname", "hostname"), ("ip_addr", "ip"),
    ("type", "type"), ("vendor", "vendor"), ("model", "model"),
    ("description", "description"), ("location", "location"),
    ("rack", "rackId"), ("rack_start", "rackStartU"), ("rack_size", "rackSizeU"),
]
DETAIL_FOLDER = [
    ("id", "id"), ("name", "name"), ("description", "description"),
]


# ---------------------------------------------------------------------------
# Text formatting helpers  (token-efficient output)
# ---------------------------------------------------------------------------
_MAX_COL_W = 30   # truncate list-table values to save tokens


def _v(val: Any) -> str:
    """Format a single value; None/empty → '-'."""
    if val is None or val == "" or val == "None":
        return "-"
    return str(val).strip()


def _tv(val: Any) -> str:
    """Format + truncate a value for list tables."""
    s = _v(val)
    if len(s) > _MAX_COL_W:
        return s[: _MAX_COL_W - 2] + ".."
    return s


def _fmt_table(records: List[Dict], cols: List[tuple]) -> str:
    """Render a list of dicts as a compact pipe-separated table."""
    if not records:
        return "(empty)"
    header = "|".join(h for _, h in cols)
    rows = [header]
    for r in records:
        rows.append("|".join(_tv(r.get(k)) for k, _ in cols))
    return "\n".join(rows)


# Maximum number of results returned by search tools to prevent context overflow
_MAX_SEARCH_RESULTS = 50


def _fmt_page(path: str, page: int, page_size: int, cols: List[tuple]) -> str:
    """Fetch one page and return as pipe-table + pagination footer."""
    page = max(1, page)
    page_size = max(1, min(page_size, 500))
    offset = (page - 1) * page_size

    data = _api_request("GET", path, params={"offset": offset, "limit": page_size})
    items = _ensure_list(data) if data else []

    table = _fmt_table(items, cols)
    parts = [f"page {page}", f"{len(items)} items"]
    if len(items) >= page_size:
        parts.append("has_more")
    return f"{table}\n[{', '.join(parts)}]"


def _fmt_detail(record: Dict, fields: List[tuple]) -> str:
    """Render a single record using an allowlist of fields (key:value lines).
    Only shows fields in the allowlist that have non-empty values.
    """
    if not record or not isinstance(record, dict):
        return str(record) if record else "(empty)"
    lines = []
    for key, label in fields:
        fv = _v(record.get(key))
        if fv != "-":
            lines.append(f"{label}: {fv}")
    return "\n".join(lines)


def _fmt_record(record: Dict) -> str:
    """Render a dict as key:value lines. Fallback for resources without a DETAIL_ spec."""
    if not record or not isinstance(record, dict):
        return str(record) if record else "(empty)"
    skip = {"editDate", "editedBy", "lastSeen", "dirtyFields", "customer_id",
            "masterSubnetId", "permissions", "allowRequests", "showName",
            "showVLAN", "showVRF", "showSupernetOnly", "pingSubnet",
            "discoverSubnet", "resolveDNS", "DNSrecursive", "DNSrecords",
            "scanAgent", "linked_subnet", "firewallAddressObject", "threshold",
            "calculation", "device"}
    lines = []
    for k, v in record.items():
        if k in skip:
            continue
        fv = _v(v)
        if fv != "-":
            lines.append(f"{k}: {fv}")
    return "\n".join(lines)


def _fmt_search(records: List[Dict], cols: List[tuple], term: str) -> str:
    """Render search results as pipe-table + match count. Caps at _MAX_SEARCH_RESULTS."""
    total = len(records)
    truncated = total > _MAX_SEARCH_RESULTS
    if truncated:
        records = records[:_MAX_SEARCH_RESULTS]
    table = _fmt_table(records, cols)
    footer = f"[{total} matches"
    if truncated:
        footer += f", showing first {_MAX_SEARCH_RESULTS}"
    footer += "]"
    return f"{table}\n{footer}"


def _compress_ranges(nums: List[int]) -> str:
    """Compress a sorted list of ints into range notation: [1,2,3,5,7,8,9] → '1-3, 5, 7-9'."""
    if not nums:
        return "(none)"
    ranges = []
    start = prev = nums[0]
    for n in nums[1:]:
        if n == prev + 1:
            prev = n
        else:
            ranges.append(f"{start}-{prev}" if prev > start else str(start))
            start = prev = n
    ranges.append(f"{start}-{prev}" if prev > start else str(start))
    return ", ".join(ranges)


# ===================================================================
# SECTION TOOLS
# ===================================================================

@mcp.tool()
def list_sections(page: int = 1, page_size: int = 50) -> str:
    """List all IP address management sections.
    Sections are top-level containers that group subnets.
    Use this first to find the section_id needed by list_subnets.
    Only fetch the next page if the user explicitly asks for more results.

    Args:
        page: Page number starting from 1. Default is 1.
        page_size: Number of records per page, between 1 and 500. Default is 50.
    """
    try:
        return _fmt_page("sections/", page, page_size, COLS_SECTION)
    except Exception as e:
        return f"ERROR: {e}"


@mcp.tool()
def get_section(section_id: int) -> str:
    """Get details of one section by its ID.
    Returns section name, description, permissions, and subnet count.

    Args:
        section_id: The numeric ID of the section (for example 1, 2, 3).
    """
    try:
        return _fmt_detail(_api_request("GET", f"sections/{section_id}/"), DETAIL_SECTION)
    except Exception as e:
        return f"ERROR: {e}"


# ===================================================================
# SUBNET TOOLS
# ===================================================================

@mcp.tool()
def list_subnets(section_id: int = 0, page: int = 1, page_size: int = 50) -> str:
    """List subnets. Can list all subnets or filter by a specific section.
    Returns subnet CIDR, description, VLAN ID, and gateway for each subnet.
    Set section_id to 0 (or omit it) to list subnets from ALL sections.
    Only fetch the next page if the user explicitly asks for more results.

    Args:
        section_id: Filter by section. Use 0 to list all subnets. Default is 0.
        page: Page number starting from 1. Default is 1.
        page_size: Number of records per page, between 1 and 500. Default is 50.
    """
    try:
        path = f"sections/{section_id}/subnets/" if section_id > 0 else "subnets/"
        return _fmt_page(path, page, page_size, COLS_SUBNET)
    except Exception as e:
        return f"ERROR: {e}"


@mcp.tool()
def get_subnet(subnet_id: int) -> str:
    """Get full details of one subnet by its ID.
    Returns CIDR, mask, description, gateway, VLAN, nameservers, and permissions.

    Args:
        subnet_id: The numeric ID of the subnet.
    """
    try:
        return _fmt_detail(_api_request("GET", f"subnets/{subnet_id}/"), DETAIL_SUBNET)
    except Exception as e:
        return f"ERROR: {e}"


@mcp.tool()
def get_subnet_usage(subnet_id: int) -> str:
    """Get IP address usage statistics for one subnet (used/free/total counts).
    Use this when you only need usage numbers, not a free IP.
    To get usage AND the next available IP, use find_free_ip instead.

    Args:
        subnet_id: The numeric ID of the subnet.
    """
    try:
        usage = _api_request("GET", f"subnets/{subnet_id}/usage/")
        if isinstance(usage, dict):
            parts = [f"subnet_id: {subnet_id}"]
            for k in ("used", "maxhosts", "freehosts", "freehosts_percent", "Used_percent"):
                if k in usage:
                    parts.append(f"{k}: {usage[k]}")
            return "\n".join(parts)
        return _fmt_record(usage)
    except Exception as e:
        return f"ERROR: {e}"


@mcp.tool()
def find_free_ip(subnet_id: int = 0, cidr: str = "") -> str:
    """Find the next available IP address in a subnet. USE THIS when the user asks for a free/available/unused IP.
    You can specify a subnet by its ID or by CIDR. Returns usage stats + next free IP.
    - By ID:   find_free_ip(subnet_id=5)
    - By CIDR: find_free_ip(cidr="192.168.1.0/24")
    - Partial: find_free_ip(cidr="10.0")  matches all 10.0.x.x subnets
    You must provide at least one of subnet_id or cidr.

    Args:
        subnet_id: The numeric subnet ID to check. Use 0 to search by cidr instead. Default is 0.
        cidr: Network address or CIDR to search, such as "192.168.1.0/24" or "10.0". Default is empty.
    """
    try:
        cidr = cidr.strip()

        if subnet_id <= 0 and not cidr:
            return "ERROR: Provide subnet_id or cidr. Example: find_free_ip(subnet_id=5) or find_free_ip(cidr=\"192.168.1.0/24\")"

        # Resolve subnet(s)
        subnets: list = []
        if subnet_id > 0:
            sub = _api_request("GET", f"subnets/{subnet_id}/")
            if sub:
                subnets = [sub] if isinstance(sub, dict) else _ensure_list(sub)
        else:
            data = _api_request("GET", f"subnets/search/{cidr}/")
            subnets = _ensure_list(data)

        if not subnets:
            key = f"subnet_id={subnet_id}" if subnet_id > 0 else f"cidr={cidr}"
            return f"No subnets found for {key}"

        results = []
        for sub in subnets[:_MAX_SEARCH_RESULTS]:
            sid = sub.get("id")
            net = f"{sub.get('subnet')}/{sub.get('mask')}"
            desc = _v(sub.get("description"))

            # Usage stats
            try:
                usage = _api_request("GET", f"subnets/{sid}/usage/")
                used = usage.get("used", "?")
                maxh = usage.get("maxhosts", "?")
                freeh = usage.get("freehosts", "?")
                pct = usage.get("Used_percent", "?")
            except Exception:
                used = maxh = freeh = pct = "?"

            # First free IP
            try:
                free_ip = _api_request("GET", f"subnets/{sid}/first_free/")
            except Exception:
                free_ip = "(full)"

            results.append(
                f"[Subnet {sid}] {net} ({desc})\n"
                f"usage: {used}/{maxh} ({pct}%), {freeh} free\n"
                f"first_free_ip: {free_ip}"
            )

        return "\n\n".join(results) + f"\n[{len(results)} subnets]"
    except Exception as e:
        return f"ERROR: {e}"


@mcp.tool()
def search_subnet(cidr: str) -> str:
    """Search for subnet records by CIDR or network address. Returns subnet ID, CIDR, VLAN, and section.
    Use this to look up subnet details. To find a free IP, use find_free_ip instead.
    Example inputs: "192.168.1.0/24", "10.0.0.0", "172.16".

    Args:
        cidr: The subnet CIDR or network address to search for, such as "192.168.1.0/24".
    """
    try:
        data = _ensure_list(_api_request("GET", f"subnets/search/{cidr}/"))
        return _fmt_search(data, COLS_SUBNET, cidr)
    except Exception as e:
        return f"ERROR: {e}"


@mcp.tool()
def list_subnet_addresses(subnet_id: int, page: int = 1, page_size: int = 50) -> str:
    """List USED IP addresses in a subnet (shows who is using each IP).
    Returns IP, hostname, description, MAC, and status for each assigned address.
    To find a free/available IP, use find_free_ip instead.
    Only fetch the next page if the user explicitly asks for more results.

    Args:
        subnet_id: The numeric ID of the subnet whose addresses you want to list.
        page: Page number starting from 1. Default is 1.
        page_size: Number of records per page, between 1 and 500. Default is 50.
    """
    try:
        return _fmt_page(f"subnets/{subnet_id}/addresses/", page, page_size, COLS_ADDRESS)
    except Exception as e:
        return f"ERROR: {e}"


# ===================================================================
# ADDRESS / SEARCH TOOLS
# ===================================================================

@mcp.tool()
def search_ip(ip_address: str) -> str:
    """Search for a specific IP address across all subnets.
    Returns matching records with hostname, subnet, MAC address, and status.
    Use this when you know the IP but not which subnet it belongs to.

    Args:
        ip_address: The IP address to search for, such as "192.168.1.100" or "10.0.0.5".
    """
    try:
        data = _ensure_list(_api_request("GET", f"addresses/search/{ip_address}/"))
        return _fmt_search(data, COLS_ADDRESS, ip_address)
    except Exception as e:
        return f"ERROR: {e}"


@mcp.tool()
def search_hostname(hostname: str) -> str:
    """Search IP address records by hostname. Supports partial match.
    Returns all IPs whose hostname contains the search string.
    Use this when you know the server/device name but not its IP.

    Args:
        hostname: Full or partial hostname to search for, such as "web-server" or "db".
    """
    try:
        data = _ensure_list(_api_request("GET", f"addresses/search_hostname/{hostname}/"))
        return _fmt_search(data, COLS_ADDRESS, hostname)
    except Exception as e:
        return f"ERROR: {e}"


# ===================================================================
# VLAN TOOLS
# ===================================================================

@mcp.tool()
def list_vlans(page: int = 1, page_size: int = 50) -> str:
    """List all VLANs defined in phpIPAM.
    Returns VLAN number (802.1Q tag), name, and description for each VLAN.
    Only fetch the next page if the user explicitly asks for more results.

    Args:
        page: Page number starting from 1. Default is 1.
        page_size: Number of records per page, between 1 and 500. Default is 50.
    """
    try:
        return _fmt_page("vlan/", page, page_size, COLS_VLAN)
    except Exception as e:
        return f"ERROR: {e}"


@mcp.tool()
def get_vlan(vlan_id: int) -> str:
    """Get details of one VLAN by its database ID.
    IMPORTANT: vlan_id is the database row ID, NOT the 802.1Q VLAN number.
    Use list_vlans first to find the correct vlan_id.

    Args:
        vlan_id: The database ID of the VLAN (not the VLAN number/tag).
    """
    try:
        return _fmt_detail(_api_request("GET", f"vlan/{vlan_id}/"), DETAIL_VLAN)
    except Exception as e:
        return f"ERROR: {e}"


# ===================================================================
# DEVICE TOOLS
# ===================================================================

@mcp.tool()
def list_devices(page: int = 1, page_size: int = 50) -> str:
    """List all network devices (switches, routers, firewalls, servers, etc.).
    Returns hostname, IP address, type, vendor, and model for each device.
    Only fetch the next page if the user explicitly asks for more results.

    Args:
        page: Page number starting from 1. Default is 1.
        page_size: Number of records per page, between 1 and 500. Default is 50.
    """
    try:
        return _fmt_page("devices/", page, page_size, COLS_DEVICE)
    except Exception as e:
        return f"ERROR: {e}"


@mcp.tool()
def get_device(device_id: int) -> str:
    """Get full details of one network device by its ID.
    Returns hostname, IP, type, vendor, model, rack position, and all custom fields.

    Args:
        device_id: The numeric ID of the device.
    """
    try:
        return _fmt_detail(_api_request("GET", f"devices/{device_id}/"), DETAIL_DEVICE)
    except Exception as e:
        return f"ERROR: {e}"


# ===================================================================
# RACK TOOLS
# ===================================================================

@mcp.tool()
def list_racks(page: int = 1, page_size: int = 50) -> str:
    """List all server/network racks.
    Returns rack name, size in U (rack units), and location.
    Only fetch the next page if the user explicitly asks for more results.

    Args:
        page: Page number starting from 1. Default is 1.
        page_size: Number of records per page, between 1 and 500. Default is 50.
    """
    try:
        return _fmt_page("tools/racks/", page, page_size, COLS_RACK)
    except Exception as e:
        return f"ERROR: {e}"


@mcp.tool()
def get_rack(rack_id: int) -> str:
    """Get rack details including all mounted devices and space utilization.
    Returns rack size, device list with U positions (start_u, size_u, side),
    used/free unit counts, and utilization percentage.

    Args:
        rack_id: The numeric ID of the rack.
    """
    try:
        rack = _api_request("GET", f"tools/racks/{rack_id}/")

        try:
            devices_raw = _ensure_list(
                _api_request("GET", f"tools/racks/{rack_id}/devices/")
            )
        except Exception:
            devices_raw = []

        rack_size = int(rack.get("size", 42))
        occupied = set()
        devices = []

        for d in devices_raw:
            start = int(d.get("rack_start", 0))
            size = int(d.get("rack_size", 1))
            devices.append({
                "hostname": d.get("hostname"),
                "type": d.get("type"),
                "start_u": start,
                "size_u": size,
                "end_u": start + size - 1,
                "side": "rear" if d.get("rack_side") == "1" else "front",
            })
            for u in range(start, start + size):
                occupied.add(u)

        devices.sort(key=lambda x: x["start_u"])
        free_units = sorted(u for u in range(1, rack_size + 1) if u not in occupied)
        used = len(occupied)
        pct = round(used / rack_size * 100, 1) if rack_size > 0 else 0

        lines = [
            "[Rack]",
            f"id: {rack_id}",
            f"name: {_v(rack.get('name'))}",
            f"size_u: {rack_size}",
            f"location: {_v(rack.get('location'))}",
            f"description: {_v(rack.get('description'))}",
            "",
            f"[Devices] {len(devices)} items",
            _fmt_table(devices, COLS_RACK_DEVICE),
            "",
            f"[Utilization] {used}/{rack_size} U ({pct}%)",
            f"free_units: {_compress_ranges(free_units)}",
        ]
        return "\n".join(lines)
    except Exception as e:
        return f"ERROR: {e}"


# ===================================================================
# FOLDER TOOLS
# ===================================================================

@mcp.tool()
def list_folders(page: int = 1, page_size: int = 50) -> str:
    """List all organizational folders.
    Folders group sections for organizational purposes.
    Only fetch the next page if the user explicitly asks for more results.

    Args:
        page: Page number starting from 1. Default is 1.
        page_size: Number of records per page, between 1 and 500. Default is 50.
    """
    try:
        return _fmt_page("folders/", page, page_size, COLS_FOLDER)
    except Exception as e:
        return f"ERROR: {e}"


@mcp.tool()
def get_folder(folder_id: int) -> str:
    """Get folder details and the list of sections it contains.

    Args:
        folder_id: The numeric ID of the folder.
    """
    try:
        folder = _api_request("GET", f"folders/{folder_id}/")
        try:
            sections = _ensure_list(
                _api_request("GET", f"folders/{folder_id}/sections/")
            )
        except Exception:
            sections = []

        lines = [
            "[Folder]",
            _fmt_detail(folder, DETAIL_FOLDER),
            "",
            f"[Sections] {len(sections)} items",
            _fmt_table(sections, COLS_SECTION),
        ]
        return "\n".join(lines)
    except Exception as e:
        return f"ERROR: {e}"


# ===================================================================
# TAG TOOLS
# ===================================================================

@mcp.tool()
def list_tags() -> str:
    """List all IP address status tags (for example: Used, Available, Reserved, DHCP).
    Tags indicate the current status of IP address records.
    """
    try:
        data = _ensure_list(_api_request("GET", "addresses/tags/"))
        return f"{_fmt_table(data, COLS_TAG)}\n[{len(data)} tags]"
    except Exception as e:
        return f"ERROR: {e}"


# ===================================================================
# SYSTEM TOOLS
# ===================================================================

@mcp.tool()
def health_check() -> str:
    """Check if the phpIPAM API is reachable and responding.
    Returns API response time, cache statistics, and server configuration.
    Use this to verify the connection is working or to diagnose issues.
    """
    try:
        t0 = time.time()
        _api_request("GET", "sections/", use_cache=False)
        ms = round((time.time() - t0) * 1000, 1)
        stats = cache.stats()
        lines = [
            "status: healthy",
            f"api_response_ms: {ms}",
            f"endpoint: {config.BASE_URL}/api/{config.APP_ID}",
            f"cache_active_keys: {stats['active_keys']}",
            f"cache_ttl: {stats['ttl_seconds']}s",
            f"timeout: {config.TIMEOUT}s",
            f"max_retries: {config.MAX_RETRIES}",
            f"ssl_verify: {config.VERIFY_SSL}",
        ]
        return "\n".join(lines)
    except Exception as e:
        return f"status: unhealthy\nerror: {e}"


@mcp.tool()
def clear_cache() -> str:
    """Clear the API response cache so the next queries return fresh data.
    Use this after making changes in phpIPAM to avoid stale results.
    """
    cache.clear()
    return "status: ok\nmessage: Cache cleared"


# ===================================================================
# MAIN
# ===================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="phpIPAM MCP Server v2.1")
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default="stdio",
        help="Transport mode (default: stdio)",
    )
    parser.add_argument(
        "--host", default=None,
        help="Host for streamable-http (default: 0.0.0.0). Overrides FASTMCP_HOST env.",
    )
    parser.add_argument(
        "--port", type=int, default=None,
        help="Port for streamable-http (default: 8000). Overrides FASTMCP_PORT env.",
    )
    args = parser.parse_args()

    # Override host/port in mcp.settings if provided via CLI
    if args.host is not None:
        mcp.settings.host = args.host
    if args.port is not None:
        mcp.settings.port = args.port

    logger.info("=" * 60)
    logger.info("phpIPAM FastMCP Server v2.1")
    logger.info(f"  URL       : {config.BASE_URL}/api/{config.APP_ID}")
    logger.info(f"  Transport : {args.transport}")
    if args.transport == "streamable-http":
        logger.info(f"  Listen    : http://{mcp.settings.host}:{mcp.settings.port}")
    logger.info("=" * 60)

    mcp.run(transport=args.transport)
