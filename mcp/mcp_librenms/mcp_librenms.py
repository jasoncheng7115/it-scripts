#!/usr/bin/env python3
"""
MCP server for LibreNMS API – v4.0.0 Slim (Weak-Model Optimized)
=================================================================
Author: Jason Cheng (Jason Tools) - Enhanced by Claude
License: MIT

FastMCP-based LibreNMS integration optimized for weak/small LLMs.
20 tools, compact responses, human-readable parameters.
Supports stdio and streamable-http transport.

pip install mcp requests

Changelog:
  v4.0.0 - Complete rewrite for weak/small LLM optimization
    - 32 → 20 tools (merged overlapping, removed debug/niche tools)
    - Compact JSON via _R() (no indent, no ensure_ascii)
    - Slim device/port objects (_slim_device ~11 fields, _slim_port ~7 fields)
    - _resolve_device() accepts hostname/IP/device_id
    - Human-readable params: state="ok"/"warning"/"critical", vlan_tag not vlan_id
    - Consistent response format: {"data": [...], "count": N}
    - [YES]/[NO] intent markers in docstrings (Chinese + English)
    - Added get_top_cpu, get_top_memory (requires custom_top_devices.php helper)
    - sysName included in all device-referencing tool responses
    - Dual transport: stdio (default) + streamable-http (--transport http)
  v3.11.0 - Added dual transport support (stdio + streamable-http)
  v3.10.2 - VLAN mapping fix (vlan_id vs vlan_vlan)
  v3.x    - Initial FastMCP implementation, 32 tools
"""

import os
import sys
import re
import json
import time
import hashlib
import logging
import argparse
import ipaddress
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from functools import wraps

import requests
from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("mcp-librenms")


# ───────────────────────── Configuration ─────────────────────────

class Config:
    def __init__(self, args=None):
        if args:
            self.BASE_URL = args.url or os.getenv("LIBRENMS_URL")
            self.TOKEN = args.token or os.getenv("LIBRENMS_TOKEN")
            self.CACHE_TTL = args.cache_ttl if args.cache_ttl is not None else int(os.getenv("LIBRENMS_CACHE_TTL", "300"))
            self.TIMEOUT = args.timeout if args.timeout is not None else int(os.getenv("LIBRENMS_TIMEOUT", "30"))
            self.MAX_RETRIES = args.max_retries if args.max_retries is not None else int(os.getenv("LIBRENMS_MAX_RETRIES", "3"))
            self.BATCH_SIZE = args.batch_size if args.batch_size is not None else int(os.getenv("LIBRENMS_BATCH_SIZE", "200"))
            self.VERIFY_SSL = args.verify_ssl if args.verify_ssl is not None else True
        else:
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
            logger.error("  Command line: --url <URL> --token <TOKEN>")
            logger.error("  Environment:  LIBRENMS_URL=<URL> LIBRENMS_TOKEN=<TOKEN>")
            sys.exit(1)
        self.BASE_URL = self.BASE_URL.rstrip('/')
        if not self.BASE_URL.endswith('/api/v0'):
            self.BASE_URL += '/api/v0'
        logger.info(f"LibreNMS URL: {self.BASE_URL}")


config = None


class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


class SimpleCache:
    def __init__(self, ttl: int = 300):
        self.cache = {}
        self.ttl = ttl

    def _key(self, key_data: str) -> str:
        return hashlib.md5(key_data.encode('utf-8')).hexdigest()

    def get(self, key: str) -> Optional[Any]:
        safe_key = self._key(key)
        if safe_key in self.cache:
            data, ts = self.cache[safe_key]
            if time.time() - ts < self.ttl:
                return data
            del self.cache[safe_key]
        return None

    def set(self, key: str, value: Any):
        self.cache[self._key(key)] = (value, time.time())

    def clear(self):
        self.cache.clear()

    def stats(self) -> Dict[str, int]:
        now = time.time()
        active = sum(1 for _, (_, ts) in self.cache.items() if now - ts < self.ttl)
        return {"total_keys": len(self.cache), "active_keys": active, "ttl_seconds": self.ttl}


cache = None
session = None
mcp = FastMCP("LibreNMS")


def initialize_session():
    global session
    session = requests.Session()
    session.headers.update({
        "X-Auth-Token": config.TOKEN,
        "User-Agent": "mcp-librenms/4.0.0",
        "Accept": "application/json",
        "Content-Type": "application/json"
    })
    session.verify = config.VERIFY_SSL


# ───────────────────────── Core Helpers ─────────────────────────

def _api_request(method: str, endpoint: str, params: Optional[Dict] = None,
                 json_body: Optional[Dict] = None, use_cache: bool = True) -> Dict:
    """Send API request to LibreNMS with caching and retry logic."""
    cache_key = f"{method}:{endpoint}:{json.dumps(params, sort_keys=True)}:{json.dumps(json_body, sort_keys=True)}" if use_cache else None

    if cache_key and method.upper() == 'GET':
        cached = cache.get(cache_key)
        if cached:
            return cached

    url = f"{config.BASE_URL}/{endpoint.lstrip('/')}"
    last_exc = None

    for attempt in range(config.MAX_RETRIES):
        try:
            resp = session.request(method.upper(), url, params=params, json=json_body, timeout=config.TIMEOUT)
            resp.raise_for_status()
            result = resp.json()
            if cache_key and method.upper() == 'GET' and resp.status_code == 200:
                cache.set(cache_key, result)
            return result
        except requests.exceptions.RequestException as e:
            last_exc = e
            if attempt < config.MAX_RETRIES - 1:
                time.sleep(1.0 * (2 ** attempt))

    raise Exception(f"LibreNMS API error: {last_exc}")


def _extract_data(result: Any, keys: List[str] = None) -> List[Dict]:
    """Extract data array from API response."""
    if keys is None:
        keys = ['devices', 'services', 'alerts', 'data', 'results', 'eventlog',
                'alertlog', 'ports_fdb', 'fdb', 'ports', 'arp', 'ip_arp', 'vlans',
                'processors', 'mempools', 'graphs', 'sensors']

    if isinstance(result, list):
        return result

    if isinstance(result, dict):
        for key in keys:
            if key in result:
                val = result[key]
                if isinstance(val, list):
                    return val
        # Fallback: find any list with dict items
        for key, val in result.items():
            if isinstance(val, list) and val and isinstance(val[0], dict):
                return val
        # Single-item result
        if result and not any(isinstance(v, list) for v in result.values()):
            return [result]

    return []


def _paginate(endpoint: str, params: Optional[Dict] = None,
              max_items: Optional[int] = None) -> List[Dict]:
    """Paginated API requests."""
    all_items = []
    offset = 0
    limit = min(config.BATCH_SIZE, 200)
    consecutive_empty = 0
    if params is None:
        params = {}

    for _ in range(50):  # Safety limit
        p = {**params, "limit": limit, "offset": offset}
        try:
            result = _api_request("GET", endpoint, params=p)
            items = _extract_data(result)

            if not items:
                consecutive_empty += 1
                if consecutive_empty >= 2 or offset == 0:
                    break
                offset += limit
                continue

            consecutive_empty = 0
            all_items.extend(items)

            if max_items and len(all_items) >= max_items:
                return all_items[:max_items]
            if len(items) < limit:
                break
            offset += limit
        except Exception as e:
            consecutive_empty += 1
            if consecutive_empty >= 2:
                break
            offset += limit

    # Fallback: large request if pagination got nothing
    if not all_items:
        try:
            result = _api_request("GET", endpoint, params={**params, "limit": 10000})
            all_items = _extract_data(result)
        except Exception:
            pass

    return all_items[:max_items] if max_items else all_items


# ───────────────────────── Utility Helpers ─────────────────────────

def _safe_parse_datetime(ts: Any) -> Optional[datetime]:
    if not ts or ts == '0000-00-00 00:00:00':
        return None
    ts = str(ts)
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M:%S.%f',
                '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%d %H:%M:%S.%f'):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(ts.replace('Z', '').split('+')[0])
    except Exception:
        return None


def _format_timestamp(ts: str) -> str:
    dt = _safe_parse_datetime(ts)
    return dt.strftime('%Y-%m-%d %H:%M:%S') if dt else (str(ts) if ts else "N/A")


def _normalize_mac(mac: str) -> str:
    if not mac:
        return ""
    clean = re.sub(r'[:\-.]', '', mac.lower())
    if len(clean) != 12:
        raise ValueError(f"Invalid MAC: {mac}")
    return clean


def _format_mac(mac: str) -> str:
    if not mac:
        return ""
    clean = re.sub(r'[:\-.]', '', mac.lower())
    if len(clean) != 12:
        return mac
    return ':'.join(clean[i:i+2] for i in range(0, 12, 2))


def _validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _validate_cidr(net: str) -> bool:
    try:
        ipaddress.ip_network(net, strict=False)
        return True
    except ValueError:
        return False


def _normalize_port_status(val) -> str:
    if val is None:
        return 'unknown'
    if isinstance(val, str):
        return val.lower().strip()
    if isinstance(val, int):
        return {1: 'up', 2: 'down', 3: 'testing', 4: 'unknown',
                5: 'dormant', 6: 'notpresent', 7: 'lowerlayerdown'}.get(val, 'unknown')
    return str(val).lower().strip()


def _evaluate_port_quality(ports: list, device_os: str = None) -> dict:
    if not ports:
        return {"confidence": "none", "has_ifOperStatus": False}
    total = len(ports)
    has_oper = sum(1 for p in ports if p.get('ifOperStatus') is not None)
    if has_oper == total:
        conf = "high"
    elif has_oper > total * 0.5:
        conf = "medium"
    else:
        conf = "low"
    return {"confidence": conf, "has_ifOperStatus": has_oper > 0,
            "ports_with_status": has_oper, "total_ports": total}


# ───────────────────────── v4.0 Slim Helpers ─────────────────────────

def _R(obj) -> str:
    """Compact JSON serialization (no indent, no ASCII escape)."""
    return json.dumps(obj, ensure_ascii=False, cls=DateTimeEncoder)


def _device_status_str(val) -> str:
    if val == 1 or val == "1":
        return "up"
    if val == 0 or val == "0":
        return "down"
    if val == 2 or val == "2":
        return "disabled"
    return "unknown"


def _slim_device(d: dict) -> dict:
    """Keep only essential device fields."""
    if not isinstance(d, dict):
        return d
    return {
        "device_id": d.get("device_id"),
        "hostname": d.get("hostname"),
        "sysName": d.get("sysName"),
        "ip": d.get("ip"),
        "os": d.get("os"),
        "version": d.get("version"),
        "hardware": d.get("hardware"),
        "type": d.get("type"),
        "location": d.get("location"),
        "status": _device_status_str(d.get("status")),
        "uptime": d.get("uptime"),
    }


def _slim_port(p: dict) -> dict:
    """Keep only essential port fields."""
    if not isinstance(p, dict):
        return p
    return {
        "port_id": p.get("port_id"),
        "ifName": p.get("ifName"),
        "ifDescr": p.get("ifDescr"),
        "ifAlias": p.get("ifAlias"),
        "ifOperStatus": p.get("ifOperStatus"),
        "ifSpeed": p.get("ifSpeed"),
        "ifType": p.get("ifType"),
    }


def _resolve_device(device: str) -> Optional[Dict]:
    """Resolve device by hostname, IP, or numeric ID. Returns slim device dict or None."""
    if not device:
        return None

    # Try numeric ID first
    try:
        device_id = int(device)
        result = _api_request("GET", f"devices/{device_id}")
        devs = _extract_data(result, ['devices'])
        if devs:
            return _slim_device(devs[0])
    except (ValueError, Exception):
        pass

    # Try hostname / IP search
    for field in ['hostname', 'ip']:
        try:
            result = _api_request("GET", "devices", params={field: device})
            devs = _extract_data(result, ['devices'])
            if devs:
                return _slim_device(devs[0])
        except Exception:
            pass

    # Fallback: search all devices
    try:
        all_devs = _paginate("devices", max_items=500)
        dev_lower = device.lower()
        for d in all_devs:
            if not isinstance(d, dict):
                continue
            if (dev_lower == str(d.get("hostname", "")).lower() or
                dev_lower == str(d.get("sysName", "")).lower() or
                dev_lower == str(d.get("ip", "")).lower()):
                return _slim_device(d)
    except Exception:
        pass

    return None


def _build_vlan_cache() -> Dict:
    """Build vlan_id (DB ID) -> {vlan_tag, vlan_name} mapping."""
    mapping = {}
    try:
        result = _api_request("GET", "resources/vlans")
        for v in _extract_data(result, ['vlans']):
            db_id = str(v.get("vlan_id", ""))
            tag = v.get("vlan_vlan")
            if db_id and tag is not None:
                mapping[db_id] = {"vlan_tag": tag, "vlan_name": v.get("vlan_name", "")}
    except Exception as e:
        logger.warning(f"VLAN cache build failed: {e}")
    return mapping


def _enrich_vlan(entry: dict, vcache: dict) -> dict:
    """Add flat vlan_tag and vlan_name fields to entry."""
    vid = entry.get("vlan_id")
    if vid:
        m = vcache.get(str(vid))
        if m:
            entry["vlan_tag"] = m["vlan_tag"]
            entry["vlan_name"] = m["vlan_name"]
        else:
            entry["vlan_tag"] = None
            entry["vlan_name"] = None
    return entry


def _get_device_info_dict(device_id) -> Optional[dict]:
    """Fetch single device, return slim dict."""
    try:
        result = _api_request("GET", f"devices/{device_id}")
        devs = _extract_data(result, ['devices'])
        return _slim_device(devs[0]) if devs else None
    except Exception:
        return None


def _get_port_info_dict(port_id) -> Optional[dict]:
    """Fetch single port, return slim dict."""
    try:
        result = _api_request("GET", f"ports/{port_id}")
        ports = _extract_data(result, ['ports'])
        return _slim_port(ports[0]) if ports else None
    except Exception:
        return None


# ───────────────────────── MCP Tools (18) ─────────────────────────

@mcp.tool()
def librenms_api(method: str, endpoint: str, params: Optional[Dict[str, Any]] = None,
                 json_body: Optional[Dict[str, Any]] = None) -> str:
    """Execute raw request to any LibreNMS REST API endpoint.
    [YES] Use for any API call not covered by other tools.
    [NO] Don't use if a specific tool exists for your task."""
    try:
        result = _api_request(method, endpoint, params, json_body, use_cache=False)
        return _R(result)
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def health_check() -> str:
    """Check LibreNMS API connectivity, response time, and cache status.
    [YES] Use to verify API is working.
    [NO] Don't use for device-specific checks."""
    try:
        t0 = time.time()
        _api_request("GET", "devices", params={"limit": 1}, use_cache=False)
        ms = round((time.time() - t0) * 1000, 2)
        return _R({
            "status": "healthy",
            "api_response_ms": ms,
            "endpoint": config.BASE_URL,
            "cache": cache.stats(),
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return _R({"status": "unhealthy", "error": str(e)})


@mcp.tool()
def get_device_info(device: str) -> str:
    """Get information for a single device.
    [YES] Use when user asks about a specific device by hostname, IP, or ID.
    [NO] Don't use to list multiple devices -> use list_devices().

    Args:
        device: Hostname, IP address, or numeric device ID."""
    try:
        d = _resolve_device(device)
        if not d:
            return _R({"error": f"Device not found: {device}"})
        return _R({"data": d})
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def list_devices(limit: int = 0, status: Optional[str] = None,
                 os_filter: Optional[str] = None, location: Optional[str] = None,
                 search: Optional[str] = None) -> str:
    """List/search LibreNMS devices.
    [YES] "Show all devices", "List down devices", "Find proxmox devices", "Search for device X".
    [NO] "Show device 123 details" -> use get_device_info().
    [NO] "Show devices WITH ports" -> use get_devices_with_ports().

    Args:
        limit: Max devices (0=all).
        status: Filter: "up", "down", "disabled".
        os_filter: Filter by OS: "proxmox", "linux", "ios", etc.
        location: Filter by location string.
        search: Search hostname/sysName/IP (partial match)."""
    try:
        params = {}
        if status:
            params["status"] = {"up": "1", "down": "0", "disabled": "2"}.get(status.lower(), status)
        if location:
            params["location"] = location

        max_items = None if limit == 0 else limit
        devices = _paginate("devices", params, max_items=max_items)

        # Post-filter by OS
        if os_filter:
            os_lower = os_filter.lower()
            devices = [d for d in devices if isinstance(d, dict) and os_lower in d.get('os', '').lower()]

        # Post-filter by search
        if search:
            s = search.lower()
            devices = [d for d in devices if isinstance(d, dict) and (
                s in str(d.get('hostname', '')).lower() or
                s in str(d.get('sysName', '')).lower() or
                s in str(d.get('ip', '')).lower()
            )]

        slim = [_slim_device(d) for d in devices if isinstance(d, dict)]

        # Stats
        stats = {"up": 0, "down": 0, "disabled": 0, "unknown": 0}
        for d in slim:
            st = d.get("status", "unknown")
            stats[st] = stats.get(st, 0) + 1

        return _R({"data": slim, "count": len(slim), "status_breakdown": stats})
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def get_device_ports(device: str, status_filter: Optional[str] = None) -> str:
    """Get ports/interfaces for a specific device.
    [YES] "Show ports for device X", "Which ports are up on switch01?".
    [NO] "Show ports for ALL proxmox devices" -> use get_devices_with_ports().

    Args:
        device: Hostname, IP, or device ID.
        status_filter: "up", "down", "admin_down", or None for all."""
    try:
        dev = _resolve_device(device)
        if not dev:
            return _R({"error": f"Device not found: {device}"})
        device_id = dev["device_id"]

        result = _api_request("GET", f"devices/{device_id}/ports")
        all_ports = _extract_data(result, ['ports'])

        quality = _evaluate_port_quality(all_ports, dev.get("os"))

        if status_filter and quality["has_ifOperStatus"]:
            sf = status_filter.lower()
            filtered = [p for p in all_ports if _normalize_port_status(p.get('ifOperStatus')) == sf.replace('admin_down', 'admindown')]
        else:
            filtered = all_ports

        slim = [_slim_port(p) for p in filtered]
        stats = {}
        for p in slim:
            s = _normalize_port_status(p.get('ifOperStatus'))
            stats[s] = stats.get(s, 0) + 1

        return _R({
            "device": {"device_id": device_id, "hostname": dev.get("hostname"), "sysName": dev.get("sysName"), "os": dev.get("os")},
            "data": slim, "count": len(slim), "status_breakdown": stats,
            "data_quality": quality
        })
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def get_devices_with_ports(os_filter: Optional[str] = None,
                           device_status: Optional[str] = None,
                           port_status: Optional[str] = None,
                           limit: int = 10) -> str:
    """Get devices AND their ports in one batch call.
    [YES] "Show proxmox devices with their ports", "Devices + ports in one query".
    [NO] "Show ports for one device" -> use get_device_ports().

    Args:
        os_filter: Filter by OS ("proxmox", "linux", "ios").
        device_status: Filter devices by "up" or "down".
        port_status: Filter ports by "up", "down", or None for all.
        limit: Max devices (default 10)."""
    try:
        params = {}
        if device_status:
            params["status"] = {"up": "1", "down": "0"}.get(device_status.lower(), device_status)

        devices = _extract_data(_api_request("GET", "devices", params={**params, "limit": limit * 2}), ['devices'])
        if os_filter:
            devices = [d for d in devices if os_filter.lower() in d.get('os', '').lower()]
        devices = devices[:limit]

        result_devices = []
        for d in devices:
            did = d.get('device_id')
            if not did:
                continue
            try:
                ports_result = _api_request("GET", f"devices/{did}/ports")
                ports = _extract_data(ports_result, ['ports'])
                quality = _evaluate_port_quality(ports, d.get('os'))

                if port_status and quality["has_ifOperStatus"]:
                    ps = port_status.lower()
                    ports = [p for p in ports if _normalize_port_status(p.get('ifOperStatus')) == ps]
                elif port_status and not quality["has_ifOperStatus"]:
                    ports = [p for p in ports if not p.get('disabled', 0)]

                result_devices.append({
                    "device_id": did,
                    "hostname": d.get("hostname"),
                    "sysName": d.get("sysName"),
                    "os": d.get("os"),
                    "status": _device_status_str(d.get("status")),
                    "ip": d.get("ip"),
                    "ports": [_slim_port(p) for p in ports],
                    "port_count": len(ports),
                    "data_quality": quality
                })
            except Exception as e:
                result_devices.append({"device_id": did, "hostname": d.get("hostname"), "error": str(e), "ports": []})

        return _R({"data": result_devices, "count": len(result_devices)})
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def search_ip_to_mac(ip_address: str) -> str:
    """Find MAC address for an IP address via ARP table.
    [YES] "What MAC is at IP 192.168.1.100?", "IP to MAC lookup".
    [NO] "Find IP for this MAC" -> use search_mac_to_ip().
    [NO] "Full IP investigation" -> use troubleshoot_ip().

    Args:
        ip_address: IP address to look up."""
    try:
        if not _validate_ip(ip_address):
            return _R({"error": f"Invalid IP: {ip_address}"})

        vcache = _build_vlan_cache()
        entries = []

        # Direct ARP lookup
        try:
            result = _api_request("GET", f"resources/ip/arp/{ip_address}")
            entries.extend(_extract_data(result, ['arp', 'ip_arp']))
        except Exception:
            pass

        # Device-specific fallback
        if not entries:
            try:
                devs = _extract_data(_api_request("GET", "devices", params={"limit": 5}), ['devices'])
                for d in devs:
                    did = d.get('device_id')
                    if not did:
                        continue
                    try:
                        arp = _extract_data(_api_request("GET", f"devices/{did}/arp"), ['arp', 'ip_arp'])
                        for e in arp:
                            if (e.get("ipv4_address") or e.get("ip_address")) == ip_address:
                                entries.append(e)
                                break
                        if entries:
                            break
                    except Exception:
                        pass
            except Exception:
                pass

        # Deduplicate
        seen = set()
        unique = []
        for e in entries:
            key = f"{e.get('mac_address', '')}_{e.get('device_id', '')}"
            if key not in seen:
                seen.add(key)
                unique.append(e)

        # Enrich
        enriched = []
        for e in unique:
            entry = {
                "ip_address": e.get("ipv4_address") or e.get("ip_address"),
                "mac_address": _format_mac(e.get("mac_address", "")),
                "device_id": e.get("device_id"),
                "port_id": e.get("port_id"),
            }
            _enrich_vlan(e, vcache)
            entry["vlan_tag"] = e.get("vlan_tag")
            entry["vlan_name"] = e.get("vlan_name")

            # Add device/port context
            dev = _get_device_info_dict(e.get("device_id"))
            if dev:
                entry["device_hostname"] = dev.get("hostname")
                entry["device_sysName"] = dev.get("sysName")
            port = _get_port_info_dict(e.get("port_id"))
            if port:
                entry["port_name"] = port.get("ifName")

            enriched.append(entry)

        return _R({"data": enriched, "count": len(enriched)})
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def search_mac_to_ip(mac_address: str) -> str:
    """Find IP addresses for a MAC address via ARP table.
    [YES] "What IP does this MAC have?", "MAC to IP lookup".
    [NO] "Find MAC for IP" -> use search_ip_to_mac().
    [NO] "Find switch port for MAC" -> use search_fdb_by_mac().

    Args:
        mac_address: MAC address (any format: aa:bb:cc:dd:ee:ff, aabb.ccdd.eeff, etc.)."""
    try:
        vcache = _build_vlan_cache()
        try:
            normalized = _normalize_mac(mac_address)
        except Exception:
            normalized = mac_address

        entries = []
        try:
            all_arp = _paginate("resources/ip/arp", max_items=5000)
            for e in all_arp:
                emac = e.get("mac_address", "")
                if (emac.lower() == mac_address.lower() or
                    emac.lower() == normalized.lower() or
                    mac_address.lower() in emac.lower()):
                    entries.append(e)
        except Exception:
            pass

        enriched = []
        for e in entries:
            entry = {
                "ip_address": e.get("ipv4_address") or e.get("ip_address"),
                "mac_address": _format_mac(e.get("mac_address", "")),
                "device_id": e.get("device_id"),
            }
            _enrich_vlan(e, vcache)
            entry["vlan_tag"] = e.get("vlan_tag")
            entry["vlan_name"] = e.get("vlan_name")
            enriched.append(entry)

        return _R({"data": enriched, "count": len(enriched)})
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def search_fdb_by_mac(mac_address: str) -> str:
    """Find which switch port a MAC address is on via FDB table.
    [YES] "Which switch is this MAC on?", "Find port for MAC aa:bb:cc:dd:ee:ff".
    [NO] "Find MAC for IP" -> use search_ip_to_mac().

    Args:
        mac_address: MAC address (any format)."""
    try:
        vcache = _build_vlan_cache()
        try:
            normalized = _normalize_mac(mac_address)
        except Exception:
            normalized = mac_address

        fdb = []
        try:
            result = _api_request("GET", f"resources/fdb/{normalized}")
            fdb.extend(_extract_data(result, ['ports_fdb']))
        except Exception:
            pass

        if not fdb:
            try:
                all_fdb = _paginate("resources/fdb", max_items=5000)
                for e in all_fdb:
                    emac = e.get("mac_address", "")
                    if normalized in emac.lower() or mac_address.lower() in emac.lower():
                        fdb.append(e)
            except Exception:
                pass

        # Deduplicate
        seen = set()
        unique = []
        for e in fdb:
            eid = e.get("ports_fdb_id") or str(e)
            if eid not in seen:
                seen.add(eid)
                unique.append(e)

        device_cache = {}
        port_cache = {}
        enriched = []

        for e in unique:
            entry = {
                "mac_address": _format_mac(e.get("mac_address", "")),
                "device_id": e.get("device_id"),
                "port_id": e.get("port_id"),
            }
            _enrich_vlan(e, vcache)
            entry["vlan_tag"] = e.get("vlan_tag")
            entry["vlan_name"] = e.get("vlan_name")

            # Device info with cache
            did = e.get("device_id")
            if did:
                if did not in device_cache:
                    device_cache[did] = _get_device_info_dict(did)
                dev = device_cache[did]
                if dev:
                    entry["device_hostname"] = dev.get("hostname")
                    entry["device_sysName"] = dev.get("sysName")
                    entry["device_ip"] = dev.get("ip")
                    entry["device_location"] = dev.get("location")

            # Port info with cache
            pid = e.get("port_id")
            if pid:
                if pid not in port_cache:
                    port_cache[pid] = _get_port_info_dict(pid)
                port = port_cache[pid]
                if port:
                    entry["port_name"] = port.get("ifName")
                    entry["port_descr"] = port.get("ifDescr")

            enriched.append(entry)

        return _R({"data": enriched, "count": len(enriched)})
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def troubleshoot_ip(ip_address: str) -> str:
    """One-stop IP investigation: ARP -> MAC -> FDB -> switch port.
    [YES] "Where is IP 192.168.1.100 connected?", "Trace IP to switch port".
    [NO] "Just find MAC for IP" -> use search_ip_to_mac().

    Args:
        ip_address: IP address to investigate."""
    try:
        result = {"ip_address": ip_address, "status": "investigating"}

        # Step 1: ARP -> MAC
        arp_result = json.loads(search_ip_to_mac(ip_address))
        arp_entries = arp_result.get("data", [])

        if not arp_entries:
            result["status"] = "not_found"
            result["message"] = "IP not found in ARP table. Device may be offline or outside monitored network."
            return _R(result)

        arp = arp_entries[0]
        mac = arp.get("mac_address", "")
        result["mac_address"] = mac
        result["arp_device"] = arp.get("device_hostname")
        result["arp_device_sysName"] = arp.get("device_sysName")
        result["arp_vlan_tag"] = arp.get("vlan_tag")
        result["arp_vlan_name"] = arp.get("vlan_name")

        if not mac:
            result["status"] = "partial"
            result["message"] = "Found ARP entry but no MAC address."
            return _R(result)

        # Step 2: FDB -> switch port
        fdb_result = json.loads(search_fdb_by_mac(mac))
        fdb_entries = fdb_result.get("data", [])

        if not fdb_entries:
            result["status"] = "partial"
            result["message"] = f"Found MAC {mac} but not in FDB table. Device may be on router not switch."
            return _R(result)

        fdb = fdb_entries[0]
        result["switch_hostname"] = fdb.get("device_hostname")
        result["switch_sysName"] = fdb.get("device_sysName")
        result["switch_ip"] = fdb.get("device_ip")
        result["switch_port"] = fdb.get("port_name")
        result["switch_port_descr"] = fdb.get("port_descr")
        result["fdb_vlan_tag"] = fdb.get("vlan_tag")
        result["fdb_vlan_name"] = fdb.get("vlan_name")

        # Step 3: Switch details
        did = fdb.get("device_id")
        if did:
            dev = _get_device_info_dict(did)
            if dev:
                result["switch_os"] = dev.get("os")
                result["switch_location"] = dev.get("location")
                result["switch_status"] = dev.get("status")

        result["status"] = "success"
        result["summary"] = (
            f"IP {ip_address} -> MAC {mac} -> "
            f"{fdb.get('device_hostname', '?')} port {fdb.get('port_name', '?')} "
            f"(VLAN {fdb.get('vlan_tag', '?')})"
        )

        if len(fdb_entries) > 1:
            result["other_locations"] = [
                {"device": e.get("device_hostname"), "port": e.get("port_name")}
                for e in fdb_entries[1:5]
            ]

        return _R(result)
    except Exception as e:
        return _R({"error": str(e), "ip_address": ip_address})


@mcp.tool()
def list_fdb_entries(limit: int = 100, vlan_tag: Optional[int] = None,
                     device_id: Optional[int] = None, mac_filter: Optional[str] = None) -> str:
    """List FDB (forwarding database) entries.
    [YES] "Show FDB table", "List MAC addresses on VLAN 100".
    [NO] "Find specific MAC location" -> use search_fdb_by_mac().

    Args:
        limit: Max entries (default 100).
        vlan_tag: Filter by VLAN tag number (e.g., 100), NOT database ID.
        device_id: Filter by device ID.
        mac_filter: Filter by partial MAC address."""
    try:
        vcache = _build_vlan_cache()

        # Build reverse mapping: vlan_tag -> list of vlan_db_ids
        tag_to_dbids = {}
        for db_id, info in vcache.items():
            t = info.get("vlan_tag")
            if t is not None:
                tag_to_dbids.setdefault(str(t), []).append(db_id)

        params = {}
        if device_id is not None:
            params["device_id"] = device_id

        # If vlan_tag specified, find matching DB IDs
        target_dbids = None
        if vlan_tag is not None:
            target_dbids = set(tag_to_dbids.get(str(vlan_tag), []))

        entries = _paginate("resources/fdb", params, max_items=limit * 2 if vlan_tag else limit)

        # Filter by vlan_tag
        if target_dbids is not None:
            entries = [e for e in entries if str(e.get("vlan_id", "")) in target_dbids]

        # Filter by MAC
        if mac_filter:
            try:
                nf = _normalize_mac(mac_filter)
                entries = [e for e in entries if nf in e.get("mac_address", "")]
            except Exception:
                entries = [e for e in entries if mac_filter.lower() in e.get("mac_address", "").lower()]

        entries = entries[:limit]

        enriched = []
        for e in entries:
            entry = {
                "mac_address": _format_mac(e.get("mac_address", "")),
                "device_id": e.get("device_id"),
                "port_id": e.get("port_id"),
            }
            _enrich_vlan(e, vcache)
            entry["vlan_tag"] = e.get("vlan_tag")
            entry["vlan_name"] = e.get("vlan_name")
            enriched.append(entry)

        return _R({"data": enriched, "count": len(enriched)})
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def get_network_arp_table(network_cidr: str, limit: int = 500) -> str:
    """Get ARP table entries for a network segment.
    [YES] "Show ARP table for 192.168.1.0/24".
    [NO] "Find MAC for single IP" -> use search_ip_to_mac().

    Args:
        network_cidr: Network in CIDR format (e.g., "192.168.1.0/24").
        limit: Max entries (default 500)."""
    try:
        if not _validate_cidr(network_cidr):
            return _R({"error": f"Invalid CIDR: {network_cidr}"})

        vcache = _build_vlan_cache()
        network = ipaddress.ip_network(network_cidr, strict=False)

        all_arp = _paginate("resources/ip/arp", max_items=limit * 2)
        filtered = []
        for e in all_arp:
            ip_str = e.get("ipv4_address") or e.get("ip_address")
            if ip_str:
                try:
                    if ipaddress.ip_address(ip_str) in network:
                        filtered.append(e)
                except ValueError:
                    continue
            if len(filtered) >= limit:
                break

        enriched = []
        for e in filtered:
            entry = {
                "ip_address": e.get("ipv4_address") or e.get("ip_address"),
                "mac_address": _format_mac(e.get("mac_address", "")),
                "device_id": e.get("device_id"),
            }
            _enrich_vlan(e, vcache)
            entry["vlan_tag"] = e.get("vlan_tag")
            entry["vlan_name"] = e.get("vlan_name")
            enriched.append(entry)

        ip_count = len(set(e["ip_address"] for e in enriched if e.get("ip_address")))
        total_addr = network.num_addresses
        usable = max(total_addr - 2, 1) if network.prefixlen >= 24 else total_addr

        return _R({
            "network": network_cidr,
            "data": enriched,
            "count": len(enriched),
            "unique_ips": ip_count,
            "utilization_pct": round((ip_count / usable) * 100, 1)
        })
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def list_all_services(state: Optional[str] = None, limit: int = 100,
                      service_type: Optional[str] = None) -> str:
    """List monitored services with filtering.
    [YES] "Show all services", "List critical services", "Which services are warning?".
    [NO] "Check specific device health" -> use diagnose_device().

    Args:
        state: Filter by state: "ok", "warning", "critical" (or "0", "1", "2").
        limit: Max services (default 100).
        service_type: Filter by type (e.g., "http", "ping")."""
    try:
        params = {}
        if state is not None:
            state_map = {"ok": "0", "warning": "1", "critical": "2", "0": "0", "1": "1", "2": "2"}
            params["state"] = state_map.get(state.lower(), state)
        if service_type:
            params["type"] = service_type

        services = _paginate("services", params, max_items=limit)

        stats = {"ok": 0, "warning": 0, "critical": 0, "unknown": 0}
        for svc in services:
            if not isinstance(svc, dict):
                continue
            s = str(svc.get("service_status", ""))
            if s == "0":
                stats["ok"] += 1
            elif s == "1":
                stats["warning"] += 1
            elif s == "2":
                stats["critical"] += 1
            else:
                stats["unknown"] += 1

        return _R({"data": services, "count": len(services), "status_breakdown": stats})
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def get_recent_alerts(limit: int = 10, severity: Optional[str] = None) -> str:
    """Get current ACTIVE alerts (firing right now).
    [YES] "現在有哪些告警?", "今天告警", "active alerts", "當前警報", "裝置狀況告警".
    [NO] "過去一週的告警歷史" -> use get_alert_history().

    Args:
        limit: Max alerts (default 10).
        severity: Filter by severity (e.g., "critical", "warning")."""
    try:
        params = {"limit": limit}
        if severity:
            params["severity"] = severity

        alerts = _extract_data(_api_request("GET", "alerts", params=params), ['alerts'])

        # Enrich with device info
        dev_cache = {}
        for alert in alerts:
            did = alert.get('device_id')
            if did and did not in dev_cache:
                dev_cache[did] = _get_device_info_dict(did)
            if did and dev_cache.get(did):
                d = dev_cache[did]
                alert['device_hostname'] = d.get('hostname')
                alert['device_sysName'] = d.get('sysName')
                alert['device_ip'] = d.get('ip')

        return _R({"data": alerts, "count": len(alerts)})
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def get_alert_history(days: int = 30, limit: int = 100,
                      severity: Optional[str] = None) -> str:
    """Get historical alerts (including resolved) from multiple sources.
    [YES] "告警歷史", "今天的告警記錄", "過去7天告警", "alert history", "past alerts", "resolved alerts".
    [NO] "現在有哪些告警?" -> use get_recent_alerts().

    Args:
        days: Look back period (default 30).
        limit: Max alerts (default 100).
        severity: Filter by severity."""
    try:
        end = datetime.now()
        start = end - timedelta(days=days)
        all_alerts = []

        # Active alerts
        try:
            params = {"limit": min(limit, 500)}
            if severity:
                params["severity"] = severity
            active = _extract_data(_api_request("GET", "alerts", params=params), ['alerts'])
            for a in active:
                a["source"] = "active"
            all_alerts.extend(active)
        except Exception:
            pass

        # Alert log
        try:
            log = _extract_data(_api_request("GET", "alertlog", params={"limit": min(300, limit)}), ['alertlog'])
            for e in log:
                all_alerts.append({
                    "id": f"log_{e.get('id', '')}",
                    "timestamp": e.get("datetime") or e.get("time_logged"),
                    "device_id": e.get("device_id"),
                    "message": e.get("details", ""),
                    "severity": e.get("severity", "info"),
                    "rule": e.get("rule", ""),
                    "state": e.get("state", 0),
                    "source": "alertlog"
                })
        except Exception:
            pass

        # Filter by date
        filtered = []
        for a in all_alerts:
            ts = a.get("timestamp") or a.get("datetime")
            if ts:
                dt = _safe_parse_datetime(ts)
                if dt and not (start <= dt <= end):
                    continue
            if severity:
                a_sev = str(a.get("severity", "")).lower()
                if severity.lower() not in a_sev:
                    continue
            filtered.append(a)

        filtered = filtered[:limit]
        return _R({"data": filtered, "count": len(filtered), "period_days": days})
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def diagnose_device(device: str) -> str:
    """Comprehensive device diagnostics with health score.
    [YES] "Diagnose device X", "Check health of switch01", "Why is device X down?".
    [NO] "Just show device info" -> use get_device_info().
    [NO] "Network overview" -> use network_health_overview().

    Args:
        device: Hostname, IP, or device ID."""
    try:
        dev = _resolve_device(device)
        if not dev:
            return _R({"error": f"Device not found: {device}"})

        device_id = dev["device_id"]
        diag = {
            "device": dev,
            "health_score": 0,
            "status": "analyzing"
        }

        # Port analysis
        port_score = 50
        try:
            ports_result = _api_request("GET", f"devices/{device_id}/ports")
            all_ports = _extract_data(ports_result, ['ports'])
            active_ports = [p for p in all_ports if not p.get('ignore') and not p.get('disabled')]
            quality = _evaluate_port_quality(active_ports, dev.get("os"))

            port_stats = {"up": 0, "down": 0, "unknown": 0}
            for p in active_ports:
                s = _normalize_port_status(p.get('ifOperStatus'))
                if s == 'up':
                    port_stats["up"] += 1
                elif s == 'down':
                    port_stats["down"] += 1
                else:
                    port_stats["unknown"] += 1

            diag["ports"] = {
                "total": len(all_ports),
                "active": len(active_ports),
                "status_breakdown": port_stats,
                "data_quality": quality
            }
            if active_ports:
                port_score = round((port_stats["up"] / len(active_ports)) * 100, 1)
        except Exception as e:
            diag["ports"] = {"error": str(e)}

        # Alert analysis
        alert_score = 100
        try:
            alerts = _extract_data(_api_request("GET", "alerts", params={"device_id": device_id}), ['alerts'])
            sev = {"critical": 0, "warning": 0, "info": 0}
            for a in alerts:
                s = str(a.get("severity", "")).lower()
                if "crit" in s or s == "5":
                    sev["critical"] += 1
                elif "warn" in s or s == "4":
                    sev["warning"] += 1
                else:
                    sev["info"] += 1

            diag["alerts"] = {"total": len(alerts), "severity": sev}
            alert_score = max(0, 100 - sev["critical"] * 30 - sev["warning"] * 10 - sev["info"] * 2)
        except Exception as e:
            diag["alerts"] = {"error": str(e)}

        # Health score: device_status 40%, ports 30%, alerts 30%
        dev_score = 100 if dev.get("status") == "up" else 0
        health = round(dev_score * 0.4 + port_score * 0.3 + alert_score * 0.3, 1)
        diag["health_score"] = health

        if health >= 90:
            diag["status"] = "excellent"
        elif health >= 75:
            diag["status"] = "good"
        elif health >= 50:
            diag["status"] = "fair"
        else:
            diag["status"] = "poor"

        # Recommendations
        recs = []
        if dev.get("status") != "up":
            recs.append(f"Device is {dev.get('status', 'unknown').upper()} - check connectivity and power")
        if diag.get("alerts", {}).get("severity", {}).get("critical", 0) > 0:
            recs.append(f"{diag['alerts']['severity']['critical']} critical alert(s) need attention")
        if diag.get("ports", {}).get("status_breakdown", {}).get("down", 0) > 0:
            recs.append(f"{diag['ports']['status_breakdown']['down']} port(s) are down")
        if not recs:
            recs.append("No issues detected")
        diag["recommendations"] = recs

        return _R(diag)
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def network_health_overview(location: Optional[str] = None, device_type: Optional[str] = None) -> str:
    """Network health dashboard with scores and problem devices.
    [YES] "How is the network?", "Network health overview", "Any problems?".
    [NO] "Show specific device" -> use get_device_info().
    [NO] "List all devices" -> use list_devices().

    Args:
        location: Filter by location.
        device_type: Filter by device type/OS."""
    try:
        report = {"health_score": 0, "status": "analyzing"}

        # Device stats
        dev_result = json.loads(list_devices(limit=0, location=location, os_filter=device_type))
        devices = dev_result.get("data", [])
        total = len(devices)

        stats = {"total": total, "up": 0, "down": 0, "disabled": 0}
        problems = []
        os_dist = {}

        for d in devices:
            s = d.get("status", "unknown")
            if s == "up":
                stats["up"] += 1
            elif s == "down":
                stats["down"] += 1
                problems.append({"device_id": d.get("device_id"), "hostname": d.get("hostname"),
                                 "sysName": d.get("sysName"), "ip": d.get("ip"),
                                 "reason": "Device DOWN", "severity": "critical"})
            elif s == "disabled":
                stats["disabled"] += 1
            os_name = d.get("os", "unknown")
            os_dist[os_name] = os_dist.get(os_name, 0) + 1

        report["device_stats"] = stats
        report["os_distribution"] = dict(sorted(os_dist.items(), key=lambda x: x[1], reverse=True)[:10])

        # Alert stats
        alert_result = json.loads(get_recent_alerts(limit=100))
        alerts = alert_result.get("data", [])
        alert_stats = {"total": len(alerts), "critical": 0, "warning": 0}

        for a in alerts:
            sev = str(a.get("severity", "")).lower()
            if "crit" in sev or sev == "5":
                alert_stats["critical"] += 1
            elif "warn" in sev or sev == "4":
                alert_stats["warning"] += 1

        report["alert_stats"] = alert_stats

        # Health score
        dev_health = (stats["up"] / max(total, 1)) * 60
        alert_penalty = (alert_stats["critical"] * 5 + alert_stats["warning"] * 2) / max(total, 1)
        alert_health = max(0, 40 - alert_penalty)
        score = round(dev_health + alert_health, 1)

        report["health_score"] = score
        report["status"] = "excellent" if score >= 90 else "good" if score >= 75 else "fair" if score >= 50 else "poor"
        report["problem_devices"] = problems[:10]
        report["problem_count"] = len(problems)

        # Recommendations
        recs = []
        if stats["down"] > 0:
            recs.append(f"{stats['down']} device(s) DOWN - investigate immediately")
        if alert_stats["critical"] > 0:
            recs.append(f"{alert_stats['critical']} critical alert(s) need attention")
        if total > 0:
            recs.append(f"Network uptime: {round(stats['up']/total*100, 1)}% ({stats['up']}/{total})")
        report["recommendations"] = recs

        return _R(report)
    except Exception as e:
        return _R({"error": str(e)})


def _get_base_url() -> str:
    """Extract base domain URL from API URL (strip /api/v0)."""
    url = config.BASE_URL
    for suffix in ['/api/v0/', '/api/v0']:
        if url.endswith(suffix):
            return url[:-len(suffix)]
    return url


def _try_custom_top_devices(metric_type: str, limit: int) -> Optional[List[Dict]]:
    """Try calling custom_top_devices.php helper on LibreNMS server.
    Returns list of ranked device dicts, or None if helper not deployed."""
    base = _get_base_url()
    url = f"{base}/custom_top_devices.php"
    try:
        resp = session.request("GET", url,
                               params={"type": metric_type, "limit": limit},
                               timeout=config.TIMEOUT)
        if resp.status_code == 200:
            result = resp.json()
            if result.get("status") == "ok" and isinstance(result.get("data"), list):
                return result["data"]
    except Exception:
        pass
    return None


def _build_health_ranking(metric_type: str, usage_field: str,
                          pct_key: str, count_key: str, limit: int) -> str:
    """Build device ranking by processor or mempool usage.
    Strategy 1: custom_top_devices.php helper (single SQL query, fast).
    Strategy 2: Per-device API calls (fallback, slow)."""
    try:
        # ── Strategy 1: Custom helper endpoint (recommended) ──
        custom_data = _try_custom_top_devices(metric_type, limit)
        if custom_data:
            return _R({"data": custom_data[:limit], "count": min(limit, len(custom_data)),
                        "source": "custom_top_devices"})

        # ── Strategy 2: Per-device API calls (fallback) ──
        devices = _paginate("devices", max_items=500)
        rankings = []
        up_count = 0
        api_ok = 0

        for d in devices:
            if not isinstance(d, dict):
                continue
            did = d.get("device_id")
            if not did or _device_status_str(d.get("status")) != "up":
                continue
            up_count += 1

            # Try multiple endpoint patterns
            items = []
            for ep in [f"devices/{did}/{metric_type}s",
                       f"devices/{did}/health/device_{metric_type}",
                       f"devices/{did}/health/{metric_type}"]:
                try:
                    result = _api_request("GET", ep, use_cache=True)
                    items = _extract_data(result)
                    if items:
                        break
                except Exception:
                    continue
            if not items:
                continue

            usages = []
            for item in items:
                val = item.get(usage_field) or item.get("sensor_current")
                if val is not None:
                    try:
                        usages.append(float(val))
                    except (ValueError, TypeError):
                        pass
            if not usages:
                continue

            api_ok += 1
            avg = round(sum(usages) / len(usages), 1)
            rankings.append({
                "device_id": did,
                "hostname": d.get("hostname"),
                "sysName": d.get("sysName"),
                "ip": d.get("ip"),
                pct_key: avg,
                count_key: len(usages)
            })

        rankings.sort(key=lambda x: x[pct_key], reverse=True)
        result = {"data": rankings[:limit], "count": min(limit, len(rankings))}

        if not rankings and up_count > 0:
            result["note"] = (
                f"No {metric_type} data via API ({up_count} up devices checked). "
                f"LibreNMS API does not expose {metric_type}/mempool values (known limitation). "
                f"Deploy custom_top_devices.php to LibreNMS server: "
                f"cp custom_top_devices.php /opt/librenms/html/ && "
                f"chown librenms:librenms /opt/librenms/html/custom_top_devices.php"
            )
        return _R(result)
    except Exception as e:
        return _R({"error": str(e)})


@mcp.tool()
def get_top_cpu(limit: int = 10) -> str:
    """Get devices ranked by CPU usage (highest first).
    [YES] "CPU排行", "CPU usage top 10", "哪些設備CPU最高?", "cpu使用率排行榜".
    [NO] "Memory排行" -> use get_top_memory().

    Args:
        limit: Top N devices (default 10)."""
    return _build_health_ranking("processor", "processor_usage",
                                 "cpu_usage_pct", "processor_count", limit)


@mcp.tool()
def get_top_memory(limit: int = 10) -> str:
    """Get devices ranked by memory usage (highest first).
    [YES] "Memory排行", "memory usage top 10", "記憶體使用率排行", "哪些設備記憶體最高?".
    [NO] "CPU排行" -> use get_top_cpu().

    Args:
        limit: Top N devices (default 10)."""
    return _build_health_ranking("mempool", "mempool_perc",
                                 "memory_usage_pct", "mempool_count", limit)


@mcp.tool()
def clear_cache() -> str:
    """Clear the internal API cache.
    [YES] Use when data seems stale or after making changes."""
    try:
        before = cache.stats()
        cache.clear()
        return _R({"status": "cleared", "keys_cleared": before["total_keys"]})
    except Exception as e:
        return _R({"error": str(e)})


# ───────────────────────── Main Entry Point ─────────────────────────

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="LibreNMS FastMCP Server v4.0.0 - Slim (Weak-Model Optimized)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # stdio mode (default):
  python3 mcp_librenms.py --url "http://192.168.1.68" --token "your_token"

  # Streamable HTTP mode:
  python3 mcp_librenms.py --transport streamable-http --port 8000 --url "http://192.168.1.68" --token "your_token"
        """
    )
    parser.add_argument('--url', '--host', dest='url',
                        help='LibreNMS base URL')
    parser.add_argument('--token', '--api-token', dest='token',
                        help='LibreNMS API token')
    parser.add_argument('--verify-ssl', type=lambda x: x.lower() in ('true', '1', 'yes'),
                        default=None, help='Verify SSL (true/false)')
    parser.add_argument('--cache-ttl', type=int, default=None, help='Cache TTL seconds (default: 300)')
    parser.add_argument('--timeout', type=int, default=None, help='API timeout seconds (default: 30)')
    parser.add_argument('--max-retries', type=int, default=None, help='Max retries (default: 3)')
    parser.add_argument('--batch-size', type=int, default=None, help='Batch size (default: 200)')
    parser.add_argument('--transport', choices=['stdio', 'streamable-http'], default='stdio',
                        help='Transport: stdio (default) or streamable-http')
    parser.add_argument('--listen', default='0.0.0.0', help='HTTP bind address (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8000, help='HTTP port (default: 8000)')
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()
    config = Config(args)
    cache = SimpleCache(config.CACHE_TTL)
    initialize_session()

    logger.info("=" * 60)
    logger.info("LibreNMS FastMCP Server v4.0.0 - Slim (20 tools)")
    logger.info("=" * 60)
    logger.info(f"Transport: {args.transport}")
    if args.transport == 'streamable-http':
        logger.info(f"HTTP Listen: {args.listen}:{args.port}")
    logger.info(f"Cache TTL={config.CACHE_TTL}s, Timeout={config.TIMEOUT}s")
    logger.info("=" * 60)

    if args.transport == 'streamable-http':
        mcp.run(transport='streamable-http', host=args.listen, port=args.port)
    else:
        mcp.run(transport='stdio')
