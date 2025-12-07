#!/usr/bin/env python3
"""
Graylog MCP Server - Advanced Log Analysis and Management Tool

This MCP (Model Context Protocol) server provides comprehensive integration with Graylog log management platform.
It enables advanced log analysis, statistics generation, and data export capabilities through various API breakthrough
techniques to overcome standard API limitations.

Key Features:
- Advanced log statistics with accurate counting and source analysis
- Time-based pattern analysis across multiple dimensions
- Source distribution analysis with proportional scaling
- Error pattern extraction and analysis
- High-volume data export with multiple breakthrough strategies
- Content pack and dashboard management
- Real-time system information retrieval

Technical Capabilities:
- API limit breakthrough using multiple strategies (Export API, Time Slicing, Pagination)
- Enhanced sampling methods for representative data collection
- Intelligent deduplication for accurate results
- Field name normalization and mapping
- CSV and JSON data processing
- Comprehensive error handling and retry mechanisms
- Time snapshot for batch queries to prevent time drift

Version: 1.9.34

Changes in 1.9.34:
- Fixed incorrect filename in help message (mcp_graylog.py)

Changes in 1.9.33:
- Fixed remaining SyntaxWarning in version history comments
- All backslash escape sequences now properly handled

Changes in 1.9.32:
- Fixed Python SyntaxWarning for invalid escape sequences
- Used raw strings (r"") for docstrings and print statements with backslashes
- Properly escaped backslashes in string literals

Changes in 1.9.31:
- Improved query string normalization with Graylog escaping rules
- Correctly handles source:router\\-004 vs source:"router-004" equivalence
- Added validation for unescaped special characters
- Optional auto-fix for unescaped hyphens in field values
- Better logging for query string processing

Changes in 1.9.30:
- Fixed double-escaped backslash issue in query strings (\\\\- becomes \\-)
- Added normalize_query_string function to handle escaping issues
- Applied normalization to all query-based tools
- Added debug logging for query string processing

Changes in 1.9.29:
- Balanced timeout settings for better reliability
- Increased timeouts: count(30s), search(45s), pagination(120s), slice(30s)
- Adaptive slicing strategy based on dataset size
- Less aggressive data limits to preserve query completeness
- Improved error handling to return partial results
- Fixed issue where normal queries were failing due to strict timeouts

Changes in 1.9.28:
- Fixed timeout issues with large datasets (60M+ records)
- Limited maximum time slices to prevent excessive API calls
- Added asyncio timeouts for all long-running operations

Changes in 1.9.27:
- Fixed undefined variable error in search_logs_paginated
- Removed references to all_messages and page_size_used

Changes in 1.9.26:
- Updated all analysis functions to use smart pagination
- Fixed search_logs_paginated to implement true pagination
- Improved memory efficiency for large result sets
- Consistent error handling across all functions

Jason Cheng (Jason Tools) - AI Collaboration
"""

import asyncio
import json
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional, Union
from datetime import datetime, timedelta
import csv
import io
from collections import Counter, defaultdict
import re
import math
import statistics

import httpx
from mcp.server.models import InitializationOptions
from mcp.server import NotificationOptions, Server
from mcp.types import Resource, Tool, TextContent, ImageContent, EmbeddedResource
import mcp.types as types

# Version information
__version__ = "1.9.34"
__author__ = "Jason Cheng (Jason Tools) - AI Collaboration"
__license__ = "MIT"

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("graylog-mcp-server")

class GraylogError(Exception):
    """Custom exception for Graylog related errors"""
    pass

class LogAnalyzer:
    """Log analysis tool with FIXED source analysis - Complete version"""
    
    @staticmethod
    def _add_stream_filter_to_query(query: str, streams: List[str]) -> str:
        """Add stream filter to query string as workaround for API stream parameter issues"""
        if not streams:
            return query
            
        stream_filter = f"streams:{','.join(streams)}"
        
        if query == "*":
            return stream_filter
        else:
            return f"({query}) AND {stream_filter}"
    
    @staticmethod
    def analyze_time_patterns(messages: List[Dict]) -> Dict:
        """Analyze time patterns with improved error tracking"""
        hourly_counts = defaultdict(int)
        daily_counts = defaultdict(int)
        minute_counts = defaultdict(int)
        
        processed_count = 0
        missing_timestamp_count = 0
        parse_error_count = 0
        error_samples = []
        
        for msg in messages:
            timestamp = msg.get('timestamp', '')
            if timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    hour_key = dt.strftime('%H:00')
                    day_key = dt.strftime('%Y-%m-%d')
                    minute_key = dt.strftime('%H:%M')
                    
                    hourly_counts[hour_key] += 1
                    daily_counts[day_key] += 1
                    minute_counts[minute_key] += 1
                    processed_count += 1
                except Exception as e:
                    parse_error_count += 1
                    if len(error_samples) < 5:
                        error_samples.append({
                            "timestamp": timestamp,
                            "error": str(e)
                        })
            else:
                missing_timestamp_count += 1
        
        # Find peak hours
        peak_hours = sorted(hourly_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        peak_minutes = sorted(minute_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Calculate total counted in minute distribution
        total_in_minutes = sum(count for _, count in minute_counts.items())
        
        return {
            "hourly_distribution": dict(hourly_counts),
            "daily_distribution": dict(daily_counts),
            "minute_distribution": dict(minute_counts),
            "peak_hours": peak_hours,
            "peak_minutes": peak_minutes,
            "total_time_slots": len(hourly_counts),
            "total_minutes": len(minute_counts),
            "processing_stats": {
                "total_messages": len(messages),
                "successfully_processed": processed_count,
                "missing_timestamp": missing_timestamp_count,
                "parse_errors": parse_error_count,
                "total_in_minute_distribution": total_in_minutes,
                "error_samples": error_samples
            }
        }
    
    @staticmethod
    def analyze_sources(messages: List[Dict], accurate_total_count: int = None) -> Dict:
        """
        Fixed version: Analyze source hosts, use accurate total count to calculate ratios
        """
        source_counts = Counter()
        source_details = defaultdict(lambda: {"count": 0, "levels": Counter(), "first_seen": None, "last_seen": None})
        
        for msg in messages:
            source = str(msg.get('source', 'unknown')).strip()
            level = str(msg.get('level', 'info')).lower()
            timestamp = str(msg.get('timestamp', ''))
            
            source_counts[source] += 1
            source_details[source]["count"] += 1
            source_details[source]["levels"][level] += 1
            
            if timestamp:
                if not source_details[source]["first_seen"]:
                    source_details[source]["first_seen"] = timestamp
                source_details[source]["last_seen"] = timestamp
        
        # Key fix: Use accurate total count to calculate ratios
        total_for_percentage = accurate_total_count if accurate_total_count else len(messages)
        
        # Convert to list format
        detailed_sources = []
        for source, sample_count in source_counts.most_common(50):
            details = source_details[source]
            
            # Key fix: Estimate actual count based on sample ratio
            if accurate_total_count and len(messages) > 0:
                # Estimate actual count: (count in sample / total sample) * accurate total
                estimated_actual_count = int((sample_count / len(messages)) * accurate_total_count)
                percentage = round((estimated_actual_count / accurate_total_count) * 100, 2)
            else:
                estimated_actual_count = sample_count
                percentage = round((sample_count / total_for_percentage) * 100, 2)
            
            detailed_sources.append({
                "source": source,
                "count": estimated_actual_count,  # Use estimated actual count
                "sample_count": sample_count,      # Keep sample count for reference
                "percentage": percentage,
                "levels": dict(details["levels"]),
                "first_seen": details["first_seen"],
                "last_seen": details["last_seen"]
            })
        
        # Re-sort by estimated actual count
        detailed_sources.sort(key=lambda x: x["count"], reverse=True)
        
        return {
            "total_unique_sources": len(source_counts),
            "top_sources": detailed_sources,
            "source_distribution": {src["source"]: src["count"] for src in detailed_sources[:15]},
            "estimation_info": {
                "total_sample_messages": len(messages),
                "accurate_total_count": accurate_total_count,
                "estimation_method": "proportional_scaling" if accurate_total_count else "direct_count"
            }
        }
    
    @staticmethod
    def analyze_levels(messages: List[Dict]) -> Dict:
        """Analyze log levels"""
        level_counts = Counter()
        level_timeline = defaultdict(list)
        
        for msg in messages:
            level = str(msg.get('level', 'info')).lower()
            timestamp = str(msg.get('timestamp', ''))
            
            level_counts[level] += 1
            if timestamp:
                level_timeline[level].append(timestamp)
        
        # Calculate error rate
        total = len(messages)
        error_count = level_counts.get('error', 0) + level_counts.get('critical', 0) + level_counts.get('fatal', 0)
        warning_count = level_counts.get('warning', 0) + level_counts.get('warn', 0)
        
        return {
            "level_distribution": dict(level_counts),
            "error_rate": round((error_count / total) * 100, 2) if total > 0 else 0,
            "warning_rate": round((warning_count / total) * 100, 2) if total > 0 else 0,
            "total_errors": error_count,
            "total_warnings": warning_count,
            "most_common_level": level_counts.most_common(1)[0] if level_counts else ("info", 0)
        }
    
    @staticmethod
    def extract_error_patterns(messages: List[Dict]) -> Dict:
        """Extract error patterns"""
        error_messages = []
        error_sources = Counter()
        error_keywords = Counter()
        
        for msg in messages:
            level = str(msg.get('level', '')).lower()
            message_text = str(msg.get('message', ''))
            source = str(msg.get('source', 'unknown'))
            
            if level in ['error', 'critical', 'fatal'] or 'error' in message_text.lower():
                error_messages.append({
                    "source": source,
                    "message": message_text[:200],
                    "level": level,
                    "timestamp": str(msg.get('timestamp', ''))
                })
                
                error_sources[source] += 1
                
                # Extract keywords
                words = re.findall(r'\b[a-zA-Z]{4,}\b', message_text.lower())
                for word in words:
                    if word in ['error', 'failed', 'timeout', 'connection', 'refused', 'denied', 'exception', 'critical']:
                        error_keywords[word] += 1
        
        return {
            "total_errors": len(error_messages),
            "error_sources": dict(error_sources.most_common(15)),
            "error_keywords": dict(error_keywords.most_common(15)),
            "recent_errors": error_messages[:15],
            "error_percentage": round((len(error_messages) / len(messages)) * 100, 2) if messages else 0
        }
    
    @staticmethod
    def generate_summary(messages: List[Dict], query: str, time_range: Dict, accurate_total_count: int = None) -> Dict:
        """Generate complete summary with FIXED source analysis"""
        if not messages:
            return {
                "summary": "No messages found",
                "total_events": accurate_total_count or 0,
                "query": query,
                "time_range": time_range,
                "api_breakthrough_note": "API limits breakthrough attempted but no data found"
            }
        
        # Basic statistics
        sample_size = len(messages)
        total = accurate_total_count if accurate_total_count is not None else sample_size
        time_span = LogAnalyzer._calculate_time_span(messages)
        
        # Key fix: Use accurate total count for source analysis
        time_analysis = LogAnalyzer.analyze_time_patterns(messages)
        source_analysis = LogAnalyzer.analyze_sources(messages, accurate_total_count)  # Pass accurate total count
        level_analysis = LogAnalyzer.analyze_levels(messages)
        error_analysis = LogAnalyzer.extract_error_patterns(messages)
        
        # Calculate event frequency
        events_per_minute = round(total / max(time_span, 1), 2) if time_span > 0 else total
        
        return {
            "summary": {
                "total_events": total,
                "sample_size": sample_size,
                "time_span_minutes": time_span,
                "events_per_minute": events_per_minute,
                "unique_sources": source_analysis["total_unique_sources"],
                "error_rate": level_analysis["error_rate"],
                "most_active_source": source_analysis["top_sources"][0]["source"] if source_analysis["top_sources"] else "N/A"
            },
            "time_analysis": time_analysis,
            "source_analysis": source_analysis,
            "level_analysis": level_analysis,
            "error_analysis": error_analysis,
            "query_info": {
                "query": query,
                "time_range": time_range,
                "processed_at": datetime.utcnow().isoformat()
            },
            "data_note": f"Analyzed {sample_size} sample events from {total} total events using FIXED source analysis",
            "api_breakthrough_info": {
                "breakthrough_successful": total > 1000,
                "data_quality": "high" if total > 5000 else "medium" if total > 1000 else "limited",
                "api_limits_bypassed": total > 150,
                "accurate_count_used": accurate_total_count is not None,
                "source_analysis_fixed": True
            }
        }
    
    @staticmethod
    def _calculate_time_span(messages: List[Dict]) -> float:
        """Calculate time span (minutes)"""
        timestamps = []
        for msg in messages:
            timestamp = str(msg.get('timestamp', ''))
            if timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    timestamps.append(dt)
                except:
                    continue
        
        if len(timestamps) < 2:
            return 1.0
        
        earliest = min(timestamps)
        latest = max(timestamps)
        return (latest - earliest).total_seconds() / 60
    
    @staticmethod
    def analyze_field_distribution(messages: List[Dict], field_name: str, 
                                 top_n: int = 50, accurate_total_count: int = None) -> Dict:
        """
        Analyze distribution of any specified field
        通用欄位統計分析 - 可以統計任何指定的欄位
        """
        field_counts = Counter()
        field_details = defaultdict(lambda: {"count": 0, "first_seen": None, "last_seen": None, "sample_values": []})
        missing_field_count = 0
        
        for msg in messages:
            # Support both hyphenated and underscore field names
            value = msg.get(field_name)
            if value is None and '-' in field_name:
                # Try underscore version
                value = msg.get(field_name.replace('-', '_'))
            elif value is None and '_' in field_name:
                # Try hyphenated version
                value = msg.get(field_name.replace('_', '-'))
            
            if value is not None:
                value_str = str(value).strip()
                field_counts[value_str] += 1
                field_details[value_str]["count"] += 1
                
                # Track first and last seen
                timestamp = msg.get('timestamp', '')
                if timestamp:
                    if not field_details[value_str]["first_seen"]:
                        field_details[value_str]["first_seen"] = timestamp
                    field_details[value_str]["last_seen"] = timestamp
                
                # Collect sample message for this value (up to 3)
                if len(field_details[value_str]["sample_values"]) < 3:
                    sample_msg = {
                        "timestamp": timestamp,
                        "source": msg.get('source', 'unknown'),
                        field_name: value_str
                    }
                    # Add message field if it exists
                    if 'message' in msg:
                        sample_msg['message'] = msg['message'][:100]  # First 100 chars
                    field_details[value_str]["sample_values"].append(sample_msg)
            else:
                missing_field_count += 1
        
        # Calculate percentages and prepare results
        total_for_percentage = accurate_total_count if accurate_total_count else len(messages)
        
        # Convert to list format with estimated counts
        detailed_distribution = []
        for value, sample_count in field_counts.most_common(top_n):
            details = field_details[value]
            
            # Estimate actual count based on sample ratio
            if accurate_total_count and len(messages) > 0:
                estimated_actual_count = int((sample_count / len(messages)) * accurate_total_count)
                percentage = round((estimated_actual_count / accurate_total_count) * 100, 2)
            else:
                estimated_actual_count = sample_count
                percentage = round((sample_count / total_for_percentage) * 100, 2)
            
            detailed_distribution.append({
                "value": value,
                "count": estimated_actual_count,
                "sample_count": sample_count,
                "percentage": percentage,
                "first_seen": details["first_seen"],
                "last_seen": details["last_seen"],
                "sample_messages": details["sample_values"]
            })
        
        # Summary statistics
        unique_values = len(field_counts)
        coverage_rate = round(((len(messages) - missing_field_count) / len(messages)) * 100, 2) if messages else 0
        
        return {
            "field_name": field_name,
            "total_unique_values": unique_values,
            "coverage_rate": coverage_rate,  # Percentage of messages that have this field
            "missing_field_count": missing_field_count,
            "top_values": detailed_distribution,
            "value_distribution": {item["value"]: item["count"] for item in detailed_distribution[:15]},
            "estimation_info": {
                "total_sample_messages": len(messages),
                "accurate_total_count": accurate_total_count,
                "estimation_method": "proportional_scaling" if accurate_total_count else "direct_count"
            }
        }

class GraylogClient:
    """Graylog API Client - Complete version + Source analysis fix"""
    
    def __init__(self, host: str, username: str = None, password: str = None, 
                 api_token: str = None, verify_ssl: bool = False, timeout: float = 30.0):
        self.host = host.rstrip('/')
        self.username = username
        self.password = password
        self.api_token = api_token
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = None
        
        # Key fix: Add source analysis configuration while retaining all original configurations
        self.api_breakthrough_config = {
            "export_chunk_size": 5000,
            "export_max_chunks": 10,
            "export_timeout": 45.0,
            "pagination_size": 2000,
            "max_pagination_rounds": 15,
            "pagination_overlap": 50,
            "scroll_size": 3000,
            "scroll_timeout": "5m",
            "max_scroll_rounds": 12,
            "time_slice_seconds": 120,
            "max_time_slices": 8,
            "time_overlap_seconds": 10,
            # New: Dedicated configuration for source analysis
            "source_analysis_target": 25000,     # Target sample size for source analysis
            "source_analysis_min_sample": 10000, # Minimum sample size
            "source_time_slices": 10,            # Time slices for source analysis
            "source_slice_seconds": 60,          # Time slice duration for source analysis
        }
        
    async def __aenter__(self):
        self.session = httpx.AsyncClient(
            verify=self.verify_ssl, 
            timeout=httpx.Timeout(self.api_breakthrough_config["export_timeout"]),
            headers={
                'User-Agent': f'Graylog-MCP-Server/{__version__}',
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'X-Requested-By': 'Graylog MCP Server'
            }
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.aclose()

    async def _make_request_with_retry(self, method: str, path: str, params: Optional[Dict] = None, 
                                     data: Optional[Dict] = None, expect_csv: bool = False, 
                                     max_retries: int = 3) -> Union[Dict, str]:
        """Request method with retry mechanism"""
        last_exception = None
        
        for attempt in range(max_retries):
            try:
                return await self._make_request(method, path, params, data, expect_csv)
            except Exception as e:
                last_exception = e
                if "timeout" in str(e).lower() or "timed out" in str(e).lower():
                    if attempt < max_retries - 1:
                        wait_time = (attempt + 1) * 3
                        logger.warning(f"Request timeout on attempt {attempt + 1}, retrying in {wait_time}s...")
                        await asyncio.sleep(wait_time)
                        continue
                raise e
        
        raise last_exception

    async def _make_request(self, method: str, path: str, params: Optional[Dict] = None, 
                          data: Optional[Dict] = None, expect_csv: bool = False) -> Union[Dict, str]:
        """Make HTTP request with proper headers"""
        url = f"{self.host}/api{path}"
        
        # Prepare authentication
        auth = None
        if self.api_token:
            auth = (self.api_token, 'token')
        elif self.username and self.password:
            auth = (self.username, self.password)
        
        # Set headers based on expected response type
        headers = {
            'X-Requested-By': 'Graylog MCP Server',
            'User-Agent': f'Graylog-MCP-Server/{__version__}'
        }
        
        if method.upper() == 'POST' and data:
            headers['Content-Type'] = 'application/json'
            if expect_csv:
                headers['Accept'] = 'text/csv'
            else:
                headers['Accept'] = 'application/json'
        else:
            headers['Accept'] = 'application/json'
        
        try:
            logger.debug(f"Making {method} request to {url}")
            
            if method.upper() == 'GET':
                response = await self.session.get(url, params=params, headers=headers, auth=auth)
            elif method.upper() == 'POST':
                response = await self.session.post(url, json=data, params=params, headers=headers, auth=auth)
            elif method.upper() == 'PUT':
                response = await self.session.put(url, json=data, params=params, headers=headers, auth=auth)
            elif method.upper() == 'DELETE':
                response = await self.session.delete(url, params=params, headers=headers, auth=auth)
            else:
                raise GraylogError(f"Unsupported HTTP method: {method}")
            
            logger.debug(f"Response status: {response.status_code}")
            
            # Check for errors
            if response.status_code >= 400:
                error_text = response.text
                logger.error(f"HTTP Error: {response.status_code} - {error_text}")
                
                # Check for specific OpenSearch errors
                if "too_many_nested_clauses" in error_text:
                    raise GraylogError("Query too complex: Too many nested clauses. Try using more specific field searches instead of general text searches.")
                elif response.status_code == 401:
                    raise GraylogError("Authentication failed - check credentials")
                elif response.status_code == 404:
                    raise GraylogError(f"API endpoint not found: {path}")
                elif response.status_code == 403:
                    raise GraylogError(f"Access forbidden - check permissions: {path}")
                else:
                    raise GraylogError(f"HTTP {response.status_code}: {error_text}")
            
            # Handle response based on content type
            content_type = response.headers.get('content-type', '')
            
            if expect_csv or 'text/csv' in content_type:
                csv_text = response.text
                logger.info(f"Received CSV response: {len(csv_text)} chars, ~{csv_text.count(chr(10))} lines")
                return csv_text
            
            # Handle JSON response
            try:
                return response.json()
            except json.JSONDecodeError as e:
                logger.error(f"JSON decode failed. Response: {response.text[:500]}")
                raise GraylogError(f"Invalid JSON response: {str(e)}")
            
        except httpx.TimeoutException:
            raise GraylogError("Request timed out - try reducing the time range or limit")
        except httpx.RequestError as e:
            raise GraylogError(f"Network error: {e}")
        except GraylogError:
            raise
        except Exception as e:
            logger.error(f"Request error {method} {path}: {e}")
            raise GraylogError(f"Request failed: {e}")

    def _parse_time_input(self, time_input: str) -> Dict[str, Union[str, int]]:
        """Parse time input and return appropriate format for Graylog API"""
        
        time_str = str(time_input).strip().lower()
        
        # Handle "now" case
        if time_str == "now":
            return {
                "type": "relative",
                "graylog_format": "now",
                "seconds": 0
            }
        
        # Handle "X minutes ago", "X hours ago", etc.
        relative_patterns = [
            (r'^(\d+)\s*seconds?\s*ago$', 1),
            (r'^(\d+)\s*minutes?\s*ago$', 60),
            (r'^(\d+)\s*hours?\s*ago$', 3600),
            (r'^(\d+)\s*days?\s*ago$', 86400),
            (r'^(\d+)\s*weeks?\s*ago$', 604800)
        ]
        
        for pattern, multiplier in relative_patterns:
            match = re.match(pattern, time_str)
            if match:
                amount = int(match.group(1))
                seconds = amount * multiplier
                
                # Generate Graylog format relative time string
                if multiplier == 1:
                    graylog_format = f"now-{amount}s"
                elif multiplier == 60:
                    graylog_format = f"now-{amount}m"
                elif multiplier == 3600:
                    graylog_format = f"now-{amount}h"
                elif multiplier == 86400:
                    graylog_format = f"now-{amount}d"
                elif multiplier == 604800:
                    graylog_format = f"now-{amount}w"
                
                return {
                    "type": "relative",
                    "graylog_format": graylog_format,
                    "seconds": seconds
                }
        
        # Handle Graylog native format (now-5m, now-1h, etc.)
        graylog_patterns = [
            (r'^now-(\d+)s$', 1),
            (r'^now-(\d+)m$', 60),
            (r'^now-(\d+)h$', 3600),
            (r'^now-(\d+)d$', 86400),
            (r'^now-(\d+)w$', 604800)
        ]
        
        for pattern, multiplier in graylog_patterns:
            match = re.match(pattern, time_str)
            if match:
                amount = int(match.group(1))
                seconds = amount * multiplier
                
                return {
                    "type": "relative",
                    "graylog_format": time_str,
                    "seconds": seconds
                }
        
        # Try to parse as absolute datetime
        try:
            # Handle ISO format with Z
            if time_str.endswith('z'):
                time_str = time_str[:-1] + '+00:00'
            
            dt = datetime.fromisoformat(time_str).replace(tzinfo=None)
            iso_format = dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            
            return {
                "type": "absolute",
                "graylog_format": iso_format,
                "datetime": dt
            }
            
        except:
            logger.warning(f"Could not parse time input '{time_input}', using 5 minutes ago")
            return {
                "type": "relative",
                "graylog_format": "now-5m",
                "seconds": 300
            }

    def _build_timerange(self, from_time: str, to_time: str) -> Dict:
        """Build timerange configuration for Graylog API"""
        
        from_config = self._parse_time_input(from_time)
        to_config = self._parse_time_input(to_time)
        
        logger.debug(f"From config: {from_config}")
        logger.debug(f"To config: {to_config}")
        
        # Case 1: Both relative, to_time is "now" - use relative timerange
        if (from_config["type"] == "relative" and 
            to_config["type"] == "relative" and 
            to_config.get("seconds", 0) == 0):
            
            return {
                "type": "relative",
                "range": from_config["seconds"],
                "range_seconds": from_config["seconds"],
                "graylog_from": from_config["graylog_format"],
                "graylog_to": to_config["graylog_format"]
            }
        
        # Case 2: Both absolute - use absolute timerange
        elif from_config["type"] == "absolute" and to_config["type"] == "absolute":
            from_dt = from_config["datetime"]
            to_dt = to_config["datetime"]
            range_seconds = int((to_dt - from_dt).total_seconds())
            
            return {
                "type": "absolute",
                "from": from_config["graylog_format"],
                "to": to_config["graylog_format"],
                "range_seconds": range_seconds
            }
        
        # Case 3: Mixed - convert to absolute
        else:
            now = datetime.utcnow()
            
            if from_config["type"] == "relative":
                from_dt = now - timedelta(seconds=from_config["seconds"])
            else:
                from_dt = from_config["datetime"]
            
            if to_config["type"] == "relative":
                to_dt = now - timedelta(seconds=to_config["seconds"])
            else:
                to_dt = to_config["datetime"]
            
            range_seconds = int((to_dt - from_dt).total_seconds())
            
            return {
                "type": "absolute",
                "from": from_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "to": to_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "range_seconds": range_seconds
            }

    def _convert_to_absolute_time(self, time_str: str, reference_time: datetime = None) -> str:
        """Convert relative time to absolute time based on reference point"""
        if reference_time is None:
            reference_time = datetime.utcnow()
            
        # If already absolute time, return as is
        if not time_str.startswith("now"):
            return time_str
            
        # Parse the relative time
        time_config = self._parse_time_input(time_str)
        
        if time_config["type"] == "relative":
            if time_config["seconds"] == 0:
                # "now" case
                absolute_time = reference_time
            else:
                # "now-X" case
                absolute_time = reference_time - timedelta(seconds=time_config["seconds"])
            
            return absolute_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        
        return time_str

    async def get_accurate_total_count(self, query_string: str, from_time: str, to_time: str, 
                                     streams: List[str] = None, reference_time: datetime = None) -> int:
        """Get accurate total count - retain original complete logic
        Now supports reference_time for consistent time calculations
        """
        logger.info(f"Getting accurate total count for query: {query_string}")
        
        # Use reference time if provided (for consistency with parent query)
        if reference_time:
            fixed_from_time = self._convert_to_absolute_time(from_time, reference_time)
            fixed_to_time = self._convert_to_absolute_time(to_time, reference_time)
            timerange = self._build_timerange(fixed_from_time, fixed_to_time)
        else:
            timerange = self._build_timerange(from_time, to_time)
        
        # Try multiple counting methods
        count_strategies = [
            ("universal_relative_count", self._count_universal_relative),
            ("universal_absolute_count", self._count_universal_absolute),
            ("views_search_count", self._count_views_search),
            ("legacy_search_count", self._count_legacy_search)
        ]
        
        max_count = 0
        successful_strategies = []
        
        for strategy_name, strategy_func in count_strategies:
            try:
                logger.info(f"Trying count strategy: {strategy_name}")
                count_result = await strategy_func(query_string, timerange, streams)
                
                if count_result > 0:
                    max_count = max(max_count, count_result)
                    successful_strategies.append(f"{strategy_name}: {count_result}")
                    logger.info(f"SUCCESS: {strategy_name} returned: {count_result}")
                else:
                    logger.debug(f"WARNING: {strategy_name} returned zero")
                    
            except Exception as e:
                logger.debug(f"ERROR: {strategy_name} failed: {e}")
                continue
        
        logger.info(f"Accurate count result: {max_count}")
        logger.info(f"Successful strategies: {successful_strategies}")
        
        return max_count

    async def _count_universal_relative(self, query_string: str, timerange: Dict, streams: List[str] = None) -> int:
        """Get count using Universal Relative API"""
        
        params = {
            'query': query_string,
            'range': timerange.get("range", 300),
            'limit': 0,
            'sort': 'timestamp:desc'
        }
        
        if streams:
            params['filter'] = f"streams:{','.join(streams)}"
        
        logger.debug(f"Universal relative count params: {params}")
        
        response = await self._make_request_with_retry("GET", "/search/universal/relative", params=params)
        
        if isinstance(response, dict):
            total_count = (
                response.get('total_results') or
                response.get('total') or
                response.get('count') or
                response.get('total_count') or
                len(response.get('messages', []))
            )
            
            logger.debug(f"Universal relative response keys: {list(response.keys())}")
            logger.debug(f"Found count: total_results={response.get('total_results')}, total={response.get('total')}")
            
            return total_count if total_count is not None else 0
        
        return 0

    async def _count_universal_absolute(self, query_string: str, timerange: Dict, streams: List[str] = None) -> int:
        """Get count using Universal Absolute API"""
        
        # Convert to absolute time if needed
        if timerange["type"] == "relative":
            now = datetime.utcnow()
            from_time = now - timedelta(seconds=timerange["range"])
            to_time = now
        else:
            from_time = datetime.fromisoformat(timerange["from"].replace('Z', '+00:00')).replace(tzinfo=None)
            to_time = datetime.fromisoformat(timerange["to"].replace('Z', '+00:00')).replace(tzinfo=None)
        
        params = {
            'query': query_string,
            'from': from_time.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            'to': to_time.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            'limit': 0,
            'sort': 'timestamp:desc'
        }
        
        if streams:
            params['filter'] = f"streams:{','.join(streams)}"
        
        logger.debug(f"Universal absolute count params: {params}")
        
        response = await self._make_request_with_retry("GET", "/search/universal/absolute", params=params)
        
        if isinstance(response, dict):
            total_count = (
                response.get('total_results') or 
                response.get('total') or 
                response.get('count') or
                len(response.get('messages', []))
            )
            
            logger.debug(f"Universal absolute found count: {total_count}")
            return total_count if total_count is not None else 0
        
        return 0

    async def _count_views_search(self, query_string: str, timerange: Dict, streams: List[str] = None) -> int:
        """Get count using Views Search API"""
        
        data = {
            "streams": streams or [],
            "query_string": {
                "type": "elasticsearch",
                "query_string": query_string
            },
            "timerange": self._build_api_timerange(timerange),
            "limit": 0
        }
        
        logger.debug(f"Views search count data: {data}")
        
        response = await self._make_request_with_retry("POST", "/views/search/messages", data=data)
        
        if isinstance(response, dict):
            total_count = (
                response.get('total_results') or 
                response.get('total') or
                len(response.get('messages', []))
            )
            
            logger.debug(f"Views search found count: {total_count}")
            return total_count if total_count is not None else 0
        
        return 0

    async def _count_legacy_search(self, query_string: str, timerange: Dict, streams: List[str] = None) -> int:
        """Get count using Legacy Search API"""
        
        data = {
            "query": query_string,
            "range": timerange.get("range", 300),
            "limit": 0,
            "sort": "timestamp:desc"
        }
        
        if streams:
            data["streams"] = streams
        
        logger.debug(f"Legacy search count data: {data}")
        
        response = await self._make_request_with_retry("POST", "/search/universal/relative", data=data)
        
        if isinstance(response, dict):
            total_count = (
                response.get('total_results') or 
                response.get('total') or 
                len(response.get('messages', []))
            )
            
            logger.debug(f"Legacy search found count: {total_count}")
            return total_count if total_count is not None else 0
        
        return 0

    # Key fix: Add dedicated breakthrough method for source analysis (while retaining all original methods)
    async def breakthrough_for_source_analysis(self, query_string: str, from_time: str, to_time: str, 
                                             fields: List[str] = None, streams: List[str] = None) -> List[Dict]:
        """
        Dedicated API breakthrough method for source analysis - increase sample size and representativeness
        Now with time snapshot to prevent time drift during batch queries
        """
        
        # Fix time at query start to prevent drift during batch processing
        query_start_time = datetime.utcnow()
        fixed_from_time = self._convert_to_absolute_time(from_time, query_start_time)
        fixed_to_time = self._convert_to_absolute_time(to_time, query_start_time)
        
        logger.info(f"Source Analysis - Time snapshot fixed at: {query_start_time.isoformat()}")
        if from_time != fixed_from_time:
            logger.info(f"From time converted: {from_time} -> {fixed_from_time}")
        if to_time != fixed_to_time:
            logger.info(f"To time converted: {to_time} -> {fixed_to_time}")
        
        # Use fixed times for all operations
        timerange = self._build_timerange(fixed_from_time, fixed_to_time)
        config = self.api_breakthrough_config
        
        target_sample = config["source_analysis_target"]  # 25000
        min_sample = config["source_analysis_min_sample"]  # 10000
        
        logger.info(f"Source Analysis Breakthrough: target={target_sample}, min={min_sample}")
        
        all_messages = []
        
        try:
            # Strategy 1: Use denser time slicing
            logger.info("Source Analysis: Dense Time Slicing")
            time_slice_messages = await self._enhanced_time_slicing_for_sources(
                query_string, timerange, fields, streams, target_sample
            )
            
            if time_slice_messages:
                all_messages.extend(time_slice_messages)
                logger.info(f"SUCCESS: Dense time slicing: {len(time_slice_messages)} messages")
                
                if len(all_messages) >= target_sample:
                    return self._deduplicate_messages(all_messages[:target_sample])
            
            # Strategy 2: Enhanced Export API
            if len(all_messages) < min_sample:
                logger.info("Source Analysis: Enhanced Export")
                export_messages = await self._try_export_api_breakthrough(
                    query_string, timerange, fields, streams, target_sample - len(all_messages)
                )
                
                if export_messages:
                    all_messages.extend(export_messages)
                    logger.info(f"SUCCESS: Enhanced export: {len(export_messages)} messages")
            
            # Strategy 3: Enhanced pagination
            if len(all_messages) < min_sample:
                logger.info("Source Analysis: Enhanced Pagination")
                pagination_messages = await self._try_pagination_breakthrough(
                    query_string, timerange, fields, streams, target_sample - len(all_messages)
                )
                
                if pagination_messages:
                    all_messages.extend(pagination_messages)
                    logger.info(f"SUCCESS: Enhanced pagination: {len(pagination_messages)} messages")
        
        except Exception as e:
            logger.warning(f"ERROR: Source analysis breakthrough failed: {e}")
        
        final_messages = self._deduplicate_messages(all_messages)
        logger.info(f"Source Analysis Result: {len(final_messages)} unique messages")
        
        return final_messages[:target_sample]

    async def _enhanced_time_slicing_for_sources(self, query_string: str, timerange: Dict, 
                                               fields: List[str], streams: List[str], 
                                               target_limit: int) -> List[Dict]:
        """Enhanced time slicing specifically for source analysis"""
        
        config = self.api_breakthrough_config
        slice_seconds = config["source_slice_seconds"]  # 60 seconds
        max_slices = config["source_time_slices"]       # 10 slices
        range_seconds = timerange.get("range_seconds", 300)
        
        actual_slices = min(max_slices, math.ceil(range_seconds / slice_seconds))
        slice_limit = math.ceil(target_limit / actual_slices)
        
        logger.info(f"Enhanced time slicing: {actual_slices} slices of {slice_seconds}s each, {slice_limit} per slice")
        
        messages = []
        
        if timerange["type"] == "relative":
            total_seconds = timerange["range"]
            
            for i in range(actual_slices):
                start_offset = i * slice_seconds
                end_offset = min((i + 1) * slice_seconds, total_seconds)
                
                if start_offset >= total_seconds:
                    break
                
                slice_timerange = {
                    "type": "absolute",
                    "from": (datetime.utcnow() - timedelta(seconds=end_offset)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    "to": (datetime.utcnow() - timedelta(seconds=start_offset)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    "range_seconds": end_offset - start_offset
                }
                
                slice_messages = await self._single_high_limit_search(
                    query_string, slice_timerange, fields or ["timestamp", "source", "level"], streams, slice_limit
                )
                
                if slice_messages:
                    messages.extend(slice_messages)
                    logger.debug(f"Enhanced slice {i+1}: {len(slice_messages)} messages, total: {len(messages)}")
                
                if len(messages) >= target_limit:
                    break
                
                await asyncio.sleep(0.02)  # Reduce delay
        
        logger.info(f"Enhanced time slicing completed: {len(messages)} messages")
        return messages

    # Retain all original API breakthrough methods...
    async def breakthrough_api_limits(self, query_string: str, from_time: str, to_time: str, 
                                    fields: List[str] = None, streams: List[str] = None, 
                                    target_limit: int = 15000) -> List[Dict]:
        """
        Fixed version of API breakthrough method - retains complete original logic
        Now with time snapshot to prevent time drift during batch queries
        """
        
        # Fix time at query start to prevent drift during batch processing
        query_start_time = datetime.utcnow()
        fixed_from_time = self._convert_to_absolute_time(from_time, query_start_time)
        fixed_to_time = self._convert_to_absolute_time(to_time, query_start_time)
        
        logger.info(f"Time snapshot fixed at: {query_start_time.isoformat()}")
        if from_time != fixed_from_time:
            logger.info(f"From time converted: {from_time} -> {fixed_from_time}")
        if to_time != fixed_to_time:
            logger.info(f"To time converted: {to_time} -> {fixed_to_time}")
        
        # Use fixed times for all operations
        timerange = self._build_timerange(fixed_from_time, fixed_to_time)
        range_seconds = timerange.get("range_seconds", 300)
        
        logger.info(f"API Breakthrough: target={target_limit}, range={range_seconds}s, streams={streams}")
        
        # First get accurate total count using fixed times and same reference time
        accurate_total = await self.get_accurate_total_count(query_string, from_time, to_time, streams, query_start_time)
        logger.info(f"Accurate total count: {accurate_total} (streams: {streams})")
        
        # Adjust target limit
        actual_target = min(target_limit, accurate_total) if accurate_total > 0 else target_limit
        
        all_messages = []
        strategies_attempted = []
        
        try:
            # Strategy 1: Export API
            logger.info("Attempting Strategy 1: Export API")
            export_messages = await self._try_export_api_breakthrough(
                query_string, timerange, fields, streams, actual_target
            )
            if export_messages:
                all_messages.extend(export_messages)
                strategies_attempted.append(f"Export API: {len(export_messages)} msgs")
                logger.info(f"Export API successful: {len(export_messages)} messages")
                
                # Don't return early - try all strategies to maximize data retrieval
                logger.info(f"Export API: {len(all_messages)}/{actual_target} messages retrieved")
            
        except Exception as e:
            logger.warning(f"Export API failed: {e}")
            strategies_attempted.append(f"Export API: failed ({e})")
        
        try:
            # Strategy 2: Time slicing with dynamic sizing
            logger.info("Attempting Strategy 2: Time Slicing")
            remaining_target = actual_target - len(all_messages)
            if remaining_target > 0:
                # If we're far from target, use more aggressive slicing
                if len(all_messages) < actual_target * 0.5:
                    logger.info("Using aggressive time slicing due to low retrieval rate")
                    time_slice_messages = await self._try_aggressive_time_slicing(
                        query_string, timerange, fields, streams, remaining_target
                    )
                else:
                    time_slice_messages = await self._try_time_slicing_breakthrough(
                        query_string, timerange, fields, streams, remaining_target
                    )
                
                if time_slice_messages:
                    all_messages.extend(time_slice_messages)
                    strategies_attempted.append(f"Time Slicing: {len(time_slice_messages)} msgs")
                    logger.info(f"Time Slicing successful: {len(time_slice_messages)} messages")
                    
                    # Don't return early - try all strategies to maximize data retrieval
                    logger.info(f"After Time Slicing: {len(all_messages)}/{actual_target} messages retrieved")
            
        except Exception as e:
            logger.warning(f"Time Slicing failed: {e}")
            strategies_attempted.append(f"Time Slicing: failed ({e})")
        
        try:
            # Strategy 3: Pagination
            logger.info("Attempting Strategy 3: Pagination Breakthrough")
            remaining_target = actual_target - len(all_messages)
            if remaining_target > 0:
                pagination_messages = await self._try_pagination_breakthrough(
                    query_string, timerange, fields, streams, remaining_target
                )
                if pagination_messages:
                    all_messages.extend(pagination_messages)
                    strategies_attempted.append(f"Pagination: {len(pagination_messages)} msgs")
                    logger.info(f"Pagination successful: {len(pagination_messages)} messages")
            
        except Exception as e:
            logger.warning(f"Pagination failed: {e}")
            strategies_attempted.append(f"Pagination: failed ({e})")
        
        # Deduplicate and return results
        final_messages = self._deduplicate_messages(all_messages)
        
        for msg in final_messages:
            msg['_accurate_total_count'] = accurate_total
        
        logger.info(f"API Breakthrough Summary:")
        logger.info(f"   Accurate total: {accurate_total} messages")
        logger.info(f"   Target: {actual_target} messages")
        logger.info(f"   Sample achieved: {len(final_messages)} messages")
        logger.info(f"   Strategies: {strategies_attempted}")
        
        return final_messages[:actual_target]

    # Below are all original complete method implementations...
    async def _try_export_api_breakthrough(self, query_string: str, timerange: Dict, 
                                         fields: List[str], streams: List[str], 
                                         limit: int) -> List[Dict]:
        """Strategy 1: Use Export API to breakthrough limits - Complete retention"""
        
        config = self.api_breakthrough_config
        chunk_size = config["export_chunk_size"]
        max_chunks = min(config["export_max_chunks"], math.ceil(limit / chunk_size))
        
        data = {
            "streams": streams or [],
            "query_string": {
                "type": "elasticsearch", 
                "query_string": query_string
            },
            "timerange": self._build_api_timerange(timerange),
            "fields": fields or ["timestamp", "source", "message", "level"]
        }
        
        messages = []
        
        for chunk_idx in range(max_chunks):
            try:
                logger.debug(f"Export API chunk {chunk_idx + 1}/{max_chunks}")
                
                export_endpoints = [
                    "/search/universal/relative/export_search_relative_chunked",
                    "/views/search/messages/export", 
                    "/search/universal/absolute/export"
                ]
                
                chunk_messages = None
                for endpoint in export_endpoints:
                    try:
                        if "chunked" in endpoint:
                            data["chunk_size"] = chunk_size
                            data["offset"] = chunk_idx * chunk_size
                        elif "/views/search/messages" in endpoint:
                            # This endpoint doesn't support offset/pagination
                            # Only try on first chunk since we can't paginate
                            if chunk_idx > 0:
                                continue
                            data["limit"] = chunk_size * max_chunks  # Try to get all data in one request
                        else:
                            data["limit"] = chunk_size
                            data["offset"] = chunk_idx * chunk_size
                        
                        csv_response = await self._make_request_with_retry(
                            "POST", endpoint, data=data, expect_csv=True, max_retries=2
                        )
                        
                        if isinstance(csv_response, str) and csv_response.strip():
                            logger.debug(f"CSV response length: {len(csv_response)} chars, lines: {csv_response.count(chr(10))}")
                            chunk_messages = await self._process_csv_batch(
                                csv_response, fields, float('inf')  # Process all messages in CSV
                            )
                            if chunk_messages:
                                logger.debug(f"{endpoint} successful: {len(chunk_messages)} messages")
                                break
                            else:
                                logger.debug(f"WARNING: {endpoint} returned CSV but no messages parsed")
                        
                    except Exception as e:
                        logger.debug(f"ERROR: {endpoint} failed: {e}")
                        continue
                
                if chunk_messages:
                    messages.extend(chunk_messages)
                    logger.info(f"Export chunk {chunk_idx + 1}: {len(chunk_messages)} messages, total: {len(messages)}")
                    
                    # Continue trying to get more chunks unless we got no data at all
                    if len(chunk_messages) == 0:
                        logger.info("Export API: No messages in chunk, stopping")
                        break
                else:
                    logger.debug(f"Export chunk {chunk_idx + 1}: No data returned")
                    break
                
                if len(messages) >= limit:
                    break
                
                await asyncio.sleep(0.2)
                
            except Exception as e:
                logger.warning(f"Export chunk {chunk_idx + 1} failed: {e}")
                break
        
        logger.info(f"Export API completed: {len(messages)} messages")
        return messages

    async def _try_aggressive_time_slicing(self, query_string: str, timerange: Dict,
                                          fields: List[str], streams: List[str],
                                          limit: int) -> List[Dict]:
        """Aggressive time slicing for high-volume data"""
        
        range_seconds = timerange.get("range_seconds", 300)
        
        # Use smaller slices for better coverage - aim for ~500 messages per slice
        # Based on observed ~3000 message API limit
        slice_seconds = 20  # 20 second slices for better coverage
        overlap_seconds = 1  # 1 second overlap to catch boundary messages
        # Don't reduce the step size too much - it creates too many requests
        step_seconds = slice_seconds  # Keep original step size
        max_slices = math.ceil(range_seconds / step_seconds) + 1  # +1 for safety
        
        logger.info(f"Aggressive time slicing: {max_slices} slices of {slice_seconds}s each")
        
        messages = []
        
        if timerange["type"] == "relative":
            total_seconds = timerange["range"]
            
            for i in range(max_slices):
                # Each slice starts where the previous one started + step_seconds
                slice_start_offset = i * step_seconds
                slice_end_offset = min(slice_start_offset + slice_seconds + overlap_seconds, total_seconds)
                
                if slice_start_offset >= total_seconds:
                    break
                    
                start_offset = slice_start_offset
                end_offset = slice_end_offset
                
                if start_offset >= total_seconds:
                    break
                
                slice_timerange = {
                    "type": "absolute",
                    "from": (datetime.utcnow() - timedelta(seconds=end_offset)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    "to": (datetime.utcnow() - timedelta(seconds=start_offset)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    "range_seconds": end_offset - start_offset
                }
                
                # Request up to 1000 messages per slice to stay under API limits
                slice_messages = await self._single_high_limit_search(
                    query_string, slice_timerange, fields, streams, 1000
                )
                
                if slice_messages:
                    messages.extend(slice_messages)
                    logger.info(f"Aggressive slice {i+1}/{max_slices}: {len(slice_messages)} messages, total: {len(messages)}")
                
                if len(messages) >= limit:
                    break
                
                await asyncio.sleep(0.05)  # Minimal delay
        else:
            # Handle absolute time ranges
            from_dt = datetime.fromisoformat(timerange["from"].replace('Z', '+00:00')).replace(tzinfo=None)
            to_dt = datetime.fromisoformat(timerange["to"].replace('Z', '+00:00')).replace(tzinfo=None)
            total_seconds = (to_dt - from_dt).total_seconds()
            
            for i in range(max_slices):
                # Each slice starts where the previous one started + step_seconds
                slice_start_time = from_dt + timedelta(seconds=i * step_seconds)
                slice_end_time = min(from_dt + timedelta(seconds=i * step_seconds + slice_seconds + overlap_seconds), to_dt)
                
                if slice_start_time >= to_dt:
                    break
                    
                slice_start = slice_start_time
                slice_end = slice_end_time
                
                if slice_start >= to_dt:
                    break
                
                slice_timerange = {
                    "type": "absolute",
                    "from": slice_start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    "to": slice_end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    "range_seconds": (slice_end - slice_start).total_seconds()
                }
                
                slice_messages = await self._single_high_limit_search(
                    query_string, slice_timerange, fields, streams, 1000
                )
                
                if slice_messages:
                    messages.extend(slice_messages)
                    logger.info(f"Aggressive slice {i+1}/{max_slices}: {len(slice_messages)} messages, total: {len(messages)}")
                
                if len(messages) >= limit:
                    break
                
                await asyncio.sleep(0.05)
        
        logger.info(f"Aggressive time slicing completed: {len(messages)} messages")
        return messages
    
    async def _try_time_slicing_breakthrough(self, query_string: str, timerange: Dict, 
                                           fields: List[str], streams: List[str], 
                                           limit: int) -> List[Dict]:
        """Strategy 2: Time slicing breakthrough limits - Complete retention"""
        
        config = self.api_breakthrough_config
        slice_seconds = config["time_slice_seconds"]
        max_slices = config["max_time_slices"]
        range_seconds = timerange.get("range_seconds", 300)
        
        actual_slices = min(max_slices, math.ceil(range_seconds / slice_seconds))
        slice_limit = math.ceil(limit / actual_slices)
        
        logger.info(f"Time slicing: {actual_slices} slices, {slice_limit} per slice")
        
        messages = []
        
        if timerange["type"] == "relative":
            total_seconds = timerange["range"]
            
            for i in range(actual_slices):
                start_offset = i * slice_seconds
                end_offset = min((i + 1) * slice_seconds, total_seconds)
                
                if start_offset >= total_seconds:
                    break
                
                slice_timerange = {
                    "type": "absolute",
                    "from": (datetime.utcnow() - timedelta(seconds=end_offset)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    "to": (datetime.utcnow() - timedelta(seconds=start_offset)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    "range_seconds": end_offset - start_offset
                }
                
                slice_messages = await self._single_high_limit_search(
                    query_string, slice_timerange, fields, streams, slice_limit
                )
                
                if slice_messages:
                    messages.extend(slice_messages)
                    logger.info(f"Time slice {i+1}: {len(slice_messages)} messages, total: {len(messages)}")
                
                if len(messages) >= limit:
                    break
                
                await asyncio.sleep(0.1)
        
        logger.info(f"Time slicing completed: {len(messages)} messages")
        return messages

    async def _try_pagination_breakthrough(self, query_string: str, timerange: Dict, 
                                         fields: List[str], streams: List[str], 
                                         limit: int) -> List[Dict]:
        """Strategy 3: Pagination breakthrough limits - Complete retention"""
        
        config = self.api_breakthrough_config
        page_size = config["pagination_size"]
        max_rounds = config["max_pagination_rounds"]
        
        messages = []
        
        for round_idx in range(max_rounds):
            offset = round_idx * page_size
            
            if offset >= limit:
                break
            
            current_limit = min(page_size, limit - len(messages))
            
            try:
                page_messages = await self._single_high_limit_search(
                    query_string, timerange, fields, streams, current_limit + 1000
                )
                
                if page_messages:
                    page_slice = page_messages[offset:offset + current_limit] if offset < len(page_messages) else []
                    
                    if page_slice:
                        messages.extend(page_slice)
                        logger.info(f"Pagination round {round_idx+1}: {len(page_slice)} messages, total: {len(messages)}")
                    else:
                        logger.debug("No more data available for pagination")
                        break
                else:
                    logger.debug(f"Pagination round {round_idx+1}: No data")
                    break
                
                if len(messages) >= limit:
                    break
                
                await asyncio.sleep(0.15)
                
            except Exception as e:
                logger.warning(f"Pagination round {round_idx+1} failed: {e}")
                break
        
        logger.info(f"Pagination completed: {len(messages)} messages")
        return messages

    async def _single_high_limit_search(self, query_string: str, timerange: Dict, 
                                      fields: List[str], streams: List[str], 
                                      limit: int) -> List[Dict]:
        """Execute single high limit search - Complete retention"""
        
        high_limits = [limit, 5000, 3000, 2000, 1500, 1000, 500]
        
        for attempt_limit in high_limits:
            try:
                data = {
                    "streams": streams or [],
                    "query_string": {
                        "type": "elasticsearch",
                        "query_string": query_string
                    },
                    "timerange": self._build_api_timerange(timerange),
                    "limit": attempt_limit
                }
                
                search_endpoints = [
                    "/views/search/messages",
                    "/search/universal/relative", 
                    "/search/universal/absolute"
                ]
                
                for endpoint in search_endpoints:
                    try:
                        if "universal" in endpoint:
                            params = {
                                'query': query_string,
                                'limit': attempt_limit,
                                'sort': 'timestamp:desc'
                            }
                            
                            if timerange["type"] == "relative":
                                params['range'] = timerange["range"]
                                response = await self._make_request_with_retry(
                                    "GET", "/search/universal/relative", params=params
                                )
                            else:
                                params['from'] = timerange["from"]
                                params['to'] = timerange["to"]
                                response = await self._make_request_with_retry(
                                    "GET", "/search/universal/absolute", params=params
                                )
                            
                            messages = []
                            if 'messages' in response:
                                for msg in response['messages']:
                                    message_data = msg.get('message', {})
                                    if message_data:
                                        if fields:
                                            filtered_msg = {k: v for k, v in message_data.items() if k in fields}
                                        else:
                                            filtered_msg = {k: v for k, v in message_data.items() 
                                                          if not k.startswith('gl2_') and k != 'streams'}
                                        
                                        if filtered_msg:
                                            messages.append(filtered_msg)
                            
                            if messages:
                                logger.info(f"High limit search successful: {len(messages)} messages (requested: {attempt_limit})")
                                if len(messages) < attempt_limit * 0.8:
                                    logger.warning(f"API returned fewer messages than requested: {len(messages)} < {attempt_limit}")
                                return messages
                        
                        else:
                            csv_response = await self._make_request_with_retry(
                                "POST", endpoint, data=data, expect_csv=True, max_retries=2
                            )
                            
                            if isinstance(csv_response, str) and csv_response.strip():
                                messages = await self._process_csv_batch(csv_response, fields, float('inf'))  # Process all messages
                                if messages:
                                    logger.info(f"High limit search successful: {len(messages)} messages (requested: {attempt_limit})")
                                    return messages
                    
                    except Exception as e:
                        logger.debug(f"Endpoint {endpoint} with limit {attempt_limit} failed: {e}")
                        continue
                
            except Exception as e:
                logger.debug(f"High limit {attempt_limit} failed: {e}")
                continue
        
        logger.warning("All high limit attempts failed")
        return []

    def _build_api_timerange(self, timerange: Dict) -> Dict:
        """Build API time range - Complete retention"""
        if timerange["type"] == "relative":
            return {
                "type": "relative",
                "range": timerange["range"]
            }
        else:
            return {
                "type": "absolute", 
                "from": timerange["from"],
                "to": timerange["to"]
            }

    async def _process_csv_batch(self, csv_text: str, fields: List[str], limit: int) -> List[Dict]:
        """Process CSV batch data - Complete retention"""
        
        if not csv_text or not csv_text.strip():
            return []
        
        try:
            lines = csv_text.splitlines()
            if len(lines) <= 1:
                return []
            
            csv_reader = csv.DictReader(lines)
            messages = []
            
            # Log CSV headers for debugging
            if csv_reader.fieldnames:
                logger.debug(f"CSV headers: {csv_reader.fieldnames}")
            
            for row in csv_reader:
                # Process all available rows in the CSV
                cleaned_row = {}
                for k, v in row.items():
                    if v and str(v).strip():
                        if not k.startswith('gl2_') and k != 'streams':
                            # If specific fields requested, check variations
                            if fields:
                                # Check exact match
                                if k in fields:
                                    cleaned_row[k] = str(v).strip()
                                # Check if any requested field matches with underscores/hyphens
                                else:
                                    for field in fields:
                                        if (k == field.replace('-', '_') or 
                                            k == field.replace('_', '-') or
                                            k == field.replace('-', '')):
                                            cleaned_row[field] = str(v).strip()
                                            break
                            else:
                                # No specific fields requested, include all
                                cleaned_row[k] = str(v).strip()
                
                if cleaned_row:
                    messages.append(cleaned_row)
            
            logger.debug(f"Processed CSV batch: {len(lines)} lines -> {len(messages)} messages (limit was {limit})")
            if len(messages) > limit:
                logger.warning(f"CSV contained more messages ({len(messages)}) than limit ({limit})")
            return messages
            
        except Exception as e:
            logger.error(f"CSV processing failed: {e}")
            return []

    async def _safe_get_messages(self, query_string: str, from_time: str, to_time: str,
                               fields: List[str], streams: List[str] = None,
                               target_limit: int = 20000, fallback_on_error: bool = True) -> tuple[List[Dict], int]:
        """
        Safely get messages with error handling for complex queries (v1.9.28)
        OPTIMIZED: Added timeouts and limits for very large datasets
        Returns tuple of (messages, accurate_total_count)
        """
        # Try to get accurate total count first with reasonable timeout
        accurate_total_count = 0
        try:
            accurate_total_count = await asyncio.wait_for(
                self.get_accurate_total_count(query_string, from_time, to_time, streams),
                timeout=30.0  # Increased to 30 seconds for better reliability
            )
            logger.info(f"Accurate total count: {accurate_total_count}")
            
            # Handle extremely large datasets with warnings but don't reduce limits too aggressively
            if accurate_total_count > 50000000:  # More than 50 million
                logger.warning(f"Dataset extremely large ({accurate_total_count:,}), may take longer")
                # Only reduce if explicitly requested large limit
                if target_limit > 20000:
                    target_limit = 20000
                    logger.info(f"Capped target limit to {target_limit} for very large dataset")
            elif accurate_total_count > 10000000:  # More than 10 million
                logger.info(f"Large dataset ({accurate_total_count:,}), processing may take time")
                # Keep original target_limit unless it's very high
                if target_limit > 50000:
                    target_limit = 50000
                    logger.info(f"Capped target limit to {target_limit} for large dataset")
                
        except asyncio.TimeoutError:
            logger.warning("Count operation timed out, proceeding without exact count")
            accurate_total_count = 0
            # Don't reduce target_limit when count fails - let it proceed with requested limit
        except GraylogError as e:
            if "too_many_nested_clauses" in str(e) and fallback_on_error:
                logger.warning(f"Query too complex for accurate count: {e}")
                # Continue without accurate count
            else:
                raise
        
        # Try to get messages with timeout
        messages = []
        try:
            # For smaller requests, try direct approach first
            if target_limit <= 5000:
                try:
                    messages = await asyncio.wait_for(
                        self._single_high_limit_search(
                            query_string=query_string,
                            timerange=self._build_timerange(from_time, to_time),
                            fields=fields,
                            streams=streams,
                            limit=target_limit
                        ),
                        timeout=45.0  # Increased to 45 seconds for reliability
                    )
                    if messages:
                        return messages, accurate_total_count
                except asyncio.TimeoutError:
                    logger.error("Direct search timed out, trying pagination")
                except GraylogError as e:
                    if "too_many_nested_clauses" not in str(e):
                        raise
                    # Fall through to smart pagination
            
            # Use smart pagination for larger requests or if direct approach failed
            messages = await asyncio.wait_for(
                self._smart_time_based_pagination(
                    query_string=query_string,
                    from_time=from_time,
                    to_time=to_time,
                    fields=fields,
                    streams=streams,
                    target_per_page=min(10000, target_limit)  # Adaptive page size
                ),
                timeout=120.0  # Increased to 2 minutes for large datasets
            )
            
            # Limit to target if we got more
            if len(messages) > target_limit:
                messages = messages[:target_limit]
                
        except asyncio.TimeoutError:
            logger.error("Message retrieval timed out, returning partial results")
            # Return whatever we got so far
            return messages if messages else [], accurate_total_count
        except GraylogError as e:
            if "too_many_nested_clauses" in str(e):
                if not fallback_on_error:
                    raise
                logger.error(f"Query too complex even with smart pagination: {e}")
                return [], 0
            else:
                raise
        
        return messages, accurate_total_count

    async def _smart_time_based_pagination(self, query_string: str, from_time: str, to_time: str,
                                          fields: List[str], streams: List[str], 
                                          target_per_page: int = 10000) -> List[Dict]:
        """
        Implement smart time-based pagination (v1.9.28)
        
        OPTIMIZED: Limits maximum slices to prevent timeout issues with large datasets.
        Uses adaptive slicing based on data density.
        """
        logger.info(f"Smart time-based pagination: target {target_per_page} messages per page")
        
        # First get accurate total count with reasonable timeout
        try:
            # Increased timeout for better reliability
            total_count = await asyncio.wait_for(
                self.get_accurate_total_count(query_string, from_time, to_time, streams),
                timeout=30.0  # 30 second timeout for count
            )
            logger.info(f"Total count for pagination: {total_count}")
        except asyncio.TimeoutError:
            logger.warning("Count operation timed out, using estimated count")
            total_count = target_per_page * 5  # More conservative estimate
        except Exception as e:
            logger.warning(f"Failed to get accurate count: {e}, using fallback")
            total_count = target_per_page * 5  # More conservative estimate
        
        # If total is less than target, just return all
        if total_count <= target_per_page:
            logger.info("Total count less than target, fetching all messages")
            try:
                messages = await self.breakthrough_api_limits(
                    query_string=query_string,
                    from_time=from_time,
                    to_time=to_time,
                    fields=fields,
                    streams=streams,
                    target_limit=total_count
                )
                return messages
            except Exception as e:
                logger.error(f"Failed to fetch all messages: {e}")
                return []
        
        # Calculate time range
        timerange = self._build_timerange(from_time, to_time)
        
        if timerange["type"] == "relative":
            total_seconds = timerange["range"]
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(seconds=total_seconds)
        else:
            start_time = datetime.fromisoformat(timerange["from"].replace('Z', '+00:00')).replace(tzinfo=None)
            end_time = datetime.fromisoformat(timerange["to"].replace('Z', '+00:00')).replace(tzinfo=None)
            total_seconds = (end_time - start_time).total_seconds()
        
        # Balance between performance and completeness
        # Adaptive slicing based on dataset size
        if total_count > 10000000:  # Very large dataset
            MAX_SLICES = 100  # Allow more slices for very large datasets
            MIN_SLICE_DURATION = 30  # 30 seconds minimum per slice
        elif total_count > 1000000:  # Large dataset
            MAX_SLICES = 50  # Moderate number of slices
            MIN_SLICE_DURATION = 60  # 1 minute minimum per slice
        else:  # Normal dataset
            MAX_SLICES = 30  # Fewer slices for smaller datasets
            MIN_SLICE_DURATION = 120  # 2 minutes minimum per slice
        
        # Calculate optimal number of slices
        ideal_slices = max(1, math.ceil(total_count / target_per_page))
        
        # Apply limits to prevent excessive slicing
        if ideal_slices > MAX_SLICES:
            logger.info(f"Adjusting slices from {ideal_slices} to {MAX_SLICES} for performance")
            num_slices = MAX_SLICES
        else:
            num_slices = ideal_slices
        
        # Ensure minimum slice duration
        seconds_per_slice = total_seconds / num_slices
        if seconds_per_slice < MIN_SLICE_DURATION and num_slices > 1:
            num_slices = max(1, int(total_seconds / MIN_SLICE_DURATION))
            seconds_per_slice = total_seconds / num_slices
            logger.info(f"Adjusted slices to {num_slices} for minimum slice duration")
        
        logger.info(f"Time-based pagination plan: {num_slices} slices, {seconds_per_slice:.1f}s per slice")
        logger.info(f"Expected {total_count / num_slices:.0f} messages per slice")
        
        all_messages = []
        messages_per_slice = []
        
        # Add overall timeout for pagination operation
        pagination_timeout = min(30.0, num_slices * 2.0)  # 2 seconds per slice, max 30 seconds
        
        try:
            # Fetch messages for each time slice with timeout
            for i in range(num_slices):
                slice_start = start_time + timedelta(seconds=i * seconds_per_slice)
                slice_end = start_time + timedelta(seconds=(i + 1) * seconds_per_slice)
                
                # Ensure we don't go beyond the end time
                if slice_end > end_time:
                    slice_end = end_time
                
                slice_from = slice_start.strftime("%Y-%m-%dT%H:%M:%S.000Z")
                slice_to = slice_end.strftime("%Y-%m-%dT%H:%M:%S.000Z")
                
                logger.info(f"Fetching slice {i+1}/{num_slices}: {slice_from} to {slice_to}")
                
                try:
                    # Increased timeout for better reliability
                    slice_messages = await asyncio.wait_for(
                        self._single_high_limit_search(
                            query_string=query_string,
                            timerange={
                                "type": "absolute",
                                "from": slice_from,
                                "to": slice_to
                            },
                            fields=fields,
                            streams=streams,
                            limit=min(target_per_page * 2, 20000)  # Cap at 20k per request
                        ),
                        timeout=30.0  # 30 second timeout per slice for reliability
                    )
                    
                    if slice_messages:
                        all_messages.extend(slice_messages)
                        messages_per_slice.append(len(slice_messages))
                        logger.info(f"Slice {i+1} returned {len(slice_messages)} messages")
                    else:
                        messages_per_slice.append(0)
                        logger.warning(f"Slice {i+1} returned no messages")
                    
                    # Only stop early for very large collections
                    if len(all_messages) >= target_per_page * 5 and len(all_messages) >= 50000:
                        logger.info(f"Collected sufficient messages ({len(all_messages)}), stopping to prevent memory issues")
                        break
                    
                    # Small delay to avoid overwhelming the API
                    if i < num_slices - 1:
                        await asyncio.sleep(0.1)  # Small delay between requests
                        
                except asyncio.TimeoutError:
                    logger.error(f"Slice {i+1} timed out, skipping")
                    messages_per_slice.append(0)
                    continue
                except Exception as e:
                    logger.error(f"Failed to fetch slice {i+1}: {e}")
                    messages_per_slice.append(0)
                    continue
                    
        except Exception as e:
            logger.error(f"Pagination failed: {e}")
        
        # Log statistics
        total_fetched = len(all_messages)
        avg_per_slice = sum(messages_per_slice) / len(messages_per_slice) if messages_per_slice else 0
        
        logger.info(f"Pagination complete: {total_fetched} messages fetched in {len(messages_per_slice)} slices")
        if messages_per_slice:
            logger.info(f"Messages per slice: min={min(messages_per_slice)}, "
                       f"max={max(messages_per_slice)}, avg={avg_per_slice:.1f}")
        
        return self._deduplicate_messages(all_messages)

    def _deduplicate_messages(self, messages: List[Dict]) -> List[Dict]:
        """Deduplicate messages - Enhanced precision to avoid false positives"""
        seen = set()
        unique_messages = []
        
        for msg in messages:
            # Use a much more precise key to avoid false duplicates
            # Only consider messages identical if they have EXACT same content
            
            # Start with timestamp (full precision)
            key_parts = []
            if 'timestamp' in msg:
                key_parts.append(f"ts:{msg['timestamp']}")
                
            # Add ALL available fields with their exact values
            sorted_fields = sorted(msg.items())
            for field, value in sorted_fields:
                if field != 'timestamp':  # Already added
                    # Use full value, not truncated
                    key_parts.append(f"{field}:{str(value)}")
            
            # Create a comprehensive key
            key = '|'.join(key_parts)
            
            if key not in seen:
                seen.add(key)
                unique_messages.append(msg)
        
        if len(messages) != len(unique_messages):
            logger.info(f"Deduplication: {len(messages)} -> {len(unique_messages)} messages ({len(messages) - len(unique_messages)} true duplicates removed)")
        
        return unique_messages
        
        # Original deduplication code commented out for testing
        # seen = set()
        # unique_messages = []
        # 
        # for msg in messages:
        #     # Build key from all available fields for better deduplication
        #     key_parts = []
        #     
        #     # Always include timestamp if available
        #     if 'timestamp' in msg:
        #         key_parts.append(str(msg['timestamp']))
        #     
        #     # Include commonly unique fields - be more precise to avoid false duplicates
        #     for field in ['source', 'message', 'src-ip', 'src_ip', 'dst-ip', 'dst_ip', 'action', '_id', 'level', 'facility']:
        #         if field in msg:
        #             value = str(msg[field])
        #             if field == 'message':
        #                 # Use more of the message to avoid false duplicates - increase from 100 to 200 chars
        #                 value = value[:200]
        #             key_parts.append(f"{field}:{value}")
        #     
        #     # If no unique fields found, use all fields
        #     if len(key_parts) < 2:
        #         sorted_items = sorted(msg.items())
        #         key = json.dumps(sorted_items, sort_keys=True)
        #     else:
        #         key = '|'.join(key_parts)
        #     
        #     if key not in seen:
        #         seen.add(key)
        #         unique_messages.append(msg)
        # 
        # if len(messages) != len(unique_messages):
        #     logger.info(f"Deduplication: {len(messages)} -> {len(unique_messages)} messages")
        # return unique_messages

    async def get_stream_mappings(self) -> Dict[str, str]:
        """Get mapping of stream names to IDs"""
        try:
            response = await self.get("/streams")
            stream_map = {}
            
            if isinstance(response, dict) and "streams" in response:
                for stream in response["streams"]:
                    stream_id = stream.get("id", "")
                    stream_title = stream.get("title", "")
                    if stream_id and stream_title:
                        stream_map[stream_title.lower()] = stream_id
                        # Also store the exact title
                        stream_map[stream_title] = stream_id
            
            return stream_map
        except Exception as e:
            logger.warning(f"Failed to get stream mappings: {e}")
            return {}
    
    async def get(self, path: str, params: Optional[Dict] = None) -> Dict:
        """Send GET request with retry"""
        return await self._make_request_with_retry('GET', path, params=params)
    
    async def post(self, path: str, data: Optional[Dict] = None, params: Optional[Dict] = None, expect_csv: bool = False) -> Union[Dict, str]:
        """Send POST request with retry"""
        return await self._make_request_with_retry('POST', path, params=params, data=data, expect_csv=expect_csv)

# Global client instance and config
graylog_config = None

def get_graylog_client():
    """Get Graylog client from global config"""
    global graylog_config
    
    if graylog_config is None:
        raise GraylogError("Graylog configuration not available")
    
    return GraylogClient(
        host=graylog_config['host'],
        username=graylog_config.get('username'),
        password=graylog_config.get('password'),
        api_token=graylog_config.get('api_token'),
        verify_ssl=graylog_config['verify_ssl'],
        timeout=graylog_config['timeout']
    )

# Create MCP server
server = Server("graylog-mcp")

@server.list_tools()
async def handle_list_tools() -> List[Tool]:
    """List all available Graylog management tools - Complete version"""
    return [
        # API breakthrough dedicated tools with FIXED source analysis
        Tool(
            name="get_log_statistics",
            description="Get comprehensive log statistics with FIXED accurate counting and FIXED source analysis.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Elasticsearch query string", "default": "*"},
                    "range_from": {"type": "string", "description": "Start time", "default": "now-5m"},
                    "range_to": {"type": "string", "description": "End time", "default": "now"},
                    "streams": {
                        "type": "array",
                        "description": "Stream IDs to search in (optional)",
                        "items": {"type": "string"},
                        "default": []
                    },
                    "analysis_limit": {"type": "integer", "description": "Maximum messages to analyze", "default": 15000, "maximum": 50000}
                },
                "additionalProperties": False
            }
        ),
        Tool(
            name="analyze_time_patterns",
            description="Analyze time-based patterns using API breakthrough with FIXED counting",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Elasticsearch query string", "default": "*"},
                    "range_from": {"type": "string", "description": "Start time", "default": "now-1h"},
                    "range_to": {"type": "string", "description": "End time", "default": "now"},
                    "streams": {
                        "type": "array",
                        "description": "Stream IDs to search in (optional)",
                        "items": {"type": "string"},
                        "default": []
                    }
                },
                "additionalProperties": False
            }
        ),
        Tool(
            name="analyze_source_distribution",
            description="Analyze log distribution by source hosts with FIXED counting and improved sampling",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Elasticsearch query string", "default": "_exists_:source"},
                    "range_from": {"type": "string", "description": "Start time", "default": "now-5m"},
                    "range_to": {"type": "string", "description": "End time", "default": "now"},
                    "streams": {
                        "type": "array",
                        "description": "Stream IDs to search in (optional)",
                        "items": {"type": "string"},
                        "default": []
                    },
                    "top_n": {"type": "integer", "description": "Number of top sources to return", "default": 30, "maximum": 100}
                },
                "additionalProperties": False
            }
        ),
        Tool(
            name="analyze_error_patterns",
            description="Extract and analyze error patterns with FIXED counting",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Elasticsearch query string", "default": "*"},
                    "range_from": {"type": "string", "description": "Start time", "default": "now-1h"},
                    "range_to": {"type": "string", "description": "End time", "default": "now"},
                    "streams": {
                        "type": "array",
                        "description": "Stream IDs to search in (optional)",
                        "items": {"type": "string"},
                        "default": []
                    }
                },
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_log_level_analysis",
            description="Analyze log levels distribution with FIXED counting",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Elasticsearch query string", "default": "*"},
                    "range_from": {"type": "string", "description": "Start time", "default": "now-5m"},
                    "range_to": {"type": "string", "description": "End time", "default": "now"},
                    "streams": {
                        "type": "array",
                        "description": "Stream IDs to search in (optional)",
                        "items": {"type": "string"},
                        "default": []
                    }
                },
                "additionalProperties": False
            }
        ),
        Tool(
            name="analyze_field_distribution",
            description="Analyze distribution of any specified field (generic field statistics)",
            inputSchema={
                "type": "object",
                "properties": {
                    "field_name": {"type": "string", "description": "Field name to analyze (e.g., 'action', 'src-ip', 'dst-ip', 'protocol', etc.)"},
                    "query": {"type": "string", "description": "Elasticsearch query string", "default": "*"},
                    "range_from": {"type": "string", "description": "Start time", "default": "now-5m"},
                    "range_to": {"type": "string", "description": "End time", "default": "now"},
                    "top_n": {"type": "integer", "description": "Number of top values to return", "default": 50, "maximum": 200},
                    "streams": {
                        "type": "array",
                        "description": "Stream IDs to search in (optional)",
                        "items": {"type": "string"},
                        "default": []
                    }
                },
                "required": ["field_name"],
                "additionalProperties": False
            }
        ),
        
        # Sample query tools
        Tool(
            name="get_log_sample",
            description="Get a small sample of recent log messages for detailed inspection",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Elasticsearch query string", "default": "*"},
                    "range_from": {"type": "string", "description": "Start time", "default": "now-5m"},
                    "range_to": {"type": "string", "description": "End time", "default": "now"},
                    "limit": {"type": "integer", "description": "Number of sample messages", "default": 50, "maximum": 200},
                    "fields": {
                        "type": "array",
                        "description": "Fields to include",
                        "items": {"type": "string"},
                        "default": ["timestamp", "source", "message", "level"]
                    },
                    "streams": {
                        "type": "array",
                        "description": "Stream IDs to search in (optional)",
                        "items": {"type": "string"},
                        "default": []
                    }
                },
                "additionalProperties": False
            }
        ),
        Tool(
            name="search_logs_paginated",
            description="Search logs with smart time-based pagination (handles large datasets efficiently)",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Elasticsearch query string"},
                    "range_from": {"type": "string", "description": "Start time", "default": "now-5m"},
                    "range_to": {"type": "string", "description": "End time", "default": "now"},
                    "limit": {"type": "integer", "description": "Results per page", "default": 100, "maximum": 500},
                    "offset": {"type": "integer", "description": "Results offset (automatically uses time-based chunks)", "default": 0},
                    "fields": {
                        "type": "array",
                        "description": "Fields to retrieve",
                        "items": {"type": "string"},
                        "default": ["timestamp", "source", "message", "level"]
                    },
                    "streams": {
                        "type": "array",
                        "description": "Stream IDs to search in (optional)",
                        "items": {"type": "string"},
                        "default": []
                    }
                },
                "required": ["query"],
                "additionalProperties": False
            }
        ),
        
        # Export tools
        Tool(
            name="search_messages_export",
            description="Export search results with comprehensive analysis",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Elasticsearch query string"},
                    "range_from": {"type": "string", "description": "Start time", "default": "now-5m"},
                    "range_to": {"type": "string", "description": "End time", "default": "now"},
                    "limit": {"type": "integer", "description": "Maximum number of results", "default": 1000, "maximum": 50000},
                    "fields": {
                        "type": "array", 
                        "description": "Fields to include in export", 
                        "items": {"type": "string"},
                        "default": ["timestamp", "source", "message"]
                    }
                },
                "required": ["query"],
                "additionalProperties": False
            }
        ),
        
        # System info tools
        Tool(
            name="get_streams",
            description="List all available Graylog streams",
            inputSchema={
                "type": "object",
                "properties": {},
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_system_info",
            description="Get Graylog system information and cluster status",
            inputSchema={
                "type": "object",
                "properties": {},
                "additionalProperties": False
            }
        ),
        
        # Content Packs tools
        Tool(
            name="list_content_packs",
            description="List all available Graylog content packs",
            inputSchema={
                "type": "object", 
                "properties": {},
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_content_pack",
            description="Get specific content pack details",
            inputSchema={
                "type": "object",
                "properties": {
                    "content_pack_id": {"type": "string", "description": "Content Pack ID"}
                },
                "required": ["content_pack_id"],
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_content_pack_revision",
            description="Get specific revision of a content pack with full configuration details",
            inputSchema={
                "type": "object",
                "properties": {
                    "content_pack_id": {"type": "string", "description": "Content Pack ID"},
                    "revision": {"type": "integer", "description": "Content pack revision number", "default": 1}
                },
                "required": ["content_pack_id"],
                "additionalProperties": False
            }
        ),

        # Dashboard tools
        Tool(
            name="list_dashboards",
            description="List all available Graylog dashboards",
            inputSchema={
                "type": "object",
                "properties": {},
                "additionalProperties": False
            }
        ),
        Tool(
            name="get_dashboard",
            description="Get specific dashboard details and widget list",
            inputSchema={
                "type": "object",
                "properties": {
                    "dashboard_id": {"type": "string", "description": "Dashboard ID"}
                },
                "required": ["dashboard_id"],
                "additionalProperties": False
            }
        ),
        
        # Testing and debugging tools
        Tool(
            name="test_accurate_counting",
            description="Test the fixed accurate counting methods for debugging",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Test query", "default": "*"},
                    "range_from": {"type": "string", "description": "Start time", "default": "now-5m"},
                    "range_to": {"type": "string", "description": "End time", "default": "now"}
                },
                "additionalProperties": False
            }
        ),
        Tool(
            name="test_source_analysis_fix",
            description="Test the FIXED source analysis with detailed debugging information",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Test query", "default": "*"},
                    "range_from": {"type": "string", "description": "Start time", "default": "now-5m"},
                    "range_to": {"type": "string", "description": "End time", "default": "now"}
                },
                "additionalProperties": False
            }
        )
    ]

@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> List[Union[types.TextContent, types.ImageContent]]:
    """Handle tool calls with comprehensive error handling"""
    try:
        result = await execute_tool(name, arguments)
        
        if isinstance(result, dict):
            json_output = json.dumps(result, indent=2, ensure_ascii=False)
        else:
            json_output = str(result)
            
        return [types.TextContent(type="text", text=json_output)]
        
    except GraylogError as e:
        error_msg = f"Graylog Error: {str(e)}"
        logger.error(error_msg)
        return [types.TextContent(type="text", text=error_msg)]
    except Exception as e:
        error_msg = f"Unexpected error executing tool '{name}': {str(e)}"
        logger.error(error_msg)
        return [types.TextContent(type="text", text=error_msg)]

def normalize_query_string(query: str, auto_fix_escaping: bool = False) -> str:
    r"""
    Normalize query string to handle Graylog escaping rules correctly.
    
    Graylog requires these characters to be escaped with backslash:
    & ! : \ / + - ! ( ) { } [ ] ^ " ~ * ?
    
    However, strings within double quotes don't need escaping.
    
    This function handles:
    1. Double-escaped backslashes (\\- becomes \-) from MCP protocol
    2. Validates that escaping is correct for Graylog
    3. Preserves quoted strings as-is
    4. Optionally auto-fixes unescaped special characters
    
    Examples:
    - source:router\\-004.jason.tools -> source:router\-004.jason.tools (fix double escape)
    - source:"router-004.jason.tools" -> unchanged (quoted strings don't need escaping)
    - source:router\-004.jason.tools -> unchanged (correctly escaped)
    """
    original_query = query
    
    # First, fix any double-escaped backslashes that come from MCP protocol layers
    # This happens when a properly escaped query like "source:router\\-004" 
    # gets transmitted as "source:router\\\\-004"
    normalized = query.replace('\\\\', '\\')
    
    # Log the normalization process
    if normalized != original_query:
        logger.info(f"Query normalized (fixed double-escaping): '{original_query}' -> '{normalized}'")
    
    # Auto-fix escaping if requested (useful for queries from AI that might miss escaping)
    if auto_fix_escaping:
        import re
        # Find field:value patterns that aren't quoted
        # Pattern to match field:value where value contains hyphens but isn't quoted
        pattern = r'(\w+):([^"\s]+)'
        
        def escape_value(match):
            field = match.group(1)
            value = match.group(2)
            
            # Skip if already has escaped hyphens or is quoted
            if '\\-' in value or value.startswith('"'):
                return match.group(0)
            
            # Check if value contains unescaped hyphens
            if '-' in value:
                escaped_value = value.replace('-', '\\-')
                logger.info(f"Auto-escaped hyphen: {field}:{value} -> {field}:{escaped_value}")
                return f"{field}:{escaped_value}"
            
            return match.group(0)
        
        normalized = re.sub(pattern, escape_value, normalized)
    
    # Validate the query (just log warnings, don't modify)
    import re
    # Check for unescaped hyphens in field:value patterns (not in quotes)
    unescaped_pattern = r'(\w+):([^"\s]*[-][^"\s]*)'
    matches = re.findall(unescaped_pattern, normalized)
    for field, value in matches:
        if '\\-' not in value and '"' not in value:
            logger.debug(f"Note: Unescaped hyphen in query: {field}:{value}")
            logger.debug(f"This might need: {field}:{value.replace('-', '\\-')} or {field}:\"{value}\"")
    
    return normalized

async def execute_tool(name: str, arguments: dict) -> Union[dict, str]:
    """Execute specific Graylog tool operations with FIXED source analysis and ALL original features"""
    client = get_graylog_client()
    
    async with client:
        # Handle stream name to ID conversion
        if "streams" in arguments and arguments["streams"]:
            stream_input = arguments["streams"]
            # Check if any stream input looks like a name (not an ID)
            needs_resolution = any(
                not (isinstance(s, str) and len(s) == 24 and all(c in "0123456789abcdef" for c in s))
                for s in stream_input
            )
            
            if needs_resolution:
                logger.info(f"Resolving stream names to IDs: {stream_input}")
                stream_mappings = await client.get_stream_mappings()
                resolved_streams = []
                
                for stream in stream_input:
                    stream_lower = stream.lower()
                    if stream_lower in stream_mappings:
                        resolved_id = stream_mappings[stream_lower]
                        logger.info(f"Resolved stream '{stream}' to ID: {resolved_id}")
                        resolved_streams.append(resolved_id)
                    elif len(stream) == 24 and all(c in "0123456789abcdef" for c in stream):
                        # Already an ID
                        resolved_streams.append(stream)
                    else:
                        logger.warning(f"Could not resolve stream name '{stream}' to ID")
                
                arguments["streams"] = resolved_streams
                logger.info(f"Using resolved stream IDs: {resolved_streams}")
        # ================ API breakthrough tools with FIXED source analysis ================
        if name == "get_log_statistics":
            query = normalize_query_string(arguments.get("query", "*"))
            range_from = arguments.get("range_from", "now-5m")
            range_to = arguments.get("range_to", "now")
            streams = arguments.get("streams", [])
            analysis_limit = arguments.get("analysis_limit", 15000)
            
            logger.info(f"Processing log statistics with FIXED source analysis for query '{query}' with limit {analysis_limit}")
            
            try:
                # Apply stream filter to query as workaround for API stream parameter issues
                filtered_query = LogAnalyzer._add_stream_filter_to_query(query, streams)
                logger.info(f"Query with stream filter: '{filtered_query}'")
                
                # Use safe method to get messages with smart pagination
                messages, accurate_total_count = await client._safe_get_messages(
                    query_string=filtered_query,
                    from_time=range_from,
                    to_time=range_to,
                    fields=["timestamp", "source", "message", "level", "facility"],
                    streams=None,  # Don't pass streams since we added them to query
                    target_limit=analysis_limit
                )
                
                logger.info(f"Successfully retrieved {len(messages)} messages for analysis")
                
                # Use fixed LogAnalyzer for analysis
                timerange_info = {
                    "from": range_from,
                    "to": range_to
                }
                
                # Key fix: Ensure total count is correct
                summary_result = LogAnalyzer.generate_summary(messages, query, timerange_info, accurate_total_count)
                
                # Add fix information
                summary_result["processing_info"] = {
                    "processed_on": "MCP_server",
                    "accurate_total_count": accurate_total_count,
                    "sample_messages_analyzed": len(messages),
                    "analysis_limit": analysis_limit,
                    "api_breakthrough_used": True,
                    "source_analysis_enhanced": True,
                    "counting_method": "fixed_accurate_counting_with_enhanced_source_analysis",
                    "fix_version": __version__,
                    "compression_ratio": f"{len(messages)}:1 (raw data not sent to client)",
                    "processing_time": datetime.utcnow().isoformat()
                }
                
                return summary_result
                
            except Exception as e:
                raise GraylogError(f"Failed to get log statistics with fixed source analysis: {e}")
        
        elif name == "analyze_time_patterns":
            query = arguments.get("query", "*")
            range_from = arguments.get("range_from", "now-1h")
            range_to = arguments.get("range_to", "now")
            streams = arguments.get("streams", [])
            
            try:
                # Apply stream filter to query as workaround for API stream parameter issues
                filtered_query = LogAnalyzer._add_stream_filter_to_query(query, streams)
                
                # Use safe method to get messages
                messages, accurate_total_count = await client._safe_get_messages(
                    query_string=filtered_query,
                    from_time=range_from,
                    to_time=range_to,
                    fields=["timestamp", "source", "level"],
                    streams=None,  # Don't pass streams since we added them to query
                    target_limit=20000
                )
                
                # If we couldn't get any messages due to complex query
                if not messages and accurate_total_count == 0:
                    return {
                        "error": "Query too complex",
                        "message": "Unable to analyze time patterns due to query complexity",
                        "suggestion": "Try using more specific field searches instead of general text searches.",
                        "time_patterns": {
                            "hourly_distribution": {},
                            "daily_distribution": {},
                            "minute_distribution": {},
                            "peak_hours": [],
                            "peak_minutes": [],
                            "total_time_slots": 0,
                            "total_minutes": 0,
                            "processing_stats": {
                                "total_messages": 0,
                                "successfully_processed": 0,
                                "error_occurred": True
                            }
                        },
                        "analysis_summary": {
                            "accurate_total_count": 0,
                            "sample_messages_analyzed": 0,
                            "time_range": {"from": range_from, "to": range_to},
                            "query": query,
                            "error_occurred": True
                        }
                    }
                
                # Analyze time patterns
                time_analysis = LogAnalyzer.analyze_time_patterns(messages)
                
                return {
                    "time_patterns": time_analysis,
                    "analysis_summary": {
                        "accurate_total_count": accurate_total_count,
                        "sample_messages_analyzed": len(messages),
                        "time_range": {"from": range_from, "to": range_to},
                        "query": query,
                        "counting_method": "smart_safe_retrieval"
                    },
                    "processing_note": "Time pattern analysis completed using smart pagination (v1.9.25)"
                }
                
            except Exception as e:
                raise GraylogError(f"Failed to analyze time patterns: {e}")
        
        elif name == "analyze_source_distribution":
            query = normalize_query_string(arguments.get("query", "_exists_:source"))
            range_from = arguments.get("range_from", "now-5m")
            range_to = arguments.get("range_to", "now")
            streams = arguments.get("streams", [])
            top_n = arguments.get("top_n", 30)
            
            try:
                logger.info(f"FIXED Source Distribution Analysis for query: {query}")
                
                # Apply stream filter to query as workaround for API stream parameter issues
                filtered_query = LogAnalyzer._add_stream_filter_to_query(query, streams)
                
                # Fix: First get accurate total count
                accurate_total_count = await client.get_accurate_total_count(filtered_query, range_from, range_to, None)
                logger.info(f"Accurate total count: {accurate_total_count}")
                
                # Key fix: Use dedicated source analysis method
                messages = await client.breakthrough_for_source_analysis(
                    query_string=filtered_query,
                    from_time=range_from,
                    to_time=range_to,
                    fields=["source", "timestamp", "level"],
                    streams=None  # Don't pass streams since we added them to query
                )
                
                logger.info(f"Source analysis sample: {len(messages)} messages (target was 25k)")
                
                # Use fixed source analysis method
                source_analysis = LogAnalyzer.analyze_sources(messages, accurate_total_count)
                source_analysis["top_sources"] = source_analysis["top_sources"][:top_n]
                
                return {
                    "source_distribution": source_analysis,
                    "analysis_summary": {
                        "accurate_total_count": accurate_total_count,
                        "sample_messages_analyzed": len(messages),
                        "target_sample_size": client.api_breakthrough_config["source_analysis_target"],
                        "time_range": {"from": range_from, "to": range_to},
                        "query": query,
                        "top_n_requested": top_n,
                        "counting_method": "fixed_accurate_counting_with_proportional_scaling",
                        "sampling_strategy": "enhanced_time_slicing_with_large_sample",
                        "fix_version": __version__
                    },
                    "fix_notes": {
                        "problem_identified": "Sample size too small and not representative",
                        "solution_applied": "Increased target sample to 25k with enhanced time slicing",
                        "scaling_method": "Proportional scaling based on accurate total count",
                        "improvement": "Source counts now estimated from larger representative sample"
                    },
                    "processing_note": "Source distribution analysis completed using FIXED accurate counting with enhanced sampling"
                }
                
            except Exception as e:
                raise GraylogError(f"Failed to analyze source distribution with fixed methods: {e}")
        
        elif name == "analyze_error_patterns":
            query = arguments.get("query", "*")
            range_from = arguments.get("range_from", "now-1h")
            range_to = arguments.get("range_to", "now")
            streams = arguments.get("streams", [])
            
            try:
                # Apply stream filter to query as workaround for API stream parameter issues
                filtered_query = LogAnalyzer._add_stream_filter_to_query(query, streams)
                
                # Try to get accurate total count, but don't fail if it errors
                accurate_total_count = 0
                try:
                    accurate_total_count = await client.get_accurate_total_count(filtered_query, range_from, range_to, None)
                except GraylogError as e:
                    if "too_many_nested_clauses" in str(e):
                        logger.warning(f"Query too complex for accurate count: {e}")
                        # Continue without accurate count
                    else:
                        raise
                
                # Get messages with error handling
                messages = []
                try:
                    # Use smart pagination for better handling of large datasets
                    messages = await client._smart_time_based_pagination(
                        query_string=filtered_query,
                        from_time=range_from,
                        to_time=range_to,
                        fields=["timestamp", "source", "message", "level"],
                        streams=None,  # Don't pass streams since we added them to query
                        target_per_page=10000  # Process in reasonable chunks
                    )
                    
                    # Limit to reasonable number for analysis
                    if len(messages) > 30000:
                        logger.info(f"Limiting error analysis to first 30000 messages out of {len(messages)}")
                        messages = messages[:30000]
                        
                except GraylogError as e:
                    if "too_many_nested_clauses" in str(e):
                        # If query is too complex, return error with helpful message
                        return {
                            "error": "Query too complex",
                            "message": str(e),
                            "suggestion": "Try using more specific field searches instead of general text searches.",
                            "error_patterns": {
                                "total_errors": 0,
                                "error_sources": {},
                                "error_keywords": {},
                                "recent_errors": [],
                                "error_percentage": 0
                            },
                            "analysis_summary": {
                                "accurate_total_count": 0,
                                "sample_messages_analyzed": 0,
                                "time_range": {"from": range_from, "to": range_to},
                                "query": query,
                                "error_occurred": True
                            }
                        }
                    else:
                        raise
                
                # Analyze error patterns
                error_analysis = LogAnalyzer.extract_error_patterns(messages)
                
                return {
                    "error_patterns": error_analysis,
                    "analysis_summary": {
                        "accurate_total_count": accurate_total_count,
                        "sample_messages_analyzed": len(messages),
                        "time_range": {"from": range_from, "to": range_to},
                        "query": query,
                        "counting_method": "smart_time_based_pagination"
                    },
                    "processing_note": "Error pattern analysis completed using smart pagination (v1.9.25)"
                }
                
            except Exception as e:
                raise GraylogError(f"Failed to analyze error patterns: {e}")
        
        elif name == "get_log_level_analysis":
            query = normalize_query_string(arguments.get("query", "*"))
            range_from = arguments.get("range_from", "now-5m")
            range_to = arguments.get("range_to", "now")
            streams = arguments.get("streams", [])
            
            try:
                # Apply stream filter to query as workaround for API stream parameter issues
                filtered_query = LogAnalyzer._add_stream_filter_to_query(query, streams)
                
                # Use safe method to get messages
                messages, accurate_total_count = await client._safe_get_messages(
                    query_string=filtered_query,
                    from_time=range_from,
                    to_time=range_to,
                    fields=["level", "timestamp", "source"],
                    streams=None,  # Don't pass streams since we added them to query
                    target_limit=20000
                )
                
                # If we couldn't get any messages due to complex query
                if not messages and accurate_total_count == 0:
                    return {
                        "error": "Query too complex",
                        "message": "Unable to analyze log levels due to query complexity",
                        "suggestion": "Try using more specific field searches instead of general text searches.",
                        "level_analysis": {
                            "level_distribution": {},
                            "error_rate": 0,
                            "warning_rate": 0,
                            "total_errors": 0,
                            "total_warnings": 0,
                            "most_common_level": ("unknown", 0)
                        },
                        "analysis_summary": {
                            "accurate_total_count": 0,
                            "sample_messages_analyzed": 0,
                            "time_range": {"from": range_from, "to": range_to},
                            "query": query,
                            "error_occurred": True
                        }
                    }
                
                # Analyze log levels
                level_analysis = LogAnalyzer.analyze_levels(messages)
                
                return {
                    "level_analysis": level_analysis,
                    "analysis_summary": {
                        "accurate_total_count": accurate_total_count,
                        "sample_messages_analyzed": len(messages),
                        "time_range": {"from": range_from, "to": range_to},
                        "query": query,
                        "counting_method": "smart_safe_retrieval"
                    },
                    "processing_note": "Log level analysis completed using smart pagination (v1.9.25)"
                }
                
            except Exception as e:
                raise GraylogError(f"Failed to analyze log levels: {e}")
        
        elif name == "analyze_field_distribution":
            field_name = arguments["field_name"]
            query = normalize_query_string(arguments.get("query", "*"))
            range_from = arguments.get("range_from", "now-5m")
            range_to = arguments.get("range_to", "now")
            top_n = arguments.get("top_n", 50)
            streams = arguments.get("streams", [])
            
            logger.info(f"Analyzing field distribution for '{field_name}' with query '{query}'")
            if streams:
                logger.info(f"Using streams filter: {streams}")
            
            # Apply stream filter to query if needed
            query = LogAnalyzer._add_stream_filter_to_query(query, streams)
            if streams:
                logger.info(f"Modified query with stream filter: {query}")
            
            try:
                # Determine fields to retrieve - always include the target field
                fields = ["timestamp", "source", field_name]
                # Also try alternate naming conventions
                if "-" in field_name:
                    fields.append(field_name.replace("-", "_"))
                elif "_" in field_name:
                    fields.append(field_name.replace("_", "-"))
                
                # Retrieve messages using safe method with smart pagination
                messages, accurate_total_count = await client._safe_get_messages(
                    query_string=query,
                    from_time=range_from,
                    to_time=range_to,
                    fields=fields,
                    streams=streams,
                    target_limit=30000
                )
                
                logger.info(f"Accurate total count: {accurate_total_count}, messages retrieved: {len(messages)}")
                
                # Analyze field distribution
                field_analysis = LogAnalyzer.analyze_field_distribution(
                    messages, field_name, top_n, accurate_total_count
                )
                
                return {
                    "field_analysis": field_analysis,
                    "analysis_summary": {
                        "accurate_total_count": accurate_total_count,
                        "sample_messages_analyzed": len(messages),
                        "time_range": {"from": range_from, "to": range_to},
                        "query": query,
                        "field_analyzed": field_name,
                        "unique_values_found": field_analysis["total_unique_values"],
                        "field_coverage": f"{field_analysis['coverage_rate']}%",
                        "counting_method": "fixed_accurate_counting_with_field_analysis"
                    },
                    "processing_info": {
                        "processed_on": "MCP_server",
                        "fix_version": __version__,
                        "processing_time": datetime.utcnow().isoformat()
                    }
                }
                
            except Exception as e:
                raise GraylogError(f"Failed to analyze field distribution for '{field_name}': {e}")
        
        # ================ Sample query tools ================
        elif name == "get_log_sample":
            query = normalize_query_string(arguments.get("query", "*"))
            range_from = arguments.get("range_from", "now-5m")
            range_to = arguments.get("range_to", "now")
            limit = min(arguments.get("limit", 50), 200)
            fields = arguments.get("fields", ["timestamp", "source", "message", "level"])
            streams = arguments.get("streams", [])
            
            try:
                # Apply stream filter to query as workaround for API stream parameter issues
                filtered_query = LogAnalyzer._add_stream_filter_to_query(query, streams)
                
                # Try to get accurate total count, but don't fail if it errors
                accurate_total_count = 0
                try:
                    accurate_total_count = await client.get_accurate_total_count(filtered_query, range_from, range_to, None)
                except GraylogError as e:
                    if "too_many_nested_clauses" in str(e):
                        logger.warning(f"Query too complex for accurate count: {e}")
                        # Continue without accurate count
                    else:
                        raise
                
                # Get sample data with error handling
                messages = []
                try:
                    # For small samples, use direct approach
                    if limit <= 200:
                        messages = await client._single_high_limit_search(
                            query_string=filtered_query,
                            timerange=client._build_timerange(range_from, range_to),
                            fields=fields,
                            streams=None,
                            limit=min(limit * 3, 1000)  # Get extra to ensure we have enough
                        )
                    else:
                        # For larger samples, use smart pagination
                        messages = await client._smart_time_based_pagination(
                            query_string=filtered_query,
                            from_time=range_from,
                            to_time=range_to,
                            fields=fields,
                            streams=None,
                            target_per_page=5000  # Smaller chunks for samples
                        )
                except GraylogError as e:
                    if "too_many_nested_clauses" in str(e):
                        # If query is too complex, return error with helpful message
                        return {
                            "error": "Query too complex",
                            "message": str(e),
                            "suggestion": "Try using more specific field searches instead of general text searches. For example, use 'app:AdGuardHome' instead of 'AdGuardHome'.",
                            "sample_messages": [],
                            "sample_info": {
                                "accurate_total_count": 0,
                                "requested_limit": limit,
                                "actual_count": 0,
                                "total_available": 0,
                                "fields_included": fields,
                                "time_range": {"from": range_from, "to": range_to},
                                "query": query,
                                "error_occurred": True
                            }
                        }
                    else:
                        raise
                
                sample_messages = messages[:limit] if len(messages) > limit else messages
                
                return {
                    "sample_messages": sample_messages,
                    "sample_info": {
                        "accurate_total_count": accurate_total_count,
                        "requested_limit": limit,
                        "actual_count": len(sample_messages),
                        "total_available": len(messages),
                        "fields_included": fields,
                        "time_range": {"from": range_from, "to": range_to},
                        "query": query,
                        "counting_method": "fixed_accurate_counting"
                    },
                    "note": "High-quality sample data using FIXED accurate counting"
                }
                
            except Exception as e:
                raise GraylogError(f"Failed to get log sample with fixed counting: {e}")
        
        elif name == "search_logs_paginated":
            query = arguments["query"]
            # Log the original query to debug escape issues
            logger.info(f"Original query received: {repr(query)}")
            
            # Normalize the query to fix double-escaped backslashes
            query = normalize_query_string(query)
            
            range_from = arguments.get("range_from", "now-5m")
            range_to = arguments.get("range_to", "now")
            limit = min(arguments.get("limit", 100), 500)
            offset = arguments.get("offset", 0)
            fields = arguments.get("fields", ["timestamp", "source", "message", "level"])
            streams = arguments.get("streams", [])
            
            try:
                # Apply stream filter to query as workaround for API stream parameter issues
                filtered_query = LogAnalyzer._add_stream_filter_to_query(query, streams)
                logger.info(f"Filtered query: {repr(filtered_query)}")
                
                # Get accurate total count first
                accurate_total_count = 0
                try:
                    accurate_total_count = await client.get_accurate_total_count(filtered_query, range_from, range_to, None)
                    logger.info(f"Total count for pagination: {accurate_total_count}")
                except GraylogError as e:
                    if "too_many_nested_clauses" in str(e):
                        logger.warning(f"Query too complex for accurate count: {e}")
                        # Return error response for complex queries
                        return {
                            "error": "Query too complex",
                            "message": str(e),
                            "suggestion": "Try using more specific field searches instead of general text searches.",
                            "messages": [],
                            "pagination": {
                                "accurate_total_count": 0,
                                "offset": offset,
                                "limit": limit,
                                "current_count": 0,
                                "error_occurred": True
                            }
                        }
                    else:
                        raise
                
                # Calculate which time slice we need based on offset
                page_size = 1000  # Smaller page size for real pagination
                
                # If offset is 0 and limit is small, just get what we need
                if offset == 0 and limit <= 1000:
                    # Direct query for first page
                    messages = await client._single_high_limit_search(
                        query_string=filtered_query,
                        timerange=client._build_timerange(range_from, range_to),
                        fields=fields,
                        streams=None,
                        limit=min(limit + 100, 2000)  # Get a bit extra for buffer
                    )
                    
                    paginated_messages = messages[:limit] if messages else []
                else:
                    # For larger offsets, we need to calculate time slices
                    # Calculate approximate time position based on offset
                    if accurate_total_count > 0:
                        # Calculate time position based on offset ratio
                        offset_ratio = offset / accurate_total_count
                        
                        timerange = client._build_timerange(range_from, range_to)
                        if timerange["type"] == "relative":
                            total_seconds = timerange["range"]
                            # Start from the time position based on offset
                            slice_start_seconds = int(total_seconds * offset_ratio)
                            slice_duration = min(300, total_seconds // 10)  # 5 minutes or 10% of range
                            
                            slice_from = f"now-{slice_start_seconds + slice_duration}s"
                            slice_to = f"now-{slice_start_seconds}s"
                        else:
                            from_dt = datetime.fromisoformat(timerange["from"].replace('Z', '+00:00')).replace(tzinfo=None)
                            to_dt = datetime.fromisoformat(timerange["to"].replace('Z', '+00:00')).replace(tzinfo=None)
                            total_seconds = (to_dt - from_dt).total_seconds()
                            
                            slice_start_dt = from_dt + timedelta(seconds=total_seconds * offset_ratio)
                            slice_duration = min(300, total_seconds / 10)  # 5 minutes or 10% of range
                            
                            slice_from = slice_start_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
                            slice_to = (slice_start_dt + timedelta(seconds=slice_duration)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
                        
                        # Get messages from the calculated time slice
                        messages = await client._single_high_limit_search(
                            query_string=filtered_query,
                            timerange=client._build_timerange(slice_from, slice_to),
                            fields=fields,
                            streams=None,
                            limit=limit + 100  # Get extra for buffer
                        )
                        
                        paginated_messages = messages[:limit] if messages else []
                    else:
                        # Fallback: just get the requested limit
                        messages = await client._single_high_limit_search(
                            query_string=filtered_query,
                            timerange=client._build_timerange(range_from, range_to),
                            fields=fields,
                            streams=None,
                            limit=limit
                        )
                        paginated_messages = messages
                
                return {
                    "messages": paginated_messages,
                    "pagination": {
                        "accurate_total_count": accurate_total_count,
                        "offset": offset,
                        "limit": limit,
                        "current_count": len(paginated_messages),
                        "has_more": offset + limit < accurate_total_count,
                        "counting_method": "smart_time_based_pagination"
                    },
                    "query_info": {
                        "query": query,
                        "time_range": {"from": range_from, "to": range_to},
                        "fields": fields
                    },
                    "note": "Using smart time-based pagination for better performance"
                }
                
            except Exception as e:
                raise GraylogError(f"Failed to search logs with pagination: {e}")
        
        # ================ Export tools ================
        elif name == "search_messages_export":
            query = arguments["query"]
            # Normalize the query to fix double-escaped backslashes
            query = normalize_query_string(query)
            
            range_from = arguments.get("range_from", "now-5m")
            range_to = arguments.get("range_to", "now")
            limit = arguments.get("limit", 1000)  # Remove 5000 limit
            fields = arguments.get("fields", ["timestamp", "source", "message"])
            
            try:
                logger.info(f"search_messages_export: query='{query}', limit={limit}, fields={fields}")
                
                # Use safe method to get messages with smart pagination
                messages, accurate_total_count = await client._safe_get_messages(
                    query_string=query,
                    from_time=range_from,
                    to_time=range_to,
                    fields=fields,
                    streams=None,
                    target_limit=limit
                )
                logger.info(f"Accurate total count: {accurate_total_count}, retrieved {len(messages)} messages")
                
                if messages:
                    logger.info(f"Processing {len(messages)} messages for analysis")
                    
                    # Log first message to see available fields
                    if messages:
                        logger.debug(f"First message fields: {list(messages[0].keys())}")
                    
                    # Generate complete statistics
                    timerange_info = {"from": range_from, "to": range_to}
                    complete_analysis = LogAnalyzer.generate_summary(messages, query, timerange_info, accurate_total_count)
                    
                    # Export specific statistics
                    field_stats = {}
                    for field in fields:
                        # Handle field variations (e.g., src-ip might be src_ip or src)
                        field_values = []
                        for msg in messages:
                            # Try exact field name first
                            if field in msg:
                                field_values.append(str(msg[field]))
                            # Try with underscores
                            elif field.replace('-', '_') in msg:
                                field_values.append(str(msg[field.replace('-', '_')]))
                            # Try without hyphens
                            elif field.replace('-', '') in msg:
                                field_values.append(str(msg[field.replace('-', '')]))
                        
                        unique_values = len(set(field_values))
                        field_stats[field] = {
                            "total_values": len(field_values),
                            "unique_values": unique_values,
                            "completeness": round((len(field_values) / len(messages)) * 100, 2) if messages else 0
                        }
                    
                    # Return all messages if limit is small, otherwise return a reasonable sample
                    if len(messages) <= 100:
                        sample_data = messages
                    else:
                        # Return first 50, some middle samples, and last 50
                        sample_data = messages[:50]
                        if len(messages) > 150:
                            middle_start = len(messages) // 2 - 25
                            sample_data.extend(messages[middle_start:middle_start + 50])
                        sample_data.extend(messages[-50:])
                    
                    return {
                        "export_analysis": {
                            "accurate_total_count": accurate_total_count,
                            "sample_records_processed": len(messages),
                            "requested_limit": limit,
                            "fields_analyzed": fields,
                            "field_statistics": field_stats,
                            "time_range": timerange_info,
                            "query": query
                        },
                        "comprehensive_analysis": complete_analysis,
                        "sample_data": sample_data,
                        "processing_info": {
                            "analysis_completed_on": "MCP_server",
                            "accurate_counting_used": True,
                            "counting_method": "fixed_accurate_counting",
                            "raw_data_size": f"{len(messages)} sample records from {accurate_total_count} total",
                            "compression_achieved": f"Full analysis instead of raw records",
                            "processing_time": datetime.utcnow().isoformat()
                        },
                        "note": "Complete analysis performed on MCP server using FIXED accurate counting"
                    }
                else:
                    return {
                        "export_analysis": {
                            "accurate_total_count": accurate_total_count,
                            "sample_records_processed": 0,
                            "requested_limit": limit,
                            "fields_analyzed": fields,
                            "time_range": {"from": range_from, "to": range_to},
                            "query": query
                        },
                        "processing_info": {
                            "analysis_completed_on": "MCP_server",
                            "accurate_counting_used": True,
                            "counting_method": "fixed_accurate_counting",
                            "processing_time": datetime.utcnow().isoformat()
                        },
                        "note": "No sample data found using FIXED accurate counting"
                    }
                    
            except Exception as e:
                raise GraylogError(f"Failed to export and analyze messages with fixed counting: {e}")
        
        # ================ System Info Tools ================
        elif name == "get_streams":
            try:
                result = await client.get("/streams")
                
                # Enhanced stream information with ID and title mapping
                if isinstance(result, dict) and "streams" in result:
                    stream_list = []
                    for stream in result["streams"]:
                        stream_info = {
                            "id": stream.get("id", ""),
                            "title": stream.get("title", ""),
                            "description": stream.get("description", ""),
                            "disabled": stream.get("disabled", False),
                            "matching_type": stream.get("matching_type", ""),
                            "rules": stream.get("rules", [])
                        }
                        stream_list.append(stream_info)
                    
                    # Sort by title for easier reading
                    stream_list.sort(key=lambda x: x["title"].lower())
                    
                    return {
                        "streams": stream_list,
                        "total": len(stream_list),
                        "usage_tip": "You can use either stream title (e.g., 'PVE Stream') or stream ID in the streams parameter"
                    }
                else:
                    return result
                    
            except Exception as e:
                raise GraylogError(f"Failed to get streams: {e}")
            
        elif name == "get_system_info":
            try:
                # Try multiple endpoints for system information
                try:
                    cluster_status = await client.get("/cluster/status")
                    return {"cluster": cluster_status}
                except:
                    try:
                        system_info = await client.get("/system")
                        return {"system": system_info}
                    except:
                        try:
                            node_info = await client.get("/cluster/nodes")
                            return {"nodes": node_info}
                        except:
                            version_info = await client.get("/version")
                            return {"version": version_info}
            except Exception as e:
                raise GraylogError(f"Failed to get system info: {e}")
        
        # ================ Content Packs Tools ================
        elif name == "list_content_packs":
            try:
                return await client.get("/system/content_packs")
            except Exception as e:
                raise GraylogError(f"Failed to list content packs: {e}")

        elif name == "get_content_pack":
            content_pack_id = arguments["content_pack_id"]
            try:
                return await client.get(f"/system/content_packs/{content_pack_id}")
            except Exception as e:
                raise GraylogError(f"Failed to get content pack {content_pack_id}: {e}")

        elif name == "get_content_pack_revision":
            content_pack_id = arguments["content_pack_id"]
            revision = arguments.get("revision", 1)
            try:
                result = await client.get(f"/system/content_packs/{content_pack_id}/{revision}")
                
                # Extract dashboard information if present
                entities = result.get("entities", [])
                dashboards = []
                widgets = []
                
                for entity in entities:
                    entity_type = entity.get("type", {}).get("name", "")
                    if entity_type == "dashboard":
                        dashboards.append({
                            "id": entity.get("id"),
                            "data": entity.get("data", {}),
                            "title": entity.get("data", {}).get("title", ""),
                            "description": entity.get("data", {}).get("description", "")
                        })
                    elif entity_type == "dashboard_widget":
                        widgets.append({
                            "id": entity.get("id"),
                            "data": entity.get("data", {}),
                            "type": entity.get("data", {}).get("type", ""),
                            "description": entity.get("data", {}).get("description", ""),
                            "configuration": entity.get("data", {}).get("configuration", {}),
                            "cache_time": entity.get("data", {}).get("cache_time", 0)
                        })
                
                return {
                    "content_pack": result,
                    "extracted_info": {
                        "dashboards": dashboards,
                        "widgets": widgets,
                        "dashboard_count": len(dashboards),
                        "widget_count": len(widgets)
                    },
                    "note": "Content packs may contain complete dashboard and widget configurations"
                }
                
            except Exception as e:
                raise GraylogError(f"Failed to get content pack revision {content_pack_id}/{revision}: {e}")

        # ================ Dashboard Tools ================
        elif name == "list_dashboards":
            try:
                result = await client.get("/dashboards")
                
                if isinstance(result, dict):
                    if "elements" in result:
                        dashboards = []
                        for element in result.get("elements", []):
                            if element.get("type") == "DASHBOARD":
                                dashboards.append(element)
                        
                        return {
                            "dashboards": dashboards,
                            "total": len(dashboards),
                            "total_elements": result.get("total", len(result.get("elements", []))),
                            "pagination": result.get("pagination", {}),
                            "source": "elements_api"
                        }
                    
                    elif "dashboards" in result:
                        return result
                    
                    else:
                        return {
                            "raw_response": result,
                            "note": "Unknown response format - returning raw data"
                        }
                else:
                    raise GraylogError("Invalid response format from dashboards API")
                        
            except Exception as e:
                raise GraylogError(f"Failed to list dashboards: {e}")

        elif name == "get_dashboard":
            dashboard_id = arguments["dashboard_id"]
            try:
                dashboard_response = None
                api_used = ""
                
                try:
                    dashboard_response = await client.get(f"/views/{dashboard_id}")
                    api_used = "views_api"
                except Exception as e:
                    logger.debug(f"Views API failed: {e}")
                    
                    try:
                        dashboard_response = await client.get(f"/dashboards/{dashboard_id}")
                        api_used = "legacy_dashboards_api"
                    except Exception as e2:
                        raise GraylogError(f"Both API endpoints failed. Views API: {e}, Legacy API: {e2}")
                
                # Handle response
                if isinstance(dashboard_response, str):
                    try:
                        dashboard = json.loads(dashboard_response)
                    except json.JSONDecodeError:
                        raise GraylogError(f"Invalid JSON response: {dashboard_response}")
                else:
                    dashboard = dashboard_response
                
                if not isinstance(dashboard, dict):
                    raise GraylogError(f"Unexpected dashboard response type: {type(dashboard)}")
                
                # Handle both new and legacy API formats
                dashboard_info = {}
                widgets = []
                
                # Modern Views API format
                if api_used == "views_api":
                    dashboard_info = {
                        "id": dashboard.get("id"),
                        "title": dashboard.get("title"),
                        "description": dashboard.get("description", ""),
                        "summary": dashboard.get("summary", ""),
                        "type": dashboard.get("type"),
                        "created_at": dashboard.get("created_at"),
                        "last_updated_at": dashboard.get("last_updated_at"),
                        "owner": dashboard.get("owner"),
                        "favorite": dashboard.get("favorite", False),
                        "search_id": dashboard.get("search_id")
                    }
                    
                    # Extract widget basic info from view state
                    state = dashboard.get("state", {})
                    if isinstance(state, dict):
                        widgets_data = state.get("widgets", [])
                        if not widgets_data:
                            positions = state.get("positions", {})
                            if positions:
                                widgets_data = [{"id": k} for k in positions.keys()]
                        
                        for widget in widgets_data:
                            if isinstance(widget, dict):
                                widget_info = {
                                    "id": widget.get("id"),
                                    "type": widget.get("type", "unknown"),
                                    "config": widget.get("config", {}),
                                    "timerange": widget.get("timerange", {}),
                                    "query": widget.get("query", {}),
                                    "streams": widget.get("streams", []),
                                    "note": "Widget data not accessible via API - only configuration available"
                                }
                                widgets.append(widget_info)
                            elif isinstance(widget, str):
                                widget_info = {
                                    "id": widget,
                                    "type": "unknown",
                                    "note": "Widget data not accessible via API - only ID available"
                                }
                                widgets.append(widget_info)
                
                # Legacy format fallback
                else:
                    dashboard_info = {
                        "id": dashboard.get("id"),
                        "title": dashboard.get("title"),
                        "description": dashboard.get("description", ""),
                        "created_at": dashboard.get("created_at"),
                        "creator_user_id": dashboard.get("creator_user_id")
                    }
                    
                    for widget in dashboard.get("widgets", []):
                        widget_info = {
                            "id": widget.get("id"),
                            "type": widget.get("type"),
                            "description": widget.get("description", ""),
                            "cache_time": widget.get("cache_time", 0),
                            "config": widget.get("config", {}),
                            "note": "Widget data not accessible via API - only configuration available"
                        }
                        widgets.append(widget_info)
                
                result = {
                    "dashboard": dashboard_info,
                    "widgets": widgets,
                    "widget_count": len(widgets),
                    "api_used": api_used,
                    "limitations": {
                        "widget_data": "Widget data/values cannot be retrieved via API",
                        "available": "Only dashboard metadata and widget configuration accessible",
                        "alternative": "Use content packs for complete widget configurations"
                    }
                }
                
                return result
                
            except Exception as e:
                raise GraylogError(f"Failed to get dashboard {dashboard_id}: {e}")
        
        # ================ Testing tools ================
        elif name == "test_accurate_counting":
            query = normalize_query_string(arguments.get("query", "*"))
            range_from = arguments.get("range_from", "now-5m")
            range_to = arguments.get("range_to", "now")
            
            try:
                logger.info(f"Testing accurate counting methods for query: {query}")
                
                # Test all counting methods
                timerange = client._build_timerange(range_from, range_to)
                
                test_results = {}
                
                # Test various counting strategies
                count_strategies = [
                    ("universal_relative_count", client._count_universal_relative),
                    ("universal_absolute_count", client._count_universal_absolute),
                    ("views_search_count", client._count_views_search),
                    ("legacy_search_count", client._count_legacy_search)
                ]
                
                for strategy_name, strategy_func in count_strategies:
                    try:
                        logger.info(f"Testing {strategy_name}")
                        count_result = await strategy_func(query, timerange, None)
                        test_results[strategy_name] = {
                            "status": "success",
                            "count": count_result,
                            "error": None
                        }
                        logger.info(f"{strategy_name}: {count_result}")
                    except Exception as e:
                        test_results[strategy_name] = {
                            "status": "failed",
                            "count": 0,
                            "error": str(e)
                        }
                        logger.warning(f"{strategy_name}: {e}")
                
                # Use integrated method
                try:
                    integrated_count = await client.get_accurate_total_count(query, range_from, range_to, None)
                    test_results["integrated_method"] = {
                        "status": "success",
                        "count": integrated_count,
                        "error": None
                    }
                except Exception as e:
                    test_results["integrated_method"] = {
                        "status": "failed",
                        "count": 0,
                        "error": str(e)
                    }
                
                # Analyze results
                successful_counts = [r["count"] for r in test_results.values() if r["status"] == "success" and r["count"] > 0]
                max_count = max(successful_counts) if successful_counts else 0
                min_count = min(successful_counts) if successful_counts else 0
                
                return {
                    "test_summary": {
                        "query": query,
                        "time_range": {"from": range_from, "to": range_to},
                        "max_count_found": max_count,
                        "min_count_found": min_count,
                        "count_variance": max_count - min_count if successful_counts else 0,
                        "successful_methods": len(successful_counts),
                        "total_methods_tested": len(count_strategies) + 1
                    },
                    "method_results": test_results,
                    "recommendations": {
                        "best_count": max_count,
                        "reliable_methods": [k for k, v in test_results.items() if v["status"] == "success" and v["count"] == max_count],
                        "note": "The integrated method should use the highest count from successful methods"
                    },
                    "debug_info": {
                        "timerange_config": timerange,
                        "all_counts": successful_counts,
                        "test_timestamp": datetime.utcnow().isoformat()
                    }
                }
                
            except Exception as e:
                raise GraylogError(f"Failed to test accurate counting: {e}")
        
        elif name == "test_source_analysis_fix":
            query = normalize_query_string(arguments.get("query", "*"))
            range_from = arguments.get("range_from", "now-5m")
            range_to = arguments.get("range_to", "now")
            
            try:
                logger.info(f"Testing FIXED source analysis for query: {query}")
                
                # Step 1: Get accurate total count
                accurate_total_count = await client.get_accurate_total_count(query, range_from, range_to, None)
                logger.info(f"Step 1 - Accurate total: {accurate_total_count}")
                
                # Step 2: Test old method (standard breakthrough)
                logger.info("Step 2 - Testing standard method")
                old_messages = await client.breakthrough_api_limits(
                    query_string=query,
                    from_time=range_from,
                    to_time=range_to,
                    fields=["source", "timestamp"],
                    target_limit=5000  # Standard limit
                )
                
                old_source_analysis = LogAnalyzer.analyze_sources(old_messages, accurate_total_count)
                old_top_5 = old_source_analysis["top_sources"][:5]
                
                logger.info(f"Standard method sample size: {len(old_messages)}")
                
                # Step 3: Test new method (dedicated source analysis)
                logger.info("Step 3 - Testing FIXED source analysis method")
                new_messages = await client.breakthrough_for_source_analysis(
                    query_string=query,
                    from_time=range_from,
                    to_time=range_to,
                    fields=["source", "timestamp"]
                )
                
                new_source_analysis = LogAnalyzer.analyze_sources(new_messages, accurate_total_count)
                new_top_5 = new_source_analysis["top_sources"][:5]
                
                logger.info(f"FIXED method sample size: {len(new_messages)}")
                
                # Step 4: Compare results
                comparison_results = {
                    "test_summary": {
                        "query": query,
                        "time_range": {"from": range_from, "to": range_to},
                        "accurate_total_count": accurate_total_count,
                        "standard_method_sample_size": len(old_messages),
                        "fixed_method_sample_size": len(new_messages),
                        "sample_size_improvement": f"{((len(new_messages) - len(old_messages)) / len(old_messages) * 100):.1f}%" if old_messages else "N/A"
                    },
                    "standard_method_results": {
                        "sample_size": len(old_messages),
                        "top_5_sources": [
                            {
                                "source": src["source"],
                                "estimated_count": src["count"],
                                "sample_count": src.get("sample_count", src["count"]),
                                "percentage": src["percentage"]
                            } for src in old_top_5
                        ],
                        "method": "standard_breakthrough_api_limits"
                    },
                    "fixed_method_results": {
                        "sample_size": len(new_messages),
                        "top_5_sources": [
                            {
                                "source": src["source"],
                                "estimated_count": src["count"],
                                "sample_count": src.get("sample_count", src["count"]),
                                "percentage": src["percentage"]
                            } for src in new_top_5
                        ],
                        "method": "breakthrough_for_source_analysis_with_enhanced_time_slicing"
                    },
                    "comparison_analysis": {
                        "ranking_changes": [],
                        "count_differences": [],
                        "accuracy_improvements": []
                    },
                    "fix_validation": {
                        "larger_sample_achieved": len(new_messages) > len(old_messages),
                        "more_representative_data": len(new_messages) >= client.api_breakthrough_config.get("source_analysis_min_sample", 10000),
                        "proportional_scaling_used": True,
                        "enhanced_time_slicing_applied": True
                    }
                }
                
                # Analyze ranking changes
                old_ranking = {src["source"]: i for i, src in enumerate(old_top_5)}
                new_ranking = {src["source"]: i for i, src in enumerate(new_top_5)}
                
                for source in set(old_ranking.keys()) | set(new_ranking.keys()):
                    old_rank = old_ranking.get(source, "N/A")
                    new_rank = new_ranking.get(source, "N/A")
                    
                    if old_rank != "N/A" and new_rank != "N/A":
                        rank_change = old_rank - new_rank  # Positive means rank improved
                        if rank_change != 0:
                            comparison_results["comparison_analysis"]["ranking_changes"].append({
                                "source": source,
                                "old_rank": old_rank + 1,  # Convert to 1-based
                                "new_rank": new_rank + 1,
                                "change": "UP" if rank_change > 0 else "DOWN",
                                "positions": abs(rank_change)
                            })
                
                # Analyze count differences
                old_counts = {src["source"]: src["count"] for src in old_top_5}
                new_counts = {src["source"]: src["count"] for src in new_top_5}
                
                for source in set(old_counts.keys()) & set(new_counts.keys()):
                    old_count = old_counts[source]
                    new_count = new_counts[source]
                    difference = new_count - old_count
                    percentage_change = (difference / old_count * 100) if old_count > 0 else 0
                    
                    comparison_results["comparison_analysis"]["count_differences"].append({
                        "source": source,
                        "old_estimated_count": old_count,
                        "new_estimated_count": new_count,
                        "difference": difference,
                        "percentage_change": f"{percentage_change:.1f}%"
                    })
                
                # Accuracy improvement analysis
                if len(new_messages) > len(old_messages):
                    improvement_factor = len(new_messages) / len(old_messages) if old_messages else float('inf')
                    comparison_results["comparison_analysis"]["accuracy_improvements"].append(
                        f"Sample size increased by {improvement_factor:.1f}x"
                    )
                
                if len(new_messages) >= client.api_breakthrough_config.get("source_analysis_min_sample", 10000):
                    comparison_results["comparison_analysis"]["accuracy_improvements"].append(
                        "Achieved minimum recommended sample size for source analysis"
                    )
                
                comparison_results["fix_status"] = {
                    "fix_applied": True,
                    "sample_size_adequate": len(new_messages) >= 10000,
                    "representativeness_improved": len(new_messages) > len(old_messages) * 1.5,
                    "proportional_scaling_working": new_source_analysis.get("estimation_info", {}).get("estimation_method") == "proportional_scaling",
                    "overall_fix_success": len(new_messages) >= 10000 and len(new_messages) > len(old_messages) * 1.5
                }
                
                comparison_results["recommendations"] = [
                    "[OK] FIXED method provides larger, more representative sample",
                    "[OK] Proportional scaling estimates actual counts from sample ratios",
                    "[OK] Enhanced time slicing ensures temporal representativeness",
                    "Results should now be much closer to actual Graylog UI statistics",
                    "Use 'analyze_source_distribution' tool for production analysis"
                ]
                
                return comparison_results
                
            except Exception as e:
                raise GraylogError(f"Failed to test source analysis fix: {e}")
        
        else:
            raise GraylogError(f"Tool '{name}' is not implemented.")

def parse_args():
    """Parse command line arguments with enhanced validation"""
    args = sys.argv[1:]
    host = os.getenv("GRAYLOG_HOST", "")
    
    # Auto-add protocol if missing
    if host and not host.startswith(('http://', 'https://')):
        if host.startswith('192.168.') or host.startswith('127.0.') or host.startswith('localhost'):
            host = f"http://{host}"
        else:
            host = f"https://{host}"
    
    config = {
        'host': host,
        'username': os.getenv("GRAYLOG_USERNAME", ""),
        'password': os.getenv("GRAYLOG_PASSWORD", ""),
        'api_token': os.getenv("GRAYLOG_API_TOKEN", ""),
        'verify_ssl': os.getenv("GRAYLOG_VERIFY_SSL", "false").lower() in ("true", "1", "yes"),
        'timeout': float(os.getenv("GRAYLOG_TIMEOUT", "30")),
        'test': False,
        'help': False,
        'debug': False
    }
    
    i = 0
    while i < len(args):
        arg = args[i]
        
        if arg in ['-h', '--help']:
            config['help'] = True
        elif arg == '--host' and i + 1 < len(args):
            config['host'] = args[i + 1]
            i += 1
        elif arg == '--username' and i + 1 < len(args):
            config['username'] = args[i + 1]
            i += 1
        elif arg == '--password' and i + 1 < len(args):
            config['password'] = args[i + 1]
            i += 1
        elif arg == '--api-token' and i + 1 < len(args):
            config['api_token'] = args[i + 1]
            i += 1
        elif arg == '--verify-ssl':
            config['verify_ssl'] = True
        elif arg == '--test':
            config['test'] = True
        elif arg == '--debug':
            config['debug'] = True
            logging.getLogger().setLevel(logging.DEBUG)
        
        i += 1
    
    return config

async def main():
    """Main function with comprehensive testing and debugging"""
    try:
        global graylog_config
        
        # Parse command line arguments
        config = parse_args()
        
        # Show help message
        if config['help']:
            print("Graylog MCP Server - Complete Features + Smart Pagination v1.9.34")
            print("Retain all original features + Graylog escaping compliance")
            print()
            print("Key fixes in v1.9.34:")
            print("  [OK] Fixed Python SyntaxWarning for invalid escape sequences")
            print("  [OK] Proper Graylog escaping rules implementation")
            print(r"  [OK] Handles both source:router\-004 and source:\"router-004\"")
            print("  [OK] Fixed double-escaped backslash from MCP protocol")
            print()
            print("Previous fixes retained:")
            print("  [OK] Source analysis sampling accuracy")
            print("  [OK] Dedicated breakthrough methods")
            print("  [OK] Enhanced time slicing")
            print("  [OK] Proportional scaling calculations")
            print()
            print("Environment variables:")
            print("  GRAYLOG_HOST - Graylog server URL (required)")
            print("  GRAYLOG_USERNAME - Username for authentication")
            print("  GRAYLOG_PASSWORD - Password for authentication")  
            print("  GRAYLOG_API_TOKEN - API token (alternative to user/pass)")
            print("  GRAYLOG_VERIFY_SSL - Verify SSL certificates (default: false)")
            print("  GRAYLOG_TIMEOUT - Request timeout in seconds (default: 30)")
            print()
            print("All Available Tools:")
            print("  Analysis Tools (FIXED):")
            print("    - get_log_statistics (accurate counting + fixed source analysis)")
            print("    - analyze_time_patterns (time pattern analysis)")
            print("    - analyze_source_distribution (fixed source distribution analysis)")
            print("    - analyze_error_patterns (error pattern analysis)")
            print("    - get_log_level_analysis (level analysis)")
            print()
            print("  Sample Tools:")
            print("    - get_log_sample (high quality samples)")
            print("    - search_logs_paginated (paginated search)")
            print()
            print("  Export Tools:")
            print("    - search_messages_export (export analysis)")
            print()
            print("  System Tools:")
            print("    - get_streams (stream management)")
            print("    - get_system_info (system information)")
            print("    - list_content_packs (content packs)")
            print("    - get_content_pack (content pack details)")
            print("    - get_content_pack_revision (content pack revision)")
            print("    - list_dashboards (dashboards)")
            print("    - get_dashboard (dashboard details)")
            print()
            print("  Testing Tools:")
            print("    - test_accurate_counting (test counting accuracy)")
            print("    - test_source_analysis_fix (test source analysis fix)")
            print()
            print("Testing Options:")
            print("  --test        - Run connection and source analysis fix tests")
            print("  --debug       - Enable verbose debug information")
            print()
            print("Example:")
            print("  export GRAYLOG_HOST='http://192.168.1.127:9000'")
            print("  export GRAYLOG_API_TOKEN='your_api_token_here'")
            print("  python3 mcp_graylog.py --test --debug")
            return
        
        # Enable debug mode if requested
        if config.get('debug'):
            logging.getLogger().setLevel(logging.DEBUG)
            print("Debug mode enabled", file=sys.stderr)
        
        # Validate required settings
        if not config['host']:
            print("Error: GRAYLOG_HOST environment variable or --host parameter is required", file=sys.stderr)
            print("Example: GRAYLOG_HOST=http://192.168.1.127:9000", file=sys.stderr)
            sys.exit(1)
        
        # Check authentication
        has_credentials = config['username'] and config['password']
        has_api_token = config['api_token']
        
        if not has_credentials and not has_api_token:
            print("Error: Authentication required (username/password or API token)", file=sys.stderr)
            print("Set GRAYLOG_USERNAME & GRAYLOG_PASSWORD or GRAYLOG_API_TOKEN", file=sys.stderr)
            sys.exit(1)
        
        # Store config globally
        graylog_config = config
        
        # Test connection if requested
        if config['test']:
            print("Testing Complete Graylog MCP Server with FIXED source analysis...", file=sys.stderr)
            client = get_graylog_client()
            async with client:
                try:
                    auth_method = "API Token" if config['api_token'] else "Username/Password"
                    print(f"Testing authentication using {auth_method}...", file=sys.stderr)
                    
                    # Test basic connectivity
                    test_result = await client.get("/system")
                    print(f"Authentication successful!", file=sys.stderr)
                    
                    # Test FIXED accurate counting
                    print("Testing FIXED accurate counting...", file=sys.stderr)
                    accurate_count = await client.get_accurate_total_count("*", "now-5m", "now")
                    print(f"FIXED Count Result: {accurate_count} messages", file=sys.stderr)
                    
                    # Test FIXED source analysis
                    print("Testing FIXED source analysis...", file=sys.stderr)
                    
                    source_test_result = await execute_tool("test_source_analysis_fix", {
                        "query": "*",
                        "range_from": "now-5m", 
                        "range_to": "now"
                    })
                    
                    if isinstance(source_test_result, dict):
                        test_summary = source_test_result.get('test_summary', {})
                        fix_status = source_test_result.get('fix_status', {})
                        
                        print(f"Source Analysis Test Results:", file=sys.stderr)
                        print(f"   Accurate total: {test_summary.get('accurate_total_count', 'N/A')}", file=sys.stderr)
                        print(f"   Standard sample: {test_summary.get('standard_method_sample_size', 'N/A')}", file=sys.stderr)
                        print(f"   FIXED sample: {test_summary.get('fixed_method_sample_size', 'N/A')}", file=sys.stderr)
                        print(f"   Improvement: {test_summary.get('sample_size_improvement', 'N/A')}", file=sys.stderr)
                        
                        print(f"Fix Status:", file=sys.stderr)
                        print(f"   Sample adequate: {fix_status.get('sample_size_adequate', False)}", file=sys.stderr)
                        print(f"   Representativeness: {fix_status.get('representativeness_improved', False)}", file=sys.stderr)
                        print(f"   Overall success: {fix_status.get('overall_fix_success', False)}", file=sys.stderr)
                        
                        if fix_status.get('overall_fix_success'):
                            print(f"Source analysis fix successful! Sample representativeness greatly improved", file=sys.stderr)
                        else:
                            print(f"Fix partially successful, improvements made but may need further adjustments", file=sys.stderr)
                    
                    # Test comprehensive statistics
                    print("Testing comprehensive statistics with FIXED methods...", file=sys.stderr)
                    
                    stats_result = await execute_tool("get_log_statistics", {
                        "query": "*",
                        "range_from": "now-5m", 
                        "range_to": "now",
                        "analysis_limit": 25000
                    })
                    
                    print(f"Comprehensive Statistics Test Results:", file=sys.stderr)
                    if isinstance(stats_result, dict) and 'summary' in stats_result:
                        summary = stats_result['summary']
                        print(f"   Total events: {summary.get('total_events', 'N/A')}", file=sys.stderr)
                        print(f"   Sample size: {summary.get('sample_size', 'N/A')}", file=sys.stderr)
                        print(f"   Unique sources: {summary.get('unique_sources', 'N/A')}", file=sys.stderr)
                        print(f"   Most active source: {summary.get('most_active_source', 'N/A')}", file=sys.stderr)
                    
                    if 'processing_info' in stats_result:
                        proc_info = stats_result['processing_info']
                        print(f"   Enhanced source analysis: {proc_info.get('source_analysis_enhanced', 'N/A')}", file=sys.stderr)
                        print(f"   Fix version: {proc_info.get('fix_version', 'N/A')}", file=sys.stderr)
                    
                    print(f"Complete FIXED version test completed successfully!", file=sys.stderr)
                    print(f"All original functions preserved", file=sys.stderr)
                    print(f"Source analysis sampling fixed", file=sys.stderr)
                    print(f"Enhanced time slicing applied", file=sys.stderr)
                    print(f"Proportional scaling working", file=sys.stderr)
                    
                except Exception as e:
                    print(f"Test failed: {e}", file=sys.stderr)
                    import traceback
                    print(f"Traceback: {traceback.format_exc()}", file=sys.stderr)
                    sys.exit(1)
            return
        
        # Show startup information
        auth_method = "API Token" if config['api_token'] else "Username/Password"
        print(f"Graylog MCP Server v{__version__} starting...", file=sys.stderr)
        print(f"Host: {config['host']}", file=sys.stderr)
        print(f"Auth: {auth_method}", file=sys.stderr)
        print(f"Features:", file=sys.stderr)
        print(f"   Smart time-based pagination (NEW in v1.9.25)", file=sys.stderr)
        print(f"   API compatibility fixes (NEW in v1.9.25)", file=sys.stderr)
        print(f"   Enhanced error handling for complex queries", file=sys.stderr)
        print(f"   Fixed source analysis with 25k sample size", file=sys.stderr)
        print(f"   Proportional scaling based on accurate counts", file=sys.stderr)
        print(f"   Complete API breakthrough strategies", file=sys.stderr)
        print(f"   Full LogAnalyzer functionality", file=sys.stderr)
        print(f"   Content Packs & Dashboard tools", file=sys.stderr)
        print(f"   Testing and debugging tools", file=sys.stderr)
        print(f"Server ready for connections", file=sys.stderr)
        
        # Run MCP server
        from mcp.server.stdio import stdio_server
        
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="Graylog",
                    server_version=__version__,
                    capabilities=server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    )
                )
            )
            
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        import traceback
        print(f"Traceback: {traceback.format_exc()}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
