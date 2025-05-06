#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jt_log_analyzer.py - Log File Event Counter and Analyzer

This script analyzes log files to generate statistics by time intervals.
It efficiently processes large log files using chunk reading and optional keyword filtering.

Author: Jason Cheng
Email: jason@jason.tools
Company: Jason Tools
Created: January 1, 2025
Last Modified: May 6, 2025

Features:
- Counts events by time intervals from log files
- Optional keyword filtering
- Configurable time interval (1m, 10m, 15m, 30m, 45m, 60m, 1h, 2h, 12h, 24h)
- Displays statistics in a readable format with text-based bar charts
- Exports results to CSV format
- Memory-efficient chunk reading for large files
- Progress tracking for large file processing
- Auto-detection for multiple timestamp formats (added May 6, 2025)

Usage:
    python jt_log_analyzer.py <log_file_path> [filter_keyword] [-i interval]

Example:
    python jt_log_analyzer.py server.log
    python jt_log_analyzer.py server.log "ERROR"
    python jt_log_analyzer.py server.log -i 15m
    python jt_log_analyzer.py server.log -i 2h
    python jt_log_analyzer.py /var/log/syslog "account" -i 24h

Dependencies:
    - Python 3.6+
    - re (built-in)
    - csv (built-in)
    - sys (built-in)
    - datetime (built-in)
    - collections (built-in)

Output:
    - Terminal display with text-based bar charts
    - jt_log_statistics.csv with Time,Count columns

Copyright (c) 2025 Jason Cheng / Jason Tools
All rights reserved.
"""

import re
import csv
import sys
from datetime import datetime, timedelta
from collections import defaultdict

def parse_interval_string(interval_str):
    """Parse interval string like '15m' or '2h' into value and unit"""
    match = re.match(r'^(\d+)([mh])$', interval_str.lower())
    if not match:
        raise ValueError(f"Invalid interval format: {interval_str}")
    
    value = int(match.group(1))
    unit = match.group(2)
    
    # Validate intervals
    if unit == 'm':
        if value not in [1, 10, 15, 30, 45, 60]:
            raise ValueError(f"Minutes interval must be one of: 1, 10, 15, 30, 45, 60")
        return value, 'minutes'
    else:  # 'h'
        if value not in [1, 2, 12, 24]:
            raise ValueError(f"Hours interval must be one of: 1, 2, 12, 24")
        return value, 'hours'

def round_to_interval(dt, interval_value, interval_unit):
    """Round datetime to nearest interval"""
    if interval_unit == 'minutes':
        minutes = interval_value * (dt.minute // interval_value)
        return dt.replace(minute=minutes, second=0, microsecond=0)
    else:  # hours
        hours = interval_value * (dt.hour // interval_value)
        return dt.replace(hour=hours, minute=0, second=0, microsecond=0)

def get_time_format(interval_unit):
    """Get appropriate time format based on interval unit"""
    if interval_unit == 'minutes':
        return '%Y-%m-%d %H:%M'
    else:  # hours
        return '%Y-%m-%d %H:00'

def detect_timestamp_format(first_chunk):
    """
    Detect timestamp format from first chunk of the log file
    Returns the most likely regex pattern to use for timestamp extraction
    """
    # Define different timestamp patterns to check
    patterns = [
        # Standard format: 2025-04-26 08:21:55
        (r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}):\d{2}', '%Y-%m-%d %H:%M'),
        
        # Syslog format: May 6 21:44:57
        (r'([A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}):\d{2}', '%b %d %H:%M'),
        
        # Another common format: 26/Apr/2025:08:21:55
        (r'(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}):\d{2}', '%d/%b/%Y:%H:%M'),
        
        # ISO format: 2025-04-26T08:21:55
        (r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}):\d{2}', '%Y-%m-%dT%H:%M'),
    ]
    
    # Sample some lines from the first chunk
    lines = first_chunk.split('\n')[:100]  # Check first 100 lines or less
    
    # Count matches for each pattern
    pattern_counts = {i: 0 for i in range(len(patterns))}
    
    for line in lines:
        for i, (pattern, _) in enumerate(patterns):
            if re.search(pattern, line):
                pattern_counts[i] += 1
    
    # Find the pattern with the most matches
    if not pattern_counts:
        # Default to standard format if no matches
        return patterns[0]
    
    best_pattern_idx = max(pattern_counts, key=pattern_counts.get)
    return patterns[best_pattern_idx]

def parse_timestamp(timestamp_str, timestamp_format, current_year=None):
    """
    Parse timestamp string using the given format
    For formats without year, use the current_year parameter
    """
    try:
        # For formats with complete date information
        if '%Y' in timestamp_format:
            return datetime.strptime(timestamp_str, timestamp_format)
        else:
            # For formats without year (like syslog)
            if current_year is None:
                current_year = datetime.now().year
            
            # Parse the timestamp without year
            dt = datetime.strptime(timestamp_str, timestamp_format)
            
            # Add the current year
            dt = dt.replace(year=current_year)
            
            # If the resulting date is in the future, use previous year
            # This handles logs from December being processed in January
            if dt > datetime.now() + timedelta(days=1):  # Allow 1 day difference for timezone issues
                dt = dt.replace(year=current_year - 1)
                
            return dt
    except ValueError as e:
        print(f"Warning: Failed to parse timestamp '{timestamp_str}' with format '{timestamp_format}': {e}")
        return None

def parse_log_file(log_file_path, filter_keyword=None, interval_value=1, interval_unit='minutes', chunk_size=10*1024*1024):
    """Parse log file and count events per time interval using chunk reading"""
    events_per_interval = defaultdict(int)
    
    # Variables for timestamp format detection
    timestamp_pattern = None
    timestamp_format = None
    current_year = datetime.now().year
    
    total_lines = 0
    filtered_lines = 0
    unparseable_lines = 0
    
    try:
        with open(log_file_path, 'r', encoding='utf-8', buffering=chunk_size) as file:
            # Read first chunk for format detection
            first_chunk = file.read(min(chunk_size, 10*1024))  # Read up to 10KB for detection
            
            # Detect timestamp format from first chunk
            timestamp_pattern, timestamp_format = detect_timestamp_format(first_chunk)
            print(f"Detected timestamp format: {timestamp_format}")
            
            # Recompile regex pattern based on detection
            timestamp_regex = re.compile(timestamp_pattern)
            
            # Go back to beginning of file
            file.seek(0)
            
            # Read remaining partial line from previous chunk
            partial_line = ''
            
            while True:
                # Read one chunk
                chunk = file.read(chunk_size)
                
                if not chunk:
                    break
                
                # Combine previous partial line with current chunk
                chunk = partial_line + chunk
                
                # Find last newline position
                last_newline = chunk.rfind('\n')
                
                # If newline found, process up to that position
                if last_newline >= 0:
                    to_process = chunk[:last_newline + 1]
                    partial_line = chunk[last_newline + 1:]
                else:
                    # If no newline found, the entire chunk is part of a single line
                    to_process = chunk
                    partial_line = ''
                
                # Process lines in chunk
                lines = to_process.split('\n')
                
                for line in lines:
                    if not line:  # Empty line
                        continue
                    
                    total_lines += 1
                    
                    # Progress display
                    if total_lines % 1000000 == 0:
                        print(f"Processed {total_lines:,} lines...", end='\r')
                    
                    # Filter
                    if filter_keyword and filter_keyword not in line:
                        continue
                    
                    filtered_lines += 1
                    
                    # Search for timestamp
                    match = timestamp_regex.search(line)
                    if match:
                        timestamp_str = match.group(1)
                        dt = parse_timestamp(timestamp_str, timestamp_format, current_year)
                        
                        if dt:
                            rounded_dt = round_to_interval(dt, interval_value, interval_unit)
                            interval_timestamp = rounded_dt.strftime(get_time_format(interval_unit))
                            events_per_interval[interval_timestamp] += 1
                        else:
                            unparseable_lines += 1
                    else:
                        unparseable_lines += 1
            
            # Process last partial line
            if partial_line:
                total_lines += 1
                if not filter_keyword or filter_keyword in partial_line:
                    filtered_lines += 1
                    match = timestamp_regex.search(partial_line)
                    if match:
                        timestamp_str = match.group(1)
                        dt = parse_timestamp(timestamp_str, timestamp_format, current_year)
                        
                        if dt:
                            rounded_dt = round_to_interval(dt, interval_value, interval_unit)
                            interval_timestamp = rounded_dt.strftime(get_time_format(interval_unit))
                            events_per_interval[interval_timestamp] += 1
                        else:
                            unparseable_lines += 1
                    else:
                        unparseable_lines += 1
    
    except FileNotFoundError:
        print(f"Error: File not found '{log_file_path}'")
        sys.exit(1)
    except Exception as e:
        print(f"Error: Failed to read file: {e}")
        sys.exit(1)
    
    # Clear progress display line
    print(" " * 50, end='\r')
    
    # Print parsing statistics
    if unparseable_lines > 0:
        print(f"Warning: {unparseable_lines:,} lines had no parseable timestamp")
    
    return events_per_interval, total_lines, filtered_lines

def save_to_csv(events_dict, output_file, interval_value=1, interval_unit='minutes'):
    """Save statistics to CSV file using generator to save memory"""
    try:
        with open(output_file, 'w', newline='', encoding='utf-8-sig') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write header
            writer.writerow(['Time', 'Count'])
            
            # Get all timestamps and find time range
            sorted_timestamps = sorted(events_dict.keys())
            
            if sorted_timestamps:
                # Get first and last interval
                time_format = get_time_format(interval_unit)
                min_time = datetime.strptime(sorted_timestamps[0], time_format)
                max_time = datetime.strptime(sorted_timestamps[-1], time_format)
                
                # Generate all intervals in the range
                current_time = min_time
                while current_time <= max_time:
                    timestamp = current_time.strftime(time_format)
                    count = events_dict.get(timestamp, 0)
                    writer.writerow([timestamp, count])
                    
                    if interval_unit == 'minutes':
                        current_time += timedelta(minutes=interval_value)
                    else:  # hours
                        current_time += timedelta(hours=interval_value)
            
        print(f"\nStatistics saved to: {output_file}")
        print()  # 加入空行
        
    except Exception as e:
        print(f"Error: Failed to write CSV file: {e}")
        sys.exit(1)

def create_bar_chart(value, max_value, max_width=50):
    """Create text-based bar chart using blocks"""
    if max_value == 0:
        return ""
    
    # Calculate bar width
    bar_width = int((value / max_value) * max_width)
    
    # Create bar using Unicode blocks
    bar = "█" * bar_width
    
    return bar

def display_statistics(events_dict, filter_keyword=None, interval_value=1, interval_unit='minutes'):
    """Display complete statistics on screen with text bar chart"""
    
    interval_desc = f"{interval_value} {interval_unit.capitalize()}" if interval_value > 1 else interval_unit.capitalize()
    print(f"\n=== Events per {interval_desc} Statistics ===")
    if filter_keyword:
        print(f"Filter keyword: '{filter_keyword}'")
    print("-" * 80)
    print(f"{'Time':<20} | {'Count':<6} | Bar Chart")
    print("-" * 80)
    
    # Get all timestamps and find time range
    sorted_timestamps = sorted(events_dict.keys())
    
    if sorted_timestamps:
        # Get first and last interval
        time_format = get_time_format(interval_unit)
        min_time = datetime.strptime(sorted_timestamps[0], time_format)
        max_time = datetime.strptime(sorted_timestamps[-1], time_format)
        
        # Generate all intervals in the range
        all_intervals = []
        current_time = min_time
        while current_time <= max_time:
            all_intervals.append(current_time.strftime(time_format))
            
            if interval_unit == 'minutes':
                current_time += timedelta(minutes=interval_value)
            else:  # hours
                current_time += timedelta(hours=interval_value)
        
        # Find max value for bar chart scaling
        max_value = max(events_dict.values()) if events_dict else 1
        
        # Display all intervals including those with 0 events
        for timestamp in all_intervals:
            count = events_dict.get(timestamp, 0)
            bar = create_bar_chart(count, max_value)
            print(f"{timestamp:<20} | {count:<6} | {bar}")
        
        print("-" * 80)
        
        # Display summary information
        total_events = sum(events_dict.values())
        
        print(f"Total events: {total_events:,}")
        print(f"Time range: {sorted_timestamps[0]} to {sorted_timestamps[-1]}")
        print(f"Total intervals: {len(all_intervals):,}")
        print(f"Intervals with events: {len(events_dict):,}")
        print(f"Max events per interval: {max_value:,}")
        print("-" * 80)
    else:
        print("No data to display")
        print("-" * 80)

def main():
    # Parse command line arguments
    log_file = None
    filter_keyword = None
    interval_value = 1
    interval_unit = 'minutes'
    
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == '-i':
            if i + 1 < len(sys.argv):
                try:
                    interval_value, interval_unit = parse_interval_string(sys.argv[i + 1])
                    i += 2
                except ValueError as e:
                    print(f"Error: {e}")
                    sys.exit(1)
            else:
                print("Error: -i requires an interval value")
                sys.exit(1)
        elif log_file is None:
            log_file = sys.argv[i]
            i += 1
        elif filter_keyword is None:
            filter_keyword = sys.argv[i]
            i += 1
        else:
            i += 1
    
    if log_file is None:
        print("Usage: python jt_log_analyzer.py <log_file_path> [filter_keyword] [-i interval]")
        print("\nBasic examples:")
        print("Example 1: python jt_log_analyzer.py /path/to/file.log")
        print("Example 2: python jt_log_analyzer.py ./server.log")
        print("Example 3: python jt_log_analyzer.py /var/log/apache/access.log")
        
        print("\nWith interval options:")
        print("Example 4: python jt_log_analyzer.py /path/file.log -i 1m")
        print("Example 5: python jt_log_analyzer.py /path/file.log -i 15m")
        print("Example 6: python jt_log_analyzer.py /path/file.log -i 30m")
        print("Example 7: python jt_log_analyzer.py /path/file.log -i 1h")
        print("Example 8: python jt_log_analyzer.py /path/file.log -i 2h")
        print("Example 9: python jt_log_analyzer.py /path/file.log -i 12h")
        print("Example 10: python jt_log_analyzer.py /path/file.log -i 24h")
        
        print("\nAvailable intervals:")
        print("Minutes: 1m, 10m, 15m, 30m, 45m, 60m")
        print("Hours: 1h, 2h, 12h, 24h")
        
        print("\nCombined examples:")
        print("Example 11: python jt_log_analyzer.py /path/file.log ERROR -i 30m")
        print("Example 12: python jt_log_analyzer.py /path/file.log 'account' -i 24h")
        
        print("\nSupported timestamp formats:")
        print("- YYYY-MM-DD HH:MM:SS (e.g., 2025-04-26 08:21:55)")
        print("- MMM D HH:MM:SS (e.g., May 6 21:44:57) - Syslog format")
        print("- DD/MMM/YYYY:HH:MM:SS (e.g., 26/Apr/2025:08:21:55)")
        print("- YYYY-MM-DDTHH:MM:SS (e.g., 2025-04-26T08:21:55) - ISO format")
        
        print("\nNotes:")
        print("- Default interval is 1 minute (1m)")
        print("- If filter keyword contains spaces, enclose in quotes")
        print("- Output CSV file will be saved in current directory as jt_log_statistics.csv")
        print("- Bar chart shows relative frequency of events, longer bars = more events")
        print("- Timestamp format is auto-detected from the log file")
        
        sys.exit(1)
    
    output_csv = "jt_log_statistics.csv"
    
    # Create interval display string
    interval_str = f"{interval_value}{'m' if interval_unit == 'minutes' else 'h'}"
    
    if filter_keyword:
        print(f"Analyzing file: {log_file} (Filter keyword: '{filter_keyword}') [Interval: {interval_str}]")
    else:
        print(f"Analyzing file: {log_file} [Interval: {interval_str}]")
    
    events_per_interval, total_lines, filtered_lines = parse_log_file(log_file, filter_keyword, interval_value, interval_unit)
    
    print(f"\nTotal lines: {total_lines:,}")
    print(f"Filtered lines: {filtered_lines:,}")
    
    if events_per_interval:
        display_statistics(events_per_interval, filter_keyword, interval_value, interval_unit)
        save_to_csv(events_per_interval, output_csv, interval_value, interval_unit)
    else:
        print(f"\nNo matching events found")

if __name__ == "__main__":
    main()
