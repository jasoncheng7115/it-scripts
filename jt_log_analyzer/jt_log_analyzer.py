#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jt_log_analyzer.py - Log File Event Counter and Analyzer

Version - 1.2

This script analyzes log files to generate statistics by time intervals.
It efficiently processes large log files using chunk reading and optional keyword filtering.
Now supports real-time monitoring with the -r parameter.

Author: Jason Cheng
Email: jason@jason.tools
Company: Jason Tools
Created: January 1, 2025
Last Modified: May 7, 2025

Features:
- Counts events by time intervals from log files
- Optional keyword filtering
- Configurable time interval (1m, 10m, 15m, 30m, 45m, 60m, 1h, 2h, 12h, 24h)
- Displays statistics in a readable format with text-based bar charts
- Exports results to CSV format
- Memory-efficient chunk reading for large files
- Progress tracking for large file processing
- Auto-detection for multiple timestamp formats (added May 6, 2025)
- Real-time monitoring with continuous updates (added May 7, 2025)

Usage:
    ./jt_log_analyzer.py <log_file_path> [filter_keyword] [-i interval] [-r]

Example:
    ./jt_log_analyzer.py server.log
    ./jt_log_analyzer.py server.log "ERROR"
    ./jt_log_analyzer.py server.log -i 15m
    ./jt_log_analyzer.py server.log -i 2h -r
    ./jt_log_analyzer.py /var/log/syslog "account" -i 24h -r

Dependencies:
    - Python 3.6+
    - re (built-in)
    - csv (built-in)
    - sys (built-in)
    - datetime (built-in)
    - collections (built-in)
    - time (built-in)
    - os (built-in)
    - signal (built-in, added for real-time monitoring)

Output:
    - Terminal display with text-based bar charts
    - jt_log_statistics.csv with Time,Count columns

Copyright (c) 2025 Jason Cheng / Jason Tools
All rights reserved.
"""

import re
import csv
import sys
import os
import time
import signal
from datetime import datetime, timedelta
from collections import defaultdict

# Global variables for real-time monitoring
monitoring = False
should_exit = False
timestamp_regex = None
timestamp_format = None
in_realtime_display = False

def signal_handler(sig, frame):
    """Handle Ctrl+C to gracefully exit real-time monitoring"""
    global should_exit
    print("\n\nExiting real-time monitoring. Processing final statistics...")
    should_exit = True

# ANSI terminal control functions
def position_cursor(x=0, y=0):
    """Move cursor to specified position instead of clearing entire screen"""
    # ANSI escape sequence: ESC[{y};{x}H
    print(f"\033[{y};{x}H", end="")

def save_cursor_position():
    """Save current cursor position"""
    print("\033[s", end="")

def restore_cursor_position():
    """Restore previously saved cursor position"""
    print("\033[u", end="")

def clear_line():
    """Clear current line"""
    print("\033[2K", end="")

def clear_to_end():
    """Clear from cursor position to the bottom of screen"""
    print("\033[J", end="")

def init_display():
    """Initialize display area (executed only once at start)"""
    # Clear screen once
    print("\033[2J", end="")
    # Move cursor to top-left corner
    position_cursor(0, 0)
    print("Initializing real-time monitoring...\n")
    print("Processing initial data, please wait...\n")
    # Force flush output buffer
    sys.stdout.flush()

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
        if not monitoring or not in_realtime_display:
            print(f"Warning: Failed to parse timestamp '{timestamp_str}' with format '{timestamp_format}': {e}")
        return None

def parse_log_file(log_file_path, filter_keyword=None, interval_value=1, interval_unit='minutes', 
                   chunk_size=10*1024*1024, start_position=0, real_time=False):
    """Parse log file and count events per time interval using chunk reading"""
    global timestamp_regex, timestamp_format, in_realtime_display
    
    events_per_interval = defaultdict(int)
    
    # Variables for timestamp format detection
    current_year = datetime.now().year
    
    total_lines = 0
    filtered_lines = 0
    unparseable_lines = 0
    has_new_data = False
    detected_format = None
    
    try:
        with open(log_file_path, 'r', encoding='utf-8', buffering=chunk_size) as file:
            # If resuming from a position, seek to that position
            if start_position > 0:
                file.seek(start_position)
            else:
                # Read first chunk for format detection
                first_chunk = file.read(min(chunk_size, 10*1024))  # Read up to 10KB for detection
                
                # Detect timestamp format from first chunk
                timestamp_pattern, timestamp_format = detect_timestamp_format(first_chunk)
                timestamp_regex = re.compile(timestamp_pattern)
                detected_format = timestamp_format
                
                # Only show format detection message if not in real-time display mode
                if not in_realtime_display and not real_time:
                    print(f"Detected timestamp format: {timestamp_format}")
                
                # Go back to beginning of file
                file.seek(0)
            
            # Read remaining partial line from previous chunk
            partial_line = ''
            file_at_end = False
            
            while not file_at_end and not should_exit:
                # Read one chunk
                chunk = file.read(chunk_size)
                
                if not chunk:
                    file_at_end = True
                    if not real_time:
                        break
                    # Don't immediately break in real-time mode
                    # We might process partial_line and return
                
                # Combine previous partial line with current chunk
                if chunk:
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
                        has_new_data = True
                        
                        # Progress display
                        if not real_time and total_lines % 1000000 == 0:
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
                
                # Process last partial line if we're at the end and not in real-time mode
                if file_at_end and not real_time and partial_line:
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
                
                # In real-time mode, after processing the entire file once, break to show statistics
                if file_at_end and real_time and start_position == 0:
                    break
                
                # If in real-time mode and we've reached the end, wait and then continue
                if file_at_end and real_time:
                    time.sleep(1)  # Wait before checking for new data
                    file_at_end = False
    
    except FileNotFoundError:
        print(f"Error: File not found '{log_file_path}'")
        sys.exit(1)
    except Exception as e:
        print(f"Error: Failed to read file: {e}")
        sys.exit(1)
    
    # Clear progress display line
    if not real_time:
        print(" " * 50, end='\r')
    
    # Print parsing statistics
    if not real_time and unparseable_lines > 0:
        print(f"Warning: {unparseable_lines:,} lines had no parseable timestamp")
    
    # Return the current file position for real-time monitoring
    if real_time:
        try:
            current_position = file.tell()
        except:
            current_position = 0
        return events_per_interval, total_lines, filtered_lines, current_position, unparseable_lines, has_new_data, detected_format
    
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
        print()  # Add a blank line
        
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

def update_statistics_display(events_dict, filter_keyword, interval_value, interval_unit, 
                              total_lines, filtered_lines, unparseable_lines, timestamp_format):
    """Update statistics display using cursor control instead of clearing entire screen"""
    global in_realtime_display
    
    # Set flag to prevent unwanted output during display update
    in_realtime_display = True
    
    print("\033[2J", end="")  
    print("\033[3J", end="")  
    print("\033[H", end="")   
    
    # Show title information including detected timestamp format
    interval_desc = f"{interval_value} {interval_unit.capitalize()}" if interval_value > 1 else interval_unit.capitalize()
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"=== Real-time Monitoring: Events per {interval_desc} === {current_time} ===")
    print(f"Format: {timestamp_format} | Total lines: {total_lines:,} | ", end="")
    
    if filter_keyword:
        print(f"Filter: '{filter_keyword}' | Matching: {filtered_lines:,}")
    else:
        print(f"Matching lines: {filtered_lines:,}")
    
    if unparseable_lines > 0:
        print(f"Lines with unparseable timestamps: {unparseable_lines:,}")
    
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
            
        # Clear remaining old lines (if any)
        clear_to_end()
        
        print("-" * 80)
        
        # Display summary information
        total_events = sum(events_dict.values())
        print(f"Total events: {total_events:,}")
        print(f"Time range: {sorted_timestamps[0]} to {sorted_timestamps[-1]}")
        print(f"Total intervals: {len(all_intervals):,}")
        print(f"Intervals with events: {len(events_dict):,}")
        print(f"Max events per interval: {max_value:,}")
        print("-" * 80)
        print("Press Ctrl+C to exit monitoring")
    else:
        print("No data to display yet")
        print("-" * 80)
        print("Press Ctrl+C to exit monitoring")
    
    # Force flush output buffer
    sys.stdout.flush()
    
    # Reset flag after display update
    in_realtime_display = False

def monitor_file_in_real_time(log_file_path, filter_keyword=None, interval_value=1, interval_unit='minutes'):
    """Monitor log file in real-time using improved terminal display"""
    global monitoring, should_exit, in_realtime_display
    
    monitoring = True
    should_exit = False
    in_realtime_display = False
    
    # Set up signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    # Initialize display
    init_display()
    
    print(f"Starting real-time monitoring of: {log_file_path}...")
    if filter_keyword:
        print(f"Filter keyword: '{filter_keyword}'")
    print(f"Time interval: {interval_value} {interval_unit}")
    print("Loading initial data...")
    print("Press Ctrl+C to exit monitoring")
    sys.stdout.flush()
    
    # Initial file position
    file_position = 0
    
    # Initial run to get started
    events_dict, total_lines, filtered_lines, file_position, unparseable_lines, has_new_data, detected_format = parse_log_file(
        log_file_path, filter_keyword, interval_value, interval_unit, 
        start_position=file_position, real_time=True
    )
    
    # First display of statistics - even if there's no data
    update_statistics_display(events_dict, filter_keyword, interval_value, interval_unit,
                            total_lines, filtered_lines, unparseable_lines, detected_format)
    
    # Polling interval (seconds)
    poll_interval = 1.0
    
    # Continue monitoring until user interrupts
    try:
        while not should_exit:
            # Wait before polling again to reduce CPU usage
            time.sleep(poll_interval)
            
            # Parse any new data added to the file
            new_events_dict, new_total, new_filtered, file_position, new_unparseable, has_new_data, detected_format = parse_log_file(
                log_file_path, filter_keyword, interval_value, interval_unit,
                start_position=file_position, real_time=True
            )
            
            # Check if there's new data, update display if there is
            if has_new_data:
                total_lines = new_total
                filtered_lines = new_filtered
                unparseable_lines += new_unparseable
                
                # New event stats are merged automatically in parse_log_file
                events_dict = new_events_dict
                
                # Update display
                update_statistics_display(events_dict, filter_keyword, interval_value, interval_unit,
                                        total_lines, filtered_lines, unparseable_lines, detected_format)
    
    except KeyboardInterrupt:
        # This should be caught by the signal handler, but just in case
        print("\nMonitoring interrupted.")
    
    # Final statistics and save to CSV
    print("\nGenerating final statistics...")
    if events_dict:
        # Use the standard display function, not the real-time version
        display_statistics(events_dict, filter_keyword, interval_value, interval_unit)
        save_to_csv(events_dict, "jt_log_statistics.csv", interval_value, interval_unit)
    else:
        print("No events found during monitoring.")
    
    monitoring = False
    should_exit = False
    in_realtime_display = False

def main():
    # Parse command line arguments
    log_file = None
    filter_keyword = None
    interval_value = 1
    interval_unit = 'minutes'
    real_time_mode = False
    
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
        elif sys.argv[i] == '-r':
            real_time_mode = True
            i += 1
        elif log_file is None:
            log_file = sys.argv[i]
            i += 1
        elif filter_keyword is None:
            filter_keyword = sys.argv[i]
            i += 1
        else:
            i += 1
    
    if log_file is None:
        print("Usage: ./jt_log_analyzer.py <log_file_path> [filter_keyword] [-i interval] [-r]")
        print("\nBasic examples:")
        print("Example 1: ./jt_log_analyzer.py /path/to/file.log")
        print("Example 2: ./jt_log_analyzer.py ./server.log")
        print("Example 3: ./jt_log_analyzer.py /var/log/apache/access.log")
        
        print("\nWith interval options:")
        print("Example 4: ./jt_log_analyzer.py /path/file.log -i 1m")
        print("Example 5: ./jt_log_analyzer.py /path/file.log -i 15m")
        print("Example 6: ./jt_log_analyzer.py /path/file.log -i 30m")
        print("Example 7: ./jt_log_analyzer.py /path/file.log -i 1h")
        print("Example 8: ./jt_log_analyzer.py /path/file.log -i 2h")
        print("Example 9: ./jt_log_analyzer.py /path/file.log -i 12h")
        print("Example 10: ./jt_log_analyzer.py /path/file.log -i 24h")
        
        print("\nReal-time monitoring:")
        print("Example 11: ./jt_log_analyzer.py /path/file.log -r")
        print("Example 12: ./jt_log_analyzer.py /path/file.log ERROR -i 30m -r")
        print("Example 13: ./jt_log_analyzer.py /var/log/syslog -i 10m -r")
        
        print("\nAvailable intervals:")
        print("Minutes: 1m, 10m, 15m, 30m, 45m, 60m")
        print("Hours: 1h, 2h, 12h, 24h")
        
        print("\nCombined examples:")
        print("Example 14: ./jt_log_analyzer.py /path/file.log ERROR -i 30m")
        print("Example 15: ./jt_log_analyzer.py /path/file.log 'account' -i 24h")
        print("Example 16: ./jt_log_analyzer.py /var/log/nginx/access.log '404' -i 5m -r")
        
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
        print("- Real-time mode (-r) continuously monitors the file and updates statistics")
        print("- Press Ctrl+C to exit real-time monitoring")
        
        sys.exit(1)
    
    output_csv = "jt_log_statistics.csv"
    
    # Create interval display string
    interval_str = f"{interval_value}{'m' if interval_unit == 'minutes' else 'h'}"
    
    if real_time_mode:
        if filter_keyword:
            print(f"Analyzing file in real-time: {log_file} (Filter keyword: '{filter_keyword}') [Interval: {interval_str}]")
        else:
            print(f"Analyzing file in real-time: {log_file} [Interval: {interval_str}]")
            
        monitor_file_in_real_time(log_file, filter_keyword, interval_value, interval_unit)
    else:
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
