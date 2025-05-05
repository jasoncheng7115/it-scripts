#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jt_log_analyzer.py - Log File Event Counter and Analyzer

This script analyzes log files to generate per-minute event statistics.
It efficiently processes large log files using chunk reading and optional keyword filtering.

Author: Jason Cheng
Email: jason@jason.tools
Company: Jason Tools
Created: January 1, 2025
Last Modified: May 5, 2025

Features:
- Counts events per minute from log files
- Optional keyword filtering
- Displays statistics in a readable format with text-based bar charts
- Exports results to CSV format
- Memory-efficient chunk reading for large files
- Progress tracking for large file processing

Usage:
    python jt_log_analyzer.py <log_file_path> [filter_keyword]

Example:
    python jt_log_analyzer.py server.log
    python jt_log_analyzer.py server.log "ERROR"
    python jt_log_analyzer.py /var/log/syslog "account"

Dependencies:
    - Python 3.6+
    - re (built-in)
    - csv (built-in)
    - sys (built-in)
    - datetime (built-in)
    - collections (built-in)

Output:
    - Terminal display with text-based bar charts
    - log_statistics.csv with Time,Count columns

Copyright (c) 2025 Jason Cheng / Jason Tools
All rights reserved.
"""

import re
import csv
import sys
from datetime import datetime
from collections import defaultdict

def parse_log_file(log_file_path, filter_keyword=None, chunk_size=10*1024*1024):  # 10MB chunk
    """Parse log file and count events per minute using chunk reading"""
    events_per_minute = defaultdict(int)
    
    # Pre-compile regex pattern
    timestamp_pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}):\d{2}')
    
    total_lines = 0
    filtered_lines = 0
    
    try:
        with open(log_file_path, 'r', encoding='utf-8', buffering=chunk_size) as file:
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
                    match = timestamp_pattern.search(line)
                    if match:
                        timestamp = match.group(1)
                        events_per_minute[timestamp] += 1
            
            # Process last partial line
            if partial_line:
                total_lines += 1
                if not filter_keyword or filter_keyword in partial_line:
                    filtered_lines += 1
                    match = timestamp_pattern.search(partial_line)
                    if match:
                        timestamp = match.group(1)
                        events_per_minute[timestamp] += 1
    
    except FileNotFoundError:
        print(f"Error: File not found '{log_file_path}'")
        sys.exit(1)
    except Exception as e:
        print(f"Error: Failed to read file: {e}")
        sys.exit(1)
    
    # Clear progress display line
    print(" " * 50, end='\r')
    
    return events_per_minute, total_lines, filtered_lines

def save_to_csv(events_dict, output_file):
    """Save statistics to CSV file using generator to save memory"""
    try:
        with open(output_file, 'w', newline='', encoding='utf-8-sig') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write header
            writer.writerow(['Time', 'Count'])
            
            # Use generator to avoid creating full sorted list
            for timestamp in sorted(events_dict.keys()):
                writer.writerow([timestamp, events_dict[timestamp]])
        
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

def display_statistics(events_dict, filter_keyword=None):
    """Display complete statistics on screen with text bar chart"""
    
    print("\n=== Events per Minute Statistics ===")
    if filter_keyword:
        print(f"Filter keyword: '{filter_keyword}'")
    print("-" * 80)
    print(f"{'Time':<20} | {'Count':<6} | Bar Chart")
    print("-" * 80)
    
    # Display all timestamps without skipping any records
    sorted_timestamps = sorted(events_dict.keys())
    
    # Find max value for bar chart scaling
    max_value = max(events_dict.values()) if events_dict else 0
    
    for timestamp in sorted_timestamps:
        count = events_dict[timestamp]
        bar = create_bar_chart(count, max_value)
        print(f"{timestamp:<20} | {count:<6} | {bar}")
    
    print("-" * 80)
    
    # Display summary information
    total_events = sum(events_dict.values())
    min_time = sorted_timestamps[0] if sorted_timestamps else "None"
    max_time = sorted_timestamps[-1] if sorted_timestamps else "None"
    
    print(f"Total events: {total_events:,}")
    print(f"Time range: {min_time} to {max_time}")
    print(f"Total minutes: {len(events_dict):,}")
    print(f"Max events per minute: {max_value:,}")
    print("-" * 80)

def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python log_analyzer.py <log_file_path> [filter_keyword]")
        print("\nBasic examples:")
        print("Example 1: python log_analyzer.py /path/to/file.log")
        print("Example 2: python log_analyzer.py ./server.log")
        print("Example 3: python log_analyzer.py /var/log/apache/access.log")
        
        print("\nError level filtering:")
        print("Example 4: python log_analyzer.py /path/file.log ERROR")
        print("Example 5: python log_analyzer.py /path/file.log WARNING")  
        print("Example 6: python log_analyzer.py /path/file.log CRITICAL")
        print("Example 7: python log_analyzer.py /path/file.log DEBUG")
        
        print("\nSpecific function filtering:")
        print("Example 8: python log_analyzer.py /path/file.log 'account'")
        print("Example 9: python log_analyzer.py /path/file.log 'login'")
        print("Example 10: python log_analyzer.py /path/file.log 'database'")
        print("Example 11: python log_analyzer.py /path/file.log '[Pop3SSLServer-'")
        
        print("\nError message filtering:")
        print("Example 12: python log_analyzer.py /path/file.log 'authentication failed'")
        print("Example 13: python log_analyzer.py /path/file.log 'connection timeout'")
        print("Example 14: python log_analyzer.py /path/file.log 'external LDAP auth failed'")
        print("Example 15: python log_analyzer.py /path/file.log 'unable to ldap authenticate'")
        
        print("\nComplete error message example:")
        print("Example 16: python log_analyzer.py /path/file.log 'external LDAP auth failed, LDAP error:  - unable to ldap authenticate: An error occurred while attempting to connect to server'")
        
        print("\nMixed filter examples:")
        print("Example 17: python log_analyzer.py /path/file.log 'ERROR.*account'")
        print("Example 18: python log_analyzer.py /path/file.log '\\[Pop3SSLServer-.*account'")
        
        print("\nFile path examples:")
        print("Example 19: python log_analyzer.py '/var/log/syslog'")
        print("Example 20: python log_analyzer.py '/home/user/logs/app.log' 'OutOfMemory'")
        print("Example 21: python log_analyzer.py '../logs/2025-04/server.log' 'session timeout'")
        
        print("\nNotes:")
        print("- If filter keyword contains spaces, enclose in quotes")
        print("- Can use regular expressions (must be enclosed in quotes)")
        print("- Output CSV file will be saved in current directory as log_statistics.csv")
        print("- Bar chart shows relative frequency of events, longer bars = more events")
        
        sys.exit(1)
    
    log_file = sys.argv[1]
    filter_keyword = sys.argv[2] if len(sys.argv) == 3 else None
    output_csv = "jt_log_statistics.csv"
    
    if filter_keyword:
        print(f"Analyzing file: {log_file} (Filter keyword: '{filter_keyword}')")
    else:
        print(f"Analyzing file: {log_file}")
    
    events_per_minute, total_lines, filtered_lines = parse_log_file(log_file, filter_keyword)
    
    print(f"\nTotal lines: {total_lines:,}")
    print(f"Filtered lines: {filtered_lines:,}")
    
    if events_per_minute:
        display_statistics(events_per_minute, filter_keyword)
        save_to_csv(events_per_minute, output_csv)
    else:
        print(f"\nNo matching events found")

if __name__ == "__main__":
    main()
