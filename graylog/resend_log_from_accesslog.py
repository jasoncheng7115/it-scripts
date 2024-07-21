#!/usr/bin/python3
# This line specifies the path of the Python interpreter to use when executing the script

"""
This script reads web server access logs and sends them formatted as GELF via UDP to a Graylog server.
"""

import re
import json
import socket
from datetime import datetime

# Configuration settings
graylog_server = '192.168.1.83'
graylog_port = 12201
log_source = "webserver-logs"  # Static value representing the log source
log_file_path = '/var/log/apache2/access.log'
debug = 'N'  # Set to 'Y' to enable debug mode

# Regular expression pattern for Apache/Nginx log format
log_pattern = re.compile(r'(?P<source_ip>\S+) - (?P<user>\S+) \[(?P<timestamp>[^\]]+)\] "(?P<http_method>\w+) (?P<request_uri>[^\s]+) (?P<http_protocol>HTTP/\d\.\d)" (?P<http_status>\d+) (?P<response_size>\d+) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"')

# Setup UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Function to convert log datetime to timestamp
def get_timestamp(log_datetime):
    dt_format = '%d/%b/%Y:%H:%M:%S %z'
    dt = datetime.strptime(log_datetime, dt_format)
    return dt.timestamp()

# Process the log file
line_counter = 0
with open(log_file_path, 'r') as file:
    for line in file:
        match = log_pattern.match(line)
        if match:
            data = match.groupdict()
            data['timestamp'] = get_timestamp(data['timestamp'])  # Convert to UNIX timestamp
            gelf_message = {
                "version": "1.1",
                "host": log_source,
                "short_message": f"{data['http_method']} request to {data['request_uri']} returned {data['http_status']}",
                "timestamp": data['timestamp'],
                "_source_ip": data['source_ip'],
                "_user": data['user'],
                "_http_method": data['http_method'],
                "_http_protocol": data['http_protocol'],
                "_request_uri": data['request_uri'],
                "_http_status": data['http_status'],
                "_response_size": data['response_size'],
                "_referrer": data['referrer'],
                "_user_agent": data['user_agent']
            }
            message_json = json.dumps(gelf_message)
            sock.sendto(message_json.encode('utf-8'), (graylog_server, graylog_port))
            if debug == 'Y':
                print(f"Debug: {message_json}")
        line_counter += 1
        if line_counter % 100 == 0:
            print(f"{line_counter} lines processed.")

sock.close()
print(f"Total lines processed: {line_counter}")
