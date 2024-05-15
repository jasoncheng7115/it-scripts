#!/usr/bin/env python3
# pip install requests pytz csv time
# Jason@jason.tools
# www.jason.tools
# v1.0

import requests
import json
import csv
import pytz
import time
from datetime import datetime, timedelta

# Set whether to ignore system fields (Y/N)
IGNORE_SYSTEM_FIELDS = 'Y'

# Time range for data retrieval in days (e.g., 1 for 1 day, 7 for 7 days)
DATA_RETRIEVAL_TIME_RANGE_DAYS = 1

# Data retrieval interval in minutes
DATA_RETRIEVAL_INTERVAL_MINUTES = 15

# Graylog API Url
url = "http://127.0.0.1:9000/api/views/search/messages"
headers = {
    'X-Requested-By': 'JasonTools',
    'Content-Type': 'application/json'
}
auth = ('admin', 'yourpassword')  # Replace 'yourpassword' with the actual password

# Specify output format: "csv" or "json"
OUTPUT_FORMAT = "csv"  # Default to CSV output

# Set the output file name based on the specified format
if OUTPUT_FORMAT == "json":
    output_file_name = "/tmp/get_wdrop_iplist.json"
else:
    output_file_name = "/tmp/get_wdrop_iplist.csv"

query_string = "suricata_action:wDrop"

#fields_file_name = "/tmp/all_fields.json"
#with open(fields_file_name, "r") as file:
#    fields_to_query = json.load(file)
fields_to_query = ["suricata_srcip"]

# Track unique suricata_srcip values
seen_srcips = set()

end_time = datetime.utcnow()
start_time = end_time - timedelta(days=DATA_RETRIEVAL_TIME_RANGE_DAYS)
total_intervals = (end_time - start_time).total_seconds() / (DATA_RETRIEVAL_INTERVAL_MINUTES * 60)
current_start = start_time
interval_count = 0

all_data = []

while current_start < end_time:
    current_end = min(current_start + timedelta(minutes=DATA_RETRIEVAL_INTERVAL_MINUTES), end_time)
    date_from = current_start.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    date_to = current_end.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # Build request data
    data = {
        "streams": [],
        "query_string": {
            "type": "elasticsearch",
            "query_string": query_string
        },
        "timerange": {
            "type": "absolute",
            "from": date_from,
            "to": date_to
        },
        "fields_in_order": fields_to_query
    }

    response = requests.post(url, headers=headers, auth=auth, json=data)

    if response.status_code == 200:
        lines = response.text.splitlines()
        if len(lines) > 1:
            reader = csv.DictReader(lines)
            for row in reader:
                # Remove empty data fields and ignore system fields if specified
                if IGNORE_SYSTEM_FIELDS == 'Y':
                    row = {k: v for k, v in row.items() if v and not k.startswith('gl2_') and k != 'streams'}
                else:
                    row = {k: v for k, v in row.items() if v}
                
                # Check for unique suricata_srcip
                if row.get('suricata_srcip') not in seen_srcips:
                    seen_srcips.add(row.get('suricata_srcip'))
                    all_data.append(row)
            interval_count += 1
            progress_percent = (interval_count / total_intervals) * 100
            print(f"Processed time range: {date_from} to {date_to}, fetched {len(seen_srcips)} unique records. Progress: {progress_percent:.2f}%")
        else:
            print(f"Processed time range: {date_from} to {date_to}, no data fetched.")
    else:
        print("Error with status code:", response.status_code)
        print(response.text)

    current_start = current_end
    time.sleep(0.001)  # Pause for 1 millisecond

# Sort all data by suricata_srcip
all_data = sorted(all_data, key=lambda x: x['suricata_srcip'])

# Save sorted data to a file based on the specified format
with open(output_file_name, 'w', newline='') as file:
    if OUTPUT_FORMAT == "json":
        json.dump(all_data, file, indent=4)
        print(f"JSON file '{output_file_name}' has been created with unique and sorted data.")
    else:
        writer = csv.DictWriter(file, fieldnames=fields_to_query)
        writer.writeheader()
        writer.writerows(all_data)
        print(f"CSV file '{output_file_name}' has been created with unique and sorted data.")
