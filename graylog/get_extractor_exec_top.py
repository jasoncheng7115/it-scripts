#!/usr/bin/env python3

import requests
import json

# Graylog credentials and address
graylog_url = 'http://192.168.1.127:9000/api/'
username = 'admin'
password = 'password'
auth = (username, password)  # Authentication tuple

# Node ID
node_id = '0b63ce27-e340-4f38-bcd7-ddc91dc5b514'

def get_node_details():
    url = f"{graylog_url}cluster"
    response = requests.get(url, auth=auth)
    if response.status_code == 200:
        nodes = response.json()
        node_info = nodes.get(node_id, None)
        if node_info:
            return node_info.get('hostname', 'Unknown Node')
        else:
            return 'Unknown Node'
    else:
        return 'Unknown Node'

def get_input_details(input_id):
    url = f"{graylog_url}system/inputs/{input_id}"
    response = requests.get(url, auth=auth)
    if response.status_code == 200:
        input_details = response.json()
        return input_details.get('title', 'Unknown Input')
    else:
        return 'Unknown Input'

def get_all_inputs():
    """
    Fetch all inputs from the Graylog system inputs API.
    Returns a list of input IDs.
    """
    url = f"{graylog_url}system/inputs"
    response = requests.get(url, auth=auth)
    if response.status_code == 200:
        inputs_data = response.json()
        return [(input_detail['id'], input_detail['title']) for input_detail in inputs_data.get('inputs', [])]
    else:
        print(f"Error fetching inputs: {response.status_code} {response.text}")
        return []


def find_top_slowest_extractors_for_input(input_id, input_name):
    """
    Identifies and lists the top 15 slowest extractors for a given input,
    displaying their ID, title, and mean execution time.
    """
    url = f"{graylog_url}system/inputs/{input_id}/extractors"
    response = requests.get(url, auth=auth)
    if response.status_code == 200:
        extractors_data = response.json()['extractors']
        extractor_times = []

        for extractor in extractors_data:
            if 'metrics' in extractor and 'total' in extractor['metrics'] and 'time' in extractor['metrics']['total']:
                mean_time = extractor['metrics']['total']['time']['mean']
                duration_unit = extractor['metrics']['total']['duration_unit']
                if duration_unit == "milliseconds":
                    display_time = f"{mean_time:,.3f} ms"
                elif duration_unit == "seconds":
                    display_time = f"{mean_time:,.3f} s"
                elif duration_unit == "microseconds":
                    display_time = f"{mean_time:,.0f}μs"
                elif duration_unit == "nanoseconds":
                    display_time = f"{mean_time:,.0f} ns"
                else:
                    display_time = f"{mean_time} {duration_unit}"

                extractor_times.append((extractor['title'], extractor['id'], mean_time, display_time))

        top_slowest_extractors = sorted(extractor_times, key=lambda x: x[2], reverse=True)[:15]

        print(f"\nInput ID: {input_id} ({input_name}) - Top 15 slowest extractors:")
        for i, (title, ext_id, _, display) in enumerate(top_slowest_extractors, start=1):
            print(f"{i}. {title} (ID: {ext_id}) - Mean execution time: {display}")
    else:
        print(f"Error fetching extractors for input {input_id}: {response.status_code} {response.text}")

def find_top_slowest_extractors_for_all_inputs():
    """
    Fetches all inputs and finds the top 15 slowest extractors for each input.
    """
    inputs = get_all_inputs()
    for input_id, input_name in inputs:
        find_top_slowest_extractors_for_input(input_id, input_name)

# Run the script to find the slowest extractors for all inputs
find_top_slowest_extractors_for_all_inputs()