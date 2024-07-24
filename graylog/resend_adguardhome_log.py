#!/usr/local/bin/python3
"""
This script includes functionality to monitor a log file and rotate it when it exceeds a certain size.
It also starts a TCP server to accept connections for live monitoring and requires the client to authenticate with a password.
Installation requirements:
    python3 -m ensurepip
    python3 -m pip install watchdog
    python3 -m pip install python-dateutil

Author: Jason Tools (www.jason.tools) - Jason Cheng (jason@jason.tools)
"""
import json
import socket
import time
import threading
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import yaml
from dateutil import parser
import os

def iso_to_unix_timestamp(iso_str):
    dt = parser.parse(iso_str)
    return dt.timestamp()

def load_filterlist_names(config_path):
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
        return {item['id']: item['name'] for item in config['filters'] if item.get('enabled', False)}

def tcp_server(host, port, password):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"TCP Server listening on {host}:{port}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr}")
        data = client_socket.recv(1024).decode().strip()
        if data == password:
            client_socket.sendall("OK".encode())
        else:
            client_socket.sendall("Unauthorized".encode())
        client_socket.close()

class LogHandler(FileSystemEventHandler):
    def __init__(self, file_path, graylog_host, graylog_port, config_path, last_position_file, max_file_size_mb):
        self.file_path = file_path
        self.graylog_host = graylog_host
        self.graylog_port = graylog_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.hostname = socket.gethostname()
        self.filterlist_names = load_filterlist_names(config_path)
        self.last_position_file = last_position_file
        self.last_position = self.load_last_position()
        self.max_file_size_mb = max_file_size_mb
        print(f"Initialized for {file_path}, sending to {graylog_host}:{graylog_port}")
        self.read_and_send_logs()  # Read and send logs upon initialization

    def load_last_position(self):
        if os.path.exists(self.last_position_file):
            with open(self.last_position_file, 'r') as file:
                position = file.read()
                return int(position) if position.isdigit() else 0
        return 0

    def save_last_position(self):
        with open(self.last_position_file, 'w') as file:
            file.write(str(self.last_position))

    def on_created(self, event):
        if not event.is_directory and event.src_path == self.file_path:
            self.last_position = 0
            self.save_last_position()
            self.read_and_send_logs()

    def on_modified(self, event):
        if not event.is_directory and event.src_path == self.file_path:
            self.read_and_send_logs()

    def read_and_send_logs(self):
        if os.path.exists(self.file_path):
            with open(self.file_path, 'r') as f:
                f.seek(self.last_position)
                logs = f.readlines()
                self.last_position = f.tell()
                for log in logs:
                    try:
                        log_data = json.loads(log)
                        self.send_to_graylog(log_data)
                    except json.JSONDecodeError:
                        continue
                self.save_last_position()
                self.rotate_log_file_if_needed()

    def rotate_log_file_if_needed(self):
        file_size = os.path.getsize(self.file_path) / (1024 * 1024)  # Convert size to MB
        if file_size > self.max_file_size_mb:
            old_file_path = self.file_path + ".old"
            if os.path.exists(old_file_path):
                os.remove(old_file_path)
            os.rename(self.file_path, old_file_path)
            print(f"Rotated log file: {self.file_path} has been renamed to {old_file_path}")

    def send_to_graylog(self, log_data):
        is_filtered = log_data.get("Result", {}).get("IsFiltered", False)
        action = "Blocked" if is_filtered else "Allowed"
        source_ip = log_data.get("IP", "Unknown IP")
        query_target = log_data.get("QH", "Unknown Host")

        gelf_message = {
            "version": "1.1",
            "host": self.hostname,
            "short_message": f"Query from {source_ip} for {query_target}",
            "full_message": json.dumps(log_data),
            "timestamp": iso_to_unix_timestamp(log_data.get("T", "")),
            "_app": "AdGuardHome",
            "_action": action
        }

        # Additional fields for filter rules
        rules = log_data.get("Result", {}).get("Rules", [])
        if rules:
            rule = rules[0]
            if "Text" in rule:
                gelf_message["_filtertext"] = rule["Text"]
            if "FilterListID" in rule:
                gelf_message["_filterlist_id"] = rule["FilterListID"]
            if rule.get("FilterListID") in self.filterlist_names:
                gelf_message["_filterlist_name"] = self.filterlist_names[rule["FilterListID"]]

        for key, value in log_data.items():
            if key not in gelf_message and key not in ["Result"]:
                gelf_message[f"_{key}"] = value

        message_json = json.dumps(gelf_message).encode('utf-8')
        self.sock.sendto(message_json, (self.graylog_host, self.graylog_port))
        # print(f"Sent to Graylog: {json.dumps(gelf_message, indent=2)}")

if __name__ == '__main__':
    log_file_path = '/usr/local/AdGuardHome/data/querylog.json'
    last_position_file = '/opt/resend_adguardhome_log.tmp'
    config_path = '/usr/local/AdGuardHome/AdGuardHome.yaml'
    graylog_host = '192.168.1.83'
    graylog_port = 32201
    max_file_size_mb = 20  # Maximum log file size in megabytes before rotation

    # TCP server settings
    tcp_host = '192.168.1.1'  # Listen on all interfaces
    tcp_port = 39299      # Port to listen on
    password = "pw_adg_logserver"  # Password to verify

    # Start TCP server in a separate thread
    server_thread = threading.Thread(target=tcp_server, args=(tcp_host, tcp_port, password))
    server_thread.start()

    event_handler = LogHandler(log_file_path, graylog_host, graylog_port, config_path, last_position_file, max_file_size_mb)
    observer = Observer()
    observer.schedule(event_handler, path=os.path.dirname(log_file_path), recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        observer.join()
        print("Stopped monitoring.")
