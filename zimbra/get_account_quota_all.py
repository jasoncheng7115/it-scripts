#!/usr/bin/env python3
"""
Zimbra Quota Reporter
Author: Jason Cheng (jason@jason.tools)
Version: 1.0

This script reports the quota usage for Zimbra accounts, including mailbox, calendar, task, and document quotas.

Dependencies: 
- No additional modules are required to be installed with pip3 as this script only uses standard Python libraries.
"""

import subprocess
import re
import csv
import sys

# Domain to be listed
domain = "yourdomain.com"

# Check if the email address is valid
def is_valid_email(email):
    if re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return True
    else:
        return False

# Convert byte count to KB, MB, or GB
def convert_bytes(num):
    for unit in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if num < 1024.0:
            return f"{num:3.1f} {unit}"
        num /= 1024.0

# Retrieve a list of all accounts
def get_accounts():
    command = f'zmprov -l gaa {domain}'
    output = subprocess.check_output(command, shell=True)
    accounts = output.decode().split("\n")
    accounts = [account for account in accounts if is_valid_email(account)]
    return accounts

# Retrieve and parse all quotas from zmsoap output
def get_all_quotas(account):
    command = f'zmsoap -z -m "{account}" GetFolderRequest'
    output = subprocess.check_output(command, shell=True)
    data = output.decode()

    # Parsing quotas for different views
    views = ["message", "appointment", "task", "document"]
    quotas = {view: parse_quota(data, view) for view in views}
    return quotas

# General function to parse quota for a given view type
def parse_quota(data, view_type):
    pattern = rf'<folder [^>]*view="{view_type}"[^>]*?\bs="(\d+)"'
    matches = re.findall(pattern, data)
    total_quota = sum([int(match) for match in matches])
    return total_quota

# Main function
def main():
    accounts = get_accounts()

    # Initialize CSV writer with quotechar as double quotes
    writer = csv.DictWriter(sys.stdout, fieldnames=["Account", "Mailbox Quota", "Calendar Quota", "Task Quota", "Document Quota"], quotechar='"', quoting=csv.QUOTE_ALL)

    writer.writeheader()

    for account in accounts:
        quotas = get_all_quotas(account)

        account_stat = {
            "Account": account,
            "Mailbox Quota": convert_bytes(quotas["message"]),
            "Calendar Quota": convert_bytes(quotas["appointment"]),
            "Task Quota": convert_bytes(quotas["task"]),
            "Document Quota": convert_bytes(quotas["document"])
        }

        # Print the account stat immediately after processing
        writer.writerow(account_stat)

if __name__ == "__main__":
    main()

