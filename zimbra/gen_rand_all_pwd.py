#!/usr/bin/env python3
#
# Jason Cheng (Jason Tools)
# jason@jason.tools
# v1.0 (2024/03/29)
# 
import random
import string
import time
import subprocess
import xml.etree.ElementTree as ET

# Configuration variables
domains = ["testauth.com", "testabcde.com"]
excluded_accounts = ["admin@testauth.com", "galsync@testauth.com"]
password_length = 20
include_uppercase = True
include_lowercase = True
include_digits = True
include_symbols = True
symbols = "#$%^"
dryrun = "Y"
show_passwords = "Y"

def generate_password(length=10):
    characters = ""
    if include_uppercase:
        characters += string.ascii_uppercase
    if include_lowercase:
        characters += string.ascii_lowercase
    if include_digits:
        characters += string.digits
    if include_symbols:
        characters += symbols
    
    return ''.join(random.choice(characters) for _ in range(length))

def get_accounts(domain):
    cmd = ["zmprov", "-l", "gaa", domain]
    try:
        result = subprocess.run(cmd, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        accounts = result.stdout.strip().split('\n')
        # Filter out excluded accounts
        accounts = [account for account in accounts if account not in excluded_accounts]
        return accounts
    except subprocess.CalledProcessError as e:
        print(f"Failed to fetch accounts for domain {domain}: {e.stderr}")
        return []

def get_zimbra_id(account):
    cmd = [
        "zmsoap", "-z", "GetAccountInfoRequest/account={}".format(account), "@by=name"
    ]
    try:
        result = subprocess.run(cmd, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        root = ET.fromstring(result.stdout)
        ns = {'zimbraAdmin': 'urn:zimbraAdmin'}
        zimbra_id_element = root.find('.//zimbraAdmin:a[@n="zimbraId"]', namespaces=ns)
        if zimbra_id_element is not None:
            zimbra_id = zimbra_id_element.text
            return zimbra_id
    except Exception as e:
        print(f"Failed to get zimbraId for {account}: {str(e)}")
    return None

def set_password(account, new_password, current_num, total):
    zimbra_id = get_zimbra_id(account)
    if not zimbra_id:
        print(f"Skipping password set for {account} due to missing zimbraId")
        return
    password_display = new_password if show_passwords == "Y" else "*****"
    cmd = ["zmsoap", "-z", "SetPasswordRequest", f"@id={zimbra_id}", f'@newPassword={password_display}']
    
    print_cmd = ["zmsoap", "-z", "SetPasswordRequest", f"@id={zimbra_id}", f'@newPassword={password_display}']
    print(f"{account} - Command to execute: {' '.join(print_cmd)}")
    
    if dryrun != "Y":
        exec_cmd = ["zmsoap", "-z", "SetPasswordRequest", f"@id={zimbra_id}", f'@newPassword={new_password}']
        try:
            result = subprocess.run(exec_cmd, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.stderr:
                print(f"Command error: {result.stderr}")
            else:
                print(f"Password set successfully for {account}")
        except subprocess.CalledProcessError as e:
            print(f"Failed to set password for {account}: {e.stderr}")
    else:
        if show_passwords == "Y":
            print(f"{account} - Password to be set: '{new_password}'")
        else:
            print(f"{account} - Password to be set: '*****'")

def main():
    current_account_num = 0
    accounts_list = [(domain, account) for domain in domains for account in get_accounts(domain)]
    total_accounts = len(accounts_list)
    for domain, account in accounts_list:
        current_account_num += 1
        new_password = generate_password(password_length)
        set_password(account, new_password, current_account_num, total_accounts)
        time.sleep(0.001)

if __name__ == "__main__":
    main()
           