#!/usr/bin/env python3
"""Quick script to create Wazuh API user."""

import sys
import json
import getpass
import argparse

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("Error: requests library required. Install with: pip install requests")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description='Create Wazuh API User')
    parser.add_argument('--host', default='localhost', help='Wazuh API host (default: localhost)')
    parser.add_argument('--port', type=int, default=55000, help='Wazuh API port (default: 55000)')
    parser.add_argument('--admin-user', default='wazuh', help='Existing admin username (default: wazuh)')
    parser.add_argument('--admin-pass', help='Existing admin password (will prompt if not provided)')
    parser.add_argument('--new-user', required=True, help='New username to create')
    parser.add_argument('--new-pass', help='New user password (will prompt if not provided)')
    parser.add_argument('--role', default='administrator',
                       choices=['administrator', 'readonly', 'agents_admin', 'cluster_admin'],
                       help='Role to assign (default: administrator)')

    args = parser.parse_args()

    # Get passwords interactively if not provided
    admin_pass = args.admin_pass or getpass.getpass(f"Enter password for '{args.admin_user}': ")
    new_pass = args.new_pass or getpass.getpass(f"Enter password for new user '{args.new_user}': ")

    base_url = f"https://{args.host}:{args.port}"

    # Role ID mapping
    role_map = {
        'administrator': 1,
        'readonly': 2,
        'agents_admin': 4,
        'cluster_admin': 5
    }

    print(f"\nConnecting to {base_url}...")

    # Step 1: Authenticate
    try:
        resp = requests.post(
            f"{base_url}/security/user/authenticate",
            auth=(args.admin_user, admin_pass),
            verify=False,
            timeout=30
        )
        if resp.status_code != 200:
            print(f"Error: Authentication failed - {resp.text}")
            sys.exit(1)

        token = resp.json()['data']['token']
        print("✓ Authenticated successfully")
    except Exception as e:
        print(f"Error: Failed to connect - {e}")
        sys.exit(1)

    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

    # Step 2: Create user
    try:
        resp = requests.post(
            f"{base_url}/security/users",
            headers=headers,
            json={'username': args.new_user, 'password': new_pass},
            verify=False,
            timeout=30
        )
        data = resp.json()

        if resp.status_code == 200 and data.get('data', {}).get('affected_items'):
            print(f"✓ User '{args.new_user}' created")
        elif 'already exists' in str(data):
            print(f"! User '{args.new_user}' already exists, updating role...")
        else:
            print(f"Error: Failed to create user - {data}")
            sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

    # Step 3: Assign role
    try:
        role_id = role_map[args.role]
        resp = requests.post(
            f"{base_url}/security/users/{args.new_user}/roles?role_ids={role_id}",
            headers=headers,
            verify=False,
            timeout=30
        )
        data = resp.json()

        if resp.status_code == 200:
            print(f"✓ Role '{args.role}' assigned")
        else:
            print(f"Warning: Role assignment - {data}")
    except Exception as e:
        print(f"Warning: Role assignment failed - {e}")

    print(f"\n{'='*50}")
    print(f"API User Created Successfully!")
    print(f"{'='*50}")
    print(f"  Host:     {args.host}:{args.port}")
    print(f"  Username: {args.new_user}")
    print(f"  Password: {'*' * len(new_pass)}")
    print(f"  Role:     {args.role}")
    print(f"{'='*50}")
    print(f"\nTest with:")
    print(f"  curl -k -u {args.new_user}:PASSWORD https://{args.host}:{args.port}/security/user/authenticate")


if __name__ == '__main__':
    main()
