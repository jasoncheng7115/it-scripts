#!/usr/bin/env python3
"""
Before running this script, ensure the following package is installed:
- mysql-connector-python (Install using: pip3 install mysql-connector-python)

Usage: python3 script_name.py --dryrun=Y|N

Jason Tools (jason@jason.tools)
v1.0
"""

try:
    import mysql.connector
except ImportError:
    print("mysql-connector-python is not installed. Please install it using:")
    print("pip3 install mysql-connector-python")
    exit()

import os
import sys

def load_db_config(env_file_path='/opt/librenms/.env'):
    db_config = {}
    with open(env_file_path, 'r') as file:
        for line in file:
            if line.strip() and not line.strip().startswith('#'):
                key, value = line.strip().split('=', 1)
                if key == 'DB_HOST':
                    db_config['host'] = value
                elif key == 'DB_DATABASE':
                    db_config['database'] = value
                elif key == 'DB_USER' or key == 'DB_USERNAME':
                    db_config['user'] = value
                elif key == 'DB_PASSWORD':
                    db_config['password'] = value
    db_config['raise_on_warnings'] = True
    return db_config

# Parsing command line arguments for dryrun option and making it mandatory
args = {arg.split('=')[0]: arg.split('=')[1] for arg in sys.argv[1:] if '=' in arg}
if '--dryrun' in args and args['--dryrun'] in ['Y', 'N']:
    dryrun = True if args['--dryrun'] == 'Y' else False
else:
    print("Usage: python3 script_name.py --dryrun=Y|N")
    exit()

db_config = load_db_config()

try:
    cnx = mysql.connector.connect(**db_config)
    cursor = cnx.cursor()
    query = (
        "SELECT ports.port_id, devices.hostname "
        "FROM ports, devices "
        "WHERE devices.device_id = ports.device_id AND ports.disabled = 1"
    )
    cursor.execute(query)
    
    for (port_id, hostname) in cursor:
        rrd_file = f"/opt/librenms/rrd/{hostname}/port-id{port_id}.rrd"
        if os.path.exists(rrd_file):
            if dryrun:
                print(f"Would delete {rrd_file}...")
            else:
                print(f"Deleting {rrd_file}...")
                os.remove(rrd_file)
        else:
            print(f"File {rrd_file} does not exist or has already been deleted.")
    
    cursor.close()
except mysql.connector.Error as err:
    print(f"Database Error: {err}")
finally:
    if 'cnx' in locals() and cnx.is_connected():
        cnx.close()
