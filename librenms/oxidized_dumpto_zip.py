#!/usr/bin/env python3
"""
To schedule this script to run as the 'oxidized' user using cron:
1. Log in as the 'oxidized' user.
2. Open the crontab file for editing by running: crontab -e
3. Add a line specifying the schedule and command to run the script. For example,
   to run the script every day at 3 AM, add the following line:
   0 3 * * * /usr/bin/python3 /opt/oxidized_dumpto_zip.py
   Make sure to replace "/opt/oxidized_dumpto_zip.py" with the actual path to this script.
4. Save and close the crontab editor. The cron job is now scheduled.

jason@jason.tools
Jason Tools Co., Ltd.
v1.0
"""

import subprocess
import datetime
import os
import getpass
import shutil

# Check if the current user is 'oxidized'. If not, print an error message.
current_user = getpass.getuser()
if current_user != 'oxidized':
    print("Error: This script must be run by the 'oxidized' user.")
    exit(1)

# Check if the 'zip' command is installed on the system.
if shutil.which('zip') is None:
    print("Error: The 'zip' tool is not installed on the system.")
    exit(1)

# Variables declaration
git_repo_path = '/home/oxidized/devices_git'  # Set the git repository path
destination_path = '/tmp'  # Set the destination path for the zip file
file_prefix = 'backup'  # Prefix for the zip file name

# Get the current timestamp in the format of year, month, day, hour, minute, second
timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')

# Create the full name for the zip file
zip_filename = f"{file_prefix}_{timestamp}.zip"

# Change to the git repository path
os.chdir(git_repo_path)

# Export the latest version of the git repository to a temporary directory and zip it
export_command = f"git archive --format zip --output {destination_path}/{zip_filename} HEAD"
try:
    subprocess.check_call(export_command, shell=True)
except subprocess.CalledProcessError as e:
    print(f"An error occurred while executing the git archive command: {e}")
    exit(1)

print(f"Repository has been exported and zipped as {zip_filename} in {destination_path}")
