#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Jason Cheng (Jason Tools)
# jason@jason.tools
# v1.0
#
# This program requires a zimbra account to run.

import os
import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# setting
domains = ['yourdomain.com']
days_to_notify = 7
admin_email = ['checkpwdexpire@yourdomain.com']
dryrun = 'Y'  # 'Y' is try, 'N' will send mail
smtp_server = "localhost"

def fetch_accounts(domain):
    pathtozmsoap = "/opt/zimbra/bin/zmsoap"
    get_return = os.popen(f'{pathtozmsoap} -z GetAllAccountsRequest/domain="{domain}" @by=name')
    lists = get_return.read()
    
    if lists.strip():
        try:
            accounts = []
            from xml.etree.ElementTree import fromstring, ElementTree
            tree = ElementTree(fromstring(lists))
            root = tree.getroot()
            for account in root:
                email = account.attrib.get('name')
                modified_time = ""
                max_age_days = ""
                for a in account:
                    if a.attrib.get('n') == 'zimbraPasswordModifiedTime':
                        modified_time = a.text
                    elif a.attrib.get('n') == 'zimbraPasswordMaxAge':
                        max_age_days = a.text
                if email and modified_time and max_age_days:
                    accounts.append({'email': email, 'zimbraPasswordModifiedTime': modified_time, 'zimbraPasswordMaxAge': int(max_age_days)})
            return accounts
        except Exception as e:
            print(f"Failed to parse XML: {e}")
            return []
    else:
        print("No valid XML data received from zmsoap command.")
        return []

def check_password_expiry(accounts):
    expiring_accounts = []
    today = datetime.datetime.now()
    for account in accounts:
        email = account['email']
        modified_time = account['zimbraPasswordModifiedTime']
        max_age_days = account['zimbraPasswordMaxAge']

        if max_age_days == 0:
            continue

        try:
            password_last_changed = datetime.datetime.strptime(modified_time, '%Y%m%d%H%M%S.%fZ')
            password_expiry_date = password_last_changed + datetime.timedelta(days=max_age_days)
            days_until_expiry = (password_expiry_date - today).days
            if days_until_expiry <= days_to_notify:
                if days_until_expiry >= 0:
                    expiring_accounts.append((email, days_until_expiry))
                    print(f"Account {email} will expire in {days_until_expiry} days and will be notified.")
                else:
                    expiring_accounts.append((email, days_until_expiry))
                    print(f"Account {email} password has already expired. It expired {abs(days_until_expiry)} days ago.")
        except ValueError as e:
            print(f"Error parsing date {modified_time} for account {email}: {e}")

    return expiring_accounts

def send_emails(expiring_accounts, domain):
    print(f"Preparing to send emails for domain: {domain} (Dry run: {dryrun})")
    server = smtplib.SMTP(smtp_server, 25)
    server.starttls()
    
    for account, days in expiring_accounts:
        msg = prepare_email_message(account, days)
        if dryrun == 'N':
            server.send_message(msg)
            print(f"Sent email to {account}")
        else:
            # Convert days to positive if they are negative (i.e., password already expired)
            positive_days = abs(days)
            #print(f"Dry run: email ready for {account}, which will expire in {positive_days} days, but not sent.")
    
    server.quit()

def prepare_email_message(account, days_until_expiry):
    msg = MIMEMultipart()
    msg['From'] = admin_email[0]
    msg['To'] = account
    if days_until_expiry < 0:
        msg['Subject'] = "Urgent: Password Expired Notification"
        body = (f"Dear {account.split('@')[0]},\n\n"
                "Your password has already expired. It expired "
                f"{abs(days_until_expiry)} days ago. Please reset your password "
                "immediately to maintain account security.\n\n"
                "If you need assistance, please contact IT support.\n\n"
                "Best regards,\n"
                "IT Team")
    else:
        msg['Subject'] = "Password Expiry Notification"
        body = (f"Dear {account.split('@')[0]},\n\n"
                f"Your password will expire in {days_until_expiry} days. "
                "Please consider resetting your password soon to avoid any disruption in service.\n\n"
                "Visit our password reset page or contact IT support if you need assistance.\n\n"
                "Best regards,\n"
                "IT Team")
    msg.attach(MIMEText(body, 'plain'))
    return msg

for domain in domains:
    accounts = fetch_accounts(domain)
    expiring_accounts = check_password_expiry(accounts)
    send_emails(expiring_accounts, domain)
