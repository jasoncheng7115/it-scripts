#!/bin/bash

# Jason Tools (www.jason.tools) - Jason Cheng (jason@jason.tools)

# === Configuration ===
BLOCKLIST_URL="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/iblocklist_ciarmy_malicious.netset"
TMP_FILE="/var/ossec/etc/lists/tmp_ips.txt"
CDB_FILE="/var/ossec/etc/lists/malicious-ip"

touch "/var/ossec/etc/lists/malicious-ip"

# === Download ===
echo "[INFO] Downloading malicious IP list from: $BLOCKLIST_URL"
curl -s "$BLOCKLIST_URL" -o "$TMP_FILE"

chown wazuh:wazuh "$CDB_FILE"

if [ $? -ne 0 ] || [ ! -s "$TMP_FILE" ]; then
  echo "[ERROR] Failed to download or file is empty: $BLOCKLIST_URL"
  exit 1
fi

# === Convert to CDB format ===
echo "[INFO] Converting to CDB format..."
awk '!/^#/ && NF { print $1 ":1" }' "$TMP_FILE" > "$CDB_FILE"

# === Clean up temporary file ===
rm -f "$TMP_FILE"

# === Generate optional CDB index (legacy support) ===
if [ -x /var/ossec/bin/wazuh-cdb ]; then
  echo "[INFO] Building CDB index..."
  /var/ossec/bin/wazuh-cdb list "$CDB_FILE" > /dev/null 2>&1
fi

echo "[INFO] Malicious IP list successfully updated: $CDB_FILE"
