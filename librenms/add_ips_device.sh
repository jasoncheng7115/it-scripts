#!/bin/bash
# Author: Jason Cheng (jason@jason.tools)
# Description: Batch add devices within a given IP range to LibreNMS using specified SNMP version and community.
# Requires to be run as the 'librenms' user.

# Check if the script is run as the 'librenms' user
if [ "$(whoami)" != "librenms" ]; then
    echo "This script must be run as the 'librenms' user."
    exit 1
fi

# Check if sufficient parameters are provided
if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <start_ip> <end_ip> <snmp_version> <community>"
    echo "Example: $0 192.168.1.1 192.168.1.254 v2c public"
    exit 1
fi

start_ip=$1
end_ip=$2
snmp_version=$3
community=$4

# Convert IP to integer
ip_to_int() {
    local IFS=.
    read ip1 ip2 ip3 ip4 <<< "$1"
    echo $((ip1 * 256 ** 3 + ip2 * 256 ** 2 + ip3 * 256 + ip4))
}

# Convert integer back to IP
int_to_ip() {
    local ui32=$1
    local ip1=$((ui32 >> 24 & 255))
    local ip2=$((ui32 >> 16 & 255))
    local ip3=$((ui32 >> 8 & 255))
    local ip4=$((ui32 & 255))
    echo "$ip1.$ip2.$ip3.$ip4"
}

# Main loop
start=$(ip_to_int $start_ip)
end=$(ip_to_int $end_ip)
for ip in $(seq $start $end); do
    device_ip=$(int_to_ip $ip)
    # Add device
    echo "Adding device: $device_ip"
    lnms device:add $device_ip --$snmp_version -c $community
done