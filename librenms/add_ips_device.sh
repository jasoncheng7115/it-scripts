#!/bin/bash
# Author: Jason Cheng (jason@jason.tools)
# Description: Batch add devices from multiple specified subnets to LibreNMS using specified SNMP version and community.
# Requires to be run as the 'librenms' user.

# Check if the script is run as the 'librenms' user
if [ "$(whoami)" != "librenms" ]; then
    echo "This script must be run as the 'librenms' user."
    exit 1
fi

# Check if minimum parameters are provided
if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <snmp_version> <community> <subnet1> [<subnet2> ...]"
    echo "Example: $0 v2c public 192.168.1.0/24 192.168.2.0/24"
    exit 1
fi

snmp_version=$1
community=$2
shift 2 # Remove the first two arguments, rest are subnets

# Function to convert CIDR to a range of IPs
cidr_to_ips() {
    local cidr=$1
    IFS='/' read -r ip mask <<< "$cidr"
    local IFS='.'; read -r i1 i2 i3 i4 <<< "$ip"
    local ip_num=$((i1 * 256**3 + i2 * 256**2 + i3 * 256 + i4))
    local range=$((2**(32-mask)))
    echo $(seq $((ip_num+1)) $((ip_num+range-2)))
}

# Main loop to add devices within a subnet
add_subnet() {
    local subnet=$1
    local version=$2
    local community=$3
    for ip_num in $(cidr_to_ips $subnet); do
        local ip1=$((ip_num >> 24 & 255))
        local ip2=$((ip_num >> 16 & 255))
        local ip3=$((ip_num >> 8 & 255))
        local ip4=$((ip_num & 255))
        local device_ip="$ip1.$ip2.$ip3.$ip4"
        # Add device
        echo "Adding device: $device_ip"
        lnms device:add $device_ip --$version -c $community
    done
}

# Process each subnet
for subnet in "$@"; do
    echo "Processing subnet: $subnet"
    add_subnet $subnet $snmp_version $community
done
