#!/usr/bin/env bash
# jt_nicmon.sh - NIC/Bridge/Bond status monitor (two sections)
# Author: Jason Cheng (Jason Tools)
# Version: 1.2.1
# Date: 2025/09/29
#
# Changelog:
# v1.2.1 (2025/09/29) - Filter out PVE firewall/temporary interfaces (fwbr/fwln/fwpr/veth/vnet/tap) from bridge MEMBERS
#                     - Keep attribute-based detection; no name-based filters
# v1.2   (2025/09/29) - Support PVE 9 interface name pinning (nic0/nic1/...)
#                     - Remove name-based filters; rely on sysfs attributes
#                     - Attribute-based bridge importance and member listing
# v1.1   (2025/09/16) - Smart filtering for bridges; better detection
# v1.0   (2025/08/20) - Initial release

set -o pipefail

# Column widths (auto-fit to terminal)
cols=$(tput cols 2>/dev/null || echo 120)
W_IF=12; W_TP=5; W_STATE=6; W_LNK=3; W_SPD=10; W_DUP=6; W_MAC=17
W_IP=18; W_MEM=$((cols - W_IF - 1 - W_TP - 1 - W_IP - 2))
[ $W_MEM -lt 8 ] && W_MEM=8

pad()  { local s="$1" w="$2"; printf "%-*.*s" "$w" "$w" "$s"; }
padc() { local s="$1" w="$2" color="$3"; printf "%b" "${color}$(printf "%-*.*s" "$w" "$w" "$s")\033[0m"; }

# Determine device type using sysfs attributes only
get_type() {
  local i="$1"
  if   [ -d "/sys/class/net/$i/bridge" ] || [ -d "/sys/class/net/$i/brif" ]; then
    echo BR
  elif [ -d "/sys/class/net/$i/bonding" ]; then
    echo BOND
  elif [ -d "/sys/class/net/$i/device" ]; then
    # Has a backing device -> physical or SR-IOV PF/VF; treat as physical for monitoring
    echo PHY
  else
    echo SKIP
  fi
}

# Helper: true if a device is a physical NIC (has /device and is not a bridge or bond)
is_phy() {
  local i="$1"
  [ -d "/sys/class/net/$i/device" ] && \
  [ ! -d "/sys/class/net/$i/bridge" ] && \
  [ ! -d "/sys/class/net/$i/bonding" ]
}

# Determine link state (prefer sysfs carrier; fallback to ethtool)
link_for_dev() {
  local dev="$1" link="-"
  if [ -r "/sys/class/net/$dev/carrier" ]; then
    local carr; carr=$(cat "/sys/class/net/$dev/carrier" 2>/dev/null)
    case "$carr" in 1) link="yes" ;; 0) link="no" ;; *) link="-" ;; esac
  else
    link=$(ethtool "$dev" 2>/dev/null | awk -F": " '/Link detected:/{print $2}')
    [ -z "$link" ] && link="-"
  fi
  echo "$link"
}

# Get speed/duplex for physical NICs
speed_duplex_for_phy() {
  local dev="$1" et speed duplex
  et="$(ethtool "$dev" 2>/dev/null)"
  speed=$(printf "%s" "$et" | awk -F": " '/Speed:/{print $2}')
  duplex=$(printf "%s" "$et" | awk -F": " '/Duplex:/{print $2}')
  case "$speed" in ""|Unknown*|*"255"*) speed="-" ;; esac
  case "$duplex" in ""|Unknown*|unknow) duplex="-" ;; esac
  echo "$speed|$duplex"
}

# List members (bridge ports or bond slaves), filtering out temporary/ephemeral devices
members_of() {
  local dev="$1" list=()
  # Bridge members
  if [ -d "/sys/class/net/$dev/brif" ]; then
    local m
    for p in /sys/class/net/$dev/brif/*; do
      [ -e "$p" ] || continue
      m=$(basename "$p")

      # Skip PVE firewall/transient/ephemeral interfaces
      if [[ "$m" =~ ^(fwbr|fwln|fwpr|veth|vnet|tap) ]]; then
        continue
      fi

      # Keep bond devices as members
      if [ -d "/sys/class/net/$m/bonding" ]; then
        list+=("$m")
        continue
      fi

      # Keep physical NICs (covers pinned names like nic0/nic1 and en*/eth*/enx*)
      if [ -d "/sys/class/net/$m/device" ]; then
        list+=("$m")
        continue
      fi

      # Keep VLAN subinterfaces (e.g., enp3s0.10 or nic0.10)
      if [[ "$m" =~ \.[0-9]+$ ]]; then
        list+=("$m")
        continue
      fi
      # Other types are omitted from output
    done
  fi

  # Bond slaves (if the device itself is a bond)
  if [ -r "/sys/class/net/$dev/bonding/slaves" ]; then
    for b in $(cat "/sys/class/net/$dev/bonding/slaves"); do
      # Skip ephemeral types if any appear as bond slaves (rare)
      if [[ "$b" =~ ^(fwbr|fwln|fwpr|veth|vnet|tap) ]]; then
        continue
      fi
      list+=("$b")
    done
  fi

  # Deduplicate and print
  if [ ${#list[@]} -gt 0 ]; then
    printf "%s\n" "${list[@]}" | awk '!seen[$0]++' | xargs echo
  else
    echo "-"
  fi
}

# Decide whether a bridge/bond is "important" enough to display
is_important_bridge() {
  local dev="$1"

  # Always keep vmbr* and bond*
  [[ "$dev" =~ ^vmbr[0-9]+$ ]] && return 0
  [[ "$dev" =~ ^bond[0-9]+$ ]] && return 0

  # Hide common transient/ephemeral top-level devices
  [[ "$dev" =~ ^(vnet|fwbr|fwln|fwpr|tap)[0-9]+ ]] && return 1
  [[ "$dev" =~ ^sdn[0-9]+$ ]] && return 1

  # Keep bridges that have an IPv4 address
  local has_ip
  has_ip=$(ip -4 -o addr show dev "$dev" 2>/dev/null | awk '{print $4}' | head -n1)
  [ -n "$has_ip" ] && [ "$has_ip" != "-" ] && return 0

  # Keep bridges that have at least one physical or bond member
  if [ -d "/sys/class/net/$dev/brif" ]; then
    local m
    for p in /sys/class/net/$dev/brif/*; do
      [ -e "$p" ] || continue
      m=$(basename "$p")
      if is_phy "$m" || [ -d "/sys/class/net/$m/bonding" ]; then
        return 0
      fi
    done
  fi

  # Otherwise, do not show
  return 1
}

# ===== Section 1: Physical NICs =====
pad IFACE $W_IF; printf " "; pad TYPE $W_TP; printf " "; pad STATE $W_STATE; printf " "
pad LNK $W_LNK; printf " "; pad SPEED $W_SPD; printf " "; pad DUPLX $W_DUP; printf " "; pad MAC $W_MAC; printf "\n"

for dev in $(ls -1 /sys/class/net | sort); do
  tp=$(get_type "$dev")
  [[ "$tp" != "PHY" ]] && continue  # Attribute-based; supports pinned nic0/nic1
  operstate=$(cat "/sys/class/net/$dev/operstate" 2>/dev/null); [ -z "$operstate" ] && operstate="-"
  link=$(link_for_dev "$dev")
  IFS="|" read -r speed duplex < <(speed_duplex_for_phy "$dev")
  mac=$(cat "/sys/class/net/$dev/address" 2>/dev/null); [ -z "$mac" ] && mac="-"

  pad "$dev" $W_IF; printf " "
  pad "$tp"  $W_TP; printf " "
  case "$operstate" in
    up)   padc "$operstate" $W_STATE $'\033[32m' ;;
    down) padc "$operstate" $W_STATE $'\033[33m' ;;
    *)    pad "$operstate" $W_STATE ;;
  esac
  printf " "
  case "$link" in
    yes)  padc "$link" $W_LNK $'\033[32m' ;;
    no)   padc "$link" $W_LNK $'\033[31m' ;;
    *)    pad "$link" $W_LNK ;;
  esac
  printf " "
  pad "$speed"  $W_SPD; printf " "
  pad "$duplex" $W_DUP; printf " "
  pad "$mac"    $W_MAC; printf "\n"
done

echo

# ===== Section 2: Bridges/Bonds =====
pad IFACE $W_IF; printf " "; pad TYPE $W_TP; printf " "; pad IPV4 $W_IP; printf " "; pad "MEMBERS" $W_MEM; printf "\n"

for dev in $(ls -1 /sys/class/net | sort); do
  tp=$(get_type "$dev")
  [[ "$tp" != "BR" && "$tp" != "BOND" ]] && continue

  is_important_bridge "$dev" || continue

  ip=$(ip -4 -o addr show dev "$dev" 2>/dev/null | awk '{print $4}' | head -n1)
  [ -z "$ip" ] && ip="-"
  members=$(members_of "$dev")

  pad "$dev" $W_IF; printf " "
  pad "$tp"  $W_TP; printf " "
  pad "$ip"  $W_IP; printf " "
  pad "$members" $W_MEM; printf "\n"
done
