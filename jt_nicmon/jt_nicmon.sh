#!/usr/bin/env bash
# jt_nicmon.sh - NIC/Bridge/Bond status monitor (two sections)
# Author: Jason Cheng (Jason Tools)
# Version: 1.1
# Date: 2025/09/16
#
# Changelog:
# v1.1 (2025/09/16) - Smart filtering: show bridges with IP or physical members
#                   - Always show vmbr*, bond*, and custom named bridges
#                   - Fixed bridge detection to use system attributes instead of naming patterns
#                   - Now correctly identifies bridges regardless of naming convention
# v1.0 (2025/08/20) - Initial release

cols=$(tput cols)
W_IF=12; W_TP=5; W_STATE=6; W_LNK=3; W_SPD=10; W_DUP=6; W_MAC=17
W_IP=18; W_MEM=$((cols - W_IF - 1 - W_TP - 1 - W_IP - 2))
[ $W_MEM -lt 8 ] && W_MEM=8

pad()  { local s="$1" w="$2"; printf "%-*.*s" "$w" "$w" "$s"; }
padc() { local s="$1" w="$2" color="$3"; printf "%b" "${color}$(printf "%-*.*s" "$w" "$w" "$s")\033[0m"; }

get_type() {
  local i="$1"
  if [ -d "/sys/class/net/$i/bridge" ] || [ -d "/sys/class/net/$i/brif" ]; then
    echo BR
  elif [ -d "/sys/class/net/$i/bonding" ]; then
    echo BOND
  elif [ -d "/sys/class/net/$i/device" ]; then
    echo PHY
  else
    echo SKIP
  fi
}

is_important_bridge() {
  local dev="$1"
  
  [[ "$dev" =~ ^vmbr[0-9]+$ ]] && return 0
  [[ "$dev" =~ ^bond[0-9]+$ ]] && return 0
  
  [[ "$dev" =~ ^(vnet|fwbr|fwln|fwpr|tap)[0-9]+ ]] && return 1
  [[ "$dev" =~ ^sdn[0-9]+$ ]] && return 1
  
  local has_ip=$(ip -4 -o addr show dev "$dev" 2>/dev/null | awk '{print $4}' | head -n1)
  [ -n "$has_ip" ] && [ "$has_ip" != "-" ] && return 0
  
  if [ -d "/sys/class/net/$dev/brif" ]; then
    for p in /sys/class/net/$dev/brif/*; do
      [ -e "$p" ] || continue
      local member; member=$(basename "$p")
      if [[ "$member" =~ ^(en|eth|bond) ]]; then
        return 0
      fi
    done
  fi
  
  return 0
}

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

speed_duplex_for_phy() {
  local dev="$1" et speed duplex
  et="$(ethtool "$dev" 2>/dev/null)"
  speed=$(printf "%s" "$et" | awk -F": " '/Speed:/{print $2}')
  duplex=$(printf "%s" "$et" | awk -F": " '/Duplex:/{print $2}')
  case "$speed" in ""|Unknown*|*"255"*) speed="-" ;; esac
  case "$duplex" in ""|Unknown*|unknow) duplex="-" ;; esac
  echo "$speed|$duplex"
}

members_of() {
  local dev="$1" list=()
  if [ -d "/sys/class/net/$dev/brif" ]; then
    for p in /sys/class/net/$dev/brif/*; do
      [ -e "$p" ] || continue
      local b; b=$(basename "$p")
      if [[ "$b" =~ ^bond[0-9]+$ || "$b" =~ ^en.* || "$b" =~ ^eth.* ]]; then
        list+=("$b")
      fi
    done
  elif [ -r "/sys/class/net/$dev/bonding/slaves" ]; then
    for b in $(cat "/sys/class/net/$dev/bonding/slaves"); do
      list+=("$b")
    done
  fi
  [ ${#list[@]} -gt 0 ] && echo "${list[*]}" || echo "-"
}

pad IFACE $W_IF; printf " "; pad TYPE $W_TP; printf " "; pad STATE $W_STATE; printf " "
pad LNK $W_LNK; printf " "; pad SPEED $W_SPD; printf " "; pad DUPLX $W_DUP; printf " "; pad MAC $W_MAC; printf "\n"

for dev in $(ls -1 /sys/class/net | sort); do
  tp=$(get_type "$dev")
  [[ "$tp" != "PHY" ]] && continue
  [[ "$dev" =~ ^(en|eth) ]] || continue

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
pad IFACE $W_IF; printf " "; pad TYPE $W_TP; printf " "; pad IPV4 $W_IP; printf " "; pad "MEMBERS" $W_MEM; printf "\n"

for dev in $(ls -1 /sys/class/net | sort); do
  tp=$(get_type "$dev")
  [[ "$tp" != "BR" && "$tp" != "BOND" ]] && continue
  
  is_important_bridge "$dev" || continue

  ip=$(ip -4 -o addr show dev "$dev" 2>/dev/null | awk '{print $4}' | head -n1); [ -z "$ip" ] && ip="-"
  members=$(members_of "$dev")

  pad "$dev" $W_IF; printf " "
  pad "$tp"  $W_TP; printf " "
  pad "$ip"  $W_IP; printf " "
  pad "$members" $W_MEM; printf "\n"
done
