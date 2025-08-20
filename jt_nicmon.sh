#!/usr/bin/env bash
# jt_nicmon.sh - NIC/Bridge/Bond status monitor (two sections)
# Author: Jason Cheng (Jason Tools)
# Date: 2025/08/20 .1

cols=$(tput cols)
W_IF=12; W_TP=5; W_STATE=6; W_LNK=3; W_SPD=10; W_DUP=6; W_MAC=17
W_IP=18; W_MEM=$((cols - W_IF - 1 - W_TP - 1 - W_IP - 2))
[ $W_MEM -lt 8 ] && W_MEM=8

pad()  { local s="$1" w="$2"; printf "%-*.*s" "$w" "$w" "$s"; }
padc() { local s="$1" w="$2" color="$3"; printf "%b" "${color}$(printf "%-*.*s" "$w" "$w" "$s")\033[0m"; }

# Type
get_type() {
  local i="$1"
  if [[ "$i" =~ ^vmbr[0-9]+$ ]]; then echo BR
  elif [[ "$i" =~ ^bond[0-9]+$ ]]; then echo BOND
  elif [ -d "/sys/class/net/$i/device" ]; then echo PHY
  else echo SKIP
  fi
}

# Link
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

# Speed/Duplex
speed_duplex_for_phy() {
  local dev="$1" et speed duplex
  et="$(ethtool "$dev" 2>/dev/null)"
  speed=$(printf "%s" "$et" | awk -F": " '/Speed:/{print $2}')
  duplex=$(printf "%s" "$et" | awk -F": " '/Duplex:/{print $2}')
  case "$speed" in ""|Unknown*|*"255"*) speed="-" ;; esac
  case "$duplex" in ""|Unknown*|unknow) duplex="-" ;; esac
  echo "$speed|$duplex"
}

# PHY interface
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

### Sec. 1: Physcal interface
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
### Sec. 2: vmbr/bond
pad IFACE $W_IF; printf " "; pad TYPE $W_TP; printf " "; pad IPV4 $W_IP; printf " "; pad "MEMBERS" $W_MEM; printf "\n"

for dev in $(ls -1 /sys/class/net | sort); do
  tp=$(get_type "$dev")
  [[ "$tp" != "BR" && "$tp" != "BOND" ]] && continue

  ip=$(ip -4 -o addr show dev "$dev" 2>/dev/null | awk '{print $4}' | head -n1); [ -z "$ip" ] && ip="-"
  members=$(members_of "$dev")

  pad "$dev" $W_IF; printf " "
  pad "$tp"  $W_TP; printf " "
  pad "$ip"  $W_IP; printf " "
  pad "$members" $W_MEM; printf "\n"
done
