#!/usr/bin/env bash

# Script      : pve-disk-led.sh
# Version     : 1.1
# Author      : Jason Cheng (Jason Tools Co., Ltd.)
# Description : List disks on Proxmox VE host and light up disk LEDs for identification.
#               Output columns: Model, Serial, Size, SMART, SSD wear %.

BS="1M"
SPIN_INTERVAL=0.25
SHOW_DISKID=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --show-diskid) SHOW_DISKID=1; shift;;
    *) echo "Usage: $0 [--show-diskid]"; exit 1;;
  esac
done

for cmd in smartctl lsblk awk; do
  command -v "$cmd" &>/dev/null || { echo "Error: $cmd not found."; exit 1; }
done

readarray -t disks < <(lsblk -dn -o NAME | grep -E '^(sd|hd|nvme)[a-z0-9]+' | sort)
[[ ${#disks[@]} -eq 0 ]] && { echo "No disks detected."; exit 1; }

get_id() {
  local dev="/dev/$1"
  for p in /dev/disk/by-id/*; do
    [[ $(readlink -f "$p") == "$dev" ]] && { basename "$p"; return; }
  done
  echo "$dev"
}

is_ssd() {
  local dev="/dev/$1"
  smartctl -i "$dev" 2>/dev/null | grep -q "Solid State Device"
}

get_wear() {
  local dev="/dev/$1"
  local val out

  # NVMe
  out=$(smartctl -A "$dev" 2>/dev/null | awk '/Percentage Used/ {print $NF; exit}')
  val=$(echo "$out" | sed 's/^0*//;s/%//')
  [[ -n "$val" && "$val" =~ ^[0-9]+$ && "$val" -le 100 ]] && echo "$val%" && return

  # Media_Wearout_Indicator
  out=$(smartctl -A "$dev" 2>/dev/null | awk '/Media_Wearout_Indicator/ {print $4; exit}')
  val=$(echo "$out" | sed 's/^0*//')
  [[ -n "$val" && "$val" =~ ^[0-9]+$ && "$val" -le 100 ]] && echo "$((100 - val))%" && return

  # Wear_Leveling_Count
  out=$(smartctl -A "$dev" 2>/dev/null | awk '/Wear_Leveling_Count/ {print $4; exit}')
  val=$(echo "$out" | sed 's/^0*//')
  [[ -n "$val" && "$val" =~ ^[0-9]+$ && "$val" -le 100 ]] && echo "$((100 - val))%" && return

  # Percent_Lifetime_Remain
  out=$(smartctl -A "$dev" 2>/dev/null | awk '/Percent_Lifetime_Remain/ {print $4; exit}')
  val=$(echo "$out" | sed 's/^0*//')
  [[ -n "$val" && "$val" =~ ^[0-9]+$ && "$val" -le 100 ]] && echo "$((100 - val))%" && return

  # INTEL DC SSD
  out=$(smartctl -A "$dev" 2>/dev/null | awk '/Percentage Used Endurance Indicator/ {print $NF; exit}')
  val=$(echo "$out" | sed 's/^0*//;s/%//')
  [[ -n "$val" && "$val" =~ ^[0-9]+$ && "$val" -le 100 ]] && echo "$val%" && return

  echo "N/A"
}

# Format bytes to "X.XX TB/GB/MB" (decimal, same as PVE)
pretty_capacity() {
  local bytes="$1"
  if [[ -z "$bytes" ]] || ! [[ "$bytes" =~ ^[0-9]+$ ]]; then
    echo "N/A"
    return
  fi
  awk -v b="$bytes" 'BEGIN{
    if (b >= 1e12)
      printf "%.2f TB", b/1e12;
    else if (b >= 1e9)
      printf "%.2f GB", b/1e9;
    else if (b >= 1e6)
      printf "%.2f MB", b/1e6;
    else
      printf "%d B", b;
  }'
}

get_model_serial_size() {
  local name="$1"
  local m s sz
  m=$(lsblk -dn -o MODEL "/dev/$name" 2>/dev/null)
  s=$(lsblk -dn -o SERIAL "/dev/$name" 2>/dev/null)
  sz=$(lsblk -dn -o SIZE -b "/dev/$name" 2>/dev/null)
  [[ -z "$m" ]] && m="N/A"
  [[ -z "$s" ]] && s="N/A"
  [[ -z "$sz" ]] && sz="N/A"
  echo -e "$m\t$s\t$sz"
}

print_header() {
  if (( SHOW_DISKID )); then
    printf "\n%-3s %-28s %-20s %-12s %-8s %-8s %-48s\n" \
      "No" "Model" "Serial" "Size" "SMART" "Wear" "DiskID"
    printf "%-3s %-28s %-20s %-12s %-8s %-8s %-48s\n" \
      "--" "----------------------------" "--------------------" "------------" "-------" "------" "------------------------------------------------"
  else
    printf "\n%-3s %-28s %-20s %-12s %-8s %-8s\n" \
      "No" "Model" "Serial" "Size" "SMART" "Wear"
    printf "%-3s %-28s %-20s %-12s %-8s %-8s\n" \
      "--" "----------------------------" "--------------------" "------------" "-------" "------"
  fi
}

list_disks() {
  print_header
  for i in "${!disks[@]}"; do
    name="${disks[i]}"
    IFS=$'\t' read -r model serial size_bytes < <(get_model_serial_size "$name")
    size=$(pretty_capacity "$size_bytes")
    smart=$(smartctl -H "/dev/$name" 2>/dev/null | awk -F: '/overall-health/ {gsub(/^ +/,"",$2); print $2; exit}')
    [[ -z $smart ]] && smart="Unknown"
    wear=$(get_wear "$name")
    if (( SHOW_DISKID )); then
      id=$(get_id "$name")
      printf "%-3s %-28.28s %-20.20s %-12.12s %-8.8s %-8.8s %-48.48s\n" \
        "$((i+1))" "$model" "$serial" "$size" "$smart" "$wear" "$id"
    else
      printf "%-3s %-28.28s %-20.20s %-12.12s %-8.8s %-8.8s\n" \
        "$((i+1))" "$model" "$serial" "$size" "$smart" "$wear"
    fi
  done
}

while true; do
  list_disks
  echo
  read -rp "Which disk to light up? (Enter number or 'Q' to quit): " sel
  [[ $sel =~ ^[Qq]$ ]] && { echo "Bye."; break; }
  if ! [[ $sel =~ ^[0-9]+$ ]] || (( sel < 1 || sel > ${#disks[@]} )); then
    echo "Invalid selection."; continue
  fi

  name="${disks[sel-1]}"
  IFS=$'\t' read -r model serial _ < <(get_model_serial_size "$name")
  echo "Lighting up /dev/$name [$model $serial]. Press Q to stop."
  dd if="/dev/$name" of=/dev/null bs=$BS status=none & pid=$!
  spin=("|" "/" "-" "\\"); idx=0
  while kill -0 $pid 2>/dev/null; do
    printf "\r[%c] Working..." "${spin[idx]}"; idx=$(((idx+1)%4))
    read -n1 -s -t $SPIN_INTERVAL k && [[ $k =~ [Qq] ]] && kill $pid 2>/dev/null
  done
  wait $pid 2>/dev/null
  printf "\rStopped lighting disk /dev/$name.\n"
done
