#!/usr/bin/env bash
# jt_nicmon.sh - NIC/Bridge/Bond status monitor (two sections)
# Author: Jason Cheng (Jason Tools)
# Version: 1.4
# Date: 2025/09/29
#
# Changelog:
# v1.5   (2025/09/29) - Logging is now ON by default; one log file per run (jt_nicmon_<ts>_<pid>.log)
#                     - Only the newest log is kept (--keep N to change, 0 = keep all)
#                     - Replace -l/--log with --no-log / -d|--log-dir
#                     - Fix: LNK showed "-" instead of "no" for admin-down NICs; reading
#                       carrier returns EINVAL while down, so now fall back to ethtool
# v1.4   (2025/09/29) - Add -m/--model to show NIC model (vendor/device) resolved via lspci
#                     - Gracefully skips the column when lspci is unavailable
# v1.3   (2025/09/29) - Add -l/--log [FILE] to dump raw output of every command / sysfs read
#                     - Log is written next to the script, with a per-run header
#                     - Add -h/--help
# v1.2.1 (2025/09/29) - Filter out PVE firewall/temporary interfaces (fwbr/fwln/fwpr/veth/vnet/tap) from bridge MEMBERS
#                     - Keep attribute-based detection; no name-based filters
# v1.2   (2025/09/29) - Support PVE 9 interface name pinning (nic0/nic1/...)
#                     - Remove name-based filters; rely on sysfs attributes
#                     - Attribute-based bridge importance and member listing
# v1.1   (2025/09/16) - Smart filtering for bridges; better detection
# v1.0   (2025/08/20) - Initial release

set -o pipefail

VERSION="1.5"

# Logs live next to this script, regardless of the current working directory
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
[ -n "$SCRIPT_DIR" ] || SCRIPT_DIR="."

LOG_ENABLED=1                 # logging is on by default
LOG_DIR="$SCRIPT_DIR"
LOG_KEEP=1                    # how many recent log files to keep (0 = keep all)
LOG_PREFIX="jt_nicmon_"
LOG_FILE=""                   # generated per run in log_init()
SHOW_MODEL=0
LSPCI_DATA=""

usage() {
  cat <<EOF
jt_nicmon.sh v$VERSION - NIC/Bridge/Bond status monitor

Usage: ${0##*/} [options]

Logging is ON by default: every run writes the raw output of all commands and
sysfs reads to its own file, ${LOG_PREFIX}<date>-<time>_<pid>.log, in
$LOG_DIR
Only the newest log is kept; older ones are deleted on each run.

Options:
      --no-log       Do not write a log file for this run.
  -d, --log-dir DIR  Write log files to DIR instead of the script directory.
      --keep N       Keep the N most recent log files instead of $LOG_KEEP (0 = keep all).
  -m, --model        Add a MODEL column to the physical NIC table, showing the
                     vendor/device name resolved from the PCI address via lspci.
                     Silently skipped if lspci is not installed.
  -h, --help         Show this help and exit.

Examples:
  ${0##*/}
  ${0##*/} --model
  ${0##*/} --no-log
  ${0##*/} --log-dir /var/log/jt_nicmon --keep-hours 72
  watch -n 2 "${0##*/} --model --no-log"

Note: with watch, every refresh creates a new log file. Use --no-log for
      long monitoring sessions, or a longer watch interval.
EOF
}

# ===== Argument parsing =====
while [ $# -gt 0 ]; do
  case "$1" in
    --no-log)
      LOG_ENABLED=0
      ;;
    -d|--log-dir)
      [ -n "$2" ] || { printf "Option %s requires a directory\n" "$1" >&2; exit 1; }
      LOG_DIR="$2"; shift
      ;;
    --log-dir=*)
      LOG_DIR="${1#--log-dir=}"
      ;;
    --keep)
      [ -n "$2" ] || { printf "Option %s requires a number\n" "$1" >&2; exit 1; }
      LOG_KEEP="$2"; shift
      ;;
    --keep=*)
      LOG_KEEP="${1#--keep=}"
      ;;
    -m|--model)
      SHOW_MODEL=1
      ;;
    -h|--help)
      usage; exit 0
      ;;
    *)
      printf "Unknown option: %s\n\n" "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

# ===== Logging helpers =====
# All log writes use >> so they stay correct even when called from a subshell
# (most collectors run inside $( ) command substitution).
# Keep only the LOG_KEEP most recent log files; echoes how many were removed.
# Called after the current run's file exists, so it always counts as the newest.
log_prune() {
  local n=0 f
  case "$LOG_KEEP" in
    ''|*[!0-9]*) echo 0; return 0 ;;   # not a number, skip pruning
    0)           echo 0; return 0 ;;   # 0 = keep all
  esac
  for f in $(ls -1t "$LOG_DIR/${LOG_PREFIX}"*.log 2>/dev/null | tail -n "+$((LOG_KEEP + 1))"); do
    rm -f "$f" 2>/dev/null && n=$((n + 1))
  done
  echo "$n"
}

log_init() {
  [ "$LOG_ENABLED" -eq 1 ] || return 0

  if [ ! -d "$LOG_DIR" ]; then
    printf "Log directory does not exist: %s\n" "$LOG_DIR" >&2
    exit 1
  fi

  # One file per run; PID keeps it unique even for two runs in the same second
  LOG_FILE="$LOG_DIR/${LOG_PREFIX}$(date '+%Y%m%d-%H%M%S')_$$.log"

  # NOTE: 2>/dev/null must come first so it is in effect when >> is evaluated
  if ! : 2>/dev/null >>"$LOG_FILE"; then
    printf "Cannot write to log file: %s\n" "$LOG_FILE" >&2
    exit 1
  fi

  local pruned; pruned=$(log_prune)

  {
    printf '==== RUN %s | host=%s | jt_nicmon v%s ====\n' \
      "$(date '+%Y-%m-%d %H:%M:%S')" "$(hostname 2>/dev/null || echo '-')" "$VERSION"
    printf '# kernel: %s\n' "$(uname -sr 2>/dev/null || echo '-')"
    printf '# log: %s (keep %s, %s old file(s) pruned)\n' \
      "$LOG_FILE" "$LOG_KEEP" "$pruned"
  } >>"$LOG_FILE"
}

# log_entry <command-label> <rc> <raw-output>
log_entry() {
  [ "$LOG_ENABLED" -eq 1 ] || return 0
  {
    printf '$ %s  [rc=%s]\n' "$1" "$2"
    if [ -n "$3" ]; then printf '%s\n' "$3"; else printf '(no output)\n'; fi
  } >>"$LOG_FILE"
}

# log_note <text> - record something that is not a command (globs, decisions)
log_note() {
  [ "$LOG_ENABLED" -eq 1 ] || return 0
  printf '# %s\n' "$1" >>"$LOG_FILE"
}

# run <cmd> [args...] - run a command, log its raw stdout, echo stdout back
run() {
  local out rc
  out=$("$@" 2>/dev/null); rc=$?
  log_entry "$*" "$rc" "$out"
  printf '%s' "$out"
}

# rd <file> - read a sysfs/proc file, log its raw content, echo it back
rd() {
  local out rc
  out=$(cat "$1" 2>/dev/null); rc=$?
  log_entry "cat $1" "$rc" "$out"
  printf '%s' "$out"
}

log_init

# Column widths (auto-fit to terminal)
cols=$(run tput cols); [ -z "$cols" ] && cols=120
W_IF=12; W_TP=5; W_STATE=6; W_LNK=3; W_SPD=10; W_DUP=6; W_MAC=17
W_IP=18; W_MEM=$((cols - W_IF - 1 - W_TP - 1 - W_IP - 2))
[ $W_MEM -lt 8 ] && W_MEM=8
# MODEL takes whatever is left on the line after the fixed section-1 columns.
# MAC values fill their column exactly, so MODEL is separated by two spaces
# (6 single separators + 1 double = 8) to keep it visually distinct.
W_MODEL=$((cols - W_IF - W_TP - W_STATE - W_LNK - W_SPD - W_DUP - W_MAC - 8))
[ $W_MODEL -lt 10 ] && W_MODEL=10

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
  local dev="$1" link carr
  carr=$(rd "/sys/class/net/$dev/carrier")
  case "$carr" in
    1) echo "yes"; return 0 ;;
    0) echo "no";  return 0 ;;
  esac

  # The kernel returns EINVAL for carrier while an interface is admin-down, so
  # an unreadable value is not "unknown" - ethtool still reports the real state.
  link=$(run ethtool "$dev" | awk -F": " '/Link detected:/{print $2}')
  [ -z "$link" ] && link="-"
  echo "$link"
}

# Get speed/duplex for physical NICs
speed_duplex_for_phy() {
  local dev="$1" et speed duplex
  et="$(run ethtool "$dev")"
  speed=$(printf "%s" "$et" | awk -F": " '/Speed:/{print $2}')
  duplex=$(printf "%s" "$et" | awk -F": " '/Duplex:/{print $2}')
  case "$speed" in ""|Unknown*|*"255"*) speed="-" ;; esac
  case "$duplex" in ""|Unknown*|unknow) duplex="-" ;; esac
  echo "$speed|$duplex"
}

# Resolve the PCI address behind a netdev, e.g. 0000:17:00.0 (empty if not PCI-backed)
pci_addr_for_dev() {
  local dev="$1" path base
  path=$(run readlink -f "/sys/class/net/$dev/device")
  [ -n "$path" ] || return 0
  base=$(basename "$path")
  # Virtual/USB/platform NICs resolve to something that is not a PCI BDF
  [[ "$base" =~ ^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-9a-fA-F]$ ]] || return 0
  printf '%s' "$base"
}

# Look up "<vendor> <device>" for a NIC from the cached lspci output
model_for_dev() {
  local dev="$1" addr line vendor device
  addr=$(pci_addr_for_dev "$dev")
  [ -n "$addr" ] || { echo "-"; return 0; }

  line=$(printf '%s\n' "$LSPCI_DATA" | grep -m1 "^${addr} ")
  [ -n "$line" ] || { echo "-"; return 0; }

  # lspci -mm quotes each field: <bdf> "class" "vendor" "device" -rXX "subvendor" "subdevice"
  vendor=$(printf '%s' "$line" | awk -F'"' '{print $4}')
  device=$(printf '%s' "$line" | awk -F'"' '{print $6}')

  # Shorten well-known vendor strings so the model still fits the column
  case "$vendor" in
    Intel*)                    vendor="Intel" ;;
    Mellanox*)                 vendor="Mellanox" ;;
    Broadcom*)                 vendor="Broadcom" ;;
    Realtek*)                  vendor="Realtek" ;;
    "Advanced Micro Devices"*) vendor="AMD" ;;
    Solarflare*)               vendor="Solarflare" ;;
    Chelsio*)                  vendor="Chelsio" ;;
    QLogic*)                   vendor="QLogic" ;;
    Emulex*)                   vendor="Emulex" ;;
    VMware*)                   vendor="VMware" ;;
    "Red Hat"*)                vendor="Red Hat" ;;
  esac

  if [ -n "$vendor" ] || [ -n "$device" ]; then
    printf '%s %s\n' "$vendor" "$device"
  else
    echo "-"
  fi
}

# List members (bridge ports or bond slaves), filtering out temporary/ephemeral devices
members_of() {
  local dev="$1" list=()
  # Bridge members
  if [ -d "/sys/class/net/$dev/brif" ]; then
    local m
    log_note "brif of $dev: $(echo /sys/class/net/$dev/brif/* | xargs -n1 basename 2>/dev/null | xargs echo)"
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
    for b in $(rd "/sys/class/net/$dev/bonding/slaves"); do
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
  has_ip=$(run ip -4 -o addr show dev "$dev" | awk '{print $4}' | head -n1)
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
# Query lspci once and cache it; per-NIC lookups are then pure text matching
if [ "$SHOW_MODEL" -eq 1 ]; then
  if command -v lspci >/dev/null 2>&1; then
    LSPCI_DATA=$(run lspci -D -mm)
  else
    SHOW_MODEL=0
    log_note "lspci not found, MODEL column disabled"
    printf "Note: lspci not found, MODEL column disabled.\n" >&2
  fi
fi

log_note "--- section 1: physical NICs ---"
pad IFACE $W_IF; printf " "; pad TYPE $W_TP; printf " "; pad STATE $W_STATE; printf " "
pad LNK $W_LNK; printf " "; pad SPEED $W_SPD; printf " "; pad DUPLX $W_DUP; printf " "; pad MAC $W_MAC
if [ "$SHOW_MODEL" -eq 1 ]; then printf "  "; pad MODEL $W_MODEL; fi
printf "\n"

netdevs=$(run ls -1 /sys/class/net | sort)

for dev in $netdevs; do
  tp=$(get_type "$dev")
  [[ "$tp" != "PHY" ]] && continue  # Attribute-based; supports pinned nic0/nic1
  operstate=$(rd "/sys/class/net/$dev/operstate"); [ -z "$operstate" ] && operstate="-"
  link=$(link_for_dev "$dev")
  IFS="|" read -r speed duplex < <(speed_duplex_for_phy "$dev")
  mac=$(rd "/sys/class/net/$dev/address"); [ -z "$mac" ] && mac="-"
  [ "$SHOW_MODEL" -eq 1 ] && model=$(model_for_dev "$dev")

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
  pad "$mac"    $W_MAC
  if [ "$SHOW_MODEL" -eq 1 ]; then printf "  "; pad "$model" $W_MODEL; fi
  printf "\n"
done

echo

# ===== Section 2: Bridges/Bonds =====
log_note "--- section 2: bridges/bonds ---"
pad IFACE $W_IF; printf " "; pad TYPE $W_TP; printf " "; pad IPV4 $W_IP; printf " "; pad "MEMBERS" $W_MEM; printf "\n"

for dev in $netdevs; do
  tp=$(get_type "$dev")
  [[ "$tp" != "BR" && "$tp" != "BOND" ]] && continue

  is_important_bridge "$dev" || continue

  ip=$(run ip -4 -o addr show dev "$dev" | awk '{print $4}' | head -n1)
  [ -z "$ip" ] && ip="-"
  members=$(members_of "$dev")

  pad "$dev" $W_IF; printf " "
  pad "$tp"  $W_TP; printf " "
  pad "$ip"  $W_IP; printf " "
  pad "$members" $W_MEM; printf "\n"
done

log_note "--- end of run ---"
