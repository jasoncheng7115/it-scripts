#!/usr/bin/env bash
##########################################################################
#  jt_pve2ova.sh - Convert a Proxmox-VE VM to a thin-provisioned OVA
#                  suitable for VMware ESXi
#
#  Author   : Jason Cheng  (Jason Tools Co., Ltd.)
#  E-mail   : jason@jason.tools
#
#  License  : Provided "as-is" with no warranty. You may modify or
#             redistribute provided this header remains intact.
#
#  Version  : 1.4  (2025-11-25)
#             * Fix storage type detection for LVM/LVM-thin
#             * Activate inactive LVM/LVM-thin LVs on PVE 9 when VM is off
#             * Correct CPU sockets/cores/vCPU mapping in generated VMX
#             * Do not abort when optional fields (vcpus, smbios1) are missing
#             * ASCII-only output
##########################################################################
set -euo pipefail

# ------------------------ helper functions ----------------------------- #

show_usage() {
cat <<'USAGE'
Usage:  jt_pve2ova.sh <VMID> <WORK_DIR> <ESXI_VERSION> [MODE]

  <VMID>         Proxmox-VE virtual-machine ID (e.g. 203)
  <WORK_DIR>     Temporary working directory for output files
  <ESXI_VERSION> Target ESXi version (8.0 | 7.0u3 | 7.0 | 6.7 | 6.5)
  [MODE]         keep  -> keep VMX/VMDK files after OVA is built
                 clean -> delete temporary files  (default)
USAGE
}

error() { echo "Error: $*" >&2; exit 1; }

# ------------------------ argument parsing ----------------------------- #

[[ $# -eq 1 && $1 == "-h" ]] && { show_usage; exit 0; }
[[ $# -lt 3 || $# -gt 4 ]] && { show_usage; exit 1; }

VMID="$1"
WORKDIR="$(readlink -f "$2")"
ESXIVER_RAW="$3"
MODE="${4:-clean}"

[[ $VMID =~ ^[0-9]+$ ]] || error "VMID must be numeric"
[[ $MODE =~ ^(keep|clean)$ ]] || error "MODE must be keep | clean"

OVFTOOL="/opt/ovftool/ovftool"
STORAGE_CFG="/etc/pve/storage.cfg"

# ------------------------ sanity checks -------------------------------- #

[[ -x $OVFTOOL ]]     || error "ovftool not found at $OVFTOOL"
[[ -f $STORAGE_CFG ]] || error "storage.cfg not found at $STORAGE_CFG"

command -v qemu-img  >/dev/null || error "qemu-img not installed"
command -v qm        >/dev/null || error "qm command not found"
command -v pvesm     >/dev/null || error "pvesm command not found"
command -v lvdisplay >/dev/null || error "lvdisplay command not found"
command -v lvchange  >/dev/null || error "lvchange command not found"
command -v numfmt    >/dev/null || error "numfmt command not found"

qemu_ver="$(qemu-img --version | head -n1 | awk '{print $3}')"
printf "INFO: Detected qemu-img %s\n" "$qemu_ver"

mkdir -p "$WORKDIR"

# ------------- obtain a snapshot-free VM configuration ---------------- #

if qm config "$VMID" --current &>/dev/null; then
  CFG_CMD=(qm config "$VMID" --current)
else
  CFG_FILE="/etc/pve/qemu-server/${VMID}.conf"
  [[ -f $CFG_FILE ]] || error "VM config $CFG_FILE not found"
  CFG_CMD=(awk '
    BEGIN { insnap=0 }
    /^\[snapshot/ { insnap=1; next }
    /^\[/ && $0 !~ /^\[snapshot/ { insnap=0 }
    !insnap { print }
  ' "$CFG_FILE")
fi

cfg() {
  local key="$1"
  "${CFG_CMD[@]}" | awk -F': ' -v k="$key" '
    $1 == k {
      $1 = ""
      sub(/^ /, "", $0)
      print
      exit
    }
  '
}

# ------------------------ parse VM metadata ---------------------------- #

name="$(cfg name)"
sockets="$(cfg sockets)"
cores="$(cfg cores)"
vcpus_conf="$(cfg vcpus)"
memory="$(cfg memory)"
ostype="$(cfg ostype)"

uuid="$("${CFG_CMD[@]}" | awk -F'[, ]' '
  /^smbios1:/ {
    for (i = 1; i <= NF; i++) {
      if ($i ~ /^uuid=/) {
        sub(/^uuid=/, "", $i)
        print $i
        exit
      }
    }
  }
')"

if [[ -z "${uuid:-}" ]]; then
  if command -v uuidgen >/dev/null 2>&1; then
    uuid="$(uuidgen)"
  elif [[ -r /proc/sys/kernel/random/uuid ]]; then
    uuid="$(cat /proc/sys/kernel/random/uuid)"
  else
    uuid="00000000-0000-0000-0000-000000000000"
  fi
fi

[[ -z "${sockets:-}" ]] && sockets=1
[[ -z "${cores:-}"   ]] && cores=1
[[ -z "${memory:-}"  ]] && memory=1024
[[ -z "${ostype:-}"  ]] && ostype="l26"

if [[ -n "${vcpus_conf:-}" ]]; then
  vcpus="$vcpus_conf"
else
  vcpus=$((sockets * cores))
fi

if "${CFG_CMD[@]}" | grep -q '^bios:[[:space:]]*ovmf'; then
  firmware="efi"
else
  firmware="bios"
fi

printf "INFO: VM '%s' BIOS=%s vCPU=%s (sockets=%s, cores=%s) RAM=%s MB\n" \
  "${name:-pve-vm$VMID}" "$firmware" "$vcpus" "$sockets" "$cores" "$memory"

case "$ostype" in
  l26|l24|l32) guestos="ubuntu-64";;
  win*)        guestos="windows9-64";;
  *)           guestos="otherlinux-64";;
esac

# ---------------- ESXi version -> virtualHW version -------------------- #

shopt -s nocasematch
case "$ESXIVER_RAW" in
  8*)                     VHW=20;;
  7.0u*|7.0u[0-9]*|7.0u)  VHW=19;;
  7*)                     VHW=17;;
  6.7*)                   VHW=17;;
  6.5*)                   VHW=13;;
  *) error "Unsupported ESXi version '$ESXIVER_RAW'";;
esac
shopt -u nocasematch

printf "INFO: Target ESXi %s -> virtualHW %d\n" "$ESXIVER_RAW" "$VHW"

# ---------------------- collect data disks ----------------------------- #

set +e
declare -a src_disks vmdk_files vmx_lines sizes
declare -A seen_vol
idx=0

while IFS= read -r line; do
  [[ $line =~ media=cdrom ]] && { echo "INFO: Skip optical: $line"; continue; }
  echo "$line" | grep -q 'size=' || { echo "INFO: Skip non-disk: $line"; continue; }

  raw=${line#*: }
  storage=${raw%%:*}
  rest=${raw#*:}
  volname=${rest%%,*}

  if [[ -n "${seen_vol[$volname]:-}" ]]; then
    echo "INFO: Skip duplicate $volname"
    continue
  fi
  seen_vol[$volname]=1

  size_field="$(echo "$raw" | grep -oP '(?<=size=)[^,]+')"
  size_bytes="$(numfmt --from=iec "$size_field" 2>/dev/null || \
                numfmt --from=si  "$size_field")"

  # Detect storage type by matching "type: storageid" lines
  stype="$(awk -v s="$storage" '
    $2 == s && $1 ~ /:$/ {
      t = $1
      sub(":", "", t)
      print t
      exit
  }' "$STORAGE_CFG")"
  [[ -z "$stype" ]] && stype="dir"

  if [[ "$stype" == "rbd" ]]; then
    src="rbd:${storage}/${volname}"
  else
    src="$(pvesm path "${storage}:${volname}" 2>/dev/null)"
    if [[ -z "$src" ]]; then
      echo "WARN: pvesm path failed; fallback to default image directory."
      src="/var/lib/vz/images/$VMID/${volname##*/}"
    fi

    # For LVM / LVM-thin volumes, on PVE 9 the LV can be inactive when the VM
    # is powered off. Use the VG/LV name to check and activate.
    if [[ "$stype" == lvm* ]]; then
      lv_id="${src#/dev/}"   # e.g. ovatest/vm-156-disk-0
      if lvdisplay "$lv_id" 2>/dev/null | grep -q "LV Status *NOT available"; then
        echo "INFO: LV $lv_id is inactive (NOT available); activating with lvchange -ay..."
        if ! lvchange -ay "$lv_id" 2>/dev/null; then
          echo "WARN: lvchange -ay $lv_id failed; trying /dev/$lv_id..."
          lvchange -ay "/dev/$lv_id" 2>/dev/null || \
            error "Unable to activate LV for $lv_id; please check LVM state."
        fi
      fi
      # Ensure src points to a device path after activation
      if [[ ! -e "$src" ]]; then
        src="/dev/$lv_id"
      fi
    fi
  fi

  dest="disk${idx}.vmdk"
  src_disks+=("$src")
  vmdk_files+=("$dest")
  sizes+=("$size_bytes")
  vmx_lines+=("scsi0:${idx}.present = \"TRUE\"")
  vmx_lines+=("scsi0:${idx}.fileName = \"${dest}\"")
  vmx_lines+=("scsi0:${idx}.deviceType = \"disk\"")

  echo "INFO: Added disk $src ($size_field)"
  ((idx++))
done < <("${CFG_CMD[@]}" | grep -E '^[[:space:]]*(scsi|sata|ide|virtio)[0-9]+:')

set -e

[[ ${#src_disks[@]} -eq 0 ]] && error "No valid data disks found"

# ---------------- verify enough workspace capacity -------------------- #

need=0
for s in "${sizes[@]}"; do
  ((need += s))
done
need=$((need * 12 / 10))   # +20% headroom

avail="$(df --output=avail -B1 "$WORKDIR" | tail -n1)"

printf "INFO: Required space ~%s, available %s\n" \
  "$(numfmt --to=iec "$need")" "$(numfmt --to=iec "$avail")"

(( avail >= need )) || error "Not enough free space in $WORKDIR"

# --------------- convert each disk to streamOptimized VMDK ------------ #

echo "INFO: Converting disks to streamOptimized VMDK..."
for i in "${!src_disks[@]}"; do
  echo "INFO: [${i}/${#src_disks[@]}] ${src_disks[$i]} -> ${vmdk_files[$i]}"
  qemu-img convert -p -f raw "${src_disks[$i]}" \
    -O vmdk -o subformat=streamOptimized,adapter_type=lsilogic,compat6 \
    "${WORKDIR}/${vmdk_files[$i]}"
done
echo "INFO: All disks converted."

# ---------------------- generate the VMX file -------------------------- #

vmx="${WORKDIR}/${name:-pve-vm$VMID}.vmx"

{
  cat <<EOF
.encoding            = "UTF-8"
config.version       = "8"
virtualHW.version    = "$VHW"
displayName          = "${name:-pve-vm$VMID}"
guestOS              = "$guestos"
firmware             = "$firmware"
uuid.bios            = "$uuid"
numvcpus             = "$vcpus"
cpuid.coresPerSocket = "$cores"
memsize              = "$memory"
scsi0.present        = "TRUE"
scsi0.virtualDev     = "lsilogic"
EOF

  for l in "${vmx_lines[@]}"; do
    echo "$l"
  done

  cat <<'EOF'
ethernet0.present    = "TRUE"
ethernet0.virtualDev = "vmxnet3"
ethernet0.addressType= "generated"
EOF
} > "$vmx"

echo "INFO: VMX generated -> $vmx"

# ------------------------ build the OVA package ------------------------ #

ova="${WORKDIR}/${name:-pve-vm$VMID}.ova"

echo "INFO: Packing OVA with ovftool..."
"$OVFTOOL" --acceptAllEulas --diskMode=thin "$vmx" "$ova"
echo "SUCCESS: OVA ready -> $ova"

# ----------------------------- cleanup -------------------------------- #

if [[ "$MODE" == "clean" ]]; then
  echo "INFO: Removing temporary VMX/VMDK files..."
  rm -f "$vmx" "${WORKDIR}/"disk*.vmdk
  echo "INFO: Temporary files removed."
else
  echo "INFO: Temporary VMX/VMDK files kept as requested."
fi
