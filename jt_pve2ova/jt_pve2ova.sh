#!/usr/bin/env bash
##########################################################################
#  pve2ova.sh – Convert a PVE VM into Thin-provisioned OVA for ESXi
#
#  Author    : Jason Cheng  (Jason Tools Co., Ltd.)
#  E-mail    : jason@jason.tools
#
#  License   : Provided “as-is” with no warranty. You may modify or
#              redistribute provided this header remains intact.
##########################################################################

set -euo pipefail

### ---------- Functions -------------------------------------------------
show_usage() {
cat <<'USAGE'
Usage:  pve2ova.sh <VMID> <WORK_DIR> <ESXI_VERSION> [MODE]

  <VMID>         PVE virtual machine ID, e.g. 203
  <WORK_DIR>     Temporary working directory for output files
  <ESXI_VERSION> Target ESXi version (8.0 | 7.0u3 | 7.0 | 6.7 | 6.5)
  [MODE]         keep  -> keep VMX/VMDK after OVA built
                 clean -> delete temp files  (default)
USAGE
}

error() { echo "Error: $*" >&2; exit 1; }

### ---------- 1. Args ---------------------------------------------------
[[ $# -eq 1 && $1 == "-h" ]] && { show_usage; exit 0; }
[[ $# -lt 3 || $# -gt 4 ]] && { show_usage; exit 1; }

VMID="$1"; WORKDIR="$(readlink -f "$2")"; ESXIVER_RAW="$3"; MODE="${4:-clean}"
[[ $MODE =~ ^(keep|clean)$ ]] || error "MODE must be keep|clean"

OVFTOOL="/opt/ovftool/ovftool"
PVE_CONF="/etc/pve/qemu-server/${VMID}.conf"
STORAGE_CFG="/etc/pve/storage.cfg"

### ---------- 2. Validation --------------------------------------------
[[ -x $OVFTOOL ]]          || error "ovftool not found at /opt/ovftool/"
[[ -f $PVE_CONF ]]         || error "PVE config $PVE_CONF not found"
[[ -f $STORAGE_CFG ]]      || error "storage.cfg not found"
command -v qemu-img >/dev/null || error "qemu-img not installed"

printf "INFO: Detected qemu-img %s\n" "$(qemu-img --version | awk '{print $3}')"
mkdir -p "$WORKDIR"

### ---------- 3. ESXi → virtualHW --------------------------------------
shopt -s nocasematch
case $ESXIVER_RAW in
  8*)                 VHW=20;;
  7.0u*|7.0u[0-9]*|7.0u) VHW=19;;
  7*)                 VHW=17;;
  6.7*)               VHW=17;;
  6.5*)               VHW=13;;
  *) error "Unsupported ESXi version '$ESXIVER_RAW'";;
esac
shopt -u nocasematch
printf "INFO: Target ESXi %s -> virtualHW %d\n" "$ESXIVER_RAW" "$VHW"

### ---------- 4. Parse PVE config --------------------------------------
name=$(grep -E '^name:' "$PVE_CONF" | cut -d' ' -f2-)
cores=$(grep -E '^cores:' "$PVE_CONF" | cut -d' ' -f2 || echo 1)
memory=$(grep -E '^memory:' "$PVE_CONF" | cut -d' ' -f2 || echo 1024)
ostype=$(grep -E '^ostype:' "$PVE_CONF" | cut -d' ' -f2 || echo l26)
uuid=$(grep -E '^smbios1:' "$PVE_CONF" | sed -n 's/.*uuid=\([0-9a-fA-F-]*\).*/\1/p')
[[ -z $uuid ]] && uuid=$(uuidgen)
firmware=$(grep -q '^bios: ovmf' "$PVE_CONF" && echo efi || echo bios)

printf "INFO: VM '%s' BIOS=%s vCPU=%s RAM=%sMB\n" \
        "${name:-pve-vm$VMID}" "$firmware" "$cores" "$memory"

case $ostype in
  l26|l24|l32) guestos=ubuntu-64;;  win*) guestos=windows9-64;;  *) guestos=otherlinux-64;;
esac

### ---------- 5. Collect disks -----------------------------------------
set +e
declare -a src_disks vmdk_files vmx_lines sizes
idx=0
while IFS= read -r line; do
  [[ $line =~ media=cdrom ]] && { echo "INFO: Skip optical: $line"; continue; }
  grep -q 'size=' <<<"$line" || { echo "INFO: Skip non-disk: $line"; continue; }

  raw=${line#*: }; storage=${raw%%:*}; rest=${raw#*:}; volname=${rest%%,*}
  size_field=$(grep -oP '(?<=size=)[^,]+' <<<"$raw")
  size_bytes=$(numfmt --from=iec "$size_field" 2>/dev/null || numfmt --from=si "$size_field")

  stype=$(awk -v s="$storage" '$1=="storage"&&$2==s{getline;print $2;exit}' "$STORAGE_CFG")
  [[ -z $stype ]] && stype=dir

  if [[ $stype == rbd ]]; then
    src="rbd:${storage}/${volname}"
  else
    src=$(pvesm path "${storage}:${volname}" 2>/dev/null)
    [[ -z $src ]] && { echo "WARN: pvesm path failed, fallback."; src="/var/lib/vz/images/$VMID/${volname##*/}"; }
  fi

  dest="disk${idx}.vmdk"
  src_disks+=("$src"); vmdk_files+=("$dest"); sizes+=("$size_bytes")
  vmx_lines+=("scsi0:${idx}.present = \"TRUE\"")
  vmx_lines+=("scsi0:${idx}.fileName = \"${dest}\"")
  vmx_lines+=("scsi0:${idx}.deviceType = \"disk\"")
  echo "INFO: Added disk $src ($size_field)"
  ((idx++))
done < <(grep -E '^[[:space:]]*(scsi|sata|ide|virtio)[0-9]+:' "$PVE_CONF")
set -e
[[ ${#src_disks[@]} -eq 0 ]] && error "No valid data disks found"

### ---------- 6. Capacity check ----------------------------------------
need=0; for s in "${sizes[@]}"; do ((need+=s)); done; need=$((need*12/10))
avail=$(df --output=avail -B1 "$WORKDIR" | tail -1)
printf "INFO: Required space ~%s, Free %s\n" "$(numfmt --to=iec "$need")" "$(numfmt --to=iec "$avail")"
(( avail >= need )) || error "Not enough free space in $WORKDIR"

### ---------- 7. Convert disks -----------------------------------------
echo "INFO: Converting disks to streamOptimized VMDK..."
for i in "${!src_disks[@]}"; do
  echo "INFO: [${i}/${#src_disks[@]}] ${src_disks[$i]} -> ${vmdk_files[$i]}"
  qemu-img convert -p -f raw "${src_disks[$i]}" \
    -O vmdk -o subformat=streamOptimized,adapter_type=lsilogic,compat6 \
    "${WORKDIR}/${vmdk_files[$i]}"
done
echo "INFO: All disks converted."

### ---------- 8. Generate VMX -----------------------------------------
vmx="${WORKDIR}/${name:-pve-vm$VMID}.vmx"
{
cat <<EOF
.encoding = "UTF-8"
config.version = "8"
virtualHW.version = "$VHW"
displayName = "${name:-pve-vm$VMID}"
guestOS = "$guestos"
firmware = "$firmware"
uuid.bios = "$uuid"
numvcpus = "$cores"
cpuid.coresPerSocket = "$cores"
memsize = "$memory"
scsi0.present = "TRUE"
scsi0.virtualDev = "lsilogic"
EOF
for l in "${vmx_lines[@]}"; do echo "$l"; done
cat <<'EOF'
ethernet0.present = "TRUE"
ethernet0.virtualDev = "vmxnet3"
ethernet0.addressType = "generated"
EOF
} > "$vmx"
echo "INFO: VMX generated -> $vmx"

### ---------- 9. Build OVA & cleanup -----------------------------------
ova="${WORKDIR}/${name:-pve-vm$VMID}.ova"
echo "INFO: Packing OVA with ovftool..."
"$OVFTOOL" --acceptAllEulas --diskMode=thin "$vmx" "$ova"
echo "SUCCESS: OVA ready -> $ova"

if [[ $MODE == clean ]]; then
  echo "INFO: Cleaning temporary VMX/VMDK files..."
  rm -f "$vmx" "${WORKDIR}/"disk*.vmdk
  echo "INFO: Temporary files removed."
else
  echo "INFO: Temporary VMX/VMDK kept as requested."
fi

