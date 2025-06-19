#!/usr/bin/env bash
##########################################################################
#  jt_pve2ova.sh – Convert a Proxmox-VE VM to a thin-provisioned OVA
#                   suitable for VMware ESXi
#
#  Author   : Jason Cheng  (Jason Tools Co., Ltd.)
#  E-mail   : jason@jason.tools
#
#  License  : Provided “as-is” with no warranty. You may modify or
#             redistribute provided this header remains intact.
#
#  Version  : 1.1  (2025-06-19)
#             * Fix duplicate disks / fields when the VM has snapshots
##########################################################################
set -euo pipefail

#───────────────────────── helper functions ─────────────────────────────#
show_usage() {
cat <<'USAGE'
Usage:  jt_pve2ova.sh <VMID> <WORK_DIR> <ESXI_VERSION> [MODE]

  <VMID>         Proxmox-VE virtual-machine ID (e.g. 203)
  <WORK_DIR>     Temporary working directory for output files
  <ESXI_VERSION> Target ESXi version (8.0 | 7.0u3 | 7.0 | 6.7 | 6.5)
  [MODE]         keep  → keep VMX/VMDK files after OVA is built
                 clean → delete temporary files  (default)
USAGE
}

error() { echo "Error: $*" >&2; exit 1; }

#───────────────────────── argument parsing ─────────────────────────────#
[[ $# -eq 1 && $1 == "-h" ]] && { show_usage; exit 0; }
[[ $# -lt 3 || $# -gt 4 ]] && { show_usage; exit 1; }

VMID="$1"
WORKDIR="$(readlink -f "$2")"
ESXIVER_RAW="$3"
MODE="${4:-clean}"
[[ $MODE =~ ^(keep|clean)$ ]] || error "MODE must be keep | clean"

OVFTOOL="/opt/ovftool/ovftool"
STORAGE_CFG="/etc/pve/storage.cfg"

#───────────────────────── sanity checks ────────────────────────────────#
[[ -x $OVFTOOL ]]          || error "ovftool not found at /opt/ovftool/"
[[ -f $STORAGE_CFG ]]      || error "storage.cfg not found"
command -v qemu-img >/dev/null || error "qemu-img not installed"
command -v qm       >/dev/null || error "qm command not found"

printf "INFO: Detected qemu-img %s\n" "$(qemu-img --version | awk '{print $3}')"
mkdir -p "$WORKDIR"

#───────────────── obtain a snapshot-free VM configuration ──────────────#
# Proxmox 7.4+ provides `qm config --current`; on older versions we
# strip snapshot sections from the raw config file with awk.
if qm config "$VMID" --current &>/dev/null; then
  CFG_CMD=(qm config "$VMID" --current)
else
  CFG_FILE="/etc/pve/qemu-server/${VMID}.conf"
  [[ -f $CFG_FILE ]] || error "VM config $CFG_FILE not found"
  CFG_CMD=(awk 'BEGIN{s=0} /^\[/{s=1} !s' "$CFG_FILE")
fi

# Helper: return the first matching field value
cfg() { "${CFG_CMD[@]}" | grep -m1 -E "^$1:" | cut -d' ' -f2- ; }

#───────────────────────── parse VM metadata ────────────────────────────#
name="$(cfg name)"
cores="$(cfg cores   || echo 1)"
memory="$(cfg memory || echo 1024)"
ostype="$(cfg ostype || echo l26)"
uuid="$("${CFG_CMD[@]}" | grep -m1 -E '^smbios1:' | \
        sed -n 's/.*uuid=\([0-9a-fA-F-]*\).*/\1/p')"
[[ -z $uuid ]] && uuid=$(uuidgen)

if "${CFG_CMD[@]}" | grep -q '^bios:[[:space:]]*ovmf'; then
  firmware=efi
else
  firmware=bios
fi

printf "INFO: VM '%s' BIOS=%s vCPU=%s RAM=%s MB\n" \
        "${name:-pve-vm$VMID}" "$firmware" "$cores" "$memory"

case $ostype in
  l26|l24|l32) guestos=ubuntu-64;;
  win*)        guestos=windows9-64;;
  *)           guestos=otherlinux-64;;
esac

#──────────────── ESXi version → virtualHW version ──────────────────────#
shopt -s nocasematch
case $ESXIVER_RAW in
  8*)                   VHW=20;;
  7.0u*|7.0u[0-9]*|7.0u) VHW=19;;
  7*)                   VHW=17;;
  6.7*)                 VHW=17;;
  6.5*)                 VHW=13;;
  *) error "Unsupported ESXi version '$ESXIVER_RAW'";;
esac
shopt -u nocasematch
printf "INFO: Target ESXi %s → virtualHW %d\n" "$ESXIVER_RAW" "$VHW"

#────────────────────── collect data disks ──────────────────────────────#
set +e
declare -a src_disks vmdk_files vmx_lines sizes
declare -A seen_vol                                    # deduplication
idx=0
while IFS= read -r line; do
  [[ $line =~ media=cdrom ]] && { echo "INFO: Skip optical: $line"; continue; }
  grep -q 'size=' <<<"$line" || { echo "INFO: Skip non-disk: $line"; continue; }

  raw=${line#*: }; storage=${raw%%:*}; rest=${raw#*:}; volname=${rest%%,*}
  # Skip duplicates originating from snapshot sections
  [[ -n ${seen_vol[$volname]:-} ]] && \
      { echo "INFO: Skip duplicate $volname"; continue; }
  seen_vol[$volname]=1

  size_field=$(grep -oP '(?<=size=)[^,]+' <<<"$raw")
  size_bytes=$(numfmt --from=iec "$size_field" 2>/dev/null || \
               numfmt --from=si  "$size_field")

  stype=$(awk -v s="$storage" '$1=="storage" && $2==s {getline; print $2; exit}' \
          "$STORAGE_CFG")
  [[ -z $stype ]] && stype=dir

  if [[ $stype == rbd ]]; then
    src="rbd:${storage}/${volname}"
  else
    src=$(pvesm path "${storage}:${volname}" 2>/dev/null)
    [[ -z $src ]] && {
      echo "WARN: pvesm path failed; fallback to default image directory."
      src="/var/lib/vz/images/$VMID/${volname##*/}"
    }
  fi

  dest="disk${idx}.vmdk"
  src_disks+=("$src"); vmdk_files+=("$dest"); sizes+=("$size_bytes")
  vmx_lines+=("scsi0:${idx}.present = \"TRUE\"")
  vmx_lines+=("scsi0:${idx}.fileName = \"${dest}\"")
  vmx_lines+=("scsi0:${idx}.deviceType = \"disk\"")
  echo "INFO: Added disk $src ($size_field)"
  ((idx++))
done < <("${CFG_CMD[@]}" | \
         grep -E '^[[:space:]]*(scsi|sata|ide|virtio)[0-9]+:')
set -e
[[ ${#src_disks[@]} -eq 0 ]] && error "No valid data disks found"

#────────────── verify enough workspace capacity (20 % headroom) ───────#
need=0; for s in "${sizes[@]}"; do ((need+=s)); done; need=$((need*12/10))
avail=$(df --output=avail -B1 "$WORKDIR" | tail -1)
printf "INFO: Required space ≈%s, available %s\n" \
        "$(numfmt --to=iec "$need")" "$(numfmt --to=iec "$avail")"
(( avail >= need )) || error "Not enough free space in $WORKDIR"

#──────────────── convert each disk to streamOptimized VMDK ─────────────#
echo "INFO: Converting disks to streamOptimized VMDK…"
for i in "${!src_disks[@]}"; do
  echo "INFO: [${i}/${#src_disks[@]}] ${src_disks[$i]} → ${vmdk_files[$i]}"
  qemu-img convert -p -f raw "${src_disks[$i]}" \
    -O vmdk -o subformat=streamOptimized,adapter_type=lsilogic,compat6 \
    "${WORKDIR}/${vmdk_files[$i]}"
done
echo "INFO: All disks converted."

#────────────────────── generate the VMX file ───────────────────────────#
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
numvcpus             = "$cores"
cpuid.coresPerSocket = "$cores"
memsize              = "$memory"
scsi0.present        = "TRUE"
scsi0.virtualDev     = "lsilogic"
EOF
for l in "${vmx_lines[@]}"; do echo "$l"; done
cat <<'EOF'
ethernet0.present    = "TRUE"
ethernet0.virtualDev = "vmxnet3"
ethernet0.addressType= "generated"
EOF
} > "$vmx"
echo "INFO: VMX generated → $vmx"

#──────────────────────── build the OVA package ─────────────────────────#
ova="${WORKDIR}/${name:-pve-vm$VMID}.ova"
echo "INFO: Packing OVA with ovftool…"
"$OVFTOOL" --acceptAllEulas --diskMode=thin "$vmx" "$ova"
echo "SUCCESS: OVA ready → $ova"

#────────────────────────── cleanup section ─────────────────────────────#
if [[ $MODE == clean ]]; then
  echo "INFO: Removing temporary VMX/VMDK files…"
  rm -f "$vmx" "${WORKDIR}/"disk*.vmdk
  echo "INFO: Temporary files removed."
else
  echo "INFO: Temporary VMX/VMDK files kept as requested."
fi
