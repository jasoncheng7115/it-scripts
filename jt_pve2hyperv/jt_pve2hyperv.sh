#!/usr/bin/env bash
##########################################################################
#  jt_pve2hyperv.sh - Convert a Proxmox-VE VM to dynamic VHDX disks
#                     suitable for Microsoft Hyper-V
#
#  Author   : Jason Cheng  (Jason Tools Co., Ltd.)
#  E-mail   : jason@jason.tools
#
#  License  : Provided "as-is" with no warranty. You may modify or
#             redistribute provided this header remains intact.
#
#  Version  : 1.2  (2026-06-01)
#             * Fix RBD conversion failure ("error connecting" / DNS SRV
#               ceph-mon): resolve the RBD source via "pvesm path", which
#               emits a complete librbd URI (pool, conf/mon_host, id,
#               keyring) that qemu-img can open, instead of the bare
#               "rbd:<storeid>/<vol>". Falls back to reconstructing the
#               URI from storage.cfg if pvesm path is unavailable.
#
#  Version  : 1.1  (2026-05-28)
#             * Carry over PVE VM description into Hyper-V VM notes
#               (written to a separate UTF-8 <vm>_notes.txt file and
#               applied by the generated PowerShell script via
#               Set-VM -Notes). PS1 remains pure ASCII.
#
#             1.0  (2026-05-28)
#             * Initial release
#             * Convert PVE VM disks (RBD/dir/ZFS/LVM/LVM-thin) to
#               dynamic (thin) VHDX via qemu-img
#             * Map PVE BIOS/UEFI -> Hyper-V Generation 1/2
#             * Generate customer-facing setup guide (EN or zh-TW)
#             * Generate PowerShell script to auto-create the VM and
#               attach VHDX files on the Hyper-V host
#             * PowerShell script is pure ASCII (no BOM, no CJK)
##########################################################################
set -euo pipefail

VERSION="1.2"

# ------------------------ helper functions ----------------------------- #

show_usage() {
cat <<EOF
jt_pve2hyperv.sh v${VERSION} - Convert a Proxmox-VE VM to Hyper-V VHDX

Usage:  jt_pve2hyperv.sh <VMID> <WORK_DIR> <LANG> [MODE]

  <VMID>      Proxmox-VE virtual-machine ID (e.g. 203)
  <WORK_DIR>  Working directory for output files
  <LANG>      Setup guide language: en | zh-TW
  [MODE]      all   -> convert disks to VHDX + generate guide + ps1 (default)
              guide -> generate guide + ps1 only (no VHDX conversion)
EOF
}

show_version() { echo "jt_pve2hyperv.sh v${VERSION}"; }
error() { echo "Error: $*" >&2; exit 1; }

# ------------------------ argument parsing ----------------------------- #

[[ $# -eq 1 && $1 == "-h" ]] && { show_usage; exit 0; }
[[ $# -eq 1 && $1 == "-v" ]] && { show_version; exit 0; }
[[ $# -lt 3 || $# -gt 4 ]] && { show_usage; exit 1; }

VMID="$1"
WORKDIR="$(readlink -f "$2")"
LANG_RAW="$3"
MODE="${4:-all}"

[[ $VMID =~ ^[0-9]+$ ]] || error "VMID must be numeric"
[[ $MODE =~ ^(all|guide)$ ]] || error "MODE must be all | guide"

case "$LANG_RAW" in
  en|EN|english|English)           GUIDE_LANG="en";;
  zh-TW|zh-tw|tw|TW|cht|CHT|zh|ZH) GUIDE_LANG="zh-TW";;
  *) error "LANG must be 'en' or 'zh-TW'";;
esac

STORAGE_CFG="/etc/pve/storage.cfg"

# ------------------------ sanity checks -------------------------------- #

[[ -f $STORAGE_CFG ]] || error "storage.cfg not found at $STORAGE_CFG"

command -v qm        >/dev/null || error "qm command not found"
command -v pvesm     >/dev/null || error "pvesm command not found"
command -v lvdisplay >/dev/null || error "lvdisplay command not found"
command -v lvchange  >/dev/null || error "lvchange command not found"
command -v numfmt    >/dev/null || error "numfmt command not found"

if [[ "$MODE" != "guide" ]]; then
  command -v qemu-img >/dev/null || error "qemu-img not installed"
  qemu_ver="$(qemu-img --version | head -n1 | awk '{print $3}')"
  printf "INFO: Detected qemu-img %s\n" "$qemu_ver"
else
  echo "INFO: Guide-only mode (no VHDX conversion)"
fi

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
    $1 == k { $1=""; sub(/^ /,"",$0); print; exit }
  '
}

# ------------------------ parse VM metadata ---------------------------- #

name="$(cfg name)"
sockets="$(cfg sockets)"
cores="$(cfg cores)"
vcpus_conf="$(cfg vcpus)"
memory="$(cfg memory)"
ostype="$(cfg ostype)"
description_raw="$(cfg description)"

# PVE stores description URL-encoded on a single line (e.g. spaces as %20,
# newlines as %0A). Decode it via perl (perl is a hard dependency of PVE
# itself, so safe to assume). Result may contain CJK / multi-line text and
# will be written to a separate UTF-8 file — NOT embedded in the .ps1.
description=""
if [[ -n "$description_raw" ]]; then
  if command -v perl >/dev/null 2>&1; then
    description="$(printf '%s' "$description_raw" | \
      perl -pe 's/%([0-9A-Fa-f]{2})/chr(hex($1))/ge' | tr -d '\000')"
  else
    echo "WARN: perl not found; VM description will be passed through URL-encoded."
    description="$description_raw"
  fi
  # trim leading/trailing whitespace
  description="$(printf '%s' "$description" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
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
  firmware="uefi"
  hv_generation=2
else
  firmware="bios"
  hv_generation=1
fi

case "$ostype" in
  l24|l26|l32) guest_kind="Linux";   is_linux_guest="true";;
  win11)       guest_kind="Windows 11";              is_linux_guest="false";;
  win10)       guest_kind="Windows 10";              is_linux_guest="false";;
  win8)        guest_kind="Windows 8/8.1/Server 2012"; is_linux_guest="false";;
  win7)        guest_kind="Windows 7/Server 2008 R2"; is_linux_guest="false";;
  wxp)         guest_kind="Windows XP/Server 2003";  is_linux_guest="false";;
  w2k)         guest_kind="Windows 2000";            is_linux_guest="false";;
  win*)        guest_kind="Windows";                 is_linux_guest="false";;
  *)           guest_kind="Other";                   is_linux_guest="false";;
esac

# original (possibly CJK) name for the .txt guide
vm_display_name="${name:-pve-vm$VMID}"

# ASCII-safe name for filenames and the .ps1 (ASCII-only constraint)
vmname_ascii="$(printf '%s' "$vm_display_name" | LC_ALL=C tr -c 'A-Za-z0-9._-' '_' )"
# collapse repeated underscores, trim leading/trailing underscores
vmname_ascii="$(echo "$vmname_ascii" | sed -E 's/_+/_/g; s/^_+//; s/_+$//')"
[[ -z "$vmname_ascii" ]] && vmname_ascii="pve-vm${VMID}"

printf "INFO: VM '%s' (ascii='%s') firmware=%s -> Hyper-V Gen %d  vCPU=%s (sockets=%s, cores=%s)  RAM=%s MB  guest=%s\n" \
  "$vm_display_name" "$vmname_ascii" "$firmware" "$hv_generation" "$vcpus" "$sockets" "$cores" "$memory" "$guest_kind"

# ---------------------- collect data disks ----------------------------- #

set +e
declare -a src_disks vhdx_files sizes src_formats disk_buses
declare -A seen_vol
idx=0

while IFS= read -r line; do
  [[ $line =~ media=cdrom ]] && { echo "INFO: Skip optical: $line"; continue; }

  prefix=${line%%:*}
  bus_dev=$(echo "$prefix" | tr -d '[:space:]')

  raw=${line#*: }
  storage=${raw%%:*}
  rest=${raw#*:}
  volname=${rest%%,*}

  if [[ -n "${seen_vol[$volname]:-}" ]]; then
    echo "INFO: Skip duplicate $volname"
    continue
  fi
  seen_vol[$volname]=1

  size_field="$(echo "$raw" | grep -oP '(?<=size=)[^,]+' 2>/dev/null || true)"
  fmt_field="$(echo "$raw" | grep -oP '(?<=format=)[^,]+' 2>/dev/null || true)"
  size_bytes=""
  src_fmt=""

  stype="$(awk -v s="$storage" '
    $2 == s && $1 ~ /:$/ { t=$1; sub(":","",t); print t; exit }
  ' "$STORAGE_CFG")"
  [[ -z "$stype" ]] && stype="dir"

  if [[ "$stype" == "rbd" ]]; then
    # A bare "rbd:pool/img" URI makes qemu-img fall back to /etc/ceph/ceph.conf
    # and DNS SRV monitor discovery, which fails on PVE. Prefer PVE's own
    # pvesm path(), which emits a fully-formed librbd connection string
    # (pool, mon_host, id, keyring, conf) that qemu-img can open directly.
    src="$(pvesm path "${storage}:${volname}" 2>/dev/null || true)"

    # If PVE returned nothing usable, or a krbd block device that isn't
    # currently mapped, reconstruct a librbd URI from storage.cfg instead.
    if [[ -z "$src" || ( "$src" == /dev/* && ! -e "$src" ) ]]; then
      # storage block header is "<type>: <storeid>" -> match $2, not $1.
      rbd_block="$(awk -v s="$storage" '
          $1 ~ /:$/ && $2 == s {grab=1; next}
          $1 ~ /:$/            {grab=0}
          grab {print}
      ' "$STORAGE_CFG")"

      rbd_pool="$(echo "$rbd_block" | awk '$1=="pool"{print $2; exit}')"
      [[ -z "$rbd_pool" ]] && rbd_pool="$storage"

      rbd_user="$(echo "$rbd_block" | awk '$1=="username"{print $2; exit}')"
      [[ -z "$rbd_user" ]] && rbd_user="admin"

      # monhost: space-separated in storage.cfg -> comma-separated for librados
      rbd_mon="$(echo "$rbd_block" | awk '$1=="monhost"{$1=""; sub(/^[ \t]+/,""); gsub(/[ \t]+/,","); print; exit}')"

      rbd_conf="/etc/pve/priv/ceph/${storage}.conf"
      [[ -f "$rbd_conf" ]] || rbd_conf="/etc/ceph/ceph.conf"
      rbd_keyring="/etc/pve/priv/ceph/${storage}.keyring"

      src="rbd:${rbd_pool}/${volname}:id=${rbd_user}"
      [[ -n "$rbd_mon" ]]     && src="${src}:mon_host=${rbd_mon}"
      [[ -f "$rbd_conf" ]]    && src="${src}:conf=${rbd_conf}"
      [[ -f "$rbd_keyring" ]] && src="${src}:keyring=${rbd_keyring}"
    fi

    [[ -z "$fmt_field" ]] && src_fmt="raw"
  else
    src="$(pvesm path "${storage}:${volname}" 2>/dev/null)"
    if [[ -z "$src" ]]; then
      echo "WARN: pvesm path failed; fallback to default image directory."
      src="/var/lib/vz/images/$VMID/${volname##*/}"
    fi

    if [[ "$MODE" != "guide" && "$stype" == lvm* ]]; then
      lv_id="${src#/dev/}"
      if lvdisplay "$lv_id" 2>/dev/null | grep -q "LV Status *NOT available"; then
        echo "INFO: LV $lv_id is inactive; activating with lvchange -ay..."
        if ! lvchange -ay "$lv_id" 2>/dev/null; then
          echo "WARN: lvchange -ay $lv_id failed; trying /dev/$lv_id..."
          lvchange -ay "/dev/$lv_id" 2>/dev/null || \
            error "Unable to activate LV for $lv_id; please check LVM state."
        fi
      fi
      [[ ! -e "$src" ]] && src="/dev/$lv_id"
      [[ -z "$fmt_field" ]] && src_fmt="raw"
    fi
  fi

  # size in bytes
  if [[ -n "$size_field" ]]; then
    size_bytes="$(numfmt --from=iec "$size_field" 2>/dev/null || \
                  numfmt --from=si  "$size_field" 2>/dev/null || true)"
  fi
  if [[ -z "$size_bytes" ]]; then
    size_bytes="$(pvesm list "$storage" 2>/dev/null | \
      awk -v v="${storage}:${volname}" '$1 == v {print $4; exit}')"
  fi
  if [[ -z "$size_bytes" && "$MODE" != "guide" && -n "$src" && -e "$src" ]]; then
    if command -v blockdev >/dev/null 2>&1; then
      size_bytes="$(blockdev --getsize64 "$src" 2>/dev/null || true)"
    fi
  fi
  if [[ "$MODE" != "guide" && -z "$size_bytes" ]]; then
    echo "WARN: Unable to determine size for ${storage}:${volname}; skipping."
    continue
  fi
  [[ -z "$size_bytes" ]] && size_bytes=0

  # disk format
  if [[ "$MODE" != "guide" ]]; then
    [[ -z "$src_fmt" && -n "$fmt_field" ]] && src_fmt="$fmt_field"
    if [[ -z "$src_fmt" ]]; then
      src_fmt="$(pvesm list "$storage" 2>/dev/null | \
        awk -v v="${storage}:${volname}" '$1 == v {print $2; exit}')"
    fi
    [[ -z "$src_fmt" ]] && src_fmt="raw"
  fi

  src_disks+=("$src")
  sizes+=("$size_bytes")
  src_formats+=("$src_fmt")
  disk_buses+=("$bus_dev")
  # vhdx filename placeholder; finalized after rename check
  vhdx_files+=("__disk${idx}__")

  if [[ "$MODE" != "guide" ]]; then
    echo "INFO: Added disk $src (${size_bytes} bytes, format=${src_fmt}, src bus=${bus_dev})"
  else
    echo "INFO: Added disk $src (guide-only mode, src bus=${bus_dev})"
  fi

  ((idx++))
done < <("${CFG_CMD[@]}" | grep -E '^[[:space:]]*(scsi|sata|ide|virtio)[0-9]+:')

set -e

[[ ${#src_disks[@]} -eq 0 ]] && error "No valid data disks found"

# ---------------- verify enough workspace capacity -------------------- #

if [[ "$MODE" != "guide" ]]; then
  need=0
  for s in "${sizes[@]}"; do ((need += s)); done
  need=$((need * 12 / 10))

  avail="$(df --output=avail -B1 "$WORKDIR" | tail -n1)"

  printf "INFO: Required space ~%s, available %s\n" \
    "$(numfmt --to=iec "$need")" "$(numfmt --to=iec "$avail")"

  (( avail >= need )) || error "Not enough free space in $WORKDIR"
fi

# ------------- check for existing output files & auto-rename ---------- #

base_tag="$vmname_ascii"
probe_disk0="${WORKDIR}/${base_tag}_disk0.vhdx"

if [[ "$MODE" != "guide" && -f "$probe_disk0" ]]; then
  seq=1
  while [[ -f "${WORKDIR}/${base_tag}_${seq}_disk0.vhdx" ]]; do
    ((seq++))
  done
  base_tag="${base_tag}_${seq}"
  echo "INFO: Output files already exist, auto-renamed with suffix _${seq}"
elif [[ "$MODE" == "guide" && -f "${WORKDIR}/${base_tag}_hyperv_setup_guide.txt" ]]; then
  seq=1
  while [[ -f "${WORKDIR}/${base_tag}_${seq}_hyperv_setup_guide.txt" ]]; do
    ((seq++))
  done
  base_tag="${base_tag}_${seq}"
  echo "INFO: Output files already exist, auto-renamed with suffix _${seq}"
fi

# finalize vhdx filenames
for i in "${!vhdx_files[@]}"; do
  vhdx_files[$i]="${base_tag}_disk${i}.vhdx"
done

# finalize notes filename (only meaningful if description is non-empty)
notes_basename="${base_tag}_notes.txt"
notes_file="${WORKDIR}/${notes_basename}"
has_notes="false"
if [[ -n "$description" ]]; then
  printf '%s\n' "$description" > "$notes_file"
  has_notes="true"
  echo "INFO: VM notes file -> $notes_file"
fi

# --------------- convert each disk to dynamic VHDX -------------------- #

if [[ "$MODE" != "guide" ]]; then
  echo "INFO: Converting disks to dynamic VHDX..."
  for i in "${!src_disks[@]}"; do
    src="${src_disks[$i]}"
    dest="${vhdx_files[$i]}"
    fmt="${src_formats[$i]}"
    echo "INFO: [$((i+1))/${#src_disks[@]}] ${src} (format=${fmt}) -> ${dest}"
    qemu-img convert -p -f "$fmt" "$src" \
      -O vhdx -o subformat=dynamic \
      "${WORKDIR}/${dest}"
  done
  echo "INFO: All disks converted."
fi

# ---------------------- generate setup guide -------------------------- #

guide_file="${WORKDIR}/${base_tag}_hyperv_setup_guide.txt"
ps1_file="${WORKDIR}/${base_tag}_hyperv_create.ps1"
ps1_basename="$(basename "$ps1_file")"
gen_ts="$(date '+%Y-%m-%d %H:%M:%S')"
mem_gb=$(( memory / 1024 ))
(( mem_gb == 0 )) && mem_gb=1
firmware_upper="$(echo "$firmware" | tr '[:lower:]' '[:upper:]')"

# build disk list lines (shared style for both guides)
disk_table=""
for i in "${!vhdx_files[@]}"; do
  sz="${sizes[$i]}"
  if (( sz > 0 )); then
    sz_iec="$(numfmt --to=iec "$sz")"
  else
    sz_iec="(unknown)"
  fi
  disk_table+="    Disk ${i}: ${vhdx_files[$i]}  (size ~${sz_iec}, PVE bus=${disk_buses[$i]})"$'\n'
done

# notes line for the file list (only if there is a description)
notes_line_en=""
notes_line_zh=""
if [[ "$has_notes" == "true" ]]; then
  notes_line_en=$'\n'"    ${notes_basename}                <- PVE VM notes (UTF-8, applied by PS1)"
  notes_line_zh=$'\n'"    ${notes_basename}                <- PVE 來源 VM 備註（UTF-8，PS1 會自動套用）"
fi

if [[ "$GUIDE_LANG" == "zh-TW" ]]; then
  cat > "$guide_file" <<GUIDEEOF
===========================================================================
  Hyper-V VM 建立指南 - ${vm_display_name}
===========================================================================

  來源 VM     : ${vm_display_name}  (PVE VMID ${VMID})
  客體 OS     : ${guest_kind}
  韌體類型    : ${firmware_upper}  ->  Hyper-V Generation ${hv_generation}
  vCPU        : ${vcpus} (sockets=${sockets}, cores=${cores})
  記憶體      : ${memory} MB (~${mem_gb} GB)
  磁碟數量    : ${#src_disks[@]}

  輸出檔案 (請整批複製到 Hyper-V 主機):
${disk_table}    ${ps1_basename}                <- PowerShell 自動建立腳本${notes_line_zh}

---------------------------------------------------------------------------
  方法一：使用提供的 PowerShell 腳本（最推薦，全自動）
---------------------------------------------------------------------------

  1. 將所有 .vhdx 檔案與 ${ps1_basename}
     一起複製到 Hyper-V 主機的同一個資料夾，
     例如 C:\\HyperV\\${base_tag}\\

  2. 以「系統管理員身分」開啟 PowerShell。

  3. 若這是第一次執行未簽署的腳本，請先放行：
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

  4. 切換到該資料夾並執行腳本：
        cd C:\\HyperV\\${base_tag}
        .\\${ps1_basename}

     可用參數（皆有預設值）：
        -VMName       VM 名稱（預設：${vmname_ascii}）
        -VHDXPath     .vhdx 所在目錄（預設：目前目錄）
        -SwitchName   虛擬交換器名稱（預設：Default Switch）
        -Force        若已存在同名 VM 則先刪除

     範例：
        .\\${ps1_basename} -VMName "${vmname_ascii}" -SwitchName "External Switch"

  5. 執行完成後請開啟 Hyper-V Manager 確認 VM 設定，
     再開機（建議先確認網路、CPU、記憶體無誤）。

---------------------------------------------------------------------------
  方法二：透過 Hyper-V Manager (GUI) 手動建立
---------------------------------------------------------------------------

  1. 將所有 .vhdx 檔案複製到 Hyper-V 主機的儲存位置，
     例如 C:\\HyperV\\${base_tag}\\

  2. 開啟「Hyper-V 管理員」-> 在右側「動作」面板按
     「新增」-> 「虛擬機器...」

  3. 依照精靈設定：
     a. 名稱：${vmname_ascii}
     b. 世代：選擇「第 ${hv_generation} 代」(Generation ${hv_generation})
        注意：必須與來源 PVE 韌體相符（${firmware_upper}）。
     c. 指派記憶體：${memory} MB
        建議取消勾選「為這部虛擬機器使用動態記憶體」
     d. 設定網路功能：選擇可用的虛擬交換器（vSwitch）
     e. 連接虛擬硬碟：選擇「使用現有的虛擬硬碟」
        瀏覽並指定第一顆磁碟：${vhdx_files[0]}
     f. 完成

  4. 在 VM 上按右鍵 -> 「設定」：
     a. 「處理器」-> 虛擬處理器數量改為 ${vcpus}
     b. 若磁碟超過一顆，將其餘 .vhdx 逐一加入：
        - Gen 1：「IDE 控制器 1」或「SCSI 控制器」-> 新增
        - Gen 2：「SCSI 控制器」-> 新增 -> 硬碟 -> 瀏覽
     c. 若為 Generation 2 且來源為 Linux，請至
        「安全性」-> 取消勾選「啟用安全開機」(Enable Secure Boot)
     d. 確認網路介面卡已連接到正確的 vSwitch

  5. 開機前最終確認 -> 啟動 VM。

---------------------------------------------------------------------------
  常見問題排除
---------------------------------------------------------------------------

  * 開機後進入 UEFI shell / 找不到開機裝置
    -> 確認 Generation 與韌體相符（本機應為 Gen ${hv_generation}）。
    -> Gen 2 + Linux 請務必關閉「安全開機 (Secure Boot)」。
    -> 檢查「韌體」設定中的開機順序，將硬碟調到最前面。

  * Linux Gen 2 開機卡在 grub 或無法載入核心
    -> 關閉 Secure Boot：
       Set-VMFirmware -VMName "<VM>" -EnableSecureBoot Off

  * Windows 來源 VM 開機 BSOD (INACCESSIBLE_BOOT_DEVICE)
    -> 來源 Windows 安裝了 VirtIO 驅動，Hyper-V 無對應裝置。
       解法一：在 PVE 端先將磁碟控制器改為 SATA/IDE 後關機，再執行本工具。
       解法二：在 Hyper-V 內以救援模式開機，移除 VirtIO 驅動。
       建議：轉移前先在 PVE 內安裝 Hyper-V Integration Services 並
              將開機磁碟改為 IDE/SATA。

  * 網路無法連線
    -> Hyper-V 不認得 PVE 的 virtio-net / vmxnet3。
       VM 內的網路介面卡會是新的合成介面卡，
       Linux 通常會自動載入 hv_netvsc 模組，可能需要重新設定 IP。
       Windows 來源 VM 在第一次開機後請安裝整合服務並重設 IP。

  * .vhdx 路徑找不到
    -> PowerShell 腳本以「目前所在目錄」為預設搜尋路徑，
       請先 cd 到 .vhdx 所在資料夾，或加上 -VHDXPath 參數。

  * 「VM Switch 'Default Switch' not found」
    -> 該虛擬交換器只存在於 Windows 10/11 Client，
       Windows Server 上請先建立 External / Internal Switch，
       再用 -SwitchName 指定。

  * 「Hyper-V cmdlets not found」
    -> 該主機尚未啟用 Hyper-V 角色。
       Windows Server：安裝「Hyper-V」角色。
       Windows 10/11 Pro：啟用「Hyper-V」Windows 功能。

===========================================================================
  由 jt_pve2hyperv.sh v${VERSION} 產生於 ${gen_ts}
  Jason Tools Co., Ltd. | jason@jason.tools
===========================================================================
GUIDEEOF
else
  cat > "$guide_file" <<GUIDEEOF
===========================================================================
  Hyper-V VM Setup Guide - ${vm_display_name}
===========================================================================

  Source VM   : ${vm_display_name}  (PVE VMID ${VMID})
  Guest OS    : ${guest_kind}
  Firmware    : ${firmware_upper}  ->  Hyper-V Generation ${hv_generation}
  vCPU        : ${vcpus} (sockets=${sockets}, cores=${cores})
  Memory      : ${memory} MB (~${mem_gb} GB)
  Disk count  : ${#src_disks[@]}

  Output files (copy ALL of these to the Hyper-V host):
${disk_table}    ${ps1_basename}                <- PowerShell auto-create script${notes_line_en}

---------------------------------------------------------------------------
  Method 1 : Provided PowerShell script (recommended, fully automated)
---------------------------------------------------------------------------

  1. Copy every .vhdx file and ${ps1_basename}
     into the SAME folder on the Hyper-V host,
     e.g. C:\\HyperV\\${base_tag}\\

  2. Open PowerShell "as Administrator".

  3. If unsigned scripts are blocked, allow them for this session:
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

  4. cd into the folder and run the script:
        cd C:\\HyperV\\${base_tag}
        .\\${ps1_basename}

     Optional parameters (all have defaults):
        -VMName       VM name (default: ${vmname_ascii})
        -VHDXPath     Folder containing .vhdx (default: current directory)
        -SwitchName   Virtual switch name (default: Default Switch)
        -Force        Remove existing VM with the same name first

     Example:
        .\\${ps1_basename} -VMName "${vmname_ascii}" -SwitchName "External Switch"

  5. After the script completes, review the VM in Hyper-V Manager
     and then power it on.

---------------------------------------------------------------------------
  Method 2 : Hyper-V Manager (GUI), manual creation
---------------------------------------------------------------------------

  1. Copy all .vhdx files to a folder on the Hyper-V host,
     e.g. C:\\HyperV\\${base_tag}\\

  2. Open "Hyper-V Manager" -> right-side "Actions" pane ->
     "New" -> "Virtual Machine...".

  3. Walk through the wizard:
     a. Name      : ${vmname_ascii}
     b. Generation: Generation ${hv_generation}
                    NOTE: must match the source firmware (${firmware_upper}).
     c. Memory    : ${memory} MB
                    Uncheck "Use Dynamic Memory" (PVE uses static RAM).
     d. Networking: pick an existing Virtual Switch
     e. Connect VHD: choose "Use an existing virtual hard disk",
                    browse to: ${vhdx_files[0]}
     f. Finish.

  4. Right-click the VM -> "Settings":
     a. Processor -> Number of virtual processors = ${vcpus}
     b. If there is more than one disk, attach each remaining .vhdx:
        - Gen 1 : IDE Controller 1 or SCSI Controller -> Add
        - Gen 2 : SCSI Controller -> Add -> Hard Drive -> Browse
     c. If this is Generation 2 AND the guest is Linux:
        Security -> uncheck "Enable Secure Boot".
     d. Make sure the Network Adapter is bound to the correct vSwitch.

  5. Review settings one more time, then start the VM.

---------------------------------------------------------------------------
  Troubleshooting
---------------------------------------------------------------------------

  * VM boots to UEFI shell / no bootable device
    -> Verify Generation matches the source firmware
       (this VM should be Gen ${hv_generation}).
    -> For Gen 2 + Linux, Secure Boot MUST be disabled.
    -> Check Firmware -> Boot order, move the hard drive to the top.

  * Linux Gen 2 stuck at grub or kernel won't load
    -> Disable Secure Boot:
       Set-VMFirmware -VMName "<VM>" -EnableSecureBoot Off

  * Windows source VM bluescreens with INACCESSIBLE_BOOT_DEVICE
    -> Source Windows had VirtIO drivers; Hyper-V has no matching device.
       Option A: in PVE, switch the disk controller to SATA/IDE,
                 shut down, then re-run this tool.
       Option B: boot the VM in recovery mode under Hyper-V
                 and uninstall the VirtIO drivers.
       Best practice: before migration, install the Hyper-V
                       Integration Services inside the guest and
                       move the boot disk to IDE/SATA in PVE.

  * No network connectivity
    -> Hyper-V does not understand PVE's virtio-net / vmxnet3.
       The guest will see a brand new synthetic NIC.
       Linux usually auto-loads hv_netvsc; reconfigure IP if needed.
       Windows guests: install Integration Services on first boot
       and reconfigure the IP address.

  * Cannot find the .vhdx path
    -> The PowerShell script defaults to the current directory.
       cd into the folder first, or pass -VHDXPath.

  * "VM Switch 'Default Switch' not found"
    -> "Default Switch" only exists on Windows 10/11 client.
       On Windows Server, create an External / Internal switch first
       and pass it via -SwitchName.

  * "Hyper-V cmdlets not found"
    -> Hyper-V is not enabled on this host.
       Windows Server : install the "Hyper-V" role.
       Windows 10/11 Pro: enable the "Hyper-V" Windows feature.

===========================================================================
  Generated by jt_pve2hyperv.sh v${VERSION} on ${gen_ts}
  Jason Tools Co., Ltd. | jason@jason.tools
===========================================================================
GUIDEEOF
fi

echo "INFO: Setup guide -> $guide_file"

# ---------------------- generate PowerShell script -------------------- #
#
# IMPORTANT: the .ps1 below is ASCII-only, no BOM, no CJK characters.
# All embedded values are sanitized to ASCII by the bash logic above.

# build disk array literal for the ps1 (one quoted entry per line)
ps_disk_list=""
for v in "${vhdx_files[@]}"; do
  ps_disk_list+="    \"${v}\","$'\n'
done
# strip trailing comma+newline
ps_disk_list="${ps_disk_list%,$'\n'}"

# IsLinuxGuest as PowerShell literal
if [[ "$is_linux_guest" == "true" ]]; then
  ps_islinux='$true'
else
  ps_islinux='$false'
fi

# Optional notes block: read external UTF-8 file written by bash above and
# apply via Set-VM -Notes. Only emitted if the source VM has a description,
# so the .ps1 stays clean when there is nothing to apply. The .ps1 itself
# is still pure ASCII -- the CJK / multi-line content lives in the .txt
# file that the .ps1 reads with -Encoding UTF8 at runtime.
ps_notes_block=""
if [[ "$has_notes" == "true" ]]; then
  ps_notes_block="
# --- 10. Apply VM notes from external UTF-8 file (PVE description) ---
\$notesFile = Join-Path -Path \$VHDXPath -ChildPath \"${notes_basename}\"
if (Test-Path -LiteralPath \$notesFile) {
    try {
        \$notesContent = Get-Content -LiteralPath \$notesFile -Raw -Encoding UTF8
        Set-VM -Name \$VMName -Notes \$notesContent
        Write-Host (\"Applied VM notes from \" + \$notesFile)
    } catch {
        Write-Warning (\"Could not apply VM notes: \" + \$_.Exception.Message)
    }
} else {
    Write-Warning (\"Notes file not found: \" + \$notesFile + \" (skipping notes)\")
}"
fi

# Use unquoted heredoc so bash expands ${...} placeholders.
# Every PowerShell variable is written as \$ to keep it literal.
cat > "$ps1_file" <<PS1EOF
#Requires -RunAsAdministrator
# ---------------------------------------------------------------------------
# Hyper-V VM auto-create script
# Generated by jt_pve2hyperv.sh v${VERSION} on ${gen_ts}
# Source: PVE VMID ${VMID} (${vmname_ascii})
# Target: Hyper-V Generation ${hv_generation}
# ---------------------------------------------------------------------------

param(
    [string]\$VMName       = "${vmname_ascii}",
    [string]\$VHDXPath     = (Get-Location).Path,
    [string]\$SwitchName   = "Default Switch",
    [switch]\$Force
)

\$ErrorActionPreference = "Stop"

# --- Embedded VM specs (from PVE config) ---
\$Generation   = ${hv_generation}
\$CPUCount     = ${vcpus}
\$MemoryMB     = ${memory}
\$IsLinuxGuest = ${ps_islinux}
\$DiskFiles    = @(
${ps_disk_list}
)

Write-Host "=== Hyper-V VM Creation Script ==="
Write-Host "Source PVE VMID : ${VMID}"
Write-Host "VM Name         : \$VMName"
Write-Host "Generation      : \$Generation"
Write-Host "vCPU            : \$CPUCount"
Write-Host "Memory (MB)     : \$MemoryMB"
Write-Host "VHDX folder     : \$VHDXPath"
Write-Host "Virtual Switch  : \$SwitchName"
Write-Host "Disk count      : \$(\$DiskFiles.Count)"
Write-Host "Linux guest     : \$IsLinuxGuest"
Write-Host ""

# --- 1. Verify Hyper-V is available ---
if (-not (Get-Command New-VM -ErrorAction SilentlyContinue)) {
    Write-Error "Hyper-V cmdlets not found. Enable the Hyper-V role/feature first."
    exit 1
}

# --- 2. Handle existing VM with the same name ---
\$existing = Get-VM -Name \$VMName -ErrorAction SilentlyContinue
if (\$existing) {
    if (\$Force) {
        Write-Host "Existing VM '\$VMName' found; removing (-Force)..."
        try { Stop-VM -Name \$VMName -TurnOff -Force -ErrorAction SilentlyContinue } catch {}
        Remove-VM -Name \$VMName -Force
    } else {
        Write-Error "VM '\$VMName' already exists. Re-run with -Force to overwrite."
        exit 1
    }
}

# --- 3. Verify the virtual switch ---
\$sw = Get-VMSwitch -Name \$SwitchName -ErrorAction SilentlyContinue
if (-not \$sw) {
    Write-Warning "Virtual switch '\$SwitchName' not found. Available switches:"
    Get-VMSwitch | Format-Table Name, SwitchType, NetAdapterInterfaceDescription -AutoSize
    Write-Error "Pass a valid switch name via -SwitchName, or create one first."
    exit 1
}

# --- 4. Validate that every .vhdx file exists ---
\$diskPaths = @()
foreach (\$d in \$DiskFiles) {
    \$p = Join-Path -Path \$VHDXPath -ChildPath \$d
    if (-not (Test-Path -LiteralPath \$p)) {
        Write-Error "Disk file not found: \$p"
        exit 1
    }
    \$diskPaths += (Resolve-Path -LiteralPath \$p).Path
    Write-Host ("Found disk: " + \$p)
}

# --- 5. Create the VM with the first disk attached ---
Write-Host ""
Write-Host "Creating VM '\$VMName' (Generation \$Generation)..."
\$memBytes = [int64]\$MemoryMB * 1MB
New-VM -Name \$VMName -Generation \$Generation -MemoryStartupBytes \$memBytes -VHDPath \$diskPaths[0] -SwitchName \$SwitchName | Out-Null

# --- 6. Set CPU count ---
Set-VMProcessor -VMName \$VMName -Count \$CPUCount

# --- 7. Disable Dynamic Memory (PVE source uses static RAM) ---
Set-VMMemory -VMName \$VMName -DynamicMemoryEnabled \$false -StartupBytes \$memBytes

# --- 8. Disable Secure Boot for Linux Gen 2 guests ---
if (\$Generation -eq 2 -and \$IsLinuxGuest) {
    Write-Host "Disabling Secure Boot for Linux Gen 2 guest..."
    Set-VMFirmware -VMName \$VMName -EnableSecureBoot Off
}

# --- 9. Attach additional disks (disk index 1..N) ---
for (\$i = 1; \$i -lt \$diskPaths.Count; \$i++) {
    Write-Host ("Attaching disk " + \$i + ": " + \$diskPaths[\$i])
    Add-VMHardDiskDrive -VMName \$VMName -Path \$diskPaths[\$i]
}
${ps_notes_block}

Write-Host ""
Write-Host "SUCCESS: VM '\$VMName' has been created."
Write-Host "Review the configuration in Hyper-V Manager before starting the VM."
Write-Host ""
Write-Host "To start the VM:"
Write-Host ("  Start-VM -Name '" + \$VMName + "'")
PS1EOF

# Strip any UTF-8 BOM if one somehow ended up there (defensive)
if head -c 3 "$ps1_file" 2>/dev/null | LC_ALL=C grep -q $'\xef\xbb\xbf'; then
  tail -c +4 "$ps1_file" > "${ps1_file}.tmp" && mv "${ps1_file}.tmp" "$ps1_file"
fi

# Strict ASCII check: fail loudly if anything non-ASCII slipped in.
if LC_ALL=C grep -P '[\x80-\xff]' "$ps1_file" >/dev/null 2>&1; then
  error "Generated PS1 contains non-ASCII bytes (please report this bug)."
fi

chmod 0644 "$ps1_file"
echo "INFO: PowerShell script -> $ps1_file"

# ---------------------------------------------------------------------- #

echo ""
echo "SUCCESS: All done."
echo "  Work directory : $WORKDIR"
echo "  Guide ($GUIDE_LANG) : $(basename "$guide_file")"
echo "  PS1 script     : $(basename "$ps1_file")"
if [[ "$has_notes" == "true" ]]; then
  echo "  Notes file     : $notes_basename"
fi
if [[ "$MODE" != "guide" ]]; then
  echo "  VHDX files     :"
  for v in "${vhdx_files[@]}"; do
    echo "                   $v"
  done
fi
