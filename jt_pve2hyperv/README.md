# JT_PVE2HYPERV 1.0

Package a Proxmox VE virtual machine into **dynamic VHDX** files that can be imported by Microsoft Hyper-V — **directly on the Proxmox VE node itself**!

In addition to the VHDX disks, the script generates a customer-facing setup guide (English or Traditional Chinese) and a ready-to-run **PowerShell script** that creates the Hyper-V VM and attaches all VHDX disks automatically.

Supports multiple storage back-ends such as RBD / dir / ZFS / LVM / LVM-thin.

[繁體中文版說明](README_zh-TW.md)

Sister project: [jt_pve2ova](../jt_pve2ova) — same idea, but targets VMware ESXi via OVA.

---

## Features

- **One-liner workflow** — convert VHDX -> generate setup guide -> generate PowerShell auto-create script
- **Slim image** — VHDX is written with `subformat=dynamic` (thin-provisioned)
- **Smart source detection** — RBD handled directly by `qemu-img`; others via `pvesm path`
- **PVE firmware aware** — `bios: ovmf` -> Hyper-V **Generation 2**, otherwise **Generation 1**
- **Customer-facing PowerShell script** — `.ps1` is ASCII-only, no BOM, no CJK; runs on Windows out of the box
- **Bilingual setup guide** — English or Traditional Chinese (selected via parameter)
- **LVM auto-activation** — activates inactive LVM/LVM-thin LVs on PVE 9 when VM is off
- **Auto-rename on conflict** — detects existing output files before conversion starts and auto-appends `_N` suffix to avoid wasted work
- **Linux Gen 2 awareness** — automatically disables Secure Boot in the generated PS1 when source is a Linux guest
- **Guide-only mode** — generate the guide + PS1 without running the long disk conversion

---

## Requirements

| Software               | Min. Version | Notes                                             |
|------------------------|--------------|---------------------------------------------------|
| Proxmox VE             | 8.x +        | Includes `pvesm`, `ceph-common`, ...              |
| **qemu-img**           | 8.0 +        | VHDX dynamic subformat support                    |
| bash, numfmt           | —            | Standard GNU coreutils                            |
| (Customer side) Windows with Hyper-V | Win 10/11 Pro/Ent, or Win Server 2016+ | To consume the VHDX + PS1 |

> No `ovftool` required (unlike the sister jt_pve2ova project). VHDX is produced natively by `qemu-img`.

---

## Install

```bash
curl -Lo /opt/jt_pve2hyperv.sh "https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/jt_pve2hyperv/jt_pve2hyperv.sh"
chmod +x /opt/jt_pve2hyperv.sh
```

---

## Usage

```bash
/opt/jt_pve2hyperv.sh <VMID> <WORK_DIR> <LANG> [MODE]
```

| Parameter   | Description                                                                       |
| ----------- | --------------------------------------------------------------------------------- |
| `VMID`      | Proxmox VE VM ID (e.g. `203`)                                                     |
| `WORK_DIR`  | Output directory (must have ~1.2x the total disk size free)                       |
| `LANG`      | Setup guide language: **`en`** or **`zh-TW`**                                     |
| `MODE`      | `all` (default) — convert VHDX + guide + PS1<br>`guide` — generate guide + PS1 only |

### PVE Firmware -> Hyper-V Generation

| PVE `bios:` | Hyper-V Generation | Notes                            |
| ----------- | ------------------ | -------------------------------- |
| `ovmf`      | Gen 2 (UEFI)       | Linux guests: Secure Boot auto-disabled |
| (default seabios) | Gen 1 (BIOS) |                                  |

### Quick Examples

```bash
# 1 - Convert VM 203, English guide
/opt/jt_pve2hyperv.sh 203 /vmimage/tmp en

# 2 - Convert VM 105, Traditional Chinese guide
/opt/jt_pve2hyperv.sh 105 /export/hyperv zh-TW

# 3 - Generate only the guide + PowerShell (no disk conversion) for previewing
/opt/jt_pve2hyperv.sh 203 /vmimage/tmp en guide
```

### Output Files

After a successful run, the following files appear in `WORK_DIR`:

```
myvm_disk0.vhdx                              <- dynamic VHDX (thin)
myvm_disk1.vhdx                              <- (if VM has multiple disks)
myvm_hyperv_setup_guide.txt                  <- customer-facing guide (EN or zh-TW)
myvm_hyperv_create.ps1                       <- PowerShell auto-create script (ASCII)
```

If the files already exist, the script auto-renames the whole batch with a `_N` suffix (e.g. `_1`, `_2`) **before** starting disk conversion — so no work is wasted.

---

## How the Customer Uses the Output

1. Copy every `.vhdx` AND the `.ps1` to the **same folder** on the Hyper-V host.
2. Open PowerShell **as Administrator**.
3. (First time only) allow unsigned scripts in this session:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```
4. Run:
   ```powershell
   cd C:\HyperV\myvm
   .\myvm_hyperv_create.ps1
   ```

   Optional parameters (all have defaults):
   - `-VMName`     — VM name (default = source VM name, ASCII-sanitized)
   - `-VHDXPath`   — folder containing the `.vhdx` files (default = current directory)
   - `-SwitchName` — virtual switch (default = `Default Switch`)
   - `-Force`      — remove an existing VM with the same name before creating

5. Review the VM in Hyper-V Manager, then power it on.

The script validates Hyper-V availability, the virtual switch, and every VHDX path before creating anything — failures abort cleanly without leaving a half-built VM.

---

## Workflow

1. **Environment check** — validate `qemu-img`, PVE config (skipped in `guide` mode for qemu-img)
2. **Parse VM config** — CPU (sockets/cores/vCPUs), RAM, ostype, UEFI/BIOS, disk list
3. **Sanitize VM name** — `LC_ALL=C tr -c 'A-Za-z0-9._-' '_'` produces an ASCII-safe name for all output files and the PS1
4. **Disk path resolution**
   - **RBD** -> `rbd:<pool>/<image>`
   - **LVM / LVM-thin** -> auto-activate inactive LVs if needed
   - Others -> `pvesm path ...` / fallback `/var/lib/vz/images`
5. **Space estimate** — adds 20% headroom; aborts if insufficient
6. **Output file check** — detects existing files, auto-renames the entire batch
7. **`qemu-img convert`** -> `vhdx` with `subformat=dynamic`
8. **Generate `.txt` setup guide** — English or Traditional Chinese
9. **Generate `.ps1`** — ASCII-only, BOM-free, post-write byte scan verifies no non-ASCII slipped in

---

## FAQ

| Symptom / Message                            | Resolution                                                                |
| -------------------------------------------- | ------------------------------------------------------------------------- |
| VM boots to UEFI shell / no bootable device  | Generation must match source firmware. Linux Gen 2 also requires Secure Boot off. |
| Linux Gen 2 stuck at grub                    | `Set-VMFirmware -VMName "<VM>" -EnableSecureBoot Off`                     |
| Windows BSOD `INACCESSIBLE_BOOT_DEVICE`      | Source had VirtIO boot disk. Switch to SATA/IDE in PVE before re-running, or remove VirtIO from a Hyper-V recovery boot. |
| No network connectivity in guest             | Synthetic NIC differs from virtio/vmxnet3 — reconfigure IP; install Integration Services on Windows. |
| `VM Switch 'Default Switch' not found`       | Windows Server has no Default Switch. Create an External/Internal switch and pass `-SwitchName`. |
| `Hyper-V cmdlets not found`                  | Enable the Hyper-V role (Server) / Hyper-V Windows feature (Client).      |
| `Disk file not found: ...`                   | Run the PS1 from the same folder as the `.vhdx`, or pass `-VHDXPath`.      |
| LV inactive on PVE 9                         | Script auto-activates; if it fails, run `lvchange -ay` manually.          |

---

## TODO / Roadmap

- [ ] Optional fixed-size VHDX flag for performance-sensitive imports
- [ ] Detect Windows guest VirtIO boot disk and warn before conversion
- [ ] Multi-NIC mapping in the generated PS1

Goal: make Proxmox VE -> Hyper-V image migration painless!

---

## License

Provided "as-is" with no warranty. You may modify or redistribute provided the original header remains intact.

**Author:** Jason Cheng (Jason Tools Co., Ltd.) — jason@jason.tools
