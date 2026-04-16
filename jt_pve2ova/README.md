# JT_PVE2OVA 1.8

Package a Proxmox VE virtual machine into an OVA file that can be imported by ESXi — **directly on the Proxmox VE node itself**!

The key feature is automatic conversion of disks to **Thin-Provision VMDK**, supporting multiple storage back-ends such as RBD / dir / ZFS / LVM / LVM-thin.

Successfully tested on VMware Workstation 17, ESXi 6.5 / 6.7 / 7.0 / 8.0 — imported correctly without issues.

[繁體中文版說明](README_zh-TW.md)

---

## Features

- **One-liner workflow** – convert VMDK → generate VMX → pack into OVA
- **Slim image** – uses `streamOptimized` sub-format + `--diskMode=thin`
- **Smart source detection** – RBD handled directly by `qemu-img`; others via `pvesm path`
- **Temp cleanup** – `MODE=clean` (default) removes VMX/VMDK after packing
- **Accurate version mapping** – `virtualHW.version` is precisely matched to ESXi version (6.5 → 13, 6.7 → 14, 7.0 → 17, 7.0u1 → 18, 7.0u2+ → 19, 8.0 → 20, 8.0u2+ → 21)
- **Boot mode aware** – reads the `bios:` field and writes the matching `firmware=` entry
- **SHA1 compatibility** – automatically uses SHA1 manifests for ESXi 6.5/6.7 to avoid import failures
- **LVM auto-activation** – activates inactive LVM/LVM-thin LVs on PVE 9 when VM is off
- **Import guide generator** – produces a customer-facing import SOP (Web UI + CLI) alongside the OVA
- **VMX-only mode** – generate VMX configuration without disk conversion or OVA packaging

![PVE2OVA_convert](https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/jt_pve2ova/pve_vmdisk_zfs_to_ova.png)

---

## Requirements

| Software               | Min. Version | Notes                                             |
|------------------------|--------------|---------------------------------------------------|
| Proxmox VE             | 8.x ↑        | Includes `pvesm`, `ceph-common`, …                |
| **qemu-img**           | 8.0 ↑        | 8.x recommended for `subformat=vmfs` support      |
| **VMware OVF Tool**    | 4.x ↑        | Install under `/opt/ovftool/`                     |
| bash, numfmt, uuidgen  | —            | Standard GNU coreutils                            |

---

## Install

### OVF Tool

```bash
# Download & install OVF Tool
# Source: https://developer.broadcom.com/tools/open-virtualization-format-ovf-tool/latest
# Place VMware-ovftool-x.x.x-xxxxxxxx-lin.x86_64.zip in /opt/
cd /opt
unzip VMware-ovftool-x.x.x-xxxxxxxx-lin.x86_64.zip
```

### JT_PVE2OVA

```bash
# Download & install jt_pve2ova
curl -Lo /opt/jt_pve2ova.sh "https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/jt_pve2ova/jt_pve2ova.sh"
chmod +x /opt/jt_pve2ova.sh
```

---

## Usage

```bash
/opt/jt_pve2ova.sh <VMID> <WORK_DIR> <ESXI_VERSION> [MODE]
```

| Parameter      | Description                                                                            |
| -------------- | -------------------------------------------------------------------------------------- |
| `VMID`         | Proxmox VE VM ID (e.g. `203`)                                                          |
| `WORK_DIR`     | Temp / output directory (must have enough space; script will estimate and check)       |
| `ESXI_VERSION` | Target ESXi version: **8.0u2 \| 8.0 \| 7.0u3 \| 7.0u1 \| 7.0 \| 6.7 \| 6.5**        |
| `MODE`         | `clean` – build OVA, remove VMX/VMDK after (default)<br>`keep` – build OVA, keep VMX/VMDK<br>`vmx` – generate only the VMX file (no VMDK conversion, no OVA) |

### ESXi Version → virtualHW Mapping

| ESXi Version | virtualHW | SHA Algorithm |
|-------------|-----------|---------------|
| 8.0u2+      | 21        | SHA256        |
| 8.0         | 20        | SHA256        |
| 7.0u2 / u3  | 19        | SHA256        |
| 7.0u1       | 18        | SHA256        |
| 7.0         | 17        | SHA256        |
| 6.7         | 14        | SHA1          |
| 6.5         | 13        | SHA1          |

### Quick Examples

```bash
# 1 – Build OVA for ESXi 8.0, auto-clean temp files
/opt/jt_pve2ova.sh 203 /vmimage/tmp 8.0

# 2 – Build OVA for ESXi 7.0u3, keep VMX/VMDK for manual testing
/opt/jt_pve2ova.sh 105 /export/ova 7.0u3 keep

# 3 – Build OVA for ESXi 6.5 (auto SHA1 manifest)
/opt/jt_pve2ova.sh 310 /export/ova 6.5

# 4 – Generate VMX only (no disk conversion)
/opt/jt_pve2ova.sh 203 /vmimage/tmp 8.0 vmx
```

### Output Files

After a successful run, the following files appear in `WORK_DIR`:

```
graylog5-customer.ova                    ← deploy directly in vSphere Client
graylog5-customer_import_guide.txt       ← customer-facing import SOP
```

The import guide contains step-by-step instructions for both vSphere Web UI and ovftool CLI, along with VM specs and common troubleshooting tips.

---

## Sample Output

```bash
root@host-108:/opt# ./jt_pve2ova.sh 203 /vmimage/temp 8.0
INFO: Detected qemu-img 9.2.0
INFO: Target ESXi 8.0 -> virtualHW 20
INFO: VM 'graylog5-customer' BIOS=bios vCPU=4 (sockets=1, cores=4) RAM=8192 MB
INFO: Skip optical: ide2: none,media=cdrom
INFO: Added disk /vmimage/images/203/vm-203-disk-0.qcow2 (45097156608 bytes, format=qcow2)
INFO: Added disk /vmimage/images/203/vm-203-disk-1.qcow2 (68719476736 bytes, format=qcow2)
INFO: Required space ~128G, available 1.4T
INFO: Converting disks to streamOptimized VMDK...
INFO: [0/2] ... -> disk0.vmdk (100.00/100%)
INFO: [1/2] ... -> disk1.vmdk (100.00/100%)
INFO: All disks converted.
INFO: VMX generated -> /vmimage/temp/graylog5-customer.vmx
INFO: Packing OVA with ovftool...
Opening VMX source: /vmimage/temp/graylog5-customer.vmx
Opening OVA target: /vmimage/temp/graylog5-customer.ova
Writing OVA package: /vmimage/temp/graylog5-customer.ova
Transfer Completed
Completed successfully
SUCCESS: OVA ready -> /vmimage/temp/graylog5-customer.ova
INFO: Import guide -> /vmimage/temp/graylog5-customer_import_guide.txt
INFO: Removing temporary VMX/VMDK files...
INFO: Temporary files removed.
```

---

## Workflow

1. **Environment check** – validate `ovftool`, `qemu-img`, PVE config
2. **Parse VM config** – CPU (sockets/cores/vCPUs), RAM, UUID, UEFI/BIOS, disk list
3. **Disk path resolution**
   * **RBD** → `rbd:<pool>/<image>`
   * **LVM / LVM-thin** → auto-activate inactive LVs if needed
   * Others → `pvesm path …` / fallback `/var/lib/vz/images`
4. **Space estimate** – adds 20% headroom; aborts if insufficient
5. **`qemu-img convert`** → `streamOptimized`, `adapter=lsilogic`, `compat6`
6. **Generate VMX** – correct `virtualHW.version` based on ESXi version
7. **`ovftool`** – build OVA with `--diskMode=thin`; use `--shaAlgorithm=SHA1` for ESXi ≤ 6.7
8. **Generate import guide** – customer-facing SOP with Web UI + CLI instructions
9. **Cleanup** (`MODE=clean`) or keep (`MODE=keep`) temp files

---

## FAQ

| Symptom / Message                            | Resolution                                                                |
| -------------------------------------------- | ------------------------------------------------------------------------- |
| `ovftool not found`                          | Ensure `/opt/ovftool/ovftool` is executable                               |
| `Invalid OVF manifest / checksum error`      | ESXi 6.5/6.7 requires SHA1 — use the correct ESXi version parameter      |
| `Unsupported hardware family vmx-XX`         | The OVA was built for a newer ESXi — re-export with correct version       |
| `unsupported or invalid disk type 7`         | Verify `streamOptimized` + `ovftool --diskMode=thin`                      |
| VM boots to UEFI shell / no bootable device  | Verify source VM firmware type; check boot order after import             |
| Network unreachable after import             | NIC type is vmxnet3 — install VMware Tools; verify port group mapping     |
| VM boots with IDE controller                 | ESXi should auto-switch to LSI SAS; change manually if not               |
| RBD permission denied                        | Check `/etc/pve/ceph.conf` and keyring permissions                        |
| LV inactive on PVE 9                         | Script auto-activates; if it fails, run `lvchange -ay` manually          |

---

## TODO / Roadmap

- [ ] Auto-upload to ESXi datastore (requires **govc**)
- [ ] Multi-NIC & custom MAC support
- [ ] Integrate `pv` for prettier conversion progress

Goal: make Proxmox VE → ESXi image migration painless!

---

## License

Provided "as-is" with no warranty. You may modify or redistribute provided the original header remains intact.

**Author:** Jason Cheng (Jason Tools Co., Ltd.) — jason@jason.tools
