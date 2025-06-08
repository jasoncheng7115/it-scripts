# JT_PVE2OVA

Package a Proxmox VE virtual machine into an ESXi-importable **OVA**.  
The key feature is automatic conversion of disks to **Thin-Provisioned VMDK**, supporting multiple storage back-ends such as **RBD / dir / ZFS / LVM-thin**.

---

## Features

- **One-liner workflow** – convert VMDK → generate VMX → pack into OVA  
- **Slim image** – uses `streamOptimized` sub-format + `--diskMode=thin`  
- **Smart source detection** – RBD handled directly by `qemu-img`; others via `pvesm path`  
- **Temp cleanup** – `MODE=clean` (default) removes VMX/VMDK after packing  
- **Version mapping** – `virtualHW.version` is chosen from the ESXi version passed in  
- **Boot mode aware** – reads the `bios:` field and writes the matching `firmware=` entry  

---

## Requirements

| Software               | Min. Version | Notes                                             |
|------------------------|--------------|---------------------------------------------------|
| Proxmox VE             | 8.x ↑        | Includes `pvesm`, `ceph-common`, …                |
| **qemu-img**           | 8.0 ↑        | 8.x recommended for `subformat=vmfs` support      |
| **VMware OVF Tool**    | 4.x ↑        | Install under `/opt/ovftool/`                     |
| bash, numfmt, uuidgen  | —            | Standard GNU coreutils                            |

---

## Install Tools

### OVF Tool

```bash
# Download & install OVF Tool
# Source: https://developer.broadcom.com/tools/open-virtualization-format-ovf-tool/latest
# Place VMware-ovftool-x.x.x-xxxxxxxx-lin.x86_64.zip in /opt/
cd /opt
unzip VMware-ovftool-x.x.x-xxxxxxxx-lin.x86_64.zip
````

### JT\_PVE2OVA

```bash
# Download & install jt_pve2ova
curl -Lo /opt/jt_pve2ova.sh "https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/jt_pve2ova/jt_pve2ova.sh"
chmod +x /opt/jt_pve2ova.sh
```

---

## Usage

```bash
jt_pve2ova.sh <VMID> <WORK_DIR> <ESXI_VERSION> [MODE]
```

| Parameter      | Description                                                                            |
| -------------- | -------------------------------------------------------------------------------------- |
| `VMID`         | Proxmox VE VM ID (e.g. `203`)                                                          |
| `WORK_DIR`     | Temp / output directory (must have enough space; script will estimate and check)       |
| `ESXI_VERSION` | Target ESXi version: **8.0 / 7.0u3 / 7.0 / 6.7 / 6.5**                                 |
| `MODE`         | `keep` – keep converted VMX/VMDK<br>`clean` – remove them after OVA is built (default) |

### Quick examples

```bash
# 1 – Build OVA and auto-clean temp files
jt_pve2ova.sh 203 /vmimage/tmp 8.0

# 2 – Build OVA and keep VMX / VMDK for manual testing
jt_pve2ova.sh 105 /export/ova 7.0u3 keep
```

The resulting file appears in `WORK_DIR`, named after the Proxmox VM:

```
graylog5-customer.ova   ← deploy directly in vSphere Client
```

---

## Sample Output

Convert QCOW2 disks and pack into OVA:

```bash
root@host-108:/opt# ./jt_pve2ova.sh 203 /vmimage/temp 8.0
INFO: Detected qemu-img 9.2.0
2003–2024
INFO: Target ESXi 8.0  -> virtualHW 20
INFO: VM 'graylog5-customer'  BIOS=bios  vCPU=4  RAM=8192MB
INFO: Skip optical: ide2: none,media=cdrom
INFO: Added disk /vmimage/images/203/vm-203-disk-0.qcow2 (42G)
INFO: Added disk /vmimage/images/203/vm-203-disk-1.qcow2 (64G)
INFO: Required space ~128G, Free 1.4T
INFO: Converting disks to streamOptimized VMDK...
INFO: [0/2] /vmimage/images/203/vm-203-disk-0.qcow2 -> disk0.vmdk (100.00/100%)
INFO: [1/2] /vmimage/images/203/vm-203-disk-1.qcow2 -> disk1.vmdk (100.00/100%)
INFO: All disks converted.
INFO: VMX generated -> /vmimage/temp/graylog5-customer.vmx
INFO: Packing OVA with ovftool...
Opening VMX source: /vmimage/temp/graylog5-customer.vmx
Opening OVA target: /vmimage/temp/graylog5-customer.ova
Writing OVA package: /vmimage/temp/graylog5-customer.ova
Transfer Completed
Completed successfully
SUCCESS: OVA ready -> /vmimage/temp/graylog5-customer.ova
```

Convert Ceph RBD disks and pack into OVA:

```bash
root@host-108:/opt# ./jt_pve2ova.sh 203 /vmimage/temp 8.0
INFO: Detected qemu-img 9.2.0
2003-2024
INFO: Target ESXi 8.0 -> virtualHW 20
INFO: VM 'graylog5-customer' BIOS=bios vCPU=4 RAM=8192MB
INFO: Skip optical: ide2: none,media=cdrom
INFO: Added disk rbd:ceph1/vm-203-disk-0:conf=/etc/pve/ceph.conf:id=admin:keyring=/etc/pve/priv/ceph/ceph1.keyring (42G)
INFO: Added disk rbd:ceph1/vm-203-disk-1:conf=/etc/pve/ceph.conf:id=admin:keyring=/etc/pve/priv/ceph/ceph1.keyring (64G)
INFO: Required space ~128G, Free 1.4T
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
INFO: Cleaning temporary VMX/VMDK files...
INFO: Temporary files removed.
```

---

## Workflow

1. **Environment check** – validate `ovftool`, `qemu-img`, PVE config
2. **Parse VM config** – CPU, RAM, UUID, UEFI/Bios, disk list
3. **Disk path resolution**

   * **RBD** → `rbd:<pool>/<image>`
   * Others → `pvesm path …` / fallback `/var/lib/vz/images`
4. **Space estimate** – adds 20 % headroom; aborts if insufficient
5. **`qemu-img convert`** → `streamOptimized`, `adapter=lsilogic`, `compat6`
6. **Generate VMX** – here-doc with correct `virtualHW.version`
7. **`ovftool --diskMode=thin`** to build OVA
8. **Cleanup** (`MODE=clean`) or keep (`MODE=keep`) temp files

---

## FAQ

| Symptom / Message                    | Resolution                                                 |
| ------------------------------------ | ---------------------------------------------------------- |
| `ovftool not found`                  | Ensure `/opt/ovftool/ovftool` is executable                |
| `unsupported or invalid disk type 7` | Verify `streamOptimized` + `ovftool --diskMode=thin`       |
| VM boots with IDE controller         | ESXi should auto-switch to LSI SAS; change manually if not |
| RBD permission denied                | Check `/etc/pve/ceph.conf` and keyring permissions         |

---

## TODO / Roadmap

* [ ] Auto-upload to ESXi datastore (requires **govc**)
* [ ] Multi-NIC & custom MAC support
* [ ] Integrate `pv` for prettier conversion progress

Goal: make Proxmox VE ↔ ESXi image migration painless! 

