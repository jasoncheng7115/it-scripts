# Changelog

All notable changes to JT_PVE2OVA are documented in this file.

[繁體中文版](CHANGELOG_zh-TW.md)

---

## [1.10] - 2026-06-01

### Fixed
- **RBD conversion failure** — converting a VM whose disk lives on a Ceph/RBD storage failed with `unable to get monitor info from DNS SRV with service name: ceph-mon` and `qemu-img: Could not open 'rbd:<storeid>/<vol>': error connecting`. The script previously passed a bare `rbd:<storeid>/<volname>` URI to `qemu-img`, which (1) assumed the PVE storage id equals the Ceph pool name and (2) provided no ceph.conf/keyring/monitors, so qemu-img fell back to DNS SRV monitor discovery and failed. The RBD source is now resolved via `pvesm path`, which emits a complete librbd URI (real pool, `conf`/`mon_host`, `id`, `keyring`) that qemu-img can open directly — this also covers hyper-converged clusters whose conf lives at `/etc/pve/ceph.conf`. If `pvesm path` is unavailable, the script falls back to reconstructing the URI from `storage.cfg` (`pool`, `username`, `monhost`) plus the conf/keyring under `/etc/pve/priv/ceph/`.

---

## [1.9] - 2026-04-21

### Added
- **Pre-conversion file check** — before starting disk conversion, the script checks if the output OVA (or VMX in vmx mode) already exists. If so, it auto-appends a `_N` suffix (e.g. `_1`, `_2`) and informs the user, avoiding wasted conversion time.
- **ESXi version in output filenames** — output files now include the target ESXi version (e.g. `vmname_esxi6.7.ova`, `vmname_esxi8.0.vmx`), making it easy to identify which ESXi version an OVA was built for.

---

## [1.8] - 2026-04-16

### Fixed
- **ESXi 6.7 virtualHW version** — corrected from 17 (wrong) to 14. This was the primary cause of OVA import failures on ESXi 6.7 hosts, as virtualHW 17 requires ESXi 7.0+.
- **ESXi 7.0u1 virtualHW version** — corrected from 19 to 18. virtualHW 19 requires ESXi 7.0 Update 2 or later.
- **OVA SHA manifest for ESXi 6.5/6.7** — newer ovftool (4.4+) defaults to SHA256, which ESXi 6.5 and early 6.7 builds reject with "Invalid OVF manifest" errors. The script now automatically applies `--shaAlgorithm=SHA1` when the target virtualHW version is ≤ 14.

### Added
- **ESXi 8.0u2+ mapping** — added virtualHW version 21 for ESXi 8.0 Update 2 and later.
- **Customer-facing import guide** — after OVA creation, a `<vmname>_import_guide.txt` file is generated alongside the OVA, containing step-by-step import instructions for both vSphere Web UI and ovftool CLI, VM specifications, and common troubleshooting tips.

### Changed
- Cleaned up redundant case patterns in ESXi version matching (`7.0u*|7.0u[0-9]*|7.0u)` simplified to precise per-update patterns).
- Updated usage text to list all supported ESXi version inputs.

---

## [1.7] - 2025-11-25

### Added
- **VMX-only mode** (`MODE=vmx`) — generate VMX configuration without VMDK conversion or OVA packaging.
- **Disk format detection** — automatically detect raw/qcow2 format from VM config or `pvesm list`.
- **Disk size fallback** — determine disk size via `pvesm list` or `blockdev` when the config `size=` field is unavailable.
- **LVM auto-activation** — activate inactive LVM/LVM-thin logical volumes on PVE 9 when the VM is powered off.

### Fixed
- **CPU topology mapping** — correct sockets/cores/vCPU values in the generated VMX file.
- **Optional field handling** — no longer abort when `vcpus` or `smbios1` fields are missing from the VM config.

### Changed
- ASCII-only output (removed Unicode characters from log messages).

---

## [1.6] - 2025-06-08

### Added
- Initial public release.
- Convert Proxmox VE VM disks to streamOptimized thin-provisioned VMDK.
- Generate VMX with correct virtualHW version for ESXi 6.5 / 6.7 / 7.0 / 7.0u3 / 8.0.
- Package OVA using VMware ovftool.
- Support for RBD, dir, ZFS, LVM-thin storage backends.
- Boot mode detection (BIOS / UEFI).
- Automatic workspace capacity check.
- Two modes: `clean` (default) and `keep`.
