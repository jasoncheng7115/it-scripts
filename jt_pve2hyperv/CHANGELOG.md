# Changelog

All notable changes to JT_PVE2HYPERV are documented in this file.

[繁體中文版](CHANGELOG_zh-TW.md)

---

## [1.2] - 2026-06-01

### Fixed
- **RBD conversion failure** — converting a VM whose disk lives on a Ceph/RBD storage failed with `unable to get monitor info from DNS SRV with service name: ceph-mon` and `qemu-img: Could not open 'rbd:<storeid>/<vol>': error connecting`. The script previously passed a bare `rbd:<storeid>/<volname>` URI to `qemu-img`, which (1) assumed the PVE storage id equals the Ceph pool name and (2) provided no ceph.conf/keyring/monitors, so qemu-img fell back to DNS SRV monitor discovery and failed. The RBD source is now resolved via `pvesm path`, which emits a complete librbd URI (real pool, `conf`/`mon_host`, `id`, `keyring`) that qemu-img can open directly — this also covers hyper-converged clusters whose conf lives at `/etc/pve/ceph.conf`. If `pvesm path` is unavailable, the script falls back to reconstructing the URI from `storage.cfg` (`pool`, `username`, `monhost`) plus the conf/keyring under `/etc/pve/priv/ceph/`.

---

## [1.1] - 2026-05-28

### Added
- **PVE VM description → Hyper-V VM notes** — the source VM's `description:` field is now URL-decoded and written to a separate `<vmname>_notes.txt` (UTF-8, no BOM). The generated PowerShell script reads it at runtime via `Get-Content -Encoding UTF8 -Raw` and applies it with `Set-VM -Notes`. The notes block is only emitted into the PS1 when the source description is non-empty; the PS1 itself stays pure ASCII (CJK / multi-line content lives in the `.txt` sidecar). Setup guide and final SUCCESS summary list the notes file alongside the VHDX / PS1 outputs.

---

## [1.0] - 2026-05-28

### Added
- **Initial public release.**
- Convert Proxmox VE VM disks to **dynamic (thin) VHDX** via `qemu-img convert -O vhdx -o subformat=dynamic`.
- **PVE firmware -> Hyper-V Generation mapping** — `bios: ovmf` maps to Generation 2 (UEFI); otherwise Generation 1 (BIOS).
- **Bilingual setup guide** — generates `<vmname>_hyperv_setup_guide.txt` in English or Traditional Chinese (selected via mandatory `<LANG>` argument: `en` or `zh-TW`). Guide covers VM specs summary, Hyper-V Manager GUI steps, PowerShell usage, and troubleshooting.
- **Customer-facing PowerShell auto-create script** — generates `<vmname>_hyperv_create.ps1` that:
  - Accepts `-VMName`, `-VHDXPath`, `-SwitchName`, `-Force` parameters
  - Validates Hyper-V availability, virtual switch presence, and every VHDX path before creating anything
  - Creates the VM with the correct Generation, CPU count, and memory
  - Disables Dynamic Memory (PVE uses static RAM)
  - Auto-disables Secure Boot for Linux Gen 2 guests
  - Attaches additional disks (disk 1..N) via `Add-VMHardDiskDrive`
- **ASCII / BOM safety** — generated `.ps1` is pure ASCII, no BOM, no CJK characters. VM names containing non-ASCII characters are sanitized via `LC_ALL=C tr -c 'A-Za-z0-9._-' '_'` before being used in filenames or the PS1. Defensive post-write byte scan fails loudly if any non-ASCII byte slipped in.
- **Storage backend support** — RBD, dir, ZFS, LVM, LVM-thin (same code path as related project `jt_pve2ova`).
- **LVM auto-activation** — inactive LVM/LVM-thin LVs are activated automatically on PVE 9 when the VM is powered off.
- **Disk format detection** — automatically detects raw/qcow2 format from VM config or `pvesm list`.
- **Disk size fallback** — determines disk size via config `size=`, then `pvesm list`, then `blockdev --getsize64`.
- **Workspace capacity check** — estimates required space at 1.2x source disk total and aborts if insufficient.
- **Auto-rename on conflict** — if output files already exist in `WORK_DIR`, the entire batch is renamed with a `_N` suffix **before** disk conversion starts, so a long conversion is never wasted.
- **Two execution modes**:
  - `all` (default) — convert disks to VHDX + generate guide + generate PS1
  - `guide` — generate guide + PS1 only (no disk conversion); useful for previewing the customer-facing artifacts.

### Notes
- No `ovftool` dependency (unlike the related `jt_pve2ova` project). VHDX is produced natively by `qemu-img`.
- All bash log output is ASCII-only (no Unicode in log messages).
