
# pve-disk-led.sh

A disk identification utility, designed for software-defined storage environments such as Proxmox VE or TrueNAS. Easily identify disk slot locations directly from the CLI, list all local disk information (matching the Proxmox VE WebUI disk details), and provide a one-click disk LED blinking feature for effortless identification and hot-swap operations.

[繁體中文版說明](https://github.com/jasoncheng7115/it-scripts/blob/master/pve-disk-led/README_zh-TW.md)

by Jason Cheng (Jason Tools)

---

## Features

* List all local physical disks on the PVE host
* Columns and information align with the WebUI (Model, Serial, Size, SMART, Wear)
* Supports SATA/SAS SSD, HDD, NVMe, USB Disk
* Correctly reads SMART health and SSD wear from SAS/SCSI SSDs (e.g. Toshiba PX05) as well as ATA/NVMe drives
* Light up a specific disk for easy on-site tray identification (leveraging the read activity via dd)
* Pure Bash script, no extra dependencies required

---

## Requirements

* Proxmox VE (also works on Debian/Ubuntu-based hosts)
* `smartmontools`
* `lsblk`
* Bash (4.2+)

---

## Installation & Usage

### Download

```bash
cd /opt
wget -O pve-disk-led.sh https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/pve-disk-led/pve-disk-led.sh
chmod +x pve-disk-led.sh
```

### Basic Usage

```bash
sudo /opt/pve-disk-led.sh
```

* Lists all disks with auto-numbering
* Enter the corresponding number to blink the disk’s LED (forces read activity to trigger blinking)
* Press `Q` to exit or continue to light up other disks

### Show Disk ID (Advanced: show /dev/disk/by-id info)

```bash
sudo /opt/pve-disk-led.sh --show-diskid
```

---

## Field Descriptions

| Field  | Description                  | Example                 |
| ------ | ---------------------------- | ----------------------- |
| No     | Index number                 | 1                       |
| Model  | Device model (incl. USB)     | KINGSTON SM2280S3G2240G |
| Serial | Disk serial number           | 50026B727902853F        |
| Size   | Actual capacity (auto units) | 240 GB, 1.92 TB         |
| SMART  | Health status                | PASSED / OK / Unknown   |
| Wear   | SSD wearout (% used)         | 8%, 0%, N/A             |

---

## Example Screenshot

![CLI Output Example](https://github.com/jasoncheng7115/it-scripts/blob/master/pve-disk-led/screenshot01.png)

---

## FAQ

* If some disks do not show model or serial, it is usually because the device does not properly support `smartctl` or `/sys/block` does not provide the information.
* SMART status differs by bus: ATA drives report `PASSED`, while SAS/SCSI drives report `OK`. Both are handled.
* SSD wear is read from several SMART fields depending on the drive: NVMe `Percentage Used`, ATA `Media_Wearout_Indicator` / `Wear_Leveling_Count` / `Percent_Lifetime_Remain`, and the SAS/SCSI `Percentage used endurance indicator`. The value shown is the **percentage used** (matches the PVE WebUI "Wearout" column).
* This script does **not** write to disks, it only forces read activity using `dd` to trigger the LED blink.

---

## Changelog

* **1.2** — Fixed SMART health and SSD wear not showing for SAS/SCSI SSDs (e.g. Toshiba PX05). SMART now also matches `SMART Health Status: OK`, and wear matches the SAS `Percentage used endurance indicator` field (case-insensitive).
* **1.1** — Initial public release.

---

## Contribution & License

by Jason Cheng, MIT License

