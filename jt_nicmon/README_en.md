# jt\_nicmon.sh v1.5

> **v1.5** (2025/09/29) — Logging is now **on by default**, one file per run keeping only the newest; fixes the `LNK` column for admin-down NICs.
> **v1.4** — Adds `-m` / `--model` to show the NIC model via `lspci`.

A network interface monitoring script suitable for **Proxmox VE** or Linux environments.
It is used to view the status of physical NICs and bridge/bond interfaces in real time, making it easy to check the mapping between interfaces and physical ports, as well as cable connections—especially convenient during system installation.

<img width="667" height="237" alt="image" src="https://github.com/user-attachments/assets/96254760-2046-4ae6-98f7-9d098a7de32e" />

---

## Features

* **Dual-Block Display**

  * **Block 1**: Lists all physical NICs (PHY) and displays:

    * `IFACE`: Interface name
    * `TYPE`: Type (PHY)
    * `STATE`: Interface state (color-coded: `up` = green, `down` = yellow)
    * `LNK`: Physical link status (color-coded: `yes` = green, `no` = red)
    * `SPEED`: Speed
    * `DUPLX`: Duplex mode
    * `MAC`: MAC address
    * `MODEL`: NIC model, resolved via `lspci` (requires `-m` / `--model`)

  * **Block 2**: Lists all `vmbr` and `bond` interfaces, displaying:

    * `IFACE`: Interface name
    * `TYPE`: Type (BR or BOND)
    * `IPV4`: IPv4 address
    * `MEMBERS`: Member interfaces connected underneath (only shows bond and physical NICs)

* **Real-Time Updates**
  Works with the `watch` command for per-second updates, enabling real-time monitoring.

* **Optimized for Proxmox VE**
  Filters out unnecessary virtual interfaces (fwbr, fwpr, tap, vnet, sdn, etc.) according to Proxmox VE network topology.

* **Terminal Formatting**
  Fixed column widths ensure alignment, preventing formatting issues caused by varying data lengths.

* **NIC Model Display (new in v1.4)**
  With `-m` / `--model`, the PCI address is resolved from `/sys/class/net/<dev>/device` and looked up via `lspci` to show the vendor and model (e.g. `Intel Ethernet Connection X722 for 10GBASE-T`), making it easier to match interfaces to physical cards. The column is skipped automatically if `lspci` is not installed.

* **Raw Data Logging (on by default since v1.5)**
  Every run writes the raw output of **all commands and sysfs reads** (including return codes) to its own log file, named `jt_nicmon_<date>-<time>_<pid>.log`, in the script's directory by default, and **only the newest file is kept** (older ones are deleted on each run). Use `--no-log` to turn it off.

---

## Installation & Usage

1. **Download the script**

   ```bash
   wget https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/jt_nicmon/jt_nicmon.sh -O /opt/jt_nicmon.sh
   chmod +x /opt/jt_nicmon.sh
   ```

2. **Run once**

   ```bash
   /opt/jt_nicmon.sh
   ```

3. **Real-time monitoring (update every 2 seconds)**

   ```bash
   watch -n 2 /opt/jt_nicmon.sh
   ```

4. **Show NIC models**

   ```bash
   /opt/jt_nicmon.sh --model
   ```

5. **Adjust logging**

   ```bash
   # Disable logging (recommended for long watch sessions)
   /opt/jt_nicmon.sh --no-log

   # Write to a specific directory and keep the 10 most recent logs
   /opt/jt_nicmon.sh --log-dir /var/log/jt_nicmon --keep 10
   ```

---

## Options

| Option | Description |
|--------|-------------|
| *(none)* | Logging is **on by default**, writing `jt_nicmon_<date>-<time>_<pid>.log` in the script's directory and keeping only the newest file. |
| `--no-log` | Do not write a log file for this run. |
| `-d`, `--log-dir DIR` | Write log files to DIR (must already exist). `--log-dir=DIR` also works. |
| `--keep N` | Keep the N most recent log files, default `1`; `0` keeps them all. `--keep=N` also works. |
| `-m`, `--model` | Add a `MODEL` column to block 1, showing the NIC vendor and model via `lspci`. Skipped automatically if `lspci` is missing. |
| `-h`, `--help` | Show help and exit. |

> **Note**: only the newest log is kept by default, so under `watch` each refresh overwrites the previous one. To keep the full history, use `--keep 0` (keep all) or `--keep N`.

---

## Example Log Output

```
==== RUN 2025-09-29 14:03:11 | host=pve01 | jt_nicmon v1.5 ====
# kernel: Linux 6.8.12-4-pve
# log: /opt/jt_nicmon_20250929-140311_3195774.log (keep 1, 1 old file(s) pruned)
$ tput cols  [rc=0]
120
# --- section 1: physical NICs ---
$ ls -1 /sys/class/net  [rc=0]
eno1np0
eno2np1
...
$ cat /sys/class/net/eno2np1/carrier  [rc=0]
1
$ ethtool eno2np1  [rc=0]
Settings for eno2np1:
        Speed: 1000Mb/s
        Duplex: Full
        Link detected: yes
# --- section 2: bridges/bonds ---
$ ip -4 -o addr show dev vmbr0  [rc=0]
6: vmbr0    inet 192.168.1.109/24 scope global vmbr0\       valid_lft forever preferred_lft forever
# brif of vmbr0: eno2np1 fwpr102p0 fwpr113p0
# --- end of run ---
```

---

## Example Output

```
IFACE        TYPE  STATE  LNK SPEED      DUPLX  MAC
eno1np0      PHY   down   no  -          -      3c:ec:ef:7e:75:98
eno2np1      PHY   up     yes 1000Mb/s   Full   3c:ec:ef:7e:75:99
enp23s0      PHY   down   no  -          -      00:02:c9:42:22:f0
enp23s0d1    PHY   up     yes 40000Mb/s  Full   00:02:c9:42:22:f1

IFACE        TYPE  IPV4               MEMBERS
bond0        BOND  -                  eno1np0 enp23s0
vmbr0        BR    192.168.1.109/24   eno2np1
vmbr10       BR    172.16.100.109/24  enp23s0d1
vmbr20       BR    172.16.110.109/24  bond0
```

With `--model`, block 1 gains a `MODEL` column:

```
IFACE        TYPE  STATE  LNK SPEED      DUPLX  MAC                MODEL
eno1np0      PHY   down   no  -          -      3c:ec:ef:7e:76:42  Intel Ethernet Connection X722 for 10GBASE-T
eno2np1      PHY   up     yes 1000Mb/s   Full   3c:ec:ef:7e:76:43  Intel Ethernet Connection X722 for 10GBASE-T
enp23s0      PHY   down   no  -          -      24:be:05:b6:64:91  Mellanox MT27500 Family [ConnectX-3]
enp23s0d1    PHY   up     yes 40000Mb/s  Full   24:be:05:b6:64:92  Mellanox MT27500 Family [ConnectX-3]
```

---

## License

MIT License

