# jt\_nicmon.sh

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

---

## License

MIT License

