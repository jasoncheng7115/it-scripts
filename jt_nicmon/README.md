# jt_nicmon.sh v1.5

> **v1.5** (2025/09/29) — Log 改為**預設開啟**，每次執行產生獨立檔案並只保留最新一份；修正 admin-down 網卡 `LNK` 欄顯示錯誤。
> **v1.4** — 新增 `-m` / `--model` 參數，透過 `lspci` 顯示網卡型號。

適合用在 **Proxmox VE** 或 Linux 環境下的網路介面監控指令搞，用於即時檢視實體網卡、橋接/聚合介面的狀態，方便檢查介面與實體連接埠對應與接線關係，在裝機時尤其方便。

<img width="667" height="237" alt="image" src="https://github.com/user-attachments/assets/96254760-2046-4ae6-98f7-9d098a7de32e" />
  
  
---

## 功能特色

- **雙區塊顯示**
  - **區塊 1**：列出所有實體網卡 (PHY)，顯示：
    - `IFACE`：介面名稱
    - `TYPE`：型別（PHY）
    - `STATE`：介面狀態（彩色顯示 `up`=綠色、`down`=黃色）
    - `LNK`：實體連線狀態（彩色顯示 `yes`=綠色、`no`=紅色）
    - `SPEED`：速率
    - `DUPLX`：雙工模式
    - `MAC`：MAC 位址
    - `MODEL`：網卡型號（需加 `-m` / `--model`，由 `lspci` 解析）

  - **區塊 2**：列出所有 `vmbr` 與 `bond` 介面，顯示：
    - `IFACE`：介面名稱
    - `TYPE`：型別（BR 或 BOND）
    - `IPV4`：IPv4 位址
    - `MEMBERS`：下層連接的介面成員（只顯示 bond 與實體 NIC）

- **即時更新**  
  搭配 `watch` 指令可每秒更新，方便即時監控。

- **Proxmox VE 最佳化**  
  針對 Proxmox VE 網路拓樸，篩選掉不必要的虛擬介面（fwbr、fwpr、tap、vnet、sdn...等等）。

- **終端處理**  
  欄位長度固定對齊，不會因為資料長短導致排版混亂。

- **網卡型號顯示（v1.4 新增）**  
  加上 `-m` / `--model` 參數，會從 `/sys/class/net/<dev>/device` 解出 PCI 位址，再透過 `lspci` 查出廠牌與型號（例如 `Intel Ethernet Connection X722 for 10GBASE-T`），裝機時對照實體卡片更直覺。系統若未安裝 `lspci` 會自動略過此欄位。

- **原始資料記錄（v1.5 起預設開啟）**  
  每次執行都會把**所有指令與 sysfs 讀取的原始輸出**（含回傳碼）寫入獨立的 log 檔，檔名為 `jt_nicmon_<日期>-<時間>_<PID>.log`，預設放在與腳本同資料夾，且**只保留最新一份**（舊的會在每次執行時自動刪除）。不需要時可用 `--no-log` 關閉。

  

    
## 安裝使用

1. **下載程式**
   ```bash
   wget https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/jt_nicmon/jt_nicmon.sh -O /opt/jt_nicmon.sh
   chmod +x /opt/jt_nicmon.sh
   ```

2. **單次執行**

   ```bash
   /opt/jt_nicmon.sh
   ```

3. **即時監控（每 2 秒更新顯示一次）**

   ```bash
   watch -n 2 /opt/jt_nicmon.sh
   ```

4. **顯示網卡型號**

   ```bash
   /opt/jt_nicmon.sh --model
   ```

5. **調整 log 行為**

   ```bash
   # 關閉 log（長時間 watch 監控時建議加上）
   /opt/jt_nicmon.sh --no-log

   # 改寫到指定目錄，並保留最近 10 份
   /opt/jt_nicmon.sh --log-dir /var/log/jt_nicmon --keep 10
   ```

## 參數說明

| 參數 | 說明 |
|------|------|
| *(無參數)* | Log **預設開啟**，寫入與腳本同資料夾的 `jt_nicmon_<日期>-<時間>_<PID>.log`，並只保留最新一份。 |
| `--no-log` | 本次執行不產生 log 檔。 |
| `-d`, `--log-dir DIR` | 改將 log 寫入 DIR（目錄需已存在）。亦可用 `--log-dir=DIR`。 |
| `--keep N` | 保留最近 N 份 log，預設 `1`；設為 `0` 表示全部保留。亦可用 `--keep=N`。 |
| `-m`, `--model` | 在區塊 1 增加 `MODEL` 欄位，透過 `lspci` 顯示網卡廠牌與型號。未安裝 `lspci` 時自動略過。 |
| `-h`, `--help` | 顯示說明。 |

> **注意**：預設只保留最新一份 log，所以搭配 `watch` 時每次更新都會覆蓋掉上一份。若要保留完整歷程，請用 `--keep 0`（全部保留）或 `--keep N` 指定份數。

## Log 內容範例

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

   
## 範例輸出

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

加上 `--model` 時，區塊 1 會多一欄 `MODEL`：

```
IFACE        TYPE  STATE  LNK SPEED      DUPLX  MAC                MODEL
eno1np0      PHY   down   no  -          -      3c:ec:ef:7e:76:42  Intel Ethernet Connection X722 for 10GBASE-T
eno2np1      PHY   up     yes 1000Mb/s   Full   3c:ec:ef:7e:76:43  Intel Ethernet Connection X722 for 10GBASE-T
enp23s0      PHY   down   no  -          -      24:be:05:b6:64:91  Mellanox MT27500 Family [ConnectX-3]
enp23s0d1    PHY   up     yes 40000Mb/s  Full   24:be:05:b6:64:92  Mellanox MT27500 Family [ConnectX-3]
```

  
  
## 授權條款
MIT License
