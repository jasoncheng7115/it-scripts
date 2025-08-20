# jt-nicmon.sh

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

  - **區塊 2**：列出所有 `vmbr` 與 `bond` 介面，顯示：
    - `IFACE`：介面名稱
    - `TYPE`：型別（BR 或 BOND）
    - `IPV4`：IPv4 位址
    - `MEMBERS`：下層連接的介面成員（只顯示 bond 與實體 NIC）

- **即時更新**  
  搭配 `watch` 指令可每秒更新，方便即時監控。

- **PVE 最佳化**  
  針對 Proxmox VE 網路拓樸，篩選掉不必要的虛擬介面（fwbr、fwpr、tap、vnet、sdn...等等）。

- **終端處理**  
  欄位長度固定對齊，不會因為資料長短導致排版混亂。

## 安裝與使用

1. **下載指令稿**
   ```bash
   wget https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/jt_nicmon/jt_nicmon.sh -O /opt/jt_nicmon.sh
   chmod +x /opt/jt_nicmon.sh
   ```

2. **執行一次**

   ```bash
   /opt/jt_nicmon.sh
   ```

3. **即時監控（每 2 秒更新顯示一次）**

   ```bash
   watch -n 2 /opt/jt_nicmon.sh
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

## 授權條款
MIT License
