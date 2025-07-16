
# pve-disk-led.sh

磁碟識別小工具，適用於採用軟體定義儲存的 Proxmox VE 或 TrueNAS 等系統，從 CLI 即可方便識別磁碟所在槽位，並列出本機所有磁碟資訊（與 Proxmox VE WebUI 的磁碟資訊相同），提供一鍵點亮硬碟功能，讓你輕鬆辨識、無痛抽換。


by Jason Cheng (Jason Tools)

---

## 功能

- 完整列出 PVE Host 本機所有實體磁碟
- 欄位資訊與 WebUI 對齊（Model、Serial、Size、SMART、Wear）
- 支援 SSD、HDD、NVMe、USB Disk
- 點亮指定磁碟，現場確認機櫃 Tray 好幫手（利用 dd 讀取特性，只讀不寫）
- 純 Bash Script 開發，不用特別安裝其它套件

---

## 需求

- Proxmox VE (Debian/Ubuntu 相關發行版本的主機亦可)
- `smartmontools`
- `lsblk`
- Bash (4.2+)

---

## 安裝使用

### 下載

```bash
cd /opt
wget https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/pve-disk-led/pve-disk-led.sh
chmod +x pve-disk-led.sh
```

### 使用方式

```bash
sudo /opt/pve-disk-led.sh
```

* 執行後，列出所有磁碟資訊並自動編號
* 輸入對應編號可點亮硬碟（強制讀取使 LED 閃爍）
* 按 `Q` 可離開或繼續點亮其他硬碟

### 顯示磁碟 ID（進階指令，顯示 /dev/disk/by-id 下的資訊）

```bash
sudo /opt/pve-disk-led.sh --show-diskid
```

---

## 欄位說明

| 欄位     | 說明          | 範例                      |
| ------ | ----------- | ----------------------- |
| No     | 編號          | 1                       |
| Model  | 裝置型號（含 USB） | KINGSTON SM2280S3G2240G |
| Serial | 硬碟序號        | 50026B727902853F        |
| Size   | 實際容量，自動單位換算 | 240 GB、1.92 TB      |
| SMART  | 健康狀態        | PASSED / Unknown        |
| Wear   | SSD 耗損率  | 0%、N/A                  |

---

## 使用擷圖

![CLI Output Example](https://github.com/jasoncheng7115/it-scripts/blob/master/pve-disk-led/screenshot01.png)

---

## 常見問題

* 若某些磁碟未顯示型號或序號，通常是該裝置未正確支援 `smartctl` 或 /sys/block 未提供資訊
* 本 script 不會對磁碟寫入，僅以 dd 強制讀取強迫點亮

---

## 貢獻與授權

by Jason Cheng, MIT License

