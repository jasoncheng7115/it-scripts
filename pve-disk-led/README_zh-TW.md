
# pve-disk-led

磁碟識別小工具，適用於採用軟體定義儲存的 Proxmox VE 或 TrueNAS 等系統，從 CLI 即可方便識別磁碟所在槽位，並列出本機所有磁碟資訊（對齊 PVE WebUI 風格），並提供一鍵點亮硬碟功能，讓你輕鬆辨識、無痛抽換。


**by Jason Cheng (Jason Tools)

---

## 特色 Features

- 完整列出 PVE Host 本機所有實體磁碟
- 欄位資訊與 WebUI 對齊（Model、Serial、Size、SMART、Wear）
- 支援 SSD、HDD、NVMe、USB Disk
- 點亮指定磁碟，現場確認機櫃 Tray 好幫手
- 純 Bash Script 開發，不用特別安裝其它套件

---

## 需求 Requirements

- Proxmox VE (Debian/Ubuntu 相關發行版本的主機亦可)
- `smartmontools`
- `lsblk`
- Bash (4.2+)

---

## 安裝與使用 Installation & Usage

### 下載

```bash
wget https://raw.githubusercontent.com/your_github/pve-disk-led/main/pve-disk-led.sh
chmod +x pve-disk-led.sh
````

### 使用方式

```bash
sudo ./pve-disk-led.sh
```

* 執行後，列出所有磁碟資訊並自動編號
* 輸入對應編號可點亮硬碟（強制讀取，LED 會閃爍）
* 再按 `Q` 離開或繼續點亮其他硬碟

### 顯示磁碟 ID（進階指令）

```bash
sudo ./pve-disk-led.sh --show-diskid
```

---

## 欄位說明

| 欄位     | 說明          | 範例                      |
| ------ | ----------- | ----------------------- |
| No     | 編號          | 1                       |
| Model  | 裝置型號（含 USB） | KINGSTON SM2280S3G2240G |
| Serial | 硬碟序號        | 50026B727902853F        |
| Size   | 實際容量，自動單位換算 | 240.06 GB、10.00 TB      |
| SMART  | 健康狀態        | PASSED / Unknown        |
| Wear   | SSD耗損率/壽命%  | 0%、N/A                  |

---

## 實機螢幕截圖

![CLI Output Example](screenshot-cli.png)

---

## 常見問題 (FAQ)

* 若某些磁碟未顯示型號或序號，通常是該裝置未正確支援 `smartctl` 或 /sys/block 未提供資訊
* 本 script 不會對磁碟寫入，僅以 dd 強制讀取強迫點亮

---

## 貢獻與授權 Contribute & License

by Jason Cheng, MIT License

