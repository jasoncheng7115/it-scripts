# JT_PVE2OVA 1.9

將 Proxmox VE 虛擬機打包成 ESXi 可匯入的 OVA 檔案 — **直接在 Proxmox VE 節點上完成**！

核心特色是自動將磁碟轉換為 **Thin-Provision VMDK**，支援 RBD / dir / ZFS / LVM / LVM-thin 等多種儲存後端。

已於 VMware Workstation 17、ESXi 6.5 / 6.7 / 7.0 / 8.0 測試成功，匯入無問題。

[English Version](README.md)

---

## 功能特色

- **一鍵完成** – 轉換 VMDK → 產生 VMX → 打包 OVA
- **精簡映像** – 使用 `streamOptimized` 子格式 + `--diskMode=thin`
- **智慧偵測** – RBD 由 `qemu-img` 直接處理；其他儲存透過 `pvesm path`
- **自動清理** – `MODE=clean`（預設）打包後移除暫存 VMX/VMDK
- **精確版本對應** – `virtualHW.version` 依 ESXi 版本精準匹配（6.5 → 13、6.7 → 14、7.0 → 17、7.0u1 → 18、7.0u2+ → 19、8.0 → 20、8.0u2+ → 21）
- **韌體感知** – 讀取 `bios:` 欄位，自動寫入對應的 `firmware=` 設定
- **SHA1 相容** – ESXi 6.5/6.7 自動使用 SHA1 manifest，避免匯入失敗
- **LVM 自動啟用** – PVE 9 VM 關機時自動啟用非活動的 LVM/LVM-thin LV
- **匯入指南產生器** – OVA 匯出時同時產生中英文客戶用匯入 SOP（Web UI + CLI）
- **衝突自動更名** – 轉換前即檢查輸出檔案是否存在，自動加 `_N` 後綴避免白做工
- **檔名含 ESXi 版本** – 輸出檔案包含目標 ESXi 版本（如 `vmname_esxi6.7.ova`）
- **VMX 模式** – 僅產生 VMX 設定檔，不轉磁碟、不打包 OVA

![PVE2OVA_convert](https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/jt_pve2ova/pve_vmdisk_zfs_to_ova.png)

---

## 系統需求

| 軟體                    | 最低版本      | 備註                                               |
|------------------------|-------------|---------------------------------------------------|
| Proxmox VE             | 8.x 以上     | 含 `pvesm`、`ceph-common` 等                        |
| **qemu-img**           | 8.0 以上     | 建議 8.x 以支援 `subformat=vmfs`                     |
| **VMware OVF Tool**    | 4.x 以上     | 安裝於 `/opt/ovftool/`                              |
| bash, numfmt, uuidgen  | —           | 標準 GNU coreutils                                  |

---

## 安裝

### OVF Tool

```bash
# 下載並安裝 OVF Tool
# 來源：https://developer.broadcom.com/tools/open-virtualization-format-ovf-tool/latest
# 將 VMware-ovftool-x.x.x-xxxxxxxx-lin.x86_64.zip 放置於 /opt/
cd /opt
unzip VMware-ovftool-x.x.x-xxxxxxxx-lin.x86_64.zip
```

### JT_PVE2OVA

```bash
# 下載並安裝 jt_pve2ova
curl -Lo /opt/jt_pve2ova.sh "https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/jt_pve2ova/jt_pve2ova.sh"
chmod +x /opt/jt_pve2ova.sh
```

---

## 使用方式

```bash
/opt/jt_pve2ova.sh <VMID> <WORK_DIR> <ESXI_VERSION> [MODE]
```

| 參數            | 說明                                                                                    |
| -------------- | -------------------------------------------------------------------------------------- |
| `VMID`         | Proxmox VE 虛擬機 ID（例如 `203`）                                                       |
| `WORK_DIR`     | 暫存／輸出目錄（需有足夠空間，腳本會自動估算並檢查）                                           |
| `ESXI_VERSION` | 目標 ESXi 版本：**8.0u2 \| 8.0 \| 7.0u3 \| 7.0u1 \| 7.0 \| 6.7 \| 6.5**                |
| `MODE`         | `clean` – 打包 OVA 後移除 VMX/VMDK（預設）<br>`keep` – 打包 OVA 並保留 VMX/VMDK<br>`vmx` – 僅產生 VMX 檔（不轉換磁碟、不打包 OVA） |

### ESXi 版本 → virtualHW 對應表

| ESXi 版本    | virtualHW | SHA 演算法 |
|-------------|-----------|-----------|
| 8.0u2+      | 21        | SHA256    |
| 8.0         | 20        | SHA256    |
| 7.0u2 / u3  | 19        | SHA256    |
| 7.0u1       | 18        | SHA256    |
| 7.0         | 17        | SHA256    |
| 6.7         | 14        | SHA1      |
| 6.5         | 13        | SHA1      |

### 快速範例

```bash
# 1 – 匯出 ESXi 8.0 OVA，自動清理暫存檔
/opt/jt_pve2ova.sh 203 /vmimage/tmp 8.0

# 2 – 匯出 ESXi 7.0u3 OVA，保留 VMX/VMDK 供手動測試
/opt/jt_pve2ova.sh 105 /export/ova 7.0u3 keep

# 3 – 匯出 ESXi 6.5 OVA（自動使用 SHA1 manifest）
/opt/jt_pve2ova.sh 310 /export/ova 6.5

# 4 – 僅產生 VMX（不轉磁碟）
/opt/jt_pve2ova.sh 203 /vmimage/tmp 8.0 vmx
```

### 輸出檔案

執行成功後，`WORK_DIR` 下會產生以下檔案：

```
graylog5-customer_esxi8.0.ova                         ← 直接在 vSphere Client 部署
graylog5-customer_esxi8.0_import_guide_en.txt          ← 匯入操作指南（英文）
graylog5-customer_esxi8.0_import_guide_zh-TW.txt       ← 匯入操作指南（繁體中文）
```

若檔案已存在，腳本會在磁碟轉換**之前**自動加上 `_N` 後綴（如 `_1`、`_2`），避免浪費時間。

匯入指南包含 vSphere Web UI 及 ovftool CLI 的逐步操作說明、VM 規格摘要及常見問題排除。

---

## 執行範例

```bash
root@host-108:/opt# ./jt_pve2ova.sh 203 /vmimage/temp 8.0
INFO: Detected qemu-img 9.2.0
INFO: Target ESXi 8.0 -> virtualHW 20
INFO: VM 'graylog5-customer' BIOS=bios vCPU=4 (sockets=1, cores=4) RAM=8192 MB
INFO: Skip optical: ide2: none,media=cdrom
INFO: Added disk /vmimage/images/203/vm-203-disk-0.qcow2 (45097156608 bytes, format=qcow2)
INFO: Added disk /vmimage/images/203/vm-203-disk-1.qcow2 (68719476736 bytes, format=qcow2)
INFO: Required space ~128G, available 1.4T
INFO: Converting disks to streamOptimized VMDK...
INFO: [0/2] ... -> disk0.vmdk (100.00/100%)
INFO: [1/2] ... -> disk1.vmdk (100.00/100%)
INFO: All disks converted.
INFO: VMX generated -> /vmimage/temp/graylog5-customer_esxi8.0.vmx
INFO: Packing OVA with ovftool...
Opening VMX source: /vmimage/temp/graylog5-customer_esxi8.0.vmx
Opening OVA target: /vmimage/temp/graylog5-customer_esxi8.0.ova
Writing OVA package: /vmimage/temp/graylog5-customer_esxi8.0.ova
Transfer Completed
Completed successfully
SUCCESS: OVA ready -> /vmimage/temp/graylog5-customer_esxi8.0.ova
INFO: Import guide (EN) -> /vmimage/temp/graylog5-customer_esxi8.0_import_guide_en.txt
INFO: Import guide (ZH) -> /vmimage/temp/graylog5-customer_esxi8.0_import_guide_zh-TW.txt
INFO: Removing temporary VMX/VMDK files...
INFO: Temporary files removed.
```

---

## 處理流程

1. **環境檢查** – 驗證 `ovftool`、`qemu-img`、PVE 設定
2. **解析 VM 設定** – CPU（sockets/cores/vCPUs）、記憶體、UUID、UEFI/BIOS、磁碟清單
3. **磁碟路徑解析**
   * **RBD** → `rbd:<pool>/<image>`
   * **LVM / LVM-thin** → 必要時自動啟用非活動 LV
   * 其他 → `pvesm path …` / 備援 `/var/lib/vz/images`
4. **空間估算** – 加上 20% 餘裕；不足則中止
5. **輸出檔案檢查** – 偵測已存在檔案，轉換前自動更名
6. **`qemu-img convert`** → `streamOptimized`、`adapter=lsilogic`、`compat6`
7. **產生 VMX** – 依 ESXi 版本寫入正確的 `virtualHW.version`
8. **`ovftool`** – 以 `--diskMode=thin` 打包 OVA；ESXi ≤ 6.7 自動加 `--shaAlgorithm=SHA1`
9. **產生匯入指南** – 中英文客戶用 SOP（Web UI + CLI 操作步驟）
10. **清理** (`MODE=clean`) 或保留 (`MODE=keep`) 暫存檔

---

## 常見問題

| 症狀 / 錯誤訊息                              | 解決方式                                                                  |
| -------------------------------------------- | ------------------------------------------------------------------------- |
| `ovftool not found`                          | 確認 `/opt/ovftool/ovftool` 存在且可執行                                    |
| `Invalid OVF manifest / checksum error`      | ESXi 6.5/6.7 需要 SHA1 — 請使用正確的 ESXi 版本參數                         |
| `Unsupported hardware family vmx-XX`         | OVA 是為較新版 ESXi 打包的，請以正確版本重新匯出                               |
| `unsupported or invalid disk type 7`         | 確認使用 `streamOptimized` + `ovftool --diskMode=thin`                      |
| VM 開機進入 UEFI shell / 無可開機裝置          | 確認來源 VM 韌體類型；匯入後檢查開機順序                                      |
| 匯入後網路無法連線                              | 網卡類型為 vmxnet3，需安裝 VMware Tools；確認 Port Group 對應正確              |
| VM 以 IDE 控制器開機                           | ESXi 應自動切換為 LSI SAS，若未切換請手動修改                                  |
| RBD 權限不足                                  | 檢查 `/etc/pve/ceph.conf` 及 keyring 權限                                  |
| PVE 9 LV 未啟用                              | 腳本會自動啟用；若失敗請手動執行 `lvchange -ay`                                |

---

## TODO / 路線圖

- [ ] 自動上傳至 ESXi datastore（需 **govc**）
- [ ] 多網卡及自訂 MAC 支援
- [ ] 整合 `pv` 以顯示更美觀的轉換進度

目標：讓 Proxmox VE → ESXi 映像遷移毫無痛苦！

---

## 授權

以「現狀」提供，不附帶任何保證。可自由修改或散佈，惟須保留原始檔頭聲明。

**作者：** Jason Cheng（Jason Tools Co., Ltd.）— jason@jason.tools
