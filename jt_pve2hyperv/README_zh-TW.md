# JT_PVE2HYPERV 1.2

將 Proxmox VE 虛擬機封裝成 Microsoft Hyper-V 可以直接匯入的 **動態 VHDX** 檔案——**直接在 Proxmox VE 節點上執行即可**！

除了產生 VHDX 磁碟外，腳本還會自動產生：
- 一份客戶用的**操作說明檔**（可選繁中或英文）
- 一支客戶在 Hyper-V 主機上執行就能**自動建立 VM、自動掛載 VHDX** 的 PowerShell 腳本

支援多種儲存後端：RBD / dir / ZFS / LVM / LVM-thin。

[English version](README.md)

相關專案：[jt_pve2ova](../jt_pve2ova) — 相同概念，但目標是 VMware ESXi 的 OVA。

---

## 功能特色

- **一鍵流程** — 轉 VHDX → 產生操作指南 → 產生 PowerShell 自動建立腳本
- **精簡映像** — VHDX 採用 `subformat=dynamic`（動態 / 精簡佈建）
- **智慧來源偵測** — RBD 透過 `pvesm path` 解析為完整 librbd URI（pool、mon_host、id、keyring、conf）；其他類型同樣透過 `pvesm path`
- **PVE 韌體自動對應** — `bios: ovmf` → Hyper-V **Generation 2**；其他 → **Generation 1**
- **客戶用 PowerShell 腳本** — `.ps1` 純 ASCII、無 BOM、無 CJK，在 Windows 上直接執行
- **雙語操作指南** — 可選擇英文或繁體中文（透過參數）
- **LVM 自動啟用** — PVE 9 上若 LV 未啟用，自動 `lvchange -ay`
- **檔案衝突自動改名** — 開始轉換前先檢查輸出檔，若存在則整批加 `_N` 後綴，避免做白工
- **Linux Gen 2 自動處理** — 來源為 Linux 時，產生的 PS1 會自動關閉 Secure Boot
- **VM 備註自動帶入** — PVE `description:` 會另存為 UTF-8 的 `<vm>_notes.txt`，PS1 執行時會以 `Set-VM -Notes` 套用到 Hyper-V VM（支援 CJK / 多行；PS1 仍維持純 ASCII）
- **僅產生說明檔模式** — 不執行漫長的磁碟轉換，只產生指南 + PS1 供預覽

---

## 系統需求

| 軟體                   | 最低版本     | 備註                                              |
|------------------------|--------------|---------------------------------------------------|
| Proxmox VE             | 8.x +        | 內建 `pvesm`、`ceph-common` 等                    |
| **qemu-img**           | 8.0 +        | 須支援 VHDX dynamic subformat                     |
| bash, numfmt           | —            | 標準 GNU coreutils                                |
| （客戶端）Windows + Hyper-V | Win 10/11 Pro/Ent，或 Win Server 2016+ | 用來執行 PS1 並匯入 VHDX |

> **不需要 ovftool**（與相關專案 jt_pve2ova 不同），VHDX 由 `qemu-img` 直接產生。

---

## 安裝

```bash
curl -Lo /opt/jt_pve2hyperv.sh "https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/jt_pve2hyperv/jt_pve2hyperv.sh"
chmod +x /opt/jt_pve2hyperv.sh
```

---

## 用法

```bash
/opt/jt_pve2hyperv.sh <VMID> <WORK_DIR> <LANG> [MODE]
```

| 參數         | 說明                                                                          |
| ------------ | ----------------------------------------------------------------------------- |
| `VMID`       | Proxmox VE 的 VM ID（例如 `203`）                                             |
| `WORK_DIR`   | 輸出目錄（需要約 1.2 倍磁碟總量的可用空間）                                  |
| `LANG`       | 說明檔語言：**`en`** 或 **`zh-TW`**                                           |
| `MODE`       | `all`（預設）— 轉 VHDX + 指南 + PS1<br>`guide` — 只產生指南 + PS1，不轉磁碟 |

### PVE 韌體 → Hyper-V Generation 對應

| PVE `bios:`        | Hyper-V Generation | 備註                              |
| ------------------ | ------------------ | --------------------------------- |
| `ovmf`             | Gen 2（UEFI）      | Linux 客體：自動關 Secure Boot    |
| （預設 seabios）   | Gen 1（BIOS）      |                                   |

### 快速範例

```bash
# 1 - 轉換 VM 203，產生英文指南
/opt/jt_pve2hyperv.sh 203 /vmimage/tmp en

# 2 - 轉換 VM 105，產生繁中指南
/opt/jt_pve2hyperv.sh 105 /export/hyperv zh-TW

# 3 - 只產生指南 + PS1（不轉磁碟），用來預覽客戶會看到什麼
/opt/jt_pve2hyperv.sh 203 /vmimage/tmp zh-TW guide
```

### 輸出檔案

成功執行後，`WORK_DIR` 下會出現：

```
myvm_disk0.vhdx                              <- 動態 VHDX（精簡）
myvm_disk1.vhdx                              <- 若 VM 有多顆磁碟
myvm_hyperv_setup_guide.txt                  <- 客戶用操作指南（EN 或 zh-TW）
myvm_hyperv_create.ps1                       <- PowerShell 自動建立腳本（ASCII）
```

若檔案已存在，腳本會在**開始轉換前**整批改名加上 `_N` 後綴（如 `_1`、`_2`），避免長時間轉換做白工。

---

## 客戶端如何使用產出物

1. 把所有 `.vhdx` 與 `.ps1` 複製到 Hyper-V 主機的**同一個資料夾**。
2. 以「系統管理員身分」開啟 PowerShell。
3. （第一次執行才需要）放行未簽署腳本：
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```
4. 執行：
   ```powershell
   cd C:\HyperV\myvm
   .\myvm_hyperv_create.ps1
   ```

   可用參數（皆有預設值）：
   - `-VMName`     — VM 名稱（預設 = 來源 VM 名稱，已 ASCII 化）
   - `-VHDXPath`   — `.vhdx` 所在資料夾（預設 = 目前目錄）
   - `-SwitchName` — 虛擬交換器名稱（預設 = `Default Switch`）
   - `-Force`      — 若已存在同名 VM 先刪除再建立

5. 在 Hyper-V Manager 確認 VM 設定後再開機。

PS1 會在建立 VM 前先檢查 Hyper-V 是否可用、虛擬交換器是否存在、每顆 VHDX 是否存在——任何失敗都會乾淨中止，不會留下半成品。

---

## 執行流程

1. **環境檢查** — `qemu-img`、PVE config 等（`guide` 模式不需要 qemu-img）
2. **解析 VM config** — CPU（sockets/cores/vCPU）、RAM、ostype、UEFI/BIOS、磁碟列表
3. **VM 名稱 ASCII 化** — `LC_ALL=C tr -c 'A-Za-z0-9._-' '_'` 產生安全字串，用於所有輸出檔名與 PS1
4. **磁碟路徑解析**
   - **RBD** → `pvesm path` 產生完整 librbd URI（pool、mon_host、id、keyring、conf）；不可用時改由 `storage.cfg` 重建
   - **LVM / LVM-thin** → 必要時自動啟用 LV
   - 其他 → `pvesm path ...` / 回退 `/var/lib/vz/images`
5. **空間估算** — 加 20% 緩衝，不足則中止
6. **輸出檔檢查** — 若存在則整批改名
7. **`qemu-img convert`** → `vhdx` 加 `subformat=dynamic`
8. **產生 `.txt` 指南** — 英文或繁中
9. **產生 `.ps1`** — 純 ASCII、無 BOM，寫完後再做 byte scan 驗證

---

## 常見問題

| 症狀 / 訊息                                | 解決方式                                                                    |
| ----------------------------------------- | --------------------------------------------------------------------------- |
| 開機進入 UEFI shell / 找不到開機裝置       | Generation 必須與來源韌體相符；Linux Gen 2 還要關閉 Secure Boot              |
| Linux Gen 2 卡在 grub                      | `Set-VMFirmware -VMName "<VM>" -EnableSecureBoot Off`                       |
| Windows BSOD `INACCESSIBLE_BOOT_DEVICE`    | 來源 Windows 的開機碟用 VirtIO。先在 PVE 改成 SATA/IDE 後再執行；或在 Hyper-V 救援模式移除 VirtIO 驅動 |
| 客體網路不通                                | Hyper-V 合成介面卡與 virtio/vmxnet3 不同——重設 IP；Windows 還要裝整合服務 |
| `VM Switch 'Default Switch' not found`     | Windows Server 沒有 Default Switch，請先建立 External/Internal Switch 並用 `-SwitchName` 指定 |
| `Hyper-V cmdlets not found`                | Server 安裝 Hyper-V 角色；Client 啟用 Hyper-V Windows 功能                  |
| `Disk file not found: ...`                 | 從 `.vhdx` 所在資料夾執行 PS1，或加上 `-VHDXPath` 參數                       |
| PVE 9 上 LV 未啟用                          | 腳本會自動啟用；若失敗請手動 `lvchange -ay`                                  |

---

## TODO / Roadmap

- [ ] 提供 fixed-size VHDX 選項（效能敏感場景）
- [ ] 自動偵測 Windows 客體 VirtIO 開機碟並在轉換前警告
- [ ] 多網卡對應寫入 PS1

目標：讓 Proxmox VE → Hyper-V 的映像移轉一氣呵成！

---

## 授權

「依現狀」提供，無任何擔保。你可以自由修改或散布，前提是保留原始檔頭。

**作者：** Jason Cheng（Jason Tools Co., Ltd.）— jason@jason.tools
