# 更新日誌

JT_PVE2OVA 所有重要變更記錄於此。

[English Version](CHANGELOG.md)

---

## [1.8] - 2026-04-16

### 修正
- **ESXi 6.7 virtualHW 版本** — 從 17（錯誤）修正為 14。這是 ESXi 6.7 主機匯入 OVA 失敗的主要原因，virtualHW 17 需要 ESXi 7.0 以上。
- **ESXi 7.0u1 virtualHW 版本** — 從 19 修正為 18。virtualHW 19 需要 ESXi 7.0 Update 2 以上。
- **ESXi 6.5/6.7 的 OVA SHA manifest** — 較新版 ovftool（4.4+）預設使用 SHA256，但 ESXi 6.5 及早期 6.7 會拒絕並報「Invalid OVF manifest」錯誤。腳本現在於目標 virtualHW ≤ 14 時自動加上 `--shaAlgorithm=SHA1`。

### 新增
- **ESXi 8.0u2+ 對應** — 新增 virtualHW 版本 21，適用於 ESXi 8.0 Update 2 及以上。
- **客戶匯入指南** — OVA 建立後同時產生 `<VM名稱>_import_guide.txt`，內含 vSphere Web UI 及 ovftool CLI 逐步匯入說明、VM 規格資訊及常見問題排除。

### 變更
- 清理 ESXi 版本比對中的冗餘 pattern（`7.0u*|7.0u[0-9]*|7.0u)` 簡化為精確的各 Update 版本比對）。
- 更新使用說明，列出所有支援的 ESXi 版本輸入值。

---

## [1.7] - 2025-11-25

### 新增
- **VMX 模式** (`MODE=vmx`) — 僅產生 VMX 設定檔，不轉換 VMDK、不打包 OVA。
- **磁碟格式偵測** — 自動從 VM 設定或 `pvesm list` 偵測 raw/qcow2 格式。
- **磁碟大小備援** — 當設定檔無 `size=` 欄位時，透過 `pvesm list` 或 `blockdev` 取得磁碟大小。
- **LVM 自動啟用** — PVE 9 VM 關機時，自動啟用非活動的 LVM/LVM-thin 邏輯卷。

### 修正
- **CPU 拓撲對應** — 修正產生的 VMX 中 sockets/cores/vCPU 值。
- **選用欄位處理** — VM 設定缺少 `vcpus` 或 `smbios1` 時不再中止。

### 變更
- 輸出訊息改為純 ASCII（移除 Unicode 字元）。

---

## [1.6] - 2025-06-08

### 新增
- 首次公開發佈。
- 將 Proxmox VE VM 磁碟轉換為 streamOptimized thin-provisioned VMDK。
- 產生具正確 virtualHW 版本的 VMX，支援 ESXi 6.5 / 6.7 / 7.0 / 7.0u3 / 8.0。
- 使用 VMware ovftool 打包 OVA。
- 支援 RBD、dir、ZFS、LVM-thin 儲存後端。
- 開機模式偵測（BIOS / UEFI）。
- 自動工作空間容量檢查。
- 兩種模式：`clean`（預設）及 `keep`。
