# 變更紀錄

本檔案紀錄 JT_PVE2HYPERV 的所有版本變更。

[English version](CHANGELOG.md)

---

## [1.0] - 2026-05-28

### 新增
- **初版公開釋出。**
- 透過 `qemu-img convert -O vhdx -o subformat=dynamic` 將 Proxmox VE VM 磁碟轉換成**動態（精簡）VHDX**。
- **PVE 韌體 → Hyper-V Generation 自動對應** — `bios: ovmf` 對應 Generation 2（UEFI）；其他則對應 Generation 1（BIOS）。
- **雙語操作指南** — 產生 `<vmname>_hyperv_setup_guide.txt`，可選英文或繁體中文（透過必填的 `<LANG>` 參數：`en` 或 `zh-TW`）。指南內容包含 VM 規格摘要、Hyper-V Manager GUI 操作步驟、PowerShell 使用方式、常見問題排除。
- **客戶用 PowerShell 自動建立腳本** — 產生 `<vmname>_hyperv_create.ps1`，功能包括：
  - 支援 `-VMName`、`-VHDXPath`、`-SwitchName`、`-Force` 參數
  - 在建立前先驗證 Hyper-V 是否可用、虛擬交換器是否存在、每顆 VHDX 是否存在
  - 用正確的 Generation、CPU 數量、記憶體大小建立 VM
  - 關閉動態記憶體（PVE 採用靜態 RAM）
  - 若為 Linux Gen 2 客體，自動關閉 Secure Boot
  - 透過 `Add-VMHardDiskDrive` 附掛其餘磁碟（disk 1..N）
- **ASCII / BOM 安全性** — 產出的 `.ps1` 為純 ASCII、無 BOM、不含任何 CJK 字元。VM 名稱若包含非 ASCII 字元，會先透過 `LC_ALL=C tr -c 'A-Za-z0-9._-' '_'` 清理後才用於檔名或 PS1。寫檔後再做防禦性 byte 掃描，發現任何非 ASCII byte 都會立即報錯。
- **儲存後端支援** — RBD、dir、ZFS、LVM、LVM-thin（與姊妹專案 `jt_pve2ova` 共用同一套邏輯）。
- **LVM 自動啟用** — PVE 9 上若 VM 關機且 LV 未啟用，會自動 `lvchange -ay`。
- **磁碟格式偵測** — 自動從 VM config 或 `pvesm list` 判斷 raw/qcow2 格式。
- **磁碟大小回退鏈** — 依序嘗試 config 的 `size=`、`pvesm list`、`blockdev --getsize64`。
- **工作空間容量檢查** — 預估需要約 1.2 倍來源磁碟總量，不足則中止。
- **檔案衝突自動改名** — 若 `WORK_DIR` 已有同名輸出檔，會在**開始磁碟轉換前**整批加上 `_N` 後綴，避免長時間轉換做白工。
- **兩種執行模式**：
  - `all`（預設）— 轉 VHDX + 產生指南 + 產生 PS1
  - `guide` — 只產生指南 + PS1（不轉磁碟）；用於預覽客戶會看到什麼

### 備註
- 不需要 `ovftool`（與姊妹專案 `jt_pve2ova` 不同），VHDX 由 `qemu-img` 直接產生。
- 所有 bash log 輸出皆為純 ASCII（log 訊息不含 Unicode）。
