# JT Process Performance Analyzer

## 📖 簡介

**JT Process Performance Analyzer** 是一款全方位的 Windows Process 效能監控與分析工具，能夠深入收集 CPU、記憶體、I/O、Thread、Handle 等多種效能指標，並提供記憶體洩漏偵測功能。

### ✨ 主要特色

- ✅ **完整的效能指標收集**
  - CPU 使用率、CPU Time、User/Kernel Time、Priority
  - 記憶體（Working Set、Private、Virtual、Paged/Non-Paged）
  - I/O 速率（Read/Write KB/s、IOPS）
  - Thread 與 Handle 計數
  - Process 狀態、Owner、版本資訊

- ✅ **記憶體洩漏偵測**
  - 自動追蹤記憶體增長趨勢（MB/分鐘）
  - Handle 洩漏偵測（Handle 增長速率）
  - 自動標記可疑的記憶體洩漏 Process

- ✅ **彈性的篩選機制**
  - 白名單/黑名單（Include/Exclude）
  - 精確比對、萬用字元、正規表示式
  - CPU/記憶體門檻篩選

- ✅ **多種輸出格式**
  - JSON（含 Metadata）
  - CSV（Excel 相容，含註解）
  - TSV（Tab 分隔）

- ✅ **即時寫入模式** 🔥 NEW!
  - 資料邊收集邊寫入檔案（不需等待完成）
  - 可隨時開啟檔案查看進度
  - 隨時中斷（Ctrl+C）不損失已收集資料
  - 避免記憶體佔用過高

- ✅ **友善的使用者介面**
  - 即時進度顯示（百分比、ETA）
  - 彩色輸出（成功/警告/錯誤）
  - 執行摘要報告
  - 寫入狀態即時提示

- ✅ **完整的錯誤處理**
  - 環境檢查（PowerShell 版本、權限、磁碟空間）
  - 錯誤計數與統計
  - 可選的詳細日誌（Transcript）

---

## 🚀 快速開始

### 系統需求

- **作業系統**: Windows 7 / Windows Server 2008 R2 或更新版本
- **PowerShell**: 5.1 或更新版本（建議 7.x）
- **權限**: 一般使用者權限即可（部分進階指標需要管理員權限）

### 安裝

1. 下載 `jt_procperf_analyzer.ps1`
2. （可選）解除封鎖檔案：
   ```powershell
   Unblock-File -Path .\jt_procperf_analyzer.ps1
   ```

### 基本使用

```powershell
# 使用預設設定（監控 60 分鐘，每 10 秒取樣，輸出 JSON）
.\jt_procperf_analyzer.ps1

# 自訂監控時長與間隔
.\jt_procperf_analyzer.ps1 -DurationMinutes 30 -IntervalSeconds 5

# 輸出為 CSV 格式
.\jt_procperf_analyzer.ps1 -OutputFormat CSV -OutputPath "C:\PerfLogs"
```

---

## 📚 使用範例

### 範例 1: 監控特定 Process

```powershell
# 只監控 Chrome 瀏覽器
.\jt_procperf_analyzer.ps1 -IncludeProcesses "chrome" -MatchMode Wildcard

# 監控多個 Process（Chrome、Firefox、Edge）
.\jt_procperf_analyzer.ps1 -IncludeProcesses "chrome","firefox","msedge"

# 使用正規表示式監控（所有包含 "sql" 的 Process）
.\jt_procperf_analyzer.ps1 -IncludeProcesses ".*sql.*" -MatchMode Regex
```

### 範例 2: 排除系統 Process

```powershell
# 排除常見系統 Process
.\jt_procperf_analyzer.ps1 -ExcludeProcesses "svchost","System","Idle","csrss","smss"

# 結合 Include 與 Exclude
.\jt_procperf_analyzer.ps1 `
    -IncludeProcesses "*sql*" `
    -ExcludeProcesses "sqlwriter" `
    -MatchMode Wildcard
```

### 範例 3: 效能門檻篩選

```powershell
# 只收集 CPU > 5% 的 Process
.\jt_procperf_analyzer.ps1 -MinimumCPU 5

# 只收集記憶體使用 > 100MB 的 Process
.\jt_procperf_analyzer.ps1 -MinimumMemoryMB 100

# 結合 CPU 與記憶體門檻
.\jt_procperf_analyzer.ps1 -MinimumCPU 10 -MinimumMemoryMB 50
```

### 範例 4: 記憶體洩漏偵測

```powershell
# 長時間監控（6 小時）以偵測記憶體洩漏
.\jt_procperf_analyzer.ps1 `
    -DurationMinutes 360 `
    -IntervalSeconds 60 `
    -OutputFormat JSON `
    -EnableLogging

# 分析輸出檔案，找出可疑的記憶體洩漏
# 查看 PossibleMemoryLeak = true 的 Process
```

### 範例 5: 系統整體效能監控

```powershell
# 包含系統整體指標（總 CPU、可用記憶體等）
.\jt_procperf_analyzer.ps1 -IncludeSystemMetrics

# 系統指標會輸出到獨立的檔案 system_metrics_*.json
```

### 範例 6: 高頻率短時間監控

```powershell
# 5 分鐘高頻監控（每秒取樣）
.\jt_procperf_analyzer.ps1 -DurationMinutes 5 -IntervalSeconds 1 -NoProgress
```

### 範例 7: 跳過特定指標（節省效能）

```powershell
# 跳過 I/O 指標（減少 WMI 呼叫次數）
.\jt_procperf_analyzer.ps1 -SkipIOMetrics

# 跳過 GUI 指標
.\jt_procperf_analyzer.ps1 -SkipGUIMetrics
```

### 範例 8: 靜默模式與日誌

```powershell
# 靜默模式（最小化輸出）
.\jt_procperf_analyzer.ps1 -QuietMode

# 啟用詳細日誌
.\jt_procperf_analyzer.ps1 -EnableLogging

# 結合靜默模式與日誌（適合排程任務）
.\jt_procperf_analyzer.ps1 -QuietMode -EnableLogging
```

---

## 🔥 即時寫入功能（Real-time Streaming）

### 什麼是即時寫入？

從 v2.0 開始，工具採用**即時寫入模式**，資料會邊收集邊寫入檔案，而不是等到全部完成才寫入。

### 優點

✅ **資料安全**：即使程式崩潰或手動中斷（Ctrl+C），已收集的資料不會遺失
✅ **即時查看**：監控期間可以開啟檔案查看進度
✅ **記憶體友善**：不會在記憶體中累積大量資料
✅ **長時間監控**：適合 24 小時以上的長時間監控

### 如何使用？

**完全自動！不需要任何特殊參數。**

```powershell
# 正常執行即可，資料會自動即時寫入
.\jt_procperf_analyzer.ps1 -DurationMinutes 60

# 執行中可以開啟檔案查看（檔案會立即產生）
# 位置：C:\Users\YourName\Documents\process_metrics_*.csv
```

### 執行期間的提示訊息

```
[INFO] 開始收集效能數據（即時寫入模式：每個取樣間隔寫入一次）...
[INFO] 輸出檔案：C:\Users\...\process_metrics_20251213_143000.json
[INFO] 提示：資料正在即時寫入，您可以隨時開啟檔案查看或按 Ctrl+C 中斷

[寫入] 間隔 1/360：已儲存 156 個 Process（總計 156 筆記錄）
[寫入] 間隔 2/360：已儲存 158 個 Process（總計 314 筆記錄）
[寫入] 間隔 3/360：已儲存 155 個 Process（總計 469 筆記錄）
...
```

**說明**：
- 每個取樣間隔（例如每 10 秒）會寫入一次
- 該間隔的所有 Process 資料會一起寫入（不是每個 Process 寫一次）
- 顯示「已儲存 N 個 Process」= 這個間隔收集了幾個 Process
- 顯示「總計 X 筆記錄」= 從開始到現在累計收集的 Process 數量

### 隨時中斷不損失資料

如果您需要提前結束監控：

1. **按 `Ctrl + C`** 中斷執行
2. 已收集的資料**已經安全儲存**在檔案中
3. 直接開啟檔案即可分析

### 測試即時寫入

快速測試（1 分鐘）：

```powershell
# 執行測試腳本
.\Test-RealTimeWrite.ps1

# 或手動測試
.\jt_procperf_analyzer.ps1 -DurationMinutes 1 -IntervalSeconds 5

# 執行期間立即開啟 Documents 資料夾
# 您會看到檔案即時產生並持續增大
```

### 技術細節

- **寫入策略**：每個取樣間隔結束後，把該間隔的所有 Process 資料一起寫入
  - 例如：10 秒間隔，收集到 150 個 Process，會一次寫入這 150 個 Process 的資料
  - 而不是每個 Process 就寫一次（減少 I/O 次數）
- **檔案格式**：
  - CSV/TSV：先寫入標頭，然後逐行 append
  - JSON：使用 JSONL 格式（每行一個 JSON 物件，每個間隔寫入多行）
- **效能影響**：極小（按間隔批次寫入，平衡即時性與效能）

---

## 📊 輸出格式說明

### JSON 格式

```json
{
  "Metadata": {
    "CollectionStart": "2025-12-13 14:30:00",
    "CollectionEnd": "2025-12-13 15:30:00",
    "DurationMinutes": 60,
    "IntervalSeconds": 10,
    "TotalSamples": 1234,
    "Parameters": {
      "IncludeProcesses": ["chrome"],
      "ExcludeProcesses": [],
      "MatchMode": "Wildcard",
      "MinimumCPU": 0,
      "MinimumMemoryMB": 0
    }
  },
  "Metrics": [
    {
      "Timestamp": "2025-12-13 14:30:00",
      "ProcessName": "chrome",
      "ProcessID": 12345,
      "CPUPercent": 15.23,
      "WorkingSetMB": 512.45,
      "PrivateMemoryMB": 480.12,
      "IOReadKBSec": 123.45,
      "IOWriteKBSec": 56.78,
      "ThreadCount": 42,
      "HandleCount": 1234,
      "MemoryGrowthMBPerMin": 2.5,
      "HandleGrowthPerMin": 5,
      "PossibleMemoryLeak": false,
      ...
    }
  ]
}
```

### CSV 格式

```csv
# Process Performance Metrics
# Collection Start: 2025-12-13 14:30:00
# Collection End: 2025-12-13 15:30:00
# Duration: 60 minutes
# Interval: 10 seconds
# Total Samples: 1234
Timestamp,ProcessName,ProcessID,CPUPercent,WorkingSetMB,PrivateMemoryMB,...
2025-12-13 14:30:00,chrome,12345,15.23,512.45,480.12,...
```

---

## 🔍 收集的效能指標清單

### 基本資訊
- `Timestamp` - 取樣時間
- `ProcessName` - Process 名稱
- `ProcessID` - Process ID (PID)
- `ProcessPath` - 執行檔完整路徑
- `CommandLine` - 啟動命令列
- `Owner` - 執行帳戶（Domain\User）
- `CompanyName` - 程式發行者
- `ProductVersion` - 程式版本

### CPU 指標
- `CPUPercent` - CPU 使用率（%）
- `CPUTimeTotalSec` - 累積 CPU 時間（秒）
- `UserTimeSec` - 使用者模式時間
- `PrivilegedTimeSec` - 核心模式時間
- `PriorityClass` - 優先權類別
- `BasePriority` - 基礎優先權

### 記憶體指標
- `WorkingSetMB` - 實體記憶體使用量（MB）
- `PrivateMemoryMB` - 私有記憶體（MB）
- `VirtualMemoryMB` - 虛擬記憶體（MB）
- `PagedMemoryMB` - 可分頁記憶體（MB）
- `NonPagedMemoryMB` - 不可分頁記憶體（MB）
- `PeakWorkingSetMB` - 歷史最高記憶體使用（MB）

### 記憶體洩漏指標
- `MemoryGrowthMBPerMin` - 記憶體增長速率（MB/分鐘）
- `HandleGrowthPerMin` - Handle 增長速率（個/分鐘）
- `PossibleMemoryLeak` - 可疑洩漏標記（true/false）

### I/O 指標
- `IOReadKBSec` - 磁碟讀取速率（KB/秒）
- `IOWriteKBSec` - 磁碟寫入速率（KB/秒）
- `IOOtherKBSec` - 其他 I/O 速率（KB/秒）
- `IODataKBSec` - 總 I/O 速率（KB/秒）
- `IOReadOpsSec` - 讀取 IOPS
- `IOWriteOpsSec` - 寫入 IOPS

### Thread 與 Handle
- `ThreadCount` - 執行緒數量
- `HandleCount` - 控制碼數量

### Process 狀態
- `StartTime` - 啟動時間
- `UptimeHours` - 執行時長（小時）
- `Responding` - 是否回應中
- `SessionID` - 工作階段 ID

---

## 🛠️ 進階使用技巧

### 1. 分析記憶體洩漏

使用 PowerShell 分析輸出的 JSON 檔案：

```powershell
# 讀取 JSON 檔案
$Data = Get-Content -Path "process_metrics_20251213_143000.json" | ConvertFrom-Json

# 找出可疑的記憶體洩漏 Process
$LeakProcesses = $Data.Metrics | Where-Object { $_.PossibleMemoryLeak -eq $true } |
    Group-Object -Property ProcessName |
    Select-Object Name, Count

$LeakProcesses | Format-Table -AutoSize

# 繪製特定 Process 的記憶體趨勢圖（需要額外模組）
$ChromeData = $Data.Metrics | Where-Object { $_.ProcessName -eq "chrome" }
$ChromeData | Select-Object Timestamp, WorkingSetMB | Export-Csv -Path "chrome_memory.csv" -NoTypeInformation
```

### 2. 找出 CPU 使用率最高的 Process

```powershell
$Data = Get-Content -Path "process_metrics_20251213_143000.json" | ConvertFrom-Json

$TopCPU = $Data.Metrics |
    Group-Object -Property ProcessName |
    ForEach-Object {
        [PSCustomObject]@{
            ProcessName = $_.Name
            AvgCPU      = [Math]::Round(($_.Group | Measure-Object -Property CPUPercent -Average).Average, 2)
            MaxCPU      = [Math]::Round(($_.Group | Measure-Object -Property CPUPercent -Maximum).Maximum, 2)
            Samples     = $_.Count
        }
    } | Sort-Object -Property AvgCPU -Descending | Select-Object -First 10

$TopCPU | Format-Table -AutoSize
```

### 3. I/O 密集型 Process 分析

```powershell
$Data = Get-Content -Path "process_metrics_20251213_143000.json" | ConvertFrom-Json

$TopIO = $Data.Metrics |
    Group-Object -Property ProcessName |
    ForEach-Object {
        [PSCustomObject]@{
            ProcessName   = $_.Name
            AvgReadKBSec  = [Math]::Round(($_.Group | Measure-Object -Property IOReadKBSec -Average).Average, 2)
            AvgWriteKBSec = [Math]::Round(($_.Group | Measure-Object -Property IOWriteKBSec -Average).Average, 2)
            TotalIOKBSec  = 0
        }
    }

$TopIO | ForEach-Object { $_.TotalIOKBSec = $_.AvgReadKBSec + $_.AvgWriteKBSec }
$TopIO | Sort-Object -Property TotalIOKBSec -Descending | Select-Object -First 10 | Format-Table -AutoSize
```

### 4. 排程自動化監控

建立 Windows 工作排程器任務：

```powershell
$Action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -File C:\Scripts\jt_procperf_analyzer.ps1 -DurationMinutes 60 -QuietMode -EnableLogging"

$Trigger = New-ScheduledTaskTrigger -Daily -At "02:00AM"

$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "Process Performance Monitor" `
    -Action $Action `
    -Trigger $Trigger `
    -Principal $Principal `
    -Description "每日凌晨 2 點執行 Process 效能監控"
```

---

## ❓ 常見問題 (FAQ)

### Q1: 執行時出現「無法載入，因為這個系統禁止執行指令碼」

**A:** 這是 PowerShell 執行原則限制，請使用以下任一方式解決：

```powershell
# 方法 1: 臨時繞過執行原則
powershell.exe -ExecutionPolicy Bypass -File .\jt_procperf_analyzer.ps1

# 方法 2: 解除檔案封鎖
Unblock-File -Path .\jt_procperf_analyzer.ps1

# 方法 3: 變更執行原則（需管理員權限）
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Q2: 為什麼有些 Process 的 CPU 使用率顯示為 0？

**A:** CPU 使用率需要兩次取樣才能計算，因此第一次迭代時所有 Process 的 CPU 使用率都會是 0。從第二次迭代開始會顯示正確的數值。

### Q3: I/O 指標全部顯示為 0

**A:** 可能原因：
1. 第一次取樣時尚未建立基準值（第二次迭代後會正常）
2. Process 確實沒有 I/O 活動
3. WMI 查詢失敗（權限不足或 WMI 服務異常）

建議以管理員權限執行腳本。

### Q4: 輸出檔案中文顯示為亂碼

**A:** 確保腳本檔案以 **UTF-8 with BOM** 編碼儲存，並且輸出路徑沒有特殊字元。

### Q5: 監控時系統變慢

**A:** 監控本身會消耗資源，建議：
1. 增加取樣間隔（-IntervalSeconds 30 或更長）
2. 使用篩選條件減少監控的 Process 數量
3. 跳過不需要的指標（-SkipIOMetrics）

### Q6: 如何只監控目前正在執行的特定 Process？

**A:** 先查詢 Process ID，然後使用 IncludeProcesses：

```powershell
# 取得 Process 名稱
$ProcessName = (Get-Process -Id 1234).Name

# 監控該 Process
.\jt_procperf_analyzer.ps1 -IncludeProcesses $ProcessName
```

### Q7: 記憶體洩漏偵測的門檻可以調整嗎？

**A:** 可以！修改腳本中 `Get-MemoryLeakIndicators` 函式的判斷邏輯（477-479 行）：

```powershell
# 預設門檻
if ($LeakIndicators.MemoryGrowthMBPerMin -gt 5 -or $LeakIndicators.HandleGrowthPerMin -gt 10)

# 調整為更嚴格的門檻
if ($LeakIndicators.MemoryGrowthMBPerMin -gt 2 -or $LeakIndicators.HandleGrowthPerMin -gt 5)
```

---

## 🔧 疑難排解

### 錯誤：「無法建立輸出目錄」

**解決方法:**
- 檢查路徑是否正確
- 確認有寫入權限
- 使用絕對路徑而非相對路徑

### 錯誤：「Access Denied」或權限相關錯誤

**解決方法:**
- 以管理員權限執行 PowerShell
- 右鍵點選 PowerShell → 「以系統管理員身分執行」

### 效能計數器無法存取

**解決方法:**
```powershell
# 重建效能計數器
lodctr /R

# 確認 Performance Logs and Alerts 服務正在執行
Get-Service -Name "pla" | Start-Service
```

### WMI 查詢失敗

**解決方法:**
```powershell
# 重啟 WMI 服務
Restart-Service -Name "Winmgmt" -Force
```

---

## 📝 檔案編碼注意事項

**重要：** 腳本檔案必須以 **UTF-8 with BOM** 編碼儲存，否則中文註解可能無法正確顯示。

### 儲存方式
- **Visual Studio Code**: 點選右下角編碼 → "Save with Encoding" → "UTF-8 with BOM"
- **PowerShell ISE**: 預設為 UTF-8 with BOM（無需額外設定）
- **Notepad++**: 編碼選單 → "以 UTF-8-BOM 格式編碼"

---

## 📄 授權與支援

- **授權**: MIT License
- **作者**: JT Performance Analyzer Team
- **版本**: 2.0
- **更新日期**: 2025-12-13

### 意見回饋與問題回報

如有任何問題、建議或錯誤回報，請聯繫開發團隊或建立 Issue。

---

## 🎯 效能分析關鍵指標參考

### CPU 瓶頸
- `CPUPercent` > 80% 持續時間長
- `PrivilegedTimeSec` 高於 `UserTimeSec`（可能是 Driver 或 Kernel 問題）

### 記憶體洩漏
- `MemoryGrowthMBPerMin` > 5 持續增長
- `HandleGrowthPerMin` > 10 持續增長
- `PossibleMemoryLeak` = true

### I/O 瓶頸
- `IODataKBSec` > 10000（高 I/O 負載）
- `IOWriteKBSec` 遠高於 `IOReadKBSec`（大量寫入）

### 資源洩漏
- `HandleCount` 持續增長且不回收
- `ThreadCount` 異常增長

### 異常 Process
- `Responding` = false（未回應）
- `UptimeHours` 過長但持續高 CPU（可能卡住）
- `CPUPercent` = 100% 持續（可能進入無窮迴圈）

---

**Happy Monitoring! 🚀**
