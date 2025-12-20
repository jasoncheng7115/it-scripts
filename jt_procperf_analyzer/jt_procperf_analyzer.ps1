<#
================================================================================
  JT Process Performance Analyzer v2.10.14 (修復 PID 類型不匹配導致 I/O 為 0)
  Windows Process 效能監控與分析工具
================================================================================

  作者：   Jason Cheng (Jason Tools)
  版本：   2.10.14 (修復 PID 類型不匹配導致 I/O 為 0)
  日期：   2025-12-20
  授權：   MIT License

  Copyright (c) 2025 Jason Cheng (Jason Tools)

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.

================================================================================
  檔案編碼注意事項 / File Encoding Notice
================================================================================
  重要：此腳本必須以 UTF-8 with BOM 編碼儲存，以確保中文註解正確顯示

  儲存方式：
  - Visual Studio Code: 點選右下角編碼 → "Save with Encoding" → "UTF-8 with BOM"
  - PowerShell ISE: 預設為 UTF-8 with BOM（無需額外設定）
  - Notepad++: 編碼選單 → "以 UTF-8-BOM 格式編碼"

  執行原則設定（如遇到執行被封鎖）：
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
    或
    powershell.exe -ExecutionPolicy Bypass -File .\jt_procperf_analyzer.ps1
================================================================================

.SYNOPSIS
    Windows Process 效能監控與分析工具

.DESCRIPTION
    全方位的 Windows Process 效能監控工具，支援 CPU、記憶體、I/O、Thread、Handle 等多種效能指標收集。
    提供彈性的篩選機制、多種輸出格式，以及完整的錯誤處理與進度顯示。

    主要功能：
    ✓ 完整的效能指標收集（CPU、記憶體、I/O、Thread、Handle）
    ✓ 記憶體洩漏偵測（追蹤記憶體增長趨勢）
    ✓ 彈性的 Process 篩選（Include/Exclude、萬用字元、正規表示式）
    ✓ 多種輸出格式（JSON、CSV、TSV）
    ✓ 系統整體效能指標（可選）
    ✓ 即時進度顯示與 ETA 計算
    ✓ 完整的錯誤處理與日誌功能

.PARAMETER DurationMinutes
    監控總時長（分鐘），預設 60 分鐘

.PARAMETER IntervalSeconds
    取樣間隔（秒），範圍 1-3600，預設 60 秒

.PARAMETER OutputFormat
    輸出格式：CSV、JSON 或 TSV，預設 CSV

.PARAMETER OutputPath
    輸出目錄路徑，預設為腳本所在目錄

.PARAMETER OutputFileName
    自訂輸出檔名（不含副檔名），預設自動產生時間戳記檔名

.PARAMETER IncludeProcesses
    包含的 Process 名稱（包含名單），支援萬用字元或正規表示式

.PARAMETER ExcludeProcesses
    排除的 Process 名稱（排除名單），支援萬用字元或正規表示式

.PARAMETER MatchMode
    比對模式：Exact（精確）、Wildcard（萬用字元）或 Regex（正規表示式），預設 Wildcard

.PARAMETER IncludeSystemMetrics
    包含系統整體效能指標（CPU、記憶體、磁碟、網路）

.PARAMETER SkipGUIMetrics
    跳過 GUI 相關指標（GDI Objects、USER Objects）

.PARAMETER SkipIOMetrics
    跳過 I/O 相關指標（節省效能）

.PARAMETER EnableLogging
    啟用詳細執行日誌（Transcript）

.PARAMETER QuietMode
    靜默模式，最小化輸出資訊

.PARAMETER NoProgress
    不顯示進度列

.PARAMETER MinimumCPU
    只收集 CPU 使用率大於此值的 Process（百分比），預設 0.1%

.PARAMETER MinimumMemoryMB
    只收集記憶體使用量大於此值的 Process（MB）

.EXAMPLE
    .\jt_procperf_analyzer.ps1
    使用預設設定監控 60 分鐘，每 60 秒取樣一次，輸出 CSV 格式（預設不包含 Owner 資訊）

.EXAMPLE
    .\jt_procperf_analyzer.ps1 -DurationMinutes 30 -IntervalSeconds 5 -OutputFormat CSV
    監控 30 分鐘，每 5 秒取樣，輸出 CSV 格式

.EXAMPLE
    .\jt_procperf_analyzer.ps1 -IncludeProcesses "chrome","firefox" -MatchMode Wildcard
    只監控名稱包含 chrome 或 firefox 的 Process

.EXAMPLE
    .\jt_procperf_analyzer.ps1 -ExcludeProcesses "svchost","System" -MinimumCPU 5
    排除系統 Process，只收集 CPU > 5% 的 Process

.EXAMPLE
    .\jt_procperf_analyzer.ps1 -IncludeSystemMetrics -EnableLogging -OutputPath "C:\PerfLogs"
    包含系統指標、啟用日誌、自訂輸出路徑

.NOTES
    作者: Jason Cheng (Jason Tools)
    版本: 2.10.14
    發布日期: 2025-12-20
    需求: PowerShell 5.1+, Windows 7/Server 2008 R2+
    建議: 以管理員權限執行以取得完整指標
#>

[CmdletBinding()]
param(
    # Help 參數
    [Parameter(HelpMessage = "顯示詳細使用說明")]
    [Alias("h")]
    [switch]$Help,

    # 時間控制參數
    [Parameter(HelpMessage = "監控時長（分鐘）")]
    [Alias("Duration", "D")]
    [ValidateRange(1, 1440)]
    [int]$DurationMinutes = 60,

    [Parameter(HelpMessage = "取樣間隔（秒）")]
    [Alias("Interval", "I")]
    [ValidateRange(1, 3600)]
    [int]$IntervalSeconds = 60,

    # 輸出控制參數
    [Parameter(HelpMessage = "輸出格式：CSV、JSON 或 TSV")]
    [Alias("Format", "F")]
    [ValidateSet("CSV", "JSON", "TSV")]
    [string]$OutputFormat = "CSV",

    [Parameter(HelpMessage = "輸出目錄路徑")]
    [Alias("Path", "O")]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = $PSScriptRoot,

    [Parameter(HelpMessage = "自訂檔名（不含副檔名）")]
    [Alias("File", "Name")]
    [string]$OutputFileName = "",

    # Process 篩選參數
    [Parameter(HelpMessage = "包含的 Process（包含名單）")]
    [Alias("Include", "Inc")]
    [string[]]$IncludeProcesses = @(),

    [Parameter(HelpMessage = "排除的 Process（排除名單）")]
    [Alias("Exclude", "Exc")]
    [string[]]$ExcludeProcesses = @(),

    [Parameter(HelpMessage = "比對模式：Exact、Wildcard、Regex")]
    [Alias("Match", "M")]
    [ValidateSet("Exact", "Wildcard", "Regex")]
    [string]$MatchMode = "Wildcard",

    # 指標控制參數
    [Parameter(HelpMessage = "包含系統整體指標")]
    [Alias("System", "Sys")]
    [switch]$IncludeSystemMetrics,

    [Parameter(HelpMessage = "包含 CommandLine 資訊（預設不包含，可提升 30% 效能）")]
    [Alias("Cmd", "CommandLine")]
    [switch]$IncludeCommandLine,

    [Parameter(HelpMessage = "包含檔案版本資訊（預設不包含，可提升效能）")]
    [Alias("Ver", "Version")]
    [switch]$IncludeVersionInfo,

    [Parameter(HelpMessage = "包含 Owner 查詢（預設不包含，因會增加 WMI 負載）")]
    [Alias("Owner")]
    [switch]$IncludeOwnerInfo,

    [Parameter(HelpMessage = "跳過 GUI 相關指標")]
    [Alias("SkipGUI")]
    [switch]$SkipGUIMetrics,

    [Parameter(HelpMessage = "跳過 I/O 指標")]
    [Alias("SkipIO")]
    [switch]$SkipIOMetrics,

    # 資料聚合參數
    [Parameter(HelpMessage = "按 Process 名稱分組（合併相同名稱的 Process，加總 CPU、記憶體、I/O 等指標）")]
    [Alias("Group", "Aggregate", "Merge")]
    [switch]$GroupByProcessName,

    # 執行控制參數
    [Parameter(HelpMessage = "啟用詳細日誌")]
    [Alias("Log")]
    [switch]$EnableLogging,

    [Parameter(HelpMessage = "靜默模式")]
    [Alias("Quiet", "Q")]
    [switch]$QuietMode,

    [Parameter(HelpMessage = "不顯示進度列")]
    [Alias("NoProg")]
    [switch]$NoProgress,

    # 進階篩選參數
    [Parameter(HelpMessage = "最低 CPU 使用率（%），低於此值不記錄")]
    [Alias("MinCPU", "CPU")]
    [ValidateRange(0, 100)]
    [double]$MinimumCPU = 0.1,

    [Parameter(HelpMessage = "最低記憶體使用量（MB）")]
    [Alias("MinMemory", "Mem")]
    [ValidateRange(0, 1048576)]
    [int]$MinimumMemoryMB = 0,

    # 磁碟空間控制參數
    [Parameter(HelpMessage = "最低可用磁碟空間（MB），低於此值將自動停止收集")]
    [Alias("MinFreeSpace", "Space")]
    [ValidateRange(100, 102400)]
    [int]$MinimumFreeSpaceMB = 500
)

#region 版本資訊 (統一管理，只需修改此處)
$Script:VERSION = "2.10.14"
$Script:VERSION_NOTE = "修復 PID 類型不匹配導致 I/O 為 0"
$Script:VERSION_DATE = "2025-12-20"
$Script:AUTHOR = "Jason Cheng (Jason Tools)"
#endregion

#region Help 說明
if ($Help) {
    Write-Host @"
================================================================================
  JT Process Performance Analyzer v$Script:VERSION
  作者：$Script:AUTHOR
================================================================================

用途：
  Windows Process 效能監控與分析工具，支援 CPU、記憶體、I/O、記憶體洩漏偵測

基本用法：
  .\jt_procperf_analyzer.ps1 [參數...]

常用參數（使用短別名）：
  -D, -Duration <分鐘>         監控時長（預設：60）
  -I, -Interval <秒>           取樣間隔（預設：60）
  -F, -Format <格式>           輸出格式：CSV、JSON、TSV（預設：CSV）
  -O, -Path <路徑>             輸出目錄（預設：腳本所在目錄）
  -Inc, -Include <陣列>        包含的 Process（包含名單）
  -Exc, -Exclude <陣列>        排除的 Process（排除名單）
  -CPU, -MinCPU <百分比>       只收集 CPU > N% 的 Process（預設：0.1）
  -Mem, -MinMemory <MB>        只收集記憶體 > N MB 的 Process
  -Space <MB>                  最低磁碟可用空間（預設：500），低於此值自動停止
  -Owner                       包含 Owner 資訊（預設不包含，降低 WMI 負載）
  -Sys, -System                包含系統整體指標
  -Log                         啟用詳細日誌
  -Q, -Quiet                   靜默模式（最小化輸出）

常用範例（使用短別名）：

  1. 基本監控（60 分鐘，自動過濾 CPU < 0.1% 的 Process）
     .\jt_procperf_analyzer.ps1

  2. 快速監控（5 分鐘，CSV 格式）
     .\jt_procperf_analyzer.ps1 -D 5 -F CSV

  3. 監控特定 Process
     .\jt_procperf_analyzer.ps1 -Inc chrome,firefox

  4. 記憶體洩漏偵測（長時間監控）
     .\jt_procperf_analyzer.ps1 -D 360 -I 60

  5. 找出 CPU 殺手（只記錄 CPU > 10%）
     .\jt_procperf_analyzer.ps1 -CPU 10 -D 10

  6. 記錄所有 Process（包含 CPU < 0.1%）
     .\jt_procperf_analyzer.ps1 -CPU 0

  7. 完整系統監控
     .\jt_procperf_analyzer.ps1 -Sys -Log

  8. 10 秒間隔高頻監控（3 分鐘）
     .\jt_procperf_analyzer.ps1 -D 3 -I 10

  9. 只監控高記憶體程序（> 500 MB）
     .\jt_procperf_analyzer.ps1 -Mem 500

更多說明：
  Get-Help .\jt_procperf_analyzer.ps1 -Full
  或查看 README.md、QUICKSTART.md、Examples.ps1

輸出檔案位置：
  預設：C:\Users\<使用者>\Documents\process_metrics_YYYYMMDD_HHmmss.<格式>

作者：
  $Script:AUTHOR - v$Script:VERSION ($Script:VERSION_DATE)

================================================================================
"@ -ForegroundColor Cyan
    exit 0
}
#endregion

#region 停用 QuickEdit 模式（避免點擊視窗造成程式暫停）
try {
    # 使用 Windows API 停用 QuickEdit 模式
    # 這可以防止使用者誤點 PowerShell 視窗導致程式暫停執行

    # 檢查類型是否已載入（避免重複載入）
    $TypeLoaded = $null -ne ([System.Management.Automation.PSTypeName]'ConsoleQuickEdit').Type

    if (-not $TypeLoaded) {
        Add-Type @"
using System;
using System.Runtime.InteropServices;

public class ConsoleQuickEdit {
    private const uint ENABLE_QUICK_EDIT = 0x0040;
    private const uint ENABLE_EXTENDED_FLAGS = 0x0080;

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll")]
    private static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

    [DllImport("kernel32.dll")]
    private static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

    [DllImport("kernel32.dll")]
    private static extern bool FlushConsoleInputBuffer(IntPtr hConsoleInput);

    private const int STD_INPUT_HANDLE = -10;

    public static void Disable() {
        IntPtr handle = GetStdHandle(STD_INPUT_HANDLE);
        uint mode;
        GetConsoleMode(handle, out mode);
        mode &= ~ENABLE_QUICK_EDIT;
        mode |= ENABLE_EXTENDED_FLAGS;
        SetConsoleMode(handle, mode);
    }

    public static void FlushInput() {
        IntPtr handle = GetStdHandle(STD_INPUT_HANDLE);
        FlushConsoleInputBuffer(handle);
    }
}
"@
    }

    [ConsoleQuickEdit]::Disable()
    $Timestamp = Get-Date -Format "HH:mm:ss.fff"
    Write-Host "[$Timestamp] " -ForegroundColor DarkGray -NoNewline
    Write-Host "[系統] QuickEdit 模式已停用（避免點擊視窗造成暫停）" -ForegroundColor Green
}
catch {
    # 如果停用失敗（例如在非 Windows Console 環境），顯示警告
    $Timestamp = Get-Date -Format "HH:mm:ss.fff"
    Write-Host "[$Timestamp] " -ForegroundColor DarkGray -NoNewline
    Write-Host "[警告] 無法停用 QuickEdit 模式：$($_.Exception.Message)" -ForegroundColor Yellow
    $Timestamp = Get-Date -Format "HH:mm:ss.fff"
    Write-Host "[$Timestamp] " -ForegroundColor DarkGray -NoNewline
    Write-Host "[警告] 請勿點擊 PowerShell 視窗，否則程式可能暫停" -ForegroundColor Yellow
}
#endregion

#region 全域變數設定
$ErrorActionPreference = "Continue"
$Script:ErrorCount = 0
$Script:StartTime = Get-Date
$Script:TotalIterations = [Math]::Floor($DurationMinutes * 60 / $IntervalSeconds)
$Script:CurrentIteration = 0
$Script:ProcessMetricsCollection = [System.Collections.ArrayList]::new()
$Script:SystemMetricsCollection = [System.Collections.ArrayList]::new()
$Script:LastCPUMeasurements = @{}
$Script:LastMemoryMeasurements = @{}
$Script:LastIOMeasurements = @{}
#endregion

#region 輔助函式 - 顏色輸出
function Get-Timestamp {
    return (Get-Date -Format "HH:mm:ss.fff")
}

function Write-ColorMessage {
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Type = "Info"
    )

    if ($QuietMode -and $Type -ne "Error") { return }

    $ColorMap = @{
        "Info"    = "Cyan"
        "Success" = "Green"
        "Warning" = "Yellow"
        "Error"   = "Red"
    }

    $Prefix = @{
        "Info"    = "[INFO]"
        "Success" = "[✓]"
        "Warning" = "[!]"
        "Error"   = "[✗]"
    }

    $Timestamp = Get-Timestamp
    Write-Host "[$Timestamp] " -ForegroundColor DarkGray -NoNewline
    Write-Host "$($Prefix[$Type]) " -ForegroundColor $ColorMap[$Type] -NoNewline
    Write-Host $Message
}

function Write-DebugMessage {
    param([string]$Message)
    if ($QuietMode) { return }
    $Timestamp = Get-Timestamp
    Write-Host "[$Timestamp] " -ForegroundColor DarkGray -NoNewline
    Write-Host $Message
}
#endregion

#region 輔助函式 - 環境檢查
function Test-DiskSpace {
    <#
    .SYNOPSIS
        檢查指定路徑所在磁碟的可用空間

    .PARAMETER Path
        要檢查的路徑

    .PARAMETER MinimumFreeMB
        最低可用空間（MB）

    .PARAMETER StopOnLowSpace
        如果可用空間不足，是否應該停止（$true）或僅警告（$false）

    .OUTPUTS
        如果空間充足返回 $true，否則返回 $false
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [int]$MinimumFreeMB,

        [Parameter(Mandatory = $false)]
        [bool]$StopOnLowSpace = $true
    )

    try {
        # 取得磁碟機資訊
        $Drive = (Get-Item $Path -ErrorAction Stop).PSDrive
        $FreeSpaceMB = [Math]::Round(($Drive.Free / 1MB), 2)
        $FreeSpaceGB = [Math]::Round(($Drive.Free / 1GB), 2)

        # 檢查空間是否足夠
        if ($Drive.Free -lt ($MinimumFreeMB * 1MB)) {
            if ($StopOnLowSpace) {
                Write-ColorMessage "磁碟空間不足！可用空間：${FreeSpaceMB} MB (${FreeSpaceGB} GB)，需要：${MinimumFreeMB} MB" -Type Error
                Write-ColorMessage "程式將自動停止以避免寫入失敗" -Type Error
            }
            else {
                Write-ColorMessage "磁碟空間偏低：${FreeSpaceMB} MB (${FreeSpaceGB} GB)，建議最少：${MinimumFreeMB} MB" -Type Warning
            }
            return $false
        }
        else {
            Write-Verbose "磁碟可用空間：${FreeSpaceMB} MB (${FreeSpaceGB} GB)"
            return $true
        }
    }
    catch {
        Write-ColorMessage "無法檢查磁碟空間：$($_.Exception.Message)" -Type Warning
        # 如果無法檢查，保守起見返回 true 允許繼續
        return $true
    }
}

function Test-Environment {
    Write-ColorMessage "正在檢查執行環境..." -Type Info

    # 檢查 PowerShell 版本
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-ColorMessage "需要 PowerShell 5.1 或更新版本，目前版本：$($PSVersionTable.PSVersion)" -Type Error
        return $false
    }

    # 檢查是否為管理員
    $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $IsAdmin) {
        Write-ColorMessage "未以管理員權限執行，某些效能計數器可能無法存取" -Type Warning
    }

    # 檢查輸出路徑
    if (-not (Test-Path -Path $OutputPath)) {
        try {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
            Write-ColorMessage "已建立輸出目錄：$OutputPath" -Type Success
        }
        catch {
            Write-ColorMessage "無法建立輸出目錄：$($_.Exception.Message)" -Type Error
            return $false
        }
    }

    # 檢查寫入權限
    $TestFile = Join-Path $OutputPath "test_write_$(Get-Random).tmp"
    try {
        [System.IO.File]::WriteAllText($TestFile, "test")
        Remove-Item $TestFile -Force
    }
    catch {
        Write-ColorMessage "輸出目錄無寫入權限：$OutputPath" -Type Error
        return $false
    }

    # 檢查磁碟空間
    if (-not (Test-DiskSpace -Path $OutputPath -MinimumFreeMB $MinimumFreeSpaceMB -StopOnLowSpace $true)) {
        Write-ColorMessage "磁碟空間不足，無法開始收集" -Type Error
        return $false
    }

    Write-ColorMessage "環境檢查完成 ✓" -Type Success
    return $true
}
#endregion

#region 輔助函式 - Process 篩選
function Test-ProcessMatch {
    param(
        [string]$ProcessName,
        [string[]]$Patterns,
        [string]$Mode
    )

    if ($Patterns.Count -eq 0) { return $false }

    foreach ($Pattern in $Patterns) {
        $IsMatch = switch ($Mode) {
            "Exact" { $ProcessName -eq $Pattern }
            "Wildcard" { $ProcessName -like $Pattern }
            "Regex" { $ProcessName -match $Pattern }
        }

        if ($IsMatch) { return $true }
    }

    return $false
}

function Test-ProcessFilter {
    param(
        [string]$ProcessName
    )

    # 如果有包含名單，必須符合包含名單
    if ($IncludeProcesses.Count -gt 0) {
        if (-not (Test-ProcessMatch -ProcessName $ProcessName -Patterns $IncludeProcesses -Mode $MatchMode)) {
            return $false
        }
    }

    # 檢查排除名單
    if ($ExcludeProcesses.Count -gt 0) {
        if (Test-ProcessMatch -ProcessName $ProcessName -Patterns $ExcludeProcesses -Mode $MatchMode) {
            return $false
        }
    }

    return $true
}
#endregion

#region 輔助函式 - 效能數據收集
function Get-ProcessCPUPercent {
    param(
        [System.Diagnostics.Process]$Process
    )

    try {
        $ProcessID = $Process.Id
        $ProcessName = $Process.Name

        # 取得當前 CPU Time
        $CurrentCPUTime = $Process.TotalProcessorTime.TotalMilliseconds
        $CurrentTime = Get-Date

        # 如果有上次的測量值，計算 CPU 使用率
        if ($Script:LastCPUMeasurements.ContainsKey($ProcessID)) {
            $LastMeasure = $Script:LastCPUMeasurements[$ProcessID]
            $TimeDiff = ($CurrentTime - $LastMeasure.Time).TotalMilliseconds

            if ($TimeDiff -gt 0) {
                $CPUDiff = $CurrentCPUTime - $LastMeasure.CPUTime
                $CPUPercent = [Math]::Round(($CPUDiff / $TimeDiff) * 100 / $env:NUMBER_OF_PROCESSORS, 2)
            }
            else {
                $CPUPercent = 0
            }
        }
        else {
            $CPUPercent = 0
        }

        # 儲存當前測量值
        $Script:LastCPUMeasurements[$ProcessID] = @{
            Time    = $CurrentTime
            CPUTime = $CurrentCPUTime
        }

        return $CPUPercent
    }
    catch {
        return 0
    }
}

function Get-ProcessIOMetrics {
    param(
        [System.Diagnostics.Process]$Process,
        [Parameter(Mandatory = $false)]
        [object]$WMIProcessData = $null,  # 預先查詢的 WMI Process 資料（批次查詢優化）
        [Parameter(Mandatory = $false)]
        [DateTime]$CurrentTime = (Get-Date)  # 當前時間（避免重複呼叫 Get-Date）
    )

    try {
        $ProcessID = $Process.Id

        # 只讀取 Read/Write，完全跳過 Other（節省 33% 操作）
        $ReadBytes = 0
        $WriteBytes = 0

        # 從 WMI 取得 I/O 資訊（優先使用批次查詢的資料）
        if ($null -ne $WMIProcessData) {
            $ReadBytes = 0 + $WMIProcessData.ReadTransferCount
            $WriteBytes = 0 + $WMIProcessData.WriteTransferCount
        }

        # 計算速率（與上次測量比較）
        $ReadBytesSec = 0
        $WriteBytesSec = 0

        if ($Script:LastIOMeasurements.ContainsKey($ProcessID)) {
            $LastMeasure = $Script:LastIOMeasurements[$ProcessID]
            $TimeDiff = ($CurrentTime - $LastMeasure.Time).TotalSeconds

            if ($TimeDiff -gt 0) {
                $TimeDiffKB = $TimeDiff * 1KB
                $ReadDiff = $ReadBytes - $LastMeasure.ReadBytes
                $WriteDiff = $WriteBytes - $LastMeasure.WriteBytes

                if ($ReadDiff -gt 0) { $ReadBytesSec = [Math]::Round($ReadDiff / $TimeDiffKB, 1) }
                if ($WriteDiff -gt 0) { $WriteBytesSec = [Math]::Round($WriteDiff / $TimeDiffKB, 1) }
            }
        }

        # 更新測量值（只儲存 Read/Write，節省記憶體和時間）
        if (-not $Script:LastIOMeasurements.ContainsKey($ProcessID)) {
            $Script:LastIOMeasurements[$ProcessID] = @{
                Time       = $CurrentTime
                ReadBytes  = $ReadBytes
                WriteBytes = $WriteBytes
            }
        } else {
            $Measure = $Script:LastIOMeasurements[$ProcessID]
            $Measure.Time = $CurrentTime
            $Measure.ReadBytes = $ReadBytes
            $Measure.WriteBytes = $WriteBytes
        }

        # 只返回 Read/Write 速率
        return @{
            ReadBytesSec  = $ReadBytesSec
            WriteBytesSec = $WriteBytesSec
            OtherBytesSec = 0
            ReadOpsSec    = 0
            WriteOpsSec   = 0
            OtherOpsSec   = 0
        }
    }
    catch {
        return @{
            ReadBytesSec  = 0
            WriteBytesSec = 0
            OtherBytesSec = 0
            ReadOpsSec    = 0
            WriteOpsSec   = 0
            OtherOpsSec   = 0
        }
    }
}

function Get-AllServicesMap {
    # 批次查詢所有服務，建立 PID -> 服務名稱 的映射表
    # 這樣只查詢一次，避免每個 Process 都查詢
    try {
        $ServiceMap = @{}
        $AllServices = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue

        foreach ($Service in $AllServices) {
            $PID = $Service.ProcessId
            if ($PID -gt 0) {
                if ($ServiceMap.ContainsKey($PID)) {
                    # 如果已經有服務，追加
                    $ServiceMap[$PID] += "; $($Service.Name)"
                }
                else {
                    # 第一個服務
                    $ServiceMap[$PID] = $Service.Name
                }
            }
        }

        return $ServiceMap
    }
    catch {
        return @{}
    }
}

function Get-MemoryLeakIndicators {
    param(
        [int]$ProcessID,
        [double]$CurrentWorkingSetMB,
        [double]$CurrentPrivateMemoryMB,
        [int]$CurrentHandleCount
    )

    try {
        $LeakIndicators = @{
            MemoryGrowthMBPerMin = 0
            HandleGrowthPerMin   = 0
            PossibleLeak         = $false
        }

        if ($Script:LastMemoryMeasurements.ContainsKey($ProcessID)) {
            $LastMeasure = $Script:LastMemoryMeasurements[$ProcessID]
            $TimeDiff = ((Get-Date) - $LastMeasure.Time).TotalMinutes

            if ($TimeDiff -gt 0) {
                $WorkingSetDelta = $CurrentWorkingSetMB - $LastMeasure.WorkingSetMB
                $PrivateMemoryDelta = $CurrentPrivateMemoryMB - $LastMeasure.PrivateMemoryMB
                $HandleDelta = $CurrentHandleCount - $LastMeasure.HandleCount

                $LeakIndicators.MemoryGrowthMBPerMin = [Math]::Round($WorkingSetDelta / $TimeDiff, 2)
                $LeakIndicators.HandleGrowthPerMin = [Math]::Round($HandleDelta / $TimeDiff, 2)

                # 簡單的洩漏偵測邏輯：持續增長
                if ($LeakIndicators.MemoryGrowthMBPerMin -gt 5 -or $LeakIndicators.HandleGrowthPerMin -gt 10) {
                    $LeakIndicators.PossibleLeak = $true
                }
            }
        }

        # 更新測量值
        $Script:LastMemoryMeasurements[$ProcessID] = @{
            Time              = Get-Date
            WorkingSetMB      = $CurrentWorkingSetMB
            PrivateMemoryMB   = $CurrentPrivateMemoryMB
            HandleCount       = $CurrentHandleCount
        }

        return $LeakIndicators
    }
    catch {
        return @{
            MemoryGrowthMBPerMin = 0
            HandleGrowthPerMin   = 0
            PossibleLeak         = $false
        }
    }
}

function Get-ProcessMetrics {
    param(
        [System.Diagnostics.Process]$Process,
        [Parameter(Mandatory = $false)]
        [object]$WMIProcessData = $null,  # 預先查詢的 WMI Process 資料（批次查詢優化）
        [Parameter(Mandatory = $false)]
        [bool]$IsWarmup = $false,  # 是否為暖機階段（前兩次取樣）
        [Parameter(Mandatory = $false)]
        [hashtable]$ProcessMap = $null,  # PID -> Process 的 Hashtable（用於快速查找父程序）
        [Parameter(Mandatory = $false)]
        [hashtable]$ServiceMap = $null,  # PID -> 服務名稱 的 Hashtable（用於快速查找服務）
        [Parameter(Mandatory = $false)]
        [string]$SamplingTimestamp = ""  # 取樣時間戳記（同一取樣間隔的所有 Process 使用相同時間）
    )

    $FunctionStart = Get-Date
    $StepTimes = @{}

    try {
        $Metrics = [PSCustomObject]@{
            # 基本資訊
            Timestamp       = if ($SamplingTimestamp) { $SamplingTimestamp } else { Get-Date -Format "yyyy-MM-dd HH:mm:ss" }
            ProcessName     = $Process.Name
            ProcessID       = $Process.Id
            ParentProcessID = 0
            ParentProcessName = ""
            ProcessPath     = ""
            CommandLine     = ""
            IsWarmup        = $IsWarmup

            # CPU 指標
            CPUPercent      = 0
            CPUTimeTotalSec = 0
            UserTimeSec     = 0
            PrivilegedTimeSec = 0
            PriorityClass   = ""
            BasePriority    = 0

            # 記憶體指標
            WorkingSetMB    = 0
            PrivateMemoryMB = 0
            VirtualMemoryMB = 0
            PagedMemoryMB   = 0
            NonPagedMemoryMB = 0
            PeakWorkingSetMB = 0
            PageFaultsSec   = 0

            # 記憶體洩漏指標
            MemoryGrowthMBPerMin = 0
            HandleGrowthPerMin   = 0
            PossibleMemoryLeak   = $false

            # I/O 指標
            IOReadKBSec     = 0
            IOWriteKBSec    = 0
            IOOtherKBSec    = 0
            IOReadOpsSec    = 0
            IOWriteOpsSec   = 0
            IODataKBSec     = 0

            # Thread 與 Handle
            ThreadCount     = 0
            HandleCount     = 0

            # Process 狀態
            StartTime       = ""
            UptimeHours     = 0
            Responding      = $true
            SessionID       = 0
            Owner           = ""
            CompanyName     = ""
            ProductVersion  = ""
            ServiceNames    = ""
        }

        # 基本資訊
        try { $Metrics.ProcessPath = $Process.Path } catch { }
        $StepTimes.BasicInfo = ((Get-Date) - $FunctionStart).TotalMilliseconds

        $ExtInfoStart = Get-Date

        # 父程序資訊（始終收集，因為從 Hashtable 查找很快，零效能影響）
        if ($null -ne $WMIProcessData) {
            try {
                if ($WMIProcessData.ParentProcessId) {
                    $Metrics.ParentProcessID = $WMIProcessData.ParentProcessId

                    # 查找父程序名稱（從 Hashtable 中查找，O(1) 時間複雜度）
                    if ($null -ne $ProcessMap -and $ProcessMap.ContainsKey($WMIProcessData.ParentProcessId)) {
                        try {
                            $ParentProc = $ProcessMap[$WMIProcessData.ParentProcessId]
                            if ($ParentProc) {
                                $Metrics.ParentProcessName = $ParentProc.Name
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        # CommandLine 資訊（預設不收集，可選擇包含）
        if ($IncludeCommandLine) {
            try {
                if ($null -ne $WMIProcessData) {
                    $Metrics.CommandLine = $WMIProcessData.CommandLine
                }
                else {
                    # 如果沒有傳入 WMI 資料，則個別查詢（向後相容）
                    $WMIProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction SilentlyContinue
                    if ($WMIProcess) {
                        $Metrics.CommandLine = $WMIProcess.CommandLine
                    }
                }
            }
            catch { }
        }

        # Owner 查詢（預設不查詢，因為每個 Process 都需要調用 WMI 方法，會增加 CPU 負載）
        if ($IncludeOwnerInfo) {
            try {
                if ($null -ne $WMIProcessData) {
                    $Owner = Invoke-CimMethod -InputObject $WMIProcessData -MethodName GetOwner -ErrorAction SilentlyContinue
                    if ($Owner -and $Owner.User) {
                        $Metrics.Owner = "$($Owner.Domain)\$($Owner.User)"
                    }
                }
                else {
                    $WMIProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction SilentlyContinue
                    if ($WMIProcess) {
                        $Owner = Invoke-CimMethod -InputObject $WMIProcess -MethodName GetOwner -ErrorAction SilentlyContinue
                        if ($Owner -and $Owner.User) {
                            $Metrics.Owner = "$($Owner.Domain)\$($Owner.User)"
                        }
                    }
                }
            }
            catch { }
        }

        # 取得版本資訊（預設不收集，可選擇包含）
        if ($IncludeVersionInfo) {
            $VersionStart = Get-Date
            try {
                if ($Process.Path) {
                    $FileInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Process.Path)
                    $Metrics.CompanyName = $FileInfo.CompanyName
                    $Metrics.ProductVersion = $FileInfo.ProductVersion
                }
            }
            catch { }
            $StepTimes.VersionInfo = ((Get-Date) - $VersionStart).TotalMilliseconds
        }

        $StepTimes.ExtInfoTotal = ((Get-Date) - $ExtInfoStart).TotalMilliseconds

        # CPU 指標
        $CPUStart = Get-Date
        $Metrics.CPUPercent = Get-ProcessCPUPercent -Process $Process
        $Metrics.CPUTimeTotalSec = [Math]::Round($Process.TotalProcessorTime.TotalSeconds, 2)
        $Metrics.UserTimeSec = [Math]::Round($Process.UserProcessorTime.TotalSeconds, 2)
        $Metrics.PrivilegedTimeSec = [Math]::Round($Process.PrivilegedProcessorTime.TotalSeconds, 2)
        try { $Metrics.PriorityClass = $Process.PriorityClass.ToString() } catch { $Metrics.PriorityClass = "Unknown" }
        $Metrics.BasePriority = $Process.BasePriority
        $StepTimes.CPU = ((Get-Date) - $CPUStart).TotalMilliseconds

        # 記憶體指標
        $MemStart = Get-Date
        $Metrics.WorkingSetMB = [Math]::Round($Process.WorkingSet64 / 1MB, 2)
        $Metrics.PrivateMemoryMB = [Math]::Round($Process.PrivateMemorySize64 / 1MB, 2)
        $Metrics.VirtualMemoryMB = [Math]::Round($Process.VirtualMemorySize64 / 1MB, 2)
        $Metrics.PagedMemoryMB = [Math]::Round($Process.PagedMemorySize64 / 1MB, 2)
        $Metrics.NonPagedMemoryMB = [Math]::Round($Process.NonpagedSystemMemorySize64 / 1MB, 2)
        $Metrics.PeakWorkingSetMB = [Math]::Round($Process.PeakWorkingSet64 / 1MB, 2)
        $StepTimes.Memory = ((Get-Date) - $MemStart).TotalMilliseconds

        # Thread 與 Handle
        $ThreadStart = Get-Date
        # 優先從 WMI 取得 ThreadCount（避免遍歷 Threads 集合，效能提升巨大）
        if ($null -ne $WMIProcessData -and $WMIProcessData.ThreadCount) {
            $Metrics.ThreadCount = $WMIProcessData.ThreadCount
        } else {
            $Metrics.ThreadCount = $Process.Threads.Count  # 後備方案（慢）
        }
        $Metrics.HandleCount = $Process.HandleCount
        $StepTimes.ThreadHandle = ((Get-Date) - $ThreadStart).TotalMilliseconds

        # 記憶體洩漏偵測
        $LeakStart = Get-Date
        $LeakIndicators = Get-MemoryLeakIndicators -ProcessID $Process.Id -CurrentWorkingSetMB $Metrics.WorkingSetMB -CurrentPrivateMemoryMB $Metrics.PrivateMemoryMB -CurrentHandleCount $Metrics.HandleCount
        $Metrics.MemoryGrowthMBPerMin = $LeakIndicators.MemoryGrowthMBPerMin
        $Metrics.HandleGrowthPerMin = $LeakIndicators.HandleGrowthPerMin
        $Metrics.PossibleMemoryLeak = $LeakIndicators.PossibleLeak
        $StepTimes.MemoryLeak = ((Get-Date) - $LeakStart).TotalMilliseconds

        # I/O 指標（內聯計算以提升效能，避免函數調用開銷）
        if (-not $SkipIOMetrics) {
            $IOStart = Get-Date

            # 從 WMI 讀取 I/O 數據（只讀 Read/Write，跳過 Other）
            $ReadBytes = 0
            $WriteBytes = 0
            if ($null -ne $WMIProcessData) {
                $ReadBytes = 0 + $WMIProcessData.ReadTransferCount
                $WriteBytes = 0 + $WMIProcessData.WriteTransferCount
            }

            # 計算速率（與上次測量比較）
            $ProcessID = $Process.Id
            if ($Script:LastIOMeasurements.ContainsKey($ProcessID)) {
                $LastMeasure = $Script:LastIOMeasurements[$ProcessID]
                $TimeDiff = ($FunctionStart - $LastMeasure.Time).TotalSeconds

                if ($TimeDiff -gt 0) {
                    $TimeDiffKB = $TimeDiff * 1KB
                    $ReadDiff = $ReadBytes - $LastMeasure.ReadBytes
                    $WriteDiff = $WriteBytes - $LastMeasure.WriteBytes

                    if ($ReadDiff -gt 0) { $Metrics.IOReadKBSec = [Math]::Round($ReadDiff / $TimeDiffKB, 1) }
                    if ($WriteDiff -gt 0) { $Metrics.IOWriteKBSec = [Math]::Round($WriteDiff / $TimeDiffKB, 1) }
                }
            }

            # 更新測量值
            if (-not $Script:LastIOMeasurements.ContainsKey($ProcessID)) {
                $Script:LastIOMeasurements[$ProcessID] = @{
                    Time = $FunctionStart
                    ReadBytes = $ReadBytes
                    WriteBytes = $WriteBytes
                }
            } else {
                $Measure = $Script:LastIOMeasurements[$ProcessID]
                $Measure.Time = $FunctionStart
                $Measure.ReadBytes = $ReadBytes
                $Measure.WriteBytes = $WriteBytes
            }

            $Metrics.IODataKBSec = $Metrics.IOReadKBSec + $Metrics.IOWriteKBSec
            $StepTimes.IO = ((Get-Date) - $IOStart).TotalMilliseconds
        }

        # Process 狀態
        $StatusStart = Get-Date
        try {
            # 檢查 StartTime 是否為有效的 DateTime 物件
            if ($null -ne $Process.StartTime -and $Process.StartTime -is [DateTime]) {
                $Metrics.StartTime = $Process.StartTime.ToString("yyyy-MM-dd HH:mm:ss")
                $Metrics.UptimeHours = [Math]::Round(((Get-Date) - $Process.StartTime).TotalHours, 2)
            }
            else {
                # StartTime 無效或不存在（如 Idle, System Process）
                $Metrics.StartTime = ""
                $Metrics.UptimeHours = 0
            }
        }
        catch {
            # 使用空字串而非 "N/A"，避免 CSV 寫入時 DateTime 轉換錯誤
            $Metrics.StartTime = ""
            $Metrics.UptimeHours = 0
        }

        try { $Metrics.Responding = $Process.Responding } catch { $Metrics.Responding = $true }
        $Metrics.SessionID = $Process.SessionId

        # 服務名稱（對於 svchost 等服務承載進程特別有用）
        if ($null -ne $ServiceMap -and $ServiceMap.ContainsKey($Process.Id)) {
            $Metrics.ServiceNames = $ServiceMap[$Process.Id]
        }

        $StepTimes.Status = ((Get-Date) - $StatusStart).TotalMilliseconds

        # 診斷：如果處理時間超過 100ms，輸出詳細計時
        $FunctionEnd = Get-Date
        $TotalTime = ($FunctionEnd - $FunctionStart).TotalMilliseconds
        if ($TotalTime -gt 100) {
            Write-DebugMessage "[效能診斷] Process '$($Process.Name)' (PID: $($Process.Id)) 處理耗時: $([Math]::Round($TotalTime, 0)) ms"
            if ($StepTimes.Count -gt 0) {
                $StepDetails = $StepTimes.Keys | ForEach-Object { "$_=$([Math]::Round($StepTimes[$_], 0))ms" }
                Write-DebugMessage "  分段耗時: $($StepDetails -join ', ')"
            }
        }

        return $Metrics
    }
    catch {
        Write-Verbose "收集 Process $($Process.Name) (PID: $($Process.Id)) 的效能數據時發生錯誤: $($_.Exception.Message)"
        $Script:ErrorCount++
        return $null
    }
}

function Get-SystemMetrics {
    try {
        $Metrics = [PSCustomObject]@{
            Timestamp           = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            TotalCPUPercent     = 0
            AvailableMemoryMB   = 0
            CommittedMemoryMB   = 0
            CommittedMemoryPercent = 0
            ProcessCount        = 0
            ThreadCount         = 0
        }

        # CPU 使用率
        $CPUCounter = Get-Counter -Counter "\Processor(_Total)\% Processor Time" -ErrorAction SilentlyContinue
        if ($CPUCounter) {
            $Metrics.TotalCPUPercent = [Math]::Round($CPUCounter.CounterSamples[0].CookedValue, 2)
        }

        # 記憶體資訊
        $OS = Get-CimInstance Win32_OperatingSystem
        $Metrics.AvailableMemoryMB = [Math]::Round($OS.FreePhysicalMemory / 1KB, 2)
        $Metrics.CommittedMemoryMB = [Math]::Round(($OS.TotalVisibleMemorySize - $OS.FreePhysicalMemory) / 1KB, 2)
        $Metrics.CommittedMemoryPercent = [Math]::Round(($Metrics.CommittedMemoryMB / ($OS.TotalVisibleMemorySize / 1KB)) * 100, 2)

        # Process 與 Thread 數量
        $Metrics.ProcessCount = (Get-Process).Count
        $Metrics.ThreadCount = (Get-Process | Measure-Object -Property Threads -Sum).Sum

        return $Metrics
    }
    catch {
        Write-Verbose "收集系統效能數據時發生錯誤: $($_.Exception.Message)"
        return $null
    }
}
#endregion

#region 輔助函式 - 檔案輸出
function Get-OutputFilePath {
    $Extension = switch ($OutputFormat) {
        "CSV" { ".csv" }
        "JSON" { ".json" }
        "TSV" { ".tsv" }
    }

    if ([string]::IsNullOrWhiteSpace($OutputFileName)) {
        $FileName = "process_metrics_$(Get-Date -Format 'yyyyMMdd_HHmmss')$Extension"
    }
    else {
        $FileName = "$OutputFileName$Extension"
    }

    return Join-Path $OutputPath $FileName
}

function Merge-ProcessMetricsByName {
    <#
    .SYNOPSIS
        合併相同 ProcessName 的所有 Process 指標

    .DESCRIPTION
        將相同 ProcessName 的所有 Process 實例合併成一筆資料
        數值型指標（CPU、記憶體、I/O 等）會加總
        文字型指標會合併或取代表性值

    .PARAMETER Metrics
        要合併的 Process 指標陣列

    .OUTPUTS
        合併後的指標陣列
    #>
    param(
        [Parameter(Mandatory = $true)]
        [array]$Metrics
    )

    if ($Metrics.Count -eq 0) {
        return @()
    }

    # 按 ProcessName 分組
    $GroupedMetrics = $Metrics | Group-Object -Property ProcessName

    $MergedMetrics = @()

    foreach ($Group in $GroupedMetrics) {
        $ProcessName = $Group.Name
        $Instances = $Group.Group
        $InstanceCount = $Instances.Count

        # 如果只有一個實例，直接使用
        if ($InstanceCount -eq 1) {
            $MergedMetrics += $Instances[0]
            continue
        }

        # 多個實例：建立合併後的指標
        $Merged = [PSCustomObject]@{
            Timestamp           = $Instances[0].Timestamp
            ProcessName         = $ProcessName
            ProcessID           = "Multiple ($InstanceCount)"  # 顯示實例數量
            ParentProcessID     = if ($Instances[0].ParentProcessID) { "Various" } else { "" }
            ParentProcessName   = if ($Instances[0].ParentProcessName) { "Various" } else { "" }
            ProcessPath         = $Instances[0].ProcessPath  # 取第一個
            CommandLine         = if ($Instances[0].CommandLine) { "Multiple instances" } else { "" }
            IsWarmup            = $Instances[0].IsWarmup

            # CPU 指標（加總）
            CPUPercent          = ($Instances | Measure-Object -Property CPUPercent -Sum).Sum
            CPUTimeTotalSec     = ($Instances | Measure-Object -Property CPUTimeTotalSec -Sum).Sum
            UserTimeSec         = ($Instances | Measure-Object -Property UserTimeSec -Sum).Sum
            PrivilegedTimeSec   = ($Instances | Measure-Object -Property PrivilegedTimeSec -Sum).Sum

            # 優先級（取第一個）
            PriorityClass       = $Instances[0].PriorityClass
            BasePriority        = $Instances[0].BasePriority

            # 記憶體指標（加總）
            WorkingSetMB        = ($Instances | Measure-Object -Property WorkingSetMB -Sum).Sum
            PrivateMemoryMB     = ($Instances | Measure-Object -Property PrivateMemoryMB -Sum).Sum
            VirtualMemoryMB     = ($Instances | Measure-Object -Property VirtualMemoryMB -Sum).Sum
            PagedMemoryMB       = ($Instances | Measure-Object -Property PagedMemoryMB -Sum).Sum
            NonPagedMemoryMB    = ($Instances | Measure-Object -Property NonPagedMemoryMB -Sum).Sum
            PeakWorkingSetMB    = ($Instances | Measure-Object -Property PeakWorkingSetMB -Sum).Sum

            # 記憶體成長率（加總）
            PageFaultsSec       = ($Instances | Measure-Object -Property PageFaultsSec -Sum).Sum
            MemoryGrowthMBPerMin = ($Instances | Measure-Object -Property MemoryGrowthMBPerMin -Sum).Sum
            HandleGrowthPerMin  = ($Instances | Measure-Object -Property HandleGrowthPerMin -Sum).Sum
            PossibleMemoryLeak  = ($Instances | Where-Object { $_.PossibleMemoryLeak -eq $true }).Count -gt 0

            # I/O 指標（加總）
            IOReadKBSec         = ($Instances | Measure-Object -Property IOReadKBSec -Sum).Sum
            IOWriteKBSec        = ($Instances | Measure-Object -Property IOWriteKBSec -Sum).Sum
            IOOtherKBSec        = ($Instances | Measure-Object -Property IOOtherKBSec -Sum).Sum
            IOReadOpsSec        = ($Instances | Measure-Object -Property IOReadOpsSec -Sum).Sum
            IOWriteOpsSec       = ($Instances | Measure-Object -Property IOWriteOpsSec -Sum).Sum
            IODataKBSec         = ($Instances | Measure-Object -Property IODataKBSec -Sum).Sum

            # Thread 和 Handle（加總）
            ThreadCount         = ($Instances | Measure-Object -Property ThreadCount -Sum).Sum
            HandleCount         = ($Instances | Measure-Object -Property HandleCount -Sum).Sum

            # StartTime（取最早的）
            StartTime           = ($Instances | Where-Object { $_.StartTime -ne "" } | Sort-Object StartTime | Select-Object -First 1).StartTime
            UptimeHours         = ($Instances | Measure-Object -Property UptimeHours -Average).Average

            # 回應狀態（全部回應才算回應）
            Responding          = ($Instances | Where-Object { $_.Responding -eq $false }).Count -eq 0

            # SessionID（取第一個）
            SessionID           = $Instances[0].SessionID

            # Owner（合併唯一值）
            Owner               = ($Instances.Owner | Where-Object { $_ -ne "" } | Select-Object -Unique) -join "; "

            # 版本資訊（取第一個）
            CompanyName         = $Instances[0].CompanyName
            ProductVersion      = $Instances[0].ProductVersion

            # 服務名稱（合併所有服務）
            ServiceNames        = ($Instances.ServiceNames | Where-Object { $_ -ne "" } | Select-Object -Unique) -join "; "
        }

        # 四捨五入數值（保持與原始資料一致）
        $Merged.CPUPercent = [Math]::Round($Merged.CPUPercent, 2)
        $Merged.CPUTimeTotalSec = [Math]::Round($Merged.CPUTimeTotalSec, 2)
        $Merged.UserTimeSec = [Math]::Round($Merged.UserTimeSec, 2)
        $Merged.PrivilegedTimeSec = [Math]::Round($Merged.PrivilegedTimeSec, 2)
        $Merged.WorkingSetMB = [Math]::Round($Merged.WorkingSetMB, 2)
        $Merged.PrivateMemoryMB = [Math]::Round($Merged.PrivateMemoryMB, 2)
        $Merged.VirtualMemoryMB = [Math]::Round($Merged.VirtualMemoryMB, 2)
        $Merged.PagedMemoryMB = [Math]::Round($Merged.PagedMemoryMB, 2)
        $Merged.NonPagedMemoryMB = [Math]::Round($Merged.NonPagedMemoryMB, 2)
        $Merged.PeakWorkingSetMB = [Math]::Round($Merged.PeakWorkingSetMB, 2)
        $Merged.PageFaultsSec = [Math]::Round($Merged.PageFaultsSec, 1)
        $Merged.MemoryGrowthMBPerMin = [Math]::Round($Merged.MemoryGrowthMBPerMin, 2)
        $Merged.HandleGrowthPerMin = [Math]::Round($Merged.HandleGrowthPerMin, 1)
        $Merged.IOReadKBSec = [Math]::Round($Merged.IOReadKBSec, 1)
        $Merged.IOWriteKBSec = [Math]::Round($Merged.IOWriteKBSec, 1)
        $Merged.IOOtherKBSec = [Math]::Round($Merged.IOOtherKBSec, 1)
        $Merged.IOReadOpsSec = [Math]::Round($Merged.IOReadOpsSec, 1)
        $Merged.IOWriteOpsSec = [Math]::Round($Merged.IOWriteOpsSec, 1)
        $Merged.IODataKBSec = [Math]::Round($Merged.IODataKBSec, 1)
        $Merged.UptimeHours = [Math]::Round($Merged.UptimeHours, 2)

        $MergedMetrics += $Merged
    }

    return $MergedMetrics
}

function Export-MetricsData {
    param(
        [array]$Data,
        [string]$FilePath
    )

    if ($Data.Count -eq 0) {
        Write-ColorMessage "沒有數據可輸出" -Type Warning
        return $false
    }

    try {
        switch ($OutputFormat) {
            "JSON" {
                $OutputObject = @{
                    Metadata = @{
                        CollectionStart = $Script:StartTime.ToString("yyyy-MM-dd HH:mm:ss")
                        CollectionEnd   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                        DurationMinutes = $DurationMinutes
                        IntervalSeconds = $IntervalSeconds
                        TotalSamples    = $Data.Count
                        Parameters      = @{
                            IncludeProcesses = $IncludeProcesses
                            ExcludeProcesses = $ExcludeProcesses
                            MatchMode        = $MatchMode
                            MinimumCPU       = $MinimumCPU
                            MinimumMemoryMB  = $MinimumMemoryMB
                        }
                    }
                    Metrics  = $Data
                }

                $OutputObject | ConvertTo-Json -Depth 10 | Set-Content -Path $FilePath -Encoding UTF8
            }

            "CSV" {
                # CSV 格式直接輸出（Export-Csv 會自動加標頭）
                $Data | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
            }

            "TSV" {
                # TSV 格式輸出
                $Headers = ($Data[0].PSObject.Properties | ForEach-Object { $_.Name }) -join "`t"
                $Headers | Set-Content -Path $FilePath -Encoding UTF8

                foreach ($Row in $Data) {
                    $Values = ($Row.PSObject.Properties | ForEach-Object { $_.Value }) -join "`t"
                    $Values | Add-Content -Path $FilePath -Encoding UTF8
                }
            }
        }

        return $true
    }
    catch {
        Write-ColorMessage "輸出檔案時發生錯誤：$($_.Exception.Message)" -Type Error
        return $false
    }
}
#endregion

#region 輔助函式 - 進度顯示
function Show-Progress {
    param(
        [int]$Current,
        [int]$Total,
        [int]$ProcessCount
    )

    if ($NoProgress) { return }

    $Percent = [Math]::Round(($Current / $Total) * 100, 1)
    $Elapsed = (Get-Date) - $Script:StartTime
    $EstimatedTotal = ($Elapsed.TotalSeconds / $Current) * $Total
    $Remaining = [TimeSpan]::FromSeconds($EstimatedTotal - $Elapsed.TotalSeconds)

    $Status = "進度: $Current/$Total ($Percent%) | Process: $ProcessCount | 剩餘時間: $($Remaining.ToString('hh\:mm\:ss'))"

    Write-Progress -Activity "正在收集 Process 效能數據" -Status $Status -PercentComplete $Percent
}

function Show-Summary {
    param(
        [string]$FilePath,
        [int]$TotalRecords
    )

    $Duration = (Get-Date) - $Script:StartTime
    $FileSize = if (Test-Path $FilePath) {
        [Math]::Round((Get-Item $FilePath).Length / 1MB, 2)
    }
    else { 0 }

    Write-Host "`n" -NoNewline
    Write-ColorMessage "========================================" -Type Success
    Write-ColorMessage "收集完成！" -Type Success
    Write-ColorMessage "========================================" -Type Success
    Write-Host ""
    Write-Host "  總執行時間：   " -NoNewline
    Write-Host "$($Duration.ToString('hh\:mm\:ss'))" -ForegroundColor Cyan
    Write-Host "  收集記錄數：   " -NoNewline
    Write-Host "$TotalRecords" -ForegroundColor Cyan
    Write-Host "  輸出檔案：     " -NoNewline
    Write-Host "$FilePath" -ForegroundColor Cyan
    Write-Host "  檔案大小：     " -NoNewline
    Write-Host "${FileSize} MB" -ForegroundColor Cyan

    if ($Script:ErrorCount -gt 0) {
        Write-Host "  錯誤次數：     " -NoNewline
        Write-Host "$($Script:ErrorCount)" -ForegroundColor Yellow
    }

    Write-Host ""
}
#endregion

#region 主程式流程
function Start-PerformanceCollection {
    # 環境檢查
    if (-not (Test-Environment)) {
        Write-ColorMessage "環境檢查失敗，程式終止" -Type Error
        return
    }

    # 啟用 Logging
    $LogFilePath = $null
    if ($EnableLogging) {
        $LogFilePath = Join-Path $OutputPath "process_metrics_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        Start-Transcript -Path $LogFilePath
        Write-ColorMessage "已啟用日誌記錄：$LogFilePath" -Type Info
    }

    # 顯示執行計畫
    if (-not $QuietMode) {
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "  Process 效能監控工具 v$Script:VERSION ($Script:VERSION_NOTE)" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  監控時長：     " -NoNewline
        Write-Host "$DurationMinutes 分鐘" -ForegroundColor Yellow
        Write-Host "  取樣間隔：     " -NoNewline
        Write-Host "$IntervalSeconds 秒" -ForegroundColor Yellow
        Write-Host "  預計取樣次數： " -NoNewline
        Write-Host "$($Script:TotalIterations) 次" -ForegroundColor Yellow
        Write-Host "  輸出格式：     " -NoNewline
        Write-Host "$OutputFormat" -ForegroundColor Yellow
        Write-Host "  輸出路徑：     " -NoNewline
        Write-Host "$OutputPath" -ForegroundColor Yellow

        if ($IncludeProcesses.Count -gt 0) {
            Write-Host "  包含 Process：  " -NoNewline
            Write-Host ($IncludeProcesses -join ", ") -ForegroundColor Green
        }

        if ($ExcludeProcesses.Count -gt 0) {
            Write-Host "  排除 Process：  " -NoNewline
            Write-Host ($ExcludeProcesses -join ", ") -ForegroundColor Red
        }

        if ($MinimumCPU -gt 0) {
            Write-Host "  最低 CPU：     " -NoNewline
            Write-Host "$MinimumCPU%" -ForegroundColor Yellow
        }

        if ($MinimumMemoryMB -gt 0) {
            Write-Host "  最低記憶體：   " -NoNewline
            Write-Host "$MinimumMemoryMB MB" -ForegroundColor Yellow
        }

        Write-Host "`n========================================`n" -ForegroundColor Cyan
    }

    # 準備輸出檔案（即時寫入模式 - 每個取樣間隔寫入一次）
    $OutputFilePath = Get-OutputFilePath
    $IsFirstWrite = $true

    # JSON 格式使用 JSONL（每行一個 JSON 物件）
    if ($OutputFormat -eq "JSON") {
        # 先寫入 Metadata
        $Metadata = @{
            CollectionStart = $Script:StartTime.ToString("yyyy-MM-dd HH:mm:ss")
            DurationMinutes = $DurationMinutes
            IntervalSeconds = $IntervalSeconds
            Parameters      = @{
                IncludeProcesses = $IncludeProcesses
                ExcludeProcesses = $ExcludeProcesses
                MatchMode        = $MatchMode
                MinimumCPU       = $MinimumCPU
                MinimumMemoryMB  = $MinimumMemoryMB
            }
        }
        ("# METADATA: " + ($Metadata | ConvertTo-Json -Compress)) | Set-Content -Path $OutputFilePath -Encoding UTF8
    }

    # 主收集迴圈
    Write-ColorMessage "開始收集效能數據（即時寫入模式：每個取樣間隔寫入一次）..." -Type Info
    Write-ColorMessage "輸出檔案：$OutputFilePath" -Type Info
    Write-ColorMessage "提示：資料正在即時寫入，您可以隨時開啟檔案查看或按 Ctrl+C 中斷" -Type Info

    # 初始化服務映射表（只查詢一次，所有迴圈共用）
    $ServiceMap = @{}

    for ($i = 1; $i -le $Script:TotalIterations; $i++) {
        $IterationStartTime = Get-Date
        try {
            Write-DebugMessage "`n[DEBUG] ========== 開始第 $i 次取樣 (迴圈開始時間: $(Get-Timestamp)) =========="

            $Script:CurrentIteration = $i
            $CurrentIntervalMetrics = @()  # 本次間隔收集的所有 Process 資料

            # 清空 Console 輸入緩衝區（避免累積的輸入事件造成暫停）
            try {
                [ConsoleQuickEdit]::FlushInput()
                if ($i -eq 1) {
                    Write-DebugMessage "[DEBUG] Console 輸入緩衝區已清空"
                }
            }
            catch {
                # 忽略錯誤（非 Windows Console 環境可能會失敗）
            }

            # 定期檢查磁碟空間（每 10 次迴圈檢查一次，避免過度消耗效能）
            if ($i -eq 1 -or $i % 10 -eq 0) {
                if (-not (Test-DiskSpace -Path $OutputPath -MinimumFreeMB $MinimumFreeSpaceMB -StopOnLowSpace $true)) {
                    Write-ColorMessage "磁碟空間不足，自動停止收集（已收集 $i 次取樣）" -Type Error
                    break  # 跳出收集迴圈
                }
            }

            # 取得所有 Process
            $AllProcesses = Get-Process -ErrorAction SilentlyContinue

            # 建立 PID -> Process 的 Hashtable（用於快速查找父程序）
            $ProcessMap = @{}
            foreach ($Proc in $AllProcesses) {
                $ProcessMap[$Proc.Id] = $Proc
            }
            Write-DebugMessage "[DEBUG] 已建立 Process 對應表：$($ProcessMap.Count) 個 Process"

            # 套用篩選條件
            $FilteredProcesses = $AllProcesses | Where-Object {
                # 篩選器
                $PassFilter = Test-ProcessFilter -ProcessName $_.Name

                # CPU 篩選（第三次迴圈後才篩選，前兩次讓 CPU 數據穩定）
                if ($PassFilter -and $MinimumCPU -gt 0 -and $i -gt 2) {
                    try {
                        $CPUPercent = Get-ProcessCPUPercent -Process $_
                        $PassFilter = $CPUPercent -ge $MinimumCPU
                    }
                    catch { }
                }

                # 記憶體篩選
                if ($PassFilter -and $MinimumMemoryMB -gt 0) {
                    $PassFilter = ($_.WorkingSet64 / 1MB) -ge $MinimumMemoryMB
                }

                $PassFilter
            }

            # 批次查詢優化：一次查詢所有 Process 的 WMI 資料（父程序、CommandLine、I/O 都需要）
            $WMIProcessMap = @{}
            # 注意：$ServiceMap 在迴圈外初始化，第一次取樣建立後所有迴圈共用
            $UseBatchQuery = $true  # 始終使用批次查詢（效能最佳）

            if ($UseBatchQuery) {
                try {
                    if ($i -eq 1 -and -not $QuietMode) {
                        $Timestamp = Get-Timestamp
                        Write-Host "[$Timestamp] " -ForegroundColor DarkGray -NoNewline
                        Write-Host "[優化] 使用批次查詢模式（一次查詢所有 Process，減少 WMI 負載）" -ForegroundColor Green
                    }
                    Write-Verbose "批次查詢 WMI Process 資料（完整查詢以確保 I/O 計數器正確）..."
                    $WMIQueryStart = Get-Date
                    # 完整查詢 Win32_Process（-Property 參數可能導致 I/O 計數器返回 null）
                    $AllWMIProcesses = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
                    $WMIQueryEnd = Get-Date
                    $WMIQueryTime = ($WMIQueryEnd - $WMIQueryStart).TotalMilliseconds

                    if ($AllWMIProcesses) {
                        # 建立 PID -> WMI Process 的對應表（快速查找）
                        foreach ($WMIProc in $AllWMIProcesses) {
                            $WMIProcessMap[$WMIProc.ProcessId] = $WMIProc
                        }
                        Write-Verbose "批次查詢完成：$($WMIProcessMap.Count) 個 Process"
                        if ($i -eq 1 -and -not $QuietMode) {
                            $Timestamp = Get-Timestamp
                            Write-Host "[$Timestamp] " -ForegroundColor DarkGray -NoNewline
                            Write-Host "[優化] 批次查詢完成：已載入 $($WMIProcessMap.Count) 個 Process 的 WMI 資料 (耗時: $([Math]::Round($WMIQueryTime, 0)) ms)" -ForegroundColor Green
                        }
                    }

                    # 批次查詢服務映射表（用於識別 svchost 等服務承載程序）
                    if ($i -eq 1) {
                        Write-Verbose "批次查詢服務映射表..."
                        $ServiceQueryStart = Get-Date
                        $ServiceMap = Get-AllServicesMap
                        $ServiceQueryEnd = Get-Date
                        $ServiceQueryTime = ($ServiceQueryEnd - $ServiceQueryStart).TotalMilliseconds

                        if ($ServiceMap.Count -gt 0) {
                            Write-Verbose "服務映射表建立完成：$($ServiceMap.Count) 個服務程序"
                            if (-not $QuietMode) {
                                $Timestamp = Get-Timestamp
                                Write-Host "[$Timestamp] " -ForegroundColor DarkGray -NoNewline
                                Write-Host "[優化] 服務映射表建立完成：$($ServiceMap.Count) 個服務程序 (耗時: $([Math]::Round($ServiceQueryTime, 0)) ms)" -ForegroundColor Green
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "批次查詢 WMI 失敗，將回退到個別查詢"
                    if (-not $QuietMode) {
                        $Timestamp = Get-Timestamp
                        Write-Host "[$Timestamp] " -ForegroundColor DarkGray -NoNewline
                        Write-Host "[警告] 批次查詢失敗，將使用個別查詢（可能會增加 CPU 使用）" -ForegroundColor Yellow
                    }
                }
            }
            else {
                if ($i -eq 1 -and -not $QuietMode) {
                    $Timestamp = Get-Timestamp
                    Write-Host "[$Timestamp] " -ForegroundColor DarkGray -NoNewline
                    Write-Host "[資訊] 已跳過 WMI 查詢（-SkipExtendedInfo -SkipIOMetrics）" -ForegroundColor Cyan
                }
            }

            # 收集每個 Process 的指標
            Write-DebugMessage "[DEBUG] 開始收集 $($FilteredProcesses.Count) 個 Process 的指標... (開始時間: $(Get-Timestamp))"
            $ProcessCollectionStart = Get-Date
            $ProcessCounter = 0

            # 產生本次取樣的時間戳記（同一取樣間隔的所有 Process 使用相同時間）
            $CurrentSamplingTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

            foreach ($Process in $FilteredProcesses) {
                $ProcessCounter++
                $SingleProcessStart = Get-Date

                # 從 WMI 對應表中取得該 Process 的 WMI 資料
                # 注意：需要將 Int32 轉換為 UInt32，因為 WMI ProcessId 是 UInt32 類型
                $WMIData = if ($WMIProcessMap.ContainsKey([uint32]$Process.Id)) {
                    $WMIProcessMap[[uint32]$Process.Id]
                } else {
                    $null
                }

                # 傳入 WMI 資料（如果有的話）、暖機標記、Process 對應表（Hashtable）、服務映射表、以及取樣時間戳記
                $Metrics = Get-ProcessMetrics -Process $Process -WMIProcessData $WMIData -IsWarmup ($i -le 2) -ProcessMap $ProcessMap -ServiceMap $ServiceMap -SamplingTimestamp $CurrentSamplingTimestamp
                if ($null -ne $Metrics) {
                    $CurrentIntervalMetrics += $Metrics
                    [void]$Script:ProcessMetricsCollection.Add($Metrics)
                }

                $SingleProcessEnd = Get-Date
                $SingleProcessTime = ($SingleProcessEnd - $SingleProcessStart).TotalMilliseconds

                # 如果某個 Process 處理超過 500ms，顯示警告
                if ($SingleProcessTime -gt 500) {
                    Write-DebugMessage "[警告] Process '$($Process.Name)' (PID: $($Process.Id)) 處理耗時: $([Math]::Round($SingleProcessTime, 0)) ms"
                }

                # 每 50 個 Process 顯示一次進度
                if ($ProcessCounter % 50 -eq 0) {
                    $ElapsedSoFar = ((Get-Date) - $ProcessCollectionStart).TotalSeconds
                    Write-DebugMessage "[DEBUG] 已處理 $ProcessCounter/$($FilteredProcesses.Count) 個 Process (已耗時: $([Math]::Round($ElapsedSoFar, 1)) 秒)"
                }
            }

            $ProcessCollectionEnd = Get-Date
            $ProcessCollectionTime = ($ProcessCollectionEnd - $ProcessCollectionStart).TotalSeconds
            Write-DebugMessage "[DEBUG] 收集完成！總共處理 $($FilteredProcesses.Count) 個 Process，耗時: $([Math]::Round($ProcessCollectionTime, 2)) 秒 (平均每個: $([Math]::Round($ProcessCollectionTime / $FilteredProcesses.Count * 1000, 0)) ms)"

            # 收集系統指標
            if ($IncludeSystemMetrics) {
                $SystemMetrics = Get-SystemMetrics
                if ($null -ne $SystemMetrics) {
                    [void]$Script:SystemMetricsCollection.Add($SystemMetrics)
                }
            }

            # 按 ProcessName 分組（如果啟用）
            if ($GroupByProcessName -and $CurrentIntervalMetrics.Count -gt 0) {
                Write-DebugMessage "[DEBUG] 按 ProcessName 分組合併資料..."
                $BeforeMergeCount = $CurrentIntervalMetrics.Count
                $CurrentIntervalMetrics = Merge-ProcessMetricsByName -Metrics $CurrentIntervalMetrics
                $AfterMergeCount = $CurrentIntervalMetrics.Count
                Write-DebugMessage "[DEBUG] 合併完成：$BeforeMergeCount 個 Process 合併為 $AfterMergeCount 個 ProcessName"

                if (-not $QuietMode -and $i -eq 2) {
                    # 第一次寫入時顯示提示
                    $Timestamp = Get-Timestamp
                    Write-Host "[$Timestamp] " -ForegroundColor DarkGray -NoNewline
                    Write-Host "[分組] 已啟用 ProcessName 分組模式（相同名稱的 Process 會合併，加總 CPU/記憶體/I/O）" -ForegroundColor Cyan
                }
            }

            # *** 每個取樣間隔寫入一次：把這個間隔的所有 Process 資料寫入檔案 ***
            # 跳過第一次取樣（只用於建立基準，CPUPercent 和 I/O 指標為 0）
            if ($CurrentIntervalMetrics.Count -gt 0 -and $i -gt 1) {
                try {
                    switch ($OutputFormat) {
                        "CSV" {
                            # 使用自訂 CSV 寫入邏輯，避免 Export-Csv 的型別推斷問題
                            if ($IsFirstWrite) {
                                # 第一次寫入：包含標頭
                                $Headers = ($CurrentIntervalMetrics[0].PSObject.Properties | ForEach-Object { $_.Name }) -join ","
                                $Headers | Set-Content -Path $OutputFilePath -Encoding UTF8
                                $IsFirstWrite = $false
                            }

                            # 寫入資料列（逐行寫入，避免型別推斷）
                            foreach ($Metric in $CurrentIntervalMetrics) {
                                $Values = $Metric.PSObject.Properties | ForEach-Object {
                                    $val = $_.Value
                                    # 處理空值和特殊字元（使用類型安全的比較避免 0 被誤判為空）
                                    if ($null -eq $val -or ($val -is [string] -and $val -eq "")) {
                                        '""'  # 空值用空引號
                                    }
                                    else {
                                        # 先轉為字串
                                        $valStr = $val.ToString()
                                        # 檢查是否需要引號
                                        if ($valStr.Contains(",") -or $valStr.Contains('"') -or $valStr.Contains("`n")) {
                                            # 包含逗號、引號或換行的值需要用引號包起來，並轉義引號
                                            '"' + $valStr.Replace('"', '""') + '"'
                                        }
                                        else {
                                            $valStr
                                        }
                                    }
                                }
                                $Line = $Values -join ","
                                $Line | Add-Content -Path $OutputFilePath -Encoding UTF8
                            }
                        }

                        "TSV" {
                            foreach ($Metric in $CurrentIntervalMetrics) {
                                if ($IsFirstWrite) {
                                    # 寫入標頭
                                    $Headers = ($Metric.PSObject.Properties | ForEach-Object { $_.Name }) -join "`t"
                                    $Headers | Set-Content -Path $OutputFilePath -Encoding UTF8
                                    $IsFirstWrite = $false
                                }
                                # 寫入資料
                                $Values = ($Metric.PSObject.Properties | ForEach-Object { $_.Value }) -join "`t"
                                $Values | Add-Content -Path $OutputFilePath -Encoding UTF8
                            }
                        }

                        "JSON" {
                            # JSONL 格式：每行一個 JSON 物件
                            $JsonLines = $CurrentIntervalMetrics | ForEach-Object { $_ | ConvertTo-Json -Compress }
                            $JsonLines | Add-Content -Path $OutputFilePath -Encoding UTF8
                        }
                    }

                    # 顯示寫入訊息（非靜默模式）
                    if (-not $QuietMode) {
                        $TotalRecords = $Script:ProcessMetricsCollection.Count
                        $IntervalRecords = $CurrentIntervalMetrics.Count
                        $Timestamp = Get-Timestamp
                        Write-Host "[$Timestamp] " -ForegroundColor DarkGray -NoNewline
                        Write-Host "[寫入] 間隔 $i/$($Script:TotalIterations)：已儲存 $IntervalRecords 個 Process（總計 $TotalRecords 筆記錄）" -ForegroundColor Green
                    }
                }
                catch {
                    Write-ColorMessage "寫入檔案時發生錯誤：$($_.Exception.Message)" -Type Error
                    Write-ColorMessage "錯誤位置：$($_.InvocationInfo.ScriptLineNumber) 行" -Type Error
                    Write-ColorMessage "錯誤詳情：$($_.Exception)" -Type Error
                    $Script:ErrorCount++
                }
            }

            # 顯示進度
            Write-DebugMessage "[DEBUG] 準備顯示進度... (時間: $(Get-Timestamp))"
            # 暫時停用 Write-Progress 來測試是否造成延遲
            # Show-Progress -Current $i -Total $Script:TotalIterations -ProcessCount $FilteredProcesses.Count
            Write-DebugMessage "[DEBUG] 進度: $i/$($Script:TotalIterations) ($(([Math]::Round(($i / $Script:TotalIterations) * 100, 1)))%) - Process: $($FilteredProcesses.Count)"
            Write-DebugMessage "[DEBUG] 進度顯示完成 (時間: $(Get-Timestamp))"

            # 等待下次取樣（最後一次不用等）
            if ($i -lt $Script:TotalIterations) {
                Write-DebugMessage "[DEBUG] 準備等待 $IntervalSeconds 秒後進行第 $($i+1) 次取樣... (開始時間: $(Get-Timestamp))"

                # 診斷：顯示實際要 Sleep 的秒數
                Write-DebugMessage "[DEBUG] IntervalSeconds 變數值 = $IntervalSeconds (型別: $($IntervalSeconds.GetType().Name))"

                $SleepStart = Get-Date
                Start-Sleep -Seconds $IntervalSeconds
                $SleepEnd = Get-Date
                $ActualSleep = ($SleepEnd - $SleepStart).TotalSeconds

                Write-DebugMessage "[DEBUG] 等待完成！實際等待時間: $([Math]::Round($ActualSleep, 2)) 秒 (應為 $IntervalSeconds 秒) - 開始第 $($i+1) 次取樣"
                Write-DebugMessage "[DEBUG] Sleep 完成時間: $(Get-Timestamp)，即將進入下一次迴圈..."
            }

            # 計算本次迴圈總耗時
            $IterationEndTime = Get-Date
            $IterationTotalTime = ($IterationEndTime - $IterationStartTime).TotalSeconds
            Write-DebugMessage "[DEBUG] ========== 第 $i 次取樣結束 (迴圈總耗時: $([Math]::Round($IterationTotalTime, 2)) 秒) =========="
        }
        catch {
            Write-ColorMessage "迴圈 $i 發生錯誤：$($_.Exception.Message)" -Type Error
            Write-ColorMessage "錯誤位置：$($_.InvocationInfo.ScriptLineNumber) 行" -Type Error
            Write-ColorMessage "錯誤指令：$($_.InvocationInfo.Line.Trim())" -Type Error
            $Script:ErrorCount++
        }
    }

    # 完成進度列
    if (-not $NoProgress) {
        Write-Progress -Activity "正在收集 Process 效能數據" -Completed
    }

    # 資料已在迴圈中即時寫入，這裡只需處理系統指標（如果有的話）
    Write-ColorMessage "Process 效能數據已即時寫入：$OutputFilePath" -Type Success

    # 如果有系統指標，輸出到獨立檔案
    if ($IncludeSystemMetrics -and $Script:SystemMetricsCollection.Count -gt 0) {
        Write-ColorMessage "正在輸出系統效能數據..." -Type Info
        $SystemOutputPath = $OutputFilePath -replace "process_metrics", "system_metrics"
        if (Export-MetricsData -Data $Script:SystemMetricsCollection -FilePath $SystemOutputPath) {
            Write-ColorMessage "系統效能數據已輸出：$SystemOutputPath" -Type Success
        }
    }

    # 顯示摘要
    Show-Summary -FilePath $OutputFilePath -TotalRecords $Script:ProcessMetricsCollection.Count

    # 停止 Logging
    if ($EnableLogging) {
        Stop-Transcript
        Write-ColorMessage "日誌已儲存：$LogFilePath" -Type Info
    }
}

# 執行主程式
try {
    Start-PerformanceCollection
}
catch {
    Write-ColorMessage "程式執行時發生嚴重錯誤：$($_.Exception.Message)" -Type Error
    Write-ColorMessage "詳細資訊：$($_.ScriptStackTrace)" -Type Error
    exit 1
}
finally {
    # 清理資源
    if ($EnableLogging) {
        try { Stop-Transcript -ErrorAction SilentlyContinue } catch { }
    }
}
#endregion
