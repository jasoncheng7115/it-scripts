# Windows vs Linux 欄位對照表

此文件詳細說明 Windows 版本（PowerShell）與 Linux 版本（Bash）之間的欄位映射關係。

## 📊 完整欄位對照表（44 欄位）

| # | 欄位名稱 | Windows 來源 | Linux 來源 | 差異說明 |
|---|---------|------------|----------|---------|
| 1 | **Timestamp** | `Get-Date` | `date '+%Y-%m-%d %H:%M:%S'` | ✅ 完全相同 |
| 2 | **ProcessName** | `$Process.Name` | `/proc/[pid]/comm` | ✅ 完全相同 |
| 3 | **ProcessID** | `$Process.Id` | PID | ✅ 完全相同 |
| 4 | **ParentProcessID** | `Win32_Process.ParentProcessId` | `/proc/[pid]/stat` (ppid) | ✅ 完全相同 |
| 5 | **ParentProcessName** | 查找父 Process | `/proc/[ppid]/comm` | ✅ 完全相同 |
| 6 | **ProcessPath** | `$Process.Path` | `/proc/[pid]/exe` (readlink) | ✅ 完全相同 |
| 7 | **CommandLine** | `Win32_Process.CommandLine` | `/proc/[pid]/cmdline` | ✅ 完全相同 |
| 8 | **IsWarmup** | 程式邏輯 | 程式邏輯 | ✅ 完全相同 |
| 9 | **CPUPercent** | 計算 TotalProcessorTime 差值 | 計算 utime+stime 差值 | ⚠️ 計算方法類似但來源不同 |
| 10 | **CPUTimeTotalSec** | `TotalProcessorTime.TotalSeconds` | `(utime + stime) / 100` | ⚠️ 單位相同，來源不同 |
| 11 | **UserTimeSec** | `UserProcessorTime.TotalSeconds` | `utime / 100` | ⚠️ 單位相同，來源不同 |
| 12 | **PrivilegedTimeSec** | `PrivilegedProcessorTime.TotalSeconds` | `stime / 100` | ⚠️ 單位相同，來源不同 |
| 13 | **PriorityClass** | `$Process.PriorityClass` (Enum) | `nice` (-20 到 19) | ❌ 概念不同 |
| 14 | **BasePriority** | `$Process.BasePriority` | `/proc/[pid]/stat` priority | ⚠️ 數值範圍不同 |
| 15 | **WorkingSetMB** | `WorkingSet64 / 1MB` | `VmRSS / 1024` | ✅ 對應 RSS |
| 16 | **PrivateMemoryMB** | `PrivateMemorySize64 / 1MB` | `RssAnon / 1024` | ⚠️ 概念類似 |
| 17 | **VirtualMemoryMB** | `VirtualMemorySize64 / 1MB` | `VmSize / 1024` | ✅ 完全對應 |
| 18 | **PagedMemoryMB** | `PagedMemorySize64 / 1MB` | `N/A` | ❌ Windows 特有 |
| 19 | **NonPagedMemoryMB** | `NonpagedSystemMemorySize64 / 1MB` | `N/A` | ❌ Windows 特有 |
| 20 | **PeakWorkingSetMB** | `PeakWorkingSet64 / 1MB` | `VmHWM / 1024` | ✅ 完全對應 |
| 21 | **PageFaultsSec** | 計算 PageFaults 差值 | 計算 minflt+majflt 差值 | ⚠️ 計算邏輯相同 |
| 22 | **MemoryGrowthMBPerMin** | 計算 WorkingSet 增長率 | 計算 RSS 增長率 | ✅ 完全相同 |
| 23 | **HandleGrowthPerMin** | 計算 Handle 增長率 | 計算 FD 增長率 | ⚠️ Handle vs FD |
| 24 | **PossibleMemoryLeak** | 計算邏輯 | 計算邏輯 | ✅ 完全相同 |
| 25 | **IOReadKBSec** | `ReadTransferCount` 差值 | `read_bytes` 差值 | ✅ 對應良好 |
| 26 | **IOWriteKBSec** | `WriteTransferCount` 差值 | `write_bytes` 差值 | ✅ 對應良好 |
| 27 | **IOOtherKBSec** | `OtherTransferCount` 差值 | `0` (無對應) | ❌ Windows 特有 |
| 28 | **IOReadOpsSec** | `ReadOperationCount` 差值 | `syscr` 差值 | ⚠️ 概念類似 |
| 29 | **IOWriteOpsSec** | `WriteOperationCount` 差值 | `syscw` 差值 | ⚠️ 概念類似 |
| 30 | **IODataKBSec** | Read + Write + Other | Read + Write | ⚠️ Linux 無 Other |
| 31 | **ThreadCount** | `$Process.Threads.Count` | `/proc/[pid]/status` Threads | ✅ 完全對應 |
| 32 | **HandleCount** | `$Process.HandleCount` | FD 數量 (`ls /proc/[pid]/fd`) | ❌ Handle vs FD |
| 33 | **StartTime** | `$Process.StartTime` | `starttime` 轉換 | ✅ 完全對應 |
| 34 | **UptimeHours** | 計算運行時數 | 計算運行時數 | ✅ 完全相同 |
| 35 | **Responding** | `$Process.Responding` (Bool) | `/proc/[pid]/stat` state | ❌ Bool vs State |
| 36 | **SessionID** | `$Process.SessionId` | `/proc/[pid]/stat` session | ✅ 完全對應 |
| 37 | **Owner** | `Win32_Process.GetOwner()` | Uid → username | ✅ 完全對應 |
| 38 | **CompanyName** | `FileVersionInfo.CompanyName` | `N/A` | ❌ Windows 特有 |
| 39 | **ProductVersion** | `FileVersionInfo.ProductVersion` | `N/A` | ❌ Windows 特有 |
| 40 | **ServiceNames** | 查詢 Service 對應 | `N/A` | ❌ Windows 特有 |
| 41 | **Nice** | `N/A` (Linux 專屬) | `/proc/[pid]/stat` nice | 🆕 Linux 專屬 |
| 42 | **State** | `N/A` (Linux 專屬) | `/proc/[pid]/stat` state | 🆕 Linux 專屬 |
| 43 | **RssFileMB** | `N/A` (Linux 專屬) | `RssFile / 1024` | 🆕 Linux 專屬 |
| 44 | **RssShmemMB** | `N/A` (Linux 專屬) | `RssShmem / 1024` | 🆕 Linux 專屬 |
| 45 | **SwapUsageMB** | `N/A` (Linux 專屬) | `VmSwap / 1024` | 🆕 Linux 專屬 |
| 46 | **VoluntaryCtxtSwitches** | `N/A` (Linux 專屬) | `voluntary_ctxt_switches` | 🆕 Linux 專屬 |
| 47 | **NonvoluntaryCtxtSwitches** | `N/A` (Linux 專屬) | `nonvoluntary_ctxt_switches` | 🆕 Linux 專屬 |

---

## 🔍 重要差異詳解

### 1. CPU 相關欄位

#### **PriorityClass** (欄位 13)

| 平台 | 值類型 | 可能值 | 說明 |
|-----|-------|-------|------|
| Windows | Enum | Idle, BelowNormal, Normal, AboveNormal, High, RealTime | Process 優先級類別 |
| Linux | Integer | -20 到 19 | Nice 值（越小優先級越高） |

**對應關係（參考）：**
- RealTime → Nice -20
- High → Nice -10
- AboveNormal → Nice -5
- Normal → Nice 0
- BelowNormal → Nice 10
- Idle → Nice 19

#### **BasePriority** (欄位 14)

| 平台 | 值範圍 | 說明 |
|-----|-------|------|
| Windows | 0-31 | 基礎優先級 |
| Linux | 0-139 | 實際優先級（數值越小優先級越高） |

### 2. 記憶體相關欄位

#### **PrivateMemoryMB** (欄位 16)

| 平台 | 對應 | 說明 |
|-----|------|------|
| Windows | PrivateMemorySize64 | Process 私有記憶體（不與其他 Process 共享） |
| Linux | RssAnon | 匿名 RSS（Anonymous Resident Set Size） |

**差異：** 概念類似但不完全相同。Windows 的 Private Memory 包含所有私有分配，Linux 的 RssAnon 只計算匿名頁面。

#### **PagedMemoryMB / NonPagedMemoryMB** (欄位 18-19)

| 平台 | 狀態 | 說明 |
|-----|------|------|
| Windows | ✅ 有值 | Windows 記憶體管理特有概念 |
| Linux | ❌ `N/A` | Linux 記憶體管理方式不同，無此概念 |

### 3. Handle vs File Descriptor

#### **HandleCount** (欄位 32)

| 平台 | 計數對象 | 包含 |
|-----|---------|------|
| Windows | Handle | 檔案、Registry、Thread、Mutex、Event 等所有核心物件 |
| Linux | File Descriptor | 檔案、Socket、Pipe 等（不包含 Thread、Mutex） |

**注意：** 無法直接比較，Linux 的 FD 數量通常會小於 Windows 的 Handle 數量。

### 4. Process 狀態

#### **Responding** (欄位 35)

| 平台 | 值類型 | 可能值 | 說明 |
|-----|-------|-------|------|
| Windows | Boolean | true/false | Process 是否回應 |
| Linux | Char | R/S/D/Z/T/t/W/X | Process 狀態代碼 |

**Linux State 對應：**
- `R` (Running) → `true`
- `S` (Sleeping) → `true`
- `D` (Disk Sleep) → `false` (無回應)
- `Z` (Zombie) → `false`
- `T` (Stopped) → `false`

### 5. I/O 相關欄位

#### **IOOtherKBSec** (欄位 27)

| 平台 | 狀態 | 說明 |
|-----|------|------|
| Windows | ✅ 有值 | 非讀寫的其他 I/O 操作（如 metadata 更新） |
| Linux | ❌ `0` | `/proc/[pid]/io` 無此欄位 |

#### **IOReadOpsSec / IOWriteOpsSec** (欄位 28-29)

| 平台 | 對應 | 說明 |
|-----|------|------|
| Windows | ReadOperationCount / WriteOperationCount | 實際的 I/O 操作數 |
| Linux | syscr / syscw | System call 計數（read/write calls） |

**差異：** Windows 計數實際 I/O，Linux 計數 system call（可能包含 buffer cache）。

---

## 🆕 Linux 專屬欄位

這些欄位在 Windows 版本中不存在，為 Linux 特有資訊：

### **Nice** (欄位 41)
- **範圍**: -20 到 19
- **說明**: 排程優先級，數值越小優先級越高
- **用途**: 調整 Process CPU 時間分配

### **State** (欄位 42)
- **可能值**: R/S/D/Z/T/t/W/X
- **說明**:
  - `R`: Running（運行中）
  - `S`: Sleeping（可中斷睡眠）
  - `D`: Disk Sleep（不可中斷睡眠，通常是 I/O 等待）
  - `Z`: Zombie（殭屍 Process）
  - `T`: Traced or Stopped（被追蹤或停止）
- **用途**: 診斷 Process 狀態問題

### **RssFileMB** (欄位 43)
- **說明**: File-backed RSS（檔案支援的記憶體）
- **用途**: 分析共享函式庫和 mmap 檔案的記憶體使用

### **RssShmemMB** (欄位 44)
- **說明**: Shared memory RSS（共享記憶體）
- **用途**: 分析 IPC 共享記憶體使用

### **SwapUsageMB** (欄位 45)
- **說明**: Process 使用的 Swap 空間
- **用途**: 診斷記憶體不足問題

### **VoluntaryCtxtSwitches** (欄位 46)
- **說明**: 自願性 context switch 次數
- **用途**: Process 主動讓出 CPU（如等待 I/O）

### **NonvoluntaryCtxtSwitches** (欄位 47)
- **說明**: 非自願性 context switch 次數
- **用途**: Process 被搶佔 CPU（CPU 競爭指標）

---

## 📋 跨平台分析建議

### 可直接比較的欄位（26 個）

這些欄位在兩個平台上意義相同，可以直接比較：

```
Timestamp, ProcessName, ProcessID, ParentProcessID, ParentProcessName,
ProcessPath, CommandLine, CPUPercent, CPUTimeTotalSec, UserTimeSec,
PrivilegedTimeSec, WorkingSetMB, VirtualMemoryMB, PeakWorkingSetMB,
MemoryGrowthMBPerMin, PossibleMemoryLeak, IOReadKBSec, IOWriteKBSec,
IOReadOpsSec, IOWriteOpsSec, IODataKBSec, ThreadCount, StartTime,
UptimeHours, SessionID, Owner
```

### 需要轉換的欄位（5 個）

這些欄位需要轉換才能比較：

| 欄位 | 轉換方式 |
|-----|---------|
| PriorityClass | 使用對照表轉換 |
| BasePriority | 正規化到 0-100 範圍 |
| PrivateMemoryMB | 視為近似值 |
| HandleCount | 僅用於趨勢分析，不比較絕對值 |
| Responding | Linux State 轉為 Boolean |

### 平台特有欄位（11 個）

這些欄位無法跨平台比較：

**Windows 專屬：**
- PagedMemoryMB, NonPagedMemoryMB
- IOOtherKBSec
- CompanyName, ProductVersion, ServiceNames

**Linux 專屬：**
- Nice, State, RssFileMB, RssShmemMB, SwapUsageMB
- VoluntaryCtxtSwitches, NonvoluntaryCtxtSwitches

---

## 💡 實務建議

### 1. 跨平台效能比較

```bash
# Windows
.\jt_procperf_analyzer.ps1 -D 60 -I 60 -Include "myapp*"

# Linux
./jt_procperf_analyzer.sh -d 60 -i 60 --include "myapp*"

# 比較 CPU 使用率（欄位 9）
# 比較記憶體使用（欄位 15）
# 比較 I/O 速率（欄位 25-26）
```

### 2. 記憶體分析差異

Windows 記憶體欄位：
- WorkingSetMB: 總實體記憶體
- PrivateMemoryMB: 私有記憶體
- PagedMemoryMB: 可分頁記憶體
- VirtualMemoryMB: 虛擬記憶體

Linux 記憶體欄位：
- WorkingSetMB (RSS): 總實體記憶體
- PrivateMemoryMB (RssAnon): 匿名私有記憶體
- RssFileMB: 檔案支援記憶體
- RssShmemMB: 共享記憶體
- VirtualMemoryMB: 虛擬記憶體

### 3. I/O 分析注意事項

- Windows 的 IOOtherKBSec 在 Linux 上永遠是 0
- Linux 的 syscr/syscw 可能高於 Windows 的 OperationCount（因計算方式不同）
- 比較時建議使用 IODataKBSec（總 I/O 速率）

---

## 📊 CSV 標頭對照

### Windows 版本（37 欄位）
```csv
Timestamp,ProcessName,ProcessID,...,Owner,CompanyName,ProductVersion,ServiceNames
```

### Linux 版本（44 欄位）
```csv
Timestamp,ProcessName,ProcessID,...,Owner,CompanyName,ProductVersion,ServiceNames,Nice,State,RssFileMB,RssShmemMB,SwapUsageMB,VoluntaryCtxtSwitches,NonvoluntaryCtxtSwitches
```

**相容性：** Linux 版本的前 37 個欄位與 Windows 完全相同，可用相同工具分析前 37 欄。

---

## 🔗 相關文件

- [Windows 版本 README](./README.md)
- [Linux 版本 README](./README_LINUX.md)
- [Windows 快速開始](./QUICKSTART.md)
- [Linux 快速開始](./QUICKSTART_LINUX.md)
