# JT Log Analyzer

記錄檔快速統計分析工具，能計算特定時間區段內符合篩選字串的事件數量，並以視覺化的文字直條圖顯示分析結果。

## 專案概述

`jt_log_analyzer.py` 採用 Python 撰寫，為 IT 人員在文字介面下方便統計分析記錄而設計，支援自訂時間區間統計事件數，並同時輸出終端顯示和 CSV 格式的分析結果。特別適合用於分析大型記錄檔案，並識別事件發生的趨勢。


![demo2.png](https://github.com/jasoncheng7115/it-scripts/blob/master/jt_log_analyzer/demo2.png?raw=true)

## 主要功能

- **區間統計**：支援分鐘（1、10、15、30、45、60分鐘）和小時（1、2、12、24小時）區間
- **字串篩選**：附加篩選功能，分析特定類型的事件
- **文字圖表**：視覺化呈現事件頻率，包含零值時間點
- **資料匯出**：將結果儲存為 CSV 格式，包含所有時間區間
- **省記憶體**：採用區塊讀取方式處理大檔案
- **進度追蹤**：處理大檔案時顯示進度

## 系統需求

- Python 3.6+


## 安裝方式

直接下載 `jt_log_analyzer.py` 使用。

```bash
curl -O https://raw.githubusercontent.com/your-repo/jt_log_analyzer.py
chmod +x jt_log_analyzer.py
```

## 使用方法

### 基本語法

```bash
./jt_log_analyzer.py <log_file_path> [filter_keyword] [-i interval]
```

### 使用範例

#### 1. 基本分析（預設每分鐘統計）
```bash
./jt_log_analyzer.py /path/to/file.log
```

#### 2. 指定時間區間分析
```bash
# 每 15 分鐘統計
./jt_log_analyzer.py /path/file.log -i 15m

# 每 2 小時統計
./jt_log_analyzer.py /path/file.log -i 2h

# 每 24 小時統計
./jt_log_analyzer.py /path/file.log -i 24h
```

#### 3. 搭配關鍵字篩選
```bash
# 篩選 ERROR 相關的事件，每 30 分鐘統計
./jt_log_analyzer.py /path/file.log ERROR -i 30m

# 篩選帳號相關的錯誤，每 24 小時統計
./jt_log_analyzer.py /path/file.log 'account error' -i 24h
```

#### 4. 更多實用範例
```bash
# 分析登入失敗事件
./jt_log_analyzer.py auth.log 'authentication failed' -i 1h

# 監控資料庫連線問題
./jt_log_analyzer.py app.log 'database connection' -i 15m

# 檢查系統錯誤趨勢
./jt_log_analyzer.py /var/log/syslog CRITICAL -i 12h
```

![demo1.png](https://github.com/jasoncheng7115/it-scripts/blob/master/jt_log_analyzer/demo1.png?raw=true)


## 輸出格式

### 1. 終端顯示（完整範例）

```
=== Events per 15 Minutes Statistics ===
Filter keyword: 'ERROR'
--------------------------------------------------------------------------------
Time                 | Count  | Bar Chart
--------------------------------------------------------------------------------
2025-04-26 02:00     | 23     | ███████████████████████
2025-04-26 02:15     | 45     | █████████████████████████████████████████████
2025-04-26 02:30     | 10     | ██████████
2025-04-26 02:45     | 0      | 
2025-04-26 03:00     | 5      | █████
--------------------------------------------------------------------------------
Total events: 83
Time range: 2025-04-26 02:00 to 2025-04-26 03:00
Total intervals: 5
Intervals with events: 4
Max events per interval: 45
--------------------------------------------------------------------------------

Statistics saved to: jt_log_statistics.csv
```

### 2. CSV 輸出格式

產出的 `jt_log_statistics.csv` 檔案內容：

```csv
Time,Count
2025-04-26 02:00,23
2025-04-26 02:15,45
2025-04-26 02:30,10
2025-04-26 02:45,0
2025-04-26 03:00,5
```

CSV 檔案可以直接用試算表軟體開啟，例如 Microsoft Excel 或 LibreOffice Calc，即可方便的製作圖表。
![demo3.png](https://github.com/jasoncheng7115/it-scripts/blob/master/jt_log_analyzer/demo3.png?raw=true)


## 支援的時間區間

### 分鐘等級
- `1m` - 每分鐘（預設）
- `10m` - 每 10 分鐘
- `15m` - 每 15 分鐘
- `30m` - 每 30 分鐘
- `45m` - 每 45 分鐘
- `60m` - 每 60 分鐘

### 小時等級
- `1h` - 每小時
- `2h` - 每 2 小時
- `12h` - 每 12 小時
- `24h` - 每 24 小時

## 記錄檔案格式需求

分析器預期的記錄檔案時間戳格式：

```
YYYY-MM-DD HH:MM:SS
```

範例記錄：
```
2025-04-26 02:29:35,769 INFO [Pop3SSLServer-24] [ip=127.0.0.1;] account - login success
2025-04-26 02:30:12,156 ERROR [ApiHandler-8] [cid=2306516;] authentication failed
```

## 效能特性

- 有效處理大型檔案（數 GB 以上）分次區塊方式讀取
- 記憶體使用量取決於記錄中時間區間數，而非檔案大小
- 百萬行以上的檔案會自動顯示目前處理進度


## 注意事項

1. 若篩選字串包含空格、中文、特殊符號等，請用單引號包起來
2. 輸出的 CSV 檔案會自動儲為 `jt_log_statistics.csv`
3. 文字直條圖中，越長的直條代表事件越多
4. 在指定時間範圍內的所有時間區間都會顯示，包含統計為 0 的時間區段

## 版本歷史

- **1.0.0** (2025-05-05): 首次發布
  - 基本事件統計功能
  - 多種時間區間支援
  - 文字直條圖顯示
  - 完整時間範圍 CSV 匯出
  - 關鍵字篩選

