# JT Log Analyzer
Quick log analysis tool that calculates event counts within specific time intervals based on filter keywords and displays results in a visual text-based bar chart.

## Project Overview
`jt_log_analyzer.py` is written in Python, designed for IT professionals to conveniently analyze logs in a terminal interface. It supports custom time interval statistics and provides output in both terminal display and CSV format. Particularly suitable for analyzing large log files and identifying event trends.

![demo2.png](https://github.com/jasoncheng7115/it-scripts/blob/master/jt_log_analyzer/demo2.png?raw=true)

## Key Features
- **Interval Statistics**: Supports minutes (1, 10, 15, 30, 45, 60 minutes) and hours (1, 2, 12, 24 hours) intervals
- **String Filtering**: Additional filtering functionality to analyze specific types of events
- **Text Charts**: Visualizes event frequency, including zero-value time points
- **Data Export**: Saves results to CSV format, including all time intervals
- **Memory Efficient**: Uses chunk reading to handle large files
- **Progress Tracking**: Displays progress when processing large files

## System Requirements
- Python 3.6+

## Installation
Download `jt_log_analyzer.py` directly.

```bash
curl -O https://raw.githubusercontent.com/your-repo/jt_log_analyzer.py
chmod +x jt_log_analyzer.py
```

## Usage
### Basic Syntax
```bash
./jt_log_analyzer.py <log_file_path> [filter_keyword] [-i interval]
```

### Usage Examples
#### 1. Basic Analysis (default minute-by-minute statistics)
```bash
./jt_log_analyzer.py /path/to/file.log
```

#### 2. Specified Time Interval Analysis
```bash
# Every 15 minutes
./jt_log_analyzer.py /path/file.log -i 15m

# Every 2 hours
./jt_log_analyzer.py /path/file.log -i 2h

# Every 24 hours
./jt_log_analyzer.py /path/file.log -i 24h
```

#### 3. Combined with Keyword Filtering
```bash
# Filter ERROR related events, every 30 minutes
./jt_log_analyzer.py /path/file.log ERROR -i 30m

# Filter account-related errors, every 24 hours
./jt_log_analyzer.py /path/file.log 'account error' -i 24h
```

#### 4. More Practical Examples
```bash
# Analyze login failure events
./jt_log_analyzer.py auth.log 'authentication failed' -i 1h

# Monitor database connection issues
./jt_log_analyzer.py app.log 'database connection' -i 15m

# Check system error trends
./jt_log_analyzer.py /var/log/syslog CRITICAL -i 12h
```

![demo1.png](https://github.com/jasoncheng7115/it-scripts/blob/master/jt_log_analyzer/demo1.png?raw=true)

## Output Format
### 1. Terminal Display (Complete Example)
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

### 2. CSV Output Format
Generated `jt_log_statistics.csv` file contents:

```csv
Time,Count
2025-04-26 02:00,23
2025-04-26 02:15,45
2025-04-26 02:30,10
2025-04-26 02:45,0
2025-04-26 03:00,5
```

CSV files can be directly opened with spreadsheet software such as Microsoft Excel or LibreOffice Calc to easily create charts.

![demo3.png](https://github.com/jasoncheng7115/it-scripts/blob/master/jt_log_analyzer/demo3.png?raw=true)

## Supported Time Intervals
### Minute Level
- `1m` - Every minute (default)
- `10m` - Every 10 minutes
- `15m` - Every 15 minutes
- `30m` - Every 30 minutes
- `45m` - Every 45 minutes
- `60m` - Every 60 minutes

### Hour Level
- `1h` - Every hour
- `2h` - Every 2 hours
- `12h` - Every 12 hours
- `24h` - Every 24 hours

## Log File Format Requirements
The analyzer expects log file timestamp format:

```
YYYY-MM-DD HH:MM:SS
```

Sample logs:
```
2025-04-26 02:29:35,769 INFO [Pop3SSLServer-24] [ip=127.0.0.1;] account - login success
2025-04-26 02:30:12,156 ERROR [ApiHandler-8] [cid=2306516;] authentication failed
```

## Performance Characteristics
- Efficiently handles large files (multiple GBs) by chunk reading
- Memory usage depends on the number of time intervals in the log, not file size
- Automatically displays current processing progress for files with millions of lines

## Notes
1. If filter strings contain spaces, Chinese characters, or special symbols, enclose them in single quotes
2. Output CSV file will be automatically saved as `jt_log_statistics.csv`
3. In text bar charts, longer bars represent more events
4. All time intervals within the specified range are displayed, including periods with 0 statistics

## Version History
- **1.0.0** (2025-05-05): First release
  - Basic event statistics functionality
  - Multiple time interval support
  - Text bar chart display
  - CSV export of processing results
  - Keyword filtering
