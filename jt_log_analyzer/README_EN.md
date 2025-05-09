# JT Log Analyzer
Quick log analysis tool that calculates event counts within specific time intervals based on filter keywords and displays results in a visual text-based bar chart.

## Project Overview
`jt_log_analyzer.py` is written in Python, designed for IT professionals to conveniently analyze logs in a terminal interface. It supports custom time interval statistics and provides output in both terminal display and CSV format. Particularly suitable for analyzing large log files and identifying event trends.

In addition to the features mentioned above, the tool also supports real-time monitoring mode. When this mode is enabled, after the initial log file analysis is completed, the program continues to monitor file changes. If new log entries are detected, the text-based bar charts will update in real-time to reflect these changes.

![realtime1.gif](https://github.com/jasoncheng7115/it-scripts/blob/master/jt_log_analyzer/realtime1.gif?raw=true)

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
curl -O https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/jt_log_analyzer/jt_log_analyzer.py
chmod +x jt_log_analyzer.py
```

# Usage

### Basic Syntax

```bash
# Concise syntax
./jt_log_analyzer.py <log_file_path> [filter_keyword] [-i interval] [-r]

# Explicit parameter syntax
./jt_log_analyzer.py -f <log_file_path> [-q filter_keyword] [-i interval] [-r] [-d] [-e encoding]

# Reading from pipeline
cat logfile.log | ./jt_log_analyzer.py [-q filter_keyword] [-i interval] [-d] [-e encoding]
```

### Examples

#### 1. Basic Analysis (Default: 1-minute intervals)
```bash
./jt_log_analyzer.py -f /path/to/file.log
```

![demo2.png](https://github.com/jasoncheng7115/it-scripts/blob/master/jt_log_analyzer/demo2.png?raw=true)

#### 2. Specifying Time Intervals
```bash
# 15-minute intervals
./jt_log_analyzer.py -f /path/file.log -i 15m

# 2-hour intervals
./jt_log_analyzer.py -f /path/file.log -i 2h

# 24-hour intervals
./jt_log_analyzer.py -f /path/file.log -i 24h
```

#### 3. Using Keyword Filtering
```bash
# Filter for ERROR-related events, 30-minute intervals
./jt_log_analyzer.py -f /path/file.log -q 'ERROR' -i 30m

# Filter for account-related errors, 24-hour intervals
./jt_log_analyzer.py -f /path/file.log -q 'account error' -i 24h
```

#### 4. Real-time Monitoring
```bash
# Basic real-time monitoring
./jt_log_analyzer.py -f /path/file.log -r

# Real-time monitoring with error filtering
./jt_log_analyzer.py -f /path/file.log -q 'ERROR' -r

# Real-time monitoring with specific intervals (10-minute)
./jt_log_analyzer.py -f /path/file.log -i 10m -r

# Real-time monitoring for specific error types with custom intervals
./jt_log_analyzer.py -f /var/log/nginx/access.log -q '404' -i 5m -r
```

#### 5. Additional Practical Examples
```bash
# Analyzing authentication failure events
./jt_log_analyzer.py -f auth.log -q 'authentication failed' -i 1h

# Monitoring database connection issues
./jt_log_analyzer.py -f app.log -q 'database connection' -i 15m

# Checking system error trends
./jt_log_analyzer.py -f /var/log/syslog -q CRITICAL -i 12h

# Real-time monitoring of system login attempts
./jt_log_analyzer.py -f /var/log/auth.log -q 'Failed password' -i 5m -r

# Real-time monitoring of web server errors
./jt_log_analyzer.py -f /var/log/apache2/error.log -r
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
Supported timestamp formats for the analyzer:

1. **Standard Format**: `YYYY-MM-DD HH:MM:SS`
   ```
   2025-04-26 02:29:35,769 INFO [Pop3SSLServer-24] [ip=127.0.0.1;] account - login success
   2025-04-26 02:30:12,156 ERROR [ApiHandler-8] [cid=2306516;] authentication failed
   ```

2. **Syslog Format**: `MMM D HH:MM:SS` (no year, automatically determined)
   ```
   May 6 21:44:57 dc1 slapd[1477]: conn=1151 op=15272 SRCH base="dc=jason,dc=tools" scope=2 deref=0 filter="(&(objectClass=posixAccount)(uid=\2A))"
   Apr 26 08:12:45 server1 dhclient[2179]: DHCPACK from 10.0.0.1 (xid=0x3b8743e)
   ```

3. **Apache Format**: `DD/MMM/YYYY:HH:MM:SS`
   ```
   10.0.0.1 - - [26/Apr/2025:08:21:55 +0800] "GET /index.html HTTP/1.1" 200 2326
   192.168.1.100 - user [27/Apr/2025:09:43:12 +0800] "POST /api/login HTTP/1.1" 401 172
   ```

4. **ISO Format**: `YYYY-MM-DDTHH:MM:SS`
   ```
   2025-04-26T08:21:55.123Z INFO [ServerThread-1] Connection established from 192.168.1.5
   2025-04-26T09:15:22.456Z ERROR [WorkerPool-3] Database connection timeout after 30s
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

- **1.3.1** (2025-05-09): Pipeline Input and Debug Mode
   - Support for reading data from standard input (stdin) (`cat file.log | ./jt_log_analyzer.py`)
   - Added `-f <file_path>` parameter to explicitly specify input file
   - Added `-q <keyword>` parameter to explicitly specify filter keyword
   - Added `-d` / `--debug` debug mode providing detailed diagnostic information
   - Added `-e` / `--encoding` option to specify file encoding
   - Added `-h` / `--help` to display detailed help message
   - Enhanced error handling and troubleshooting suggestions
   - Strengthened timestamp detection with support for more formats
   - Added fallback mechanism when standard patterns fail to match
   - Structured code for improved readability and maintainability
   - Updated usage instructions and troubleshooting guidance

- **1.2.0** (2025-05-07): Real-time Monitoring
   - Added `-r` parameter to enable real-time monitoring mode
   - Supports continuous monitoring of log file changes with automatic statistics updates
   - Implements real-time text-based bar chart display
   - Added user interrupt handling (Ctrl+C) for graceful exit from monitoring
   - Improved file reading with position tracking to process only new content
   - Displays last update time and processing progress information
   - Added polling interval adjustment options to conserve CPU resources
   - Updated usage instructions and examples
     
- **1.1.0** (2025-05-06): Multi-format Timestamp Support
  - Automatic detection of log file timestamp formats
  - Added support for Syslog format (MMM D HH:MM:SS)
  - Added support for Apache format (DD/MMM/YYYY:HH:MM:SS)
  - Added support for ISO format (YYYY-MM-DDTHH:MM:SS)
  - Improved handling of timestamps without year (automatically uses current year)
  - Optimized parsing logic for cross-year log files
  - Added statistics for unparseable lines
  - Updated usage instructions and documentation
  - 
- **1.0.0** (2025-05-05): First release
  - Basic event statistics functionality
  - Multiple time interval support
  - Text bar chart display
  - CSV export of processing results
  - Keyword filtering
