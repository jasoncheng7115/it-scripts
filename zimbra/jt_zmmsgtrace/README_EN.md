# jt_zmmsgtrace - Enhanced Email Tracer for Zimbra

English Version | [繁體中文版](README.md)

Python rewrite of `zmmsgtrace`, solving the issue where the original version fails to find recipients in Zimbra's message deduplication scenario, with a powerful Web UI interface.

---

## Use Cases

### Limitations of Zimbra's Built-in Tool

While Zimbra includes the `zmmsgtrace` tool for email tracking, it has the following limitations in practical use:

- **Cannot Handle Deduplicated Messages**: When Zimbra's message deduplication feature is enabled, `zmmsgtrace` misses some recipients, resulting in incomplete tracking
- **Lack of Graphical Interface**: Requires command-line operation, which has a high barrier for administrators unfamiliar with Linux
- **Limited Search Functionality**: Cannot conveniently search historical log files or perform batch queries by time range
- **Difficult Email Content Viewing**: Cannot directly view email content, headers, or source code, requiring additional tools

### Practical Needs of Email Administrators

As an email system administrator, daily operations often require:

1. **Track Email Flow**
   - Quickly find incoming or outgoing records of specific emails
   - Confirm whether emails were successfully delivered to all recipients
   - Identify reasons for email delivery failures

2. **View Detailed Email Information**
   - Conveniently view complete email content, headers, and source code
   - Quickly check DKIM, SPF, DMARC validation results from email headers
   - View spam scores, virus scan results, and other security information
   - Track which servers the email passed through (Received headers)

3. **Efficiency and Convenience**
   - No need to memorize complex command-line parameters
   - Ability to batch query multiple email records
   - Multi-language interface support for administrators in different regions

**jt_zmmsgtrace is designed to meet these practical needs**, providing complete email tracking, deduplication handling, Web graphical interface, and rich email viewing functionality.

---

## Key Features

### 1. Solve Zimbra Deduplication Problem

The original Perl tool misses recipients when handling Zimbra message deduplication. The new version:

- Fully parses all recipients in Amavis records (`<r1>,<r2>,<r3>` format)
- Integrates Amavis and Postfix data
- Displays recipients even without individual Postfix delivery records
- Marks potentially deduplicated recipients

**Example Output**:
```
Message ID 'abc123@domain.com'
Log: /var/log/zimbra.log
sender@domain.com -->
    user1@domain.com
    user2@domain.com [from Amavis - may be deduplicated]
    user3@domain.com [from Amavis - may be deduplicated]
  Recipient user1@domain.com
    Sep 14 18:30:02 - mailhost (192.168.1.1) --> relay.host status sent
  Recipient user2@domain.com
    Processed by Amavis but no individual Postfix delivery record
```

### 2. Display Log Source File

Added `Log:` field showing which log file the record was found in:

- When using `--all-logs` to load multiple log files, clearly shows which file each record came from
- Convenient for tracking record sources when specifying multiple log files
- Especially useful for querying historical logs or searching across multiple archived files

### 3. Web UI Interface

- **Multi-language Support**: Automatically detects browser language, supports switching between Chinese and English
- **Browser-Friendly**: No need to memorize complex command-line parameters
- **Real-time Search**: Graphical search form with visualized results
- **Email Viewing**: View complete email content, headers, and security checks directly in browser
- **Security Analysis**: Display DKIM, SPF, DMARC, SPAM check results
- **Email Routing**: Visualize email delivery path
- **Download Function**: Support downloading .eml format emails
- **Password Protection**: Requires administrator password login

### 4. **Compatibility**

- Fully compatible with original command-line parameters
- Support for the same regex search
- Support for compressed files (.gz, .bz2)
- **Tested Products**:
  - Zimbra Open Source Edition
  - Zimbra Network Edition
- **Tested Versions**:
  - Zimbra 9.0.0p38 ~ 9.0.0p44
  - Zimbra 10.1.10 ~ 10.1.11

---

## Quick Start

### System Requirements

```bash
# Python 3.7 or higher
python3 --version

# No additional packages needed, uses standard library
```

### Web UI Mode

```bash
# 1. Launch Web UI as root
sudo ./jt_zmmsgtrace.py --web

# 2. Open browser from remote computer and connect to Zimbra server
# Replace 192.168.1.100 with your Zimbra server IP address
http://192.168.1.100:8989/

# 3. Login with Zimbra administrator account
# 4. Search emails in the web interface
```

Note: This program needs to run as root to read Zimbra log files. When executing Zimbra commands (such as zmprov, zmsoap, zmmailbox), the program will automatically switch to the zimbra user.

### Command-Line Mode

```bash
# Search for specific sender
sudo ./jt_zmmsgtrace.py -s "user@domain.com"

# Search for deduplicated recipient
sudo ./jt_zmmsgtrace.py -r "user2@domain.com"

# Time range query
sudo ./jt_zmmsgtrace.py -t 20250101,20250131
```

---

## Installation and Deployment

### Basic Installation

```bash
# 1. Download the program to server
curl -o /opt/jasontools/jt_zmmsgtrace.py https://raw.githubusercontent.com/jasoncheng7115/it-scripts/refs/heads/master/zimbra/jt_zmmsgtrace/jt_zmmsgtrace.py

# 2. Set permissions
chmod +x /opt/jasontools/jt_zmmsgtrace.py

# 3. Test execution
sudo /opt/jasontools/jt_zmmsgtrace.py --help
```

**Firewall and Security Settings**:
- If you have a firewall, remember to open the port used by jt_zmmsgtrace (default is 8989)
- **Important Security Warning**: DO NOT expose this Web UI directly to the Internet!
  - Only allow access from internal networks (e.g., 192.168.x.x, 10.x.x.x)
  - Or access via VPN connection
  - Recommend using firewall rules to restrict source IP ranges
  - If Internet access is required, use a reverse proxy (e.g., Nginx) with HTTPS and additional authentication mechanisms

---

## Usage

### Command-Line Options

#### Search Filter Parameters

| Option | Short | Description |
|--------|-------|-------------|
| `--id` | `-i` | Message ID (regex) |
| `--sender` | `-s` | Sender address (regex) |
| `--recipient` | `-r` | Recipient address (regex) |
| `--srchost` | `-F` | Source hostname or IP (regex) |
| `--desthost` | `-D` | Destination hostname or IP (regex) |
| `--time` | `-t` | Time range: `YYYYMM[DD[HH[MM[SS]]]],YYYYMM[DD[HH[MM[SS]]]]` |
| `--year` | | Specify log file year (default: current year)<br>Note: Zimbra log timestamps lack year information, must specify when viewing old logs |

#### Web UI Parameters

| Option | Description |
|--------|-------------|
| `--web` | Launch Web UI mode |
| `--port` | Specify Web UI port (default: 8989) |
| `--login-attempts` | Maximum login failure limit (default: 5 times) |
| `--login-timeout` | Login failure tracking time range in minutes (default: 10 minutes) |

**Login Failure Protection Mechanism**:
- When the total number of login failures from all IP addresses exceeds the `--login-attempts` limit within the `--login-timeout` time window, **the entire Web UI server will automatically shut down**
- After the server shuts down, all users (including other IPs) cannot access the Web UI
- **Manual server restart by administrator is required**, will not automatically recover
- This mechanism effectively prevents brute force attacks

#### Log File Parameters

| Option | Description |
|--------|-------------|
| `--all-logs` | Load all `/var/log/zimbra*` files (default: only load `/var/log/zimbra.log`) |
| `--nosort` | Do not sort files by modification time |
| `files` | Specify log files to process (positional argument, can specify multiple files) |

#### Other Parameters

| Option | Short | Description |
|--------|-------|-------------|
| `--debug` | | Increase debug output (can be repeated for more verbosity) |
| `--version` | `-v` | Display version information |

### Usage Examples

Note: All examples below need to run as root (using `sudo` or logging in as root directly).

#### Web UI Mode

```bash
# Launch Web UI (default port 8989)
sudo ./jt_zmmsgtrace.py --web

# Custom port
sudo ./jt_zmmsgtrace.py --web --port 9000

# Debug mode
sudo ./jt_zmmsgtrace.py --web --debug

# Open browser from remote computer (replace IP with your Zimbra server address)
# http://192.168.1.100:8989/
```

**Web UI Features**:
- Multi-language interface (Chinese/English)
- Beautiful graphical interface
- Real-time search with visualized results
- Complete email viewing functionality
- Security analysis (DKIM/SPF/DMARC/SPAM)
- Email routing visualization
- Support .eml download
- Automatically mark deduplicated recipients

#### Command-Line Mode

##### Basic Search Examples

```bash
# Track all emails (using default log file)
sudo ./jt_zmmsgtrace.py

# Search for specific sender
sudo ./jt_zmmsgtrace.py -s "user@domain.com"

# Search for deduplicated recipient
sudo ./jt_zmmsgtrace.py -r "user2@domain.com"

# Search for specific Message-ID
sudo ./jt_zmmsgtrace.py -i "ABC123@domain.com"

# Time range query
sudo ./jt_zmmsgtrace.py -t 20250101,20250131

# Complex query (using regex)
sudo ./jt_zmmsgtrace.py -s "^admin" -r "@example.com$" -t 202501
```

##### Specify Log Files

```bash
# Specify single log file
sudo ./jt_zmmsgtrace.py /var/log/zimbra.log

# Specify multiple log files (including compressed)
sudo ./jt_zmmsgtrace.py /var/log/zimbra.log.1.gz /var/log/zimbra.log

# Use wildcards to specify multiple files
sudo ./jt_zmmsgtrace.py /var/log/zimbra.log*

# Load all zimbra log files (including archived)
sudo ./jt_zmmsgtrace.py --all-logs

# Don't sort files (process in command-line order)
sudo ./jt_zmmsgtrace.py --nosort /var/log/zimbra.log.2.gz /var/log/zimbra.log.1.gz
```

##### Debug and Advanced Options

```bash
# Debug mode (show detailed processing information)
sudo ./jt_zmmsgtrace.py --debug -r "user@domain.com"

# More verbose debug (can repeat --debug)
sudo ./jt_zmmsgtrace.py --debug --debug -s "admin@"

# Specify log file year (when viewing old logs)
# Zimbra log time format is "Jan 15 10:30:00" (no year)
# Must specify --year 2024 when viewing 2024 old logs
sudo ./jt_zmmsgtrace.py --year 2024 /var/log/zimbra.log.2024.gz -s "user@domain.com"

# Search December 2024 logs with time range
sudo ./jt_zmmsgtrace.py --year 2024 -t 20241201,20241231 /var/log/old-zimbra.log

# Display version information
sudo ./jt_zmmsgtrace.py --version
```

##### Web UI Advanced Options

```bash
# Custom Web UI port
sudo ./jt_zmmsgtrace.py --web --port 9000

# Load all log files and launch Web UI
sudo ./jt_zmmsgtrace.py --web --all-logs

# Adjust login security settings
sudo ./jt_zmmsgtrace.py --web --login-attempts 3 --login-timeout 5

# Web UI + debug mode
sudo ./jt_zmmsgtrace.py --web --debug
```

### Web UI Interface Screenshots

#### 1. Login Page

![Login Page](images/1%20login_en.png)

Multi-language selection support, login with Zimbra administrator account.

#### 2. Search Page

![Search Page](images/2%20search_en.png)

Provides multiple search criteria including sender, recipient, Message-ID, time range, and option to search historical log files.

#### 3. Email View Page

![Email View](images/3%20viewmail_en.png)

Displays detailed email information including security check results (DKIM, SPF, DMARC, SPAM score), and support downloading .eml format.

#### 4. Email Routing Information

![Email Routing](images/4%20mailroute_en.png)

Visualizes email delivery path, including delivery status for each recipient.

#### 5. Email Content View

![Email Content](images/5%20mailbody_en.png)

View complete email content, raw source, and full headers.

---

## Security

This tool has implemented the following security measures:

### Implemented Protections

- **Regex Injection Attack Protection**: Limit pattern length (max 500 characters)
- **XSS Attack Protection**: All output processed with `html.escape()`
- **Path Traversal Attack Protection**: Log file paths hardcoded in program
- **Input Validation**: Limit all input field lengths
- **Parameter Validation**: Pagination parameter limits (offset ≤ 100,000, limit ≤ 500)
- **Error Handling**: Friendly error messages, no system information leakage
- **Login Protection**: Failure count limit, prevent brute force

For detailed security information, see [SECURITY.md](SECURITY.md)

### Deployment Recommendations

1. **Run as root user** (needs to read Zimbra log files; Zimbra commands such as zmprov, zmsoap, zmmailbox will automatically switch to zimbra user)
2. **Use HTTPS** (via reverse proxy)
3. **Enable firewall** (restrict access IP)
4. **Properly set file permissions**
5. **Regularly update to latest version**

---

## FAQ

### Q1: Why do some recipients show "[from Amavis - may be deduplicated]"?

This indicates the recipient was only found in Amavis records without an individual Postfix delivery record. This typically occurs with Zimbra message deduplication.

### Q2: How to know if an email was deduplicated by Zimbra?

If you see multiple recipients in the output, but only some have complete delivery records (status sent), while others show "Processed by Amavis but no individual Postfix delivery record", it's likely a deduplication situation.

### Q3: Web UI cannot view email content?

Please confirm:
1. Program runs as root user (needs to read email content; Zimbra commands such as zmprov, zmsoap, zmmailbox will automatically switch to zimbra user)
2. Account is a Zimbra internal account (external accounts cannot view)

### Q4: How to switch language?

- **Login page**: Use language selector
- **After login**: Click language switch button in upper right corner
- Language selection is automatically saved in Cookie

### Q5: Why use `--year` parameter?

Zimbra log files (`/var/log/zimbra.log`) timestamp format is `Jan 15 10:30:00`, **without year information**.

**Usage scenarios**:
- **View current year logs**: No need to specify (defaults to current year)
- **View old year logs**: Must specify `--year`

**Examples**:
```bash
# View 2025 logs in 2025 (no need for --year)
sudo ./jt_zmmsgtrace.py -s "user@domain.com"

# View 2024 old logs in 2025 (must specify --year 2024)
sudo ./jt_zmmsgtrace.py --year 2024 /var/log/zimbra.log.2024.gz -s "user@domain.com"
```

**Note**: If `--year` is not specified, the program will misidentify old logs as current year data, causing time comparison errors.

### Q6: What happens when login failures exceed the limit?

When the total number of login failures from all IP addresses exceeds the limit (default 5 times) within the time window:

1. **Server Shutdown**: The entire Web UI server will automatically shut down, not just blocking a single IP
2. **Error Message**: Displays "Too many failed login attempts! Server will shut down. Please wait X seconds before restarting."
3. **Impact Scope**: All users (including other IPs) cannot access the Web UI
4. **Recovery Method**: **Administrator must manually restart the program**, will not automatically recover
5. **Time Window**: Default 10 minutes (adjustable via `--login-timeout`)

**Adjust Security Settings Examples**:
```bash
# Stricter setting: 3 failures, 30-minute time window
sudo ./jt_zmmsgtrace.py --web --login-attempts 3 --login-timeout 30

# Looser setting: 10 failures, 5-minute time window
sudo ./jt_zmmsgtrace.py --web --login-attempts 10 --login-timeout 5
```

**Important Reminder**: Since failure counts track the total across all IPs, it's recommended to appropriately increase the `--login-attempts` value in multi-user environments to avoid server shutdown due to multiple people entering incorrect passwords.

---

## Comparison with Original

| Feature | Original Perl | New Python (jt_zmmsgtrace) |
|---------|---------------|----------------------------|
| Parse Postfix logs | Supported | Supported |
| Parse Amavis logs | Supported | Supported |
| **Parse Amavis Multiple Recipients** | Not supported | Supported |
| **Integrate Deduplicated Recipients** | Not supported | Supported |
| **Search Deduplicated Recipients** | Not supported | Supported |
| **Mark Deduplication Status** | Not supported | Supported |
| **Display Log Source File (Log: field)** | Not supported | Supported |
| **Web UI Interface** | Not supported | Supported |
| **Multi-language Support** | Not supported | Supported |
| **Email Viewing Function** | Not supported | Supported |
| **Security Analysis** | Not supported | Supported |
| Compressed file support | Supported | Supported |
| Regex search | Supported | Supported |

---

## Version History

- **v2.3.3** (2025-11-16): Fix duplicate program name display in email routing
- **v2.3.2** (2025-11-16): Support RFC 2047 email subject decoding
- **v2.3.1** (2025-11-15): UI fixes (text overflow, Chinese translation)
- **v2.3.0** (2025-11-12): Multi-language support, Message-ID format improvements
- **v2.2.0** (2025-11-12): Use zmsoap, email viewing function
- **v2.1.0** (2025-11-11): Add Web UI interface
- **v2.0.0** (2025-11-10): Python rewrite, solve deduplication problem

For detailed changes, see [CHANGELOG.md](CHANGELOG.md)

---

## Technical Details

### Data Structures

```python
@dataclass
class RecipientInfo:
    address: str
    orig_recip: Optional[str]
    status: Optional[str]
    from_amavis_only: bool  # Key: mark recipients found only in Amavis

@dataclass
class Message:
    message_id: str
    sender: Optional[str]
    recipients: Dict[str, RecipientInfo]  # Contains all recipients

@dataclass
class AmavisRecord:
    recipients: List[str]  # Key: parsed recipient list
```

### Key Algorithm: Integrate Amavis Data

```python
def integrate_amavis_data(self):
    """Integrate Amavis data, supplement deduplicated recipients"""
    for amav in self.amavis_records.values():
        msg = self.find_message(amav)

        # Key: create entry for each recipient in Amavis
        for recip_addr in amav.recipients:
            if recip_addr not in msg.recipients:
                # This recipient has no Postfix record (may be deduplicated)
                msg.recipients[recip_addr] = RecipientInfo(
                    address=recip_addr,
                    from_amavis_only=True,  # Mark
                    status='processed'
                )
```

---

## Performance Considerations

- Same as original, loads log data into memory
- Large log files require sufficient memory
- Web UI mode parses logs on startup, then queries are fast

---

## Debugging

Use `--debug` option to see detailed processing:

```bash
# Command-line mode
sudo ./jt_zmmsgtrace.py --debug -r "user@domain.com" 2>&1 | less

# Web UI mode
sudo ./jt_zmmsgtrace.py --web --debug
```

Output includes:
- File reading progress
- Amavis log parsing
- Deduplicated recipient additions
- Email filtering statistics
- Web UI request handling

---

## Version Information

- **Version**: 2.3.3
- **Language**: Python 3.7+
- **Original**: Perl (v1.05)
- **Author**: Jason Cheng (Jason Tools) (Collaborated with Claude Code)
- **Date**: 2025-11-16
- **License**: GNU GPL v2

---

## Latest Updates (v2.3.3)

### Bug Fixes
- **Fixed duplicate program name display in email routing**: Some servers in email routing page showed duplicate program names
  - Issue: `mail.jason.tools (Postfix) (Postfix)` displayed twice
  - Cause: `by_match` regex captured parenthesis content, then `program_match` captured it again
  - Solution: Modified `by_match` to only capture hostname, program info handled by `program_match` exclusively
  - Affected file: `jt_zmmsgtrace.py` line 4231

### v2.3.2 Updates
- **RFC 2047 Email Subject Decoding Support**: When Zimbra enables `custom_header_check`, subjects appear in encoded format in logs
  - Support Base64 encoding: `=?utf-8?B?5ris6Kmm?=` → `測試`
  - Support Quoted-Printable encoding: `=?iso-8859-1?Q?Andr=E9?=` → `André`
  - Support multiple character sets: UTF-8, ISO-8859-1, Latin1, etc.
  - Both CLI and Web UI can correctly display decoded subjects
  - Added `decode_header_value()` utility function for email header decoding

### v2.3.1 Updates
- **Fixed CLI mode empty email display issue**: CLI execution no longer displays empty NOQUEUE emails
- **Fixed email view page overflow issue**: Raw content and full headers area no longer overflow right boundary
- **Fixed Traditional Chinese translation**: Email header fields correctly display in Chinese

### Multi-language Support (v2.3.0)
- **Automatic language detection**: Automatically select interface based on browser language
- **Supported languages**: Traditional Chinese, English
- **Language switching**: Login page language selection, all pages provide switch button
- **Complete translation**: All pages, messages, buttons support multi-language

### Message-ID Format Improvements (v2.3.0)
- Support more RFC 5322 standard characters: `+ ~ ! = ? # $ % & * /`
- Fix issue where Message-IDs with special characters cannot be viewed
- Compatible with Gmail, Exchange, and various email system Message-ID formats

---

## Related Documentation

- [SECURITY.md](SECURITY.md) - Security documentation
- [CHANGELOG.md](CHANGELOG.md) - Complete change log

---

## License

Same as original, using **GNU General Public License v2.0**

---

## Authors

- **Original**: Synacor, Inc. (Zimbra)
- **Python Rewrite & Web UI**: Jason Cheng (Jason Tools) - 2025 (Collaborated with Claude Code)

---

## References

- [Original zmmsgtrace Official Documentation](https://wiki.zimbra.com/wiki/CLI_zmmsgtrace)
- [Zimbra SOAP API](https://wiki.zimbra.com/wiki/SOAP_API_Reference_Material_Beginning_with_ZCS_8)
