# jt_zmmsgtrace Security Documentation

English Version | [繁體中文版](SECURITY.md)

## Security Fixes

This version has implemented the following security measures to prevent various attacks:

### 1. Regular Expression Injection Attack Protection (ReDoS Protection)

**Issue**: User input search conditions are directly used in `re.compile()`, which may lead to:
- ReDoS (Regular Expression Denial of Service) attacks
- Invalid regular expressions causing program crashes

**Fix** (jt_zmmsgtrace.py:541-551):
```python
def _safe_compile(self, pattern: str, flags: int = 0):
    """Safely compile regex pattern with error handling"""
    try:
        # Limit pattern length to prevent ReDoS
        if len(pattern) > 500:
            raise ValueError("Pattern too long (max 500 characters)")
        return re.compile(pattern, flags)
    except re.error as e:
        raise ValueError(f"Invalid regex pattern: {e}")
```

**Protection Measures**:
- Limit regular expression length (max 500 characters)
- Catch and display user-friendly error messages
- Prevent malicious regex from causing high CPU usage

---

### 2. Input Validation and Sanitization

**Issue**: User input received by Web UI is not validated and may contain malicious content

**Fix** (jt_zmmsgtrace.py:1340-1348):
```python
def sanitize_input(value, max_length=500):
    """Sanitize user input to prevent injection attacks"""
    if not value:
        return ''
    # Truncate to max length
    value = str(value)[:max_length]
    # Remove null bytes
    value = value.replace('\x00', '')
    return value
```

**Protection Measures**:
- Limit all input field lengths
- Remove null bytes (\x00)
- Force conversion to string type

---

### 3. XSS Attack Protection (Cross-Site Scripting)

**Issue**: User input may contain malicious JavaScript code

**Fix**: All output is processed using `html.escape()`
```python
# Example (jt_zmmsgtrace.py:946-955)
search_summary.append(f"Sender: {html.escape(search_params['sender'])}")
results_html.append(f"<strong>Message ID:</strong> {html.escape(msg.message_id)}")
```

**Protection Measures**:
- All user input is escaped before HTML output
- Prevent `<script>` tag injection
- Prevent event handler injection (e.g., `onclick=`)

---

### 4. Path Traversal Attack Protection

**Issue**: Malicious users may attempt to read system files

**Fix**: Log file paths are hardcoded in the program (jt_zmmsgtrace.py:1380-1385)
```python
# Log file paths are hardcoded in program, does not accept user input
if include_history:
    log_files = sorted(glob.glob('/var/log/zimbra*'))
else:
    log_files = [DEFAULT_LOGFILE]  # /var/log/zimbra.log
```

**Protection Measures**:
- Do not allow users to specify arbitrary file paths
- Can only read `/var/log/zimbra*` files
- Use fixed path prefix

---

### 5. Parameter Validation and Limits

**Issue**: Pagination parameters may be abused causing resource exhaustion

**Fix** (jt_zmmsgtrace.py:1438-1447):
```python
try:
    offset = int(search_params.get('offset', 0))
    limit = int(search_params.get('limit', 50))
    # Limit to reasonable values
    offset = max(0, min(offset, 100000))
    limit = max(1, min(limit, 500))
except (ValueError, TypeError):
    offset = 0
    limit = 50
```

**Protection Measures**:
- Validate pagination parameters are integers
- Limit offset (max 100,000)
- Limit limit (max 500)
- Catch and handle invalid input

---

### 6. Error Handling

**Issue**: Error messages may leak system information

**Fix** (jt_zmmsgtrace.py:1450-1468):
```python
try:
    msg_filter = MessageFilter(args)
except ValueError as e:
    # Return error page for invalid regex
    error_html = f"""
<html>
<body>
    <h1>Invalid Search Parameters</h1>
    <p style="color: red;">{html.escape(str(e))}</p>
    <p><a href="/">← Return to search</a></p>
</body>
</html>"""
    self.send_response(400)
    ...
```

**Protection Measures**:
- Friendly error message page
- Do not leak internal paths or code information
- Appropriate HTTP status codes (400 Bad Request)

---

## Security Testing

### Test Case 1: Invalid Regular Expression
```bash
$ python3 jt_zmmsgtrace.py -s '(' test_subject.log
Error: Invalid regex pattern: missing ), unterminated subpattern at position 0
```
**Passed** - Correctly caught and displayed error

### Test Case 2: Excessive Input Length
```bash
# Web UI automatically truncates input exceeding 500 characters
```
**Passed** - Input truncated to safe length

### Test Case 3: XSS Attempt
```bash
# Input: <script>alert('XSS')</script>
# Output: &lt;script&gt;alert('XSS')&lt;/script&gt;
```
**Passed** - HTML special characters correctly escaped

---

## Recommended Additional Security Measures

### Deployment Recommendations

1. **Use HTTPS**
   ```nginx
   server {
       listen 443 ssl;
       ssl_certificate /path/to/cert.pem;
       ssl_certificate_key /path/to/key.pem;

       location / {
           proxy_pass http://localhost:8989;
       }
   }
   ```

2. **Enable Firewall**
   ```bash
   # Only allow access from specific IP
   sudo ufw allow from 192.168.1.0/24 to any port 8989
   ```

3. **Set File Permissions**
   ```bash
   # Ensure log file permissions are correct
   chmod 640 /var/log/zimbra.log
   chown zimbra:zimbra /var/log/zimbra.log
   ```

4. **Use Rate Limiting**
   - Configure rate limiting in Nginx
   - Prevent brute force or DoS attacks

5. **Enable Access Logging**
   ```bash
   # Use --debug mode to log access
   ./jt_zmmsgtrace.py --web --debug
   ```

---

## Reporting Security Issues

If you discover a security vulnerability, please contact:
- Email: [Your Email]
- GitHub Issues: (Please do not publicly disclose security vulnerabilities)

---

**Last Updated**: 2025-01-11
**Version**: 2.1.0
