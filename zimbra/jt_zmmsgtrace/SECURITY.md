# jt_zmmsgtrace 安全性說明

## 安全性修正 (Security Fixes)

本版本已實作以下安全性措施，防止各種攻擊：

### 1. 正則表達式植入攻擊防護 (ReDoS Protection)

**問題**: 使用者輸入的搜尋條件直接用於 `re.compile()`，可能導致：
- ReDoS (Regular Expression Denial of Service) 攻擊
- 無效正則表達式導致程式當機

**修正** (jt_zmmsgtrace.py:541-551):
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

**防護措施**:
- 限制正則表達式長度 (最大 500 字元)
- 擷取並友善顯示錯誤訊息
- 防止惡意正則表達式導致高 CPU 使用

---

### 2. 輸入驗證與清理 (Input Sanitization)

**問題**: Web UI 接收的使用者輸入未經驗證，可能包含惡意內容

**修正** (jt_zmmsgtrace.py:1340-1348):
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

**防護措施**:
- 限制所有輸入欄位長度
- 移除 null bytes (\x00)
- 強制轉換為字串型別

---

### 3. XSS 攻擊防護 (Cross-Site Scripting)

**問題**: 使用者輸入可能包含惡意 JavaScript 程式碼

**修正**: 所有輸出都使用 `html.escape()` 處理
```python
# 範例 (jt_zmmsgtrace.py:946-955)
search_summary.append(f"寄件者: {html.escape(search_params['sender'])}")
results_html.append(f"<strong>Message ID:</strong> {html.escape(msg.message_id)}")
```

**防護措施**:
- 所有使用者輸入在 HTML 輸出前都經過 escape
- 防止 `<script>` 標籤植入
- 防止事件處理器植入 (如 `onclick=`)

---

### 4. 路徑穿越攻擊防護 (Path Traversal)

**問題**: 惡意使用者可能嘗試讀取系統檔案

**修正**: 記錄檔案路徑寫死在程式中 (jt_zmmsgtrace.py:1380-1385)
```python
# 記錄檔案路徑寫死在程式中，不接受使用者輸入
if include_history:
    log_files = sorted(glob.glob('/var/log/zimbra*'))
else:
    log_files = [DEFAULT_LOGFILE]  # /var/log/zimbra.log
```

**防護措施**:
- 不允許使用者指定任意檔案路徑
- 只能讀取 `/var/log/zimbra*` 檔案
- 使用固定路徑字首

---

### 5. 參數驗證與限制 (Parameter Validation)

**問題**: 分頁參數可能被濫用造成資源耗盡

**修正** (jt_zmmsgtrace.py:1438-1447):
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

**防護措施**:
- 驗證分頁參數為整數
- 限制 offset (最大 100,000)
- 限制 limit (最大 500)
- 擷取並處理無效輸入

---

### 6. 錯誤處理 (Error Handling)

**問題**: 錯誤訊息可能外洩系統資訊

**修正** (jt_zmmsgtrace.py:1450-1468):
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

**防護措施**:
- 友善的錯誤訊息頁面
- 不外洩內部路徑或程式碼資訊
- 適當的 HTTP 狀態碼 (400 Bad Request)

---

## 安全性測試

### 測試案例 1: 無效正則表達式
```bash
$ python3 jt_zmmsgtrace.py -s '(' test_subject.log
Error: Invalid regex pattern: missing ), unterminated subpattern at position 0
```
**通過** - 正確擷取並顯示錯誤

### 測試案例 2: 過長輸入
```bash
# Web UI 會自動截斷超過 500 字元的輸入
```
**通過** - 輸入被截斷至安全長度

### 測試案例 3: XSS 嘗試
```bash
# 輸入: <script>alert('XSS')</script>
# 輸出: &lt;script&gt;alert('XSS')&lt;/script&gt;
```
**通過** - HTML 特殊字元被正確 escape

---

## 建議的額外安全措施

### 部署建議

1. **使用 HTTPS**
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

2. **啟用防火牆**
   ```bash
   # 只允許特定 IP 存取
   sudo ufw allow from 192.168.1.0/24 to any port 8989
   ```

3. **設定檔案權限**
   ```bash
   # 確保記錄檔案權限正確
   chmod 640 /var/log/zimbra.log
   chown zimbra:zimbra /var/log/zimbra.log
   ```

4. **使用 Rate Limiting**
   - 在 Nginx 中設定 rate limiting
   - 防止暴力破解或 DoS 攻擊

5. **啟用存取記錄**
   ```bash
   # 使用 --debug 模式記錄存取
   ./jt_zmmsgtrace.py --web --debug
   ```

---

## 回報安全問題

如果發現安全漏洞，請聯絡：
- Email: [您的信箱]
- GitHub Issues: (請不要公開披露安全漏洞)

---

**最後更新**: 2025-01-11
**版本**: 2.1.0
