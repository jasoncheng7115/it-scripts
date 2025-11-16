# jt_zmmsgtrace Change Log

English Version | [繁體中文版](CHANGELOG.md)

## Version 2.3.3 (2025-11-16)

### Bug Fixes

#### Fixed Duplicate Program Name Display in Email Routing
- **Issue**: Some servers in email routing page showed duplicate program names
  - Example: `mail.jason.tools (Postfix) (Postfix)` displayed twice
- **Cause**: The `by_match` regex (line 4231) captured both hostname and parenthesis content, then `program_match` captured the parenthesis content again
- **Solution**:
  - Modified `by_match` regex from `r'by\s+([^\s]+(?:\s+\([^)]+\))?)'` to `r'by\s+([^\s]+)'`
  - Now `by_match` only captures hostname without parenthesis content
  - Program info is handled exclusively by `program_match`
- **Affected File**: `jt_zmmsgtrace.py` line 4231
- **Effect**: Email routing page correctly displays program names without duplication

### Documentation Updates
- Updated version number to 2.3.3
- Updated README.md and README_EN.md version information
- Added program name duplication fix documentation

---

## Version 2.3.2 (2025-11-16)

### New Features

#### RFC 2047 Email Subject Decoding Support
- **Feature**: When Zimbra enables `custom_header_check`, subjects appear in RFC 2047 encoded format in logs, the program now automatically decodes them
- **Supported Encoding Formats**:
  - Base64 encoding: `=?utf-8?B?5ris6Kmm?=` → `測試`
  - Quoted-Printable encoding: `=?iso-8859-1?Q?Andr=E9?=` → `André`
- **Supported Character Sets**: UTF-8, ISO-8859-1, Latin1, Big5, and other common character sets
- **Implementation Details**:
  - Added `decode_header_value()` utility function (lines 508-543)
  - Uses Python standard library `email.header.decode_header`
  - Automatically decodes subjects when parsing Postfix cleanup records (lines 697-698)
  - Removed duplicate internal function definition, unified to use global function (line 4202)
- **Impact Scope**: Both CLI mode and Web UI mode can correctly display decoded subjects
- **Error Handling**: If decoding fails, returns original value without causing program crash
- **Log Example**:
  ```
  postfix/cleanup[xxx]: warning: header Subject: =?utf-8?B?5ris6Kmm?= from ...
  ```
  Displays as: `Subject: 測試`

### Documentation Updates
- Updated version number to 2.3.2
- Updated README.md and README_EN.md version information
- Added RFC 2047 decoding feature documentation

---

## Version 2.3.1 (2025-11-15)

### Bug Fixes

#### Fixed CLI Mode Empty Message Display Issue
- **Issue**: CLI mode execution displays empty NOQUEUE messages at the end
  ```
  Message ID: [unknown:NOQUEUE]
  Log: /var/log/zimbra.log
  From: unknown
  To:
  ```
- **Cause**: NOQUEUE records are still displayed even without recipients
- **Solution**: Filter out messages without recipients in main loop
- **Affected Files**: `jt_zmmsgtrace.py` lines 6081-6083
- **Effect**: Cleaner CLI output, no useless empty messages displayed

#### Fixed Email View Page Overflow Issue
- **Issue**: Raw content and full headers `<textarea>` areas overflow right boundary
- **Cause**:
  - `width: 100%` conflicts with `padding: 15px` and `border: 1px`
  - `white-space: pre` causes long lines not to wrap automatically
- **Solution**:
  - Add `box-sizing: border-box` to ensure padding and border included in width
  - Change to `white-space: pre-wrap` for automatic line wrapping
  - Add `overflow-wrap: break-word` to force word breaking
- **Affected Files**: `jt_zmmsgtrace.py` lines 5111, 5136
- **Effect**: Text areas correctly display within container, no longer overflow

#### Fixed Traditional Chinese Translation
- **Issue**: Email header fields (Subject, From, To, Date, etc.) still display in English in Traditional Chinese interface
- **Solution**: Update translation dictionary
  - `message_id`: 'Message ID' → '郵件 ID'
  - `subject`: 'Subject' → '主旨'
  - `from`: 'From' → '寄件者'
  - `to`: 'To' → '收件者'
  - `cc`: 'Cc' → '副本'
  - `date`: 'Date' → '日期'
  - `log`: 'Log' → '記錄檔'
- **Affected Files**: `jt_zmmsgtrace.py` lines 69, 102-107
- **Effect**: Complete Chinese localization for Traditional Chinese interface

### Document Updates
- Complete rewrite of README.md, integrating all document content
- Includes latest installation, deployment, and usage guides
- Added Q&A section
