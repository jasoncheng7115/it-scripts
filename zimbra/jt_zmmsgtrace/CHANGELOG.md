# jt_zmmsgtrace 更新記錄

[English Version](CHANGELOG_EN.md) | 繁體中文版

## Version 2.3.3 (2025-11-16)

### Bug 修正

#### 修正郵件路由顯示程式名稱重複問題
- **問題**: 郵件路由頁面中部分伺服器會顯示重複的程式名稱
  - 例如：`mail.jason.tools (Postfix) (Postfix)` 重複顯示兩次
- **原因**: `by_match` 正則表達式（第 4231 行）抓取了主機名稱和括號內容，然後 `program_match` 又再次抓取括號內容
- **解決方案**:
  - 修改 `by_match` 正則表達式從 `r'by\s+([^\s]+(?:\s+\([^)]+\))?)'` 改為 `r'by\s+([^\s]+)'`
  - 現在 `by_match` 只抓取主機名稱，不包含括號內容
  - 程式資訊由 `program_match` 專門處理
- **影響檔案**: `jt_zmmsgtrace.py` 第 4231 行
- **效果**: 郵件路由頁面正確顯示程式名稱，不再重複

### 文件更新
- 更新版本號至 2.3.3
- 更新 README.md 和 README_EN.md 版本資訊
- 新增程式名稱重複問題修正說明

---

## Version 2.3.2 (2025-11-16)

### 新功能

#### RFC 2047 郵件主旨解碼支援
- **功能**: 當 Zimbra 啟用 `custom_header_check` 時，log 中的主旨會以 RFC 2047 編碼格式出現，程式現在能自動解碼
- **支援編碼格式**:
  - Base64 編碼：`=?utf-8?B?5ris6Kmm?=` → `測試`
  - Quoted-Printable 編碼：`=?iso-8859-1?Q?Andr=E9?=` → `André`
- **支援字元集**: UTF-8, ISO-8859-1, Latin1, Big5 等常見字元集
- **實作細節**:
  - 新增 `decode_header_value()` 工具函數（第 508-543 行）
  - 使用 Python 標準函式庫 `email.header.decode_header`
  - 在解析 Postfix cleanup 的主旨記錄時自動解碼（第 697-698 行）
  - 移除重複定義的內部函數，統一使用全域函數（第 4202 行）
- **影響範圍**: CLI 模式和 Web UI 模式都能正確顯示解碼後的主旨
- **容錯處理**: 如果解碼失敗，返回原始值，不會導致程式崩潰
- **Log 範例**:
  ```
  postfix/cleanup[xxx]: warning: header Subject: =?utf-8?B?5ris6Kmm?= from ...
  ```
  顯示為：`主旨: 測試`

### 文件更新
- 更新版本號至 2.3.2
- 更新 README.md 和 README_EN.md 版本資訊
- 新增 RFC 2047 解碼功能說明

---

## Version 2.3.1 (2025-11-15)

### Bug Fixes

#### 修正 CLI 模式顯示空訊息問題
- **問題**: CLI 模式執行時，最後會顯示空的 NOQUEUE 訊息
  ```
  Message ID: [unknown:NOQUEUE]
  Log: /var/log/zimbra.log
  From: unknown
  To:
  ```
- **原因**: NOQUEUE 記錄如果沒有收件者仍會被顯示
- **解決**: 在主循環中過濾掉沒有收件者的訊息
- **影響檔案**: `jt_zmmsgtrace.py` 第 6081-6083 行
- **效果**: CLI 輸出更乾淨，不會顯示無用的空訊息

#### 修正郵件檢視頁面超出問題
- **問題**: 原始內容和完整標頭的 `<textarea>` 區域超出右邊界
- **原因**:
  - `width: 100%` 與 `padding: 15px` 和 `border: 1px` 衝突
  - `white-space: pre` 導致長行不自動換行
- **解決**:
  - 加入 `box-sizing: border-box` 確保 padding 和 border 包含在 width 內
  - 改用 `white-space: pre-wrap` 讓長行自動換行
  - 加入 `overflow-wrap: break-word` 強制斷字
- **影響檔案**: `jt_zmmsgtrace.py` 第 5111、5136 行
- **效果**: 文字區域正確顯示在容器內，不再超出

#### 修正繁體中文翻譯
- **問題**: 郵件標頭欄位（Subject, From, To, Date 等）在繁體中文介面仍顯示英文
- **解決**: 更新翻譯字典
  - `message_id`: 'Message ID' → '郵件 ID'
  - `subject`: 'Subject' → '主旨'
  - `from`: 'From' → '寄件者'
  - `to`: 'To' → '收件者'
  - `cc`: 'Cc' → '副本'
  - `date`: 'Date' → '日期'
  - `log`: 'Log' → '記錄檔'
- **影響檔案**: `jt_zmmsgtrace.py` 第 69、102-107 行
- **效果**: 繁體中文介面完整中文化

### 文件更新
- 完整重寫 README.md，整合所有文件內容
- 包含最新的安裝、部署、使用指南
- 新增 Q&A 章節
