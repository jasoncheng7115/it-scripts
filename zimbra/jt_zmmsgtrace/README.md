# jt_zmmsgtrace - Enhanced Email Tracer for Zimbra

Python 重寫版本的 `zmmsgtrace`，解決了原版在 Zimbra 郵件去除重複情況下找不到收件者的問題，並提供強大的 Web UI 介面。

---

## 使用情境

### Zimbra 原有工具的限制

Zimbra 雖然內建 `zmmsgtrace` 工具用於追蹤郵件，但在實務使用上存在以下限制：

- **無法處理去除重複的郵件**：當 Zimbra 啟用郵件去除重複功能時，`zmmsgtrace` 會遺漏部分收件者，導致追蹤不完整
- **缺乏圖形介面**：必須使用指令列操作，對於不熟悉 Linux 的管理員來說門檻較高
- **搜尋功能有限**：無法方便地搜尋歷史記錄檔案或依時間範圍批次查詢
- **郵件內容檢視困難**：無法直接檢視郵件內容、標頭或原始碼，需要額外使用其他工具

### 郵件管理員的實務需求

身為郵件系統管理員，在日常維運中經常需要：

1. **追蹤郵件流向**
   - 快速找到特定郵件的收入或寄出記錄
   - 確認郵件是否成功投遞給所有收件者
   - 找出郵件傳遞失敗的原因

2. **檢視郵件詳細資訊**
   - 方便檢視郵件完整內容、標頭、原始碼
   - 從郵件標頭中快速檢視 DKIM、SPF、DMARC 驗證結果
   - 查看垃圾郵件評分、病毒掃描結果等安全性資訊
   - 追蹤郵件經過哪些伺服器轉送（Received headers）

3. **效率與便利性**
   - 不需要記憶複雜的指令列參數
   - 能夠批次查詢多筆郵件記錄
   - 支援多語言介面，方便不同地區的管理員使用

**jt_zmmsgtrace 正是為了滿足這些實務需求而設計**，提供完整的郵件追蹤、去除重複處理、Web 圖形介面，以及豐富的郵件檢視功能。

---

## 主要功能

### 1. 解決 Zimbra 去除重複問題

原版 Perl 工具在處理 Zimbra 郵件去除重複時會遺漏收件者。新版本：

- 完整解析 Amavis 記錄中的所有收件者（`<r1>,<r2>,<r3>` 格式）
- 整合 Amavis 和 Postfix 資料
- 顯示即使沒有獨立 Postfix 投遞記錄的收件者
- 標註可能被去除重複的收件者

**範例輸出**：
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

### 2. 顯示記錄來源檔案

新增 `Log:` 欄位，顯示該記錄是在哪個記錄檔中找到的：

- 使用 `--all-logs` 載入多個記錄檔時，可以清楚知道每筆記錄來自哪個檔案
- 指定多個記錄檔案時，方便追蹤記錄來源
- 特別適用於查詢歷史記錄或跨多個歸檔檔案搜尋

### 3. Web UI 介面

- **多語言支援**：自動偵測瀏覽器語言，支援中英文切換
- **瀏覽器友善**：不需要記憶複雜指令列參數
- **即時搜尋**：圖形化搜尋表單，結果視覺化呈現
- **郵件檢視**：直接在瀏覽器查看完整郵件內容、標頭、安全性檢查
- **安全性分析**：顯示 DKIM、SPF、DMARC、SPAM 檢查結果
- **郵件路由**：視覺化顯示郵件傳遞路徑
- **下載功能**：支援下載 .eml 格式郵件
- **回應式設計**：支援手機、平板、電腦
- **密碼保護**：需要管理員密碼登入

### 4. **相容性**

- 完全相容原版的指令列參數
- 支援相同的正則表達式搜尋
- 支援壓縮檔案（.gz, .bz2）
- **已測試通過產品**：
  - Zimbra Open Source Edition
  - Zimbra Network Edition
- **已測試通過版本**：
  - Zimbra 9.0.0p38 ~ 9.0.0p44
  - Zimbra 10.1.10 ~ 10.1.11

---

## 快速開始

### 系統需求

```bash
# Python 3.7 或更高版本
python3 --version

# 無需額外套件，使用標準庫
```

### Web UI 模式（推薦）

```bash
# 1. 以 root 身份啟動 Web UI
sudo ./jt_zmmsgtrace.py --web

# 2. 開啟瀏覽器
http://localhost:8989/

# 3. 使用 Zimbra 管理員帳號登入
# 4. 在網頁介面中搜尋郵件
```

注意：本程式需要以 root 身份執行，以便讀取 Zimbra 記錄檔案和使用 zmprov 指令。

### 指令列模式

```bash
# 搜尋特定寄件者
./jt_zmmsgtrace.py -s "user@domain.com"

# 搜尋被去除重複的收件者（關鍵改進！）
./jt_zmmsgtrace.py -r "user2@domain.com"

# 時間範圍查詢
./jt_zmmsgtrace.py -t 20250101,20250131
```

---

## 安裝與部署

### 基本安裝

```bash
# 1. 複製到伺服器
scp jt_zmmsgtrace.py root@mail-server:/opt/jasontools/

# 2. 設定權限
chmod +x /opt/jasontools/jt_zmmsgtrace.py

# 3. 測試執行
./jt_zmmsgtrace.py --help
```

注意：如有防火牆，記得將 jt_zmmsgtrace 使用的連接埠打開（預設為 8989）。

---

## 使用方法

### 指令列選項

#### 搜尋篩選參數

| 選項 | 簡寫 | 說明 |
|------|------|------|
| `--id` | `-i` | Message ID（正則表達式） |
| `--sender` | `-s` | 寄件者地址（正則表達式） |
| `--recipient` | `-r` | 收件者地址（正則表達式） |
| `--srchost` | `-F` | 來源主機名稱或 IP（正則表達式） |
| `--desthost` | `-D` | 目標主機名稱或 IP（正則表達式） |
| `--time` | `-t` | 時間範圍：`YYYYMM[DD[HH[MM[SS]]]],YYYYMM[DD[HH[MM[SS]]]]` |
| `--year` | | 指定記錄檔所屬年份（預設：目前年份）<br>注意：Zimbra 記錄檔時間戳記無年份資訊，檢視舊記錄時必須指定 |

#### Web UI 參數

| 選項 | 說明 |
|------|------|
| `--web` | 啟動 Web UI 模式 |
| `--port` | 指定 Web UI 連接埠（預設：8989） |
| `--login-attempts` | 最大登入失敗次數限制（預設：5 次） |
| `--login-timeout` | 登入失敗追蹤時間範圍，單位為分鐘（預設：10 分鐘） |

#### 記錄檔案參數

| 選項 | 說明 |
|------|------|
| `--all-logs` | 載入所有 `/var/log/zimbra*` 檔案（預設：僅載入 `/var/log/zimbra.log`） |
| `--nosort` | 不依修改時間排序檔案 |
| `files` | 指定要處理的記錄檔案（位置參數，可指定多個檔案） |

#### 其他參數

| 選項 | 簡寫 | 說明 |
|------|------|------|
| `--debug` | | 增加除錯輸出（可重複使用，增加詳細程度） |
| `--version` | `-v` | 顯示版本資訊 |

### 使用範例

注意：以下範例均需以 root 身份執行（使用 `sudo` 或直接以 root 登入）。

#### Web UI 模式（推薦）

```bash
# 啟動 Web UI（預設 port 8989）
sudo ./jt_zmmsgtrace.py --web

# 自訂 port
sudo ./jt_zmmsgtrace.py --web --port 9000

# Debug 模式
sudo ./jt_zmmsgtrace.py --web --debug

# 開啟瀏覽器
# http://localhost:8989/
# 或從遠端: http://192.168.1.119:8989/
```

**Web UI 特色**：
- 多語言介面（中文/英文）
- 漂亮的圖形化介面
- 即時搜尋，結果視覺化
- 完整郵件檢視功能
- 安全性分析（DKIM/SPF/DMARC/SPAM）
- 郵件路由視覺化
- 支援下載 .eml
- 回應式設計
- 自動標註去除重複收件者

#### 指令列模式

##### 基本搜尋範例

```bash
# 追蹤所有郵件（使用預設記錄檔案）
./jt_zmmsgtrace.py

# 搜尋特定寄件者
./jt_zmmsgtrace.py -s "user@domain.com"

# 搜尋被去除重複的收件者（關鍵改進！）
./jt_zmmsgtrace.py -r "user2@domain.com"

# 搜尋特定 Message-ID
./jt_zmmsgtrace.py -i "ABC123@domain.com"

# 時間範圍查詢
./jt_zmmsgtrace.py -t 20250101,20250131

# 複合查詢（使用正則表達式）
./jt_zmmsgtrace.py -s "^admin" -r "@example.com$" -t 202501
```

##### 指定記錄檔案

```bash
# 指定單一記錄檔案
./jt_zmmsgtrace.py /var/log/zimbra.log

# 指定多個記錄檔案（包含壓縮檔）
./jt_zmmsgtrace.py /var/log/zimbra.log.1.gz /var/log/zimbra.log

# 使用萬用字元指定多個檔案
./jt_zmmsgtrace.py /var/log/zimbra.log*

# 載入所有 zimbra 記錄檔案（包含已歸檔的）
./jt_zmmsgtrace.py --all-logs

# 不排序檔案（依指令列順序處理）
./jt_zmmsgtrace.py --nosort /var/log/zimbra.log.2.gz /var/log/zimbra.log.1.gz
```

##### 除錯與進階選項

```bash
# 除錯模式（顯示詳細處理資訊）
./jt_zmmsgtrace.py --debug -r "user@domain.com"

# 更詳細的除錯（可重複使用 --debug）
./jt_zmmsgtrace.py --debug --debug -s "admin@"

# 指定記錄檔所屬年份（檢視舊記錄檔時）
# Zimbra 記錄的時間格式是 "Jan 15 10:30:00"（沒有年份）
# 檢視 2024 年的舊記錄必須指定 --year 2024
./jt_zmmsgtrace.py --year 2024 /var/log/zimbra.log.2024.gz -s "user@domain.com"

# 搭配時間範圍搜尋 2024 年 12 月的記錄
./jt_zmmsgtrace.py --year 2024 -t 20241201,20241231 /var/log/old-zimbra.log

# 顯示版本資訊
./jt_zmmsgtrace.py --version
```

##### Web UI 進階選項

```bash
# 自訂 Web UI 連接埠
sudo ./jt_zmmsgtrace.py --web --port 9000

# 載入所有記錄檔案並啟動 Web UI
sudo ./jt_zmmsgtrace.py --web --all-logs

# 調整登入安全設定
sudo ./jt_zmmsgtrace.py --web --login-attempts 3 --login-timeout 5

# Web UI + 除錯模式
sudo ./jt_zmmsgtrace.py --web --debug
```

---

## 安全性

本工具已實作以下安全性措施：

### 已實作的防護

- **正則表達式注入攻擊防護**：限制 pattern 長度（最大 500 字元）
- **XSS 攻擊防護**：所有輸出使用 `html.escape()` 處理
- **路徑穿越攻擊防護**：記錄檔案路徑寫死在程式中
- **輸入驗證**：限制所有輸入欄位長度
- **參數驗證**：分頁參數限制（offset ≤ 100,000, limit ≤ 500）
- **錯誤處理**：友善錯誤訊息，不外洩系統資訊
- **登入保護**：失敗次數限制，防止暴力破解

詳細安全性說明請見 [SECURITY.md](SECURITY.md)

### 部署建議

1. **以 root 使用者執行**（需要讀取 Zimbra 記錄檔案和執行 zmprov）
2. **使用 HTTPS**（透過反向代理）
3. **啟用防火牆**（限制存取 IP）
4. **正確設定檔案權限**
5. **定期更新到最新版本**

---

## 常見問題

### Q1: 為什麼有些收件者顯示 "[from Amavis - may be deduplicated]"？

這表示該收件者只在 Amavis 記錄中找到，沒有獨立的 Postfix 投遞記錄。這通常發生在 Zimbra 郵件去除重複的情況下。

### Q2: 如何知道郵件是否被 Zimbra 去除重複？

如果你在輸出中看到多個收件者，但只有部分有完整的投遞記錄（status sent），其他顯示 "Processed by Amavis but no individual Postfix delivery record"，那很可能是去除重複的情況。

### Q3: Web UI 無法檢視郵件內容？

請確認：
1. 程式以 root 使用者執行（需要執行 zmprov 和讀取郵件內容）
2. 帳號是 Zimbra 內部帳號（外部帳號無法檢視）

### Q4: 如何切換語言？

- **登入頁面**：使用語言選擇器
- **登入後**：點選右上角的語言切換按鈕
- 語言選擇會自動儲存在 Cookie 中

### Q5: 為什麼需要使用 `--year` 參數？

Zimbra 記錄檔（`/var/log/zimbra.log`）的時間戳記格式是 `Jan 15 10:30:00`，**沒有包含年份資訊**。

**使用時機**：
- **檢視當年記錄**：不需要指定（預設為目前年份）
- **檢視舊年度記錄**：必須指定 `--year`

**範例**：
```bash
# 2025 年檢視 2025 年的記錄（不需要 --year）
./jt_zmmsgtrace.py -s "user@domain.com"

# 2025 年檢視 2024 年的舊記錄（必須指定 --year 2024）
./jt_zmmsgtrace.py --year 2024 /var/log/zimbra.log.2024.gz -s "user@domain.com"
```

**注意**：如果不指定 `--year`，程式會將舊記錄誤認為今年的資料，導致時間比對錯誤。

---

## 與原版的比較

| 功能 | 原版 Perl | 新版 Python (jt_zmmsgtrace) |
|------|-----------|------------------------------|
| 解析 Postfix 記錄 | 支援 | 支援 |
| 解析 Amavis 記錄 | 支援 | 支援 |
| **拆解 Amavis 多收件者** | 不支援 | 支援 |
| **整合去除重複收件者** | 不支援 | 支援 |
| **搜尋去除重複收件者** | 不支援 | 支援 |
| **標註去除重複狀態** | 不支援 | 支援 |
| **顯示記錄來源檔案（Log: 欄位）** | 不支援 | 支援 |
| **Web UI 介面** | 不支援 | 支援 |
| **多語言支援** | 不支援 | 支援 |
| **郵件檢視功能** | 不支援 | 支援 |
| **安全性分析** | 不支援 | 支援 |
| 壓縮檔案支援 | 支援 | 支援 |
| 正則表達式搜尋 | 支援 | 支援 |

---

## 版本歷史

- **v2.3.1** (2025-01-15): UI 修正（文字超出、中文翻譯）
- **v2.3.0** (2025-01-12): 多語言支援、Message-ID 格式改進
- **v2.2.0** (2025-01-12): 改用 zmsoap、郵件檢視功能
- **v2.1.0** (2025-01-11): 新增 Web UI 介面
- **v2.0.0** (2025-01-10): Python 重寫，解決去除重複問題

詳細變更請見 [CHANGELOG.md](CHANGELOG.md)

---

## 技術細節

### 資料結構

```python
@dataclass
class RecipientInfo:
    address: str
    orig_recip: Optional[str]
    status: Optional[str]
    from_amavis_only: bool  # 關鍵：標記只在 Amavis 找到的收件者

@dataclass
class Message:
    message_id: str
    sender: Optional[str]
    recipients: Dict[str, RecipientInfo]  # 包含所有收件者

@dataclass
class AmavisRecord:
    recipients: List[str]  # 關鍵：拆解後的收件者列表
```

### 關鍵演算法：整合 Amavis 資料

```python
def integrate_amavis_data(self):
    """整合 Amavis 資料，補充被去除重複的收件者"""
    for amav in self.amavis_records.values():
        msg = self.find_message(amav)

        # 關鍵：為 Amavis 中的每個收件者建立條目
        for recip_addr in amav.recipients:
            if recip_addr not in msg.recipients:
                # 這個收件者沒有 Postfix 記錄（可能被去除重複）
                msg.recipients[recip_addr] = RecipientInfo(
                    address=recip_addr,
                    from_amavis_only=True,  # 標記
                    status='processed'
                )
```

---

## 效能考量

- 與原版相同，會將記錄資料載入記憶體
- 大型記錄檔案需要足夠的記憶體
- Web UI 模式會在啟動時解析記錄，之後查詢速度快

---

## 除錯

使用 `--debug` 選項可以看到詳細的處理過程：

```bash
# 指令列模式
sudo ./jt_zmmsgtrace.py --debug -r "user@domain.com" 2>&1 | less

# Web UI 模式
sudo ./jt_zmmsgtrace.py --web --debug
```

輸出會包含：
- 檔案讀取進度
- Amavis 記錄解析
- 去除重複收件者的新增
- 郵件篩選統計
- Web UI 請求處理

---

## 版本資訊

- **版本**: 2.3.1
- **語言**: Python 3.7+
- **原版**: Perl (v1.05)
- **作者**: Jason Cheng (Jason Tools) (與 Claude Code 協作)
- **日期**: 2025-01-15
- **授權**: GNU GPL v2

---

## 最新更新 (v2.3.1)

### Bug 修正
- **修正 CLI 模式顯示空郵件問題**：CLI 執行時不再顯示空的 NOQUEUE 郵件
  - 篩選掉沒有收件者的郵件
  - CLI 輸出更乾淨
- **修正郵件檢視頁面超出問題**：原始內容和完整標頭區域不再超出右邊界
  - 加入 `box-sizing: border-box` 確保 padding/border 包含在 width 內
  - 改用 `white-space: pre-wrap` 讓長行自動換行
- **修正繁體中文翻譯**：郵件標頭欄位正確顯示中文
  - Message ID → 郵件 ID
  - Subject → 主旨
  - From → 寄件者
  - To → 收件者
  - Date → 日期

### 多語言支援 (v2.3.0)
- **自動語言偵測**：根據瀏覽器語言自動選擇介面
- **支援語言**：繁體中文、English
- **語言切換**：登入頁面可選擇語言，所有頁面提供切換按鈕
- **完整翻譯**：所有頁面、訊息、按鈕皆支援多語言

### Message-ID 格式改進 (v2.3.0)
- 支援更多 RFC 5322 標準字元：`+ ~ ! = ? # $ % & * /`
- 修正包含特殊字元的 Message-ID 無法檢視的問題
- 相容 Gmail、Exchange、各種郵件系統的 Message-ID 格式

---

## 相關文件

- [SECURITY.md](SECURITY.md) - 安全性說明
- [CHANGELOG.md](CHANGELOG.md) - 完整變更記錄

---

## 授權

與原版相同，採用 **GNU General Public License v2.0**

---

## 作者

- **原版**: Synacor, Inc. (Zimbra)
- **Python 重寫 & Web UI**: Jason Cheng (Jason Tools) - 2025 (與 Claude Code 協作)

---

## 參考資料

- [原版 zmmsgtrace 官方文件](https://wiki.zimbra.com/wiki/CLI_zmmsgtrace)
- [Zimbra SOAP API](https://wiki.zimbra.com/wiki/SOAP_API_Reference_Material_Beginning_with_ZCS_8)
