# JT Wazuh Agent Manager

[English](README.md) | [繁體中文](README_zh-TW.md)

強化版 Wazuh Agent 管理工具，支援 master/worker 多節點叢集環境。提供 Web 介面與 CLI 兩種操作方式。

> **開發目的**：本工具是為了補足 Wazuh Dashboard 缺少或操作不夠方便的管理功能而開發，**並非**要取代 Wazuh Dashboard，而是作為輔助工具。

> **建議**：以 Web UI 為主要操作介面，這是本工具的主力功能，具備完整的操作體驗。

![Version](https://img.shields.io/badge/version-1.3.103-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

## 功能特色

### Agent 管理
- 視覺化顯示所有 agent 狀態
- 進階篩選功能（狀態、群組、節點、OS、版本、IP、名稱、同步狀態）
- **方便的多選操作**：輕鬆選取多個 agent 進行批次處理
- **分布圖**：視覺化顯示 agent 分布統計（狀態、OS、版本、群組、節點、同步狀態）
  - 點擊色塊可快速篩選
  - 切換類型時有動畫效果
- **統計區自動更新**：頂部統計數字每 10 秒自動更新，數值變化時有滑入動畫
- **群組操作**：
  - 加入群組 / 移出群組
  - 合併至其它群組
  - 僅保留在特定群組（從其它群組移除）
  - 群組重新命名
  - **從 CSV 匯入**：大量批次加入群組
- 批次操作：重啟、重連、刪除
- **Move to Node**（規劃中）：搭配 HAProxy 將 agent 遷移至指定節點（開發中）
- 健康檢查與重複 agent 偵測
- **Queue DB 容量檢查**：監控 agent 佇列資料庫使用量
- Agent 升級：選擇 agent 後可批次升級，即時追蹤升級進度

### 叢集支援
- 完整支援 master/worker 多節點架構
- 節點服務狀態監控
- **編輯 ossec.conf**：編輯 master 與 worker 節點的設定檔
- **重啟服務**：重啟任一節點的 Wazuh 服務
- **下載 cluster.key**：從 master 節點下載叢集金鑰
- **WPK 檔案管理**：上傳、刪除 WPK 升級檔案
- **同步狀態檢查**：監控 master 與 worker 之間的檔案同步
  - Rules、Decoders、Groups、Keys、Lists、SCA
  - 顯示差異檔案清單
- SSH 遠端管理 worker 節點

### 統計報表
- 依狀態、群組、節點、OS、版本、網段分組統計
- 所有統計表格欄位可點擊排序
- 匯出為 JSON / CSV 格式

### Rules 規則檢視器
- **規則階層視覺化**：以可收折的樹狀結構顯示規則的上下層關係
- 依 Rule ID 搜尋
- 顯示規則等級、描述與來源檔案
- 點擊展開查看完整的規則 XML 內容
- 支援內建規則與自訂規則

### 安全性
- 所有輸入參數驗證
- 命令注入防護
- 路徑遍歷防護
- 安全的檔案上傳處理
- **完整記錄與稽核**：可查看所有操作記錄與稽核事件
- **API 帳號管理**：新增、修改、管理 Wazuh API 使用者與角色

### 其他功能
- **Dry-run 模式**：所有寫入操作都支援預覽模式
- **多種輸出格式**：Table / JSON / CSV（CLI）
- **自動 SSL 憑證**：`--ssl-auto` 自動產生自簽憑證

## 截圖

### 登入頁面
![Login](screenshots/1_login.png)

### Agent 列表
![Agents](screenshots/2_agents.png)

### Agent 操作與 Queue DB
![Agent Actions](screenshots/3_selected_action_queuedb.png)

### 群組管理
![Groups](screenshots/4_groups.png)

### 節點管理
![Nodes](screenshots/5_nodes.png)

### WPK 檔案管理
![WPK Files](screenshots/6_nodes_wpkfiles.png)

### 規則檢視器
![Rules](screenshots/7_rule.png)

### API 使用者
![API Users](screenshots/8_apiusers.png)

### 記錄檢視器
![Logs](screenshots/9_logs.png)

### 編輯 ossec.conf
![Edit Config](screenshots/10_node_editconfig.png)

### Agent 升級
![Upgrade Step 1](screenshots/11_upgrade_agent_1.png)
![Upgrade Step 2](screenshots/12_upgrade_agent_2.png)
![Upgrade Step 3](screenshots/13_upgrade_agent_3.png)

### Agent 詳細資訊
![Agent Detail](screenshots/14_agent_detail.png)

## 專案結構

```
jt_wazuh_agent_mgr/
├── wazuh_agent_mgr.py      # 主程式入口
├── create_api_user.py      # 建立 Wazuh API 使用者工具
├── config.yaml             # 設定檔
├── requirements.txt        # 相依套件
├── README.md
└── lib/
    ├── __init__.py
    ├── config.py           # 設定檔載入
    ├── wazuh_cli.py        # Wazuh CLI 封裝
    ├── wazuh_api.py        # Wazuh API 封裝 (重連功能用)
    ├── agent_ops.py        # Agent 操作
    ├── group_ops.py        # 群組操作
    ├── node_ops.py         # 節點操作
    ├── stats.py            # 統計功能
    ├── output.py           # 輸出格式化
    └── web_ui.py           # Web 介面
```

## 系統需求

- Python 3.8+
- Wazuh Manager 4.x
- **必須安裝在 Wazuh Manager 上**（叢集模式請安裝在 Master 節點）

## 安裝

```bash
curl -sL https://raw.githubusercontent.com/jasoncheng7115/it-scripts/master/jt_wazuh_agent_mgr/install.sh | bash
```

> **提示**：需以 root 執行。重複執行相同指令可更新版本（config.yaml 設定檔會保留）。

## 快速啟動（推薦）

```bash
./wazuh_agent_mgr.py --web --ssl-auto
```

完成！開啟瀏覽器前往 **https://YOUR_WAZUH_MANAGER_IP:5000**，使用 Wazuh API 帳號登入即可。

> **提示**：使用 `wazuh` 或 `wazuh-wui` 帳號，密碼請查看安裝時產生的 `wazuh-install-files.tar` 或安裝記錄。

### 其他啟動選項

```bash
# 自訂連接埠
./wazuh_agent_mgr.py --web --port 8443 --ssl-auto

# 使用自訂 SSL 憑證
./wazuh_agent_mgr.py --web --ssl-cert /path/to/cert.pem --ssl-key /path/to/key.pem
```

## 設定

編輯 `config.yaml`：

```yaml
# Wazuh 安裝路徑
wazuh_path: /var/ossec

# API 設定
# Web UI 模式：不需要設定 username/password（使用者透過瀏覽器登入）
# CLI 模式：需要設定 username/password（執行 ./wazuh_agent_mgr.py agent list 等指令）
api:
  enabled: false           # CLI 模式需設為 true
  host: localhost
  port: 55000
  username: wazuh          # 僅 CLI 模式需要
  password: "your-password"  # 僅 CLI 模式需要，密碼請查看 wazuh-install-files.tar
  verify_ssl: false

# 預設輸出格式: table, json, csv（僅 CLI 模式）
output_format: table

# SSH 設定（選用，用於遠端管理 worker 節點）
# ssh:
#   enabled: true
#   key_file: /root/.ssh/wazuh_cluster_key
#   nodes:
#     worker01:
#       host: 192.168.1.100
#       port: 22
#       user: root
```

### Web UI 與 CLI 設定差異

| 設定項目 | Web UI | CLI |
|---------|--------|-----|
| `api.enabled` | 不需要 | `true` |
| `api.username` | 不需要（瀏覽器登入） | 需要 |
| `api.password` | 不需要（瀏覽器登入） | 需要 |
| `ssh.*` | 選用（遠端節點管理） | 選用 |

## CLI 使用方式

### Agent 管理

```bash
# 列出所有 agent
./wazuh_agent_mgr.py agent list

# 篩選 agent (支援正則表達式)
./wazuh_agent_mgr.py agent list --status=Active
./wazuh_agent_mgr.py agent list --status=Disconnected
./wazuh_agent_mgr.py agent list --group=webservers
./wazuh_agent_mgr.py agent list --node=worker01
./wazuh_agent_mgr.py agent list --name="web-.*"
./wazuh_agent_mgr.py agent list --ip="192.168.1.*"

# 組合篩選
./wazuh_agent_mgr.py agent list --status=Active --group=production

# 查看 agent 詳細資訊
./wazuh_agent_mgr.py agent info 001

# 快速狀態查詢
./wazuh_agent_mgr.py agent pending           # Pending agents
./wazuh_agent_mgr.py agent disconnected      # 斷線 agents
./wazuh_agent_mgr.py agent never-connected   # 從未連線
./wazuh_agent_mgr.py agent active            # 活躍 agents

# 健康檢查
./wazuh_agent_mgr.py agent health

# 找出重複的 agent
./wazuh_agent_mgr.py agent duplicate --by=ip
./wazuh_agent_mgr.py agent duplicate --by=name

# 重啟 agent
./wazuh_agent_mgr.py agent restart 001 002 003
./wazuh_agent_mgr.py agent restart 001 002 --dry-run  # 預覽模式

# 刪除 agent
./wazuh_agent_mgr.py agent delete 001
./wazuh_agent_mgr.py agent delete 001 002 --dry-run   # 預覽模式

# 匯出 agent 清單
./wazuh_agent_mgr.py agent export --format=csv
./wazuh_agent_mgr.py agent export --format=json
```

### 群組管理

```bash
# 列出所有群組
./wazuh_agent_mgr.py group list

# 查看群組詳情與成員
./wazuh_agent_mgr.py group show webservers

# 建立群組
./wazuh_agent_mgr.py group create newgroup
./wazuh_agent_mgr.py group create newgroup --dry-run

# 刪除群組
./wazuh_agent_mgr.py group delete oldgroup
./wazuh_agent_mgr.py group delete oldgroup --dry-run

# 批次將 agent 加入群組
./wazuh_agent_mgr.py group add-agent webservers 001 002 003
./wazuh_agent_mgr.py group add-agent webservers 001 002 --dry-run

# 批次將 agent 移出群組
./wazuh_agent_mgr.py group remove-agent webservers 001
./wazuh_agent_mgr.py group remove-agent webservers 001 002 --dry-run
```

### 節點管理

```bash
# 列出叢集節點
./wazuh_agent_mgr.py node list

# 查看節點詳情
./wazuh_agent_mgr.py node show worker01

# 列出節點上的 agent
./wazuh_agent_mgr.py node agents worker01

# 強迫 agent 重連 (需要啟用 API)
./wazuh_agent_mgr.py node reconnect 001 002
./wazuh_agent_mgr.py node reconnect 001 002 --dry-run

# 遷移整個節點的 agent (強迫重連)
./wazuh_agent_mgr.py node migrate --from=worker01
./wazuh_agent_mgr.py node migrate --from=worker01 --to=worker02
./wazuh_agent_mgr.py node migrate --from=worker01 --dry-run
```

### 統計功能

```bash
# 總覽統計
./wazuh_agent_mgr.py stats summary

# 依狀態分組統計
./wazuh_agent_mgr.py stats by-status

# 依群組分組統計
./wazuh_agent_mgr.py stats by-group

# 依節點分組統計
./wazuh_agent_mgr.py stats by-node

# 依作業系統分組統計
./wazuh_agent_mgr.py stats by-os

# 依版本分組統計
./wazuh_agent_mgr.py stats by-version

# 完整報告
./wazuh_agent_mgr.py stats report
```

### 輸出格式

```bash
# 表格輸出 (預設)
./wazuh_agent_mgr.py agent list --format=table

# JSON 輸出 (適合程式處理)
./wazuh_agent_mgr.py agent list --format=json

# CSV 輸出 (適合匯入試算表)
./wazuh_agent_mgr.py agent list --format=csv

# 搭配其他指令
./wazuh_agent_mgr.py stats summary --format=json
./wazuh_agent_mgr.py group list --format=csv
```

## Web 介面

啟動 Web 伺服器：

```bash
# 預設監聽 0.0.0.0:5000
./wazuh_agent_mgr.py --web

# 自訂 host 和 port
./wazuh_agent_mgr.py --web --host=127.0.0.1 --port=8080
```

### SSL/HTTPS 設定 (建議)

**推薦使用 `--ssl-auto` 自動產生自簽憑證：**

```bash
# 自動產生自簽憑證並啟用 HTTPS (推薦)
./wazuh_agent_mgr.py --web --ssl-auto

# 自訂 port 並使用自動 SSL
./wazuh_agent_mgr.py --web --port=8443 --ssl-auto
```

如果需要使用自己的憑證：

```bash
# 使用自訂憑證
./wazuh_agent_mgr.py --web --ssl-cert=/path/to/cert.pem --ssl-key=/path/to/key.pem
```

然後用瀏覽器開啟 `https://localhost:5000` (使用 SSL) 或 `http://localhost:5000` (未使用 SSL)

> **注意**：使用 `--ssl-auto` 時，瀏覽器會提示憑證不受信任，這是正常的。點擊「進階」→「繼續前往」即可。

### 登入方式

Web 介面啟動後會顯示登入頁面，需要輸入 **Wazuh API 帳號** (不是 Dashboard 帳號)：

| 欄位 | 說明 | 預設值 |
|------|------|--------|
| Wazuh API Host | Wazuh Manager 的 IP 或 hostname | localhost |
| Wazuh API Port | Wazuh API 埠號 | 55000 |
| Username | Wazuh API 使用者名稱 | wazuh |
| Password | Wazuh API 密碼 | (無預設) |

> **注意**：Wazuh API 帳號與 Dashboard 帳號是不同的系統！
> - Dashboard 帳號：用於登入 Wazuh Dashboard (預設: `admin`)
> - API 帳號：用於呼叫 Wazuh Manager API (預設: `wazuh` 或 `wazuh-wui`，或其他具 `administrator` 角色的帳號)

登入成功後，系統會自動取得 API Token 並用於後續所有操作。Token 過期時會自動重新取得。

### 建立 Wazuh API 使用者

如果需要建立新的 API 使用者，可使用內建工具：

```bash
# 互動式建立 (會提示輸入密碼)
./create_api_user.py --new-user api_admin

# 完整參數
./create_api_user.py \
  --host localhost \
  --admin-user wazuh \
  --admin-pass 現有管理員密碼 \
  --new-user api_admin \
  --new-pass 新使用者密碼 \
  --role administrator
```

**可用角色：**

| 角色 | 說明 |
|------|------|
| `administrator` | 完整權限 (預設) |
| `readonly` | 唯讀權限 |
| `agents_admin` | Agent 管理權限 |
| `cluster_admin` | 叢集管理權限 |

**查看現有 API 密碼：**

```bash
# 解壓縮安裝時產生的密碼檔（通常在執行安裝的目錄下）
tar -xvf wazuh-install-files.tar
cat wazuh-install-files/wazuh-passwords.txt
```

### Web 介面功能

- **Agent 列表**：視覺化顯示所有 agent，支援即時搜尋與篩選
- **批次操作**：複選多個 agent 進行批次操作
  - 批次加入群組
  - 批次移出群組
  - 批次重啟
  - 批次重連 (Reconnect)
  - 批次刪除
- **群組管理**：建立、刪除群組，查看群組成員
- **節點管理**：查看節點資訊，批次重連節點上的 agent
- **統計報表**：依狀態、群組、OS 分組的統計圖表
- **Dry-run 模式**：勾選後所有操作僅預覽不實際執行
- **登出功能**：點擊右上角 Logout 按鈕可登出

## Dry-run 模式

所有寫入操作都支援 `--dry-run` 參數，可以預覽將執行的動作而不實際執行：

```bash
./wazuh_agent_mgr.py agent delete 001 --dry-run
# 輸出: [DRY-RUN] Would execute: /var/ossec/bin/manage_agents -r 001

./wazuh_agent_mgr.py group add-agent production 001 002 --dry-run
# 輸出: [DRY-RUN] Would execute: /var/ossec/bin/agent_groups -a -i 001 -g production
# 輸出: [DRY-RUN] Would execute: /var/ossec/bin/agent_groups -a -i 002 -g production
```

## 對應的 Wazuh CLI 指令

| 功能 | Wazuh CLI 指令 |
|------|----------------|
| 列出 agent | `/var/ossec/bin/agent_control -l` |
| Agent 資訊 | `/var/ossec/bin/agent_control -i <id>` |
| 重啟 agent | `/var/ossec/bin/agent_control -R <id>` |
| 列出群組 | `/var/ossec/bin/agent_groups -l` |
| 群組成員 | `/var/ossec/bin/agent_groups -l -g <group>` |
| 加入群組 | `/var/ossec/bin/agent_groups -a -i <id> -g <group>` |
| 移出群組 | `/var/ossec/bin/agent_groups -r -i <id> -g <group>` |
| 建立群組 | `/var/ossec/bin/agent_groups -a -g <group>` |
| 刪除群組 | `/var/ossec/bin/agent_groups -r -g <group>` |
| 刪除 agent | `/var/ossec/bin/manage_agents -r <id>` |
| 節點資訊 | `/var/ossec/bin/cluster_control -l` |
| 強迫重連 | Wazuh API: `PUT /agents/{id}/reconnect` |

## SSH 設定 (選用)

如果您想要從 Web 介面遠端編輯 worker 節點的設定檔或重啟服務，需要設定 SSH：

```yaml
# 在 config.yaml 中加入
ssh:
  enabled: true
  key_file: /root/.ssh/wazuh_cluster_key
  nodes:
    worker-node-name:
      host: 192.168.1.100
      port: 22
      user: root
```

> **注意**：修改 `config.yaml` 後需要重新啟動程式才會生效。

詳細設定步驟請參考 Web 介面中的「SSH Setup Guide」。

## 注意事項

1. **此工具必須安裝在 Master 節點上**
2. 需要有執行 `/var/ossec/bin/*` 的權限
3. 節點重連功能需要啟用 API 並設定 credentials
4. 建議先使用 `--dry-run` 預覽操作再實際執行
5. 修改 `config.yaml` 後需要重新啟動程式

## 更新記錄

### v1.3.103 (2026-01-04)
- **修正分布圖動畫**：切換頁籤時不再重複播放動畫
- **修正統計區歸零問題**：API 回傳無效資料時保留原有數值

### v1.3.102 (2026-01-04)
- **分布圖動畫**：切換類型時從左往右展開動畫

### v1.3.101 (2026-01-04)
- **分布圖動畫效果**：下拉選單切換時有動畫

### v1.3.100 (2026-01-04)
- **統計區滑入動畫**：數字更新時有從上而下滑入效果

### v1.3.99 (2026-01-04)
- **統計區自動更新**：頂部統計數字每 10 秒自動更新

### v1.3.98 (2026-01-04)
- **Groups 頁面最佳化**：
  - Agent Count 欄位置中對齊
  - 所有按鈕統一寬度

### v1.3.97 (2026-01-04)
- **分布圖配色調整**：使用深色系確保白色文字可讀性

### v1.3.95 (2026-01-04)
- **分布圖對齊**：與表格左右對齊
- **小區塊文字截斷**：空間不足時只顯示開頭文字

### v1.3.90 (2026-01-04)
- **新增分布圖**：Agent 列表上方新增視覺化分布統計條
  - 支援狀態、OS、版本、群組、節點、同步狀態
  - 點擊色塊快速篩選

### v1.3.89 (2026-01-04)
- **表格列高統一**：固定 50px 高度，Name 欄位過長時截斷顯示
- **Group 標籤最佳化**：更緊湊的樣式，最多顯示兩行

### v1.3.83 (2026-01-04)
- **統計百分比格式**：統一顯示一位小數

### v1.3.36 (2026-01-02)
- **Rules 頁籤強化**：
  - 自訂規則以橘色「Custom」標籤標示
  - Level 0 規則以灰色斜體標示（不會被記錄）
  - XML 內容顯示支援語法高亮（標籤、屬性、值、註解）
  - 新增「展開全部」與「收合全部」按鈕

### v1.3.35 (2026-01-02)
- **新增 Rules 頁籤**：規則階層檢視器
  - 依 Rule ID 搜尋，顯示規則的上下層關係（if_sid、if_matched_sid）
  - 以可收折的樹狀結構呈現
  - 標記目標規則，區分父規則與子規則
  - 點擊規則可展開查看完整 XML 內容
  - 支援內建規則（/var/ossec/ruleset/rules/）與自訂規則（/var/ossec/etc/rules/）

### v1.3.32 (2025-01-01)
- **修正版本排序**：統計頁面的 By Agent Version 改用語意化版本排序（v4.14.1 > v4.9.2）

### v1.3.31 (2025-01-01)
- **統計頁面可排序欄位**：所有區塊的欄位標題都可點擊排序
- **By OS 預設排序**：改為依 OS 名稱字母順序排序

### v1.3.30 (2025-01-01)
- **Move to Node 說明更新**：新增 HAProxy LB 整合說明

### v1.3.29 (2025-01-01)
- **Nodes 頁面 Refresh 按鈕強化**：同時重新讀取節點資料、服務狀態、同步狀態
- **移除 Check Services 按鈕**：功能已整合至 Refresh 按鈕

### v1.3.28 (2025-01-01)
- **Favicon 設定**：使用 logo-1.png 作為網站圖示
- **新增 /images/ 路由**：支援讀取 images 目錄下的靜態檔案

### v1.3.27 (2025-01-01)
- **Sync Status 標籤不換行**：修正 "not synced" 被換行的問題

### v1.3.26 (2025-01-01)
- **Sync Status 載入指示**：Worker 節點同步狀態讀取中顯示 "⟳ Loading..."

### v1.3.25 (2025-01-01)
- **修正 Clear Upgrade History**：清除按鈕現在會正確清除舊的升級記錄

### v1.3.24 (2025-01-01)
- **安全性強化**：
  - 新增輸入驗證函數：`validate_node_name`, `validate_agent_id`, `validate_group_name`, `validate_username`
  - 新增路徑白名單驗證：`validate_path`, `ALLOWED_PATHS`
  - 新增 Shell 參數跳脫：`safe_shell_arg` (使用 shlex.quote)
  - 新增記錄清理：`sanitize_for_log`
  - Sync-detail 端點使用白名單 `ALLOWED_SYNC_ITEMS` 防止路徑遍歷
  - 所有 URL 參數端點加入輸入驗證
  - 檔案上傳使用 `werkzeug.utils.secure_filename()`

### v1.3.23 (2025-01-01)
- **Master 節點 Sync Status 美化**：顯示 6 個藍色同步項目（Rules, Decoders, Groups, Keys, Lists, SCA）並標示 "source"

### v1.2.x 系列
- Agent Upgrade 功能
- Upgrade Files 管理
- 升級進度追蹤

### v1.1.4 (2024-12-31)
- **Columns 下拉選單風格統一**：改用與篩選器相同的 multi-select 風格

### v1.1.3 (2024-12-31)
- **響應式寬度**：移除 container 的 max-width 限制，畫面拉寬時會自動延展

### v1.1.2 (2024-12-31)
- **Agents 表格欄位自訂**：新增「Columns」下拉選單，可顯示/隱藏欄位（設定會儲存在 localStorage）
- **移除 worker 節點的 cluster.key 下載**：只有 master 節點顯示 cluster.key 下載按鈕

### v1.1.1 (2024-12-31)
- **Queue DB 多節點支援**：如果 agent 在多個節點都有 queue DB 檔案，會顯示所有節點的容量
- **Sync Filter 修正**：下拉選單永遠顯示 "synced"、"not synced"、"unknown" 三個選項
- **時間格式統一**：所有時間顯示改用 24 小時制

### v1.1.0 (2024-12-31)
- **Node Download 功能支援 SSH**：遠端節點的 ossec.conf 和 cluster.key 可透過 SSH 下載
- **Node Restart 功能支援 SSH**：可透過 SSH 重啟遠端節點的 Wazuh 服務
- **Sync Filter 增強**：Agent 篩選器的 Sync 下拉選單現在包含 "not synced" 和 "unknown" 選項
- **README 更新**：新增 SSL/HTTPS 設定說明，推薦使用 `--ssl-auto`

### v1.0.99 (2024-12-31)
- Queue DB 功能支援透過 SSH 讀取遠端節點的 queue 資料
- 修正 SSH 已設定時仍顯示 SSH 警告的問題
- `/api/agents/queue-size` 端點回傳 `loaded_nodes` 和 `ssh_failed_nodes` 資訊
- 前端依據 SSH 讀取結果顯示適當的成功/警告訊息

### v1.0.98 (2024-12-31)
- SSH Setup Guide 顯示實際的 config.yaml 完整路徑

### v1.0.97
- 新增 SSH 遠端設定檔讀取/儲存功能
- config.py 新增 SSH 相關屬性 (`ssh_enabled`, `ssh_key_file`, `ssh_nodes`)
- Node Config GET/PUT 端點支援透過 SSH 操作遠端節點
- SSH Setup Guide 更新：
  - 開頭加入「Optional Setup」說明
  - Step 4 後加入「Important」重啟提示

### v1.0.96
- 新增 Settings 按鈕（在 Logout 旁邊）
- 新增 Settings Modal 顯示：
  - API Connection 資訊
  - SSH Configuration 狀態
  - About 區塊（版本、作者、GitHub 連結）
- 新增 `/api/settings` API 端點

### v1.0.95
- 修正 JavaScript 語法錯誤：SSH Setup Guide 中的 `cmd4` 變數 `\n` 跳脫問題

### v1.0.94
- 修正多處 JavaScript 正則表達式跳脫問題：
  - Version 排序的 `\d`
  - SSH config 複製的 `\n`
  - 密碼驗證的 `\d`
  - Log 高亮的 `\d`, `\w`, `\[`, `\]`, `\.`

### v1.0.93
- 修正 JavaScript 正則表達式中的 Python 跳脫序列問題

### v1.0.92
- 修正 SSH Setup Guide 複製到剪貼簿功能（使用 data-copy 屬性）
- Agent 篩選器新增 Sync filter
- Node Name 欄位新增 `white-space: nowrap` 防止換行
- 版本統計排序改用正確的版本號解析

### v1.0.91
- Statistics 頁面新增 Agent 版本統計

### v1.0.90
- 移除無效節點顯示的「(removed)」文字
- SSH Setup Guide 新增複製到剪貼簿按鈕

### v1.0.89
- Agent 表格中不存在的節點以紅色刪除線顯示

### v1.0.88
- 新增 SSH Setup Tutorial 功能
- 遠端節點操作失敗時顯示 SSH 設定說明
- Queue DB 顯示節點警告資訊

### v1.0.87
- 登入頁面的 Wazuh API Host 和 Port 欄位改為唯讀

### v1.0.86
- 簡化 Worker 節點設定處理，直接顯示錯誤訊息

### v1.0.85
- 修正 `get_nodes_status` 個別取得每個節點的服務狀態

### v1.0.84
- 修正 Worker 節點 Edit Config 顯示錯誤設定檔的問題
- 新增本地/遠端節點檢測邏輯

## 免責聲明

本軟體按「現狀」提供，不提供任何明示或暗示的保證。作者不對因使用本軟體而產生的任何損害或損失負責。使用風險自負。

在執行任何操作（尤其是刪除、重啟或升級）之前，強烈建議：
- 使用 `--dry-run` 模式預覽操作
- 備份重要設定檔
- 先在非正式環境測試

## License

MIT License
