# MCP HTTP Proxy - 解決 Claude Desktop 網路限制

## 問題描述

在 macOS 上，當安裝了某些安全軟體（如 Avast、Norton 等）時，Claude Desktop 啟動的 MCP 子程序可能無法連線到內網服務，出現 `No route to host`（errno=65 `EHOSTUNREACH`）或 `Connection failed` 錯誤。

用終端機手動執行同一支 MCP 程式卻完全正常：

| 執行方式 | 能否連線內網 |
|---------|-------------|
| 終端機手動執行 Python | 可以 |
| Claude Desktop 子程序 | 被阻擋 |
| launchd 背景服務 | 被阻擋 |

### 根因分析

安全軟體（如 Avast）會安裝 macOS **Network Extension**，對不同來源的程序套用不同的網路過濾策略：

- **互動式程序**（從終端機啟動）：允許內網連線
- **非互動式程序**（Claude Desktop 子程序、launchd 服務）：阻擋內網連線

即使在安全軟體中關閉「檔案防護」和「網頁守衛」，Network Extension 仍然在系統層級運行。

可用以下命令確認是否有 Network Extension：

```bash
systemextensionsctl list
# 若看到 network_extension 類型的項目（如 Avast、Norton），即為此問題的原因
```

## 解決方案

使用 HTTP Proxy 作為中介，所有 MCP 服務透過一個本地代理連線到目標服務。

```
MCP Server → localhost:28080 (Proxy) → 內網服務
```

---

## 快速設置

### 1. 檔案位置

```
/path/to/mcp_proxy/
├── mcp_proxy.py          # 代理程式
├── start_proxy.command   # macOS 啟動腳本（雙擊執行）
└── README.md             # 本文件
```

### 2. 啟動代理

**macOS**：雙擊 `start_proxy.command`

**Linux/手動**：
```bash
cd /path/to/mcp_proxy
python3 -u mcp_proxy.py &
```

### 3. 設定 Claude Desktop

編輯 `~/Library/Application Support/Claude/claude_desktop_config.json`，為每個 MCP 服務的 `env` 添加：

```json
{
  "mcpServers": {
    "your-mcp-server": {
      "command": "...",
      "args": ["..."],
      "env": {
        "HTTP_PROXY": "http://127.0.0.1:28080",
        "HTTPS_PROXY": "http://127.0.0.1:28080",
        "...其他原有設定..."
      }
    }
  }
}
```

### 4. 重啟 Claude Desktop

設定完成後，重新啟動 Claude Desktop。

---

## 開機自動啟動

### macOS

1. 打開 **系統設定** → **一般** → **登入項目**
2. 點擊 **+** 添加 `start_proxy.command`

### Linux (systemd)

建立 `/etc/systemd/user/mcp-proxy.service`：

```ini
[Unit]
Description=MCP HTTP Proxy

[Service]
ExecStart=/usr/bin/python3 -u /path/to/mcp_proxy/mcp_proxy.py
Restart=always

[Install]
WantedBy=default.target
```

啟用：
```bash
systemctl --user enable mcp-proxy
systemctl --user start mcp-proxy
```

---

## 管理命令

```bash
# 查看代理狀態
lsof -i :28080

# 停止代理
pkill -f mcp_proxy.py

# 手動啟動（前台）
python3 -u /path/to/mcp_proxy/mcp_proxy.py

# 手動啟動（背景）
nohup python3 -u /path/to/mcp_proxy/mcp_proxy.py > /tmp/mcp_proxy.log 2>&1 &

# 查看日誌
tail -f /tmp/mcp_proxy.log
```

---

## 測試

```bash
# 測試代理是否運行
curl -x http://127.0.0.1:28080 -k https://your-internal-host:port/

# 預期結果：能連線到目標服務（可能返回 401 等認證錯誤，但不是連線錯誤）
```

---

## 故障排除

### 代理無法啟動
```
Error: Port already in use
```
解決：`pkill -f mcp_proxy.py` 然後重新啟動

### MCP 仍然無法連線
1. 確認代理正在運行：`lsof -i :28080`
2. 確認 Claude Desktop 配置正確
3. 重啟 Claude Desktop

### 代理日誌顯示連線錯誤
```
[ERROR] host:port - [Errno 65] No route to host
```
這表示代理本身也被阻擋，確認代理是從**終端機手動啟動**而非 launchd 服務。

---

## 工作原理

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Claude Desktop │     │   MCP Proxy     │     │  內網服務        │
│                 │     │  (Terminal)     │     │                 │
│  MCP Server ────┼────►│  127.0.0.1:28080├────►│  192.168.x.x    │
│  (受限程序)      │     │  (不受限)        │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

1. MCP Server 設定 `HTTP_PROXY`/`HTTPS_PROXY` 環境變數
2. MCP Server 透過 HTTP CONNECT 方法連線到本地代理
3. 代理（終端機啟動）連線到實際目標服務
4. 代理轉發雙向流量

---

## 注意事項

- 代理必須從**終端機手動啟動**，不能用 launchd
- 代理需要保持運行，關閉終端機窗口會停止代理
- 建議使用 `start_proxy.command` 並加入登入項目

---

**作者**: Jason Cheng (jason@jason.tools)
**最後更新**: 2026-02-09
