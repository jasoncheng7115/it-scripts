

# Proxmox VE MCP 伺服器

本專案提供將 MCP 整合至 Proxmox VE 的設定範例，支援使用帳號密碼或 API 權杖進行認證。


需要安裝 
```
pip install mcp requests httpx pydantic typing-extensions Pillow pycryptodome coloredlogs  websockets websocket-client
```

---

## 🔧 設定說明

MCP 需要一個 JSON 格式的設定檔，用來描述如何執行 Proxmox VE MCP，並透過環境變數傳遞認證資訊。

### 選項一：使用帳號密碼

```json
{
  "mcpServers": {
    "proxmox-ve": {
      "command": "/path/to/venv/bin/python",
      "args": [
        "/path/to/scripts/mcp_pve/mcp_pve.py"
      ],
      "env": {
        "PVE_HOST": "https://your-proxmox-host:8006",
        "PVE_USERNAME": "root@pam",
        "PVE_PASSWORD": "your_password",
        "PVE_VERIFY_SSL": "false"
      }
    }
  }
}
````

> ⚠️ 此方式較為簡單，但不建議用於正式環境，因為明文帳密有安全風險。

---

### 選項二：使用 API 權杖（建議採用此方式）

```json
{
  "mcpServers": {
    "proxmox-ve": {
      "command": "/path/to/venv/bin/python",
      "args": [
        "/path/to/scripts/mcp_pve/mcp_pve.py"
      ],
      "env": {
        "PVE_HOST": "https://your-proxmox-host:8006",
        "PVE_API_TOKEN_ID": "root@pam!mcp-token",
        "PVE_API_TOKEN_SECRET": "your_token_secret",
        "PVE_VERIFY_SSL": "false"
      }
    }
  }
}
```

> ✅ 使用 API 權杖較為安全。

---

## 🔐 Proxmox VE 建議角色設定

為了正確控管存取權限，請依照使用需求指派合適的角色：

| 存取類型      | 建議角色         |
| --------- | ------------ |
| 僅查詢 / 監控用 | `PVEAuditor` |
| 完整管理操作    | `PVEAdmin`   |

> 請確保該帳號或權杖擁具有資料中心、節點或虛擬機的存取權。

---

## 📌 注意事項

* 若您的 Proxmox VE 使用有效 SSL 憑證，請將 `PVE_VERIFY_SSL` 設為 `"true"`。
* 避免在設定檔中直接撰寫敏感資訊，建議使用 `.env` 或其他密碼管理工具。
* 確保您的 Python 虛擬環境已安裝所有相依套件。

---

## ⚠️ 免責聲明

本軟體採「現狀提供（as-is）」方式提供，**不提供任何形式的保證**。
使用本專案所造成的任何損害、資料遺失或系統問題，作者及貢獻者均不負任何責任，請使用者自行承擔風險。

---

## 📄 授權條款

本專案採用 MIT 授權條款發佈。

