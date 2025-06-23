# Proxmox VE MCP Server

This repository contains configuration examples for integrating MCP with Proxmox VE using either username/password authentication or API token-based access.

[繁體中文版](https://github.com/jasoncheng7115/it-scripts/blob/master/mcp/mcp_pve/README_zh-TW.md)


---

Requirements:
```
pip install mcp requests httpx pydantic typing-extensions Pillow pycryptodome coloredlogs  websockets websocket-client
```

---

## 🔧 Configuration

MCP requires a JSON configuration file describing how to invoke the Proxmox VE plugin and provide environment variables for authentication.

### Option 1: Username and Password

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

> ⚠️ This method is simple but not recommended for production due to credential sensitivity.

---

### Option 2: API Token (Recommended)

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

> ✅ Using an API token is safer and supports fine-grained access control.

---

## 🔐 Proxmox VE Role Recommendations

To ensure proper access control, assign appropriate roles to the API token or user:

| Access Type      | Suggested Role |
| ---------------- | -------------- |
| Read-only access | `PVEAuditor`   |
| Full access      | `PVEAdmin`     |

> Make sure the token or user has access to the relevant datacenter, nodes, or VMs.

---

## 📌 Notes

* Set `PVE_VERIFY_SSL` to `"true"` if your Proxmox VE uses a valid SSL certificate.
* Avoid hardcoding sensitive values in configuration files; consider using `.env` or secrets management tools.
* Ensure your Python virtual environment contains all required dependencies.


---

## ⚠️ Disclaimer

This software is provided **as-is** and **without any warranty**.
Use it at your own risk. The authors and contributors shall not be held liable for any damage, loss, or issues arising from the use of this project, whether directly or indirectly.

---

## 📄 License

This project is licensed under the MIT License.

