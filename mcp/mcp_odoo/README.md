```
{
  "mcpServers": {
    "odoo": {
      "command": "/path/to/venv/bin/python",
      "args": ["/path/to/scripts/mcp_odoo/mcp_odoo.py"],
      "env": {
        "ODOO_URL": "http://your-odoo-host:8069",
        "ODOO_DATABASE": "your_odoo_db",
        "ODOO_USERNAME": "your_username",
        "ODOO_PASSWORD": "your_password",
        "ODOO_DEFAULT_LANGUAGE": "zh_TW",
        "ODOO_CACHE_TTL": "300",
        "ODOO_TIMEOUT": "30",
        "ODOO_MAX_RETRIES": "3"
      }
    }
  }
}
```
