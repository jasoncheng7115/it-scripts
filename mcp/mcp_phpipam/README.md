```
{
  "mcpServers": {
    "phpipam": {
        "command": "/path/to/venv/bin/python",
        "args": ["/path/to/scripts/mcp_phpipam/mcp_phpipam.py"],
        "env": {
            "PHPIPAM_URL": "https://your-phpipam-host",
            "PHPIPAM_TOKEN": "your_token",
            "PHPIPAM_APP_ID": "your_app_id",
            "PHPIPAM_CACHE_TTL": "300",
            "PHPIPAM_TIMEOUT": "30",
            "PHPIPAM_VERIFY_SSL": "false"
        }
    }
  }
}
```
