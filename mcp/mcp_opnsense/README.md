
```
{
  "mcpServers": {
    "opnsense": {
     "command": "/path/to/venv/bin/python",
      "args": [
        "/path/to/scripts/mcp_opnsense/mcp_opnsense.py"
      ],
      "env": {
        "OPNSENSE_HOST": "https://your-opnsense-host",
        "OPNSENSE_API_KEY": "your-opnsense-api-key",
        "OPNSENSE_API_SECRET": "your-opnsense-api-secret",
        "OPNSENSE_VERIFY_SSL": "false",
        "OPNSENSE_TIMEOUT": "30"
      }
    }
  }
}
```
