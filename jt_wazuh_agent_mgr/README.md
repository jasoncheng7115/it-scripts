# JT Wazuh Agent Manager

[English](README.md) | [繁體中文](README_zh-TW.md)

A powerful web-based management tool for Wazuh agents in cluster environments.

![Version](https://img.shields.io/badge/version-1.3.33-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

## Features

### Agent Management
- View all agents with real-time status
- Advanced filtering (status, group, node, OS, version, IP, name)
- Batch operations: restart, reconnect, delete, add/remove from groups
- Health check and duplicate detection
- Agent upgrade with progress tracking

### Cluster Support
- Full master/worker cluster support
- Node service status monitoring
- Sync status checking between master and workers
- SSH remote management for worker nodes

### Statistics & Reports
- Statistics by status, group, node, OS, version, network segment
- Sortable columns in all statistics tables
- Export to JSON/CSV

### Security
- Input validation for all parameters
- Command injection protection
- Path traversal prevention
- Secure file upload handling

## Screenshots

### Agent List
![Agent List](images/screenshot-agents.png)

### Node Management
![Nodes](images/screenshot-nodes.png)

### Statistics
![Statistics](images/screenshot-stats.png)

## Quick Start

### Requirements
- Python 3.8+
- Wazuh Manager 4.x
- Run on Wazuh Manager server

### Installation

```bash
# Clone to recommended directory
git clone https://github.com/your-repo/jt_wazuh_agent_mgr.git /opt/jt_wazuh_agent_mgr
cd /opt/jt_wazuh_agent_mgr

# Install dependencies
pip install -r requirements.txt
```

### Run Web UI

```bash
# Start with auto-generated SSL certificate (recommended)
./wazuh_agent_mgr.py --web --ssl-auto

# Or specify custom port
./wazuh_agent_mgr.py --web --port 8443 --ssl-auto
```

Then open `https://localhost:5000` in your browser.

### Login

Use your **Wazuh API credentials** (not Dashboard credentials):
- Default API user: `wazuh` or `wazuh-wui`
- API password: Check `/var/ossec/etc/wazuh-passwords.txt`

## CLI Usage

```bash
# List all agents
./wazuh_agent_mgr.py agent list

# Filter agents
./wazuh_agent_mgr.py agent list --status=Active --group=production

# Quick status queries
./wazuh_agent_mgr.py agent disconnected
./wazuh_agent_mgr.py agent pending

# Group management
./wazuh_agent_mgr.py group list
./wazuh_agent_mgr.py group add-agent webservers 001 002 003

# Node management
./wazuh_agent_mgr.py node list
./wazuh_agent_mgr.py node reconnect 001 002

# Statistics
./wazuh_agent_mgr.py stats report
```

### Output Formats

Supports three output formats: `table` (default), `json`, `csv`

```bash
# Table format (default)
./wazuh_agent_mgr.py agent list --format=table

# JSON format (for programmatic processing)
./wazuh_agent_mgr.py agent list --format=json

# CSV format (for spreadsheet import)
./wazuh_agent_mgr.py agent list --format=csv

# Export to file
./wazuh_agent_mgr.py agent list --format=csv > agents.csv
./wazuh_agent_mgr.py stats report --format=json > report.json
```

## Configuration

Create `config.yaml`:

```yaml
wazuh_path: /var/ossec

api:
  enabled: true
  host: localhost
  port: 55000
  username: wazuh
  password: "your-api-password"
  verify_ssl: false

# Optional: SSH for remote worker node management
ssh:
  enabled: true
  key_file: /root/.ssh/wazuh_cluster_key
  nodes:
    worker01:
      host: 192.168.1.100
      port: 22
      user: root
```

## Key Features Explained

### Dry-Run Mode
All write operations support `--dry-run` to preview actions without executing:
```bash
./wazuh_agent_mgr.py agent delete 001 --dry-run
# Output: [DRY-RUN] Would execute: /var/ossec/bin/manage_agents -r 001
```

### Agent Upgrade
- Upload WPK files for agent upgrades
- Track upgrade progress in real-time
- Support batch upgrades

### Cluster Sync Monitoring
- Monitor file synchronization between master and workers
- View sync details: Rules, Decoders, Groups, Keys, Lists, SCA
- Identify files that differ between nodes

## Tech Stack

- **Backend**: Python, Flask
- **Frontend**: Vanilla JavaScript, CSS
- **Wazuh Integration**: CLI commands + REST API

## Changelog

See [README_zh-TW.md](README_zh-TW.md) for full changelog (Chinese).

### Recent Updates (v1.3.x)
- Statistics page with sortable columns
- Security hardening (input validation, injection prevention)
- Upgrade history management
- Sync status loading indicators
- Favicon support
- HAProxy LB integration preparation

## License

MIT License

## Author

Jason Cheng

---

**Note**: This tool is designed to run on the Wazuh Manager server and requires appropriate permissions to execute Wazuh CLI commands.
