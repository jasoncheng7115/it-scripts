#!/bin/bash
# MCP HTTP Proxy Starter
# Double-click to start, or add to Login Items for auto-start

cd "$(dirname "$0")"

# Kill existing proxy
pkill -f "mcp_proxy.py" 2>/dev/null
sleep 1

echo "Starting MCP HTTP Proxy..."
python3 -u mcp_proxy.py
