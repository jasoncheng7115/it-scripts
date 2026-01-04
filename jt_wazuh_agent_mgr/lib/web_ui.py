#!/usr/bin/env python3
"""Web UI for JT Wazuh Agent Manager with login support.

Icons from Iconoir (https://iconoir.com/)
MIT License - Copyright 2021 Luca Burgio
https://github.com/iconoir-icons/iconoir/blob/main/LICENSE
"""

from . import __version__ as VERSION

import json
import os
import glob
import secrets
import logging
from datetime import datetime
from typing import Optional
from functools import wraps

# Setup logging
def setup_logging(log_file: str = None):
    """Setup logging to file and console."""
    if log_file is None:
        log_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        log_file = os.path.join(log_dir, 'wazuh_agent_mgr.log')

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # File handler
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)

    # Get logger
    logger = logging.getLogger('wazuh_mgr')
    logger.setLevel(logging.INFO)
    logger.addHandler(file_handler)

    return logger

# Initialize logger
logger = setup_logging()

try:
    from flask import Flask, render_template_string, jsonify, request, session, redirect, url_for
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

try:
    import requests as http_requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from .wazuh_cli import WazuhCLI
from .agent_ops import AgentOperations
from .group_ops import GroupOperations
from .node_ops import NodeOperations
from .stats import StatisticsOperations
from .config import get_config

import re
import shlex

# ============ Security Utilities ============

# Allowed base paths for file operations (whitelist)
ALLOWED_PATHS = [
    '/var/ossec/etc/',
    '/var/ossec/ruleset/',
    '/var/ossec/logs/',
    '/var/ossec/queue/',
]

# Valid patterns for various inputs
VALID_NODE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\.]+$')
VALID_AGENT_ID_PATTERN = re.compile(r'^[0-9]{1,6}$')
VALID_GROUP_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\.]+$')
VALID_PATH_COMPONENT_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\.\/]+$')
VALID_USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\.]+$')


def validate_node_name(name: str) -> bool:
    """Validate node name to prevent injection attacks."""
    if not name or len(name) > 128:
        return False
    return bool(VALID_NODE_NAME_PATTERN.match(name))


def validate_agent_id(agent_id: str) -> bool:
    """Validate agent ID format."""
    if not agent_id:
        return False
    return bool(VALID_AGENT_ID_PATTERN.match(str(agent_id)))


def validate_group_name(name: str) -> bool:
    """Validate group name to prevent injection attacks."""
    if not name or len(name) > 128:
        return False
    return bool(VALID_GROUP_NAME_PATTERN.match(name))


def validate_username(name: str) -> bool:
    """Validate username to prevent injection attacks."""
    if not name or len(name) > 64:
        return False
    return bool(VALID_USERNAME_PATTERN.match(name))


def validate_path(path: str) -> bool:
    """Validate that path is within allowed directories and has no injection."""
    if not path:
        return False

    # Normalize path to prevent directory traversal
    try:
        normalized = os.path.normpath(path)
    except Exception:
        return False

    # Check for directory traversal attempts
    if '..' in path or '\x00' in path:
        return False

    # Check for shell metacharacters
    dangerous_chars = ['$', '`', '|', ';', '&', '>', '<', '\n', '\r', '(', ')', '{', '}', '[', ']', '!', '#']
    if any(c in path for c in dangerous_chars):
        return False

    # Validate path pattern
    if not VALID_PATH_COMPONENT_PATTERN.match(path):
        return False

    # Check if path is within allowed directories
    for allowed in ALLOWED_PATHS:
        if normalized.startswith(allowed) or normalized.rstrip('/') + '/' == allowed:
            return True

    return False


def safe_shell_arg(arg: str) -> str:
    """Safely escape argument for shell command."""
    return shlex.quote(arg)


def sanitize_for_log(value: str, max_length: int = 200) -> str:
    """Sanitize value for logging to prevent log injection."""
    if not value:
        return ''
    # Remove control characters and limit length
    sanitized = ''.join(c for c in str(value) if c.isprintable())
    return sanitized[:max_length]


# Login page template
LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JT Wazuh Agent Manager - Login</title>
    <link rel="icon" type="image/png" href="/images/logo-1.png">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .login-container {
            background: #16213e;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            width: 100%;
            max-width: 440px;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 {
            color: #4fc3f7;
            font-size: 28px;
            margin-bottom: 5px;
            white-space: nowrap;
        }
        .logo p {
            color: #888;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            color: #aaa;
            margin-bottom: 8px;
            font-size: 14px;
        }
        .form-group input {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #0f3460;
            background: #1a1a2e;
            color: #eee;
            border-radius: 6px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        .form-group input:focus {
            outline: none;
            border-color: #4fc3f7;
        }
        .form-group input:disabled {
            background: #0d0d1a;
            color: #666;
            cursor: not-allowed;
            border-color: #0a0a1a;
        }
        .btn-login {
            width: 100%;
            padding: 14px;
            background: #4fc3f7;
            color: #1a1a2e;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.3s;
        }
        .btn-login:hover {
            background: #81d4fa;
        }
        .btn-login:disabled {
            background: #555;
            cursor: not-allowed;
        }
        .error-message {
            background: #e9456033;
            border: 1px solid #e94560;
            color: #ff6b6b;
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 14px;
        }
        .info-text {
            color: #666;
            font-size: 12px;
            text-align: center;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>JT Wazuh Agent Manager</h1>
            <div style="font-size: 14px; color: #888; margin-top: 5px;">v{{ version }}</div>
            <p style="margin-top: 15px;">Login with your Wazuh credentials</p>
        </div>

        {% if error %}
        <div class="error-message">{{ error }}</div>
        {% endif %}

        <form method="POST" action="/login">
            <input type="hidden" name="host" value="{{ host or 'localhost' }}">
            <input type="hidden" name="port" value="{{ port or '55000' }}">
            <div class="form-group">
                <label for="username">Wazuh API Username</label>
                <input type="text" id="username" name="username" value="{{ username or '' }}" required autocomplete="username" placeholder="Username">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required autocomplete="current-password">
                <p style="margin-top: 8px; font-size: 12px; color: #ffc107;">Session expires after {{ token_timeout_minutes }} minutes</p>
            </div>
            <button type="submit" class="btn-login">Login</button>
        </form>
        <p class="info-text">
            API: {{ host or 'localhost' }}:{{ port or '55000' }}
            <a href="#" onclick="toggleAdvanced(); return false;" style="color:#4fc3f7;margin-left:10px;font-size:11px;">Settings</a>
        </p>
        <div id="advancedSettings" style="display:none;margin-top:15px;padding:15px;background:#1a1a2e;border-radius:6px;">
            <div class="form-group" style="margin-bottom:10px;">
                <label for="hostInput" style="font-size:12px;">API Host</label>
                <input type="text" id="hostInput" value="{{ host or 'localhost' }}" style="font-size:14px;" onchange="document.querySelector('input[name=host]').value=this.value">
            </div>
            <div class="form-group" style="margin-bottom:0;">
                <label for="portInput" style="font-size:12px;">API Port</label>
                <input type="number" id="portInput" value="{{ port or '55000' }}" style="font-size:14px;" onchange="document.querySelector('input[name=port]').value=this.value">
            </div>
        </div>
        <script>
            function toggleAdvanced() {
                var el = document.getElementById('advancedSettings');
                el.style.display = el.style.display === 'none' ? 'block' : 'none';
            }
        </script>
    </div>
</body>
</html>
'''


# Main application template
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JT Wazuh Agent Manager</title>
    <link rel="icon" type="image/png" href="/images/logo-1.png">
    <!-- CodeMirror for config editor -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/codemirror.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/theme/dracula.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/codemirror.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/mode/xml/xml.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/mode/javascript/javascript.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/addon/mode/simple.min.js"></script>
    <script>
    // Custom Wazuh alerts.log mode
    document.addEventListener('DOMContentLoaded', function() {
        if (typeof CodeMirror !== 'undefined' && CodeMirror.defineSimpleMode) {
            CodeMirror.defineSimpleMode('wazuh-alerts', {
                start: [
                    {regex: /^\*\* Alert \d+\.\d+:/, token: 'keyword'},
                    {regex: /^Rule: \d+ \(level \d+\)/, token: 'def'},
                    {regex: /-> '[^']*'/, token: 'string'},
                    {regex: /- [a-zA-Z0-9_,]+,$/, token: 'tag'},
                    {regex: /^\d{4} [A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2}/, token: 'number'},
                    {regex: /[a-zA-Z0-9_-]+->(?:journald|\/var\/log\/[^\s]+)/, token: 'variable-2'},
                    {regex: /(?:Src IP|Src Port|User|uid|Dst IP|Dst Port|Protocol|Action):/, token: 'attribute'},
                    {regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/, token: 'number'},
                    {regex: /\b\d+\b/, token: 'number'}
                ]
            });
        }
    });
    </script>
    <style>
        /* CodeMirror custom styles */
        .CodeMirror { font-size: 14px; line-height: 1.6; }
        .CodeMirror-lines { padding: 10px 0; }
        .CodeMirror-gutters { background: #1a1a2e; border-right: 2px solid #4fc3f7; }
        .CodeMirror-linenumber { color: #666; padding: 0 8px 0 8px; min-width: 40px; text-align: right; }
        .json-gutter { width: 28px; display: flex; align-items: center; justify-content: center; }
        .json-expand-marker { cursor: pointer; display: flex; align-items: center; justify-content: center; width: 100%; height: 21px; }
        .json-expand-marker svg { width: 12px; height: 12px; color: #4fc3f7; transition: color 0.2s; }
        .json-expand-marker:hover svg { color: #fff; }
        .json-expand-marker.expanded svg { color: #4ade80; }
        .json-expanded-widget { background: #0d1117; border-left: 3px solid #4fc3f7; margin: 4px 0 4px 20px; padding: 8px 12px; font-family: monospace; font-size: 13px; white-space: pre; overflow-x: auto; max-height: 300px; overflow-y: auto; color: #e6edf3; }
        .json-expanded-widget .json-key { color: #ff79c6; }
        .json-expanded-widget .json-string { color: #50fa7b; }
        .json-expanded-widget .json-number { color: #bd93f9; }
        .json-expanded-widget .json-boolean { color: #ffb86c; }
        .json-expanded-widget .json-null { color: #ff5555; }
        .json-expanded-widget .json-bracket { color: #f8f8f2; }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        html { height: 100%; overflow: hidden; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; color: #eee; display: flex; flex-direction: column; height: 100%; overflow: hidden; }
        .container { margin: 0 auto; padding: 20px 20px 10px 20px; flex: 1; display: flex; flex-direction: column; width: 100%; overflow: hidden; min-height: 0; }
        header { background: #16213e; padding: 20px; margin-bottom: 20px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; }
        header h1 { color: #4fc3f7; }
        .header-right { display: flex; align-items: center; gap: 20px; }
        .user-info { color: #aaa; font-size: 13px; text-align: center; }
        .user-info > div { margin-bottom: 6px; }
        .user-info > div:last-child { margin-bottom: 0; }
        .user-info strong { color: #4fc3f7; }
        .header-buttons { display: flex; flex-direction: column; gap: 8px; }
        .btn-settings { padding: 6px 12px; background: #0f3460; color: #4fc3f7; border: 1px solid #4fc3f7; border-radius: 4px; cursor: pointer; font-size: 12px; display: inline-flex; align-items: center; gap: 4px; }
        .btn-settings:hover { background: #1a4a7a; }
        .btn-settings .icon { width: 14px; height: 14px; }
        .btn-logout { padding: 6px 12px; background: #e94560; color: #fff; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; font-size: 12px; display: inline-flex; align-items: center; gap: 4px; }
        .btn-logout:hover { background: #ff6b6b; }
        .btn-logout .icon { width: 14px; height: 14px; }
        .stats-bar { display: flex; gap: 20px; }
        .stat-item { background: #0f3460; padding: 10px 20px; border-radius: 6px; text-align: center; cursor: pointer; transition: transform 0.2s, box-shadow 0.2s; }
        .stat-item:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
        .stat-value { font-size: 24px; font-weight: bold; color: #4fc3f7; overflow: hidden; position: relative; height: 32px; line-height: 32px; }
        .stat-value span { display: block; }
        .stat-value span.slide-in { animation: slideIn 0.3s ease-out; }
        @keyframes slideIn { from { transform: translateY(-100%); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
        .stat-label { font-size: 12px; color: #aaa; }
        .stat-item.disconnected .stat-value { color: #e94560; }
        .stat-item.pending .stat-value { color: #ffc107; }
        .stat-item.active .stat-value { color: #00c853; }

        .tabs { display: flex; gap: 2px; margin-bottom: 0; }
        .tab { padding: 10px 20px; background: #0a0a15; border: none; color: #888; cursor: pointer; border-radius: 6px 6px 0 0; display: inline-flex; align-items: center; gap: 8px; position: relative; bottom: -1px; border: 1px solid transparent; border-bottom: none; }
        .tab.active { background: #16213e; color: #4fc3f7; border-color: #0f3460; z-index: 1; }
        .tab:hover:not(.active) { color: #aaa; background: #0f0f1a; }

        .panel { background: #16213e; border-radius: 0 8px 8px 8px; padding: 20px 20px 10px 20px; display: none; flex-direction: column; flex: 1; overflow: hidden; border: 1px solid #0f3460; min-height: 0; }
        .panel.active { display: flex; }

        .toolbar { display: flex; gap: 10px; margin-bottom: 10px; flex-wrap: wrap; align-items: center; flex-shrink: 0; }
        .toolbar-row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
        .toolbar-spacer { flex: 1; min-width: 10px; }
        .action-bar-container { position: relative; min-height: 52px; margin-bottom: 10px; }
        .action-bar { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; flex-shrink: 0; padding: 10px 15px; background: #0f3460; border-radius: 6px; min-height: 44px; position: absolute; top: 0; left: 0; right: 0; z-index: 10; opacity: 0; pointer-events: none; transition: opacity 0.2s; }
        .action-bar.visible { opacity: 1; pointer-events: auto; }
        .distribution-bar { display: flex; gap: 12px; align-items: center; padding: 10px 15px; background: #0f3460; border-radius: 6px; min-height: 44px; }
        .distribution-bar select { padding: 4px 8px; border: 1px solid #0f3460; background: #1a1a2e; color: #eee; border-radius: 4px; font-size: 12px; cursor: pointer; }
        .distribution-chart { flex: 1; height: 24px; background: #1a1a2e; border-radius: 4px; overflow: hidden; display: flex; gap: 2px; padding: 0 1px; }
        .distribution-chart.animating .distribution-segment { animation: segmentExpand 0.4s ease-out; }
        @keyframes segmentExpand { from { transform: scaleX(0); } to { transform: scaleX(1); } }
        .distribution-segment { transform-origin: left center; }
        .distribution-segment { height: 100%; display: flex; align-items: center; justify-content: center; font-size: 10px; color: #fff; overflow: hidden; min-width: 0; transition: width 0.3s; cursor: pointer; border-radius: 2px; }
        .distribution-segment:hover { filter: brightness(1.2); }
        .distribution-segment span { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; text-shadow: 0 0 2px rgba(0,0,0,0.5); padding: 0 6px; }
        .toolbar select { padding: 8px 12px; border: 1px solid #0f3460; background: #1a1a2e; color: #eee; border-radius: 4px; }
        .toolbar > input[type="text"], .toolbar-filters > input[type="text"] { padding: 8px 12px; border: 1px solid #0f3460; background: #1a1a2e; color: #eee; border-radius: 4px; min-width: 180px; flex-shrink: 1; }
        .btn { padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-weight: 500; display: inline-flex; align-items: center; gap: 6px; }
        .btn-primary { background: #4fc3f7; color: #1a1a2e; }
        .btn-danger { background: #e94560; color: #fff; }
        .btn-success { background: #00c853; color: #fff; }
        .btn-warning { background: #ffc107; color: #1a1a2e; }
        .btn:hover { opacity: 0.9; }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .btn-sm { padding: 4px 8px; font-size: 12px; gap: 4px; }
        .btn-icon { padding: 4px 6px; font-size: 14px; line-height: 1; }
        .btn-wrap { display: flex; flex-wrap: wrap; gap: 5px; }
        #nodesTable .btn-wrap .btn { width: 100px; justify-content: center; box-sizing: border-box; }
        #groupsTable .btn-wrap .btn { width: 110px; justify-content: center; box-sizing: border-box; }
        /* Icons - Iconoir MIT License */
        .icon { width: 16px; height: 16px; flex-shrink: 0; }
        .btn-sm .icon { width: 14px; height: 14px; }
        .tab .icon { width: 18px; height: 18px; }

        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #0f3460; vertical-align: middle; }
        tbody tr { height: 50px; }
        th { background: #0f3460; color: #4fc3f7; position: sticky; top: 0; }
        th.sortable { cursor: pointer; user-select: none; white-space: nowrap; }
        th.sortable:hover { background: #1a3a70; }
        th.sortable .sort-icon { width: 12px; height: 12px; margin-left: 4px; opacity: 0.3; vertical-align: middle; }
        th.sortable .sort-asc, th.sortable .sort-desc { display: none; }
        th.sortable.asc .sort-asc { display: inline; opacity: 1; }
        th.sortable.asc .sort-desc { display: none; }
        th.sortable.desc .sort-desc { display: inline; opacity: 1; }
        th.sortable.desc .sort-asc { display: none; }
        th.sortable:not(.asc):not(.desc) .sort-asc { display: inline; }
        tr:hover { background: #1a1a2e; }
        .modal-body table tr td { padding-left: 8px; padding-right: 8px; border-radius: 4px; }

        .checkbox-cell { width: 40px; }
        input[type="checkbox"] { width: 18px; height: 18px; cursor: pointer; }

        .status { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500; }
        .status-active { background: #00c853; color: #fff; }
        .status-disconnected { background: #e94560; color: #fff; }
        .status-pending { background: #ffc107; color: #1a1a2e; }
        .status-never { background: #666; color: #fff; }

        .sync-status { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500; white-space: nowrap; }
        .sync-ok { background: #00c85333; color: #00c853; }
        .sync-pending { background: #ffc10733; color: #ffc107; }
        .sync-unknown { background: #66666633; color: #888; }

        .group-label { display: inline-block; padding: 1px 4px; margin: 1px 2px; border-radius: 3px; font-size: 11px; background: #0f3460; color: #4fc3f7; }

        .queue-entry { display: flex; gap: 6px; align-items: center; white-space: nowrap; }
        .queue-size { font-weight: 500; min-width: 60px; text-align: right; }
        .queue-node { color: #888; font-size: 11px; }

        .table-container { flex: 1; overflow-y: auto; min-height: 0; }
        .log-container { flex: 1; overflow: hidden; min-height: 0; display: flex; flex-direction: column; }
        .log-container pre { flex: 1; overflow: auto; min-height: 0; margin: 0; }
        .rules-content { flex: 1; overflow: auto; min-height: 0; }
        .stats-content { flex: 1; overflow: auto; min-height: 0; }
        #nodesTable td:first-child { white-space: nowrap; }

        /* Rules Tree Styles */
        .rule-tree { font-family: monospace; }
        .rule-tree ul { list-style: none; padding-left: 20px; margin: 0; }
        .rule-tree > ul { padding-left: 0; }
        .rule-tree li { position: relative; padding: 5px 0; }
        .rule-tree li::before { content: ''; position: absolute; left: -15px; top: 0; border-left: 1px solid #444; height: 100%; }
        .rule-tree li::after { content: ''; position: absolute; left: -15px; top: 15px; border-top: 1px solid #444; width: 15px; }
        .rule-tree li:last-child::before { height: 15px; }
        .rule-tree > ul > li::before, .rule-tree > ul > li::after { display: none; }
        .rule-node { display: inline-flex; align-items: center; gap: 8px; padding: 8px 12px; background: #1a1a2e; border: 1px solid #333; border-radius: 4px; cursor: pointer; transition: all 0.2s; }
        .rule-node:hover { background: #252545; border-color: #4fc3f7; }
        .rule-node.highlight { background: #2d4a3e; border-color: #4ade80; box-shadow: 0 0 10px rgba(74, 222, 128, 0.3); }
        .rule-node.parent { border-color: #ffc107; }
        .rule-node.child { border-color: #17a2b8; }
        .rule-id { font-weight: bold; color: #4fc3f7; }
        .rule-level { font-size: 11px; padding: 2px 6px; border-radius: 3px; background: #333; }
        .rule-level.high { background: #dc3545; }
        .rule-level.medium { background: #ffc107; color: #000; }
        .rule-level.low { background: #28a745; }
        .rule-level.zero { background: #6c757d; color: #ccc; font-style: italic; }
        .rule-desc { color: #aaa; font-size: 12px; max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .rule-file { color: #888; font-size: 11px; }
        .rule-file.custom { color: #f39c12; }
        .rule-custom-badge { font-size: 10px; padding: 1px 5px; border-radius: 3px; background: #f39c12; color: #000; font-weight: bold; margin-left: 5px; }
        .rule-if-group-badge { font-size: 10px; padding: 1px 5px; border-radius: 3px; background: #9b59b6; color: #fff; font-weight: bold; margin-left: 5px; }
        .rule-node.group { background: #2d3e50; border-color: #5dade2; cursor: default; }
        .rule-node.group .rule-id { color: #5dade2; font-weight: bold; }
        .rule-node.more { background: transparent; border: none; color: #888; cursor: default; font-style: italic; }
        .rule-expand { color: #888; cursor: pointer; margin-left: -5px; padding: 4px; border-radius: 4px; background: rgba(255,255,255,0.05); transition: all 0.2s; }
        .rule-expand:hover { color: #4fc3f7; background: rgba(79,195,247,0.2); }
        .rule-content { margin-top: 0; padding: 0; background: #0a0a15; border-radius: 4px; font-size: 12px; line-height: 1.6; overflow: hidden; max-height: 0; opacity: 0; transition: max-height 0.3s ease, opacity 0.3s ease, padding 0.3s ease, margin 0.3s ease; position: relative; }
        .rule-content.show { max-height: 2000px; opacity: 1; padding: 15px; padding-right: 50px; overflow-x: auto; margin-top: 10px; }
        .rule-content code { color: #e0e0e0; white-space: pre; display: block; tab-size: 2; }
        .rule-copy-btn { position: absolute; top: 8px; right: 8px; background: #333; border: 1px solid #444; color: #aaa; padding: 4px 8px; border-radius: 4px; cursor: pointer; font-size: 11px; transition: all 0.2s; }
        .rule-copy-btn:hover { background: #444; color: #fff; border-color: #4fc3f7; }
        .rule-copy-btn.copied { background: #28a745; color: #fff; border-color: #28a745; }
        .rule-content .xml-tag { color: #4fc3f7; }
        .rule-content .xml-attr { color: #f39c12; }
        .rule-content .xml-value { color: #4ade80; }
        .rule-content .xml-comment { color: #6c757d; font-style: italic; }
        .rule-content .xml-text { color: #e0e0e0; }
        .rule-tree li > ul { max-height: 5000px; overflow: hidden; transition: max-height 0.3s ease-out, opacity 0.3s ease-out; opacity: 1; }
        .collapsed > ul { max-height: 0 !important; opacity: 0; transition: max-height 0.2s ease-in, opacity 0.2s ease-in; }
        .rule-expand svg { transition: transform 0.2s ease; }
        .collapsed .rule-expand svg { transform: rotate(-90deg); }

        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 1000; }
        .modal.show { display: flex; justify-content: center; align-items: center; }
        .modal-content { background: #16213e; padding: 30px; border-radius: 8px; min-width: 500px; max-width: 800px; max-height: 90vh; overflow-y: auto; }
        .modal-content.resizable { resize: both; overflow: auto; min-width: 600px; min-height: 400px; max-width: 95vw; max-height: 90vh; cursor: default; position: relative; }
        .modal-content.resizable::after { content: ''; position: absolute; bottom: 5px; right: 5px; width: 15px; height: 15px; cursor: se-resize; background: linear-gradient(135deg, transparent 50%, #4fc3f7 50%, #4fc3f7 60%, transparent 60%, transparent 70%, #4fc3f7 70%, #4fc3f7 80%, transparent 80%); pointer-events: none; z-index: 10; }
        .modal-content.wide { max-width: 95vw; width: 1000px; }
        .modal-header { display: flex; justify-content: space-between; margin-bottom: 20px; }
        .modal-close { background: none; border: none; color: #aaa; font-size: 24px; cursor: pointer; }
        .modal-body { margin-bottom: 20px; }
        .modal-content.resizable .modal-body { flex: 1; overflow: auto; display: flex; flex-direction: column; min-height: 0; margin-bottom: 10px; }
        .modal-content.resizable { display: flex; flex-direction: column; }
        .modal-footer { display: flex; gap: 10px; justify-content: flex-end; }

        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; color: #aaa; }
        .form-group input, .form-group select { width: 100%; padding: 10px; border: 1px solid #0f3460; background: #1a1a2e; color: #eee; border-radius: 4px; }

        .alert { padding: 15px; border-radius: 4px; margin-bottom: 15px; }
        .alert-success { background: #00c85333; border: 1px solid #00c853; }
        .alert-error { background: #e9456033; border: 1px solid #e94560; }
        .alert-warning { background: #ffc10733; border: 1px solid #ffc107; }

        .loading { text-align: center; padding: 40px; color: #aaa; }
        .spinner { border: 3px solid #0f3460; border-top: 3px solid #4fc3f7; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto 10px; }
        .icon-spin { animation: spin 1s linear infinite; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .connection-error { text-align: center; padding: 60px 40px; color: #aaa; }
        .connection-error .error-icon { font-size: 48px; margin-bottom: 15px; color: #e94560; }
        .connection-error .error-title { font-size: 18px; color: #e94560; margin-bottom: 10px; font-weight: bold; }
        .connection-error .error-message { font-size: 14px; color: #888; margin-bottom: 20px; }
        .connection-error .retry-btn { padding: 10px 24px; background: #4fc3f7; color: #0a0a1a; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: bold; }
        .connection-error .retry-btn:hover { background: #81d4fa; }
        .api-status.disconnected { background: #e94560; color: #fff; }

        .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; background: #0f3460; }
        .badge-master { background: #9c27b0; color: #fff; }
        .badge-worker { background: #0288d1; color: #fff; }

        /* Service status indicators */
        .service-status { display: flex; flex-wrap: wrap; gap: 4px; max-width: 500px; }
        .service-indicator { display: inline-flex; align-items: center; gap: 4px; padding: 2px 6px; border-radius: 4px; font-size: 11px; background: #0f3460; width: 90px; }
        .service-indicator .dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
        .service-indicator .dot.running { background: #00c853; box-shadow: 0 0 4px #00c853; }
        .service-indicator .dot.stopped { background: #e94560; box-shadow: 0 0 4px #e94560; }
        .service-indicator .dot.pending { background: #ffc107; box-shadow: 0 0 4px #ffc107; }
        .service-indicator .dot.unknown { background: #888; }
        .service-indicator .dot.source { background: #4fc3f7; box-shadow: 0 0 4px #4fc3f7; }
        .service-indicator.sync-item { cursor: pointer; width: 80px; }
        .service-indicator.sync-source { width: 80px; opacity: 0.85; }

        .dry-run-notice { background: #ffc10722; border: 1px dashed #ffc107; padding: 10px; border-radius: 4px; margin-bottom: 15px; }

        .selected-count { background: #4fc3f733; padding: 6px 14px; border-radius: 4px; color: #4fc3f7; font-weight: 500; }

        .api-status { font-size: 12px; padding: 4px 8px; border-radius: 4px; }
        .api-status.connected { background: #00c85333; color: #00c853; }
        .api-status.disconnected { background: #e9456033; color: #e94560; }

        .pagination-bar { display: flex; justify-content: space-between; align-items: center; padding: 8px 0 0 0; border-top: 1px solid #0f3460; margin-top: 10px; flex-shrink: 0; }
        .pagination-info { color: #aaa; font-size: 14px; }
        .pagination-controls { display: flex; align-items: center; gap: 10px; }
        .pagination-controls label { color: #aaa; font-size: 14px; display: flex; align-items: center; gap: 8px; }
        .pagination-controls select { padding: 6px 10px; border: 1px solid #0f3460; background: #1a1a2e; color: #eee; border-radius: 4px; }
        .pagination-controls .btn { padding: 6px 12px; min-width: auto; }
        .pagination-controls .btn:disabled { opacity: 0.4; cursor: not-allowed; }
        .page-indicator { color: #aaa; font-size: 14px; display: flex; align-items: center; gap: 5px; }
        .page-indicator input { width: 60px; padding: 6px; border: 1px solid #0f3460; background: #1a1a2e; color: #eee; border-radius: 4px; text-align: center; }

        #stats-panel table { table-layout: fixed; margin-bottom: 10px; }
        #stats-panel h3 { color: #4fc3f7; margin-bottom: 10px; }

        /* Multi-select dropdown */
        .multi-select { position: relative; display: inline-block; }
        .multi-select-btn { padding: 8px 14px; border: 1px solid #0f3460; background: #1a1a2e; color: #eee; border-radius: 4px; cursor: pointer; font-size: 14px; white-space: nowrap; display: inline-flex; align-items: center; gap: 6px; }
        .multi-select-btn:hover { border-color: #4fc3f7; background: #1f2a4a; }
        .multi-select-btn.active { border-color: #4fc3f7; background: #1f2a4a; }
        .multi-select-btn .icon { width: 12px; height: 12px; color: #888; }
        .multi-select-dropdown { display: none; position: absolute; top: calc(100% + 4px); left: 0; background: #1a1a2e; border: 1px solid #0f3460; border-radius: 6px; max-height: 280px; overflow-y: auto; overflow-x: hidden; z-index: 100; box-shadow: 0 4px 16px rgba(0,0,0,0.4); }
        .multi-select-dropdown.show { display: block; }
        .multi-select-item { padding: 6px 12px; cursor: pointer; font-size: 13px; white-space: nowrap; line-height: 20px; }
        .multi-select-item:hover { background: #0f3460; }
        .multi-select-item input[type="checkbox"] { width: 14px; height: 14px; vertical-align: middle; accent-color: #4fc3f7; cursor: pointer; margin: 0; }
        .multi-select-item-text { vertical-align: middle; margin-left: 8px; }
        .multi-select-clear { padding: 8px 12px; border-top: 1px solid #0f3460; color: #4fc3f7; cursor: pointer; text-align: center; font-size: 13px; }
        .multi-select-clear:hover { background: #0f3460; }
        .filter-badge { background: #4fc3f7; color: #1a1a2e; padding: 2px 7px; border-radius: 10px; font-size: 11px; font-weight: 600; margin-left: 6px; }
        /* Toggle switch with box background */
        .toggle-switch-box { display: flex; align-items: center; gap: 8px; cursor: pointer; user-select: none; background: #0f3460; padding: 6px 12px; border-radius: 6px; border: 1px solid #1a3a5c; }
        .toggle-switch-box:hover { border-color: #4fc3f7; }
        .toggle-switch-box input { display: none; }
        .toggle-switch-box .toggle-slider { width: 36px; height: 20px; background: #444; border-radius: 10px; position: relative; transition: background 0.2s; flex-shrink: 0; }
        .toggle-switch-box .toggle-slider::after { content: ''; position: absolute; top: 2px; left: 2px; width: 16px; height: 16px; background: #888; border-radius: 50%; transition: transform 0.2s, background 0.2s; }
        .toggle-switch-box input:checked + .toggle-slider { background: #4fc3f7; }
        .toggle-switch-box input:checked + .toggle-slider::after { transform: translateX(16px); background: #fff; }
        .toggle-switch-box .toggle-label { color: #aaa; font-size: 13px; white-space: nowrap; }
        .toggle-switch-box input:checked ~ .toggle-label { color: #4fc3f7; }

        /* Export dropdown */
        .export-dropdown { position: relative; display: inline-block; }
        .export-menu { display: none; position: absolute; top: calc(100% + 4px); left: 0; background: #1a1a2e; border: 1px solid #0f3460; border-radius: 6px; z-index: 100; box-shadow: 0 4px 12px rgba(0,0,0,0.3); min-width: 80px; }
        .export-menu.show { display: block; }
        .export-item { padding: 8px 14px; cursor: pointer; font-size: 13px; transition: background 0.15s; }
        .export-item:hover { background: #0f3460; }
        .export-item:first-child { border-radius: 6px 6px 0 0; }
        .export-item:last-child { border-radius: 0 0 6px 6px; }

        /* Toast notifications */
        .toast-container { position: fixed; top: 20px; right: 20px; z-index: 2000; display: flex; flex-direction: column; gap: 10px; }
        .toast { padding: 14px 20px; border-radius: 6px; color: #fff; font-size: 14px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); animation: toastIn 0.3s ease-out; max-width: 400px; display: flex; align-items: center; gap: 10px; }
        .toast.success { background: #00c853; }
        .toast.error { background: #e94560; }
        .toast.warning { background: #ffc107; color: #1a1a2e; }
        .toast.info { background: #4fc3f7; color: #1a1a2e; }
        .toast-close { background: none; border: none; color: inherit; font-size: 18px; cursor: pointer; margin-left: auto; opacity: 0.7; }
        .toast-close:hover { opacity: 1; }
        @keyframes toastIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        @keyframes toastOut { from { transform: translateX(0); opacity: 1; } to { transform: translateX(100%); opacity: 0; } }
    </style>
</head>
<body>
    <!-- Icons from Iconoir (https://iconoir.com/) - MIT License Copyright 2021 Luca Burgio -->
    <svg xmlns="http://www.w3.org/2000/svg" style="display:none;">
        <symbol id="icon-refresh" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21.168 8A10.003 10.003 0 0 0 12 2c-5.185 0-9.449 3.947-9.95 9"/><path d="M17 8h4.4a.6.6 0 0 0 .6-.6V3M2.881 16c1.544 3.532 5.068 6 9.168 6 5.186 0 9.45-3.947 9.951-9"/><path d="M7.05 16h-4.4a.6.6 0 0 0-.6.6V21"/></symbol>
        <symbol id="icon-clock" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 6v6h6"/><path d="M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10Z"/></symbol>
        <symbol id="icon-check" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="m5 13 4 4L19 7"/></symbol>
        <symbol id="icon-copy" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M19.4 20H9.6a.6.6 0 0 1-.6-.6V9.6a.6.6 0 0 1 .6-.6h9.8a.6.6 0 0 1 .6.6v9.8a.6.6 0 0 1-.6.6Z"/><path d="M15 9V4.6a.6.6 0 0 0-.6-.6H4.6a.6.6 0 0 0-.6.6v9.8a.6.6 0 0 0 .6.6H9"/></symbol>
        <symbol id="icon-edit" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14.363 5.652l1.48-1.48a2 2 0 0 1 2.829 0l1.414 1.414a2 2 0 0 1 0 2.828l-1.48 1.48m-4.243-4.242l-9.616 9.616a2 2 0 0 0-.578 1.238l-.242 2.74a1 1 0 0 0 1.084 1.085l2.74-.242a2 2 0 0 0 1.24-.578l9.615-9.616m-4.243-4.243l4.243 4.243"/></symbol>
        <symbol id="icon-download" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M6 20h12M12 4v12m0 0l3.5-3.5M12 16l-3.5-3.5"/></symbol>
        <symbol id="icon-restart" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M6.677 20.567C2.531 18.021.758 12.758 2.717 8.144 4.875 3.06 10.745.688 15.829 2.846c5.084 2.158 7.456 8.029 5.298 13.113a9.954 9.954 0 0 1-3.962 4.608"/><path d="M17 16v4.4a.6.6 0 0 1-.6.6H12m10-9h-1"/></symbol>
        <symbol id="icon-link" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14 11.998C14 9.506 11.683 7 8.857 7H7.143C4.303 7 2 9.238 2 11.998c0 2.378 1.71 4.368 4 4.873m4-4.873c0 2.492 2.317 4.999 5.143 4.999h1.714c2.84 0 5.143-2.237 5.143-4.997 0-2.379-1.71-4.37-4-4.874"/></symbol>
        <symbol id="icon-trash" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 9l-1.995 11.346A2 2 0 0 1 16.035 22h-8.07a2 2 0 0 1-1.97-1.654L4 9m17-3h-5.625M3 6h5.625m0 0V4a2 2 0 0 1 2-2h2.75a2 2 0 0 1 2 2v2m-6.75 0h6.75"/></symbol>
        <symbol id="icon-plus" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M6 12h6m6 0h-6m0 0V6m0 6v6"/></symbol>
        <symbol id="icon-eye" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4Z"/><path d="M21 12c-1.889 2.991-5.282 6-9 6s-7.111-3.009-9-6c2.299-2.842 4.992-6 9-6s6.701 3.158 9 6Z"/></symbol>
        <symbol id="icon-upload" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M6 20h12M12 16V4m0 0l3.5 3.5M12 4L8.5 7.5"/></symbol>
        <symbol id="icon-move" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8l4 4-4 4M6 8l-4 4 4 4M2 12h20"/></symbol>
        <symbol id="icon-search" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="m17 17 4 4M3 11a8 8 0 1 0 16 0 8 8 0 0 0-16 0Z"/></symbol>
        <symbol id="icon-users" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M1 20v-1a7 7 0 0 1 7-7v0a7 7 0 0 1 7 7v1"/><path d="M13 14v0a5 5 0 0 1 5-5v0a5 5 0 0 1 5 5v.5"/><path d="M8 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm10-1a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z"/></symbol>
        <symbol id="icon-logout" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 12h7m0 0-3 3m3-3-3-3M19 6V5a2 2 0 0 0-2-2H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-1"/></symbol>
        <symbol id="icon-server" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M6 17.5v-11h12v11H6Z"/><path d="M5 13.5H4a1 1 0 0 0-1 1v3a1 1 0 0 0 1 1h16a1 1 0 0 0 1-1v-3a1 1 0 0 0-1-1h-1"/><path d="M5 10.5H4a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1h16a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1h-1M6 9h1m-1 6h1"/></symbol>
        <symbol id="icon-stats" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M17 20v-8m-5 8V10m-5 10v-4M3 3v18h18"/></symbol>
        <symbol id="icon-file" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M4 21.4V2.6a.6.6 0 0 1 .6-.6h11.652a.6.6 0 0 1 .424.176l3.148 3.148a.6.6 0 0 1 .176.424V21.4a.6.6 0 0 1-.6.6H4.6a.6.6 0 0 1-.6-.6Z"/><path d="M16 2v4h4"/></symbol>
        <symbol id="icon-file-code" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M4 21.4V2.6a.6.6 0 0 1 .6-.6h11.652a.6.6 0 0 1 .424.176l3.148 3.148a.6.6 0 0 1 .176.424V21.4a.6.6 0 0 1-.6.6H4.6a.6.6 0 0 1-.6-.6Z"/><path d="M16 2v4h4"/><path d="M9 13l-2 2 2 2m6-4l2 2-2 2"/></symbol>
        <symbol id="icon-folder" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M2 11V4.6a.6.6 0 0 1 .6-.6h6.178a.6.6 0 0 1 .39.144l3.164 2.712a.6.6 0 0 0 .39.144H21.4a.6.6 0 0 1 .6.6V11M2 11v8.4a.6.6 0 0 0 .6.6h18.8a.6.6 0 0 0 .6-.6V11M2 11h20"/></symbol>
        <symbol id="icon-export" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 19V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z"/><path d="M8.5 15.5L12 12m0 0l3.5 3.5M12 12v-4"/></symbol>
        <symbol id="icon-agents" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8m-4-4v4"/><circle cx="12" cy="10" r="1" fill="currentColor"/></symbol>
        <symbol id="icon-rename" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3v4M7 3v4M3 9.5h18M4 3h16a1 1 0 0 1 1 1v16a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Zm5 10h6"/></symbol>
        <symbol id="icon-remove" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M9.172 14.828 12.001 12m2.828-2.828L12.001 12m0 0L9.172 9.172M12.001 12l2.828 2.828M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10Z"/></symbol>
        <symbol id="icon-add-group" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M17 10h2m2 0h-2m0 0V8m0 2v2M1 20v-1a7 7 0 0 1 7-7v0a7 7 0 0 1 7 7v1"/><path d="M8 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z"/></symbol>
        <symbol id="icon-exclusive" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M6 18.01l.01-.011M6 6.01l.01-.011M2 12.01l.01-.011M18 12.01l.01-.011M12 12.01l.01-.011M2 18.01l.01-.011M2 6.01l.01-.011M22 6v12M12 2v20M12 6.01l.01-.011M12 18.01l.01-.011M6 12.01l.01-.011"/></symbol>
        <symbol id="icon-info" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10Z"/><path d="M12 8h.01"/><path d="M11 12h1v4h1"/></symbol>
        <symbol id="icon-nav-arrow-down" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></symbol>
        <symbol id="icon-nav-arrow-up" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="m6 15 6-6 6 6"/></symbol>
        <symbol id="icon-undo" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M4.5 8H15s0 0 0 0 5 0 5 4.706C20 18 15 18 15 18H6.286"/><path d="M7.5 11.5 4 8l3.5-3.5"/></symbol>
        <symbol id="icon-redo" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M19.5 8H9s0 0 0 0-5 0-5 4.706C4 18 9 18 9 18h8.714"/><path d="m16.5 11.5 3.5-3.5-3.5-3.5"/></symbol>
        <symbol id="icon-xmark" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="m6.758 17.243 10.485-10.486m0 10.486L6.758 6.757"/></symbol>
        <symbol id="icon-save" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 20.4V3.6a.6.6 0 0 1 .6-.6h13.686a.6.6 0 0 1 .424.176l3.314 3.314a.6.6 0 0 1 .176.424V20.4a.6.6 0 0 1-.6.6H3.6a.6.6 0 0 1-.6-.6Z"/><path d="M8 3v4h8V3m-4 18v-6H8v6"/></symbol>
        <symbol id="icon-database" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.657 4.03 3 9 3s9-1.343 9-3V5"/><path d="M3 12c0 1.657 4.03 3 9 3s9-1.343 9-3"/></symbol>
        <symbol id="icon-columns" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="18" rx="1"/><rect x="14" y="3" width="7" height="18" rx="1"/></symbol>
        <symbol id="icon-column-settings" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h4m4 0h10M3 12h4m4 0h10M3 18h4m4 0h10"/><circle cx="9" cy="6" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="9" cy="18" r="2"/></symbol>
        <symbol id="icon-package" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2Z"/><path d="M12 4v8l2.5-1.5L17 12V4"/></symbol>
        <symbol id="icon-settings" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z"/><path d="M19.622 10.395l-1.097-2.65L20 6l-2-2-1.735 1.483-2.707-1.113L12.935 2h-1.954l-.632 2.401-2.645 1.115L6 4 4 6l1.453 1.789-1.08 2.657L2 11v2l2.401.656 1.113 2.707L4 18l2 2 1.791-1.46 2.606 1.072L11 22h2l.604-2.387 2.651-1.098C16.697 18.832 18 20 18 20l2-2-1.484-1.734 1.083-2.658L22 13v-2l-2.378-.605Z"/></symbol>
        <symbol id="icon-tree" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v8m0 0l4-4m-4 4l-4-4"/><path d="M3 14h4v6H3zm14 0h4v6h-4zM12 14v-2m0 8v-2m0 0H7m5 0h5"/><rect x="9" y="14" width="6" height="6" rx="1"/></symbol>
        <symbol id="icon-bell" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8.4c0-1.697-.632-3.325-1.757-4.525C15.117 2.675 13.59 2 12 2c-1.591 0-3.117.674-4.243 1.875C6.632 5.075 6 6.703 6 8.4 6 15.867 3 18 3 18h18s-3-2.133-3-9.6Z"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></symbol>
        <symbol id="icon-file-text" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M4 21.4V2.6a.6.6 0 0 1 .6-.6h11.652a.6.6 0 0 1 .424.176l3.148 3.148a.6.6 0 0 1 .176.424V21.4a.6.6 0 0 1-.6.6H4.6a.6.6 0 0 1-.6-.6Z"/><path d="M16 2v4h4"/><path d="M8 10h8m-8 4h8m-8 4h4"/></symbol>
        <symbol id="icon-chevron-right" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m9 6 6 6-6 6"/></symbol>
        <symbol id="icon-chevron-down" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></symbol>
    </svg>
    <div class="container">
        <header>
            <h1>JT Wazuh Agent Manager <span style="font-size: 14px; color: #888; font-weight: normal;">v{{ version }}</span></h1>
            <div class="header-right">
                <div class="stats-bar" id="statsBar">
                    <div class="stat-item" onclick="filterByStatus('')" title="Show all agents"><div class="stat-value" id="totalAgents"><span>-</span></div><div class="stat-label">Total Agents</div></div>
                    <div class="stat-item active" onclick="filterByStatus('active')" title="Show active agents"><div class="stat-value" id="activeAgents"><span>-</span></div><div class="stat-label">Active</div></div>
                    <div class="stat-item disconnected" onclick="filterByStatus('disconnected')" title="Show disconnected agents"><div class="stat-value" id="disconnectedAgents"><span>-</span></div><div class="stat-label">Disconnected</div></div>
                    <div class="stat-item pending" onclick="filterByStatus('pending')" title="Show pending agents"><div class="stat-value" id="pendingAgents"><span>-</span></div><div class="stat-label">Pending</div></div>
                </div>
                <div class="user-info">
                    <div><span class="api-status connected">API Connected</span></div>
                    <div><strong>{{ username }}</strong></div>
                    <div id="sessionTimer" style="font-size:11px;color:#888;"></div>
                </div>
                <div class="header-buttons">
                    <button class="btn-settings" onclick="showSettingsModal()"><svg class="icon"><use href="#icon-settings"/></svg>Settings</button>
                    <a href="/logout" class="btn-logout"><svg class="icon"><use href="#icon-logout"/></svg>Logout</a>
                </div>
            </div>
        </header>

        <div class="tabs">
            <button class="tab active" data-tab="agents"><svg class="icon"><use href="#icon-agents"/></svg>Agents</button>
            <button class="tab" data-tab="groups"><svg class="icon"><use href="#icon-folder"/></svg>Groups</button>
            <button class="tab" data-tab="nodes"><svg class="icon"><use href="#icon-server"/></svg>Nodes</button>
            <button class="tab" data-tab="rules"><svg class="icon"><use href="#icon-tree"/></svg>Rules</button>
            <button class="tab" data-tab="stats"><svg class="icon"><use href="#icon-stats"/></svg>Statistics</button>
            <button class="tab" data-tab="users"><svg class="icon"><use href="#icon-users"/></svg>API Users</button>
            <button class="tab" data-tab="logs"><svg class="icon"><use href="#icon-file"/></svg>Logs</button>
        </div>

        <!-- Agents Panel -->
        <div class="panel active" id="agents-panel">
            <div class="toolbar toolbar-row">
                <input type="text" id="agentSearch" placeholder="Search agents...">
                <div class="multi-select" id="statusFilterWrap">
                    <div class="multi-select-btn" onclick="toggleMultiSelect('statusFilter')">Status <svg class="icon"><use href="#icon-nav-arrow-down"/></svg></div>
                    <div class="multi-select-dropdown" id="statusFilterDropdown">
                        <div class="multi-select-item" onclick="toggleCheckbox(this, event)"><input type="checkbox" value="active" onchange="onFilterChange()"><span class="multi-select-item-text">Active</span></div>
                        <div class="multi-select-item" onclick="toggleCheckbox(this, event)"><input type="checkbox" value="disconnected" onchange="onFilterChange()"><span class="multi-select-item-text">Disconnected</span></div>
                        <div class="multi-select-item" onclick="toggleCheckbox(this, event)"><input type="checkbox" value="pending" onchange="onFilterChange()"><span class="multi-select-item-text">Pending</span></div>
                        <div class="multi-select-item" onclick="toggleCheckbox(this, event)"><input type="checkbox" value="never_connected" onchange="onFilterChange()"><span class="multi-select-item-text">Never Connected</span></div>
                        <div class="multi-select-clear" onclick="clearFilter('statusFilter')">Clear</div>
                    </div>
                </div>
                <div class="multi-select" id="groupFilterWrap">
                    <div class="multi-select-btn" onclick="toggleMultiSelect('groupFilter')">Group <svg class="icon"><use href="#icon-nav-arrow-down"/></svg></div>
                    <div class="multi-select-dropdown" id="groupFilterDropdown"></div>
                </div>
                <div class="multi-select" id="osFilterWrap">
                    <div class="multi-select-btn" onclick="toggleMultiSelect('osFilter')">OS <svg class="icon"><use href="#icon-nav-arrow-down"/></svg></div>
                    <div class="multi-select-dropdown" id="osFilterDropdown"></div>
                </div>
                <div class="multi-select" id="versionFilterWrap">
                    <div class="multi-select-btn" onclick="toggleMultiSelect('versionFilter')">Version <svg class="icon"><use href="#icon-nav-arrow-down"/></svg></div>
                    <div class="multi-select-dropdown" id="versionFilterDropdown"></div>
                </div>
                <div class="multi-select" id="nodeFilterWrap">
                    <div class="multi-select-btn" onclick="toggleMultiSelect('nodeFilter')">Node <svg class="icon"><use href="#icon-nav-arrow-down"/></svg></div>
                    <div class="multi-select-dropdown" id="nodeFilterDropdown"></div>
                </div>
                <div class="multi-select" id="syncFilterWrap">
                    <div class="multi-select-btn" onclick="toggleMultiSelect('syncFilter')">Sync <svg class="icon"><use href="#icon-nav-arrow-down"/></svg></div>
                    <div class="multi-select-dropdown" id="syncFilterDropdown"></div>
                </div>
                <div class="toolbar-spacer"></div>
                <button class="btn btn-primary" onclick="refreshAgents()" title="Refresh agent list"><svg class="icon"><use href="#icon-refresh"/></svg></button>
                <div class="multi-select" id="columnsFilterWrap">
                    <button class="btn" onclick="toggleMultiSelect('columnsFilter')" title="Show/Hide Columns"><svg class="icon"><use href="#icon-column-settings"/></svg></button>
                    <div class="multi-select-dropdown" id="columnsFilterDropdown">
                        <div class="multi-select-item" onclick="toggleColumnItem(event, this, 'id')"><input type="checkbox" checked data-col="id"><span class="multi-select-item-text">ID</span></div>
                        <div class="multi-select-item" onclick="toggleColumnItem(event, this, 'name')"><input type="checkbox" checked data-col="name"><span class="multi-select-item-text">Name</span></div>
                        <div class="multi-select-item" onclick="toggleColumnItem(event, this, 'ip')"><input type="checkbox" checked data-col="ip"><span class="multi-select-item-text">IP</span></div>
                        <div class="multi-select-item" onclick="toggleColumnItem(event, this, 'status')"><input type="checkbox" checked data-col="status"><span class="multi-select-item-text">Status</span></div>
                        <div class="multi-select-item" onclick="toggleColumnItem(event, this, 'os')"><input type="checkbox" checked data-col="os"><span class="multi-select-item-text">OS</span></div>
                        <div class="multi-select-item" onclick="toggleColumnItem(event, this, 'version')"><input type="checkbox" checked data-col="version"><span class="multi-select-item-text">Version</span></div>
                        <div class="multi-select-item" onclick="toggleColumnItem(event, this, 'group')"><input type="checkbox" checked data-col="group"><span class="multi-select-item-text">Group</span></div>
                        <div class="multi-select-item" onclick="toggleColumnItem(event, this, 'node_name')"><input type="checkbox" checked data-col="node_name"><span class="multi-select-item-text">Node</span></div>
                        <div class="multi-select-item" onclick="toggleColumnItem(event, this, 'synced')"><input type="checkbox" checked data-col="synced"><span class="multi-select-item-text">Sync</span></div>
                    </div>
                </div>
                <button class="btn" id="btnUpgradeProgress" style="background:#17a2b8;color:#fff;" onclick="showAllUpgradeProgress()" title="View upgrade progress"><svg class="icon"><use href="#icon-clock"/></svg></button>
                <div class="export-dropdown">
                    <button class="btn" onclick="toggleExportMenu()" title="Export to file"><svg class="icon"><use href="#icon-download"/></svg></button>
                    <div class="export-menu" id="exportMenu">
                        <div class="export-item" onclick="exportData('csv')">CSV</div>
                        <div class="export-item" onclick="exportData('tsv')">TSV</div>
                        <div class="export-item" onclick="exportData('json')">JSON</div>
                    </div>
                </div>
                <label class="toggle-switch-box" title="Show Queue DB column (loads from filesystem)">
                    <input type="checkbox" id="toggleQueueDB" onchange="toggleQueueDB()">
                    <span class="toggle-slider"></span>
                    <span class="toggle-label">Queue DB</span>
                </label>
                <label class="toggle-switch-box" title="Preview changes without executing">
                    <input type="checkbox" id="dryRunMode">
                    <span class="toggle-slider"></span>
                    <span class="toggle-label">Dry Run</span>
                </label>
            </div>
            <div class="action-bar-container">
                <div class="distribution-bar" id="distributionBar">
                    <select id="distributionType" onchange="updateDistributionBar(true)">
                        <option value="status">Status</option>
                        <option value="os">OS</option>
                        <option value="version">Version</option>
                        <option value="group">Group</option>
                        <option value="node">Node</option>
                        <option value="sync">Sync</option>
                    </select>
                    <div class="distribution-chart" id="distributionChart"></div>
                </div>
                <div class="action-bar" id="actionBar">
                    <div class="selected-count" id="selectedCount">Selected: <span>0</span></div>
                    <button class="btn btn-success" id="btnAddToGroup" onclick="showAddToGroupModal()"><svg class="icon"><use href="#icon-add-group"/></svg>Add to Group</button>
                    <button class="btn btn-warning" id="btnRemoveFromGroup" onclick="showRemoveFromGroupModal()"><svg class="icon"><use href="#icon-remove"/></svg>Remove from Group</button>
                    <button class="btn btn-primary" id="btnMoveToNode" onclick="showMoveToNodeModal()"><svg class="icon"><use href="#icon-move"/></svg>Move to Node</button>
                    <button class="btn btn-warning" id="btnRestart" onclick="restartSelected()"><svg class="icon"><use href="#icon-restart"/></svg>Restart</button>
                    <button class="btn btn-primary" id="btnReconnect" onclick="reconnectSelected()"><svg class="icon"><use href="#icon-link"/></svg>Reconnect</button>
                    <button class="btn" id="btnUpgrade" style="background:#fd7e14;color:#fff;" onclick="upgradeSelected()"><svg class="icon"><use href="#icon-upload"/></svg>Upgrade</button>
                    <button class="btn btn-danger" id="btnDelete" onclick="deleteSelected()"><svg class="icon"><use href="#icon-trash"/></svg>Delete</button>
                </div>
            </div>
            <div class="table-container">
                <table id="agentsTable">
                    <thead>
                        <tr>
                            <th class="checkbox-cell"><input type="checkbox" id="selectAll" onchange="toggleSelectAll()"></th>
                            <th></th>
                            <th class="sortable" data-sort="id" data-col="id" onclick="sortAgents('id')">ID<svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                            <th class="sortable" data-sort="name" data-col="name" onclick="sortAgents('name')">Name<svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                            <th class="sortable" data-sort="ip" data-col="ip" onclick="sortAgents('ip')">IP<svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                            <th class="sortable" data-sort="status" data-col="status" onclick="sortAgents('status')">Status<svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                            <th class="sortable" data-sort="os" data-col="os" onclick="sortAgents('os')">OS<svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                            <th class="sortable" data-sort="version" data-col="version" onclick="sortAgents('version')">Version<svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                            <th class="sortable" data-sort="group" data-col="group" onclick="sortAgents('group')">Group<svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                            <th class="sortable" data-sort="node_name" data-col="node_name" onclick="sortAgents('node_name')">Node<svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                            <th class="sortable" data-sort="synced" data-col="synced" onclick="sortAgents('synced')">Sync<svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                            <th class="sortable queue-db-cell" data-sort="queue_size" data-col="queue_size" onclick="sortAgents('queue_size')" style="display:none">Queue DB<svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                        </tr>
                    </thead>
                    <tbody id="agentsBody"></tbody>
                </table>
            </div>
            <div class="pagination-bar">
                <div class="pagination-info">
                    <span id="paginationInfo">Showing 0 - 0 of 0</span>
                </div>
                <div class="pagination-controls">
                    <label>Per page:
                        <select id="pageSizeSelect" onchange="changePageSize(this.value)">
                            <option value="50">50</option>
                            <option value="100" selected>100</option>
                            <option value="500">500</option>
                            <option value="1000">1000</option>
                            <option value="5000">5000</option>
                        </select>
                    </label>
                    <button class="btn" id="btnFirstPage" onclick="goToPage(1)">&laquo;</button>
                    <button class="btn" id="btnPrevPage" onclick="prevPage()">&lsaquo; Prev</button>
                    <span class="page-indicator">Page <input type="number" id="pageInput" min="1" value="1" onchange="goToPage(this.value)"> of <span id="totalPages">1</span></span>
                    <button class="btn" id="btnNextPage" onclick="nextPage()">Next &rsaquo;</button>
                    <button class="btn" id="btnLastPage" onclick="goToPage(999999)">&raquo;</button>
                </div>
            </div>
        </div>

        <!-- Groups Panel -->
        <div class="panel" id="groups-panel">
            <div class="toolbar">
                <button class="btn btn-success" onclick="showCreateGroupModal()"><svg class="icon"><use href="#icon-plus"/></svg>Create Group</button>
                <button class="btn btn-primary" onclick="refreshGroups()"><svg class="icon"><use href="#icon-refresh"/></svg>Refresh</button>
            </div>
            <div class="table-container">
                <table id="groupsTable">
                    <thead>
                        <tr>
                            <th class="sortable" data-sort="name" onclick="sortGroups('name')">Group Name<svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                            <th class="sortable" data-sort="count" style="text-align:center" onclick="sortGroups('count')">Agent Count<svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                            <th>Agent Actions</th>
                            <th>Group Actions</th>
                        </tr>
                    </thead>
                    <tbody id="groupsBody"></tbody>
                </table>
            </div>
        </div>

        <!-- Nodes Panel -->
        <div class="panel" id="nodes-panel">
            <div class="toolbar">
                <button class="btn btn-primary" onclick="refreshNodes()"><svg class="icon"><use href="#icon-refresh"/></svg>Refresh</button>
            </div>
            <div class="table-container">
                <table id="nodesTable">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th style="text-align:center">Type</th>
                            <th style="text-align:center">Version</th>
                            <th>IP</th>
                            <th style="text-align:center">Agents</th>
                            <th>Services</th>
                            <th>Sync Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="nodesBody"></tbody>
                </table>
            </div>
        </div>

        <!-- Rules Panel -->
        <div class="panel" id="rules-panel">
            <div class="toolbar">
                <div class="search-box" style="flex:1;max-width:400px;">
                    <input type="text" id="ruleIdSearch" placeholder="Enter Rule ID (e.g., 100001)" style="width:100%;padding:8px 12px;border:1px solid #333;border-radius:4px;background:#1a1a2e;color:#fff;" onkeydown="if(event.key==='Enter')searchRuleHierarchy()">
                </div>
                <button class="btn btn-primary" onclick="searchRuleHierarchy()"><svg class="icon"><use href="#icon-search"/></svg>Search</button>
                <button class="btn" onclick="clearRuleSearch()"><svg class="icon"><use href="#icon-xmark"/></svg>Clear</button>
                <button class="btn" onclick="expandAllRules()" title="Expand All"><svg class="icon"><use href="#icon-nav-arrow-down"/></svg>Expand</button>
                <button class="btn" onclick="collapseAllRules()" title="Collapse All"><svg class="icon"><use href="#icon-nav-arrow-up"/></svg>Collapse</button>
                <span id="ruleSearchStatus" style="margin-left:15px;color:#888;font-size:13px;"></span>
            </div>
            <div style="padding:10px 15px 0 15px;color:#888;font-size:12px;">
                Search by Rule ID to view the rule hierarchy (parent-child relationships via if_sid/if_matched_sid/if_group). Click on a rule to view its XML content.
            </div>
            <div class="rules-content" style="padding:15px;">
                <div id="ruleTreeContainer" style="min-height:200px;">
                    <div style="color:#888;text-align:center;padding:40px;">
                        <svg class="icon" style="width:48px;height:48px;opacity:0.5;margin-bottom:15px;"><use href="#icon-tree"/></svg>
                        <p>Enter a Rule ID to view its hierarchy and relationships.</p>
                        <p style="font-size:12px;margin-top:10px;">The tree will show parent rules (if_sid, if_matched_sid) and child rules.</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Stats Panel -->
        <div class="panel" id="stats-panel">
            <div class="toolbar">
                <button class="btn btn-primary" onclick="refreshStats()"><svg class="icon"><use href="#icon-refresh"/></svg>Refresh</button>
            </div>
            <div class="stats-content" id="statsContent"></div>
        </div>

        <!-- Users Panel -->
        <div class="panel" id="users-panel">
            <div class="toolbar">
                <button class="btn btn-success" onclick="showCreateUserModal()"><svg class="icon"><use href="#icon-plus"/></svg>Create User</button>
                <button class="btn btn-primary" onclick="refreshUsers()"><svg class="icon"><use href="#icon-refresh"/></svg>Refresh</button>
            </div>
            <div class="table-container">
                <table id="usersTable">
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>Roles</th>
                            <th>Allow Run As</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="usersBody"></tbody>
                </table>
            </div>
        </div>

        <!-- Logs Panel -->
        <div class="panel" id="logs-panel">
            <div class="toolbar">
                <button class="btn btn-primary" onclick="refreshLogs()"><svg class="icon"><use href="#icon-refresh"/></svg>Refresh</button>
                <select id="logLines" onchange="refreshLogs()">
                    <option value="50">Last 50 lines</option>
                    <option value="100" selected>Last 100 lines</option>
                    <option value="200">Last 200 lines</option>
                    <option value="500">Last 500 lines</option>
                    <option value="1000">Last 1000 lines</option>
                </select>
                <button class="btn" onclick="downloadLogs()"><svg class="icon"><use href="#icon-download"/></svg>Download Full Log</button>
                <span style="margin-left:auto;color:#888;font-size:12px;">
                    <strong>Log file:</strong> <code id="logFilePath" style="color:#4fc3f7;">-</code>
                    <span id="logFileInfo" style="margin-left:10px;"></span>
                </span>
            </div>
            <div class="log-container" id="logContainer">
                <pre id="logContent" style="padding:15px;background:#0a0a15;border-radius:4px;font-size:12px;line-height:1.5;white-space:pre-wrap;word-wrap:break-word;">Click Refresh to load logs...</pre>
            </div>
        </div>
    </div>

    <!-- Modals -->
    <div class="modal" id="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="modalTitle">Modal</h3>
                <button class="modal-close" onclick="closeModal()"><svg class="icon" style="width:20px;height:20px;"><use href="#icon-xmark"/></svg></button>
            </div>
            <div class="modal-body" id="modalBody"></div>
            <div class="modal-footer" id="modalFooter"></div>
        </div>
    </div>

    <!-- Footer -->
    <footer style="text-align:center;padding:5px;color:#555;font-size:12px;flex-shrink:0;">
        by <a href="https://github.com/jasoncheng7115/it-scripts/tree/master/jt_wazuh_agent_mgr" target="_blank" style="color:#666;text-decoration:none;">Jason Cheng (Jason Tools)</a>
    </footer>

    <!-- Toast Container -->
    <div class="toast-container" id="toastContainer"></div>

    <script>
        let agents = [];
        let groups = [];
        let selectedAgents = new Set();
        let sortColumn = 'id';
        let sortDirection = 'asc';
        let groupSortColumn = 'name';
        let groupSortDirection = 'asc';
        let queueSizes = {};
        let queueSizeNode = '';
        let queueOtherNodes = [];
        let showQueueDB = false;  // Queue DB is disabled by default for performance
        let validNodeNames = [];  // List of valid node names in current cluster
        let managerVersion = '';  // Manager/master node version for comparison

        // Session timer - uses actual JWT expiration from Wazuh API
        const tokenExp = {{ token_exp }};  // JWT expiration timestamp
        const tokenIat = {{ token_iat }};  // JWT issued at timestamp
        let sessionTimerInterval = null;

        function updateSessionTimer() {
            const timerEl = document.getElementById('sessionTimer');
            if (!timerEl || !tokenExp) return;

            const now = Math.floor(Date.now() / 1000);
            const remaining = tokenExp - now;

            if (remaining <= 0) {
                timerEl.innerHTML = '<span style="color:#e94560;">Session expired</span>';
                clearInterval(sessionTimerInterval);
                showToast('Session expired. Redirecting to login...', 'warning');
                setTimeout(() => { window.location.href = '/logout'; }, 2000);
                return;
            }

            const mins = Math.floor(remaining / 60);
            const secs = remaining % 60;
            const timeStr = mins + ':' + String(secs).padStart(2, '0');

            if (remaining <= 60) {
                timerEl.innerHTML = '<span style="color:#e94560;">Expires: ' + timeStr + '</span>';
            } else if (remaining <= 180) {
                timerEl.innerHTML = '<span style="color:#ffc107;">Expires: ' + timeStr + '</span>';
            } else {
                timerEl.textContent = 'Expires: ' + timeStr;
            }
        }

        // Start session timer on page load
        if (tokenExp) {
            updateSessionTimer();
            sessionTimerInterval = setInterval(updateSessionTimer, 1000);
        }

        // Column visibility - load from localStorage or use defaults
        const defaultColumns = { id: true, name: true, ip: true, status: true, os: true, version: true, group: true, node_name: true, synced: true };
        let visibleColumns = JSON.parse(localStorage.getItem('agentColumnsVisibility')) || { ...defaultColumns };

        // Initialize column visibility on page load
        function initColumnVisibility() {
            // Apply stored visibility to header checkboxes
            document.querySelectorAll('#columnsFilterDropdown input[data-col]').forEach(cb => {
                const col = cb.dataset.col;
                cb.checked = visibleColumns[col] !== false;
            });
            applyColumnVisibility();
        }

        // Toggle column visibility (for multi-select style)
        function toggleColumnItem(event, elem, col) {
            const checkbox = elem.querySelector('input[type="checkbox"]');
            // Only toggle if click was not directly on the checkbox (checkbox handles itself)
            if (event.target.tagName !== 'INPUT') {
                checkbox.checked = !checkbox.checked;
            }
            visibleColumns[col] = checkbox.checked;
            localStorage.setItem('agentColumnsVisibility', JSON.stringify(visibleColumns));
            applyColumnVisibility();
        }

        // Apply column visibility to table
        function applyColumnVisibility() {
            // Apply to headers
            document.querySelectorAll('#agentsTable th[data-col]').forEach(th => {
                const col = th.dataset.col;
                if (col === 'queue_size') return; // Queue DB has its own toggle
                th.style.display = visibleColumns[col] === false ? 'none' : '';
            });
            // Apply to body cells - re-render will handle this
            renderAgents();
        }

        // Pagination
        let currentPage = 1;
        let pageSize = 100;  // Default 100 items per page

        // Toast notification system
        function showToast(message, type = 'info', duration = 4000) {
            const container = document.getElementById('toastContainer');
            const toast = document.createElement('div');
            toast.className = `toast ${type}`;
            toast.innerHTML = `
                <span>${message}</span>
                <button class="toast-close" onclick="this.parentElement.remove()"><svg class="icon" style="width:14px;height:14px;"><use href="#icon-xmark"/></svg></button>
            `;
            container.appendChild(toast);

            // Auto remove after duration
            setTimeout(() => {
                toast.style.animation = 'toastOut 0.3s ease-out forwards';
                setTimeout(() => toast.remove(), 300);
            }, duration);
        }

        function formatBytes(bytes) {
            if (!bytes || bytes === 0) return '-';
            const units = ['B', 'KB', 'MB', 'GB'];
            let i = 0;
            while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }
            return bytes.toFixed(1) + ' ' + units[i];
        }

        function formatQueueSize(agent) {
            const entries = agent.queue_entries || [];

            if (entries.length > 0) {
                if (entries.length === 1) {
                    // Single node - show size with node name
                    const e = entries[0];
                    return `<div class="queue-entry"><span class="queue-size">${formatBytes(e.size)}</span><span class="queue-node">${escapeHtml(e.node)}</span></div>`;
                } else {
                    // Multiple nodes - show each entry aligned
                    return entries.map(e =>
                        `<div class="queue-entry"><span class="queue-size">${formatBytes(e.size)}</span><span class="queue-node">${escapeHtml(e.node)}</span></div>`
                    ).join('');
                }
            }

            // Check if agent is on a node we don't have queue data for
            const agentNode = agent.node_name || '';
            const otherNode = queueOtherNodes.find(n => n.name === agentNode);
            if (otherNode && agentNode !== queueSizeNode) {
                return `<a href="#" onclick="showSSHSetupTutorial('${escapeHtml(agentNode)}', '${escapeHtml(otherNode.ip)}'); return false;" style="color:#f39c12;text-decoration:underline;cursor:pointer;" title="SSH access required for ${escapeHtml(agentNode)}">SSH required</a>`;
            }

            return '-';
        }

        function formatNodeName(nodeName) {
            if (!nodeName) return '-';

            const escaped = escapeHtml(nodeName);

            // Check if this node exists in the current cluster
            if (validNodeNames.length > 0 && !validNodeNames.includes(nodeName)) {
                return `<span style="color:#e94560;text-decoration:line-through;" title="Node '${escaped}' no longer exists in cluster">${escaped}</span>`;
            }

            return escaped;
        }

        function formatGroupLabels(groupStr) {
            if (!groupStr || groupStr.trim() === '') return '-';
            const groups = groupStr.split(',').map(g => g.trim()).filter(g => g);
            if (groups.length === 0) return '-';
            return groups.map(g => `<span class="group-label">${escapeHtml(g)}</span>`).join(' ');
        }

        function escapeHtml(str) {
            if (!str) return '';
            return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }

        // Format file size in human-readable format
        function formatFileSize(bytes) {
            if (!bytes || bytes === 0) return '0 B';
            const units = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(1024));
            const size = (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0);
            return size + ' ' + units[i];
        }

        // Compare version strings (e.g., "4.14.0" vs "4.13.1")
        // Returns: -1 if v1 < v2, 0 if equal, 1 if v1 > v2
        function compareVersions(v1, v2) {
            if (!v1 || !v2) return 0;
            // Remove 'v' prefix if present
            v1 = v1.replace(/^v/i, '');
            v2 = v2.replace(/^v/i, '');
            const parts1 = v1.split('.').map(p => parseInt(p) || 0);
            const parts2 = v2.split('.').map(p => parseInt(p) || 0);
            const maxLen = Math.max(parts1.length, parts2.length);
            for (let i = 0; i < maxLen; i++) {
                const p1 = parts1[i] || 0;
                const p2 = parts2[i] || 0;
                if (p1 < p2) return -1;
                if (p1 > p2) return 1;
            }
            return 0;
        }

        // Format agent version with color coding
        function formatAgentVersion(version) {
            if (!version) return '-';
            const v = escapeHtml(version);
            if (!managerVersion) return v;
            const cmp = compareVersions(version, managerVersion);
            if (cmp < 0) {
                // Older than manager - show in orange/warning color
                return `<span style="color:#fd7e14;" title="Older than manager (${managerVersion})">${v}</span>`;
            } else if (cmp > 0) {
                // Newer than manager - show in cyan (unusual)
                return `<span style="color:#17a2b8;" title="Newer than manager (${managerVersion})">${v}</span>`;
            }
            // Same version - normal color (green)
            return `<span style="color:#28a745;">${v}</span>`;
        }

        // Tab switching
        function switchToTab(tabName) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
            const targetTab = document.querySelector(`.tab[data-tab="${tabName}"]`);
            if (targetTab) {
                targetTab.classList.add('active');
                document.getElementById(tabName + '-panel').classList.add('active');

                // Auto-refresh data for the tab
                if (tabName === 'agents') refreshAgents();
                else if (tabName === 'stats') {
                    refreshStats();
                    if (agents.length === 0) refreshAgents();
                }
                else if (tabName === 'nodes') refreshNodes();
                else if (tabName === 'groups') refreshGroups();
                else if (tabName === 'users') refreshUsers();
                else if (tabName === 'logs') refreshLogs();
            }
        }

        function showNodeManagement() {
            switchToTab('nodes');
        }

        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                switchToTab(tab.dataset.tab);
            });
        });

        // API calls
        let isBackendConnected = true;

        function updateConnectionStatus(connected) {
            isBackendConnected = connected;
            const statusEl = document.querySelector('.api-status');
            if (statusEl) {
                if (connected) {
                    statusEl.textContent = 'API Connected';
                    statusEl.className = 'api-status connected';
                } else {
                    statusEl.textContent = 'Connection Lost';
                    statusEl.className = 'api-status disconnected';
                }
            }
        }

        function getConnectionErrorHtml(retryFunc) {
            return `
                <div class="connection-error">
                    <div class="error-icon"><svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4m0 4h.01"/></svg></div>
                    <div class="error-title">Backend Service Unavailable</div>
                    <div class="error-message">The backend server is not running or connection lost.<br>Please check if the service is started.</div>
                    <button class="retry-btn" onclick="${retryFunc}"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-right:6px;"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/></svg>Retry</button>
                </div>
            `;
        }

        async function api(endpoint, method = 'GET', data = null) {
            const options = { method, headers: { 'Content-Type': 'application/json' } };
            if (data) options.body = JSON.stringify(data);
            try {
                const res = await fetch('/api' + endpoint, options);
                if (res.status === 401) {
                    window.location.href = '/login';
                    return null;
                }
                const json = await res.json();
                // Handle session expired from API response
                if (json && json.session_expired) {
                    showToast('Session expired. Redirecting to login...', 'warning');
                    setTimeout(() => { window.location.href = '/login'; }, 1500);
                    return null;
                }
                // Connection restored
                if (!isBackendConnected) {
                    updateConnectionStatus(true);
                    showToast('Connection restored', 'success');
                }
                return json;
            } catch (err) {
                // Network error - backend is likely down
                if (err.name === 'TypeError' || err.message.includes('Failed to fetch') || err.message.includes('NetworkError')) {
                    updateConnectionStatus(false);
                    throw new Error('BACKEND_UNAVAILABLE');
                }
                throw err;
            }
        }

        // Load agents
        async function refreshAgents() {
            const body = document.getElementById('agentsBody');
            body.innerHTML = '<tr><td colspan="20" class="loading"><div class="spinner"></div>Loading...</td></tr>';

            try {
                // Also load valid node names and manager version if not already loaded
                if (validNodeNames.length === 0) {
                    const nodesData = await api('/nodes');
                    if (nodesData && nodesData.nodes) {
                        validNodeNames = nodesData.nodes.map(n => n.name);
                        // Get master node version as the manager version
                        const masterNode = nodesData.nodes.find(n => n.type === 'master') || nodesData.nodes[0];
                        if (masterNode && masterNode.version) {
                            managerVersion = masterNode.version.replace(/^v|^Wazuh /i, '');
                            console.log('Manager version detected:', managerVersion, 'from', masterNode.version);
                        }
                    }
                }

                const agentData = await api('/agents');
                if (!agentData) return;

                if (agentData.error) {
                    body.innerHTML = `<tr><td colspan="20" class="loading" style="color:#e94560;">Error: ${agentData.error}</td></tr>`;
                    showToast('Failed to load agents: ' + agentData.error, 'error');
                    return;
                }

                agents = agentData.agents || [];

                // Only load queue sizes if enabled (to avoid filesystem reads on every refresh)
                if (showQueueDB) {
                    await loadQueueSizes();
                }

                updateFilterOptions();
                renderAgents();
                updateStats();
            } catch (err) {
                if (err.message === 'BACKEND_UNAVAILABLE') {
                    body.innerHTML = `<tr><td colspan="20">${getConnectionErrorHtml('refreshAgents()')}</td></tr>`;
                } else {
                    body.innerHTML = `<tr><td colspan="20" class="loading" style="color:#e94560;">Error loading agents: ${escapeHtml(err.message)}</td></tr>`;
                    showToast('Error loading agents: ' + err.message, 'error');
                }
                console.error('refreshAgents error:', err);
            }
        }

        // Load queue DB sizes separately (filesystem operation)
        async function loadQueueSizes() {
            const queueData = await api('/agents/queue-size');
            if (queueData && queueData.queue_sizes) {
                queueSizes = queueData.queue_sizes;  // Now an object with arrays: {agent_id: [{size, node}, ...]}
                queueSizeNode = queueData.local_node || '';
                queueOtherNodes = queueData.other_nodes || [];
                const loadedNodes = queueData.loaded_nodes || [];
                const failedNodes = queueData.ssh_failed_nodes || [];

                agents.forEach(a => {
                    const qInfoList = queueSizes[a.id];  // Array of {size, node}
                    if (qInfoList && qInfoList.length > 0) {
                        // Store all entries for display
                        a.queue_entries = qInfoList;
                        // Calculate total size for sorting
                        a.queue_size = qInfoList.reduce((sum, q) => sum + (q.size || 0), 0);
                    } else {
                        a.queue_entries = [];
                        a.queue_size = 0;
                    }
                });

                // Show appropriate message based on results
                if (failedNodes.length > 0) {
                    showToast(`Queue DB loaded from: ${loadedNodes.join(', ')}. Failed: ${failedNodes.join(', ')}`, 'warning', 6000);
                } else if (loadedNodes.length > 1) {
                    showToast(`Queue DB loaded from all nodes: ${loadedNodes.join(', ')}`, 'success', 4000);
                } else if (loadedNodes.length === 1) {
                    showToast(`Queue DB loaded from ${loadedNodes[0]}`, 'success', 3000);
                }
            }
        }

        // Toggle Queue DB column visibility
        async function toggleQueueDB() {
            const checkbox = document.getElementById('toggleQueueDB');
            showQueueDB = checkbox.checked;

            // Update column visibility
            updateQueueDBColumn();

            // Load queue sizes if just enabled
            if (showQueueDB && Object.keys(queueSizes).length === 0) {
                await loadQueueSizes();
                renderAgents();
            } else {
                renderAgents();
            }
        }

        // Show/hide Queue DB column in table
        function updateQueueDBColumn() {
            const queueHeader = document.querySelector('th[data-sort="queue_size"]');
            if (queueHeader) {
                queueHeader.style.display = showQueueDB ? '' : 'none';
            }
        }

        // Multi-select functions
        function toggleMultiSelect(filterId) {
            const dropdown = document.getElementById(filterId + 'Dropdown');
            const btn = dropdown.previousElementSibling;
            const isOpen = dropdown.classList.contains('show');

            // Close all dropdowns first
            document.querySelectorAll('.multi-select-dropdown').forEach(d => d.classList.remove('show'));
            document.querySelectorAll('.multi-select-btn').forEach(b => b.classList.remove('active'));

            if (!isOpen) {
                dropdown.classList.add('show');
                btn.classList.add('active');
            }
        }

        function getFilterValues(filterId) {
            const dropdown = document.getElementById(filterId + 'Dropdown');
            const checked = dropdown.querySelectorAll('input[type="checkbox"]:checked');
            return Array.from(checked).map(cb => cb.value);
        }

        function updateFilterButton(filterId) {
            const values = getFilterValues(filterId);
            const btn = document.querySelector('#' + filterId + 'Wrap .multi-select-btn');
            const labels = { statusFilter: 'Status', groupFilter: 'Group', osFilter: 'OS', versionFilter: 'Version', nodeFilter: 'Node', syncFilter: 'Sync' };
            const arrowIcon = '<svg class="icon"><use href="#icon-nav-arrow-down"/></svg>';
            if (values.length === 0) {
                btn.innerHTML = labels[filterId] + ' ' + arrowIcon;
            } else {
                btn.innerHTML = labels[filterId] + ' <span class="filter-badge">' + values.length + '</span> ' + arrowIcon;
            }
        }

        function clearFilter(filterId) {
            const dropdown = document.getElementById(filterId + 'Dropdown');
            dropdown.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
            updateFilterButton(filterId);
            currentPage = 1;  // Reset to first page
            renderAgents();
        }

        function onFilterChange() {
            ['statusFilter', 'groupFilter', 'osFilter', 'versionFilter', 'nodeFilter', 'syncFilter'].forEach(updateFilterButton);
            currentPage = 1;  // Reset to first page
            renderAgents();
        }

        function toggleCheckbox(item, event) {
            // Don't toggle if clicking directly on checkbox (it handles itself)
            if (event && event.target.type === 'checkbox') return;
            const cb = item.querySelector('input[type="checkbox"]');
            if (cb) {
                cb.checked = !cb.checked;
                onFilterChange();
            }
        }

        // Close dropdowns when clicking outside
        document.addEventListener('click', (e) => {
            if (!e.target.closest('.multi-select')) {
                document.querySelectorAll('.multi-select-dropdown').forEach(d => d.classList.remove('show'));
                document.querySelectorAll('.multi-select-btn').forEach(b => b.classList.remove('active'));
            }
            if (!e.target.closest('.export-dropdown')) {
                const exportMenu = document.getElementById('exportMenu');
                if (exportMenu) exportMenu.classList.remove('show');
            }
        });

        function renderAgents() {
            const search = document.getElementById('agentSearch').value.toLowerCase();
            const statusValues = getFilterValues('statusFilter');
            const groupValues = getFilterValues('groupFilter');
            const osValues = getFilterValues('osFilter');
            const versionValues = getFilterValues('versionFilter');
            const nodeValues = getFilterValues('nodeFilter');
            const syncValues = getFilterValues('syncFilter');

            let filtered = agents.filter(a => {
                // Search all columns
                if (search) {
                    const searchFields = [
                        a.id, a.name, a.ip, a.status, a.os, a.version, a.group, a.node_name, a.synced
                    ].map(f => (f || '').toLowerCase());
                    if (!searchFields.some(f => f.includes(search))) return false;
                }
                if (statusValues.length > 0 && !statusValues.includes(a.status.toLowerCase().replace(' ', '_'))) return false;
                // Group can be comma-separated list, check if any selected group matches
                if (groupValues.length > 0) {
                    const agentGroups = (a.group || '').split(',').map(g => g.trim()).filter(g => g);
                    // Handle "(no group)" filter
                    const hasNoGroup = !a.group || a.group.trim() === '';
                    const matchesNoGroup = groupValues.includes('(no group)') && hasNoGroup;
                    const matchesGroup = groupValues.some(g => g !== '(no group)' && agentGroups.includes(g));
                    if (!matchesNoGroup && !matchesGroup) return false;
                }
                if (osValues.length > 0 && !osValues.includes(a.os || '')) return false;
                if (versionValues.length > 0 && !versionValues.includes(a.version || '')) return false;
                if (nodeValues.length > 0 && !nodeValues.includes(a.node_name || '')) return false;
                if (syncValues.length > 0 && !syncValues.includes(a.synced || 'unknown')) return false;
                return true;
            });

            // Apply sorting
            filtered.sort((a, b) => {
                let valA = a[sortColumn] || '';
                let valB = b[sortColumn] || '';

                // Handle numeric sorting for ID and queue_size
                if (sortColumn === 'id' || sortColumn === 'queue_size') {
                    valA = parseInt(valA) || 0;
                    valB = parseInt(valB) || 0;
                    if (valA < valB) return sortDirection === 'asc' ? -1 : 1;
                    if (valA > valB) return sortDirection === 'asc' ? 1 : -1;
                    return 0;
                }
                // Handle version sorting using semantic version comparison
                else if (sortColumn === 'version') {
                    const cmp = compareVersions(valA, valB);
                    return sortDirection === 'asc' ? cmp : -cmp;
                }
                // Default string sorting
                else {
                    valA = String(valA).toLowerCase();
                    valB = String(valB).toLowerCase();
                    if (valA < valB) return sortDirection === 'asc' ? -1 : 1;
                    if (valA > valB) return sortDirection === 'asc' ? 1 : -1;
                    return 0;
                }
            });

            // Pagination
            const totalFiltered = filtered.length;
            const totalPages = Math.ceil(totalFiltered / pageSize) || 1;

            // Ensure currentPage is valid
            if (currentPage > totalPages) currentPage = totalPages;
            if (currentPage < 1) currentPage = 1;

            const startIndex = (currentPage - 1) * pageSize;
            const endIndex = Math.min(startIndex + pageSize, totalFiltered);
            const paged = filtered.slice(startIndex, endIndex);

            // Update pagination UI
            updatePaginationUI(startIndex, endIndex, totalFiltered, totalPages);

            const body = document.getElementById('agentsBody');
            // Helper to conditionally show/hide column
            const colStyle = (col) => visibleColumns[col] === false ? 'display:none' : '';

            body.innerHTML = paged.map(a => `
                <tr>
                    <td class="checkbox-cell"><input type="checkbox" value="${escapeHtml(a.id)}" onchange="toggleAgent('${escapeHtml(a.id)}')" ${selectedAgents.has(a.id) ? 'checked' : ''}></td>
                    <td><button class="btn btn-sm btn-icon" onclick="showAgentDetails('${escapeHtml(a.id)}')" title="View Details"><svg class="icon"><use href="#icon-search"/></svg></button></td>
                    <td style="${colStyle('id')}">${escapeHtml(a.id)}</td>
                    <td style="${colStyle('name')}; max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(a.name)}">${escapeHtml(a.name)}</td>
                    <td style="${colStyle('ip')}; white-space: nowrap;">${escapeHtml(a.ip)}</td>
                    <td style="${colStyle('status')}"><span class="status status-${getStatusClass(a.status)}">${escapeHtml(a.status)}</span></td>
                    <td style="${colStyle('os')}; white-space: nowrap;">${escapeHtml(a.os) || '-'}</td>
                    <td style="${colStyle('version')}">${formatAgentVersion(a.version)}</td>
                    <td style="${colStyle('group')}; max-width: 200px; max-height: 32px; overflow: hidden; line-height: 16px;" title="${escapeHtml(a.group)}">${formatGroupLabels(a.group)}</td>
                    <td style="${colStyle('node_name')}">${formatNodeName(a.node_name)}</td>
                    <td style="${colStyle('synced')}"><span class="sync-status sync-${a.synced === 'synced' ? 'ok' : (a.synced === 'not synced' ? 'pending' : 'unknown')}">${escapeHtml(a.synced) || '-'}</span></td>
                    <td class="queue-db-cell" style="display:${showQueueDB ? '' : 'none'}">${formatQueueSize(a)}</td>
                </tr>
            `).join('');
        }

        // Pagination functions
        function updatePaginationUI(start, end, total, totalPages) {
            document.getElementById('paginationInfo').textContent =
                total > 0 ? `Showing ${start + 1} - ${end} of ${total}` : 'No results';
            document.getElementById('totalPages').textContent = totalPages;
            document.getElementById('pageInput').value = currentPage;
            document.getElementById('pageInput').max = totalPages;

            // Enable/disable buttons
            document.getElementById('btnFirstPage').disabled = currentPage <= 1;
            document.getElementById('btnPrevPage').disabled = currentPage <= 1;
            document.getElementById('btnNextPage').disabled = currentPage >= totalPages;
            document.getElementById('btnLastPage').disabled = currentPage >= totalPages;
        }

        function changePageSize(newSize) {
            pageSize = parseInt(newSize);
            currentPage = 1;  // Reset to first page
            renderAgents();
        }

        function goToPage(page) {
            currentPage = parseInt(page);
            renderAgents();
        }

        function prevPage() {
            if (currentPage > 1) {
                currentPage--;
                renderAgents();
            }
        }

        function nextPage() {
            currentPage++;
            renderAgents();
        }

        async function showAgentDetails(agentId) {
            showModal('Agent Details', '<div class="loading"><div class="spinner"></div>Loading...</div>', '');

            try {
                const data = await api(`/agents/${agentId}`);
                if (!data || data.error) {
                    document.getElementById('modalBody').innerHTML = '<div class="alert alert-error">' + ((data && data.error) || 'Failed to load agent details') + '</div>';
                    return;
                }

                const a = data.agent || {};
                const formatDate = (d) => {
                    if (!d) return '-';
                    // Handle Unix timestamp (seconds) - if number is small enough to be seconds
                    if (typeof d === 'number' && d < 9999999999) {
                        d = d * 1000;  // Convert to milliseconds
                    }
                    const date = new Date(d);
                    // Check if valid date
                    if (isNaN(date.getTime())) return '-';
                    // Use 24-hour format
                    return date.toLocaleString('zh-TW', { hour12: false });
                };
                const formatBytes = (b) => {
                    if (!b) return '-';
                    const units = ['B', 'KB', 'MB', 'GB'];
                    let i = 0;
                    while (b >= 1024 && i < units.length - 1) { b /= 1024; i++; }
                    return b.toFixed(1) + ' ' + units[i];
                };

                // Format queue DB sizes for modal (may have multiple nodes)
                const queueEntries = queueSizes[a.id] || [];
                let queueSizeDisplay = '-';
                if (queueEntries.length === 1) {
                    queueSizeDisplay = `${formatBytes(queueEntries[0].size)} <span style="color:#888;font-size:11px">(on ${queueEntries[0].node})</span>`;
                } else if (queueEntries.length > 1) {
                    queueSizeDisplay = queueEntries.map(e =>
                        `${formatBytes(e.size)} <span style="color:#888;font-size:11px">(on ${e.node})</span>`
                    ).join('<br>');
                }

                const html = `
                    <table style="width:100%">
                        <tr><td style="color:#aaa;width:40%">ID</td><td><strong>${a.id || '-'}</strong></td></tr>
                        <tr><td style="color:#aaa">Name</td><td><strong>${a.name || '-'}</strong></td></tr>
                        <tr><td style="color:#aaa">IP</td><td>${a.ip || '-'}</td></tr>
                        <tr><td style="color:#aaa">Status</td><td><span class="status status-${getStatusClass(a.status || '')}">${a.status || '-'}</span></td></tr>
                        <tr><td style="color:#aaa">Manager</td><td>${a.manager || '-'}</td></tr>
                        <tr><td style="color:#aaa">Node</td><td>${a.node_name || '-'}</td></tr>
                        <tr><td style="color:#aaa">Version</td><td>${a.version || '-'}</td></tr>
                        <tr><td style="color:#aaa">OS</td><td>${(a.os && a.os.name) || (a.os && a.os.platform) || '-'} ${(a.os && a.os.version) || ''}</td></tr>
                        <tr><td style="color:#aaa">OS Architecture</td><td>${(a.os && a.os.arch) || '-'}</td></tr>
                        <tr><td style="color:#aaa">Groups</td><td>${(a.group || []).join(', ') || '-'}</td></tr>
                        <tr><td style="color:#aaa">Registration Date</td><td>${formatDate(a.dateAdd)}</td></tr>
                        <tr><td style="color:#aaa">Last Keep Alive</td><td>${formatDate(a.lastKeepAlive)}</td></tr>
                        <tr><td style="color:#aaa">Queue DB Size</td><td>${queueSizeDisplay}</td></tr>
                        <tr><td style="color:#aaa">Config Sum</td><td style="font-family:monospace;font-size:11px">${a.configSum || '-'}</td></tr>
                        <tr><td style="color:#aaa">Merged Sum</td><td style="font-family:monospace;font-size:11px">${a.mergedSum || '-'}</td></tr>
                    </table>
                `;

                document.getElementById('modalBody').innerHTML = html;
                document.getElementById('modalFooter').innerHTML = '';
            } catch (e) {
                document.getElementById('modalBody').innerHTML = `<div class="alert alert-error">Error: ${e.message}</div>`;
            }
        }

        function getStatusClass(status) {
            status = status.toLowerCase();
            if (status.includes('active')) return 'active';
            if (status.includes('disconnected')) return 'disconnected';
            if (status.includes('pending')) return 'pending';
            return 'never';
        }

        function sortAgents(column) {
            // Toggle direction if same column
            if (sortColumn === column) {
                sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
            } else {
                sortColumn = column;
                sortDirection = 'asc';
            }

            // Update header styles
            document.querySelectorAll('th.sortable').forEach(th => {
                th.classList.remove('asc', 'desc');
                if (th.dataset.sort === column) {
                    th.classList.add(sortDirection);
                }
            });

            renderAgents();
        }

        function toggleAgent(id) {
            if (selectedAgents.has(id)) selectedAgents.delete(id);
            else selectedAgents.add(id);
            updateSelectedUI();
        }

        function toggleSelectAll() {
            const checked = document.getElementById('selectAll').checked;
            document.querySelectorAll('#agentsBody input[type="checkbox"]').forEach(cb => {
                cb.checked = checked;
                if (checked) selectedAgents.add(cb.value);
                else selectedAgents.delete(cb.value);
            });
            updateSelectedUI();
        }

        function updateSelectedUI() {
            const count = selectedAgents.size;
            const actionBar = document.getElementById('actionBar');
            const countEl = document.getElementById('selectedCount');

            if (count > 0) {
                actionBar.classList.add('visible');
            } else {
                actionBar.classList.remove('visible');
            }
            countEl.querySelector('span').textContent = count;
        }

        async function updateStats() {
            // Always calculate from loaded agents for accuracy
            updateStatsFromAgents();
        }

        function updateStatValue(elementId, newValue) {
            const el = document.getElementById(elementId);
            const span = el.querySelector('span');
            const currentValue = span.textContent;

            if (currentValue !== String(newValue)) {
                // Value changed, animate
                span.classList.remove('slide-in');
                void span.offsetWidth; // Trigger reflow to restart animation
                span.textContent = newValue;
                span.classList.add('slide-in');
            }
        }

        function updateStatsFromAgents() {
            // Calculate stats from loaded agents
            if (!agents || agents.length === 0) {
                updateStatValue('totalAgents', '0');
                updateStatValue('activeAgents', '0');
                updateStatValue('disconnectedAgents', '0');
                updateStatValue('pendingAgents', '0');
                return;
            }

            const total = agents.length;
            const active = agents.filter(a => a.status && a.status.toLowerCase() === 'active').length;
            const disconnected = agents.filter(a => a.status && a.status.toLowerCase() === 'disconnected').length;
            const pending = agents.filter(a => a.status && a.status.toLowerCase() === 'pending').length;

            updateStatValue('totalAgents', total);
            updateStatValue('activeAgents', active);
            updateStatValue('disconnectedAgents', disconnected);
            updateStatValue('pendingAgents', pending);

            // Update distribution bar
            updateDistributionBar();
        }

        // Distribution bar colors (dark colors for white text readability)
        const distributionColors = {
            status: { 'active': '#2e7d32', 'disconnected': '#c62828', 'pending': '#f57c00', 'never_connected': '#616161' },
            os: ['#1565c0', '#7b1fa2', '#c62828', '#2e7d32', '#ad1457', '#00838f', '#558b2f', '#d84315', '#4527a0', '#00695c'],
            version: ['#1565c0', '#2e7d32', '#ef6c00', '#c62828', '#6a1b9a', '#00838f', '#558b2f', '#d84315'],
            group: ['#1565c0', '#2e7d32', '#ef6c00', '#c62828', '#6a1b9a', '#00838f', '#558b2f', '#d84315', '#4527a0', '#00695c'],
            node: ['#303f9f', '#00695c', '#9e9d24', '#d84315', '#5d4037'],
            sync: { 'synced': '#2e7d32', 'not synced': '#ef6c00', 'unknown': '#616161' }
        };

        // Simplify OS name for display
        function simplifyOsName(os) {
            if (!os) return 'Unknown';
            const osLower = os.toLowerCase();
            if (osLower.includes('ubuntu')) return 'Ubuntu';
            if (osLower.includes('debian')) return 'Debian';
            if (osLower.includes('centos')) return 'CentOS';
            if (osLower.includes('red hat') || osLower.includes('rhel')) return 'RHEL';
            if (osLower.includes('rocky')) return 'Rocky';
            if (osLower.includes('alma')) return 'AlmaLinux';
            if (osLower.includes('fedora')) return 'Fedora';
            if (osLower.includes('suse') || osLower.includes('sles')) return 'SUSE';
            if (osLower.includes('oracle')) return 'Oracle Linux';
            if (osLower.includes('amazon')) return 'Amazon Linux';
            if (osLower.includes('windows server')) return 'Windows Server';
            if (osLower.includes('windows 11')) return 'Windows 11';
            if (osLower.includes('windows 10')) return 'Windows 10';
            if (osLower.includes('windows')) return 'Windows';
            if (osLower.includes('macos') || osLower.includes('mac os')) return 'macOS';
            if (osLower.includes('freebsd') || osLower.includes('bsd')) return 'BSD';
            if (osLower.includes('arch')) return 'Arch';
            if (osLower.includes('gentoo')) return 'Gentoo';
            if (osLower.includes('alpine')) return 'Alpine';
            if (osLower.includes('proxmox')) return 'Proxmox';
            if (osLower.includes('univention')) return 'Univention';
            // Return first word or truncated name
            const parts = os.split(' ');
            return parts[0].length > 15 ? parts[0].substring(0, 12) + '...' : parts[0];
        }

        function updateDistributionBar(animate = false) {
            const chart = document.getElementById('distributionChart');
            const type = document.getElementById('distributionType').value;

            if (animate) {
                chart.classList.remove('animating');
                void chart.offsetWidth; // Trigger reflow
                chart.classList.add('animating');
            } else {
                chart.classList.remove('animating');
            }

            if (!agents || agents.length === 0) {
                chart.innerHTML = '<div style="color:#666;padding:0 10px;font-size:11px;">No data</div>';
                return;
            }

            // Calculate distribution based on type
            const counts = {};
            agents.forEach(a => {
                let key;
                switch(type) {
                    case 'status':
                        key = (a.status || 'unknown').toLowerCase();
                        break;
                    case 'os':
                        key = simplifyOsName(a.os);
                        break;
                    case 'version':
                        key = a.version || 'Unknown';
                        break;
                    case 'group':
                        // Count each group separately (agent can be in multiple groups)
                        const groups = (a.group || '').split(',').map(g => g.trim()).filter(g => g);
                        if (groups.length === 0) {
                            key = '(no group)';
                            counts[key] = (counts[key] || 0) + 1;
                        } else {
                            groups.forEach(g => { counts[g] = (counts[g] || 0) + 1; });
                        }
                        return; // Already counted
                    case 'node':
                        key = a.node_name || 'Unknown';
                        break;
                    case 'sync':
                        key = a.synced || 'unknown';
                        break;
                    default:
                        key = 'unknown';
                }
                counts[key] = (counts[key] || 0) + 1;
            });

            // Sort by count descending
            const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
            const total = agents.length;

            // Build chart segments
            let chartHtml = '';
            const colorMap = distributionColors[type];

            sorted.forEach(([name, count], index) => {
                const pct = (count / total * 100);
                const color = typeof colorMap === 'object' && !Array.isArray(colorMap)
                    ? (colorMap[name] || colorMap[name.replace(' ', '_')] || '#666')
                    : colorMap[index % colorMap.length];

                // Always show label, CSS will truncate if too long
                const label = `<span>${name} (${count})</span>`;
                chartHtml += `<div class="distribution-segment" style="width:${pct}%;background:${color}" title="${name}: ${count} (${pct.toFixed(1)}%)" onclick="filterByDistribution('${type}','${escapeHtml(name)}')">${label}</div>`;
            });

            chart.innerHTML = chartHtml;
        }

        function filterByDistribution(type, value) {
            // Clear all filters first
            ['statusFilter', 'groupFilter', 'osFilter', 'versionFilter', 'nodeFilter', 'syncFilter'].forEach(filterId => {
                const dropdown = document.getElementById(filterId + 'Dropdown');
                if (dropdown) dropdown.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
            });

            // Apply the selected filter
            let filterId;
            switch(type) {
                case 'status': filterId = 'statusFilter'; break;
                case 'os': filterId = 'osFilter'; break;
                case 'version': filterId = 'versionFilter'; break;
                case 'group': filterId = 'groupFilter'; break;
                case 'node': filterId = 'nodeFilter'; break;
                case 'sync': filterId = 'syncFilter'; break;
            }

            if (filterId) {
                const dropdown = document.getElementById(filterId + 'Dropdown');
                if (dropdown) {
                    // For OS, we need to match simplified name to full name
                    if (type === 'os') {
                        dropdown.querySelectorAll('input[type="checkbox"]').forEach(cb => {
                            if (simplifyOsName(cb.value) === value) cb.checked = true;
                        });
                    } else {
                        dropdown.querySelectorAll('input[type="checkbox"]').forEach(cb => {
                            if (cb.value === value || cb.value.toLowerCase() === value.toLowerCase()) cb.checked = true;
                        });
                    }
                }
            }

            // Update filter buttons and render
            ['statusFilter', 'groupFilter', 'osFilter', 'versionFilter', 'nodeFilter', 'syncFilter'].forEach(updateFilterButton);
            document.getElementById('agentSearch').value = '';
            currentPage = 1;
            renderAgents();
        }

        function filterByStatus(status) {
            // Switch to Agents tab
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
            document.querySelector('[data-tab="agents"]').classList.add('active');
            document.getElementById('agents-panel').classList.add('active');

            // Clear all filters
            ['statusFilter', 'groupFilter', 'osFilter', 'versionFilter', 'nodeFilter', 'syncFilter'].forEach(filterId => {
                const dropdown = document.getElementById(filterId + 'Dropdown');
                if (dropdown) {
                    dropdown.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
                }
            });

            // Set the status filter if provided
            if (status) {
                const statusDropdown = document.getElementById('statusFilterDropdown');
                statusDropdown.querySelectorAll('input[type="checkbox"]').forEach(cb => {
                    if (cb.value === status) cb.checked = true;
                });
            }

            // Update all filter buttons and render
            ['statusFilter', 'groupFilter', 'osFilter', 'versionFilter', 'nodeFilter', 'syncFilter'].forEach(updateFilterButton);
            document.getElementById('agentSearch').value = '';
            currentPage = 1;  // Reset to first page
            renderAgents();
        }

        function filterByNode(nodeName) {
            // Switch to Agents tab
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
            document.querySelector('[data-tab="agents"]').classList.add('active');
            document.getElementById('agents-panel').classList.add('active');

            // Clear all filters
            ['statusFilter', 'groupFilter', 'osFilter', 'versionFilter', 'nodeFilter', 'syncFilter'].forEach(filterId => {
                const dropdown = document.getElementById(filterId + 'Dropdown');
                if (dropdown) {
                    dropdown.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
                }
            });

            // Set the node filter if provided
            if (nodeName) {
                const nodeDropdown = document.getElementById('nodeFilterDropdown');
                nodeDropdown.querySelectorAll('input[type="checkbox"]').forEach(cb => {
                    if (cb.value === nodeName) cb.checked = true;
                });
            }

            // Update all filter buttons and render
            ['statusFilter', 'groupFilter', 'osFilter', 'versionFilter', 'nodeFilter', 'syncFilter'].forEach(updateFilterButton);
            document.getElementById('agentSearch').value = '';
            currentPage = 1;  // Reset to first page
            renderAgents();
        }

        function updateFilterOptions() {
            // Save current filter selections before rebuilding
            const savedFilters = {};
            ['groupFilter', 'osFilter', 'versionFilter', 'nodeFilter', 'syncFilter'].forEach(filterId => {
                savedFilters[filterId] = getFilterValues(filterId);
            });

            // Get unique values for each filter
            const groupSet = new Set();
            const osSet = new Set();
            const versionSet = new Set();
            const nodeSet = new Set();
            const syncSet = new Set();

            agents.forEach(a => {
                // Split groups
                if (a.group) {
                    a.group.split(',').forEach(g => groupSet.add(g.trim()));
                } else {
                    groupSet.add('(no group)');
                }
                if (a.os) osSet.add(a.os);
                if (a.version) versionSet.add(a.version);
                if (a.node_name) nodeSet.add(a.node_name);
                // Add sync status (handle empty as 'unknown')
                const syncVal = a.synced || 'unknown';
                syncSet.add(syncVal);
            });

            // Ensure common sync statuses are always available
            syncSet.add('synced');
            syncSet.add('not synced');

            // Helper to create dropdown items with preserved selections
            const createItems = (values, filterId, sortFn = null) => {
                const sorted = sortFn ? [...values].sort(sortFn) : [...values].sort();
                const savedValues = savedFilters[filterId] || [];
                return sorted.map(v => {
                    const isChecked = savedValues.includes(v) ? ' checked' : '';
                    return `<div class="multi-select-item" onclick="toggleCheckbox(this, event)"><input type="checkbox" value="${v}"${isChecked} onchange="onFilterChange()"><span class="multi-select-item-text">${v}</span></div>`;
                }).join('') + `<div class="multi-select-clear" onclick="clearFilter('${filterId}')">Clear</div>`;
            };

            // Version sort function (high to low)
            const versionSort = (a, b) => {
                // Extract version numbers (e.g., "Wazuh v4.14.0" -> [4, 14, 0])
                const parseVersion = (v) => {
                    const match = v.match(/(\\d+)\\.(\\d+)\\.(\\d+)/);
                    return match ? [parseInt(match[1]), parseInt(match[2]), parseInt(match[3])] : [0, 0, 0];
                };
                const va = parseVersion(a);
                const vb = parseVersion(b);
                // Sort descending (high to low)
                for (let i = 0; i < 3; i++) {
                    if (vb[i] !== va[i]) return vb[i] - va[i];
                }
                return 0;
            };

            // Update Group filter
            document.getElementById('groupFilterDropdown').innerHTML = createItems(groupSet, 'groupFilter');

            // Update OS filter
            document.getElementById('osFilterDropdown').innerHTML = createItems(osSet, 'osFilter');

            // Update Version filter (sorted high to low)
            document.getElementById('versionFilterDropdown').innerHTML = createItems(versionSet, 'versionFilter', versionSort);

            // Update Node filter
            document.getElementById('nodeFilterDropdown').innerHTML = createItems(nodeSet, 'nodeFilter');

            // Update Sync filter
            document.getElementById('syncFilterDropdown').innerHTML = createItems(syncSet, 'syncFilter');

            // Update filter button labels to reflect restored selections
            ['statusFilter', 'groupFilter', 'osFilter', 'versionFilter', 'nodeFilter', 'syncFilter'].forEach(updateFilterButton);
        }

        // Groups
        async function refreshGroups() {
            const body = document.getElementById('groupsBody');
            body.innerHTML = '<tr><td colspan="4" class="loading"><div class="spinner"></div>Loading...</td></tr>';

            try {
                const data = await api('/groups');
                if (!data) return;
                groups = data.groups || [];
                renderGroups();
            } catch (err) {
                if (err.message === 'BACKEND_UNAVAILABLE') {
                    body.innerHTML = `<tr><td colspan="4">${getConnectionErrorHtml('refreshGroups()')}</td></tr>`;
                } else {
                    body.innerHTML = `<tr><td colspan="4" class="loading" style="color:#e94560;">Error loading groups: ${escapeHtml(err.message)}</td></tr>`;
                }
            }
        }

        function sortGroups(column) {
            // Toggle direction if same column
            if (groupSortColumn === column) {
                groupSortDirection = groupSortDirection === 'asc' ? 'desc' : 'asc';
            } else {
                groupSortColumn = column;
                groupSortDirection = 'asc';
            }

            // Update header styles
            document.querySelectorAll('#groupsTable th.sortable').forEach(th => {
                th.classList.remove('asc', 'desc');
                if (th.dataset.sort === column) {
                    th.classList.add(groupSortDirection);
                }
            });

            renderGroups();
        }

        function renderGroups() {
            const body = document.getElementById('groupsBody');

            // Sort groups
            const sorted = [...groups].sort((a, b) => {
                let valA, valB;
                if (groupSortColumn === 'count') {
                    valA = a.count || 0;
                    valB = b.count || 0;
                } else {
                    valA = (a.name || '').toLowerCase();
                    valB = (b.name || '').toLowerCase();
                }
                if (valA < valB) return groupSortDirection === 'asc' ? -1 : 1;
                if (valA > valB) return groupSortDirection === 'asc' ? 1 : -1;
                return 0;
            });

            body.innerHTML = sorted.map(g => {
                const safeName = escapeHtml(g.name);
                const jsName = g.name.replace(/'/g, "\\'").replace(/"/g, '\\"');
                return `
                <tr>
                    <td>${safeName}</td>
                    <td style="text-align:center"><a href="#" onclick="showGroupAgents('${jsName}');return false;" style="color:#4fc3f7;text-decoration:none;cursor:pointer;" title="View agents in this group">${g.count || 0}</a></td>
                    <td>
                        <div class="btn-wrap">
                            <button class="btn btn-sm btn-success" onclick="showImportCsvModal('${jsName}')"><svg class="icon"><use href="#icon-upload"/></svg>Import CSV</button>
                            <button class="btn btn-sm" style="background:#17a2b8;color:#fff;" onclick="exportGroupAgentsCsv('${jsName}')" ${g.count ? '' : 'disabled'}><svg class="icon"><use href="#icon-download"/></svg>Export CSV</button>
                            <button class="btn btn-sm btn-warning" onclick="showMoveGroupAgentsModal('${jsName}')" ${g.count ? '' : 'disabled'}><svg class="icon"><use href="#icon-move"/></svg>Move Agents</button>
                            <button class="btn btn-sm" style="background:#9c27b0;" onclick="setExclusiveGroup('${jsName}')" ${g.count ? '' : 'disabled'}><svg class="icon"><use href="#icon-exclusive"/></svg>Only This</button>
                            <button class="btn btn-sm btn-danger" onclick="removeAllFromGroup('${jsName}')" ${g.count ? '' : 'disabled'}><svg class="icon"><use href="#icon-remove"/></svg>Remove All</button>
                        </div>
                    </td>
                    <td>
                        <div class="btn-wrap">
                            <button class="btn btn-sm btn-primary" onclick="showGroupAgentConfModal('${jsName}')"><svg class="icon"><use href="#icon-file-code"/></svg>agent.conf</button>
                            <button class="btn btn-sm" style="background:#6f42c1;color:#fff;" onclick="showRenameGroupModal('${jsName}')"><svg class="icon"><use href="#icon-rename"/></svg>Rename</button>
                            <button class="btn btn-sm btn-danger" onclick="deleteGroup('${jsName}')"><svg class="icon"><use href="#icon-trash"/></svg>Delete</button>
                        </div>
                    </td>
                </tr>
            `;}).join('');
        }

        // Nodes
        let nodeServices = {};  // Store service status per node

        let nodeSyncStatus = {};  // Store sync status per node
        let syncStatusLoading = false;  // Track if sync status is being loaded
        let nodeArchives = {};  // Store archives file info per node

        async function refreshNodes() {
            const body = document.getElementById('nodesBody');

            // Clear cached data to force fresh load
            nodeServices = {};
            nodeSyncStatus = {};
            nodeArchives = {};

            // Step 1: Load nodes
            body.innerHTML = '<tr><td colspan="9" class="loading"><div class="spinner"></div>Loading nodes...</td></tr>';

            try {
                const nodesData = await api('/nodes');

                if (!nodesData) return;
                const nodes = nodesData.nodes || [];

                // Store valid node names for use in agent table
                validNodeNames = nodes.map(n => n.name);

                if (nodes.length === 0) {
                    body.innerHTML = '<tr><td colspan="9" class="loading">Cluster not configured or not running</td></tr>';
                    return;
                }

                // Render nodes first (without services/sync)
                renderNodes(nodes);

                // Step 2: Load services in background
                body.querySelector('.loading-status')?.remove();
                const loadingRow = document.createElement('tr');
                loadingRow.className = 'loading-status-row';
                loadingRow.innerHTML = '<td colspan="9" style="padding:8px;color:#888;font-size:12px;text-align:center;"><span class="icon-spin" style="display:inline-block;margin-right:6px;">⟳</span>Loading services...</td>';
                body.appendChild(loadingRow);

                const servicesData = await api('/nodes/services');
                if (servicesData && !servicesData.error) {
                    nodeServices = servicesData.services || {};
                    renderNodes(nodes);
                }

                // Step 3: Load sync status
                loadingRow.innerHTML = '<td colspan="9" style="padding:8px;color:#888;font-size:12px;text-align:center;"><span class="icon-spin" style="display:inline-block;margin-right:6px;">⟳</span>Loading sync status...</td>';
                syncStatusLoading = true;
                renderNodes(nodes);  // Re-render to show loading indicator

                const syncData = await api('/nodes/sync-status');
                syncStatusLoading = false;
                if (syncData && !syncData.error) {
                    nodeSyncStatus = syncData.sync_status || {};
                }
                renderNodes(nodes);

                // Step 4: Load logs info (archives and alerts) for each node (in parallel)
                loadingRow.innerHTML = '<td colspan="9" style="padding:8px;color:#888;font-size:12px;text-align:center;"><span class="icon-spin" style="display:inline-block;margin-right:6px;">⟳</span>Loading logs info...</td>';

                const logsPromises = nodes.map(n =>
                    api('/nodes/' + encodeURIComponent(n.name) + '/logs-info')
                        .then(data => {
                            if (data && !data.error) {
                                nodeArchives[n.name] = data.files || {};
                            }
                        })
                        .catch(() => {})
                );
                await Promise.all(logsPromises);
                renderNodes(nodes);

                // Remove loading row
                body.querySelector('.loading-status-row')?.remove();
            } catch (err) {
                if (err.message === 'BACKEND_UNAVAILABLE') {
                    body.innerHTML = `<tr><td colspan="9">${getConnectionErrorHtml('refreshNodes()')}</td></tr>`;
                } else {
                    body.innerHTML = `<tr><td colspan="9" class="loading" style="color:#e94560;">Error loading nodes: ${escapeHtml(err.message)}</td></tr>`;
                }
            }
        }

        function renderNodes(nodes) {
            const body = document.getElementById('nodesBody');
            body.innerHTML = nodes.map(n => {
                const safeName = escapeHtml(n.name);
                const jsName = n.name.replace(/'/g, "\\'").replace(/"/g, '\\"');
                const services = nodeServices[n.name] || null;
                let servicesHtml = '<span style="color:#888">-</span>';
                if (services) {
                    servicesHtml = '<div class="service-status">' + services.map(s =>
                        `<span class="service-indicator"><span class="dot ${escapeHtml(s.status)}"></span>${escapeHtml(s.name)}</span>`
                    ).join('') + '</div>';
                }

                // Sync status (only for worker nodes)
                let syncHtml = '<span style="color:#888">-</span>';
                if (n.type === 'worker') {
                    const sync = nodeSyncStatus[n.name];
                    if (sync && sync.length > 0) {
                        syncHtml = '<div class="service-status">' + sync.map(s => {
                            const statusClass = s.status === 'synced' ? 'running' :
                                               s.status === 'in_progress' ? 'pending' :
                                               s.status === 'unknown' ? 'unknown' : 'stopped';
                            const clickable = s.status !== 'unknown' ? `onclick="showSyncDetail('${jsName}', '${escapeHtml(s.name)}', '${escapeHtml(s.path)}')"` : '';
                            return `<span class="service-indicator sync-item" title="${escapeHtml(s.path)}" ${clickable}><span class="dot ${statusClass}"></span>${escapeHtml(s.name)}</span>`;
                        }).join('') + '</div>';
                    } else if (syncStatusLoading) {
                        // Show loading indicator while sync status is being fetched
                        syncHtml = '<span style="color:#888;font-size:12px;"><span class="icon-spin" style="display:inline-block;margin-right:4px;">⟳</span>Loading...</span>';
                    } else {
                        syncHtml = '<span style="color:#888">-</span>';
                    }
                } else {
                    // Master node - show as reference source with blue indicators
                    const syncItems = ['Rules', 'Decoders', 'Groups', 'Keys', 'Lists', 'SCA'];
                    syncHtml = '<div class="service-status">' + syncItems.map(item =>
                        `<span class="service-indicator sync-source" title="Reference source"><span class="dot source"></span>${item}</span>`
                    ).join('') + '</div>';
                }

                // Only show cluster.key download for master node
                const clusterKeyBtn = n.type === 'master' ?
                    `<button class="btn btn-sm" style="background:#6f42c1;color:#fff;" onclick="downloadFile('${jsName}', 'cluster-key')" title="Download cluster.key for worker nodes"><svg class="icon"><use href="#icon-download"/></svg>cluster.key</button>` : '';

                // Log viewer buttons - only show if file exists
                const logs = nodeArchives[n.name] || {};
                // Archives buttons
                const archivesLogBtn = logs.archives_log && logs.archives_log.exists ?
                    `<button class="btn btn-sm" style="background:#20c997;color:#fff;" onclick="showLogViewerModal('${jsName}', 'archives', 'log')" title="View archives.log (${formatFileSize(logs.archives_log.size)})"><svg class="icon"><use href="#icon-file-text"/></svg>archives.log</button>` : '';
                const archivesJsonBtn = logs.archives_json && logs.archives_json.exists ?
                    `<button class="btn btn-sm" style="background:#17a2b8;color:#fff;" onclick="showLogViewerModal('${jsName}', 'archives', 'json')" title="View archives.json (${formatFileSize(logs.archives_json.size)})"><svg class="icon"><use href="#icon-file-code"/></svg>archives.json</button>` : '';
                // Alerts buttons
                const alertsLogBtn = logs.alerts_log && logs.alerts_log.exists ?
                    `<button class="btn btn-sm" style="background:#e91e63;color:#fff;" onclick="showLogViewerModal('${jsName}', 'alerts', 'log')" title="View alerts.log (${formatFileSize(logs.alerts_log.size)})"><svg class="icon"><use href="#icon-bell"/></svg>alerts.log</button>` : '';
                const alertsJsonBtn = logs.alerts_json && logs.alerts_json.exists ?
                    `<button class="btn btn-sm" style="background:#9c27b0;color:#fff;" onclick="showLogViewerModal('${jsName}', 'alerts', 'json')" title="View alerts.json (${formatFileSize(logs.alerts_json.size)})"><svg class="icon"><use href="#icon-bell"/></svg>alerts.json</button>` : '';

                return `<tr>
                    <td>${safeName}${n.hostname ? `<br><span style="color:#888;">(${escapeHtml(n.hostname)})</span>` : ''}</td>
                    <td style="text-align:center"><span class="badge ${n.type === 'master' ? 'badge-master' : 'badge-worker'}">${escapeHtml(n.type)}</span></td>
                    <td style="text-align:center">${escapeHtml(n.version)}</td>
                    <td>${escapeHtml(n.ip)}</td>
                    <td style="text-align:center">${n.count ? `<a href="#" onclick="filterByNode('${jsName}'); return false;" style="color:#4fc3f7;text-decoration:none;font-weight:bold;" title="View agents on this node">${n.count}</a>` : "-"}</td>
                    <td>${servicesHtml}</td>
                    <td>${syncHtml}</td>
                    <td>
                        <div class="btn-wrap">
                            <button class="btn btn-sm btn-success" onclick="restartNodeServices('${jsName}')" title="Restart Wazuh Manager services on this node"><svg class="icon"><use href="#icon-restart"/></svg>Restart</button>
                            <button class="btn btn-sm btn-warning" onclick="reconnectNodeAgents('${jsName}')" title="Force all agents on this node to reconnect"><svg class="icon"><use href="#icon-link"/></svg>Reconnect</button>
                            <button class="btn btn-sm btn-primary" onclick="showConfigModal('${jsName}')" title="View/Edit ossec.conf configuration file"><svg class="icon"><use href="#icon-file-code"/></svg>ossec.conf</button>
                            ${archivesLogBtn}
                            ${archivesJsonBtn}
                            ${alertsLogBtn}
                            ${alertsJsonBtn}
                            ${clusterKeyBtn}
                            <button class="btn btn-sm" style="background:#fd7e14;color:#fff;" onclick="showUpgradeFiles('${jsName}')" title="Manage WPK upgrade files on this node"><svg class="icon"><use href="#icon-package"/></svg>WPK Files</button>
                        </div>
                    </td>
                </tr>`;
            }).join('');
        }

        // Show sync detail modal
        async function showSyncDetail(nodeName, itemName, itemPath) {
            showModal('Sync Detail: ' + itemName, '<div class="loading"><div class="spinner"></div>Loading comparison...</div>', '', true);

            try {
                const data = await api('/nodes/' + encodeURIComponent(nodeName) + '/sync-detail?item=' + encodeURIComponent(itemName) + '&path=' + encodeURIComponent(itemPath));

                if (!data || data.error) {
                    document.getElementById('modalBody').innerHTML = '<div class="alert alert-error">' + (data ? data.error : 'Failed to load') + '</div>';
                    return;
                }

                let statusBadge = '';
                if (data.status === 'synced') {
                    statusBadge = '<span style="background:#00c853;color:#fff;padding:4px 12px;border-radius:4px;font-weight:bold;">Synced</span>';
                } else if (data.status === 'not_synced') {
                    statusBadge = '<span style="background:#e94560;color:#fff;padding:4px 12px;border-radius:4px;font-weight:bold;">Not Synced</span>';
                } else {
                    statusBadge = '<span style="background:#888;color:#fff;padding:4px 12px;border-radius:4px;font-weight:bold;">Unknown</span>';
                }

                let html = `
                    <div style="margin-bottom:15px;">
                        <div style="display:flex;align-items:center;gap:15px;margin-bottom:10px;">
                            <strong style="font-size:16px;">${escapeHtml(itemName)}</strong>
                            ${statusBadge}
                        </div>
                        <div style="color:#888;font-size:13px;">
                            <strong>Path:</strong> <code style="background:#0f3460;padding:2px 6px;border-radius:3px;">${escapeHtml(itemPath)}</code>
                        </div>
                        <div style="color:#888;font-size:13px;margin-top:5px;">
                            <strong>Worker Node:</strong> ${escapeHtml(nodeName)}
                        </div>
                    </div>
                `;

                if (data.status === 'synced') {
                    html += '<div class="alert alert-success">All files are synchronized between master and worker.</div>';
                    if (data.file_count !== undefined) {
                        html += '<div style="color:#aaa;font-size:13px;">Total files: ' + data.file_count + '</div>';
                    }
                } else if (data.status === 'not_synced') {
                    html += '<div class="alert alert-warning" style="background:#ffc10722;border-color:#ffc107;">Files are different between master and worker.</div>';

                    if (data.master_only && data.master_only.length > 0) {
                        html += '<h4 style="margin:15px 0 10px;color:#4fc3f7;">Only on Master (' + data.master_only.length + ')</h4>';
                        html += '<div style="max-height:150px;overflow-y:auto;background:#0a0a1a;padding:10px;border-radius:4px;font-family:monospace;font-size:12px;">';
                        html += data.master_only.map(f => '<div style="color:#00c853;">+ ' + escapeHtml(f) + '</div>').join('');
                        html += '</div>';
                    }

                    if (data.worker_only && data.worker_only.length > 0) {
                        html += '<h4 style="margin:15px 0 10px;color:#4fc3f7;">Only on Worker (' + data.worker_only.length + ')</h4>';
                        html += '<div style="max-height:150px;overflow-y:auto;background:#0a0a1a;padding:10px;border-radius:4px;font-family:monospace;font-size:12px;">';
                        html += data.worker_only.map(f => '<div style="color:#e94560;">- ' + escapeHtml(f) + '</div>').join('');
                        html += '</div>';
                    }

                    if (data.different && data.different.length > 0) {
                        html += '<h4 style="margin:15px 0 10px;color:#4fc3f7;">Different Content (' + data.different.length + ')</h4>';
                        html += '<div style="max-height:150px;overflow-y:auto;background:#0a0a1a;padding:10px;border-radius:4px;font-family:monospace;font-size:12px;">';
                        html += data.different.map(f => '<div style="color:#ffc107;">~ ' + escapeHtml(f) + '</div>').join('');
                        html += '</div>';
                    }
                }

                document.getElementById('modalBody').innerHTML = html;
            } catch (err) {
                document.getElementById('modalBody').innerHTML = '<div class="alert alert-error">Error: ' + escapeHtml(err.message) + '</div>';
            }
        }

        // Stats
        let statsData = null;
        let statsSortState = {
            by_status: { col: 'count', dir: 'desc' },
            by_group: { col: 'count', dir: 'desc' },
            by_network: { col: 'name', dir: 'asc' },
            by_os: { col: 'name', dir: 'asc' },
            by_version: { col: 'name', dir: 'desc' }
        };

        function parseVersion(ver) {
            const match = (ver || '').match(/(\d+)\.(\d+)\.(\d+)/);
            if (match) return [parseInt(match[1]), parseInt(match[2]), parseInt(match[3])];
            return [0, 0, 0];
        }

        function compareVersions(a, b) {
            const va = parseVersion(a);
            const vb = parseVersion(b);
            for (let i = 0; i < 3; i++) {
                if (va[i] < vb[i]) return -1;
                if (va[i] > vb[i]) return 1;
            }
            return 0;
        }

        function sortStatsData(data, section, col, dir) {
            const arr = [...data];
            arr.sort((a, b) => {
                let va, vb, cmp;
                if (col === 'name') {
                    // Get the name field based on section
                    const nameKey = section === 'by_status' ? 'status' :
                                   section === 'by_group' ? 'group' :
                                   section === 'by_network' ? 'network' :
                                   section === 'by_os' ? 'os' : 'version';
                    // Use version comparison for by_version section
                    if (section === 'by_version') {
                        cmp = compareVersions(a[nameKey], b[nameKey]);
                        return dir === 'asc' ? cmp : -cmp;
                    }
                    va = (a[nameKey] || '').toLowerCase();
                    vb = (b[nameKey] || '').toLowerCase();
                } else if (col === 'count') {
                    va = a.count;
                    vb = b.count;
                } else if (col === 'percentage') {
                    va = a.percentage;
                    vb = b.percentage;
                }
                if (va < vb) return dir === 'asc' ? -1 : 1;
                if (va > vb) return dir === 'asc' ? 1 : -1;
                return 0;
            });
            return arr;
        }

        function sortStats(section, col) {
            if (!statsData) return;
            const state = statsSortState[section];
            if (state.col === col) {
                state.dir = state.dir === 'asc' ? 'desc' : 'asc';
            } else {
                state.col = col;
                state.dir = col === 'name' ? 'asc' : 'desc';
            }
            renderStats();
        }

        function renderStats() {
            if (!statsData) return;
            const content = document.getElementById('statsContent');
            const sortIcons = '<svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg>';

            function getSortClass(section, col) {
                const state = statsSortState[section];
                if (state.col === col) return state.dir;
                return '';
            }

            function renderTable(section, title, nameCol, nameKey, note = '') {
                const state = statsSortState[section];
                const data = sortStatsData(statsData[section] || [], section, state.col, state.dir);
                return `
                    <h3 style="margin-top:20px">${title}</h3>
                    ${note ? `<p style="color:#888;font-size:12px;margin:5px 0 10px 0;font-style:italic;">${note}</p>` : ''}
                    <table>
                        <thead><tr>
                            <th class="sortable ${getSortClass(section, 'name')}" style="width:50%" onclick="sortStats('${section}','name')">${nameCol}${sortIcons}</th>
                            <th class="sortable ${getSortClass(section, 'count')}" style="width:25%;text-align:right" onclick="sortStats('${section}','count')">Count${sortIcons}</th>
                            <th class="sortable ${getSortClass(section, 'percentage')}" style="width:25%;text-align:right" onclick="sortStats('${section}','percentage')">%${sortIcons}</th>
                        </tr></thead>
                        <tbody>${data.map(item => `<tr><td>${item[nameKey]}</td><td style="text-align:right">${item.count}</td><td style="text-align:right">${item.percentage.toFixed(1)}%</td></tr>`).join('')}</tbody>
                    </table>
                `;
            }

            content.innerHTML =
                renderTable('by_status', 'By Status', 'Status', 'status').replace('style="margin-top:20px"', '') +
                renderTable('by_group', 'By Group', 'Group', 'group', '* Agents can belong to multiple groups, so percentages may exceed 100%') +
                renderTable('by_network', 'By Network Segment', 'Network', 'network') +
                renderTable('by_os', 'By OS', 'OS', 'os') +
                renderTable('by_version', 'By Agent Version', 'Version', 'version');
        }

        async function refreshStats() {
            const content = document.getElementById('statsContent');
            content.innerHTML = '<div class="loading"><div class="spinner"></div>Loading...</div>';

            try {
                const data = await api('/stats/report');
                if (!data) return;

                if (data.error) {
                    content.innerHTML = `<div class="alert alert-error">${data.error}</div>`;
                    return;
                }

                statsData = data;
                renderStats();
            } catch (err) {
                if (err.message === 'BACKEND_UNAVAILABLE') {
                    content.innerHTML = getConnectionErrorHtml('refreshStats()');
                } else {
                    content.innerHTML = `<div class="alert alert-error">Error loading statistics: ${escapeHtml(err.message)}</div>`;
                }
            }
        }

        // Modal functions
        function showModal(title, body, footer, wide = false) {
            document.getElementById('modalTitle').textContent = title;
            document.getElementById('modalBody').innerHTML = body;
            document.getElementById('modalFooter').innerHTML = footer;
            const modalContent = document.querySelector('.modal-content');
            if (wide) modalContent.classList.add('wide');
            else modalContent.classList.remove('wide');
            document.getElementById('modal').classList.add('show');
        }

        function closeModal() {
            document.getElementById('modal').classList.remove('show');
            const modalContent = document.querySelector('.modal-content');
            modalContent.classList.remove('wide', 'resizable');
            modalContent.style.width = '';
            modalContent.style.height = '';
            modalContent.style.maxWidth = '';
            modalContent.style.position = '';
        }

        // Custom confirm dialog (returns Promise)
        let confirmResolve = null;

        // Close modal on ESC key
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape' && document.getElementById('modal').classList.contains('show')) {
                if (confirmResolve) { confirmResolve(false); confirmResolve = null; }
                closeModal();
            }
        });
        function showConfirm(message, isDanger = false) {
            return new Promise((resolve) => {
                confirmResolve = resolve;
                const body = '<p style="margin:0;font-size:15px;">' + message + '</p>';
                const btnClass = isDanger ? 'btn-danger' : 'btn-primary';
                const footer = '<button class="btn" onclick="confirmResolve(false);closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>' +
                    '<button class="btn ' + btnClass + '" onclick="confirmResolve(true);closeModal()"><svg class="icon"><use href="#icon-check"/></svg>Confirm</button>';
                showModal('Confirm', body, footer);
            });
        }

        function showAddToGroupModal() {
            const body = `
                <div class="form-group">
                    <label>Select Group</label>
                    <select id="targetGroup">${groups.map(g => `<option value="${g.name}">${g.name}</option>`).join('')}</select>
                </div>
                <p>Will add ${selectedAgents.size} agent(s) to the selected group.</p>
                ${document.getElementById('dryRunMode').checked ? '<div class="dry-run-notice">Dry Run Mode: No changes will be made</div>' : ''}
            `;
            const footer = `
                <button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>
                <button class="btn btn-success" onclick="addToGroup()"><svg class="icon"><use href="#icon-add-group"/></svg>Add to Group</button>
            `;
            showModal('Add Agents to Group', body, footer);
        }

        async function addToGroup() {
            const group = document.getElementById('targetGroup').value;
            const dryRun = document.getElementById('dryRunMode').checked;
            const result = await api('/groups/' + group + '/agents', 'POST', {
                agent_ids: Array.from(selectedAgents),
                dry_run: dryRun
            });
            closeModal();
            if (result) {
                showToast(result.message || 'Agents added to group', 'success');
                if (!dryRun) { selectedAgents.clear(); updateSelectedUI(); refreshAgents(); }
            }
        }

        function showRemoveFromGroupModal() {
            // Get currently selected group from filter (if any)
            const selectedGroupFilters = getFilterValues('groupFilter');
            const preselectedGroup = selectedGroupFilters.length === 1 ? selectedGroupFilters[0] : '';

            const body = `
                <div class="form-group">
                    <label>Select Group</label>
                    <select id="targetGroup">${groups.map(g => `<option value="${g.name}"${g.name === preselectedGroup ? ' selected' : ''}>${g.name}</option>`).join('')}</select>
                </div>
                <p>Will remove ${selectedAgents.size} agent(s) from the selected group.</p>
                ${document.getElementById('dryRunMode').checked ? '<div class="dry-run-notice">Dry Run Mode: No changes will be made</div>' : ''}
            `;
            const footer = `
                <button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>
                <button class="btn btn-warning" onclick="removeFromGroup()"><svg class="icon"><use href="#icon-remove"/></svg>Remove from Group</button>
            `;
            showModal('Remove Agents from Group', body, footer);
        }

        async function removeFromGroup() {
            const group = document.getElementById('targetGroup').value;
            const dryRun = document.getElementById('dryRunMode').checked;
            const result = await api('/groups/' + group + '/agents', 'DELETE', {
                agent_ids: Array.from(selectedAgents),
                dry_run: dryRun
            });
            closeModal();
            if (result) {
                showToast(result.message || 'Agents removed from group', 'success');
                if (!dryRun) { selectedAgents.clear(); updateSelectedUI(); refreshAgents(); }
            }
        }

        async function showMoveToNodeModal() {
            const body = `
                <div style="text-align:center;padding:30px;">
                    <svg class="icon" style="width:48px;height:48px;color:#ffc107;margin-bottom:15px;"><use href="#icon-move"/></svg>
                    <h3 style="color:#ffc107;margin-bottom:15px;">Under Development</h3>
                    <p style="color:#aaa;">Move to Node feature is still under development.</p>
                    <p style="color:#888;font-size:12px;margin-top:10px;">This feature will allow you to force agents to reconnect to a specific cluster node.</p>
                    <p style="color:#888;font-size:12px;margin-top:8px;">Will integrate with HAProxy LB to route agents to designated nodes.</p>
                </div>
            `;
            showModal('Move Agents to Node', body, '');
        }

        async function moveToNode() {
            // Function placeholder - feature under development
            showToast('This feature is still under development', 'warning');
        }

        async function restartSelected() {
            if (!await showConfirm('Restart ' + selectedAgents.size + ' agent(s)?')) return;
            const dryRun = document.getElementById('dryRunMode').checked;
            const result = await api('/agents/restart', 'POST', {
                agent_ids: Array.from(selectedAgents),
                dry_run: dryRun
            });
            if (result) {
                showToast(result.message || 'Restart command sent', 'success');
                if (!dryRun) { selectedAgents.clear(); updateSelectedUI(); }
            }
        }

        async function reconnectSelected() {
            if (!await showConfirm('Reconnect ' + selectedAgents.size + ' agent(s)?')) return;
            const dryRun = document.getElementById('dryRunMode').checked;
            const result = await api('/agents/reconnect', 'POST', {
                agent_ids: Array.from(selectedAgents),
                dry_run: dryRun
            });
            if (result) {
                showToast(result.message || 'Reconnect command sent', 'success');
                if (!dryRun) { selectedAgents.clear(); updateSelectedUI(); }
            }
        }

        async function deleteSelected() {
            if (!await showConfirm('DELETE ' + selectedAgents.size + ' agent(s)? This cannot be undone!', true)) return;
            // Second confirmation for safety
            if (!await showConfirm('⚠️ FINAL CONFIRMATION ⚠️\\n\\nAre you ABSOLUTELY sure you want to permanently delete ' + selectedAgents.size + ' agent(s)?\\n\\nThis action CANNOT be undone!', true)) return;
            const dryRun = document.getElementById('dryRunMode').checked;
            const result = await api('/agents', 'DELETE', {
                agent_ids: Array.from(selectedAgents),
                dry_run: dryRun
            });
            if (result) {
                showToast(result.message || 'Agents deleted', 'success');
                if (!dryRun) { selectedAgents.clear(); updateSelectedUI(); refreshAgents(); }
            }
        }

        async function upgradeSelected() {
            // Get selected agents info
            const selectedList = Array.from(selectedAgents);
            const selectedAgentData = agents.filter(a => selectedList.includes(a.id));

            // Group by version for display
            const versionGroups = {};
            selectedAgentData.forEach(a => {
                const v = a.version || 'unknown';
                if (!versionGroups[v]) versionGroups[v] = [];
                versionGroups[v].push(a.name);
            });

            let versionSummary = Object.entries(versionGroups).map(([v, names]) =>
                `<div style="margin:5px 0;"><span class="badge">${escapeHtml(v)}</span> ${names.length} agent(s)</div>`
            ).join('');

            const dryRun = document.getElementById('dryRunMode').checked;
            const dryRunNotice = dryRun ?
                '<div class="dry-run-notice" style="margin-bottom:15px;">Dry Run Mode: No changes will be made</div>' : '';

            const body = `
                ${dryRunNotice}
                <div style="background:#1a1a2e;border-left:3px solid #fd7e14;padding:10px 15px;margin-bottom:15px;border-radius:4px;">
                    <p style="color:#aaa;font-size:12px;margin:0;">Upgrade will update agents to the latest available version from Wazuh repository. Make sure the manager has internet access or the WPK files are available locally.</p>
                </div>
                <p style="color:#aaa;margin-bottom:5px;">Selected Agents (${selectedList.length})</p>
                <div style="max-height:120px;overflow-y:auto;background:#1a1a2e;padding:10px;border-radius:4px;margin-bottom:15px;">
                    ${versionSummary}
                </div>
                <p style="color:#aaa;margin-bottom:5px;">Upgrade Options</p>
                <div style="background:#1a1a2e;padding:12px;border-radius:4px;margin-bottom:15px;">
                    <div style="margin-bottom:10px;"><input type="radio" name="upgradeType" value="latest" id="upgradeLatest" checked style="margin-right:8px;"><label for="upgradeLatest" style="cursor:pointer;">Upgrade to manager version${managerVersion ? ' (<span style="color:#4fc3f7;">v' + managerVersion + '</span>)' : ''}</label></div>
                    <div><input type="radio" name="upgradeType" value="custom" id="upgradeCustom" style="margin-right:8px;"><label for="upgradeCustom" style="cursor:pointer;">Specify version:</label> <input type="text" id="customVersion" placeholder="e.g., 4.14.0" style="width:100px;margin-left:5px;background:#0f3460;border:1px solid #1a3a6e;color:#eee;padding:6px 10px;border-radius:4px;" onfocus="document.getElementById('upgradeCustom').checked=true;"></div>
                </div>
                <div><input type="checkbox" id="upgradeForce" style="margin-right:8px;"><label for="upgradeForce" style="cursor:pointer;">Force upgrade (even if same version)</label></div>
            `;
            const footer = `
                <button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>
                <button class="btn" style="background:#fd7e14;color:#fff;" onclick="executeUpgrade()"><svg class="icon"><use href="#icon-upload"/></svg>Upgrade</button>
            `;
            showModal('Upgrade Agents', body, footer);
        }

        async function executeUpgrade() {
            const selectedList = Array.from(selectedAgents);
            const upgradeType = document.querySelector('input[name="upgradeType"]:checked').value;
            const customVersion = document.getElementById('customVersion').value.trim();
            const force = document.getElementById('upgradeForce').checked;
            const dryRun = document.getElementById('dryRunMode').checked;

            if (upgradeType === 'custom' && !customVersion) {
                showToast('Please enter a version number', 'warning');
                return;
            }

            closeModal();

            if (!await showConfirm('Upgrade ' + selectedList.length + ' agent(s)' + (upgradeType === 'custom' ? ' to v' + customVersion : ' to latest version') + '?', true)) return;

            showToast('Starting upgrade for ' + selectedList.length + ' agent(s)...', 'info');

            const result = await api('/agents/upgrade', 'POST', {
                agent_ids: selectedList,
                version: upgradeType === 'custom' ? customVersion : null,
                force: force,
                dry_run: dryRun
            });

            if (result) {
                if (result.error) {
                    showToast('Upgrade failed: ' + result.error, 'error');
                } else {
                    const successCount = result.success_count || 0;
                    const failCount = result.fail_count || 0;
                    const failedAgents = result.failed_agents || [];

                    if (failCount > 0 && successCount === 0) {
                        // All failed - show error details in modal
                        showUpgradeErrorModal(failedAgents);
                    } else if (failCount > 0) {
                        // Partial success
                        showToast(`Upgrade: ${successCount} success, ${failCount} failed`, 'warning', 8000);
                        if (!dryRun) {
                            showUpgradeProgress(selectedList);
                        }
                    } else {
                        showToast(result.message || 'Upgrade initiated for ' + successCount + ' agent(s)', 'success');
                        if (!dryRun && successCount > 0) {
                            showUpgradeProgress(selectedList);
                        }
                    }
                }
            }
        }

        function showUpgradeErrorModal(failedAgents) {
            const agentMap = {};
            agents.forEach(a => { agentMap[a.id] = a; });

            // Check if any error is WPK related
            const hasWpkError = failedAgents.some(fa =>
                (fa.error && (fa.error.toLowerCase().includes('wpk') ||
                              fa.error.includes('Upgrade task not created') ||
                              fa.error.includes('/var/ossec/var/upgrade')))
            );

            let html = '<table style="width:100%;border-collapse:collapse;">';
            html += '<thead><tr style="background:#0f3460;"><th style="padding:10px;text-align:left;">Agent</th><th style="padding:10px;text-align:left;">Error</th></tr></thead>';
            html += '<tbody>';

            for (const fa of failedAgents) {
                const agent = agentMap[fa.id] || {};
                const agentName = agent.name || fa.id;
                const agentVersion = agent.version || '';
                const agentNode = agent.node_name || '';
                html += '<tr style="border-bottom:1px solid #1a3a6e;">';
                html += '<td style="padding:10px;"><span style="color:#0dcaf0;">' + escapeHtml(fa.id) + '</span><br><span style="color:#888;font-size:11px;">' + escapeHtml(agentName) + (agentVersion ? ' (' + agentVersion + ')' : '') + '</span></td>';
                // Format error message with line breaks for readability
                const errorHtml = escapeHtml(fa.error || 'Unknown error').replace(/\\n/g, '<br>');
                html += '<td style="padding:10px;color:#dc3545;white-space:pre-line;">' + errorHtml + '</td>';
                html += '</tr>';
            }

            html += '</tbody></table>';

            // Build hint section if WPK error detected
            let wpkHint = '';
            if (hasWpkError) {
                wpkHint = `
                    <div style="background:#1a1a2e;border-left:3px solid #fd7e14;padding:15px;margin-bottom:15px;border-radius:4px;">
                        <p style="color:#fd7e14;font-size:13px;font-weight:600;margin:0 0 10px 0;">WPK File Required</p>
                        <p style="color:#aaa;font-size:12px;margin:0 0 10px 0;">
                            The agent upgrade requires a WPK (Wazuh PacKage) file that is not available on the manager.
                            Please go to <strong>Node Management</strong> → select the node → <strong>Upgrade Files</strong> to:
                        </p>
                        <ul style="color:#aaa;font-size:12px;margin:0;padding-left:20px;">
                            <li>Upload the WPK file manually, or</li>
                            <li>Check if the WPK files exist for your target version</li>
                        </ul>
                        <p style="color:#888;font-size:11px;margin:10px 0 0 0;">
                            WPK files can be downloaded from: <a href="https://packages.wazuh.com/4.x/wpk/" target="_blank" style="color:#4fc3f7;">https://packages.wazuh.com/4.x/wpk/</a>
                        </p>
                    </div>
                `;
            }

            const body = `
                <div style="background:#1a1a2e;border-left:3px solid #dc3545;padding:10px 15px;margin-bottom:15px;border-radius:4px;">
                    <p style="color:#dc3545;font-size:14px;margin:0;">Upgrade failed for ${failedAgents.length} agent(s)</p>
                </div>
                ${wpkHint}
                <div style="max-height:350px;overflow-y:auto;">
                    ${html}
                </div>
            `;
            const footer = hasWpkError ? '<button class="btn" style="background:#fd7e14;color:#fff;" onclick="closeModal();showNodeManagement();">Go to Node Management</button>' : '';
            showModal('Upgrade Failed', body, footer);
        }

        let upgradeProgressInterval = null;
        let lastUpgradedAgentIds = [];  // Store recently upgraded agent IDs
        let upgradeHistoryCleared = false;  // Flag to track if history was manually cleared

        function showUpgradeProgress(agentIds) {
            // Store for later viewing and reset cleared flag
            lastUpgradedAgentIds = agentIds;
            upgradeHistoryCleared = false;
            const body = `
                <div style="background:#1a1a2e;border-left:3px solid #17a2b8;padding:10px 15px;margin-bottom:15px;border-radius:4px;">
                    <p style="color:#aaa;font-size:12px;margin:0;">Tracking upgrade progress for ${agentIds.length} agent(s). Status updates every 5 seconds.</p>
                </div>
                <div id="upgradeProgressContent" style="max-height:400px;overflow-y:auto;">
                    <div style="text-align:center;padding:30px;color:#888;">
                        <div class="spinner" style="margin:0 auto 15px;"></div>
                        Loading upgrade status...
                    </div>
                </div>
            `;
            const footer = `
                <button class="btn" onclick="closeUpgradeProgress()"><svg class="icon"><use href="#icon-xmark"/></svg>Close</button>
                <button class="btn" onclick="refreshUpgradeProgress()"><svg class="icon"><use href="#icon-refresh"/></svg>Refresh</button>
            `;
            showModal('Upgrade Progress', body, footer);

            // Store agent IDs for polling
            window.upgradeAgentIds = agentIds;

            // Initial fetch
            refreshUpgradeProgress();

            // Start polling every 5 seconds
            upgradeProgressInterval = setInterval(refreshUpgradeProgress, 5000);
        }

        function closeUpgradeProgress() {
            if (upgradeProgressInterval) {
                clearInterval(upgradeProgressInterval);
                upgradeProgressInterval = null;
            }
            closeModal();
            refreshAgents();
        }

        async function refreshUpgradeProgress() {
            const agentIds = window.upgradeAgentIds || [];
            if (!agentIds.length) return;

            try {
                const resp = await fetch('/api/agents/upgrade-result?agent_ids=' + agentIds.join(','));
                const data = await resp.json();

                if (data.error) {
                    document.getElementById('upgradeProgressContent').innerHTML =
                        '<div style="color:#dc3545;padding:20px;">Error: ' + escapeHtml(data.error) + '</div>';
                    return;
                }

                const results = data.results || [];
                let html = '<table style="width:100%;border-collapse:collapse;">';
                html += '<thead><tr style="background:#0f3460;"><th style="padding:10px;text-align:left;">Agent</th><th style="padding:10px;text-align:left;">Status</th><th style="padding:10px;text-align:left;">Details</th></tr></thead>';
                html += '<tbody>';

                // Get agent names from cache
                const agentMap = {};
                agents.forEach(a => { agentMap[a.id] = a.name; });

                // Track completion
                let completedCount = 0;
                let failedCount = 0;

                for (const agentId of agentIds) {
                    const result = results.find(r => r.agent_id === agentId);
                    const agentName = agentMap[agentId] || agentId;

                    let status = 'Pending';
                    let statusColor = '#888';
                    let statusIcon = 'clock';
                    let iconSpin = false;
                    let details = '';

                    if (result) {
                        const s = result.status.toLowerCase();
                        if (s === 'updated' || s === 'done' || s === 'success') {
                            status = 'Updated';
                            statusColor = '#28a745';
                            statusIcon = 'check';
                            completedCount++;
                        } else if (s === 'updating' || s === 'in progress' || s === 'downloading') {
                            status = s.charAt(0).toUpperCase() + s.slice(1);
                            statusColor = '#17a2b8';
                            statusIcon = 'refresh';
                            iconSpin = true;
                        } else if (s === 'error' || s === 'failed') {
                            status = 'Failed';
                            statusColor = '#dc3545';
                            statusIcon = 'xmark';
                            details = result.error || '';
                            failedCount++;
                            completedCount++;
                        } else {
                            status = s.charAt(0).toUpperCase() + s.slice(1);
                        }
                    }

                    const iconClass = iconSpin ? 'icon icon-spin' : 'icon';
                    html += '<tr style="border-bottom:1px solid #1a3a6e;">';
                    html += '<td style="padding:10px;"><span style="color:#0dcaf0;">' + escapeHtml(agentId) + '</span><br><span style="color:#888;font-size:11px;">' + escapeHtml(agentName) + '</span></td>';
                    html += '<td style="padding:10px;"><span style="color:' + statusColor + ';"><svg class="' + iconClass + '" style="width:14px;height:14px;vertical-align:middle;margin-right:5px;"><use href="#icon-' + statusIcon + '"/></svg>' + status + '</span></td>';
                    html += '<td style="padding:10px;color:#888;font-size:12px;">' + escapeHtml(details) + '</td>';
                    html += '</tr>';
                }

                html += '</tbody></table>';

                // Summary
                const remaining = agentIds.length - completedCount;
                let summary = '<div style="padding:15px;background:#0a0a15;border-radius:4px;margin-top:15px;">';
                summary += '<span style="color:#28a745;margin-right:15px;"><svg class="icon" style="width:14px;height:14px;vertical-align:middle;margin-right:5px;"><use href="#icon-check"/></svg>' + (completedCount - failedCount) + ' Updated</span>';
                if (failedCount > 0) {
                    summary += '<span style="color:#dc3545;margin-right:15px;"><svg class="icon" style="width:14px;height:14px;vertical-align:middle;margin-right:5px;"><use href="#icon-xmark"/></svg>' + failedCount + ' Failed</span>';
                }
                if (remaining > 0) {
                    summary += '<span style="color:#888;"><svg class="icon" style="width:14px;height:14px;vertical-align:middle;margin-right:5px;"><use href="#icon-clock"/></svg>' + remaining + ' In Progress</span>';
                }
                summary += '</div>';

                document.getElementById('upgradeProgressContent').innerHTML = html + summary;

                // Stop polling if all done
                if (remaining === 0 && upgradeProgressInterval) {
                    clearInterval(upgradeProgressInterval);
                    upgradeProgressInterval = null;
                }

            } catch (e) {
                console.error('Failed to fetch upgrade progress:', e);
            }
        }

        async function showAllUpgradeProgress() {
            // If history was cleared and no new upgrades, show empty state
            if (upgradeHistoryCleared && lastUpgradedAgentIds.length === 0) {
                const body = `
                    <div style="text-align:center;padding:40px;color:#888;">
                        <svg class="icon" style="width:48px;height:48px;margin-bottom:15px;opacity:0.5;"><use href="#icon-check"/></svg>
                        <p>No recent upgrade tasks.</p>
                        <p style="font-size:12px;color:#666;">Upgrade history has been cleared.</p>
                    </div>
                `;
                showModal('Upgrade Progress', body, '');
                return;
            }

            // Use stored agent IDs if available, otherwise fetch all
            const useAgentIds = lastUpgradedAgentIds.length > 0;
            const agentCount = useAgentIds ? lastUpgradedAgentIds.length : 'all';

            // Show modal with loading state
            const body = `
                <div style="background:#1a1a2e;border-left:3px solid #17a2b8;padding:10px 15px;margin-bottom:15px;border-radius:4px;">
                    <p style="color:#aaa;font-size:12px;margin:0;">${useAgentIds ? `Showing upgrade progress for ${agentCount} recent agent(s).` : 'Showing all recent upgrade tasks from Wazuh API.'}</p>
                </div>
                <div id="allUpgradeProgressContent" style="max-height:400px;overflow-y:auto;">
                    <div style="text-align:center;padding:30px;color:#888;">
                        <div class="spinner" style="margin:0 auto 15px;"></div>
                        Loading upgrade tasks...
                    </div>
                </div>
            `;
            const footer = `
                <button class="btn" onclick="clearUpgradeHistory()" title="Clear history"><svg class="icon"><use href="#icon-trash"/></svg></button>
                <button class="btn btn-primary" onclick="showAllUpgradeProgress()"><svg class="icon"><use href="#icon-refresh"/></svg>Refresh</button>
            `;
            showModal('Upgrade Progress', body, footer);

            // Fetch upgrade results (with agent filter if available)
            try {
                const url = useAgentIds
                    ? '/api/agents/upgrade-result?agent_ids=' + lastUpgradedAgentIds.join(',')
                    : '/api/agents/upgrade-result';
                const resp = await fetch(url);
                const data = await resp.json();

                const container = document.getElementById('allUpgradeProgressContent');
                if (!container) return;

                if (data.error) {
                    container.innerHTML = '<div style="color:#dc3545;padding:20px;">Error: ' + escapeHtml(data.error) + '</div>';
                    return;
                }

                const results = data.results || [];
                if (results.length === 0) {
                    container.innerHTML = '<div style="text-align:center;padding:30px;color:#888;">No recent upgrade tasks found.</div>';
                    return;
                }

                // Build table
                const agentMap = {};
                agents.forEach(a => { agentMap[a.id] = a; });

                let html = '<table style="width:100%;border-collapse:collapse;">';
                html += '<thead><tr style="background:#0f3460;"><th style="padding:10px;text-align:left;">Agent</th><th style="padding:10px;text-align:left;">Status</th><th style="padding:10px;text-align:left;">Time</th></tr></thead>';
                html += '<tbody>';

                let updatedCount = 0, failedCount = 0, inProgressCount = 0;

                for (const result of results) {
                    const agent = agentMap[result.agent_id] || {};
                    const agentName = agent.name || result.agent_id;

                    let status = result.status || 'Unknown';
                    let statusColor = '#888';
                    let statusIcon = 'clock';

                    const s = status.toLowerCase();
                    if (s === 'updated' || s === 'done' || s === 'success') {
                        statusColor = '#28a745';
                        statusIcon = 'check';
                        updatedCount++;
                    } else if (s === 'updating' || s === 'in progress' || s === 'downloading') {
                        statusColor = '#17a2b8';
                        statusIcon = 'refresh';
                        inProgressCount++;
                    } else if (s === 'error' || s === 'failed') {
                        statusColor = '#dc3545';
                        statusIcon = 'xmark';
                        failedCount++;
                    } else if (s === 'legacy') {
                        statusColor = '#ffc107';
                        statusIcon = 'clock';
                    }

                    const timeStr = result.update_time || result.create_time || '';

                    html += '<tr style="border-bottom:1px solid #1a3a6e;">';
                    html += '<td style="padding:10px;"><span style="color:#0dcaf0;">' + escapeHtml(result.agent_id) + '</span><br><span style="color:#888;font-size:11px;">' + escapeHtml(agentName) + '</span></td>';
                    html += '<td style="padding:10px;"><span style="color:' + statusColor + ';"><svg class="icon" style="width:14px;height:14px;vertical-align:middle;margin-right:5px;"><use href="#icon-' + statusIcon + '"/></svg>' + escapeHtml(status) + '</span>';
                    if (result.error) {
                        html += '<br><span style="color:#888;font-size:11px;">' + escapeHtml(result.error) + '</span>';
                    }
                    html += '</td>';
                    html += '<td style="padding:10px;color:#888;font-size:12px;">' + escapeHtml(timeStr) + '</td>';
                    html += '</tr>';
                }

                html += '</tbody></table>';

                // Summary
                let summary = '<div style="padding:15px;background:#0a0a15;border-radius:4px;margin-top:15px;">';
                summary += '<span style="margin-right:15px;">Total: ' + results.length + '</span>';
                if (updatedCount > 0) summary += '<span style="color:#28a745;margin-right:15px;"><svg class="icon" style="width:14px;height:14px;vertical-align:middle;margin-right:5px;"><use href="#icon-check"/></svg>' + updatedCount + ' Updated</span>';
                if (failedCount > 0) summary += '<span style="color:#dc3545;margin-right:15px;"><svg class="icon" style="width:14px;height:14px;vertical-align:middle;margin-right:5px;"><use href="#icon-xmark"/></svg>' + failedCount + ' Failed</span>';
                if (inProgressCount > 0) summary += '<span style="color:#17a2b8;"><svg class="icon" style="width:14px;height:14px;vertical-align:middle;margin-right:5px;"><use href="#icon-clock"/></svg>' + inProgressCount + ' In Progress</span>';
                summary += '</div>';

                container.innerHTML = html + summary;

            } catch (e) {
                console.error('Failed to fetch upgrade progress:', e);
                const container = document.getElementById('allUpgradeProgressContent');
                if (container) {
                    container.innerHTML = '<div style="color:#dc3545;padding:20px;">Error: ' + e.message + '</div>';
                }
            }
        }

        function clearUpgradeHistory() {
            lastUpgradedAgentIds = [];
            upgradeHistoryCleared = true;
            showToast('Upgrade history cleared', 'info');
            closeModal();
        }

        function showCreateGroupModal() {
            const body = `
                <div class="form-group">
                    <label>Group Name</label>
                    <input type="text" id="newGroupName" placeholder="Enter group name">
                </div>
            `;
            const footer = `
                <button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>
                <button class="btn btn-success" onclick="createGroup()"><svg class="icon"><use href="#icon-plus"/></svg>Create</button>
            `;
            showModal('Create Group', body, footer);
        }

        async function createGroup() {
            const name = document.getElementById('newGroupName').value;
            if (!name) { showToast('Please enter a group name', 'warning'); return; }
            const dryRun = document.getElementById('dryRunMode').checked;
            const result = await api('/groups', 'POST', { name, dry_run: dryRun });
            closeModal();
            if (result) {
                showToast(result.message || 'Group created', 'success');
                if (!dryRun) refreshGroups();
            }
        }

        async function deleteGroup(name) {
            if (!await showConfirm('Delete group "' + name + '"?', true)) return;
            const dryRun = document.getElementById('dryRunMode').checked;
            const result = await api('/groups/' + name, 'DELETE', { dry_run: dryRun });
            if (result) {
                showToast(result.message || 'Group deleted', 'success');
                if (!dryRun) refreshGroups();
            }
        }

        let renameFromGroup = '';
        function showRenameGroupModal(groupName) {
            renameFromGroup = groupName;
            const group = groups.find(g => g.name === groupName);
            const count = group ? group.count : 0;
            const dryRunNotice = document.getElementById('dryRunMode').checked ?
                '<div class="dry-run-notice">Dry Run Mode: No changes will be made</div>' : '';
            const body = `
                <div class="form-group">
                    <label>Current Name</label>
                    <input type="text" value="${groupName}" disabled style="background:#0a0a15;">
                </div>
                <div class="form-group">
                    <label>New Name</label>
                    <input type="text" id="newGroupNameInput" placeholder="Enter new group name">
                </div>
                <p style="color:#888;font-size:12px;margin-top:10px;">
                    This will: 1) Create new group, 2) Move ${count} agent(s) to new group, 3) Delete old group
                </p>
                ${dryRunNotice}
            `;
            const footer = `
                <button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>
                <button class="btn btn-primary" onclick="renameGroup()"><svg class="icon"><use href="#icon-rename"/></svg>Rename</button>
            `;
            showModal('Rename Group', body, footer);
            setTimeout(() => document.getElementById('newGroupNameInput').focus(), 100);
        }

        async function renameGroup() {
            const newName = document.getElementById('newGroupNameInput').value.trim();
            if (!newName) { showToast('Please enter a new group name', 'warning'); return; }
            if (newName === renameFromGroup) { showToast('New name is the same as current name', 'warning'); return; }
            if (groups.find(g => g.name === newName)) { showToast('Group "' + newName + '" already exists', 'warning'); return; }

            const dryRun = document.getElementById('dryRunMode').checked;
            closeModal();
            showToast('Renaming group...', 'info');

            const result = await api('/groups/rename', 'POST', {
                old_name: renameFromGroup,
                new_name: newName,
                dry_run: dryRun
            });

            if (result) {
                if (result.error) {
                    showToast(result.error, 'error');
                } else {
                    showToast(result.message || 'Group renamed successfully', 'success');
                    if (!dryRun) { refreshGroups(); refreshAgents(); }
                }
            }
        }

        async function removeAllFromGroup(groupName) {
            const group = groups.find(g => g.name === groupName);
            const count = group ? group.count : 0;
            if (!await showConfirm('Remove all ' + count + ' agent(s) from group "' + groupName + '"?', true)) return;
            const dryRun = document.getElementById('dryRunMode').checked;
            const result = await api('/groups/' + groupName + '/agents/all', 'DELETE', { dry_run: dryRun });
            if (result) {
                showToast(result.message || 'All agents removed from group', 'success');
                if (!dryRun) { refreshGroups(); refreshAgents(); }
            }
        }

        async function setExclusiveGroup(groupName) {
            const group = groups.find(g => g.name === groupName);
            const count = group ? group.count : 0;
            if (!await showConfirm(
                'Set "' + groupName + '" as exclusive group for ' + count + ' agent(s)?\\n\\n' +
                'This will REMOVE these agents from ALL other groups.', true)) return;
            const dryRun = document.getElementById('dryRunMode').checked;
            const result = await api('/groups/' + groupName + '/exclusive', 'POST', { dry_run: dryRun });
            if (result) {
                if (result.error) {
                    showToast('Error: ' + result.error, 'error');
                } else {
                    showToast(result.message || 'Agents now only belong to this group', 'success');
                    if (!dryRun) { refreshGroups(); refreshAgents(); }
                }
            }
        }

        let moveFromGroup = '';
        function showMoveGroupAgentsModal(groupName) {
            moveFromGroup = groupName;
            const group = groups.find(g => g.name === groupName);
            const count = group ? group.count : 0;
            const otherGroups = groups.filter(g => g.name !== groupName);
            const options = otherGroups.map(g => '<option value="' + g.name + '">' + g.name + ' (' + g.count + ' agents)</option>').join('');
            const body = '<div class="form-group">' +
                '<label>Move ' + count + ' agent(s) from "' + groupName + '" to:</label>' +
                '<select id="moveTargetGroup">' + options + '</select>' +
                '</div>' +
                '<p style="color:#888;font-size:12px;">Note: Agents will be added to the target group and removed from "' + groupName + '".</p>';
            const footer = '<button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>' +
                '<button class="btn btn-primary" onclick="moveGroupAgents()"><svg class="icon"><use href="#icon-move"/></svg>Move</button>';
            showModal('Move Agents to Another Group', body, footer);
        }

        async function moveGroupAgents() {
            const targetGroup = document.getElementById('moveTargetGroup').value;
            if (!targetGroup) { showToast('Please select a target group', 'warning'); return; }
            const dryRun = document.getElementById('dryRunMode').checked;
            const result = await api('/groups/' + moveFromGroup + '/move', 'POST', {
                target_group: targetGroup,
                dry_run: dryRun
            });
            closeModal();
            if (result) {
                showToast(result.message || 'Agents moved successfully', 'success');
                if (!dryRun) { refreshGroups(); refreshAgents(); }
            }
        }

        // CSV Import functions
        let importTargetGroup = '';
        let pendingImportData = [];

        function showImportCsvModal(groupName) {
            importTargetGroup = groupName;
            const body = '<div class="form-group">' +
                '<label>Select CSV file to import agents into group "' + groupName + '"</label>' +
                '<input type="file" id="csvFileInput" accept=".csv" style="margin-top:10px;">' +
                '</div>' +
                '<div style="background:#1a1a2e;padding:12px;border-radius:4px;margin-top:15px;font-size:12px;">' +
                '<p style="color:#4fc3f7;margin:0 0 8px 0;font-weight:bold;">CSV Format Rules:</p>' +
                '<ul style="color:#aaa;margin:0;padding-left:20px;line-height:1.8;">' +
                '<li>Must have at least one column: <b style="color:#fff;">ID</b>, <b style="color:#fff;">Name</b> (or Hostname), or <b style="color:#fff;">IP</b> (or Address)</li>' +
                '<li>Column order does not matter</li>' +
                '<li>If multiple match columns exist, leftmost takes priority</li>' +
                '<li>Other columns will be ignored</li>' +
                '<li>First row must be header</li>' +
                '</ul></div>' +
                '<p style="margin-top:10px;"><a href="#" onclick="downloadCsvTemplate(); return false;" style="color:#4fc3f7;">Download CSV Template</a></p>';
            const footer = '<button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>' +
                '<button class="btn btn-primary" onclick="previewCsvImport()"><svg class="icon"><use href="#icon-eye"/></svg>Preview</button>';
            showModal('Import Agents from CSV', body, footer);
        }

        function downloadCsvTemplate() {
            const template = 'ID,Name,IP' + String.fromCharCode(10) + '001,agent-example,192.168.1.100' + String.fromCharCode(10) + '002,another-agent,192.168.1.101';
            const blob = new Blob([template], { type: 'text/csv;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = 'agent_import_template.csv';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
            showToast('Template downloaded', 'success');
        }

        function exportGroupAgentsCsv(groupName) {
            // Filter agents by group
            const groupAgents = agents.filter(a => {
                if (!a.group) return false;
                const groups = a.group.split(',').map(g => g.trim());
                return groups.includes(groupName);
            });

            if (groupAgents.length === 0) {
                showToast('No agents in this group', 'warning');
                return;
            }

            // Build CSV with same columns as import template: ID, Name, IP
            let csv = 'ID,Name,IP' + String.fromCharCode(10);
            groupAgents.forEach(a => {
                const id = (a.id || '').replace(/"/g, '""');
                const name = (a.name || '').replace(/"/g, '""');
                const ip = (a.ip || '').replace(/"/g, '""');
                csv += '"' + id + '","' + name + '","' + ip + '"' + String.fromCharCode(10);
            });

            const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = groupName + '_agents.csv';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
            showToast('Exported ' + groupAgents.length + ' agents to CSV', 'success');
        }

        async function previewCsvImport() {
            const fileInput = document.getElementById('csvFileInput');
            if (!fileInput.files || fileInput.files.length === 0) {
                showToast('Please select a CSV file', 'warning');
                return;
            }

            const file = fileInput.files[0];
            const text = await file.text();
            const lines = text.trim().split(/\\r?\\n/);

            if (lines.length < 2) {
                showToast('CSV file is empty or has no data rows', 'warning');
                return;
            }

            // Parse header - support multiple column name variations
            const header = lines[0].split(',').map(h => h.trim().toLowerCase().replace(/[_-]/g, ''));

            // Find matching columns (first/leftmost match wins)
            let idIndex = -1, nameIndex = -1, ipIndex = -1;
            const idNames = ['id', 'agentid', 'agent'];
            const nameNames = ['name', 'hostname', 'agentname', 'host'];
            const ipNames = ['ip', 'address', 'ipaddress', 'addr'];

            for (let i = 0; i < header.length; i++) {
                const h = header[i];
                if (idIndex === -1 && idNames.includes(h)) idIndex = i;
                if (nameIndex === -1 && nameNames.includes(h)) nameIndex = i;
                if (ipIndex === -1 && ipNames.includes(h)) ipIndex = i;
            }

            if (idIndex === -1 && nameIndex === -1 && ipIndex === -1) {
                showToast('CSV must have at least one of: ID, Name/Hostname, IP/Address columns', 'error');
                return;
            }

            // Determine priority: leftmost matching column
            const matchCols = [];
            if (idIndex >= 0) matchCols.push({ type: 'id', idx: idIndex });
            if (nameIndex >= 0) matchCols.push({ type: 'name', idx: nameIndex });
            if (ipIndex >= 0) matchCols.push({ type: 'ip', idx: ipIndex });
            matchCols.sort((a, b) => a.idx - b.idx);
            const primaryMatch = matchCols[0].type;

            // Parse data rows
            const importData = [];
            for (let i = 1; i < lines.length; i++) {
                const cols = lines[i].split(',').map(c => c.trim().replace(/^"|"$/g, ''));
                if (cols.length === 0 || (cols.length === 1 && !cols[0])) continue;
                importData.push({
                    id: idIndex >= 0 && cols[idIndex] ? cols[idIndex] : null,
                    name: nameIndex >= 0 && cols[nameIndex] ? cols[nameIndex] : null,
                    ip: ipIndex >= 0 && cols[ipIndex] ? cols[ipIndex] : null,
                    primaryMatch: primaryMatch
                });
            }

            if (importData.length === 0) {
                showToast('No valid data rows found in CSV', 'warning');
                return;
            }

            // Store for later import
            pendingImportData = importData;

            // Call API with preview mode to get matching info
            showToast('Analyzing CSV data...', 'info');
            const result = await api('/groups/' + importTargetGroup + '/import', 'POST', {
                agents: importData,
                dry_run: true
            });

            if (!result) {
                showToast('Failed to analyze CSV', 'error');
                return;
            }

            // Show preview modal
            let previewHtml = '<div style="margin-bottom:15px;">' +
                '<div style="display:flex;gap:20px;flex-wrap:wrap;">' +
                '<div style="background:#00c85333;padding:10px 15px;border-radius:6px;text-align:center;min-width:100px;">' +
                '<div style="font-size:24px;font-weight:bold;color:#00c853;">' + (result.added ? result.added.length : 0) + '</div>' +
                '<div style="font-size:12px;color:#aaa;">Will be added</div></div>' +
                '<div style="background:#ffc10733;padding:10px 15px;border-radius:6px;text-align:center;min-width:100px;">' +
                '<div style="font-size:24px;font-weight:bold;color:#ffc107;">' + (result.already_in_group ? result.already_in_group.length : 0) + '</div>' +
                '<div style="font-size:12px;color:#aaa;">Already in group</div></div>' +
                '<div style="background:#e9456033;padding:10px 15px;border-radius:6px;text-align:center;min-width:100px;">' +
                '<div style="font-size:24px;font-weight:bold;color:#e94560;">' + (result.not_found ? result.not_found.length : 0) + '</div>' +
                '<div style="font-size:12px;color:#aaa;">Not found</div></div>' +
                '</div></div>';

            previewHtml += '<div style="max-height:300px;overflow-y:auto;background:#0a0a15;border-radius:4px;padding:10px;">';

            if (result.added && result.added.length > 0) {
                previewHtml += '<div style="margin-bottom:10px;"><span style="color:#00c853;font-weight:bold;">Will be added:</span><div style="margin-top:5px;padding-left:10px;color:#ccc;font-size:13px;">' +
                    result.added.map(a => '<div>' + escapeHtml(a) + '</div>').join('') + '</div></div>';
            }
            if (result.already_in_group && result.already_in_group.length > 0) {
                previewHtml += '<div style="margin-bottom:10px;"><span style="color:#ffc107;font-weight:bold;">Already in group (will skip):</span><div style="margin-top:5px;padding-left:10px;color:#888;font-size:13px;">' +
                    result.already_in_group.map(a => '<div>' + escapeHtml(a) + '</div>').join('') + '</div></div>';
            }
            if (result.not_found && result.not_found.length > 0) {
                previewHtml += '<div style="margin-bottom:10px;"><span style="color:#e94560;font-weight:bold;">Not found (no matching agent):</span><div style="margin-top:5px;padding-left:10px;color:#888;font-size:13px;">' +
                    result.not_found.map(a => '<div>' + escapeHtml(a) + '</div>').join('') + '</div></div>';
            }
            previewHtml += '</div>';

            const canImport = result.added && result.added.length > 0;
            const footer = '<button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>' +
                (canImport ? '<button class="btn btn-success" onclick="confirmCsvImport()"><svg class="icon"><use href="#icon-check"/></svg>Confirm Import (' + result.added.length + ')</button>' : '');

            showModal('Import Preview - ' + importTargetGroup, previewHtml, footer);
        }

        async function confirmCsvImport() {
            if (pendingImportData.length === 0) {
                showToast('No data to import', 'warning');
                return;
            }

            closeModal();
            showToast('Importing agents...', 'info');

            const result = await api('/groups/' + importTargetGroup + '/import', 'POST', {
                agents: pendingImportData,
                dry_run: false
            });

            pendingImportData = [];

            if (result) {
                const addedCount = result.added ? result.added.length : 0;
                if (addedCount > 0) {
                    showToast('Successfully added ' + addedCount + ' agent(s) to group', 'success');
                    refreshGroups();
                    refreshAgents();
                } else {
                    showToast('No agents were added', 'warning');
                }
            }
        }

        async function reconnectNodeAgents(nodeName) {
            if (!await showConfirm('Reconnect all agents on node "' + nodeName + '"?')) return;
            const dryRun = document.getElementById('dryRunMode').checked;
            const result = await api('/nodes/' + nodeName + '/reconnect', 'POST', { dry_run: dryRun });
            if (result) showToast(result.message || 'Reconnect command sent', 'success');
        }

        // Config Editor
        let configEditor = null;
        let currentConfigNode = null;
        let configEditMode = false;
        let configContent = '';

        async function showConfigModal(nodeName) {
            currentConfigNode = nodeName;
            configEditMode = false;
            showToast('Loading config...', 'info');

            const result = await api('/nodes/' + nodeName + '/config');
            if (!result || result.error) {
                // Check if this is a remote node error - show SSH setup tutorial
                if (result && result.is_remote) {
                    showSSHSetupTutorial(nodeName, result.node_ip || '');
                    return;
                }
                showToast(result ? result.error : 'Failed to load config', 'error');
                return;
            }

            configContent = result.content || '';

            const body = `
                <div style="margin-bottom:10px;display:flex;justify-content:space-between;align-items:center;">
                    <div><strong>File:</strong> <code>${escapeHtml(result.path) || '/var/ossec/etc/ossec.conf'}</code></div>
                    <div id="configToolbar" style="display:none;gap:8px;">
                        <button class="btn btn-sm" onclick="configEditor && configEditor.undo()"><svg class="icon"><use href="#icon-undo"/></svg>Undo</button>
                        <button class="btn btn-sm" onclick="configEditor && configEditor.redo()"><svg class="icon"><use href="#icon-redo"/></svg>Redo</button>
                    </div>
                </div>
                <div id="configEditorContainer" style="border:1px solid #444;border-radius:4px;overflow:auto;flex:1;min-height:300px;height:60vh;">
                    <textarea id="configEditorArea">${escapeHtml(configContent)}</textarea>
                </div>
                <div id="configSaveResult" style="margin-top:10px;"></div>
            `;
            const footer = `
                <button class="btn" onclick="downloadConfigFromModal()" title="Download ossec.conf"><svg class="icon"><use href="#icon-download"/></svg>Download</button>
                <button id="configEditBtn" class="btn btn-primary" onclick="toggleConfigEditMode()"><svg class="icon"><use href="#icon-edit"/></svg>Edit</button>
                <button id="configCancelBtn" class="btn" onclick="cancelConfigEdit()" style="display:none;"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>
                <button id="configSaveBtn" class="btn btn-success" onclick="saveConfig()" style="display:none;"><svg class="icon"><use href="#icon-save"/></svg>Save</button>
            `;
            showModal('ossec.conf - ' + nodeName, body, footer, true);

            // Make modal resizable
            const modalContent = document.querySelector('.modal-content');
            if (modalContent) {
                modalContent.classList.add('resizable');
            }

            // Initialize CodeMirror in read-only mode
            setTimeout(() => {
                const textarea = document.getElementById('configEditorArea');
                const container = document.getElementById('configEditorContainer');
                if (textarea && typeof CodeMirror !== 'undefined') {
                    configEditor = CodeMirror.fromTextArea(textarea, {
                        mode: 'xml',
                        theme: 'dracula',
                        lineNumbers: true,
                        lineWrapping: true,
                        indentUnit: 2,
                        tabSize: 2,
                        readOnly: true
                    });
                    configEditor.setSize('100%', '100%');

                    // Update editor size when modal is resized
                    if (container) {
                        const resizeObserver = new ResizeObserver(() => {
                            configEditor.refresh();
                        });
                        resizeObserver.observe(container);
                    }
                }
            }, 100);
        }

        function toggleConfigEditMode() {
            configEditMode = true;
            const editBtn = document.getElementById('configEditBtn');
            const saveBtn = document.getElementById('configSaveBtn');
            const cancelBtn = document.getElementById('configCancelBtn');
            const toolbar = document.getElementById('configToolbar');

            // Switch to edit mode
            if (configEditor) {
                configEditor.setOption('readOnly', false);
                configEditor.focus();
            }
            editBtn.style.display = 'none';
            cancelBtn.style.display = '';
            saveBtn.style.display = '';
            toolbar.style.display = 'flex';
            showToast('Edit mode enabled', 'info');
        }

        function cancelConfigEdit() {
            configEditMode = false;
            const editBtn = document.getElementById('configEditBtn');
            const saveBtn = document.getElementById('configSaveBtn');
            const cancelBtn = document.getElementById('configCancelBtn');
            const toolbar = document.getElementById('configToolbar');

            // Revert content and switch to view mode
            if (configEditor) {
                configEditor.setValue(configContent);  // Restore original content
                configEditor.setOption('readOnly', true);
            }
            editBtn.style.display = '';
            cancelBtn.style.display = 'none';
            saveBtn.style.display = 'none';
            toolbar.style.display = 'none';
            showToast('Edit cancelled', 'info');
        }

        function downloadConfigFromModal() {
            if (!currentConfigNode) return;
            // Create download from current content
            const content = configEditor ? configEditor.getValue() : configContent;
            const blob = new Blob([content], { type: 'application/xml' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = currentConfigNode + '_ossec.conf';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            showToast('Downloaded ' + currentConfigNode + '_ossec.conf', 'success');
        }

        async function saveConfig() {
            if (!configEditor || !currentConfigNode) return;

            const content = configEditor.getValue();
            if (!content.trim()) {
                showToast('Config cannot be empty', 'error');
                return;
            }

            const resultDiv = document.getElementById('configSaveResult');
            resultDiv.innerHTML = '<span style="color:#888;">Saving...</span>';

            const result = await api('/nodes/' + currentConfigNode + '/config', 'PUT', { content: content });

            if (!result) {
                resultDiv.innerHTML = '<span style="color:#e94560;">Failed to save config</span>';
                return;
            }

            if (result.error) {
                resultDiv.innerHTML = '<span style="color:#e94560;">Error: ' + result.error + '</span>';
                return;
            }

            let msg = '<span style="color:#4ade80;">Config saved successfully!</span>';
            if (result.backup_path) {
                msg += '<br><span style="color:#888;font-size:12px;">Backup: ' + result.backup_path + '</span>';
            }
            msg += '<br><br><span style="color:#f39c12;font-weight:bold;">Remember to restart services for changes to take effect!</span>';
            resultDiv.innerHTML = msg;

            showToast('Config saved! Remember to restart services.', 'success', 5000);
        }

        // Log Viewer Modal (for archives and alerts)
        let currentLogNode = null;
        let currentLogCategory = null;  // 'archives' or 'alerts'
        let currentLogType = null;  // 'log' or 'json'
        let currentLogLines = 100;
        let logViewerEditor = null;
        let jsonExpandState = {};  // Track expanded lines: {lineNum: {original, expandedCount}}

        async function showLogViewerModal(nodeName, category, logType) {
            currentLogNode = nodeName;
            currentLogCategory = category;
            currentLogType = logType;
            currentLogLines = 100;
            jsonExpandState = {};
            showToast('Loading ' + category + '...', 'info');

            const result = await api('/nodes/' + nodeName + '/logs/' + category + '/' + logType + '?lines=' + currentLogLines);
            if (!result || result.error) {
                if (result && result.is_remote) {
                    showSSHSetupTutorial(nodeName, '');
                    return;
                }
                showToast(result ? result.error : 'Failed to load ' + category, 'error');
                return;
            }

            const fileName = category + '.' + logType;
            const fileSize = formatFileSize(result.size || 0);

            const body = `
                <div style="margin-bottom:10px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;">
                    <div>
                        <strong>File:</strong> <code>${escapeHtml(result.path) || '/var/ossec/logs/' + category + '/' + fileName}</code>
                        <span style="margin-left:15px;color:#888;">Size: <strong>${fileSize}</strong></span>
                    </div>
                    <div style="display:flex;align-items:center;gap:10px;">
                        <label style="color:#888;font-size:13px;display:flex;align-items:center;gap:4px;cursor:pointer;">
                            <input type="checkbox" id="logWrapToggle" onchange="toggleLogWrap()" style="cursor:pointer;">
                            Wrap
                        </label>
                        <label style="color:#888;font-size:13px;">Lines:</label>
                        <select id="logLinesSelect" onchange="refreshLogViewerContent()" style="background:#1a1a2e;color:#eee;border:1px solid #444;padding:4px 8px;border-radius:4px;">
                            <option value="100" selected>Last 100</option>
                            <option value="500">Last 500</option>
                            <option value="1000">Last 1,000</option>
                            <option value="5000">Last 5,000</option>
                            <option value="10000">Last 10,000</option>
                        </select>
                        <button class="btn btn-sm btn-primary" onclick="refreshLogViewerContent()" title="Refresh content"><svg class="icon"><use href="#icon-refresh"/></svg>Refresh</button>
                    </div>
                </div>
                <div id="logViewerContainer" style="border:1px solid #444;border-radius:4px;overflow:auto;flex:1;min-height:0;">
                    <textarea id="logViewerArea">${escapeHtml(result.content || '')}</textarea>
                </div>
            `;
            const footer = `<button class="btn" onclick="downloadLogFromModal()" title="Download ${fileName}"><svg class="icon"><use href="#icon-download"/></svg>Download</button>`;
            showModal(fileName + ' - ' + nodeName, body, footer, true);

            // Make modal resizable
            const modalContent = document.querySelector('.modal-content');
            if (modalContent) {
                modalContent.classList.add('resizable');
            }

            // Initialize CodeMirror in read-only mode
            setTimeout(() => {
                const textarea = document.getElementById('logViewerArea');
                const container = document.getElementById('logViewerContainer');
                if (textarea && typeof CodeMirror !== 'undefined') {
                    const mode = currentLogType === 'json' ? {name: 'javascript', json: true} : 'wazuh-alerts';
                    const gutters = currentLogType === 'json' ? ['json-gutter', 'CodeMirror-linenumbers'] : ['CodeMirror-linenumbers'];
                    logViewerEditor = CodeMirror.fromTextArea(textarea, {
                        mode: mode,
                        theme: 'dracula',
                        lineNumbers: true,
                        lineWrapping: false,
                        readOnly: true,
                        scrollbarStyle: 'native',
                        gutters: gutters
                    });

                    // Set height based on container
                    const containerHeight = container ? container.clientHeight : 400;
                    logViewerEditor.setSize('100%', Math.max(containerHeight, 400) + 'px');

                    // Update editor size when modal is resized
                    if (container) {
                        const resizeObserver = new ResizeObserver(() => {
                            const newHeight = container.clientHeight || 400;
                            logViewerEditor.setSize('100%', Math.max(newHeight, 400) + 'px');
                            logViewerEditor.refresh();
                        });
                        resizeObserver.observe(container);
                    }

                    // Add JSON expand markers
                    if (currentLogType === 'json') {
                        addJsonExpandMarkers();
                    }

                    // Scroll to bottom
                    logViewerEditor.scrollIntoView({line: logViewerEditor.lineCount() - 1, ch: 0});
                }
            }, 100);
        }

        function addJsonExpandMarkers() {
            if (!logViewerEditor) return;
            const lineCount = logViewerEditor.lineCount();
            for (let i = 0; i < lineCount; i++) {
                const line = logViewerEditor.getLine(i);
                if (line && (line.trim().startsWith('{') || line.trim().startsWith('['))) {
                    const marker = document.createElement('span');
                    marker.className = 'json-expand-marker';
                    marker.innerHTML = '<svg><use href="#icon-chevron-right"/></svg>';
                    marker.title = 'Expand JSON';
                    marker.onclick = (function(lineNum) {
                        return function(e) {
                            e.stopPropagation();
                            toggleJsonExpand(lineNum);
                        };
                    })(i);
                    logViewerEditor.setGutterMarker(i, 'json-gutter', marker);
                }
            }
        }

        function highlightJson(json) {
            return json.replace(/("(?:\\u[\da-fA-F]{4}|\\[^u]|[^\\"])*")(\s*:)?|(\b(?:true|false)\b)|(\bnull\b)|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|([{}\[\],:])/g,
                function(match, str, colon, bool, nil, num, bracket) {
                    if (str) {
                        if (colon) {
                            return '<span class="json-key">' + escapeHtml(str) + '</span>:';
                        }
                        return '<span class="json-string">' + escapeHtml(str) + '</span>';
                    }
                    if (bool) return '<span class="json-boolean">' + bool + '</span>';
                    if (nil) return '<span class="json-null">' + nil + '</span>';
                    if (num) return '<span class="json-number">' + num + '</span>';
                    if (bracket) return '<span class="json-bracket">' + bracket + '</span>';
                    return match;
                });
        }

        function toggleJsonExpand(lineNum) {
            if (!logViewerEditor) return;
            const state = jsonExpandState[lineNum];
            if (state) {
                // Collapse: remove widget
                if (state.widget) {
                    state.widget.clear();
                }
                const marker = document.createElement('span');
                marker.className = 'json-expand-marker';
                marker.innerHTML = '<svg><use href="#icon-chevron-right"/></svg>';
                marker.title = 'Expand JSON';
                marker.onclick = (function(ln) {
                    return function(e) { e.stopPropagation(); toggleJsonExpand(ln); };
                })(lineNum);
                logViewerEditor.setGutterMarker(lineNum, 'json-gutter', marker);
                delete jsonExpandState[lineNum];
            } else {
                // Expand: add widget below line
                const lineContent = logViewerEditor.getLine(lineNum);
                try {
                    const parsed = JSON.parse(lineContent.trim());
                    const formatted = JSON.stringify(parsed, null, 2);
                    const widgetEl = document.createElement('div');
                    widgetEl.className = 'json-expanded-widget';
                    widgetEl.innerHTML = highlightJson(formatted);
                    const widget = logViewerEditor.addLineWidget(lineNum, widgetEl, {coverGutter: false, noHScroll: false});
                    jsonExpandState[lineNum] = { widget: widget };
                    const marker = document.createElement('span');
                    marker.className = 'json-expand-marker expanded';
                    marker.innerHTML = '<svg><use href="#icon-chevron-down"/></svg>';
                    marker.title = 'Collapse JSON';
                    marker.onclick = (function(ln) {
                        return function(e) { e.stopPropagation(); toggleJsonExpand(ln); };
                    })(lineNum);
                    logViewerEditor.setGutterMarker(lineNum, 'json-gutter', marker);
                } catch (e) {
                    showToast('Invalid JSON', 'error');
                }
            }
        }

        function rebuildJsonMarkers() {
            if (!logViewerEditor || currentLogType !== 'json') return;
            // Clear all widgets
            for (const lineNum in jsonExpandState) {
                if (jsonExpandState[lineNum].widget) {
                    jsonExpandState[lineNum].widget.clear();
                }
            }
            const lineCount = logViewerEditor.lineCount();
            for (let i = 0; i < lineCount; i++) {
                logViewerEditor.setGutterMarker(i, 'json-gutter', null);
            }
            jsonExpandState = {};
            addJsonExpandMarkers();
        }

        function toggleLogWrap() {
            if (!logViewerEditor) return;
            const checkbox = document.getElementById('logWrapToggle');
            const wrap = checkbox ? checkbox.checked : false;
            logViewerEditor.setOption('lineWrapping', wrap);
        }

        async function refreshLogViewerContent() {
            if (!currentLogNode || !currentLogCategory || !currentLogType) return;

            const select = document.getElementById('logLinesSelect');
            if (select) {
                currentLogLines = parseInt(select.value) || 100;
            }

            showToast('Refreshing...', 'info');
            const result = await api('/nodes/' + currentLogNode + '/logs/' + currentLogCategory + '/' + currentLogType + '?lines=' + currentLogLines);

            if (!result || result.error) {
                showToast(result ? result.error : 'Failed to refresh', 'error');
                return;
            }

            // Clear existing widgets
            for (const lineNum in jsonExpandState) {
                if (jsonExpandState[lineNum].widget) {
                    jsonExpandState[lineNum].widget.clear();
                }
            }
            jsonExpandState = {};
            if (logViewerEditor) {
                logViewerEditor.setValue(result.content || '');
                if (currentLogType === 'json') {
                    setTimeout(function() { addJsonExpandMarkers(); }, 50);
                }
                // Scroll to bottom
                setTimeout(function() {
                    logViewerEditor.scrollIntoView({line: logViewerEditor.lineCount() - 1, ch: 0});
                }, 60);
            }
            showToast('Content refreshed (' + currentLogLines + ' lines)', 'success');
        }

        function downloadLogFromModal() {
            if (!currentLogNode || !currentLogCategory || !currentLogType) return;
            const fileName = currentLogCategory + '.' + currentLogType;
            const content = logViewerEditor ? logViewerEditor.getValue() : '';
            const mimeType = currentLogType === 'json' ? 'application/json' : 'text/plain';
            const blob = new Blob([content], { type: mimeType });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = currentLogNode + '_' + fileName;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            showToast('Downloaded ' + currentLogNode + '_' + fileName, 'success');
        }

        // SSH Setup Tutorial
        function copyToClipboard(btn) {
            const text = btn.getAttribute('data-copy');
            if (!text) return;

            navigator.clipboard.writeText(text).then(() => {
                const originalHtml = btn.innerHTML;
                btn.innerHTML = '<svg class="icon" style="width:14px;height:14px;color:#4ade80;"><use href="#icon-check"/></svg>';
                showToast('Copied to clipboard', 'success', 1500);
                setTimeout(() => { btn.innerHTML = originalHtml; }, 1500);
            }).catch((err) => {
                // Fallback for older browsers or non-secure contexts
                const textarea = document.createElement('textarea');
                textarea.value = text;
                textarea.style.position = 'fixed';
                textarea.style.opacity = '0';
                document.body.appendChild(textarea);
                textarea.select();
                try {
                    document.execCommand('copy');
                    const originalHtml = btn.innerHTML;
                    btn.innerHTML = '<svg class="icon" style="width:14px;height:14px;color:#4ade80;"><use href="#icon-check"/></svg>';
                    showToast('Copied to clipboard', 'success', 1500);
                    setTimeout(() => { btn.innerHTML = originalHtml; }, 1500);
                } catch (e) {
                    showToast('Failed to copy to clipboard', 'error');
                }
                document.body.removeChild(textarea);
            });
        }

        // Settings Modal
        async function showSettingsModal() {
            showModal('Settings', '<div class="loading"><div class="spinner"></div>Loading...</div>', '');

            try {
                const data = await api('/settings');
                if (!data) {
                    document.getElementById('modalBody').innerHTML = '<div class="alert alert-error">Failed to load settings</div>';
                    return;
                }

                const sshEnabled = data.ssh_enabled || false;
                const sshNodes = data.ssh_nodes || {};
                const sshNodesCount = Object.keys(sshNodes).length;

                const body = `
                    <div style="display:flex;flex-direction:column;gap:20px;">
                        <div style="background:#0f3460;padding:15px;border-radius:8px;">
                            <h4 style="color:#4fc3f7;margin:0 0 15px 0;">API Connection</h4>
                            <table style="width:100%;font-size:14px;">
                                <tr><td style="color:#888;padding:5px 8px;width:120px;">Host</td><td style="color:#eee;padding:5px 8px;">{{ host }}</td></tr>
                                <tr><td style="color:#888;padding:5px 8px;">Port</td><td style="color:#eee;padding:5px 8px;">{{ port }}</td></tr>
                                <tr><td style="color:#888;padding:5px 8px;">Username</td><td style="color:#eee;padding:5px 8px;">{{ username }}</td></tr>
                                <tr><td style="color:#888;padding:5px 8px;">SSL Verify</td><td style="color:#eee;padding:5px 8px;">${data.api_verify_ssl ? '<span style="color:#4ade80;">Enabled</span>' : '<span style="color:#ffc107;">Disabled</span>'}</td></tr>
                            </table>
                        </div>

                        <div style="background:#0f3460;padding:15px;border-radius:8px;">
                            <h4 style="color:#4fc3f7;margin:0 0 15px 0;">SSH Configuration</h4>
                            <table style="width:100%;font-size:14px;">
                                <tr><td style="color:#888;padding:5px 8px;width:120px;">Status</td><td style="padding:5px 8px;">${sshEnabled ? '<span style="color:#4ade80;">Enabled</span>' : '<span style="color:#888;">Disabled</span>'}</td></tr>
                                <tr><td style="color:#888;padding:5px 8px;">Key File</td><td style="color:#eee;padding:5px 8px;">${data.ssh_key_file || '<span style="color:#666;">Not configured</span>'}</td></tr>
                                <tr><td style="color:#888;padding:5px 8px;">Configured Nodes</td><td style="color:#eee;padding:5px 8px;">${sshNodesCount > 0 ? sshNodesCount + ' node(s)' : '<span style="color:#666;">None</span>'}</td></tr>
                            </table>
                            ${sshNodesCount > 0 ? '<div style="margin-top:10px;padding:10px;background:#1a1a2e;border-radius:4px;font-size:12px;color:#aaa;">' + Object.entries(sshNodes).map(([name, cfg]) => name + ' → ' + (cfg.host || cfg.ip || '?') + ':' + (cfg.port || 22)).join('<br>') + '</div>' : ''}
                            ${!sshEnabled ? '<p style="color:#888;font-size:12px;margin:10px 0 0 0;">SSH is required for remote node config editing and service management.</p>' : ''}
                        </div>

                        <div style="background:#0f3460;padding:15px;border-radius:8px;">
                            <h4 style="color:#4fc3f7;margin:0 0 15px 0;">About</h4>
                            <table style="width:100%;font-size:14px;">
                                <tr><td style="color:#888;padding:5px 8px;width:120px;">Version</td><td style="color:#eee;padding:5px 8px;">v{{ version }}</td></tr>
                                <tr><td style="color:#888;padding:5px 8px;">Author</td><td style="color:#eee;padding:5px 8px;">Jason Cheng</td></tr>
                                <tr><td style="color:#888;padding:5px 8px;">Repository</td><td style="padding:5px 8px;"><a href="https://github.com/jasoncheng7115/it-scripts/tree/master/jt_wazuh_agent_mgr" target="_blank" style="color:#4fc3f7;">GitHub</a></td></tr>
                            </table>
                        </div>
                    </div>
                `;

                showModal('Settings', body, '');
            } catch (e) {
                document.getElementById('modalBody').innerHTML = '<div class="alert alert-error">Error loading settings: ' + e.message + '</div>';
            }
        }

        async function showSSHSetupTutorial(nodeName, nodeIp) {
            // Get config file path from settings
            let configFilePath = 'config.yaml';
            try {
                const settings = await api('/settings');
                if (settings && settings.config_file_path) {
                    configFilePath = settings.config_file_path;
                }
            } catch (e) { /* ignore */ }

            const cmd1 = 'ssh-keygen -t ed25519 -f /root/.ssh/wazuh_cluster_key -N ""';
            const cmd2 = 'ssh-copy-id -i /root/.ssh/wazuh_cluster_key.pub root@' + nodeIp;
            const cmd3 = 'ssh -i /root/.ssh/wazuh_cluster_key root@' + nodeIp + ' "hostname"';
            const cmd4 = 'ssh:\\n  enabled: true\\n  key_file: /root/.ssh/wazuh_cluster_key\\n  nodes:\\n    ' + nodeName + ':\\n      host: ' + nodeIp + '\\n      user: root';

            const codeBlockStyle = 'background:#0d0d1a;padding:12px;border-radius:6px;overflow-x:auto;color:#4ade80;font-size:13px;display:flex;justify-content:space-between;align-items:center;gap:10px;';
            const copyBtnStyle = 'background:transparent;border:1px solid #444;border-radius:4px;padding:4px 8px;cursor:pointer;color:#888;flex-shrink:0;display:flex;align-items:center;';

            const body = `
                <div style="line-height:1.8;">
                    <div style="background:#1f2d1f;padding:15px;border-radius:8px;margin-bottom:15px;border-left:4px solid #4ade80;">
                        <strong style="color:#4ade80;">Optional Setup</strong>
                        <p style="margin:10px 0 0 0;color:#aaa;">
                            SSH configuration is <strong>optional</strong>. Only needed if you want to edit worker node configs
                            or restart services remotely from this web interface.
                        </p>
                    </div>

                    <div style="background:#1a1a2e;padding:15px;border-radius:8px;margin-bottom:20px;border-left:4px solid #4fc3f7;">
                        <strong style="color:#4fc3f7;">Why SSH Setup?</strong>
                        <p style="margin:10px 0 0 0;color:#aaa;">
                            Wazuh API does not provide access to raw config files on worker nodes.
                            To enable remote config editing, you need to set up SSH key-based authentication
                            from the master node to worker nodes.
                        </p>
                    </div>

                    <h4 style="color:#4fc3f7;margin:20px 0 10px 0;">Step 1: Generate SSH Key on Master Node</h4>
                    <p style="color:#aaa;margin-bottom:10px;">Run this on the <strong>master node</strong> (as root):</p>
                    <div style="${codeBlockStyle}">
                        <code style="white-space:pre-wrap;word-break:break-all;">${escapeHtml(cmd1)}</code>
                        <button style="${copyBtnStyle}" data-copy="${escapeHtml(cmd1)}" onclick="copyToClipboard(this)" title="Copy to clipboard"><svg class="icon" style="width:14px;height:14px;"><use href="#icon-copy"/></svg></button>
                    </div>

                    <h4 style="color:#4fc3f7;margin:20px 0 10px 0;">Step 2: Copy Public Key to Worker Node</h4>
                    <p style="color:#aaa;margin-bottom:10px;">Copy the public key to <strong>${escapeHtml(nodeName)}</strong> (${escapeHtml(nodeIp)}):</p>
                    <div style="${codeBlockStyle}">
                        <code style="white-space:pre-wrap;word-break:break-all;">${escapeHtml(cmd2)}</code>
                        <button style="${copyBtnStyle}" data-copy="${escapeHtml(cmd2)}" onclick="copyToClipboard(this)" title="Copy to clipboard"><svg class="icon" style="width:14px;height:14px;"><use href="#icon-copy"/></svg></button>
                    </div>
                    <p style="color:#888;font-size:12px;margin-top:5px;">Or manually append the public key to <code>/root/.ssh/authorized_keys</code> on the worker node.</p>

                    <h4 style="color:#4fc3f7;margin:20px 0 10px 0;">Step 3: Test SSH Connection</h4>
                    <p style="color:#aaa;margin-bottom:10px;">Verify passwordless SSH works:</p>
                    <div style="${codeBlockStyle}">
                        <code style="white-space:pre-wrap;word-break:break-all;">${escapeHtml(cmd3)}</code>
                        <button style="${copyBtnStyle}" data-copy="${escapeHtml(cmd3)}" onclick="copyToClipboard(this)" title="Copy to clipboard"><svg class="icon" style="width:14px;height:14px;"><use href="#icon-copy"/></svg></button>
                    </div>

                    <h4 style="color:#4fc3f7;margin:20px 0 10px 0;">Step 4: Configure This Tool</h4>
                    <p style="color:#aaa;margin-bottom:10px;">Add SSH settings to <code style="color:#4ade80;">${escapeHtml(configFilePath)}</code>:</p>
                    <div style="${codeBlockStyle}">
                        <code style="white-space:pre-wrap;">${escapeHtml(cmd4)}</code>
                        <button style="${copyBtnStyle}" data-copy="${escapeHtml(cmd4).replace(/\\n/g, '&#10;')}" onclick="copyToClipboard(this)" title="Copy to clipboard"><svg class="icon" style="width:14px;height:14px;"><use href="#icon-copy"/></svg></button>
                    </div>

                    <div style="background:#2d2d1f;padding:15px;border-radius:8px;margin-top:15px;border-left:4px solid #ffc107;">
                        <strong style="color:#ffc107;">Important</strong>
                        <p style="margin:10px 0 0 0;color:#aaa;">
                            After modifying <code>config.yaml</code>, you must <strong>restart this tool</strong> for changes to take effect.
                        </p>
                    </div>

                    <div style="background:#2d1f1f;padding:15px;border-radius:8px;margin-top:15px;border-left:4px solid #e94560;">
                        <strong style="color:#e94560;">Security Note</strong>
                        <p style="margin:10px 0 0 0;color:#aaa;">
                            Ensure proper file permissions on SSH keys (600 for private key).
                            Consider using a dedicated service account instead of root for production environments.
                        </p>
                    </div>
                </div>
            `;
            showModal('SSH Setup Guide - ' + escapeHtml(nodeName), body, '', true);
        }

        // Group Config Editor
        let groupConfigEditor = null;
        let currentConfigGroup = null;

        let groupConfigEditMode = false;

        async function showGroupAgentConfModal(groupName) {
            currentConfigGroup = groupName;
            groupConfigEditMode = false;
            showToast('Loading agent.conf...', 'info');

            const result = await api('/groups/' + encodeURIComponent(groupName) + '/config');
            if (!result || result.error) {
                showToast(result ? result.error : 'Failed to load config', 'error');
                return;
            }

            renderGroupAgentConfModal(groupName, result.content, result.path);
        }

        function renderGroupAgentConfModal(groupName, content, filePath) {
            const isEdit = groupConfigEditMode;
            const body = `
                <div style="margin-bottom:10px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;">
                    <div><strong>File:</strong> <code>${escapeHtml(filePath) || '/var/ossec/etc/shared/' + escapeHtml(groupName) + '/agent.conf'}</code></div>
                    <div style="display:flex;gap:8px;" id="groupConfigToolbar">
                        ${isEdit ? `
                            <button class="btn btn-sm" onclick="groupConfigEditor && groupConfigEditor.undo()"><svg class="icon"><use href="#icon-undo"/></svg>Undo</button>
                            <button class="btn btn-sm" onclick="groupConfigEditor && groupConfigEditor.redo()"><svg class="icon"><use href="#icon-redo"/></svg>Redo</button>
                        ` : ''}
                    </div>
                </div>
                <div id="groupConfigEditorContainer" style="border:1px solid #444;border-radius:4px;overflow:auto;flex:1;min-height:300px;height:60vh;">
                    <textarea id="groupConfigEditorArea">${escapeHtml(content) || ''}</textarea>
                </div>
                ${isEdit ? `<p style="color:#888;font-size:12px;margin-top:10px;">This config will be applied to all agents in group "${escapeHtml(groupName)}".</p>` : ''}
                <div id="groupConfigSaveResult" style="margin-top:10px;"></div>
            `;
            const footer = isEdit ? `
                <button class="btn" onclick="switchGroupConfigMode(false)"><svg class="icon"><use href="#icon-eye"/></svg>View</button>
                <button class="btn" onclick="downloadGroupConfig('${groupName.replace(/'/g, "\\'")}')"><svg class="icon"><use href="#icon-download"/></svg>Download</button>
                <button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>
                <button class="btn btn-success" onclick="saveGroupConfig()"><svg class="icon"><use href="#icon-save"/></svg>Save</button>
            ` : `
                <button class="btn btn-primary" onclick="switchGroupConfigMode(true)"><svg class="icon"><use href="#icon-edit"/></svg>Edit</button>
                <button class="btn" onclick="downloadGroupConfig('${groupName.replace(/'/g, "\\'")}')"><svg class="icon"><use href="#icon-download"/></svg>Download</button>
            `;

            showModal('agent.conf - ' + escapeHtml(groupName), body, footer, true);

            // Make modal resizable
            const modalContent = document.querySelector('.modal-content');
            if (modalContent) {
                modalContent.classList.add('resizable');
            }

            // Initialize CodeMirror
            setTimeout(() => {
                const textarea = document.getElementById('groupConfigEditorArea');
                const container = document.getElementById('groupConfigEditorContainer');
                if (textarea && typeof CodeMirror !== 'undefined') {
                    groupConfigEditor = CodeMirror.fromTextArea(textarea, {
                        mode: 'xml',
                        theme: 'dracula',
                        lineNumbers: true,
                        lineWrapping: true,
                        indentUnit: 2,
                        tabSize: 2,
                        readOnly: !isEdit
                    });
                    groupConfigEditor.setSize('100%', '100%');

                    // Update editor size when modal is resized
                    if (container) {
                        const resizeObserver = new ResizeObserver(() => {
                            groupConfigEditor.refresh();
                        });
                        resizeObserver.observe(container);
                    }
                }
            }, 100);
        }

        function switchGroupConfigMode(editMode) {
            if (!groupConfigEditor || !currentConfigGroup) return;
            const content = groupConfigEditor.getValue();
            groupConfigEditMode = editMode;
            renderGroupAgentConfModal(currentConfigGroup, content, null);
        }

        async function saveGroupConfig() {
            if (!groupConfigEditor || !currentConfigGroup) return;

            const content = groupConfigEditor.getValue();
            const resultDiv = document.getElementById('groupConfigSaveResult');
            resultDiv.innerHTML = '<span style="color:#888;">Saving...</span>';

            const result = await api('/groups/' + encodeURIComponent(currentConfigGroup) + '/config', 'PUT', { content: content });

            if (!result) {
                resultDiv.innerHTML = '<span style="color:#e94560;">Failed to save config</span>';
                return;
            }

            if (result.error) {
                resultDiv.innerHTML = '<span style="color:#e94560;">Error: ' + escapeHtml(result.error) + '</span>';
                return;
            }

            let msg = '<span style="color:#4ade80;">Config saved successfully!</span>';
            if (result.backup_path) {
                msg += '<br><span style="color:#888;font-size:12px;">Backup: ' + escapeHtml(result.backup_path) + '</span>';
            }
            msg += '<br><br><span style="color:#f39c12;">Agents will receive updated config on next keepalive.</span>';
            resultDiv.innerHTML = msg;

            showToast('Group config saved!', 'success', 5000);
        }

        function downloadGroupConfig(groupName) {
            window.open('/api/groups/' + encodeURIComponent(groupName) + '/config/download', '_blank');
        }

        async function restartNodeServices(nodeName) {
            if (!await showConfirm('Restart all Wazuh services on node "' + nodeName + '"? This may briefly interrupt monitoring.', true)) return;

            // Show waiting modal
            const modalBody = `
                <div style="text-align:center;padding:20px;">
                    <div class="spinner" style="margin:0 auto 20px;"></div>
                    <div id="restartStatus" style="color:#4fc3f7;font-size:16px;margin-bottom:10px;">Sending restart command...</div>
                    <div id="restartProgress" style="color:#888;font-size:13px;"></div>
                </div>
            `;
            showModal('Restarting ' + nodeName, modalBody, '', false);

            const updateStatus = (status, progress) => {
                const statusEl = document.getElementById('restartStatus');
                const progressEl = document.getElementById('restartProgress');
                if (statusEl) statusEl.textContent = status;
                if (progressEl) progressEl.textContent = progress || '';
            };

            const result = await api('/nodes/' + nodeName + '/restart', 'POST');

            if (!result) {
                closeModal();
                showToast('Failed to restart services', 'error');
                return;
            }

            if (result.error) {
                closeModal();
                if (result.is_remote) {
                    showSSHSetupTutorial(nodeName, result.node_ip || '');
                    return;
                }
                showToast('Error: ' + result.error, 'error');
                return;
            }

            // Wait for node to come back up
            updateStatus('Services restarting...', 'Waiting for node to come back online');

            let attempts = 0;
            const maxAttempts = 30;  // 30 attempts * 2 seconds = 60 seconds max
            const checkInterval = 2000;

            const checkNodeStatus = async () => {
                attempts++;
                updateStatus('Waiting for services...', `Checking status (${attempts}/${maxAttempts})`);

                try {
                    const statusResult = await api('/nodes/' + nodeName + '/services');
                    if (statusResult && !statusResult.error && statusResult.services) {
                        // Check if all critical services are running
                        const runningCount = statusResult.services.filter(s => s.status === 'running').length;
                        const totalCount = statusResult.services.length;

                        if (runningCount > 0) {
                            updateStatus('Services starting...', `${runningCount}/${totalCount} services running`);

                            // Consider success if most services are running
                            if (runningCount >= totalCount * 0.8) {
                                closeModal();
                                showToast('Services restarted successfully on ' + nodeName, 'success');
                                refreshNodes();
                                return;
                            }
                        }
                    }
                } catch (e) {
                    // Node might still be restarting, continue waiting
                }

                if (attempts < maxAttempts) {
                    setTimeout(checkNodeStatus, checkInterval);
                } else {
                    closeModal();
                    showToast('Restart command sent. Node may still be starting up.', 'warning');
                    refreshNodes();
                }
            };

            // Start checking after initial delay
            setTimeout(checkNodeStatus, 3000);
        }

        async function downloadFile(nodeName, fileType) {
            const url = '/api/nodes/' + nodeName + '/download/' + fileType;
            try {
                const response = await fetch(url);
                if (!response.ok) {
                    const data = await response.json();
                    // Check if this is a remote node error - show SSH setup tutorial
                    if (data.is_remote) {
                        showSSHSetupTutorial(nodeName, data.node_ip || '');
                        return;
                    }
                    showToast(data.error || 'Download failed', 'error');
                    return;
                }
                // Trigger download
                const blob = await response.blob();
                const filename = fileType === 'config' ? nodeName + '_ossec.conf' : nodeName + '_cluster.key';
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = filename;
                a.click();
                URL.revokeObjectURL(a.href);
            } catch (e) {
                showToast('Download failed: ' + e.message, 'error');
            }
        }

        let upgradeFilesData = [];
        let upgradeFilesSortCol = 'version';
        let upgradeFilesSortAsc = false;
        let upgradeFilesNodeName = '';
        let upgradeFilesManagerVersion = '';

        async function showUpgradeFiles(nodeName) {
            upgradeFilesNodeName = nodeName;
            const body = `<div id="upgradeFilesContent"><div class="loading"><div class="spinner"></div>Loading...</div></div>`;
            showModal('Agent Upgrade Files - ' + nodeName, body, '');
            // Make modal wider and resizable
            const modalContent = document.querySelector('.modal-content');
            modalContent.classList.add('resizable');
            modalContent.style.width = '1000px';
            modalContent.style.height = '600px';
            modalContent.style.maxWidth = '95vw';
            modalContent.style.position = 'relative';

            await loadUpgradeFiles(nodeName);
        }

        async function loadUpgradeFiles(nodeName) {
            const content = document.getElementById('upgradeFilesContent');
            content.style.height = '100%';
            content.innerHTML = '<div class="loading"><div class="spinner"></div>Loading...</div>';

            const data = await api('/nodes/' + nodeName + '/upgrade-files');

            if (!data) {
                content.innerHTML = '<div style="color:#e94560;">Failed to load upgrade files</div>';
                return;
            }

            if (data.error) {
                if (data.is_remote) {
                    showSSHSetupTutorial(nodeName, data.node_ip || '');
                    return;
                }
                content.innerHTML = '<div style="color:#e94560;">Error: ' + escapeHtml(data.error) + '</div>';
                return;
            }

            upgradeFilesManagerVersion = data.manager_version || '';
            const files = data.files || [];

            // Parse and store files data
            upgradeFilesData = files.map(f => {
                const match = f.name.match(/wazuh_agent_v([\d.]+)_(\w+)/);
                return {
                    name: f.name,
                    version: match ? match[1] : '-',
                    platform: match ? match[2] : '-',
                    size: f.size
                };
            });
            // Default sort by version descending (newest first)
            upgradeFilesSortCol = 'version';
            upgradeFilesSortAsc = false;

            renderUpgradeFilesTable(data.path);
        }

        function renderUpgradeFilesTable(path) {
            const content = document.getElementById('upgradeFilesContent');

            // Format file size
            function formatSize(bytes) {
                if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(1) + ' GB';
                if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
                if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB';
                return bytes + ' B';
            }

            // Sort data
            const sorted = [...upgradeFilesData].sort((a, b) => {
                let valA = a[upgradeFilesSortCol];
                let valB = b[upgradeFilesSortCol];
                if (upgradeFilesSortCol === 'size') {
                    return upgradeFilesSortAsc ? valA - valB : valB - valA;
                }
                if (upgradeFilesSortCol === 'version') {
                    // Version comparison (e.g., 4.13.0 vs 4.12.0)
                    const partsA = valA.split('.').map(Number);
                    const partsB = valB.split('.').map(Number);
                    for (let i = 0; i < Math.max(partsA.length, partsB.length); i++) {
                        const diff = (partsA[i] || 0) - (partsB[i] || 0);
                        if (diff !== 0) return upgradeFilesSortAsc ? diff : -diff;
                    }
                    return 0;
                }
                return upgradeFilesSortAsc ? valA.localeCompare(valB) : valB.localeCompare(valA);
            });

            // Generate sort indicator (same style as agents table)
            function sortClass(col) {
                if (upgradeFilesSortCol !== col) return '';
                return upgradeFilesSortAsc ? 'asc' : 'desc';
            }
            const sortIcons = '<svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg>';

            let tableRows = '';
            if (sorted.length === 0) {
                tableRows = '<tr><td colspan="5" style="text-align:center;color:#888;padding:20px;">No WPK files found</td></tr>';
            } else {
                tableRows = sorted.map(f => `<tr>
                    <td style="font-family:monospace;font-size:12px;">${escapeHtml(f.name)}</td>
                    <td style="text-align:center;">${f.version}</td>
                    <td style="text-align:center;">${f.platform}</td>
                    <td style="text-align:right;white-space:nowrap;">${formatSize(f.size)}</td>
                    <td style="text-align:center;"><button class="btn btn-sm btn-danger" onclick="deleteUpgradeFile('${escapeHtml(f.name).replace(/'/g, "\\'")}')"><svg class="icon"><use href="#icon-trash"/></svg></button></td>
                </tr>`).join('');
            }

            const versionInfo = upgradeFilesManagerVersion ?
                `<span style="background:#0f3460;padding:4px 10px;border-radius:4px;margin-left:10px;">Manager: <strong style="color:#4fc3f7;">v${escapeHtml(upgradeFilesManagerVersion)}</strong></span>` : '';

            content.innerHTML = `
                <div style="display:flex;flex-direction:column;height:100%;">
                    <div style="background:#1a1a2e;border-left:3px solid #4fc3f7;padding:10px 15px;margin-bottom:15px;border-radius:4px;flex-shrink:0;">
                        <p style="color:#aaa;font-size:12px;margin:0;">These WPK packages are automatically downloaded from Wazuh official site when an agent connected to this node requests an upgrade. You can also manually upload WPK files for offline environments.</p>
                    </div>
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:15px;flex-wrap:wrap;gap:10px;flex-shrink:0;">
                        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
                            <span style="color:#888;">Path: <code style="background:#1a1a2e;padding:4px 8px;border-radius:4px;">${escapeHtml(path)}</code></span>
                            ${versionInfo}
                        </div>
                        <div style="display:flex;gap:8px;flex-wrap:wrap;">
                            <a href="https://documentation.wazuh.com/current/user-manual/agent/agent-management/remote-upgrading/wpk-files/wpk-list.html" target="_blank" class="btn btn-sm" style="background:#17a2b8;color:#fff;text-decoration:none;"><svg class="icon"><use href="#icon-link"/></svg>Official WPK List</a>
                            <button class="btn btn-sm btn-success" onclick="document.getElementById('wpkFileInput').click()"><svg class="icon"><use href="#icon-upload"/></svg>Upload WPK</button>
                            <input type="file" id="wpkFileInput" accept=".wpk" style="display:none;" onchange="uploadWpkFile(this)">
                        </div>
                    </div>
                    <div style="flex:1;overflow-y:auto;min-height:150px;">
                        <table style="table-layout:auto;width:100%;" id="upgradeFilesTable">
                            <thead><tr>
                                <th class="sortable ${sortClass('name')}" style="text-align:left;" onclick="sortUpgradeFiles('name','${path}')">Filename${sortIcons}</th>
                                <th class="sortable ${sortClass('version')}" style="width:80px;text-align:center;" onclick="sortUpgradeFiles('version','${path}')">Version${sortIcons}</th>
                                <th class="sortable ${sortClass('platform')}" style="width:100px;text-align:center;" onclick="sortUpgradeFiles('platform','${path}')">Platform${sortIcons}</th>
                                <th class="sortable ${sortClass('size')}" style="width:80px;text-align:right;" onclick="sortUpgradeFiles('size','${path}')">Size${sortIcons}</th>
                                <th style="width:50px;text-align:center;">Del</th>
                            </tr></thead>
                            <tbody>${tableRows}</tbody>
                        </table>
                    </div>
                    <p style="color:#888;margin-top:15px;font-size:12px;flex-shrink:0;">Total: ${upgradeFilesData.length} file(s)</p>
                </div>
            `;
        }

        function sortUpgradeFiles(col, path) {
            if (upgradeFilesSortCol === col) {
                upgradeFilesSortAsc = !upgradeFilesSortAsc;
            } else {
                upgradeFilesSortCol = col;
                upgradeFilesSortAsc = true;
            }
            renderUpgradeFilesTable(path);
        }

        async function uploadWpkFile(input) {
            if (!input.files || input.files.length === 0) return;

            const file = input.files[0];
            if (!file.name.endsWith('.wpk')) {
                showToast('Only .wpk files are allowed', 'error');
                input.value = '';
                return;
            }

            showToast('Uploading ' + file.name + '...', 'info');

            const formData = new FormData();
            formData.append('file', file);

            try {
                const response = await fetch('/api/nodes/' + upgradeFilesNodeName + '/upgrade-files', {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();

                if (data.error) {
                    if (data.is_remote) {
                        showSSHSetupTutorial(upgradeFilesNodeName, data.node_ip || '');
                    } else {
                        showToast('Upload failed: ' + data.error, 'error');
                    }
                } else {
                    showToast(data.message || 'File uploaded successfully', 'success');
                    // Reload file list
                    await loadUpgradeFiles(upgradeFilesNodeName);
                }
            } catch (e) {
                showToast('Upload failed: ' + e.message, 'error');
            }

            input.value = '';
        }

        async function deleteUpgradeFile(filename) {
            if (!await showConfirm('Delete "' + filename + '"?', true)) return;

            showToast('Deleting ' + filename + '...', 'info');

            const response = await fetch('/api/nodes/' + upgradeFilesNodeName + '/upgrade-files/' + encodeURIComponent(filename), {
                method: 'DELETE'
            });

            const data = await response.json();

            if (data.error) {
                if (data.is_remote) {
                    showSSHSetupTutorial(upgradeFilesNodeName, data.node_ip || '');
                } else {
                    showToast('Delete failed: ' + data.error, 'error');
                }
            } else {
                showToast(data.message || 'File deleted successfully', 'success');
                // Reload file list
                await loadUpgradeFiles(upgradeFilesNodeName);
            }
        }

        // User Management functions
        let apiUsers = [];
        let availableRoles = [];

        async function refreshUsers() {
            const body = document.getElementById('usersBody');
            body.innerHTML = '<tr><td colspan="4" class="loading"><div class="spinner"></div>Loading...</td></tr>';

            try {
                const data = await api('/users');
                if (!data) return;

                if (data.error) {
                    body.innerHTML = '<tr><td colspan="4" class="loading" style="color:#e94560;">Error: ' + data.error + '</td></tr>';
                    return;
                }

                apiUsers = data.users || [];
                availableRoles = data.roles || [];

                // Show warning if roles couldn't be fetched
                if (data.roles_warning) {
                    showToast(data.roles_warning, 'warning', 6000);
                }

                if (apiUsers.length === 0) {
                    body.innerHTML = '<tr><td colspan="4" class="loading">No users found</td></tr>';
                    return;
                }

                body.innerHTML = apiUsers.map(u => {
                    const roles = (u.roles || []).map(r => `<span class="badge">${r}</span>`).join(' ');
                    const isSystem = u.username === 'wazuh' || u.username === 'wazuh-wui';
                    let userNote = '';
                    if (u.username === 'wazuh') userNote = " <span style='color:#888;font-size:11px;'>(system - API admin)</span>";
                    else if (u.username === 'wazuh-wui') userNote = " <span style='color:#888;font-size:11px;'>(system - Dashboard)</span>";
                    else userNote = " <span style='color:#888;font-size:11px;'>(API user)</span>";
                    const actionBtns = isSystem ?
                        '<div class="btn-wrap"><span style="display:inline-block;padding:4px 8px;color:#888;font-size:12px;">Protected</span></div>' :
                        `<div class="btn-wrap"><button class="btn btn-sm btn-warning" onclick="showEditUserRolesModal('${u.username}')"><svg class="icon"><use href="#icon-edit"/></svg>Edit Roles</button>
                         <button class="btn btn-sm btn-danger" onclick="deleteUser('${u.username}')"><svg class="icon"><use href="#icon-trash"/></svg>Delete</button></div>`;
                    return `<tr>
                        <td>${u.username}${userNote}</td>
                        <td>${roles || "<span style='color:#888'>none</span>"}</td>
                        <td>${u.allow_run_as ? "Yes" : "No"}</td>
                        <td>${actionBtns}</td>
                    </tr>`;
                }).join('');
            } catch (err) {
                if (err.message === 'BACKEND_UNAVAILABLE') {
                    body.innerHTML = `<tr><td colspan="4">${getConnectionErrorHtml('refreshUsers()')}</td></tr>`;
                } else {
                    body.innerHTML = `<tr><td colspan="4" class="loading" style="color:#e94560;">Error loading users: ${escapeHtml(err.message)}</td></tr>`;
                }
            }
        }

        function showCreateUserModal() {
            let roleOptions;
            let roleNote = '';
            if (availableRoles.length === 0) {
                roleOptions = '<span style="color:#888;font-style:italic;">Roles will be assigned after creation using "Edit Roles"</span>';
                roleNote = '<p style="color:#f39c12;font-size:12px;margin-top:5px;">Note: Use "Edit Roles" button after creating user to assign roles.</p>';
            } else {
                roleOptions = availableRoles.map(r =>
                    `<div class="multi-select-item" onclick="toggleCheckbox(this, event)">
                    <input type="checkbox" value="${r.name}"><span class="multi-select-item-text">${r.name}</span></div>`
                ).join('');
            }

            const body = `<div class="form-group">
                <label>Username</label>
                <input type="text" id="newUsername" placeholder="Enter username">
                </div>
                <div class="form-group">
                <label>Password</label>
                <input type="password" id="newPassword" placeholder="Enter password">
                <p style="color:#888;font-size:11px;margin-top:5px;">Must contain: uppercase, lowercase, number, special char, min 8 chars</p>
                </div>
                <div class="form-group">
                <label>Roles (optional)</label>
                <div id="roleCheckboxes" style="max-height:200px;overflow-y:auto;background:#1a1a2e;padding:10px;border-radius:4px;">${roleOptions}</div>
                ${roleNote}
                </div>`;
            const footer = `<button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>
                <button class="btn btn-success" onclick="createUser()"><svg class="icon"><use href="#icon-plus"/></svg>Create</button>`;
            showModal('Create API User', body, footer);
        }

        async function createUser() {
            const username = document.getElementById('newUsername').value.trim();
            const password = document.getElementById('newPassword').value;

            if (!username) { showToast('Username is required', 'warning'); return; }
            if (!password) { showToast('Password is required', 'warning'); return; }

            // Validate password meets Wazuh requirements
            const pwdRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^A-Za-z0-9]).{8,}$/;
            if (!pwdRegex.test(password)) {
                showToast('Password must contain: uppercase, lowercase, number, special char, min 8 chars', 'warning');
                return;
            }

            const selectedRoles = [];
            document.querySelectorAll('#roleCheckboxes input[type="checkbox"]:checked').forEach(cb => {
                selectedRoles.push(cb.value);  // Role names (strings)
            });

            const result = await api('/users', 'POST', {
                username: username,
                password: password,
                role_names: selectedRoles  // Send role names for CLI
            });

            closeModal();
            if (result) {
                if (result.error) {
                    showToast('Error: ' + result.error, 'error');
                } else {
                    showToast(result.message || 'User created', 'success');
                    refreshUsers();
                }
            }
        }

        function showEditUserRolesModal(username) {
            const user = apiUsers.find(u => u.username === username);
            const userRoleIds = (user && user.role_ids) || [];

            const roleOptions = availableRoles.map(r => {
                const checked = userRoleIds.includes(r.id) ? 'checked' : '';
                return `<div class="multi-select-item" onclick="toggleCheckbox(this, event)">
                    <input type="checkbox" value="${r.id}" ${checked}><span class="multi-select-item-text">${r.name}</span></div>`;
            }).join('');

            const body = `<div class="form-group">
                <label>Roles for user "${username}"</label>
                <div id="roleCheckboxes" style="max-height:200px;overflow-y:auto;background:#1a1a2e;padding:10px;border-radius:4px;">${roleOptions}</div>
                </div>`;
            const footer = `<button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>
                <button class="btn btn-primary" onclick="updateUserRoles('${username}')"><svg class="icon"><use href="#icon-save"/></svg>Save</button>`;
            showModal('Edit User Roles', body, footer);
        }

        async function updateUserRoles(username) {
            const selectedRoles = [];
            document.querySelectorAll('#roleCheckboxes input[type="checkbox"]:checked').forEach(cb => {
                selectedRoles.push(parseInt(cb.value));
            });

            const result = await api('/users/' + username + '/roles', 'PUT', {
                role_ids: selectedRoles
            });

            closeModal();
            if (result) {
                if (result.error) {
                    showToast('Error: ' + result.error, 'error');
                } else {
                    showToast(result.message || 'Roles updated', 'success');
                    refreshUsers();
                }
            }
        }

        async function deleteUser(username) {
            if (!await showConfirm('Delete user "' + username + '"?', true)) return;

            const result = await api('/users/' + username, 'DELETE');
            if (result) {
                if (result.error) {
                    showToast('Error: ' + result.error, 'error');
                } else {
                    showToast(result.message || 'User deleted', 'success');
                    refreshUsers();
                }
            }
        }

        // Log functions
        function highlightLog(text) {
            if (!text) return '';
            return text
                .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')  // Escape HTML
                .replace(/^(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})/gm, '<span style="color:#888">$1</span>')  // Timestamp
                .replace(/\\[INFO\\]/g, '<span style="color:#4fc3f7;font-weight:bold">[INFO]</span>')
                .replace(/\\[WARNING\\]/g, '<span style="color:#ffc107;font-weight:bold">[WARNING]</span>')
                .replace(/\\[ERROR\\]/g, '<span style="color:#e94560;font-weight:bold">[ERROR]</span>')
                .replace(/\\[DEBUG\\]/g, '<span style="color:#9e9e9e">[DEBUG]</span>')
                .replace(/(LOGIN SUCCESS:)/g, '<span style="color:#4ade80">$1</span>')
                .replace(/(LOGIN FAILED:)/g, '<span style="color:#f87171">$1</span>')
                .replace(/(SERVER START:)/g, '<span style="color:#60a5fa">$1</span>')
                .replace(/(USER DELETE:?|USER CREATE:?|USER ROLES UPDATE:?)/g, '<span style="color:#c084fc">$1</span>')
                .replace(/(GROUP |AGENT )/g, '<span style="color:#34d399">$1</span>')
                .replace(/(user=\\w+|operator=\\w+)/g, '<span style="color:#fbbf24">$1</span>')
                .replace(/(from=[\\d\\.]+)/g, '<span style="color:#94a3b8">$1</span>');
        }

        async function refreshLogs() {
            const lines = document.getElementById('logLines').value;
            const content = document.getElementById('logContent');
            content.innerHTML = '<span style="color:#888">Loading...</span>';

            try {
                const data = await api('/logs?lines=' + lines);
                if (!data) {
                    content.innerHTML = '<span style="color:#e94560">Failed to load logs</span>';
                    return;
                }

                if (data.error) {
                    content.innerHTML = '<span style="color:#e94560">Error: ' + escapeHtml(data.error) + '</span>';
                    return;
                }

                content.innerHTML = highlightLog(data.content) || '<span style="color:#888">No log entries</span>';

                // Update path and info
                if (data.path) {
                    document.getElementById('logFilePath').textContent = data.path;
                }
                if (data.total_lines !== undefined) {
                    document.getElementById('logFileInfo').textContent =
                        `(showing ${data.showing || 0} of ${data.total_lines} lines)`;
                }

                // Scroll to bottom after content renders
                setTimeout(function() {
                    content.scrollTop = content.scrollHeight;
                }, 50);
            } catch (err) {
                if (err.message === 'BACKEND_UNAVAILABLE') {
                    content.innerHTML = getConnectionErrorHtml('refreshLogs()').replace('class="connection-error"', 'class="connection-error" style="padding:30px 20px;"');
                } else {
                    content.innerHTML = '<span style="color:#e94560">Error loading logs: ' + escapeHtml(err.message) + '</span>';
                }
            }
        }

        function downloadLogs() {
            window.open('/api/logs/download', '_blank');
        }

        // Rules functions
        let rulesCache = {};

        async function searchRuleHierarchy() {
            const ruleId = document.getElementById('ruleIdSearch').value.trim();
            if (!ruleId) {
                showToast('Please enter a Rule ID', 'warning');
                return;
            }

            const container = document.getElementById('ruleTreeContainer');
            const status = document.getElementById('ruleSearchStatus');
            container.innerHTML = '<div class="loading"><div class="spinner"></div>Searching rules...</div>';
            status.textContent = '';

            try {
                const data = await api('/rules/hierarchy?rule_id=' + encodeURIComponent(ruleId));
                if (!data || data.error) {
                    container.innerHTML = '<div style="color:#e94560;text-align:center;padding:20px;">' +
                        escapeHtml((data && data.error) || 'Rule not found') + '</div>';
                    return;
                }

                rulesCache = data.all_rules || {};
                renderRuleTree(data, ruleId);
                status.textContent = 'Found ' + Object.keys(data.all_rules || {}).length + ' related rules';
            } catch (err) {
                container.innerHTML = '<div style="color:#e94560;text-align:center;padding:20px;">Error: ' +
                    escapeHtml(err.message) + '</div>';
            }
        }

        function renderRuleTree(data, targetRuleId) {
            const container = document.getElementById('ruleTreeContainer');
            const hierarchy = data.hierarchy || [];
            const targetRule = data.target_rule;

            if (!targetRule) {
                container.innerHTML = '<div style="color:#e94560;text-align:center;padding:20px;">Rule not found</div>';
                return;
            }

            let html = '<div class="rule-tree"><ul>';
            html += renderRuleNode(hierarchy, targetRuleId, 0);
            html += '</ul></div>';

            container.innerHTML = html;

            // Add enter key listener
            document.getElementById('ruleIdSearch').onkeypress = function(e) {
                if (e.key === 'Enter') searchRuleHierarchy();
            };
        }

        function renderRuleNode(nodes, targetRuleId, depth) {
            if (!nodes || nodes.length === 0) return '';

            let html = '';
            for (const node of nodes) {
                const isTarget = node.id === targetRuleId;
                const isParent = depth < getTargetDepth(nodes, targetRuleId, 0);
                const hasChildren = node.children && node.children.length > 0;
                const isGroup = node.is_group === true;
                const isMore = node.is_more === true;
                const levelClass = node.level === 0 ? 'zero' : (node.level >= 12 ? 'high' : (node.level >= 6 ? 'medium' : 'low'));
                let nodeClass = isTarget ? 'highlight' : (isParent ? 'parent' : 'child');
                if (isGroup) nodeClass = 'group';
                if (isMore) nodeClass = 'more';

                html += '<li>';

                if (isMore) {
                    // Just show text for "more" indicator
                    html += '<div class="rule-node ' + nodeClass + '">';
                    html += '<span class="rule-id">' + escapeHtml(node.id) + '</span>';
                    html += '</div>';
                } else if (isGroup) {
                    // Group node - clickable to show member rules
                    const memberRulesJson = node.member_rules ? JSON.stringify(node.member_rules) : '[]';
                    const groupName = node.group_name || '';
                    html += '<div class="rule-node ' + nodeClass + '" onclick="toggleGroupContent(this, ' + escapeHtml(memberRulesJson) + ', \\'' + escapeHtml(groupName) + '\\')" style="cursor:pointer;">';
                    if (hasChildren) {
                        html += '<span class="rule-expand" onclick="event.stopPropagation();toggleRuleExpand(this.parentElement.parentElement)"><svg class="icon" style="width:16px;height:16px;"><use href="#icon-nav-arrow-down"/></svg></span>';
                    }
                    html += '<span class="rule-id">' + escapeHtml(node.id) + '</span>';
                    html += '<span class="rule-desc">' + escapeHtml(node.description || '') + '</span>';
                    html += '</div>';
                    html += '<div class="rule-content" id="group-content-' + escapeHtml(groupName) + '"></div>';
                } else {
                    // Regular rule node
                    html += '<div class="rule-node ' + nodeClass + '" onclick="toggleRuleContent(this, \\'' + escapeHtml(node.id) + '\\')">';
                    if (hasChildren) {
                        html += '<span class="rule-expand" onclick="event.stopPropagation();toggleRuleExpand(this.parentElement.parentElement)"><svg class="icon" style="width:16px;height:16px;"><use href="#icon-nav-arrow-down"/></svg></span>';
                    }
                    html += '<span class="rule-id">' + escapeHtml(node.id) + '</span>';
                    html += '<span class="rule-level ' + levelClass + '">L' + node.level + '</span>';
                    if (node.is_custom) {
                        html += '<span class="rule-custom-badge">Custom</span>';
                    }
                    if (node.if_group) {
                        html += '<span class="rule-if-group-badge">if_group: ' + escapeHtml(node.if_group) + '</span>';
                    }
                    html += '<span class="rule-desc">' + escapeHtml(node.description || '') + '</span>';
                    html += '<span class="rule-file' + (node.is_custom ? ' custom' : '') + '">' + escapeHtml(node.file || '') + '</span>';
                    html += '</div>';
                    html += '<div class="rule-content" id="rule-content-' + escapeHtml(node.id) + '"></div>';
                }

                if (hasChildren) {
                    html += '<ul>' + renderRuleNode(node.children, targetRuleId, depth + 1) + '</ul>';
                }
                html += '</li>';
            }
            return html;
        }

        function getTargetDepth(nodes, targetRuleId, currentDepth) {
            for (const node of nodes) {
                if (node.id === targetRuleId) return currentDepth;
                if (node.children) {
                    const childDepth = getTargetDepth(node.children, targetRuleId, currentDepth + 1);
                    if (childDepth >= 0) return childDepth;
                }
            }
            return -1;
        }

        function toggleRuleExpand(li) {
            li.classList.toggle('collapsed');
        }

        async function toggleRuleContent(nodeEl, ruleId) {
            const contentEl = document.getElementById('rule-content-' + ruleId);
            if (!contentEl) return;

            if (contentEl.classList.contains('show')) {
                contentEl.classList.remove('show');
                return;
            }

            // Load content if not cached
            if (!contentEl.querySelector('code')) {
                contentEl.innerHTML = '<span style="color:#888">Loading...</span>';
                try {
                    const data = await api('/rules/' + encodeURIComponent(ruleId));
                    if (data && data.content) {
                        contentEl.innerHTML = '<button class="rule-copy-btn" onclick="copyRuleContent(this, \\'' + ruleId + '\\')">Copy</button><code>' + highlightXml(data.content) + '</code>';
                        contentEl.dataset.rawContent = data.content;
                    } else {
                        contentEl.innerHTML = '<span style="color:#888">No content available</span>';
                    }
                } catch (err) {
                    contentEl.innerHTML = '<span style="color:#e94560">Error loading rule</span>';
                }
            }

            contentEl.classList.add('show');
        }

        async function toggleGroupContent(nodeEl, memberRules, groupName) {
            const contentEl = document.getElementById('group-content-' + groupName);
            if (!contentEl) return;

            if (contentEl.classList.contains('show')) {
                contentEl.classList.remove('show');
                return;
            }

            // Load content if not cached
            if (!contentEl.querySelector('code')) {
                contentEl.innerHTML = '<span style="color:#888">Loading member rules...</span>';
                try {
                    let html = '';
                    for (const ruleId of memberRules) {
                        const data = await api('/rules/' + encodeURIComponent(ruleId));
                        if (data && data.content) {
                            html += '<div style="margin-bottom:15px;border-bottom:1px solid #333;padding-bottom:15px;">';
                            html += '<div style="color:#5dade2;font-weight:bold;margin-bottom:8px;">Rule ' + ruleId + '</div>';
                            html += '<code>' + highlightXml(data.content) + '</code>';
                            html += '</div>';
                        }
                    }
                    if (html) {
                        contentEl.innerHTML = html;
                    } else {
                        contentEl.innerHTML = '<span style="color:#888">No member rule content available</span>';
                    }
                } catch (err) {
                    contentEl.innerHTML = '<span style="color:#e94560">Error loading rules</span>';
                }
            }

            contentEl.classList.add('show');
        }

        function clearRuleSearch() {
            document.getElementById('ruleIdSearch').value = '';
            document.getElementById('ruleSearchStatus').textContent = '';
            document.getElementById('ruleTreeContainer').innerHTML = '<div style="color:#888;text-align:center;padding:40px;">' +
                '<svg class="icon" style="width:48px;height:48px;opacity:0.5;margin-bottom:15px;"><use href="#icon-tree"/></svg>' +
                '<p>Enter a Rule ID to view its hierarchy and relationships.</p>' +
                '<p style="font-size:12px;margin-top:10px;">The tree will show parent rules (if_sid, if_matched_sid) and child rules.</p>' +
                '</div>';
            rulesCache = {};
        }

        async function copyRuleContent(btn, ruleId) {
            const contentEl = document.getElementById('rule-content-' + ruleId);
            if (!contentEl || !contentEl.dataset.rawContent) return;

            try {
                await navigator.clipboard.writeText(contentEl.dataset.rawContent);
                btn.textContent = 'Copied!';
                btn.classList.add('copied');
                setTimeout(() => {
                    btn.textContent = 'Copy';
                    btn.classList.remove('copied');
                }, 2000);
            } catch (err) {
                showToast('Failed to copy to clipboard', 'error');
            }
        }

        function highlightXml(xml) {
            // Escape HTML first
            let escaped = escapeHtml(xml);
            // Highlight comments
            escaped = escaped.replace(/(&lt;!--[\s\S]*?--&gt;)/g, '<span class="xml-comment">$1</span>');
            // Highlight tags (including < and </ as part of tag color)
            escaped = escaped.replace(/(&lt;\/?)([\w:-]+)/g, '<span class="xml-tag">$1$2</span>');
            escaped = escaped.replace(/([\w:-]+)(=)(&quot;[^&]*&quot;)/g, '<span class="xml-attr">$1</span>$2<span class="xml-value">$3</span>');
            // Highlight closing bracket
            escaped = escaped.replace(/(\/?&gt;)/g, '<span class="xml-tag">$1</span>');
            return escaped;
        }

        function expandAllRules() {
            // Expand all collapsed tree nodes
            document.querySelectorAll('#ruleTreeContainer li.collapsed').forEach(li => {
                li.classList.remove('collapsed');
            });
            // Also show all rule content that has been loaded
            document.querySelectorAll('#ruleTreeContainer .rule-content').forEach(el => {
                if (el.innerHTML && el.innerHTML.trim()) {
                    el.classList.add('show');
                }
            });
        }

        function collapseAllRules() {
            // Collapse all tree nodes that have children
            document.querySelectorAll('#ruleTreeContainer li').forEach(li => {
                if (li.querySelector(':scope > ul')) {
                    li.classList.add('collapsed');
                }
            });
            // Also hide all rule content
            document.querySelectorAll('#ruleTreeContainer .rule-content.show').forEach(el => {
                el.classList.remove('show');
            });
        }

        // Export functions
        function toggleExportMenu() {
            const menu = document.getElementById('exportMenu');
            menu.classList.toggle('show');
        }

        function getFilteredAgents() {
            const search = document.getElementById('agentSearch').value.toLowerCase();
            const statusValues = getFilterValues('statusFilter');
            const groupValues = getFilterValues('groupFilter');
            const osValues = getFilterValues('osFilter');
            const versionValues = getFilterValues('versionFilter');
            const nodeValues = getFilterValues('nodeFilter');

            return agents.filter(a => {
                if (search) {
                    const searchFields = [
                        a.id, a.name, a.ip, a.status, a.os, a.version, a.group, a.node_name
                    ].map(f => (f || '').toLowerCase());
                    if (!searchFields.some(f => f.includes(search))) return false;
                }
                if (statusValues.length > 0 && !statusValues.includes(a.status.toLowerCase().replace(' ', '_'))) return false;
                if (groupValues.length > 0) {
                    const agentGroups = (a.group || '').split(',').map(g => g.trim()).filter(g => g);
                    // Handle "(no group)" filter
                    const hasNoGroup = !a.group || a.group.trim() === '';
                    const matchesNoGroup = groupValues.includes('(no group)') && hasNoGroup;
                    const matchesGroup = groupValues.some(g => g !== '(no group)' && agentGroups.includes(g));
                    if (!matchesNoGroup && !matchesGroup) return false;
                }
                if (osValues.length > 0 && !osValues.includes(a.os || '')) return false;
                if (versionValues.length > 0 && !versionValues.includes(a.version || '')) return false;
                if (nodeValues.length > 0 && !nodeValues.includes(a.node_name || '')) return false;
                return true;
            });
        }

        function exportData(format) {
            document.getElementById('exportMenu').classList.remove('show');

            const filtered = getFilteredAgents();
            if (filtered.length === 0) {
                showToast('No data to export', 'warning');
                return;
            }

            const columns = ['id', 'name', 'ip', 'status', 'os', 'version', 'group', 'node_name', 'synced'];
            const headers = ['ID', 'Name', 'IP', 'Status', 'OS', 'Version', 'Group', 'Node', 'Sync'];
            let content, filename, mimeType;

            if (format === 'json') {
                const exportData = filtered.map(a => {
                    const obj = {};
                    columns.forEach((col, i) => obj[headers[i]] = a[col] || '');
                    return obj;
                });
                content = JSON.stringify(exportData, null, 2);
                filename = 'agents.json';
                mimeType = 'application/json';
            } else {
                const separator = format === 'tsv' ? String.fromCharCode(9) : ',';
                const rows = [headers.join(separator)];
                filtered.forEach(a => {
                    const row = columns.map(col => {
                        let val = a[col] || '';
                        // Escape quotes and wrap in quotes if contains separator or quotes
                        if (format === 'csv' && (val.includes(',') || val.includes('"') || val.includes(String.fromCharCode(10)))) {
                            val = '"' + val.replace(/"/g, '""') + '"';
                        }
                        return val;
                    });
                    rows.push(row.join(separator));
                });
                content = rows.join(String.fromCharCode(10));
                filename = format === 'tsv' ? 'agents.tsv' : 'agents.csv';
                mimeType = format === 'tsv' ? 'text/tab-separated-values' : 'text/csv';
            }

            // Download file
            const blob = new Blob([content], { type: mimeType + ';charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = filename;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);

            showToast(`Exported ${filtered.length} agents to ${filename}`, 'success');
        }

        function showGroupAgents(groupName) {
            // Clear search field
            document.getElementById('agentSearch').value = '';
            // Clear all filters first
            ['statusFilter', 'groupFilter', 'osFilter', 'versionFilter', 'nodeFilter', 'syncFilter'].forEach(filterId => {
                const dropdown = document.getElementById(filterId + 'Dropdown');
                if (dropdown) {
                    dropdown.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
                }
            });
            // Set the group filter - find checkbox by iterating (avoid template literal in querySelector)
            const groupDropdown = document.getElementById('groupFilterDropdown');
            let found = false;
            if (groupDropdown) {
                groupDropdown.querySelectorAll('input[type="checkbox"]').forEach(cb => {
                    if (cb.value === groupName) {
                        cb.checked = true;
                        found = true;
                    }
                });
            }
            // If group not in dropdown (e.g., has 0 agents), add it temporarily
            if (!found && groupDropdown) {
                const item = document.createElement('div');
                item.className = 'multi-select-item';
                item.innerHTML = '<input type="checkbox" value="' + groupName + '" onchange="onFilterChange()" checked><span class="multi-select-item-text">' + groupName + '</span>';
                item.onclick = function(e) { toggleCheckbox(this, e); };
                groupDropdown.insertBefore(item, groupDropdown.firstChild);
            }
            ['statusFilter', 'groupFilter', 'osFilter', 'versionFilter', 'nodeFilter', 'syncFilter'].forEach(updateFilterButton);
            document.querySelector('[data-tab="agents"]').click();
            currentPage = 1;
            renderAgents();
        }

        // Event listeners
        document.getElementById('agentSearch').addEventListener('input', () => {
            currentPage = 1;  // Reset to first page on search
            renderAgents();
        });

        // Initial load
        initColumnVisibility();
        refreshAgents();
        refreshGroups();

        // Auto-refresh stats every 10 seconds (only stats, not the table)
        setInterval(async () => {
            try {
                const data = await api('/stats/summary');
                if (data && data.summary && !data.summary.error) {
                    const s = data.summary;
                    // Only update if we have valid data (total_agents should be a positive number)
                    const total = s.total_agents;
                    if (typeof total === 'number' && total > 0) {
                        updateStatValue('totalAgents', total);
                        updateStatValue('activeAgents', s.status_breakdown?.Active || 0);
                        updateStatValue('disconnectedAgents', s.status_breakdown?.Disconnected || 0);
                        updateStatValue('pendingAgents', s.status_breakdown?.Pending || 0);
                    }
                }
            } catch (e) { /* ignore */ }
        }, 10000);
    </script>
</body>
</html>
'''


class SessionExpiredException(Exception):
    """Raised when Wazuh API session/token has expired."""
    pass


class WazuhAPISession:
    """Wazuh API session manager."""

    # Class-level SSL setting (can be True, False, or path to CA cert)
    ssl_verify = os.environ.get('WAZUH_SSL_VERIFY', 'false').lower() not in ('false', '0', 'no')
    ssl_cert_path = os.environ.get('WAZUH_SSL_CERT', None)

    def __init__(self, host: str, port: int, username: str, password: str):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.base_url = f"https://{host}:{port}"
        self.token = None
        # Use cert path if provided, otherwise use boolean
        self._verify = self.ssl_cert_path if self.ssl_cert_path and os.path.exists(self.ssl_cert_path) else self.ssl_verify

    def authenticate(self) -> bool:
        """Authenticate and get token. Raises descriptive exceptions on failure."""
        try:
            response = http_requests.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(self.username, self.password),
                verify=self._verify,
                timeout=30
            )
            if response.status_code == 200:
                data = response.json()
                self.token = data.get('data', {}).get('token')
                return bool(self.token)
            elif response.status_code == 401:
                raise Exception("Invalid username or password")
            elif response.status_code == 403:
                raise Exception("Access forbidden - check user permissions")
            else:
                raise Exception(f"API returned status {response.status_code}")
        except http_requests.exceptions.ConnectionError:
            raise Exception(f"Cannot connect to Wazuh API at {self.host}:{self.port} - check if the service is running")
        except http_requests.exceptions.Timeout:
            raise Exception(f"Connection timeout - Wazuh API at {self.host}:{self.port} is not responding")
        except http_requests.exceptions.SSLError as e:
            raise Exception(f"SSL certificate error - {str(e)}")
        except Exception as e:
            if "Invalid username or password" in str(e) or "Cannot connect" in str(e) or "timeout" in str(e).lower():
                raise
            raise Exception(f"Connection failed: {str(e)}")

    def request(self, method: str, endpoint: str, data=None, params=None):
        """Make authenticated API request."""
        if not self.token:
            raise Exception("Not authenticated")

        headers = {
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/json'
        }

        try:
            response = http_requests.request(
                method=method,
                url=f"{self.base_url}{endpoint}",
                headers=headers,
                json=data,
                params=params,
                verify=self._verify,
                timeout=60
            )

            # Token expired - raise exception so it propagates up
            if response.status_code == 401:
                raise SessionExpiredException("Session expired. Please login again.")

            return response.json()
        except SessionExpiredException:
            raise  # Re-raise session expired
        except Exception as e:
            return {'error': str(e)}

    def get_agents(self, status=None, group=None, limit=10000):
        """Get agents list."""
        params = {'limit': limit, 'select': 'id,name,ip,status,os.platform,os.name,os.version,version,group,node_name,group_config_status'}
        if status:
            params['status'] = status
        if group:
            params['group'] = group
        result = self.request('GET', '/agents', params=params)
        items = result.get('data', {}).get('affected_items', [])
        # Flatten the response
        agents = []
        for item in items:
            # Clean version string: "Wazuh v4.14.0" -> "v4.14.0"
            version = item.get('version') or ''
            if version.startswith('Wazuh '):
                version = version[6:]  # Remove "Wazuh " prefix
            agent = {
                'id': item.get('id'),
                'name': item.get('name'),
                'ip': item.get('ip'),
                'status': item.get('status'),
                'os': (item.get('os', {}).get('name') or item.get('os', {}).get('platform', '')) + (' ' + item.get('os', {}).get('version', '') if item.get('os', {}).get('version') else ''),
                'version': version,
                'group': ','.join(item.get('group', [])) if item.get('group') else '',
                'node_name': item.get('node_name', ''),
                'synced': item.get('group_config_status', '')
            }
            agents.append(agent)
        return agents

    def get_groups(self):
        """Get groups list."""
        result = self.request('GET', '/groups')
        items = result.get('data', {}).get('affected_items', [])
        return [{'name': g.get('name'), 'count': g.get('count', 0)} for g in items]

    def get_nodes(self):
        """Get cluster nodes. Falls back to manager info if cluster not configured."""
        result = self.request('GET', '/cluster/nodes')
        items = result.get('data', {}).get('affected_items', [])

        # Get local hostname directly from system
        import socket
        local_hostname = socket.gethostname()

        # Get local cluster node name for matching
        try:
            local_info = self.request('GET', '/cluster/local/info')
            local_data = local_info.get('data', {}).get('affected_items', [])
            local_node = local_data[0] if local_data else {}
            local_node_name = local_node.get('node', '') or local_node.get('name', '')
        except:
            local_node_name = ''

        # Get agent counts per node
        agent_counts = {}
        try:
            agents_result = self.request('GET', '/agents', params={'select': 'node_name', 'limit': 100000})
            agents_data = agents_result.get('data', {}).get('affected_items', [])
            for agent in agents_data:
                node = agent.get('node_name', 'unknown')
                agent_counts[node] = agent_counts.get(node, 0) + 1
        except:
            pass

        if items:
            nodes = []
            for n in items:
                node_name = n.get('name', '')
                ip = n.get('ip', '')
                # If IP is localhost, use the configured API host
                if ip in ['localhost', '127.0.0.1', '']:
                    ip = f"{self.host} (API)"
                # Use hostname for local node (match by type=master or node name)
                is_local = n.get('type') == 'master' or node_name == local_node_name
                # For local node use system hostname, for remote nodes try to derive from node name
                if is_local:
                    hostname = local_hostname
                else:
                    # Try to get hostname from node name (e.g., "edr2-server" -> try to resolve)
                    # For now, we'll use the node name as a hint or show the IP
                    hostname = node_name.replace('-server', '') if '-server' in node_name else ''
                # Clean version string: "Wazuh v4.14.0" -> "v4.14.0"
                version = n.get('version') or ''
                if version.startswith('Wazuh '):
                    version = version[6:]
                nodes.append({
                    'name': node_name,
                    'hostname': hostname,
                    'type': n.get('type'),
                    'version': version,
                    'ip': ip,
                    'count': agent_counts.get(node_name, 0)
                })
            return nodes

        # Fallback: get manager info for single-node setup
        try:
            manager_result = self.request('GET', '/manager/info')
            manager_data = manager_result.get('data', {}).get('affected_items', [])
            if manager_data:
                m = manager_data[0]
                # Clean version string
                version = m.get('version', '')
                if version.startswith('Wazuh '):
                    version = version[6:]
                node_name = local_node_name or 'manager'
                return [{
                    'name': node_name,
                    'hostname': local_hostname,
                    'type': 'master',
                    'version': version,
                    'ip': f"{self.host} (API)",
                    'count': agent_counts.get(node_name, sum(agent_counts.values()))
                }]
        except:
            pass

        return []

    def add_agents_to_group(self, group_name: str, agent_ids: list):
        """Add agents to group."""
        params = {'group_id': group_name, 'agents_list': ','.join(agent_ids)}
        return self.request('PUT', '/agents/group', params=params)

    def remove_agents_from_group(self, group_name: str, agent_ids: list):
        """Remove agents from group."""
        params = {'group_id': group_name, 'agents_list': ','.join(agent_ids)}
        return self.request('DELETE', '/agents/group', params=params)

    def create_group(self, group_name: str):
        """Create a group."""
        return self.request('POST', '/groups', data={'group_id': group_name})

    def delete_group(self, group_name: str):
        """Delete a group."""
        params = {'groups_list': group_name}
        return self.request('DELETE', '/groups', params=params)

    def restart_agents(self, agent_ids: list):
        """Restart agents."""
        params = {'agents_list': ','.join(agent_ids)}
        return self.request('PUT', '/agents/restart', params=params)

    def reconnect_agents(self, agent_ids: list):
        """Force agents to reconnect."""
        params = {'agents_list': ','.join(agent_ids)}
        return self.request('PUT', '/agents/reconnect', params=params)

    def delete_agents(self, agent_ids: list):
        """Delete agents."""
        params = {'agents_list': ','.join(agent_ids), 'status': 'all', 'older_than': '0s'}
        return self.request('DELETE', '/agents', params=params)

    def get_agent_details(self, agent_id: str):
        """Get detailed agent information."""
        result = self.request('GET', f'/agents?agents_list={agent_id}')
        items = result.get('data', {}).get('affected_items', [])
        return items[0] if items else None

    def get_stats_summary(self):
        """Get agent statistics summary."""
        result = self.request('GET', '/agents/summary/status')

        # Handle error response (error != 0 means failure)
        if result.get('error') and result.get('error') != 0:
            return {'error': result['error']}

        # The data structure might vary - handle both cases
        data = result.get('data', {})

        # If data has 'affected_items', it's a different response format
        if 'affected_items' in data:
            data = data.get('affected_items', [{}])[0] if data.get('affected_items') else {}

        # Extract status counts - only sum numeric values
        status_values = {}
        for key, value in data.items():
            if isinstance(value, (int, float)):
                status_values[key] = value

        total = sum(status_values.values()) if status_values else 0
        active = status_values.get('active', 0)

        return {
            'total_agents': total,
            'active_agents': active,
            'active_percentage': round((active / total * 100) if total > 0 else 0, 1),
            'status_breakdown': {
                'Active': status_values.get('active', 0),
                'Disconnected': status_values.get('disconnected', 0),
                'Pending': status_values.get('pending', 0),
                'Never connected': status_values.get('never_connected', 0)
            }
        }

    # ============ User Management Methods ============

    def get_users(self):
        """Get all API users."""
        # First fetch all roles to create ID-to-name mapping
        all_roles = self.get_roles()
        role_id_to_name = {r['id']: r['name'] for r in all_roles}

        result = self.request('GET', '/security/users')
        users = result.get('data', {}).get('affected_items', [])
        parsed_users = []
        for u in users:
            roles = u.get('roles', [])
            # Handle both dict format and int format for roles
            role_names = []
            role_ids = []
            for r in roles:
                if isinstance(r, dict):
                    role_names.append(r.get('name', ''))
                    role_ids.append(r.get('id'))
                elif isinstance(r, int):
                    role_ids.append(r)
                    # Look up role name from ID
                    role_name = role_id_to_name.get(r, f'role_{r}')
                    role_names.append(role_name)
            parsed_users.append({
                'user_id': u.get('id'),
                'username': u.get('username'),
                'roles': role_names,
                'role_ids': role_ids,
                'allow_run_as': u.get('allow_run_as', False)
            })
        return parsed_users

    def get_roles(self):
        """Get all available roles."""
        result = self.request('GET', '/security/roles')
        roles = result.get('data', {}).get('affected_items', [])
        return [{'id': r.get('id'), 'name': r.get('name')} for r in roles]

    def create_user(self, username: str, password: str):
        """Create a new API user."""
        result = self.request('POST', '/security/users', data={
            'username': username,
            'password': password
        })
        if result.get('data', {}).get('affected_items'):
            return {'success': True}
        else:
            failed = result.get('data', {}).get('failed_items', [])
            if failed:
                error_msg = failed[0].get('error', {}).get('message', 'Unknown error')
                return {'error': error_msg}
            if result.get('error'):
                return {'error': result.get('error')}
            return {'error': 'Failed to create user'}

    def delete_user(self, username: str):
        """Delete an API user."""
        # First get user ID from username
        users = self.get_users()
        user_id = None
        for u in users:
            if u.get('username') == username:
                user_id = u.get('user_id')
                break

        if user_id is None:
            return {'error': f'User "{username}" not found'}

        result = self.request('DELETE', '/security/users', params={'user_ids': str(user_id)})
        if result.get('data', {}).get('affected_items'):
            return {'success': True}
        else:
            failed = result.get('data', {}).get('failed_items', [])
            if failed:
                error_msg = failed[0].get('error', {}).get('message', 'Unknown error')
                return {'error': error_msg}
            return {'error': 'Failed to delete user'}

    def assign_user_role(self, user_id: int, role_id: int):
        """Assign a role to a user."""
        result = self.request('POST', f'/security/users/{user_id}/roles', params={'role_ids': role_id})
        if result.get('error'):
            return {'error': result['error']}
        return {'success': True}

    def remove_user_role(self, user_id: int, role_id: int):
        """Remove a role from a user."""
        result = self.request('DELETE', f'/security/users/{user_id}/roles', params={'role_ids': role_id})
        if result.get('error'):
            return {'error': result['error']}
        return {'success': True}

    # ============ Service Status Methods ============

    def get_manager_status(self):
        """Get manager daemon status."""
        result = self.request('GET', '/manager/status')
        daemons = result.get('data', {}).get('affected_items', [])
        services = []
        if daemons:
            daemon_dict = daemons[0] if daemons else {}
            for daemon_name, status in daemon_dict.items():
                services.append({
                    'name': daemon_name,
                    'status': status.lower() if status else 'unknown'
                })
        return services

    def get_cluster_status(self):
        """Get cluster status."""
        result = self.request('GET', '/cluster/status')
        return result.get('data', {})

    def get_nodes_status(self):
        """Get status for all nodes individually."""
        result = {}
        nodes = self.get_nodes()

        for node in nodes:
            node_name = node.get('name', 'manager')
            node_type = node.get('type', 'master')

            try:
                # Try to get status for this specific node via cluster API
                api_result = self.request('GET', f'/cluster/{node_name}/status')
                daemons = api_result.get('data', {}).get('affected_items', [])

                services = []
                if daemons:
                    daemon_dict = daemons[0] if daemons else {}
                    for daemon_name, status in daemon_dict.items():
                        services.append({
                            'name': daemon_name,
                            'status': status.lower() if status else 'unknown'
                        })

                if services:
                    result[node_name] = services
                else:
                    result[node_name] = [{'name': 'Unknown', 'status': 'unknown'}]

            except Exception as e:
                # Fallback: if cluster API fails, try manager status for master node
                if node_type == 'master':
                    services = self.get_manager_status()
                    result[node_name] = services if services else [{'name': 'Unknown', 'status': 'unknown'}]
                else:
                    result[node_name] = [{'name': 'Remote', 'status': 'unknown'}]

        return result

    def get_agent_info(self, agent_id: str):
        """Get detailed info for a single agent.

        Args:
            agent_id: Agent ID

        Returns:
            Agent info dictionary or None
        """
        try:
            result = self.request('GET', f'/agents', params={'agents_list': agent_id})
            items = result.get('data', {}).get('affected_items', [])
            if items:
                return items[0]
            return None
        except Exception:
            return None

    def upgrade_agent(self, agent_id: str, version: str = None, force: bool = False, manager_version: str = None):
        """Upgrade an agent to specified version or latest.

        Args:
            agent_id: Agent ID
            version: Target version (None for latest/manager version)
            force: Force upgrade even if same version
            manager_version: Manager version to use when version is None

        Returns:
            Result dictionary with success or error
        """
        import logging
        logger = logging.getLogger('wazuh_mgr')

        try:
            # Pre-flight check: Get agent info to verify status
            agent_info = self.get_agent_info(agent_id)
            if not agent_info:
                return {'error': f'Agent {agent_id} not found'}

            agent_status = agent_info.get('status', 'unknown')
            agent_name = agent_info.get('name', agent_id)
            agent_version = agent_info.get('version', '')

            # Check if agent is in a valid state for upgrade
            if agent_status not in ['active', 'connected']:
                return {
                    'error': f'Agent must be active/connected to upgrade (current status: {agent_status})',
                    'agent_status': agent_status
                }

            # Build params using correct Wazuh API format
            # Endpoint: PUT /agents/upgrade?agents_list=xxx
            # NOT: PUT /agents/{id}/upgrade
            params = {
                'agents_list': agent_id
            }
            if force:
                params['force'] = 'true'

            # If no version specified, use manager version (more reliable than "latest")
            target_version = version
            if not target_version and manager_version:
                # Clean the manager version (remove 'v' prefix if present, remove 'Wazuh ' prefix)
                target_version = manager_version.replace('Wazuh ', '').replace('v', '').strip()

            # Use 'upgrade_version' parameter (not 'version')
            if target_version:
                params['upgrade_version'] = target_version

            # Print to terminal for debugging
            print(f"[UPGRADE] Agent {agent_id}: target_version={target_version}, params={params}")
            logger.info(f"Upgrade request: agent={agent_id} ({agent_name}) current_version={agent_version} target_version={target_version or 'latest'} force={force} params={params}")

            # Use the correct endpoint: PUT /agents/upgrade (not /agents/{id}/upgrade)
            result = self.request('PUT', '/agents/upgrade', params=params)
            print(f"[UPGRADE] Agent {agent_id} API response: {json.dumps(result)}")
            logger.info(f"Wazuh API upgrade response for agent {agent_id}: {json.dumps(result)}")

            # Check for errors in response
            if result.get('error'):
                error_msg = result.get('error')
                if isinstance(error_msg, dict):
                    error_msg = error_msg.get('message', str(error_msg))
                logger.warning(f"Upgrade error for agent {agent_id}: {error_msg}")
                return {'error': error_msg}

            # Check for failed_items
            if result.get('data', {}).get('failed_items'):
                failed = result['data']['failed_items']
                if failed:
                    error_info = failed[0].get('error', {})
                    if isinstance(error_info, dict):
                        error_code = error_info.get('code', 0)
                        error_msg = error_info.get('message', 'Unknown error')
                        # Provide more helpful messages for common errors
                        if error_code == 1810:
                            error_msg = f'WPK file not found. Please upload the WPK file for the target version to the manager\'s /var/ossec/var/upgrade/ directory.'
                        elif error_code == 1811:
                            error_msg = f'Agent version is already up to date or newer.'
                        elif 'WPK' in error_msg.upper() or 'wpk' in error_msg.lower():
                            error_msg = f'{error_msg}. Please check if the WPK file exists in /var/ossec/var/upgrade/'
                    else:
                        error_msg = str(error_info)
                    logger.warning(f"Upgrade failed_items for agent {agent_id}: {error_msg}")
                    return {'error': error_msg}

            # Check if there are affected_items (success)
            affected = result.get('data', {}).get('affected_items', [])
            if affected:
                print(f"[UPGRADE] Agent {agent_id}: SUCCESS - upgrade initiated")
                logger.info(f"Upgrade initiated for agent {agent_id}: {affected}")
                return {'success': True, 'result': result}
            else:
                # No affected items and no errors - Wazuh silently ignored the request
                # This typically means WPK not available or version mismatch
                print(f"[UPGRADE] Agent {agent_id}: FAILED - no affected_items in response")
                logger.warning(f"No affected_items in upgrade response for agent {agent_id}. Full response: {json.dumps(result)}")

                # Use the computed target version for error message
                target_v = target_version or 'latest'
                return {
                    'error': f'Upgrade task not created. Possible causes:\n'
                             f'1. WPK file for target version ({target_v}) not found in /var/ossec/var/upgrade/\n'
                             f'2. Agent already at target version\n'
                             f'3. Wazuh manager cannot download WPK automatically (check network/firewall)\n'
                             f'Please check the Upgrade Files in Node Management to verify WPK availability.',
                    'needs_wpk': True
                }

        except Exception as e:
            logger.error(f"Upgrade exception for agent {agent_id}: {str(e)}")
            return {'error': str(e)}

    def get_upgrade_result(self, agent_ids: list = None):
        """Get upgrade task results for agents.

        Args:
            agent_ids: List of agent IDs to check. If None, returns all.

        Returns:
            Dictionary with upgrade results per agent
        """
        try:
            params = {}
            if agent_ids:
                params['agents_list'] = ','.join(agent_ids)

            result = self.request('GET', '/agents/upgrade_result', params=params)

            # Handle Wazuh API error format (error in data.failed_items)
            if result.get('data', {}).get('failed_items'):
                failed = result['data']['failed_items']
                if failed:
                    # Log but don't treat as error - might be partial results
                    import logging
                    logging.getLogger('web_ui').debug(f"Upgrade result failed_items: {failed}")

            return result

        except Exception as e:
            return {'error': str(e)}


def create_app(max_login_attempts: int = 3, lockout_minutes: int = 30) -> 'Flask':
    """Create Flask application with login support.

    Args:
        max_login_attempts: Max failed login attempts before IP lockout
        lockout_minutes: IP lockout duration in minutes
    """
    if not HAS_FLASK:
        raise ImportError("Flask is required for web UI. Install with: pip install flask")

    if not HAS_REQUESTS:
        raise ImportError("requests is required for API calls. Install with: pip install requests")

    from datetime import datetime, timedelta

    app = Flask(__name__)
    app.secret_key = secrets.token_hex(32)

    # Security: Session cookie settings
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)  # Session timeout
    # Enable secure cookies if SSL is configured
    ssl_cert = os.environ.get('WEB_SSL_CERT')
    ssl_key = os.environ.get('WEB_SSL_KEY')
    if ssl_cert and ssl_key:
        app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookie over HTTPS

    # IP lockout tracking: {ip: {'attempts': count, 'locked_until': datetime}}
    ip_lockout = {}

    def get_client_ip():
        """Get client IP address, considering proxies."""
        if request.headers.get('X-Forwarded-For'):
            return request.headers.get('X-Forwarded-For').split(',')[0].strip()
        return request.remote_addr or 'unknown'

    def get_wazuh_api_token_timeout():
        """Get Wazuh API token timeout from api.yaml config file."""
        api_config_paths = [
            '/var/ossec/api/configuration/api.yaml',
            '/var/ossec/api/configuration/api.yml'
        ]
        for config_path in api_config_paths:
            if os.path.exists(config_path):
                try:
                    with open(config_path, 'r') as f:
                        import yaml
                        config = yaml.safe_load(f) or {}
                        # auth_token_exp_timeout is in seconds, default 900 (15 minutes)
                        return config.get('auth_token_exp_timeout', 900)
                except Exception:
                    pass
        return 900  # Default 15 minutes

    def is_ip_locked(ip):
        """Check if IP is currently locked."""
        if ip not in ip_lockout:
            return False, 0
        info = ip_lockout[ip]
        if info.get('locked_until'):
            remaining = (info['locked_until'] - datetime.now()).total_seconds()
            if remaining > 0:
                return True, int(remaining / 60) + 1
            else:
                # Lockout expired, reset
                del ip_lockout[ip]
        return False, 0

    def record_failed_login(ip):
        """Record a failed login attempt for an IP."""
        if ip not in ip_lockout:
            ip_lockout[ip] = {'attempts': 0, 'locked_until': None}
        ip_lockout[ip]['attempts'] += 1
        if ip_lockout[ip]['attempts'] >= max_login_attempts:
            ip_lockout[ip]['locked_until'] = datetime.now() + timedelta(minutes=lockout_minutes)
            return True
        return False

    def clear_failed_logins(ip):
        """Clear failed login attempts for an IP after successful login."""
        if ip in ip_lockout:
            del ip_lockout[ip]

    def login_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'api_session' not in session:
                return jsonify({'error': 'Not authenticated'}), 401
            return f(*args, **kwargs)
        return decorated_function

    def get_api_session() -> Optional[WazuhAPISession]:
        """Get API session from Flask session."""
        if 'api_session' not in session:
            return None
        sess_data = session['api_session']
        # Security: Create API session with token only (no password stored)
        api = WazuhAPISession(
            sess_data['host'],
            sess_data['port'],
            sess_data['username'],
            ''  # Password not stored for security
        )
        api.token = sess_data.get('token')
        return api

    @app.route('/images/<path:filename>')
    def serve_image(filename):
        """Serve images from the images directory."""
        from flask import send_from_directory
        # Get the images directory path (relative to the main script)
        images_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'images')
        return send_from_directory(images_dir, filename)

    @app.route('/')
    def index():
        if 'api_session' not in session:
            return redirect(url_for('login'))
        sess_data = session['api_session']
        return render_template_string(
            HTML_TEMPLATE,
            username=sess_data['username'],
            host=sess_data['host'],
            port=sess_data['port'],
            token_exp=sess_data.get('token_exp', 0),
            token_iat=sess_data.get('token_iat', 0),
            version=VERSION
        )

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        error = None
        host = request.form.get('host', 'localhost')
        port = request.form.get('port', '55000')
        username = request.form.get('username', '')

        # Check IP lockout
        client_ip = get_client_ip()
        locked, remaining_minutes = is_ip_locked(client_ip)
        if locked:
            error = f'IP locked due to too many failed attempts. Try again in {remaining_minutes} minute(s).'
            token_timeout_seconds = get_wazuh_api_token_timeout()
            token_timeout_minutes = token_timeout_seconds // 60
            return render_template_string(
                LOGIN_TEMPLATE,
                error=error,
                host=host,
                port=port,
                username=username,
                token_timeout_minutes=token_timeout_minutes,
                version=VERSION
            )

        if request.method == 'POST':
            password = request.form.get('password', '')
            try:
                port_int = int(port)
                api = WazuhAPISession(host, port_int, username, password)
                if api.authenticate():
                    clear_failed_logins(client_ip)  # Clear on successful login
                    # Security: Don't store password in session, only token
                    # Decode JWT to get actual expiration time
                    import time
                    import base64
                    token_exp = 0
                    token_iat = int(time.time())
                    try:
                        # JWT format: header.payload.signature
                        payload = api.token.split('.')[1]
                        # Add padding if needed
                        payload += '=' * (4 - len(payload) % 4)
                        decoded = json.loads(base64.urlsafe_b64decode(payload))
                        token_exp = decoded.get('exp', 0)
                        token_iat = decoded.get('iat', token_iat)
                    except Exception:
                        # Fallback to default 15 minutes if decode fails
                        token_exp = int(time.time()) + 900

                    session['api_session'] = {
                        'host': host,
                        'port': port_int,
                        'username': username,
                        'token': api.token,
                        'token_exp': token_exp,  # Token expiration timestamp from JWT
                        'token_iat': token_iat   # Token issued at timestamp
                    }
                    session.permanent = True  # Use permanent session with timeout
                    logger.info(f"LOGIN SUCCESS: user={username} from={client_ip} api={host}:{port_int}")
                    return redirect(url_for('index'))
                else:
                    # Record failed attempt
                    just_locked = record_failed_login(client_ip)
                    logger.warning(f"LOGIN FAILED: user={username} from={client_ip} api={host}:{port_int}")
                    if just_locked:
                        logger.warning(f"IP LOCKED: {client_ip} due to too many failed attempts")
                        error = f'Too many failed attempts. IP locked for {lockout_minutes} minutes.'
                    else:
                        attempts_left = max_login_attempts - ip_lockout.get(client_ip, {}).get('attempts', 0)
                        error = f'Authentication failed. {attempts_left} attempt(s) remaining.'
            except ValueError:
                error = 'Invalid port number.'
            except Exception as e:
                error_msg = str(e)
                logger.warning(f"LOGIN ERROR: user={username} from={client_ip} api={host}:{port} error={error_msg}")
                # Only record failed attempt for auth errors, not connection errors
                if "Invalid username or password" in error_msg:
                    just_locked = record_failed_login(client_ip)
                    if just_locked:
                        error = f'Too many failed attempts. IP locked for {lockout_minutes} minutes.'
                    else:
                        attempts_left = max_login_attempts - ip_lockout.get(client_ip, {}).get('attempts', 0)
                        error = f'{error_msg}. {attempts_left} attempt(s) remaining.'
                else:
                    # Connection/API errors - show the descriptive message
                    error = error_msg

        token_timeout_seconds = get_wazuh_api_token_timeout()
        token_timeout_minutes = token_timeout_seconds // 60
        return render_template_string(
            LOGIN_TEMPLATE,
            error=error,
            host=host,
            port=port,
            username=username,
            token_timeout_minutes=token_timeout_minutes,
            version=VERSION
        )

    @app.route('/logout')
    def logout():
        api_session = session.get('api_session', {})
        username = api_session.get('username', 'unknown')
        client_ip = get_client_ip()
        logger.info(f"LOGOUT: user={username} from={client_ip}")
        session.pop('api_session', None)
        return redirect(url_for('login'))

    # Global error handler for session expired
    @app.errorhandler(SessionExpiredException)
    def handle_session_expired(e):
        return jsonify({'error': 'Session expired. Please login again.', 'session_expired': True}), 401

    @app.route('/api/agents', methods=['GET'])
    @login_required
    def get_agents():
        try:
            api = get_api_session()
            agents = api.get_agents()
            return jsonify({'agents': agents})
        except SessionExpiredException:
            raise  # Let the error handler handle it
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/agents/<agent_id>', methods=['GET'])
    @login_required
    def get_agent_detail(agent_id):
        if not validate_agent_id(agent_id):
            return jsonify({'error': 'Invalid agent ID'}), 400
        try:
            api = get_api_session()
            agent = api.get_agent_details(agent_id)
            if not agent:
                return jsonify({'error': 'Agent not found'}), 404
            return jsonify({'agent': agent})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/agents/queue-size', methods=['GET'])
    @login_required
    def get_agents_queue_size():
        """Get queue database sizes for all agents from /var/ossec/queue/db/"""
        import socket
        import subprocess
        try:
            wazuh_path = '/var/ossec'
            queue_db_path = os.path.join(wazuh_path, 'queue', 'db')
            local_hostname = socket.gethostname()

            # Get cluster nodes info
            api = get_api_session()
            nodes = api.get_nodes()

            # Get SSH config
            config = get_config()

            # Determine local node name
            local_node_name = local_hostname
            other_nodes = []
            ssh_failed_nodes = []
            loaded_nodes = []

            for n in nodes:
                node_name = n.get('name', '')
                if (node_name == local_hostname or
                    node_name.replace('-server', '') == local_hostname or
                    local_hostname.replace('-server', '') == node_name.replace('-server', '')):
                    local_node_name = node_name
                else:
                    other_nodes.append({
                        'name': node_name,
                        'ip': n.get('ip', ''),
                        'type': n.get('type', '')
                    })

            queue_sizes = {}  # agent_id -> list of {size, node}

            # Helper function to add queue size entry
            def add_queue_entry(agent_id, size, node_name):
                if agent_id not in queue_sizes:
                    queue_sizes[agent_id] = []
                queue_sizes[agent_id].append({
                    'size': size,
                    'node': node_name
                })

            # Read local queue db
            if os.path.exists(queue_db_path):
                for db_file in glob.glob(os.path.join(queue_db_path, '*.db')):
                    filename = os.path.basename(db_file)
                    agent_id = filename.replace('.db', '')
                    try:
                        size = os.path.getsize(db_file)
                        add_queue_entry(agent_id, size, local_node_name)
                    except OSError:
                        pass
                loaded_nodes.append(local_node_name)

            # Try to read remote queue db via SSH
            for node in other_nodes:
                node_name = node['name']
                ssh_cfg = config.get_ssh_config_for_node(node_name)

                if ssh_cfg:
                    try:
                        # Get list of db files and their sizes from remote node
                        ssh_cmd = [
                            'ssh',
                            '-i', ssh_cfg['key_file'],
                            '-o', 'StrictHostKeyChecking=no',
                            '-o', 'ConnectTimeout=5',
                            '-p', str(ssh_cfg['port']),
                            f"{ssh_cfg['user']}@{ssh_cfg['host']}",
                            f"find {queue_db_path} -name '*.db' -exec stat --format='%n %s' {{}} \\; 2>/dev/null"
                        ]
                        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=15)

                        if result.returncode == 0 and result.stdout.strip():
                            for line in result.stdout.strip().split('\n'):
                                if line:
                                    parts = line.rsplit(' ', 1)
                                    if len(parts) == 2:
                                        filepath, size_str = parts
                                        filename = os.path.basename(filepath)
                                        agent_id = filename.replace('.db', '')
                                        try:
                                            size = int(size_str)
                                            add_queue_entry(agent_id, size, node_name)
                                        except ValueError:
                                            pass
                            loaded_nodes.append(node_name)
                        else:
                            ssh_failed_nodes.append(node_name)
                    except Exception as e:
                        logger.warning(f"SSH queue-size failed for {node_name}: {e}")
                        ssh_failed_nodes.append(node_name)
                else:
                    ssh_failed_nodes.append(node_name)

            # Build note message
            if ssh_failed_nodes:
                note = f"Queue sizes loaded from: {', '.join(loaded_nodes)}. Failed nodes: {', '.join(ssh_failed_nodes)}."
            else:
                note = f"Queue sizes loaded from all nodes: {', '.join(loaded_nodes)}."

            # Log for debugging
            for agent_id, entries in queue_sizes.items():
                for entry in entries:
                    logger.debug(f"Queue DB: agent={agent_id}, size={entry['size']} bytes, node={entry['node']}")

            return jsonify({
                'queue_sizes': queue_sizes,
                'path': queue_db_path,
                'local_node': local_node_name,
                'loaded_nodes': loaded_nodes,
                'other_nodes': other_nodes,
                'ssh_failed_nodes': ssh_failed_nodes,
                'has_other_nodes': len(other_nodes) > 0,
                'note': note
            })
        except Exception as e:
            return jsonify({'error': str(e), 'queue_sizes': {}}), 500

    def get_current_user():
        """Get current logged in username for logging."""
        api_session = session.get('api_session', {})
        return api_session.get('username', 'unknown')

    @app.route('/api/agents', methods=['DELETE'])
    @login_required
    def delete_agents():
        try:
            data = request.get_json()
            agent_ids = data.get('agent_ids', [])
            dry_run = data.get('dry_run', False)

            user = get_current_user()
            if dry_run:
                logger.info(f"AGENT DELETE [DRY-RUN]: user={user} agents={agent_ids}")
                return jsonify({
                    'message': f"[DRY-RUN] Would delete {len(agent_ids)} agents",
                    'dry_run': True
                })

            api = get_api_session()
            result = api.delete_agents(agent_ids)
            affected = len(result.get('data', {}).get('affected_items', []))
            logger.info(f"AGENT DELETE: user={user} agents={agent_ids} affected={affected}")
            return jsonify({
                'message': f"Deleted {affected}/{len(agent_ids)} agents",
                'result': result
            })
        except Exception as e:
            logger.error(f"AGENT DELETE ERROR: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/agents/restart', methods=['POST'])
    @login_required
    def restart_agents():
        try:
            data = request.get_json()
            agent_ids = data.get('agent_ids', [])
            dry_run = data.get('dry_run', False)

            user = get_current_user()
            if dry_run:
                logger.info(f"AGENT RESTART [DRY-RUN]: user={user} agents={agent_ids}")
                return jsonify({
                    'message': f"[DRY-RUN] Would restart {len(agent_ids)} agents",
                    'dry_run': True
                })

            api = get_api_session()
            result = api.restart_agents(agent_ids)
            affected = len(result.get('data', {}).get('affected_items', []))
            logger.info(f"AGENT RESTART: user={user} agents={agent_ids} affected={affected}")
            return jsonify({
                'message': f"Restarted {affected}/{len(agent_ids)} agents",
                'result': result
            })
        except Exception as e:
            logger.error(f"AGENT RESTART ERROR: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/agents/reconnect', methods=['POST'])
    @login_required
    def reconnect_agents():
        try:
            data = request.get_json()
            agent_ids = data.get('agent_ids', [])
            dry_run = data.get('dry_run', False)

            user = get_current_user()
            if dry_run:
                logger.info(f"AGENT RECONNECT [DRY-RUN]: user={user} agents={agent_ids}")
                return jsonify({
                    'message': f"[DRY-RUN] Would reconnect {len(agent_ids)} agents",
                    'dry_run': True
                })

            api = get_api_session()
            result = api.reconnect_agents(agent_ids)
            affected = len(result.get('data', {}).get('affected_items', []))
            logger.info(f"AGENT RECONNECT: user={user} agents={agent_ids} affected={affected}")
            return jsonify({
                'message': f"Reconnected {affected}/{len(agent_ids)} agents",
                'result': result
            })
        except Exception as e:
            logger.error(f"AGENT RECONNECT ERROR: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/agents/upgrade', methods=['POST'])
    @login_required
    def upgrade_agents():
        """Upgrade selected agents to a specified or latest version."""
        try:
            data = request.get_json()
            agent_ids = data.get('agent_ids', [])
            version = data.get('version')  # None means use manager version
            force = data.get('force', False)
            dry_run = data.get('dry_run', False)

            user = get_current_user()
            api = get_api_session()

            # Get manager version to use as target when no version specified
            manager_version = None
            if not version:
                try:
                    nodes = api.get_nodes()
                    print(f"[UPGRADE] Nodes: {nodes}")
                    master_node = next((n for n in nodes if n.get('type') == 'master'), nodes[0] if nodes else None)
                    if master_node:
                        raw_version = master_node.get('version', '')
                        manager_version = raw_version.replace('Wazuh ', '').replace('v', '').strip()
                        print(f"[UPGRADE] Master node: {master_node.get('name')}, raw_version={raw_version}, manager_version={manager_version}")
                        logger.info(f"Manager version detected: {manager_version}")
                except Exception as e:
                    print(f"[UPGRADE] ERROR getting manager version: {e}")
                    logger.warning(f"Could not get manager version: {e}")

            version_str = f"v{version}" if version else f"v{manager_version}" if manager_version else "latest"

            if dry_run:
                logger.info(f"AGENT UPGRADE [DRY-RUN]: user={user} agents={agent_ids} version={version_str} force={force}")
                return jsonify({
                    'message': f"[DRY-RUN] Would upgrade {len(agent_ids)} agents to {version_str}",
                    'dry_run': True,
                    'success_count': len(agent_ids),
                    'fail_count': 0
                })

            # Upgrade agents one by one and collect results
            success_count = 0
            fail_count = 0
            failed_agents = []

            for agent_id in agent_ids:
                try:
                    result = api.upgrade_agent(agent_id, version=version, force=force, manager_version=manager_version)
                    if result.get('error'):
                        fail_count += 1
                        failed_agents.append({'id': agent_id, 'error': result.get('error')})
                    else:
                        success_count += 1
                except Exception as e:
                    fail_count += 1
                    failed_agents.append({'id': agent_id, 'error': str(e)})

            logger.info(f"AGENT UPGRADE: user={user} agents={agent_ids} version={version_str} force={force} success={success_count} fail={fail_count}")

            return jsonify({
                'message': f"Upgrade initiated: {success_count} success, {fail_count} failed",
                'success_count': success_count,
                'fail_count': fail_count,
                'failed_agents': failed_agents if failed_agents else None
            })
        except Exception as e:
            logger.error(f"AGENT UPGRADE ERROR: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/agents/upgrade-result', methods=['GET'])
    @login_required
    def get_upgrade_result():
        """Get upgrade task results for agents."""
        try:
            api = get_api_session()

            agent_ids = request.args.get('agent_ids', '').split(',') if request.args.get('agent_ids') else None
            if agent_ids:
                agent_ids = [aid.strip() for aid in agent_ids if aid.strip()]

            result = api.get_upgrade_result(agent_ids if agent_ids else None)
            logger.debug(f"Upgrade result API response: {result}")

            # Handle various Wazuh API error response formats
            if result.get('error'):
                error_info = result.get('error')
                # Error might be a dict with 'message' or just a string/code
                if isinstance(error_info, dict):
                    error_msg = error_info.get('message', str(error_info))
                else:
                    error_msg = str(error_info)

                # Wazuh returns error code 1 or "No task in DB" when no tasks found
                if error_msg in ['1', '2'] or 'no task' in error_msg.lower() or 'not found' in error_msg.lower():
                    return jsonify({'results': [], 'total': 0})

                logger.warning(f"Upgrade result error: {error_msg}")
                return jsonify({'error': error_msg}), 400

            # Check for failed_items in data (Wazuh API often puts errors here)
            data = result.get('data', {})
            failed_items = data.get('failed_items', [])
            if failed_items and not data.get('affected_items'):
                # All queries failed - likely no tasks for these agents
                error_msgs = []
                for fi in failed_items:
                    err = fi.get('error', {})
                    if isinstance(err, dict):
                        error_msgs.append(err.get('message', str(err)))
                    else:
                        error_msgs.append(str(err))
                # "No task in DB" or similar means no upgrade tasks - return empty
                if any('no task' in m.lower() or m in ['1', '2'] for m in error_msgs):
                    return jsonify({'results': [], 'total': 0})

            # Parse upgrade results
            items = data.get('affected_items', [])
            upgrade_results = []
            for item in items:
                upgrade_results.append({
                    'agent_id': str(item.get('agent', '')),
                    'task_id': item.get('task_id'),
                    'status': item.get('status', 'unknown'),
                    'error': item.get('error_message', ''),
                    'create_time': item.get('create_time', ''),
                    'update_time': item.get('update_time', '')
                })

            return jsonify({
                'results': upgrade_results,
                'total': len(upgrade_results)
            })
        except Exception as e:
            logger.error(f"GET UPGRADE RESULT ERROR: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/groups', methods=['GET'])
    @login_required
    def get_groups():
        try:
            api = get_api_session()
            groups = api.get_groups()
            return jsonify({'groups': groups})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/groups', methods=['POST'])
    @login_required
    def create_group():
        try:
            data = request.get_json()
            name = data.get('name')
            dry_run = data.get('dry_run', False)
            user = get_current_user()

            if dry_run:
                logger.info(f"GROUP CREATE [DRY-RUN]: user={user} group={name}")
                return jsonify({
                    'message': f"[DRY-RUN] Would create group '{name}'",
                    'dry_run': True
                })

            api = get_api_session()
            result = api.create_group(name)
            logger.info(f"GROUP CREATE: user={user} group={name}")
            return jsonify({'success': True, 'message': f"Group '{name}' created", 'result': result})
        except Exception as e:
            logger.error(f"GROUP CREATE ERROR: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/groups/<name>', methods=['DELETE'])
    @login_required
    def delete_group(name):
        # Validate group name
        if not validate_group_name(name):
            return jsonify({'error': 'Invalid group name'}), 400
        try:
            data = request.get_json() or {}
            dry_run = data.get('dry_run', False)
            user = get_current_user()

            if dry_run:
                logger.info(f"GROUP DELETE [DRY-RUN]: user={user} group={name}")
                return jsonify({
                    'message': f"[DRY-RUN] Would delete group '{name}'",
                    'dry_run': True
                })

            api = get_api_session()
            result = api.delete_group(name)
            logger.info(f"GROUP DELETE: user={user} group={name}")
            return jsonify({'success': True, 'message': f"Group '{name}' deleted", 'result': result})
        except Exception as e:
            logger.error(f"GROUP DELETE ERROR: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/groups/rename', methods=['POST'])
    @login_required
    def rename_group():
        """Rename a group by creating new, copying config, moving agents, deleting old."""
        import shutil
        try:
            data = request.get_json()
            old_name = data.get('old_name', '')
            new_name = data.get('new_name', '')
            dry_run = data.get('dry_run', False)
            user = get_current_user()

            if not old_name or not new_name:
                return jsonify({'error': 'Both old_name and new_name are required'}), 400

            # Validate group names
            if not validate_group_name(old_name) or not validate_group_name(new_name):
                return jsonify({'error': 'Invalid group name'}), 400

            if old_name == new_name:
                return jsonify({'error': 'New name is the same as old name'}), 400

            # Validate group names (security: prevent path traversal)
            if '/' in old_name or '\\' in old_name or '..' in old_name:
                return jsonify({'error': 'Invalid old group name'}), 400
            if '/' in new_name or '\\' in new_name or '..' in new_name:
                return jsonify({'error': 'Invalid new group name'}), 400

            api = get_api_session()

            # Get agents in old group
            agents = api.get_agents(group=old_name)
            agent_ids = [a.get('id') for a in agents if a.get('id')]
            agent_count = len(agent_ids)

            # Check if old group has config files
            old_group_path = f'/var/ossec/etc/shared/{old_name}'
            new_group_path = f'/var/ossec/etc/shared/{new_name}'
            has_config = os.path.exists(old_group_path)
            config_files = []
            if has_config:
                config_files = [f for f in os.listdir(old_group_path) if os.path.isfile(os.path.join(old_group_path, f))]

            if dry_run:
                logger.info(f"GROUP RENAME [DRY-RUN]: user={user} old={old_name} new={new_name} agents={agent_count}")
                steps = [
                    f"1. Create new group '{new_name}'",
                    f"2. Copy config files ({len(config_files)} files: {', '.join(config_files[:5])}{'...' if len(config_files) > 5 else ''})" if config_files else "2. No config files to copy",
                    f"3. Move {agent_count} agent(s) to '{new_name}'",
                    f"4. Delete old group '{old_name}'"
                ]
                return jsonify({
                    'message': f"[DRY-RUN] Would rename '{old_name}' to '{new_name}' ({agent_count} agents, {len(config_files)} config files)",
                    'steps': steps,
                    'dry_run': True
                })

            # Step 1: Create new group
            try:
                api.create_group(new_name)
                logger.info(f"GROUP RENAME: Created new group '{new_name}'")
            except Exception as e:
                if 'already exists' not in str(e).lower():
                    raise Exception(f"Failed to create new group: {e}")

            # Step 2: Copy config files from old group to new group
            copied_files = []
            if has_config and os.path.exists(new_group_path):
                try:
                    for filename in config_files:
                        src = os.path.join(old_group_path, filename)
                        dst = os.path.join(new_group_path, filename)
                        shutil.copy2(src, dst)
                        copied_files.append(filename)
                    logger.info(f"GROUP RENAME: Copied {len(copied_files)} config files to '{new_name}'")
                except Exception as e:
                    logger.warning(f"GROUP RENAME: Failed to copy some config files: {e}")

            # Step 3: Move agents to new group (if any)
            if agent_ids:
                try:
                    api.add_agents_to_group(new_name, agent_ids)
                    logger.info(f"GROUP RENAME: Moved {agent_count} agents to '{new_name}'")
                except Exception as e:
                    logger.error(f"GROUP RENAME: Failed to move agents: {e}")
                    # Try to clean up - delete the new group
                    try:
                        api.delete_group(new_name)
                    except:
                        pass
                    raise Exception(f"Failed to move agents: {e}")

            # Step 4: Delete old group
            try:
                api.delete_group(old_name)
                logger.info(f"GROUP RENAME: Deleted old group '{old_name}'")
            except Exception as e:
                logger.warning(f"GROUP RENAME: Failed to delete old group (agents already moved): {e}")

            logger.info(f"GROUP RENAME: user={user} old={old_name} new={new_name} agents={agent_count} configs={len(copied_files)}")
            return jsonify({
                'success': True,
                'message': f"Group renamed from '{old_name}' to '{new_name}' ({agent_count} agents moved, {len(copied_files)} config files copied)"
            })

        except Exception as e:
            logger.error(f"GROUP RENAME ERROR: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/groups/<name>/agents', methods=['POST'])
    @login_required
    def add_agents_to_group(name):
        if not validate_group_name(name):
            return jsonify({'error': 'Invalid group name'}), 400
        try:
            data = request.get_json()
            agent_ids = data.get('agent_ids', [])
            dry_run = data.get('dry_run', False)

            if dry_run:
                return jsonify({
                    'message': f"[DRY-RUN] Would add {len(agent_ids)} agents to group '{name}'",
                    'dry_run': True
                })

            api = get_api_session()
            result = api.add_agents_to_group(name, agent_ids)

            # Log result for debugging
            print(f"[DEBUG] Add to group '{name}' agents={agent_ids}: {result}")

            # Check for errors in the result (error != 0 means failure)
            if result.get('error') and result.get('error') != 0:
                return jsonify({
                    'message': f"Error: {result.get('error')}",
                    'result': result
                }), 400

            data = result.get('data', {})
            affected = len(data.get('affected_items', []))
            failed = data.get('failed_items', [])
            total_failed = data.get('total_failed_items', 0)

            msg = f"Added {affected}/{len(agent_ids)} agents to '{name}'"

            # Parse failed items - id can be string or list
            if total_failed > 0 or failed:
                error_msgs = []
                for f in failed[:5]:
                    err_msg = f.get('error', {}).get('message', 'unknown error')
                    ids = f.get('id', [])
                    if isinstance(ids, list):
                        ids_str = ','.join(str(i) for i in ids[:3])
                    else:
                        ids_str = str(ids)
                    error_msgs.append(f"{ids_str}: {err_msg}")
                if error_msgs:
                    msg += f". Errors: {'; '.join(error_msgs)}"

            return jsonify({
                'message': msg,
                'result': result
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/groups/<name>/agents', methods=['DELETE'])
    @login_required
    def remove_agents_from_group(name):
        if not validate_group_name(name):
            return jsonify({'error': 'Invalid group name'}), 400
        try:
            data = request.get_json()
            agent_ids = data.get('agent_ids', [])
            dry_run = data.get('dry_run', False)

            if dry_run:
                return jsonify({
                    'message': f"[DRY-RUN] Would remove {len(agent_ids)} agents from group '{name}'",
                    'dry_run': True
                })

            api = get_api_session()
            result = api.remove_agents_from_group(name, agent_ids)

            # Check for errors in the result (error != 0 means failure)
            if result.get('error') and result.get('error') != 0:
                return jsonify({
                    'message': f"Error: {result.get('error')}",
                    'result': result
                }), 400

            affected = len(result.get('data', {}).get('affected_items', []))
            failed = result.get('data', {}).get('failed_items', [])
            failed_count = len(failed)

            msg = f"Removed {affected}/{len(agent_ids)} agents from '{name}'"
            if failed_count > 0:
                errors = [f"{f.get('id', '?')}: {f.get('error', {}).get('message', 'unknown')}" for f in failed[:3]]
                msg += f". Failed: {', '.join(errors)}"

            return jsonify({
                'message': msg,
                'result': result
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/groups/<name>/agents/all', methods=['DELETE'])
    @login_required
    def remove_all_agents_from_group(name):
        """Remove all agents from a group."""
        if not validate_group_name(name):
            return jsonify({'error': 'Invalid group name'}), 400
        try:
            data = request.get_json() or {}
            dry_run = data.get('dry_run', False)

            api = get_api_session()
            # First get all agents in this group
            all_agents = api.get_agents()
            agents_in_group = [a for a in all_agents if name in (a.get('group') or '').split(',')]
            agent_ids = [a['id'] for a in agents_in_group]

            if len(agent_ids) == 0:
                return jsonify({'message': f"No agents in group '{name}'"})

            if dry_run:
                return jsonify({
                    'message': f"[DRY-RUN] Would remove {len(agent_ids)} agents from group '{name}'",
                    'dry_run': True
                })

            result = api.remove_agents_from_group(name, agent_ids)

            # Check for errors (error != 0 means failure)
            if result.get('error') and result.get('error') != 0:
                return jsonify({'message': f"Error: {result.get('error')}", 'result': result}), 400

            affected = len(result.get('data', {}).get('affected_items', []))
            return jsonify({
                'message': f"Removed {affected}/{len(agent_ids)} agents from group '{name}'",
                'result': result
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/groups/<name>/exclusive', methods=['POST'])
    @login_required
    def set_exclusive_group(name):
        """Remove agents in this group from all other groups."""
        if not validate_group_name(name):
            return jsonify({'error': 'Invalid group name'}), 400
        try:
            data = request.get_json() or {}
            dry_run = data.get('dry_run', False)

            api = get_api_session()
            # Get all agents in this group
            all_agents = api.get_agents()
            agents_in_group = [a for a in all_agents if name in (a.get('group') or '').split(',')]

            if len(agents_in_group) == 0:
                return jsonify({'message': f"No agents in group '{name}'"})

            # Find agents that belong to other groups
            affected_count = 0
            other_groups_removed = set()

            for agent in agents_in_group:
                agent_groups = [g.strip() for g in (agent.get('group') or '').split(',') if g.strip()]
                other_groups = [g for g in agent_groups if g != name]

                if other_groups:
                    if dry_run:
                        for g in other_groups:
                            other_groups_removed.add(g)
                        affected_count += 1
                    else:
                        # Remove agent from each other group
                        for other_group in other_groups:
                            api.remove_agents_from_group(other_group, [agent['id']])
                            other_groups_removed.add(other_group)
                        affected_count += 1

            if affected_count == 0:
                return jsonify({'message': f"All agents in '{name}' already belong only to this group"})

            if dry_run:
                return jsonify({
                    'message': f"[DRY-RUN] Would remove {affected_count} agent(s) from other groups: {', '.join(sorted(other_groups_removed))}",
                    'dry_run': True
                })

            return jsonify({
                'message': f"Removed {affected_count} agent(s) from other groups: {', '.join(sorted(other_groups_removed))}"
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/groups/<name>/move', methods=['POST'])
    @login_required
    def move_group_agents(name):
        """Move all agents from one group to another."""
        if not validate_group_name(name):
            return jsonify({'error': 'Invalid group name'}), 400
        try:
            data = request.get_json() or {}
            target_group = data.get('target_group')
            dry_run = data.get('dry_run', False)

            if not target_group:
                return jsonify({'error': 'Target group is required'}), 400

            # Validate target group name too
            if not validate_group_name(target_group):
                return jsonify({'error': 'Invalid target group name'}), 400

            api = get_api_session()
            # Get all agents in source group
            all_agents = api.get_agents()
            agents_in_group = [a for a in all_agents if name in (a.get('group') or '').split(',')]
            agent_ids = [a['id'] for a in agents_in_group]

            if len(agent_ids) == 0:
                return jsonify({'message': f"No agents in group '{name}'"})

            if dry_run:
                return jsonify({
                    'message': f"[DRY-RUN] Would move {len(agent_ids)} agents from '{name}' to '{target_group}'",
                    'dry_run': True
                })

            # Add agents to target group first
            add_result = api.add_agents_to_group(target_group, agent_ids)
            added = len(add_result.get('data', {}).get('affected_items', []))

            # Then remove from source group
            remove_result = api.remove_agents_from_group(name, agent_ids)
            removed = len(remove_result.get('data', {}).get('affected_items', []))

            return jsonify({
                'message': f"Moved {removed}/{len(agent_ids)} agents from '{name}' to '{target_group}'",
                'added': added,
                'removed': removed
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/groups/<name>/import', methods=['POST'])
    @login_required
    def import_agents_to_group(name):
        """Import agents to a group from CSV data."""
        if not validate_group_name(name):
            return jsonify({'error': 'Invalid group name'}), 400
        try:
            data = request.get_json() or {}
            agents_data = data.get('agents', [])
            dry_run = data.get('dry_run', False)

            if not agents_data:
                return jsonify({'error': 'No agents data provided'}), 400

            api = get_api_session()
            all_agents = api.get_agents()

            # Build lookup tables
            id_map = {a['id']: a for a in all_agents}
            name_map = {a['name'].lower(): a for a in all_agents}
            ip_map = {a['ip']: a for a in all_agents}

            added = []
            not_found = []
            already_in_group = []
            agent_ids_to_add = []

            for row in agents_data:
                agent = None
                identifier = None
                primary = row.get('primaryMatch', 'id')

                # Define match order based on primaryMatch (leftmost column in CSV)
                if primary == 'id':
                    match_order = ['id', 'name', 'ip']
                elif primary == 'name':
                    match_order = ['name', 'id', 'ip']
                else:  # ip
                    match_order = ['ip', 'id', 'name']

                # Try to find agent in priority order
                for match_type in match_order:
                    if agent:
                        break
                    if match_type == 'id' and row.get('id'):
                        agent = id_map.get(row['id'])
                        identifier = identifier or f"ID:{row['id']}"
                    elif match_type == 'name' and row.get('name'):
                        agent = name_map.get(row['name'].lower())
                        identifier = identifier or f"Name:{row['name']}"
                    elif match_type == 'ip' and row.get('ip'):
                        agent = ip_map.get(row['ip'])
                        identifier = identifier or f"IP:{row['ip']}"

                if not identifier:
                    continue

                if not agent:
                    not_found.append(identifier)
                    continue

                # Check if already in group
                current_groups = (agent.get('group') or '').split(',')
                current_groups = [g.strip() for g in current_groups if g.strip()]
                if name in current_groups:
                    already_in_group.append(f"{agent['id']} ({agent['name']})")
                    continue

                added.append(f"{agent['id']} ({agent['name']})")
                agent_ids_to_add.append(agent['id'])

            if dry_run:
                return jsonify({
                    'message': f"[DRY-RUN] Would add {len(agent_ids_to_add)} agents to group '{name}'",
                    'dry_run': True,
                    'added': added,
                    'not_found': not_found,
                    'already_in_group': already_in_group
                })

            # Actually add agents
            if agent_ids_to_add:
                api.add_agents_to_group(name, agent_ids_to_add)

            return jsonify({
                'message': f"Added {len(agent_ids_to_add)} agents to group '{name}'",
                'added': added,
                'not_found': not_found,
                'already_in_group': already_in_group
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/groups/<name>/config', methods=['GET'])
    @login_required
    def get_group_config(name):
        """Get agent.conf for a group."""
        # Security: validate group name
        if not validate_group_name(name):
            return jsonify({'error': 'Invalid group name'}), 400
        try:

            config_path = f'/var/ossec/etc/shared/{name}/agent.conf'
            user = get_current_user()

            if not os.path.exists(config_path):
                # Return empty template if file doesn't exist
                default_content = '''<!-- agent.conf for group: ''' + name + ''' -->
<agent_config>
    <!-- Add your configuration here -->
    <!-- Example:
    <localfile>
        <log_format>syslog</log_format>
        <location>/var/log/example.log</location>
    </localfile>
    -->
</agent_config>
'''
                return jsonify({
                    'content': default_content,
                    'path': config_path,
                    'exists': False
                })

            with open(config_path, 'r', encoding='utf-8') as f:
                content = f.read()

            logger.info(f"Group config read: {config_path} by user '{user}'")
            return jsonify({
                'content': content,
                'path': config_path,
                'exists': True
            })

        except Exception as e:
            logger.error(f"Group config read error: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/groups/<name>/config', methods=['PUT'])
    @login_required
    def save_group_config(name):
        """Save agent.conf for a group."""
        # Security: validate group name
        if not validate_group_name(name):
            return jsonify({'error': 'Invalid group name'}), 400
        try:
            data = request.get_json()
            content = data.get('content', '')
            user = get_current_user()

            group_dir = f'/var/ossec/etc/shared/{name}'
            config_path = f'{group_dir}/agent.conf'

            # Check if group directory exists
            if not os.path.exists(group_dir):
                return jsonify({'error': f"Group '{name}' does not exist"}), 404

            # Create backup if file exists
            backup_path = None
            if os.path.exists(config_path):
                from datetime import datetime
                backup_dir = '/var/ossec/etc/backup'
                os.makedirs(backup_dir, exist_ok=True)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                backup_path = f'{backup_dir}/agent.conf.{name}.{timestamp}.bak'
                import shutil
                shutil.copy2(config_path, backup_path)
                logger.info(f"Group config backup created: {backup_path}")

            # Save new content
            with open(config_path, 'w', encoding='utf-8') as f:
                f.write(content)

            # Set proper permissions (ossec:ossec)
            try:
                import pwd
                import grp
                uid = pwd.getpwnam('ossec').pw_uid
                gid = grp.getgrnam('ossec').gr_gid
                os.chown(config_path, uid, gid)
                os.chmod(config_path, 0o660)
            except:
                pass  # Ignore permission errors on non-Wazuh systems

            logger.info(f"Group config saved: {config_path} by user '{user}'")
            return jsonify({
                'success': True,
                'message': f"Config saved for group '{name}'",
                'backup_path': backup_path
            })

        except Exception as e:
            logger.error(f"Group config save error: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/groups/<name>/config/download', methods=['GET'])
    @login_required
    def download_group_config(name):
        """Download agent.conf for a group."""
        # Security: validate group name
        if not validate_group_name(name):
            return jsonify({'error': 'Invalid group name'}), 400
        from flask import Response
        try:

            config_path = f'/var/ossec/etc/shared/{name}/agent.conf'
            user = get_current_user()

            if not os.path.exists(config_path):
                return jsonify({'error': f"Config file not found for group '{name}'"}), 404

            with open(config_path, 'r', encoding='utf-8') as f:
                content = f.read()

            logger.info(f"Group config downloaded: {config_path} by user '{user}'")

            return Response(
                content,
                mimetype='application/xml',
                headers={
                    'Content-Disposition': f'attachment; filename=agent.conf.{name}'
                }
            )

        except Exception as e:
            logger.error(f"Group config download error: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes', methods=['GET'])
    @login_required
    def get_nodes():
        try:
            api = get_api_session()
            nodes = api.get_nodes()

            # Calculate agent count per node
            if nodes:
                agents = api.get_agents()
                node_counts = {}
                for agent in agents:
                    node_name = agent.get('node_name', '')
                    if node_name:
                        node_counts[node_name] = node_counts.get(node_name, 0) + 1

                # For single-node setup, assign all agents to that node
                if len(nodes) == 1:
                    nodes[0]['count'] = len(agents)
                else:
                    for node in nodes:
                        node['count'] = node_counts.get(node['name'], 0)

            return jsonify({'nodes': nodes})
        except Exception as e:
            return jsonify({'error': str(e), 'nodes': []})

    @app.route('/api/nodes/<name>/reconnect', methods=['POST'])
    @login_required
    def reconnect_node(name):
        # Validate node name
        if not validate_node_name(name):
            return jsonify({'error': 'Invalid node name'}), 400
        try:
            data = request.get_json() or {}
            dry_run = data.get('dry_run', False)

            api = get_api_session()
            # Get agents on this node
            agents = api.get_agents()
            node_agents = [a['id'] for a in agents if a.get('node_name') == name]

            if dry_run:
                return jsonify({
                    'message': f"[DRY-RUN] Would reconnect {len(node_agents)} agents on node '{name}'",
                    'dry_run': True
                })

            if not node_agents:
                return jsonify({'message': f"No agents found on node '{name}'"})

            result = api.reconnect_agents(node_agents)
            affected = len(result.get('data', {}).get('affected_items', []))
            return jsonify({
                'message': f"Reconnected {affected}/{len(node_agents)} agents on '{name}'",
                'result': result
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes/services', methods=['GET'])
    @login_required
    def get_nodes_services():
        """Get Wazuh service status for all nodes via API."""
        try:
            api = get_api_session()

            # Get nodes status via API
            nodes_status = api.get_nodes_status()

            # Friendly name mapping
            service_names = {
                'wazuh-modulesd': 'Modules',
                'wazuh-db': 'DB',
                'wazuh-execd': 'Exec',
                'wazuh-analysisd': 'Analysis',
                'wazuh-syscheckd': 'Syscheck',
                'wazuh-remoted': 'Remote',
                'wazuh-logcollector': 'Logcollect',
                'wazuh-monitord': 'Monitor',
                'wazuh-clusterd': 'Cluster',
                'wazuh-apid': 'API'
            }

            # Format services with friendly names
            result = {}
            for node_name, services in nodes_status.items():
                formatted_services = []
                for svc in services:
                    svc_name = svc.get('name', '')
                    friendly_name = service_names.get(svc_name, svc_name.replace('wazuh-', '').title())
                    formatted_services.append({
                        'name': friendly_name,
                        'status': svc.get('status', 'unknown')
                    })
                result[node_name] = formatted_services

            # Also get cluster status
            cluster_status = api.get_cluster_status()

            return jsonify({
                'services': result,
                'cluster': cluster_status
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes/sync-status', methods=['GET'])
    @login_required
    def get_nodes_sync_status():
        """Get cluster sync status by comparing files between master and worker nodes."""
        import subprocess
        import hashlib
        import socket

        # Define sync items to check
        # type: 'dir' = compare all files in directory
        # type: 'file' = compare single file
        # type: 'subdirs' = only compare subdirectories (not root files)
        SYNC_ITEMS = [
            {'name': 'Rules', 'path': '/var/ossec/etc/rules/', 'type': 'dir'},
            {'name': 'Decoders', 'path': '/var/ossec/etc/decoders/', 'type': 'dir'},
            {'name': 'Groups', 'path': '/var/ossec/etc/shared/', 'type': 'subdirs'},  # Only compare group subdirs
            {'name': 'Keys', 'path': '/var/ossec/etc/client.keys', 'type': 'file'},
            {'name': 'Lists', 'path': '/var/ossec/etc/lists/', 'type': 'dir'},
            {'name': 'SCA', 'path': '/var/ossec/ruleset/sca/', 'type': 'dir'},
        ]

        def get_path_checksum(path, item_type, ssh_cmd=None):
            """Get checksum for a path (file or directory).

            item_type:
            - 'file': Compare single file
            - 'dir': Compare all files in directory recursively
            - 'subdirs': Only compare files within subdirectories (skip root-level files)
            """
            try:
                if item_type == 'file':
                    if ssh_cmd:
                        cmd = f"{ssh_cmd} 'md5sum {path} 2>/dev/null || echo NOTFOUND'"
                    else:
                        cmd = f"md5sum {path} 2>/dev/null || echo NOTFOUND"
                elif item_type == 'subdirs':
                    # Only compare files within subdirectories, skip root-level files
                    # Find all directories first, then find files within them
                    if ssh_cmd:
                        cmd = f"{ssh_cmd} 'find {path} -mindepth 2 -type f -exec md5sum {{}} \\; 2>/dev/null | sort || echo NOTFOUND'"
                    else:
                        cmd = f"find {path} -mindepth 2 -type f -exec md5sum {{}} \\; 2>/dev/null | sort || echo NOTFOUND"
                else:
                    # For directories, get sorted list of files with their checksums
                    if ssh_cmd:
                        cmd = f"{ssh_cmd} 'find {path} -type f -exec md5sum {{}} \\; 2>/dev/null | sort || echo NOTFOUND'"
                    else:
                        cmd = f"find {path} -type f -exec md5sum {{}} \\; 2>/dev/null | sort || echo NOTFOUND"

                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                output = result.stdout.strip()

                if not output or 'NOTFOUND' in output or result.returncode != 0:
                    return None

                # Hash the entire output to get a single checksum representing the directory state
                return hashlib.md5(output.encode()).hexdigest()
            except Exception as e:
                return None

        try:
            api = get_api_session()

            # Get cluster nodes
            nodes_result = api.request('GET', '/cluster/nodes')
            if nodes_result.get('error'):
                return jsonify({'error': nodes_result.get('error')}), 500

            nodes = nodes_result.get('data', {}).get('affected_items', [])

            # Find master and workers
            master_node = None
            worker_nodes = []
            for node in nodes:
                if node.get('type') == 'master':
                    master_node = node
                elif node.get('type') == 'worker':
                    worker_nodes.append(node)

            if not master_node:
                return jsonify({'sync_status': {}, 'message': 'No master node found'})

            if not worker_nodes:
                return jsonify({'sync_status': {}, 'message': 'No worker nodes found'})

            # Get master checksums (local)
            master_checksums = {}
            for item in SYNC_ITEMS:
                master_checksums[item['name']] = get_path_checksum(item['path'], item['type'])

            # Check each worker node
            sync_status = {}
            local_hostname = socket.gethostname()

            # Get SSH config from application config
            from .config import get_config
            config = get_config()

            for worker in worker_nodes:
                worker_name = worker.get('name', '')
                worker_ip = worker.get('ip', '')

                sync_items = []

                # Build SSH command for this worker using config
                ssh_cmd = None
                ssh_config = config.get_ssh_config_for_node(worker_name)

                if ssh_config:
                    # Use configured SSH settings
                    ssh_host = ssh_config.get('host', worker_ip)
                    ssh_port = ssh_config.get('port', 22)
                    ssh_user = ssh_config.get('user', 'root')
                    ssh_key = ssh_config.get('key_file', '')

                    if ssh_key:
                        ssh_cmd = f"ssh -i {ssh_key} -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p {ssh_port} {ssh_user}@{ssh_host}"
                    else:
                        ssh_cmd = f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p {ssh_port} {ssh_user}@{ssh_host}"
                elif worker_ip and worker_ip not in ['localhost', '127.0.0.1', local_hostname]:
                    # Fallback: try default SSH key location
                    default_key = '/root/.ssh/wazuh_cluster_key'
                    import os
                    if os.path.exists(default_key):
                        ssh_cmd = f"ssh -i {default_key} -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@{worker_ip}"
                    else:
                        ssh_cmd = f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@{worker_ip}"

                if ssh_cmd:
                    # Test SSH connection first
                    test_result = subprocess.run(
                        f"{ssh_cmd} 'echo OK' 2>/dev/null",
                        shell=True, capture_output=True, text=True, timeout=15
                    )
                    if 'OK' not in test_result.stdout:
                        # SSH not available, mark all as unknown
                        for item in SYNC_ITEMS:
                            sync_items.append({
                                'name': item['name'],
                                'path': item['path'],
                                'status': 'unknown'
                            })
                        sync_status[worker_name] = sync_items
                        continue
                else:
                    # No SSH available for this node
                    for item in SYNC_ITEMS:
                        sync_items.append({
                            'name': item['name'],
                            'path': item['path'],
                            'status': 'unknown'
                        })
                    sync_status[worker_name] = sync_items
                    continue

                # Compare each sync item
                for item in SYNC_ITEMS:
                    worker_checksum = get_path_checksum(item['path'], item['type'], ssh_cmd)
                    master_checksum = master_checksums.get(item['name'])

                    if master_checksum is None and worker_checksum is None:
                        status = 'synced'  # Both don't have it, considered synced
                    elif master_checksum is None or worker_checksum is None:
                        status = 'not_synced'  # One has it, one doesn't
                    elif master_checksum == worker_checksum:
                        status = 'synced'
                    else:
                        status = 'not_synced'

                    sync_items.append({
                        'name': item['name'],
                        'path': item['path'],
                        'status': status
                    })

                sync_status[worker_name] = sync_items

            return jsonify({'sync_status': sync_status})
        except Exception as e:
            import traceback
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes/<name>/sync-detail', methods=['GET'])
    @login_required
    def get_node_sync_detail(name):
        """Get detailed sync comparison for a specific item on a worker node."""
        import subprocess
        import socket

        # Validate node name
        if not validate_node_name(name):
            logger.warning(f"Invalid node name attempt: {sanitize_for_log(name)}")
            return jsonify({'error': 'Invalid node name'}), 400

        item_name = request.args.get('item', '')
        item_path = request.args.get('path', '')

        if not item_name or not item_path:
            return jsonify({'error': 'Missing item or path parameter'}), 400

        # Whitelist of allowed sync items (prevent arbitrary path access)
        ALLOWED_SYNC_ITEMS = {
            'Rules': '/var/ossec/etc/rules/',
            'Decoders': '/var/ossec/etc/decoders/',
            'Groups': '/var/ossec/etc/shared/',
            'Keys': '/var/ossec/etc/client.keys',
            'Lists': '/var/ossec/etc/lists/',
            'SCA': '/var/ossec/ruleset/sca/',
        }

        # Validate item_name is in whitelist
        if item_name not in ALLOWED_SYNC_ITEMS:
            logger.warning(f"Invalid sync item attempt: {sanitize_for_log(item_name)}")
            return jsonify({'error': 'Invalid sync item'}), 400

        # Validate item_path matches expected path for this item
        expected_path = ALLOWED_SYNC_ITEMS[item_name]
        if item_path != expected_path:
            logger.warning(f"Path mismatch for {item_name}: expected {expected_path}, got {sanitize_for_log(item_path)}")
            return jsonify({'error': 'Invalid path for sync item'}), 400

        # Determine type based on path and item name
        is_dir = item_path.endswith('/')
        # Groups need special handling - only compare subdirectories
        is_subdirs = (item_name == 'Groups')

        def get_file_list(path, ssh_cmd=None):
            """Get list of files with their md5sums."""
            try:
                if not is_dir:
                    # Single file
                    if ssh_cmd:
                        cmd = f"{ssh_cmd} 'md5sum {path} 2>/dev/null'"
                    else:
                        cmd = f"md5sum {path} 2>/dev/null"
                elif is_subdirs:
                    # Only files in subdirectories (mindepth 2 skips root-level files)
                    if ssh_cmd:
                        cmd = f"{ssh_cmd} 'find {path} -mindepth 2 -type f -exec md5sum {{}} \\; 2>/dev/null | sort'"
                    else:
                        cmd = f"find {path} -mindepth 2 -type f -exec md5sum {{}} \\; 2>/dev/null | sort"
                else:
                    # All files in directory
                    if ssh_cmd:
                        cmd = f"{ssh_cmd} 'find {path} -type f -exec md5sum {{}} \\; 2>/dev/null | sort'"
                    else:
                        cmd = f"find {path} -type f -exec md5sum {{}} \\; 2>/dev/null | sort"

                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
                output = result.stdout.strip()

                if not output:
                    return {}

                # Parse md5sum output: "checksum  filepath"
                files = {}
                for line in output.split('\n'):
                    if line.strip():
                        parts = line.split(None, 1)
                        if len(parts) == 2:
                            checksum, filepath = parts
                            # Remove base path for cleaner display
                            rel_path = filepath.replace(path, '').lstrip('/')
                            files[rel_path or os.path.basename(filepath)] = checksum
                return files
            except Exception as e:
                return {}

        try:
            api = get_api_session()

            # Get worker node info
            nodes_result = api.request('GET', '/cluster/nodes')
            if nodes_result.get('error'):
                return jsonify({'error': nodes_result.get('error')}), 500

            nodes = nodes_result.get('data', {}).get('affected_items', [])
            worker_node = None
            for node in nodes:
                if node.get('name') == name:
                    worker_node = node
                    break

            if not worker_node:
                return jsonify({'error': f'Node {name} not found'}), 404

            if worker_node.get('type') != 'worker':
                return jsonify({'error': 'Can only compare worker nodes'}), 400

            worker_ip = worker_node.get('ip', '')

            # Get SSH config
            from .config import get_config
            config = get_config()
            ssh_config = config.get_ssh_config_for_node(name)

            ssh_cmd = None
            local_hostname = socket.gethostname()

            if ssh_config:
                ssh_host = ssh_config.get('host', worker_ip)
                ssh_port = ssh_config.get('port', 22)
                ssh_user = ssh_config.get('user', 'root')
                ssh_key = ssh_config.get('key_file', '')

                if ssh_key:
                    ssh_cmd = f"ssh -i {ssh_key} -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p {ssh_port} {ssh_user}@{ssh_host}"
                else:
                    ssh_cmd = f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p {ssh_port} {ssh_user}@{ssh_host}"
            elif worker_ip and worker_ip not in ['localhost', '127.0.0.1', local_hostname]:
                default_key = '/root/.ssh/wazuh_cluster_key'
                if os.path.exists(default_key):
                    ssh_cmd = f"ssh -i {default_key} -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@{worker_ip}"

            if not ssh_cmd:
                return jsonify({'error': 'SSH not configured for this node'}), 400

            # Get file lists from master and worker
            master_files = get_file_list(item_path)
            worker_files = get_file_list(item_path, ssh_cmd)

            # Compare
            master_only = []
            worker_only = []
            different = []

            all_files = set(master_files.keys()) | set(worker_files.keys())

            for f in sorted(all_files):
                m_checksum = master_files.get(f)
                w_checksum = worker_files.get(f)

                if m_checksum and not w_checksum:
                    master_only.append(f)
                elif w_checksum and not m_checksum:
                    worker_only.append(f)
                elif m_checksum != w_checksum:
                    different.append(f)

            if not master_only and not worker_only and not different:
                status = 'synced'
            else:
                status = 'not_synced'

            return jsonify({
                'status': status,
                'item': item_name,
                'path': item_path,
                'file_count': len(all_files),
                'master_only': master_only,
                'worker_only': worker_only,
                'different': different
            })
        except Exception as e:
            import traceback
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes/<name>/config', methods=['GET'])
    @login_required
    def get_node_config(name):
        """Get ossec.conf for a node."""
        # Validate node name
        if not validate_node_name(name):
            return jsonify({'error': 'Invalid node name'}), 400
        try:
            import subprocess
            import socket

            # Default config path
            config_path = '/var/ossec/etc/ossec.conf'

            api = get_api_session()
            nodes = api.get_nodes()

            # Find the requested node
            target_node = None
            for n in nodes:
                if n.get('name') == name:
                    target_node = n
                    break

            if not target_node:
                return jsonify({'error': f'Node "{name}" not found'}), 404

            # Check if this is the local node by comparing hostname
            local_hostname = socket.gethostname()
            is_local = (target_node.get('type') == 'master' or
                       name == local_hostname or
                       name.replace('-server', '') == local_hostname or
                       local_hostname.replace('-server', '') == name.replace('-server', ''))

            if is_local:
                # Read local config file
                if not os.path.exists(config_path):
                    return jsonify({'error': f'Config file not found: {config_path}'}), 404

                with open(config_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                logger.info(f"Config read: {config_path} by user '{session.get('api_session', {}).get('username', 'unknown')}'")

                return jsonify({
                    'content': content,
                    'path': config_path,
                    'node': name,
                    'is_local': True
                })
            else:
                # Remote worker node - try SSH if configured
                config = get_config()
                ssh_cfg = config.get_ssh_config_for_node(name)

                if ssh_cfg:
                    # Try to read config via SSH
                    try:
                        ssh_cmd = [
                            'ssh',
                            '-i', ssh_cfg['key_file'],
                            '-o', 'StrictHostKeyChecking=no',
                            '-o', 'ConnectTimeout=10',
                            '-p', str(ssh_cfg['port']),
                            f"{ssh_cfg['user']}@{ssh_cfg['host']}",
                            f"cat {config_path}"
                        ]
                        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)

                        if result.returncode == 0:
                            logger.info(f"Config read via SSH: {name}:{config_path} by user '{session.get('api_session', {}).get('username', 'unknown')}'")
                            return jsonify({
                                'content': result.stdout,
                                'path': config_path,
                                'node': name,
                                'is_local': False,
                                'via_ssh': True
                            })
                        else:
                            error_msg = result.stderr.strip() or 'SSH command failed'
                            logger.warning(f"SSH read failed for {name}: {error_msg}")
                            return jsonify({
                                'error': f'SSH read failed: {error_msg}',
                                'is_remote': True,
                                'node_ip': target_node.get('ip', '')
                            }), 400
                    except subprocess.TimeoutExpired:
                        return jsonify({
                            'error': 'SSH connection timed out',
                            'is_remote': True,
                            'node_ip': target_node.get('ip', '')
                        }), 400
                    except Exception as e:
                        logger.error(f"SSH error for {name}: {str(e)}")
                        return jsonify({
                            'error': f'SSH error: {str(e)}',
                            'is_remote': True,
                            'node_ip': target_node.get('ip', '')
                        }), 400
                else:
                    # SSH not configured for this node
                    return jsonify({
                        'error': f'Worker node "{name}" requires SSH configuration. SSH is {"enabled" if config.ssh_enabled else "disabled"} but node "{name}" is not in the configured nodes list.',
                        'is_remote': True,
                        'node_ip': target_node.get('ip', '')
                    }), 400
        except PermissionError:
            return jsonify({'error': 'Permission denied. Run with sudo or as root.'}), 403
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes/<name>/config', methods=['PUT'])
    @login_required
    def save_node_config(name):
        """Save ossec.conf for a node with auto-backup."""
        # Validate node name
        if not validate_node_name(name):
            return jsonify({'error': 'Invalid node name'}), 400
        try:
            import subprocess
            import shutil
            import socket

            data = request.get_json() or {}
            content = data.get('content', '')

            if not content or not content.strip():
                return jsonify({'error': 'Config content cannot be empty'}), 400

            # Check if this is a local or remote node
            api = get_api_session()
            nodes = api.get_nodes()

            target_node = None
            for n in nodes:
                if n.get('name') == name:
                    target_node = n
                    break

            if not target_node:
                return jsonify({'error': f'Node "{name}" not found'}), 404

            # Check if this is the local node
            local_hostname = socket.gethostname()
            is_local = (target_node.get('type') == 'master' or
                       name == local_hostname or
                       name.replace('-server', '') == local_hostname or
                       local_hostname.replace('-server', '') == name.replace('-server', ''))

            config_path = '/var/ossec/etc/ossec.conf'
            backup_dir = '/var/ossec/etc/backup'

            if is_local:
                # Ensure backup directory exists
                if not os.path.exists(backup_dir):
                    os.makedirs(backup_dir, mode=0o750)

                # Create backup with timestamp
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                backup_filename = f'ossec.conf.{timestamp}.bak'
                backup_path = os.path.join(backup_dir, backup_filename)

                # Backup current config
                if os.path.exists(config_path):
                    shutil.copy2(config_path, backup_path)
                    logger.info(f"Config backup created: {backup_path}")

                # Write new config
                with open(config_path, 'w', encoding='utf-8') as f:
                    f.write(content)

                logger.info(f"Config saved: {config_path} by user '{session.get('api_session', {}).get('username', 'unknown')}'")

                return jsonify({
                    'success': True,
                    'message': 'Config saved successfully',
                    'backup_path': backup_path
                })
            else:
                # Remote node - try SSH if configured
                config = get_config()
                ssh_cfg = config.get_ssh_config_for_node(name)

                if ssh_cfg:
                    try:
                        # Create backup command and save command
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        backup_path = f'{backup_dir}/ossec.conf.{timestamp}.bak'
                        remote_cmd = f"mkdir -p {backup_dir} && cp {config_path} {backup_path} 2>/dev/null; cat > {config_path}"

                        ssh_cmd = [
                            'ssh',
                            '-i', ssh_cfg['key_file'],
                            '-o', 'StrictHostKeyChecking=no',
                            '-o', 'ConnectTimeout=10',
                            '-p', str(ssh_cfg['port']),
                            f"{ssh_cfg['user']}@{ssh_cfg['host']}",
                            remote_cmd
                        ]

                        result = subprocess.run(ssh_cmd, input=content, capture_output=True, text=True, timeout=30)

                        if result.returncode == 0:
                            logger.info(f"Config saved via SSH: {name}:{config_path} by user '{session.get('api_session', {}).get('username', 'unknown')}'")
                            return jsonify({
                                'success': True,
                                'message': f'Config saved to {name} via SSH',
                                'backup_path': backup_path,
                                'via_ssh': True
                            })
                        else:
                            error_msg = result.stderr.strip() or 'SSH command failed'
                            logger.warning(f"SSH save failed for {name}: {error_msg}")
                            return jsonify({'error': f'SSH save failed: {error_msg}'}), 400

                    except subprocess.TimeoutExpired:
                        return jsonify({'error': 'SSH connection timed out'}), 400
                    except Exception as e:
                        logger.error(f"SSH save error for {name}: {str(e)}")
                        return jsonify({'error': f'SSH error: {str(e)}'}), 400
                else:
                    return jsonify({
                        'error': f'Cannot save config to remote node "{name}". SSH is not configured for this node.'
                    }), 400
        except PermissionError:
            return jsonify({'error': 'Permission denied. Run with sudo or as root.'}), 403
        except Exception as e:
            logger.error(f"Config save failed: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes/<name>/logs-info', methods=['GET'])
    @login_required
    def get_node_logs_info(name):
        """Get info about log files (archives and alerts) for a node."""
        # Validate node name
        if not validate_node_name(name):
            return jsonify({'error': 'Invalid node name'}), 400
        try:
            import subprocess
            import socket

            # Define all log files to check
            log_files = {
                'archives_log': '/var/ossec/logs/archives/archives.log',
                'archives_json': '/var/ossec/logs/archives/archives.json',
                'alerts_log': '/var/ossec/logs/alerts/alerts.log',
                'alerts_json': '/var/ossec/logs/alerts/alerts.json'
            }

            api = get_api_session()
            nodes = api.get_nodes()

            # Find the requested node
            target_node = None
            for n in nodes:
                if n.get('name') == name:
                    target_node = n
                    break

            if not target_node:
                return jsonify({'error': f'Node "{name}" not found'}), 404

            # Check if this is the local node
            local_hostname = socket.gethostname()
            is_local = (target_node.get('type') == 'master' or
                       name == local_hostname or
                       name.replace('-server', '') == local_hostname or
                       local_hostname.replace('-server', '') == name.replace('-server', ''))

            result = {'node': name, 'files': {}}

            if is_local:
                # Check local files
                for file_type, file_path in log_files.items():
                    if os.path.exists(file_path):
                        try:
                            stat = os.stat(file_path)
                            result['files'][file_type] = {
                                'exists': True,
                                'path': file_path,
                                'size': stat.st_size
                            }
                        except Exception:
                            result['files'][file_type] = {'exists': False}
                    else:
                        result['files'][file_type] = {'exists': False}

                return jsonify(result)
            else:
                # Remote worker node - try SSH if configured
                config = get_config()
                ssh_cfg = config.get_ssh_config_for_node(name)

                if ssh_cfg:
                    try:
                        # Use stat command to get file info for all log files
                        file_paths = ' '.join(log_files.values())
                        check_cmd = f"for f in {file_paths}; do if [ -f \"$f\" ]; then stat -c '%s' \"$f\" 2>/dev/null || stat -f '%z' \"$f\" 2>/dev/null; else echo 'NOT_FOUND'; fi; done"
                        ssh_cmd = [
                            'ssh',
                            '-i', ssh_cfg['key_file'],
                            '-o', 'StrictHostKeyChecking=no',
                            '-o', 'ConnectTimeout=10',
                            '-p', str(ssh_cfg['port']),
                            f"{ssh_cfg['user']}@{ssh_cfg['host']}",
                            check_cmd
                        ]
                        proc_result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)

                        if proc_result.returncode == 0:
                            lines = proc_result.stdout.strip().split('\n')
                            for i, (file_type, file_path) in enumerate(log_files.items()):
                                if i < len(lines):
                                    if lines[i] == 'NOT_FOUND':
                                        result['files'][file_type] = {'exists': False}
                                    else:
                                        try:
                                            size = int(lines[i])
                                            result['files'][file_type] = {
                                                'exists': True,
                                                'path': file_path,
                                                'size': size
                                            }
                                        except ValueError:
                                            result['files'][file_type] = {'exists': False}
                                else:
                                    result['files'][file_type] = {'exists': False}
                            return jsonify(result)
                        else:
                            return jsonify({'error': f'SSH command failed: {proc_result.stderr}'}), 400
                    except subprocess.TimeoutExpired:
                        return jsonify({'error': 'SSH connection timed out'}), 400
                    except Exception as e:
                        return jsonify({'error': f'SSH error: {str(e)}'}), 400
                else:
                    return jsonify({
                        'error': f'Worker node "{name}" requires SSH configuration.',
                        'is_remote': True
                    }), 400
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes/<name>/logs/<category>/<log_type>', methods=['GET'])
    @login_required
    def get_node_log_content(name, category, log_type):
        """Get log file content (archives or alerts) for a node."""
        # Validate node name, category, and log type
        if not validate_node_name(name):
            return jsonify({'error': 'Invalid node name'}), 400
        if category not in ['archives', 'alerts']:
            return jsonify({'error': 'Invalid category. Must be "archives" or "alerts".'}), 400
        if log_type not in ['log', 'json']:
            return jsonify({'error': 'Invalid log type. Must be "log" or "json".'}), 400

        try:
            import subprocess
            import socket

            # Get line limit from query params (default 100)
            lines_limit = request.args.get('lines', 100, type=int)
            if lines_limit < 1:
                lines_limit = 100
            if lines_limit > 10000:
                lines_limit = 10000

            log_dir = f'/var/ossec/logs/{category}'
            file_name = f'{category}.{log_type}'
            file_path = os.path.join(log_dir, file_name)

            api = get_api_session()
            nodes = api.get_nodes()

            # Find the requested node
            target_node = None
            for n in nodes:
                if n.get('name') == name:
                    target_node = n
                    break

            if not target_node:
                return jsonify({'error': f'Node "{name}" not found'}), 404

            # Check if this is the local node
            local_hostname = socket.gethostname()
            is_local = (target_node.get('type') == 'master' or
                       name == local_hostname or
                       name.replace('-server', '') == local_hostname or
                       local_hostname.replace('-server', '') == name.replace('-server', ''))

            if is_local:
                # Read local file
                if not os.path.exists(file_path):
                    return jsonify({'error': f'Archive file not found: {file_path}'}), 404

                # Get file size
                stat = os.stat(file_path)
                file_size = stat.st_size

                # Read last N lines using tail
                try:
                    proc = subprocess.run(
                        ['tail', '-n', str(lines_limit), file_path],
                        capture_output=True,
                        text=True,
                        timeout=60
                    )
                    content = proc.stdout.rstrip('\n')
                except Exception as e:
                    # Fallback: read entire file and get last N lines
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        all_lines = f.readlines()
                        content = ''.join(all_lines[-lines_limit:]).rstrip('\n')

                logger.info(f"Log read: {file_path} (last {lines_limit} lines) by user '{session.get('api_session', {}).get('username', 'unknown')}'")

                return jsonify({
                    'content': content,
                    'path': file_path,
                    'node': name,
                    'category': category,
                    'type': log_type,
                    'lines': lines_limit,
                    'size': file_size,
                    'is_local': True
                })
            else:
                # Remote worker node - try SSH if configured
                config = get_config()
                ssh_cfg = config.get_ssh_config_for_node(name)

                if ssh_cfg:
                    try:
                        # Get file size and content
                        remote_cmd = f"stat -c '%s' {file_path} 2>/dev/null || stat -f '%z' {file_path} 2>/dev/null; echo '---SEPARATOR---'; tail -n {lines_limit} {file_path}"
                        ssh_cmd = [
                            'ssh',
                            '-i', ssh_cfg['key_file'],
                            '-o', 'StrictHostKeyChecking=no',
                            '-o', 'ConnectTimeout=10',
                            '-p', str(ssh_cfg['port']),
                            f"{ssh_cfg['user']}@{ssh_cfg['host']}",
                            remote_cmd
                        ]
                        proc_result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=60)

                        if proc_result.returncode == 0:
                            output = proc_result.stdout
                            parts = output.split('---SEPARATOR---\n', 1)
                            file_size = 0
                            content = ''
                            if len(parts) == 2:
                                try:
                                    file_size = int(parts[0].strip())
                                except ValueError:
                                    pass
                                content = parts[1].rstrip('\n')
                            else:
                                content = output.rstrip('\n')

                            logger.info(f"Log read via SSH: {name}:{file_path} (last {lines_limit} lines) by user '{session.get('api_session', {}).get('username', 'unknown')}'")

                            return jsonify({
                                'content': content,
                                'path': file_path,
                                'node': name,
                                'category': category,
                                'type': log_type,
                                'lines': lines_limit,
                                'size': file_size,
                                'is_local': False,
                                'via_ssh': True
                            })
                        else:
                            error_msg = proc_result.stderr.strip() or 'SSH command failed'
                            if 'No such file' in error_msg or 'cannot open' in error_msg.lower():
                                return jsonify({'error': f'Log file not found on {name}'}), 404
                            return jsonify({'error': f'SSH read failed: {error_msg}'}), 400
                    except subprocess.TimeoutExpired:
                        return jsonify({'error': 'SSH connection timed out'}), 400
                    except Exception as e:
                        return jsonify({'error': f'SSH error: {str(e)}'}), 400
                else:
                    return jsonify({
                        'error': f'Worker node "{name}" requires SSH configuration.',
                        'is_remote': True
                    }), 400
        except PermissionError:
            return jsonify({'error': 'Permission denied. Run with sudo or as root.'}), 403
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes/<name>/restart', methods=['POST'])
    @login_required
    def restart_node_services(name):
        """Restart all Wazuh services on a node."""
        # Validate node name
        if not validate_node_name(name):
            return jsonify({'error': 'Invalid node name'}), 400
        try:
            import subprocess
            import socket

            logger.info(f"Services restart requested for node '{sanitize_for_log(name)}' by user '{session.get('api_session', {}).get('username', 'unknown')}'")

            # Check if this is a local or remote node
            api = get_api_session()
            nodes = api.get_nodes()

            target_node = None
            for n in nodes:
                if n.get('name') == name:
                    target_node = n
                    break

            if not target_node:
                return jsonify({'error': f'Node "{name}" not found'}), 404

            # Check if this is the local node
            local_hostname = socket.gethostname()
            is_local = (target_node.get('type') == 'master' or
                       name == local_hostname or
                       name.replace('-server', '') == local_hostname or
                       local_hostname.replace('-server', '') == name.replace('-server', ''))

            if is_local:
                # Local node - restart directly
                result = None
                error_msg = None

                # Try systemctl first (modern systems)
                try:
                    result = subprocess.run(
                        ['systemctl', 'restart', 'wazuh-manager'],
                        capture_output=True,
                        text=True,
                        timeout=120
                    )
                    if result.returncode == 0:
                        logger.info(f"Services restarted successfully on node '{name}' via systemctl")
                        return jsonify({
                            'success': True,
                            'message': f'Wazuh services restarted on {name}'
                        })
                    else:
                        error_msg = result.stderr or 'Unknown error'
                except FileNotFoundError:
                    pass  # systemctl not available
                except subprocess.TimeoutExpired:
                    error_msg = 'Restart command timed out'

                # Fallback to wazuh-control
                wazuh_control = '/var/ossec/bin/wazuh-control'
                if os.path.exists(wazuh_control):
                    try:
                        result = subprocess.run(
                            [wazuh_control, 'restart'],
                            capture_output=True,
                            text=True,
                            timeout=120
                        )
                        if result.returncode == 0:
                            logger.info(f"Services restarted successfully on node '{name}' via wazuh-control")
                            return jsonify({
                                'success': True,
                                'message': f'Wazuh services restarted on {name}'
                            })
                        else:
                            error_msg = result.stderr or result.stdout or 'Unknown error'
                    except subprocess.TimeoutExpired:
                        error_msg = 'Restart command timed out'

                if error_msg:
                    logger.error(f"Services restart failed on node '{name}': {error_msg}")
                    return jsonify({'error': error_msg}), 500

                return jsonify({'error': 'No restart method available'}), 500
            else:
                # Remote node - try SSH if configured
                config = get_config()
                ssh_cfg = config.get_ssh_config_for_node(name)

                if ssh_cfg:
                    try:
                        # Try systemctl first via SSH
                        ssh_cmd = [
                            'ssh',
                            '-i', ssh_cfg['key_file'],
                            '-o', 'StrictHostKeyChecking=no',
                            '-o', 'ConnectTimeout=10',
                            '-p', str(ssh_cfg['port']),
                            f"{ssh_cfg['user']}@{ssh_cfg['host']}",
                            'systemctl restart wazuh-manager || /var/ossec/bin/wazuh-control restart'
                        ]
                        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=120)

                        if result.returncode == 0:
                            logger.info(f"Services restarted successfully on remote node '{name}' via SSH")
                            return jsonify({
                                'success': True,
                                'message': f'Wazuh services restarted on {name} (via SSH)'
                            })
                        else:
                            error_msg = result.stderr.strip() or result.stdout.strip() or 'SSH command failed'
                            logger.error(f"Remote restart failed for {name}: {error_msg}")
                            return jsonify({'error': f'Restart failed: {error_msg}'}), 500
                    except subprocess.TimeoutExpired:
                        return jsonify({'error': 'SSH restart command timed out (120s)'}), 500
                    except Exception as e:
                        logger.error(f"SSH restart error for {name}: {str(e)}")
                        return jsonify({'error': f'SSH error: {str(e)}'}), 500
                else:
                    # SSH not configured for this node
                    return jsonify({
                        'error': f'Worker node "{name}" requires SSH configuration.',
                        'is_remote': True,
                        'node_ip': target_node.get('ip', '')
                    }), 400

        except PermissionError:
            return jsonify({'error': 'Permission denied. Run with sudo or as root.'}), 403
        except Exception as e:
            logger.error(f"Services restart failed: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes/<name>/download/<file_type>', methods=['GET'])
    @login_required
    def download_node_file(name, file_type):
        """Download ossec.conf or cluster.key for a node."""
        # Validate node name and file_type
        if not validate_node_name(name):
            return jsonify({'error': 'Invalid node name'}), 400
        # file_type is validated below against whitelist

        from flask import send_file, Response
        import io
        import socket

        try:
            # Check if this is a local or remote node
            api = get_api_session()
            nodes = api.get_nodes()

            target_node = None
            for n in nodes:
                if n.get('name') == name:
                    target_node = n
                    break

            if not target_node:
                return jsonify({'error': f'Node "{name}" not found'}), 404

            # Check if this is the local node
            local_hostname = socket.gethostname()
            is_local = (target_node.get('type') == 'master' or
                       name == local_hostname or
                       name.replace('-server', '') == local_hostname or
                       local_hostname.replace('-server', '') == name.replace('-server', ''))

            # Define file paths
            file_paths = {
                'config': '/var/ossec/etc/ossec.conf',
                'cluster-key': '/var/ossec/etc/cluster.key'
            }

            if file_type not in file_paths:
                return jsonify({'error': 'Invalid file type'}), 400

            file_path = file_paths[file_type]

            # Generate download filename with node name
            if file_type == 'config':
                download_name = f'{name}_ossec.conf'
            else:
                download_name = f'{name}_cluster.key'

            if is_local:
                # Local node - read file directly
                if not os.path.exists(file_path):
                    if file_type == 'cluster-key':
                        return jsonify({'error': 'cluster.key not found. This file only exists in cluster mode setups.'}), 404
                    return jsonify({'error': f'File not found: {file_path}'}), 404

                # Read file content - try text first, then binary
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    mimetype = 'text/plain'
                except UnicodeDecodeError:
                    with open(file_path, 'rb') as f:
                        content = f.read()
                    mimetype = 'application/octet-stream'

                logger.info(f"File downloaded: {file_path} as {download_name} by user '{session.get('api_session', {}).get('username', 'unknown')}'")
            else:
                # Remote node - try SSH if configured
                import subprocess
                config = get_config()
                ssh_cfg = config.get_ssh_config_for_node(name)

                if ssh_cfg:
                    try:
                        ssh_cmd = [
                            'ssh',
                            '-i', ssh_cfg['key_file'],
                            '-o', 'StrictHostKeyChecking=no',
                            '-o', 'ConnectTimeout=10',
                            '-p', str(ssh_cfg['port']),
                            f"{ssh_cfg['user']}@{ssh_cfg['host']}",
                            f"cat {file_path}"
                        ]
                        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)

                        if result.returncode == 0:
                            content = result.stdout
                            mimetype = 'text/plain'
                            logger.info(f"File downloaded via SSH: {name}:{file_path} as {download_name} by user '{session.get('api_session', {}).get('username', 'unknown')}'")
                        else:
                            error_msg = result.stderr.strip() or 'SSH command failed'
                            if 'No such file' in error_msg:
                                if file_type == 'cluster-key':
                                    return jsonify({'error': 'cluster.key not found on remote node. This file only exists in cluster mode setups.'}), 404
                                return jsonify({'error': f'File not found on remote node: {file_path}'}), 404
                            return jsonify({
                                'error': f'SSH read failed: {error_msg}',
                                'is_remote': True,
                                'node_ip': target_node.get('ip', '')
                            }), 400
                    except subprocess.TimeoutExpired:
                        return jsonify({
                            'error': 'SSH connection timed out',
                            'is_remote': True,
                            'node_ip': target_node.get('ip', '')
                        }), 400
                    except Exception as e:
                        logger.error(f"SSH download error for {name}: {str(e)}")
                        return jsonify({
                            'error': f'SSH error: {str(e)}',
                            'is_remote': True,
                            'node_ip': target_node.get('ip', '')
                        }), 400
                else:
                    # SSH not configured for this node
                    return jsonify({
                        'error': f'Worker node "{name}" requires SSH configuration.',
                        'is_remote': True,
                        'node_ip': target_node.get('ip', '')
                    }), 400

            # Return as downloadable file
            return Response(
                content,
                mimetype=mimetype,
                headers={
                    'Content-Disposition': f'attachment; filename={download_name}'
                }
            )

        except PermissionError:
            return jsonify({'error': 'Permission denied. Run with sudo or as root.'}), 403
        except Exception as e:
            logger.error(f"File download failed: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes/<name>/upgrade-files', methods=['GET'])
    @login_required
    def get_node_upgrade_files(name):
        """Get list of agent upgrade files (WPK packages) on a node."""
        # Validate node name
        if not validate_node_name(name):
            return jsonify({'error': 'Invalid node name'}), 400

        import subprocess
        import socket
        import re

        try:
            # Check if this is a local or remote node
            api = get_api_session()
            nodes = api.get_nodes()

            target_node = None
            for n in nodes:
                if n.get('name') == name:
                    target_node = n
                    break

            if not target_node:
                return jsonify({'error': f'Node "{name}" not found'}), 404

            # Check if this is the local node
            local_hostname = socket.gethostname()
            is_local = (target_node.get('type') == 'master' or
                       name == local_hostname or
                       name.replace('-server', '') == local_hostname or
                       local_hostname.replace('-server', '') == name.replace('-server', ''))

            upgrade_path = '/var/ossec/var/upgrade'
            files = []

            if is_local:
                # Local node - read directory directly
                if os.path.isdir(upgrade_path):
                    for filename in os.listdir(upgrade_path):
                        filepath = os.path.join(upgrade_path, filename)
                        if os.path.isfile(filepath) and filename.endswith('.wpk'):
                            stat = os.stat(filepath)
                            files.append({
                                'name': filename,
                                'size': stat.st_size,
                                'mtime': stat.st_mtime
                            })
            else:
                # Remote node - try SSH if configured
                config = get_config()
                ssh_cfg = config.get_ssh_config_for_node(name)

                if ssh_cfg:
                    try:
                        # Use ls -la to get file details
                        ssh_cmd = [
                            'ssh',
                            '-i', ssh_cfg['key_file'],
                            '-o', 'StrictHostKeyChecking=no',
                            '-o', 'ConnectTimeout=10',
                            '-p', str(ssh_cfg['port']),
                            f"{ssh_cfg['user']}@{ssh_cfg['host']}",
                            f"ls -la {upgrade_path}/*.wpk 2>/dev/null || echo ''"
                        ]
                        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)

                        if result.returncode == 0 and result.stdout.strip():
                            for line in result.stdout.strip().split('\n'):
                                if '.wpk' in line:
                                    # Parse ls -la output: -rw-r--r-- 1 root root 12345678 Jan  1 12:00 filename.wpk
                                    parts = line.split()
                                    if len(parts) >= 9:
                                        filename = parts[-1].split('/')[-1]
                                        try:
                                            size = int(parts[4])
                                        except:
                                            size = 0
                                        files.append({
                                            'name': filename,
                                            'size': size,
                                            'mtime': 0  # Skip mtime parsing for simplicity
                                        })
                    except subprocess.TimeoutExpired:
                        return jsonify({
                            'error': 'SSH connection timed out',
                            'is_remote': True,
                            'node_ip': target_node.get('ip', '')
                        }), 400
                    except Exception as e:
                        logger.error(f"SSH upgrade files error for {name}: {str(e)}")
                        return jsonify({
                            'error': f'SSH error: {str(e)}',
                            'is_remote': True,
                            'node_ip': target_node.get('ip', '')
                        }), 400
                else:
                    # SSH not configured for this node
                    return jsonify({
                        'error': f'Worker node "{name}" requires SSH configuration.',
                        'is_remote': True,
                        'node_ip': target_node.get('ip', '')
                    }), 400

            # Sort by filename
            files.sort(key=lambda x: x['name'])

            # Get manager version
            manager_version = target_node.get('version', '')

            return jsonify({
                'node': name,
                'path': upgrade_path,
                'files': files,
                'manager_version': manager_version
            })

        except Exception as e:
            logger.error(f"Get upgrade files failed: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes/<name>/upgrade-files', methods=['POST'])
    @login_required
    def upload_node_upgrade_file(name):
        """Upload a WPK file to a node's upgrade directory."""
        # Validate node name
        if not validate_node_name(name):
            return jsonify({'error': 'Invalid node name'}), 400

        import subprocess
        import socket
        import tempfile
        from werkzeug.utils import secure_filename

        try:
            # Check if file was uploaded
            if 'file' not in request.files:
                return jsonify({'error': 'No file provided'}), 400

            file = request.files['file']
            if file.filename == '':
                return jsonify({'error': 'No file selected'}), 400

            # Sanitize filename
            safe_filename = secure_filename(file.filename)
            if not safe_filename:
                return jsonify({'error': 'Invalid filename'}), 400

            # Validate file extension
            if not safe_filename.endswith('.wpk'):
                return jsonify({'error': 'Only .wpk files are allowed'}), 400

            # Check if this is a local or remote node
            api = get_api_session()
            nodes = api.get_nodes()

            target_node = None
            for n in nodes:
                if n.get('name') == name:
                    target_node = n
                    break

            if not target_node:
                return jsonify({'error': f'Node "{name}" not found'}), 404

            # Check if this is the local node
            local_hostname = socket.gethostname()
            is_local = (target_node.get('type') == 'master' or
                       name == local_hostname or
                       name.replace('-server', '') == local_hostname or
                       local_hostname.replace('-server', '') == name.replace('-server', ''))

            upgrade_path = '/var/ossec/var/upgrade'
            dest_path = os.path.join(upgrade_path, safe_filename)

            if is_local:
                # Local node - save file directly
                # Ensure directory exists
                if not os.path.isdir(upgrade_path):
                    os.makedirs(upgrade_path, mode=0o755, exist_ok=True)

                # Save file
                file.save(dest_path)

                # Set proper permissions: root:root 660 (same as Wazuh's own downloads)
                os.chmod(dest_path, 0o660)
                try:
                    import pwd
                    import grp
                    uid = pwd.getpwnam('root').pw_uid
                    gid = grp.getgrnam('root').gr_gid
                    os.chown(dest_path, uid, gid)
                except Exception as e:
                    logger.warning(f"Could not set ownership: {e}")

                logger.info(f"WPK uploaded: {dest_path} by user '{session.get('api_session', {}).get('username', 'unknown')}'")

                return jsonify({
                    'success': True,
                    'message': f'File "{safe_filename}" uploaded successfully',
                    'path': dest_path
                })

            else:
                # Remote node - use SCP via SSH
                config = get_config()
                ssh_cfg = config.get_ssh_config_for_node(name)

                if ssh_cfg:
                    try:
                        # Save to temp file first
                        with tempfile.NamedTemporaryFile(delete=False, suffix='.wpk') as tmp:
                            file.save(tmp.name)
                            tmp_path = tmp.name

                        try:
                            # SCP file to remote node
                            scp_cmd = [
                                'scp',
                                '-i', ssh_cfg['key_file'],
                                '-o', 'StrictHostKeyChecking=no',
                                '-o', 'ConnectTimeout=10',
                                '-P', str(ssh_cfg['port']),
                                tmp_path,
                                f"{ssh_cfg['user']}@{ssh_cfg['host']}:{dest_path}"
                            ]
                            result = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=120)

                            if result.returncode != 0:
                                return jsonify({
                                    'error': f'SCP failed: {result.stderr.strip()}',
                                    'is_remote': True,
                                    'node_ip': target_node.get('ip', '')
                                }), 400

                            # Set permissions via SSH: root:root 660 (same as Wazuh's own downloads)
                            ssh_cmd = [
                                'ssh',
                                '-i', ssh_cfg['key_file'],
                                '-o', 'StrictHostKeyChecking=no',
                                '-o', 'ConnectTimeout=10',
                                '-p', str(ssh_cfg['port']),
                                f"{ssh_cfg['user']}@{ssh_cfg['host']}",
                                f"chmod 660 {dest_path} && chown root:root {dest_path}"
                            ]
                            subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)

                            logger.info(f"WPK uploaded via SSH: {name}:{dest_path} by user '{session.get('api_session', {}).get('username', 'unknown')}'")

                            return jsonify({
                                'success': True,
                                'message': f'File "{safe_filename}" uploaded to {name} successfully',
                                'path': dest_path
                            })

                        finally:
                            # Clean up temp file
                            os.unlink(tmp_path)

                    except subprocess.TimeoutExpired:
                        return jsonify({
                            'error': 'SSH/SCP connection timed out',
                            'is_remote': True,
                            'node_ip': target_node.get('ip', '')
                        }), 400
                    except Exception as e:
                        logger.error(f"SSH upload error for {name}: {str(e)}")
                        return jsonify({
                            'error': f'SSH error: {str(e)}',
                            'is_remote': True,
                            'node_ip': target_node.get('ip', '')
                        }), 400
                else:
                    return jsonify({
                        'error': f'Worker node "{name}" requires SSH configuration.',
                        'is_remote': True,
                        'node_ip': target_node.get('ip', '')
                    }), 400

        except Exception as e:
            logger.error(f"Upload WPK failed: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes/<name>/upgrade-files/<filename>', methods=['DELETE'])
    @login_required
    def delete_node_upgrade_file(name, filename):
        """Delete a WPK file from a node's upgrade directory."""
        # Validate node name
        if not validate_node_name(name):
            return jsonify({'error': 'Invalid node name'}), 400

        import subprocess
        import socket
        from werkzeug.utils import secure_filename

        try:
            # Sanitize and validate filename
            safe_filename = secure_filename(filename)
            if not safe_filename or not safe_filename.endswith('.wpk'):
                return jsonify({'error': 'Invalid file type'}), 400

            # Additional path traversal protection
            if '/' in filename or '\\' in filename or '..' in filename:
                return jsonify({'error': 'Invalid filename'}), 400

            # Check if this is a local or remote node
            api = get_api_session()
            nodes = api.get_nodes()

            target_node = None
            for n in nodes:
                if n.get('name') == name:
                    target_node = n
                    break

            if not target_node:
                return jsonify({'error': f'Node "{name}" not found'}), 404

            # Check if this is the local node
            local_hostname = socket.gethostname()
            is_local = (target_node.get('type') == 'master' or
                       name == local_hostname or
                       name.replace('-server', '') == local_hostname or
                       local_hostname.replace('-server', '') == name.replace('-server', ''))

            upgrade_path = '/var/ossec/var/upgrade'
            file_path = os.path.join(upgrade_path, safe_filename)

            if is_local:
                # Local node - delete file directly
                if not os.path.exists(file_path):
                    return jsonify({'error': f'File not found: {safe_filename}'}), 404

                os.remove(file_path)
                logger.info(f"WPK deleted: {file_path} by user '{session.get('api_session', {}).get('username', 'unknown')}'")

                return jsonify({
                    'success': True,
                    'message': f'File "{safe_filename}" deleted successfully'
                })

            else:
                # Remote node - use SSH
                config = get_config()
                ssh_cfg = config.get_ssh_config_for_node(name)

                if ssh_cfg:
                    try:
                        # Use safe_shell_arg for the file path in the remote command
                        ssh_cmd = [
                            'ssh',
                            '-i', ssh_cfg['key_file'],
                            '-o', 'StrictHostKeyChecking=no',
                            '-o', 'ConnectTimeout=10',
                            '-p', str(ssh_cfg['port']),
                            f"{ssh_cfg['user']}@{ssh_cfg['host']}",
                            f"rm -f {safe_shell_arg(file_path)}"
                        ]
                        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)

                        if result.returncode != 0:
                            return jsonify({
                                'error': f'SSH delete failed: {result.stderr.strip()}',
                                'is_remote': True,
                                'node_ip': target_node.get('ip', '')
                            }), 400

                        logger.info(f"WPK deleted via SSH: {name}:{file_path} by user '{session.get('api_session', {}).get('username', 'unknown')}'")

                        return jsonify({
                            'success': True,
                            'message': f'File "{safe_filename}" deleted from {name} successfully'
                        })

                    except subprocess.TimeoutExpired:
                        return jsonify({
                            'error': 'SSH connection timed out',
                            'is_remote': True,
                            'node_ip': target_node.get('ip', '')
                        }), 400
                    except Exception as e:
                        logger.error(f"SSH delete error for {name}: {str(e)}")
                        return jsonify({
                            'error': f'SSH error: {str(e)}',
                            'is_remote': True,
                            'node_ip': target_node.get('ip', '')
                        }), 400
                else:
                    return jsonify({
                        'error': f'Worker node "{name}" requires SSH configuration.',
                        'is_remote': True,
                        'node_ip': target_node.get('ip', '')
                    }), 400

        except Exception as e:
            logger.error(f"Delete WPK failed: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/settings', methods=['GET'])
    @login_required
    def get_settings():
        """Get current settings for display in Settings modal."""
        try:
            config = get_config()
            return jsonify({
                'config_file_path': config.config_file_path,
                'api_verify_ssl': config.api_verify_ssl,
                'ssh_enabled': config.ssh_enabled,
                'ssh_key_file': config.ssh_key_file if config.ssh_enabled else None,
                'ssh_nodes': config.ssh_nodes if config.ssh_enabled else {}
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/stats/summary', methods=['GET'])
    @login_required
    def get_stats_summary():
        try:
            api = get_api_session()
            summary = api.get_stats_summary()
            return jsonify({'summary': summary})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/stats/report', methods=['GET'])
    @login_required
    def get_stats_report():
        try:
            api = get_api_session()
            agents = api.get_agents()

            # Calculate stats
            from collections import defaultdict

            # Pre-initialize all possible agent statuses (including 0 counts)
            ALL_STATUSES = ['active', 'disconnected', 'pending', 'never_connected']
            status_counts = defaultdict(int, {s: 0 for s in ALL_STATUSES})
            group_counts = defaultdict(int)
            os_counts = defaultdict(int)
            network_counts = defaultdict(int)
            version_counts = defaultdict(int)

            for agent in agents:
                status_counts[agent.get('status', 'Unknown')] += 1
                # Split comma-separated groups and count each separately
                group_str = agent.get('group') or ''
                if group_str:
                    for g in group_str.split(','):
                        group_counts[g.strip()] += 1
                else:
                    group_counts['(no group)'] += 1
                os_name = agent.get('os') or 'Unknown'
                os_counts[os_name] += 1
                # Count agent versions
                version = agent.get('version') or 'Unknown'
                version_counts[version] += 1
                # Calculate network segment (/24)
                ip = agent.get('ip') or ''
                if ip and ip != 'any':
                    parts = ip.split('.')
                    if len(parts) == 4:
                        network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                        network_counts[network] += 1
                    else:
                        network_counts['(invalid IP)'] += 1
                else:
                    network_counts['(no IP)'] += 1

            total = len(agents)

            by_status = [{'status': k, 'count': v, 'percentage': round(v/total*100, 1) if total else 0}
                        for k, v in sorted(status_counts.items(), key=lambda x: x[1], reverse=True)]
            by_group = [{'group': k, 'count': v, 'percentage': round(v/total*100, 1) if total else 0}
                       for k, v in sorted(group_counts.items(), key=lambda x: x[1], reverse=True)]
            by_os = [{'os': k, 'count': v, 'percentage': round(v/total*100, 1) if total else 0}
                    for k, v in sorted(os_counts.items(), key=lambda x: x[0].lower())]
            # Sort networks by IP address for better readability
            def sort_network(item):
                net = item[0]
                if net.startswith('('):
                    return (999, 999, 999, 0)  # Put special entries at end
                parts = net.replace('/24', '').split('.')
                return tuple(int(p) for p in parts)
            by_network = [{'network': k, 'count': v, 'percentage': round(v/total*100, 1) if total else 0}
                         for k, v in sorted(network_counts.items(), key=sort_network)]
            # Sort versions in descending order (newest first)
            def parse_version(ver):
                """Parse version string like 'v4.14.0' or 'Wazuh v4.14.0' into tuple."""
                import re
                match = re.search(r'(\d+)\.(\d+)\.(\d+)', ver)
                if match:
                    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
                return (0, 0, 0)

            by_version = [{'version': k, 'count': v, 'percentage': round(v/total*100, 1) if total else 0}
                         for k, v in sorted(version_counts.items(), key=lambda x: parse_version(x[0]), reverse=True)]

            return jsonify({
                'by_status': by_status,
                'by_group': by_group,
                'by_os': by_os,
                'by_network': by_network,
                'by_version': by_version
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    # User Management API endpoints
    @app.route('/api/users', methods=['GET'])
    @login_required
    def get_users():
        """Get all API users and available roles."""
        try:
            api = get_api_session()

            # Get users
            users = api.get_users()

            # Get roles - try API first, then CLI as fallback
            roles = api.get_roles()
            roles_source = 'api'

            if not roles:
                # Fallback to CLI
                try:
                    cli = WazuhCLI()
                    roles = cli.list_roles()
                    if roles:
                        roles_source = 'cli'
                except Exception as cli_err:
                    print(f"[WebUI] CLI roles fallback failed: {cli_err}")

            result = {
                'users': users,
                'roles': roles,
                'roles_source': roles_source
            }

            # Note if roles couldn't be fetched
            if not roles:
                result['roles_warning'] = 'Could not fetch roles via API or CLI. Check permissions.'

            return jsonify(result)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/users', methods=['POST'])
    @login_required
    def create_user():
        """Create a new API user via API."""
        try:
            data = request.get_json() or {}
            username = data.get('username')
            password = data.get('password')
            role_names = data.get('role_names', [])
            operator = get_current_user()

            if not username:
                return jsonify({'error': 'Username is required'}), 400
            if not password:
                return jsonify({'error': 'Password is required'}), 400

            api = get_api_session()

            # Create user via API
            result = api.create_user(username, password)

            if result.get('error'):
                logger.warning(f"USER CREATE FAILED: operator={operator} new_user={username} error={result['error']}")
                return jsonify({'error': result['error']}), 400

            # Assign roles if specified
            if role_names:
                # Get user_id of newly created user
                users = api.get_users()
                new_user = next((u for u in users if u['username'] == username), None)
                if new_user and new_user.get('user_id'):
                    user_id = new_user['user_id']
                    roles = api.get_roles()
                    role_map = {r['name']: r['id'] for r in roles}
                    for role_name in role_names:
                        role_id = role_map.get(role_name)
                        if role_id:
                            api.assign_user_role(user_id, role_id)

            logger.info(f"USER CREATE: operator={operator} new_user={username} roles={role_names}")
            return jsonify({'message': f"User '{username}' created successfully"})
        except Exception as e:
            logger.error(f"USER CREATE ERROR: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/users/<username>', methods=['DELETE'])
    @login_required
    def delete_user(username):
        """Delete an API user via API."""
        if not validate_username(username):
            return jsonify({'error': 'Invalid username'}), 400
        try:
            operator = get_current_user()
            # Prevent deleting system users
            if username in ['wazuh', 'wazuh-wui']:
                logger.warning(f"USER DELETE BLOCKED: operator={operator} attempted to delete system user={username}")
                return jsonify({'error': 'Cannot delete system users'}), 400

            api = get_api_session()
            result = api.delete_user(username)

            if result.get('error'):
                logger.warning(f"USER DELETE FAILED: operator={operator} target={username} error={result['error']}")
                return jsonify({'error': result['error']}), 400

            logger.info(f"USER DELETE: operator={operator} deleted_user={username}")
            return jsonify({
                'message': f"User '{username}' deleted successfully"
            })
        except Exception as e:
            logger.error(f"USER DELETE ERROR: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/users/<username>/roles', methods=['PUT'])
    @login_required
    def update_user_roles(username):
        """Update roles for a user."""
        if not validate_username(username):
            return jsonify({'error': 'Invalid username'}), 400
        try:
            data = request.get_json() or {}
            role_ids = data.get('role_ids', [])
            operator = get_current_user()

            api = get_api_session()

            # First get user_id from username
            users = api.get_users()
            user = next((u for u in users if u['username'] == username), None)
            if not user:
                return jsonify({'error': f"User '{username}' not found"}), 404

            user_id = user.get('user_id')
            if not user_id:
                return jsonify({'error': 'Could not get user ID'}), 400

            old_roles = user.get('role_ids', [])
            # Remove all current roles
            if user.get('role_ids'):
                for role_id in user['role_ids']:
                    api.remove_user_role(user_id, role_id)

            # Then assign new roles
            for role_id in role_ids:
                api.assign_user_role(user_id, role_id)

            logger.info(f"USER ROLES UPDATE: operator={operator} target={username} old_roles={old_roles} new_roles={role_ids}")
            return jsonify({
                'message': f"Roles updated for user '{username}'"
            })
        except Exception as e:
            logger.error(f"USER ROLES UPDATE ERROR: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/logs', methods=['GET'])
    @login_required
    def get_logs():
        """Get application logs."""
        try:
            lines = request.args.get('lines', 100, type=int)
            lines = min(max(lines, 10), 5000)  # Limit between 10 and 5000

            log_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            log_file = os.path.join(log_dir, 'wazuh_agent_mgr.log')

            if not os.path.exists(log_file):
                return jsonify({'content': 'Log file not found', 'path': log_file})

            # Read last N lines efficiently
            with open(log_file, 'r', encoding='utf-8') as f:
                all_lines = f.readlines()
                last_lines = all_lines[-lines:] if len(all_lines) > lines else all_lines

            return jsonify({
                'content': ''.join(last_lines),
                'path': log_file,
                'total_lines': len(all_lines),
                'showing': len(last_lines)
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/logs/download', methods=['GET'])
    @login_required
    def download_logs():
        """Download full log file."""
        from flask import Response

        try:
            log_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            log_file = os.path.join(log_dir, 'wazuh_agent_mgr.log')

            if not os.path.exists(log_file):
                return jsonify({'error': 'Log file not found'}), 404

            with open(log_file, 'r', encoding='utf-8') as f:
                content = f.read()

            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'wazuh_agent_mgr_{timestamp}.log'

            logger.info(f"Log downloaded by user '{session.get('api_session', {}).get('username', 'unknown')}'")

            return Response(
                content,
                mimetype='text/plain',
                headers={
                    'Content-Disposition': f'attachment; filename={filename}'
                }
            )
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    # ============ Rules API ============

    def parse_rule_file(file_path: str, is_custom: bool = False) -> list:
        """Parse a Wazuh rule XML file and extract rule information."""
        import xml.etree.ElementTree as ET
        rules = []
        try:
            # Read file content and wrap in root element for parsing
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Wrap content if it doesn't have a single root
            if not content.strip().startswith('<?xml'):
                content = '<rules>' + content + '</rules>'
            else:
                # Remove XML declaration and wrap
                lines = content.split('\n')
                if lines[0].startswith('<?xml'):
                    content = '<rules>' + '\n'.join(lines[1:]) + '</rules>'

            root = ET.fromstring(content)

            for group in root.findall('.//group'):
                outer_group_name = group.get('name', '')
                for rule in group.findall('rule'):
                    rule_id = rule.get('id', '')
                    level = rule.get('level', '0')

                    # Get description
                    desc_elem = rule.find('description')
                    description = desc_elem.text if desc_elem is not None else ''

                    # Get inner <group> element (additional groups this rule belongs to)
                    inner_group_elem = rule.find('group')
                    inner_group = inner_group_elem.text.strip() if inner_group_elem is not None and inner_group_elem.text else ''

                    # Combine outer and inner groups
                    all_groups = outer_group_name
                    if inner_group:
                        if all_groups:
                            all_groups = all_groups.rstrip(',') + ',' + inner_group
                        else:
                            all_groups = inner_group

                    # Get parent references
                    if_sid = rule.find('if_sid')
                    if_matched_sid = rule.find('if_matched_sid')
                    if_group_elem = rule.find('if_group')
                    parent_id = None
                    if_group = None
                    if if_sid is not None and if_sid.text:
                        parent_id = if_sid.text.strip()
                    elif if_matched_sid is not None and if_matched_sid.text:
                        parent_id = if_matched_sid.text.strip()
                    elif if_group_elem is not None and if_group_elem.text:
                        if_group = if_group_elem.text.strip()

                    rules.append({
                        'id': rule_id,
                        'level': int(level) if level.isdigit() else 0,
                        'description': description,
                        'parent_id': parent_id,
                        'if_group': if_group,
                        'group': all_groups,
                        'file': os.path.basename(file_path),
                        'is_custom': is_custom
                    })

            # Also check for rules directly under root (not in group)
            for rule in root.findall('rule'):
                rule_id = rule.get('id', '')
                level = rule.get('level', '0')
                desc_elem = rule.find('description')
                description = desc_elem.text if desc_elem is not None else ''

                # Get inner <group> element
                inner_group_elem = rule.find('group')
                inner_group = inner_group_elem.text.strip() if inner_group_elem is not None and inner_group_elem.text else ''

                if_sid = rule.find('if_sid')
                if_matched_sid = rule.find('if_matched_sid')
                if_group_elem = rule.find('if_group')
                parent_id = None
                if_group = None
                if if_sid is not None and if_sid.text:
                    parent_id = if_sid.text.strip()
                elif if_matched_sid is not None and if_matched_sid.text:
                    parent_id = if_matched_sid.text.strip()
                elif if_group_elem is not None and if_group_elem.text:
                    if_group = if_group_elem.text.strip()

                rules.append({
                    'id': rule_id,
                    'level': int(level) if level.isdigit() else 0,
                    'description': description,
                    'parent_id': parent_id,
                    'if_group': if_group,
                    'group': inner_group,
                    'file': os.path.basename(file_path),
                    'is_custom': is_custom
                })
        except Exception as e:
            logger.debug(f"Error parsing rule file {file_path}: {e}")
        return rules

    def get_all_rules() -> tuple:
        """Get all rules from Wazuh ruleset directories.

        Returns:
            Tuple of (rules_dict, group_to_rules mapping)
        """
        rules_dict = {}
        group_to_rules = {}  # Maps group name to list of rule IDs
        rule_dirs = [
            ('/var/ossec/ruleset/rules/', False),  # Built-in rules
            ('/var/ossec/etc/rules/', True)         # Custom rules
        ]

        for rule_dir, is_custom in rule_dirs:
            if os.path.isdir(rule_dir):
                for filename in os.listdir(rule_dir):
                    if filename.endswith('.xml'):
                        file_path = os.path.join(rule_dir, filename)
                        parsed_rules = parse_rule_file(file_path, is_custom)
                        for rule in parsed_rules:
                            if rule['id']:
                                rules_dict[rule['id']] = rule
                                # Build group-to-rules mapping
                                group_name = rule.get('group', '')
                                if group_name:
                                    # Group name may contain multiple groups separated by comma
                                    for g in group_name.split(','):
                                        g = g.strip()
                                        if g:
                                            if g not in group_to_rules:
                                                group_to_rules[g] = []
                                            group_to_rules[g].append(rule['id'])

        return rules_dict, group_to_rules

    def get_rule_content(rule_id: str) -> str:
        """Get the XML content of a specific rule."""
        import re
        rule_dirs = [
            '/var/ossec/ruleset/rules/',
            '/var/ossec/etc/rules/'
        ]

        for rule_dir in rule_dirs:
            if os.path.isdir(rule_dir):
                for filename in os.listdir(rule_dir):
                    if filename.endswith('.xml'):
                        file_path = os.path.join(rule_dir, filename)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()

                            # Find the rule with matching ID, including leading whitespace
                            pattern = rf'^[ \t]*<rule\s+id="{re.escape(rule_id)}"[^>]*>.*?</rule>'
                            match = re.search(pattern, content, re.DOTALL | re.MULTILINE)
                            if match:
                                return match.group(0)
                        except Exception:
                            continue
        return ''

    def build_hierarchy(rules_dict: dict, group_to_rules: dict, target_rule_id: str) -> dict:
        """Build a hierarchy tree for the target rule, showing parents and children."""
        if target_rule_id not in rules_dict:
            return {'error': f'Rule {target_rule_id} not found'}

        target_rule = rules_dict[target_rule_id]
        visited = {target_rule_id}

        # Find all ancestors (parents going up)
        ancestors = []
        current_id = target_rule.get('parent_id')

        while current_id and current_id in rules_dict and current_id not in visited:
            visited.add(current_id)
            ancestors.insert(0, current_id)
            current_id = rules_dict[current_id].get('parent_id')

        # Check if target rule has if_group (group-based parent)
        if_group = target_rule.get('if_group')
        group_parent_rules = []
        if if_group and not ancestors:
            # Find rules that belong to this group
            group_parent_rules = group_to_rules.get(if_group, [])

        # Find all descendants (children going down)
        def find_children(parent_id: str, parent_group: str = None) -> list:
            children = []
            for rid, rule in rules_dict.items():
                if rid in visited:
                    continue
                # Check if_sid or if_matched_sid
                if rule.get('parent_id') == parent_id:
                    visited.add(rid)
                    children.append({
                        'id': rid,
                        'level': rule.get('level', 0),
                        'description': rule.get('description', ''),
                        'file': rule.get('file', ''),
                        'is_custom': rule.get('is_custom', False),
                        'children': find_children(rid, rule.get('group'))
                    })
                # Check if_group (this rule depends on parent's group)
                elif parent_group and rule.get('if_group'):
                    rule_if_group = rule.get('if_group')
                    # Check if parent's group contains the if_group
                    parent_groups = [g.strip() for g in parent_group.split(',')]
                    if rule_if_group in parent_groups:
                        visited.add(rid)
                        children.append({
                            'id': rid,
                            'level': rule.get('level', 0),
                            'description': rule.get('description', ''),
                            'file': rule.get('file', ''),
                            'is_custom': rule.get('is_custom', False),
                            'if_group': rule_if_group,
                            'children': find_children(rid, rule.get('group'))
                        })
            return children

        # Build the tree starting from the root ancestor
        def build_tree(rule_id: str, remaining_ancestors: list) -> dict:
            rule = rules_dict.get(rule_id, {})
            node = {
                'id': rule_id,
                'level': rule.get('level', 0),
                'description': rule.get('description', ''),
                'file': rule.get('file', ''),
                'is_custom': rule.get('is_custom', False),
                'children': []
            }

            if remaining_ancestors:
                # Continue building the ancestor chain
                next_id = remaining_ancestors[0]
                node['children'] = [build_tree(next_id, remaining_ancestors[1:])]
            elif rule_id == target_rule_id:
                # At target, find children
                node['children'] = find_children(target_rule_id, rule.get('group'))

            return node

        # Build hierarchy
        if ancestors:
            hierarchy = [build_tree(ancestors[0], ancestors[1:] + [target_rule_id])]
        elif if_group and group_parent_rules:
            # Target rule uses if_group - show group as parent
            # Filter out target rule from group members
            member_rules = [rid for rid in group_parent_rules if rid != target_rule_id]
            # Build description with member rule IDs
            if len(member_rules) <= 5:
                members_str = ', '.join(member_rules)
            else:
                members_str = ', '.join(member_rules[:5]) + f' ... (+{len(member_rules) - 5} more)'

            group_node = {
                'id': f'[group: {if_group}]',
                'level': '-',
                'description': f'Members: {members_str}' if members_str else f'Group "{if_group}"',
                'file': '',
                'is_custom': False,
                'is_group': True,
                'group_name': if_group,
                'member_rules': member_rules[:10],  # Limit to 10 for display
                'children': []
            }
            # Target rule is the only child of group node (shows dependency clearly)
            target_node = {
                'id': target_rule_id,
                'level': target_rule.get('level', 0),
                'description': target_rule.get('description', ''),
                'file': target_rule.get('file', ''),
                'is_custom': target_rule.get('is_custom', False),
                'if_group': if_group,
                'children': find_children(target_rule_id, target_rule.get('group'))
            }
            group_node['children'].append(target_node)
            hierarchy = [group_node]
        else:
            # No ancestors, start from target
            hierarchy = [{
                'id': target_rule_id,
                'level': target_rule.get('level', 0),
                'description': target_rule.get('description', ''),
                'file': target_rule.get('file', ''),
                'is_custom': target_rule.get('is_custom', False),
                'children': find_children(target_rule_id, target_rule.get('group'))
            }]

        return {
            'target_rule': target_rule,
            'hierarchy': hierarchy,
            'all_rules': {rid: rules_dict[rid] for rid in visited}
        }

    @app.route('/api/rules/hierarchy', methods=['GET'])
    @login_required
    def get_rules_hierarchy():
        """Get rule hierarchy for a given rule ID."""
        try:
            rule_id = request.args.get('rule_id', '').strip()
            if not rule_id:
                return jsonify({'error': 'rule_id parameter is required'}), 400

            # Validate rule_id format (numeric only)
            if not rule_id.isdigit():
                return jsonify({'error': 'Invalid rule ID format'}), 400

            rules_dict, group_to_rules = get_all_rules()
            result = build_hierarchy(rules_dict, group_to_rules, rule_id)

            if 'error' in result:
                return jsonify(result), 404

            return jsonify(result)
        except Exception as e:
            logger.error(f"Error getting rule hierarchy: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/rules/<rule_id>', methods=['GET'])
    @login_required
    def get_rule_detail(rule_id: str):
        """Get detailed content of a specific rule."""
        try:
            # Validate rule_id format
            if not rule_id.isdigit():
                return jsonify({'error': 'Invalid rule ID format'}), 400

            content = get_rule_content(rule_id)
            if not content:
                return jsonify({'error': f'Rule {rule_id} not found'}), 404

            return jsonify({'rule_id': rule_id, 'content': content})
        except Exception as e:
            logger.error(f"Error getting rule detail: {e}")
            return jsonify({'error': str(e)}), 500

    return app


def _check_cert_valid(cert_path: str) -> bool:
    """Check if certificate exists and is not expired."""
    if not os.path.exists(cert_path):
        return False
    try:
        import subprocess
        result = subprocess.run(
            ['openssl', 'x509', '-checkend', '0', '-noout', '-in', cert_path],
            capture_output=True, text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def _generate_ssl_cert(cert_path: str, key_path: str, days: int = 365) -> bool:
    """Generate self-signed SSL certificate using openssl."""
    import subprocess
    import socket

    hostname = socket.gethostname()
    print(f"Generating self-signed SSL certificate (valid for {days} days)...")

    try:
        # Generate private key and certificate in one command
        result = subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
            '-keyout', key_path,
            '-out', cert_path,
            '-days', str(days),
            '-nodes',  # No passphrase
            '-subj', f'/CN={hostname}/O=JT Wazuh Agent Manager/C=TW'
        ], capture_output=True, text=True)

        if result.returncode == 0:
            print(f"  Certificate generated: {cert_path}")
            print(f"  Private key generated: {key_path}")
            return True
        else:
            print(f"  ERROR: Failed to generate certificate: {result.stderr}")
            return False
    except FileNotFoundError:
        print("  ERROR: openssl command not found. Please install OpenSSL.")
        return False
    except Exception as e:
        print(f"  ERROR: {e}")
        return False


def run_web_server(host: str = '0.0.0.0', port: int = 5000, debug: bool = False,
                   max_login_attempts: int = 3, lockout_minutes: int = 30,
                   ssl_cert: str = None, ssl_key: str = None, ssl_auto: bool = False):
    """Run the web server.

    Args:
        host: Host to bind to
        port: Port to listen on
        debug: Enable debug mode
        max_login_attempts: Max failed login attempts before IP lockout
        lockout_minutes: IP lockout duration in minutes
        ssl_cert: Path to SSL certificate file (for HTTPS)
        ssl_key: Path to SSL private key file (for HTTPS)
        ssl_auto: Auto-generate self-signed certificate if missing or expired

    Environment variables (override parameters):
        WEB_SSL_CERT: Path to SSL certificate file
        WEB_SSL_KEY: Path to SSL private key file
        WEB_SSL_AUTO: Set to 'true' to enable auto-generation
    """
    app = create_app(max_login_attempts=max_login_attempts, lockout_minutes=lockout_minutes)

    # Check environment variables for SSL (override parameters)
    ssl_cert = os.environ.get('WEB_SSL_CERT', ssl_cert)
    ssl_key = os.environ.get('WEB_SSL_KEY', ssl_key)
    ssl_auto = os.environ.get('WEB_SSL_AUTO', '').lower() in ('true', '1', 'yes') or ssl_auto

    # Default certificate paths for ssl_auto
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    default_cert = os.path.join(script_dir, 'ssl_cert.pem')
    default_key = os.path.join(script_dir, 'ssl_key.pem')

    # Handle ssl_auto: auto-generate certificates if needed
    if ssl_auto:
        # Use provided paths or defaults
        ssl_cert = ssl_cert or default_cert
        ssl_key = ssl_key or default_key

        # Check if certificates exist and are valid
        cert_valid = _check_cert_valid(ssl_cert)
        key_exists = os.path.exists(ssl_key)

        if not cert_valid or not key_exists:
            if not cert_valid and os.path.exists(ssl_cert):
                print(f"SSL certificate expired or invalid: {ssl_cert}")
            elif not os.path.exists(ssl_cert):
                print(f"SSL certificate not found: {ssl_cert}")

            # Generate new certificates
            if not _generate_ssl_cert(ssl_cert, ssl_key, days=365):
                print("WARNING: Failed to generate SSL certificate, falling back to HTTP")
                ssl_cert = None
                ssl_key = None

    # Configure SSL context if certificates provided
    ssl_context = None
    protocol = 'http'
    if ssl_cert and ssl_key:
        if os.path.exists(ssl_cert) and os.path.exists(ssl_key):
            ssl_context = (ssl_cert, ssl_key)
            protocol = 'https'
            print(f"SSL enabled: cert={ssl_cert}, key={ssl_key}")
        else:
            print(f"WARNING: SSL cert/key files not found, falling back to HTTP")
            if not os.path.exists(ssl_cert):
                print(f"  - Certificate not found: {ssl_cert}")
            if not os.path.exists(ssl_key):
                print(f"  - Key not found: {ssl_key}")

    logger.info(f"SERVER START: version={VERSION} host={host} port={port} protocol={protocol}")
    print(f"Starting JT Wazuh Agent Manager Web UI v{VERSION} at {protocol}://{host}:{port}")
    print("Login with your Wazuh API credentials to continue.")
    print(f"IP lockout: {max_login_attempts} failed attempts = {lockout_minutes} min lockout")
    print(f"Log file: wazuh_agent_mgr.log")

    # Suppress only the Flask development server warning, keep request logs
    import logging as _logging

    class DevServerWarningFilter(_logging.Filter):
        def filter(self, record):
            # Filter out the development server warning
            return 'This is a development server' not in record.getMessage()

    werkzeug_logger = _logging.getLogger('werkzeug')
    werkzeug_logger.addFilter(DevServerWarningFilter())

    app.run(host=host, port=port, debug=debug, ssl_context=ssl_context)
