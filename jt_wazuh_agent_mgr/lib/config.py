#!/usr/bin/env python3
"""Configuration management for Wazuh Agent Manager."""

import os
import yaml
from pathlib import Path
from typing import Optional, Dict, Any


class Config:
    """Configuration handler for Wazuh Agent Manager."""

    DEFAULT_CONFIG = {
        'wazuh_path': '/var/ossec',
        'api': {
            'enabled': False,
            'host': 'localhost',
            'port': 55000,
            'username': 'wazuh',
            'password': '',
            'verify_ssl': False
        },
        'output_format': 'table',
        'interactive': {
            'page_size': 20
        }
    }

    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration.

        Args:
            config_path: Path to config file. If None, searches default locations.
        """
        self._config: Dict[str, Any] = self.DEFAULT_CONFIG.copy()
        self._config_path = config_path
        self._load_config()

    def _find_config_file(self) -> Optional[Path]:
        """Find config file in default locations."""
        search_paths = [
            Path.cwd() / 'config.yaml',
            Path.cwd() / 'config.yml',
            Path(__file__).parent.parent / 'config.yaml',
            Path(__file__).parent.parent / 'config.yml',
            Path.home() / '.wazuh_agent_mgr.yaml',
            Path('/etc/wazuh_agent_mgr/config.yaml'),
        ]

        for path in search_paths:
            if path.exists():
                return path
        return None

    def _load_config(self) -> None:
        """Load configuration from file."""
        config_file = None

        if self._config_path:
            config_file = Path(self._config_path)
            if not config_file.exists():
                raise FileNotFoundError(f"Config file not found: {self._config_path}")
        else:
            config_file = self._find_config_file()

        self._loaded_config_file = config_file  # Store the loaded config file path

        if config_file:
            with open(config_file, 'r', encoding='utf-8') as f:
                file_config = yaml.safe_load(f) or {}
                self._merge_config(file_config)

    def _merge_config(self, file_config: Dict[str, Any]) -> None:
        """Merge file config with defaults."""
        def deep_merge(base: dict, override: dict) -> dict:
            result = base.copy()
            for key, value in override.items():
                if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                    result[key] = deep_merge(result[key], value)
                else:
                    result[key] = value
            return result

        self._config = deep_merge(self._config, file_config)

    @property
    def config_file_path(self) -> str:
        """Get the path of the loaded config file."""
        if self._loaded_config_file:
            return str(self._loaded_config_file.absolute())
        return ''

    @property
    def wazuh_path(self) -> str:
        """Get Wazuh installation path."""
        return self._config.get('wazuh_path', '/var/ossec')

    @property
    def bin_path(self) -> str:
        """Get Wazuh bin directory path."""
        return os.path.join(self.wazuh_path, 'bin')

    @property
    def api_enabled(self) -> bool:
        """Check if API is enabled."""
        return self._config.get('api', {}).get('enabled', False)

    @property
    def api_host(self) -> str:
        """Get API host."""
        return self._config.get('api', {}).get('host', 'localhost')

    @property
    def api_port(self) -> int:
        """Get API port."""
        return self._config.get('api', {}).get('port', 55000)

    @property
    def api_username(self) -> str:
        """Get API username."""
        return self._config.get('api', {}).get('username', 'wazuh')

    @property
    def api_password(self) -> str:
        """Get API password."""
        return self._config.get('api', {}).get('password', '')

    @property
    def api_verify_ssl(self) -> bool:
        """Get API SSL verification setting."""
        return self._config.get('api', {}).get('verify_ssl', False)

    @property
    def api_base_url(self) -> str:
        """Get API base URL."""
        return f"https://{self.api_host}:{self.api_port}"

    @property
    def output_format(self) -> str:
        """Get default output format."""
        return self._config.get('output_format', 'table')

    @property
    def page_size(self) -> int:
        """Get interactive page size."""
        return self._config.get('interactive', {}).get('page_size', 20)

    @property
    def ssh_enabled(self) -> bool:
        """Check if SSH is enabled for remote node access."""
        return self._config.get('ssh', {}).get('enabled', False)

    @property
    def ssh_key_file(self) -> str:
        """Get SSH key file path."""
        return self._config.get('ssh', {}).get('key_file', '')

    @property
    def ssh_nodes(self) -> Dict[str, Any]:
        """Get SSH nodes configuration."""
        return self._config.get('ssh', {}).get('nodes', {})

    def get_ssh_config_for_node(self, node_name: str) -> Optional[Dict[str, Any]]:
        """Get SSH configuration for a specific node.

        Args:
            node_name: Name of the node

        Returns:
            Dict with host, port, user, or None if not configured
        """
        if not self.ssh_enabled:
            return None
        nodes = self.ssh_nodes
        if node_name in nodes:
            cfg = nodes[node_name]
            return {
                'host': cfg.get('host', cfg.get('ip', node_name)),
                'port': cfg.get('port', 22),
                'user': cfg.get('user', 'root'),
                'key_file': self.ssh_key_file
            }
        return None

    def get(self, key: str, default: Any = None) -> Any:
        """Get config value by key."""
        return self._config.get(key, default)

    def to_dict(self) -> Dict[str, Any]:
        """Return config as dictionary."""
        return self._config.copy()


# Global config instance
_config: Optional[Config] = None


def get_config(config_path: Optional[str] = None) -> Config:
    """Get or create global config instance."""
    global _config
    if _config is None or config_path is not None:
        _config = Config(config_path)
    return _config
