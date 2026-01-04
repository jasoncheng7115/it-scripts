#!/usr/bin/env python3
"""Node operations for Wazuh Agent Manager."""

from typing import List, Dict, Any, Optional, Tuple
from .wazuh_cli import WazuhCLI
from .wazuh_api import WazuhAPI, get_api
from .agent_ops import AgentOperations
from .config import get_config


class NodeOperations:
    """High-level cluster node operations."""

    def __init__(self, cli: Optional[WazuhCLI] = None, api: Optional[WazuhAPI] = None):
        """Initialize NodeOperations.

        Args:
            cli: WazuhCLI instance. If None, creates new one.
            api: WazuhAPI instance. If None, tries to get one if API is enabled.
        """
        self.cli = cli or WazuhCLI()
        self.api = api or get_api()
        self.agent_ops = AgentOperations(self.cli)

    def list_nodes(self) -> List[Dict[str, Any]]:
        """List all cluster nodes.

        Returns:
            List of node dictionaries
        """
        nodes = self.cli.list_nodes()

        # Try to enrich with API data if available
        if self.api:
            try:
                api_nodes = self.api.get_cluster_nodes()
                if api_nodes:
                    # Merge additional info from API
                    for node in nodes:
                        api_node = next((n for n in api_nodes
                                        if n.get('name') == node.name), None)
                        if api_node:
                            node.ip = api_node.get('ip', node.ip)
            except Exception:
                pass

        return [n.to_dict() for n in nodes]

    def get_node_info(self, node_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed node information.

        Args:
            node_name: Node name

        Returns:
            Node info dictionary or None
        """
        nodes = self.cli.list_nodes()
        node = next((n for n in nodes if n.name == node_name), None)

        if not node:
            return None

        # Get agents on this node
        agents = self._get_node_agents(node_name)

        info = node.to_dict()
        info['agent_count'] = len(agents)
        info['agents'] = agents

        return info

    def _get_node_agents(self, node_name: str) -> List[Dict[str, Any]]:
        """Get agents connected to a node.

        Args:
            node_name: Node name

        Returns:
            List of agent dictionaries
        """
        # Try API first (faster and more accurate)
        if self.api:
            try:
                agents = self.api.get_agents_by_node(node_name)
                return agents
            except Exception:
                pass

        # Fallback to CLI (slower, needs to check each agent)
        agents = self.cli.get_node_agents(node_name)
        return [a.to_dict() for a in agents]

    def get_node_agents(self, node_name: str) -> List[Dict[str, Any]]:
        """Get all agents connected to a specific node.

        Args:
            node_name: Node name

        Returns:
            List of agent dictionaries
        """
        return self._get_node_agents(node_name)

    def get_cluster_status(self) -> Dict[str, Any]:
        """Get cluster status information.

        Returns:
            Cluster status dictionary
        """
        nodes = self.list_nodes()

        if not nodes:
            return {
                'cluster_enabled': False,
                'message': 'Cluster not configured or not running'
            }

        status = {
            'cluster_enabled': True,
            'node_count': len(nodes),
            'nodes': nodes
        }

        # Add API info if available
        if self.api:
            try:
                api_status = self.api.get_cluster_status()
                if api_status:
                    status.update(api_status)
            except Exception:
                pass

        return status

    def reconnect_agent(self, agent_id: str,
                        dry_run: bool = False) -> Tuple[bool, str]:
        """Force an agent to reconnect.

        Requires API to be enabled.

        Args:
            agent_id: Agent ID
            dry_run: If True, only show what would be done

        Returns:
            Tuple of (success, message)
        """
        if not self.api:
            return False, "API not enabled. Enable API in config to use reconnect feature."

        return self.api.reconnect_agent(agent_id, dry_run)

    def reconnect_agents(self, agent_ids: List[str],
                         dry_run: bool = False) -> List[Tuple[str, bool, str]]:
        """Force multiple agents to reconnect.

        Requires API to be enabled.

        Args:
            agent_ids: List of agent IDs
            dry_run: If True, only show what would be done

        Returns:
            List of (agent_id, success, message) tuples
        """
        if not self.api:
            return [(aid, False, "API not enabled") for aid in agent_ids]

        return self.api.reconnect_agents(agent_ids, dry_run)

    def reconnect_node_agents(self, node_name: str,
                              dry_run: bool = False) -> List[Tuple[str, bool, str]]:
        """Force all agents on a node to reconnect.

        Args:
            node_name: Node name
            dry_run: If True, only show what would be done

        Returns:
            List of (agent_id, success, message) tuples
        """
        agents = self._get_node_agents(node_name)
        agent_ids = [a.get('id', a['id']) if isinstance(a, dict) else a.id for a in agents]

        if not agent_ids:
            return []

        return self.reconnect_agents(agent_ids, dry_run)

    def migrate_node_agents(self, from_node: str, to_node: Optional[str] = None,
                            dry_run: bool = False) -> List[Tuple[str, bool, str]]:
        """Migrate all agents from one node to another.

        This forces agents to reconnect, allowing them to connect to a different node.
        Note: Actual node assignment depends on Wazuh cluster configuration.

        Args:
            from_node: Source node name
            to_node: Target node name (informational only, actual assignment by Wazuh)
            dry_run: If True, only show what would be done

        Returns:
            List of (agent_id, success, message) tuples
        """
        if dry_run:
            agents = self._get_node_agents(from_node)
            results = []
            for agent in agents:
                agent_id = agent.get('id') if isinstance(agent, dict) else agent.id
                msg = f"[DRY-RUN] Would reconnect agent {agent_id} (from {from_node})"
                if to_node:
                    msg += f" to migrate toward {to_node}"
                results.append((agent_id, True, msg))
            return results

        return self.reconnect_node_agents(from_node, dry_run)

    def get_node_agent_distribution(self) -> Dict[str, Any]:
        """Get agent distribution across nodes.

        Returns:
            Dictionary with node distribution info
        """
        nodes = self.list_nodes()
        distribution = {}

        for node in nodes:
            node_name = node['name']
            agents = self._get_node_agents(node_name)
            distribution[node_name] = {
                'node_type': node.get('type', 'unknown'),
                'agent_count': len(agents),
                'agent_ids': [a.get('id') if isinstance(a, dict) else a.id for a in agents]
            }

        total_agents = sum(d['agent_count'] for d in distribution.values())

        return {
            'total_agents': total_agents,
            'node_count': len(nodes),
            'distribution': distribution
        }
