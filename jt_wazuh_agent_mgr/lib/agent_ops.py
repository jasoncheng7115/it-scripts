#!/usr/bin/env python3
"""Agent operations for Wazuh Agent Manager."""

import re
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict
from .wazuh_cli import WazuhCLI, Agent
from .output import get_formatter


class AgentOperations:
    """High-level agent operations."""

    def __init__(self, cli: Optional[WazuhCLI] = None):
        """Initialize AgentOperations.

        Args:
            cli: WazuhCLI instance. If None, creates new one.
        """
        self.cli = cli or WazuhCLI()

    def list_agents(self, status: Optional[str] = None,
                    group: Optional[str] = None,
                    node: Optional[str] = None,
                    os_filter: Optional[str] = None,
                    version: Optional[str] = None,
                    name: Optional[str] = None,
                    ip: Optional[str] = None,
                    detailed: bool = False) -> List[Dict[str, Any]]:
        """List agents with optional filters.

        Args:
            status: Filter by status (regex)
            group: Filter by group (regex)
            node: Filter by node (regex)
            os_filter: Filter by OS (regex)
            version: Filter by version (regex)
            name: Filter by name (regex)
            ip: Filter by IP (regex)
            detailed: If True, get detailed info for each agent

        Returns:
            List of agent dictionaries
        """
        agents = self.cli.list_agents()

        # Get detailed info if needed
        if detailed or any([group, node, os_filter, version]):
            detailed_agents = []
            for agent in agents:
                info = self.cli.get_agent_info(agent.id)
                if info:
                    detailed_agents.append(info)
                else:
                    detailed_agents.append(agent)
            agents = detailed_agents

        # Apply filters
        def matches(pattern: Optional[str], value: str) -> bool:
            if pattern is None:
                return True
            try:
                return bool(re.search(pattern, value, re.IGNORECASE))
            except re.error:
                return pattern.lower() in value.lower()

        filtered = []
        for agent in agents:
            if not matches(status, agent.status):
                continue
            if not matches(name, agent.name):
                continue
            if not matches(ip, agent.ip):
                continue
            if not matches(group, agent.group):
                continue
            if not matches(node, agent.node):
                continue
            if not matches(os_filter, agent.os):
                continue
            if not matches(version, agent.version):
                continue
            filtered.append(agent)

        return [a.to_dict() for a in filtered]

    def get_pending_agents(self) -> List[Dict[str, Any]]:
        """Get all pending agents.

        Returns:
            List of pending agent dictionaries
        """
        agents = self.cli.get_agents_by_status('Pending')
        return [a.to_dict() for a in agents]

    def get_disconnected_agents(self) -> List[Dict[str, Any]]:
        """Get all disconnected agents.

        Returns:
            List of disconnected agent dictionaries
        """
        agents = self.cli.get_agents_by_status('Disconnected')
        return [a.to_dict() for a in agents]

    def get_never_connected_agents(self) -> List[Dict[str, Any]]:
        """Get all never connected agents.

        Returns:
            List of never connected agent dictionaries
        """
        agents = self.cli.get_agents_by_status('Never connected')
        return [a.to_dict() for a in agents]

    def get_active_agents(self) -> List[Dict[str, Any]]:
        """Get all active agents.

        Returns:
            List of active agent dictionaries
        """
        agents = self.cli.get_agents_by_status('Active')
        return [a.to_dict() for a in agents]

    def get_agent_info(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed info for an agent.

        Args:
            agent_id: Agent ID

        Returns:
            Agent dictionary or None
        """
        agent = self.cli.get_agent_info(agent_id)
        return agent.to_dict() if agent else None

    def restart_agents(self, agent_ids: List[str],
                       dry_run: bool = False) -> List[Tuple[str, bool, str]]:
        """Restart multiple agents.

        Args:
            agent_ids: List of agent IDs
            dry_run: If True, only show what would be done

        Returns:
            List of (agent_id, success, message) tuples
        """
        results = []
        for agent_id in agent_ids:
            success, message = self.cli.restart_agent(agent_id, dry_run)
            results.append((agent_id, success, message))
        return results

    def delete_agents(self, agent_ids: List[str],
                      dry_run: bool = False) -> List[Tuple[str, bool, str]]:
        """Delete multiple agents.

        Args:
            agent_ids: List of agent IDs
            dry_run: If True, only show what would be done

        Returns:
            List of (agent_id, success, message) tuples
        """
        results = []
        for agent_id in agent_ids:
            success, message = self.cli.delete_agent(agent_id, dry_run)
            results.append((agent_id, success, message))
        return results

    def find_duplicate_agents(self, by: str = 'ip') -> Dict[str, List[Dict[str, Any]]]:
        """Find duplicate agents by IP or name.

        Args:
            by: Field to check for duplicates ('ip' or 'name')

        Returns:
            Dictionary of {value: [agents]} for duplicates
        """
        agents = self.cli.list_agents()
        groups = defaultdict(list)

        for agent in agents:
            key = getattr(agent, by, '')
            if key and key.lower() not in ('any', 'any/any', '0.0.0.0'):
                groups[key].append(agent.to_dict())

        # Return only duplicates
        return {k: v for k, v in groups.items() if len(v) > 1}

    def health_check(self) -> Dict[str, Any]:
        """Perform health check on agents.

        Returns:
            Health check report dictionary
        """
        agents = self.cli.list_agents()

        # Categorize agents
        status_counts = defaultdict(int)
        issues = []

        for agent in agents:
            status_lower = agent.status.lower()
            status_counts[agent.status] += 1

            # Check for issues
            if 'disconnected' in status_lower:
                issues.append({
                    'type': 'disconnected',
                    'severity': 'warning',
                    'agent_id': agent.id,
                    'agent_name': agent.name,
                    'message': f"Agent {agent.id} ({agent.name}) is disconnected"
                })
            elif 'never connected' in status_lower:
                issues.append({
                    'type': 'never_connected',
                    'severity': 'warning',
                    'agent_id': agent.id,
                    'agent_name': agent.name,
                    'message': f"Agent {agent.id} ({agent.name}) has never connected"
                })
            elif 'pending' in status_lower:
                issues.append({
                    'type': 'pending',
                    'severity': 'info',
                    'agent_id': agent.id,
                    'agent_name': agent.name,
                    'message': f"Agent {agent.id} ({agent.name}) is pending"
                })

        # Check for duplicates
        dup_ips = self.find_duplicate_agents('ip')
        dup_names = self.find_duplicate_agents('name')

        for ip, dups in dup_ips.items():
            issues.append({
                'type': 'duplicate_ip',
                'severity': 'warning',
                'message': f"Duplicate IP {ip}: {[d['id'] for d in dups]}"
            })

        for name, dups in dup_names.items():
            issues.append({
                'type': 'duplicate_name',
                'severity': 'info',
                'message': f"Duplicate name {name}: {[d['id'] for d in dups]}"
            })

        return {
            'total_agents': len(agents),
            'status_counts': dict(status_counts),
            'issues_count': len(issues),
            'issues': issues,
            'duplicate_ips': len(dup_ips),
            'duplicate_names': len(dup_names)
        }

    def export_agents(self, format_type: str = 'csv',
                      filters: Optional[Dict[str, str]] = None) -> str:
        """Export agents to specified format.

        Args:
            format_type: Output format (csv, json)
            filters: Optional filters to apply

        Returns:
            Formatted output string
        """
        filters = filters or {}
        agents = self.list_agents(detailed=True, **filters)

        formatter = get_formatter(format_type)

        if format_type == 'json':
            return formatter.format_json(agents)
        else:  # csv
            return formatter.format_csv(agents)

    def search_agents(self, pattern: str,
                      fields: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Search agents across multiple fields.

        Args:
            pattern: Search pattern (regex)
            fields: Fields to search (default: name, ip, id)

        Returns:
            List of matching agent dictionaries
        """
        if fields is None:
            fields = ['name', 'ip', 'id']

        agents = self.cli.list_agents()
        results = []

        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error:
            regex = None

        for agent in agents:
            for field in fields:
                value = getattr(agent, field, '')
                if regex and regex.search(value):
                    results.append(agent.to_dict())
                    break
                elif not regex and pattern.lower() in value.lower():
                    results.append(agent.to_dict())
                    break

        return results
