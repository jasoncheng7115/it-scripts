#!/usr/bin/env python3
"""Statistics operations for Wazuh Agent Manager."""

from typing import List, Dict, Any, Optional
from collections import defaultdict
from .wazuh_cli import WazuhCLI
from .agent_ops import AgentOperations
from .group_ops import GroupOperations
from .node_ops import NodeOperations


class StatisticsOperations:
    """High-level statistics operations."""

    def __init__(self, cli: Optional[WazuhCLI] = None):
        """Initialize StatisticsOperations.

        Args:
            cli: WazuhCLI instance. If None, creates new one.
        """
        self.cli = cli or WazuhCLI()
        self.agent_ops = AgentOperations(self.cli)
        self.group_ops = GroupOperations(self.cli)
        self.node_ops = NodeOperations(self.cli)

    def get_summary(self) -> Dict[str, Any]:
        """Get overall summary statistics.

        Returns:
            Summary dictionary
        """
        agents = self.agent_ops.list_agents(detailed=True)

        # Count by status
        status_counts = defaultdict(int)
        for agent in agents:
            status = agent.get('status', 'Unknown')
            status_counts[status] += 1

        # Get group and node counts
        groups = self.group_ops.list_groups()
        nodes = self.node_ops.list_nodes()

        # Calculate percentages
        total = len(agents)
        active_count = status_counts.get('Active', 0)
        active_pct = (active_count / total * 100) if total > 0 else 0

        return {
            'total_agents': total,
            'active_agents': active_count,
            'active_percentage': round(active_pct, 1),
            'status_breakdown': dict(status_counts),
            'total_groups': len(groups),
            'total_nodes': len(nodes),
            'cluster_enabled': len(nodes) > 0
        }

    def get_stats_by_status(self) -> List[Dict[str, Any]]:
        """Get statistics grouped by status.

        Returns:
            List of status statistics
        """
        agents = self.cli.list_agents()

        status_stats = defaultdict(lambda: {'count': 0, 'agents': []})

        for agent in agents:
            status = agent.status
            status_stats[status]['count'] += 1
            status_stats[status]['agents'].append({
                'id': agent.id,
                'name': agent.name
            })

        total = len(agents)
        result = []
        for status, data in sorted(status_stats.items()):
            pct = (data['count'] / total * 100) if total > 0 else 0
            result.append({
                'status': status,
                'count': data['count'],
                'percentage': round(pct, 1)
            })

        return result

    def get_stats_by_group(self) -> List[Dict[str, Any]]:
        """Get statistics grouped by group.

        Returns:
            List of group statistics
        """
        groups = self.group_ops.list_groups()
        total_agents = len(self.cli.list_agents())

        result = []
        ungrouped_count = total_agents

        for group in groups:
            group_agents = self.group_ops.get_group_agents(group['name'])
            count = len(group_agents)
            pct = (count / total_agents * 100) if total_agents > 0 else 0

            # Count active in group
            active_count = sum(1 for a in group_agents
                              if 'active' in a.get('status', '').lower())

            result.append({
                'group': group['name'],
                'count': count,
                'percentage': round(pct, 1),
                'active_count': active_count
            })

            ungrouped_count -= count

        # Add ungrouped if any
        if ungrouped_count > 0:
            pct = (ungrouped_count / total_agents * 100) if total_agents > 0 else 0
            result.append({
                'group': '(no group)',
                'count': ungrouped_count,
                'percentage': round(pct, 1),
                'active_count': 0
            })

        return sorted(result, key=lambda x: x['count'], reverse=True)

    def get_stats_by_node(self) -> List[Dict[str, Any]]:
        """Get statistics grouped by node.

        Returns:
            List of node statistics
        """
        nodes = self.node_ops.list_nodes()

        if not nodes:
            return [{
                'node': '(standalone)',
                'type': 'standalone',
                'count': len(self.cli.list_agents()),
                'percentage': 100.0
            }]

        distribution = self.node_ops.get_node_agent_distribution()
        total = distribution['total_agents']

        result = []
        for node_name, data in distribution['distribution'].items():
            count = data['agent_count']
            pct = (count / total * 100) if total > 0 else 0
            result.append({
                'node': node_name,
                'type': data['node_type'],
                'count': count,
                'percentage': round(pct, 1)
            })

        return sorted(result, key=lambda x: x['count'], reverse=True)

    def get_stats_by_os(self) -> List[Dict[str, Any]]:
        """Get statistics grouped by operating system.

        Returns:
            List of OS statistics
        """
        agents = self.agent_ops.list_agents(detailed=True)

        os_stats = defaultdict(int)
        for agent in agents:
            os_name = agent.get('os', 'Unknown') or 'Unknown'
            # Simplify OS name
            if 'windows' in os_name.lower():
                os_key = 'Windows'
            elif 'linux' in os_name.lower() or 'ubuntu' in os_name.lower() or \
                 'centos' in os_name.lower() or 'rhel' in os_name.lower() or \
                 'debian' in os_name.lower():
                os_key = 'Linux'
            elif 'macos' in os_name.lower() or 'darwin' in os_name.lower():
                os_key = 'macOS'
            else:
                os_key = os_name.split()[0] if os_name else 'Unknown'

            os_stats[os_key] += 1

        total = len(agents)
        result = []
        for os_name, count in sorted(os_stats.items(), key=lambda x: x[1], reverse=True):
            pct = (count / total * 100) if total > 0 else 0
            result.append({
                'os': os_name,
                'count': count,
                'percentage': round(pct, 1)
            })

        return result

    def get_stats_by_version(self) -> List[Dict[str, Any]]:
        """Get statistics grouped by agent version.

        Returns:
            List of version statistics
        """
        agents = self.agent_ops.list_agents(detailed=True)

        version_stats = defaultdict(int)
        for agent in agents:
            version = agent.get('version', 'Unknown') or 'Unknown'
            # Extract version number
            if version and version != 'Unknown':
                # Try to extract Wazuh version
                import re
                match = re.search(r'v?(\d+\.\d+(?:\.\d+)?)', version)
                if match:
                    version = match.group(1)
            version_stats[version] += 1

        total = len(agents)
        result = []
        for version, count in sorted(version_stats.items(), key=lambda x: x[1], reverse=True):
            pct = (count / total * 100) if total > 0 else 0
            result.append({
                'version': version,
                'count': count,
                'percentage': round(pct, 1)
            })

        return result

    def get_detailed_report(self) -> Dict[str, Any]:
        """Get comprehensive statistics report.

        Returns:
            Detailed report dictionary
        """
        return {
            'summary': self.get_summary(),
            'by_status': self.get_stats_by_status(),
            'by_group': self.get_stats_by_group(),
            'by_node': self.get_stats_by_node(),
            'by_os': self.get_stats_by_os(),
            'by_version': self.get_stats_by_version(),
            'health': self.agent_ops.health_check()
        }

    def get_top_groups(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top groups by agent count.

        Args:
            limit: Number of groups to return

        Returns:
            List of top group statistics
        """
        stats = self.get_stats_by_group()
        return stats[:limit]

    def get_problematic_agents(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get agents with issues.

        Returns:
            Dictionary of issue type to agent lists
        """
        return {
            'disconnected': self.agent_ops.get_disconnected_agents(),
            'pending': self.agent_ops.get_pending_agents(),
            'never_connected': self.agent_ops.get_never_connected_agents()
        }

    def get_agent_trend_info(self) -> Dict[str, Any]:
        """Get information useful for trend analysis.

        Note: This provides current state. Historical data requires external storage.

        Returns:
            Current state information for trend tracking
        """
        summary = self.get_summary()

        return {
            'timestamp': None,  # To be filled by caller
            'total': summary['total_agents'],
            'active': summary['active_agents'],
            'disconnected': summary['status_breakdown'].get('Disconnected', 0),
            'pending': summary['status_breakdown'].get('Pending', 0),
            'never_connected': summary['status_breakdown'].get('Never connected', 0)
        }
