#!/usr/bin/env python3
"""Group operations for Wazuh Agent Manager."""

from typing import List, Dict, Any, Optional, Tuple
from .wazuh_cli import WazuhCLI
from .agent_ops import AgentOperations


class GroupOperations:
    """High-level group operations."""

    def __init__(self, cli: Optional[WazuhCLI] = None):
        """Initialize GroupOperations.

        Args:
            cli: WazuhCLI instance. If None, creates new one.
        """
        self.cli = cli or WazuhCLI()
        self.agent_ops = AgentOperations(self.cli)

    def list_groups(self) -> List[Dict[str, Any]]:
        """List all groups.

        Returns:
            List of group dictionaries
        """
        groups = self.cli.list_groups()

        # Enrich with agent counts
        result = []
        for group in groups:
            agents = self.cli.get_group_agents(group.name)
            result.append({
                'name': group.name,
                'agent_count': len(agents)
            })

        return result

    def get_group_info(self, group_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed group information.

        Args:
            group_name: Group name

        Returns:
            Group info dictionary or None
        """
        groups = self.cli.list_groups()
        group = next((g for g in groups if g.name == group_name), None)

        if not group:
            return None

        agents = self.cli.get_group_agents(group_name)

        return {
            'name': group.name,
            'agent_count': len(agents),
            'agents': [a.to_dict() for a in agents]
        }

    def get_group_agents(self, group_name: str) -> List[Dict[str, Any]]:
        """Get all agents in a group.

        Args:
            group_name: Group name

        Returns:
            List of agent dictionaries
        """
        agents = self.cli.get_group_agents(group_name)
        return [a.to_dict() for a in agents]

    def create_group(self, group_name: str,
                     dry_run: bool = False) -> Tuple[bool, str]:
        """Create a new group.

        Args:
            group_name: Group name
            dry_run: If True, only show what would be done

        Returns:
            Tuple of (success, message)
        """
        return self.cli.create_group(group_name, dry_run)

    def delete_group(self, group_name: str,
                     dry_run: bool = False) -> Tuple[bool, str]:
        """Delete a group.

        Args:
            group_name: Group name
            dry_run: If True, only show what would be done

        Returns:
            Tuple of (success, message)
        """
        return self.cli.delete_group(group_name, dry_run)

    def add_agents_to_group(self, agent_ids: List[str], group_name: str,
                            dry_run: bool = False) -> List[Tuple[str, bool, str]]:
        """Add multiple agents to a group.

        Args:
            agent_ids: List of agent IDs
            group_name: Group name
            dry_run: If True, only show what would be done

        Returns:
            List of (agent_id, success, message) tuples
        """
        results = []
        for agent_id in agent_ids:
            success, message = self.cli.add_agent_to_group(agent_id, group_name, dry_run)
            results.append((agent_id, success, message))
        return results

    def remove_agents_from_group(self, agent_ids: List[str], group_name: str,
                                 dry_run: bool = False) -> List[Tuple[str, bool, str]]:
        """Remove multiple agents from a group.

        Args:
            agent_ids: List of agent IDs
            group_name: Group name
            dry_run: If True, only show what would be done

        Returns:
            List of (agent_id, success, message) tuples
        """
        results = []
        for agent_id in agent_ids:
            success, message = self.cli.remove_agent_from_group(agent_id, group_name, dry_run)
            results.append((agent_id, success, message))
        return results

    def add_agents_by_filter(self, group_name: str,
                             status: Optional[str] = None,
                             name_pattern: Optional[str] = None,
                             ip_pattern: Optional[str] = None,
                             dry_run: bool = False) -> List[Tuple[str, bool, str]]:
        """Add agents matching filter to a group.

        Args:
            group_name: Group name
            status: Status filter
            name_pattern: Name regex pattern
            ip_pattern: IP regex pattern
            dry_run: If True, only show what would be done

        Returns:
            List of (agent_id, success, message) tuples
        """
        agents = self.agent_ops.list_agents(
            status=status,
            name=name_pattern,
            ip=ip_pattern
        )

        agent_ids = [a['id'] for a in agents]
        return self.add_agents_to_group(agent_ids, group_name, dry_run)

    def remove_agents_by_filter(self, group_name: str,
                                status: Optional[str] = None,
                                name_pattern: Optional[str] = None,
                                ip_pattern: Optional[str] = None,
                                dry_run: bool = False) -> List[Tuple[str, bool, str]]:
        """Remove agents matching filter from a group.

        Args:
            group_name: Group name
            status: Status filter
            name_pattern: Name regex pattern
            ip_pattern: IP regex pattern
            dry_run: If True, only show what would be done

        Returns:
            List of (agent_id, success, message) tuples
        """
        # Get agents in group first
        group_agents = self.get_group_agents(group_name)

        # Filter within group
        agent_ids = []
        for agent in group_agents:
            if status and status.lower() not in agent.get('status', '').lower():
                continue
            if name_pattern:
                import re
                if not re.search(name_pattern, agent.get('name', ''), re.IGNORECASE):
                    continue
            if ip_pattern:
                import re
                if not re.search(ip_pattern, agent.get('ip', ''), re.IGNORECASE):
                    continue
            agent_ids.append(agent['id'])

        return self.remove_agents_from_group(agent_ids, group_name, dry_run)

    def move_agents_between_groups(self, agent_ids: List[str],
                                   from_group: str, to_group: str,
                                   dry_run: bool = False) -> Dict[str, List[Tuple[str, bool, str]]]:
        """Move agents from one group to another.

        Args:
            agent_ids: List of agent IDs
            from_group: Source group name
            to_group: Target group name
            dry_run: If True, only show what would be done

        Returns:
            Dictionary with 'removed' and 'added' results
        """
        removed = self.remove_agents_from_group(agent_ids, from_group, dry_run)
        added = self.add_agents_to_group(agent_ids, to_group, dry_run)

        return {
            'removed': removed,
            'added': added
        }

    def sync_group_agents(self, group_name: str,
                          agent_ids: List[str],
                          dry_run: bool = False) -> Dict[str, List[Tuple[str, bool, str]]]:
        """Sync group membership to match the given agent list.

        Adds agents not in group, removes agents not in list.

        Args:
            group_name: Group name
            agent_ids: Target list of agent IDs
            dry_run: If True, only show what would be done

        Returns:
            Dictionary with 'added' and 'removed' results
        """
        current_agents = self.get_group_agents(group_name)
        current_ids = set(a['id'] for a in current_agents)
        target_ids = set(agent_ids)

        to_add = target_ids - current_ids
        to_remove = current_ids - target_ids

        added = self.add_agents_to_group(list(to_add), group_name, dry_run)
        removed = self.remove_agents_from_group(list(to_remove), group_name, dry_run)

        return {
            'added': added,
            'removed': removed
        }
