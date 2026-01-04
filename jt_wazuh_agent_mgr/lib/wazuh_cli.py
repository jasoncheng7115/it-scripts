#!/usr/bin/env python3
"""Wazuh CLI wrapper for executing Wazuh commands."""

import os
import re
import subprocess
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from .config import get_config


@dataclass
class Agent:
    """Agent data structure."""
    id: str
    name: str
    ip: str
    status: str
    os: str = ""
    version: str = ""
    node: str = ""
    group: str = ""
    last_keepalive: str = ""
    date_add: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'ip': self.ip,
            'status': self.status,
            'os': self.os,
            'version': self.version,
            'node': self.node,
            'group': self.group,
            'last_keepalive': self.last_keepalive,
            'date_add': self.date_add
        }


@dataclass
class Group:
    """Group data structure."""
    name: str
    agent_count: int = 0
    merged_sum: str = ""
    conf_sum: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'name': self.name,
            'agent_count': self.agent_count,
            'merged_sum': self.merged_sum,
            'conf_sum': self.conf_sum
        }


@dataclass
class Node:
    """Cluster node data structure."""
    name: str
    node_type: str
    version: str
    ip: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'name': self.name,
            'type': self.node_type,
            'version': self.version,
            'ip': self.ip
        }


class WazuhCLI:
    """Wrapper for Wazuh CLI commands."""

    def __init__(self, config=None):
        """Initialize WazuhCLI.

        Args:
            config: Config instance. If None, uses global config.
        """
        self.config = config or get_config()
        self.bin_path = self.config.bin_path

    def _run_command(self, cmd: List[str], timeout: int = 60) -> Tuple[int, str, str]:
        """Run a command and return result.

        Args:
            cmd: Command and arguments list
            timeout: Timeout in seconds

        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", f"Command timed out after {timeout} seconds"
        except FileNotFoundError:
            return -1, "", f"Command not found: {cmd[0]}"
        except Exception as e:
            return -1, "", str(e)

    def _get_bin(self, name: str) -> str:
        """Get full path to Wazuh binary."""
        return os.path.join(self.bin_path, name)

    # ============ Agent Operations ============

    def list_agents(self) -> List[Agent]:
        """List all agents using agent_control -l.

        Returns:
            List of Agent objects
        """
        cmd = [self._get_bin('agent_control'), '-l']
        rc, stdout, stderr = self._run_command(cmd)

        if rc != 0:
            raise RuntimeError(f"Failed to list agents: {stderr}")

        agents = []
        # Parse output format:
        # ID: 001, Name: agent1, IP: 192.168.1.10, Active/Disconnected/Pending/Never connected
        for line in stdout.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('Wazuh') or line.startswith('List'):
                continue

            # Pattern: ID: 001, Name: agent-name, IP: 192.168.1.1, Active
            match = re.match(
                r'ID:\s*(\d+),\s*Name:\s*([^,]+),\s*IP:\s*([^,]+),\s*(.+)',
                line
            )
            if match:
                agent_id, name, ip, status = match.groups()
                status = status.strip()
                agents.append(Agent(
                    id=agent_id.strip(),
                    name=name.strip(),
                    ip=ip.strip(),
                    status=status
                ))

        return agents

    def get_agent_info(self, agent_id: str) -> Optional[Agent]:
        """Get detailed agent information.

        Args:
            agent_id: Agent ID

        Returns:
            Agent object with detailed info, or None if not found
        """
        cmd = [self._get_bin('agent_control'), '-i', agent_id]
        rc, stdout, stderr = self._run_command(cmd)

        if rc != 0:
            return None

        agent = Agent(id=agent_id, name="", ip="", status="")

        for line in stdout.strip().split('\n'):
            line = line.strip()
            if line.startswith('Agent ID:'):
                agent.id = line.split(':', 1)[1].strip()
            elif line.startswith('Agent Name:'):
                agent.name = line.split(':', 1)[1].strip()
            elif line.startswith('IP address:'):
                agent.ip = line.split(':', 1)[1].strip()
            elif line.startswith('Status:'):
                agent.status = line.split(':', 1)[1].strip()
            elif line.startswith('Operating system:'):
                agent.os = line.split(':', 1)[1].strip()
            elif line.startswith('Client version:'):
                agent.version = line.split(':', 1)[1].strip()
            elif line.startswith('Last keep alive:'):
                agent.last_keepalive = line.split(':', 1)[1].strip()
            elif line.startswith('Date add:'):
                agent.date_add = line.split(':', 1)[1].strip()
            elif line.startswith('Group:'):
                agent.group = line.split(':', 1)[1].strip()

        return agent

    def restart_agent(self, agent_id: str, dry_run: bool = False) -> Tuple[bool, str]:
        """Restart an agent.

        Args:
            agent_id: Agent ID
            dry_run: If True, only show what would be done

        Returns:
            Tuple of (success, message)
        """
        cmd = [self._get_bin('agent_control'), '-R', agent_id]

        if dry_run:
            return True, f"[DRY-RUN] Would execute: {' '.join(cmd)}"

        rc, stdout, stderr = self._run_command(cmd)
        if rc == 0:
            return True, f"Agent {agent_id} restart requested"
        return False, stderr or stdout

    def delete_agent(self, agent_id: str, dry_run: bool = False) -> Tuple[bool, str]:
        """Delete an agent.

        Args:
            agent_id: Agent ID
            dry_run: If True, only show what would be done

        Returns:
            Tuple of (success, message)
        """
        cmd = [self._get_bin('manage_agents'), '-r', agent_id]

        if dry_run:
            return True, f"[DRY-RUN] Would execute: {' '.join(cmd)}"

        # manage_agents requires confirmation, use -y flag if available or echo y
        rc, stdout, stderr = self._run_command(cmd)
        if rc == 0 or 'Agent' in stdout:
            return True, f"Agent {agent_id} deleted"
        return False, stderr or stdout

    # ============ Group Operations ============

    def list_groups(self) -> List[Group]:
        """List all groups.

        Returns:
            List of Group objects
        """
        cmd = [self._get_bin('agent_groups'), '-l']
        rc, stdout, stderr = self._run_command(cmd)

        if rc != 0:
            raise RuntimeError(f"Failed to list groups: {stderr}")

        groups = []
        for line in stdout.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('Groups') or line.startswith('---'):
                continue

            # Parse group line - format varies
            # Simple format: just group name
            parts = line.split()
            if parts:
                group_name = parts[0].rstrip(':')
                if group_name and not group_name.startswith('*'):
                    groups.append(Group(name=group_name))

        return groups

    def get_group_agents(self, group_name: str) -> List[Agent]:
        """Get agents in a specific group.

        Args:
            group_name: Group name

        Returns:
            List of Agent objects in the group
        """
        cmd = [self._get_bin('agent_groups'), '-l', '-g', group_name]
        rc, stdout, stderr = self._run_command(cmd)

        if rc != 0:
            return []

        agents = []
        # Parse output to find agent IDs
        for line in stdout.strip().split('\n'):
            line = line.strip()
            # Look for agent entries
            match = re.match(r'ID:\s*(\d+)', line)
            if match:
                agent_id = match.group(1)
                agent_info = self.get_agent_info(agent_id)
                if agent_info:
                    agents.append(agent_info)

        return agents

    def create_group(self, group_name: str, dry_run: bool = False) -> Tuple[bool, str]:
        """Create a new group.

        Args:
            group_name: Group name
            dry_run: If True, only show what would be done

        Returns:
            Tuple of (success, message)
        """
        cmd = [self._get_bin('agent_groups'), '-a', '-g', group_name]

        if dry_run:
            return True, f"[DRY-RUN] Would execute: {' '.join(cmd)}"

        rc, stdout, stderr = self._run_command(cmd)
        if rc == 0:
            return True, f"Group '{group_name}' created"
        return False, stderr or stdout

    def delete_group(self, group_name: str, dry_run: bool = False) -> Tuple[bool, str]:
        """Delete a group.

        Args:
            group_name: Group name
            dry_run: If True, only show what would be done

        Returns:
            Tuple of (success, message)
        """
        cmd = [self._get_bin('agent_groups'), '-r', '-g', group_name]

        if dry_run:
            return True, f"[DRY-RUN] Would execute: {' '.join(cmd)}"

        rc, stdout, stderr = self._run_command(cmd)
        if rc == 0:
            return True, f"Group '{group_name}' deleted"
        return False, stderr or stdout

    def add_agent_to_group(self, agent_id: str, group_name: str,
                           dry_run: bool = False) -> Tuple[bool, str]:
        """Add an agent to a group.

        Args:
            agent_id: Agent ID
            group_name: Group name
            dry_run: If True, only show what would be done

        Returns:
            Tuple of (success, message)
        """
        cmd = [self._get_bin('agent_groups'), '-a', '-i', agent_id, '-g', group_name]

        if dry_run:
            return True, f"[DRY-RUN] Would execute: {' '.join(cmd)}"

        rc, stdout, stderr = self._run_command(cmd)
        if rc == 0 or 'successfully' in stdout.lower():
            return True, f"Agent {agent_id} added to group '{group_name}'"
        return False, stderr or stdout

    def remove_agent_from_group(self, agent_id: str, group_name: str,
                                dry_run: bool = False) -> Tuple[bool, str]:
        """Remove an agent from a group.

        Args:
            agent_id: Agent ID
            group_name: Group name
            dry_run: If True, only show what would be done

        Returns:
            Tuple of (success, message)
        """
        cmd = [self._get_bin('agent_groups'), '-r', '-i', agent_id, '-g', group_name]

        if dry_run:
            return True, f"[DRY-RUN] Would execute: {' '.join(cmd)}"

        rc, stdout, stderr = self._run_command(cmd)
        if rc == 0 or 'successfully' in stdout.lower():
            return True, f"Agent {agent_id} removed from group '{group_name}'"
        return False, stderr or stdout

    # ============ Cluster/Node Operations ============

    def list_nodes(self) -> List[Node]:
        """List cluster nodes.

        Returns:
            List of Node objects
        """
        cmd = [self._get_bin('cluster_control'), '-l']
        rc, stdout, stderr = self._run_command(cmd)

        if rc != 0:
            # Maybe not in cluster mode
            return []

        nodes = []
        for line in stdout.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('Name') or line.startswith('---'):
                continue

            # Parse: name type version ip
            parts = line.split()
            if len(parts) >= 4:
                nodes.append(Node(
                    name=parts[0],
                    node_type=parts[1],
                    version=parts[2],
                    ip=parts[3]
                ))

        return nodes

    def get_node_agents(self, node_name: str) -> List[Agent]:
        """Get agents connected to a specific node.

        Args:
            node_name: Node name

        Returns:
            List of Agent objects connected to this node
        """
        # This requires cluster_control or API
        # For now, we'll get all agents and filter by node
        all_agents = self.list_agents()

        # Get detailed info to get node assignment
        result = []
        for agent in all_agents:
            detailed = self.get_agent_info(agent.id)
            if detailed and detailed.node == node_name:
                result.append(detailed)

        return result

    # ============ Utility Methods ============

    def get_agents_by_status(self, status: str) -> List[Agent]:
        """Get agents filtered by status.

        Args:
            status: Status to filter (Active, Disconnected, Pending, Never connected)

        Returns:
            List of matching Agent objects
        """
        agents = self.list_agents()
        status_lower = status.lower()
        return [a for a in agents if status_lower in a.status.lower()]

    def search_agents(self, pattern: str, field: str = 'name') -> List[Agent]:
        """Search agents by pattern.

        Args:
            pattern: Regex pattern
            field: Field to search (name, ip, id)

        Returns:
            List of matching Agent objects
        """
        agents = self.list_agents()
        regex = re.compile(pattern, re.IGNORECASE)

        result = []
        for agent in agents:
            value = getattr(agent, field, '')
            if regex.search(value):
                result.append(agent)

        return result

    # ============ User/Role Management (CLI) ============

    def list_roles(self) -> List[Dict[str, Any]]:
        """List available roles using wazuh-user CLI.

        Returns:
            List of role dictionaries with id and name
        """
        cmd = [self._get_bin('wazuh-user'), 'list-roles']
        rc, stdout, stderr = self._run_command(cmd)

        if rc != 0:
            return []

        roles = []
        # Parse output - each line is a role name
        for i, line in enumerate(stdout.strip().split('\n')):
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('---'):
                roles.append({
                    'id': i + 1,  # Generate ID based on position
                    'name': line
                })

        return roles

    def show_role(self, role_name: str) -> Dict[str, Any]:
        """Show role details including permissions.

        Args:
            role_name: Name of the role

        Returns:
            Dictionary with role details and permissions
        """
        cmd = [self._get_bin('wazuh-user'), 'show-role', role_name]
        rc, stdout, stderr = self._run_command(cmd)

        if rc != 0:
            return {'name': role_name, 'permissions': [], 'error': stderr or 'Failed to get role details'}

        permissions = []
        for line in stdout.strip().split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                permissions.append(line)

        return {
            'name': role_name,
            'permissions': permissions
        }

    def create_user(self, username: str, password: str) -> Dict[str, Any]:
        """Create a new API user using CLI.

        Args:
            username: Username to create
            password: Password for the user

        Returns:
            Result dictionary with success or error
        """
        # Use wazuh-user add command
        # Format: wazuh-user add <username> -p <password>
        cmd = [self._get_bin('wazuh-user'), 'add', username, '-p', password]
        rc, stdout, stderr = self._run_command(cmd)

        if rc == 0 or 'successfully' in stdout.lower() or 'created' in stdout.lower():
            return {'success': True, 'message': f"User '{username}' created successfully"}

        # Check for common errors
        output = (stdout + stderr).lower()
        if 'already exists' in output:
            return {'error': f"User '{username}' already exists"}
        if 'permission' in output or 'denied' in output:
            return {'error': 'Permission denied. Run as root or with sudo.'}

        return {'error': stderr or stdout or 'Failed to create user'}

    def delete_user(self, username: str) -> Dict[str, Any]:
        """Delete an API user using CLI.

        Args:
            username: Username to delete

        Returns:
            Result dictionary with success or error
        """
        cmd = [self._get_bin('wazuh-user'), 'delete', username]
        rc, stdout, stderr = self._run_command(cmd)

        if rc == 0 or 'successfully' in stdout.lower() or 'deleted' in stdout.lower():
            return {'success': True, 'message': f"User '{username}' deleted successfully"}

        output = (stdout + stderr).lower()
        if 'not found' in output or 'does not exist' in output:
            return {'error': f"User '{username}' not found"}

        return {'error': stderr or stdout or 'Failed to delete user'}

    def assign_user_role(self, username: str, role_name: str) -> Dict[str, Any]:
        """Assign a role to a user using CLI.

        Args:
            username: Username
            role_name: Role name to assign

        Returns:
            Result dictionary with success or error
        """
        cmd = [self._get_bin('wazuh-user'), 'assign-role', username, role_name]
        rc, stdout, stderr = self._run_command(cmd)

        if rc == 0 or 'successfully' in stdout.lower():
            return {'success': True, 'message': f"Role '{role_name}' assigned to '{username}'"}

        return {'error': stderr or stdout or 'Failed to assign role'}

    def list_users(self) -> List[Dict[str, Any]]:
        """List all API users using CLI.

        Returns:
            List of user dictionaries
        """
        cmd = [self._get_bin('wazuh-user'), 'list']
        rc, stdout, stderr = self._run_command(cmd)

        if rc != 0:
            return []

        users = []
        for line in stdout.strip().split('\n'):
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('---') and not line.startswith('Username'):
                # Parse user line - format may vary
                parts = line.split()
                if parts:
                    users.append({
                        'username': parts[0],
                        'roles': parts[1:] if len(parts) > 1 else [],
                        'allow_run_as': False
                    })

        return users

    # ============ Service Status (CLI) ============

    def get_service_status(self) -> List[Dict[str, str]]:
        """Get Wazuh service status using wazuh-control.

        Returns:
            List of service status dictionaries
        """
        cmd = [self._get_bin('wazuh-control'), 'status']
        rc, stdout, stderr = self._run_command(cmd)

        services = []

        if rc != 0 and not stdout:
            return services

        # Parse output like:
        # wazuh-clusterd is running...
        # wazuh-modulesd is running...
        # wazuh-monitord is running...
        for line in stdout.strip().split('\n'):
            line = line.strip()
            if not line:
                continue

            # Parse "service_name is running/stopped..."
            match = re.match(r'^(\S+)\s+is\s+(\w+)', line)
            if match:
                service_name = match.group(1)
                status_word = match.group(2).lower()

                if status_word == 'running':
                    status = 'running'
                elif status_word in ['stopped', 'not']:
                    status = 'stopped'
                else:
                    status = 'unknown'

                services.append({
                    'name': service_name,
                    'status': status
                })

        return services

    def get_cluster_status(self) -> Dict[str, Any]:
        """Get cluster status using cluster_control.

        Returns:
            Dictionary with cluster status information
        """
        # Check if cluster is enabled
        cmd = [self._get_bin('cluster_control'), '-s']
        rc, stdout, stderr = self._run_command(cmd)

        if rc != 0:
            return {'enabled': False, 'error': stderr or 'Cluster not available'}

        # Parse cluster status
        status = {
            'enabled': True,
            'running': False,
            'node_name': '',
            'node_type': '',
            'nodes': []
        }

        for line in stdout.strip().split('\n'):
            line = line.strip().lower()
            if 'running' in line:
                status['running'] = True
            if 'disabled' in line:
                status['enabled'] = False

        # Get node list
        nodes = self.list_nodes()
        status['nodes'] = [n.to_dict() for n in nodes]

        return status
