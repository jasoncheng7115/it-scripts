#!/usr/bin/env python3
"""Wazuh API wrapper for operations that require API access."""

import json
import urllib3
from typing import List, Dict, Any, Optional, Tuple
from .config import get_config

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class WazuhAPIError(Exception):
    """Wazuh API error."""
    pass


class WazuhAPI:
    """Wrapper for Wazuh API operations."""

    def __init__(self, config=None):
        """Initialize WazuhAPI.

        Args:
            config: Config instance. If None, uses global config.
        """
        if not HAS_REQUESTS:
            raise ImportError("requests library is required for API operations")

        self.config = config or get_config()
        self._token: Optional[str] = None

    def _get_token(self) -> str:
        """Get or refresh authentication token.

        Returns:
            JWT token string
        """
        if self._token:
            return self._token

        url = f"{self.config.api_base_url}/security/user/authenticate"

        try:
            response = requests.post(
                url,
                auth=(self.config.api_username, self.config.api_password),
                verify=self.config.api_verify_ssl,
                timeout=30
            )
            response.raise_for_status()

            data = response.json()
            self._token = data.get('data', {}).get('token')

            if not self._token:
                raise WazuhAPIError("Failed to get authentication token")

            return self._token

        except requests.exceptions.RequestException as e:
            raise WazuhAPIError(f"Authentication failed: {e}")

    def _request(self, method: str, endpoint: str,
                 data: Optional[Dict] = None,
                 params: Optional[Dict] = None) -> Dict[str, Any]:
        """Make authenticated API request.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint (e.g., /agents)
            data: Request body data
            params: Query parameters

        Returns:
            Response JSON data
        """
        url = f"{self.config.api_base_url}{endpoint}"
        headers = {
            'Authorization': f'Bearer {self._get_token()}',
            'Content-Type': 'application/json'
        }

        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=data,
                params=params,
                verify=self.config.api_verify_ssl,
                timeout=60
            )

            # Handle token expiration
            if response.status_code == 401:
                self._token = None
                headers['Authorization'] = f'Bearer {self._get_token()}'
                response = requests.request(
                    method=method,
                    url=url,
                    headers=headers,
                    json=data,
                    params=params,
                    verify=self.config.api_verify_ssl,
                    timeout=60
                )

            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            raise WazuhAPIError(f"API request failed: {e}")

    # ============ Agent Reconnect Operations ============

    def reconnect_agent(self, agent_id: str, dry_run: bool = False) -> Tuple[bool, str]:
        """Force agent to reconnect.

        Args:
            agent_id: Agent ID
            dry_run: If True, only show what would be done

        Returns:
            Tuple of (success, message)
        """
        if dry_run:
            return True, f"[DRY-RUN] Would call API: PUT /agents/{agent_id}/reconnect"

        try:
            result = self._request('PUT', f'/agents/{agent_id}/reconnect')
            return True, f"Agent {agent_id} reconnect requested"
        except WazuhAPIError as e:
            return False, str(e)

    def reconnect_agents(self, agent_ids: List[str],
                         dry_run: bool = False) -> List[Tuple[str, bool, str]]:
        """Force multiple agents to reconnect.

        Args:
            agent_ids: List of agent IDs
            dry_run: If True, only show what would be done

        Returns:
            List of (agent_id, success, message) tuples
        """
        results = []

        if dry_run:
            for agent_id in agent_ids:
                results.append((agent_id, True,
                               f"[DRY-RUN] Would call API: PUT /agents/{agent_id}/reconnect"))
            return results

        # Use batch endpoint if available
        try:
            params = {'agents_list': ','.join(agent_ids)}
            result = self._request('PUT', '/agents/reconnect', params=params)

            # Process results
            affected = result.get('data', {}).get('affected_items', [])
            failed = result.get('data', {}).get('failed_items', [])

            for agent_id in agent_ids:
                if agent_id in [str(a.get('id', a)) for a in affected]:
                    results.append((agent_id, True, "Reconnect requested"))
                else:
                    error = next((f.get('error', {}).get('message', 'Unknown error')
                                 for f in failed if str(f.get('id', '')) == agent_id), 'Failed')
                    results.append((agent_id, False, error))

        except WazuhAPIError as e:
            # Fallback to individual requests
            for agent_id in agent_ids:
                success, msg = self.reconnect_agent(agent_id)
                results.append((agent_id, success, msg))

        return results

    # ============ Agent Upgrade Operations ============

    def upgrade_agent(self, agent_id: str, version: Optional[str] = None,
                      force: bool = False) -> Dict[str, Any]:
        """Upgrade an agent to specified version or latest.

        Args:
            agent_id: Agent ID
            version: Target version (None for latest)
            force: Force upgrade even if same version

        Returns:
            Result dictionary with success or error
        """
        try:
            params = {}
            if force:
                params['force'] = 'true'

            if version:
                # Upgrade to specific version
                params['version'] = version
                result = self._request('PUT', f'/agents/{agent_id}/upgrade', params=params)
            else:
                # Upgrade to latest
                result = self._request('PUT', f'/agents/{agent_id}/upgrade', params=params)

            # Check for errors in response
            if result.get('data', {}).get('failed_items'):
                failed = result['data']['failed_items']
                if failed:
                    error_msg = failed[0].get('error', {}).get('message', 'Unknown error')
                    return {'error': error_msg}

            return {'success': True, 'result': result}

        except WazuhAPIError as e:
            return {'error': str(e)}

    def upgrade_agents(self, agent_ids: List[str], version: Optional[str] = None,
                       force: bool = False) -> Dict[str, Any]:
        """Upgrade multiple agents.

        Args:
            agent_ids: List of agent IDs
            version: Target version (None for latest)
            force: Force upgrade even if same version

        Returns:
            Result dictionary with affected_items and failed_items
        """
        try:
            params = {
                'agents_list': ','.join(agent_ids)
            }
            if force:
                params['force'] = 'true'
            if version:
                params['version'] = version

            result = self._request('PUT', '/agents/upgrade', params=params)
            return result

        except WazuhAPIError as e:
            return {'error': str(e)}

    def get_upgrade_result(self, agent_ids: Optional[List[str]] = None) -> Dict[str, Any]:
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

            result = self._request('GET', '/agents/upgrade_result', params=params)
            return result

        except WazuhAPIError as e:
            return {'error': str(e)}

    # ============ Agent Information via API ============

    def get_agents(self, status: Optional[str] = None,
                   node_name: Optional[str] = None,
                   group: Optional[str] = None,
                   limit: int = 500,
                   offset: int = 0) -> List[Dict[str, Any]]:
        """Get agents list via API.

        Args:
            status: Filter by status
            node_name: Filter by node
            group: Filter by group
            limit: Max results
            offset: Results offset

        Returns:
            List of agent dictionaries
        """
        params = {
            'limit': limit,
            'offset': offset
        }

        if status:
            params['status'] = status
        if node_name:
            params['node_name'] = node_name
        if group:
            params['group'] = group

        result = self._request('GET', '/agents', params=params)
        return result.get('data', {}).get('affected_items', [])

    def get_agents_by_node(self, node_name: str) -> List[Dict[str, Any]]:
        """Get all agents connected to a specific node.

        Args:
            node_name: Node name

        Returns:
            List of agent dictionaries
        """
        return self.get_agents(node_name=node_name)

    # ============ Cluster Information via API ============

    def get_cluster_nodes(self) -> List[Dict[str, Any]]:
        """Get cluster nodes via API.

        Returns:
            List of node dictionaries
        """
        try:
            result = self._request('GET', '/cluster/nodes')
            return result.get('data', {}).get('affected_items', [])
        except WazuhAPIError:
            return []

    def get_nodes(self) -> List[Dict[str, Any]]:
        """Get nodes list, supporting both cluster and single-node modes.

        Returns:
            List of node dictionaries with name, type, version, ip
        """
        nodes = self.get_cluster_nodes()

        if nodes:
            # Cluster mode - return cluster nodes
            return [
                {
                    'name': n.get('name', 'unknown'),
                    'type': n.get('type', 'unknown'),
                    'version': n.get('version', ''),
                    'ip': n.get('ip', '')
                }
                for n in nodes
            ]

        # Single node mode - get manager info
        try:
            result = self._request('GET', '/manager/info')
            info = result.get('data', {}).get('affected_items', [{}])[0]
            return [{
                'name': info.get('name', 'manager'),
                'type': 'master',
                'version': info.get('version', ''),
                'ip': 'localhost'
            }]
        except WazuhAPIError:
            # Fallback
            return [{
                'name': 'manager',
                'type': 'master',
                'version': '',
                'ip': 'localhost'
            }]

    def get_cluster_status(self) -> Dict[str, Any]:
        """Get cluster status.

        Returns:
            Cluster status dictionary
        """
        try:
            result = self._request('GET', '/cluster/status')
            return result.get('data', {})
        except WazuhAPIError:
            return {}

    def get_manager_status(self) -> List[Dict[str, str]]:
        """Get manager daemon status via API.

        Returns:
            List of service status dictionaries
        """
        try:
            result = self._request('GET', '/manager/status')
            daemons = result.get('data', {}).get('affected_items', [])

            services = []
            if daemons:
                # daemons is a list with one dict containing daemon statuses
                daemon_dict = daemons[0] if daemons else {}
                for daemon_name, status in daemon_dict.items():
                    services.append({
                        'name': daemon_name,
                        'status': status.lower() if status else 'unknown'
                    })

            return services
        except WazuhAPIError as e:
            print(f"[WazuhAPI] Failed to get manager status: {e}")
            return []

    def get_nodes_status(self) -> Dict[str, List[Dict[str, str]]]:
        """Get status for all nodes in cluster.

        Returns:
            Dictionary mapping node names to service status lists
        """
        result = {}

        # Get nodes using get_nodes() to ensure consistent naming
        nodes = self.get_nodes()

        for node in nodes:
            node_name = node.get('name', 'manager')
            node_type = node.get('type', 'master')

            # Try to get manager/daemon status
            services = self.get_manager_status()

            if services:
                result[node_name] = services
            elif node_type == 'master':
                # If no services returned, try cluster endpoint
                try:
                    api_result = self._request('GET', f'/cluster/{node_name}/status')
                    daemons = api_result.get('data', {}).get('affected_items', [])
                    if daemons:
                        daemon_dict = daemons[0] if daemons else {}
                        services = []
                        for daemon_name, status in daemon_dict.items():
                            services.append({
                                'name': daemon_name,
                                'status': status.lower() if status else 'unknown'
                            })
                        result[node_name] = services
                except WazuhAPIError:
                    result[node_name] = [{'name': 'Unknown', 'status': 'unknown'}]
            else:
                # Worker nodes - would need remote access
                result[node_name] = [{'name': 'Remote', 'status': 'unknown'}]

        return result

    # ============ User Management ============

    def get_users(self) -> List[Dict[str, Any]]:
        """Get all API users.

        Returns:
            List of user dictionaries
        """
        try:
            result = self._request('GET', '/security/users')
            users = result.get('data', {}).get('affected_items', [])
            # Transform to simpler format
            return [{
                'user_id': u.get('id'),
                'username': u.get('username'),
                'roles': [r.get('name') for r in u.get('roles', [])],
                'role_ids': [r.get('id') for r in u.get('roles', [])],
                'allow_run_as': u.get('allow_run_as', False)
            } for u in users]
        except WazuhAPIError as e:
            return []

    def get_roles(self) -> List[Dict[str, Any]]:
        """Get all available roles.

        Returns:
            List of role dictionaries
        """
        try:
            result = self._request('GET', '/security/roles')
            roles = result.get('data', {}).get('affected_items', [])
            return [{'id': r.get('id'), 'name': r.get('name')} for r in roles]
        except WazuhAPIError as e:
            print(f"[WazuhAPI] Failed to get roles: {e}")
            return []

    def create_user(self, username: str, password: str) -> Dict[str, Any]:
        """Create a new API user.

        Args:
            username: Username
            password: Password

        Returns:
            Result dictionary
        """
        try:
            result = self._request('POST', '/security/users', data={
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
                return {'error': 'Failed to create user'}
        except WazuhAPIError as e:
            return {'error': str(e)}

    def delete_user(self, username: str) -> Dict[str, Any]:
        """Delete an API user.

        Args:
            username: Username to delete

        Returns:
            Result dictionary
        """
        try:
            # First get user ID from username
            users = self.get_users()
            user_id = None
            for u in users:
                if u.get('username') == username:
                    user_id = u.get('user_id')
                    break

            if user_id is None:
                return {'error': f'User "{username}" not found'}

            result = self._request('DELETE', '/security/users', params={'user_ids': str(user_id)})
            if result.get('data', {}).get('affected_items'):
                return {'success': True}
            else:
                failed = result.get('data', {}).get('failed_items', [])
                if failed:
                    error_msg = failed[0].get('error', {}).get('message', 'Unknown error')
                    return {'error': error_msg}
                return {'error': 'Failed to delete user'}
        except WazuhAPIError as e:
            return {'error': str(e)}

    def assign_user_role(self, user_id: int, role_id: int) -> Dict[str, Any]:
        """Assign a role to a user.

        Args:
            user_id: User ID (numeric)
            role_id: Role ID to assign

        Returns:
            Result dictionary
        """
        try:
            result = self._request('POST', f'/security/users/{user_id}/roles',
                                  params={'role_ids': role_id})
            return {'success': True}
        except WazuhAPIError as e:
            return {'error': str(e)}

    def remove_user_role(self, user_id: int, role_id: int) -> Dict[str, Any]:
        """Remove a role from a user.

        Args:
            user_id: User ID (numeric)
            role_id: Role ID to remove

        Returns:
            Result dictionary
        """
        try:
            result = self._request('DELETE', f'/security/users/{user_id}/roles',
                                  params={'role_ids': role_id})
            return {'success': True}
        except WazuhAPIError as e:
            return {'error': str(e)}


def get_api(config=None) -> Optional[WazuhAPI]:
    """Get WazuhAPI instance if API is enabled and available.

    Args:
        config: Config instance

    Returns:
        WazuhAPI instance or None
    """
    config = config or get_config()

    if not config.api_enabled:
        return None

    if not HAS_REQUESTS:
        return None

    try:
        return WazuhAPI(config)
    except Exception:
        return None
