#!/usr/bin/env python3
"""
Wazuh Agent Manager - A comprehensive CLI tool for managing Wazuh agents.

Usage:
    wazuh_agent_mgr.py agent list [--status=<status>] [--group=<group>] [--node=<node>] [--name=<pattern>] [--ip=<pattern>]
    wazuh_agent_mgr.py agent info <agent_id>
    wazuh_agent_mgr.py agent pending
    wazuh_agent_mgr.py agent disconnected
    wazuh_agent_mgr.py agent never-connected
    wazuh_agent_mgr.py agent active
    wazuh_agent_mgr.py agent restart <agent_ids>... [--dry-run]
    wazuh_agent_mgr.py agent delete <agent_ids>... [--dry-run]
    wazuh_agent_mgr.py agent health
    wazuh_agent_mgr.py agent duplicate [--by=<field>]
    wazuh_agent_mgr.py agent export [--format=<format>]

    wazuh_agent_mgr.py group list
    wazuh_agent_mgr.py group show <group_name>
    wazuh_agent_mgr.py group create <group_name> [--dry-run]
    wazuh_agent_mgr.py group delete <group_name> [--dry-run]
    wazuh_agent_mgr.py group add-agent <group_name> <agent_ids>... [--dry-run]
    wazuh_agent_mgr.py group remove-agent <group_name> <agent_ids>... [--dry-run]

    wazuh_agent_mgr.py node list
    wazuh_agent_mgr.py node show <node_name>
    wazuh_agent_mgr.py node agents <node_name>
    wazuh_agent_mgr.py node reconnect <agent_ids>... [--dry-run]
    wazuh_agent_mgr.py node migrate --from=<node> [--to=<node>] [--dry-run]

    wazuh_agent_mgr.py stats summary
    wazuh_agent_mgr.py stats by-status
    wazuh_agent_mgr.py stats by-group
    wazuh_agent_mgr.py stats by-node
    wazuh_agent_mgr.py stats by-os
    wazuh_agent_mgr.py stats by-version
    wazuh_agent_mgr.py stats report

    wazuh_agent_mgr.py --web [--host=<host>] [--port=<port>] [--ssl-auto]
    wazuh_agent_mgr.py --web --ssl-cert=<cert> --ssl-key=<key>

Options:
    -h --help           Show this help message
    --version           Show version
    --format=<format>   Output format: table, json, csv [default: table]
    --dry-run           Show what would be done without making changes
    --web               Start web interface
    --host=<host>       Web server host [default: 0.0.0.0]
    --port=<port>       Web server port [default: 5000]
    --ssl-auto          Auto-generate self-signed certificate (1 year validity)
    --ssl-cert=<cert>   SSL certificate file for HTTPS
    --ssl-key=<key>     SSL private key file for HTTPS
    --config=<path>     Path to config file

Environment Variables (for HTTPS):
    WEB_SSL_CERT        SSL certificate file path (alternative to --ssl-cert)
    WEB_SSL_KEY         SSL private key file path (alternative to --ssl-key)
    WEB_SSL_AUTO        Set to 'true' for auto-generate (alternative to --ssl-auto)
"""

import sys
import argparse
from typing import List, Optional

# Add lib to path
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib.config import get_config
from lib.wazuh_cli import WazuhCLI
from lib.agent_ops import AgentOperations
from lib.group_ops import GroupOperations
from lib.node_ops import NodeOperations
from lib.stats import StatisticsOperations
from lib.output import get_formatter, OutputFormatter


class WazuhAgentManager:
    """Main application class."""

    def __init__(self, config_path: Optional[str] = None, output_format: str = 'table'):
        """Initialize the manager.

        Args:
            config_path: Path to config file
            output_format: Output format (table, json, csv)
        """
        self.config = get_config(config_path)
        self.cli = WazuhCLI(self.config)
        self.agent_ops = AgentOperations(self.cli)
        self.group_ops = GroupOperations(self.cli)
        self.node_ops = NodeOperations(self.cli)
        self.stats_ops = StatisticsOperations(self.cli)
        self.formatter = get_formatter(output_format)

    # ============ Agent Commands ============

    def agent_list(self, status: str = None, group: str = None, node: str = None,
                   name: str = None, ip: str = None):
        """List agents with optional filters."""
        agents = self.agent_ops.list_agents(
            status=status, group=group, node=node,
            name=name, ip=ip, detailed=True
        )
        columns = ['id', 'name', 'ip', 'status', 'os', 'version', 'group', 'node']
        self.formatter.output(agents, columns, title=f"Agents ({len(agents)})")

    def agent_info(self, agent_id: str):
        """Show agent details."""
        info = self.agent_ops.get_agent_info(agent_id)
        if info:
            self.formatter.output(info)
        else:
            self.formatter.print_error(f"Agent {agent_id} not found")

    def agent_pending(self):
        """List pending agents."""
        agents = self.agent_ops.get_pending_agents()
        self.formatter.output(agents, ['id', 'name', 'ip', 'status'],
                            title=f"Pending Agents ({len(agents)})")

    def agent_disconnected(self):
        """List disconnected agents."""
        agents = self.agent_ops.get_disconnected_agents()
        self.formatter.output(agents, ['id', 'name', 'ip', 'status'],
                            title=f"Disconnected Agents ({len(agents)})")

    def agent_never_connected(self):
        """List never connected agents."""
        agents = self.agent_ops.get_never_connected_agents()
        self.formatter.output(agents, ['id', 'name', 'ip', 'status'],
                            title=f"Never Connected Agents ({len(agents)})")

    def agent_active(self):
        """List active agents."""
        agents = self.agent_ops.get_active_agents()
        self.formatter.output(agents, ['id', 'name', 'ip', 'status'],
                            title=f"Active Agents ({len(agents)})")

    def agent_restart(self, agent_ids: List[str], dry_run: bool = False):
        """Restart agents."""
        results = self.agent_ops.restart_agents(agent_ids, dry_run)
        for agent_id, success, message in results:
            if success:
                self.formatter.print_success(message)
            else:
                self.formatter.print_error(f"Agent {agent_id}: {message}")

    def agent_delete(self, agent_ids: List[str], dry_run: bool = False):
        """Delete agents."""
        if not dry_run:
            self.formatter.print_warning(f"About to delete {len(agent_ids)} agent(s)")
            if not self.formatter.confirm("Are you sure?"):
                self.formatter.print_info("Cancelled")
                return

        results = self.agent_ops.delete_agents(agent_ids, dry_run)
        for agent_id, success, message in results:
            if success:
                self.formatter.print_success(message)
            else:
                self.formatter.print_error(f"Agent {agent_id}: {message}")

    def agent_health(self):
        """Show agent health report."""
        report = self.agent_ops.health_check()

        self.formatter.print_summary("Health Check Summary", {
            'Total Agents': report['total_agents'],
            'Issues Found': report['issues_count'],
            'Duplicate IPs': report['duplicate_ips'],
            'Duplicate Names': report['duplicate_names']
        })

        if report['issues']:
            issues_data = [{'type': i['type'], 'severity': i['severity'],
                          'message': i['message']} for i in report['issues']]
            self.formatter.output(issues_data, title="Issues")

    def agent_duplicate(self, by: str = 'ip'):
        """Find duplicate agents."""
        duplicates = self.agent_ops.find_duplicate_agents(by)

        if not duplicates:
            self.formatter.print_success(f"No duplicate agents found by {by}")
            return

        for key, agents in duplicates.items():
            self.formatter.print_warning(f"Duplicate {by}: {key}")
            self.formatter.output(agents, ['id', 'name', 'ip', 'status'])

    def agent_export(self, format_type: str = 'csv'):
        """Export agents."""
        output = self.agent_ops.export_agents(format_type)
        print(output)

    # ============ Group Commands ============

    def group_list(self):
        """List all groups."""
        groups = self.group_ops.list_groups()
        self.formatter.output(groups, ['name', 'agent_count'],
                            title=f"Groups ({len(groups)})")

    def group_show(self, group_name: str):
        """Show group details."""
        info = self.group_ops.get_group_info(group_name)
        if info:
            self.formatter.print_summary(f"Group: {group_name}", {
                'Agent Count': info['agent_count']
            })
            if info['agents']:
                self.formatter.output(info['agents'], ['id', 'name', 'ip', 'status'])
        else:
            self.formatter.print_error(f"Group {group_name} not found")

    def group_create(self, group_name: str, dry_run: bool = False):
        """Create a group."""
        success, message = self.group_ops.create_group(group_name, dry_run)
        if success:
            self.formatter.print_success(message)
        else:
            self.formatter.print_error(message)

    def group_delete(self, group_name: str, dry_run: bool = False):
        """Delete a group."""
        if not dry_run:
            if not self.formatter.confirm(f"Delete group '{group_name}'?"):
                self.formatter.print_info("Cancelled")
                return

        success, message = self.group_ops.delete_group(group_name, dry_run)
        if success:
            self.formatter.print_success(message)
        else:
            self.formatter.print_error(message)

    def group_add_agent(self, group_name: str, agent_ids: List[str], dry_run: bool = False):
        """Add agents to a group."""
        results = self.group_ops.add_agents_to_group(agent_ids, group_name, dry_run)
        for agent_id, success, message in results:
            if success:
                self.formatter.print_success(message)
            else:
                self.formatter.print_error(f"Agent {agent_id}: {message}")

    def group_remove_agent(self, group_name: str, agent_ids: List[str], dry_run: bool = False):
        """Remove agents from a group."""
        results = self.group_ops.remove_agents_from_group(agent_ids, group_name, dry_run)
        for agent_id, success, message in results:
            if success:
                self.formatter.print_success(message)
            else:
                self.formatter.print_error(f"Agent {agent_id}: {message}")

    # ============ Node Commands ============

    def node_list(self):
        """List all nodes."""
        nodes = self.node_ops.list_nodes()
        if not nodes:
            self.formatter.print_info("Cluster not configured or not running")
            return
        self.formatter.output(nodes, ['name', 'type', 'version', 'ip'],
                            title=f"Cluster Nodes ({len(nodes)})")

    def node_show(self, node_name: str):
        """Show node details."""
        info = self.node_ops.get_node_info(node_name)
        if info:
            self.formatter.print_summary(f"Node: {node_name}", {
                'Type': info.get('type', 'unknown'),
                'Version': info.get('version', 'unknown'),
                'IP': info.get('ip', 'unknown'),
                'Agent Count': info.get('agent_count', 0)
            })
        else:
            self.formatter.print_error(f"Node {node_name} not found")

    def node_agents(self, node_name: str):
        """List agents on a node."""
        agents = self.node_ops.get_node_agents(node_name)
        self.formatter.output(agents, ['id', 'name', 'ip', 'status'],
                            title=f"Agents on {node_name} ({len(agents)})")

    def node_reconnect(self, agent_ids: List[str], dry_run: bool = False):
        """Reconnect agents."""
        results = self.node_ops.reconnect_agents(agent_ids, dry_run)
        for agent_id, success, message in results:
            if success:
                self.formatter.print_success(message)
            else:
                self.formatter.print_error(f"Agent {agent_id}: {message}")

    def node_migrate(self, from_node: str, to_node: str = None, dry_run: bool = False):
        """Migrate agents from one node."""
        results = self.node_ops.migrate_node_agents(from_node, to_node, dry_run)
        for agent_id, success, message in results:
            if success:
                self.formatter.print_success(message)
            else:
                self.formatter.print_error(f"Agent {agent_id}: {message}")

    # ============ Stats Commands ============

    def stats_summary(self):
        """Show summary statistics."""
        summary = self.stats_ops.get_summary()
        self.formatter.print_summary("Agent Statistics", {
            'Total Agents': summary['total_agents'],
            'Active Agents': f"{summary['active_agents']} ({summary['active_percentage']}%)",
            'Total Groups': summary['total_groups'],
            'Total Nodes': summary['total_nodes'],
            'Cluster Enabled': 'Yes' if summary['cluster_enabled'] else 'No'
        })

        if summary['status_breakdown']:
            self.formatter.output(
                [{'status': k, 'count': v} for k, v in summary['status_breakdown'].items()],
                title="Status Breakdown"
            )

    def stats_by_status(self):
        """Show stats by status."""
        stats = self.stats_ops.get_stats_by_status()
        self.formatter.output(stats, ['status', 'count', 'percentage'],
                            title="Agents by Status")

    def stats_by_group(self):
        """Show stats by group."""
        stats = self.stats_ops.get_stats_by_group()
        self.formatter.output(stats, ['group', 'count', 'percentage', 'active_count'],
                            title="Agents by Group")

    def stats_by_node(self):
        """Show stats by node."""
        stats = self.stats_ops.get_stats_by_node()
        self.formatter.output(stats, ['node', 'type', 'count', 'percentage'],
                            title="Agents by Node")

    def stats_by_os(self):
        """Show stats by OS."""
        stats = self.stats_ops.get_stats_by_os()
        self.formatter.output(stats, ['os', 'count', 'percentage'],
                            title="Agents by OS")

    def stats_by_version(self):
        """Show stats by version."""
        stats = self.stats_ops.get_stats_by_version()
        self.formatter.output(stats, ['version', 'count', 'percentage'],
                            title="Agents by Version")

    def stats_report(self):
        """Show full statistics report."""
        self.stats_summary()
        print()
        self.stats_by_status()
        print()
        self.stats_by_group()
        print()
        self.stats_by_os()


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser."""
    # Common arguments for all subcommands
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument('-f', '--format', choices=['table', 'json', 'csv'], default='table',
                               help='Output format (default: table)')
    common_parser.add_argument('--config', help='Path to config file')

    parser = argparse.ArgumentParser(
        prog='wazuh_agent_mgr',
        description='Wazuh Agent Manager - Comprehensive CLI tool for managing Wazuh agents',
        parents=[common_parser]
    )
    from lib import __version__
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    parser.add_argument('--web', action='store_true', help='Start web interface')
    parser.add_argument('--host', default='0.0.0.0', help='Web server host (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=5000, help='Web server port (default: 5000)')
    parser.add_argument('--ssl-cert', help='SSL certificate file path for HTTPS')
    parser.add_argument('--ssl-key', help='SSL private key file path for HTTPS')
    parser.add_argument('--ssl-auto', action='store_true', help='Auto-generate self-signed certificate if missing or expired')
    parser.add_argument('--max-login-attempts', type=int, default=3, help='Max login attempts before IP lockout (default: 3)')
    parser.add_argument('--lockout-minutes', type=int, default=30, help='IP lockout duration in minutes (default: 30)')

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Agent commands
    agent_parser = subparsers.add_parser('agent', help='Agent operations', parents=[common_parser])
    agent_sub = agent_parser.add_subparsers(dest='agent_action')

    # agent list
    agent_list = agent_sub.add_parser('list', help='List agents', parents=[common_parser])
    agent_list.add_argument('--status', help='Filter by status (regex)')
    agent_list.add_argument('--group', help='Filter by group (regex)')
    agent_list.add_argument('--node', help='Filter by node (regex)')
    agent_list.add_argument('--name', help='Filter by name (regex)')
    agent_list.add_argument('--ip', help='Filter by IP (regex)')

    # agent info
    agent_info = agent_sub.add_parser('info', help='Show agent details', parents=[common_parser])
    agent_info.add_argument('agent_id', help='Agent ID')

    # agent status shortcuts
    agent_sub.add_parser('pending', help='List pending agents', parents=[common_parser])
    agent_sub.add_parser('disconnected', help='List disconnected agents', parents=[common_parser])
    agent_sub.add_parser('never-connected', help='List never connected agents', parents=[common_parser])
    agent_sub.add_parser('active', help='List active agents', parents=[common_parser])

    # agent restart
    agent_restart = agent_sub.add_parser('restart', help='Restart agents', parents=[common_parser])
    agent_restart.add_argument('agent_ids', nargs='+', help='Agent IDs')
    agent_restart.add_argument('--dry-run', action='store_true', help='Dry run mode')

    # agent delete
    agent_delete = agent_sub.add_parser('delete', help='Delete agents', parents=[common_parser])
    agent_delete.add_argument('agent_ids', nargs='+', help='Agent IDs')
    agent_delete.add_argument('--dry-run', action='store_true', help='Dry run mode')

    # agent health
    agent_sub.add_parser('health', help='Show health report', parents=[common_parser])

    # agent duplicate
    agent_dup = agent_sub.add_parser('duplicate', help='Find duplicate agents', parents=[common_parser])
    agent_dup.add_argument('--by', choices=['ip', 'name'], default='ip',
                          help='Field to check for duplicates')

    # agent export
    agent_export = agent_sub.add_parser('export', help='Export agents', parents=[common_parser])

    # Group commands
    group_parser = subparsers.add_parser('group', help='Group operations', parents=[common_parser])
    group_sub = group_parser.add_subparsers(dest='group_action')

    group_sub.add_parser('list', help='List groups', parents=[common_parser])

    group_show = group_sub.add_parser('show', help='Show group details', parents=[common_parser])
    group_show.add_argument('group_name', help='Group name')

    group_create = group_sub.add_parser('create', help='Create group', parents=[common_parser])
    group_create.add_argument('group_name', help='Group name')
    group_create.add_argument('--dry-run', action='store_true', help='Dry run mode')

    group_delete = group_sub.add_parser('delete', help='Delete group', parents=[common_parser])
    group_delete.add_argument('group_name', help='Group name')
    group_delete.add_argument('--dry-run', action='store_true', help='Dry run mode')

    group_add = group_sub.add_parser('add-agent', help='Add agents to group', parents=[common_parser])
    group_add.add_argument('group_name', help='Group name')
    group_add.add_argument('agent_ids', nargs='+', help='Agent IDs')
    group_add.add_argument('--dry-run', action='store_true', help='Dry run mode')

    group_remove = group_sub.add_parser('remove-agent', help='Remove agents from group', parents=[common_parser])
    group_remove.add_argument('group_name', help='Group name')
    group_remove.add_argument('agent_ids', nargs='+', help='Agent IDs')
    group_remove.add_argument('--dry-run', action='store_true', help='Dry run mode')

    # Node commands
    node_parser = subparsers.add_parser('node', help='Node operations', parents=[common_parser])
    node_sub = node_parser.add_subparsers(dest='node_action')

    node_sub.add_parser('list', help='List nodes', parents=[common_parser])

    node_show = node_sub.add_parser('show', help='Show node details', parents=[common_parser])
    node_show.add_argument('node_name', help='Node name')

    node_agents = node_sub.add_parser('agents', help='List agents on node', parents=[common_parser])
    node_agents.add_argument('node_name', help='Node name')

    node_reconnect = node_sub.add_parser('reconnect', help='Reconnect agents', parents=[common_parser])
    node_reconnect.add_argument('agent_ids', nargs='+', help='Agent IDs')
    node_reconnect.add_argument('--dry-run', action='store_true', help='Dry run mode')

    node_migrate = node_sub.add_parser('migrate', help='Migrate agents from node', parents=[common_parser])
    node_migrate.add_argument('--from', dest='from_node', required=True, help='Source node')
    node_migrate.add_argument('--to', dest='to_node', help='Target node (informational)')
    node_migrate.add_argument('--dry-run', action='store_true', help='Dry run mode')

    # Stats commands
    stats_parser = subparsers.add_parser('stats', help='Statistics', parents=[common_parser])
    stats_sub = stats_parser.add_subparsers(dest='stats_action')

    stats_sub.add_parser('summary', help='Show summary', parents=[common_parser])
    stats_sub.add_parser('by-status', help='Stats by status', parents=[common_parser])
    stats_sub.add_parser('by-group', help='Stats by group', parents=[common_parser])
    stats_sub.add_parser('by-node', help='Stats by node', parents=[common_parser])
    stats_sub.add_parser('by-os', help='Stats by OS', parents=[common_parser])
    stats_sub.add_parser('by-version', help='Stats by version', parents=[common_parser])
    stats_sub.add_parser('report', help='Full report', parents=[common_parser])

    return parser


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    # Start web interface if requested
    if args.web:
        try:
            from lib.web_ui import run_web_server
            run_web_server(
                host=args.host,
                port=args.port,
                max_login_attempts=args.max_login_attempts,
                lockout_minutes=args.lockout_minutes,
                ssl_cert=args.ssl_cert,
                ssl_key=args.ssl_key,
                ssl_auto=args.ssl_auto
            )
        except ImportError as e:
            print(f"Error: {e}")
            print("Install Flask with: pip install flask")
            sys.exit(1)
        return

    # Show help if no command
    if not args.command:
        parser.print_help()
        return

    # Initialize manager
    try:
        mgr = WazuhAgentManager(config_path=args.config, output_format=args.format)
    except Exception as e:
        print(f"Error initializing: {e}", file=sys.stderr)
        sys.exit(1)

    # Route commands
    try:
        if args.command == 'agent':
            if args.agent_action == 'list':
                mgr.agent_list(status=args.status, group=args.group, node=args.node,
                              name=args.name, ip=args.ip)
            elif args.agent_action == 'info':
                mgr.agent_info(args.agent_id)
            elif args.agent_action == 'pending':
                mgr.agent_pending()
            elif args.agent_action == 'disconnected':
                mgr.agent_disconnected()
            elif args.agent_action == 'never-connected':
                mgr.agent_never_connected()
            elif args.agent_action == 'active':
                mgr.agent_active()
            elif args.agent_action == 'restart':
                mgr.agent_restart(args.agent_ids, dry_run=args.dry_run)
            elif args.agent_action == 'delete':
                mgr.agent_delete(args.agent_ids, dry_run=args.dry_run)
            elif args.agent_action == 'health':
                mgr.agent_health()
            elif args.agent_action == 'duplicate':
                mgr.agent_duplicate(by=args.by)
            elif args.agent_action == 'export':
                mgr.agent_export(format_type=args.format)
            else:
                parser.parse_args(['agent', '-h'])

        elif args.command == 'group':
            if args.group_action == 'list':
                mgr.group_list()
            elif args.group_action == 'show':
                mgr.group_show(args.group_name)
            elif args.group_action == 'create':
                mgr.group_create(args.group_name, dry_run=args.dry_run)
            elif args.group_action == 'delete':
                mgr.group_delete(args.group_name, dry_run=args.dry_run)
            elif args.group_action == 'add-agent':
                mgr.group_add_agent(args.group_name, args.agent_ids, dry_run=args.dry_run)
            elif args.group_action == 'remove-agent':
                mgr.group_remove_agent(args.group_name, args.agent_ids, dry_run=args.dry_run)
            else:
                parser.parse_args(['group', '-h'])

        elif args.command == 'node':
            if args.node_action == 'list':
                mgr.node_list()
            elif args.node_action == 'show':
                mgr.node_show(args.node_name)
            elif args.node_action == 'agents':
                mgr.node_agents(args.node_name)
            elif args.node_action == 'reconnect':
                mgr.node_reconnect(args.agent_ids, dry_run=args.dry_run)
            elif args.node_action == 'migrate':
                mgr.node_migrate(args.from_node, args.to_node, dry_run=args.dry_run)
            else:
                parser.parse_args(['node', '-h'])

        elif args.command == 'stats':
            if args.stats_action == 'summary':
                mgr.stats_summary()
            elif args.stats_action == 'by-status':
                mgr.stats_by_status()
            elif args.stats_action == 'by-group':
                mgr.stats_by_group()
            elif args.stats_action == 'by-node':
                mgr.stats_by_node()
            elif args.stats_action == 'by-os':
                mgr.stats_by_os()
            elif args.stats_action == 'by-version':
                mgr.stats_by_version()
            elif args.stats_action == 'report':
                mgr.stats_report()
            else:
                parser.parse_args(['stats', '-h'])

    except KeyboardInterrupt:
        print("\nCancelled")
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
