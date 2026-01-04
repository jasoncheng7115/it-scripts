#!/usr/bin/env python3
"""Output formatting for Wazuh Agent Manager."""

import csv
import io
import json
import sys
from typing import List, Dict, Any, Optional, Union
from .config import get_config

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False


class OutputFormatter:
    """Format and display output in various formats."""

    # Status color mapping
    STATUS_COLORS = {
        'active': 'green',
        'disconnected': 'red',
        'pending': 'yellow',
        'never connected': 'dim',
        'never_connected': 'dim'
    }

    def __init__(self, format_type: Optional[str] = None):
        """Initialize formatter.

        Args:
            format_type: Output format (table, json, csv). If None, uses config default.
        """
        config = get_config()
        self.format_type = format_type or config.output_format
        self.console = Console() if HAS_RICH else None

    def _get_status_color(self, status: str) -> str:
        """Get color for status."""
        status_lower = status.lower()
        for key, color in self.STATUS_COLORS.items():
            if key in status_lower:
                return color
        return 'white'

    def _format_table_rich(self, data: List[Dict[str, Any]],
                           columns: Optional[List[str]] = None,
                           title: Optional[str] = None) -> None:
        """Format data as rich table."""
        if not data:
            self.console.print("[dim]No data to display[/dim]")
            return

        if columns is None:
            columns = list(data[0].keys())

        table = Table(title=title, box=box.ROUNDED, show_header=True, header_style="bold cyan")

        for col in columns:
            table.add_column(col.replace('_', ' ').title())

        for row in data:
            cells = []
            for col in columns:
                value = str(row.get(col, ''))
                # Apply status coloring
                if col.lower() == 'status':
                    color = self._get_status_color(value)
                    cells.append(f"[{color}]{value}[/{color}]")
                else:
                    cells.append(value)
            table.add_row(*cells)

        self.console.print(table)

    def _format_table_tabulate(self, data: List[Dict[str, Any]],
                               columns: Optional[List[str]] = None,
                               title: Optional[str] = None) -> str:
        """Format data as tabulate table."""
        if not data:
            return "No data to display"

        if columns is None:
            columns = list(data[0].keys())

        headers = [col.replace('_', ' ').title() for col in columns]
        rows = [[row.get(col, '') for col in columns] for row in data]

        output = ""
        if title:
            output = f"\n{title}\n{'=' * len(title)}\n"
        output += tabulate(rows, headers=headers, tablefmt='grid')
        return output

    def _format_table_simple(self, data: List[Dict[str, Any]],
                             columns: Optional[List[str]] = None,
                             title: Optional[str] = None) -> str:
        """Format data as simple text table."""
        if not data:
            return "No data to display"

        if columns is None:
            columns = list(data[0].keys())

        # Calculate column widths
        widths = {}
        for col in columns:
            widths[col] = max(
                len(col),
                max((len(str(row.get(col, ''))) for row in data), default=0)
            )

        # Build table
        output = []
        if title:
            output.append(f"\n{title}")
            output.append("=" * len(title))

        # Header
        header = " | ".join(col.replace('_', ' ').title().ljust(widths[col]) for col in columns)
        output.append(header)
        output.append("-" * len(header))

        # Rows
        for row in data:
            line = " | ".join(str(row.get(col, '')).ljust(widths[col]) for col in columns)
            output.append(line)

        return "\n".join(output)

    def format_table(self, data: List[Dict[str, Any]],
                     columns: Optional[List[str]] = None,
                     title: Optional[str] = None) -> Optional[str]:
        """Format data as table.

        Args:
            data: List of dictionaries to display
            columns: Column names to include (default: all keys)
            title: Optional table title

        Returns:
            Formatted string (or None if using rich console output)
        """
        if HAS_RICH and self.console:
            self._format_table_rich(data, columns, title)
            return None
        elif HAS_TABULATE:
            return self._format_table_tabulate(data, columns, title)
        else:
            return self._format_table_simple(data, columns, title)

    def format_json(self, data: Union[List, Dict], indent: int = 2) -> str:
        """Format data as JSON.

        Args:
            data: Data to format
            indent: Indentation level

        Returns:
            JSON string
        """
        return json.dumps(data, indent=indent, ensure_ascii=False, default=str)

    def format_csv(self, data: List[Dict[str, Any]],
                   columns: Optional[List[str]] = None) -> str:
        """Format data as CSV.

        Args:
            data: List of dictionaries
            columns: Column names to include

        Returns:
            CSV string
        """
        if not data:
            return ""

        if columns is None:
            columns = list(data[0].keys())

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=columns, extrasaction='ignore',
                                quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(data)
        return output.getvalue()

    def output(self, data: Union[List[Dict[str, Any]], Dict[str, Any]],
               columns: Optional[List[str]] = None,
               title: Optional[str] = None) -> None:
        """Output data in the configured format.

        Args:
            data: Data to output
            columns: Columns for table format
            title: Title for table format
        """
        # Ensure data is a list for table/csv
        if isinstance(data, dict):
            data_list = [data]
        else:
            data_list = data

        if self.format_type == 'json':
            print(self.format_json(data_list if len(data_list) > 1 else data))
        elif self.format_type == 'csv':
            print(self.format_csv(data_list, columns))
        else:  # table
            result = self.format_table(data_list, columns, title)
            if result:
                print(result)

    def print_success(self, message: str) -> None:
        """Print success message."""
        if HAS_RICH and self.console:
            self.console.print(f"[green]✓[/green] {message}")
        else:
            print(f"✓ {message}")

    def print_error(self, message: str) -> None:
        """Print error message."""
        if HAS_RICH and self.console:
            self.console.print(f"[red]✗[/red] {message}", style="red")
        else:
            print(f"✗ {message}", file=sys.stderr)

    def print_warning(self, message: str) -> None:
        """Print warning message."""
        if HAS_RICH and self.console:
            self.console.print(f"[yellow]⚠[/yellow] {message}")
        else:
            print(f"⚠ {message}")

    def print_info(self, message: str) -> None:
        """Print info message."""
        if HAS_RICH and self.console:
            self.console.print(f"[blue]ℹ[/blue] {message}")
        else:
            print(f"ℹ {message}")

    def print_dry_run(self, message: str) -> None:
        """Print dry-run message."""
        if HAS_RICH and self.console:
            self.console.print(f"[cyan][DRY-RUN][/cyan] {message}")
        else:
            print(f"[DRY-RUN] {message}")

    def print_summary(self, title: str, items: Dict[str, Any]) -> None:
        """Print a summary panel.

        Args:
            title: Summary title
            items: Dictionary of label: value pairs
        """
        if HAS_RICH and self.console:
            lines = []
            for label, value in items.items():
                lines.append(f"[bold]{label}:[/bold] {value}")
            panel = Panel("\n".join(lines), title=title, border_style="blue")
            self.console.print(panel)
        else:
            print(f"\n{title}")
            print("=" * len(title))
            for label, value in items.items():
                print(f"  {label}: {value}")
            print()

    def confirm(self, message: str, default: bool = False) -> bool:
        """Ask for user confirmation.

        Args:
            message: Confirmation message
            default: Default answer

        Returns:
            True if confirmed
        """
        if HAS_RICH and self.console:
            from rich.prompt import Confirm
            return Confirm.ask(message, default=default)
        else:
            suffix = " [Y/n]" if default else " [y/N]"
            response = input(message + suffix + ": ").strip().lower()
            if not response:
                return default
            return response in ('y', 'yes')


# Default formatter instance
_formatter: Optional[OutputFormatter] = None


def get_formatter(format_type: Optional[str] = None) -> OutputFormatter:
    """Get formatter instance.

    Args:
        format_type: Output format type

    Returns:
        OutputFormatter instance
    """
    global _formatter
    if _formatter is None or format_type is not None:
        _formatter = OutputFormatter(format_type)
    return _formatter
