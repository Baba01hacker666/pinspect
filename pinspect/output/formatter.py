"""
Unified output dispatcher handling --json, --csv, --wide, --quiet, and rich terminal output.
"""

from typing import Any, Callable, List, Optional

from pinspect.output.csv_out import (
    export_files_csv,
    export_processes_csv,
    export_sockets_csv,
)
from pinspect.output.json_out import to_json


class OutputDispatcher:
    """Dispatches command output to requested format (JSON, CSV, quiet, or rich terminal)."""

    def __init__(
        self,
        json_mode: bool = False,
        csv_mode: bool = False,
        quiet_mode: bool = False,
        wide_mode: bool = False,
    ):
        self.json_mode = json_mode
        self.csv_mode = csv_mode
        self.quiet_mode = quiet_mode
        self.wide_mode = wide_mode

    def handle(
        self,
        data: Any,
        rich_render_fn: Optional[Callable[[], None]] = None,
        csv_type: Optional[str] = None,
        quiet_extractor: Optional[Callable[[Any], List[str]]] = None,
    ) -> None:
        """Process and print output according to active flags."""
        if self.json_mode:
            print(to_json(data))
            return

        if self.csv_mode:
            if csv_type == "process" and isinstance(data, list):
                print(export_processes_csv(data), end="")
            elif csv_type == "files" and isinstance(data, dict):
                print(export_files_csv(data.get("files", []), data.get("pid", 0)), end="")
            elif csv_type == "sockets" and isinstance(data, list):
                print(export_sockets_csv(data), end="")
            else:
                # Never silently emit a different format than the user asked for
                raise ValueError("CSV output is not supported for this command; use --json or default output")
            return

        if self.quiet_mode:
            if quiet_extractor:
                for line in quiet_extractor(data):
                    print(line)
            elif isinstance(data, list):
                for item in data:
                    if hasattr(item, "pid"):
                        print(item.pid)
                    else:
                        print(str(item))
            elif hasattr(data, "pid"):
                print(data.pid)
            return

        # Default: Render rich / human terminal output
        if rich_render_fn:
            rich_render_fn()
        else:
            print(data)
