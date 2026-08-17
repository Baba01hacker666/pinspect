"""
Main CLI argument parser and subcommand router for pinspect.
"""

import argparse
import os
import sys
from typing import List, Optional

from pinspect import __version__
from pinspect.output.formatter import OutputDispatcher
from pinspect.cli.commands.ps import handle_ps
from pinspect.cli.commands.tree import handle_tree
from pinspect.cli.commands.show import handle_show
from pinspect.cli.commands.files import handle_files
from pinspect.cli.commands.network import handle_network
from pinspect.cli.commands.env import handle_env
from pinspect.cli.commands.ancestry import handle_ancestry
from pinspect.cli.commands.children import handle_children
from pinspect.cli.commands.namespaces import handle_namespaces
from pinspect.cli.commands.security import handle_security
from pinspect.cli.commands.tui import handle_tui


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser with subcommands and global flags."""
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="Output in structured JSON format (for SIEM/EDR ingestion)")
    common_parser.add_argument("--csv", action="store_true", default=argparse.SUPPRESS, help="Output in CSV format")
    common_parser.add_argument("-w", "--wide", action="store_true", default=argparse.SUPPRESS, help="Do not truncate command lines or long paths")
    common_parser.add_argument("-q", "--quiet", action="store_true", default=argparse.SUPPRESS, help="Quiet output (machine-readable IDs only)")
    common_parser.add_argument("--proc-root", default=argparse.SUPPRESS, help="Path to /proc filesystem root (default: /proc)")

    parser = argparse.ArgumentParser(
        prog="pinspect",
        description="Fast Linux process-intelligence CLI tool that goes far beyond 'ps aux'.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[common_parser],
    )

    # Global options
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Subcommand to execute")

    # 1. 'ps' subcommand
    ps_parser = subparsers.add_parser("ps", help="List processes with deep intelligence and rich filtering", parents=[common_parser])
    ps_parser.add_argument("-u", "--user", help="Filter by username or UID")
    ps_parser.add_argument("-n", "--name", help="Filter by process name (regex supported)")
    ps_parser.add_argument("-p", "--pid", type=int, help="Filter by specific PID")
    ps_parser.add_argument("--port", type=int, help="Filter by listening or connected network port")
    ps_parser.add_argument("-s", "--service", help="Filter by systemd service name")
    ps_parser.add_argument("-c", "--container", action="store_true", help="Filter for containerized processes only")
    ps_parser.add_argument("-d", "--deleted", action="store_true", help="Filter for processes holding deleted executables or files")
    ps_parser.add_argument("--state", help="Filter by process state (R, S, D, Z, T, I)")
    ps_parser.add_argument("--cmdline", help="Filter by command line pattern")
    ps_parser.add_argument("-l", "--listen", action="store_true", help="Filter for processes listening on network ports")
    ps_parser.add_argument("--sort", choices=["cpu", "mem", "pid", "user", "name", "age"], default="cpu", help="Sort column (default: cpu)")
    ps_parser.add_argument("--asc", dest="reverse", action="store_false", default=True, help="Sort in ascending order instead of descending")
    ps_parser.add_argument("--limit", type=int, help="Limit number of output processes")

    # 2. 'tree' subcommand
    tree_parser = subparsers.add_parser("tree", help="Display process hierarchy tree", parents=[common_parser])
    tree_parser.add_argument("pid", nargs="?", type=int, help="Optional PID to root tree at")
    tree_parser.add_argument("--highlight", type=int, help="PID to highlight in tree")

    # 3. 'show' subcommand
    show_parser = subparsers.add_parser("show", help="Show comprehensive intelligence card for a PID", parents=[common_parser])
    show_parser.add_argument("pid", type=int, help="Target process PID")
    show_parser.add_argument("--env", action="store_true", help="Include environment variables (redacted)")
    show_parser.add_argument("--hash", action="store_true", help="Compute SHA-256 hash of executable")

    # 4. 'files' subcommand
    files_parser = subparsers.add_parser("files", help="Enumerate open file descriptors and deleted files", parents=[common_parser])
    files_parser.add_argument("pid", type=int, help="Target process PID")
    files_parser.add_argument("-d", "--deleted", action="store_true", help="Show only unlinked / deleted files")
    files_parser.add_argument("-t", "--type", help="Filter by FD type (regular, socket, pipe, anon, char)")

    # 5. 'network' subcommand
    net_parser = subparsers.add_parser("network", help="Inspect network and unix domain sockets", parents=[common_parser])
    net_parser.add_argument("pid", nargs="?", type=int, help="Optional PID to filter sockets for")
    net_parser.add_argument("-p", "--port", type=int, help="Filter by port number")
    net_parser.add_argument("-l", "--listen", action="store_true", help="Show only listening sockets")
    net_parser.add_argument("--proto", help="Filter by protocol (TCP, UDP, UNIX)")

    # 6. 'env' subcommand
    env_parser = subparsers.add_parser("env", help="Inspect environment variables with secret redaction", parents=[common_parser])
    env_parser.add_argument("pid", type=int, help="Target process PID")
    env_parser.add_argument("--show-secrets", action="store_true", help="Reveal unredacted secret values")
    env_parser.add_argument("-f", "--filter", help="Filter environment variable names")

    # 7. 'ancestry' subcommand
    anc_parser = subparsers.add_parser("ancestry", help="Display ancestor chain up to PID 1 / init", parents=[common_parser])
    anc_parser.add_argument("pid", type=int, help="Target process PID")

    # 8. 'children' subcommand
    child_parser = subparsers.add_parser("children", help="Display child processes and descendant tree", parents=[common_parser])
    child_parser.add_argument("pid", type=int, help="Target process PID")

    # 9. 'namespaces' subcommand
    ns_parser = subparsers.add_parser("namespaces", help="Inspect Linux namespace membership and isolation", parents=[common_parser])
    ns_parser.add_argument("pid", type=int, help="Target process PID")

    # 10. 'security' subcommand
    sec_parser = subparsers.add_parser("security", help="Inspect Linux capabilities, Seccomp, NoNewPrivs, LSM, and file integrity", parents=[common_parser])
    sec_parser.add_argument("pid", type=int, help="Target process PID")
    sec_parser.add_argument("--no-hash", dest="compute_hash", action="store_false", default=True, help="Skip SHA-256 executable hashing")

    # 11. 'tui' subcommand
    tui_parser = subparsers.add_parser("tui", help="Launch interactive full-screen TUI explorer", parents=[common_parser])

    return parser


def main(args: Optional[List[str]] = None) -> int:
    """CLI main execution function."""
    parser = build_parser()
    parsed_args = parser.parse_args(args)

    dispatcher = OutputDispatcher(
        json_mode=getattr(parsed_args, "json", False),
        csv_mode=getattr(parsed_args, "csv", False),
        quiet_mode=getattr(parsed_args, "quiet", False),
        wide_mode=getattr(parsed_args, "wide", False),
    )

    proc_root = getattr(parsed_args, "proc_root", "/proc")
    command = parsed_args.command

    # If no subcommand is passed, default to 'ps'
    if command is None:
        return handle_ps(
            proc_root=proc_root,
            output_dispatcher=dispatcher,
        )

    if command == "ps":
        return handle_ps(
            proc_root=proc_root,
            user_filter=parsed_args.user,
            name_filter=parsed_args.name,
            pid_filter=parsed_args.pid,
            port_filter=parsed_args.port,
            service_filter=parsed_args.service,
            container_only=parsed_args.container,
            deleted_only=parsed_args.deleted,
            state_filter=parsed_args.state,
            cmd_filter=parsed_args.cmdline,
            listen_only=parsed_args.listen,
            sort_by=parsed_args.sort,
            reverse=parsed_args.reverse,
            limit=parsed_args.limit,
            output_dispatcher=dispatcher,
        )

    elif command == "tree":
        return handle_tree(
            proc_root=proc_root,
            root_pid=parsed_args.pid,
            highlight_pid=parsed_args.highlight or parsed_args.pid,
            output_dispatcher=dispatcher,
        )

    elif command == "show":
        return handle_show(
            pid=parsed_args.pid,
            proc_root=proc_root,
            include_env=parsed_args.env,
            compute_hash=parsed_args.hash,
            output_dispatcher=dispatcher,
        )

    elif command == "files":
        return handle_files(
            pid=parsed_args.pid,
            proc_root=proc_root,
            deleted_only=parsed_args.deleted,
            type_filter=parsed_args.type,
            output_dispatcher=dispatcher,
        )

    elif command == "network":
        return handle_network(
            pid=parsed_args.pid,
            proc_root=proc_root,
            port_filter=parsed_args.port,
            listen_only=parsed_args.listen,
            protocol_filter=parsed_args.proto,
            output_dispatcher=dispatcher,
        )

    elif command == "env":
        return handle_env(
            pid=parsed_args.pid,
            proc_root=proc_root,
            show_secrets=parsed_args.show_secrets,
            key_filter=parsed_args.filter,
            output_dispatcher=dispatcher,
        )

    elif command == "ancestry":
        return handle_ancestry(
            pid=parsed_args.pid,
            proc_root=proc_root,
            output_dispatcher=dispatcher,
        )

    elif command == "children":
        return handle_children(
            pid=parsed_args.pid,
            proc_root=proc_root,
            output_dispatcher=dispatcher,
        )

    elif command == "namespaces":
        return handle_namespaces(
            pid=parsed_args.pid,
            proc_root=proc_root,
            output_dispatcher=dispatcher,
        )

    elif command == "security":
        return handle_security(
            pid=parsed_args.pid,
            proc_root=proc_root,
            compute_hash=parsed_args.compute_hash,
            output_dispatcher=dispatcher,
        )

    elif command == "tui":
        return handle_tui(proc_root=proc_root)

    return 0


if __name__ == "__main__":
    sys.exit(main())
