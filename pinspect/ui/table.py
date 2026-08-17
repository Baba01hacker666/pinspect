"""
Rich table renderers for processes, file descriptors, network sockets, and namespaces.
"""

from typing import List, Dict, Optional
from rich.table import Table
from rich.text import Text
from pinspect.model.process import ProcessInfo
from pinspect.model.filesystem import FileDescriptorInfo, FDType
from pinspect.model.network import SocketInfo
from pinspect.model.security import NamespaceInfo
from pinspect.ui.theme import console, Theme, COLOR_HEADER
from pinspect.utils.formatting import format_bytes, format_percent, truncate_str


def render_process_table(
    processes: List[ProcessInfo],
    wide: bool = False,
    title: Optional[str] = None,
) -> None:
    """Render a clean, high-density process table."""
    table = Table(
        title=title,
        show_header=True,
        header_style=COLOR_HEADER,
        border_style="grey37",
        box=None,
        pad_edge=False,
        expand=True,
    )

    table.add_column("PID", justify="right", style="cyan", no_wrap=True, width=7)
    table.add_column("PPID", justify="right", style="dim", no_wrap=True, width=6)
    table.add_column("USER", justify="left", style="green", no_wrap=True, max_width=12)
    table.add_column("ST", justify="center", no_wrap=True, width=4)
    table.add_column("CPU%", justify="right", no_wrap=True, width=6)
    table.add_column("MEM%", justify="right", no_wrap=True, width=6)
    table.add_column("RSS", justify="right", no_wrap=True, width=8)
    table.add_column("THR", justify="right", style="dim", no_wrap=True, width=4)
    table.add_column("ORIGIN / SERVICE", justify="left", no_wrap=True, max_width=22)
    table.add_column("COMMAND", justify="left", overflow="ellipsis")

    for p in processes:
        # State styling
        st_text = Text(p.state_char, style=Theme.state_style(p.state_char))

        # CPU & Mem styling
        cpu_text = Text(f"{p.cpu.cpu_percent:.1f}", style=Theme.cpu_style(p.cpu.cpu_percent))
        mem_text = Text(f"{p.memory.mem_percent:.1f}", style=Theme.mem_style(p.memory.mem_percent))
        rss_text = Text(format_bytes(p.memory.rss_bytes), style="dim")

        # User styling (highlight root)
        user_style = "bold yellow" if p.creds.user == "root" else "green"
        user_text = Text(p.creds.user, style=user_style)

        # Origin description
        origin_str = ""
        origin_style = "blue"
        if p.cgroup.is_container:
            cid = p.cgroup.container_id or ""
            origin_str = f"📦 {p.cgroup.container_runtime or 'container'}{(':' + cid[:6]) if cid else ''}"
            origin_style = "bold cyan"
        elif p.origin.service_name:
            origin_str = f"⚙ {p.origin.service_name}"
            origin_style = "bright_blue"
        elif p.origin.launcher_type == "ssh":
            origin_str = "SSH session"
            origin_style = "magenta"
        elif p.origin.launcher_type == "cron":
            origin_str = "cron job"
            origin_style = "yellow"
        elif p.origin.launcher_type == "shell":
            origin_str = "shell"
            origin_style = "dim cyan"
        elif p.is_kernel_thread:
            origin_str = "[kthread]"
            origin_style = "dim"
        else:
            origin_str = p.origin.launcher_type
            origin_style = "dim"

        origin_text = Text(origin_str, style=origin_style)

        # Command & deleted exe warning
        cmd_text = Text()
        if p.is_deleted_exe:
            cmd_text.append("[DELETED] ", style="bold red")
        
        if wide:
            cmd_text.append(p.cmdline or p.name, style="white" if p.pid != 0 else "dim")
        else:
            cmd_text.append(p.cmdline or p.name, style="white" if p.pid != 0 else "dim")

        table.add_row(
            str(p.pid),
            str(p.ppid),
            user_text,
            st_text,
            cpu_text,
            mem_text,
            rss_text,
            str(p.threads_count),
            origin_text,
            cmd_text,
        )

    console.print(table)


def render_files_table(
    files: List[FileDescriptorInfo],
    pid: int,
    wide: bool = False,
) -> None:
    """Render file descriptors table."""
    table = Table(
        title=f"Open File Descriptors for PID {pid} ({len(files)} open)",
        show_header=True,
        header_style=COLOR_HEADER,
        border_style="grey37",
        box=None,
        pad_edge=False,
        expand=True,
    )

    table.add_column("FD", justify="right", style="cyan", no_wrap=True, width=5)
    table.add_column("TYPE", justify="left", no_wrap=True, width=15)
    table.add_column("MODE", justify="center", style="dim", no_wrap=True, width=6)
    table.add_column("POS", justify="right", style="dim", no_wrap=True, width=8)
    table.add_column("INODE", justify="right", style="dim", no_wrap=True, width=10)
    table.add_column("SIZE", justify="right", style="dim", no_wrap=True, width=10)
    table.add_column("TARGET / PATH", justify="left")

    for f in files:
        type_style = "dim"
        if f.is_deleted:
            type_style = "bold red"
        elif f.fd_type == FDType.INET_SOCKET:
            type_style = "bold green"
        elif f.fd_type == FDType.UNIX_SOCKET:
            type_style = "green"
        elif f.fd_type == FDType.PIPE:
            type_style = "yellow"
        elif f.fd_type == FDType.REGULAR:
            type_style = "white"

        type_text = Text(f.fd_type.label, style=type_style)

        target_text = Text()
        if f.is_deleted:
            target_text.append("⚠️ [DELETED] ", style="bold red")
            target_text.append(f.resolved_path, style="red")
        else:
            target_text.append(f.target, style="white")

        table.add_row(
            str(f.fd),
            type_text,
            f.mode or "-",
            str(f.pos) if f.pos is not None else "-",
            str(f.inode) if f.inode else "-",
            format_bytes(f.file_size) if f.file_size is not None else "-",
            target_text,
        )

    console.print(table)


def render_network_table(
    sockets: List[SocketInfo],
    wide: bool = False,
) -> None:
    """Render network and socket table."""
    table = Table(
        title=f"Network & Unix Domain Sockets ({len(sockets)} sockets)",
        show_header=True,
        header_style=COLOR_HEADER,
        border_style="grey37",
        box=None,
        pad_edge=False,
        expand=True,
    )

    table.add_column("PROTO", justify="left", style="bold yellow", no_wrap=True, width=6)
    table.add_column("LOCAL ADDRESS", justify="left", style="white", no_wrap=True, width=24)
    table.add_column("REMOTE ADDRESS", justify="left", style="dim", no_wrap=True, width=22)
    table.add_column("STATE", justify="center", no_wrap=True, width=12)
    table.add_column("PID", justify="right", style="cyan", no_wrap=True, width=7)
    table.add_column("PROCESS", justify="left", style="bold white", no_wrap=True, max_width=16)
    table.add_column("USER", justify="left", style="green", no_wrap=True, max_width=10)
    table.add_column("FD", justify="right", style="dim", no_wrap=True, width=4)
    table.add_column("INODE", justify="right", style="dim", no_wrap=True, width=10)

    for s in sockets:
        # State styling
        state_style = "dim"
        if s.is_listening:
            state_style = "bold green"
        elif s.is_established:
            state_style = "bold cyan"
        elif s.state.value == "TIME_WAIT":
            state_style = "dim yellow"
        state_text = Text(s.state.value, style=state_style)

        table.add_row(
            s.protocol.value,
            s.local_endpoint,
            s.remote_endpoint,
            state_text,
            str(s.pid) if s.pid else "-",
            s.process_name or "-",
            s.user or "-",
            str(s.fd) if s.fd is not None else "-",
            str(s.inode),
        )

    console.print(table)


def render_namespace_table(
    namespaces: Dict[str, NamespaceInfo],
    pid: int,
) -> None:
    """Render Linux namespaces table."""
    table = Table(
        title=f"Namespaces for PID {pid}",
        show_header=True,
        header_style=COLOR_HEADER,
        border_style="grey37",
        box=None,
        pad_edge=False,
        expand=True,
    )

    table.add_column("NAMESPACE", justify="left", style="bold cyan", width=16)
    table.add_column("INODE", justify="right", style="white", width=12)
    table.add_column("TARGET LINK", justify="left", style="dim", width=26)
    table.add_column("ISOLATION STATUS", justify="left", width=20)

    for name, ns in sorted(namespaces.items()):
        status_text = Text()
        if ns.is_isolated:
            status_text.append("🔒 ISOLATED (Container/NS)", style="bold yellow")
        else:
            status_text.append("Host / Default Namespace", style="dim green")

        table.add_row(
            name,
            str(ns.inode) if ns.inode else "-",
            ns.target_path or "-",
            status_text,
        )

    console.print(table)
