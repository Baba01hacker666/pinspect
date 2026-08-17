"""
'pinspect files <PID>' command implementation.
"""

from typing import Optional

from pinspect.collector.filesystem import FilesystemCollector
from pinspect.collector.procfs import ProcFS
from pinspect.output.formatter import OutputDispatcher
from pinspect.ui.table import render_files_table
from pinspect.ui.theme import console


def handle_files(
    pid: int,
    proc_root: str = "/proc",
    deleted_only: bool = False,
    type_filter: Optional[str] = None,
    output_dispatcher: Optional[OutputDispatcher] = None,
) -> int:
    """Enumerate and display open file descriptors for PID."""
    procfs = ProcFS(proc_root)
    fs_collector = FilesystemCollector(procfs)
    dispatcher = output_dispatcher or OutputDispatcher()

    if not procfs.exists(pid):
        if not dispatcher.quiet_mode:
            console.print(f"[bold red]Error: Process {pid} not found.[/bold red]")
        return 1

    fds = fs_collector.collect_fds(pid)

    if deleted_only:
        fds = [f for f in fds if f.is_deleted]

    if type_filter:
        fds = [f for f in fds if type_filter.lower() in f.fd_type.value.lower()]

    data = {
        "pid": pid,
        "files": fds,
        "count": len(fds),
    }

    dispatcher.handle(
        data=data,
        rich_render_fn=lambda: render_files_table(fds, pid=pid, wide=dispatcher.wide_mode),
        csv_type="files",
        quiet_extractor=lambda d: [str(f.fd) for f in fds],
    )
    return 0
