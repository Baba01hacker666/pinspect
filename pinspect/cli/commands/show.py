"""
'pinspect show <PID>' command implementation.
"""

from typing import Optional

from pinspect.collector.process import ProcessCollector
from pinspect.collector.procfs import ProcFS
from pinspect.collector.security import SecurityCollector
from pinspect.output.formatter import OutputDispatcher
from pinspect.ui.detail import render_process_detail
from pinspect.ui.theme import console


def handle_show(
    pid: int,
    proc_root: str = "/proc",
    include_env: bool = False,
    compute_hash: bool = False,
    output_dispatcher: Optional[OutputDispatcher] = None,
) -> int:
    """Show detailed process inspection."""
    procfs = ProcFS(proc_root)
    collector = ProcessCollector(procfs)
    sec_collector = SecurityCollector(procfs)
    dispatcher = output_dispatcher or OutputDispatcher()

    # Collect the target and its ancestors directly (avoids scanning all PIDs)
    pinfo = collector.collect_process_with_ancestry(pid, deep=True)

    if not pinfo:
        if not dispatcher.quiet_mode:
            console.print(f"[bold red]Error: Process {pid} does not exist or is inaccessible.[/bold red]")
        return 1

    security = sec_collector.collect(pid, compute_hash=compute_hash)

    data = {
        "process": pinfo,
        "security": security,
    }

    dispatcher.handle(
        data=data,
        rich_render_fn=lambda: render_process_detail(pinfo, security=security),
        csv_type="process",
        quiet_extractor=lambda d: [str(pid)],
    )
    return 0
