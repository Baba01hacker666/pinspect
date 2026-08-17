"""
'pinspect show <PID>' command implementation.
"""

from typing import Optional
from pinspect.collector.procfs import ProcFS
from pinspect.collector.process import ProcessCollector
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

    # Link parents and ancestry
    procs = collector.collect_all_processes(deep=True)
    pinfo = next((p for p in procs if p.pid == pid), None)

    if not pinfo:
        # Try direct read
        pinfo = collector.collect_process(pid, deep=True)

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
