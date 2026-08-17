"""
'pinspect ancestry <PID>' command implementation.
"""

from typing import Optional
from pinspect.collector.procfs import ProcFS
from pinspect.collector.process import ProcessCollector
from pinspect.output.formatter import OutputDispatcher
from pinspect.ui.tree import render_ancestry_chain
from pinspect.ui.theme import console


def handle_ancestry(
    pid: int,
    proc_root: str = "/proc",
    output_dispatcher: Optional[OutputDispatcher] = None,
) -> int:
    """Display the full lineage and ancestor chain for a PID."""
    procfs = ProcFS(proc_root)
    collector = ProcessCollector(procfs)
    dispatcher = output_dispatcher or OutputDispatcher()

    processes = collector.collect_all_processes(deep=False)
    pinfo = next((p for p in processes if p.pid == pid), None)

    if not pinfo:
        if not dispatcher.quiet_mode:
            console.print(f"[bold red]Error: Process {pid} not found.[/bold red]")
        return 1

    data = {
        "pid": pid,
        "name": pinfo.name,
        "ancestry": pinfo.ancestry,
    }

    dispatcher.handle(
        data=data,
        rich_render_fn=lambda: render_ancestry_chain(pinfo.ancestry, target_pid=pid, target_name=pinfo.name),
        quiet_extractor=lambda d: [str(a.pid) for a in pinfo.ancestry],
    )
    return 0
