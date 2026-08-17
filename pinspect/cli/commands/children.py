"""
'pinspect children <PID>' command implementation.
"""

from typing import Optional
from pinspect.collector.procfs import ProcFS
from pinspect.collector.process import ProcessCollector
from pinspect.output.formatter import OutputDispatcher
from pinspect.ui.tree import render_process_tree
from pinspect.ui.theme import console


def handle_children(
    pid: int,
    proc_root: str = "/proc",
    output_dispatcher: Optional[OutputDispatcher] = None,
) -> int:
    """Display children and descendant tree rooted at a specific PID."""
    procfs = ProcFS(proc_root)
    collector = ProcessCollector(procfs)
    dispatcher = output_dispatcher or OutputDispatcher()

    processes = collector.collect_all_processes(deep=False)
    target = next((p for p in processes if p.pid == pid), None)

    if not target:
        if not dispatcher.quiet_mode:
            console.print(f"[bold red]Error: Process {pid} not found.[/bold red]")
        return 1

    dispatcher.handle(
        data=target.children,
        rich_render_fn=lambda: render_process_tree(processes, root_pid=pid, highlight_pid=pid),
        quiet_extractor=lambda kids: [str(k) for k in kids],
    )
    return 0
