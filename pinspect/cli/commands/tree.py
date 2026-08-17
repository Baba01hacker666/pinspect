"""
'pinspect tree' command implementation.
"""

from typing import Optional
from pinspect.collector.procfs import ProcFS
from pinspect.collector.process import ProcessCollector
from pinspect.output.formatter import OutputDispatcher
from pinspect.ui.tree import render_process_tree
from pinspect.ui.theme import console


def handle_tree(
    proc_root: str = "/proc",
    root_pid: Optional[int] = None,
    highlight_pid: Optional[int] = None,
    output_dispatcher: Optional[OutputDispatcher] = None,
) -> int:
    """Execute tree command."""
    procfs = ProcFS(proc_root)
    collector = ProcessCollector(procfs)
    dispatcher = output_dispatcher or OutputDispatcher()

    processes = collector.collect_all_processes(deep=False)

    if dispatcher.json_mode or dispatcher.csv_mode or dispatcher.quiet_mode:
        # Structured output delegates to dispatcher
        dispatcher.handle(
            data=processes,
            csv_type="process",
            quiet_extractor=lambda procs: [str(p.pid) for p in procs],
        )
        return 0

    render_process_tree(
        processes=processes,
        root_pid=root_pid,
        highlight_pid=highlight_pid or root_pid,
    )
    return 0
