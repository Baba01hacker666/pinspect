"""
'pinspect namespaces <PID>' command implementation.
"""

from typing import Optional

from pinspect.collector.namespaces import NamespaceCollector
from pinspect.collector.procfs import ProcFS
from pinspect.output.formatter import OutputDispatcher
from pinspect.ui.table import render_namespace_table
from pinspect.ui.theme import console


def handle_namespaces(
    pid: int,
    proc_root: str = "/proc",
    output_dispatcher: Optional[OutputDispatcher] = None,
) -> int:
    """Inspect and display namespace membership and isolation for PID."""
    procfs = ProcFS(proc_root)
    ns_collector = NamespaceCollector(procfs)
    dispatcher = output_dispatcher or OutputDispatcher()

    if not procfs.exists(pid):
        if not dispatcher.quiet_mode:
            console.print(f"[bold red]Error: Process {pid} not found.[/bold red]")
        return 1

    namespaces = ns_collector.collect_namespaces_for_pid(pid, compare_with_host=True)

    data = {
        "pid": pid,
        "namespaces": namespaces,
        "isolated_count": sum(1 for ns in namespaces.values() if ns.is_isolated),
    }

    dispatcher.handle(
        data=data,
        rich_render_fn=lambda: render_namespace_table(namespaces, pid=pid),
        quiet_extractor=lambda d: [f"{k}={v.inode}" for k, v in d["namespaces"].items()],
    )
    return 0
