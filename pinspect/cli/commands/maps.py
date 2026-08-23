"""
'pinspect maps <PID>' command — memory map inspection with injection indicators.
"""

from typing import Optional

from rich.markup import escape
from rich.table import Table

from pinspect.collector.maps import MapsCollector
from pinspect.collector.procfs import ProcFS
from pinspect.model.maps import MapRegion, MapsReport
from pinspect.output.formatter import OutputDispatcher
from pinspect.ui.theme import console
from pinspect.utils.formatting import format_bytes


def _region_style(region: MapRegion) -> str:
    if region.is_rwx:
        return "bold red"
    if region.is_anonymous_exec or region.is_memfd:
        return "bold yellow"
    if region.is_deleted_path:
        return "yellow"
    return ""


def render_maps_report(report: MapsReport, wide: bool = False) -> None:
    """Render memory map table with forensic highlighting."""
    summary_table = Table(box=None, show_header=False, pad_edge=False)
    summary_table.add_column("Key", style="bold cyan", width=24)
    summary_table.add_column("Value", style="white")

    summary_table.add_row(
        "Total Regions:",
        f"{report.total_regions}  [dim]({format_bytes(report.total_mapped_bytes)} mapped)[/dim]",
    )
    summary_table.add_row("Executable Regions:", str(report.executable_regions))

    def _flag_row(label: str, count_or_list, noun: str) -> None:
        if isinstance(count_or_list, int):
            count, items = count_or_list, []
        else:
            count, items = len(count_or_list), list(count_or_list)
        value = f"[bold red]{count}[/bold red]" if count else "[green]0[/green]"
        if items:
            value += f"  [dim]{escape(', '.join(items[:3]))}[/dim]"
        summary_table.add_row(label, value)

    _flag_row("RWX (Writable+Exec):", report.rwx_region_count, "regions")
    _flag_row("Anonymous Exec Regions:", report.anonymous_exec_count, "regions")
    _flag_row("memfd (Fileless) Maps:", report.memfd_paths, "maps")
    _flag_row("Deleted Backing Files:", [p.split(" (deleted)")[0] for p in report.deleted_paths], "paths")

    console.print(summary_table)

    detail_table = Table(
        title=f"🗺️ Memory Mappings - PID {report.pid}",
        header_style="bold magenta",
        expand=True,
    )
    detail_table.add_column("Start", style="cyan", no_wrap=True)
    detail_table.add_column("Size", justify="right", style="dim")
    detail_table.add_column("Perms")
    detail_table.add_column("Backing File / Purpose", overflow="fold" if wide else "ellipsis")

    shown = report.regions[:300]
    for region in shown:
        path_display = region.path or "[anon]"
        if region.is_rwx:
            path_display = f"⚠️ RWX {path_display}"
        elif region.is_anonymous_exec:
            path_display = "⚠️ anon exec (no file backing)"
        elif region.is_memfd:
            path_display = f"⚠️ memfd {path_display}"
        detail_table.add_row(
            f"{region.start_addr_int:x}",
            format_bytes(region.size_bytes),
            region.perms,
            escape(path_display),
            style=_region_style(region),
        )
    if len(report.regions) > len(shown):
        detail_table.add_row("[dim]…[/dim]", "", "", f"[dim]{len(report.regions) - len(shown)} more regions[/dim]")

    console.print(detail_table)


def handle_maps(
    pid: int,
    proc_root: str = "/proc",
    output_dispatcher: Optional[OutputDispatcher] = None,
) -> int:
    """Inspect /proc/<pid>/maps with forensic indicators."""
    procfs = ProcFS(proc_root)
    collector = MapsCollector(procfs)
    dispatcher = output_dispatcher or OutputDispatcher()

    if not procfs.exists(pid):
        if not dispatcher.quiet_mode:
            console.print(f"[bold red]Error: Process {pid} not found.[/bold red]")
        return 1

    report = collector.collect(pid)
    if not report.total_regions and not dispatcher.quiet_mode:
        console.print(
            f"[yellow]Warning: no readable memory maps for PID {pid} "
            "(process may have exited or requires elevated privileges).[/yellow]"
        )

    dispatcher.handle(
        data=report,
        rich_render_fn=lambda: render_maps_report(report, wide=dispatcher.wide_mode),
        quiet_extractor=lambda r: [
            f"{reg.start_addr_int:x}-{reg.end_addr_int:x} {reg.perms} {reg.path or '[anon]'}"
            for reg in r.regions
        ],
    )
    return 0
