"""
'pinspect network [PID]' command implementation.
"""

from typing import Optional

from pinspect.collector.network import NetworkCollector
from pinspect.collector.procfs import ProcFS
from pinspect.output.formatter import OutputDispatcher
from pinspect.ui.table import render_network_table


def handle_network(
    pid: Optional[int] = None,
    proc_root: str = "/proc",
    port_filter: Optional[int] = None,
    listen_only: bool = False,
    protocol_filter: Optional[str] = None,
    output_dispatcher: Optional[OutputDispatcher] = None,
) -> int:
    """Collect and display network & socket connections."""
    procfs = ProcFS(proc_root)
    net_collector = NetworkCollector(procfs)
    dispatcher = output_dispatcher or OutputDispatcher()

    sockets = net_collector.collect_all_sockets(
        pid_filter=pid,
        port_filter=port_filter,
        listen_only=listen_only,
    )

    if protocol_filter:
        proto_up = protocol_filter.upper()
        sockets = [s for s in sockets if proto_up in s.protocol.value.upper()]

    dispatcher.handle(
        data=sockets,
        rich_render_fn=lambda: render_network_table(sockets, wide=dispatcher.wide_mode),
        csv_type="sockets",
        quiet_extractor=lambda socks: [f"{s.local_endpoint} -> {s.remote_endpoint}" for s in socks],
    )
    return 0
