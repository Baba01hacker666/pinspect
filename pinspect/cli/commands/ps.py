"""
'pinspect ps' command implementation.
"""

import re
from typing import List, Optional

from pinspect.collector.network import NetworkCollector
from pinspect.collector.process import ProcessCollector
from pinspect.collector.procfs import ProcFS
from pinspect.model.process import ProcessInfo
from pinspect.output.formatter import OutputDispatcher
from pinspect.ui.table import render_process_table


def handle_ps(
    proc_root: str = "/proc",
    user_filter: Optional[str] = None,
    name_filter: Optional[str] = None,
    pid_filter: Optional[int] = None,
    port_filter: Optional[int] = None,
    service_filter: Optional[str] = None,
    container_only: bool = False,
    deleted_only: bool = False,
    state_filter: Optional[str] = None,
    cmd_filter: Optional[str] = None,
    listen_only: bool = False,
    sort_by: str = "cpu",
    reverse: bool = True,
    limit: Optional[int] = None,
    output_dispatcher: Optional[OutputDispatcher] = None,
) -> int:
    """Execute process list command with filtering and formatting."""
    procfs = ProcFS(proc_root)
    collector = ProcessCollector(procfs)
    dispatcher = output_dispatcher or OutputDispatcher()

    # If port or listen filter is requested, build socket inode lookup
    port_matching_pids = set()
    if port_filter is not None or listen_only:
        net_collector = NetworkCollector(procfs)
        sockets = net_collector.collect_all_sockets(port_filter=port_filter, listen_only=listen_only)
        for s in sockets:
            if s.pid:
                port_matching_pids.add(s.pid)

    processes = collector.collect_all_processes(deep=deleted_only)

    filtered: List[ProcessInfo] = []
    for p in processes:
        if pid_filter is not None and p.pid != pid_filter:
            continue

        if user_filter:
            if user_filter.isdigit():
                if p.creds.ruid != int(user_filter) and p.creds.euid != int(user_filter):
                    continue
            else:
                if user_filter.lower() not in p.creds.user.lower():
                    continue

        if name_filter and not re.search(name_filter, p.name, re.IGNORECASE):
            continue

        if cmd_filter and not re.search(cmd_filter, p.cmdline, re.IGNORECASE):
            continue

        if state_filter and p.state_char.upper() != state_filter.upper():
            continue

        if service_filter:
            srv = p.origin.service_name or ""
            if service_filter.lower() not in srv.lower():
                continue

        if container_only and not p.cgroup.is_container:
            continue

        if deleted_only and not (p.is_deleted_exe or p.deleted_files_count > 0):
            continue

        if (port_filter is not None or listen_only) and p.pid not in port_matching_pids:
            continue

        filtered.append(p)

    # Sort
    if sort_by == "cpu":
        filtered.sort(key=lambda x: x.cpu.cpu_percent, reverse=reverse)
    elif sort_by == "mem":
        filtered.sort(key=lambda x: x.memory.rss_bytes, reverse=reverse)
    elif sort_by == "pid":
        filtered.sort(key=lambda x: x.pid, reverse=reverse)
    elif sort_by == "user":
        filtered.sort(key=lambda x: x.creds.user, reverse=reverse)
    elif sort_by == "name":
        filtered.sort(key=lambda x: x.name.lower(), reverse=reverse)
    elif sort_by == "age":
        filtered.sort(key=lambda x: x.age_seconds, reverse=reverse)

    if limit is not None and limit > 0:
        filtered = filtered[:limit]

    dispatcher.handle(
        data=filtered,
        rich_render_fn=lambda: render_process_table(filtered, wide=dispatcher.wide_mode),
        csv_type="process",
        quiet_extractor=lambda procs: [str(p.pid) for p in procs],
    )
    return 0
