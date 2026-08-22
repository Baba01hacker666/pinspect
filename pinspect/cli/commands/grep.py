"""
'pinspect grep <pattern>' command — built-in grep for processes, tools, and arguments.
"""

import re
import sys
from typing import List, Optional

from pinspect.collector.process import ProcessCollector
from pinspect.collector.procfs import ProcFS
from pinspect.model.process import ProcessInfo
from pinspect.output.formatter import OutputDispatcher
from pinspect.ui.table import render_process_table


def handle_grep(
    pattern: str,
    proc_root: str = "/proc",
    user_filter: Optional[str] = None,
    match_name: bool = False,
    match_cmdline: bool = False,
    match_exe: bool = False,
    limit: Optional[int] = None,
    output_dispatcher: Optional[OutputDispatcher] = None,
) -> int:
    """Search running processes like grep: by name, command line, executable, and user."""
    procfs = ProcFS(proc_root)
    collector = ProcessCollector(procfs)
    dispatcher = output_dispatcher or OutputDispatcher()

    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        print(f"Error: invalid search pattern: {exc}", file=sys.stderr)
        return 1

    # If no field scope flag was given, search all fields
    if not (match_name or match_cmdline or match_exe):
        match_name = match_cmdline = match_exe = True

    processes = collector.collect_all_processes(deep=False)

    results: List[ProcessInfo] = []
    for p in processes:
        if user_filter:
            if user_filter.isdigit():
                if p.creds.ruid != int(user_filter) and p.creds.euid != int(user_filter):
                    continue
            elif user_filter.lower() not in p.creds.user.lower():
                continue

        if not (
            (match_name and regex.search(p.name))
            or (match_cmdline and regex.search(p.cmdline or ""))
            or (match_exe and p.exe and regex.search(p.exe))
        ):
            continue

        results.append(p)

    # Relevance ordering: exact program-name matches first, then argument matches
    def rank(p: ProcessInfo) -> int:
        if match_name and regex.search(p.name):
            return 0
        if match_cmdline and regex.search(p.cmdline or ""):
            return 1
        return 2

    results.sort(key=lambda p: (rank(p), -p.cpu.cpu_percent, p.pid))

    if limit is not None and limit > 0:
        results = results[:limit]

    dispatcher.handle(
        data=results,
        rich_render_fn=lambda: render_process_table(
            results,
            wide=dispatcher.wide_mode,
            highlight_pattern=pattern,
        ),
        csv_type="process",
        quiet_extractor=lambda procs: [str(p.pid) for p in procs],
    )
    # Follow grep conventions: exit 1 when nothing matched so scripts can
    # branch on the result.
    return 0 if results else 1
