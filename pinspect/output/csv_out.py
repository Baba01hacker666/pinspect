"""
CSV exporter for process listings, open files, network sockets, and namespaces.
"""

import csv
import io
from typing import List, Any
from pinspect.model.process import ProcessInfo
from pinspect.model.filesystem import FileDescriptorInfo
from pinspect.model.network import SocketInfo
from pinspect.model.security import NamespaceInfo


def export_processes_csv(processes: List[ProcessInfo]) -> str:
    """Export process list to CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "PID",
        "PPID",
        "USER",
        "STATE",
        "CPU_PCT",
        "MEM_PCT",
        "RSS_BYTES",
        "VMS_BYTES",
        "THREADS",
        "ORIGIN_TYPE",
        "SERVICE_NAME",
        "CONTAINER_ID",
        "COMM",
        "EXE",
        "IS_DELETED_EXE",
        "CMDLINE",
    ])

    for p in processes:
        writer.writerow([
            p.pid,
            p.ppid,
            p.creds.user,
            p.state_char,
            p.cpu.cpu_percent,
            p.memory.mem_percent,
            p.memory.rss_bytes,
            p.memory.vms_bytes,
            p.threads_count,
            p.origin.launcher_type,
            p.origin.service_name or "",
            p.cgroup.container_id or "",
            p.name,
            p.exe or "",
            "true" if p.is_deleted_exe else "false",
            p.cmdline,
        ])

    return output.getvalue()


def export_files_csv(files: List[FileDescriptorInfo], pid: int) -> str:
    """Export open file descriptors to CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "PID",
        "FD",
        "TYPE",
        "MODE",
        "DELETED",
        "INODE",
        "SIZE_BYTES",
        "TARGET",
    ])

    for f in files:
        writer.writerow([
            pid,
            f.fd,
            f.fd_type.value,
            f.mode or "",
            "true" if f.is_deleted else "false",
            f.inode or "",
            f.file_size or "",
            f.target,
        ])

    return output.getvalue()


def export_sockets_csv(sockets: List[SocketInfo]) -> str:
    """Export network and unix sockets to CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "PROTO",
        "LOCAL_ADDR",
        "LOCAL_PORT",
        "REMOTE_ADDR",
        "REMOTE_PORT",
        "STATE",
        "PID",
        "PROCESS",
        "USER",
        "FD",
        "INODE",
    ])

    for s in sockets:
        writer.writerow([
            s.protocol.value,
            s.local_address,
            s.local_port or "",
            s.remote_address,
            s.remote_port or "",
            s.state.value,
            s.pid or "",
            s.process_name or "",
            s.user or "",
            s.fd or "",
            s.inode,
        ])

    return output.getvalue()
