"""
Memory map collector parsing /proc/<pid>/maps into forensic indicators.
"""

import re
from typing import List, Optional

from pinspect.collector.procfs import ProcFS
from pinspect.model.maps import MapRegion, MapsReport

_MAPS_LINE_RE = re.compile(
    r"^([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+(\S{4})\s+([0-9a-fA-F]+)\s+(\S+)\s+(\d+)\s*(.*)$"
)

_SUSPICIOUS_DIR_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")


def is_suspicious_path(path: str) -> bool:
    """True if the path lives in a world-writable staging location."""
    if not path:
        return False
    normalized = path.split(" (deleted)")[0]
    return normalized.startswith(_SUSPICIOUS_DIR_PREFIXES)


class MapsCollector:
    """Parses and analyzes /proc/<pid>/maps for a process."""

    def __init__(self, procfs: Optional[ProcFS] = None):
        self.procfs = procfs or ProcFS()

    def collect(self, pid: int) -> MapsReport:
        """Collect memory mappings for PID. Returns empty report on failure."""
        report = MapsReport(pid=pid)
        lines = self.procfs.read_lines(pid, "maps")
        if not lines:
            # Requires ptrace permissions for other users' processes
            return report

        regions: List[MapRegion] = []
        for line in lines:
            region = self._parse_line(line)
            if region is not None:
                regions.append(region)

        report.regions = regions
        report.total_regions = len(regions)
        report.total_mapped_bytes = sum(r.size_bytes for r in regions)
        report.executable_regions = sum(1 for r in regions if r.is_executable)
        report.rwx_region_count = sum(1 for r in regions if r.is_rwx)
        report.anonymous_exec_count = sum(1 for r in regions if r.is_anonymous_exec)
        report.memfd_paths = sorted({r.path for r in regions if r.is_memfd and r.path})
        report.deleted_paths = sorted({r.path for r in regions if r.is_deleted_path and r.path})
        return report

    def _parse_line(self, line: str) -> Optional[MapRegion]:
        match = _MAPS_LINE_RE.match(line.strip())
        if not match:
            return None

        start_hex, end_hex, perms, offset_hex, device, inode_str, path_part = match.groups()
        try:
            start_int = int(start_hex, 16)
            end_int = int(end_hex, 16)
            inode = int(inode_str)
        except ValueError:
            return None

        path = path_part.strip() if path_part.strip() else None
        is_readable = "r" in perms
        is_writable = "w" in perms
        is_executable = "x" in perms

        is_memfd = bool(path and path.startswith("/memfd:"))
        is_deleted_path = bool(path and path.endswith("(deleted)"))
        is_anonymous = path is None

        return MapRegion(
            start_addr=f"{start_int:x}",
            end_addr=f"{end_int:x}",
            start_addr_int=start_int,
            end_addr_int=end_int,
            size_bytes=end_int - start_int,
            perms=perms,
            offset=str(int(offset_hex, 16)) if offset_hex else "0",
            device=device,
            inode=inode,
            path=path,
            is_readable=is_readable,
            is_writable=is_writable,
            is_executable=is_executable,
            is_private="p" in perms,
            is_anonymous=is_anonymous,
            is_rwx=is_readable and is_writable and is_executable,
            is_anonymous_exec=is_anonymous and is_executable,
            is_memfd=is_memfd,
            is_deleted_path=is_deleted_path,
        )
