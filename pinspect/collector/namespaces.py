"""
Linux namespace collector (/proc/<pid>/ns).
"""

import os
import re
from typing import Dict, Optional, Tuple
from pinspect.collector.procfs import ProcFS
from pinspect.model.security import NamespaceInfo

KNOWN_NAMESPACES = [
    "cgroup",
    "ipc",
    "mnt",
    "net",
    "pid",
    "pid_for_children",
    "time",
    "time_for_children",
    "user",
    "uts",
]


class NamespaceCollector:
    """Collects and compares namespace inode information."""

    def __init__(self, procfs: Optional[ProcFS] = None):
        self.procfs = procfs or ProcFS()
        self._host_namespaces_cache: Optional[Dict[str, int]] = None

    def get_host_namespaces(self) -> Dict[str, int]:
        """
        Get baseline namespace inodes from PID 1 (or current process if PID 1 is inaccessible).
        """
        if self._host_namespaces_cache is not None:
            return self._host_namespaces_cache

        ns_map: Dict[str, int] = {}
        # Try PID 1 first
        pids_to_try = [1, os.getpid()]
        for pid in pids_to_try:
            ns_dict = self.collect_namespaces_for_pid(pid, compare_with_host=False)
            if ns_dict:
                for k, v in ns_dict.items():
                    if v.inode is not None:
                        ns_map[k] = v.inode
                if ns_map:
                    break

        self._host_namespaces_cache = ns_map
        return ns_map

    def collect_namespaces_for_pid(
        self, pid: int, compare_with_host: bool = True
    ) -> Dict[str, NamespaceInfo]:
        """Collect all namespaces for a specific PID."""
        host_ns = self.get_host_namespaces() if compare_with_host else {}
        results: Dict[str, NamespaceInfo] = {}

        ns_dir = self.procfs.path(pid, "ns")
        if not self.procfs.is_dir(pid, "ns"):
            return results

        entries = self.procfs.list_dir(pid, "ns")
        for entry in entries:
            target = self.procfs.read_symlink(pid, "ns", entry)
            inode = None
            if target:
                match = re.search(r"\[([0-9]+)\]", target)
                if match:
                    inode = int(match.group(1))
            
            if inode is None:
                st = self.procfs.stat_path(pid, "ns", entry)
                if st:
                    inode = st.st_ino

            is_isolated = False
            if compare_with_host and entry in host_ns and inode is not None:
                # If host namespace inode exists and differs, it is isolated
                if host_ns[entry] != inode:
                    is_isolated = True

            results[entry] = NamespaceInfo(
                ns_type=entry,
                inode=inode,
                target_path=target,
                is_isolated=is_isolated,
            )

        return results
