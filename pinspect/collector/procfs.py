"""
Safe, low-level Linux /proc filesystem accessor.
Supports custom procfs root directories for testing and mock data.
"""

import os
from typing import List, Optional, Union, Dict, Any


class ProcFS:
    """Safe wrapper around /proc operations with error handling and path resolution."""

    def __init__(self, proc_root: str = "/proc"):
        self.proc_root = os.path.abspath(proc_root)

    def path(self, *parts: Union[str, int]) -> str:
        """Construct an absolute path inside this procfs root."""
        str_parts = [str(p) for p in parts]
        return os.path.join(self.proc_root, *str_parts)

    def list_pids(self) -> List[int]:
        """Enumerate all numeric PID directories currently in /proc."""
        pids: List[int] = []
        try:
            for entry in os.listdir(self.proc_root):
                if entry.isdigit():
                    pids.append(int(entry))
        except (PermissionError, FileNotFoundError, OSError):
            pass
        return sorted(pids)

    def read_file(self, *parts: Union[str, int], binary: bool = False) -> Optional[Union[str, bytes]]:
        """Safely read content from a proc file."""
        target_path = self.path(*parts)
        try:
            mode = "rb" if binary else "r"
            encoding = None if binary else "utf-8"
            errors = None if binary else "replace"
            with open(target_path, mode, encoding=encoding, errors=errors) as f:
                return f.read()
        except (PermissionError, FileNotFoundError, ProcessLookupError, IsADirectoryError, OSError):
            return None

    def read_lines(self, *parts: Union[str, int]) -> List[str]:
        """Safely read lines from a proc file."""
        target_path = self.path(*parts)
        try:
            with open(target_path, "r", encoding="utf-8", errors="replace") as f:
                return [line.rstrip("\r\n") for line in f]
        except (PermissionError, FileNotFoundError, ProcessLookupError, IsADirectoryError, OSError):
            return []

    def read_symlink(self, *parts: Union[str, int]) -> Optional[str]:
        """Safely resolve a symlink in proc (e.g. /proc/<pid>/exe, cwd, root, fd/N)."""
        target_path = self.path(*parts)
        try:
            return os.readlink(target_path)
        except (PermissionError, FileNotFoundError, ProcessLookupError, NotADirectoryError, OSError):
            return None

    def list_dir(self, *parts: Union[str, int]) -> List[str]:
        """Safely list entries in a proc directory (e.g. /proc/<pid>/fd)."""
        target_path = self.path(*parts)
        try:
            return os.listdir(target_path)
        except (PermissionError, FileNotFoundError, ProcessLookupError, NotADirectoryError, OSError):
            return []

    def exists(self, *parts: Union[str, int]) -> bool:
        """Check if path exists inside procfs."""
        target_path = self.path(*parts)
        try:
            return os.path.exists(target_path)
        except OSError:
            return False

    def is_dir(self, *parts: Union[str, int]) -> bool:
        """Check if path is a directory inside procfs."""
        target_path = self.path(*parts)
        try:
            return os.path.isdir(target_path)
        except OSError:
            return False

    def stat_path(self, *parts: Union[str, int]) -> Optional[os.stat_result]:
        """Stat a path inside procfs safely."""
        target_path = self.path(*parts)
        try:
            return os.stat(target_path)
        except (PermissionError, FileNotFoundError, ProcessLookupError, OSError):
            return None
