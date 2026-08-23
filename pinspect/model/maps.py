"""
Memory map region models parsed from /proc/<pid>/maps.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class MapRegion:
    """A single memory mapping from /proc/<pid>/maps."""

    start_addr: str = "0"
    end_addr: str = "0"
    start_addr_int: int = 0
    end_addr_int: int = 0
    size_bytes: int = 0
    perms: str = ""
    offset: str = "0"
    device: str = ""
    inode: int = 0
    path: Optional[str] = None

    # Derived forensic indicators
    is_readable: bool = False
    is_writable: bool = False
    is_executable: bool = False
    is_private: bool = False
    is_anonymous: bool = True  # No file backing (heap, stack, anon mappings)
    is_rwx: bool = False  # Readable + writable + executable
    is_anonymous_exec: bool = False  # Executable with no file backing (injection evidence)
    is_memfd: bool = False  # memfd_create backed mapping (fileless execution)
    is_deleted_path: bool = False  # Backing file was unlinked after mapping


@dataclass
class MapsReport:
    """Aggregated memory map intelligence for a process."""

    pid: int
    regions: List[MapRegion] = field(default_factory=list)
    total_regions: int = 0
    total_mapped_bytes: int = 0
    executable_regions: int = 0
    rwx_region_count: int = 0
    anonymous_exec_count: int = 0
    memfd_paths: List[str] = field(default_factory=list)
    deleted_paths: List[str] = field(default_factory=list)

    @property
    def has_suspicious_mappings(self) -> bool:
        return self.rwx_region_count > 0 or self.anonymous_exec_count > 0 or bool(self.memfd_paths) or bool(self.deleted_paths)
