"""
Filesystem and file descriptor data models.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class FDType(Enum):
    REGULAR = "regular"
    DIRECTORY = "directory"
    PIPE = "pipe"
    UNIX_SOCKET = "unix_socket"
    INET_SOCKET = "inet_socket"
    CHAR_DEV = "char_device"
    BLOCK_DEV = "block_device"
    ANON_INODE = "anon_inode"
    DELETED = "deleted"
    UNKNOWN = "unknown"

    @property
    def label(self) -> str:
        labels = {
            FDType.REGULAR: "Regular File",
            FDType.DIRECTORY: "Directory",
            FDType.PIPE: "Pipe",
            FDType.UNIX_SOCKET: "Unix Socket",
            FDType.INET_SOCKET: "Network Socket",
            FDType.CHAR_DEV: "Char Device",
            FDType.BLOCK_DEV: "Block Device",
            FDType.ANON_INODE: "Anon Inode",
            FDType.DELETED: "Deleted File",
            FDType.UNKNOWN: "Unknown",
        }
        return labels.get(self, "Unknown")


@dataclass
class FileDescriptorInfo:
    fd: int
    target: str
    resolved_path: str
    fd_type: FDType
    is_deleted: bool = False
    mode: Optional[str] = None  # r, w, rw, a
    pos: Optional[int] = None
    flags: Optional[int] = None
    inode: Optional[int] = None
    file_size: Optional[int] = None
    owner_uid: Optional[int] = None
    owner_gid: Optional[int] = None
    device: Optional[str] = None


@dataclass
class DeletedFileInfo:
    fd: Optional[int]
    path: str
    file_type: str
    size_bytes: Optional[int] = None
    inode: Optional[int] = None


@dataclass
class MountInfo:
    mount_id: int
    parent_id: int
    major_minor: str
    root: str
    mount_point: str
    mount_options: str
    fs_type: str
    mount_source: str
    super_options: str
