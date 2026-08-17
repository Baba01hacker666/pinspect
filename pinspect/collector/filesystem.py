"""
Filesystem, file descriptors, and deleted-file collector.
"""

import contextlib
import os
import re
from typing import List, Optional, Set, Tuple

from pinspect.collector.procfs import ProcFS
from pinspect.model.filesystem import (
    DeletedFileInfo,
    FDType,
    FileDescriptorInfo,
    MountInfo,
)


class FilesystemCollector:
    """Enumerates open file descriptors, targets, modes, and deleted files."""

    def __init__(self, procfs: Optional[ProcFS] = None):
        self.procfs = procfs or ProcFS()

    def collect_fds(self, pid: int) -> List[FileDescriptorInfo]:
        """Enumerate all open file descriptors for a PID."""
        fd_entries = self.procfs.list_dir(pid, "fd")
        results: List[FileDescriptorInfo] = []

        # Socket fds are symlinks like "socket:[inode]" for both inet and unix
        # sockets; /proc/net/unix tells us which inodes belong to unix sockets.
        unix_inodes = self._collect_unix_inodes()

        for fd_str in fd_entries:
            if not fd_str.isdigit():
                continue
            fd_num = int(fd_str)
            target = self.procfs.read_symlink(pid, "fd", fd_str)
            if not target:
                continue

            fd_type, is_deleted, clean_path, inode = self._classify_target(target, unix_inodes)
            
            # Read fdinfo for pos & flags
            pos, flags, mode = self._parse_fdinfo(pid, fd_str)

            file_size = None
            owner_uid = None
            owner_gid = None

            # If it's a regular file or directory on disk, try stat
            if fd_type in (FDType.REGULAR, FDType.DIRECTORY, FDType.DELETED) and clean_path.startswith("/"):
                # Use /proc/<pid>/fd/<fd> to stat even if unlinked on disk
                proc_fd_path = self.procfs.path(pid, "fd", fd_str)
                try:
                    st = os.stat(proc_fd_path)
                    file_size = st.st_size
                    owner_uid = st.st_uid
                    owner_gid = st.st_gid
                    if inode is None:
                        inode = st.st_ino
                except (OSError, PermissionError):
                    pass

            results.append(
                FileDescriptorInfo(
                    fd=fd_num,
                    target=target,
                    resolved_path=clean_path,
                    fd_type=fd_type,
                    is_deleted=is_deleted,
                    mode=mode,
                    pos=pos,
                    flags=flags,
                    inode=inode,
                    file_size=file_size,
                    owner_uid=owner_uid,
                    owner_gid=owner_gid,
                )
            )

        results.sort(key=lambda x: x.fd)
        return results

    def collect_deleted_files(self, pid: int) -> List[DeletedFileInfo]:
        """Collect all files held open by the process that are unlinked from disk."""
        fds = self.collect_fds(pid)
        deleted: List[DeletedFileInfo] = []
        for f in fds:
            if f.is_deleted:
                deleted.append(
                    DeletedFileInfo(
                        fd=f.fd,
                        path=f.resolved_path,
                        file_type=f.fd_type.label,
                        size_bytes=f.file_size,
                        inode=f.inode,
                    )
                )
        return deleted

    def collect_mounts(self, pid: int) -> List[MountInfo]:
        """Parse /proc/<pid>/mountinfo."""
        lines = self.procfs.read_lines(pid, "mountinfo")
        mounts: List[MountInfo] = []

        for line in lines:
            parts = line.split()
            if len(parts) >= 7:
                try:
                    mount_id = int(parts[0])
                    parent_id = int(parts[1])
                    maj_min = parts[2]
                    root = parts[3]
                    mount_point = parts[4]
                    mount_opts = parts[5]

                    # Separator '-' divides standard fields and filesystem-specific fields
                    dash_idx = -1
                    for idx, p in enumerate(parts[6:], start=6):
                        if p == "-":
                            dash_idx = idx
                            break

                    fs_type = "?"
                    mount_source = "?"
                    super_opts = ""
                    if dash_idx != -1 and dash_idx + 2 < len(parts):
                        fs_type = parts[dash_idx + 1]
                        mount_source = parts[dash_idx + 2]
                        if dash_idx + 3 < len(parts):
                            super_opts = " ".join(parts[dash_idx + 3 :])

                    mounts.append(
                        MountInfo(
                            mount_id=mount_id,
                            parent_id=parent_id,
                            major_minor=maj_min,
                            root=root,
                            mount_point=mount_point,
                            mount_options=mount_opts,
                            fs_type=fs_type,
                            mount_source=mount_source,
                            super_options=super_opts,
                        )
                    )
                except (ValueError, IndexError):
                    continue

        return mounts

    def _collect_unix_inodes(self) -> Set[int]:
        """Collect inode numbers of unix domain sockets from /proc/net/unix."""
        inodes: Set[int] = set()
        lines = self.procfs.read_lines("net", "unix")
        # Header: Num RefCount Protocol Flags Type St Inode Path
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 7:
                try:
                    inodes.add(int(parts[6]))
                except ValueError:
                    continue
        return inodes

    def _classify_target(
        self,
        target: str,
        unix_inodes: Optional[Set[int]] = None,
    ) -> Tuple[FDType, bool, str, Optional[int]]:
        """Classify target string into FDType, is_deleted, clean_path, inode."""
        is_deleted = False
        clean_path = target
        inode = None

        if target.endswith(" (deleted)"):
            is_deleted = True
            clean_path = target[:-10]

        if clean_path.startswith("pipe:["):
            match = re.search(r"pipe:\[([0-9]+)\]", clean_path)
            if match:
                inode = int(match.group(1))
            return (FDType.PIPE, is_deleted, clean_path, inode)

        elif clean_path.startswith("socket:["):
            match = re.search(r"socket:\[([0-9]+)\]", clean_path)
            if match:
                inode = int(match.group(1))
                if unix_inodes and inode in unix_inodes:
                    return (FDType.UNIX_SOCKET, is_deleted, clean_path, inode)
            return (FDType.INET_SOCKET, is_deleted, clean_path, inode)

        elif clean_path.startswith("anon_inode:"):
            return (FDType.ANON_INODE, is_deleted, clean_path, None)

        elif clean_path.startswith("/dev/"):
            return (FDType.CHAR_DEV, is_deleted, clean_path, None)

        elif is_deleted:
            return (FDType.DELETED, True, clean_path, None)

        elif clean_path.startswith("/"):
            return (FDType.REGULAR, False, clean_path, None)

        return (FDType.UNKNOWN, is_deleted, clean_path, None)

    def _parse_fdinfo(self, pid: int, fd_str: str) -> Tuple[Optional[int], Optional[int], Optional[str]]:
        """Parse /proc/<pid>/fdinfo/<fd> for pos and flags."""
        lines = self.procfs.read_lines(pid, "fdinfo", fd_str)
        pos = None
        flags = None
        mode = None

        for line in lines:
            if line.startswith("pos:"):
                with contextlib.suppress(ValueError):
                    pos = int(line.split(":")[1].strip())
            elif line.startswith("flags:"):
                try:
                    flags_str = line.split(":")[1].strip()
                    flags = int(flags_str, 8)  # flags are formatted in octal
                    access_mode = flags & os.O_ACCMODE
                    if access_mode == os.O_RDONLY:
                        mode = "r"
                    elif access_mode == os.O_WRONLY:
                        mode = "w"
                    elif access_mode == os.O_RDWR:
                        mode = "rw"
                    if flags & os.O_APPEND:
                        mode = f"{mode or ''}+a"
                except ValueError:
                    pass

        return (pos, flags, mode)
