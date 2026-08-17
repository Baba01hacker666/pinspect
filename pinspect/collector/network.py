"""
Network socket collector parsing /proc/net/tcp, tcp6, udp, udp6, and unix.
Maps network and unix domain sockets to processes and file descriptors.
"""

import os
import socket
import struct
from typing import Dict, List, Optional, Tuple, Set
from pinspect.collector.procfs import ProcFS
from pinspect.model.network import (
    SocketInfo,
    SocketProtocol,
    SocketFamily,
    SocketState,
    NetworkSummary,
)
from pinspect.utils.system import resolve_uid


def parse_ipv4_hex(hex_str: str) -> str:
    """Convert hex string (e.g. '0100007F') from /proc/net/tcp to dotted IPv4."""
    try:
        # On Linux /proc/net/tcp, IPv4 is stored in host-order (little endian)
        packed = struct.pack("<I", int(hex_str, 16))
        return socket.inet_ntoa(packed)
    except Exception:
        return hex_str


def parse_ipv6_hex(hex_str: str) -> str:
    """Convert 32-hex-char IPv6 string from /proc/net/tcp6 to standard IPv6 string."""
    try:
        # IPv6 in /proc/net/tcp6 is 4 32-bit words in host-endian format
        words = [int(hex_str[i : i + 8], 16) for i in range(0, 32, 8)]
        packed = b"".join(struct.pack("<I", w) for w in words)
        return socket.inet_ntop(socket.AF_INET6, packed)
    except Exception:
        return hex_str


def parse_port_hex(hex_str: str) -> int:
    """Convert hex port string (e.g. '0050') to int."""
    try:
        return int(hex_str, 16)
    except Exception:
        return 0


class NetworkCollector:
    """Parses network sockets from /proc/net and associates them with PIDs."""

    def __init__(self, procfs: Optional[ProcFS] = None):
        self.procfs = procfs or ProcFS()
        self._inode_to_proc_cache: Optional[Dict[int, Tuple[int, int]]] = None

    def build_inode_process_map(self) -> Dict[int, Tuple[int, int]]:
        """
        Scan all processes' /proc/<pid>/fd/ to build a map: inode -> (pid, fd).
        """
        inode_map: Dict[int, Tuple[int, int]] = {}
        for pid in self.procfs.list_pids():
            fd_entries = self.procfs.list_dir(pid, "fd")
            for fd_str in fd_entries:
                if not fd_str.isdigit():
                    continue
                target = self.procfs.read_symlink(pid, "fd", fd_str)
                if target and target.startswith("socket:["):
                    try:
                        ino = int(target[8:-1])
                        inode_map[ino] = (pid, int(fd_str))
                    except ValueError:
                        pass
        self._inode_to_proc_cache = inode_map
        return inode_map

    def collect_all_sockets(
        self,
        pid_filter: Optional[int] = None,
        port_filter: Optional[int] = None,
        listen_only: bool = False,
    ) -> List[SocketInfo]:
        """Collect all network & unix sockets, optionally filtered."""
        inode_map = self._inode_to_proc_cache or self.build_inode_process_map()
        sockets: List[SocketInfo] = []

        # 1. TCP IPv4
        sockets.extend(self._parse_inet_table("net/tcp", SocketProtocol.TCP, SocketFamily.INET, inode_map, pid_filter))

        # 2. TCP IPv6
        sockets.extend(self._parse_inet_table("net/tcp6", SocketProtocol.TCP6, SocketFamily.INET6, inode_map, pid_filter))

        # 3. UDP IPv4
        sockets.extend(self._parse_inet_table("net/udp", SocketProtocol.UDP, SocketFamily.INET, inode_map, pid_filter))

        # 4. UDP IPv6
        sockets.extend(self._parse_inet_table("net/udp6", SocketProtocol.UDP6, SocketFamily.INET6, inode_map, pid_filter))

        # 5. Unix Domain Sockets
        sockets.extend(self._parse_unix_table(inode_map, pid_filter))

        # Apply filters
        if port_filter is not None:
            sockets = [
                s for s in sockets
                if (s.local_port == port_filter or s.remote_port == port_filter)
            ]

        if listen_only:
            sockets = [s for s in sockets if s.is_listening]

        return sockets

    def collect_process_network_summary(self, pid: int) -> NetworkSummary:
        """Collect categorized network summary for a specific PID."""
        sockets = self.collect_all_sockets(pid_filter=pid)
        summary = NetworkSummary(total_sockets_count=len(sockets))

        for s in sockets:
            if s.protocol in (SocketProtocol.TCP, SocketProtocol.TCP6):
                if s.is_listening:
                    summary.listening_tcp.append(s)
                elif s.is_established:
                    summary.established_tcp.append(s)
                else:
                    summary.other_connections.append(s)
            elif s.protocol in (SocketProtocol.UDP, SocketProtocol.UDP6):
                if s.local_port and s.local_port > 0:
                    summary.listening_udp.append(s)
                else:
                    summary.other_connections.append(s)
            elif s.protocol == SocketProtocol.UNIX:
                summary.unix_sockets.append(s)
            else:
                summary.other_connections.append(s)

        return summary

    def _parse_inet_table(
        self,
        rel_path: str,
        protocol: SocketProtocol,
        family: SocketFamily,
        inode_map: Dict[int, Tuple[int, int]],
        pid_filter: Optional[int] = None,
    ) -> List[SocketInfo]:
        lines = self.procfs.read_lines(rel_path)
        if not lines or len(lines) <= 1:
            return []

        sockets: List[SocketInfo] = []
        is_ipv6 = family == SocketFamily.INET6

        # Line 0 is header: sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 10:
                continue

            try:
                local_hex, local_port_hex = parts[1].split(":")
                remote_hex, remote_port_hex = parts[2].split(":")
                state_hex = parts[3]
                tx_rx = parts[4].split(":")
                tx_q = int(tx_rx[0], 16) if len(tx_rx) > 0 else 0
                rx_q = int(tx_rx[1], 16) if len(tx_rx) > 1 else 0
                uid = int(parts[7])
                inode = int(parts[9])

                local_addr = parse_ipv6_hex(local_hex) if is_ipv6 else parse_ipv4_hex(local_hex)
                remote_addr = parse_ipv6_hex(remote_hex) if is_ipv6 else parse_ipv4_hex(remote_hex)
                local_port = parse_port_hex(local_port_hex)
                remote_port = parse_port_hex(remote_port_hex)

                state = SocketState.from_tcp_hex(state_hex)
                if protocol in (SocketProtocol.UDP, SocketProtocol.UDP6):
                    state = SocketState.LISTEN if local_port > 0 and remote_port == 0 else SocketState.ESTABLISHED

                # Match process
                pid = None
                fd = None
                if inode in inode_map:
                    pid, fd = inode_map[inode]

                if pid_filter is not None and pid != pid_filter:
                    continue

                proc_name = None
                if pid:
                    comm = self.procfs.read_file(pid, "comm")
                    if comm:
                        proc_name = str(comm).strip()

                user_name = resolve_uid(uid)

                sockets.append(
                    SocketInfo(
                        protocol=protocol,
                        family=family,
                        local_address=local_addr,
                        local_port=local_port,
                        remote_address=remote_addr,
                        remote_port=remote_port,
                        state=state,
                        inode=inode,
                        fd=fd,
                        pid=pid,
                        process_name=proc_name,
                        user=user_name,
                        uid=uid,
                        rx_queue=rx_q,
                        tx_queue=tx_q,
                    )
                )
            except (ValueError, IndexError):
                continue

        return sockets

    def _parse_unix_table(
        self,
        inode_map: Dict[int, Tuple[int, int]],
        pid_filter: Optional[int] = None,
    ) -> List[SocketInfo]:
        lines = self.procfs.read_lines("net/unix")
        if not lines or len(lines) <= 1:
            return []

        sockets: List[SocketInfo] = []
        # Header: Num RefCount Protocol Flags Type St Inode Path
        for line in lines[1:]:
            parts = line.split(maxsplit=7)
            if len(parts) < 7:
                continue

            try:
                state_num = parts[5]
                inode = int(parts[6])
                path = parts[7].strip() if len(parts) >= 8 else None

                state = SocketState.CONNECTED if state_num == "03" else SocketState.UNCONNECTED
                if state_num == "01":
                    state = SocketState.LISTEN

                pid = None
                fd = None
                if inode in inode_map:
                    pid, fd = inode_map[inode]

                if pid_filter is not None and pid != pid_filter:
                    continue

                proc_name = None
                if pid:
                    comm = self.procfs.read_file(pid, "comm")
                    if comm:
                        proc_name = str(comm).strip()

                sockets.append(
                    SocketInfo(
                        protocol=SocketProtocol.UNIX,
                        family=SocketFamily.UNIX,
                        local_address=path or f"[inode:{inode}]",
                        local_port=None,
                        remote_address="",
                        remote_port=None,
                        state=state,
                        inode=inode,
                        fd=fd,
                        pid=pid,
                        process_name=proc_name,
                        unix_path=path,
                    )
                )
            except (ValueError, IndexError):
                continue

        return sockets
