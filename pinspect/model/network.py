"""
Network socket data models.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class SocketProtocol(Enum):
    TCP = "TCP"
    TCP6 = "TCP6"
    UDP = "UDP"
    UDP6 = "UDP6"
    UNIX = "UNIX"
    RAW = "RAW"
    RAW6 = "RAW6"
    NETLINK = "NETLINK"
    PACKET = "PACKET"
    UNKNOWN = "UNKNOWN"


class SocketFamily(Enum):
    INET = "IPv4"
    INET6 = "IPv6"
    UNIX = "UNIX"
    OTHER = "OTHER"


class SocketState(Enum):
    LISTEN = "LISTEN"
    ESTABLISHED = "ESTABLISHED"
    SYN_SENT = "SYN_SENT"
    SYN_RECV = "SYN_RECV"
    FIN_WAIT1 = "FIN_WAIT1"
    FIN_WAIT2 = "FIN_WAIT2"
    TIME_WAIT = "TIME_WAIT"
    CLOSE = "CLOSE"
    CLOSE_WAIT = "CLOSE_WAIT"
    LAST_ACK = "LAST_ACK"
    CLOSING = "CLOSING"
    UNCONNECTED = "UNCONNECTED"
    CONNECTED = "CONNECTED"
    DISCONNECTING = "DISCONNECTING"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_tcp_hex(cls, hex_code: str) -> "SocketState":
        # Standard Linux TCP states in hex from /proc/net/tcp
        states = {
            "01": cls.ESTABLISHED,
            "02": cls.SYN_SENT,
            "03": cls.SYN_RECV,
            "04": cls.FIN_WAIT1,
            "05": cls.FIN_WAIT2,
            "06": cls.TIME_WAIT,
            "07": cls.CLOSE,
            "08": cls.CLOSE_WAIT,
            "09": cls.LAST_ACK,
            "0A": cls.LISTEN,
            "0B": cls.CLOSING,
        }
        return states.get(hex_code.upper(), cls.UNKNOWN)


@dataclass
class SocketInfo:
    protocol: SocketProtocol
    family: SocketFamily
    local_address: str
    local_port: Optional[int]
    remote_address: str
    remote_port: Optional[int]
    state: SocketState
    inode: int
    fd: Optional[int] = None
    pid: Optional[int] = None
    process_name: Optional[str] = None
    user: Optional[str] = None
    uid: Optional[int] = None
    unix_path: Optional[str] = None
    rx_queue: int = 0
    tx_queue: int = 0

    @property
    def is_listening(self) -> bool:
        return self.state == SocketState.LISTEN

    @property
    def is_established(self) -> bool:
        return self.state == SocketState.ESTABLISHED

    @property
    def local_endpoint(self) -> str:
        if self.protocol == SocketProtocol.UNIX:
            return self.unix_path or f"[unix inode:{self.inode}]"
        if self.local_port is not None:
            return f"{self.local_address}:{self.local_port}"
        return self.local_address

    @property
    def remote_endpoint(self) -> str:
        if self.protocol == SocketProtocol.UNIX:
            return ""
        if self.remote_port is not None and self.remote_port > 0:
            return f"{self.remote_address}:{self.remote_port}"
        return "*:*" if not self.remote_address or self.remote_address in ("0.0.0.0", "::") else self.remote_address


@dataclass
class NetworkSummary:
    listening_tcp: List[SocketInfo] = field(default_factory=list)
    listening_udp: List[SocketInfo] = field(default_factory=list)
    established_tcp: List[SocketInfo] = field(default_factory=list)
    other_connections: List[SocketInfo] = field(default_factory=list)
    unix_sockets: List[SocketInfo] = field(default_factory=list)
    total_sockets_count: int = 0
