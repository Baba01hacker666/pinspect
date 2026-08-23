"""
Process data models representing Linux process metadata.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ProcessState(Enum):
    RUNNING = "R"
    SLEEPING = "S"
    DISK_SLEEP = "D"
    ZOMBIE = "Z"
    STOPPED = "T"
    TRACED = "t"
    PAGING = "W"  # 'W' is legacy Paging; kernels 2.6.33-3.13 reused it for Waking
    DEAD = "X"
    WAKEKILL = "K"
    PARKED = "P"
    IDLE = "I"
    UNKNOWN = "?"

    @property
    def label(self) -> str:
        labels = {
            ProcessState.RUNNING: "Running",
            ProcessState.SLEEPING: "Interruptible Sleep",
            ProcessState.DISK_SLEEP: "Uninterruptible Sleep (I/O)",
            ProcessState.ZOMBIE: "Zombie",
            ProcessState.STOPPED: "Stopped",
            ProcessState.TRACED: "Tracing Stop",
            ProcessState.PAGING: "Paging/Waking",
            ProcessState.DEAD: "Dead",
            ProcessState.WAKEKILL: "Wakekill",
            ProcessState.PARKED: "Parked",
            ProcessState.IDLE: "Idle Kernel Thread",
            ProcessState.UNKNOWN: "Unknown",
        }
        return labels.get(self, "Unknown")

    @classmethod
    def from_char(cls, char: str) -> "ProcessState":
        # Match case-sensitively. Linux stat encodes distinct states in
        # different case (e.g. 'T' = stopped, 't' = traced/ptrace-stop,
        # 'I' = idle kernel thread). Uppercasing would collapse 't' into
        # 'T' and make ProcessState.TRACED unreachable.
        if not char:
            return cls.UNKNOWN
        for member in cls:
            if member.value == char:
                return member
        return cls.UNKNOWN


@dataclass
class CredentialInfo:
    ruid: int = 0
    euid: int = 0
    suid: int = 0
    fsuid: int = 0
    rgid: int = 0
    egid: int = 0
    sgid: int = 0
    fsgid: int = 0
    user: str = "root"
    group: str = "root"
    effective_user: str = "root"
    effective_group: str = "root"
    groups: List[int] = field(default_factory=list)
    group_names: List[str] = field(default_factory=list)
    loginuid: Optional[int] = None
    loginuser: Optional[str] = None


@dataclass
class CPUStats:
    utime_ticks: int = 0
    stime_ticks: int = 0
    cutime_ticks: int = 0
    cstime_ticks: int = 0
    total_time_seconds: float = 0.0
    cpu_percent: float = 0.0
    processor: int = 0
    cpus_allowed_list: str = ""
    cpus_allowed_count: int = 1


@dataclass
class MemoryStats:
    rss_bytes: int = 0
    vms_bytes: int = 0
    shared_bytes: int = 0
    text_bytes: int = 0
    data_bytes: int = 0
    swap_bytes: int = 0
    pss_bytes: Optional[int] = None
    uss_bytes: Optional[int] = None
    peak_vms_bytes: int = 0
    peak_rss_bytes: int = 0
    mem_percent: float = 0.0


@dataclass
class CgroupInfo:
    cgroup_v2_path: Optional[str] = None
    cgroup_v1_entries: Dict[str, str] = field(default_factory=dict)
    systemd_unit: Optional[str] = None
    systemd_slice: Optional[str] = None
    systemd_user_unit: Optional[str] = None
    unit_file_path: Optional[str] = None
    is_container: bool = False
    container_runtime: Optional[str] = None
    container_id: Optional[str] = None
    container_name: Optional[str] = None
    kubernetes_pod_uid: Optional[str] = None
    kubernetes_namespace: Optional[str] = None
    kubernetes_container_name: Optional[str] = None


@dataclass
class LimitsInfo:
    max_open_files_soft: Optional[str] = None
    max_open_files_hard: Optional[str] = None
    max_processes_soft: Optional[str] = None
    max_processes_hard: Optional[str] = None
    max_memory_soft: Optional[str] = None
    max_memory_hard: Optional[str] = None
    max_locked_memory_soft: Optional[str] = None
    max_locked_memory_hard: Optional[str] = None
    max_core_size_soft: Optional[str] = None
    max_core_size_hard: Optional[str] = None


@dataclass
class ProcessAncestryNode:
    pid: int
    ppid: int
    name: str
    cmdline: str
    user: str
    exe: Optional[str] = None
    is_deleted_exe: bool = False


@dataclass
class ProcessOrigin:
    launcher_type: str = "unknown"  # systemd, cron, ssh, shell, docker, kubernetes, supervisor, kernel, init, unknown
    description: str = ""
    service_name: Optional[str] = None
    unit_file: Optional[str] = None
    cgroup_path: Optional[str] = None
    container_id: Optional[str] = None
    container_name: Optional[str] = None
    container_runtime: Optional[str] = None
    ancestor_chain: List[ProcessAncestryNode] = field(default_factory=list)
    parent_exe: Optional[str] = None
    parent_cmdline: Optional[str] = None


@dataclass
class ProcessInfo:
    pid: int
    ppid: int = 0
    name: str = ""
    cmdline: str = ""
    argv: List[str] = field(default_factory=list)
    exe: Optional[str] = None
    resolved_exe: Optional[str] = None
    is_deleted_exe: bool = False
    cwd: Optional[str] = None
    root: Optional[str] = None
    is_chroot: bool = False
    
    # State & Scheduling
    state: ProcessState = ProcessState.UNKNOWN
    state_char: str = "?"
    nice: int = 0
    priority: int = 0
    sched_policy: str = "SCHED_OTHER"
    
    # Session / TTY
    pgrp: int = 0
    session_id: int = 0
    tpgid: int = 0
    tty_nr: int = 0
    tty_name: str = "?"
    
    # Timing
    start_time_epoch: float = 0.0
    start_time_iso: str = ""
    age_seconds: float = 0.0
    age_human: str = ""
    
    # Resources
    cpu: CPUStats = field(default_factory=CPUStats)
    memory: MemoryStats = field(default_factory=MemoryStats)
    threads_count: int = 1
    thread_ids: List[int] = field(default_factory=list)
    
    # Credentials & Groups
    creds: CredentialInfo = field(default_factory=CredentialInfo)
    
    # Cgroup / Container / Origin
    cgroup: CgroupInfo = field(default_factory=CgroupInfo)
    origin: ProcessOrigin = field(default_factory=ProcessOrigin)
    
    # Relationships
    children: List[int] = field(default_factory=list)
    children_names: List[str] = field(default_factory=list)
    ancestry: List[ProcessAncestryNode] = field(default_factory=list)
    
    # Limits
    limits: LimitsInfo = field(default_factory=LimitsInfo)
    
    # Kernel & Security flags
    is_kernel_thread: bool = False
    is_zombie: bool = False
    wchan: Optional[str] = None
    
    # Additional collections (populated when requested)
    open_fd_count: Optional[int] = None
    deleted_files_count: int = 0
    listening_ports: List[int] = field(default_factory=list)
    established_conns_count: int = 0
    
    # Raw / Extra metadata
    extra: Dict[str, Any] = field(default_factory=dict)
