"""
Security metadata and observations data models.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Set


class SeccompMode(Enum):
    DISABLED = 0
    STRICT = 1
    FILTER = 2
    UNKNOWN = -1

    @property
    def label(self) -> str:
        labels = {
            SeccompMode.DISABLED: "Disabled (0)",
            SeccompMode.STRICT: "Strict (1)",
            SeccompMode.FILTER: "Filter/BPF (2)",
            SeccompMode.UNKNOWN: "Unknown",
        }
        return labels.get(self, "Unknown")


@dataclass
class CapabilitySet:
    inheritable_raw: str = "0000000000000000"
    permitted_raw: str = "0000000000000000"
    effective_raw: str = "0000000000000000"
    bounding_raw: str = "0000000000000000"
    ambient_raw: str = "0000000000000000"
    
    inheritable: Set[str] = field(default_factory=set)
    permitted: Set[str] = field(default_factory=set)
    effective: Set[str] = field(default_factory=set)
    bounding: Set[str] = field(default_factory=set)
    ambient: Set[str] = field(default_factory=set)


@dataclass
class NamespaceInfo:
    ns_type: str  # mnt, net, pid, user, ipc, uts, cgroup, time
    inode: Optional[int] = None
    target_path: Optional[str] = None
    is_isolated: bool = False  # Differs from host/PID 1 namespace


@dataclass
class SecurityObservation:
    category: str  # "PRIVILEGE", "CAPABILITY", "FILESYSTEM", "NAMESPACE", "INTEGRITY", "EXECUTION"
    title: str
    description: str
    severity: str = "INFO"  # INFO, NOTICE, ELEVATED


@dataclass
class SecurityInfo:
    pid: int
    no_new_privs: bool = False
    seccomp_mode: SeccompMode = SeccompMode.UNKNOWN
    speculation_store_bypass: Optional[str] = None
    
    # LSM (Linux Security Modules)
    apparmor_profile: Optional[str] = None
    selinux_context: Optional[str] = None
    smack_label: Optional[str] = None
    
    # Capabilities
    capabilities: CapabilitySet = field(default_factory=CapabilitySet)
    
    # Executable integrity & filesystem permissions
    exe_path: Optional[str] = None
    exe_real_path: Optional[str] = None
    exe_is_deleted: bool = False
    exe_uid: Optional[int] = None
    exe_gid: Optional[int] = None
    exe_owner: Optional[str] = None
    exe_group: Optional[str] = None
    exe_mode_octal: Optional[str] = None
    is_setuid: bool = False
    is_setgid: bool = False
    is_world_writable: bool = False
    exe_sha256: Optional[str] = None
    exe_size_bytes: Optional[int] = None
    
    # Namespaces
    namespaces: Dict[str, NamespaceInfo] = field(default_factory=dict)
    has_isolated_namespaces: bool = False
    
    # Memory observations
    has_deleted_maps: bool = False
    deleted_maps: List[str] = field(default_factory=list)
    
    # Observations list
    observations: List[SecurityObservation] = field(default_factory=list)
