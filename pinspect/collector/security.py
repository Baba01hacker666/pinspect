"""
Security intelligence collector (Linux capabilities, seccomp, NoNewPrivs, LSM, executable hashes, SUID).
"""

import contextlib
import hashlib
import os
import stat
from typing import Dict, List, Optional, Set

from pinspect.collector.namespaces import NamespaceCollector
from pinspect.collector.procfs import ProcFS
from pinspect.model.security import (
    CapabilitySet,
    SeccompMode,
    SecurityInfo,
    SecurityObservation,
)
from pinspect.utils.formatting import format_octal_mode
from pinspect.utils.system import resolve_gid, resolve_uid

# Linux Capabilities bit table (Linux kernel 6.x / POSIX cap definitions)
CAPABILITY_NAMES = {
    0: "CAP_CHOWN",
    1: "CAP_DAC_OVERRIDE",
    2: "CAP_DAC_READ_SEARCH",
    3: "CAP_FOWNER",
    4: "CAP_FSETID",
    5: "CAP_KILL",
    6: "CAP_SETGID",
    7: "CAP_SETUID",
    8: "CAP_SETPCAP",
    9: "CAP_LINUX_IMMUTABLE",
    10: "CAP_NET_BIND_SERVICE",
    11: "CAP_NET_BROADCAST",
    12: "CAP_NET_ADMIN",
    13: "CAP_NET_RAW",
    14: "CAP_IPC_LOCK",
    15: "CAP_IPC_OWNER",
    16: "CAP_SYS_MODULE",
    17: "CAP_SYS_RAWIO",
    18: "CAP_SYS_CHROOT",
    19: "CAP_SYS_PTRACE",
    20: "CAP_SYS_PACCT",
    21: "CAP_SYS_ADMIN",
    22: "CAP_SYS_BOOT",
    23: "CAP_SYS_NICE",
    24: "CAP_SYS_RESOURCE",
    25: "CAP_SYS_TIME",
    26: "CAP_SYS_TTY_CONFIG",
    27: "CAP_MKNOD",
    28: "CAP_LEASE",
    29: "CAP_AUDIT_WRITE",
    30: "CAP_AUDIT_CONTROL",
    31: "CAP_SETFCAP",
    32: "CAP_MAC_OVERRIDE",
    33: "CAP_MAC_ADMIN",
    34: "CAP_SYSLOG",
    35: "CAP_WAKE_ALARM",
    36: "CAP_BLOCK_SUSPEND",
    37: "CAP_AUDIT_READ",
    38: "CAP_PERFMON",
    39: "CAP_BPF",
    40: "CAP_CHECKPOINT_RESTORE",
}


def decode_capability_mask(hex_str: str) -> Set[str]:
    """Decode 16-hex-digit capability bitmask into a set of capability names."""
    if not hex_str:
        return set()
    try:
        mask = int(hex_str.strip(), 16)
    except ValueError:
        return set()

    caps: Set[str] = set()
    for bit, name in CAPABILITY_NAMES.items():
        if (mask & (1 << bit)) != 0:
            caps.add(name)
    return caps


class SecurityCollector:
    """Collects security parameters and performs objective security observations."""

    def __init__(self, procfs: Optional[ProcFS] = None):
        self.procfs = procfs or ProcFS()
        self.ns_collector = NamespaceCollector(self.procfs)

    def collect(
        self,
        pid: int,
        status_dict: Optional[Dict[str, str]] = None,
        compute_hash: bool = False,
    ) -> SecurityInfo:
        """Collect complete security profile for a PID."""
        sec = SecurityInfo(pid=pid)

        # 1. Parse /proc/<pid>/status for caps, seccomp, NoNewPrivs
        if status_dict is None:
            status_dict = self._parse_status(pid)

        # NoNewPrivs
        nnp_str = status_dict.get("NoNewPrivs", "0")
        sec.no_new_privs = nnp_str == "1"

        # Seccomp
        seccomp_str = status_dict.get("Seccomp", "-1")
        try:
            sec.seccomp_mode = SeccompMode(int(seccomp_str))
        except (ValueError, KeyError):
            sec.seccomp_mode = SeccompMode.UNKNOWN

        # Speculation store bypass
        sec.speculation_store_bypass = status_dict.get("Speculation_Store_Bypass")

        # Capabilities
        cap_inh_raw = status_dict.get("CapInh", "0000000000000000")
        cap_prm_raw = status_dict.get("CapPrm", "0000000000000000")
        cap_eff_raw = status_dict.get("CapEff", "0000000000000000")
        cap_bnd_raw = status_dict.get("CapBnd", "0000000000000000")
        cap_amb_raw = status_dict.get("CapAmb", "0000000000000000")

        sec.capabilities = CapabilitySet(
            inheritable_raw=cap_inh_raw,
            permitted_raw=cap_prm_raw,
            effective_raw=cap_eff_raw,
            bounding_raw=cap_bnd_raw,
            ambient_raw=cap_amb_raw,
            inheritable=decode_capability_mask(cap_inh_raw),
            permitted=decode_capability_mask(cap_prm_raw),
            effective=decode_capability_mask(cap_eff_raw),
            bounding=decode_capability_mask(cap_bnd_raw),
            ambient=decode_capability_mask(cap_amb_raw),
        )

        # 2. Linux Security Modules (AppArmor / SELinux)
        self._collect_lsm(pid, sec)

        # 3. Executable security & permissions
        self._collect_exe_security(pid, sec, compute_hash)

        # 4. Namespaces
        sec.namespaces = self.ns_collector.collect_namespaces_for_pid(pid)
        sec.has_isolated_namespaces = any(ns.is_isolated for ns in sec.namespaces.values())

        # 5. Deleted memory maps
        self._collect_deleted_maps(pid, sec)

        # 6. Generate objective security observations
        self._generate_observations(sec, status_dict)

        return sec

    def _parse_status(self, pid: int) -> Dict[str, str]:
        lines = self.procfs.read_lines(pid, "status")
        res: Dict[str, str] = {}
        for line in lines:
            if ":" in line:
                k, v = line.split(":", 1)
                res[k.strip()] = v.strip()
        return res

    def _collect_lsm(self, pid: int, sec: SecurityInfo) -> None:
        # AppArmor
        aa_curr = self.procfs.read_file(pid, "attr", "apparmor", "current")
        if not aa_curr:
            aa_curr = self.procfs.read_file(pid, "attr", "current")
        
        if aa_curr:
            aa_str = str(aa_curr).strip()
            if aa_str and aa_str != "unconfined":
                sec.apparmor_profile = aa_str

        # SELinux / Smack
        smack = self.procfs.read_file(pid, "attr", "smack", "current")
        if smack:
            sec.smack_label = str(smack).strip()

        # Check if current is SELinux context
        if aa_curr and ":" in str(aa_curr):
            sec.selinux_context = str(aa_curr).strip()

    def _collect_exe_security(self, pid: int, sec: SecurityInfo, compute_hash: bool) -> None:
        exe_link = self.procfs.read_symlink(pid, "exe")
        sec.exe_path = exe_link

        if not exe_link:
            return

        if exe_link.endswith(" (deleted)"):
            sec.exe_is_deleted = True
            sec.exe_real_path = exe_link[:-10]
        else:
            sec.exe_real_path = exe_link

        # Check file stat directly via /proc/<pid>/exe (Linux allows stat on the open inode)
        proc_exe_path = self.procfs.path(pid, "exe")
        st = None
        try:
            st = os.stat(proc_exe_path)
        except (PermissionError, FileNotFoundError, OSError):
            if sec.exe_real_path and os.path.exists(sec.exe_real_path):
                with contextlib.suppress(OSError):
                    st = os.stat(sec.exe_real_path)

        if st:
            sec.exe_uid = st.st_uid
            sec.exe_gid = st.st_gid
            sec.exe_owner = resolve_uid(st.st_uid)
            sec.exe_group = resolve_gid(st.st_gid)
            sec.exe_mode_octal = format_octal_mode(st.st_mode)
            sec.exe_size_bytes = st.st_size
            sec.is_setuid = bool(st.st_mode & stat.S_ISUID)
            sec.is_setgid = bool(st.st_mode & stat.S_ISGID)
            sec.is_world_writable = bool(st.st_mode & stat.S_IWOTH)

        # Compute SHA-256 hash if requested and binary size is reasonable (< 100 MB)
        if compute_hash and st and st.st_size < 100 * 1024 * 1024:
            sec.exe_sha256 = self.hash_executable(proc_exe_path)

    @staticmethod
    def hash_executable(path: str) -> Optional[str]:
        """Compute SHA-256 hash of an executable safely."""
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def _collect_deleted_maps(self, pid: int, sec: SecurityInfo) -> None:
        maps_lines = self.procfs.read_lines(pid, "maps")
        deleted: List[str] = []
        for line in maps_lines:
            if "(deleted)" in line:
                parts = line.split()
                if len(parts) >= 6:
                    path = " ".join(parts[5:])
                    if path not in deleted and not path.startswith("["):
                        deleted.append(path)
        if deleted:
            sec.has_deleted_maps = True
            sec.deleted_maps = deleted

    def _generate_observations(self, sec: SecurityInfo, status_dict: Dict[str, str]) -> None:
        """Generate factual, objective observations based on collected state."""
        # 1. Executable deleted observation
        if sec.exe_is_deleted:
            sec.observations.append(
                SecurityObservation(
                    category="INTEGRITY",
                    title="Deleted Executable on Disk",
                    description=f"Process is executing from memory; executable file on disk ({sec.exe_real_path}) was unlinked or replaced.",
                    severity="NOTICE",
                )
            )

        # 2. SUID / SGID executable
        if sec.is_setuid:
            sec.observations.append(
                SecurityObservation(
                    category="PRIVILEGE",
                    title="SetUID Executable",
                    description=f"Executable binary has SUID bit set (owner: {sec.exe_owner}).",
                    severity="NOTICE",
                )
            )
        if sec.is_world_writable:
            sec.observations.append(
                SecurityObservation(
                    category="FILESYSTEM",
                    title="World-Writable Executable",
                    description="The binary file on disk has write permissions enabled for other users.",
                    severity="ELEVATED",
                )
            )

        # 3. Capabilities observation
        eff_caps = sec.capabilities.effective
        if "CAP_SYS_ADMIN" in eff_caps:
            sec.observations.append(
                SecurityObservation(
                    category="CAPABILITY",
                    title="CAP_SYS_ADMIN in Effective Set",
                    description="Process holds administrative capabilities (CAP_SYS_ADMIN), granting broad kernel & mount control.",
                    severity="NOTICE",
                )
            )
        if "CAP_NET_RAW" in eff_caps or "CAP_NET_ADMIN" in eff_caps:
            net_caps = [c for c in ["CAP_NET_RAW", "CAP_NET_ADMIN"] if c in eff_caps]
            sec.observations.append(
                SecurityObservation(
                    category="CAPABILITY",
                    title=f"Network Capabilities: {', '.join(net_caps)}",
                    description="Process can create raw sockets, configure interfaces, or sniff network traffic.",
                    severity="INFO",
                )
            )

        # 4. NoNewPrivs & Seccomp
        if sec.no_new_privs:
            sec.observations.append(
                SecurityObservation(
                    category="PRIVILEGE",
                    title="NoNewPrivs Active",
                    description="Process cannot acquire additional privileges via execve (PR_SET_NO_NEW_PRIVS).",
                    severity="INFO",
                )
            )
        if sec.seccomp_mode == SeccompMode.FILTER:
            sec.observations.append(
                SecurityObservation(
                    category="SANDBOX",
                    title="Seccomp BPF Filter Active",
                    description="Process syscall execution is filtered and restricted via Seccomp BPF.",
                    severity="INFO",
                )
            )

        # 5. Namespaces
        isolated_ns = [ns.ns_type for ns in sec.namespaces.values() if ns.is_isolated]
        if isolated_ns:
            sec.observations.append(
                SecurityObservation(
                    category="NAMESPACE",
                    title=f"Isolated Namespaces ({', '.join(isolated_ns)})",
                    description="Process executes in an isolated namespace environment differing from the host.",
                    severity="INFO",
                )
            )

        # 6. Deleted memory mappings
        if sec.has_deleted_maps:
            sec.observations.append(
                SecurityObservation(
                    category="INTEGRITY",
                    title=f"Deleted Mapped Libraries ({len(sec.deleted_maps)} files)",
                    description="Process has memory mappings pointing to unlinked files or libraries.",
                    severity="INFO",
                )
            )
