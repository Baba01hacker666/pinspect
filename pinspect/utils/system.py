"""
System utilities for reading kernel parameters, resolving users, groups, and device numbers.
"""

import grp
import os
import pwd
import time
from typing import Dict, Tuple

_UID_CACHE: Dict[int, str] = {}
_GID_CACHE: Dict[int, str] = {}
_UPTIME_CACHE: Tuple[float, float] = (0.0, 0.0)  # (cached_value, timestamp)
_MEM_TOTAL_CACHE: int = 0


def get_clock_ticks() -> int:
    """Get system clock ticks per second (usually 100 on Linux)."""
    try:
        return os.sysconf(os.sysconf_names.get("SC_CLK_TCK", "SC_CLK_TCK"))
    except Exception:
        return 100


def get_page_size() -> int:
    """Get system memory page size in bytes (usually 4096)."""
    try:
        return os.sysconf(os.sysconf_names.get("SC_PAGE_SIZE", "SC_PAGE_SIZE"))
    except Exception:
        return 4096


def get_uptime(proc_root: str = "/proc") -> float:
    """Get system uptime in seconds from /proc/uptime with caching."""
    global _UPTIME_CACHE
    now = time.time()
    if now - _UPTIME_CACHE[1] < 1.0 and _UPTIME_CACHE[0] > 0:
        return _UPTIME_CACHE[0]
    
    uptime_path = os.path.join(proc_root, "uptime")
    try:
        with open(uptime_path, encoding="utf-8", errors="ignore") as f:
            line = f.readline().strip()
            if line:
                val = float(line.split()[0])
                _UPTIME_CACHE = (val, now)
                return val
    except Exception:
        pass
    
    # Fallback to boot time estimation
    return max(0.0, time.monotonic())


def get_total_memory(proc_root: str = "/proc") -> int:
    """Get total system memory in bytes from /proc/meminfo."""
    global _MEM_TOTAL_CACHE
    if _MEM_TOTAL_CACHE > 0:
        return _MEM_TOTAL_CACHE
    
    meminfo_path = os.path.join(proc_root, "meminfo")
    try:
        with open(meminfo_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    parts = line.split()
                    kb = int(parts[1])
                    _MEM_TOTAL_CACHE = kb * 1024
                    return _MEM_TOTAL_CACHE
    except Exception:
        pass
    return 1  # Avoid zero division


def resolve_uid(uid: int) -> str:
    """Resolve UID to username with caching."""
    if uid in _UID_CACHE:
        return _UID_CACHE[uid]
    try:
        name = pwd.getpwuid(uid).pw_name
    except (KeyError, Exception):
        name = str(uid)
    _UID_CACHE[uid] = name
    return name


def resolve_gid(gid: int) -> str:
    """Resolve GID to group name with caching."""
    if gid in _GID_CACHE:
        return _GID_CACHE[gid]
    try:
        name = grp.getgrgid(gid).gr_name
    except (KeyError, Exception):
        name = str(gid)
    _GID_CACHE[gid] = name
    return name


def resolve_tty(tty_nr: int) -> str:
    """
    Resolve tty_nr from /proc/<pid>/stat into human readable device name.
    In Linux stat, tty_nr encodes major/minor.
    """
    if tty_nr == 0 or tty_nr == -1:
        return "?"
    
    # Major is in bits 8-15, minor in bits 0-7 (and bits 20-31 for newer kernels)
    major = (tty_nr >> 8) & 0xFF
    minor = (tty_nr & 0xFF) | ((tty_nr >> 12) & 0xFFF00)
    
    if major == 4:
        return f"tty{minor}" if minor < 64 else f"ttyS{minor - 64}"
    if 136 <= major <= 143:
        return f"pts/{(major - 136) * 256 + minor}"
    if major == 5:
        return {0: "tty", 1: "console", 2: "ptmx"}.get(minor, f"dev(5,{minor})")
    return f"dev({major},{minor})"


def resolve_sched_policy(policy_id: int) -> str:
    """Convert scheduling policy integer into descriptive string."""
    policies = {
        0: "SCHED_OTHER (Normal)",
        1: "SCHED_FIFO (Real-Time)",
        2: "SCHED_RR (Round-Robin)",
        3: "SCHED_BATCH",
        5: "SCHED_IDLE",
        6: "SCHED_DEADLINE",
    }
    return policies.get(policy_id, f"SCHED_UNKNOWN ({policy_id})")
