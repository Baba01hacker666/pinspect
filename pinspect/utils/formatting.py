"""
Formatting utilities for human-readable output, byte conversions, and timestamps.
"""

import datetime
import re
from typing import Optional


def format_bytes(num_bytes: Optional[int], precision: int = 1) -> str:
    """Format bytes into human-readable strings (e.g., 14.2 MB)."""
    if num_bytes is None:
        return "N/A"
    if num_bytes < 0:
        return "0 B"
    
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    val = float(num_bytes)
    unit_idx = 0
    while val >= 1024.0 and unit_idx < len(units) - 1:
        val /= 1024.0
        unit_idx += 1
    
    if unit_idx == 0:
        return f"{int(val)} B"
    return f"{val:.{precision}f} {units[unit_idx]}"


def format_duration(seconds: float) -> str:
    """Format a duration in seconds into a concise human-readable string."""
    if seconds < 0:
        return "0s"
    
    secs = int(seconds)
    days = secs // 86400
    secs %= 86400
    hours = secs // 3600
    secs %= 3600
    minutes = secs // 60
    secs %= 60
    
    if days > 0:
        return f"{days}d {hours}h"
    elif hours > 0:
        return f"{hours}h {minutes}m"
    elif minutes > 0:
        return f"{minutes}m {secs}s"
    else:
        return f"{secs}s"


def format_percent(pct: float) -> str:
    """Format percentage value."""
    if pct < 0:
        return "0.0%"
    return f"{pct:.1f}%"


def format_timestamp(epoch: float) -> str:
    """Format epoch timestamp to readable ISO/local date time."""
    if epoch <= 0:
        return "N/A"
    try:
        dt = datetime.datetime.fromtimestamp(epoch)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(epoch)


def truncate_str(s: Optional[str], max_len: int = 80, suffix: str = "…") -> str:
    """Truncate string to max_len with suffix."""
    if not s:
        return ""
    if len(s) <= max_len:
        return s
    cut = max_len - len(suffix)
    return s[:cut] + suffix


def format_octal_mode(mode: int) -> str:
    """Convert integer st_mode to standard 4-digit octal string (e.g. 0755, 4755)."""
    return oct(mode & 0o7777)[2:].zfill(4)


_DURATION_UNITS = {
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
    "w": 604800,
}


def parse_duration(value: str) -> float:
    """Parse a human duration string (e.g. '30s', '10m', '2h', '1d', '1w') into seconds.

    Raises ValueError with a helpful message on malformed input.
    """
    text = value.strip().lower()
    if not text:
        raise ValueError("empty duration")

    match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([smhdw]?)", text)
    if not match:
        raise ValueError(
            f"invalid duration {value!r}: use formats like '30s', '10m', '2h', '1d'"
        )

    number, unit = match.groups()
    multiplier = _DURATION_UNITS.get(unit or "s", 1)
    return float(number) * multiplier
