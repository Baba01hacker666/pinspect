"""
Theme, colors, and styling tokens for pinspect terminal UI.
"""

from rich.console import Console
from rich.theme import Theme as RichTheme

# High-legibility color palette
COLOR_PID = "bold cyan"
COLOR_USER = "green"
COLOR_ROOT_USER = "bold yellow"
COLOR_COMM = "bold white"
COLOR_CMD = "bright_black"
COLOR_CPU = "bright_yellow"
COLOR_MEM = "bright_magenta"
COLOR_ORIGIN = "blue"
COLOR_SERVICE = "bright_blue"
COLOR_CONTAINER = "cyan"
COLOR_ALERT = "bold red"
COLOR_WARN = "bold yellow"
COLOR_INFO = "dim white"
COLOR_BORDER = "grey39"
COLOR_HEADER = "bold cyan"

# State colors
STATE_COLORS = {
    "R": "bold green",       # Running
    "S": "dim white",        # Sleeping
    "D": "bold yellow",      # Disk Sleep
    "Z": "bold red on black",# Zombie
    "T": "yellow",           # Stopped
    "t": "yellow",           # Traced
    "I": "dim cyan",         # Idle
    "?": "dim white",
}

# Rich Console instance
console = Console(
    highlight=False,
    theme=RichTheme({
        "pid": COLOR_PID,
        "user": COLOR_USER,
        "root": COLOR_ROOT_USER,
        "comm": COLOR_COMM,
        "cmd": COLOR_CMD,
        "cpu": COLOR_CPU,
        "mem": COLOR_MEM,
        "origin": COLOR_ORIGIN,
        "alert": COLOR_ALERT,
        "warn": COLOR_WARN,
        "info": COLOR_INFO,
    }),
)


class Theme:
    """Styling helpers and symbols."""
    BRANCH = "├─ "
    LAST_BRANCH = "└─ "
    VERTICAL = "│  "
    SPACE = "   "

    # Status indicators
    BULLET = "●"
    LOCK = "🔒"
    CONTAINER_GLYPH = "📦"
    SERVICE_GLYPH = "⚙"
    DELETED_GLYPH = "⚠️ DELETED"

    @classmethod
    def state_style(cls, state_char: str) -> str:
        return STATE_COLORS.get(state_char.upper(), "dim white")

    @classmethod
    def cpu_style(cls, pct: float) -> str:
        if pct >= 80.0:
            return "bold red"
        if pct >= 30.0:
            return "bold yellow"
        if pct > 0.0:
            return "green"
        return "dim white"

    @classmethod
    def mem_style(cls, pct: float) -> str:
        if pct >= 75.0:
            return "bold red"
        if pct >= 25.0:
            return "bold yellow"
        if pct > 0.0:
            return "cyan"
        return "dim white"
