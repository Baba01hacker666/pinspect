"""
'pinspect tui' command implementation.
"""

from pinspect.ui.tui import InteractiveTUI


def handle_tui(proc_root: str = "/proc") -> int:
    """Launch interactive curses TUI dashboard."""
    tui = InteractiveTUI(proc_root=proc_root)
    tui.run()
    return 0
