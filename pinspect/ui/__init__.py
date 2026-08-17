"""UI rendering components and interactive TUI."""
from pinspect.ui.theme import Theme
from pinspect.ui.table import render_process_table, render_files_table, render_network_table, render_namespace_table
from pinspect.ui.tree import render_process_tree, render_ancestry_chain
from pinspect.ui.detail import render_process_detail
from pinspect.ui.tui import InteractiveTUI

__all__ = [
    "Theme",
    "render_process_table",
    "render_files_table",
    "render_network_table",
    "render_namespace_table",
    "render_process_tree",
    "render_ancestry_chain",
    "render_process_detail",
    "InteractiveTUI",
]
