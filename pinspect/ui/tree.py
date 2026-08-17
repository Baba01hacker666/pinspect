"""
Process tree and ancestry visualizer.
"""

from typing import Dict, List, Optional, Set

from rich.text import Text
from rich.tree import Tree

from pinspect.model.process import ProcessAncestryNode, ProcessInfo
from pinspect.ui.theme import Theme, console
from pinspect.utils.formatting import truncate_str


def _build_node_label(p: ProcessInfo, highlight_pid: Optional[int] = None) -> Text:
    """Construct formatted text for a tree node."""
    text = Text()
    is_target = p.pid == highlight_pid

    # PID
    pid_style = "bold white on red" if is_target else "cyan"
    text.append(f"[{p.pid}] ", style=pid_style)

    # Process Name
    text.append(f"{p.name} ", style="bold white")

    # User
    user_style = "bold yellow" if p.creds.user == "root" else "green"
    text.append(f"({p.creds.user}) ", style=user_style)

    # State & Resources
    text.append(f"{p.state_char} ", style=Theme.state_style(p.state_char))
    text.append(f"cpu:{p.cpu.cpu_percent:.1f}% ", style=Theme.cpu_style(p.cpu.cpu_percent))
    text.append(f"mem:{p.memory.mem_percent:.1f}% ", style=Theme.mem_style(p.memory.mem_percent))

    # Origin or service if present
    if p.cgroup.is_container:
        text.append(f"📦{p.cgroup.container_runtime or 'container'} ", style="bold cyan")
    elif p.origin.service_name:
        text.append(f"⚙{p.origin.service_name} ", style="bright_blue")

    if p.is_deleted_exe:
        text.append("⚠️[DELETED] ", style="bold red")

    # Command line snippet
    cmd_snippet = p.cmdline
    if cmd_snippet and cmd_snippet != p.name:
        text.append(f"- {truncate_str(cmd_snippet, max_len=75)}", style="bright_black")

    return text


def render_process_tree(
    processes: List[ProcessInfo],
    root_pid: Optional[int] = None,
    highlight_pid: Optional[int] = None,
) -> None:
    """Render full process tree hierarchy."""
    proc_map: Dict[int, ProcessInfo] = {p.pid: p for p in processes}
    children_map: Dict[int, List[ProcessInfo]] = {}

    for p in processes:
        children_map.setdefault(p.ppid, []).append(p)

    # Sort children by PID
    for ppid in children_map:
        children_map[ppid].sort(key=lambda x: x.pid)

    # Determine root PIDs to start tree from
    roots: List[ProcessInfo] = []
    if root_pid is not None and root_pid in proc_map:
        roots = [proc_map[root_pid]]
    elif root_pid is not None:
        console.print(f"[bold red]PID {root_pid} not found.[/bold red]")
        return
    else:
        # Standard roots: processes whose PPID is 0 or PPID not present in proc_map
        for p in processes:
            if (p.ppid == 0 or p.ppid not in proc_map or p.pid == 1 or p.pid == 2) and p not in roots:
                roots.append(p)

        # Fallback if no clean root: find minimum PIDs
        if not roots and processes:
            roots = [sorted(processes, key=lambda x: x.pid)[0]]

    roots.sort(key=lambda x: x.pid)

    def attach_node(parent_tree_node: Tree, proc: ProcessInfo, visited: Set[int]) -> None:
        if proc.pid in visited:
            return
        visited.add(proc.pid)

        label = _build_node_label(proc, highlight_pid=highlight_pid)
        tree_node = parent_tree_node.add(label)

        for child in children_map.get(proc.pid, []):
            attach_node(tree_node, child, visited)

    root_tree = Tree("🌲 [bold cyan]Process Tree[/bold cyan]")
    visited_pids: Set[int] = set()

    for r in roots:
        attach_node(root_tree, r, visited_pids)

    console.print(root_tree)


def render_ancestry_chain(ancestry: List[ProcessAncestryNode], target_pid: int, target_name: str) -> None:
    """Render a step-by-step ancestry lineage chain."""
    console.print(f"\n[bold cyan]Process Ancestry for PID {target_pid} ({target_name}):[/bold cyan]\n")

    if not ancestry:
        console.print("  └─ [bold green]Direct Root / Init Process[/bold green] (No parent ancestors)")
        return

    # Reversed order: Init / Root -> Parent -> Target
    chain_reversed = list(reversed(ancestry))
    indent = ""

    for idx, node in enumerate(chain_reversed):
        is_first = (idx == 0)
        prefix = "┌─ " if is_first else "└─ "
        
        user_style = "bold yellow" if node.user == "root" else "green"
        line = Text(f"{indent}{prefix}")
        line.append(f"PID {node.pid} ", style="bold cyan")
        line.append(f"({node.name}) ", style="bold white")
        line.append(f"[{node.user}] ", style=user_style)
        if node.is_deleted_exe:
            line.append("⚠️[DELETED EXE] ", style="bold red")
        if node.cmdline and node.cmdline != node.name:
            line.append(f"-> {node.cmdline}", style="bright_black")

        console.print(line)
        indent += "    "

    # Finally the target process itself
    target_line = Text(f"{indent}└─ ")
    target_line.append(f"PID {target_pid} ", style="bold white on blue")
    target_line.append(f"({target_name}) [TARGET]", style="bold white")
    console.print(target_line)
    console.print()
