"""
'pinspect security <PID>' command implementation.
"""

from typing import Optional
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from pinspect.collector.procfs import ProcFS
from pinspect.collector.security import SecurityCollector
from pinspect.output.formatter import OutputDispatcher
from pinspect.ui.theme import console, COLOR_HEADER


def handle_security(
    pid: int,
    proc_root: str = "/proc",
    compute_hash: bool = True,
    output_dispatcher: Optional[OutputDispatcher] = None,
) -> int:
    """Perform security and privilege inspection for PID."""
    procfs = ProcFS(proc_root)
    sec_collector = SecurityCollector(procfs)
    dispatcher = output_dispatcher or OutputDispatcher()

    if not procfs.exists(pid):
        if not dispatcher.quiet_mode:
            console.print(f"[bold red]Error: Process {pid} not found.[/bold red]")
        return 1

    security = sec_collector.collect(pid, compute_hash=compute_hash)

    def render_security_view() -> None:
        table = Table(box=None, show_header=False, pad_edge=False)
        table.add_column("Key", style="bold cyan", width=24)
        table.add_column("Value", style="white")

        # Capabilities
        eff = sorted(list(security.capabilities.effective))
        table.add_row("Effective Capabilities:", f"[bold yellow]{', '.join(eff)}[/bold yellow]" if eff else "[dim]None (Unprivileged)[/dim]")
        
        prm = sorted(list(security.capabilities.permitted))
        table.add_row("Permitted Capabilities:", f"{', '.join(prm)}" if prm else "[dim]None[/dim]")

        table.add_row("Bounding Set Count:", str(len(security.capabilities.bounding)))
        table.add_row("Inheritable Count:", str(len(security.capabilities.inheritable)))

        # Sandboxing / Privileges
        table.add_row("NoNewPrivs (PR_SET):", "[green]Active (1)[/green]" if security.no_new_privs else "[dim]Disabled (0)[/dim]")
        table.add_row("Seccomp Mode:", security.seccomp_mode.label)

        # LSM
        if security.apparmor_profile:
            table.add_row("AppArmor Profile:", f"[cyan]{security.apparmor_profile}[/cyan]")
        if security.selinux_context:
            table.add_row("SELinux Context:", f"[cyan]{security.selinux_context}[/cyan]")
        if security.smack_label:
            table.add_row("Smack Label:", f"[cyan]{security.smack_label}[/cyan]")

        # Binary details
        table.add_row("Executable Path:", security.exe_path or "[unknown]")
        if security.exe_owner:
            owner_info = f"{security.exe_owner}:{security.exe_group} (mode {security.exe_mode_octal})"
            if security.is_setuid:
                owner_info += " [bold red]SetUID[/bold red]"
            if security.is_setgid:
                owner_info += " [bold red]SetGID[/bold red]"
            if security.is_world_writable:
                owner_info += " [bold red]World-Writable[/bold red]"
            table.add_row("File Ownership / Perms:", owner_info)

        if security.exe_sha256:
            table.add_row("Executable SHA-256:", security.exe_sha256)

        # Namespaces
        isolated = [ns.ns_type for ns in security.namespaces.values() if ns.is_isolated]
        if isolated:
            table.add_row("Isolated Namespaces:", f"[bold yellow]{', '.join(isolated)}[/bold yellow]")
        else:
            table.add_row("Isolated Namespaces:", "[dim]None (Host / Default)[/dim]")

        # Observations
        if security.observations:
            obs_lines = Text()
            for obs in security.observations:
                obs_style = "bold yellow" if obs.severity == "NOTICE" else ("bold red" if obs.severity == "ELEVATED" else "cyan")
                obs_lines.append(f"  ● [{obs.category}] {obs.title}: ", style=obs_style)
                obs_lines.append(f"{obs.description}\n", style="white")
            table.add_row("Security Observations:", obs_lines)

        console.print(Panel(table, title=f"🛡️ Process Security Intelligence - PID {pid}", border_style="magenta"))

    dispatcher.handle(
        data=security,
        rich_render_fn=render_security_view,
        quiet_extractor=lambda s: [f"CAP_EFF={','.join(s.capabilities.effective)}", f"NNP={s.no_new_privs}"],
    )
    return 0
