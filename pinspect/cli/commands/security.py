"""
'pinspect security <PID>' command implementation.
"""

from typing import Optional

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from pinspect.collector.maps import MapsCollector
from pinspect.collector.process import ProcessCollector
from pinspect.collector.procfs import ProcFS
from pinspect.collector.risk import RiskCollector
from pinspect.collector.security import SecurityCollector
from pinspect.model.risk import RiskInfo
from pinspect.output.formatter import OutputDispatcher
from pinspect.ui.theme import console


def _collect_process_for_risk(procfs: ProcFS, pid: int):
    """Best-effort single-PID process metadata for risk scoring."""
    try:
        return ProcessCollector(procfs).collect_process(pid, deep=False)
    except Exception:
        return None


_LEVEL_STYLES = {
    "LOW": "green",
    "MEDIUM": "yellow",
    "HIGH": "bold red",
    "CRITICAL": "bold white on red",
}


def handle_security(
    pid: int,
    proc_root: str = "/proc",
    compute_hash: bool = True,
    output_dispatcher: Optional[OutputDispatcher] = None,
) -> int:
    """Perform security and privilege inspection for PID."""
    procfs = ProcFS(proc_root)
    sec_collector = SecurityCollector(procfs)
    maps_collector = MapsCollector(procfs)
    risk_collector = RiskCollector()
    dispatcher = output_dispatcher or OutputDispatcher()

    if not procfs.exists(pid):
        if not dispatcher.quiet_mode:
            console.print(f"[bold red]Error: Process {pid} not found.[/bold red]")
        return 1

    security = sec_collector.collect(pid, compute_hash=compute_hash)
    maps_report = maps_collector.collect(pid)
    pinfo_for_risk = _collect_process_for_risk(procfs, pid)
    if pinfo_for_risk is not None:
        security.risk = risk_collector.assess(
            pinfo_for_risk,
            security=security,
            maps_report=maps_report,
        )
    else:
        security.risk = RiskInfo(pid=pid)

    def render_security_view() -> None:
        table = Table(box=None, show_header=False, pad_edge=False)
        table.add_column("Key", style="bold cyan", width=24)
        table.add_column("Value", style="white")

        # Capabilities
        eff = sorted(security.capabilities.effective)
        table.add_row("Effective Capabilities:", f"[bold yellow]{', '.join(eff)}[/bold yellow]" if eff else "[dim]None (Unprivileged)[/dim]")
        
        prm = sorted(security.capabilities.permitted)
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

        # Risk assessment panel
        risk = security.risk
        if risk is not None:
            risk_table = Table(box=None, show_header=False, pad_edge=False)
            risk_table.add_column("Key", style="bold cyan", width=24)
            risk_table.add_column("Value", style="white")

            level_style = _LEVEL_STYLES.get(risk.level, "white")
            risk_table.add_row("Risk Score:", f"[{level_style}]{risk.score}/100 ({risk.level})[/]")

            if risk.flags:
                flag_lines = Text()
                for flag in sorted(risk.flags, key=lambda f: -f.weight):
                    style = _LEVEL_STYLES.get(flag.severity, "white")
                    flag_lines.append(f"  ● [{flag.code}] {flag.title}", style=style)
                    flag_lines.append(f" (+{flag.weight})\n", style="dim")
                    flag_lines.append(f"    {flag.detail}\n", style="white")
                risk_table.add_row("Suspicion Flags:", flag_lines)
            else:
                risk_table.add_row("Suspicion Flags:", "[green]None — no suspicious indicators found[/green]")

            border = "red" if risk.is_elevated else "green"
            console.print(Panel(risk_table, title=f"🎯 Risk Assessment - PID {pid}", border_style=border))

    dispatcher.handle(
        data=security,
        rich_render_fn=render_security_view,
        quiet_extractor=lambda s: [
            f"CAP_EFF={','.join(s.capabilities.effective)}",
            f"NNP={s.no_new_privs}",
            f"RISK={s.risk.score if s.risk else 0}",
        ],
    )
    return 0
