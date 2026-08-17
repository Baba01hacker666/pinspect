"""
Deep, actionable detailed process inspection view (pinspect show <PID>).
"""

from typing import Dict, Optional

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from pinspect.model.process import ProcessInfo
from pinspect.model.security import SecurityInfo
from pinspect.ui.theme import (
    Theme,
    console,
)
from pinspect.utils.formatting import (
    format_bytes,
)


def render_process_detail(
    pinfo: ProcessInfo,
    security: Optional[SecurityInfo] = None,
    raw_environ: Optional[Dict[str, str]] = None,
) -> None:
    """Render full detailed inspection for a single process."""
    # 1. Identity & State Header
    id_table = Table(box=None, show_header=False, pad_edge=False)
    id_table.add_column("Field", style="bold cyan", width=18)
    id_table.add_column("Value", style="white")

    id_table.add_row("Process Name:", f"[bold white]{pinfo.name}[/bold white]")
    id_table.add_row("PID / PPID:", f"[bold cyan]{pinfo.pid}[/bold cyan] / [dim]{pinfo.ppid}[/dim]")
    id_table.add_row("State:", f"[{Theme.state_style(pinfo.state_char)}]{pinfo.state_char} - {pinfo.state.label}[/]")
    id_table.add_row("User (UID):", f"[green]{pinfo.creds.user}[/green] ({pinfo.creds.ruid})  [dim]| euid: {pinfo.creds.euid} suid: {pinfo.creds.suid}[/dim]")
    id_table.add_row("Group (GID):", f"[green]{pinfo.creds.group}[/green] ({pinfo.creds.rgid})  [dim]| egid: {pinfo.creds.egid}[/dim]")
    if pinfo.creds.group_names:
        id_table.add_row("Supplementary Groups:", ", ".join(pinfo.creds.group_names[:8]))
    if pinfo.creds.loginuser:
        id_table.add_row("Audit Login UID:", f"{pinfo.creds.loginuser} ({pinfo.creds.loginuid})")
    id_table.add_row("TTY / Session / PGRP:", f"{pinfo.tty_name} / SID {pinfo.session_id} / PGRP {pinfo.pgrp}")
    id_table.add_row("Started At:", f"{pinfo.start_time_iso} ([dim]Age: {pinfo.age_human}[/dim])")

    console.print(Panel(id_table, title=f"🔍 Process Identity & Execution - PID {pinfo.pid}", border_style="cyan"))

    # 2. Origin & Launch Intelligence
    orig_table = Table(box=None, show_header=False, pad_edge=False)
    orig_table.add_column("Key", style="bold cyan", width=18)
    orig_table.add_column("Value", style="white")

    orig_table.add_row("Launch Origin:", f"[bold blue]{pinfo.origin.launcher_type.upper()}[/bold blue] - {pinfo.origin.description}")
    
    # Exe & Paths
    exe_display = pinfo.exe or "[kernel thread / unknown]"
    if pinfo.is_deleted_exe:
        exe_display = f"[bold red]⚠️ {exe_display} (DELETED FROM DISK)[/bold red]"
    orig_table.add_row("Executable Path:", exe_display)
    orig_table.add_row("Working Dir (CWD):", pinfo.cwd or "[inaccessible / none]")
    
    root_display = pinfo.root or "/"
    if pinfo.is_chroot:
        root_display = f"[bold yellow]{root_display} (CHROOT / CONTAINER)[/bold yellow]"
    orig_table.add_row("Root Directory:", root_display)

    if pinfo.origin.service_name:
        orig_table.add_row("systemd Service:", f"[bright_blue]{pinfo.origin.service_name}[/bright_blue]")
    if pinfo.cgroup.unit_file_path:
        orig_table.add_row("Unit File Path:", f"[dim]{pinfo.cgroup.unit_file_path}[/dim]")
    if pinfo.cgroup.is_container:
        orig_table.add_row(
            "Container Runtime:",
            f"[bold cyan]{pinfo.cgroup.container_runtime or 'Container'}[/bold cyan] (ID: {pinfo.cgroup.container_id or 'N/A'})",
        )
    if pinfo.cgroup.kubernetes_pod_uid:
        orig_table.add_row("K8s Pod UID:", pinfo.cgroup.kubernetes_pod_uid)
    if pinfo.origin.parent_cmdline:
        orig_table.add_row("Parent Invocation:", f"[dim]{pinfo.origin.parent_cmdline}[/dim]")

    console.print(Panel(orig_table, title="🚀 Origin & Launch Intelligence", border_style="blue"))

    # 3. Command Line & Arguments
    cmd_table = Table(box=None, show_header=False, pad_edge=False)
    cmd_table.add_column("Arg", style="bold cyan", width=6)
    cmd_table.add_column("Value", style="white")

    cmd_table.add_row("CMD:", f"[bold white]{pinfo.cmdline}[/bold white]")
    if len(pinfo.argv) > 1:
        for idx, arg in enumerate(pinfo.argv[:10]):
            cmd_table.add_row(f"[{idx}]", arg)
        if len(pinfo.argv) > 10:
            cmd_table.add_row("...", f"[dim]and {len(pinfo.argv) - 10} more arguments[/dim]")

    console.print(Panel(cmd_table, title="📜 Command Line & Arguments", border_style="grey37"))

    # 4. Resources & Performance
    res_table = Table(box=None, show_header=False, pad_edge=False)
    res_table.add_column("Metric", style="bold cyan", width=18)
    res_table.add_column("Value", style="white")

    cpu_val = f"[{Theme.cpu_style(pinfo.cpu.cpu_percent)}]{pinfo.cpu.cpu_percent:.1f}%[/]  (User: {pinfo.cpu.utime_ticks} ticks, System: {pinfo.cpu.stime_ticks} ticks | Total: {pinfo.cpu.total_time_seconds:.2f}s)"
    res_table.add_row("CPU Usage:", cpu_val)
    res_table.add_row("CPU Affinity:", f"{pinfo.cpu.cpus_allowed_list or 'all'} ({pinfo.cpu.cpus_allowed_count} CPUs allowed) [dim]| Core: {pinfo.cpu.processor}[/dim]")
    res_table.add_row("Scheduling / Nice:", f"{pinfo.sched_policy} | Nice: {pinfo.nice} | Priority: {pinfo.priority}")
    
    mem_details = f"[{Theme.mem_style(pinfo.memory.mem_percent)}]{pinfo.memory.mem_percent:.1f}%[/]  |  RSS: [bold]{format_bytes(pinfo.memory.rss_bytes)}[/bold]  |  VMS: {format_bytes(pinfo.memory.vms_bytes)}"
    if pinfo.memory.pss_bytes:
        mem_details += f"  |  PSS: {format_bytes(pinfo.memory.pss_bytes)}"
    if pinfo.memory.uss_bytes:
        mem_details += f"  |  USS: {format_bytes(pinfo.memory.uss_bytes)}"
    res_table.add_row("Memory Usage:", mem_details)
    res_table.add_row("Memory Segments:", f"Shared: {format_bytes(pinfo.memory.shared_bytes)} | Text: {format_bytes(pinfo.memory.text_bytes)} | Data: {format_bytes(pinfo.memory.data_bytes)} | Swap: {format_bytes(pinfo.memory.swap_bytes)}")
    res_table.add_row("Threads:", f"{pinfo.threads_count} threads active")
    if pinfo.wchan:
        res_table.add_row("Kernel Wait Chan:", f"[dim]{pinfo.wchan}[/dim]")

    console.print(Panel(res_table, title="⚡ Resource Utilization & Scheduling", border_style="yellow"))

    # 5. Security & Isolation Profile
    if security:
        sec_table = Table(box=None, show_header=False, pad_edge=False)
        sec_table.add_column("Security Item", style="bold cyan", width=22)
        sec_table.add_column("Details", style="white")

        # Capabilities
        eff_caps = sorted(security.capabilities.effective)
        if eff_caps:
            sec_table.add_row("Effective Capabilities:", f"[bold yellow]{', '.join(eff_caps)}[/bold yellow]")
        else:
            sec_table.add_row("Effective Capabilities:", "[dim]None (Unprivileged)[/dim]")

        bnd_caps = len(security.capabilities.bounding)
        sec_table.add_row("Bounding Set:", f"{bnd_caps} capabilities in bounding set")

        # NoNewPrivs & Seccomp
        nnp_str = "[green]Enabled (PR_SET_NO_NEW_PRIVS)[/green]" if security.no_new_privs else "[dim]Disabled[/dim]"
        sec_table.add_row("NoNewPrivs:", nnp_str)
        sec_table.add_row("Seccomp Mode:", security.seccomp_mode.label)

        # LSM
        if security.apparmor_profile:
            sec_table.add_row("AppArmor Profile:", f"[cyan]{security.apparmor_profile}[/cyan]")
        if security.selinux_context:
            sec_table.add_row("SELinux Context:", f"[cyan]{security.selinux_context}[/cyan]")

        # Executable binary security
        if security.exe_owner:
            perms_str = f"Owner: {security.exe_owner}:{security.exe_group} | Mode: {security.exe_mode_octal or '?'}"
            if security.is_setuid:
                perms_str += " | [bold red]SetUID Active[/bold red]"
            if security.is_world_writable:
                perms_str += " | [bold red]World-Writable[/bold red]"
            sec_table.add_row("Binary Permissions:", perms_str)

        if security.exe_sha256:
            sec_table.add_row("Executable SHA-256:", f"[dim]{security.exe_sha256}[/dim]")

        # Observations
        if security.observations:
            obs_text = Text()
            for obs in security.observations:
                obs_style = "bold yellow" if obs.severity == "NOTICE" else ("bold red" if obs.severity == "ELEVATED" else "cyan")
                obs_text.append(f"  ● [{obs.category}] {obs.title}: ", style=obs_style)
                obs_text.append(f"{obs.description}\n", style="white")
            sec_table.add_row("Security Observations:", obs_text)

        console.print(Panel(sec_table, title="🛡️ Security, Privileges & Capabilities", border_style="magenta"))

    # 6. Ancestry Lineage
    if pinfo.ancestry:
        ancestry_text = Text()
        chain_rev = list(reversed(pinfo.ancestry))
        for node in chain_rev:
            ancestry_text.append(f"PID {node.pid} ({node.name})", style="cyan")
            ancestry_text.append(" ──▶ ", style="dim")
        ancestry_text.append(f"PID {pinfo.pid} ({pinfo.name})", style="bold white on blue")
        console.print(Panel(ancestry_text, title="🌳 Process Ancestry Lineage", border_style="grey37"))
