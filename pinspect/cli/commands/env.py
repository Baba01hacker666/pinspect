"""
'pinspect env <PID>' command implementation.
"""

from typing import Dict, Optional

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from pinspect.collector.procfs import ProcFS
from pinspect.output.formatter import OutputDispatcher
from pinspect.ui.theme import COLOR_HEADER, console
from pinspect.utils.secrets import process_environ


def handle_env(
    pid: int,
    proc_root: str = "/proc",
    show_secrets: bool = False,
    key_filter: Optional[str] = None,
    output_dispatcher: Optional[OutputDispatcher] = None,
) -> int:
    """Safely inspect process environment variables with secret redaction."""
    procfs = ProcFS(proc_root)
    dispatcher = output_dispatcher or OutputDispatcher()

    if not procfs.exists(pid):
        if not dispatcher.quiet_mode:
            console.print(f"[bold red]Error: Process {pid} not found.[/bold red]")
        return 1

    raw_env_content = procfs.read_file(pid, "environ", binary=True)
    if not raw_env_content or not isinstance(raw_env_content, bytes):
        if not dispatcher.quiet_mode:
            console.print(f"[dim]No environment variables accessible for PID {pid} (Empty or Permission Denied).[/dim]")
        return 0

    raw_dict: Dict[str, str] = {}
    for item in raw_env_content.split(b"\x00"):
        if b"=" in item:
            try:
                k, v = item.decode("utf-8", "replace").split("=", 1)
                raw_dict[k] = v
            except ValueError:
                pass

    if key_filter:
        raw_dict = {k: v for k, v in raw_dict.items() if key_filter.lower() in k.lower()}

    # Process redaction
    processed = process_environ(raw_dict, redact=not show_secrets)

    data = {
        "pid": pid,
        "env_count": len(processed),
        "secrets_redacted": not show_secrets,
        "variables": {k: val for k, (val, _) in processed.items()},
    }

    def render_env_table() -> None:
        table = Table(
            show_header=True,
            header_style=COLOR_HEADER,
            box=None,
            pad_edge=False,
            expand=True,
        )
        table.add_column("VARIABLE", style="bold cyan", no_wrap=True, width=30)
        table.add_column("VALUE", style="white")

        for k in sorted(processed.keys()):
            val, is_sec = processed[k]
            val_text = Text()
            if is_sec and not show_secrets:
                val_text.append(val, style="bold yellow on black")
                val_text.append(" [SECRET REDACTED]", style="dim yellow")
            elif is_sec:
                val_text.append(val, style="bold red")
            else:
                val_text.append(val, style="white")

            table.add_row(k, val_text)

        warning_title = f"🔐 Environment Variables for PID {pid} ({len(processed)} vars)"
        if not show_secrets:
            warning_title += " [dim]| Secrets Redacted[/dim]"
        else:
            warning_title += " [bold red]| RAW SECRETS EXPOSED[/bold red]"

        console.print(Panel(table, title=warning_title, border_style="cyan"))

    dispatcher.handle(
        data=data,
        rich_render_fn=render_env_table,
        quiet_extractor=lambda d: [f"{k}={v}" for k, v in d["variables"].items()],
    )
    return 0
