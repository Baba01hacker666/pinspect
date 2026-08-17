"""
Interactive Terminal User Interface (TUI) for process exploration.
"""

import curses
import os
import time
from typing import List, Optional, Dict, Any

from pinspect.collector.procfs import ProcFS
from pinspect.collector.process import ProcessCollector
from pinspect.collector.filesystem import FilesystemCollector
from pinspect.collector.network import NetworkCollector
from pinspect.collector.security import SecurityCollector
from pinspect.utils.secrets import process_environ
from pinspect.utils.formatting import format_bytes, format_duration


class InteractiveTUI:
    """Curses-based interactive process explorer dashboard."""

    def __init__(self, proc_root: str = "/proc"):
        self.procfs = ProcFS(proc_root)
        self.collector = ProcessCollector(self.procfs)
        self.fs_collector = FilesystemCollector(self.procfs)
        self.net_collector = NetworkCollector(self.procfs)
        self.sec_collector = SecurityCollector(self.procfs)

        self.processes: List[Any] = []
        self.filtered_procs: List[Any] = []
        self.selected_index: int = 0
        self.scroll_offset: int = 0
        self.filter_query: str = ""
        self.is_filtering: bool = False
        self.tree_mode: bool = False
        self.detail_mode: bool = False
        self.detail_tab: int = 0  # 0: Overview, 1: Files, 2: Network, 3: Security, 4: Env
        self.sort_by: str = "cpu"  # cpu, mem, pid, user, name
        self.sort_desc: bool = True
        self.status_msg: str = "Press '?' for help | '/' to filter | 'Enter' for detail | 'q' to quit"

    def run(self) -> None:
        """Run the interactive curses TUI."""
        try:
            curses.wrapper(self._main_loop)
        except KeyboardInterrupt:
            pass

    def _refresh_processes(self) -> None:
        """Reload processes from procfs."""
        self.processes = self.collector.collect_all_processes(deep=False)
        self._apply_sort()
        self._apply_filter()

    def _apply_sort(self) -> None:
        if self.sort_by == "cpu":
            self.processes.sort(key=lambda p: p.cpu.cpu_percent, reverse=self.sort_desc)
        elif self.sort_by == "mem":
            self.processes.sort(key=lambda p: p.memory.rss_bytes, reverse=self.sort_desc)
        elif self.sort_by == "pid":
            self.processes.sort(key=lambda p: p.pid, reverse=self.sort_desc)
        elif self.sort_by == "user":
            self.processes.sort(key=lambda p: p.creds.user, reverse=self.sort_desc)
        elif self.sort_by == "name":
            self.processes.sort(key=lambda p: p.name.lower(), reverse=self.sort_desc)

    def _apply_filter(self) -> None:
        if not self.filter_query:
            self.filtered_procs = list(self.processes)
        else:
            q = self.filter_query.lower()
            self.filtered_procs = [
                p for p in self.processes
                if (
                    q in str(p.pid)
                    or q in p.name.lower()
                    or q in p.creds.user.lower()
                    or q in (p.cmdline or "").lower()
                    or q in (p.origin.service_name or "").lower()
                )
            ]
        self.selected_index = max(0, min(self.selected_index, len(self.filtered_procs) - 1))

    def _main_loop(self, stdscr: Any) -> None:
        curses.curs_set(0)
        curses.use_default_colors()
        stdscr.timeout(1000)  # 1-second refresh cycle

        # Colors setup
        if curses.has_colors():
            curses.init_pair(1, curses.COLOR_CYAN, -1)     # Header / PID
            curses.init_pair(2, curses.COLOR_GREEN, -1)    # User / Ok
            curses.init_pair(3, curses.COLOR_YELLOW, -1)   # Warning / Root
            curses.init_pair(4, curses.COLOR_RED, -1)      # Alert / Zombie / Deleted
            curses.init_pair(5, curses.COLOR_BLACK, curses.COLOR_CYAN)  # Selected row
            curses.init_pair(6, curses.COLOR_BLUE, -1)     # Service / Origin

        self._refresh_processes()
        last_refresh = time.time()

        while True:
            max_y, max_x = stdscr.getmaxyx()
            stdscr.clear()

            # Auto refresh every 3 seconds
            if time.time() - last_refresh > 3.0 and not self.is_filtering and not self.detail_mode:
                self._refresh_processes()
                last_refresh = time.time()

            if self.detail_mode:
                self._draw_detail_view(stdscr, max_y, max_x)
            else:
                self._draw_process_table(stdscr, max_y, max_x)

            # Draw status bar
            self._draw_status_bar(stdscr, max_y, max_x)
            stdscr.refresh()

            try:
                ch = stdscr.getch()
            except curses.error:
                continue

            if ch == -1:
                continue

            if self.is_filtering:
                self._handle_filter_input(ch)
                continue

            if self.detail_mode:
                if ch in (ord("q"), 27, ord("\n"), curses.KEY_ENTER):  # ESC or Enter or q
                    self.detail_mode = False
                elif ch in (ord("1"), ord("2"), ord("3"), ord("4"), ord("5")):
                    self.detail_tab = ch - ord("1")
                elif ch in (ord("\t"), curses.KEY_RIGHT):
                    self.detail_tab = (self.detail_tab + 1) % 5
                elif ch == curses.KEY_LEFT:
                    self.detail_tab = (self.detail_tab - 1) % 5
                continue

            # Process table navigation
            if ch == ord("q"):
                break
            elif ch == ord("/"):
                self.is_filtering = True
                self.filter_query = ""
                curses.curs_set(1)
            elif ch == ord("r"):
                self._refresh_processes()
                last_refresh = time.time()
                self.status_msg = "Refreshed processes"
            elif ch == ord("s"):
                # Cycle sort
                sorts = ["cpu", "mem", "pid", "user", "name"]
                curr_idx = sorts.index(self.sort_by) if self.sort_by in sorts else 0
                self.sort_by = sorts[(curr_idx + 1) % len(sorts)]
                self._apply_sort()
                self._apply_filter()
                self.status_msg = f"Sorting by {self.sort_by.upper()}"
            elif ch == curses.KEY_UP or ch == ord("k"):
                if self.selected_index > 0:
                    self.selected_index -= 1
            elif ch == curses.KEY_DOWN or ch == ord("j"):
                if self.selected_index < len(self.filtered_procs) - 1:
                    self.selected_index += 1
            elif ch == curses.KEY_PPAGE:  # Page Up
                self.selected_index = max(0, self.selected_index - 15)
            elif ch == curses.KEY_NPAGE:  # Page Down
                self.selected_index = min(len(self.filtered_procs) - 1, self.selected_index + 15)
            elif ch == curses.KEY_HOME:
                self.selected_index = 0
            elif ch == curses.KEY_END:
                self.selected_index = max(0, len(self.filtered_procs) - 1)
            elif ch in (10, 13, curses.KEY_ENTER):
                if self.filtered_procs:
                    self.detail_mode = True
                    self.detail_tab = 0
            elif ch == ord("?"):
                self.status_msg = "Keys: ↑/↓/PgUp/PgDn Navigate | Enter Details | s Sort | / Filter | r Refresh | q Quit"

    def _draw_process_table(self, stdscr: Any, max_y: int, max_x: int) -> None:
        # Header banner
        header_title = f" PINSPECT - Linux Process Intelligence  (Total: {len(self.processes)} | Showing: {len(self.filtered_procs)}) "
        try:
            stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
            stdscr.addstr(0, 0, header_title[:max_x].ljust(max_x))
            stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)
        except curses.error:
            pass

        # Columns header
        col_header = "   PID   PPID USER       ST   CPU%   MEM%      RSS  THR ORIGIN / SERVICE     COMMAND"
        try:
            stdscr.attron(curses.A_STANDOUT)
            stdscr.addstr(1, 0, col_header[:max_x].ljust(max_x))
            stdscr.attroff(curses.A_STANDOUT)
        except curses.error:
            pass

        # Process list viewport
        table_height = max_y - 3
        if table_height <= 0:
            return

        # Adjust scroll offset
        if self.selected_index < self.scroll_offset:
            self.scroll_offset = self.selected_index
        elif self.selected_index >= self.scroll_offset + table_height:
            self.scroll_offset = self.selected_index - table_height + 1

        for row_idx in range(table_height):
            item_idx = self.scroll_offset + row_idx
            line_y = 2 + row_idx
            if item_idx >= len(self.filtered_procs):
                break

            p = self.filtered_procs[item_idx]
            is_selected = item_idx == self.selected_index

            origin_disp = ""
            if p.cgroup.is_container:
                origin_disp = f"[{p.cgroup.container_runtime or 'container'}]"
            elif p.origin.service_name:
                origin_disp = p.origin.service_name
            else:
                origin_disp = p.origin.launcher_type

            row_str = (
                f"{p.pid:>6} {p.ppid:>6} {p.creds.user:<10.10} {p.state_char:^2} "
                f"{p.cpu.cpu_percent:>6.1f} {p.memory.mem_percent:>6.1f} {format_bytes(p.memory.rss_bytes):>8} "
                f"{p.threads_count:>4} {origin_disp:<20.20} {p.cmdline or p.name}"
            )

            try:
                if is_selected:
                    stdscr.attron(curses.color_pair(5) | curses.A_BOLD)
                    stdscr.addstr(line_y, 0, row_str[:max_x].ljust(max_x))
                    stdscr.attroff(curses.color_pair(5) | curses.A_BOLD)
                else:
                    stdscr.addstr(line_y, 0, row_str[:max_x])
            except curses.error:
                pass

    def _draw_detail_view(self, stdscr: Any, max_y: int, max_x: int) -> None:
        if not self.filtered_procs or self.selected_index >= len(self.filtered_procs):
            self.detail_mode = False
            return

        p = self.filtered_procs[self.selected_index]
        # Collect deep info for selected process
        deep_p = self.collector.collect_process(p.pid, deep=True) or p

        # Title
        title = f" Process Details: PID {p.pid} ({p.name}) "
        try:
            stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
            stdscr.addstr(0, 0, title[:max_x].ljust(max_x))
            stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)
        except curses.error:
            pass

        # Tabs bar
        tabs = ["1: Overview", "2: Files (FDs)", "3: Network", "4: Security", "5: Environ"]
        tab_bar = "  " + "   ".join(
            f"[{t}]" if idx == self.detail_tab else t
            for idx, t in enumerate(tabs)
        )
        try:
            stdscr.attron(curses.A_STANDOUT)
            stdscr.addstr(1, 0, tab_bar[:max_x].ljust(max_x))
            stdscr.attroff(curses.A_STANDOUT)
        except curses.error:
            pass

        content_lines: List[str] = []

        if self.detail_tab == 0:  # Overview
            content_lines.append(f"PID / PPID:       {deep_p.pid} / {deep_p.ppid}   (State: {deep_p.state_char} - {deep_p.state.label})")
            content_lines.append(f"User / Group:     {deep_p.creds.user} (UID {deep_p.creds.ruid}) / {deep_p.creds.group} (GID {deep_p.creds.rgid})")
            content_lines.append(f"Launch Origin:    {deep_p.origin.launcher_type.upper()} ({deep_p.origin.description})")
            content_lines.append(f"Executable:       {deep_p.exe or '[none]'}{' [DELETED]' if deep_p.is_deleted_exe else ''}")
            content_lines.append(f"Working Dir:      {deep_p.cwd or '[none]'}")
            content_lines.append(f"Root Dir:         {deep_p.root or '/'}{' [CHROOT]' if deep_p.is_chroot else ''}")
            content_lines.append(f"Started:          {deep_p.start_time_iso} (Age: {deep_p.age_human})")
            content_lines.append(f"CPU Usage:        {deep_p.cpu.cpu_percent:.1f}% (Total: {deep_p.cpu.total_time_seconds:.2f}s | Allowed: {deep_p.cpu.cpus_allowed_list or 'all'})")
            content_lines.append(f"Memory (RSS/VMS): {format_bytes(deep_p.memory.rss_bytes)} ({deep_p.memory.mem_percent:.1f}%) / {format_bytes(deep_p.memory.vms_bytes)}")
            content_lines.append(f"Threads / Nice:   {deep_p.threads_count} threads | Nice: {deep_p.nice} | Sched: {deep_p.sched_policy}")
            content_lines.append(f"Command Line:     {deep_p.cmdline}")
            if deep_p.origin.service_name:
                content_lines.append(f"Systemd Service:  {deep_p.origin.service_name}")
            if deep_p.cgroup.is_container:
                content_lines.append(f"Container:        {deep_p.cgroup.container_runtime} ID: {deep_p.cgroup.container_id}")

        elif self.detail_tab == 1:  # Files
            fds = self.fs_collector.collect_fds(p.pid)
            content_lines.append(f"Open File Descriptors ({len(fds)} total):")
            content_lines.append(f" {'FD':<4} {'TYPE':<14} {'MODE':<5} {'INODE':<10} {'TARGET':<45}")
            content_lines.append("-" * 75)
            for f in fds[:max_y - 6]:
                del_mark = " [DELETED]" if f.is_deleted else ""
                content_lines.append(f" {f.fd:<4} {f.fd_type.label:<14} {f.mode or '-':<5} {f.inode or '-':<10} {f.target}{del_mark}")

        elif self.detail_tab == 2:  # Network
            summary = self.net_collector.collect_process_network_summary(p.pid)
            all_socks = summary.listening_tcp + summary.established_tcp + summary.listening_udp + summary.other_connections + summary.unix_sockets
            content_lines.append(f"Network Sockets ({len(all_socks)} total):")
            content_lines.append(f" {'PROTO':<6} {'LOCAL ENDPOINT':<24} {'REMOTE ENDPOINT':<22} {'STATE':<12}")
            content_lines.append("-" * 75)
            for s in all_socks[:max_y - 6]:
                content_lines.append(f" {s.protocol.value:<6} {s.local_endpoint:<24} {s.remote_endpoint:<22} {s.state.value:<12}")

        elif self.detail_tab == 3:  # Security
            sec = self.sec_collector.collect(p.pid)
            content_lines.append("Security & Privilege Profile:")
            content_lines.append(f" NoNewPrivs:       {'Enabled' if sec.no_new_privs else 'Disabled'}")
            content_lines.append(f" Seccomp Mode:     {sec.seccomp_mode.label}")
            content_lines.append(f" LSM Profile:      {sec.apparmor_profile or sec.selinux_context or 'None / Unconfined'}")
            eff_caps = ", ".join(sorted(list(sec.capabilities.effective))) or "None (Unprivileged)"
            content_lines.append(f" Effective Caps:   {eff_caps}")
            if sec.exe_owner:
                content_lines.append(f" Binary Owner:     {sec.exe_owner}:{sec.exe_group} ({sec.exe_mode_octal}) {'[SUID]' if sec.is_setuid else ''}")
            content_lines.append("\n Observations:")
            for obs in sec.observations:
                content_lines.append(f"  ● [{obs.category}] {obs.title}: {obs.description}")

        elif self.detail_tab == 4:  # Environ
            raw_env_content = self.procfs.read_file(p.pid, "environ", binary=True)
            if raw_env_content and isinstance(raw_env_content, bytes):
                raw_dict = {}
                for item in raw_env_content.split(b"\x00"):
                    if b"=" in item:
                        k, v = item.decode("utf-8", "replace").split("=", 1)
                        raw_dict[k] = v
                processed = process_environ(raw_dict, redact=True)
                content_lines.append(f"Environment Variables ({len(processed)} vars, secrets redacted):")
                for k, (v, is_sec) in sorted(processed.items()):
                    sec_tag = " [SECRET]" if is_sec else ""
                    content_lines.append(f"  {k}={v}{sec_tag}")
            else:
                content_lines.append("Environment inaccessible (Permission Denied or empty).")

        for idx, line in enumerate(content_lines[:max_y - 4]):
            try:
                stdscr.addstr(3 + idx, 1, line[:max_x - 2])
            except curses.error:
                pass

    def _draw_status_bar(self, stdscr: Any, max_y: int, max_x: int) -> None:
        try:
            if self.is_filtering:
                prompt = f" Filter query: {self.filter_query}_ "
                stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
                stdscr.addstr(max_y - 1, 0, prompt[:max_x].ljust(max_x))
                stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)
            else:
                stdscr.attron(curses.color_pair(1))
                stdscr.addstr(max_y - 1, 0, f" {self.status_msg} "[:max_x].ljust(max_x))
                stdscr.attroff(curses.color_pair(1))
        except curses.error:
            pass

    def _handle_filter_input(self, ch: int) -> None:
        if ch in (10, 13, curses.KEY_ENTER):  # Enter finishes filter
            self.is_filtering = False
            curses.curs_set(0)
            self._apply_filter()
            self.status_msg = f"Filtered by: '{self.filter_query}'"
        elif ch == 27:  # ESC cancels
            self.is_filtering = False
            self.filter_query = ""
            curses.curs_set(0)
            self._apply_filter()
            self.status_msg = "Filter cleared"
        elif ch in (curses.KEY_BACKSPACE, 127, 8):
            if self.filter_query:
                self.filter_query = self.filter_query[:-1]
                self._apply_filter()
        elif 32 <= ch <= 126:
            self.filter_query += chr(ch)
            self._apply_filter()
