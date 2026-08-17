"""
Process collector aggregating procfs metadata into ProcessInfo models.
"""

import os
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Tuple

from pinspect.collector.container import ContainerCollector
from pinspect.collector.filesystem import FilesystemCollector
from pinspect.collector.namespaces import NamespaceCollector
from pinspect.collector.network import NetworkCollector
from pinspect.collector.procfs import ProcFS
from pinspect.collector.security import SecurityCollector
from pinspect.collector.systemd import SystemdCollector
from pinspect.model.process import (
    CgroupInfo,
    CPUStats,
    CredentialInfo,
    LimitsInfo,
    MemoryStats,
    ProcessAncestryNode,
    ProcessInfo,
    ProcessOrigin,
    ProcessState,
)
from pinspect.utils.formatting import format_duration, format_timestamp
from pinspect.utils.system import (
    get_clock_ticks,
    get_page_size,
    get_total_memory,
    get_uptime,
    resolve_gid,
    resolve_sched_policy,
    resolve_tty,
    resolve_uid,
)


class ProcessCollector:
    """Collects comprehensive process intelligence from /proc."""

    def __init__(self, procfs: Optional[ProcFS] = None):
        self.procfs = procfs or ProcFS()
        self.systemd_collector = SystemdCollector()
        self.container_collector = ContainerCollector()
        self.security_collector = SecurityCollector(self.procfs)
        self.ns_collector = NamespaceCollector(self.procfs)
        self.fs_collector = FilesystemCollector(self.procfs)
        self.net_collector = NetworkCollector(self.procfs)

    def collect_all_processes(
        self,
        deep: bool = False,
        workers: int = 16,
    ) -> List[ProcessInfo]:
        """Collect all running processes from procfs."""
        pids = self.procfs.list_pids()
        if not pids:
            return []

        # Read processes (using thread pool for parallelism on large systems)
        if len(pids) > 1 and workers > 1:
            with ThreadPoolExecutor(max_workers=min(workers, len(pids))) as executor:
                procs = list(executor.map(lambda pid: self.collect_process(pid, deep=deep), pids))
        else:
            procs = [self.collect_process(pid, deep=deep) for pid in pids]

        valid_procs = [p for p in procs if p is not None]

        # Link parent/child relationships and build full ancestor chains
        proc_by_pid = {p.pid: p for p in valid_procs}
        for p in valid_procs:
            if p.ppid in proc_by_pid:
                parent = proc_by_pid[p.ppid]
                parent.children.append(p.pid)
                parent.children_names.append(p.name)

        # Build ancestry and origin intelligence
        for p in valid_procs:
            self._resolve_ancestry_and_origin(p, proc_by_pid)

        return valid_procs

    def collect_process_with_ancestry(self, pid: int, deep: bool = True) -> Optional[ProcessInfo]:
        """
        Collect a single process plus its ancestor chain without scanning all PIDs.

        Unlike collect_all_processes(), this only reads /proc for the target and its
        direct ancestors, which is far cheaper for single-PID commands on busy hosts.
        Returns None if the target process doesn't exist.
        """
        pinfo = self.collect_process(pid, deep=deep)
        if pinfo is None:
            return None

        proc_by_pid: Dict[int, ProcessInfo] = {pid: pinfo}
        curr = pinfo
        seen = {pid}
        while curr and curr.ppid > 0 and curr.ppid not in seen:
            seen.add(curr.ppid)
            parent = self.collect_process(curr.ppid, deep=False)
            if parent is None:
                break
            parent.children.append(curr.pid)
            parent.children_names.append(curr.name)
            proc_by_pid[parent.pid] = parent
            curr = parent

        self._resolve_ancestry_and_origin(pinfo, proc_by_pid)
        return pinfo

    def collect_process(self, pid: int, deep: bool = True) -> Optional[ProcessInfo]:
        """
        Collect process details for a single PID safely.
        Returns None if process doesn't exist or disappeared during read.
        """
        # 1. Read /proc/<pid>/stat
        stat_line = self.procfs.read_file(pid, "stat")
        if not stat_line:
            return None

        stat_str = stat_line.decode("utf-8", "replace") if isinstance(stat_line, bytes) else stat_line
        parsed_stat = self._parse_stat_line(stat_str)
        if not parsed_stat:
            return None

        # 2. Read /proc/<pid>/status
        status_dict = self._parse_status_file(pid)

        # 3. Read /proc/<pid>/cmdline
        cmdline, argv = self._parse_cmdline(pid)

        # 4. Read /proc/<pid>/comm
        comm = self._parse_comm(pid, parsed_stat.get("comm", ""))

        # 5. Resolve links (exe, cwd, root)
        exe_link = self.procfs.read_symlink(pid, "exe")
        cwd_link = self.procfs.read_symlink(pid, "cwd")
        root_link = self.procfs.read_symlink(pid, "root")

        is_deleted_exe = False
        resolved_exe = exe_link
        if exe_link and exe_link.endswith(" (deleted)"):
            is_deleted_exe = True
            resolved_exe = exe_link[:-10]

        is_chroot = bool(root_link and root_link != "/")

        # 6. Parse Credentials
        creds = self._parse_credentials(pid, status_dict)

        # 7. Parse Timing & CPU
        uptime = get_uptime(self.procfs.proc_root)
        clk_tck = get_clock_ticks()
        starttime_ticks = parsed_stat.get("starttime", 0)
        start_seconds_after_boot = starttime_ticks / clk_tck
        now = time.time()
        
        # Approximate start epoch
        boot_epoch = now - uptime
        start_epoch = boot_epoch + start_seconds_after_boot
        age_seconds = max(0.0, uptime - start_seconds_after_boot)

        utime_ticks = parsed_stat.get("utime", 0)
        stime_ticks = parsed_stat.get("stime", 0)
        cutime_ticks = parsed_stat.get("cutime", 0)
        cstime_ticks = parsed_stat.get("cstime", 0)
        total_cpu_seconds = (utime_ticks + stime_ticks) / clk_tck
        cpu_percent = 0.0
        if age_seconds > 0:
            cpu_percent = min(100.0 * (os.cpu_count() or 1), (total_cpu_seconds / age_seconds) * 100.0)

        cpus_allowed_list = status_dict.get("Cpus_allowed_list", "")
        cpus_allowed_count = 1
        if cpus_allowed_list:
            cpus_allowed_count = self._count_cpus_in_list(cpus_allowed_list)

        cpu_stats = CPUStats(
            utime_ticks=utime_ticks,
            stime_ticks=stime_ticks,
            cutime_ticks=cutime_ticks,
            cstime_ticks=cstime_ticks,
            total_time_seconds=total_cpu_seconds,
            cpu_percent=round(cpu_percent, 1),
            processor=parsed_stat.get("processor", 0),
            cpus_allowed_list=cpus_allowed_list,
            cpus_allowed_count=cpus_allowed_count,
        )

        # 8. Parse Memory
        page_size = get_page_size()
        total_mem = get_total_memory(self.procfs.proc_root)
        rss_pages = parsed_stat.get("rss", 0)
        rss_bytes = rss_pages * page_size
        vms_bytes = parsed_stat.get("vsize", 0)
        mem_percent = (rss_bytes / total_mem * 100.0) if total_mem > 0 else 0.0

        # Read statm & status memory fields
        statm_line = self.procfs.read_file(pid, "statm")
        shared_bytes = 0
        text_bytes = 0
        data_bytes = 0
        if statm_line:
            try:
                s_parts = (statm_line.decode() if isinstance(statm_line, bytes) else statm_line).split()
                if len(s_parts) >= 6:
                    shared_bytes = int(s_parts[2]) * page_size
                    text_bytes = int(s_parts[3]) * page_size
                    data_bytes = int(s_parts[5]) * page_size
            except Exception:
                pass

        swap_bytes = self._parse_kb(status_dict.get("VmSwap"))
        peak_vms = self._parse_kb(status_dict.get("VmPeak"))
        peak_rss = self._parse_kb(status_dict.get("VmHWM"))

        # Try smaps_rollup for PSS & USS if deep or available
        pss_bytes = None
        uss_bytes = None
        if deep:
            pss_bytes, uss_bytes = self._parse_smaps_rollup(pid)

        memory_stats = MemoryStats(
            rss_bytes=rss_bytes,
            vms_bytes=vms_bytes,
            shared_bytes=shared_bytes,
            text_bytes=text_bytes,
            data_bytes=data_bytes,
            swap_bytes=swap_bytes,
            pss_bytes=pss_bytes,
            uss_bytes=uss_bytes,
            peak_vms_bytes=peak_vms,
            peak_rss_bytes=peak_rss,
            mem_percent=round(mem_percent, 1),
        )

        # 9. Threads & State
        threads_count = int(status_dict.get("Threads", parsed_stat.get("num_threads", 1)))
        state_char = parsed_stat.get("state", "?")
        state = ProcessState.from_char(state_char)
        is_zombie = state == ProcessState.ZOMBIE

        # Check if kernel thread (PPID 2 or PID 2 or no cmdline and rss 0)
        ppid = parsed_stat.get("ppid", 0)
        is_kernel_thread = (ppid == 2 or pid == 2 or (not cmdline and rss_bytes == 0 and not exe_link))

        if not cmdline:
            cmdline = f"[{comm}]" if is_kernel_thread else comm

        # 10. Scheduling & Limits
        sched_policy_id = parsed_stat.get("policy", 0)
        sched_policy = resolve_sched_policy(sched_policy_id)
        limits_info = self._parse_limits(pid) if deep else LimitsInfo()

        # 11. Cgroup & Container
        cgroup_content = self.procfs.read_file(pid, "cgroup") or ""
        if isinstance(cgroup_content, bytes):
            cgroup_content = cgroup_content.decode("utf-8", "replace")

        unit, slice_name, user_unit = self.systemd_collector.extract_unit_and_slice(cgroup_content)
        unit_file = self.systemd_collector.find_unit_file(unit)

        container_data = self.container_collector.inspect_cgroup(cgroup_content, root_link)

        cgroup_info = CgroupInfo(
            cgroup_v2_path=cgroup_content.splitlines()[0] if cgroup_content else None,
            systemd_unit=unit,
            systemd_slice=slice_name,
            systemd_user_unit=user_unit,
            unit_file_path=unit_file,
            is_container=container_data["is_container"],
            container_runtime=container_data["container_runtime"],
            container_id=container_data["container_id"],
            container_name=container_data["container_name"],
            kubernetes_pod_uid=container_data["kubernetes_pod_uid"],
            kubernetes_namespace=container_data["kubernetes_namespace"],
            kubernetes_container_name=container_data["kubernetes_container_name"],
        )

        # 12. Construct ProcessInfo
        pinfo = ProcessInfo(
            pid=pid,
            ppid=ppid,
            name=comm,
            cmdline=cmdline,
            argv=argv,
            exe=exe_link,
            resolved_exe=resolved_exe,
            is_deleted_exe=is_deleted_exe,
            cwd=cwd_link,
            root=root_link,
            is_chroot=is_chroot,
            state=state,
            state_char=state_char,
            nice=parsed_stat.get("nice", 0),
            priority=parsed_stat.get("priority", 0),
            sched_policy=sched_policy,
            pgrp=parsed_stat.get("pgrp", 0),
            session_id=parsed_stat.get("session", 0),
            tpgid=parsed_stat.get("tpgid", 0),
            tty_nr=parsed_stat.get("tty_nr", 0),
            tty_name=resolve_tty(parsed_stat.get("tty_nr", 0)),
            start_time_epoch=start_epoch,
            start_time_iso=format_timestamp(start_epoch),
            age_seconds=round(age_seconds, 1),
            age_human=format_duration(age_seconds),
            cpu=cpu_stats,
            memory=memory_stats,
            threads_count=threads_count,
            creds=creds,
            cgroup=cgroup_info,
            limits=limits_info,
            is_kernel_thread=is_kernel_thread,
            is_zombie=is_zombie,
            wchan=self.procfs.read_file(pid, "wchan"),
        )

        # 13. Deep inspections
        if deep:
            # Open FDs & Deleted Files
            try:
                fds = self.fs_collector.collect_fds(pid)
                pinfo.open_fd_count = len(fds)
                pinfo.deleted_files_count = sum(1 for f in fds if f.is_deleted)
            except Exception:
                pass

        return pinfo

    def _resolve_ancestry_and_origin(
        self,
        pinfo: ProcessInfo,
        proc_by_pid: Dict[int, ProcessInfo],
    ) -> None:
        """Resolve full ancestor chain up to PID 1 and determine launch origin."""
        chain: List[ProcessAncestryNode] = []
        curr_ppid = pinfo.ppid
        visited = {pinfo.pid}

        while curr_ppid > 0 and curr_ppid not in visited:
            visited.add(curr_ppid)
            if curr_ppid in proc_by_pid:
                parent = proc_by_pid[curr_ppid]
                chain.append(
                    ProcessAncestryNode(
                        pid=parent.pid,
                        ppid=parent.ppid,
                        name=parent.name,
                        cmdline=parent.cmdline,
                        user=parent.creds.user,
                        exe=parent.exe,
                        is_deleted_exe=parent.is_deleted_exe,
                    )
                )
                curr_ppid = parent.ppid
            else:
                # Parent might have exited or be inaccessible
                comm = self.procfs.read_file(curr_ppid, "comm")
                if comm:
                    chain.append(
                        ProcessAncestryNode(
                            pid=curr_ppid,
                            ppid=0,
                            name=str(comm).strip(),
                            cmdline=str(comm).strip(),
                            user="?",
                        )
                    )
                break

        pinfo.ancestry = chain

        # Determine Origin Intelligence
        origin_type = "unknown"
        desc = ""
        service_name = pinfo.cgroup.systemd_unit

        # Check container
        if pinfo.cgroup.is_container:
            origin_type = "container"
            desc = f"Container ({pinfo.cgroup.container_runtime or 'OCI'}) ID {pinfo.cgroup.container_id or ''}"
        # Check systemd service
        elif pinfo.cgroup.systemd_unit and pinfo.cgroup.systemd_unit.endswith(".service"):
            origin_type = "systemd"
            desc = f"systemd service ({pinfo.cgroup.systemd_unit})"
        # Check Ancestry for SSH, cron, shells
        else:
            ancestor_names = [a.name.lower() for a in chain]
            if any("sshd" in n or "dropbear" in n for n in ancestor_names):
                origin_type = "ssh"
                desc = "Interactive SSH session"
            elif any("cron" in n or "anacron" in n or "atd" in n for n in ancestor_names):
                origin_type = "cron"
                desc = "Scheduled cron job"
            elif any(n in ("bash", "zsh", "fish", "sh", "tmux", "screen") for n in ancestor_names):
                origin_type = "shell"
                desc = f"Shell command (parent {chain[0].name if chain else 'shell'})"
            elif any("docker" in n or "containerd" in n or "podman" in n for n in ancestor_names):
                origin_type = "docker"
                desc = "Container daemon child"
            elif pinfo.is_kernel_thread:
                origin_type = "kernel"
                desc = "Kernel thread"
            elif pinfo.pid == 1:
                origin_type = "init"
                desc = "System init (PID 1)"
            else:
                origin_type = "process"
                desc = f"Spawned by {chain[0].name if chain else f'PID {pinfo.ppid}'}"

        parent_exe = chain[0].exe if chain else None
        parent_cmd = chain[0].cmdline if chain else None

        pinfo.origin = ProcessOrigin(
            launcher_type=origin_type,
            description=desc,
            service_name=service_name,
            unit_file=pinfo.cgroup.unit_file_path,
            cgroup_path=pinfo.cgroup.cgroup_v2_path,
            container_id=pinfo.cgroup.container_id,
            container_name=pinfo.cgroup.container_name,
            container_runtime=pinfo.cgroup.container_runtime,
            ancestor_chain=chain,
            parent_exe=parent_exe,
            parent_cmdline=parent_cmd,
        )

    def _parse_stat_line(self, stat_str: str) -> Optional[Dict[str, Any]]:
        """Parse Linux /proc/<pid>/stat line correctly handling parentheses in comm."""
        try:
            r_paren = stat_str.rfind(")")
            l_paren = stat_str.find("(")
            if l_paren == -1 or r_paren == -1:
                return None

            pid = int(stat_str[:l_paren].strip())
            comm = stat_str[l_paren + 1 : r_paren]
            rest = stat_str[r_paren + 1 :].strip().split()

            # rest starts from field 3 (state)
            # index 0: state (3)
            # index 1: ppid (4)
            # index 2: pgrp (5)
            # index 3: session (6)
            # index 4: tty_nr (7)
            # index 5: tpgid (8)
            # ...
            # index 11: utime (14)
            # index 12: stime (15)
            # index 13: cutime (16)
            # index 14: cstime (17)
            # index 15: priority (18)
            # index 16: nice (19)
            # index 17: num_threads (20)
            # ...
            # index 19: starttime (22)
            # index 20: vsize (23)
            # index 21: rss (24)
            # ...
            # index 36: processor (39)
            # index 38: policy (41)

            res = {
                "pid": pid,
                "comm": comm,
                "state": rest[0] if len(rest) > 0 else "?",
                "ppid": int(rest[1]) if len(rest) > 1 else 0,
                "pgrp": int(rest[2]) if len(rest) > 2 else 0,
                "session": int(rest[3]) if len(rest) > 3 else 0,
                "tty_nr": int(rest[4]) if len(rest) > 4 else 0,
                "tpgid": int(rest[5]) if len(rest) > 5 else 0,
                "utime": int(rest[11]) if len(rest) > 11 else 0,
                "stime": int(rest[12]) if len(rest) > 12 else 0,
                "cutime": int(rest[13]) if len(rest) > 13 else 0,
                "cstime": int(rest[14]) if len(rest) > 14 else 0,
                "priority": int(rest[15]) if len(rest) > 15 else 0,
                "nice": int(rest[16]) if len(rest) > 16 else 0,
                "num_threads": int(rest[17]) if len(rest) > 17 else 1,
                "starttime": int(rest[19]) if len(rest) > 19 else 0,
                "vsize": int(rest[20]) if len(rest) > 20 else 0,
                "rss": int(rest[21]) if len(rest) > 21 else 0,
                "processor": int(rest[36]) if len(rest) > 36 else 0,
                "policy": int(rest[38]) if len(rest) > 38 else 0,
            }
            return res
        except (ValueError, IndexError):
            return None

    def _parse_status_file(self, pid: int) -> Dict[str, str]:
        lines = self.procfs.read_lines(pid, "status")
        res: Dict[str, str] = {}
        for line in lines:
            if ":" in line:
                k, v = line.split(":", 1)
                res[k.strip()] = v.strip()
        return res

    def _parse_cmdline(self, pid: int) -> Tuple[str, List[str]]:
        raw = self.procfs.read_file(pid, "cmdline", binary=True)
        if not raw or not isinstance(raw, bytes):
            return ("", [])

        try:
            parts = [p.decode("utf-8", "replace") for p in raw.split(b"\x00") if p]
            cmdline = " ".join(parts)
            return (cmdline, parts)
        except Exception:
            return ("", [])

    def _parse_comm(self, pid: int, fallback: str = "") -> str:
        comm = self.procfs.read_file(pid, "comm")
        if comm:
            return str(comm).strip()
        return fallback

    def _parse_credentials(self, pid: int, status_dict: Dict[str, str]) -> CredentialInfo:
        # Uid: ruid euid suid fsuid
        uid_parts = status_dict.get("Uid", "0 0 0 0").split()
        gid_parts = status_dict.get("Gid", "0 0 0 0").split()

        ruid = int(uid_parts[0]) if len(uid_parts) > 0 else 0
        euid = int(uid_parts[1]) if len(uid_parts) > 1 else ruid
        suid = int(uid_parts[2]) if len(uid_parts) > 2 else euid
        fsuid = int(uid_parts[3]) if len(uid_parts) > 3 else euid

        rgid = int(gid_parts[0]) if len(gid_parts) > 0 else 0
        egid = int(gid_parts[1]) if len(gid_parts) > 1 else rgid
        sgid = int(gid_parts[2]) if len(gid_parts) > 2 else egid
        fsgid = int(gid_parts[3]) if len(gid_parts) > 3 else egid

        groups_str = status_dict.get("Groups", "")
        groups = [int(g) for g in groups_str.split() if g.isdigit()]
        group_names = [resolve_gid(g) for g in groups]

        # Login UID
        loginuid_val = None
        loginuser_val = None
        raw_loginuid = self.procfs.read_file(pid, "loginuid")
        if raw_loginuid:
            try:
                l_int = int(str(raw_loginuid).strip())
                if l_int != 4294967295:  # (uint32)-1 means unset in Linux audit
                    loginuid_val = l_int
                    loginuser_val = resolve_uid(l_int)
            except ValueError:
                pass

        return CredentialInfo(
            ruid=ruid,
            euid=euid,
            suid=suid,
            fsuid=fsuid,
            rgid=rgid,
            egid=egid,
            sgid=sgid,
            fsgid=fsgid,
            user=resolve_uid(ruid),
            group=resolve_gid(rgid),
            effective_user=resolve_uid(euid),
            effective_group=resolve_gid(egid),
            groups=groups,
            group_names=group_names,
            loginuid=loginuid_val,
            loginuser=loginuser_val,
        )

    def _parse_kb(self, val: Optional[str]) -> int:
        if not val:
            return 0
        parts = val.split()
        if parts and parts[0].isdigit():
            return int(parts[0]) * 1024
        return 0

    def _parse_smaps_rollup(self, pid: int) -> Tuple[Optional[int], Optional[int]]:
        lines = self.procfs.read_lines(pid, "smaps_rollup")
        if not lines:
            return (None, None)
        pss = None
        uss = None
        p_clean = 0
        p_dirty = 0
        for line in lines:
            if line.startswith("Pss:"):
                pss = self._parse_kb(line.split(":")[1])
            elif line.startswith("Private_Clean:"):
                p_clean = self._parse_kb(line.split(":")[1])
            elif line.startswith("Private_Dirty:"):
                p_dirty = self._parse_kb(line.split(":")[1])
        if p_clean or p_dirty:
            uss = p_clean + p_dirty
        return (pss, uss)

    def _parse_limits(self, pid: int) -> LimitsInfo:
        lines = self.procfs.read_lines(pid, "limits")
        lim = LimitsInfo()
        for line in lines:
            if "Max open files" in line:
                parts = line.split("files", 1)[1].split()
                if len(parts) >= 2:
                    lim.max_open_files_soft, lim.max_open_files_hard = parts[0], parts[1]
            elif "Max processes" in line:
                parts = line.split("processes", 1)[1].split()
                if len(parts) >= 2:
                    lim.max_processes_soft, lim.max_processes_hard = parts[0], parts[1]
            elif "Max locked memory" in line:
                parts = line.split("memory", 1)[1].split()
                if len(parts) >= 2:
                    lim.max_locked_memory_soft, lim.max_locked_memory_hard = parts[0], parts[1]
            elif "Max core file size" in line:
                parts = line.split("size", 1)[1].split()
                if len(parts) >= 2:
                    lim.max_core_size_soft, lim.max_core_size_hard = parts[0], parts[1]
        return lim

    def _count_cpus_in_list(self, cpu_list: str) -> int:
        count = 0
        for segment in cpu_list.split(","):
            segment = segment.strip()
            if "-" in segment:
                try:
                    start, end = map(int, segment.split("-"))
                    count += max(0, end - start + 1)
                except ValueError:
                    pass
            elif segment.isdigit():
                count += 1
        return max(1, count)
