"""
Comprehensive Mocked ProcFS Integration Test Suite for pinspect.
Validates behavior across containers, security privileges, deleted files,
permission boundaries, and SIEM/EDR JSON output.
"""

import json
import os
import tempfile
import unittest
from typing import Optional

from pinspect.collector.filesystem import FilesystemCollector
from pinspect.collector.network import NetworkCollector
from pinspect.collector.process import ProcessCollector
from pinspect.collector.procfs import ProcFS
from pinspect.collector.security import SecurityCollector
from pinspect.output.json_out import to_json


class TestComprehensiveMockedProc(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.proc_root = self.temp_dir.name
        self.procfs = ProcFS(self.proc_root)
        self.collector = ProcessCollector(self.procfs)
        self.sec_collector = SecurityCollector(self.procfs)
        self.net_collector = NetworkCollector(self.procfs)
        self.fs_collector = FilesystemCollector(self.procfs)

        # Global proc files
        with open(os.path.join(self.proc_root, "uptime"), "w") as f:
            f.write("10000.00 8000.00\n")
        with open(os.path.join(self.proc_root, "meminfo"), "w") as f:
            f.write("MemTotal:        32768000 kB\nMemFree:         16384000 kB\n")

        # 1. PID 1: systemd (init)
        self._create_process_fixture(
            pid=1,
            ppid=0,
            comm="systemd",
            cmdline=b"/lib/systemd/systemd\x00--system\x00--deserialize=38\x00",
            exe="/lib/systemd/systemd",
            cwd="/",
            root="/",
            cgroup="0::/\n",
            caps_eff="000001ffffffffff",  # Full caps
        )

        # 2. PID 1000: sshd (systemd service)
        self._create_process_fixture(
            pid=1000,
            ppid=1,
            comm="sshd",
            cmdline=b"/usr/sbin/sshd\x00-D\x00",
            exe="/usr/sbin/sshd",
            cgroup="0::/system.slice/sshd.service\n",
            caps_eff="0000000000000400",  # CAP_NET_BIND_SERVICE
            fds=[(3, "socket:[10001]")],
        )

        # 3. PID 2000: docker container payload with isolated namespaces and deleted binary
        self._create_process_fixture(
            pid=2000,
            ppid=1,
            comm="deleted-worker",
            cmdline=b"/app/worker\x00--threads=8\x00",
            exe="/app/worker (deleted)",
            cwd="/app",
            root="/var/lib/docker/overlay2/rootfs",
            cgroup="0::/system.slice/docker-a1b2c3d4e5f600112233445566778899aabbccddeeff00112233445566778899.scope\n",
            nnp=1,
            seccomp=2,
            ns_map={"net": 4026539999, "mnt": 4026538888, "pid": 4026537777},
            fds=[(4, "/app/data.log (deleted)")],
        )

        # 4. PID 3000: cron job child
        self._create_process_fixture(
            pid=3000,
            ppid=1,
            comm="cron",
            cmdline=b"/usr/sbin/cron\x00-f\x00",
            cgroup="0::/system.slice/cron.service\n",
        )
        self._create_process_fixture(
            pid=3001,
            ppid=3000,
            comm="backup.sh",
            cmdline=b"/bin/bash\x00/opt/scripts/backup.sh\x00",
        )

        # Net tables
        net_dir = os.path.join(self.proc_root, "net")
        os.makedirs(net_dir, exist_ok=True)
        tcp_content = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 10001\n"
        )
        with open(os.path.join(net_dir, "tcp"), "w") as f:
            f.write(tcp_content)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_process_fixture(
        self,
        pid: int,
        ppid: int,
        comm: str,
        cmdline: bytes,
        exe: str = "/bin/bash",
        cwd: str = "/",
        root: str = "/",
        cgroup: str = "",
        caps_eff: str = "0000000000000000",
        nnp: int = 0,
        seccomp: int = 0,
        ns_map: Optional[dict] = None,
        fds: Optional[list] = None,
    ):
        pdir = os.path.join(self.proc_root, str(pid))
        os.makedirs(pdir, exist_ok=True)

        stat_line = f"{pid} ({comm}) S {ppid} {pid} {pid} 0 -1 0 0 0 0 0 20 10 0 0 20 0 1 0 1000 20000000 2500 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
        with open(os.path.join(pdir, "stat"), "w") as f:
            f.write(stat_line)

        status_content = (
            f"Name:\t{comm}\n"
            f"PPid:\t{ppid}\n"
            f"Uid:\t0 0 0 0\n"
            f"Gid:\t0 0 0 0\n"
            f"VmRSS:\t   10000 kB\n"
            f"VmSize:\t   20000 kB\n"
            f"Threads:\t2\n"
            f"NoNewPrivs:\t{nnp}\n"
            f"Seccomp:\t{seccomp}\n"
            f"CapInh:\t0000000000000000\n"
            f"CapPrm:\t{caps_eff}\n"
            f"CapEff:\t{caps_eff}\n"
            f"CapBnd:\t000001ffffffffff\n"
            f"CapAmb:\t0000000000000000\n"
        )
        with open(os.path.join(pdir, "status"), "w") as f:
            f.write(status_content)

        with open(os.path.join(pdir, "comm"), "w") as f:
            f.write(f"{comm}\n")

        with open(os.path.join(pdir, "cmdline"), "wb") as f:
            f.write(cmdline)

        with open(os.path.join(pdir, "cgroup"), "w") as f:
            f.write(cgroup)

        os.symlink(exe, os.path.join(pdir, "exe"))
        os.symlink(cwd, os.path.join(pdir, "cwd"))
        os.symlink(root, os.path.join(pdir, "root"))

        # FDs
        fddir = os.path.join(pdir, "fd")
        os.makedirs(fddir, exist_ok=True)
        if fds:
            for fd_num, target in fds:
                os.symlink(target, os.path.join(fddir, str(fd_num)))

        # Namespaces
        nsdir = os.path.join(pdir, "ns")
        os.makedirs(nsdir, exist_ok=True)
        default_ns = {"net": 4026531992, "mnt": 4026531840, "pid": 4026531836, "user": 4026531837, "ipc": 4026531839, "uts": 4026531838}
        actual_ns = default_ns.copy()
        if ns_map:
            actual_ns.update(ns_map)
        for ns_type, ino in actual_ns.items():
            os.symlink(f"{ns_type}:[{ino}]", os.path.join(nsdir, ns_type))

    def test_collect_all_and_verify_origins(self):
        procs = self.collector.collect_all_processes(deep=True)
        self.assertEqual(len(procs), 5)
        p_by_pid = {p.pid: p for p in procs}

        # PID 1 should be init
        self.assertEqual(p_by_pid[1].origin.launcher_type, "init")

        # PID 1000 should be systemd sshd.service
        self.assertEqual(p_by_pid[1000].origin.launcher_type, "systemd")
        self.assertEqual(p_by_pid[1000].origin.service_name, "sshd.service")

        # PID 2000 should be container
        self.assertEqual(p_by_pid[2000].origin.launcher_type, "container")
        self.assertEqual(p_by_pid[2000].cgroup.container_runtime, "Docker")
        self.assertEqual(p_by_pid[2000].cgroup.container_id, "a1b2c3d4e5f6")
        self.assertTrue(p_by_pid[2000].is_deleted_exe)
        self.assertEqual(p_by_pid[2000].deleted_files_count, 1)

        # PID 3001 should be detected as cron origin
        self.assertEqual(p_by_pid[3001].origin.launcher_type, "cron")

    def test_security_profile_and_observations(self):
        sec = self.sec_collector.collect(2000)
        self.assertTrue(sec.exe_is_deleted)
        self.assertTrue(sec.no_new_privs)
        self.assertEqual(sec.seccomp_mode.value, 2)
        self.assertTrue(sec.has_isolated_namespaces)

        obs_titles = [o.title for o in sec.observations]
        self.assertIn("Deleted Executable on Disk", obs_titles)
        self.assertIn("NoNewPrivs Active", obs_titles)
        self.assertIn("Seccomp BPF Filter Active", obs_titles)

    def test_siem_edr_json_serialization(self):
        procs = self.collector.collect_all_processes(deep=True)
        json_str = to_json(procs)
        parsed = json.loads(json_str)

        self.assertIsInstance(parsed, list)
        self.assertEqual(len(parsed), 5)
        
        # Verify schema validity for EDR ingestion
        first = parsed[0]
        self.assertIn("pid", first)
        self.assertIn("cpu", first)
        self.assertIn("memory", first)
        self.assertIn("origin", first)
        self.assertIn("creds", first)
        self.assertIn("cgroup", first)


if __name__ == "__main__":
    unittest.main()
