"""
Unit tests for ProcessCollector using mock procfs trees.
"""

import os
import tempfile
import unittest
from pinspect.collector.procfs import ProcFS
from pinspect.collector.process import ProcessCollector
from pinspect.model.process import ProcessState


class TestProcessCollector(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.proc_root = self.temp_dir.name
        self.procfs = ProcFS(self.proc_root)
        self.collector = ProcessCollector(self.procfs)

        # Write global meminfo & uptime
        with open(os.path.join(self.proc_root, "uptime"), "w") as f:
            f.write("1000.00 800.00\n")
        with open(os.path.join(self.proc_root, "meminfo"), "w") as f:
            f.write("MemTotal:        16384000 kB\nMemFree:          8192000 kB\n")

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_mock_process(
        self,
        pid: int,
        comm: str,
        ppid: int = 1,
        state: str = "S",
        cmdline: bytes = b"",
        utime: int = 100,
        stime: int = 50,
        starttime: int = 1000,
        rss_pages: int = 1000,
        vsize: int = 50000000,
        cgroup: str = "",
        uid: str = "1000 1000 1000 1000",
        gid: str = "1000 1000 1000 1000",
        threads: int = 4,
    ):
        pdir = os.path.join(self.proc_root, str(pid))
        os.makedirs(pdir, exist_ok=True)

        # Construct stat line: pid (comm) state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt cmajflt utime stime cutime cstime priority nice num_threads itrealvalue starttime vsize rss ...
        # Notice fields 14=utime, 15=stime, 16=cutime, 17=cstime, 18=priority, 19=nice, 20=num_threads, 21=itrealvalue, 22=starttime, 23=vsize, 24=rss
        stat_content = (
            f"{pid} ({comm}) {state} {ppid} {pid} {pid} 0 -1 4194304 100 0 0 0 "
            f"{utime} {stime} 0 0 20 0 {threads} 0 {starttime} {vsize} {rss_pages} "
            f"18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n"
        )
        with open(os.path.join(pdir, "stat"), "w") as f:
            f.write(stat_content)

        status_content = (
            f"Name:\t{comm}\n"
            f"State:\t{state} (sleeping)\n"
            f"Tgid:\t{pid}\n"
            f"Pid:\t{pid}\n"
            f"PPid:\t{ppid}\n"
            f"Uid:\t{uid}\n"
            f"Gid:\t{gid}\n"
            f"FDSize:\t64\n"
            f"Groups:\t1000 4 27 \n"
            f"VmPeak:\t   55000 kB\n"
            f"VmSize:\t   50000 kB\n"
            f"VmHWM:\t    4200 kB\n"
            f"VmRSS:\t    4000 kB\n"
            f"Threads:\t{threads}\n"
            f"NoNewPrivs:\t0\n"
            f"Seccomp:\t0\n"
            f"Cpus_allowed_list:\t0-3\n"
        )
        with open(os.path.join(pdir, "status"), "w") as f:
            f.write(status_content)

        with open(os.path.join(pdir, "comm"), "w") as f:
            f.write(f"{comm}\n")

        with open(os.path.join(pdir, "cmdline"), "wb") as f:
            f.write(cmdline)

        with open(os.path.join(pdir, "cgroup"), "w") as f:
            f.write(cgroup)

        os.makedirs(os.path.join(pdir, "fd"), exist_ok=True)
        os.makedirs(os.path.join(pdir, "ns"), exist_ok=True)

    def test_collect_single_process(self):
        self._create_mock_process(
            pid=100,
            comm="nginx",
            ppid=1,
            cmdline=b"nginx\x00-g\x00daemon off;\x00",
            cgroup="0::/system.slice/nginx.service\n",
        )

        p = self.collector.collect_process(100, deep=False)
        self.assertIsNotNone(p)
        self.assertEqual(p.pid, 100)
        self.assertEqual(p.ppid, 1)
        self.assertEqual(p.name, "nginx")
        self.assertEqual(p.cmdline, "nginx -g daemon off;")
        self.assertEqual(p.argv, ["nginx", "-g", "daemon off;"])
        self.assertEqual(p.cgroup.systemd_unit, "nginx.service")
        self.assertEqual(p.cgroup.systemd_slice, "system.slice")
        self.assertEqual(p.threads_count, 4)

    def test_comm_with_parentheses_and_spaces(self):
        # Linux allows process names with spaces or brackets, e.g. "Web Content (1)"
        self._create_mock_process(
            pid=200,
            comm="Web Content (1)",
            ppid=1,
            cmdline=b"/usr/lib/firefox/firefox\x00-contentproc\x00",
        )

        p = self.collector.collect_process(200, deep=False)
        self.assertIsNotNone(p)
        self.assertEqual(p.name, "Web Content (1)")
        self.assertEqual(p.cmdline, "/usr/lib/firefox/firefox -contentproc")

    def test_docker_container_origin_detection(self):
        cid = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        self._create_mock_process(
            pid=300,
            comm="redis-server",
            ppid=1,
            cgroup=f"0::/system.slice/docker-{cid}.scope\n",
        )

        p = self.collector.collect_process(300, deep=False)
        self.assertIsNotNone(p)
        self.assertTrue(p.cgroup.is_container)
        self.assertEqual(p.cgroup.container_runtime, "Docker")
        self.assertEqual(p.cgroup.container_id, cid[:12])

    def test_kernel_thread_detection(self):
        self._create_mock_process(
            pid=2,
            comm="kthreadd",
            ppid=0,
            cmdline=b"",
            rss_pages=0,
        )

        p = self.collector.collect_process(2, deep=False)
        self.assertIsNotNone(p)
        self.assertTrue(p.is_kernel_thread)
        self.assertEqual(p.cmdline, "[kthreadd]")


if __name__ == "__main__":
    unittest.main()
