"""
Unit tests for process tree and ancestry resolution.
"""

import os
import tempfile
import unittest
from pinspect.collector.procfs import ProcFS
from pinspect.collector.process import ProcessCollector


class TestProcessTree(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.proc_root = self.temp_dir.name
        self.procfs = ProcFS(self.proc_root)
        self.collector = ProcessCollector(self.procfs)

        with open(os.path.join(self.proc_root, "uptime"), "w") as f:
            f.write("5000.00 4000.00\n")
        with open(os.path.join(self.proc_root, "meminfo"), "w") as f:
            f.write("MemTotal:        16384000 kB\n")

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_proc(self, pid: int, ppid: int, comm: str):
        pdir = os.path.join(self.proc_root, str(pid))
        os.makedirs(pdir, exist_ok=True)
        stat_line = f"{pid} ({comm}) S {ppid} {pid} {pid} 0 -1 0 0 0 0 0 10 5 0 0 20 0 1 0 100 10000 100 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
        with open(os.path.join(pdir, "stat"), "w") as f:
            f.write(stat_line)
        with open(os.path.join(pdir, "status"), "w") as f:
            f.write(f"Name:\t{comm}\nPPid:\t{ppid}\nUid:\t1000 1000 1000 1000\nGid:\t1000 1000 1000 1000\n")
        with open(os.path.join(pdir, "comm"), "w") as f:
            f.write(f"{comm}\n")
        with open(os.path.join(pdir, "cmdline"), "wb") as f:
            f.write(comm.encode() + b"\x00")
        os.makedirs(os.path.join(pdir, "fd"), exist_ok=True)
        os.makedirs(os.path.join(pdir, "ns"), exist_ok=True)

    def test_ancestry_chain_and_children(self):
        # 1 (systemd) -> 100 (sshd) -> 200 (bash) -> 300 (python)
        self._create_proc(1, 0, "systemd")
        self._create_proc(100, 1, "sshd")
        self._create_proc(200, 100, "bash")
        self._create_proc(300, 200, "python")

        processes = self.collector.collect_all_processes(deep=False)
        self.assertEqual(len(processes), 4)

        p_by_pid = {p.pid: p for p in processes}
        p_python = p_by_pid[300]

        # Verify ancestor chain
        ancestor_pids = [a.pid for a in p_python.ancestry]
        self.assertEqual(ancestor_pids, [200, 100, 1])

        # Verify children
        self.assertEqual(p_by_pid[1].children, [100])
        self.assertEqual(p_by_pid[100].children, [200])
        self.assertEqual(p_by_pid[200].children, [300])
        self.assertEqual(p_by_pid[300].children, [])


if __name__ == "__main__":
    unittest.main()
