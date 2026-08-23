"""
Regression tests for the bugs found during code review:

1. ProcessState.from_char() upper-cased the input, so a traced process ('t')
   was misclassified as STOPPED and ProcessState.TRACED was unreachable.
2. NetworkCollector dropped any /proc/net row whose queue field was '-'
   (e.g. TIME_WAIT sockets), under-reporting sockets.
3. SELinux context was never read (only AppArmor/smack/attr/current were
   inspected, and AppArmor names containing ':' were wrongly stored as the
   SELinux context).
4. Ancestry leaf names for missing parents were double-quoted (b'name')
   because the raw bytes were passed through str() without decoding.
5. collect_process() sampled time.time() per PID, so start_time_epoch/age
   could drift during a parallel scan and make --since inconsistent.
"""

import os
import tempfile
import unittest

from pinspect.collector.network import NetworkCollector
from pinspect.collector.process import ProcessCollector
from pinspect.collector.procfs import ProcFS
from pinspect.collector.security import SecurityCollector
from pinspect.model.process import ProcessState


class TestProcessStateFromChar(unittest.TestCase):
    def test_traced_is_not_stopped(self):
        # Lowercase 't' is ptrace-stop; must NOT collapse into 'T' (stopped).
        self.assertEqual(ProcessState.from_char("t"), ProcessState.TRACED)
        self.assertEqual(ProcessState.from_char("T"), ProcessState.STOPPED)

    def test_case_sensitive_states(self):
        self.assertEqual(ProcessState.from_char("I"), ProcessState.IDLE)
        self.assertEqual(ProcessState.from_char("R"), ProcessState.RUNNING)
        self.assertEqual(ProcessState.from_char("S"), ProcessState.SLEEPING)
        self.assertEqual(ProcessState.from_char("D"), ProcessState.DISK_SLEEP)
        self.assertEqual(ProcessState.from_char("Z"), ProcessState.ZOMBIE)

    def test_unknown(self):
        self.assertEqual(ProcessState.from_char(""), ProcessState.UNKNOWN)
        self.assertEqual(ProcessState.from_char("?"), ProcessState.UNKNOWN)
        self.assertEqual(ProcessState.from_char("Q"), ProcessState.UNKNOWN)


class TestNetworkQueuePlaceholder(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.proc_root = self.temp_dir.name
        self.procfs = ProcFS(self.proc_root)
        self.collector = NetworkCollector(self.procfs)
        os.makedirs(os.path.join(self.proc_root, "net"), exist_ok=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_time_wait_with_dash_queue_is_parsed(self):
        # A TIME_WAIT socket emits the queue field as '-' (e.g. '-:00').
        tcp_content = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345\n"
            "   1: 0100007F:1F90 00000000:0000 06 -:00 00:- 00000000   0        0 67890\n"
        )
        with open(os.path.join(self.proc_root, "net", "tcp"), "w") as f:
            f.write(tcp_content)

        sockets = self.collector.collect_all_sockets()
        # Both rows must be parsed, including the TIME_WAIT one with '-'.
        self.assertEqual(len(sockets), 2)


class TestSecuritySelinuxContext(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.proc_root = self.temp_dir.name
        self.procfs = ProcFS(self.proc_root)
        self.collector = SecurityCollector(self.procfs)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _make_proc(self, pid, status_extra="", attr_current=None, selinux=None):
        pdir = os.path.join(self.proc_root, str(pid))
        os.makedirs(pdir, exist_ok=True)
        os.makedirs(os.path.join(pdir, "attr"), exist_ok=True)
        os.makedirs(os.path.join(pdir, "ns"), exist_ok=True)
        status = (
            "Name:\ttestproc\nNoNewPrivs:\t0\nSeccomp:\t0\n"
            "CapInh:\t0000000000000000\nCapEff:\t0000000000000000\n"
            + status_extra
        )
        with open(os.path.join(pdir, "status"), "w") as f:
            f.write(status)
        if attr_current is not None:
            with open(os.path.join(pdir, "attr", "current"), "w") as f:
                f.write(attr_current)
        if selinux is not None:
            os.makedirs(os.path.join(pdir, "attr", "selinux"), exist_ok=True)
            with open(os.path.join(pdir, "attr", "selinux", "current"), "w") as f:
                f.write(selinux)

    def test_selinux_context_is_read(self):
        ctx = "system_u:system_r:httpd_t:s0\n"
        self._make_proc(1, selinux=ctx)
        sec = self.collector.collect(1)
        self.assertEqual(sec.selinux_context, ctx.strip())
        self.assertIsNone(sec.apparmor_profile)

    def test_apparmor_profileWithoutColon(self):
        self._make_proc(2, attr_current="docker-default (enforce)\n")
        sec = self.collector.collect(2)
        self.assertEqual(sec.apparmor_profile, "docker-default (enforce)")
        self.assertIsNone(sec.selinux_context)

    def test_unconfined_is_ignored(self):
        self._make_proc(3, attr_current="unconfined\n")
        sec = self.collector.collect(3)
        self.assertIsNone(sec.apparmor_profile)
        self.assertIsNone(sec.selinux_context)

    def test_apparmor_withColon_isNotMislabeledAsSelinux(self):
        # An AppArmor label containing ':' must remain an AppArmor profile;
        # only the dedicated selinux attr should populate selinux_context.
        self._make_proc(4, attr_current="foo:bar (enforce)\n", selinux="system_u:object_r:default_t:s0\n")
        sec = self.collector.collect(4)
        self.assertEqual(sec.apparmor_profile, "foo:bar (enforce)")
        self.assertEqual(sec.selinux_context, "system_u:object_r:default_t:s0")


class TestAncestryMissingParentDecode(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.proc_root = self.proc_root = self.temp_dir.name
        self.procfs = ProcFS(self.proc_root)
        self.collector = ProcessCollector(self.procfs)
        with open(os.path.join(self.proc_root, "uptime"), "w") as f:
            f.write("1000.00 800.00\n")
        with open(os.path.join(self.proc_root, "meminfo"), "w") as f:
            f.write("MemTotal:        16384000 kB\n")

    def tearDown(self):
        self.temp_dir.cleanup()

    def _make_proc(self, pid, ppid, comm, state="S", starttime=1000):
        pdir = os.path.join(self.proc_root, str(pid))
        os.makedirs(pdir, exist_ok=True)
        stat = (
            f"{pid} ({comm}) {state} {ppid} {pid} {pid} 0 -1 4194304 100 0 0 0 "
            f"100 50 0 0 20 0 1 0 {starttime} 50000000 1000 "
            f"18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n"
        )
        with open(os.path.join(pdir, "stat"), "w") as f:
            f.write(stat)
        with open(os.path.join(pdir, "status"), "w") as f:
            f.write(
                f"Name:\t{comm}\nState:\t{state}\nPid:\t{pid}\nPPid:\t{ppid}\n"
                f"Uid:\t1000 1000 1000 1000\nGid:\t1000 1000 1000 1000\n"
                f"Threads:\t1\nNoNewPrivs:\t0\nSeccomp:\t0\nCpus_allowed_list:\t0-3\n"
            )
        with open(os.path.join(pdir, "comm"), "w") as f:
            f.write(f"{comm}\n")

    def test_missing_parent_name_is_decoded(self):
        # Target whose parent (999) no longer exists: the ancestry leaf for
        # the missing parent must be the decoded comm, not b'comm'.
        self._make_proc(100, ppid=999, comm="worker")
        parent_dir = os.path.join(self.proc_root, "999")
        os.makedirs(parent_dir, exist_ok=True)
        with open(os.path.join(parent_dir, "comm"), "w") as f:
            f.write("sshd\n")

        pinfo = self.collector.collect_process_with_ancestry(100, deep=False)
        self.assertIsNotNone(pinfo)
        self.assertTrue(pinfo.ancestry)
        self.assertEqual(pinfo.ancestry[0].name, "sshd")
        self.assertNotIn("b'", pinfo.ancestry[0].name)


class TestStartTimeSampling(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.proc_root = self.temp_dir.name
        self.procfs = ProcFS(self.proc_root)
        self.collector = ProcessCollector(self.procfs)
        with open(os.path.join(self.proc_root, "uptime"), "w") as f:
            f.write("1000.00 800.00\n")
        with open(os.path.join(self.proc_root, "meminfo"), "w") as f:
            f.write("MemTotal:        16384000 kB\n")

    def tearDown(self):
        self.temp_dir.cleanup()

    def _make_proc(self, pid, starttime=1000, state="S", comm="proc"):
        pdir = os.path.join(self.proc_root, str(pid))
        os.makedirs(pdir, exist_ok=True)
        stat = (
            f"{pid} ({comm}) {state} 1 {pid} {pid} 0 -1 4194304 100 0 0 0 "
            f"100 50 0 0 20 0 1 0 {starttime} 50000000 1000 "
            f"18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n"
        )
        with open(os.path.join(pdir, "stat"), "w") as f:
            f.write(stat)
        with open(os.path.join(pdir, "status"), "w") as f:
            f.write(
                f"Name:\t{comm}\nState:\t{state}\nPid:\t{pid}\nPPid:\t1\n"
                f"Uid:\t1000 1000 1000 1000\nGid:\t1000 1000 1000 1000\n"
                f"Threads:\t1\nNoNewPrivs:\t0\nSeccomp:\t0\nCpus_allowed_list:\t0-3\n"
            )
        with open(os.path.join(pdir, "comm"), "w") as f:
            f.write(f"{comm}\n")

    def test_explicit_now_is_honored(self):
        # Passing a fixed `now` must produce a deterministic start_time_epoch
        # (now - uptime + starttime/clk_tck) regardless of wall clock.
        from pinspect.utils.system import get_clock_ticks, get_uptime

        self._make_proc(100, starttime=1000)
        now = 2000.0
        p = self.collector.collect_process(100, deep=False, now=now)
        self.assertIsNotNone(p)

        clk_tck = get_clock_ticks()
        uptime = get_uptime(self.proc_root)
        expected = (now - uptime) + (1000 / clk_tck)
        self.assertAlmostEqual(p.start_time_epoch, expected, places=3)
        # age must be positive and consistent with the same sample
        self.assertAlmostEqual(p.age_seconds, uptime - (1000 / clk_tck), places=3)


if __name__ == "__main__":
    unittest.main()
