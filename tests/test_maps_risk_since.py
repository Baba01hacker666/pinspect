"""
Tests for memory maps inspector, risk scoring, duration parsing, and ps --since.
"""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from typing import Optional

from pinspect.cli.main import main
from pinspect.collector.maps import MapsCollector, is_suspicious_path
from pinspect.collector.procfs import ProcFS
from pinspect.utils.formatting import parse_duration


def _make_maps_lines() -> str:
    return "\n".join(
        [
            # start-end perms offset dev inode path
            "00400000-00452000 r--p 00000000 08:01 1000                       /usr/bin/nginx",
            "00452000-00453000 r-xp 00052000 08:01 1000                       /usr/bin/nginx",
            "7f1000000000-7f1000010000 rw-p 00000000 00:00 0                  [anon:libc_alloc]",
            # RWX region (injection evidence)
            "7f2000000000-7f2000001000 rwxp 00000000 00:00 0 ",
            # Anonymous executable region (no path)
            "7f3000000000-7f3000002000 r-xp 00000000 00:00 0 ",
            # memfd fileless payload
            "7f4000000000-7f4000003000 rwxp 00000000 00:00 0                  /memfd:payload (deleted)",
            # Deleted backing file still mapped
            "7f5000000000-7f5000004000 r--p 00000000 08:01 2000               /tmp/evil.so (deleted)",
            # stack
            "7ffe00000000-7ffe00200000 rw-p 00000000 00:00 0                  [stack]",
            "",
        ]
    )


class MockProcBase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.proc_root = self.temp_dir.name
        self._write_uptime_meminfo()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _write_uptime_meminfo(self, uptime: float = 2000.0):
        with open(os.path.join(self.proc_root, "uptime"), "w") as f:
            f.write(f"{uptime} {uptime * 0.75}\n")
        with open(os.path.join(self.proc_root, "meminfo"), "w") as f:
            f.write("MemTotal:        16384000 kB\n")

    def make_proc(
        self,
        pid: int,
        ppid: int = 1,
        comm: str = "proc",
        cmdline: bytes = b"proc\x00",
        cgroup: str = "",
        exe_target: str = "/usr/bin/proc",
        starttime_ticks: int = 100,
        stat_extra_state: str = "S",
        maps: Optional[str] = None,
    ):
        pdir = os.path.join(self.proc_root, str(pid))
        os.makedirs(pdir, exist_ok=True)
        stat_line = (
            f"{pid} ({comm}) {stat_extra_state} {ppid} {pid} {pid} 0 -1 0 0 0 0 0 "
            f"10 5 0 0 20 0 1 0 {starttime_ticks} 10000 100 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
        )
        with open(os.path.join(pdir, "stat"), "w") as f:
            f.write(stat_line)
        with open(os.path.join(pdir, "status"), "w") as f:
            f.write(f"Name:\t{comm}\nPPid:\t{ppid}\nUid:\t0 0 0 0\nGid:\t0 0 0 0\nNoNewPrivs:\t0\nSeccomp:\t0\n")
        with open(os.path.join(pdir, "comm"), "w") as f:
            f.write(f"{comm}\n")
        with open(os.path.join(pdir, "cmdline"), "wb") as f:
            f.write(cmdline)
        with open(os.path.join(pdir, "cgroup"), "w") as f:
            f.write(cgroup)
        fd_dir = os.path.join(pdir, "fd")
        os.makedirs(fd_dir, exist_ok=True)
        if exe_target:
            os.symlink(exe_target, os.path.join(fd_dir, "..", "exe"))
        if maps is not None:
            with open(os.path.join(pdir, "maps"), "w") as f:
                f.write(maps)


class TestParseDuration(unittest.TestCase):
    def test_valid_units(self):
        self.assertEqual(parse_duration("30s"), 30.0)
        self.assertEqual(parse_duration("10m"), 600.0)
        self.assertEqual(parse_duration("2h"), 7200.0)
        self.assertEqual(parse_duration("1d"), 86400.0)
        self.assertEqual(parse_duration("1w"), 604800.0)
        self.assertEqual(parse_duration("90"), 90.0)  # bare number = seconds
        self.assertEqual(parse_duration("1.5h"), 5400.0)
        self.assertEqual(parse_duration(" 10M ".lower()), 600.0)

    def test_invalid(self):
        for bad in ["", "abc", "10x", "-5m", "h"]:
            with self.assertRaises(ValueError):
                parse_duration(bad)


class TestSuspiciousPath(unittest.TestCase):
    def test_prefixes(self):
        self.assertTrue(is_suspicious_path("/tmp/evil"))
        self.assertTrue(is_suspicious_path("/var/tmp/x"))
        self.assertTrue(is_suspicious_path("/dev/shm/payload"))
        self.assertFalse(is_suspicious_path("/usr/bin/nginx"))
        self.assertFalse(is_suspicious_path("/tmpfoo"))  # prefix must include slash


class TestMapsCollector(MockProcBase):
    def test_parse_and_flags(self):
        self.make_proc(700, comm="victim", maps=_make_maps_lines())
        report = MapsCollector(ProcFS(self.proc_root)).collect(700)

        self.assertEqual(report.total_regions, 8)
        self.assertEqual(report.total_mapped_bytes, sum(r.size_bytes for r in report.regions))
        self.assertEqual(report.rwx_region_count, 2)  # bare RWX + memfd RWX
        self.assertEqual(report.anonymous_exec_count, 2)  # bare RWX (no path) + bare r-x
        self.assertIn("/memfd:payload (deleted)", report.memfd_paths)
        self.assertEqual(len(report.deleted_paths), 2)
        self.assertTrue(report.has_suspicious_mappings)

        # Address math
        first = report.regions[0]
        self.assertEqual(first.start_addr_int, 0x400000)
        self.assertEqual(first.size_bytes, 0x452000 - 0x400000)
        self.assertFalse(first.is_anonymous)

    def test_unreadable_maps_returns_empty_report(self):
        self.make_proc(701, comm="plain")
        report = MapsCollector(ProcFS(self.proc_root)).collect(701)
        self.assertEqual(report.total_regions, 0)
        self.assertFalse(report.has_suspicious_mappings)

    def test_missing_pid(self):
        report = MapsCollector(ProcFS(self.proc_root)).collect(99999)
        self.assertEqual(report.total_regions, 0)


class TestMapsCommand(MockProcBase):
    def run_cli(self, args):
        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["--proc-root", self.proc_root, *args])
        return rc, f.getvalue()

    def test_maps_json(self):
        self.make_proc(710, comm="victim", maps=_make_maps_lines())
        rc, out = self.run_cli(["maps", "710", "--json"])
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertEqual(data["pid"], 710)
        self.assertEqual(data["rwx_region_count"], 2)
        self.assertEqual(data["anonymous_exec_count"], 2)
        self.assertEqual(data["total_regions"], 8)
        self.assertTrue(any("memfd" in p for p in data["memfd_paths"]))

    def test_maps_quiet(self):
        self.make_proc(711, comm="victim", maps=_make_maps_lines())
        rc, out = self.run_cli(["maps", "711", "--quiet"])
        self.assertEqual(rc, 0)
        lines = [ln for ln in out.strip().splitlines() if ln]
        self.assertEqual(len(lines), 8)
        self.assertIn("rwxp", lines[3])

    def test_maps_missing_pid(self):
        rc, _out = self.run_cli(["maps", "99999"])
        self.assertEqual(rc, 1)


class TestPsSinceFilter(MockProcBase):
    def test_since_filters_by_start_age(self):
        # uptime = 2000s; clk_tck assumed 100 by mocks
        # Old process: started at tick 100 -> ~1999s ago (outside any small window)
        self.make_proc(800, comm="oldproc", starttime_ticks=100)
        # Fresh process: started at tick 199500 -> 1995s after boot -> 5s ago
        self.make_proc(801, comm="newproc", starttime_ticks=199500)

        # Everything older than 1 hour: both visible
        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["--proc-root", self.proc_root, "ps", "--since", "1h", "--quiet"])
        self.assertEqual(rc, 0)
        self.assertEqual(set(f.getvalue().split()), {"800", "801"})

        # Only last 10 minutes: only the fresh one
        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["--proc-root", self.proc_root, "ps", "--since", "10m", "--quiet"])
        self.assertEqual(rc, 0)
        self.assertEqual(set(f.getvalue().split()), {"801"})

        # Last 30 seconds: the 5s-old process still shows, the ~1999s-old one doesn't
        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["--proc-root", self.proc_root, "ps", "--since", "30s", "--quiet"])
        self.assertEqual(rc, 0)
        self.assertEqual(set(f.getvalue().split()), {"801"})

    def test_invalid_duration_rejected_by_argparse(self):
        err = io.StringIO()
        try:
            from contextlib import redirect_stderr

            with redirect_stderr(err), redirect_stdout(io.StringIO()):
                rc = main(["--proc-root", self.proc_root, "ps", "--since", "nonsense"])
        except SystemExit as e:
            self.assertEqual(e.code, 2)  # argparse usage error
        else:
            self.assertNotEqual(rc, 0)


class TestRiskScoring(MockProcBase):
    def run_cli(self, args):
        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["--proc-root", self.proc_root, *args])
        return rc, f.getvalue()

    def test_clean_process_low_risk(self):
        clean_maps = "\n".join(
            [
                "00400000-00452000 r--p 00000000 08:01 1000                       /usr/bin/nginx",
                "00452000-00453000 r-xp 00052000 08:01 1000                       /usr/bin/nginx",
                "7ffe00000000-7ffe00200000 rw-p 00000000 00:00 0                  [stack]",
                "",
            ]
        )
        # Containerized so the (legitimate) unsandboxed-root flag doesn't fire
        container_cgroup = "0::/docker/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
        self.make_proc(900, comm="nginx", exe_target="/usr/bin/nginx", maps=clean_maps, cgroup=container_cgroup)
        rc, out = self.run_cli(["security", "900", "--json"])
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertIsNotNone(data.get("risk"))
        codes = {fl["code"] for fl in data["risk"]["flags"]}
        self.assertEqual(codes, set())
        self.assertEqual(data["risk"]["level"], "LOW")
        self.assertLess(data["risk"]["score"], 20)

    def test_deleted_tmp_binary_scores_critical(self):
        self.make_proc(
            901,
            comm="malware",
            cmdline=b"/tmp/.hidden/pwn\x00-i\x00",
            exe_target="/tmp/.hidden/pwn (deleted)",
            maps="7f5000000000-7f5000004000 rwxp 00000000 00:00 0                  /memfd:x (deleted)\n",
        )
        rc, out = self.run_cli(["show", "901", "--json"])
        self.assertEqual(rc, 0)
        data = json.loads(out)
        risk = data["risk"]
        codes = {fl["code"] for fl in risk["flags"]}
        self.assertIn("DELETED_EXE", codes)
        self.assertIn("TMP_EXEC", codes)
        self.assertIn("MEMFD_MAPS", codes)
        self.assertIn("RWX_REGIONS", codes)
        self.assertGreaterEqual(risk["score"], 70)
        self.assertEqual(risk["level"], "CRITICAL")

        # security view embeds the same assessment additively
        rc, out = self.run_cli(["security", "901", "--json"])
        self.assertEqual(rc, 0)
        sec_data = json.loads(out)
        self.assertEqual(sec_data["risk"]["level"], "CRITICAL")

    def test_kernel_threads_not_scored(self):
        self.make_proc(2, comm="kthreadd", cmdline=b"", exe_target="")
        rc, out = self.run_cli(["show", "2", "--json"])
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertEqual(data["risk"]["score"], 0)
        self.assertEqual(data["risk"]["level"], "LOW")


if __name__ == "__main__":
    unittest.main()
