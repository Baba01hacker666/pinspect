"""
Integration tests for CLI subcommands (ps, show, tree, files, network, env, ancestry, children, namespaces, security).
"""

import os
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pinspect.cli.main import main


class TestCLICommands(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.proc_root = self.temp_dir.name

        with open(os.path.join(self.proc_root, "uptime"), "w") as f:
            f.write("2000.00 1500.00\n")
        with open(os.path.join(self.proc_root, "meminfo"), "w") as f:
            f.write("MemTotal:        16384000 kB\n")

        # Create Mock System:
        # PID 1: systemd
        self._make_proc(1, 0, "systemd", b"/lib/systemd/systemd\x00", "0::/init.scope\n")
        # PID 50: cron
        self._make_proc(50, 1, "cron", b"/usr/sbin/cron\x00-f\x00", "0::/system.slice/cron.service\n")
        # PID 100: nginx
        self._make_proc(100, 1, "nginx", b"nginx\x00-g\x00daemon off;\x00", "0::/system.slice/nginx.service\n", fds=[(0, "/dev/null"), (3, "socket:[55555]")])

        # Write mock /proc/net/tcp for port 80
        net_dir = os.path.join(self.proc_root, "net")
        os.makedirs(net_dir, exist_ok=True)
        tcp_content = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 55555 1 0000000000000000 100 0 0 10 0\n"
        )
        with open(os.path.join(net_dir, "tcp"), "w") as f:
            f.write(tcp_content)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _make_proc(self, pid: int, ppid: int, comm: str, cmdline: bytes, cgroup: str = "", fds=None):
        pdir = os.path.join(self.proc_root, str(pid))
        os.makedirs(pdir, exist_ok=True)
        stat_line = f"{pid} ({comm}) S {ppid} {pid} {pid} 0 -1 0 0 0 0 0 10 5 0 0 20 0 1 0 100 10000 100 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
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
        with open(os.path.join(pdir, "environ"), "wb") as f:
            f.write(b"USER=root\x00API_KEY=my-secret-key-1234\x00")

        os.makedirs(os.path.join(pdir, "fd"), exist_ok=True)
        os.makedirs(os.path.join(pdir, "ns"), exist_ok=True)

        if fds:
            for fd_num, target in fds:
                os.symlink(target, os.path.join(pdir, "fd", str(fd_num)))

    def test_ps_json(self):
        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["--proc-root", self.proc_root, "ps", "--json"])
        self.assertEqual(rc, 0)
        output = f.getvalue()
        self.assertIn('"pid": 100', output)
        self.assertIn('"name": "nginx"', output)
        self.assertIn('"service_name": "nginx.service"', output)

    def test_ps_filter_by_port(self):
        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["--proc-root", self.proc_root, "ps", "--port", "80", "--quiet"])
        self.assertEqual(rc, 0)
        output = f.getvalue().strip()
        self.assertEqual(output, "100")

    def test_show_command(self):
        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["--proc-root", self.proc_root, "show", "100", "--json"])
        self.assertEqual(rc, 0)
        output = f.getvalue()
        self.assertIn('"pid": 100', output)
        self.assertIn('"nginx.service"', output)

    def test_files_command(self):
        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["--proc-root", self.proc_root, "files", "100", "--json"])
        self.assertEqual(rc, 0)
        output = f.getvalue()
        self.assertIn('"fd": 3', output)
        self.assertIn('socket:[55555]', output)

    def test_network_command(self):
        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["--proc-root", self.proc_root, "network", "--json"])
        self.assertEqual(rc, 0)
        output = f.getvalue()
        self.assertIn('"local_port": 80', output)
        self.assertIn('"state": "LISTEN"', output)

    def test_env_redaction_command(self):
        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["--proc-root", self.proc_root, "env", "100", "--json"])
        self.assertEqual(rc, 0)
        output = f.getvalue()
        self.assertIn('"API_KEY": "***REDACTED***"', output)
        self.assertIn('"USER": "root"', output)

    def test_ancestry_command(self):
        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["--proc-root", self.proc_root, "ancestry", "100", "--quiet"])
        self.assertEqual(rc, 0)
        output = f.getvalue().strip()
        self.assertEqual(output, "1")

    def test_security_command(self):
        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["--proc-root", self.proc_root, "security", "100", "--json", "--no-hash"])
        self.assertEqual(rc, 0)
        output = f.getvalue()
        self.assertIn('"no_new_privs": false', output)
        self.assertIn('"seccomp_mode": 0', output)


if __name__ == "__main__":
    unittest.main()
