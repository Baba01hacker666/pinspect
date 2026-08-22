"""
Integration tests for CLI subcommands (ps, show, tree, files, network, env, ancestry, children, namespaces, security).
"""

import io
import json
import os
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

    def test_grep_by_name(self):
        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["--proc-root", self.proc_root, "grep", "nginx", "--quiet"])
        self.assertEqual(rc, 0)
        self.assertEqual(f.getvalue().strip(), "100")

    def test_grep_by_arguments(self):
        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["--proc-root", self.proc_root, "grep", "daemon off", "--quiet"])
        self.assertEqual(rc, 0)
        self.assertEqual(f.getvalue().strip(), "100")

    def test_grep_scope_flags(self):
        # 'daemon' only appears in nginx's arguments, not its name
        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["--proc-root", self.proc_root, "grep", "daemon", "--name", "--quiet"])
        # No match under the restricted scope: exit code 1
        self.assertEqual(rc, 1)
        self.assertEqual(f.getvalue().strip(), "")

    def test_grep_user_filter(self):
        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["--proc-root", self.proc_root, "grep", "nginx", "--user", "1000", "--quiet"])
        # No match: follow grep convention of exit code 1
        self.assertEqual(rc, 1)
        self.assertEqual(f.getvalue().strip(), "")

        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["--proc-root", self.proc_root, "grep", "nginx", "--user", "root", "--quiet"])
        self.assertEqual(rc, 0)
        self.assertEqual(f.getvalue().strip(), "100")

    def test_grep_no_match_exit_code(self):
        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["--proc-root", self.proc_root, "grep", "does-not-exist-xyz", "--quiet"])
        self.assertEqual(rc, 1)
        self.assertEqual(f.getvalue().strip(), "")

    def test_grep_json(self):
        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["--proc-root", self.proc_root, "grep", "nginx", "--json"])
        self.assertEqual(rc, 0)
        self.assertIn('"pid": 100', f.getvalue())

    def test_grep_invalid_pattern(self):
        rc = main(["--proc-root", self.proc_root, "grep", "["])
        self.assertEqual(rc, 1)

    def test_csv_not_supported_returns_error(self):
        # show --csv must fail cleanly instead of silently emitting JSON
        rc = main(["--proc-root", self.proc_root, "show", "100", "--csv"])
        self.assertEqual(rc, 1)

    def test_ps_survives_corrupt_proc_entry(self):
        # A malformed /proc/<pid>/stat for one PID must not abort the listing;
        # the remaining processes still appear (warning goes to stderr only).
        self._make_proc(300, 1, "victim", b"victim\x00")
        with open(os.path.join(self.proc_root, "300", "stat"), "w") as f:
            f.write("this is not a valid stat line")

        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["--proc-root", self.proc_root, "ps", "--quiet"])
        self.assertEqual(rc, 0)
        pids = set(f.getvalue().split())
        self.assertIn("100", pids)
        self.assertNotIn("300", pids)

    def test_docker_command(self):
        # PID 200 runs inside a Docker container; nginx (100) does not
        docker_cgroup = "0::/docker/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
        self._make_proc(200, 100, "myapp", b"myapp\x00--serve\x00", docker_cgroup)

        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["--proc-root", self.proc_root, "docker", "--json"])
        self.assertEqual(rc, 0)
        output = f.getvalue()
        self.assertIn('"pid": 200', output)
        self.assertIn('"container_runtime": "Docker"', output)
        self.assertIn('"container_id": "0123456789ab"', output)
        # Only the containerized process is listed (nginx PID 100 is not)
        data = json.loads(output)
        self.assertEqual([p["pid"] for p in data], [200])

    def test_docker_quiet_and_filters(self):
        docker_cgroup = "0::/docker/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
        self._make_proc(200, 100, "myapp", b"myapp\x00--serve\x00", docker_cgroup)

        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["--proc-root", self.proc_root, "docker", "--quiet"])
        self.assertEqual(rc, 0)
        self.assertEqual(f.getvalue().strip(), "200")

        # Prefix filter that does not match
        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["--proc-root", self.proc_root, "docker", "--id", "ffff", "--quiet"])
        self.assertEqual(rc, 0)
        self.assertEqual(f.getvalue().strip(), "")

        # Runtime filter
        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["--proc-root", self.proc_root, "docker", "--runtime", "docker", "--quiet"])
        self.assertEqual(rc, 0)
        self.assertEqual(f.getvalue().strip(), "200")

        # Full-length 64-char container ID must match the stored short id
        full_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["--proc-root", self.proc_root, "docker", "--id", full_id, "--quiet"])
        self.assertEqual(rc, 0)
        self.assertEqual(f.getvalue().strip(), "200")

    def test_docker_grouped_view(self):
        # Two processes in the same container; nginx (100) is a host process
        docker_cgroup = "0::/docker/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
        self._make_proc(200, 100, "myapp", b"myapp\x00--serve\x00", docker_cgroup)
        self._make_proc(201, 200, "helper", b"helper\x00-x\x00", docker_cgroup)

        f = io.StringIO()
        with redirect_stdout(f):
            rc = main(["--proc-root", self.proc_root, "docker"])
        self.assertEqual(rc, 0)
        output = f.getvalue()
        self.assertIn("Containerized Processes", output)
        self.assertIn("myapp --serve", output)
        self.assertIn("helper -x", output)
        # Host process must not appear in the container view
        self.assertNotIn("nginx -g", output)


if __name__ == "__main__":
    unittest.main()
