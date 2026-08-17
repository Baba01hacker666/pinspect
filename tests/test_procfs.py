"""
Unit tests for safe low-level ProcFS accessor.
"""

import os
import tempfile
import unittest
from pinspect.collector.procfs import ProcFS


class TestProcFS(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.proc_root = self.temp_dir.name
        self.procfs = ProcFS(self.proc_root)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_list_pids(self):
        # Create PID directories and non-PID files
        os.makedirs(os.path.join(self.proc_root, "1"))
        os.makedirs(os.path.join(self.proc_root, "100"))
        os.makedirs(os.path.join(self.proc_root, "42"))
        os.makedirs(os.path.join(self.proc_root, "net"))
        with open(os.path.join(self.proc_root, "uptime"), "w") as f:
            f.write("12345.67 8910.11\n")

        pids = self.procfs.list_pids()
        self.assertEqual(pids, [1, 42, 100])

    def test_read_file_and_lines(self):
        os.makedirs(os.path.join(self.proc_root, "42"))
        comm_path = os.path.join(self.proc_root, "42", "comm")
        with open(comm_path, "w") as f:
            f.write("my-service\n")

        content = self.procfs.read_file(42, "comm")
        self.assertEqual(content, "my-service\n")

        lines = self.procfs.read_lines(42, "comm")
        self.assertEqual(lines, ["my-service"])

    def test_read_missing_or_inaccessible_file(self):
        # Should gracefully return None / [] without raising exceptions
        self.assertIsNone(self.procfs.read_file(99999, "status"))
        self.assertEqual(self.procfs.read_lines(99999, "status"), [])
        self.assertIsNone(self.procfs.read_symlink(99999, "exe"))
        self.assertEqual(self.procfs.list_dir(99999, "fd"), [])

    def test_read_symlink(self):
        os.makedirs(os.path.join(self.proc_root, "42"))
        link_path = os.path.join(self.proc_root, "42", "cwd")
        os.symlink("/var/log", link_path)

        target = self.procfs.read_symlink(42, "cwd")
        self.assertEqual(target, "/var/log")


if __name__ == "__main__":
    unittest.main()
