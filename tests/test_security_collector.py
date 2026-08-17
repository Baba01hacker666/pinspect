"""
Unit tests for SecurityCollector (capabilities, seccomp, NoNewPrivs, observations).
"""

import os
import tempfile
import unittest
from pinspect.collector.procfs import ProcFS
from pinspect.collector.security import (
    SecurityCollector,
    decode_capability_mask,
)
from pinspect.model.security import SeccompMode


class TestSecurityCollector(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.proc_root = self.temp_dir.name
        self.procfs = ProcFS(self.proc_root)
        self.collector = SecurityCollector(self.procfs)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_decode_capability_mask(self):
        # 0x0000000000000000 -> empty
        self.assertEqual(decode_capability_mask("0000000000000000"), set())

        # Bit 21 = CAP_SYS_ADMIN (1 << 21 = 0x200000)
        caps = decode_capability_mask("0000000000200000")
        self.assertIn("CAP_SYS_ADMIN", caps)

        # Bit 10 = CAP_NET_BIND_SERVICE (1 << 10 = 0x400)
        caps_net = decode_capability_mask("0000000000000400")
        self.assertIn("CAP_NET_BIND_SERVICE", caps_net)

    def test_collect_security_profile(self):
        pid = 42
        pdir = os.path.join(self.proc_root, str(pid))
        os.makedirs(pdir, exist_ok=True)
        os.makedirs(os.path.join(pdir, "attr"), exist_ok=True)
        os.makedirs(os.path.join(pdir, "ns"), exist_ok=True)

        status_content = (
            "Name:\tcustom-agent\n"
            "NoNewPrivs:\t1\n"
            "Seccomp:\t2\n"
            "CapInh:\t0000000000000000\n"
            "CapPrm:\t0000000000200000\n"
            "CapEff:\t0000000000200000\n"
            "CapBnd:\t000001ffffffffff\n"
            "CapAmb:\t0000000000000000\n"
        )
        with open(os.path.join(pdir, "status"), "w") as f:
            f.write(status_content)

        with open(os.path.join(pdir, "attr", "current"), "w") as f:
            f.write("docker-default (enforce)\n")

        sec = self.collector.collect(pid)
        self.assertTrue(sec.no_new_privs)
        self.assertEqual(sec.seccomp_mode, SeccompMode.FILTER)
        self.assertIn("CAP_SYS_ADMIN", sec.capabilities.effective)
        self.assertEqual(sec.apparmor_profile, "docker-default (enforce)")

        # Verify security observations
        obs_categories = [obs.category for obs in sec.observations]
        self.assertIn("PRIVILEGE", obs_categories)
        self.assertIn("CAPABILITY", obs_categories)
        self.assertIn("SANDBOX", obs_categories)

    def test_deleted_executable_observation(self):
        pid = 99
        pdir = os.path.join(self.proc_root, str(pid))
        os.makedirs(pdir, exist_ok=True)

        # Mock /proc/99/exe symlink pointing to deleted file
        os.symlink("/opt/my-app/worker (deleted)", os.path.join(pdir, "exe"))
        with open(os.path.join(pdir, "status"), "w") as f:
            f.write("Name:\tworker\nNoNewPrivs:\t0\nSeccomp:\t0\n")

        sec = self.collector.collect(pid)
        self.assertTrue(sec.exe_is_deleted)
        self.assertEqual(sec.exe_real_path, "/opt/my-app/worker")

        obs_titles = [obs.title for obs in sec.observations]
        self.assertIn("Deleted Executable on Disk", obs_titles)


if __name__ == "__main__":
    unittest.main()
