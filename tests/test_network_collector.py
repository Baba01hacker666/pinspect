"""
Unit tests for NetworkCollector parsing /proc/net files.
"""

import os
import tempfile
import unittest

from pinspect.collector.network import (
    NetworkCollector,
    parse_ipv4_hex,
    parse_port_hex,
)
from pinspect.collector.procfs import ProcFS
from pinspect.model.network import SocketProtocol, SocketState


class TestNetworkCollector(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.proc_root = self.temp_dir.name
        self.procfs = ProcFS(self.proc_root)
        self.collector = NetworkCollector(self.procfs)

        net_dir = os.path.join(self.proc_root, "net")
        os.makedirs(net_dir, exist_ok=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_parse_helpers(self):
        # 127.0.0.1 in little-endian hex is 0100007F
        self.assertEqual(parse_ipv4_hex("0100007F"), "127.0.0.1")
        # 0.0.0.0 is 00000000
        self.assertEqual(parse_ipv4_hex("00000000"), "0.0.0.0")
        # Port 80 is 0050 in hex
        self.assertEqual(parse_port_hex("0050"), 80)
        # Port 8080 is 1F90 in hex
        self.assertEqual(parse_port_hex("1F90"), 8080)

    def test_collect_tcp_sockets(self):
        # Write mock /proc/net/tcp
        tcp_content = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"
            "   1: 0100007F:1F90 0100007F:C000 01 00000000:00000000 00:00000000 00000000  1000        0 67890 1 0000000000000000 100 0 0 10 0\n"
        )
        with open(os.path.join(self.proc_root, "net", "tcp"), "w") as f:
            f.write(tcp_content)

        # Create mock process owning socket 12345
        pdir = os.path.join(self.proc_root, "100", "fd")
        os.makedirs(pdir, exist_ok=True)
        os.symlink("socket:[12345]", os.path.join(pdir, "3"))
        with open(os.path.join(self.proc_root, "100", "comm"), "w") as f:
            f.write("nginx\n")

        sockets = self.collector.collect_all_sockets()
        self.assertEqual(len(sockets), 2)

        # Socket 0: Listening on 0.0.0.0:80
        s0 = sockets[0]
        self.assertEqual(s0.protocol, SocketProtocol.TCP)
        self.assertEqual(s0.local_address, "0.0.0.0")
        self.assertEqual(s0.local_port, 80)
        self.assertEqual(s0.state, SocketState.LISTEN)
        self.assertEqual(s0.inode, 12345)
        self.assertEqual(s0.pid, 100)
        self.assertEqual(s0.fd, 3)
        self.assertEqual(s0.process_name, "nginx")

        # Socket 1: Established 127.0.0.1:8080 -> 127.0.0.1:49152
        s1 = sockets[1]
        self.assertEqual(s1.local_address, "127.0.0.1")
        self.assertEqual(s1.local_port, 8080)
        self.assertEqual(s1.state, SocketState.ESTABLISHED)
        self.assertEqual(s1.inode, 67890)

    def test_filter_by_port(self):
        tcp_content = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345\n"
            "   1: 0100007F:1F90 0100007F:C000 01 00000000:00000000 00:00000000 00000000  1000        0 67890\n"
        )
        with open(os.path.join(self.proc_root, "net", "tcp"), "w") as f:
            f.write(tcp_content)

        filtered = self.collector.collect_all_sockets(port_filter=8080)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].local_port, 8080)


if __name__ == "__main__":
    unittest.main()
