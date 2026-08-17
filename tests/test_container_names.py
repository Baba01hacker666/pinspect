"""
Unit tests for container name/detail resolution from Docker/Podman API responses.
"""

import unittest

from pinspect.collector.container_names import (
    ContainerNameResolver,
    http_get_unix,
    parse_container_details,
)

SAMPLE_CONTAINER_JSON = {
    "Id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "Name": "/my-app",
    "Config": {"Image": "nginx:latest"},
    "NetworkSettings": {
        "Networks": {
            "bridge": {"IPAddress": "172.17.0.2"},
        }
    },
    "Mounts": [
        {"Source": "/host/data", "Destination": "/app/data"},
    ],
}


class TestContainerDetailsParsing(unittest.TestCase):
    def test_parse_details(self):
        details = parse_container_details("0123456789ab", SAMPLE_CONTAINER_JSON)
        self.assertIsNotNone(details)
        self.assertEqual(details.name, "my-app")
        self.assertEqual(details.image, "nginx:latest")
        self.assertEqual(details.networks, ["172.17.0.2"])
        self.assertEqual(details.mounts, ["/host/data:/app/data"])

    def test_parse_details_none(self):
        self.assertIsNone(parse_container_details("abc", None))
        self.assertIsNone(parse_container_details("abc", {}))

    def test_parse_details_missing_optional_fields(self):
        details = parse_container_details("abc", {"Config": {"Image": "x"}})
        self.assertIsNotNone(details)
        self.assertIsNone(details.name)
        self.assertEqual(details.image, "x")
        self.assertEqual(details.networks, [])
        self.assertEqual(details.mounts, [])

    def test_http_get_unix_missing_socket(self):
        # Connecting to a nonexistent socket must fail gracefully and quickly
        self.assertIsNone(http_get_unix("/nonexistent/socket.sock", "/containers/x/json"))

    def test_resolver_no_runtime_socket(self):
        resolver = ContainerNameResolver()
        if resolver._discover_sockets():
            self.skipTest("a container runtime socket is present on this host")
        self.assertIsNone(resolver.resolve("0123456789ab"))


if __name__ == "__main__":
    unittest.main()
