"""
Container name and detail resolution via container runtime API sockets.

Docker and Podman expose a Docker-compatible REST API over a unix domain
socket. This module performs minimal HTTP GETs over those sockets (stdlib
only) to resolve container IDs to names, images, network addresses, and
volume mounts. All failures degrade gracefully to None/empty so the rest of
pinspect keeps working without any runtime access.
"""

import json
import os
import socket
from dataclasses import dataclass, field
from typing import Dict, List, Optional

DOCKER_SOCKET = "/var/run/docker.sock"
PODMAN_SOCKET_CANDIDATES = (
    "/run/podman/podman.sock",
    "/run/user/0/podman/podman.sock",
)
SOCKET_TIMEOUT = 1.5


@dataclass
class ContainerDetails:
    """Metadata about a container resolved from the runtime API."""

    container_id: str
    name: Optional[str] = None
    image: Optional[str] = None
    networks: List[str] = field(default_factory=list)
    mounts: List[str] = field(default_factory=list)


def _podman_socket_candidates() -> List[str]:
    candidates = list(PODMAN_SOCKET_CANDIDATES)
    xdg_runtime = os.environ.get("XDG_RUNTIME_DIR")
    if xdg_runtime:
        candidates.append(os.path.join(xdg_runtime, "podman", "podman.sock"))
    return candidates


def http_get_unix(sock_path: str, path: str, timeout: float = SOCKET_TIMEOUT) -> Optional[dict]:
    """Perform a minimal HTTP GET over a unix domain socket, returning parsed JSON or None."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(sock_path)
            request = f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            sock.sendall(request.encode("utf-8"))

            data = b""
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk

        header, _, body = data.partition(b"\r\n\r\n")
        status = header.split(b" ", 2)[1] if header.count(b" ") >= 2 else b""
        if status != b"200" or not body:
            return None
        return json.loads(body.decode("utf-8", "replace"))
    except (OSError, ValueError):
        return None


def parse_container_details(container_id: str, data: Optional[dict]) -> Optional[ContainerDetails]:
    """Parse a Docker/Podman `containers/{id}/json` response into ContainerDetails."""
    if not data:
        return None

    name = str(data.get("Name") or "").lstrip("/") or None

    config = data.get("Config")
    image = None
    if isinstance(config, dict):
        image = config.get("Image") or None

    mounts: List[str] = []
    for mount in data.get("Mounts") or []:
        if isinstance(mount, dict):
            src = mount.get("Source") or "?"
            dst = mount.get("Destination") or "?"
            mounts.append(f"{src}:{dst}")

    networks: List[str] = []
    net_settings = data.get("NetworkSettings")
    if isinstance(net_settings, dict):
        for _, nw in (net_settings.get("Networks") or {}).items():
            if isinstance(nw, dict) and nw.get("IPAddress"):
                networks.append(nw["IPAddress"])

    return ContainerDetails(
        container_id=container_id,
        name=name,
        image=image,
        networks=networks,
        mounts=mounts,
    )


class ContainerNameResolver:
    """Resolve container IDs to details via Docker/Podman API sockets, with caching."""

    def __init__(self) -> None:
        self._cache: Dict[str, Optional[ContainerDetails]] = {}
        self._sockets: Optional[List[str]] = None

    def _discover_sockets(self) -> List[str]:
        if self._sockets is not None:
            return self._sockets
        sockets: List[str] = []
        if os.path.exists(DOCKER_SOCKET):
            sockets.append(DOCKER_SOCKET)
        for candidate in _podman_socket_candidates():
            if os.path.exists(candidate) and candidate not in sockets:
                sockets.append(candidate)
        self._sockets = sockets
        return sockets

    def resolve(self, container_id: str) -> Optional[ContainerDetails]:
        """Resolve a container ID to details, trying each available runtime socket."""
        if container_id in self._cache:
            return self._cache[container_id]

        details: Optional[ContainerDetails] = None
        for sock_path in self._discover_sockets():
            details = parse_container_details(container_id, http_get_unix(sock_path, f"/containers/{container_id}/json"))
            if details:
                break

        self._cache[container_id] = details
        return details
