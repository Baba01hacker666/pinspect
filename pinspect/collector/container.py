"""
Container runtime, orchestrator (Docker, Podman, Kubernetes, LXC, CRI-O), and cgroup parser.
"""

import re
from typing import Any, Dict, Optional


class ContainerCollector:
    """Detects if a process is running inside or managed by a container runtime or Kubernetes."""

    # 64-character hexadecimal container IDs
    HEX_64_PATTERN = r"[0-9a-fA-F]{64}"
    UUID_PATTERN = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"

    @classmethod
    def inspect_cgroup(
        cls, cgroup_content: str, root_link: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Inspect cgroup and root mount to identify container environment.
        """
        result = {
            "is_container": False,
            "container_runtime": None,
            "container_id": None,
            "container_name": None,
            "kubernetes_pod_uid": None,
            "kubernetes_namespace": None,
            "kubernetes_container_name": None,
        }

        if not cgroup_content and not root_link:
            return result

        # Check for Kubernetes
        k8s_match = re.search(
            r"kubepods.*?(?:pod|pod_)(" + cls.UUID_PATTERN + r"|[0-9a-fA-F]{32}).*?(?:docker-|cri-containerd-|crio-)?([0-9a-fA-F]{64})",
            cgroup_content,
            re.IGNORECASE,
        )
        if k8s_match:
            result["is_container"] = True
            result["container_runtime"] = "Kubernetes"
            result["kubernetes_pod_uid"] = k8s_match.group(1)
            result["container_id"] = k8s_match.group(2)[:12]  # Short ID
            return result

        # Check for Docker
        docker_match = re.search(
            r"(?:docker/|docker-|docker\.slice/docker-)([0-9a-fA-F]{64})",
            cgroup_content,
            re.IGNORECASE,
        )
        if docker_match:
            result["is_container"] = True
            result["container_runtime"] = "Docker"
            result["container_id"] = docker_match.group(1)[:12]
            return result

        # Check for Podman / Libpod
        podman_match = re.search(
            r"(?:libpod-|libpod/)([0-9a-fA-F]{64})",
            cgroup_content,
            re.IGNORECASE,
        )
        if podman_match:
            result["is_container"] = True
            result["container_runtime"] = "Podman"
            result["container_id"] = podman_match.group(1)[:12]
            return result

        # Check for CRI-O
        crio_match = re.search(
            r"(?:crio-|crio/)([0-9a-fA-F]{64})",
            cgroup_content,
            re.IGNORECASE,
        )
        if crio_match:
            result["is_container"] = True
            result["container_runtime"] = "CRI-O"
            result["container_id"] = crio_match.group(1)[:12]
            return result

        # Check for Containerd
        containerd_match = re.search(
            r"(?:containerd/|cri-containerd-)([0-9a-fA-F]{64})",
            cgroup_content,
            re.IGNORECASE,
        )
        if containerd_match:
            result["is_container"] = True
            result["container_runtime"] = "containerd"
            result["container_id"] = containerd_match.group(1)[:12]
            return result

        # Check for LXC / LXD
        lxc_match = re.search(r"/(?:lxc|lxd)/([a-zA-Z0-9_\-]+)", cgroup_content)
        if lxc_match:
            result["is_container"] = True
            result["container_runtime"] = "LXC/LXD"
            result["container_name"] = lxc_match.group(1)
            return result

        # Check root link for proot / container root mounts
        if root_link and root_link != "/" and ("proot" in root_link or "rootfs" in root_link or "docker" in root_link):
            result["is_container"] = True
            result["container_runtime"] = "Container/RootFS Isolation"

        return result
