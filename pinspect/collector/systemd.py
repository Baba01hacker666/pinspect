"""
Systemd unit and service manager intelligence collector.
"""

import os
import re
from typing import Optional, Tuple


class SystemdCollector:
    """Extracts systemd unit, slice, and service manager information."""

    SYSTEMD_UNIT_PATHS = (
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
        "/run/systemd/system",
    )

    @staticmethod
    def extract_unit_and_slice(cgroup_content: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Parse /proc/<pid>/cgroup content to extract systemd unit, slice, and user unit.
        Returns: (systemd_unit, systemd_slice, systemd_user_unit)
        """
        if not cgroup_content:
            return (None, None, None)

        unit = None
        slice_name = None
        user_unit = None

        # Look through all lines in cgroup
        for line in cgroup_content.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(":", 2)
            if len(parts) < 3:
                continue
            path = parts[2]

            # Look for *.service, *.scope, *.slice
            service_match = re.search(r"/([a-zA-Z0-9_\-@\.]+\.service)", path)
            if service_match:
                unit = service_match.group(1)

            scope_match = re.search(r"/([a-zA-Z0-9_\-@\.]+\.scope)", path)
            if scope_match and not unit:
                unit = scope_match.group(1)

            slice_match = re.search(r"/([a-zA-Z0-9_\-@\.]+\.slice)", path)
            if slice_match:
                slice_name = slice_match.group(1)

            user_unit_match = re.search(r"/user@[0-9]+\.service/([a-zA-Z0-9_\-@\.]+\.service)", path)
            if user_unit_match:
                user_unit = user_unit_match.group(1)

        return (unit, slice_name, user_unit)

    @classmethod
    def find_unit_file(cls, unit_name: Optional[str]) -> Optional[str]:
        """Find the real unit file path on disk if accessible."""
        if not unit_name:
            return None
        
        # Base unit name without instance if templated (e.g. user@1000.service -> user@.service)
        base_unit = re.sub(r"@[^.]+\.", "@.", unit_name)

        for base_dir in cls.SYSTEMD_UNIT_PATHS:
            direct_path = os.path.join(base_dir, unit_name)
            if os.path.exists(direct_path):
                return direct_path
            if base_unit != unit_name:
                template_path = os.path.join(base_dir, base_unit)
                if os.path.exists(template_path):
                    return template_path
        return None
