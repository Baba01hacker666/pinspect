"""
Heuristic risk scoring: combines process metadata, security posture, and
memory-map forensics into a suspicion score with human-readable flags.
"""

from typing import Optional

from pinspect.collector.maps import is_suspicious_path
from pinspect.model.maps import MapsReport
from pinspect.model.process import ProcessInfo
from pinspect.model.risk import RiskFlag, RiskInfo, level_for_score
from pinspect.model.security import SecurityInfo

# Capabilities that grant dangerous host-level power
_HIGH_RISK_CAPS = {"CAP_SYS_ADMIN"}
_MED_RISK_CAPS = {"CAP_SYS_PTRACE", "CAP_SYS_RAWIO", "CAP_BPF", "CAP_SYS_MODULE", "CAP_SYS_BOOT"}

# Score cap
_MAX_SCORE = 100


class RiskCollector:
    """Computes a heuristic risk assessment for a collected process."""

    def assess(
        self,
        pinfo: ProcessInfo,
        security: Optional[SecurityInfo] = None,
        maps_report: Optional[MapsReport] = None,
    ) -> RiskInfo:
        risk = RiskInfo(pid=pinfo.pid)

        # Kernel threads and PID 1 are infrastructure, not suspects
        if pinfo.is_kernel_thread or pinfo.pid == 1:
            return risk

        self._assess_execution(pinfo, risk)
        if security is not None:
            self._assess_security(pinfo, security, risk)
        if maps_report is not None:
            self._assess_maps(maps_report, risk)

        risk.score = min(_MAX_SCORE, sum(f.weight for f in risk.flags))
        risk.level = level_for_score(risk.score)
        return risk

    def _add(self, risk: RiskInfo, code: str, title: str, detail: str, weight: int, severity: str) -> None:
        risk.flags.append(RiskFlag(code=code, title=title, detail=detail, weight=weight, severity=severity))

    def _assess_execution(self, pinfo: ProcessInfo, risk: RiskInfo) -> None:
        exe = (pinfo.resolved_exe or "").split(" (deleted)")[0]

        if pinfo.is_deleted_exe:
            self._add(
                risk,
                "DELETED_EXE",
                "Executable deleted from disk",
                f"{pinfo.exe} was unlinked after execution — common malware anti-forensics pattern",
                weight=20,
                severity="CRITICAL",
            )

        if exe.startswith("/memfd:"):
            self._add(
                risk,
                "MEMFD_EXEC",
                "Fileless memfd execution",
                "Binary runs entirely from an anonymous memory file — no on-disk artifact",
                weight=25,
                severity="CRITICAL",
            )
        elif is_suspicious_path(exe):
            self._add(
                risk,
                "TMP_EXEC",
                "Executable in world-writable directory",
                f"Running from {exe.rsplit('/', 1)[0] or '/'} — binaries should not live in staging paths",
                weight=15,
                severity="HIGH",
            )

        parent = pinfo.ancestry[0] if pinfo.ancestry else None
        if parent is not None and parent.is_deleted_exe:
            self._add(
                risk,
                "PARENT_DELETED_EXE",
                "Parent executable deleted",
                f"Parent PID {parent.pid} ({parent.name}) runs a deleted binary",
                weight=10,
                severity="HIGH",
            )

    def _assess_security(self, pinfo: ProcessInfo, security: SecurityInfo, risk: RiskInfo) -> None:
        eff_caps = security.capabilities.effective
        high_caps = sorted(eff_caps & _HIGH_RISK_CAPS)
        med_caps = sorted(eff_caps & _MED_RISK_CAPS)

        if high_caps:
            self._add(
                risk,
                "CAP_SYS_ADMIN",
                "Holds CAP_SYS_ADMIN",
                "Near-root kernel privilege: mount, namespace and device access",
                weight=15,
                severity="HIGH",
            )
        if med_caps:
            self._add(
                risk,
                "POWERFUL_CAPS",
                "Powerful capabilities",
                f"Effective: {', '.join(med_caps)}",
                weight=min(10, 4 * len(med_caps)),
                severity="MEDIUM",
            )

        if security.is_world_writable:
            self._add(
                risk,
                "WRITABLE_EXE",
                "World-writable executable",
                "Any local user can replace the binary that this process runs",
                weight=12,
                severity="HIGH",
            )

        if (
            security.seccomp_mode.value in (-1, 0)
            and not security.no_new_privs
            and pinfo.creds.euid == 0
            and not pinfo.cgroup.is_container
        ):
            self._add(
                risk,
                "UNSANDBOXED_ROOT",
                "Unsandboxed root process",
                "Root privileges with seccomp disabled and NoNewPrivs unset",
                weight=5,
                severity="LOW",
            )

        if security.apparmor_profile == "unconfined":
            self._add(
                risk,
                "UNCONFINED_LSM",
                "Unconfined AppArmor profile",
                "LSM profile explicitly set to unconfined",
                weight=4,
                severity="LOW",
            )

    def _assess_maps(self, report: MapsReport, risk: RiskInfo) -> None:
        if report.rwx_region_count:
            self._add(
                risk,
                "RWX_REGIONS",
                "RWX memory regions",
                f"{report.rwx_region_count} region(s) are simultaneously readable, writable and executable",
                weight=15,
                severity="HIGH",
            )

        if report.anonymous_exec_count:
            self._add(
                risk,
                "ANON_EXEC_MAPS",
                "Anonymous executable mappings",
                f"{report.anonymous_exec_count} executable region(s) with no file backing — possible injected code",
                weight=15,
                severity="HIGH",
            )

        if report.memfd_paths:
            self._add(
                risk,
                "MEMFD_MAPS",
                "memfd-backed mappings",
                f"Fileless payloads mapped via memfd_create: {', '.join(report.memfd_paths[:3])}",
                weight=20,
                severity="CRITICAL",
            )

        if report.deleted_paths:
            self._add(
                risk,
                "DELETED_MAPPED_FILES",
                "Deleted files still mapped",
                f"{len(report.deleted_paths)} mapped file(s) were removed after load",
                weight=8,
                severity="MEDIUM",
            )
