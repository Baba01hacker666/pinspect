"""
'pinspect docker' command — list processes running inside containers only.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from pinspect.collector.container_names import ContainerNameResolver
from pinspect.collector.process import ProcessCollector
from pinspect.collector.procfs import ProcFS
from pinspect.model.process import ProcessInfo
from pinspect.output.formatter import OutputDispatcher
from pinspect.ui.table import render_container_tree


@dataclass
class ContainerGroup:
    """A container and the processes running inside it."""

    container_id: str
    container_name: Optional[str] = None
    container_runtime: Optional[str] = None
    container_image: Optional[str] = None
    container_networks: List[str] = field(default_factory=list)
    container_mounts: List[str] = field(default_factory=list)
    kubernetes_namespace: Optional[str] = None
    processes: List[ProcessInfo] = field(default_factory=list)


def handle_docker(
    proc_root: str = "/proc",
    container_id: Optional[str] = None,
    container_name: Optional[str] = None,
    runtime_filter: Optional[str] = None,
    limit: Optional[int] = None,
    output_dispatcher: Optional[OutputDispatcher] = None,
) -> int:
    """List processes running inside containers (Docker, Podman, Kubernetes, CRI-O, LXC)."""
    procfs = ProcFS(proc_root)
    collector = ProcessCollector(procfs)
    dispatcher = output_dispatcher or OutputDispatcher()

    processes = collector.collect_all_processes(deep=False)
    container_procs = [p for p in processes if p.cgroup.is_container]

    # Resolve names / details for every distinct container ID via runtime sockets
    resolver = ContainerNameResolver()
    id_to_details: Dict[str, object] = {}
    for p in container_procs:
        cid = p.cgroup.container_id
        if cid and cid not in id_to_details:
            id_to_details[cid] = resolver.resolve(cid)

    filtered: List[ProcessInfo] = []
    for p in container_procs:
        cid = p.cgroup.container_id
        details = id_to_details.get(cid) if cid else None

        name = details.name if details else p.cgroup.container_name
        runtime = p.cgroup.container_runtime

        if container_id and (not cid or container_id.lower() not in cid.lower()):
            continue
        if container_name and (not name or container_name.lower() not in name.lower()):
            continue
        if runtime_filter and (not runtime or runtime_filter.lower() not in runtime.lower()):
            continue

        # Enrich the process with the resolved name so JSON/CSV carry it too
        if details and details.name:
            p.cgroup.container_name = details.name
        filtered.append(p)

    # Group processes by container
    groups: Dict[str, ContainerGroup] = {}
    for p in filtered:
        cid = p.cgroup.container_id or f"anon:{p.cgroup.container_runtime or '?'}"
        if cid not in groups:
            details = id_to_details.get(p.cgroup.container_id) if p.cgroup.container_id else None
            groups[cid] = ContainerGroup(
                container_id=cid,
                container_name=(details.name if details else None) or p.cgroup.container_name,
                container_runtime=p.cgroup.container_runtime,
                container_image=details.image if details else None,
                container_networks=list(details.networks) if details else [],
                container_mounts=list(details.mounts) if details else [],
                kubernetes_namespace=p.cgroup.kubernetes_namespace,
            )
        groups[cid].processes.append(p)

    for group in groups.values():
        group.processes.sort(key=lambda p: p.pid)
    group_list = sorted(groups.values(), key=lambda g: (g.container_id.lower(), g.container_name or ""))

    # --limit applies to the total number of processes across all containers
    if limit is not None and limit > 0:
        remaining = limit
        for group in group_list:
            if remaining <= 0:
                group.processes = []
            elif len(group.processes) > remaining:
                group.processes = group.processes[:remaining]
                remaining = 0
            else:
                remaining -= len(group.processes)

    # Machine formats stay flat (list of processes) for SIEM/EDR pipelines
    if dispatcher.json_mode or dispatcher.csv_mode or dispatcher.quiet_mode:
        flat = [p for group in group_list for p in group.processes]
        dispatcher.handle(
            data=flat,
            csv_type="process",
            quiet_extractor=lambda procs: [str(p.pid) for p in procs],
        )
        return 0

    dispatcher.handle(
        data=group_list,
        rich_render_fn=lambda: render_container_tree(group_list, wide=dispatcher.wide_mode),
    )
    return 0
