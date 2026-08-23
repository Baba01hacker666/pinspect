# Security & Forensics Guide

How `pinspect` evaluates process security, memory forensics, and risk.

## Risk scoring model

Every process assessed by `pinspect show` and `pinspect security` receives a
heuristic suspicion score from **0 to 100** plus explainable flags. Kernel
threads and PID 1 are exempt (always 0 / LOW).

### Levels

| Score | Level |
| --- | --- |
| 0–19 | `LOW` — no meaningful indicators |
| 20–44 | `MEDIUM` — worth a look |
| 45–69 | `HIGH` — investigate |
| 70–100 | `CRITICAL` — likely malicious |

### Flags

| Code | Weight | Meaning |
| --- | --- | --- |
| `MEMFD_EXEC` | +25 | Binary runs from an anonymous memory file (`/memfd:`) — no on-disk artifact |
| `DELETED_EXE` | +20 | Executable was unlinked from disk after execution (anti-forensics pattern) |
| `TMP_EXEC` | +15 | Executable staged in `/tmp`, `/var/tmp`, or `/dev/shm` |
| `ANON_EXEC_MAPS` | +15 | Executable memory with no file backing — possible injected code |
| `RWX_REGIONS` | +15 | Memory that is simultaneously readable, writable, and executable |
| `CAP_SYS_ADMIN` | +15 | Near-root kernel privilege (mounts, namespaces, devices) |
| `WRITABLE_EXE` | +12 | World-writable binary — any local user can replace it |
| `PARENT_DELETED_EXE` | +10 | Parent process runs a deleted binary |
| `POWERFUL_CAPS` | ≤+10 | Holds `CAP_SYS_PTRACE`, `CAP_SYS_RAWIO`, `CAP_BPF`, `CAP_SYS_MODULE`, or `CAP_SYS_BOOT` |
| `DELETED_MAPPED_FILES` | +8 | Mapped files were removed after being loaded |
| `UNSANDBOXED_ROOT` | +5 | Root with seccomp disabled and NoNewPrivs unset (host processes) |
| `UNCONFINED_LSM` | +4 | AppArmor profile explicitly set to `unconfined` |

Scores are capped at 100. The flags are heuristics: legitimate software
(JIT compilers, plugin hosts, debugging tools) can trigger individual flags —
the value is in the combination and the explanation attached to each flag.

## Memory map forensics

`pinspect maps <PID>` parses `/proc/<pid>/maps` and highlights:

- **RWX regions** — writable *and* executable memory is the classic
  self-modifying-code / shellcode indicator
- **Anonymous executable mappings** — executable regions with no backing file;
  common for injected code, rare otherwise
- **memfd payloads** — regions backed by `memfd_create`: fully fileless
  execution (e.g. what some droppers and in-memory loaders use)
- **Deleted backing files** — shared libraries or binaries removed after being
  mapped; the code still runs but the evidence on disk is gone

```bash
pinspect maps <PID>
```

```bash
pinspect maps <PID> --json
```

> Reading `/proc/<pid>/maps` of processes owned by other users requires root
> (or same-user). Without permission the report comes back empty rather than
> crashing.

## Capability & integrity analysis

`pinspect security <PID>` decodes all five capability sets
(`CapEff`, `CapPrm`, `CapInh`, `CapBnd`, `CapAmb`) to named capabilities,
reports Seccomp mode, NoNewPrivs, AppArmor/SELinux contexts, SetUID/SetGID
bits, world-writable executables, and optionally computes the SHA-256 of the
running binary:

```bash
pinspect security <PID>
```

```bash
pinspect security <PID> --no-hash    # skip hashing (faster)
```

## Incident-response workflow

A typical quick triage sequence:

```bash
# 1. What just appeared?
pinspect ps --since 15m --sort pid --asc
```

```bash
# 2. Anything running deleted or staged binaries?
pinspect ps --deleted
```

```bash
# 3. Deep-dive the suspicious PID (risk score included)
pinspect show <PID>
```

```bash
# 4. Confirm injection evidence in memory
pinspect maps <PID>
```

```bash
# 5. Export everything for the case file
pinspect show <PID> --json > host-incident-pid.json
```
