# `pinspect` — Linux Process Intelligence CLI

> **Fast, deep Linux process inspection and forensic intelligence that goes far beyond `ps aux`.**

[![PyPI version](https://img.shields.io/pypi/v/pinspect-cli.svg)](https://pypi.org/project/pinspect-cli/)
[![Python versions](https://img.shields.io/pypi/pyversions/pinspect-cli.svg)](https://pypi.org/project/pinspect-cli/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`pinspect` is an all-in-one terminal tool for systems engineers, SREs, and security investigators. It collects deep, actionable intelligence about running processes directly from native Linux `/proc` and kernel interfaces — zero external command dependencies, low overhead, graceful error recovery, and SIEM/EDR-ready output.

## 📦 Installation

Install with **pipx** (recommended — isolated environment):

```bash
pipx install pinspect-cli
```

Or with plain **pip**:

```bash
pip install pinspect-cli
```

## ⚡ Quick Start

```bash
pinspect ps                 # deep process list
pinspect show 1234          # full intelligence card for one PID
pinspect tree               # process hierarchy
pinspect security 1234      # capabilities, seccomp, LSM + risk score
```

## ✨ Highlights

- **Origin intelligence** — detects systemd, cron, SSH, shell, Docker/Podman/Kubernetes, or kernel launch origins; resolves service units and container IDs
- **Security forensics** — decodes capability bitmasks, Seccomp, NoNewPrivs, AppArmor/SELinux, SetUID/SetGID, executable SHA-256 hashes, deleted-binary execution
- **Risk scoring** — every process gets a heuristic suspicion score (0–100) with explainable flags: deleted/memfd executables, RWX memory regions, dangerous capabilities, unsandboxed root
- **Memory map forensics** — flags code-injection evidence: W+X regions, anonymous executable mappings, fileless payloads, files deleted after mapping
- **Files & sockets** — open FDs, deleted files held open, per-PID or system-wide socket mapping
- **Containers** — list only containerized processes with runtime, container ID, and name
- **Secret redaction** — `env` automatically masks tokens, keys, passwords, and credentials
- **Built-in grep** — search running processes by name, arguments, executable, or user; scriptable exit codes
- **Interactive TUI** — live dashboard with filtering, sorting, and multi-tab detail views
- **SIEM / EDR formats** — structured `--json`, `--csv`, `--quiet`, and `--wide` on every subcommand

## 📖 Documentation

| Document | Contents |
| --- | --- |
| [Installation](docs/installation.md) | PyPI, pipx, and from-source installs |
| [Command Reference](docs/commands.md) | All 13 subcommands with examples |
| [Output Formats](docs/output-formats.md) | JSON, CSV, quiet, wide modes for pipelines |
| [Security & Forensics](docs/security-forensics.md) | Risk scoring model, maps forensics, capability analysis |

## 🧪 Testing

```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

## 📜 License

MIT — see [LICENSE](LICENSE).
