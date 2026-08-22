# `pinspect` — Linux Process Intelligence CLI

> **Fast, deep Linux process inspection and forensic intelligence tool that goes far beyond `ps aux`.**

[![PyPI version](https://img.shields.io/pypi/v/pinspect-cli.svg)](https://pypi.org/project/pinspect-cli/)
[![Python versions](https://img.shields.io/pypi/pyversions/pinspect-cli.svg)](https://pypi.org/project/pinspect-cli/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`pinspect` is an all-in-one terminal tool designed for systems engineers, SREs, and security investigators. It collects deep, actionable intelligence about running processes directly from native Linux `/proc` and kernel interfaces with zero external command dependencies, low overhead, graceful error recovery, and rich terminal and SIEM/EDR output formats.

---

## 📦 Installation

Install directly from **PyPI**:

```bash
pip install pinspect-cli
```

Or install with `pipx` (isolated environment):

```bash
pipx install pinspect-cli
```

Or run from source:

```bash
git clone https://github.com/Baba01hacker666/pinspect.git
cd pinspect
pip install -e .
```

---

## ⚡ Key Highlights

- **Complete Process Visibility**: PID, PPID, ancestry chain to PID 1, command line, arguments, executable, working directory, root directory (with chroot detection), start time, real/effective/saved/fs UIDs & GIDs, supplementary groups, session ID, process group, and TTY.
- **Launch & Origin Intelligence**: Automatically detects whether a process originated from **systemd**, **cron**, **SSH**, an interactive **shell**, **Docker**, **Podman**, **Kubernetes**, a **supervisor** (e.g. `runsv`, `supervisord`), or the kernel. Resolves systemd service unit names, unit files on disk, and container IDs.
- **Security & Privilege Forensics**: Decodes 64-bit Linux capability bitmasks (`CapEff`, `CapPrm`, `CapInh`, `CapBnd`, `CapAmb`) to named capabilities (`CAP_SYS_ADMIN`, `CAP_NET_RAW`), checks `NoNewPrivs`, Seccomp filters, AppArmor/SELinux contexts, SetUID/SetGID bits, executable SHA-256 hashes, and unlinked binary execution (`(deleted)` executables & memory mappings).
- **Files & Sockets**: Inspects open file descriptors, target classification (regular files, pipes, unix sockets, network sockets, anon inodes), permissions, file size, deleted files held in memory, and system-wide/per-PID network connections.
- **Secret Redaction**: `pinspect env` automatically discovers and masks sensitive secrets and credentials (`*_TOKEN`, `*_KEY`, `*_SECRET`, `*_PASSWORD`, `AWS_*`, `DATABASE_URL`, JWT tokens, and private keys).
- **Built-in Grep**: `pinspect grep` searches running processes like grep — by program name, command-line arguments, executable path, or user — with highlighted matches and relevance-ranked results (name matches first).
- **Container Process View**: `pinspect docker` lists only processes running inside containers (Docker, Podman, Kubernetes, CRI-O, LXC) with container ID, runtime, and name.
- **Process Hierarchy Tree**: Visualizes process trees with color-coded states, CPU/memory stats, container badges, and ancestry lineages.
- **Interactive TUI**: Built-in interactive dashboard with live filtering, sortable columns, and detailed multi-tab views.
- **SIEM / EDR Formats**: Structured JSON output (`--json`), CSV export (`--csv`), wide (`--wide`), and quiet mode (`--quiet`).

---

## 📖 Command Reference

### 1. Process Listing (`pinspect ps` or `pinspect`)
Lists running processes with CPU, memory, origin, and state:
```bash
# Default process list
pinspect ps

# Filter by user or UID
pinspect ps --user root
pinspect ps --user 1000

# Filter by process name (regex)
pinspect ps --name "nginx|caddy"

# Filter by listening or connected network port
pinspect ps --port 8080
pinspect ps --listen

# Filter by systemd service name
pinspect ps --service ssh

# Filter for containerized processes only
pinspect ps --container

# Filter for processes running deleted executables or open deleted files
pinspect ps --deleted

# Sort options (cpu, mem, pid, user, name, age)
pinspect ps --sort mem --limit 10
```

### 2. Process Tree (`pinspect tree`)
Renders hierarchical process tree:
```bash
# Full system tree
pinspect tree

# Subtree rooted at a specific PID
pinspect tree 1234

# Highlight a specific PID in the tree
pinspect tree --highlight 1234
```

### 3. Detailed Process Inspection (`pinspect show <PID>`)
Displays comprehensive intelligence card for a single PID:
```bash
# Show identity, origin, CPU/mem stats, security, namespaces, ancestry
pinspect show 14847

# Include SHA-256 binary hash
pinspect show 14847 --hash
```

### 4. Open Files & Descriptors (`pinspect files <PID>`)
Inspects open FDs, targets, inode numbers, and deleted files:
```bash
pinspect files 14847

# Show only deleted files held open by process
pinspect files 14847 --deleted

# Filter by type (regular, socket, pipe, anon, char)
pinspect files 14847 --type socket
```

### 5. Network Sockets (`pinspect network [PID]`)
Inspects TCP, UDP, and Unix domain sockets mapped to processes:
```bash
# All network sockets on the host
pinspect network

# Network sockets for a specific PID
pinspect network 14847

# Filter by port and protocol
pinspect network --port 443 --proto TCP --listen
```

### 6. Environment Variables (`pinspect env <PID>`)
Inspects process environment variables with automatic secret redaction:
```bash
# Redacted view (default)
pinspect env 14847

# Search variable names
pinspect env 14847 --filter TOKEN

# Unredacted view (explicit authorization)
pinspect env 14847 --show-secrets
```

### 7. Process Ancestry & Children (`pinspect ancestry` / `pinspect children`)
Inspects process lineage chains:
```bash
# Full ancestor chain from PID 1 / init down to the process
pinspect ancestry 14847

# Subtree of children and descendants
pinspect children 14847
```

### 8. Namespaces (`pinspect namespaces <PID>`)
Compares namespace inodes against host/PID 1:
```bash
pinspect namespaces 14847
```

### 9. Security & Capability Forensics (`pinspect security <PID>`)
Inspects Linux capabilities, Seccomp, NoNewPrivs, LSM, and file integrity:
```bash
pinspect security 14847
```

### 10. Grep Processes (`pinspect grep <pattern>`)
Searches running processes like grep — by program name, arguments, executable, or user. Matches are highlighted and name matches are ranked first:
```bash
# Search by tool / program name or arguments (name + args + exe by default)
pinspect grep nginx
pinspect grep "daemon off"

# Restrict search to specific fields
pinspect grep python --name
pinspect grep "--debug" --cmdline
pinspect grep /usr/bin/ --exe

# Restrict by user
pinspect grep java --user 1000

# Machine-readable output
pinspect grep nginx --json
pinspect grep nginx --quiet

# Scripting: exits 0 when at least one process matched, 1 otherwise
pinspect grep nginx --quiet && echo "nginx is running"
```

### 11. Containerized Processes Only (`pinspect docker`)
Lists processes running inside containers, with container ID, runtime, and name. Non-container processes are excluded:
```bash
# All containerized processes
pinspect docker

# Filter by container ID prefix, name, or runtime
pinspect docker --id 0abc123
pinspect docker --name my-app
pinspect docker --runtime podman
pinspect docker --limit 20

# SIEM / EDR output
pinspect docker --json
pinspect docker --quiet
```

### 12. Interactive TUI Mode (`pinspect tui`)
Launches full-screen interactive dashboard:
```bash
pinspect tui
```
**Interactive Keybindings**:
- `↑` / `↓` / `k` / `j`: Navigate process list
- `PgUp` / `PgDn` / `Home` / `End`: Fast scroll
- `Enter`: Open process detail pane (tabs: Overview, Files, Network, Security, Env)
- `/`: Search / Filter processes in real time
- `s`: Cycle sort columns (CPU, MEM, PID, USER, NAME)
- `r`: Refresh process list
- `q` / `ESC`: Back / Quit

---

## 📊 SIEM / EDR Output Formats

Every subcommand supports structured serialization:

```bash
# Structured JSON for SIEM / EDR pipelines
pinspect ps --json
pinspect show 1234 --json
pinspect network --json
pinspect security 1234 --json

# CSV for data analysis & spreadsheets
pinspect ps --csv
pinspect files 1234 --csv
pinspect network --csv

# Quiet mode (machine-parseable PIDs or values)
pinspect ps --user nginx --quiet
```

---

## 🧪 Testing

Comprehensive test suite with full mocked `/proc` filesystem fixtures:

```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

