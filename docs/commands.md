# Command Reference

Global flags available on every subcommand:

| Flag | Effect |
| --- | --- |
| `--json` | Structured JSON output (SIEM/EDR ingestion) |
| `--csv` | CSV output (list-style commands) |
| `-q`, `--quiet` | Machine-parseable IDs/values only |
| `-w`, `--wide` | Do not truncate command lines or long paths |
| `--proc-root PATH` | Alternate /proc root (for testing/containers) |

---

## 1. Process Listing — `pinspect ps`

Lists running processes with CPU, memory, origin, and state. Running plain `pinspect` defaults to `ps`.

```bash
# Default process list
pinspect ps

# Filter by user or UID
pinspect ps --user root
pinspect ps --user 1000

# Filter by process name (regex supported)
pinspect ps --name "nginx|caddy"

# Filter by listening or connected network port
pinspect ps --port 8080
pinspect ps --listen

# Filter by systemd service name
pinspect ps --service ssh

# Filter for containerized processes only
pinspect ps --container

# Filter for processes running deleted executables or holding deleted files
pinspect ps --deleted

# Sort options: cpu, mem, pid, user, name, age
pinspect ps --sort mem --limit 10

# Incident triage: only processes started within a time window
pinspect ps --since 10m
pinspect ps --since 2h --sort pid --asc
```

Additional filters: `--pid`, `--state R|S|D|Z|T|I`, `--cmdline <pattern>`.

## 2. Process Tree — `pinspect tree`

```bash
pinspect tree                  # full system tree
pinspect tree 1234             # subtree rooted at a PID
pinspect tree --highlight 1234 # highlight a specific PID
```

Color-coded states, CPU/memory stats, container badges, and ancestry lineages.

## 3. Detailed Inspection — `pinspect show <PID>`

Comprehensive intelligence card: identity, origin, CPU/memory, scheduling,
security posture, namespaces, ancestry, and heuristic risk assessment.

```bash
pinspect show 14847
pinspect show 14847 --hash   # include SHA-256 of the executable
pinspect show 14847 --env    # include redacted environment variables
```

## 4. Open Files & Descriptors — `pinspect files <PID>`

```bash
pinspect files 14847
pinspect files 14847 --deleted            # only unlinked/deleted files
pinspect files 14847 --type socket        # regular, socket, pipe, anon, char
```

## 5. Network Sockets — `pinspect network [PID]`

Maps TCP, UDP, and Unix domain sockets to owning processes.

```bash
pinspect network                          # all sockets on the host
pinspect network 14847                    # sockets for one PID
pinspect network --port 443 --proto TCP --listen
```

## 6. Environment Variables — `pinspect env <PID>`

Automatic secret redaction (`*_TOKEN`, `*_KEY`, `*_SECRET`, `*_PASSWORD`,
`AWS_*`, `DATABASE_URL`, JWTs, private keys).

```bash
pinspect env 14847                     # redacted view (default)
pinspect env 14847 --filter TOKEN      # search variable names
pinspect env 14847 --show-secrets      # unredacted (use responsibly)
```

## 7. Ancestry & Children — `pinspect ancestry` / `pinspect children`

```bash
pinspect ancestry 14847   # ancestor chain from init down to the process
pinspect children 14847   # child subtree and descendants
```

## 8. Namespaces — `pinspect namespaces <PID>`

Compares namespace inodes against host/PID 1 to show isolation.

```bash
pinspect namespaces 14847
```

## 9. Security & Risk — `pinspect security <PID>`

Capabilities, Seccomp, NoNewPrivs, LSM context, binary integrity — plus a
heuristic risk score with explainable suspicion flags. See
[Security & Forensics](security-forensics.md) for the full scoring model.

```bash
pinspect security 14847
pinspect security 14847 --no-hash     # skip executable hashing
pinspect security 14847 --json        # includes risk.score / risk.level / risk.flags
```

## 10. Grep Processes — `pinspect grep <pattern>`

Search running processes like grep — program name, arguments, executable path,
or user. Matches are highlighted; name matches rank first.

```bash
pinspect grep nginx                   # searches name + args + exe
pinspect grep "daemon off"            # match on arguments

# Restrict search scope
pinspect grep python --name
pinspect grep "--debug" --cmdline
pinspect grep /usr/bin/ --exe

pinspect grep java --user 1000        # restrict by user
pinspect grep nginx --json            # machine-readable output

# Scripting: exit code 0 = matched, 1 = no match
pinspect grep nginx --quiet && echo "nginx is running"
```

## 11. Containerized Processes — `pinspect docker`

Lists only processes running inside containers (Docker, Podman, Kubernetes,
CRI-O, LXC) with container ID, runtime, and name.

```bash
pinspect docker
pinspect docker --id 0abc123          # container ID prefix match
pinspect docker --name my-app
pinspect docker --runtime podman
pinspect docker --limit 20
```

## 12. Memory Maps — `pinspect maps <PID>`

Dissects `/proc/<pid>/maps` with forensic indicators for code injection and
fileless execution. See [Security & Forensics](security-forensics.md).

```bash
pinspect maps 14847       # RWX regions, anon exec mappings, memfd payloads,
                          # deleted backing files are highlighted automatically
pinspect maps 14847 --json
```

## 13. Interactive TUI — `pinspect tui`

Full-screen interactive dashboard.

```bash
pinspect tui
```

**Keybindings**

| Key | Action |
| --- | --- |
| `↑` / `↓` / `k` / `j` | Navigate process list |
| `PgUp` / `PgDn` / `Home` / `End` | Fast scroll |
| `Enter` | Detail pane (tabs: Overview, Files, Network, Security, Env) |
| `/` | Search / filter in real time |
| `s` | Cycle sort columns (CPU, MEM, PID, USER, NAME) |
| `r` | Refresh process list |
| `q` / `ESC` | Back / Quit |
