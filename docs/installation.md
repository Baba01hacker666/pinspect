# Installation

## From PyPI (recommended)

```bash
pip install pinspect-cli
```

## Via pipx (isolated environment)

```bash
pipx install pinspect-cli
```

## From source

```bash
git clone https://github.com/Baba01hacker666/pinspect.git
cd pinspect
pip install -e .
```

## Requirements

- Linux (reads `/proc` directly; no external commands required)
- Python 3.8+
- [`rich`](https://github.com/Textualize/rich) — the only runtime dependency

> Some inspections (reading `/proc/<pid>/maps`, environment, or fds of processes
> owned by other users) require elevated privileges. `pinspect` degrades
> gracefully and reports what it can access.
