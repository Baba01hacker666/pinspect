# Output Formats (SIEM / EDR)

Every subcommand supports structured serialization for pipelines and log
ingestion. These flags are available globally.

## JSON

Structured JSON for SIEM / EDR pipelines:

```bash
pinspect ps --json
```

```bash
pinspect show 1234 --json
```

```bash
pinspect network --json
```

```bash
pinspect security 1234 --json
```

## CSV

CSV export for spreadsheets and data analysis (list-style commands):

```bash
pinspect ps --csv
```

```bash
pinspect files 1234 --csv
```

```bash
pinspect network --csv
```

Commands without a natural tabular form (e.g. `show`) reject `--csv` with a
clear error instead of silently emitting the wrong format — use `--json`.

## Quiet mode

Machine-parseable IDs or values only — one line per item, ideal for shell loops:

```bash
pinspect ps --user nginx --quiet
```

```bash
for pid in $(pinspect grep nginx --quiet); do pinspect show "$pid"; done
```

`grep` follows grep exit-code conventions: `0` when at least one process
matched, `1` when none did.

## Wide mode

Disables truncation of command lines and long paths:

```bash
pinspect ps --wide
```

## Alternate /proc root

Useful for containers, chroots, and testing against fixture filesystems:

```bash
pinspect --proc-root /mnt/host/proc ps
```
