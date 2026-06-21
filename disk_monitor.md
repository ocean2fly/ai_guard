# AI Guardian — Disk Monitoring System

> Real-time disk surveillance for AI agent operations on Amazon Linux 2023

**Environment:** Amazon Linux 2023 · kernel 6.1.172 · x86\_64  
**Scope:** File deletion, content overwrite, bulk operations, disk usage thresholds, file integrity

---

## Overview

The Disk Monitor is the core protective layer of AI Guardian. It intercepts destructive filesystem operations at the OS level using Linux `inotify`, creates pre-deletion backups, and holds operations pending human confirmation. No AI tool can bypass it — the gate lives below the AI's own logic.

### What It Monitors

| Category | Events | Trigger Condition |
|---|---|---|
| **Deletion** | `unlink`, `rmdir`, `rm -rf` | Any delete under watched paths |
| **Overwrite** | `CLOSE_WRITE` on existing file | File content replaced |
| **Move / Rename** | `MOVED_FROM` | File moved out of watched scope |
| **Bulk ops** | Any of the above × N | Count > `bulk_threshold` (default: 3) |
| **Disk usage** | Polling `/proc/mounts` | Used % crosses warning / critical level |
| **Integrity** | SHA-256 hash change | Watched file modified without approval |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Disk Monitor System                       │
│                                                             │
│  ┌──────────────┐   ┌──────────────┐   ┌───────────────┐  │
│  │  inotify     │   │  Usage       │   │  Integrity    │  │
│  │  Watcher     │   │  Poller      │   │  Checker      │  │
│  └──────┬───────┘   └──────┬───────┘   └──────┬────────┘  │
│         │                  │                   │            │
│         └──────────────────┼───────────────────┘            │
│                            ▼                                │
│                   ┌────────────────┐                        │
│                   │ Event Router   │                        │
│                   └───────┬────────┘                        │
│                           │                                 │
│          ┌────────────────┼────────────────┐               │
│          ▼                ▼                ▼               │
│   ┌─────────────┐  ┌──────────┐  ┌──────────────┐        │
│   │  Permission │  │  Backup  │  │  Audit       │        │
│   │  Engine     │  │  Manager │  │  Logger      │        │
│   └──────┬──────┘  └──────────┘  └──────────────┘        │
│          │                                                  │
│   ┌──────▼──────┐                                          │
│   │ Confirmation│  terminal / telegram / web               │
│   │ Gate        │                                          │
│   └─────────────┘                                          │
└─────────────────────────────────────────────────────────────┘
```

---

## Directory Layout

```
ai-guardian/
├── modules/
│   └── disk/
│       ├── __init__.py
│       ├── guardian.py          # Main disk monitor entry point
│       ├── watcher.py           # inotify event loop
│       ├── usage_poller.py      # Disk space polling
│       ├── integrity.py         # File integrity checker
│       ├── backup.py            # Backup manager
│       └── process_resolver.py  # PID → program name resolver
├── config.yaml                  # Permission rules (shared)
├── confirm/
│   ├── terminal.py              # Terminal confirmation gate
│   ├── telegram.py              # Telegram Bot gate (optional)
│   └── web.py                   # Local web gate (optional)
├── audit.log                    # JSONL audit trail
└── backups/
    └── disk/                    # Pre-deletion file snapshots
        └── YYYY-MM-DD_HHmmss/
            └── <mirrored path>
```

---

## Configuration

```yaml
# config.yaml  (disk section)

global:
  bulk_threshold: 3            # Re-confirm when ops exceed this count
  backup_retention_days: 7     # Prune backups older than N days
  timeout_seconds: 30          # Auto-deny after N seconds of silence
  confirm_method: terminal     # terminal | telegram | web

disk:
  watch_paths:
    - /home/ec2-user
    - /var/www
    - /opt/app

  usage_alerts:
    warning_pct: 75            # Warn when disk usage >= 75 %
    critical_pct: 90           # Page / alert when >= 90 %
    poll_interval_seconds: 60

  integrity:
    enabled: true
    watch_files:               # Exact paths to hash-monitor
      - /etc/passwd
      - /etc/sudoers
      - /home/ec2-user/.ssh/authorized_keys
      - /home/ec2-user/ai-guardian/config.yaml

  exclude_patterns:            # Never monitor these (reduces noise)
    - "*.pyc"
    - "__pycache__"
    - ".git"
    - "*.log"
    - "/tmp/*"

programs:
  cursor:
    disk:
      - path: /tmp/
        action: allow_always
      - path: /home/ec2-user/project/
        action: allow_always
        bulk_threshold: 3      # Still re-confirm beyond 3 files
      - path: /
        action: ask

  claude-code:
    disk:
      - path: /tmp/
        action: allow_always
      - path: /
        action: ask

  unknown:
    disk:
      - path: /
        action: deny
```

---

## Module Implementations

### 1. inotify Watcher — `modules/disk/watcher.py`

```python
import os
import inotify_simple
from pathlib import Path
from .process_resolver import resolve_process
from .backup import BackupManager
from permissions import check_permission, log_audit
from confirm.terminal import ask_user

WATCH_FLAGS = (
    inotify_simple.flags.DELETE
    | inotify_simple.flags.DELETE_SELF
    | inotify_simple.flags.MOVED_FROM
    | inotify_simple.flags.CLOSE_WRITE
    | inotify_simple.flags.CREATE        # detect new file creation for integrity
)


class InotifyWatcher:
    def __init__(self, watch_paths: list[str], exclude_patterns: list[str],
                 backup_manager: BackupManager, config: dict):
        self.inotify = inotify_simple.INotify()
        self.wd_map: dict[int, str] = {}        # watch descriptor → path
        self.exclude_patterns = exclude_patterns
        self.backup = backup_manager
        self.config = config
        self._pending: dict[str, list[str]] = {}  # program → [target, ...]

        for path in watch_paths:
            self._add_recursive(path)

    def _add_recursive(self, root: str):
        if not os.path.exists(root):
            return
        try:
            wd = self.inotify.add_watch(root, WATCH_FLAGS)
            self.wd_map[wd] = root
        except PermissionError:
            return

        for entry in os.scandir(root):
            if entry.is_dir(follow_symlinks=False):
                self._add_recursive(entry.path)

    def _is_excluded(self, path: str) -> bool:
        import fnmatch
        name = os.path.basename(path)
        return any(fnmatch.fnmatch(name, p) or fnmatch.fnmatch(path, p)
                   for p in self.exclude_patterns)

    def run(self):
        print("[DiskWatcher] Started — monitoring filesystem events")
        while True:
            for event in self.inotify.read():
                self._dispatch(event)

    def _dispatch(self, event):
        parent = self.wd_map.get(event.wd, "unknown")
        target = os.path.join(parent, event.name) if event.name else parent

        if self._is_excluded(target):
            return

        flags = inotify_simple.flags.from_mask(event.mask)
        is_delete = any(f in flags for f in (
            inotify_simple.flags.DELETE,
            inotify_simple.flags.DELETE_SELF,
            inotify_simple.flags.MOVED_FROM,
        ))
        is_write = inotify_simple.flags.CLOSE_WRITE in flags

        if not (is_delete or is_write):
            return

        program, pid = resolve_process(target)
        action_label = "delete" if is_delete else "overwrite"
        self._evaluate(target, action_label, program, pid)

    def _evaluate(self, target: str, action: str, program: str, pid: str):
        permission = check_permission(program, "disk", target, count=1)

        if permission == "allow_always":
            log_audit({"event": "disk_allowed", "action": action,
                       "target": target, "program": program})
            return

        if permission == "deny":
            log_audit({"event": "disk_denied", "action": action,
                       "target": target, "program": program})
            return

        # ask or bulk_warn: back up first, then ask
        backup_path = self.backup.snapshot(target)
        extra_warning = None
        if permission == "bulk_warn":
            extra_warning = "Authorized path — but bulk threshold exceeded"

        op = {
            "resource_type": "disk",
            "program": program,
            "pid": pid,
            "backup_path": backup_path,
            "details": {
                "Action":   action.upper(),
                "Path":     target,
                "Program":  f"{program} (PID {pid})",
            },
        }
        if extra_warning:
            op["details"]["Warning"] = extra_warning

        result = ask_user(op, timeout=self.config["global"]["timeout_seconds"])
        log_audit({
            "event": "disk_decision",
            "result": result,
            "action": action,
            "target": target,
            "program": program,
        })

        if result.startswith("allow_always"):
            from permissions import grant_permission
            grant_permission(program, "disk", target, "allow_always")
```

---

### 2. Process Resolver — `modules/disk/process_resolver.py`

```python
import subprocess
import os


def resolve_process(path: str) -> tuple[str, str]:
    """Return (program_name, pid) for the process last touching `path`."""
    for method in (_via_fuser, _via_lsof):
        name, pid = method(path)
        if name != "unknown":
            return name, pid
    return "unknown", "?"


def _via_fuser(path: str) -> tuple[str, str]:
    try:
        out = subprocess.run(
            ["fuser", path], capture_output=True, text=True, timeout=2
        ).stdout.strip()
        if out:
            pid = out.split()[0]
            comm = Path(f"/proc/{pid}/comm").read_text().strip()
            return comm, pid
    except Exception:
        pass
    return "unknown", "?"


def _via_lsof(path: str) -> tuple[str, str]:
    try:
        out = subprocess.run(
            ["lsof", "-t", path], capture_output=True, text=True, timeout=2
        ).stdout.strip()
        if out:
            pid = out.split()[0]
            comm = Path(f"/proc/{pid}/comm").read_text().strip()
            return comm, pid
    except Exception:
        pass
    return "unknown", "?"


from pathlib import Path
```

---

### 3. Backup Manager — `modules/disk/backup.py`

```python
import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path


class BackupManager:
    def __init__(self, backup_root: str, retention_days: int):
        self.root = Path(backup_root)
        self.retention_days = retention_days
        self.root.mkdir(parents=True, exist_ok=True)

    def snapshot(self, path: str) -> str | None:
        """Copy file/dir to timestamped backup slot. Returns dest path or None."""
        src = Path(path)
        if not src.exists():
            return None

        ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        rel = str(src).lstrip("/")
        dest = self.root / ts / rel
        dest.parent.mkdir(parents=True, exist_ok=True)

        try:
            if src.is_dir():
                shutil.copytree(src, dest, dirs_exist_ok=True)
            else:
                shutil.copy2(src, dest)
            return str(dest)
        except Exception as e:
            print(f"[BackupManager] Snapshot failed for {path}: {e}")
            return None

    def restore(self, backup_path: str, original_path: str) -> bool:
        """Restore a previously snapshotted file/dir to its original location."""
        src = Path(backup_path)
        dst = Path(original_path)
        if not src.exists():
            print(f"[BackupManager] Backup not found: {backup_path}")
            return False
        try:
            dst.parent.mkdir(parents=True, exist_ok=True)
            if src.is_dir():
                shutil.copytree(src, dst, dirs_exist_ok=True)
            else:
                shutil.copy2(src, dst)
            return True
        except Exception as e:
            print(f"[BackupManager] Restore failed: {e}")
            return False

    def prune(self):
        """Delete backup slots older than retention_days."""
        cutoff = datetime.now() - timedelta(days=self.retention_days)
        pruned = 0
        for slot in self.root.iterdir():
            try:
                slot_dt = datetime.strptime(slot.name, "%Y-%m-%d_%H%M%S")
                if slot_dt < cutoff:
                    shutil.rmtree(slot)
                    pruned += 1
            except (ValueError, NotADirectoryError):
                pass
        if pruned:
            print(f"[BackupManager] Pruned {pruned} old backup slot(s)")

    def list_snapshots(self) -> list[dict]:
        """Return a list of backup metadata sorted newest-first."""
        results = []
        for slot in sorted(self.root.iterdir(), reverse=True):
            size = sum(f.stat().st_size for f in slot.rglob("*") if f.is_file())
            results.append({
                "slot": slot.name,
                "path": str(slot),
                "size_mb": round(size / 1024 / 1024, 2),
            })
        return results
```

---

### 4. Disk Usage Poller — `modules/disk/usage_poller.py`

```python
import shutil
import time
import threading
from permissions import log_audit


class UsagePoller:
    def __init__(self, paths: list[str], warning_pct: int,
                 critical_pct: int, interval_seconds: int):
        self.paths = paths
        self.warning_pct = warning_pct
        self.critical_pct = critical_pct
        self.interval = interval_seconds
        self._last_alert: dict[str, str] = {}  # path → last level alerted

    def start(self):
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()

    def _loop(self):
        print("[UsagePoller] Started — polling disk usage")
        while True:
            for path in self.paths:
                self._check(path)
            time.sleep(self.interval)

    def _check(self, path: str):
        try:
            usage = shutil.disk_usage(path)
        except FileNotFoundError:
            return

        pct = usage.used / usage.total * 100
        level = self._alert_level(pct)

        if level and self._last_alert.get(path) != level:
            self._last_alert[path] = level
            self._fire_alert(path, pct, usage, level)
        elif not level:
            self._last_alert.pop(path, None)

    def _alert_level(self, pct: float) -> str | None:
        if pct >= self.critical_pct:
            return "critical"
        if pct >= self.warning_pct:
            return "warning"
        return None

    def _fire_alert(self, path: str, pct: float,
                    usage, level: str):
        free_gb = usage.free / 1024 ** 3
        msg = (
            f"[DiskUsage] {level.upper()} — {path}  "
            f"{pct:.1f}% used  ({free_gb:.1f} GB free)"
        )
        print(msg)
        log_audit({
            "event": "disk_usage_alert",
            "level": level,
            "path": path,
            "used_pct": round(pct, 1),
            "free_gb": round(free_gb, 2),
        })
```

---

### 5. File Integrity Checker — `modules/disk/integrity.py`

```python
import hashlib
import time
import threading
from pathlib import Path
from permissions import log_audit
from confirm.terminal import ask_user


class IntegrityChecker:
    def __init__(self, watch_files: list[str], poll_interval: int = 30):
        self.watch_files = watch_files
        self.interval = poll_interval
        self._hashes: dict[str, str] = {}
        self._build_baseline()

    def _hash(self, path: str) -> str | None:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (FileNotFoundError, PermissionError):
            return None

    def _build_baseline(self):
        for path in self.watch_files:
            h = self._hash(path)
            if h:
                self._hashes[path] = h
        print(f"[IntegrityChecker] Baseline built for "
              f"{len(self._hashes)} file(s)")

    def start(self):
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()

    def _loop(self):
        while True:
            time.sleep(self.interval)
            self._scan()

    def _scan(self):
        for path in self.watch_files:
            current = self._hash(path)
            if current is None:
                if path in self._hashes:
                    self._alert_deleted(path)
            elif self._hashes.get(path) != current:
                self._alert_modified(path, current)

    def _alert_modified(self, path: str, new_hash: str):
        old_hash = self._hashes.get(path, "none")
        log_audit({
            "event": "integrity_violation",
            "path": path,
            "old_hash": old_hash,
            "new_hash": new_hash,
        })

        op = {
            "resource_type": "disk",
            "program": "unknown",
            "pid": "?",
            "backup_path": None,
            "details": {
                "Action":   "INTEGRITY VIOLATION — File Modified",
                "Path":     path,
                "Old SHA256": old_hash[:16] + "...",
                "New SHA256": new_hash[:16] + "...",
            },
        }
        ask_user(op, timeout=30)
        self._hashes[path] = new_hash  # update baseline after review

    def _alert_deleted(self, path: str):
        log_audit({"event": "integrity_file_deleted", "path": path})
        print(f"[IntegrityChecker] ALERT — watched file deleted: {path}")
        del self._hashes[path]
```

---

### 6. Confirmation Gate — `confirm/terminal.py`

```python
import threading
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()


def ask_user(operation: dict, timeout: int = 30) -> str:
    """
    Display operation details and wait for human input.
    Returns: allow_once | allow_always | deny | timeout
    """
    _print_operation(operation)

    result = {"value": "timeout"}
    answered = threading.Event()

    def _input_thread():
        try:
            console.print(
                "\n[bold]Choose action:[/bold]\n"
                "  [red]1[/red]  Deny\n"
                "  [green]2[/green]  Allow once\n"
                "  [yellow]3[/yellow]  Always allow this path\n"
                "  [blue]4[/blue]  Authorize this program\n",
                highlight=False
            )
            choice = input(
                f"Enter 1-4 (auto-deny in {timeout}s): "
            ).strip()
            if choice == "1":
                result["value"] = "deny"
            elif choice == "2":
                result["value"] = "allow_once"
            elif choice == "3":
                result["value"] = _ask_always_scope(operation)
            elif choice == "4":
                result["value"] = f"program_auth:{operation.get('program')}"
            else:
                result["value"] = "deny"
        except (EOFError, KeyboardInterrupt):
            result["value"] = "deny"
        finally:
            answered.set()

    t = threading.Thread(target=_input_thread, daemon=True)
    t.start()
    answered.wait(timeout=timeout)
    return result["value"]


def _print_operation(op: dict):
    resource = op.get("resource_type", "unknown")
    color = {"disk": "red", "db": "magenta", "email": "yellow"}.get(resource, "white")

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column("Field", style="dim", width=14)
    table.add_column("Value")

    for key, val in op.get("details", {}).items():
        table.add_row(key, str(val))

    console.print(Panel(
        table,
        title=f"[bold {color}]!! AI Guardian — Dangerous Operation Intercepted[/bold {color}]",
        subtitle=f"[dim]{op.get('program', 'unknown')} (PID {op.get('pid', '?')})[/dim]",
        border_style=color,
    ))

    if op.get("backup_path"):
        console.print(f"[green]Backup saved → {op['backup_path']}[/green]")


def _ask_always_scope(op: dict) -> str:
    console.print("\n[bold]Select authorization scope:[/bold]")
    path = op.get("details", {}).get("Path", "/")
    parent = str(Path(path).parent)

    console.print(f"  1  This file/directory only: {path}")
    console.print(f"  2  Parent directory: {parent}")
    console.print(f"  3  Parent directory + re-confirm on bulk > 3 (recommended)")

    choice = input("Enter 1-3: ").strip()
    target = path if choice == "1" else parent
    suffix = "bulk_warn" if choice == "3" else "full"
    return f"allow_always:disk:{target}:{suffix}"
```

---

### 7. Main Entry Point — `modules/disk/guardian.py`

```python
import yaml
import threading
from pathlib import Path

from .watcher import InotifyWatcher
from .usage_poller import UsagePoller
from .integrity import IntegrityChecker
from .backup import BackupManager

CONFIG_FILE = "config.yaml"


def load_config() -> dict:
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f)


class DiskGuardian:
    def __init__(self):
        self.config = load_config()
        disk_cfg = self.config.get("disk", {})
        global_cfg = self.config.get("global", {})

        self.backup_manager = BackupManager(
            backup_root="backups/disk",
            retention_days=global_cfg.get("backup_retention_days", 7),
        )

        self.watcher = InotifyWatcher(
            watch_paths=disk_cfg.get("watch_paths", ["/home/ec2-user"]),
            exclude_patterns=disk_cfg.get("exclude_patterns", []),
            backup_manager=self.backup_manager,
            config=self.config,
        )

        usage_cfg = disk_cfg.get("usage_alerts", {})
        self.usage_poller = UsagePoller(
            paths=disk_cfg.get("watch_paths", ["/home/ec2-user"]),
            warning_pct=usage_cfg.get("warning_pct", 75),
            critical_pct=usage_cfg.get("critical_pct", 90),
            interval_seconds=usage_cfg.get("poll_interval_seconds", 60),
        )

        integrity_cfg = disk_cfg.get("integrity", {})
        self.integrity_checker = IntegrityChecker(
            watch_files=integrity_cfg.get("watch_files", []),
        ) if integrity_cfg.get("enabled") else None

    def start(self):
        self.usage_poller.start()

        if self.integrity_checker:
            self.integrity_checker.start()

        t = threading.Thread(target=self.watcher.run, daemon=True)
        t.start()

        print("[DiskGuardian] All subsystems running")
        t.join()
```

---

## CLI Commands

```bash
# Start disk monitoring only
python3 guardian.py start --disk

# Start with all modules
python3 guardian.py start --disk --db --email \
  --dsn "postgresql://user:pass@localhost:5432/mydb"

# Live dashboard
python3 guardian.py dashboard

# List recent backups
python3 guardian.py backups list

# Restore a specific backup
python3 guardian.py backups restore \
  --slot 2026-06-20_143022 \
  --path /home/ec2-user/project/important.py

# Prune backups older than retention days
python3 guardian.py backups prune

# Manually grant a permission
python3 guardian.py grant cursor disk /home/ec2-user/project/ \
  --action allow_always
```

---

## Dashboard — `dashboard.py` (disk section)

```python
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich import box
import shutil, json, os


def disk_panel(watch_paths: list[str], audit_log: str) -> Panel:
    usage_table = Table(box=box.SIMPLE, show_header=True,
                        header_style="bold dim", padding=(0, 1))
    usage_table.add_column("Mount", width=24)
    usage_table.add_column("Used %", width=8)
    usage_table.add_column("Free", width=10)
    usage_table.add_column("Total", width=10)

    for path in watch_paths:
        try:
            u = shutil.disk_usage(path)
            pct = u.used / u.total * 100
            color = "red" if pct >= 90 else "yellow" if pct >= 75 else "green"
            usage_table.add_row(
                path,
                f"[{color}]{pct:.1f}%[/{color}]",
                f"{u.free / 1024**3:.1f} GB",
                f"{u.total / 1024**3:.1f} GB",
            )
        except FileNotFoundError:
            usage_table.add_row(path, "N/A", "-", "-")

    return Panel(usage_table, title="[bold]Disk Usage[/bold]", border_style="blue")


def recent_disk_events(audit_log: str, n: int = 8) -> Panel:
    events = []
    if os.path.exists(audit_log):
        with open(audit_log) as f:
            lines = f.readlines()
        for line in lines[-n:]:
            try:
                e = json.loads(line.strip())
                if "disk" in e.get("event", ""):
                    events.append(e)
            except Exception:
                pass

    table = Table(box=box.SIMPLE, show_header=True,
                  header_style="bold dim", padding=(0, 1))
    table.add_column("Time", width=8)
    table.add_column("Event", width=18)
    table.add_column("Result", width=12)
    table.add_column("Target", width=36)
    table.add_column("Program", width=14)

    for e in reversed(events):
        ts = (e.get("timestamp", "")[-8:-3] or "?")
        evt = e.get("event", "?")
        result = e.get("result", "—")
        color = {"allow": "green", "deny": "red",
                 "timeout": "yellow"}.get(result, "white")
        table.add_row(
            ts, evt, f"[{color}]{result}[/{color}]",
            (e.get("target") or "?")[:34],
            e.get("program", "?"),
        )

    return Panel(table, title="[bold]Recent Disk Events[/bold]",
                 border_style="blue")
```

---

## Decision Matrix

| Scenario | Result |
|---|---|
| Single delete, authorized path, ≤ 3 files | Silent allow |
| Single delete, authorized path, > 3 files | **Bulk warning — re-confirm** |
| Any delete, unauthorized path | **Intercept — wait for human** |
| Any operation by unknown program | **Auto-deny** |
| File overwrite on watched path | **Backup + confirm** |
| Disk usage ≥ 75 % | Warning log |
| Disk usage ≥ 90 % | **Critical alert** |
| Integrity hash mismatch | **Alert + confirm** |
| Confirmation timeout (30 s) | **Auto-deny** |

---

## Installation

```bash
# System packages
sudo dnf install -y python3 python3-pip util-linux psmisc

# Python packages
pip3 install inotify-simple rich pyyaml click

# Create directory tree
mkdir -p ~/ai-guardian/{modules/disk,confirm,backups/disk}
cd ~/ai-guardian

# Start monitoring
python3 guardian.py start --disk
```

---

## Audit Log Format

Every event appends one JSON line to `audit.log`:

```jsonl
{"timestamp":"2026-06-20T14:30:22.413","event":"disk_denied","action":"delete","target":"/home/ec2-user/project/main.py","program":"cursor"}
{"timestamp":"2026-06-20T14:30:45.001","event":"disk_decision","result":"allow_once","action":"overwrite","target":"/home/ec2-user/project/config.py","program":"claude-code"}
{"timestamp":"2026-06-20T14:31:00.777","event":"disk_usage_alert","level":"warning","path":"/home/ec2-user","used_pct":76.3,"free_gb":12.4}
{"timestamp":"2026-06-20T14:31:55.321","event":"integrity_violation","path":"/etc/passwd","old_hash":"a3f2b1...","new_hash":"c9d4e2..."}
```

---

---

## Telegram Confirmation Gate

### How It Works

```
fanotify holds the syscall (kernel blocks the operation)
         │
         ▼
  TelegramGate.ask(op)
         │
         ├─── bot.send_message() ──► user's phone
         │         inline buttons: ✅ Allow Once | 🔒 Always Allow | ❌ Deny
         │
         └─── asyncio.wait_for(future, timeout=30)
                    │
              user taps button ──► callback_query ──► future.set_result()
                    │                                        │
                    │◄───────────────────────────────────────┘
                    ▼
         fanotify write FAN_ALLOW / FAN_DENY
                    │
         operation proceeds or is blocked
```

The Telegram message looks like this on the user's phone:

```
⚠️ AI Guardian — Operation Intercepted

Action:   DELETE
Path:     /home/ec2-user/project/main.py
Program:  claude-code (PID 3821)
Backup:   ✓ saved

Auto-deny in 30s if no response

[ ✅ Allow Once ]  [ 🔒 Always Allow ]
[         ❌ Deny              ]
```

---

### Step 1 — Create the Telegram Bot

```
1. Open Telegram, search @BotFather
2. Send: /newbot
3. Follow prompts → copy the bot token
4. Send any message to your new bot
5. Open: https://api.telegram.org/bot<TOKEN>/getUpdates
   → find "chat": {"id": 123456789}  ← this is your chat_id
```

Then fill `config.yaml`:

```yaml
telegram:
  bot_token: "7123456789:AAGxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  chat_id: "123456789"
```

---

### Step 2 — `confirm/telegram.py`

```python
# confirm/telegram.py
import asyncio
import threading
import uuid
from typing import Optional

from telegram import Bot, InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import Application, CallbackQueryHandler, ContextTypes


class TelegramGate:
    """
    Sends an inline-keyboard message and blocks until the user taps a button
    (or the timeout expires). Thread-safe: can be called from any thread.
    """

    def __init__(self, bot_token: str, chat_id: str):
        self.chat_id = chat_id
        self._pending: dict[str, asyncio.Future] = {}
        self._loop = asyncio.new_event_loop()
        self._app: Optional[Application] = None

        # Run the event loop in a dedicated background thread
        t = threading.Thread(target=self._run_loop, daemon=True)
        t.start()

        # Block until the bot is connected
        init_done = threading.Event()
        asyncio.run_coroutine_threadsafe(
            self._start(bot_token, init_done), self._loop
        )
        init_done.wait(timeout=15)
        print("[TelegramGate] Bot connected")

    # ------------------------------------------------------------------ #
    #  Internal async machinery                                           #
    # ------------------------------------------------------------------ #

    def _run_loop(self):
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    async def _start(self, bot_token: str, ready: threading.Event):
        self._app = (
            Application.builder()
            .token(bot_token)
            .build()
        )
        self._app.add_handler(CallbackQueryHandler(self._on_button))
        await self._app.initialize()
        await self._app.start()
        await self._app.updater.start_polling(drop_pending_updates=True)
        ready.set()

    async def _on_button(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()

        # data format: "<op_id>:<decision>"
        op_id, decision = query.data.rsplit(":", 1)
        future = self._pending.pop(op_id, None)
        if future and not future.done():
            future.set_result(decision)

        label = {
            "allow_once":    "✅ Allowed once",
            "allow_always":  "🔒 Always allowed",
            "deny":          "❌ Denied",
        }.get(decision, decision)
        await query.edit_message_text(
            query.message.text + f"\n\n<b>→ {label}</b>",
            parse_mode="HTML",
        )

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def ask(self, op: dict, timeout: int = 30) -> str:
        """
        Block the calling thread until the user responds or timeout expires.
        Returns: allow_once | allow_always | deny | timeout
        """
        future = asyncio.run_coroutine_threadsafe(
            self._send_and_wait(op, timeout), self._loop
        )
        try:
            return future.result(timeout=timeout + 5)
        except Exception:
            return "deny"

    async def _send_and_wait(self, op: dict, timeout: int) -> str:
        op_id = uuid.uuid4().hex[:8]
        future: asyncio.Future = self._loop.create_future()
        self._pending[op_id] = future

        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton(
                    "✅ Allow Once", callback_data=f"{op_id}:allow_once"
                ),
                InlineKeyboardButton(
                    "🔒 Always Allow", callback_data=f"{op_id}:allow_always"
                ),
            ],
            [
                InlineKeyboardButton(
                    "❌ Deny", callback_data=f"{op_id}:deny"
                ),
            ],
        ])

        await self._app.bot.send_message(
            chat_id=self.chat_id,
            text=self._format(op, timeout),
            reply_markup=keyboard,
            parse_mode="HTML",
        )

        try:
            return await asyncio.wait_for(
                asyncio.shield(future), timeout=timeout
            )
        except asyncio.TimeoutError:
            self._pending.pop(op_id, None)
            await self._app.bot.send_message(
                chat_id=self.chat_id,
                text="⏱ <b>Timeout — operation auto-denied.</b>",
                parse_mode="HTML",
            )
            return "deny"

    @staticmethod
    def _format(op: dict, timeout: int) -> str:
        lines = ["⚠️ <b>AI Guardian — Operation Intercepted</b>\n"]
        for key, val in op.get("details", {}).items():
            lines.append(f"<b>{key}:</b>  <code>{val}</code>")
        if op.get("backup_path"):
            lines.append("\n✓ Backup saved")
        lines.append(f"\n<i>Auto-deny in {timeout}s if no response</i>")
        return "\n".join(lines)
```

---

### Step 3 — fanotify Watcher — `modules/disk/watcher_fanotify.py`

fanotify runs at the kernel level. The file operation is **suspended** in the kernel until the guardian writes `FAN_ALLOW` or `FAN_DENY` back to the fanotify fd.

> **Honest note on what fanotify can and cannot block on kernel 6.1:**
>
> | Operation | Blockable? | How |
> |---|---|---|
> | File open for write (overwrite) | ✅ Yes | `FAN_OPEN_PERM` |
> | `unlink()` / `rm` (delete) | ⚠️ Notification only | `FAN_DELETE` — can't block, but instant backup + restore |
> | `rename()` / `mv` | ⚠️ Notification only | `FAN_RENAME` |
>
> True delete blocking requires eBPF LSM hooks (`bpf_lsm_inode_unlink`), which we cover in a later section.

```python
# modules/disk/watcher_fanotify.py
import ctypes
import ctypes.util
import os
import struct
import threading
from pathlib import Path

from .backup import BackupManager
from permissions import check_permission, log_audit

# ── fanotify constants (kernel 6.1) ───────────────────────────────────
FAN_CLOEXEC         = 0x00000001
FAN_CLASS_CONTENT   = 0x00000004

FAN_OPEN_PERM       = 0x00010000   # BLOCKS: open() for writing
FAN_CLOSE_WRITE     = 0x00000008   # notify: file written and closed
FAN_DELETE          = 0x00000200   # notify: file deleted
FAN_RENAME          = 0x10000000   # notify: file renamed

FAN_MARK_ADD        = 0x00000001
FAN_MARK_FILESYSTEM = 0x00000100

FAN_ALLOW = 0x01
FAN_DENY  = 0x02

AT_FDCWD = -100

# ── C structures ──────────────────────────────────────────────────────

class _EventMeta(ctypes.Structure):
    _fields_ = [
        ("event_len",    ctypes.c_uint32),
        ("vers",         ctypes.c_uint8),
        ("reserved",     ctypes.c_uint8),
        ("metadata_len", ctypes.c_uint16),
        ("mask",         ctypes.c_uint64),
        ("fd",           ctypes.c_int32),
        ("pid",          ctypes.c_int32),
    ]

class _Response(ctypes.Structure):
    _fields_ = [
        ("fd",       ctypes.c_int32),
        ("response", ctypes.c_uint32),
    ]

_libc = ctypes.CDLL(None, use_errno=True)


def _fanotify_init(flags: int, event_f_flags: int) -> int:
    fd = _libc.syscall(300, ctypes.c_uint(flags),
                       ctypes.c_uint(event_f_flags))
    if fd < 0:
        raise OSError(ctypes.get_errno(), "fanotify_init failed")
    return fd


def _fanotify_mark(fanotify_fd: int, flags: int, mask: int,
                   dirfd: int, path: bytes):
    ret = _libc.syscall(301,
                        ctypes.c_int(fanotify_fd),
                        ctypes.c_uint(flags),
                        ctypes.c_uint64(mask),
                        ctypes.c_int(dirfd),
                        ctypes.c_char_p(path))
    if ret < 0:
        raise OSError(ctypes.get_errno(), f"fanotify_mark failed: {path}")


# ── Watcher ───────────────────────────────────────────────────────────

class FanotifyWatcher:
    """
    Intercepts file opens-for-write (blocking) and notifies on deletes.
    Confirmation is delegated to the injected `confirm_gate`.
    """

    MASK = FAN_OPEN_PERM | FAN_CLOSE_WRITE | FAN_DELETE | FAN_RENAME
    META_SIZE = ctypes.sizeof(_EventMeta)

    def __init__(self, watch_paths: list[str], backup_manager: BackupManager,
                 confirm_gate, config: dict):
        self.backup = backup_manager
        self.gate = confirm_gate        # TelegramGate instance
        self.config = config
        self._fan_fd = _fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC,
                                      os.O_RDWR | os.O_LARGEFILE)

        for path in watch_paths:
            _fanotify_mark(
                self._fan_fd,
                FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                self.MASK,
                AT_FDCWD,
                path.encode(),
            )

    def run(self):
        print("[FanotifyWatcher] Started — kernel-level file interception active")
        buf = bytearray(4096)
        while True:
            n = os.read(self._fan_fd, len(buf))
            offset = 0
            while offset < len(n):
                meta = _EventMeta.from_buffer_copy(n, offset)
                self._dispatch(meta)
                offset += meta.event_len

    def _dispatch(self, meta: _EventMeta):
        path = self._fd_to_path(meta.fd)
        program = self._pid_to_name(meta.pid)
        is_perm = bool(meta.mask & FAN_OPEN_PERM)

        if meta.mask & FAN_DELETE or meta.mask & FAN_RENAME:
            # Notification only — backup then confirm asynchronously
            threading.Thread(
                target=self._handle_notify,
                args=(path, "delete", program, str(meta.pid)),
                daemon=True,
            ).start()
            # Cannot block delete via fanotify — fd is -1
            return

        # FAN_OPEN_PERM: we CAN block the operation
        permission = check_permission(program, "disk", path, count=1)

        if permission == "allow_always":
            log_audit({"event": "disk_allowed", "action": "open_write",
                       "target": path, "program": program})
            self._respond(meta.fd, FAN_ALLOW)
            return

        if permission == "deny":
            log_audit({"event": "disk_denied", "action": "open_write",
                       "target": path, "program": program})
            self._respond(meta.fd, FAN_DENY)
            return

        # ask / bulk_warn: backup first, then ask via Telegram (still blocking)
        backup_path = self.backup.snapshot(path)
        op = {
            "resource_type": "disk",
            "program": program,
            "pid": str(meta.pid),
            "backup_path": backup_path,
            "details": {
                "Action":  "OPEN FOR WRITE (blocked)",
                "Path":    path,
                "Program": f"{program} (PID {meta.pid})",
            },
        }
        if permission == "bulk_warn":
            op["details"]["Warning"] = "Authorized path — bulk threshold exceeded"

        timeout = self.config["global"].get("timeout_seconds", 30)
        result = self.gate.ask(op, timeout=timeout)   # blocks here

        log_audit({
            "event": "disk_decision", "result": result,
            "action": "open_write", "target": path, "program": program,
        })

        fan_resp = FAN_ALLOW if result in ("allow_once", "allow_always") else FAN_DENY
        self._respond(meta.fd, fan_resp)

        if result == "allow_always":
            from permissions import grant_permission
            grant_permission(program, "disk", path, "allow_always")

    def _handle_notify(self, path: str, action: str,
                       program: str, pid: str):
        """For DELETE: backup immediately (file may still exist briefly), then notify."""
        backup_path = self.backup.snapshot(path)
        op = {
            "resource_type": "disk",
            "program": program,
            "pid": pid,
            "backup_path": backup_path,
            "details": {
                "Action":  "DELETE (notification — cannot block)",
                "Path":    path,
                "Program": f"{program} (PID {pid})",
                "Note":    "File already deleted. Restore from backup if denied.",
            },
        }
        timeout = self.config["global"].get("timeout_seconds", 30)
        result = self.gate.ask(op, timeout=timeout)

        log_audit({
            "event": "disk_decision", "result": result,
            "action": action, "target": path, "program": program,
        })

        if result == "deny" and backup_path:
            self.backup.restore(backup_path, path)
            print(f"[FanotifyWatcher] Restored {path} from backup")

    def _respond(self, event_fd: int, response: int):
        resp = _Response(fd=event_fd, response=response)
        os.write(self._fan_fd, bytes(resp))
        if event_fd >= 0:
            os.close(event_fd)

    @staticmethod
    def _fd_to_path(fd: int) -> str:
        if fd < 0:
            return "unknown"
        try:
            return os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            return "unknown"

    @staticmethod
    def _pid_to_name(pid: int) -> str:
        try:
            return Path(f"/proc/{pid}/comm").read_text().strip()
        except OSError:
            return "unknown"
```

---

### Step 4 — Updated `modules/disk/guardian.py`

```python
# modules/disk/guardian.py
import yaml
import threading
from pathlib import Path

from .watcher_fanotify import FanotifyWatcher
from .usage_poller import UsagePoller
from .integrity import IntegrityChecker
from .backup import BackupManager
from confirm.telegram import TelegramGate

CONFIG_FILE = "config.yaml"


def load_config() -> dict:
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f)


class DiskGuardian:
    def __init__(self):
        self.config = load_config()
        disk_cfg   = self.config.get("disk", {})
        global_cfg = self.config.get("global", {})
        tg_cfg     = self.config.get("telegram", {})

        # Confirmation gate — Telegram
        self.gate = TelegramGate(
            bot_token=tg_cfg["bot_token"],
            chat_id=str(tg_cfg["chat_id"]),
        )

        # Backup manager
        self.backup = BackupManager(
            backup_root="backups/disk",
            retention_days=global_cfg.get("backup_retention_days", 7),
        )

        # fanotify watcher (kernel-level interception)
        self.watcher = FanotifyWatcher(
            watch_paths=disk_cfg.get("watch_paths", ["/home/ec2-user"]),
            backup_manager=self.backup,
            confirm_gate=self.gate,
            config=self.config,
        )

        # Disk usage poller
        usage_cfg = disk_cfg.get("usage_alerts", {})
        self.usage_poller = UsagePoller(
            paths=disk_cfg.get("watch_paths", []),
            warning_pct=usage_cfg.get("warning_pct", 75),
            critical_pct=usage_cfg.get("critical_pct", 90),
            interval_seconds=usage_cfg.get("poll_interval_seconds", 60),
        )

        # File integrity checker
        integrity_cfg = disk_cfg.get("integrity", {})
        self.integrity = IntegrityChecker(
            watch_files=integrity_cfg.get("watch_files", []),
        ) if integrity_cfg.get("enabled") else None

    def start(self):
        self.usage_poller.start()
        if self.integrity:
            self.integrity.start()

        t = threading.Thread(target=self.watcher.run, daemon=True)
        t.start()
        print("[DiskGuardian] All subsystems online")
        t.join()
```

---

### Step 5 — Install Dependencies

```bash
pip3 install python-telegram-bot~=21.0 inotify-simple rich pyyaml click
```

> `python-telegram-bot` v21+ is async-native. Do not mix with v13.

---

### End-to-End Flow Summary

```
1. AI agent calls unlink("/home/ec2-user/project/main.py")
        │
2. Kernel delivers FAN_DELETE event to guardian (non-blocking)
        │
3. BackupManager.snapshot(path)  →  backups/disk/2026-06-20_143055/...
        │
4. TelegramGate.ask(op) sends message to user's phone:
   ┌────────────────────────────────────┐
   │ ⚠️ AI Guardian — Operation         │
   │ Action:  DELETE                    │
   │ Path:    .../main.py               │
   │ Program: claude-code (PID 3821)    │
   │ Backup:  ✓ saved                   │
   │                                    │
   │ [✅ Allow Once] [🔒 Always Allow]  │
   │ [         ❌ Deny              ]   │
   └────────────────────────────────────┘
        │
5. User taps ❌ Deny (or 30s elapses → auto-deny)
        │
6. Guardian calls BackupManager.restore() → file reappears
        │
7. audit.log entry written
```

---

*AI Guardian Disk Monitor · OS-level protection · humans hold the final veto*
