import threading
from pathlib import Path

import yaml

from confirm.telegram_gate import TelegramGate
from modules.disk.backup import BackupManager
from modules.disk.ebpf_blocker import EbpfBlocker
from modules.disk.integrity import IntegrityChecker
from modules.disk.usage_poller import UsagePoller
from modules.disk.watcher import InotifyWatcher

BASE = Path(__file__).parent.parent.parent
CONFIG_FILE = BASE / "config.yaml"


def load_config() -> dict:
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f)


class DiskGuardian:
    def __init__(self, gate: TelegramGate = None):
        cfg = load_config()
        disk_cfg   = cfg.get("disk", {})
        global_cfg = cfg.get("global", {})
        tg_cfg     = cfg.get("telegram", {})

        if gate is not None:
            self.gate = gate
        else:
            self.gate = TelegramGate(
                bot_token=tg_cfg["bot_token"],
                chat_id=str(tg_cfg["chat_id"]),
                timeout_seconds=global_cfg.get("timeout_seconds", 30),
            )

        self.backup = BackupManager(
            backup_root=str(BASE / "backups" / "disk"),
            retention_days=global_cfg.get("backup_retention_days", 7),
        )

        watch_paths = disk_cfg.get("watch_paths", ["/home/ec2-user"])

        self.ebpf_blocker = EbpfBlocker(gate=self.gate, config=cfg)

        self.watcher = InotifyWatcher(
            watch_paths=watch_paths,
            exclude_patterns=disk_cfg.get("exclude_patterns", []),
            backup_manager=self.backup,
            ebpf_blocker=self.ebpf_blocker,
            config=cfg,
        )

        usage_cfg = disk_cfg.get("usage_alerts", {})
        self.poller = UsagePoller(
            paths=watch_paths,
            warning_pct=usage_cfg.get("warning_pct", 75),
            critical_pct=usage_cfg.get("critical_pct", 90),
            interval_seconds=usage_cfg.get("poll_interval_seconds", 60),
            gate=self.gate,
        )

        integrity_cfg = disk_cfg.get("integrity", {})
        if integrity_cfg.get("enabled"):
            self.integrity = IntegrityChecker(
                watch_files=integrity_cfg.get("watch_files", []),
                gate=self.gate,
            )
        else:
            self.integrity = None

        self.backup.prune()

    def start(self):
        # Pre-populate inode cache (home dir with exclusions, plus /tmp flat)
        self.ebpf_blocker.scan_paths(
            ["/home/ec2-user"],
            is_excluded=self.watcher._is_excluded,
        )
        self.ebpf_blocker.scan_paths(["/tmp"])

        self.poller.start()
        if self.integrity:
            self.integrity.start()

        # inotify watcher runs in a background thread
        t = threading.Thread(target=self.watcher.run, daemon=True)
        t.start()

        self.gate.notify(
            "🛡 <b>AI Guardian started (eBPF mode)</b>\n"
            "Disk monitoring is active — deletions are blocked at the kernel level.\n"
            "You will receive alerts here for any file deletion attempts."
        )

        # Block on the eBPF event loop
        self.ebpf_blocker.run()
