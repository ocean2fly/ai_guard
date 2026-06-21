import shutil
import threading
import time

from permissions import log_audit


class UsagePoller:
    def __init__(self, paths: list[str], warning_pct: int,
                 critical_pct: int, interval_seconds: int, gate):
        self.paths = paths
        self.warning_pct = warning_pct
        self.critical_pct = critical_pct
        self.interval = interval_seconds
        self.gate = gate
        self._last: dict[str, str] = {}

    def start(self):
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()

    def _loop(self):
        print("[UsagePoller] Started")
        while True:
            for path in self.paths:
                self._check(path)
            time.sleep(self.interval)

    def _check(self, path: str):
        try:
            u = shutil.disk_usage(path)
        except FileNotFoundError:
            return

        pct = u.used / u.total * 100
        level = None
        if pct >= self.critical_pct:
            level = "critical"
        elif pct >= self.warning_pct:
            level = "warning"

        if level and self._last.get(path) != level:
            self._last[path] = level
            free_gb = u.free / 1024 ** 3
            icon = "🔴" if level == "critical" else "🟡"
            msg = (
                f"{icon} <b>Disk {level.upper()}</b>\n"
                f"<b>Path:</b> <code>{path}</code>\n"
                f"<b>Used:</b> {pct:.1f}%   "
                f"<b>Free:</b> {free_gb:.1f} GB"
            )
            self.gate.notify(msg)
            log_audit({"event": "disk_usage_alert", "level": level,
                       "path": path, "used_pct": round(pct, 1),
                       "free_gb": round(free_gb, 2)})
        elif not level:
            self._last.pop(path, None)
