import hashlib
import threading
import time
from pathlib import Path
from typing import Optional

from permissions import log_audit


class IntegrityChecker:
    """Polls SHA-256 hashes of critical files and alerts on any change."""

    POLL_INTERVAL = 30  # seconds

    def __init__(self, watch_files: list[str], gate):
        self.gate = gate
        self._hashes: dict[str, str] = {}
        self._lock = threading.Lock()

        for f in watch_files:
            h = self._hash(Path(f))
            if h:
                self._hashes[f] = h

    def start(self):
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()
        print(f"[IntegrityChecker] Monitoring {len(self._hashes)} file(s)")

    def refresh(self, path: str):
        """Update baseline after an approved modification to a watched file."""
        h = self._hash(Path(path))
        with self._lock:
            if h:
                self._hashes[path] = h
            else:
                self._hashes.pop(path, None)

    def _loop(self):
        while True:
            time.sleep(self.POLL_INTERVAL)
            with self._lock:
                snapshot = dict(self._hashes)
            for path_str, old_hash in snapshot.items():
                self._check(path_str, old_hash)

    def _check(self, path_str: str, old_hash: str):
        new_hash = self._hash(Path(path_str))
        if new_hash is None:
            self.gate.notify(
                f"🔴 <b>Integrity Alert — FILE DELETED</b>\n"
                f"<b>Path:</b> <code>{path_str}</code>"
            )
            log_audit({"event": "integrity_violation", "type": "deleted",
                       "path": path_str})
            with self._lock:
                self._hashes.pop(path_str, None)
        elif new_hash != old_hash:
            self.gate.notify(
                f"🔴 <b>Integrity Alert — FILE MODIFIED</b>\n"
                f"<b>Path:</b> <code>{path_str}</code>\n"
                f"<b>Hash:</b> <code>{old_hash[:12]}…</code> → "
                f"<code>{new_hash[:12]}…</code>"
            )
            log_audit({"event": "integrity_violation", "type": "modified",
                       "path": path_str,
                       "old_hash": old_hash[:16], "new_hash": new_hash[:16]})
            with self._lock:
                self._hashes[path_str] = new_hash

    @staticmethod
    def _hash(path: Path) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (FileNotFoundError, PermissionError, IsADirectoryError):
            return None
