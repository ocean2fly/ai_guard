import fnmatch
import os
import threading

import inotify_simple

from modules.disk.backup import BackupManager

WATCH_FLAGS = (
    inotify_simple.flags.CLOSE_WRITE   # snapshot + inode cache update
    | inotify_simple.flags.CREATE        # watch new subdirs, cache new files
)


class InotifyWatcher:
    def __init__(self, watch_paths: list[str], exclude_patterns: list[str],
                 backup_manager: BackupManager, ebpf_blocker, config: dict):
        self.exclude = exclude_patterns
        self.backup = backup_manager
        self.blocker = ebpf_blocker
        self.config = config
        self._inotify = inotify_simple.INotify()
        self._wd_map: dict[int, str] = {}
        self._lock = threading.Lock()

        for p in watch_paths:
            self._add_recursive(p)

        print("[Watcher] Watch setup done — monitoring active")

    # ------------------------------------------------------------------ #
    #  Watch management                                                    #
    # ------------------------------------------------------------------ #

    def _add_recursive(self, root: str):
        if not os.path.exists(root) or self._is_excluded(root):
            return
        try:
            wd = self._inotify.add_watch(root, WATCH_FLAGS)
            with self._lock:
                self._wd_map[wd] = root
        except (PermissionError, FileNotFoundError):
            return
        if os.path.isdir(root):
            try:
                for entry in os.scandir(root):
                    if entry.is_dir(follow_symlinks=False):
                        self._add_recursive(entry.path)
            except PermissionError:
                pass

    def _is_excluded(self, path: str) -> bool:
        name = os.path.basename(path)
        for p in self.exclude:
            if p.startswith("/") and not any(c in p for c in ("*", "?")):
                if path == p or path.startswith(p.rstrip("/") + "/"):
                    return True
            elif fnmatch.fnmatch(name, p) or fnmatch.fnmatch(path, p):
                return True
        return False

    # ------------------------------------------------------------------ #
    #  Event loop                                                          #
    # ------------------------------------------------------------------ #

    def run(self):
        print("[Watcher] inotify event loop running")
        while True:
            for event in self._inotify.read():
                self._dispatch(event)

    def _dispatch(self, event):
        with self._lock:
            parent = self._wd_map.get(event.wd, "")
        if not parent or not event.name:
            return

        target = os.path.join(parent, event.name)
        if self._is_excluded(target):
            return

        flags = inotify_simple.flags.from_mask(event.mask)

        if inotify_simple.flags.CREATE in flags:
            if inotify_simple.flags.ISDIR in flags:
                threading.Thread(
                    target=self._add_recursive, args=(target,), daemon=True
                ).start()
            else:
                threading.Thread(
                    target=self.blocker.add_path, args=(target,), daemon=True
                ).start()
            return

        if inotify_simple.flags.CLOSE_WRITE in flags:
            threading.Thread(
                target=self.backup.snapshot, args=(target,), daemon=True
            ).start()
            threading.Thread(
                target=self.blocker.add_path, args=(target,), daemon=True
            ).start()
            return


