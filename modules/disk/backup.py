import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional


class BackupManager:
    def __init__(self, backup_root: str, retention_days: int = 7):
        self.root = Path(backup_root)
        self.retention_days = retention_days
        self.root.mkdir(parents=True, exist_ok=True)

    def snapshot(self, path: str) -> Optional[str]:
        src = Path(path)
        if not src.exists():
            return None
        ts = datetime.now().strftime("%Y-%m-%d_%H%M%S_%f")[:22]
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
            print(f"[Backup] snapshot failed for {path}: {e}")
            return None

    def restore(self, backup_path: str, original_path: str) -> bool:
        src = Path(backup_path)
        dst = Path(original_path)
        if not src.exists():
            return False
        try:
            dst.parent.mkdir(parents=True, exist_ok=True)
            if src.is_dir():
                shutil.copytree(src, dst, dirs_exist_ok=True)
            else:
                shutil.copy2(src, dst)
            return True
        except Exception as e:
            print(f"[Backup] restore failed: {e}")
            return False

    def prune(self):
        cutoff = datetime.now() - timedelta(days=self.retention_days)
        pruned = 0
        for slot in self.root.iterdir():
            try:
                slot_dt = datetime.strptime(slot.name[:19], "%Y-%m-%d_%H%M%S")
                if slot_dt < cutoff:
                    shutil.rmtree(slot)
                    pruned += 1
            except (ValueError, NotADirectoryError):
                pass
        if pruned:
            print(f"[Backup] Pruned {pruned} old slot(s)")
        return pruned

    def list_slots(self) -> list[dict]:
        slots = []
        for slot in sorted(self.root.iterdir(), reverse=True):
            if not slot.is_dir():
                continue
            size = sum(f.stat().st_size for f in slot.rglob("*") if f.is_file())
            slots.append({
                "slot": slot.name,
                "path": str(slot),
                "size_mb": round(size / 1024 / 1024, 2),
            })
        return slots
