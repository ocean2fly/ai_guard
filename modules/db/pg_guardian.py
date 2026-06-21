import threading
from pathlib import Path

import yaml

from confirm.telegram_gate import TelegramGate
from modules.db.ebpf_pg_blocker import EbpfPgBlocker

BASE = Path(__file__).parent.parent.parent
CONFIG_FILE = BASE / "config.yaml"


def load_config() -> dict:
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f)


class PgGuardian:
    def __init__(self):
        cfg = load_config()
        db_cfg     = cfg.get("db", {})
        global_cfg = cfg.get("global", {})
        tg_cfg     = cfg.get("telegram", {})

        if not db_cfg.get("enabled", True):
            raise RuntimeError("DB Guardian is disabled in config.yaml (db.enabled: false)")

        self.gate = TelegramGate(
            bot_token=tg_cfg["bot_token"],
            chat_id=str(tg_cfg["chat_id"]),
            timeout_seconds=db_cfg.get("timeout_seconds",
                                       global_cfg.get("timeout_seconds", 120)),
        )

        self.blocker = EbpfPgBlocker(gate=self.gate, config=cfg)

    def start(self):
        self.gate.notify(
            "🗄 <b>DB Guardian started</b>\n"
            "PostgreSQL query interception is active (USDT/query__start).\n"
            "DROP, TRUNCATE, DELETE, and ALTER TABLE operations will be confirmed here."
        )
        try:
            self.blocker.run()
        except KeyboardInterrupt:
            pass
        finally:
            self.blocker.release_all()
            self.gate.notify("🗄 DB Guardian stopped.")
