#!/usr/bin/env python3
import sys
import threading
from pathlib import Path

# Make project root importable from any cwd
sys.path.insert(0, str(Path(__file__).parent))

import click
import json


@click.group()
def cli():
    """AI Guardian — disk + DB operation watchdog"""
    pass


@cli.command()
def start():
    """Start disk monitoring only (inotify + Telegram)"""
    from modules.disk.guardian import DiskGuardian
    g = DiskGuardian()
    try:
        g.start()
    except KeyboardInterrupt:
        click.echo("\n[Guardian] Stopped")


@cli.command(name="db-start")
def db_start():
    """Start DB Guardian only (PostgreSQL USDT, uses own Telegram connection)"""
    from modules.db.pg_guardian import PgGuardian
    g = PgGuardian()
    try:
        g.start()
    except KeyboardInterrupt:
        click.echo("\n[DB Guardian] Stopped")


@cli.command(name="start-all")
def start_all():
    """Start Disk + DB + Email Guardian together, sharing one Telegram bot connection"""
    import yaml
    from confirm.telegram_gate import TelegramGate
    from modules.disk.guardian import DiskGuardian
    from modules.db.ebpf_pg_blocker import EbpfPgBlocker
    from modules.email.ebpf_email_blocker import EbpfEmailBlocker

    cfg_path = Path(__file__).parent / "config.yaml"
    with open(cfg_path) as f:
        cfg = yaml.safe_load(f)

    tg_cfg     = cfg.get("telegram", {})
    global_cfg = cfg.get("global", {})
    db_cfg     = cfg.get("db", {})
    email_cfg  = cfg.get("email", {})

    gate = TelegramGate(
        bot_token=tg_cfg["bot_token"],
        chat_id=str(tg_cfg["chat_id"]),
        timeout_seconds=global_cfg.get("timeout_seconds", 1800),
    )

    # Build disk guardian with the shared gate
    disk = DiskGuardian(gate=gate)

    stop_event = threading.Event()
    errors: list[Exception] = []

    def run_disk():
        try:
            disk.start()
        except Exception as exc:
            errors.append(exc)
            stop_event.set()

    disk_thread = threading.Thread(target=run_disk, daemon=True, name="disk-guardian")
    disk_thread.start()

    # Start DB guardian if enabled
    db_thread = None
    if db_cfg.get("enabled", False):
        db_blocker = EbpfPgBlocker(gate=gate, config=cfg)

        def run_db():
            try:
                db_blocker.run()
            except Exception as exc:
                errors.append(exc)
                stop_event.set()

        db_thread = threading.Thread(target=run_db, daemon=True, name="db-guardian")
        db_thread.start()
        print("[start-all] DB Guardian started")

    # Start Email guardian if enabled
    email_thread = None
    if email_cfg.get("enabled", False):
        email_blocker = EbpfEmailBlocker(gate=gate, config=cfg)

        def run_email():
            try:
                email_blocker.run()
            except Exception as exc:
                errors.append(exc)
                stop_event.set()

        email_thread = threading.Thread(target=run_email, daemon=True, name="email-guardian")
        email_thread.start()
        print("[start-all] Email Guardian started")

    modules_on = ["Disk"]
    if db_cfg.get("enabled"): modules_on.append("DB")
    if email_cfg.get("enabled"): modules_on.append("Email")
    print(f"[start-all] Running: {' + '.join(modules_on)} — Ctrl-C to stop")
    try:
        stop_event.wait()
    except KeyboardInterrupt:
        pass

    if errors:
        for e in errors:
            click.echo(f"[Guardian error] {e}")
    click.echo("\n[Guardian] Stopped")


@cli.command()
def backups():
    """List backup slots"""
    from modules.disk.backup import BackupManager
    bm = BackupManager("backups/disk")
    slots = bm.list_slots()
    if not slots:
        click.echo("No backups found.")
        return
    click.echo(f"{'Slot':<25}  {'Size (MB)':>10}  Path")
    click.echo("-" * 70)
    for s in slots:
        click.echo(f"{s['slot']:<25}  {s['size_mb']:>10.2f}  {s['path']}")


@cli.command()
@click.argument("backup_path")
@click.argument("original_path")
def restore(backup_path, original_path):
    """Restore a file from a backup slot"""
    from modules.disk.backup import BackupManager
    bm = BackupManager("backups/disk")
    if bm.restore(backup_path, original_path):
        click.echo(f"[✓] Restored {original_path}")
    else:
        click.echo(f"[✗] Restore failed — backup not found at {backup_path}")


@cli.command()
@click.option("-n", default=20, help="Number of lines to show")
def log(n):
    """Show recent audit log entries"""
    log_path = Path("audit.log")
    if not log_path.exists():
        click.echo("No audit log yet.")
        return
    lines = log_path.read_text().splitlines()
    for line in lines[-n:]:
        try:
            e = json.loads(line)
            ts = e.get("timestamp", "?")[-12:]
            ev = e.get("event", "?")
            tg = e.get("target", e.get("path", "?"))
            rs = e.get("result", "")
            click.echo(f"{ts}  {ev:<28}  {rs:<14}  {tg}")
        except Exception:
            click.echo(line)


if __name__ == "__main__":
    cli()
