import fnmatch
import json
import yaml
from datetime import datetime
from pathlib import Path

CONFIG_FILE = Path(__file__).parent / "config.yaml"
AUDIT_LOG   = Path(__file__).parent / "audit.log"


def load_config() -> dict:
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f)


def log_audit(event: dict):
    event["timestamp"] = datetime.now().isoformat(timespec="milliseconds")
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(event) + "\n")


def check_permission(program: str, target: str, count: int = 1) -> str:
    """
    Returns: allow_always | ask | deny | bulk_warn
    """
    cfg = load_config()
    bulk_threshold = cfg["global"]["bulk_threshold"]
    programs = cfg.get("programs", {})
    prog = programs.get(program, programs.get("unknown", {}))
    rules = prog.get("disk", [])

    for rule in rules:
        pattern = rule.get("path", "*")
        if fnmatch.fnmatch(target, pattern) or target.startswith(pattern):
            action = rule.get("action", "ask")
            threshold = rule.get("bulk_threshold", bulk_threshold)
            if action == "allow_always" and count > threshold:
                return "bulk_warn"
            return action

    return "ask"


def grant_permission(program: str, target: str, action: str):
    cfg = load_config()
    if program not in cfg.setdefault("programs", {}):
        cfg["programs"][program] = {}
    rules = cfg["programs"][program].setdefault("disk", [])
    # Remove existing rule for same path to avoid duplicates
    rules[:] = [r for r in rules if r.get("path") != target]
    rules.insert(0, {"path": target, "action": action})
    with open(CONFIG_FILE, "w") as f:
        yaml.dump(cfg, f, default_flow_style=False, allow_unicode=True)
    log_audit({"event": "permission_granted", "program": program,
               "target": target, "action": action})
