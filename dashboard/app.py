"""AI Guardian — Web Dashboard"""
from __future__ import annotations

import asyncio
import json
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import yaml
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

BASE      = Path(__file__).parent.parent
DASHBOARD = Path(__file__).parent
AUDIT     = BASE / "audit.log"
CONFIG    = BASE / "config.yaml"

app = FastAPI(title="AI Guardian")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])
templates = Jinja2Templates(directory=str(DASHBOARD / "templates"))


# ── helpers ──────────────────────────────────────────────────────────────────

def load_cfg() -> dict:
    with open(CONFIG) as f:
        return yaml.safe_load(f)


def save_cfg(cfg: dict):
    with open(CONFIG, "w") as f:
        yaml.dump(cfg, f, default_flow_style=False, allow_unicode=True)


def _badge(e: dict) -> dict:
    ev  = e.get("event", "")
    res = e.get("result", e.get("permission", ""))
    # DB
    if ev == "db_intercepted":
        risk = e.get("risk", "")
        return {"cls": "badge-red" if risk == "high" else "badge-yellow",
                "label": f"db {e.get('label','intercept')}"}
    if ev in ("db_decision", "db_permission_granted"):
        if res in ("allow_once", "allow_always", "allow"):
            return {"cls": "badge-green", "label": res}
        return {"cls": "badge-red", "label": "denied"}
    if ev == "db_passthrough":
        return {"cls": "badge-gray", "label": "pass"}
    if ev == "db_denied":
        return {"cls": "badge-red", "label": "denied"}
    # Email
    if ev == "email_delete_intercepted":
        return {"cls": "badge-violet", "label": "email delete"}
    if ev == "email_delete_decision":
        if res in ("allow_once", "allow_always"):
            return {"cls": "badge-green", "label": "allowed"}
        return {"cls": "badge-red", "label": "blocked"}
    # Disk
    if "allowed" in ev or res in ("allow_once", "allow_always", "allow_dir"):
        return {"cls": "badge-green", "label": res or "allowed"}
    if "denied" in ev or res == "deny":
        return {"cls": "badge-red", "label": "denied"}
    if ev == "ebpf_unlink_intercepted":
        return {"cls": "badge-yellow", "label": "intercepted"}
    return {"cls": "badge-gray", "label": ev.replace("ebpf_", "").replace("_", " ")}


def _path(e: dict) -> str:
    ev = e.get("event", "")
    if ev.startswith("db_"):
        sql = e.get("sql", "")
        if sql:
            return sql[:80] + ("…" if len(sql) > 80 else "")
        return e.get("label", "") or "—"
    if ev.startswith("email_delete_"):
        op   = e.get("operation", "DELETE")
        ids  = e.get("message_ids", "")
        subj = e.get("subject", "")
        frm  = e.get("from_addr", "")
        date = e.get("date", "")
        parts = []
        if subj: parts.append(f'"{subj}"')
        if frm:  parts.append(f"from:{frm}")
        if date: parts.append(date[:16])
        if not parts: parts = [op, f"msg:{ids}" if ids else ""]
        return "  ".join(p for p in parts if p) or "—"
    return e.get("path") or e.get("target") or e.get("directory") or "—"


def _enrich(events: list[dict]) -> list[dict]:
    for e in events:
        e["_badge"] = _badge(e)
        e["_path"]  = _path(e)
        ts = e.get("timestamp", "")
        e["_time"]  = ts[11:19] if len(ts) >= 19 else ts
    return events


def read_events(limit=200, program=None, decision=None, search=None,
                source=None) -> list[dict]:
    """
    source: None=all, 'disk'=ebpf_/disk_ events, 'db'=db_ events, 'email'=email_delete_ events
    """
    results: list[dict] = []
    try:
        lines = AUDIT.read_text().splitlines()
    except FileNotFoundError:
        return []
    for line in reversed(lines[-5000:]):
        try:
            e = json.loads(line)
        except Exception:
            continue
        ev = e.get("event", "")
        if source == "db"    and not ev.startswith("db_"):
            continue
        if source == "email" and ev != "email_delete_decision":
            continue
        if source == "disk"  and (ev.startswith("db_") or ev.startswith("email_")):
            continue
        if program and e.get("program", e.get("comm", "")) != program:
            continue
        if decision:
            combined = e.get("result", "") + e.get("permission", "") + e.get("action", "")
            if decision not in combined:
                continue
        if search:
            hay = (_path(e) + e.get("chain", "") + e.get("program", "")
                   + e.get("comm", "")).lower()
            if search.lower() not in hay:
                continue
        results.append(e)
        if len(results) >= limit:
            break
    return _enrich(results)


def stats_24h() -> dict:
    cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
    s: dict[str, int] = defaultdict(int)
    try:
        for line in AUDIT.read_text().splitlines():
            try:
                e = json.loads(line)
                if e.get("timestamp", "") < cutoff:
                    continue
                s["total"] += 1
                ev  = e.get("event", "")
                res = e.get("result", e.get("permission", ""))
                if ev == "ebpf_unlink_intercepted":
                    s["intercepted"] += 1
                if ev == "db_intercepted":
                    s["db_intercepted"] += 1
                if ev == "email_delete_intercepted":
                    s["email_intercepted"] += 1
                if "allowed" in ev or res in ("allow_once", "allow_always", "allow_dir"):
                    s["allowed"] += 1
                if "denied" in ev or res == "deny":
                    s["denied"] += 1
            except Exception:
                pass
    except FileNotFoundError:
        pass
    return dict(s)


def service_status() -> str:
    try:
        r = subprocess.run(["systemctl", "is-active", "aigate"],
                           capture_output=True, text=True, timeout=3)
        return r.stdout.strip()
    except Exception:
        return "unknown"


def guardian_statuses(cfg: dict) -> dict:
    """Return per-guardian status dict (uses single aigate service for all three)."""
    svc = service_status()
    active = (svc == "active")
    return {
        "disk":  "active" if active else svc,
        "db":    "active" if (active and cfg.get("db",    {}).get("enabled", False)) else "inactive",
        "email": "active" if (active and cfg.get("email", {}).get("enabled", False)) else "inactive",
        "svc":   svc,
    }


def all_programs() -> list[str]:
    seen: set[str] = set()
    try:
        for line in AUDIT.read_text().splitlines()[-3000:]:
            try:
                p = json.loads(line).get("program")
                if p:
                    seen.add(p)
            except Exception:
                pass
    except FileNotFoundError:
        pass
    return sorted(seen)


# ── pages ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def landing(request: Request):
    return templates.TemplateResponse("landing.html", {"request": request})


@app.get("/overview", response_class=HTMLResponse)
async def overview(request: Request):
    cfg = load_cfg()
    return templates.TemplateResponse("overview.html", {
        "request": request, "active": "overview",
        "stats":   stats_24h(),
        "events":  read_events(20),
        "gst":     guardian_statuses(cfg),
    })


@app.get("/events", response_class=HTMLResponse)
async def events_page(request: Request,
                      program: str = "", decision: str = "", search: str = ""):
    return templates.TemplateResponse("events.html", {
        "request": request, "active": "events",
        "events":   read_events(150, program or None, decision or None, search or None,
                                source="disk"),
        "programs": all_programs(),
        "fp": program, "fd": decision, "fs": search,
    })


@app.get("/db", response_class=HTMLResponse)
async def db_page(request: Request, decision: str = "", search: str = ""):
    return templates.TemplateResponse("db_events.html", {
        "request":  request, "active": "db",
        "events":   read_events(150, decision=decision or None, search=search or None,
                                source="db"),
        "fd": decision, "fs": search,
    })


@app.get("/email", response_class=HTMLResponse)
async def email_page(request: Request, decision: str = "", search: str = ""):
    return templates.TemplateResponse("email_events.html", {
        "request":  request, "active": "email",
        "events":   read_events(150, decision=decision or None, search=search or None,
                                source="email"),
        "fd": decision, "fs": search,
    })


@app.get("/permissions", response_class=HTMLResponse)
async def permissions_page(request: Request):
    cfg = load_cfg()
    return templates.TemplateResponse("permissions.html", {
        "request": request, "active": "permissions",
        "programs": cfg.get("programs", {}),
    })


@app.get("/config", response_class=HTMLResponse)
async def config_page(request: Request, saved: bool = False):
    return templates.TemplateResponse("config.html", {
        "request": request, "active": "config",
        "cfg": load_cfg(), "saved": saved,
    })


# ── API ──────────────────────────────────────────────────────────────────────

@app.get("/api/events/stream")
async def stream():
    async def gen():
        try:
            with open(AUDIT) as f:
                f.seek(0, 2)
                while True:
                    line = f.readline()
                    if line and line.strip():
                        try:
                            e = json.loads(line)
                            _enrich([e])
                            yield f"data: {json.dumps(e)}\n\n"
                        except Exception:
                            pass
                    else:
                        await asyncio.sleep(0.2)
        except Exception as exc:
            yield f"data: {json.dumps({'error': str(exc)})}\n\n"
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


@app.get("/api/stats")
async def api_stats():
    return stats_24h()


@app.get("/api/status")
async def api_status():
    return {"status": service_status()}


@app.post("/api/permissions/revoke")
async def revoke(request: Request):
    body = await request.json()
    cfg  = load_cfg()
    prog = body["program"]
    if prog in cfg.get("programs", {}):
        rules = cfg["programs"][prog].get("disk", [])
        cfg["programs"][prog]["disk"] = [
            r for r in rules
            if not (r.get("path") == body["path"] and r.get("action") == body["action"])
        ]
        save_cfg(cfg)
    return {"ok": True}


@app.post("/api/permissions/add")
async def add_perm(request: Request):
    body  = await request.json()
    cfg   = load_cfg()
    prog  = body["program"]
    rules = cfg.setdefault("programs", {}).setdefault(prog, {}).setdefault("disk", [])
    entry = {"action": body["action"], "path": body["path"]}
    if entry not in rules:
        rules.insert(0, entry)
        save_cfg(cfg)
    return {"ok": True}


@app.post("/api/config/save")
async def save_config_api(request: Request):
    body = await request.json()
    cfg  = load_cfg()
    g    = cfg.setdefault("global", {})
    g["timeout_seconds"]       = int(body.get("timeout_seconds", 1800))
    g["bulk_threshold"]        = int(body.get("bulk_threshold", 3))
    g["backup_retention_days"] = int(body.get("backup_retention_days", 7))
    paths = [p.strip() for p in body.get("watch_paths", "").splitlines() if p.strip()]
    if paths:
        cfg.setdefault("disk", {})["watch_paths"] = paths
    save_cfg(cfg)
    return {"ok": True}


@app.post("/api/service/restart")
async def restart_svc():
    try:
        subprocess.run(["systemctl", "restart", "aigate"], check=True, timeout=10)
        return {"ok": True}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
