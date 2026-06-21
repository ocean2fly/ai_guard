import ctypes
import os
import re
import signal
import subprocess
import threading
from typing import Optional

from bcc import BPF

from modules.db.sql_classifier import classify
from permissions import log_audit


def _read_proc_ancestry(pid: int, max_depth: int = 8) -> list[str]:
    """Walk /proc up the parent chain, return comm names root→leaf."""
    chain: list[str] = []
    current = pid
    for _ in range(max_depth):
        try:
            status = open(f"/proc/{current}/status").read()
            comm = next(
                l.split(None, 1)[1].strip()
                for l in status.splitlines() if l.startswith("Name:")
            )
            ppid = int(next(
                l.split(None, 1)[1].strip()
                for l in status.splitlines() if l.startswith("PPid:")
            ))
            chain.append(comm)
            if ppid <= 1:
                break
            current = ppid
        except Exception:
            break
    return list(reversed(chain))  # root first


def _find_client_pid(pg_pid: int) -> Optional[int]:
    """Find the client process connected to this postgres backend via TCP."""
    try:
        out = subprocess.check_output(
            ["ss", "-tnp", "--no-header"], text=True, timeout=2,
            stderr=subprocess.DEVNULL
        )
        # Find the peer address (= client's local addr:port) of this backend
        peer_addrs = []
        for line in out.splitlines():
            if f"pid={pg_pid}," in line:
                parts = line.split()
                if len(parts) >= 5:
                    peer_addrs.append(parts[4])
        if not peer_addrs:
            return None
        # Find the process whose local addr matches the peer
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[3] in peer_addrs:
                m = re.search(r"pid=(\d+)", line)
                if m:
                    client_pid = int(m.group(1))
                    if client_pid != pg_pid:
                        return client_pid
    except Exception as exc:
        print(f"[EbpfPgBlocker] _find_client_pid error: {exc}")
    return None

# BPF program attached as a raw uprobe at the postgresql::query__start USDT
# probe location inside exec_simple_query.  At that probe point the query
# string pointer lives in %r15 (documented by the STAPSDT ELF note).
#
# Strategy: coarse keyword check in BPF (DROP/TRUN/DELE/ALTE) avoids stopping
# every SELECT; fine-grained classification happens in Python userspace.
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <uapi/linux/signal.h>

#define MAX_SQL 480

struct pg_event_t {
    u32  pid;
    char comm[16];
    char sql[MAX_SQL];
};

// Per-CPU scratch space to avoid exceeding the 512-byte BPF stack limit.
BPF_PERCPU_ARRAY(scratch, struct pg_event_t, 1);
BPF_PERF_OUTPUT(pg_events);

int probe_query_start(struct pt_regs *ctx)
{
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    // Only intercept postgres OS user backends (uid=PG_UID).
    // Guardian's own SELECT queries are filtered by the keyword check below.
    if (uid != PG_UID)
        return 0;

    // Query string is in %r15 at this probe location (per STAPSDT ELF note).
    uint64_t query_ptr = ctx->r15;
    if (!query_ptr)
        return 0;

    int zero = 0;
    struct pg_event_t *e = scratch.lookup(&zero);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    int len = bpf_probe_read_user_str(e->sql, sizeof(e->sql), (void *)query_ptr);
    if (len <= 0)
        return 0;

    // Case-insensitive keyword check at offsets 0-4 to handle leading whitespace.
    #define UPPER(c) (((c)>='a'&&(c)<='z')?(c)-32:(c))
    #define KW4(s,i,a,b,c,d) \
        (UPPER((s)[i])==(a)&&UPPER((s)[(i)+1])==(b)&&\
         UPPER((s)[(i)+2])==(c)&&UPPER((s)[(i)+3])==(d))
    #define IS_DDL(s,i) \
        (KW4(s,i,'D','R','O','P')||KW4(s,i,'T','R','U','N')||\
         KW4(s,i,'D','E','L','E')||KW4(s,i,'A','L','T','E'))

    int dangerous = 0;
    if (IS_DDL(e->sql,0)) dangerous=1;
    if (!dangerous&&IS_DDL(e->sql,1)) dangerous=1;
    if (!dangerous&&IS_DDL(e->sql,2)) dangerous=1;
    if (!dangerous&&IS_DDL(e->sql,3)) dangerous=1;
    if (!dangerous&&IS_DDL(e->sql,4)) dangerous=1;

    if (!dangerous) return 0;

    // Emit event before freezing so userspace receives it promptly.
    pg_events.perf_submit(ctx, e, sizeof(*e));
    bpf_send_signal(SIGSTOP);
    return 0;
}
"""


class _Event(ctypes.Structure):
    _fields_ = [
        ("pid",  ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("sql",  ctypes.c_char * 480),
    ]


class _DbConn:
    """Thread-safe psycopg2 connection with auto-reconnect for pg_terminate_backend."""

    def __init__(self, dsn: str):
        self._dsn = dsn
        self._conn = None
        self._lock = threading.Lock()

    def terminate(self, pid: int) -> bool:
        with self._lock:
            try:
                self._ensure()
                cur = self._conn.cursor()
                cur.execute("SELECT pg_terminate_backend(%s)", [pid])
                row = cur.fetchone()
                return bool(row and row[0])
            except Exception as exc:
                print(f"[DbConn] terminate({pid}) failed: {exc}")
                self._conn = None
                return False

    def _ensure(self):
        if self._conn is None or self._conn.closed:
            import psycopg2
            self._conn = psycopg2.connect(self._dsn)
            self._conn.autocommit = True


def _get_probe_vma(binary: str) -> int:
    """Return the ELF VMA of postgresql::query__start from the binary's STAPSDT notes."""
    try:
        out = subprocess.check_output(
            ["readelf", "-n", binary],
            stderr=subprocess.DEVNULL, text=True,
        )
        in_qs = False
        for line in out.splitlines():
            if "query__start" in line:
                in_qs = True
            if in_qs and "Location:" in line:
                vma_str = line.split("Location:")[1].split(",")[0].strip()
                return int(vma_str, 16)
    except Exception as exc:
        raise RuntimeError(f"Cannot find query__start VMA in {binary}: {exc}")
    raise RuntimeError(f"query__start USDT probe not found in {binary}")


class EbpfPgBlocker:
    """
    Attaches a raw uprobe at postgresql::query__start (ELF STAPSDT location).
    Dangerous SQL is frozen via SIGSTOP; the guardian then either
    SIGCONT (allow) or pg_terminate_backend + SIGCONT (deny).
    """

    def __init__(self, gate, config: dict):
        self.gate = gate
        self.config = config

        db_cfg = config.get("db", {})
        pg_uid    = db_cfg.get("postgres_uid", 26)
        binary    = db_cfg.get("postgres_binary", "/usr/bin/postgres")
        dsn       = db_cfg.get("dsn", "host=localhost port=5432 user=postgres dbname=postgres")
        self._intercept = db_cfg.get("intercept", {})
        self._timeout   = db_cfg.get("timeout_seconds",
                                     config.get("global", {}).get("timeout_seconds", 120))

        self._db = _DbConn(dsn)
        self._pending: set[int] = set()
        self._lock = threading.Lock()

        probe_vma = _get_probe_vma(binary)
        print(f"[EbpfPgBlocker] query__start VMA: 0x{probe_vma:x}")

        prog = BPF_PROGRAM.replace("PG_UID", str(pg_uid))
        self._bpf = BPF(text=prog)
        self._bpf.attach_uprobe(name=binary, addr=probe_vma, fn_name="probe_query_start")

    # ------------------------------------------------------------------ #
    #  Public                                                              #
    # ------------------------------------------------------------------ #

    def run(self):
        print("[EbpfPgBlocker] uprobe active — intercepting dangerous SQL")

        def handle_event(cpu, data, size):
            e = ctypes.cast(data, ctypes.POINTER(_Event)).contents
            pid  = e.pid
            comm = e.comm.decode("utf-8", errors="replace").strip()
            sql  = e.sql.decode("utf-8",  errors="replace").strip()

            with self._lock:
                if pid in self._pending:
                    # Same backend sent multiple events before we could decide —
                    # resume it immediately so the first interception governs.
                    self._allow(pid)
                    return
                self._pending.add(pid)

            threading.Thread(
                target=self._handle_query,
                args=(pid, comm, sql),
                daemon=True,
            ).start()

        self._bpf["pg_events"].open_perf_buffer(handle_event)
        while True:
            self._bpf.perf_buffer_poll(timeout=100)

    def release_all(self):
        """SIGCONT all pending backends on guardian shutdown."""
        with self._lock:
            pids = set(self._pending)
            self._pending.clear()
        for pid in pids:
            self._allow(pid)

    # ------------------------------------------------------------------ #
    #  Internal                                                            #
    # ------------------------------------------------------------------ #

    def _allow(self, pid: int):
        with self._lock:
            self._pending.discard(pid)
        try:
            os.kill(pid, signal.SIGCONT)
        except ProcessLookupError:
            pass

    def _deny(self, pid: int):
        with self._lock:
            self._pending.discard(pid)
        self._db.terminate(pid)
        try:
            os.kill(pid, signal.SIGCONT)
        except ProcessLookupError:
            pass

    def _handle_query(self, pid: int, comm: str, sql: str):
        risk, label = classify(sql)

        # Find the actual client process chain (postgres backend ← client)
        client_pid = _find_client_pid(pid)
        if client_pid:
            chain_list = _read_proc_ancestry(client_pid)
            chain = " → ".join(chain_list) if chain_list else comm
        else:
            chain = comm

        if risk is None:
            log_audit({"event": "db_passthrough", "pid": pid, "sql": sql[:200],
                       "chain": chain})
            self._allow(pid)
            return

        action = self._intercept_action(label, risk)
        log_audit({"event": "db_intercepted", "pid": pid, "comm": comm,
                   "chain": chain, "sql": sql[:200], "risk": risk,
                   "label": label, "action": action})

        if action == "allow":
            self._allow(pid)
            return

        if action == "deny":
            log_audit({"event": "db_denied", "pid": pid, "sql": sql[:200],
                       "chain": chain})
            self.gate.notify(f"🚫 DB blocked (deny rule): <code>{sql[:120]}</code>")
            self._deny(pid)
            return

        # action == "ask" — show Telegram prompt
        sql_display = sql[:300] + ("…" if len(sql) > 300 else "")

        op = {
            "action": "db_intercept",
            "details": {
                "SQL":     sql_display,
                "Type":    label,
                "Risk":    risk,
                "Process": chain,
                "PID":     str(pid),
            },
            "buttons": [
                [("allow_once",   "✅ Allow Once"),
                 ("allow_always", "🔒 Always Allow")],
                [("deny",         "❌ Deny")],
            ],
        }

        result = self.gate.ask(op, timeout_override=self._timeout)
        log_audit({"event": "db_decision", "pid": pid, "sql": sql[:200],
                   "chain": chain, "result": result, "label": label})

        if result == "allow_always":
            self._save_allow_rule(comm, label)

        if result in ("allow_once", "allow_always"):
            self._allow(pid)
        else:
            self._deny(pid)

    def _intercept_action(self, label: str, risk: str) -> str:
        """Map SQL type label to configured action (ask/allow/deny)."""
        key_map = {
            "DROP":                         "drop",
            "TRUNCATE":                     "truncate",
            "DELETE (no WHERE)":            "delete_all",
            "DELETE (with WHERE)":          "delete_where",
            "ALTER TABLE (column change)":  "alter_column",
        }
        key = key_map.get(label)
        if key and key in self._intercept:
            return self._intercept[key]
        return "ask" if risk == "high" else "allow"

    def _save_allow_rule(self, comm: str, label: str):
        """Persist an allow rule for this program + SQL type to config.yaml."""
        import yaml
        from pathlib import Path as _Path
        cfg_path = _Path(__file__).parent.parent.parent / "config.yaml"
        try:
            with open(cfg_path) as f:
                cfg = yaml.safe_load(f)
            progs = cfg.setdefault("programs", {})
            prog  = progs.setdefault(comm, {})
            rules = prog.setdefault("db", [])
            if not any(r.get("label") == label for r in rules):
                rules.insert(0, {"label": label, "action": "allow"})
                with open(cfg_path, "w") as f:
                    yaml.dump(cfg, f, default_flow_style=False, allow_unicode=True)
                log_audit({"event": "db_permission_granted",
                           "program": comm, "label": label})
        except Exception as exc:
            print(f"[EbpfPgBlocker] Failed to save rule: {exc}")
