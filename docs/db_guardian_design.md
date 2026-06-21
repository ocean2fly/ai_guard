# DB Guardian — Design Document

## Goal

Intercept dangerous PostgreSQL queries **before** they execute, ask the user via
Telegram (Allow / Deny), and either let the query through or abort the connection.
No proxy layer. No client port changes. Hook directly into the PostgreSQL process.

---

## Architecture

```
Client (port 5432)
        │
        ▼
  PostgreSQL backend process (pid=N)
        │
        ├─ exec_simple_query("DROP TABLE users")
        │        │
        │   eBPF uprobe fires
        │        │
        │   bpf_send_signal(SIGSTOP)  ◄── backend freezes here
        │        │
        │   ring buffer event ──────────► Guardian (Python)
        │                                      │
        │                                 classify SQL
        │                                      │
        │                              Telegram: Allow / Deny
        │                                      │
        │                    ┌─────────────────┴──────────────────┐
        │                  Allow                                 Deny
        │                    │                                    │
        │            SIGCONT (pid=N)              pg_terminate_backend(N)
        │                    │                     then SIGCONT (pid=N)
        │                    ▼                                    ▼
        │           query executes                   backend wakes → finds
        │                                           termination signal → aborts
        ▼                                           client gets FATAL error
  result / error
```

---

## Hook Point

| Function | Location | Covers |
|----------|----------|--------|
| `exec_simple_query` | `/usr/bin/postgres` | Simple Query protocol (most clients) |
| `PortalRun` | `/usr/bin/postgres` | Prepared statements (phase 2) |

Phase 1 (demo): hook `exec_simple_query` only.
Phase 2: add `PortalRun` to cover prepared statements.

The first argument (`const char *query_string`) is the raw SQL string — readable
with `bpf_probe_read_user_str()`.

---

## SQL Classification

```python
DANGEROUS = [
    # Pattern                           Risk     Default
    (r"DROP\s+(TABLE|DATABASE|SCHEMA|INDEX|SEQUENCE)", "high",   "ask"),
    (r"TRUNCATE\s+",                                   "high",   "ask"),
    (r"DELETE\s+FROM\s+\w+\s*$",                       "high",   "ask"),  # no WHERE
    (r"DELETE\s+FROM\s+\w+\s*WHERE",                   "medium", "allow"),
    (r"ALTER\s+TABLE.+(DROP|RENAME)\s+COLUMN",         "medium", "ask"),
    (r"CREATE\s+OR\s+REPLACE\s+(FUNCTION|PROCEDURE)",  "low",    "allow"),
]
```

Safe queries (SELECT, INSERT, UPDATE with WHERE, CREATE TABLE) pass through
without any interception.

---

## Blocking Mechanism

### Allow path
```python
os.kill(backend_pid, signal.SIGCONT)
# backend resumes → exec_simple_query() continues → query executes
```

### Deny path
```python
# Connect as superuser from guardian (uid=0)
conn.execute("SELECT pg_terminate_backend(%s)", [backend_pid])
conn.commit()
# THEN resume so backend can process its own termination signal
os.kill(backend_pid, signal.SIGCONT)
# client receives: FATAL: terminating connection due to administrator command
```

Why terminate before SIGCONT: if we just SIGCONT without terminating, the query
runs. `pg_terminate_backend` sends SIGTERM to the backend; PostgreSQL handles it
gracefully on next opportunity (i.e. when it wakes from SIGSTOP).

---

## eBPF Program

```c
#include <uapi/linux/ptrace.h>

#define MAX_SQL 512

struct pg_event_t {
    u32  pid;
    u32  uid;
    char comm[16];
    char sql[MAX_SQL];
};

BPF_PERF_OUTPUT(pg_events);

int probe_exec_simple_query(struct pt_regs *ctx)
{
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    // Only intercept postgres backend running as the postgres OS user
    // Adjust uid to match actual postgres user on target system
    struct pg_event_t e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.uid = uid;
    bpf_get_current_comm(e.comm, sizeof(e.comm));

    // Read SQL string from first argument
    void *query_ptr = (void *)PT_REGS_PARM1(ctx);
    bpf_probe_read_user_str(e.sql, sizeof(e.sql), query_ptr);

    // Emit event to user-space BEFORE sending SIGSTOP
    pg_events.perf_submit(ctx, &e, sizeof(e));

    // Pause backend — guardian will SIGCONT or pg_terminate
    bpf_send_signal(SIGSTOP);
    return 0;
}
```

Attach:
```python
b.attach_uprobe(
    name="/usr/bin/postgres",
    sym="exec_simple_query",
    fn_name="probe_exec_simple_query",
)
```

---

## File Layout

```
modules/db/
  __init__.py
  ebpf_pg_blocker.py      # BPF program load, uprobe attach, event loop
  sql_classifier.py       # classify(sql) → ("high"/"medium"/None, label)
  pg_guardian.py          # top-level: start blocker + guardian conn pool
```

---

## Guardian Connection Pool

The guardian needs its own **superuser** psycopg2 connection to call
`pg_terminate_backend()`. This connection must be separate from the monitored
ones (so it never triggers the uprobe itself — guardian runs as uid=0, and
we filter by postgres OS uid in the eBPF program).

```python
# config.yaml  (new section)
db:
  enabled: true
  dsn: "host=localhost port=5432 user=postgres password=... dbname=postgres"
  postgres_binary: "/usr/bin/postgres"
  # UIDs to monitor (postgres OS user — check with: id postgres)
  monitor_uids: [26]   # typical on Amazon Linux; verify post-install
  intercept:
    drop_table:   ask
    drop_database: ask
    truncate:     ask
    delete_all:   ask    # DELETE without WHERE
    delete_where: allow  # DELETE with WHERE
```

---

## Telegram Message Format

```
⚠️ DB Guardian — DROP intercepted

SQL:       DROP TABLE users CASCADE
Database:  postgres  (backend pid 4821)
Program:   claude-code
Chain:     python3 → bash → claude
Command:   python3 /home/ec2-user/aigate/run.py

[Allow Once]  [Always Allow]  [Deny]
```

No "Allow Dir" button (not meaningful for DB). Three buttons only.

---

## Setup Steps (Amazon Linux 2023)

```bash
# 1. Install PostgreSQL
sudo dnf install -y postgresql15-server postgresql15

# 2. Init + start
sudo postgresql-setup --initdb
sudo systemctl enable --now postgresql

# 3. Set postgres superuser password (for guardian connection)
sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'guardianpw';"

# 4. Confirm postgres binary path + symbol exists
which postgres                          # → /usr/bin/postgres
nm /usr/bin/postgres | grep exec_simple_query
# If empty → install debuginfo:
# sudo dnf install -y postgresql15-debuginfo

# 5. Get postgres OS uid (goes into config.yaml monitor_uids)
id postgres                             # → uid=26(postgres)

# 6. Install psycopg2 for guardian
sudo pip3 install psycopg2-binary
```

---

## Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| Guardian crash → backends stuck in SIGSTOP | Watchdog thread: if guardian dies, SIGCONT all known backend PIDs |
| SIGSTOP while backend holds lock → other queries blocked | Acceptable for dangerous DDL; window = Telegram response time |
| Prepared statements not caught | Phase 2: add `PortalRun` uprobe |
| PostgreSQL binary stripped (no `exec_simple_query` symbol) | Install `postgresql-debuginfo` package |
| Guardian DB connection itself triggers uprobe | Filter by uid: guardian runs as root (uid=0), postgres backends run as uid=26 |

---

## Implementation Order

1. `sql_classifier.py` — pure Python, no dependencies, testable standalone
2. `ebpf_pg_blocker.py` — BPF load + uprobe + ring buffer + SIGSTOP logic
3. `pg_guardian.py` — ties classifier + blocker + TelegramGate together
4. `config.yaml` — add `db:` section
5. `dashboard/app.py` — add DB events endpoint + overview card update
6. systemd: add `db` module start to `guardian.py`

---

*Written 2026-06-20. PostgreSQL not yet installed on this machine — run setup
steps above before starting implementation.*
