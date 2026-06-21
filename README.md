# AI Guardian

A real-time security monitor for AI agent environments. AI Guardian intercepts dangerous operations performed by AI agents (file deletion, destructive SQL, email deletion) and requires human approval via Telegram before allowing them to proceed.

Built on Linux **eBPF** — hooks run in the kernel with zero application-level modification required.

---

## Why AI Guardian?

As AI coding agents gain access to shells, databases and email accounts, a single hallucination or prompt-injection attack can cause irreversible damage: deleted source files, dropped tables, or mass-deleted emails. AI Guardian puts a human in the loop for every destructive action, with full process-chain visibility so you always know *which agent* triggered the operation.

---

## Features

| Guardian | What it intercepts | Mechanism |
|---|---|---|
| **Disk Guardian** | File deletions, overwrites, bulk deletes | eBPF LSM `lsm/inode_unlink` hook |
| **DB Guardian** | DROP, TRUNCATE, DELETE, ALTER TABLE | eBPF uprobe on PostgreSQL `query__start` USDT |
| **Email Guardian** | IMAP `STORE +FLAGS (\Deleted)`, `MOVE` to Trash | eBPF uprobe on `SSL_write` in libssl |

**For every interception:**
- The offending process is **frozen** (`SIGSTOP`) instantly
- A **Telegram message** is sent with full context: what, who, which agent chain
- You tap **Allow** or **Deny** — the process resumes or is terminated

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Linux Kernel                       │
│                                                      │
│  eBPF LSM hook        eBPF uprobe         eBPF uprobe│
│  (inode_unlink)    (PG query__start)    (SSL_write)  │
│       │                   │                  │       │
└───────┼───────────────────┼──────────────────┼───────┘
        │  perf ring buffer │                  │
        ▼                   ▼                  ▼
┌─────────────────────────────────────────────────────┐
│                  guardian.py (Python)                │
│                                                      │
│   Disk Guardian    DB Guardian    Email Guardian     │
│        │                │               │            │
│        └────────────────┴───────────────┘            │
│                         │                            │
│                  TelegramGate                        │
│              (ask / notify / block)                  │
└─────────────────────────────────────────────────────┘
        │                                     │
        ▼                                     ▼
  audit.log                          Web Dashboard
  (JSONL)                              (FastAPI)
```

### Process freeze flow

```
1. AI agent performs dangerous operation
2. eBPF hook fires → SIGSTOP sent to process (frozen in-place)
3. Event published to Python via perf ring buffer
4. Guardian fetches context (file path / SQL / email subject+from)
5. Telegram message sent with inline Allow / Deny buttons
6. Human taps button → SIGCONT (allow) or SIGTERM+SIGCONT (deny)
7. Decision written to audit.log
```

---

## Requirements

- Linux kernel **5.15+** (eBPF LSM support)
- Python **3.9+**
- BCC (BPF Compiler Collection)
- PostgreSQL (for DB Guardian)
- libssl / OpenSSL (for Email Guardian)
- A Telegram bot token + chat ID

Tested on Amazon Linux 2023 with kernel 6.1.

---

## Installation

### 1. Clone

```bash
git clone https://github.com/yourname/aigate.git
cd aigate
```

### 2. Install Python dependencies

```bash
pip3 install bcc pyyaml fastapi uvicorn jinja2 python-telegram-bot psycopg2-binary
```

### 3. Install BCC

```bash
# Amazon Linux 2023 / RHEL / Fedora
sudo dnf install bcc bcc-tools python3-bcc

# Ubuntu / Debian
sudo apt install bpfcc-tools python3-bpfcc
```

### 4. Create a Telegram bot

1. Message `@BotFather` on Telegram → `/newbot`
2. Copy the **bot token**
3. Send any message to your bot, then visit:
   `https://api.telegram.org/bot<TOKEN>/getUpdates`
4. Copy your **chat_id** from the response

### 5. Configure

```bash
cp config.example.yaml config.yaml
# Edit config.yaml — see Configuration section below
```

### 6. Set up systemd service

```bash
sudo cp aigate.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable aigate
sudo systemctl start aigate
```

---

## Configuration

Copy `config.example.yaml` to `config.yaml` and edit:

```yaml
telegram:
  bot_token: "YOUR_BOT_TOKEN"
  chat_id: "YOUR_CHAT_ID"

global:
  confirm_method: telegram
  timeout_seconds: 1800     # auto-deny after this many seconds
  bulk_threshold: 3         # treat N+ simultaneous deletes as bulk
  backup_retention_days: 7

disk:
  watch_paths:
    - /                     # monitor entire filesystem
  exclude_patterns:
    - /proc
    - /sys
    - /tmp
    - "*.pyc"
    - ".git"
  integrity:
    enabled: true
    watch_files:
      - /home/user/.ssh/authorized_keys
  usage_alerts:
    warning_pct: 75
    critical_pct: 90
    poll_interval_seconds: 60

db:
  enabled: true
  dsn: "host=localhost port=5432 user=postgres password=SECRET dbname=postgres"
  postgres_binary: /usr/bin/postgres
  postgres_uid: 26          # OS uid of the postgres user
  timeout_seconds: 120
  intercept:
    drop: ask
    truncate: ask
    delete_all: ask         # DELETE with no WHERE clause
    delete_where: allow     # DELETE with WHERE clause (usually safe)
    alter_column: ask

email:
  enabled: true
  monitor_uid: 1000         # only intercept this OS user's SSL writes
  monitor_comms:            # process names to monitor
    - claude
    - python3
    - node
    - bash
  gmail_token_path: /home/user/.credentials/gmail_token.json
  gmail_address: you@gmail.com
  gmail_client_id: YOUR_CLIENT_ID
  gmail_client_secret: YOUR_CLIENT_SECRET
  timeout_seconds: 120
  intercept:
    delete: ask

programs:
  # Per-program allow rules — decisions saved here via "Always Allow"
  claude-code:
    disk:
      - action: allow_always
        path: /home/user/.claude/
      - action: allow_always
        path: /tmp/
```

### Intercept actions

| Action | Meaning |
|---|---|
| `ask` | Freeze process, send Telegram alert, wait for human decision |
| `allow` | Always allow silently |
| `allow_always` | Same as allow (used in saved per-program rules) |
| `deny` | Always block silently |

---

## Running

### Start all guardians

```bash
sudo python3 guardian.py start-all
```

### Start individual guardians

```bash
sudo python3 guardian.py disk      # Disk Guardian only
sudo python3 guardian.py db        # DB Guardian only
sudo python3 guardian.py email     # Email Guardian only
```

### Start the web dashboard

```bash
sudo python3 -m uvicorn dashboard.app:app --host 0.0.0.0 --port 8080
```

---

## Telegram alerts

### Disk Guardian

```
🗑 Disk Guardian — DELETE intercepted

Path:     /home/user/project/important.py
Command:  rm /home/user/project/important.py
Chain:    sshd → bash → claude → bash → rm
PID:      12345

⚠️ No backup — cannot restore if denied

Waiting for your decision...

[ ✅ Allow Once ]  [ 🔒 Always Allow ]
[ 📁 Allow Dir  ]  [ ❌ Deny         ]
```

### DB Guardian

```
🔴 DB Guardian — DROP intercepted

SQL:
DROP TABLE users;

Risk:     high
Process:  sshd → bash → claude → bash → python3
PID:      23456

Waiting for your decision...

[ ✅ Allow Once ]  [ 🔒 Always Allow ]
[ ❌ Deny        ]
```

### Email Guardian

```
🗑 Email Guardian — DELETE intercepted

Action:   Delete email  (msg 1234)
Subject:  Q3 Financial Report
From:     cfo@company.com
To:       you@gmail.com
Date:     Fri, 20 Jun 2026 09:14:22 +0000

Process:  sshd → bash → claude → bash → python3
PID:      34567

Waiting for your decision...

[ ✅ Allow delete ]  [ 🔒 Always allow ]
[ ❌ Block delete  ]
```

---

## Web Dashboard

Available at `http://your-server:8080`

| Page | URL | Description |
|---|---|---|
| Overview | `/` | 24h stats, guardian status, recent events |
| Disk Events | `/events` | File operation audit log with live stream |
| DB Events | `/db` | SQL intercepts with risk level and process chain |
| Email Events | `/email` | Email delete intercepts with subject/sender |
| Permissions | `/permissions` | View and revoke saved allow rules |
| Config | `/config` | Edit global settings |

The Events pages support **live streaming** — click the Live button to see events appear in real time without page refresh.

---

## How each guardian works

### Disk Guardian

Uses an **eBPF LSM hook** at `lsm/inode_unlink`. Every file deletion in the kernel passes through this hook. The guardian:

1. Checks if the process is in the monitored program list (by comm name or ancestry chain)
2. Matches the file path against per-program allow rules
3. If no allow rule matches: `SIGSTOP` the process, send Telegram alert
4. Creates a backup of the file before asking (if feasible)
5. On Allow: `SIGCONT`; on Deny: restore backup + `SIGCONT`

Bulk detection: if a process deletes ≥ `bulk_threshold` files in quick succession, they are grouped into a single "bulk delete" alert.

File integrity monitoring watches a configurable list of critical files (e.g. `~/.ssh/authorized_keys`) and alerts immediately on any change.

### DB Guardian

Uses an **eBPF uprobe** at the PostgreSQL `query__start` USDT probe point inside `exec_simple_query`. At intercept time the full SQL string is available in a register before execution.

1. BPF coarse filter: checks first 5 bytes for `DROP`, `TRUN`, `DELE`, `ALTE`
2. Python fine classifier: determines exact type and risk level
3. Client process discovery: traces the TCP connection from the postgres backend PID back to the actual client process (e.g. the Python script or claude session)
4. Sends Telegram with SQL, risk, and full process chain
5. On Deny: calls `pg_terminate_backend(pid)` to abort the transaction

### Email Guardian

Uses an **eBPF uprobe** on `SSL_write` in `/usr/lib/libssl.so`. Because this hook fires *before* TLS encryption, the plaintext IMAP command is visible.

1. BPF filter: scans the SSL write buffer for `\Deleted` or `MOVE` patterns (unrolled 64-position scan to satisfy BPF verifier)
2. SELECT tracking: a second scan catches `SELECT <mailbox>` to know which mailbox is active
3. Python: fetches email metadata (Subject, From, To, Date) via a separate IMAP connection using OAuth2 — this runs as root (uid=0) and is not itself intercepted
4. Sends Telegram with the email details before asking

Only `STORE +FLAGS (\Deleted)` and `MOVE` are intercepted. `EXPUNGE` is not intercepted: if the prior `\Deleted` mark was denied, `EXPUNGE` has nothing to remove; if it was allowed, deletion is already approved.

---

## Gmail OAuth2 setup (Email Guardian)

1. Go to [Google Cloud Console](https://console.cloud.google.com/) → APIs & Services → Credentials
2. Create an **OAuth 2.0 Client ID** (Desktop app type)
3. Enable the **Gmail API**
4. Run the auth helper:

```bash
python3 tools/gmail_auth.py --client-id YOUR_ID --client-secret YOUR_SECRET
```

5. Follow the URL printed, paste the auth code, token is saved to `~/.credentials/gmail_token.json`
6. Add the token path and credentials to `config.yaml` under `email:`

---

## Audit log

All events are written as JSONL to `audit.log`. Example entries:

```json
{"event": "ebpf_unlink_intercepted", "path": "/home/user/file.py", "program": "claude-code", "chain": "bash → claude → bash → rm", "cmdline": "rm /home/user/file.py", "permission": "deny", "timestamp": "2026-06-21T04:28:47.368"}
{"event": "db_intercepted", "sql": "DROP TABLE users;", "risk": "high", "label": "DROP", "chain": "bash → claude → python3", "pid": 1234, "timestamp": "2026-06-21T04:29:00.100"}
{"event": "db_decision", "sql": "DROP TABLE users;", "result": "deny", "chain": "bash → claude → python3", "timestamp": "2026-06-21T04:29:05.201"}
{"event": "email_delete_intercepted", "operation": "STORE +FLAGS \\Deleted", "message_ids": "42", "subject": "Q3 Report", "from_addr": "cfo@company.com", "chain": "bash → claude → python3", "timestamp": "2026-06-21T04:30:00.000"}
{"event": "email_delete_decision", "result": "deny", "subject": "Q3 Report", "from_addr": "cfo@company.com", "timestamp": "2026-06-21T04:30:08.000"}
```

---

## Security considerations

- AI Guardian runs as **root** (required for eBPF and SIGSTOP)
- The Telegram bot token and Gmail credentials in `config.yaml` should be kept secret — do not commit the live config file to version control
- Use `config.example.yaml` as a template in your repo
- The guardian itself is excluded from disk monitoring via allow rules in `config.yaml`
- A compromised AI agent cannot bypass the guardian by killing it — doing so would require root, and `SIGKILL` on the guardian leaves monitored processes frozen

---

## License

MIT
# ai_guard
