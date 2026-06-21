import ctypes
import imaplib
import json
import os
import re
import signal
import threading
import urllib.parse
import urllib.request
from pathlib import Path

from bcc import BPF

from modules.email.imap_parser import is_imap_delete, parse_imap_delete, parse_select_mailbox
from permissions import log_audit

_OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"
_GMAIL_CLIENT_ID  = ""   # set gmail_client_id in config.yaml
_GMAIL_CLIENT_SEC = ""   # set gmail_client_secret in config.yaml

# uprobe on SSL_write(SSL *ssl, const void *buf, int num)
#
# Monitors IMAP email DELETE operations:
#   - STORE +FLAGS (\Deleted)   → marks message(s) for deletion
#   - EXPUNGE / UID EXPUNGE     → permanently removes deleted messages
#   - MOVE <ids> <Trash>        → RFC 6851 move to trash
#
# Two-level filter:
#   1. uid == MONITOR_UID  (ec2-user; excludes system services)
#   2. comm in monitored_comms BPF map
#
# Detection: scan the SSL_write buffer for \Deleted or EXPUNGE anywhere
# (IMAP tags like "A001" prefix the command, so first-byte checks don't work).
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <uapi/linux/signal.h>
#include <linux/sched.h>

#define MAX_DATA 480

struct email_event_t {
    u32  pid;
    u32  uid;
    char comm[16];
    char pcomm[16];
    char data[MAX_DATA];
    u32  datalen;
    u8   event_type;   // 0 = delete (SIGSTOP), 1 = SELECT (context only, no SIGSTOP)
};

BPF_HASH(monitored_comms, u64, u8);
BPF_PERCPU_ARRAY(scratch, struct email_event_t, 1);
BPF_PERF_OUTPUT(email_events);

int probe_ssl_write(struct pt_regs *ctx)
{
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid != MONITOR_UID)
        return 0;

    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    u64 comm_key = 0;
    __builtin_memcpy(&comm_key, comm, sizeof(comm_key));
    u8 *flag = monitored_comms.lookup(&comm_key);
    if (!flag)
        return 0;

    void *buf = (void *)PT_REGS_PARM2(ctx);
    u32  num  = (u32)PT_REGS_PARM3(ctx);
    if (!buf || num < 8)
        return 0;

    int zero = 0;
    struct email_event_t *e = scratch.lookup(&zero);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = uid;
    __builtin_memcpy(e->comm, comm, sizeof(e->comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = NULL;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    if (parent)
        bpf_probe_read_kernel_str(e->pcomm, sizeof(e->pcomm), parent->comm);

    e->datalen = num < MAX_DATA ? num : MAX_DATA;
    bpf_probe_read_user(e->data, e->datalen, buf);

    // Scan buffer for IMAP delete indicators.
    // IMAP commands have a variable-length tag prefix (e.g. "A001 STORE …"),
    // so we scan multiple positions rather than checking only byte 0.
    // We check 64 positions (covers up to ~60-char tags, plenty for real clients).
    // Unrolled to avoid BPF verifier loop-complexity limits.
    //
    // Intercept only the intent-to-delete commands:
    //  \Deleted  → STORE +FLAGS (\Deleted)  — marks message for deletion
    //  MOVE      → MOVE <ids> <Trash>       — RFC 6851 direct move to trash
    // EXPUNGE is NOT intercepted: if \Deleted was denied the flag was never set,
    // so EXPUNGE is harmless; if \Deleted was allowed, deletion is already approved.
    #define SCAN1(i) \
        if (!found && (int)(i) < (int)e->datalen - 4) { \
            if (e->data[(i)] == 0x5c && \
                (e->data[(i)+1]=='D'||e->data[(i)+1]=='d') && \
                (e->data[(i)+2]=='E'||e->data[(i)+2]=='e') && \
                (e->data[(i)+3]=='L'||e->data[(i)+3]=='l')) found = 1; \
            if (!found && \
                e->data[(i)]=='M' && e->data[(i)+1]=='O' && \
                e->data[(i)+2]=='V' && e->data[(i)+3]=='E') found = 1; \
        } \
        if (!sel_found && (int)(i) < (int)e->datalen - 4) { \
            if ((e->data[(i)]=='S'||e->data[(i)]=='s') && \
                (e->data[(i)+1]=='E'||e->data[(i)+1]=='e') && \
                (e->data[(i)+2]=='L'||e->data[(i)+2]=='l') && \
                (e->data[(i)+3]=='E'||e->data[(i)+3]=='e')) sel_found = 1; \
        }

    int found = 0; int sel_found = 0;
    SCAN1(0)  SCAN1(1)  SCAN1(2)  SCAN1(3)  SCAN1(4)  SCAN1(5)  SCAN1(6)  SCAN1(7)
    SCAN1(8)  SCAN1(9)  SCAN1(10) SCAN1(11) SCAN1(12) SCAN1(13) SCAN1(14) SCAN1(15)
    SCAN1(16) SCAN1(17) SCAN1(18) SCAN1(19) SCAN1(20) SCAN1(21) SCAN1(22) SCAN1(23)
    SCAN1(24) SCAN1(25) SCAN1(26) SCAN1(27) SCAN1(28) SCAN1(29) SCAN1(30) SCAN1(31)
    SCAN1(32) SCAN1(33) SCAN1(34) SCAN1(35) SCAN1(36) SCAN1(37) SCAN1(38) SCAN1(39)
    SCAN1(40) SCAN1(41) SCAN1(42) SCAN1(43) SCAN1(44) SCAN1(45) SCAN1(46) SCAN1(47)
    SCAN1(48) SCAN1(49) SCAN1(50) SCAN1(51) SCAN1(52) SCAN1(53) SCAN1(54) SCAN1(55)
    SCAN1(56) SCAN1(57) SCAN1(58) SCAN1(59) SCAN1(60) SCAN1(61) SCAN1(62) SCAN1(63)

    if (!found && !sel_found) return 0;

    e->event_type = found ? 0 : 1;
    email_events.perf_submit(ctx, e, sizeof(*e));
    if (found) bpf_send_signal(SIGSTOP);
    return 0;
}
"""


class _Event(ctypes.Structure):
    _fields_ = [
        ("pid",        ctypes.c_uint32),
        ("uid",        ctypes.c_uint32),
        ("comm",       ctypes.c_char * 16),
        ("pcomm",      ctypes.c_char * 16),
        ("data",       ctypes.c_char * 480),  # must match MAX_DATA in BPF
        ("datalen",    ctypes.c_uint32),
        ("event_type", ctypes.c_uint8),       # 0=delete 1=select
    ]


def _read_proc_ancestry(pid: int, max_depth: int = 8) -> list[str]:
    """Walk /proc up the parent chain, return list of comm names root→leaf."""
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


class EbpfEmailBlocker:
    """
    Attaches a uprobe to SSL_write in libssl.so.
    Intercepts SMTP commands (MAIL FROM, RCPT TO, …) before TLS encryption,
    freezes the process with SIGSTOP, and asks for user approval via Telegram.

    Strategy:
    - MAIL FROM: capture sender in _smtp_ctx[pid], SIGCONT (don't ask yet)
    - RCPT TO:   now we have sender + recipient → SIGSTOP + ask Telegram
    - AUTH/EHLO/DATA/QUIT: always allow
    """

    LIBSSL = "/usr/lib64/libssl.so.3"

    def __init__(self, gate, config: dict):
        self.gate = gate
        self.config = config

        email_cfg = config.get("email", {})
        self._monitor_uid     = email_cfg.get("monitor_uid", 1000)
        self._monitor_comms   = email_cfg.get("monitor_comms",
                                               ["claude", "python3", "curl", "bash", "node"])
        self._delete_action = email_cfg.get("intercept", {}).get("delete", "ask")
        self._timeout = email_cfg.get("timeout_seconds",
                                      config.get("global", {}).get("timeout_seconds", 120))

        self._pending: set[int] = set()
        self._lock = threading.Lock()
        self._mailbox_ctx: dict[int, str] = {}   # pid → current selected mailbox
        self._mb_lock = threading.Lock()

        prog = BPF_PROGRAM.replace("MONITOR_UID", str(self._monitor_uid))
        self._bpf = BPF(text=prog)
        self._bpf.attach_uprobe(name=self.LIBSSL, sym="SSL_write",
                                fn_name="probe_ssl_write")

        # Populate the comm filter map
        self._fill_comm_map()
        print(f"[EbpfEmailBlocker] SSL_write uprobe active — monitoring: {self._monitor_comms}")

    # ------------------------------------------------------------------ #
    #  Public                                                              #
    # ------------------------------------------------------------------ #

    def update_comms(self, comms: list[str]):
        """Hot-reload the monitored comm list (call after config change)."""
        self._monitor_comms = comms
        self._fill_comm_map()

    def run(self):
        def handle_event(cpu, data, size):
            e = ctypes.cast(data, ctypes.POINTER(_Event)).contents
            pid        = e.pid
            comm       = e.comm.decode("utf-8", errors="replace").strip()
            raw        = bytes(e.data[:e.datalen])
            event_type = e.event_type

            # SELECT event: just record which mailbox is active for this pid
            if event_type == 1:
                mailbox = parse_select_mailbox(raw)
                if mailbox:
                    with self._mb_lock:
                        self._mailbox_ctx[pid] = mailbox
                return

            with self._lock:
                if pid in self._pending:
                    self._allow(pid)
                    return
                self._pending.add(pid)

            with self._mb_lock:
                mailbox = self._mailbox_ctx.get(pid, "INBOX")

            ancestry = _read_proc_ancestry(pid)
            threading.Thread(
                target=self._handle_write,
                args=(pid, comm, ancestry, raw, mailbox),
                daemon=True,
            ).start()

        self._bpf["email_events"].open_perf_buffer(handle_event)
        while True:
            self._bpf.perf_buffer_poll(timeout=100)

    def release_all(self):
        with self._lock:
            pids = set(self._pending)
            self._pending.clear()
        for pid in pids:
            self._allow(pid)

    # ------------------------------------------------------------------ #
    #  Internal                                                            #
    # ------------------------------------------------------------------ #

    def _fill_comm_map(self):
        comm_map = self._bpf["monitored_comms"]
        comm_map.clear()
        for name in self._monitor_comms:
            key_bytes = name.encode()[:8].ljust(8, b"\x00")
            key = ctypes.c_uint64.from_buffer_copy(key_bytes)
            comm_map[key] = ctypes.c_uint8(1)

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
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            os.kill(pid, signal.SIGCONT)
        except ProcessLookupError:
            pass

    def _fetch_email_meta(self, mailbox: str, msg_ids: str) -> dict:
        """Fetch Subject/From/To/Date via IMAP (runs as root uid=0, not intercepted by BPF)."""
        email_cfg  = self.config.get("email", {})
        token_path = email_cfg.get("gmail_token_path",
                                   "/home/ec2-user/.credentials/gmail_token.json")
        gmail_addr = email_cfg.get("gmail_address", "")
        if not gmail_addr or not Path(token_path).exists():
            return {}
        try:
            token_data = json.loads(open(token_path).read())
            resp = urllib.request.urlopen(urllib.request.Request(
                _OAUTH_TOKEN_URL,
                data=urllib.parse.urlencode({
                    "refresh_token": token_data["refresh_token"],
                    "client_id":     email_cfg.get("gmail_client_id",     _GMAIL_CLIENT_ID),
                    "client_secret": email_cfg.get("gmail_client_secret", _GMAIL_CLIENT_SEC),
                    "grant_type":    "refresh_token",
                }).encode()
            ))
            access_token = json.loads(resp.read())["access_token"]

            M = imaplib.IMAP4_SSL("imap.gmail.com", 993)
            xoauth2 = f"user={gmail_addr}\x01auth=Bearer {access_token}\x01\x01".encode()
            M.authenticate("XOAUTH2", lambda x: xoauth2)

            # Try the tracked mailbox first, fall back to All Mail
            connected = False
            for mb in [mailbox, "INBOX", '"[Gmail]/All Mail"']:
                typ, _ = M.select(mb)
                if typ == "OK":
                    connected = True
                    break

            if not connected:
                M.logout()
                return {}

            first_id = msg_ids.split(",")[0].split(":")[0].strip()
            if not first_id or first_id == "*":
                M.logout()
                return {}

            typ, data = M.fetch(first_id,
                                "(BODY.PEEK[HEADER.FIELDS (SUBJECT FROM TO DATE)])")
            M.logout()

            if typ != "OK" or not data or not data[0]:
                return {}

            result = {"subject": "", "from": "", "to": "", "date": ""}
            for line in data[0][1].decode("utf-8", errors="replace").splitlines():
                low = line.lower()
                if low.startswith("subject:"):
                    result["subject"] = line[8:].strip()
                elif low.startswith("from:"):
                    result["from"]    = line[5:].strip()
                elif low.startswith("to:"):
                    result["to"]      = line[3:].strip()
                elif low.startswith("date:"):
                    result["date"]    = line[5:].strip()
            return result
        except Exception as exc:
            print(f"[EbpfEmailBlocker] fetch_email_meta error: {exc}")
            return {}

    def _handle_write(self, pid: int, comm: str, ancestry: list, raw: bytes, mailbox: str):
        try:
            self._handle_write_inner(pid, comm, ancestry, raw, mailbox)
        except Exception as exc:
            import traceback
            print(f"[EbpfEmailBlocker] ERROR pid={pid}: {exc}")
            traceback.print_exc()
            self._allow(pid)

    def _handle_write_inner(self, pid: int, comm: str, ancestry: list, raw: bytes,
                            mailbox: str = "INBOX"):
        imap      = parse_imap_delete(raw)
        operation = imap["operation"] or "DELETE"
        msg_ids   = imap["message_ids"] or "?"
        dest      = imap["destination"]
        action    = self._delete_action

        chain_str = " → ".join(reversed(ancestry)) if ancestry else comm

        # Fetch metadata first so both log entries carry subject/from
        meta = self._fetch_email_meta(mailbox, msg_ids)

        print(f"[EbpfEmailBlocker] email delete: pid={pid} op={operation!r} "
              f"ids={msg_ids!r} subject={meta.get('subject','')!r} chain={chain_str!r}")

        log_audit({
            "event":       "email_delete_intercepted",
            "pid":         pid,
            "comm":        comm,
            "chain":       chain_str,
            "operation":   operation,
            "message_ids": msg_ids,
            "destination": dest,
            "mailbox":     mailbox,
            "subject":     meta.get("subject", ""),
            "from_addr":   meta.get("from", ""),
            "to_addr":     meta.get("to", ""),
            "date":        meta.get("date", ""),
            "action":      action,
        })

        if action == "deny":
            self.gate.notify(
                f"🚫 Email DELETE blocked (deny rule): "
                f"<code>{operation}</code> msg <code>{msg_ids}</code> "
                f"from <code>{comm}</code>"
            )
            self._deny(pid)
            return

        details: dict[str, str] = {
            "Operation":   operation,
            "Messages":    msg_ids,
            "Destination": dest,
        }
        if meta.get("subject"):
            details["Subject"] = meta["subject"]
        if meta.get("from"):
            details["From"]    = meta["from"]
        if meta.get("to"):
            details["To"]      = meta["to"]
        if meta.get("date"):
            details["Date"]    = meta["date"]
        details["Process"] = chain_str
        details["PID"]     = str(pid)

        op = {
            "action":  "email_intercept",
            "details": details,
            "buttons": [
                [("allow_once",   "✅ Allow delete"),
                 ("allow_always", "🔒 Always allow")],
                [("deny",         "❌ Block delete")],
            ],
        }

        result = self.gate.ask(op, timeout_override=self._timeout)
        log_audit({
            "event":       "email_delete_decision",
            "pid":         pid,
            "operation":   operation,
            "message_ids": msg_ids,
            "subject":     meta.get("subject", ""),
            "from_addr":   meta.get("from", ""),
            "to_addr":     meta.get("to", ""),
            "date":        meta.get("date", ""),
            "result":      result,
            "chain":       chain_str,
        })

        if result == "allow_always":
            self._save_allow_rule(comm, "delete")

        if result in ("allow_once", "allow_always"):
            self._allow(pid)
        else:
            self._deny(pid)

    def _save_allow_rule(self, comm: str, cmd: str):
        import yaml
        cfg_path = Path(__file__).parent.parent.parent / "config.yaml"
        try:
            with open(cfg_path) as f:
                cfg = yaml.safe_load(f)
            intercept = cfg.setdefault("email", {}).setdefault("intercept", {})
            intercept[cmd] = "allow"
            with open(cfg_path, "w") as f:
                yaml.dump(cfg, f, default_flow_style=False, allow_unicode=True)
            log_audit({"event": "email_permission_granted", "program": comm, "cmd": cmd})
        except Exception as exc:
            print(f"[EbpfEmailBlocker] Failed to save rule: {exc}")
