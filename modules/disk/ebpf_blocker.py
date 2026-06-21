import ctypes
import os
import subprocess
import threading
from pathlib import Path
from typing import Optional

from bcc import BPF

from permissions import check_permission, grant_permission, log_audit

BPF_PROGRAM = r"""
#include <linux/fs.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

struct event_t {
    u64 inode;
    u32 pid;
    u32 ppid;
    u32 gpid;
    char filename[256];
    char comm[16];
    char pcomm[16];
    char gcomm[16];
};

BPF_PERF_OUTPUT(events);

LSM_PROBE(inode_unlink, struct inode *dir, struct dentry *dentry)
{
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    // Only intercept the interactive user (1000); root and system accounts pass through
    if (uid != 1000)
        return 0;

    struct event_t e = {};
    e.inode = dentry->d_inode->i_ino;
    e.pid   = bpf_get_current_pid_tgid() >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_get_current_comm(e.comm, sizeof(e.comm));

    struct task_struct *parent = NULL;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    if (parent) {
        bpf_probe_read_kernel(&e.ppid, sizeof(e.ppid), &parent->tgid);
        bpf_probe_read_kernel_str(e.pcomm, sizeof(e.pcomm), parent->comm);

        struct task_struct *gparent = NULL;
        bpf_probe_read_kernel(&gparent, sizeof(gparent), &parent->real_parent);
        if (gparent) {
            bpf_probe_read_kernel(&e.gpid, sizeof(e.gpid), &gparent->tgid);
            bpf_probe_read_kernel_str(e.gcomm, sizeof(e.gcomm), gparent->comm);
        }
    }

// Only intercept if the process or any captured ancestor is claude-related.
// Check for the prefix "clau" (covers "claude", "claude-code", etc.) in all
// three comm fields. Non-claude uid=1000 processes pass through unblocked.
#define HAS_CLAU(s) ((s)[0]=='c' && (s)[1]=='l' && (s)[2]=='a' && (s)[3]=='u')
    if (!HAS_CLAU(e.comm) && !HAS_CLAU(e.pcomm) && !HAS_CLAU(e.gcomm))
        return 0;
#undef HAS_CLAU

    bpf_probe_read_kernel_str(e.filename, sizeof(e.filename),
                              dentry->d_name.name);
    events.perf_submit(ctx, &e, sizeof(e));

    return -1;
}
"""


class _Event(ctypes.Structure):
    _fields_ = [
        ("inode",    ctypes.c_uint64),
        ("pid",      ctypes.c_uint32),
        ("ppid",     ctypes.c_uint32),
        ("gpid",     ctypes.c_uint32),
        ("filename", ctypes.c_char * 256),
        ("comm",     ctypes.c_char * 16),
        ("pcomm",    ctypes.c_char * 16),
        ("gcomm",    ctypes.c_char * 16),
    ]


class EbpfBlocker:
    """
    Loads a BPF LSM hook on inode_unlink.
    Non-root unlinks are blocked (EPERM) and routed through Telegram for approval.
    Guardian (running as root) performs the actual deletion on behalf of the caller.
    """

    def __init__(self, gate, config: dict):
        self.gate = gate
        self.config = config
        self._inode_path: dict[int, str] = {}
        self._lock = threading.Lock()
        self._bpf = BPF(text=BPF_PROGRAM)

        # Batch state: (program, parent_dir) → [(inode, path), ...]
        self._batch: dict[tuple, list] = {}
        self._batch_chain: dict[tuple, str] = {}    # representative chain per key
        self._batch_cmd: dict[tuple, str] = {}      # representative cmdline per key
        self._batch_cwd: dict[tuple, str] = {}      # representative cwd per key
        self._batch_timer: Optional[threading.Timer] = None
        self._batch_lock = threading.Lock()

    # ------------------------------------------------------------------ #
    #  Inode → path cache                                                  #
    # ------------------------------------------------------------------ #

    def add_path(self, full_path: str):
        try:
            st = os.stat(full_path)
            with self._lock:
                self._inode_path[st.st_ino] = full_path
        except OSError:
            pass

    def remove_inode(self, inode: int):
        with self._lock:
            self._inode_path.pop(inode, None)

    def scan_paths(self, paths: list, is_excluded=None):
        """Pre-populate inode cache by scanning paths."""
        count = 0
        for root in paths:
            try:
                for dirpath, dirs, files in os.walk(root, onerror=lambda _: None):
                    if is_excluded and is_excluded(dirpath):
                        dirs[:] = []
                        continue
                    # Prune excluded subdirs in-place
                    dirs[:] = [d for d in dirs
                                if not (is_excluded and
                                        is_excluded(os.path.join(dirpath, d)))]
                    for fname in files:
                        fp = os.path.join(dirpath, fname)
                        if is_excluded and is_excluded(fp):
                            continue
                        try:
                            st = os.stat(fp)
                            with self._lock:
                                self._inode_path[st.st_ino] = fp
                                count += 1
                        except OSError:
                            pass
            except Exception:
                pass
        print(f"[EbpfBlocker] inode cache ready: {count} files indexed")

    def _resolve_path(self, inode: int, filename: str, pid: int) -> str:
        """Return full path for inode, with multiple fallback strategies."""
        with self._lock:
            if inode in self._inode_path:
                return self._inode_path[inode]

        # Try process's cwd (most likely location for tool temp files)
        try:
            cwd = os.readlink(f"/proc/{pid}/cwd")
            candidate = os.path.join(cwd, filename)
            if os.stat(candidate).st_ino == inode:
                with self._lock:
                    self._inode_path[inode] = candidate
                return candidate
        except OSError:
            pass

        # Try /proc/pid/fd/ symlinks (works when process has file open)
        try:
            for fd in os.listdir(f"/proc/{pid}/fd"):
                try:
                    link = os.readlink(f"/proc/{pid}/fd/{fd}")
                    if os.stat(link).st_ino == inode:
                        with self._lock:
                            self._inode_path[inode] = link
                        return link
                except OSError:
                    pass
        except OSError:
            pass

        # Try common flat temp/home locations
        for prefix in ("/tmp", "/var/tmp", "/home/ec2-user",
                       "/home/ec2-user/.claude", "/home/ec2-user/aigate"):
            candidate = os.path.join(prefix, filename)
            try:
                if os.stat(candidate).st_ino == inode:
                    with self._lock:
                        self._inode_path[inode] = candidate
                    return candidate
            except OSError:
                pass

        # Deep search under /tmp (covers nested paths like /tmp/claude-1000/.../)
        try:
            result = subprocess.run(
                ["find", "/tmp", "-name", filename, "-maxdepth", "8"],
                capture_output=True, text=True, timeout=2,
            )
            for line in result.stdout.strip().splitlines():
                try:
                    if os.stat(line).st_ino == inode:
                        with self._lock:
                            self._inode_path[inode] = line
                        return line
                except OSError:
                    pass
        except Exception:
            pass

        return filename  # last resort: just the basename

    # ------------------------------------------------------------------ #
    #  Event loop                                                          #
    # ------------------------------------------------------------------ #

    def run(self):
        print("[EbpfBlocker] LSM/inode_unlink active — intercepting claude-related unlinks only")

        def handle_event(cpu, data, size):
            e = ctypes.cast(data, ctypes.POINTER(_Event)).contents
            inode    = e.inode
            pid      = e.pid
            ppid     = e.ppid
            filename = e.filename.decode("utf-8", errors="replace")
            comm     = e.comm.decode("utf-8",  errors="replace").strip()
            pcomm    = e.pcomm.decode("utf-8", errors="replace").strip()
            gcomm    = e.gcomm.decode("utf-8", errors="replace").strip()

            # Read cmdline + cwd immediately — process may exit before thread runs
            cmdline = _read_meaningful_cmdline(pid, comm, ppid)
            try:
                cwd = os.readlink(f"/proc/{pid}/cwd")
            except OSError:
                cwd = ""

            full_path = self._resolve_path(inode, filename, pid)

            threading.Thread(
                target=self._handle_unlink,
                args=(inode, pid, ppid, comm, pcomm, gcomm, cmdline, cwd, full_path),
                daemon=True,
            ).start()

        self._bpf["events"].open_perf_buffer(handle_event)
        while True:
            self._bpf.perf_buffer_poll(timeout=100)

    # ------------------------------------------------------------------ #
    #  Decision logic                                                      #
    # ------------------------------------------------------------------ #

    def _handle_unlink(self, inode: int, pid: int, ppid: int,
                        comm: str, pcomm: str, gcomm: str,
                        cmdline: str, cwd: str, path: str):
        program = _identify_program(comm)
        permission = check_permission(program, path)

        chain = _build_chain(comm, pcomm, gcomm, ppid)

        log_audit({
            "event": "ebpf_unlink_intercepted",
            "inode": inode,
            "path": path,
            "program": program,
            "chain": chain,
            "cmdline": cmdline,
            "pid": pid,
            "ppid": ppid,
            "permission": permission,
        })

        if permission == "allow_always":
            self._do_delete(inode, path, program)
            return

        if permission == "deny":
            log_audit({"event": "disk_denied", "action": "delete",
                       "target": path, "program": program})
            self.gate.notify(f"🚫 Blocked (deny rule): <code>{path}</code>")
            return

        # Queue into batch — flush after 2 s of silence from the same operation
        parent_dir = os.path.dirname(path)
        key = (program, parent_dir)
        with self._batch_lock:
            self._batch.setdefault(key, []).append((inode, path))
            self._batch_chain.setdefault(key, chain)
            self._batch_cmd.setdefault(key, cmdline)
            self._batch_cwd.setdefault(key, cwd)
            if self._batch_timer:
                self._batch_timer.cancel()
            t = threading.Timer(2.0, self._flush_batch)
            t.daemon = True
            t.start()
            self._batch_timer = t

    def _flush_batch(self):
        with self._batch_lock:
            batch       = dict(self._batch)
            batch_chain = dict(self._batch_chain)
            batch_cmd   = dict(self._batch_cmd)
            batch_cwd   = dict(self._batch_cwd)
            self._batch.clear()
            self._batch_chain.clear()
            self._batch_cmd.clear()
            self._batch_cwd.clear()
            self._batch_timer = None

        for (program, parent_dir), items in batch.items():
            chain   = batch_chain.get((program, parent_dir), "")
            cmdline = batch_cmd.get((program, parent_dir), program)
            cwd     = batch_cwd.get((program, parent_dir), "")
            threading.Thread(
                target=self._ask_batch,
                args=(program, parent_dir, chain, cmdline, cwd, items),
                daemon=True,
            ).start()

    def _ask_batch(self, program: str, parent_dir: str,
                   chain: str, cmdline: str, cwd: str, items: list):
        count = len(items)

        if count == 1:
            inode, path = items[0]
            op = {
                "action": "delete",
                "details": {
                    "Path":    path,
                    "Program": program,
                    "Chain":   chain,
                    "PWD":     cwd,
                    "Command": cmdline,
                },
                "backup_path": None,
            }
        else:
            preview = "\n".join(
                f"  • {os.path.basename(p)}" for _, p in items[:10]
            )
            if count > 10:
                preview += f"\n  … and {count - 10} more"
            op = {
                "action": "bulk_delete",
                "details": {
                    "Directory": parent_dir,
                    "Count":     str(count),
                    "Program":   program,
                    "Chain":     chain,
                    "PWD":       cwd,
                    "Command":   cmdline,
                    "Files":     preview,
                },
                "backup_path": None,
            }

        print(f"[EbpfBlocker] sending Telegram ask: program={program} path={parent_dir}")
        try:
            result = self.gate.ask(op)
        except Exception as exc:
            print(f"[EbpfBlocker] gate.ask() FAILED: {exc}")
            return
        print(f"[EbpfBlocker] user decision: {result}")
        log_audit({"event": "disk_decision", "result": result,
                   "action": "bulk_delete" if count > 1 else "delete",
                   "directory": parent_dir, "count": count, "program": program})

        if result == "deny":
            msg = (f"🛡 Protected {count} file(s) in\n<code>{parent_dir}</code>"
                   if count > 1 else
                   f"🛡 Protected: <code>{items[0][1]}</code>")
            self.gate.notify(msg)
            return

        if result == "allow_always":
            dir_rule = parent_dir.rstrip("/") + "/"
            grant_permission(program, dir_rule, "allow_always")
        elif result == "allow_dir":
            dir_rule = parent_dir.rstrip("/") + "/"
            grant_permission(program, dir_rule, "allow_always")
            self.gate.notify(f"📁 Directory allowed: <code>{dir_rule}</code>")

        # Execute all deletions
        deleted = failed = 0
        for inode, path in items:
            try:
                os.unlink(path)
                self.remove_inode(inode)
                deleted += 1
            except FileNotFoundError:
                deleted += 1
            except OSError:
                failed += 1

        log_audit({"event": "disk_allowed", "action": "guardian_bulk_delete",
                   "directory": parent_dir, "program": program,
                   "deleted": deleted, "failed": failed})
        if failed:
            self.gate.notify(
                f"⚠️ {failed} file(s) could not be deleted in "
                f"<code>{parent_dir}</code>"
            )

    def _do_delete(self, inode: int, path: str, program: str):
        try:
            os.unlink(path)
            self.remove_inode(inode)
            log_audit({"event": "disk_allowed", "action": "guardian_delete",
                       "target": path, "program": program})
        except FileNotFoundError:
            pass
        except OSError as e:
            self.gate.notify(
                f"⚠️ Guardian delete failed:\n<code>{path}</code>\n{e}"
            )


def _identify_program(comm: str) -> str:
    """Map raw comm name to a canonical program name for permission lookup."""
    c = comm.lower()
    for keyword, name in (("claude", "claude-code"), ("cursor", "cursor")):
        if keyword in c:
            return name
    return c or "unknown"


def _read_meaningful_cmdline(pid: int, comm: str, ppid: int,
                              max_len: int = 120) -> str:
    """
    Return the most informative command string for a process.

    Short-lived processes (rm, cp, mv) often exit before handle_event runs,
    leaving /proc/{pid}/cmdline empty.  We fall back to the parent process
    (bash) which is still alive and may carry the full command via -c "...".
    """
    def _read_cmdline_raw(p: int) -> list[str]:
        """Return argv as a list of strings, or [] on failure."""
        try:
            raw = Path(f"/proc/{p}/cmdline").read_bytes()
            parts = [a.decode("utf-8", errors="replace")
                     for a in raw.rstrip(b"\x00").split(b"\x00") if a]
            return parts
        except OSError:
            return []

    def _fmt(parts: list[str]) -> str:
        s = " ".join(parts)
        return (s[:max_len] + "…") if len(s) > max_len else s

    def _read_env_var(p: int, var: str) -> str:
        try:
            environ = Path(f"/proc/{p}/environ").read_bytes()
            for entry in environ.split(b"\x00"):
                if entry.startswith(var.encode() + b"="):
                    return entry.split(b"=", 1)[1].decode("utf-8", errors="replace")
        except OSError:
            pass
        return ""

    parts = _read_cmdline_raw(pid)

    # Process still alive and has arguments → done
    if len(parts) > 1:
        return _fmt(parts)

    # Try parent (bash/sh) — stays alive while child runs
    # Claude Code's Bash tool spawns: bash -c "<actual command>"
    parent_parts = _read_cmdline_raw(ppid)
    if parent_parts:
        prog = parent_parts[0].rsplit("/", 1)[-1].lstrip("-")
        if prog in ("bash", "sh", "zsh") and "-c" in parent_parts:
            idx = parent_parts.index("-c")
            if idx + 1 < len(parent_parts):
                # The -c argument IS the shell command the user ran
                cmd = parent_parts[idx + 1]
                return (cmd[:max_len] + "…") if len(cmd) > max_len else cmd
        # Non-shell parent with arguments (e.g. python script)
        if len(parent_parts) > 1:
            skips = {"sshd", "login", "systemd", "init"}
            if prog not in skips:
                child = _fmt(parts) if parts else comm
                return f"{child} (via {_fmt(parent_parts)[:60]})"

    # Process exited, no parent info: try env '_' for full binary path
    if not parts:
        full_path = _read_env_var(pid, "_")
        return full_path if full_path else comm

    # Single-token: enrich with full binary path from env if different
    full_path = _read_env_var(pid, "_")
    if full_path and full_path != parts[0]:
        return full_path

    return _fmt(parts) if parts else comm


def _build_chain(comm: str, pcomm: str, gcomm: str, gpid: int,
                 max_depth: int = 4) -> str:
    """Build process ancestry from eBPF-captured comms + live /proc walk."""
    chain: list[str] = [c for c in (comm, pcomm, gcomm) if c]

    # Continue walking upward from gpid using /proc (grandparent usually lives)
    seen: set[int] = set()
    current = gpid
    while current > 1 and len(chain) < max_depth + 3:
        if current in seen:
            break
        seen.add(current)
        try:
            status = Path(f"/proc/{current}/status").read_text()
            info: dict[str, str] = {}
            for line in status.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    info[k.strip()] = v.strip()
            name = info.get("Name", "?")
            ppid_next = int(info.get("PPid", 0))
            if name in ("systemd", "init") and len(chain) >= 2:
                break
            if name == "sshd" and len(chain) >= 4:
                break
            # Avoid duplicating what eBPF already gave us
            if chain and chain[-1] == name:
                current = ppid_next
                continue
            chain.append(name)
            current = ppid_next
        except Exception:
            break
    return " → ".join(chain)
