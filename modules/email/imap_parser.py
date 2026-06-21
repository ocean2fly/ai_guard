"""
Lightweight IMAP delete-operation parser for SSL_write plaintext data.

IMAP delete flow (either order works):
    A001 STORE 1 +FLAGS (\Deleted)\r\n
    A002 EXPUNGE\r\n

    A001 UID STORE 123 +FLAGS.SILENT (\Deleted)\r\n
    A002 UID EXPUNGE 123\r\n

We intercept on the STORE … \Deleted command (we know the UID/seqnum
at that point) and optionally on EXPUNGE as a second gate.
"""
import re

# Matches: <tag> [UID] STORE <ids> +FLAGS[.SILENT] (\Deleted ...)
_STORE_DEL = re.compile(
    rb"[A-Za-z0-9*]+\s+"          # tag
    rb"(?:UID\s+)?"                # optional UID prefix
    rb"STORE\s+"                   # STORE command
    rb"([0-9:,*]+)\s+"             # message set (e.g. 1:5, 123, 1:*)
    rb"\+FLAGS(?:\.SILENT)?\s*"    # +FLAGS or +FLAGS.SILENT
    rb"\([^)]*\\Deleted[^)]*\)",   # flags list containing \Deleted
    re.IGNORECASE,
)

# Matches: <tag> [UID] EXPUNGE [ids]
_EXPUNGE = re.compile(
    rb"[A-Za-z0-9*]+\s+(?:UID\s+)?EXPUNGE(?:\s+([0-9:,*]+))?",
    re.IGNORECASE,
)

# Matches: <tag> MOVE <ids> <mailbox>   (some servers support RFC 6851)
_MOVE_TRASH = re.compile(
    rb"[A-Za-z0-9*]+\s+(?:UID\s+)?MOVE\s+([0-9:,*]+)\s+(\S+)",
    re.IGNORECASE,
)


_SELECT_RE = re.compile(
    rb"[A-Za-z0-9*]+\s+SELECT\s+\"?([^\"\r\n]+?)\"?\s*\r?\n",
    re.IGNORECASE,
)


def parse_select_mailbox(data: bytes) -> str:
    """Return the mailbox name from a SELECT command, or '' if not found."""
    m = _SELECT_RE.search(data)
    if m:
        return m.group(1).decode("utf-8", errors="replace").strip().strip('"')
    return ""


def is_imap_delete(data: bytes) -> bool:
    return bool(
        _STORE_DEL.search(data) or
        _EXPUNGE.search(data) or
        _MOVE_TRASH.search(data)
    )


def parse_imap_delete(data: bytes) -> dict:
    """
    Returns dict with keys: operation, message_ids, destination (for MOVE).
    """
    result = {"operation": "", "message_ids": "", "destination": ""}

    m = _STORE_DEL.search(data)
    if m:
        result["operation"]   = "STORE +FLAGS \\Deleted"
        result["message_ids"] = m.group(1).decode("utf-8", errors="replace")
        return result

    m = _EXPUNGE.search(data)
    if m:
        result["operation"]   = "EXPUNGE"
        result["message_ids"] = (m.group(1) or b"all").decode("utf-8", errors="replace")
        return result

    m = _MOVE_TRASH.search(data)
    if m:
        result["operation"]   = "MOVE"
        result["message_ids"] = m.group(1).decode("utf-8", errors="replace")
        result["destination"] = m.group(2).decode("utf-8", errors="replace")
        return result

    return result
