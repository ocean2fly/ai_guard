"""
Lightweight SMTP command parser for plaintext data captured from SSL_write.

SMTP flows we care about (after STARTTLS or on SMTPS port):
    EHLO <hostname>
    AUTH LOGIN / AUTH PLAIN ...
    MAIL FROM:<sender@domain>
    RCPT TO:<recipient@domain>
    DATA
    <body>
    .
"""
import re
from typing import Optional


# Keywords that indicate this SSL_write call is carrying SMTP traffic.
# Checked at the start of the data buffer (position 0-4 to allow whitespace).
SMTP_KEYWORDS = (b"EHLO", b"HELO", b"MAIL", b"RCPT", b"DATA", b"AUTH", b"QUIT")

_MAIL_FROM = re.compile(rb"MAIL FROM:\s*<?([^>\r\n ]+)>?", re.IGNORECASE)
_RCPT_TO   = re.compile(rb"RCPT TO:\s*<?([^>\r\n ]+)>?",   re.IGNORECASE)


def is_smtp(data: bytes) -> bool:
    """Return True if the first bytes look like an SMTP command."""
    head = data[:8].upper().lstrip()
    return any(head.startswith(kw) for kw in SMTP_KEYWORDS)


def parse_smtp(data: bytes) -> dict:
    """
    Extract SMTP metadata from a raw SSL_write buffer.
    Returns a dict with keys: command, mail_from, rcpt_to (all may be empty).
    """
    result: dict = {"command": "", "mail_from": "", "rcpt_to": ""}

    head = data[:8].upper().lstrip()
    for kw in SMTP_KEYWORDS:
        if head.startswith(kw):
            result["command"] = kw.decode()
            break

    m = _MAIL_FROM.search(data)
    if m:
        result["mail_from"] = m.group(1).decode("utf-8", errors="replace")

    m = _RCPT_TO.search(data)
    if m:
        result["rcpt_to"] = m.group(1).decode("utf-8", errors="replace")

    return result
