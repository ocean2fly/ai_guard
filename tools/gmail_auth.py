#!/usr/bin/env python3
"""
Gmail OAuth setup for Email Guardian test.
Step 1: python3 gmail_auth.py auth   → prints URL, you open it and paste the code
Step 2: python3 gmail_auth.py send <to>  → sends test email via Gmail SMTP (triggers Email Guardian)
"""
import json
import os
import sys
from pathlib import Path

CLIENT_SECRET_FILE = Path.home() / ".credentials" / "gmail_client_secret.json"
TOKEN_FILE         = Path.home() / ".credentials" / "gmail_token.json"

SCOPES = ["https://mail.google.com/"]

CLIENT_ID     = ""  # set via --client-id argument or config.yaml
CLIENT_SECRET = ""  # set via --client-secret argument or config.yaml


def _make_client_config():
    return {
        "installed": {
            "client_id":     CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "auth_uri":      "https://accounts.google.com/o/oauth2/auth",
            "token_uri":     "https://oauth2.googleapis.com/token",
            "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob", "http://localhost"],
        }
    }


def cmd_auth():
    from google_auth_oauthlib.flow import InstalledAppFlow

    Path(TOKEN_FILE.parent).mkdir(parents=True, exist_ok=True)
    flow = InstalledAppFlow.from_client_config(_make_client_config(), SCOPES)

    # Manual copy-paste flow (works on headless VPS)
    flow.redirect_uri = "urn:ietf:wg:oauth:2.0:oob"
    auth_url, _ = flow.authorization_url(prompt="consent", access_type="offline")

    print("\n=== Gmail OAuth Authorization ===")
    print("1. Open this URL in your browser:\n")
    print(f"   {auth_url}\n")
    print("2. Sign in with your Gmail account and grant access")
    print("3. Copy the authorization code shown and paste it below\n")

    code = input("Paste authorization code: ").strip()
    flow.fetch_token(code=code)
    creds = flow.credentials

    token_data = {
        "token":         creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri":     creds.token_uri,
        "client_id":     creds.client_id,
        "client_secret": creds.client_secret,
        "scopes":        list(creds.scopes) if creds.scopes else SCOPES,
    }
    TOKEN_FILE.write_text(json.dumps(token_data, indent=2))
    print(f"\n[✓] Token saved to {TOKEN_FILE}")
    print(f"    Access token: {creds.token[:30]}...")


def cmd_send(to_addr: str, subject: str = "Email Guardian Test", body: str = ""):
    """Send a real email via Gmail SMTP+OAuth — triggers Email Guardian on SSL_write."""
    import smtplib
    import base64
    import json as _json

    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials

    if not TOKEN_FILE.exists():
        print(f"[!] No token found at {TOKEN_FILE}. Run: python3 gmail_auth.py auth")
        sys.exit(1)

    data = _json.loads(TOKEN_FILE.read_text())
    creds = Credentials(
        token=data["token"],
        refresh_token=data["refresh_token"],
        token_uri=data["token_uri"],
        client_id=data["client_id"],
        client_secret=data["client_secret"],
        scopes=data["scopes"],
    )
    if not creds.valid:
        creds.refresh(Request())
        TOKEN_FILE.write_text(_json.dumps({
            "token": creds.token, "refresh_token": creds.refresh_token,
            "token_uri": creds.token_uri, "client_id": creds.client_id,
            "client_secret": creds.client_secret, "scopes": list(creds.scopes or SCOPES),
        }, indent=2))

    # Build XOAUTH2 string
    user = "me"  # Will be resolved via token
    # Get the actual Gmail address
    from google.auth.transport.requests import AuthorizedSession
    import urllib.request, urllib.error
    req = urllib.request.Request(
        "https://www.googleapis.com/oauth2/v1/userinfo",
        headers={"Authorization": f"Bearer {creds.token}"},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            uinfo = _json.loads(resp.read())
            gmail_addr = uinfo.get("email", "")
            print(f"[*] Sending from: {gmail_addr}")
    except Exception:
        gmail_addr = ""

    if not body:
        body = (
            "This is a test email sent to verify the Email Guardian intercept.\n\n"
            "If you see this in your Telegram first, the guardian is working!\n"
        )

    # Compose raw email
    from email.mime.text import MIMEText
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"]    = gmail_addr
    msg["To"]      = to_addr

    xoauth2_str = f"user={gmail_addr}\x01auth=Bearer {creds.token}\x01\x01"
    xoauth2_b64 = base64.b64encode(xoauth2_str.encode()).decode()

    print(f"[*] Connecting to smtp.gmail.com:587 (STARTTLS)...")
    print(f"    Subject: {subject}")
    print(f"    To: {to_addr}")
    print(f"    [Email Guardian should intercept MAIL FROM]")

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.docmd("AUTH", "XOAUTH2 " + xoauth2_b64)
        server.sendmail(gmail_addr, [to_addr], msg.as_string())
        print("[✓] Email sent (or blocked by guardian)")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 gmail_auth.py auth")
        print("  python3 gmail_auth.py send <recipient@email.com>")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "auth":
        cmd_auth()
    elif cmd == "send":
        if len(sys.argv) < 3:
            print("Usage: python3 gmail_auth.py send <to@email.com>")
            sys.exit(1)
        cmd_send(sys.argv[2])
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
