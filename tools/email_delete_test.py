#!/usr/bin/env python3
"""
测试脚本：创建一封测试邮件，然后删除它。
用途：验证 Email Guardian 是否能拦截 IMAP EXPUNGE 操作。
"""

import imaplib
import base64
import json
import time
import sys
import os
import warnings
warnings.filterwarnings("ignore")

import google.oauth2.credentials
import google.auth.transport.requests

TOKEN_PATH = os.environ.get(
    "GMAIL_TOKEN_PATH",
    "/home/ec2-user/.credentials/gmail_token.json"
)
IMAP_HOST = "imap.gmail.com"
IMAP_PORT = 993

def load_and_refresh_token():
    with open(TOKEN_PATH) as f:
        data = json.load(f)

    creds = google.oauth2.credentials.Credentials(
        token=data["access_token"],
        refresh_token=data["refresh_token"],
        token_uri="https://oauth2.googleapis.com/token",
        client_id=data["client_id"],
        client_secret=data["client_secret"],
        scopes=["https://mail.google.com/"],
    )

    request = google.auth.transport.requests.Request()
    creds.refresh(request)

    # 保存刷新后的 token
    data["access_token"] = creds.token
    with open(TOKEN_PATH, "w") as f:
        json.dump(data, f)

    return creds.token


def xoauth2_string(user: str, token: str) -> str:
    s = f"user={user}\x01auth=Bearer {token}\x01\x01"
    return base64.b64encode(s.encode()).decode()


def main():
    email_user = "jackzhao39@gmail.com"

    print("[1/4] 刷新 OAuth2 token ...")
    token = load_and_refresh_token()

    print(f"[2/4] 连接 IMAP {IMAP_HOST}:{IMAP_PORT} ...")
    mail = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
    auth_str = xoauth2_string(email_user, token)
    mail.authenticate("XOAUTH2", lambda x: auth_str)

    print("[3/4] 创建测试邮件（APPEND 到 INBOX）...")
    msg_body = (
        "From: jackzhao39@gmail.com\r\n"
        "To: jackzhao39@gmail.com\r\n"
        "Subject: [AI Guardian Test] 测试邮件 - 将被删除\r\n"
        "\r\n"
        "这是由 AI Agent 创建的测试邮件，用于验证 Email Guardian 删除拦截。\r\n"
    ).encode()

    result, data = mail.append(
        "INBOX", None,
        imaplib.Time2Internaldate(time.time()),
        msg_body
    )
    if result != "OK":
        print(f"创建失败：{result} {data}")
        sys.exit(1)
    print(f"    创建成功：{data}")

    print("[4/4] 搜索并删除测试邮件 ...")
    mail.select("INBOX")
    _, msg_ids = mail.search(None, 'SUBJECT "[AI Guardian Test]"')
    ids = msg_ids[0].split()
    if not ids:
        print("找不到测试邮件")
        sys.exit(1)

    target_id = ids[-1]
    print(f"    标记删除 ID={target_id.decode()} ...")
    mail.store(target_id, "+FLAGS", "\\Deleted")

    print("    执行 EXPUNGE（Email Guardian 应在此拦截）...")
    mail.expunge()

    print("\n完成：邮件已删除。")
    print("（若 Email Guardian 在线，上述 EXPUNGE 操作应已被拦截）")
    mail.logout()


if __name__ == "__main__":
    main()
