#!/usr/bin/env python3
"""
邮件管理系统 - 提供邮箱整理、归档、清理功能
"""

import imaplib, json, base64, time, os, warnings
warnings.filterwarnings("ignore")
import google.oauth2.credentials
import google.auth.transport.requests

class EmailManager:
    def __init__(self, config_path):
        self.config = json.load(open(config_path))
        self.conn = None

    def _get_token(self):
        d = self.config
        creds = google.oauth2.credentials.Credentials(
            token=d["access_token"],
            refresh_token=d["refresh_token"],
            token_uri="https://oauth2.googleapis.com/token",
            client_id=d["client_id"],
            client_secret=d["client_secret"],
            scopes=["https://mail.google.com/"],
        )
        creds.refresh(google.auth.transport.requests.Request())
        return creds.token

    def connect(self):
        token = self._get_token()
        user = "jackzhao39@gmail.com"
        self.conn = imaplib.IMAP4_SSL("imap.gmail.com")
        auth = base64.b64encode(f"user={user}\x01auth=Bearer {token}\x01\x01".encode()).decode()
        self.conn.authenticate("XOAUTH2", lambda x: auth)
        return self

    def list_folders(self):
        _, folders = self.conn.list()
        return [f.decode() for f in folders]

    def get_stats(self):
        self.conn.select("INBOX")
        _, total = self.conn.search(None, "ALL")
        _, unread = self.conn.search(None, "UNSEEN")
        return {
            "total": len(total[0].split()),
            "unread": len(unread[0].split()),
        }

    def search(self, query):
        self.conn.select("INBOX")
        _, ids = self.conn.search(None, query)
        return ids[0].split()

    def archive(self, msg_ids):
        """将邮件归档（标记为已读并移出收件箱）"""
        for mid in msg_ids:
            self.conn.store(mid, "+FLAGS", "\\Seen")

    def cleanup(self, query="SUBJECT \"[AI Guardian Test]\""):
        """清理符合条件的邮件"""
        ids = self.search(query)
        if not ids:
            print("没有找到需要清理的邮件")
            return 0
        for mid in ids:
            self.conn.store(mid, "+FLAGS", "\\Deleted")
        self.conn.expunge()
        return len(ids)

    def organize(self):
        """整理邮箱：归档已读、清理测试邮件"""
        stats = self.get_stats()
        print(f"邮箱状态: 共 {stats['total']} 封，未读 {stats['unread']} 封")

        # 归档超过30天的已读邮件
        old_ids = self.search("SEEN BEFORE 30-Jun-2025")
        if old_ids:
            self.archive(old_ids)
            print(f"归档 {len(old_ids)} 封旧邮件")

        # 清理测试邮件
        cleaned = self.cleanup()
        print(f"清理 {cleaned} 封测试邮件")

        return {"archived": len(old_ids) if old_ids else 0, "cleaned": cleaned}

    def disconnect(self):
        if self.conn:
            self.conn.logout()


if __name__ == "__main__":
    mgr = EmailManager("/home/ec2-user/.credentials/gmail_token.json")
    mgr.connect()
    result = mgr.organize()
    print("整理完成:", result)
    mgr.disconnect()
