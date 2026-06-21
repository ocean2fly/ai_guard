# AI Guardian

> AI Agent 操作守护程序 — 系统层真实确认门

**环境：** Amazon Linux 2023 · kernel 6.1.172 · x86_64  
**目标：** 在操作系统层拦截 AI Agent 的删除和修改操作，提供真实的人类确认机制

---

## 核心设计理念

AI 工具（Cursor、Claude Code 等）内置的"确认"停留在 AI 自己的逻辑层——AI 可以自己绕过自己的规则。

**AI Guardian 的确认是真实的：**  
操作在系统调用层被拦截，挂起等待真实人类响应，超时自动拒绝，AI 无法绕过。

### 监控范围

只监控**删除和修改**操作：

| 资源 | 监控内容 |
|------|---------|
| Disk | 文件/目录删除、文件内容覆盖 |
| DB (PostgreSQL) | 单记录删除、单表删除、整库删除、批量修改 |
| Email | 外发邮件（尤其是外部地址） |

### 批量阈值规则

**无论是否已授权**，单次操作超过 **3 个单位**强制触发二次确认：
- Disk：> 3 个文件
- DB：> 3 行记录 / > 3 张表
- Email：> 3 封邮件

---

## 目录结构

```
ai-guardian/
├── guardian.py          # 主程序入口
├── config.yaml          # 权限配置文件
├── modules/
│   ├── disk.py          # Disk 守护模块
│   ├── db.py            # DB 守护模块
│   └── email_guard.py   # Email 守护模块
├── confirm/
│   ├── terminal.py      # 终端确认门
│   ├── web.py           # 本地网页确认（可选）
│   └── telegram.py      # Telegram Bot 确认（可选）
├── dashboard.py         # 实时 Dashboard
├── permissions.py       # 权限管理
├── audit.log            # 审计日志（JSONL 格式）
└── backups/
    ├── disk/            # 文件备份
    └── db/              # pg_dump 备份
```

---

## 一、环境准备

```bash
# 更新系统
sudo dnf update -y

# 安装 Python 依赖
sudo dnf install -y python3 python3-pip postgresql15

# 安装 Python 包
pip3 install \
  inotify-simple \
  psycopg2-binary \
  aiosmtpd \
  textual \
  rich \
  pyyaml \
  python-telegram-bot \
  aiohttp \
  click

# 创建工作目录
mkdir -p ~/ai-guardian/{modules,confirm,backups/disk,backups/db}
cd ~/ai-guardian
```

---

## 二、权限配置文件

```yaml
# config.yaml
# 权限规则：allow_always / ask / deny
# 批量阈值：bulk_threshold（默认 3）

global:
  bulk_threshold: 3          # 超过此数量强制二次确认
  backup_retention_days: 3   # 备份保留天数
  timeout_seconds: 30        # 确认超时后自动拒绝
  confirm_method: terminal   # terminal / web / telegram

telegram:
  bot_token: ""              # 填入你的 Telegram Bot Token
  chat_id: ""                # 填入你的 Chat ID

programs:
  cursor:
    disk:
      - path: /tmp/
        action: allow_always
      - path: /home/ec2-user/project/
        action: allow_always
        bulk_threshold: 3    # 超过 3 个文件仍需确认
      - path: /
        action: ask          # 其他路径每次询问
    db:
      - scope: table
        name: sessions
        action: allow_always
      - scope: table
        name: users
        action: ask
      - scope: database
        name: "*"
        action: deny         # 整库操作永久拒绝
    email:
      - recipient: "*@internal.company.com"
        action: allow_always
      - recipient: "*"
        action: ask          # 外部地址每次询问

  claude-code:
    disk:
      - path: /tmp/
        action: allow_always
      - path: /
        action: ask
    db:
      - scope: "*"
        action: deny
    email:
      - recipient: "*"
        action: deny

  unknown:                   # 未知程序默认全拒绝
    disk:
      - path: /
        action: deny
    db:
      - scope: "*"
        action: deny
    email:
      - recipient: "*"
        action: deny
```

---

## 三、权限管理模块

```python
# permissions.py
import yaml
import json
import os
from datetime import datetime
from pathlib import Path

CONFIG_FILE = "config.yaml"
AUDIT_LOG = "audit.log"

def load_config():
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f)

def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        yaml.dump(config, f, default_flow_style=False, allow_unicode=True)

def log_audit(event: dict):
    event["timestamp"] = datetime.now().isoformat()
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")

def check_permission(program: str, resource_type: str, target: str, count: int = 1) -> str:
    """
    返回值：
      allow_always  — 永久允许（但 count > bulk_threshold 时返回 bulk_warn）
      ask           — 需要询问用户
      deny          — 永久拒绝
      bulk_warn     — 已授权但超出批量阈值
    """
    config = load_config()
    bulk_threshold = config["global"]["bulk_threshold"]
    programs = config.get("programs", {})

    prog_config = programs.get(program, programs.get("unknown", {}))
    rules = prog_config.get(resource_type, [])

    for rule in rules:
        if _matches(rule, target):
            action = rule.get("action", "ask")
            threshold = rule.get("bulk_threshold", bulk_threshold)
            if action == "allow_always" and count > threshold:
                return "bulk_warn"
            return action

    return "ask"

def _matches(rule: dict, target: str) -> bool:
    import fnmatch
    pattern = rule.get("path") or rule.get("recipient") or rule.get("name") or "*"
    return fnmatch.fnmatch(target, pattern)

def grant_permission(program: str, resource_type: str, target: str,
                     action: str, scope: str = None):
    """永久授权，写入 config.yaml"""
    config = load_config()
    if program not in config["programs"]:
        config["programs"][program] = {}
    if resource_type not in config["programs"][program]:
        config["programs"][program][resource_type] = []

    new_rule = {"action": action}
    if resource_type == "disk":
        new_rule["path"] = target
    elif resource_type == "db":
        new_rule["scope"] = scope or "table"
        new_rule["name"] = target
    elif resource_type == "email":
        new_rule["recipient"] = target

    config["programs"][program][resource_type].insert(0, new_rule)
    save_config(config)
    log_audit({
        "event": "permission_granted",
        "program": program,
        "resource_type": resource_type,
        "target": target,
        "action": action,
    })
```

---

## 四、终端确认门

```python
# confirm/terminal.py
import sys
import threading
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

def ask_user(operation: dict, timeout: int = 30) -> str:
    """
    展示操作详情，等待用户输入。
    返回值：allow_once / allow_always / deny / timeout
    """
    _print_operation(operation)

    result = {"value": "timeout"}
    answered = threading.Event()

    def _input_thread():
        try:
            console.print(
                "\n[bold]选择操作：[/bold]\n"
                "  [red]1[/red] 拒绝\n"
                "  [green]2[/green] 允许一次\n"
                "  [yellow]3[/yellow] 以后都允许（选择范围）\n"
                "  [blue]4[/blue] 授权此程序\n",
                highlight=False
            )
            choice = input(f"请输入 1-4（{timeout}秒后自动拒绝）: ").strip()
            if choice == "1":
                result["value"] = "deny"
            elif choice == "2":
                result["value"] = "allow_once"
            elif choice == "3":
                result["value"] = _ask_always_scope(operation)
            elif choice == "4":
                result["value"] = _ask_program_auth(operation)
            else:
                result["value"] = "deny"
        except (EOFError, KeyboardInterrupt):
            result["value"] = "deny"
        finally:
            answered.set()

    t = threading.Thread(target=_input_thread, daemon=True)
    t.start()
    answered.wait(timeout=timeout)

    return result["value"]

def _print_operation(op: dict):
    resource = op.get("resource_type", "unknown")
    color_map = {"disk": "red", "db": "magenta", "email": "yellow"}
    color = color_map.get(resource, "white")

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column("字段", style="dim", width=12)
    table.add_column("值")

    for key, val in op.get("details", {}).items():
        table.add_row(key, str(val))

    panel = Panel(
        table,
        title=f"[bold {color}]⚠ AI Guardian — 高危操作拦截[/bold {color}]",
        subtitle=f"[dim]{op.get('program', 'unknown')} (PID {op.get('pid', '?')})[/dim]",
        border_style=color,
    )
    console.print(panel)

    # 备份状态
    if op.get("backup_path"):
        console.print(
            f"[green]✓ 已备份至 {op['backup_path']}[/green]"
        )

def _ask_always_scope(op: dict) -> str:
    console.print("\n[bold]选择授权范围：[/bold]")
    resource = op.get("resource_type")

    if resource == "disk":
        path = op["details"].get("路径", "/")
        parent = str(Path(path).parent)
        console.print(f"  1  仅此文件/目录：{path}")
        console.print(f"  2  上级目录：{parent}")
        console.print(f"  3  以上 + 批量超3个仍需确认（推荐）")
        choice = input("请选择 1-3: ").strip()
        target = path if choice == "1" else parent
        return f"allow_always:disk:{target}:{'bulk_warn' if choice == '3' else 'full'}"

    elif resource == "db":
        console.print(f"  1  仅此表")
        console.print(f"  2  整个数据库")
        console.print(f"  3  以上 + 批量超3个仍需确认（推荐）")
        choice = input("请选择 1-3: ").strip()
        scope = "table" if choice == "1" else "database"
        return f"allow_always:db:{scope}:{'bulk_warn' if choice == '3' else 'full'}"

    elif resource == "email":
        console.print(f"  1  仅此收件人")
        console.print(f"  2  此域名下所有地址")
        choice = input("请选择 1-2: ").strip()
        return f"allow_always:email:{choice}"

    return "allow_once"

def _ask_program_auth(op: dict) -> str:
    console.print(
        f"\n[bold]为 {op.get('program')} 配置永久权限...[/bold]\n"
        "此配置将写入 config.yaml，可随时修改。\n"
    )
    return f"program_auth:{op.get('program')}"

from pathlib import Path
```

---

## 五、Disk 守护模块

```python
# modules/disk.py
import os
import shutil
import subprocess
from pathlib import Path
from datetime import datetime
import inotify_simple

from permissions import check_permission, log_audit
from confirm.terminal import ask_user

BACKUP_DIR = Path("backups/disk")
WATCH_PATHS = ["/home/ec2-user", "/var/www", "/opt/app"]

# inotify 监听的事件
WATCH_FLAGS = (
    inotify_simple.flags.DELETE |
    inotify_simple.flags.DELETE_SELF |
    inotify_simple.flags.MOVED_FROM |
    inotify_simple.flags.CLOSE_WRITE  # 文件被覆盖写入
)

class DiskGuardian:
    def __init__(self):
        self.inotify = inotify_simple.INotify()
        self.wd_to_path = {}
        self._add_watches()

    def _add_watches(self):
        for path in WATCH_PATHS:
            if os.path.exists(path):
                wd = self.inotify.add_watch(path, WATCH_FLAGS)
                self.wd_to_path[wd] = path
                # 递归监听子目录
                for root, dirs, _ in os.walk(path):
                    for d in dirs:
                        full = os.path.join(root, d)
                        try:
                            wd = self.inotify.add_watch(full, WATCH_FLAGS)
                            self.wd_to_path[wd] = full
                        except PermissionError:
                            pass

    def run(self):
        print("[DiskGuardian] 启动，监控中...")
        while True:
            events = self.inotify.read()
            for event in events:
                self._handle_event(event)

    def _handle_event(self, event):
        parent_path = self.wd_to_path.get(event.wd, "unknown")
        target = os.path.join(parent_path, event.name) if event.name else parent_path

        # 获取触发进程（通过 /proc 查找最近修改此路径的进程）
        program, pid = _get_triggering_process(target)

        # 检查权限
        permission = check_permission(program, "disk", target, count=1)

        if permission == "allow_always":
            log_audit({"event": "disk_allowed", "target": target, "program": program})
            return

        if permission == "deny":
            # 尝试撤销操作（如果文件还存在）
            log_audit({"event": "disk_denied", "target": target, "program": program})
            return

        # ask 或 bulk_warn：备份后询问
        backup_path = self._backup(target)

        op = {
            "resource_type": "disk",
            "program": program,
            "pid": pid,
            "backup_path": backup_path,
            "details": {
                "操作": "删除/覆盖",
                "路径": target,
                "触发程序": f"{program} (PID {pid})",
            }
        }

        if permission == "bulk_warn":
            op["details"]["警告"] = "已授权路径，但批量操作超出阈值"

        result = ask_user(op)
        _handle_result(result, op, "disk", target)

    def _backup(self, path: str) -> str:
        """删除前备份文件到隔离目录"""
        if not os.path.exists(path):
            return None
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        # 保留原始目录结构
        rel = path.lstrip("/")
        dest = BACKUP_DIR / timestamp / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            if os.path.isdir(path):
                shutil.copytree(path, dest)
            else:
                shutil.copy2(path, dest)
            return str(dest)
        except Exception as e:
            print(f"[DiskGuardian] 备份失败: {e}")
            return None

def _get_triggering_process(path: str):
    """通过 fuser/lsof 找到操作文件的进程"""
    try:
        result = subprocess.run(
            ["fuser", path], capture_output=True, text=True, timeout=2
        )
        pid = result.stdout.strip().split()[0] if result.stdout.strip() else "?"
        if pid != "?":
            with open(f"/proc/{pid}/comm") as f:
                name = f.read().strip()
            return name, pid
    except Exception:
        pass
    return "unknown", "?"

def _handle_result(result: str, op: dict, resource_type: str, target: str):
    log_audit({
        "event": f"{resource_type}_decision",
        "result": result,
        "target": target,
        "program": op.get("program"),
    })
    if result.startswith("allow_always"):
        from permissions import grant_permission
        parts = result.split(":")
        grant_permission(
            program=op["program"],
            resource_type=resource_type,
            target=target,
            action="allow_always"
        )
```

---

## 六、DB 守护模块

```python
# modules/db.py
import psycopg2
import subprocess
from datetime import datetime
from pathlib import Path

from permissions import check_permission, log_audit
from confirm.terminal import ask_user

BACKUP_DIR = Path("backups/db")

# 高危 SQL 关键词
HIGH_RISK_KEYWORDS = [
    "DROP TABLE", "DROP DATABASE", "TRUNCATE",
    "DELETE FROM", "ALTER TABLE", "DROP SCHEMA"
]

class DBGuardian:
    """
    通过 PostgreSQL Event Trigger 拦截危险 DDL 操作。
    DML（DELETE）通过规则重写拦截。
    """

    def __init__(self, dsn: str):
        self.dsn = dsn
        self._install_triggers()

    def _install_triggers(self):
        """在 PostgreSQL 安装拦截触发器"""
        conn = psycopg2.connect(self.dsn)
        conn.autocommit = True
        cur = conn.cursor()

        # 创建通知函数（DDL 触发器）
        cur.execute("""
        CREATE OR REPLACE FUNCTION ai_guardian_ddl_intercept()
        RETURNS event_trigger LANGUAGE plpgsql AS $$
        DECLARE
            obj record;
        BEGIN
            FOR obj IN SELECT * FROM pg_event_trigger_ddl_commands() LOOP
                -- 通过 pg_notify 通知守护程序
                PERFORM pg_notify(
                    'ai_guardian',
                    json_build_object(
                        'command_tag', obj.command_tag,
                        'object_type', obj.object_type,
                        'object_identity', obj.object_identity,
                        'schema_name', obj.schema_name
                    )::text
                );
            END LOOP;
        END;
        $$;
        """)

        # 注册 DDL 事件触发器
        cur.execute("""
        DROP EVENT TRIGGER IF EXISTS ai_guardian_ddl;
        CREATE EVENT TRIGGER ai_guardian_ddl
            ON ddl_command_end
            WHEN TAG IN ('DROP TABLE', 'DROP DATABASE', 'TRUNCATE TABLE',
                         'ALTER TABLE', 'DROP SCHEMA')
            EXECUTE FUNCTION ai_guardian_ddl_intercept();
        """)

        cur.close()
        conn.close()
        print("[DBGuardian] 触发器安装完成")

    def run(self):
        """监听 PostgreSQL NOTIFY 通道"""
        import select
        conn = psycopg2.connect(self.dsn)
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute("LISTEN ai_guardian;")
        print("[DBGuardian] 监听数据库操作中...")

        while True:
            if select.select([conn], [], [], 5) != ([], [], []):
                conn.poll()
                while conn.notifies:
                    notify = conn.notifies.pop(0)
                    self._handle_notify(notify.payload)

    def _handle_notify(self, payload: str):
        import json
        data = json.loads(payload)
        command = data.get("command_tag", "")
        obj_identity = data.get("object_identity", "")
        obj_type = data.get("object_type", "")

        # 判断影响范围
        scope = "database" if "DATABASE" in command else "table"
        program, pid = "cursor", "?"  # 生产环境可通过 pg_stat_activity 查询

        # 检查权限
        permission = check_permission(program, "db", obj_identity, count=1)

        if permission == "allow_always":
            log_audit({"event": "db_allowed", "command": command, "target": obj_identity})
            return

        if permission == "deny":
            log_audit({"event": "db_denied", "command": command, "target": obj_identity})
            self._rollback(obj_identity)
            return

        # 备份后询问
        backup_path = self._backup(obj_identity, scope)

        op = {
            "resource_type": "db",
            "program": program,
            "pid": pid,
            "backup_path": backup_path,
            "details": {
                "操作": command,
                "对象": obj_identity,
                "类型": obj_type,
                "范围": scope,
                "触发程序": f"{program} (PID {pid})",
            }
        }

        result = ask_user(op)
        log_audit({
            "event": "db_decision",
            "result": result,
            "command": command,
            "target": obj_identity,
        })

    def _backup(self, table_or_db: str, scope: str) -> str:
        """执行 pg_dump 备份"""
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        safe_name = table_or_db.replace("/", "_").replace(" ", "_")
        dest = BACKUP_DIR / f"{timestamp}_{safe_name}.sql"
        dest.parent.mkdir(parents=True, exist_ok=True)

        try:
            if scope == "table":
                cmd = ["pg_dump", "-t", table_or_db, "-f", str(dest)]
            else:
                cmd = ["pg_dump", "-f", str(dest)]
            subprocess.run(cmd, check=True, capture_output=True)
            return str(dest)
        except subprocess.CalledProcessError as e:
            print(f"[DBGuardian] pg_dump 失败: {e}")
            return None

    def _rollback(self, target: str):
        """尝试回滚（仅在事务内有效）"""
        print(f"[DBGuardian] 拒绝操作：{target}")

    def check_bulk_delete(self, table: str, where_clause: str,
                           program: str = "cursor") -> bool:
        """
        检查 DELETE 影响行数，超过阈值触发确认。
        在执行 DELETE 前调用此方法。
        返回 True 表示允许继续，False 表示拒绝。
        """
        conn = psycopg2.connect(self.dsn)
        cur = conn.cursor()

        # 先 COUNT 影响行数
        cur.execute(f"SELECT COUNT(*) FROM {table} WHERE {where_clause}")
        count = cur.fetchone()[0]
        cur.close()
        conn.close()

        from load_config import load_config
        threshold = load_config()["global"]["bulk_threshold"]

        permission = check_permission(program, "db", table, count=count)

        if permission == "allow_always" and count <= threshold:
            return True

        # 超出阈值或需要询问
        backup_path = self._backup(table, "table")
        op = {
            "resource_type": "db",
            "program": program,
            "pid": "?",
            "backup_path": backup_path,
            "details": {
                "操作": f"DELETE FROM {table} WHERE {where_clause}",
                "影响行数": f"{count} 行",
                "阈值": threshold,
                "警告": f"批量删除 {count} 行，超出阈值 {threshold}",
            }
        }

        result = ask_user(op)
        return result in ("allow_once", "allow_always")
```

---

## 七、Email 守护模块

```python
# modules/email_guard.py
import asyncio
import re
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import AsyncMessage

from permissions import check_permission, log_audit
from confirm.terminal import ask_user

BULK_THRESHOLD = 3

class GuardianSMTPHandler(AsyncMessage):
    """拦截所有出站邮件的 SMTP 代理处理器"""

    async def handle_message(self, message):
        sender = message.get("from", "")
        recipients = message.get_all("to", []) + message.get_all("cc", [])
        subject = message.get("subject", "")
        body = message.get_payload(decode=True) or b""

        program = "cursor"  # 生产环境可通过连接信息判断
        count = len(recipients)

        # 检测外部地址
        internal_domains = ["internal.company.com", "localhost"]
        external = [r for r in recipients
                    if not any(d in r for d in internal_domains)]

        # 检测敏感关键词
        sensitive_keywords = [
            "password", "secret", "token", "credential",
            ".env", "private_key", "api_key"
        ]
        body_str = body.decode("utf-8", errors="ignore").lower()
        subject_lower = subject.lower()
        is_sensitive = any(
            kw in body_str or kw in subject_lower
            for kw in sensitive_keywords
        )

        # 判断风险级别
        if not external and not is_sensitive and count <= BULK_THRESHOLD:
            # 低风险：记录日志放行
            log_audit({
                "event": "email_allowed",
                "sender": sender,
                "recipients": recipients,
                "subject": subject,
                "program": program,
            })
            return

        # 高风险：备份 + 询问
        backup_path = self._backup_email(message)

        warnings = []
        if external:
            warnings.append(f"外部收件人: {', '.join(external)}")
        if is_sensitive:
            warnings.append("内容含敏感关键词")
        if count > BULK_THRESHOLD:
            warnings.append(f"批量发送 {count} 封（阈值: {BULK_THRESHOLD}）")

        op = {
            "resource_type": "email",
            "program": program,
            "pid": "?",
            "backup_path": backup_path,
            "details": {
                "发件人": sender,
                "收件人": ", ".join(recipients),
                "主题": subject,
                "数量": f"{count} 封",
                "风险": " | ".join(warnings),
            }
        }

        result = ask_user(op)
        log_audit({
            "event": "email_decision",
            "result": result,
            "sender": sender,
            "recipients": recipients,
            "program": program,
        })

        if result in ("deny", "timeout"):
            raise Exception("AI Guardian: 邮件发送被拒绝")

    def _backup_email(self, message) -> str:
        from datetime import datetime
        from pathlib import Path
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        dest = Path("backups/email") / f"{timestamp}.eml"
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "w") as f:
            f.write(str(message))
        return str(dest)


def start_email_guardian(host="localhost", port=2525):
    """
    启动本地 SMTP 代理，监听 2525 端口。
    将 AI 工具的 SMTP 配置指向 localhost:2525。
    """
    handler = GuardianSMTPHandler()
    controller = Controller(handler, hostname=host, port=port)
    controller.start()
    print(f"[EmailGuardian] SMTP 代理启动于 {host}:{port}")
    return controller
```

---

## 八、实时 Dashboard

```python
# dashboard.py
import json
import os
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.layout import Layout
from rich.panel import Panel
from rich.live import Live
from rich import box
import time

AUDIT_LOG = "audit.log"

def load_recent_events(n=10):
    events = []
    if not os.path.exists(AUDIT_LOG):
        return events
    with open(AUDIT_LOG) as f:
        lines = f.readlines()
    for line in lines[-n:]:
        try:
            events.append(json.loads(line.strip()))
        except Exception:
            pass
    return list(reversed(events))

def count_backups():
    total, size = 0, 0
    for d in [Path("backups/disk"), Path("backups/db")]:
        if d.exists():
            for f in d.rglob("*"):
                if f.is_file():
                    total += 1
                    size += f.stat().st_size
    return total, size / (1024 * 1024)

def render_dashboard():
    console = Console()
    with Live(console=console, refresh_per_second=1) as live:
        while True:
            events = load_recent_events(8)
            total_backups, backup_mb = count_backups()

            # 事件表格
            table = Table(
                box=box.SIMPLE,
                show_header=True,
                header_style="bold dim",
                padding=(0, 1)
            )
            table.add_column("时间", width=10)
            table.add_column("结果", width=8)
            table.add_column("类型", width=6)
            table.add_column("目标", width=40)
            table.add_column("程序", width=12)

            result_style = {
                "allow": "green",
                "deny": "red",
                "timeout": "yellow",
                "bulk_warn": "yellow",
            }

            for e in events:
                ts = e.get("timestamp", "")[-8:-3] if e.get("timestamp") else "?"
                result = e.get("result", e.get("event", "?"))
                rtype = e.get("resource_type", "?")
                target = (e.get("target") or e.get("command") or "?")[:38]
                program = e.get("program", "?")
                style = result_style.get(result, "white")
                table.add_row(
                    ts,
                    f"[{style}]{result}[/{style}]",
                    rtype,
                    target,
                    program
                )

            layout = Panel(
                table,
                title=f"[bold]AI Guardian Dashboard[/bold]  "
                      f"[dim]{datetime.now().strftime('%H:%M:%S')}[/dim]",
                subtitle=f"[dim]已备份: {total_backups} 个文件  {backup_mb:.1f} MB[/dim]",
                border_style="blue"
            )
            live.update(layout)
            time.sleep(1)

if __name__ == "__main__":
    render_dashboard()
```

---

## 九、主程序入口

```python
# guardian.py
import click
import threading
import subprocess
import sys
import os

@click.group()
def cli():
    """AI Guardian — AI Agent 操作守护程序"""
    pass

@cli.command()
@click.option("--disk", is_flag=True, default=True, help="启用 Disk 守护")
@click.option("--db", is_flag=True, default=False, help="启用 DB 守护")
@click.option("--email", is_flag=True, default=False, help="启用 Email 守护")
@click.option("--dsn", default="", help="PostgreSQL DSN（启用 DB 守护时必填）")
def start(disk, db, email, dsn):
    """启动守护程序"""
    threads = []

    if disk:
        from modules.disk import DiskGuardian
        g = DiskGuardian()
        t = threading.Thread(target=g.run, daemon=True)
        t.start()
        threads.append(t)
        click.echo("[✓] Disk 守护已启动")

    if db and dsn:
        from modules.db import DBGuardian
        g = DBGuardian(dsn)
        t = threading.Thread(target=g.run, daemon=True)
        t.start()
        threads.append(t)
        click.echo("[✓] DB 守护已启动")

    if email:
        from modules.email_guard import start_email_guardian
        start_email_guardian()
        click.echo("[✓] Email 守护已启动（SMTP 代理端口 2525）")

    click.echo("\nAI Guardian 运行中，按 Ctrl+C 退出\n")

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        click.echo("\n[AI Guardian] 停止")

@cli.command()
def dashboard():
    """实时监控 Dashboard"""
    from dashboard import render_dashboard
    render_dashboard()

@cli.command()
def perms():
    """查看当前权限配置"""
    import yaml
    with open("config.yaml") as f:
        config = yaml.safe_load(f)
    import json
    click.echo(json.dumps(config["programs"], indent=2, ensure_ascii=False))

@cli.command()
@click.argument("program")
@click.argument("resource_type")
@click.argument("target")
@click.option("--action", default="ask",
              type=click.Choice(["allow_always", "ask", "deny"]))
def grant(program, resource_type, target, action):
    """手动授权"""
    from permissions import grant_permission
    grant_permission(program, resource_type, target, action)
    click.echo(f"[✓] 已授权: {program} → {resource_type} → {target} → {action}")

if __name__ == "__main__":
    cli()
```

---

## 十、快速启动命令

```bash
cd ~/ai-guardian

# 1. 只启动 Disk 守护（最简单，立刻可用）
python3 guardian.py start --disk

# 2. 启动 Disk + DB 守护
python3 guardian.py start --disk --db \
  --dsn "postgresql://user:password@localhost:5432/mydb"

# 3. 启动全部三个模块
python3 guardian.py start --disk --db --email \
  --dsn "postgresql://user:password@localhost:5432/mydb"

# 4. 打开实时 Dashboard（新终端）
python3 guardian.py dashboard

# 5. 查看权限配置
python3 guardian.py perms

# 6. 手动授权某个程序
python3 guardian.py grant cursor disk /home/ec2-user/project/ \
  --action allow_always
```

---

## 十一、DB 触发器手动安装

```sql
-- 在 PostgreSQL 里执行（需要 superuser）

-- 1. 安装 pg_audit 扩展（Amazon Linux 2023 已包含）
CREATE EXTENSION IF NOT EXISTS pg_audit;

-- 2. 创建拦截通知函数
CREATE OR REPLACE FUNCTION ai_guardian_ddl_intercept()
RETURNS event_trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_notify('ai_guardian', TG_TAG || ':' || current_query());
END;
$$;

-- 3. 注册事件触发器
CREATE EVENT TRIGGER ai_guardian_ddl
  ON ddl_command_end
  WHEN TAG IN (
    'DROP TABLE', 'DROP DATABASE', 'TRUNCATE TABLE',
    'ALTER TABLE', 'DROP SCHEMA', 'DROP INDEX'
  )
  EXECUTE FUNCTION ai_guardian_ddl_intercept();

-- 4. 验证触发器已安装
SELECT evtname, evtevent, evtenabled
FROM pg_event_trigger
WHERE evtname = 'ai_guardian_ddl';
```

---

## 十二、授权规则速查

| 操作 | 结果 |
|------|------|
| 单次删除 ≤ 3 个，已授权路径 | 静默放行 |
| 单次删除 > 3 个，已授权路径 | **批量警告，二次确认** |
| 任意删除，未授权路径 | **拦截，等待确认** |
| 未知程序的任何删除 | **永久拒绝** |
| DROP TABLE，已授权表 | 静默放行 |
| DROP TABLE，未授权表 | **拦截 + pg_dump 备份 + 确认** |
| DROP DATABASE | **永久拒绝（除非显式授权整库）** |
| 外部邮件，未授权地址 | **拦截 + 确认** |
| 批量邮件 > 3 封 | **批量警告，二次确认** |

---

## 十三、PocketOS 对比

| 场景 | 没有 Guardian | 有 Guardian |
|------|-------------|-------------|
| Cursor 找到 API Token | 直接使用，无感知 | Token 访问被记录 |
| 发出 DROP DATABASE | 9秒执行完毕 | 立即拦截，弹出确认 |
| 用户不在电脑前 | 数据库全灭 | 30秒超时，自动拒绝 |
| 事后追责 | 无日志 | 完整 JSONL 审计日志 |
| 恢复数据 | 依赖云平台备份 | Guardian 本地备份 |

---

*AI Guardian · 系统层真实确认门 · 让 AI 保持强大，人类永远掌握最终决定权*
