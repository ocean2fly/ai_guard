# eBPF LSM 阻断删除 — 实现计划

## 背景

当前 inotify 方案：文件删除后通知 → 用户拒绝 → 恢复备份。  
用户要求：**拒绝 = 文件从未被删**，需要在 syscall 层真正阻断。

---

## 内核环境确认

| 项目 | 状态 |
|------|------|
| 内核版本 | 6.1.172-216.329.amzn2023.x86_64 |
| `CONFIG_BPF_LSM` | ✅ y |
| `CONFIG_DEBUG_INFO_BTF` | ✅ y |
| `CONFIG_BPF_KPROBE_OVERRIDE` | ✅ y |
| `CONFIG_FUNCTION_ERROR_INJECTION` | ✅ y |
| 活跃 LSM 含 `bpf` | ✅ |
| `python3-bcc` | ✅ 已安装 |

---

## 关键限制发现

**`bpf_d_path` 在 unlink 钩子中被内核禁止**

`lsm/path_unlink` 和 `lsm/inode_unlink` 均不在内核的 `btf_allowlist_d_path` 白名单中，
调用 `bpf_d_path` 会报：`helper call is not allowed in probe`。

**已验证可用的能力（`lsm/inode_unlink`）：**

```c
LSM_PROBE(inode_unlink, struct inode *dir, struct dentry *dentry)
{
    if ((bpf_get_current_uid_gid() & 0xffffffff) == 0) return 0;  // 放行 root

    u64 ino = dentry->d_inode->i_ino;   // ✅ inode 号
    char name[64];
    bpf_probe_read_kernel_str(name, sizeof(name), dentry->d_name.name);  // ✅ 文件名

    // ... 发事件 + 返回 -EPERM 真正阻断 ✅
    return -EPERM;
}
```

---

## 选定方案

### 架构：eBPF 阻断 + 用户态 inode→路径缓存

```
┌─────────────────────────────────────────────────────────┐
│  进程 (uid=1000, Claude Code / rm / ...)                │
│  调用 unlink("/home/ec2-user/somefile")                  │
└──────────────────────┬──────────────────────────────────┘
                       │ syscall
                       ▼
┌─────────────────────────────────────────────────────────┐
│  eBPF LSM: lsm/inode_unlink                             │
│  1. uid==0 → 放行                                       │
│  2. inode 在 allow_map → 放行（一次性），删除 map 条目   │
│  3. 其余 → 发事件到 perf buffer → 返回 -EPERM           │
└──────────────────────┬──────────────────────────────────┘
                       │ perf event (inode + pid + filename)
                       ▼
┌─────────────────────────────────────────────────────────┐
│  Python 用户态 EbpfBlocker                              │
│                                                         │
│  inode→路径缓存（由 inotify CLOSE_WRITE 维护）          │
│    → 查缓存得到完整路径                                  │
│                                                         │
│  check_permission(program, full_path)                   │
│  ┌─ allow_always → guardian(root) 直接 os.unlink()      │
│  ├─ ask          → Telegram 发告警，等用户响应           │
│  │    allow → 写 allow_map + 通知"请重试命令"           │
│  │    deny  → 什么都不做（文件从未被删）✅               │
│  └─ deny         → 静默拒绝                             │
└─────────────────────────────────────────────────────────┘
```

### BPF Maps

| Map | 类型 | Key | Value | 用途 |
|-----|------|-----|-------|------|
| `allow_map` | HASH | u64 inode | u8 | 一次性批准，用后删除 |

### inode→路径缓存

inotify `CLOSE_WRITE` 事件已有文件路径 → 记录 `{inode: full_path}`。  
eBPF 事件到达时，用 inode 查缓存得到完整路径，再匹配 config.yaml 规则。

---

## UX 变化对比

| 场景 | 旧（inotify）| 新（eBPF）|
|------|-------------|----------|
| 用户点 Deny | 文件已删，再从备份恢复 | 文件**从未被删** ✅ |
| 用户点 Allow Once | 文件保持删除 | 进程收到 EPERM，用户需重试命令 |
| allow_always 路径 | 静默放行 | guardian 代为执行删除，进程收到 EPERM |
| 超时自动拒绝 | 文件已删，再恢复 | 文件**从未被删** ✅ |

---

## 待实现文件清单

### 新建
- `modules/disk/ebpf_blocker.py` — eBPF 程序 + Python 事件处理器

### 修改
- `modules/disk/watcher.py` — 移除 DELETE 批量处理；CLOSE_WRITE 事件额外写 inode→路径缓存
- `modules/disk/guardian.py` — 初始化 EbpfBlocker，传入共享缓存
- `/etc/systemd/system/aigate.service` — `User=root`（加载 BPF LSM 需要 CAP_SYS_ADMIN）

---

## 实现要点

```python
# ebpf_blocker.py 核心结构

BPF_PROGRAM = r"""
#include <linux/fs.h>
#include <linux/dcache.h>

struct evt_t { u32 pid; u64 inode; char comm[16]; char filename[64]; };

BPF_HASH(allow_map, u64, u8, 1024);
BPF_PERF_OUTPUT(events);

LSM_PROBE(inode_unlink, struct inode *dir, struct dentry *dentry)
{
    if ((bpf_get_current_uid_gid() & 0xffffffff) == 0) return 0;

    u64 ino = dentry->d_inode->i_ino;
    u8 *ok = allow_map.lookup(&ino);
    if (ok) { allow_map.delete(&ino); return 0; }

    struct evt_t e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.inode = ino;
    bpf_get_current_comm(e.comm, sizeof(e.comm));
    bpf_probe_read_kernel_str(e.filename, sizeof(e.filename), dentry->d_name.name);
    events.perf_submit(ctx, &e, sizeof(e));
    return -EPERM;
}
"""

class EbpfBlocker:
    def __init__(self, gate, inode_path_cache: dict):
        self._cache = inode_path_cache  # 共享，由 watcher 的 CLOSE_WRITE 填充
        self._gate = gate
        self._b = None

    def start(self): ...
    def _handle_event(self, cpu, data, size): ...
    def grant_once(self, inode: int): ...  # 写 allow_map
```
