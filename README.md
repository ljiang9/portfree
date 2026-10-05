# portfree

查出谁在占用端口，并释放它。Linux 专用小工具，纯标准库、纯本地。

## 快速开始

```bash
python3 -m portfree 8080        # 查 8080 被谁占了
python3 -m portfree --list      # 列出所有监听中的 TCP 端口
python3 -m portfree --kill 8080 # 终止占用者（会先确认）
python3 -m portfree --kill 8080 --yes  # 不确认直接终止
python3 -m portfree 8080 --json # JSON 输出，方便脚本
```

## 数据来源

1. **优先 `ss -tlnp`**：一次系统调用拿到端口 + 进程映射。
2. **`ss` 不可用时回退 `/proc`**：解析 `/proc/net/tcp`、`/proc/net/tcp6`
   的 LISTEN 条目，再经 `/proc/<pid>/fd` 的 `socket:[inode]` 反查进程。

看不到 PID/进程名通常是权限问题：只能看到自己有权限的进程，
想看全系统监听请用 root 运行。

## 终止行为

- 默认 SIGTERM（礼貌终止），确认后执行（`--yes` 跳过确认）。
- 终止后等待 2 秒复查；端口仍被占用则提示用 `kill -9 <PID>`。
- exit 0 = 端口已释放；exit 1 = 仍有占用或终止失败；exit 2 = 用法错误。

## 诚实说明

- **Linux only**：依赖 `ss` 或 `/proc`，macOS/Windows 不可用。
- 只能看到有权限的进程；容器/命名空间内的监听可能显示不全。
- 短连接、TIME_WAIT 等非 LISTEN 状态不在查询范围内。
- SIGTERM 可能被进程忽略，这是设计使然（先礼貌再强制）。
