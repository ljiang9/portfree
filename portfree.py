#!/usr/bin/env python3
"""portfree - 查出谁在占用端口，并释放它。

纯标准库，纯本地。Linux 专用：优先用 `ss -tlnp`，
不可用时回退到 /proc/net/tcp(+tcp6) 解析。
查看其他用户的进程需要相应权限（否则只能看到自己的）。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time

VERSION = "0.1.0"


# ---------------------------------------------------------------- 数据来源

def _listeners_from_ss() -> list[dict] | None:
    """用 ss -tlnp 解析监听端口；ss 不可用返回 None。"""
    try:
        out = subprocess.run(
            ["ss", "-tlnp"], capture_output=True, text=True, timeout=10
        ).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    listeners: list[dict] = []
    for line in out.splitlines():
        if not line.startswith("LISTEN"):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]  # 列: State Recv-Q Send-Q Local Peer [Process]
        port = _port_of(local)
        if port is None:
            continue
        # users:(("python3",pid=456,fd=3))
        procs = re.findall(r'\("([^"]+)",pid=(\d+),fd=\d+\)', line)
        if procs:
            for name, pid in procs:
                listeners.append({
                    "port": port, "pid": int(pid), "name": name,
                    "cmdline": _cmdline_of(int(pid)), "source": "ss",
                })
        else:
            # 有监听但看不到进程（权限不足等）
            listeners.append({
                "port": port, "pid": None, "name": None,
                "cmdline": None, "source": "ss",
            })
    return listeners


def _port_of(addr: str) -> int | None:
    # "0.0.0.0:8080" / "[::]:8080" / "*:8080"
    m = re.search(r":(\d+)$", addr.strip("[]"))
    return int(m.group(1)) if m else None


def _cmdline_of(pid: int) -> str | None:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read().replace(b"\0", b" ").strip()
        return raw.decode("utf-8", "replace") or None
    except OSError:
        return None


def _name_of(pid: int) -> str | None:
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip() or None
    except OSError:
        return None


def _listeners_from_proc() -> list[dict]:
    """回退方案：解析 /proc/net/tcp、tcp6（state 0A=LISTEN），
    再经 /proc/<pid>/fd 的 socket:[inode] 反查进程。"""
    inodes: set[str] = set()
    for path, is_v6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
        try:
            with open(path) as f:
                lines = f.read().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            cols = line.split()
            if len(cols) < 10:
                continue
            state, local, inode = cols[3], cols[1], cols[9]
            if state != "0A":  # LISTEN
                continue
            port_hex = local.rsplit(":", 1)[-1]
            try:
                port = int(port_hex, 16)
            except ValueError:
                continue
            inodes.add((inode, port))
    # inode -> (pid, ...)
    inode_pids: dict[str, list[int]] = {}
    for pid in filter(str.isdigit, os.listdir("/proc")):
        fd_dir = f"/proc/{pid}/fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            try:
                target = os.readlink(f"{fd_dir}/{fd}")
            except OSError:
                continue
            m = re.fullmatch(r"socket:\[(\d+)\]", target)
            if m:
                inode_pids.setdefault(m.group(1), []).append(int(pid))
    listeners: list[dict] = []
    seen: set[tuple] = set()
    for inode, port in inodes:
        pids = inode_pids.get(inode, [])
        if pids:
            for pid in pids:
                key = (port, pid)
                if key in seen:
                    continue
                seen.add(key)
                listeners.append({
                    "port": port, "pid": pid, "name": _name_of(pid),
                    "cmdline": _cmdline_of(pid), "source": "proc",
                })
        else:
            if (port, None) not in seen:
                seen.add((port, None))
                listeners.append({
                    "port": port, "pid": None, "name": None,
                    "cmdline": None, "source": "proc",
                })
    return listeners


def get_listeners() -> tuple[list[dict], str]:
    """返回 (listeners, 数据来源说明)。"""
    ss_result = _listeners_from_ss()
    if ss_result is not None:
        return ss_result, "ss -tlnp"
    return _listeners_from_proc(), "/proc/net/tcp(+tcp6)"


# ---------------------------------------------------------------- 展示

def fmt_table(rows: list[dict]) -> str:
    lines = [f"{'端口':>6}  {'PID':>7}  {'进程名':<16}  命令行"]
    for r in rows:
        pid = str(r["pid"]) if r["pid"] is not None else "(未知)"
        name = r["name"] or "(未知)"
        cmd = r["cmdline"] or "(无权限查看)"
        lines.append(f"{r['port']:>6}  {pid:>7}  {name:<16}  {cmd}")
    return "\n".join(lines)


def emit(obj, as_json: bool):
    if as_json:
        print(json.dumps(obj, ensure_ascii=False, indent=2))
    else:
        print(obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False))


# ---------------------------------------------------------------- 命令

def cmd_query(port: int, as_json: bool) -> int:
    listeners, _src = get_listeners()
    rows = [r for r in listeners if r["port"] == port]
    if as_json:
        emit({"port": port, "listeners": rows}, True)
    elif rows:
        print(f"端口 {port} 的监听者：\n{fmt_table(rows)}")
    else:
        print(f"端口 {port}：没有进程占用。")
    return 0


def cmd_list(as_json: bool) -> int:
    listeners, src = get_listeners()
    rows = sorted(listeners, key=lambda r: (r["port"], r["pid"] or 0))
    if as_json:
        emit({"listeners": rows, "source": src}, True)
    elif rows:
        print(f"正在监听的 TCP 端口（数据来源：{src}）：\n{fmt_table(rows)}")
    else:
        print("没有发现正在监听的 TCP 端口。")
    return 0


def _port_still_listening(port: int) -> bool:
    listeners, _ = get_listeners()
    return any(r["port"] == port for r in listeners)


def cmd_kill(port: int, yes: bool, as_json: bool) -> int:
    listeners, _ = get_listeners()
    rows = [r for r in listeners if r["port"] == port and r["pid"]]
    unknown = [r for r in listeners if r["port"] == port and not r["pid"]]
    if not rows and not unknown:
        msg = {"port": port, "killed": [], "note": "没有进程占用，无需释放"}
        if as_json:
            emit(msg, True)
        else:
            print(f"端口 {port}：没有进程占用，无需释放。")
        return 0
    if unknown and not rows:
        msg = (f"端口 {port} 有监听者但看不到 PID（可能需要 root 权限），"
               f"无法终止。")
        if as_json:
            emit({"port": port, "killed": [], "error": msg}, True)
        else:
            print(f"error: {msg}", file=sys.stderr)
        return 1
    if not yes and not as_json:
        print(f"将要终止占用端口 {port} 的进程：\n{fmt_table(rows)}")
        try:
            ans = input("确认终止？[y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n已取消。")
            return 1
        if ans not in ("y", "yes"):
            print("已取消。")
            return 1
    killed, failed = [], []
    for r in rows:
        try:
            os.kill(r["pid"], signal.SIGTERM)
            killed.append(r["pid"])
        except (ProcessLookupError, PermissionError) as e:
            failed.append({"pid": r["pid"], "error": str(e)})
    time.sleep(2)
    still = _port_still_listening(port)
    result = {"port": port, "killed": killed, "failed": failed,
              "port_free": not still}
    if still:
        result["note"] = ("端口仍被占用：进程可能忽略了 SIGTERM，"
                          "可用 kill -9 <PID> 强制终止")
    if as_json:
        emit(result, True)
    else:
        for pid in killed:
            print(f"已发送 SIGTERM 给 PID {pid}")
        for f in failed:
            print(f"终止 PID {f['pid']} 失败：{f['error']}", file=sys.stderr)
        if still:
            print(f"注意：端口 {port} 仍被占用。{result['note']}")
        else:
            print(f"端口 {port} 已释放。")
    return 0 if not still and not failed else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="portfree",
        description="查出谁在占用端口，并释放它（Linux 专用，纯本地）。")
    p.add_argument("port", nargs="?", type=int, help="要查询的端口号")
    p.add_argument("--kill", action="store_true", help="终止占用指定端口的进程")
    p.add_argument("--yes", "-y", action="store_true",
                   help="终止前不确认（默认会询问）")
    p.add_argument("--list", action="store_true",
                   help="列出所有正在监听的 TCP 端口")
    p.add_argument("--json", action="store_true", help="以 JSON 输出（方便脚本）")
    p.add_argument("--version", action="version", version=f"portfree {VERSION}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list:
        return cmd_list(args.json)
    if args.port is None:
        print("error: 请指定端口号，例如 portfree 8080；或用 --list 查看全部。",
              file=sys.stderr)
        return 2
    if not (1 <= args.port <= 65535):
        print(f"error: 端口号超出范围：{args.port}", file=sys.stderr)
        return 2
    if args.kill:
        return cmd_kill(args.port, args.yes, args.json)
    return cmd_query(args.port, args.json)


if __name__ == "__main__":
    sys.exit(main())
