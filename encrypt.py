#!/usr/bin/env python3
"""
CipherShelf 加密工具（CLI）

就地加密一个文件夹：文件内容加密、目录名/文件名变密文，目录结构保留，
一个加密索引 .svault 记录 原名 <-> 密文 映射。

用法：
    python3 encrypt.py /path/to/folder
    python3 encrypt.py /path/to/folder --password xxx --yes

密码默认交互式输入（不回显、不落盘、不进日志）。
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

import crypto


def main() -> int:
    ap = argparse.ArgumentParser(description="CipherShelf 文件夹加密工具")
    ap.add_argument("path", help="要加密的文件夹路径")
    ap.add_argument("--password", default=None, help="密码（不推荐，会留 shell 历史；缺省交互输入）")
    ap.add_argument("--yes", action="store_true", help="跳过确认提示")
    args = ap.parse_args()

    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print(f"✗ 目录不存在：{root}", file=sys.stderr)
        return 2
    if os.path.isfile(os.path.join(root, crypto.INDEX_FILENAME)):
        print("✗ 该目录已加密（已存在 .svault）", file=sys.stderr)
        return 2

    password = args.password
    if password is None:
        password = getpass.getpass("密码：")
        confirm = getpass.getpass("再次输入确认：")
        if password != confirm:
            print("✗ 两次密码不一致", file=sys.stderr)
            return 2
    message = crypto.password_strength_error(password)
    if message:
        print(f"✗ {message}", file=sys.stderr)
        return 2

    key = crypto.KeyContext(crypto.derive_master_key(password))
    password = None  # 用完即弃

    # 操作摘要
    files, dirs = crypto._scan_folder(root)
    total = sum(sz for _rel, sz, _mt in files)
    print(f"即将加密：{root}")
    print(f"  {len(dirs)} 个目录，{len(files)} 个文件，共 {_fmt(total)}")
    print("  加密后：内容变密文、名字变乱码、结构保留，生成 .svault 索引")
    if not args.yes:
        try:
            ans = input("确认加密？[y/N] ")
        except EOFError:
            ans = "n"
        if ans.strip().lower() not in ("y", "yes"):
            print("已取消")
            return 1

    def progress(done, total_bytes, label):
        pct = (done / total_bytes * 100) if total_bytes else 100.0
        print(f"\r  ▓ {pct:5.1f}%  {_fmt(done)}/{_fmt(total_bytes)}  {label}", end="", flush=True)

    try:
        n = crypto.encrypt_folder(key, root, progress=progress if total else None)
        print(f"\n✓ 完成：加密 {n} 个文件到 {root}")
        print("  索引文件：.svault（请妥善保管，它是还原的关键）")
        return 0
    except Exception as e:
        print(f"\n✗ 加密失败：{e}", file=sys.stderr)
        return 1


def _fmt(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1048576:
        return f"{n / 1024:.1f} KB"
    if n < 1073741824:
        return f"{n / 1048576:.1f} MB"
    return f"{n / 1073741824:.2f} GB"


if __name__ == "__main__":
    sys.exit(main())
