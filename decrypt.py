#!/usr/bin/env python3
"""
CipherShelf 解密工具（CLI）

解密（还原）一个已加密的文件夹：凭密码 + .svault 索引还原原文件名和目录结构。

用法：
    python3 decrypt.py /path/to/folder          # 就地还原
    python3 decrypt.py /path/to/folder -o /restore/dir   # 还原到别处

密码默认交互式输入（不回显、不落盘、不进日志）。
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

import crypto


def main() -> int:
    ap = argparse.ArgumentParser(description="CipherShelf 文件夹解密工具")
    ap.add_argument("path", help="已加密的文件夹路径（含 .svault）")
    ap.add_argument("-o", "--output", default=None, help="还原输出目录（缺省就地还原）")
    ap.add_argument("--password", default=None, help="密码（不推荐，会留 shell 历史；缺省交互输入）")
    ap.add_argument("--yes", action="store_true", help="跳过确认提示")
    args = ap.parse_args()

    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print(f"✗ 目录不存在：{root}", file=sys.stderr)
        return 2
    if not os.path.isfile(os.path.join(root, crypto.INDEX_FILENAME)):
        print(f"✗ 未找到索引文件 {crypto.INDEX_FILENAME}，该目录可能未加密", file=sys.stderr)
        return 2

    password = args.password
    if password is None:
        password = getpass.getpass("密码：")
    if not password:
        print("✗ 密码不能为空", file=sys.stderr)
        return 2

    key = crypto.derive_master_key(password)
    password = None  # 用完即弃

    # 先验证密码（读索引）
    try:
        entries = crypto.read_index(key, os.path.join(root, crypto.INDEX_FILENAME))
    except ValueError as e:
        print(f"✗ {e}", file=sys.stderr)
        return 3

    files = [e for e in entries if e.get("type") == "file"]
    total = sum(e.get("size", 0) for e in files)
    output = os.path.abspath(args.output) if args.output else root

    print(f"即将解密：{root}")
    print(f"  {len(files)} 个文件，共 {_fmt(total)}")
    print(f"  还原到：{output}")
    if not args.yes:
        try:
            ans = input("确认解密？[y/N] ")
        except EOFError:
            ans = "n"
        if ans.strip().lower() not in ("y", "yes"):
            print("已取消")
            return 1

    def progress(done, total_bytes, label):
        pct = (done / total_bytes * 100) if total_bytes else 100.0
        print(f"\r  ▓ {pct:5.1f}%  {_fmt(done)}/{_fmt(total_bytes)}  {label}", end="", flush=True)

    try:
        n = crypto.decrypt_folder(key, root, output_dir=args.output, progress=progress if total else None)
        print(f"\n✓ 完成：还原 {n} 个文件到 {output}")
        return 0
    except Exception as e:
        print(f"\n✗ 解密失败：{e}", file=sys.stderr)
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
