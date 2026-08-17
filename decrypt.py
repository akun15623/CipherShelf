#!/usr/bin/env python3
"""
secure-vault 离线解密工具（应急恢复）

用途：即使前端服务 / 容器丢失，只要保险箱的**数据目录**（vault.db + files/）还在，
你就能用这个脚本 + 保险箱密码把全部文件还原成明文。

    python3 decrypt.py --data-dir /path/to/vault-data --output /path/to/restored
    python3 decrypt.py --data-dir /path/to/vault-data --list          # 只看清单，不解密

依赖：仅需 cryptography（与后端一致）。密码用交互式输入，绝不回显、不落盘、不进日志。

安全性：解密后的文件是**明文**，请确保 --output 落在可信磁盘；用完可手动删除。
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from crypto import Vault, decrypt_chunks, decrypt_name


def main() -> int:
    ap = argparse.ArgumentParser(description="secure-vault 离线解密工具")
    ap.add_argument("--data-dir", default=os.environ.get("VAULT_DATA_DIR", "./data"),
                    help="保险箱数据目录（含 vault.db 与 files/），默认 $VAULT_DATA_DIR 或 ./data")
    ap.add_argument("--output", default="./vault-decrypted", help="解密输出目录，默认 ./vault-decrypted")
    ap.add_argument("--password", default=None, help="保险箱密码（不推荐，会留在 shell 历史；缺省时交互输入）")
    ap.add_argument("--list", action="store_true", help="只列出清单（文件名/大小/路径），不解密")
    ap.add_argument("--yes", action="store_true", help="跳过确认提示")
    args = ap.parse_args()

    data_dir = os.path.abspath(args.data_dir)
    if not os.path.isfile(os.path.join(data_dir, "vault.db")):
        print(f"✗ 未找到 vault.db：{data_dir}", file=sys.stderr)
        print("  请用 --data-dir 指向保险箱数据目录（内含 vault.db 和 files/ 文件夹）。", file=sys.stderr)
        return 2

    vault = Vault(data_dir)
    if not vault.exists:
        print("✗ 该数据目录里的保险箱尚未初始化。", file=sys.stderr)
        return 2

    password = args.password
    if password is None:
        password = getpass.getpass("保险箱密码：")

    master_key = vault.unlock(password)
    # 密码用完即弃（本进程结束后自然回收），不留引用
    password = None
    if master_key is None:
        print("✗ 密码错误。", file=sys.stderr)
        return 3

    print("✓ 密码验证通过，正在读取清单…")

    folders = vault.list_folders(master_key)
    files = vault.list_all_files(master_key)

    # 建立 文件夹 id -> 相对路径 映射
    path_of: dict[str, str] = {}

    def fpath(fid: str) -> str:
        if fid in path_of:
            return path_of[fid]
        f = next((x for x in folders if x["id"] == fid), None)
        if not f:
            return ""
        if f["parent_id"]:
            p = fpath(f["parent_id"])
            path_of[fid] = (p + "/" + f["name"]) if p else f["name"]
        else:
            path_of[fid] = f["name"]
        return path_of[fid]

    def rel_path(f: dict) -> str:
        if not f["folder_id"]:
            return f["name"]
        p = fpath(f["folder_id"])
        return f"{p}/{f['name']}" if p else f["name"]

    if args.list:
        print(f"\n共 {len(files)} 个文件：\n")
        for f in files:
            print(f"  {rel_path(f)}  ({_fmt(f['size'])})")
        return 0

    out_dir = os.path.abspath(args.output)
    if os.path.exists(out_dir) and os.listdir(out_dir) and not args.yes:
        try:
            ans = input(f"输出目录 {out_dir} 非空，继续写入（可能覆盖同名文件）？[y/N] ")
        except EOFError:
            ans = "n"
        if ans.strip().lower() not in ("y", "yes"):
            print("已取消。")
            return 1

    os.makedirs(out_dir, exist_ok=True)
    total_bytes = 0
    done = 0
    for f in files:
        rel = rel_path(f)
        # 清理路径，防止目录穿越 / 绝对路径
        parts = [p for p in rel.replace("\\", "/").split("/") if p not in ("", ".", "..")]
        if not parts:
            continue
        dst = os.path.join(out_dir, *parts)
        dst = _unique_path(dst)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        src = vault.get_file_path(f["id"])
        try:
            with open(dst, "wb") as w:
                for chunk in decrypt_chunks(master_key, f["id"], src):
                    w.write(chunk)
        except Exception as e:
            print(f"  ✗ {rel} 解密失败：{e}", file=sys.stderr)
            continue
        total_bytes += f["size"]
        done += 1
        print(f"  ✓ {rel}  ({_fmt(f['size'])})")

    print(f"\n完成：{done}/{len(files)} 个文件，共 {_fmt(total_bytes)}，输出到 {out_dir}")
    return 0


def _unique_path(path: str) -> str:
    """若目标已存在，追加 (1)/(2)... 避免覆盖。"""
    if not os.path.exists(path):
        return path
    root, ext = os.path.splitext(path)
    i = 1
    while os.path.exists(f"{root} ({i}){ext}"):
        i += 1
    return f"{root} ({i}){ext}"


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
