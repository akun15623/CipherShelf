"""
secure-vault 加密核心（v2：文件夹就地加解密工具）

设计要点（单密钥模型）：
- 一个密码 -> 一个主密钥：PBKDF2-HMAC-SHA256（固定 salt，60 万次迭代）。
  同一密码永远派生出同一个主密钥。
- 所有文件内容、目录名/文件名、索引，全部用这同一个主密钥加密。
- 就地加密：保留目录结构，但每个目录名/文件名变成随机 32 位 hex 密文。
- 索引 .svault：记录 原名 <-> 密文 映射，整体用主密钥 AES-GCM 加密。
- 密码验证：解密索引时 GCM 认证失败 = 密码错误（无需单独 verifier）。

磁盘上只有：密文文件（乱码名）+ 一个加密索引 .svault，无任何明文元数据。
"""

from __future__ import annotations

import json
import os
import shutil
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

MAGIC = b"SVLT"
VERSION = 1
KEY_SIZE = 32            # AES-256
NONCE_SIZE = 12          # GCM 推荐 12 字节
TAG_SIZE = 16            # GCM tag
BLOCK_SIZE = 1024 * 1024  # 1 MiB 分块
ITERATIONS = 600_000      # PBKDF2 迭代次数

# 固定盐（代码内置常量，16 字节）：保证「同一密码 = 同一密钥」。
# 注意：这是「都用一个密钥」心智的直接代价——任何用同一密码的人都能互相解密。
DEFAULT_SALT = b"secure-vault-v2."

# 密文文件头：magic(4) + version(1) + chunk_size(4) + block_count(4) = 13 字节
HEADER_SIZE = 4 + 1 + 4 + 4

# 索引加密头：magic(4) + version(1) + nonce(12) = 17 字节
INDEX_HEADER_SIZE = 4 + 1 + NONCE_SIZE

INDEX_FILENAME = ".svault"


# ---------------------------------------------------------------------------
# 密钥派生
# ---------------------------------------------------------------------------
def derive_master_key(password: str, salt: bytes = DEFAULT_SALT, iterations: int = ITERATIONS) -> bytes:
    """从密码派生主密钥。password 不应被记录到任何日志。"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


# ---------------------------------------------------------------------------
# 文件加解密（流式，单密钥）
# ---------------------------------------------------------------------------
def _file_aad(block_index: int) -> bytes:
    return MAGIC + bytes([VERSION]) + block_index.to_bytes(8, "big")


def encrypt_file(master_key: bytes, src_path: str, dst_path: str) -> None:
    """把明文 src_path 流式加密写入 dst_path。

    dst 布局：
      [magic 4][version 1][chunk_size 4][block_count 4]
      然后每块：[nonce 12][ciphertext + tag 16]
    每块 GCM 的 AAD = "SVLT" + version + block_index(8B BE)，防块重排/替换。
    """
    aes = AESGCM(master_key)
    plain_size = os.path.getsize(src_path)
    block_count = (plain_size + BLOCK_SIZE - 1) // BLOCK_SIZE  # 空文件 = 0

    with open(src_path, "rb") as fin, open(dst_path, "wb") as fout:
        fout.write(MAGIC)
        fout.write(bytes([VERSION]))
        fout.write(BLOCK_SIZE.to_bytes(4, "big"))
        fout.write(block_count.to_bytes(4, "big"))

        block_index = 0
        while True:
            block = fin.read(BLOCK_SIZE)
            if not block:
                break
            nonce = os.urandom(NONCE_SIZE)
            ct = aes.encrypt(nonce, block, _file_aad(block_index))
            fout.write(nonce)
            fout.write(ct)
            block_index += 1


def decrypt_file(master_key: bytes, src_path: str, dst_path: str) -> None:
    """把密文 src_path 流式解密写入 dst_path。密码错/密文损坏会抛 InvalidTag。"""
    aes = AESGCM(master_key)
    with open(src_path, "rb") as fin, open(dst_path, "wb") as fout:
        magic = fin.read(4)
        if magic != MAGIC:
            raise ValueError("不是有效的加密文件（magic 不匹配）")
        version = fin.read(1)[0]
        if version != VERSION:
            raise ValueError(f"不支持的版本：{version}")
        chunk_size = int.from_bytes(fin.read(4), "big")
        block_count = int.from_bytes(fin.read(4), "big")

        for block_index in range(block_count):
            nonce = fin.read(NONCE_SIZE)
            ct = fin.read(chunk_size + TAG_SIZE)
            pt = aes.decrypt(nonce, ct, _file_aad(block_index))  # GCM 失败抛 InvalidTag
            fout.write(pt)


# ---------------------------------------------------------------------------
# 索引 .svault（加密 JSON）
# ---------------------------------------------------------------------------
def _index_aad() -> bytes:
    return MAGIC + bytes([VERSION]) + b"index"


def write_index(master_key: bytes, path: str, entries: list[dict]) -> None:
    """把 entries 用主密钥加密写入索引文件 path。"""
    data = json.dumps(
        {"magic": "SVLT", "version": VERSION, "entries": entries},
        ensure_ascii=False,
    ).encode("utf-8")
    aes = AESGCM(master_key)
    nonce = os.urandom(NONCE_SIZE)
    ct = aes.encrypt(nonce, data, _index_aad())
    with open(path, "wb") as f:
        f.write(MAGIC)
        f.write(bytes([VERSION]))
        f.write(nonce)
        f.write(ct)


def read_index(master_key: bytes, path: str) -> list[dict]:
    """解密并解析索引，返回 entries。密码错/损坏抛 ValueError。"""
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic != MAGIC:
            raise ValueError("不是有效的索引文件（magic 不匹配）")
        version = f.read(1)[0]
        if version != VERSION:
            raise ValueError(f"不支持的索引版本：{version}")
        nonce = f.read(NONCE_SIZE)
        ct = f.read()
    aes = AESGCM(master_key)
    try:
        data = aes.decrypt(nonce, ct, _index_aad())
    except Exception:
        raise ValueError("密码错误或索引已损坏")
    obj = json.loads(data.decode("utf-8"))
    return obj.get("entries", [])


# ---------------------------------------------------------------------------
# 高层：就地加密 / 还原解密
# ---------------------------------------------------------------------------
def _scan_folder(root_dir: str) -> tuple[list[tuple[str, int, int]], list[str]]:
    """扫描文件夹，返回 (files, dirs)。
    files = [(相对路径, size, mtime), ...]（稳定排序）
    dirs  = [相对路径, ...]（稳定排序）
    符号链接不跟随、被跳过。
    """
    files: list[tuple[str, int, int]] = []
    dirs: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root_dir, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root_dir)
        if rel_dir != ".":
            dirs.append(rel_dir)
        dirnames.sort()
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            if os.path.islink(full):
                continue  # 跳过符号链接
            st = os.stat(full)
            rel = os.path.relpath(full, root_dir)
            files.append((rel, st.st_size, int(st.st_mtime)))
    dirs.sort()
    return files, dirs


def _validate_orig(orig: str) -> None:
    """校验原相对路径：拒绝绝对路径、../、空段。"""
    if os.path.isabs(orig):
        raise ValueError(f"索引包含非法路径（绝对路径）：{orig}")
    norm = os.path.normpath(orig)
    if norm.startswith("..") or norm == ".." or os.path.isabs(norm):
        raise ValueError(f"索引包含非法路径：{orig}")
    if any(seg in ("", ".", "..") for seg in orig.split("/")):
        raise ValueError(f"索引包含非法路径：{orig}")


def encrypt_folder(
    master_key: bytes,
    root_dir: str,
    progress=None,
) -> int:
    """就地加密文件夹 root_dir。

    返回加密的文件数量。progress(done_bytes, total_bytes, current_label) 可选回调。
    原子性：先全部加密到 stage 临时目录，成功后才替换 + 删明文，中途失败不丢数据。
    """
    root_dir = os.path.abspath(root_dir)
    if not os.path.isdir(root_dir):
        raise ValueError(f"目录不存在：{root_dir}")
    if os.path.isfile(os.path.join(root_dir, INDEX_FILENAME)):
        raise ValueError("该目录已加密（已存在 .svault）")

    files, dirs = _scan_folder(root_dir)

    # 生成密文名（uuid4().hex，32 位）
    enc_of: dict[str, str] = {}
    for d in dirs:
        enc_of[d] = uuid.uuid4().hex
    for rel, _sz, _mt in files:
        enc_of[rel] = uuid.uuid4().hex

    # stage 目录（同盘，root_dir 的父目录下）
    parent = os.path.dirname(root_dir) or "."
    stage = os.path.join(parent, ".svault-stage-" + uuid.uuid4().hex)
    os.makedirs(stage, exist_ok=True)

    total = sum(sz for _rel, sz, _mt in files)
    done = 0

    try:
        # 1. 在 stage 下创建密文目录结构
        for d in dirs:
            os.makedirs(os.path.join(stage, enc_of[d]), exist_ok=True)

        # 2. 加密所有文件到 stage（密文相对路径）
        entries: list[dict] = []
        for rel, size, mtime in files:
            enc_name = enc_of[rel]
            orig_parent = os.path.dirname(rel)
            if orig_parent:
                enc_full = os.path.join(enc_of[orig_parent], enc_name)
            else:
                enc_full = enc_name
            dst = os.path.join(stage, enc_full)
            encrypt_file(master_key, os.path.join(root_dir, rel), dst)
            entries.append({
                "type": "file", "orig": rel, "enc": enc_full,
                "size": size, "mtime": mtime,
            })
            done += size
            if progress:
                progress(done, total, rel)

        # 3. 目录 entries
        for d in dirs:
            entries.append({"type": "dir", "orig": d, "enc": enc_of[d]})

        # 4. 写加密索引
        write_index(master_key, os.path.join(stage, INDEX_FILENAME), entries)

        # 5. 原子替换：移走明文 -> stage 变 root_dir -> 删明文
        backup = os.path.join(parent, ".svault-backup-" + uuid.uuid4().hex)
        os.rename(root_dir, backup)
        os.rename(stage, root_dir)
        shutil.rmtree(backup, ignore_errors=True)

        return len(files)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def decrypt_folder(
    master_key: bytes,
    root_dir: str,
    output_dir: str | None = None,
    progress=None,
) -> int:
    """解密（还原）加密文件夹 root_dir。

    output_dir 为空时原地还原；否则还原到 output_dir。
    返回还原的文件数量。progress 同 encrypt_folder。
    原子性：先全部解密到 stage，成功后替换 + 删密文，中途失败不丢密文。
    """
    root_dir = os.path.abspath(root_dir)
    index_path = os.path.join(root_dir, INDEX_FILENAME)
    if not os.path.isfile(index_path):
        raise ValueError(f"未找到索引文件 {INDEX_FILENAME}，该目录可能未加密")

    entries = read_index(master_key, index_path)  # 密码错抛 ValueError

    files = [e for e in entries if e.get("type") == "file"]
    dirs = [e for e in entries if e.get("type") == "dir"]

    # 路径安全校验
    for e in entries:
        _validate_orig(e["orig"])

    output = os.path.abspath(output_dir) if output_dir else root_dir
    parent = os.path.dirname(output) or "."
    os.makedirs(parent, exist_ok=True)
    if output != root_dir and os.path.exists(output):
        raise ValueError(f"输出目录已存在：{output}")

    stage = os.path.join(parent, ".svault-stage-" + uuid.uuid4().hex)
    os.makedirs(stage, exist_ok=True)

    total = sum(e.get("size", 0) for e in files)
    done = 0

    try:
        # 1. 创建明文目录结构
        for d in dirs:
            os.makedirs(os.path.join(stage, d["orig"]), exist_ok=True)

        # 2. 解密所有文件到 stage（原相对路径）
        for e in files:
            src = os.path.join(root_dir, e["enc"])
            dst = os.path.join(stage, e["orig"])
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            decrypt_file(master_key, src, dst)
            mtime = e.get("mtime", 0)
            os.utime(dst, (mtime, mtime))
            done += e.get("size", 0)
            if progress:
                progress(done, total, e["orig"])

        # 3. 原子替换
        if output == root_dir:
            backup = os.path.join(parent, ".svault-backup-" + uuid.uuid4().hex)
            os.rename(root_dir, backup)
            os.rename(stage, root_dir)
            shutil.rmtree(backup, ignore_errors=True)
        else:
            os.rename(stage, output)

        return len(files)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


# ---------------------------------------------------------------------------
# 树：列出目录（Web 用），已加密目录返回索引中的原文件名
# ---------------------------------------------------------------------------
def list_directory(master_key: bytes, root_dir: str, rel_path: str = "") -> list[dict]:
    """列出 root_dir 下 rel_path 的子节点。

    未加密目录 -> 返回单层节点（真实磁盘名，encrypted=false）。
    已加密目录（含 .svault）-> 返回索引重建的完整子树（原名，encrypted=true）。
    """
    abs_path = os.path.abspath(os.path.join(root_dir, rel_path)) if rel_path else os.path.abspath(root_dir)
    if not os.path.isdir(abs_path):
        raise ValueError(f"目录不存在：{abs_path}")

    index_path = os.path.join(abs_path, INDEX_FILENAME)
    if os.path.isfile(index_path):
        # 已加密目录：从索引重建完整子树
        entries = read_index(master_key, index_path)
        return _build_tree_from_index(entries)

    # 未加密目录：单层真实名
    nodes: list[dict] = []
    for name in sorted(os.listdir(abs_path)):
        full = os.path.join(abs_path, name)
        if os.path.islink(full):
            continue
        if os.path.isdir(full):
            encrypted = os.path.isfile(os.path.join(full, INDEX_FILENAME))
            nodes.append({"name": name, "type": "dir", "encrypted": encrypted,
                          "size": None, "mtime": None})
        else:
            st = os.stat(full)
            nodes.append({"name": name, "type": "file", "encrypted": False,
                          "size": st.st_size, "mtime": int(st.st_mtime)})
    return nodes


def _build_tree_from_index(entries: list[dict]) -> list[dict]:
    """把索引 entries 重建为嵌套树（顶层节点列表，children 为 list）。"""
    # 用 dict 树构建，最后统一转 list
    tree: dict[str, dict] = {}

    def ensure_dir_node(path: list[str]) -> dict:
        node = tree
        for seg in path:
            child = node.setdefault(seg, {
                "_is_file": False, "_size": None, "_mtime": None, "_children": {},
            })
            node = child["_children"]
        return node

    for e in entries:
        parts = e["orig"].split("/")
        if e["type"] == "file":
            # 文件：父目录下挂文件节点
            parent = tree
            for seg in parts[:-1]:
                child = parent.setdefault(seg, {
                    "_is_file": False, "_size": None, "_mtime": None, "_children": {},
                })
                parent = child["_children"]
            fname = parts[-1]
            parent[fname] = {
                "_is_file": True, "_size": e.get("size"), "_mtime": e.get("mtime"),
                "_children": {},
            }
        else:
            # 目录：确保路径存在即可
            ensure_dir_node(parts)

    def to_list(node: dict[str, dict]) -> list[dict]:
        out = []
        for name in sorted(node.keys()):
            child = node[name]
            is_file = child.get("_is_file", False)
            item = {
                "name": name,
                "type": "file" if is_file else "dir",
                "encrypted": True,
                "size": child.get("_size"),
                "mtime": child.get("_mtime"),
            }
            if not is_file:
                item["children"] = to_list(child.get("_children", {}))
            out.append(item)
        return out

    return to_list(tree)
