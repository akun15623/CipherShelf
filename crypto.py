"""
secure-vault 加密核心

设计要点（防物理失窃 / 外人无密码不可读）：
- 密码 -> 主密钥：PBKDF2-HMAC-SHA256（随机 salt，默认 60 万次迭代）
- 每个文件用独立随机 data_key 加密（AES-256-GCM）；data_key 再用主密钥加密存进文件头。
  好处：改密码只需重算头部，不用重加密整个文件体。
- 大文件（视频/音频）按 1MB 分块加密，每块独立 AES-GCM，块序号作为 AAD。
  好处：支持随机访问（seek），视频拖进度条只需解密对应块。
- 文件名 / MIME 也加密，防止"外面看到文件名和类型"的元数据泄露。
- 元数据存 SQLite（vault.db）：salt、验证器、加密的文件清单。

磁盘上只有：密文文件 + vault.db，不含任何明文内容、明文文件名、明文密钥。
"""

from __future__ import annotations

import base64
import os
import sqlite3
import time
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac as _hmac

MAGIC = b"VLKT"
VERSION = 1
KEY_SIZE = 32            # AES-256
NONCE_SIZE = 12          # GCM 推荐 12 字节
SALT_SIZE = 16
TAG_SIZE = 16            # GCM tag
BLOCK_SIZE = 1024 * 1024  # 1 MiB 分块
ITERATIONS = 600_000      # PBKDF2 迭代次数（本地解锁可接受的安全强度）

# 文件头布局
HEADER_MAGIC = 4
HEADER_VERSION = 1
HEADER_DATA_KEY_NONCE = NONCE_SIZE
HEADER_DATA_KEY_CT = KEY_SIZE + TAG_SIZE   # data_key 密文 + tag
HEADER_BLOCK_SIZE = 4
HEADER_SIZE = (
    HEADER_MAGIC + HEADER_VERSION + HEADER_DATA_KEY_NONCE + HEADER_DATA_KEY_CT + HEADER_BLOCK_SIZE
)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def derive_master_key(password: str, salt: bytes, iterations: int = ITERATIONS) -> bytes:
    """从密码派生主密钥。password 不应被记录到任何日志。"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def make_verifier(master_key: bytes) -> str:
    """生成验证器：解锁时用来校验密码是否正确（不存密码本身）。"""
    h = _hmac.HMAC(master_key, hashes.SHA256())
    h.update(b"secure-vault-verifier")
    return _b64(h.finalize())


def verify_master_key(master_key: bytes, verifier_b64: str) -> bool:
    try:
        expected = _unb64(verifier_b64)
    except Exception:
        return False
    h = _hmac.HMAC(master_key, hashes.SHA256())
    h.update(b"secure-vault-verifier")
    try:
        h.verify(expected)
        return True
    except Exception:
        return False


def encrypt_name(master_key: bytes, file_id: str, plaintext: str) -> str:
    """加密文件名 / MIME（AAD 绑定 file_id，防止跨文件替换）。"""
    nonce = os.urandom(NONCE_SIZE)
    aes = AESGCM(master_key)
    ct = aes.encrypt(nonce, plaintext.encode("utf-8"), file_id.encode("utf-8"))
    return _b64(nonce + ct)


def decrypt_name(master_key: bytes, file_id: str, cipher_b64: str) -> str:
    raw = _unb64(cipher_b64)
    nonce, ct = raw[:NONCE_SIZE], raw[NONCE_SIZE:]
    aes = AESGCM(master_key)
    pt = aes.decrypt(nonce, ct, file_id.encode("utf-8"))
    return pt.decode("utf-8")


def encrypt_file(master_key: bytes, file_id: str, src_path: str, dst_path: str) -> tuple[int, int]:
    """把明文文件 src_path 加密写入 dst_path。返回 (明文字节数, 密文字节数)。

    dst 布局：
      [magic 4][version 1][data_key_nonce 12][data_key_ct 48][block_size 4]
      然后每块：[nonce 12][ciphertext+tag]
    每块 GCM 的 AAD = file_id + block_index(8B big-endian)，防块重排/替换。
    """
    data_key = os.urandom(KEY_SIZE)
    aes_data = AESGCM(data_key)

    # data_key 用 master_key 加密存头部
    dk_nonce = os.urandom(NONCE_SIZE)
    aes_master = AESGCM(master_key)
    dk_ct = aes_master.encrypt(dk_nonce, data_key, b"data-key")

    plain_size = 0
    with open(src_path, "rb") as fin, open(dst_path, "wb") as fout:
        fout.write(MAGIC)
        fout.write(bytes([VERSION]))
        fout.write(dk_nonce)
        fout.write(dk_ct)
        fout.write(BLOCK_SIZE.to_bytes(HEADER_BLOCK_SIZE, "big"))

        block_index = 0
        while True:
            block = fin.read(BLOCK_SIZE)
            if not block:
                break
            plain_size += len(block)
            nonce = os.urandom(NONCE_SIZE)
            aad = file_id.encode("utf-8") + block_index.to_bytes(8, "big")
            ct = aes_data.encrypt(nonce, block, aad)
            fout.write(nonce)
            fout.write(ct)
            block_index += 1

    cipher_size = os.path.getsize(dst_path)
    return plain_size, cipher_size


def _read_header(f):
    """读取并解析文件头，返回 (data_key_nonce, data_key_ct, block_size)。"""
    f.seek(0)
    magic = f.read(HEADER_MAGIC)
    if magic != MAGIC:
        raise ValueError("不是有效的加密文件（magic 不匹配）")
    version = f.read(HEADER_VERSION)[0]
    if version != VERSION:
        raise ValueError(f"不支持的版本：{version}")
    dk_nonce = f.read(HEADER_DATA_KEY_NONCE)
    dk_ct = f.read(HEADER_DATA_KEY_CT)
    block_size = int.from_bytes(f.read(HEADER_BLOCK_SIZE), "big")
    return dk_nonce, dk_ct, block_size


def _decrypt_data_key(master_key: bytes, dk_nonce: bytes, dk_ct: bytes) -> bytes:
    aes_master = AESGCM(master_key)
    return aes_master.decrypt(dk_nonce, dk_ct, b"data-key")


def block_ranges_for(start: int, length: int, block_size: int):
    """给定明文 [start, start+length)，返回需要解密的块序号列表。"""
    if length <= 0:
        return []
    first = start // block_size
    last = (start + length - 1) // block_size
    return list(range(first, last + 1))


def decrypt_range(master_key: bytes, file_id: str, path: str, start: int, length: int) -> bytes:
    """解密明文 [start, start+length)。start/length 为明文坐标系。

    用于 HTTP Range：视频 seek 时只解密涉及的块。
    """
    with open(path, "rb") as f:
        dk_nonce, dk_ct, block_size = _read_header(f)
        data_key = _decrypt_data_key(master_key, dk_nonce, dk_ct)
        aes_data = AESGCM(data_key)

        out = bytearray()
        needed_start = start
        needed_end = start + length
        for idx in block_ranges_for(start, length, block_size):
            block_off = HEADER_SIZE + idx * (NONCE_SIZE + block_size + TAG_SIZE)
            f.seek(block_off)
            nonce = f.read(NONCE_SIZE)
            ct = f.read(block_size + TAG_SIZE)
            aad = file_id.encode("utf-8") + idx.to_bytes(8, "big")
            pt = aes_data.decrypt(nonce, ct, aad)
            blk_start = idx * block_size
            s = max(blk_start, needed_start) - blk_start
            e = min(blk_start + len(pt), needed_end) - blk_start
            if e > s:
                out += pt[s:e]
        return bytes(out)


def decrypt_full(master_key: bytes, file_id: str, path: str) -> bytes:
    """解密整个文件（小文件 / 图片预览用）。"""
    total = plaintext_size(master_key, file_id, path)
    return decrypt_range(master_key, file_id, path, 0, total)


def plaintext_size(master_key: bytes, file_id: str, path: str) -> int:
    """根据密文文件大小反推明文大小（不真正解密全文件）。"""
    with open(path, "rb") as f:
        _, _, block_size = _read_header(f)
    cipher_len = os.path.getsize(path)
    body_len = cipher_len - HEADER_SIZE
    if body_len == 0:
        return 0
    full_blocks = body_len // (NONCE_SIZE + block_size + TAG_SIZE)
    remainder = body_len - full_blocks * (NONCE_SIZE + block_size + TAG_SIZE)
    last_ct_len = remainder - NONCE_SIZE if remainder > NONCE_SIZE else 0
    return full_blocks * block_size + max(0, last_ct_len - TAG_SIZE)


# ---------------------------------------------------------------------------
# 保险库（SQLite 元数据）
# ---------------------------------------------------------------------------

class Vault:
    """管理 vault.db：salt、验证器、加密的文件元数据清单。"""

    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.db_path = os.path.join(data_dir, "vault.db")
        self.files_dir = os.path.join(data_dir, "files")
        os.makedirs(self.files_dir, exist_ok=True)
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._conn() as c:
            c.execute(
                """CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )"""
            )
            c.execute(
                """CREATE TABLE IF NOT EXISTS files (
                    id TEXT PRIMARY KEY,
                    name_enc TEXT NOT NULL,
                    mime_enc TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    cipher_size INTEGER NOT NULL,
                    thumb INTEGER NOT NULL DEFAULT 0,
                    folder_id_enc TEXT NOT NULL DEFAULT '',
                    created INTEGER NOT NULL
                )"""
            )
            c.execute(
                """CREATE TABLE IF NOT EXISTS folders (
                    id TEXT PRIMARY KEY,
                    name_enc TEXT NOT NULL,
                    parent_id_enc TEXT NOT NULL DEFAULT '',
                    created INTEGER NOT NULL
                )"""
            )
            # 迁移：旧版本 folders 表缺少 parent_id_enc 列时补齐
            cols = [r[1] for r in c.execute("PRAGMA table_info(folders)").fetchall()]
            if "parent_id_enc" not in cols:
                c.execute("ALTER TABLE folders ADD COLUMN parent_id_enc TEXT NOT NULL DEFAULT ''")
            # 迁移：旧版本 files 表缺少 folder_id_enc 列时补齐
            fcols = [r[1] for r in c.execute("PRAGMA table_info(files)").fetchall()]
            if "folder_id_enc" not in fcols:
                c.execute("ALTER TABLE files ADD COLUMN folder_id_enc TEXT NOT NULL DEFAULT ''")

    # -- 初始化 / 解锁 -----------------------------------------------------
    @property
    def exists(self) -> bool:
        with self._conn() as c:
            row = c.execute("SELECT 1 FROM meta WHERE key='verifier'").fetchone()
        return row is not None

    def initialize(self, password: str) -> None:
        if self.exists:
            raise ValueError("保险库已存在")
        salt = os.urandom(SALT_SIZE)
        master_key = derive_master_key(password, salt)
        verifier = make_verifier(master_key)
        with self._conn() as c:
            c.execute("INSERT INTO meta(key,value) VALUES('version',?)", (str(VERSION),))
            c.execute("INSERT INTO meta(key,value) VALUES('kdf_salt',?)", (_b64(salt),))
            c.execute("INSERT INTO meta(key,value) VALUES('kdf_iterations',?)", (str(ITERATIONS),))
            c.execute("INSERT INTO meta(key,value) VALUES('verifier',?)", (verifier,))

    def unlock(self, password: str) -> bytes | None:
        if not self.exists:
            return None
        with self._conn() as c:
            salt = _unb64(c.execute("SELECT value FROM meta WHERE key='kdf_salt'").fetchone()["value"])
            iters = int(c.execute("SELECT value FROM meta WHERE key='kdf_iterations'").fetchone()["value"])
            verifier = c.execute("SELECT value FROM meta WHERE key='verifier'").fetchone()["value"]
        master_key = derive_master_key(password, salt, iters)
        if verify_master_key(master_key, verifier):
            return master_key
        return None

    # -- 文件操作（需已解锁，传入 master_key）-----------------------------
    def add_file(self, master_key: bytes, src_path: str, display_name: str, mime: str, folder_id: str = "") -> str:
        file_id = uuid.uuid4().hex
        dst_path = os.path.join(self.files_dir, file_id + ".enc")
        plain_size, cipher_size = encrypt_file(master_key, file_id, src_path, dst_path)

        with self._conn() as c:
            c.execute(
                "INSERT INTO files(id,name_enc,mime_enc,size,cipher_size,thumb,folder_id_enc,created) VALUES(?,?,?,?,?,0,?,?)",
                (
                    file_id,
                    encrypt_name(master_key, file_id, display_name),
                    encrypt_name(master_key, file_id, mime or "application/octet-stream"),
                    plain_size,
                    cipher_size,
                    encrypt_name(master_key, file_id, folder_id or ""),
                    int(time.time()),
                ),
            )
        return file_id

    def move_file(self, master_key: bytes, file_id: str, folder_id: str) -> bool:
        with self._conn() as c:
            cur = c.execute(
                "UPDATE files SET folder_id_enc=? WHERE id=?",
                (encrypt_name(master_key, file_id, folder_id or ""), file_id),
            )
            return cur.rowcount > 0

    def list_files(self, master_key: bytes, folder_id: str = "") -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM files ORDER BY created DESC").fetchall()
        out = []
        for r in rows:
            f_folder = decrypt_name(master_key, r["id"], r["folder_id_enc"]) if r["folder_id_enc"] else ""
            if f_folder != (folder_id or ""):
                continue
            out.append({
                "id": r["id"],
                "name": decrypt_name(master_key, r["id"], r["name_enc"]),
                "mime": decrypt_name(master_key, r["id"], r["mime_enc"]),
                "size": r["size"],
                "created": r["created"],
                "has_thumb": bool(r["thumb"]),
                "folder_id": f_folder,
            })
        return out

    def copy_file(self, master_key: bytes, src_file_id: str, dst_folder_id: str = "") -> str | None:
        """复制文件（流式：逐块解密+重加密，生成独立新 data_key，不占内存）。"""
        rec = self.get_record(src_file_id)
        if not rec:
            return None
        src_path = self.get_file_path(src_file_id)
        new_id = uuid.uuid4().hex
        dst_path = os.path.join(self.files_dir, new_id + ".enc")

        # 新 data_key（每文件独立密钥）
        new_data_key = os.urandom(KEY_SIZE)
        new_aes = AESGCM(new_data_key)
        dk_nonce = os.urandom(NONCE_SIZE)
        dk_ct = AESGCM(master_key).encrypt(dk_nonce, new_data_key, b"data-key")

        # 读原 data_key
        with open(src_path, "rb") as fin:
            old_dk_nonce, old_dk_ct, block_size = _read_header(fin)
        old_data_key = _decrypt_data_key(master_key, old_dk_nonce, old_dk_ct)
        old_aes = AESGCM(old_data_key)

        plain_size = 0
        with open(src_path, "rb") as fin, open(dst_path, "wb") as fout:
            fout.write(MAGIC)
            fout.write(bytes([VERSION]))
            fout.write(dk_nonce)
            fout.write(dk_ct)
            fout.write(block_size.to_bytes(HEADER_BLOCK_SIZE, "big"))

            fin.seek(HEADER_SIZE)
            block_index = 0
            while True:
                nonce = fin.read(NONCE_SIZE)
                if len(nonce) < NONCE_SIZE:
                    break
                ct = fin.read(block_size + TAG_SIZE)
                if len(ct) < TAG_SIZE:
                    break
                old_aad = src_file_id.encode("utf-8") + block_index.to_bytes(8, "big")
                pt = old_aes.decrypt(nonce, ct, old_aad)
                plain_size += len(pt)
                new_nonce = os.urandom(NONCE_SIZE)
                new_aad = new_id.encode("utf-8") + block_index.to_bytes(8, "big")
                new_ct = new_aes.encrypt(new_nonce, pt, new_aad)
                fout.write(new_nonce)
                fout.write(new_ct)
                block_index += 1

        cipher_size = os.path.getsize(dst_path)
        name = decrypt_name(master_key, src_file_id, rec["name_enc"])
        mime = decrypt_name(master_key, src_file_id, rec["mime_enc"])
        with self._conn() as c:
            c.execute(
                "INSERT INTO files(id,name_enc,mime_enc,size,cipher_size,thumb,folder_id_enc,created) VALUES(?,?,?,?,?,0,?,?)",
                (
                    new_id,
                    encrypt_name(master_key, new_id, name),
                    encrypt_name(master_key, new_id, mime),
                    plain_size,
                    cipher_size,
                    encrypt_name(master_key, new_id, dst_folder_id or ""),
                    int(time.time()),
                ),
            )
        # 复制缩略图
        if self.has_thumb(src_file_id):
            try:
                self.save_thumb(master_key, new_id, self.read_thumb(master_key, src_file_id))
            except Exception:
                pass
        return new_id

    # -- 文件夹操作 -----------------------------------------------------
    def create_folder(self, master_key: bytes, name: str, parent_id: str = "") -> str:
        folder_id = uuid.uuid4().hex
        with self._conn() as c:
            c.execute(
                "INSERT INTO folders(id,name_enc,parent_id_enc,created) VALUES(?,?,?,?)",
                (folder_id, encrypt_name(master_key, folder_id, name),
                 encrypt_name(master_key, folder_id, parent_id or ""), int(time.time())),
            )
        return folder_id

    def list_folders(self, master_key: bytes) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM folders ORDER BY created ASC").fetchall()
        return [
            {
                "id": r["id"],
                "name": decrypt_name(master_key, r["id"], r["name_enc"]),
                "parent_id": decrypt_name(master_key, r["id"], r["parent_id_enc"]) if r["parent_id_enc"] else "",
                "created": r["created"],
            }
            for r in rows
        ]

    def _folder_parent(self, master_key: bytes, folder_id: str) -> str:
        with self._conn() as c:
            r = c.execute("SELECT parent_id_enc FROM folders WHERE id=?", (folder_id,)).fetchone()
        if not r or not r["parent_id_enc"]:
            return ""
        return decrypt_name(master_key, folder_id, r["parent_id_enc"])

    def _folder_name(self, master_key: bytes, folder_id: str) -> str:
        with self._conn() as c:
            r = c.execute("SELECT name_enc FROM folders WHERE id=?", (folder_id,)).fetchone()
        return decrypt_name(master_key, folder_id, r["name_enc"]) if r else ""

    def _folder_children(self, master_key: bytes, folder_id: str) -> list[str]:
        with self._conn() as c:
            rows = c.execute("SELECT id, parent_id_enc FROM folders").fetchall()
        out = []
        for r in rows:
            p = decrypt_name(master_key, r["id"], r["parent_id_enc"]) if r["parent_id_enc"] else ""
            if p == folder_id:
                out.append(r["id"])
        return out

    def rename_folder(self, master_key: bytes, folder_id: str, new_name: str) -> bool:
        with self._conn() as c:
            cur = c.execute(
                "UPDATE folders SET name_enc=? WHERE id=?",
                (encrypt_name(master_key, folder_id, new_name), folder_id),
            )
            return cur.rowcount > 0

    def move_folder(self, master_key: bytes, folder_id: str, new_parent_id: str) -> bool:
        """移动文件夹到新父级。防循环：目标不能是自己或自己的子孙。"""
        if folder_id == new_parent_id:
            return False
        # 从 new_parent_id 往上走到根，若经过 folder_id 则构成循环
        cur = new_parent_id
        while cur:
            if cur == folder_id:
                return False
            cur = self._folder_parent(master_key, cur)
        with self._conn() as c:
            cur = c.execute(
                "UPDATE folders SET parent_id_enc=? WHERE id=?",
                (encrypt_name(master_key, folder_id, new_parent_id or ""), folder_id),
            )
            return cur.rowcount > 0

    def copy_folder(self, master_key: bytes, src_folder_id: str, dst_parent_id: str = "") -> str | None:
        """递归复制文件夹（含子文件夹和文件），返回新文件夹 id。"""
        # 防循环：目标不能是源自身或其子孙
        cur = dst_parent_id
        while cur:
            if cur == src_folder_id:
                return None
            cur = self._folder_parent(master_key, cur)
        src_name = self._folder_name(master_key, src_folder_id)
        new_id = self.create_folder(master_key, src_name, dst_parent_id)
        for f in self.list_files(master_key, src_folder_id):
            self.copy_file(master_key, f["id"], new_id)
        for sub in self._folder_children(master_key, src_folder_id):
            self.copy_folder(master_key, sub, new_id)
        return new_id

    def delete_folder_for_user(self, master_key: bytes, folder_id: str) -> bool:
        """递归删除文件夹：先删子孙文件夹（文件上浮到其父级），再删自身。"""
        # 递归删除子文件夹
        for sub in self._folder_children(master_key, folder_id):
            self.delete_folder_for_user(master_key, sub)
        # 本文件夹文件上浮到父级
        parent = self._folder_parent(master_key, folder_id)
        with self._conn() as c:
            files = c.execute("SELECT id, folder_id_enc FROM files").fetchall()
        for r in files:
            try:
                current = decrypt_name(master_key, r["id"], r["folder_id_enc"]) if r["folder_id_enc"] else ""
            except Exception:
                continue
            if current == folder_id:
                with self._conn() as c:
                    c.execute(
                        "UPDATE files SET folder_id_enc=? WHERE id=?",
                        (encrypt_name(master_key, r["id"], parent), r["id"]),
                    )
        # 删除文件夹记录
        with self._conn() as c:
            cur = c.execute("DELETE FROM folders WHERE id=?", (folder_id,))
            return cur.rowcount > 0

    def get_record(self, file_id: str) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
        return dict(r) if r else None

    def get_file_path(self, file_id: str) -> str:
        p = os.path.join(self.files_dir, file_id + ".enc")
        if not os.path.exists(p):
            raise FileNotFoundError(file_id)
        return p

    def thumb_path(self, file_id: str) -> str:
        return os.path.join(self.files_dir, file_id + ".thumb.enc")

    def has_thumb(self, file_id: str) -> bool:
        return os.path.exists(self.thumb_path(file_id))

    def save_thumb(self, master_key: bytes, file_id: str, jpeg_bytes: bytes) -> None:
        """加密保存缩略图 JPEG。缩略图逻辑 id = file_id + ':thumb'。"""
        import tempfile
        logical_id = file_id + ":thumb"
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".jpg")
        try:
            tmp.write(jpeg_bytes)
            tmp.close()
            encrypt_file(master_key, logical_id, tmp.name, self.thumb_path(file_id))
        finally:
            os.unlink(tmp.name)
        with self._conn() as c:
            c.execute("UPDATE files SET thumb=1 WHERE id=?", (file_id,))

    def read_thumb(self, master_key: bytes, file_id: str) -> bytes:
        logical_id = file_id + ":thumb"
        return decrypt_full(master_key, logical_id, self.thumb_path(file_id))

    def delete_file(self, file_id: str) -> bool:
        with self._conn() as c:
            cur = c.execute("DELETE FROM files WHERE id=?", (file_id,))
            deleted = cur.rowcount > 0
        for suffix in (".enc", ".thumb.enc"):
            try:
                os.remove(os.path.join(self.files_dir, file_id + suffix))
            except OSError:
                pass
        return deleted
