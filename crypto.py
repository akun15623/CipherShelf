"""CipherShelf encryption core.

New indexes use format v3 with a random per-vault PBKDF2 salt. Encrypted files
remain on the authenticated v2 format. Legacy v1/v2 indexes remain readable
for migration, but no new legacy indexes are written.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import posixpath
import re
import shutil
import stat
import tempfile
import threading
import uuid
from pathlib import PurePosixPath

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"SVLT"
LEGACY_VERSION = 1
FILE_VERSION = 2
INDEX_V2_VERSION = 2
INDEX_VERSION = 3
# Public alias for the current index format. File format has its own version.
VERSION = INDEX_VERSION
KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
BLOCK_SIZE = 1024 * 1024
ITERATIONS = 600_000
KDF_ID_PBKDF2_SHA256 = 1
DEFAULT_SALT = b"SVLT-PBKDF2-v1!!"
INDEX_FILENAME = ".svault"
MAX_DERIVED_KEYS = 256

FILE_HEADER_V1_SIZE = 4 + 1 + 4 + 4
FILE_BASE_HEADER_V2_SIZE = 4 + 1 + 4 + 8 + 16
FILE_HEADER_V2_SIZE = FILE_BASE_HEADER_V2_SIZE + NONCE_SIZE + TAG_SIZE
INDEX_HEADER_V1_SIZE = 4 + 1 + NONCE_SIZE
MAX_INDEX_SIZE = 64 * 1024 * 1024
MAX_INDEX_ENTRIES = 1_000_000
MAX_XATTR_BYTES = 1024 * 1024
VAULT_KEY_INFO = b"secure-vault/v2/vault-key"
KDF_SALT_SIZE = 16

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_WINDOWS_RESERVED = re.compile(r"^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$", re.IGNORECASE)
_RESERVED_PREFIXES = (".svault-stage-", ".svault-backup-", ".svault-txn-")

MIN_PASSWORD_LEN = 12


def password_strength_error(password: str) -> str | None:
    """返回密码强度不达标的提示；达标返回 None。

    要求：至少 12 位，且同时包含大写字母、小写字母、数字、符号。
    符号定义为非字母非数字的字符（如 !@#$% 等标点）。
    """
    if len(password) < MIN_PASSWORD_LEN:
        return f"密码至少 {MIN_PASSWORD_LEN} 位"
    if not re.search(r"[A-Z]", password):
        return "密码需包含大写字母"
    if not re.search(r"[a-z]", password):
        return "密码需包含小写字母"
    if not re.search(r"[0-9]", password):
        return "密码需包含数字"
    if not re.search(r"[^A-Za-z0-9]", password):
        return "密码需包含符号（如 !@#$%）"
    return None


def derive_master_key(password: str, salt: bytes = DEFAULT_SALT, iterations: int = ITERATIONS) -> bytes:
    """Derive the legacy-compatible password-root key.

    V3 applies a second, per-vault salted PBKDF2 step before this key is used
    for encryption. The fixed root derivation remains frozen so v1/v2 data is
    still readable.
    """
    if not isinstance(password, str) or not password:
        raise ValueError("密码不能为空")
    if salt != DEFAULT_SALT or iterations != ITERATIONS:
        raise ValueError("格式 v1/v2 的 KDF 参数固定，不允许自定义")
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=KEY_SIZE, salt=salt, iterations=iterations,
    ).derive(password.encode("utf-8"))


class KeyContext:
    """Session-scoped password-root key with a bounded v3 derivation cache."""

    def __init__(self, master_key: bytes):
        self.master_key = _validate_master_key(master_key)
        self._v3_keys: dict[bytes, bytes] = {}
        self._lock = threading.Lock()

    def v3_key(self, kdf_salt: bytes) -> bytes:
        salt = _validate_kdf_salt(kdf_salt)
        with self._lock:
            key = self._v3_keys.get(salt)
            if key is None:
                key = _derive_v3_vault_key_uncached(self.master_key, salt)
                if len(self._v3_keys) >= MAX_DERIVED_KEYS:
                    self._v3_keys.pop(next(iter(self._v3_keys)))
                self._v3_keys[salt] = key
            return key


def _validate_master_key(master_key: bytes) -> bytes:
    if not isinstance(master_key, bytes) or len(master_key) != KEY_SIZE:
        raise ValueError("主密钥必须是 32 字节")
    return master_key


def _validate_kdf_salt(kdf_salt: bytes) -> bytes:
    if not isinstance(kdf_salt, bytes) or len(kdf_salt) != KDF_SALT_SIZE:
        raise ValueError("索引 KDF salt 长度错误")
    return kdf_salt


def _as_key_context(key_material: bytes | KeyContext) -> KeyContext:
    return key_material if isinstance(key_material, KeyContext) else KeyContext(key_material)


def _root_key(key_material: bytes | KeyContext) -> bytes:
    if isinstance(key_material, KeyContext):
        return key_material.master_key
    return _validate_master_key(key_material)


def _derive_v3_vault_key_uncached(master_key: bytes, kdf_salt: bytes) -> bytes:
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=KEY_SIZE,
        salt=_validate_kdf_salt(kdf_salt), iterations=ITERATIONS,
    ).derive(_validate_master_key(master_key))


def _derive_v3_vault_key(key_material: bytes | KeyContext, kdf_salt: bytes) -> bytes:
    if isinstance(key_material, KeyContext):
        return key_material.v3_key(kdf_salt)
    return _derive_v3_vault_key_uncached(key_material, kdf_salt)


def _derive_vault_key(master_key: bytes, vault_salt: bytes) -> bytes:
    """Derive the legacy v2 vault key."""
    master_key = _validate_master_key(master_key)
    if len(vault_salt) != 16:
        raise ValueError("索引 vault_salt 长度错误")
    return HKDF(
        algorithm=hashes.SHA256(), length=KEY_SIZE, salt=vault_salt, info=VAULT_KEY_INFO,
    ).derive(master_key)


def _read_exact(stream, size: int, label: str) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise ValueError(f"加密数据截断：{label}")
    return data


def _fsync_dir(path: str) -> None:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _v1_file_aad(block_index: int) -> bytes:
    return MAGIC + bytes([LEGACY_VERSION]) + block_index.to_bytes(8, "big")


def _v2_block_aad(base_header: bytes, block_index: int) -> bytes:
    return base_header + b"block" + block_index.to_bytes(8, "big")


def encrypt_file(
    master_key: bytes, src_path: str, dst_path: str, *, file_id: str | None = None,
) -> tuple[str, str]:
    """Encrypt one regular file with format v2; return (file_id, sha256)."""
    src_stat = os.stat(src_path, follow_symlinks=False)
    if not stat.S_ISREG(src_stat.st_mode):
        raise ValueError(f"仅支持普通文件：{src_path}")
    plain_size = src_stat.st_size
    block_count = (plain_size + BLOCK_SIZE - 1) // BLOCK_SIZE
    file_id_bytes = bytes.fromhex(file_id) if file_id else uuid.uuid4().bytes
    if len(file_id_bytes) != 16:
        raise ValueError("file_id 必须是 16 字节")
    base_header = (
        MAGIC + bytes([FILE_VERSION]) + BLOCK_SIZE.to_bytes(4, "big")
        + block_count.to_bytes(8, "big") + file_id_bytes
    )
    aes = AESGCM(master_key)
    header_nonce = os.urandom(NONCE_SIZE)
    header_tag = aes.encrypt(header_nonce, b"", base_header + b"file-header")
    digest = hashlib.sha256()
    try:
        with open(src_path, "rb") as fin, open(dst_path, "xb") as fout:
            fout.write(base_header + header_nonce + header_tag)
            for block_index in range(block_count):
                block = fin.read(BLOCK_SIZE)
                if not block or (block_index < block_count - 1 and len(block) != BLOCK_SIZE):
                    raise ValueError(f"加密期间源文件大小发生变化：{src_path}")
                digest.update(block)
                nonce = os.urandom(NONCE_SIZE)
                fout.write(nonce)
                fout.write(aes.encrypt(nonce, block, _v2_block_aad(base_header, block_index)))
            if fin.read(1) or os.fstat(fin.fileno()).st_size != plain_size:
                raise ValueError(f"加密期间源文件大小发生变化：{src_path}")
            fout.flush()
            os.fsync(fout.fileno())
    except Exception:
        try:
            os.remove(dst_path)
        except OSError:
            pass
        raise
    return file_id_bytes.hex(), digest.hexdigest()


def _validate_block_layout(total_size: int, header_size: int, block_count: int) -> None:
    remaining = total_size - header_size
    if block_count == 0:
        if remaining != 0:
            raise ValueError("空文件密文包含尾随数据")
        return
    minimum = block_count * (NONCE_SIZE + TAG_SIZE + 1)
    maximum = block_count * (NONCE_SIZE + TAG_SIZE + BLOCK_SIZE)
    if remaining < minimum or remaining > maximum:
        raise ValueError("密文块数量或文件长度不一致")


def decrypt_file(
    master_key: bytes,
    src_path: str,
    dst_path: str,
    *,
    expected_file_id: str | None = None,
    expected_sha256: str | None = None,
) -> None:
    """Decrypt format v2, with format-v1 support for migration."""
    total_size = os.path.getsize(src_path)
    try:
        with open(src_path, "rb") as fin, open(dst_path, "xb") as fout:
            if _read_exact(fin, 4, "magic") != MAGIC:
                raise ValueError("不是有效的加密文件（magic 不匹配）")
            version = _read_exact(fin, 1, "version")[0]
            aes = AESGCM(master_key)
            digest = hashlib.sha256()
            if version == LEGACY_VERSION:
                chunk_size = int.from_bytes(_read_exact(fin, 4, "chunk_size"), "big")
                block_count = int.from_bytes(_read_exact(fin, 4, "block_count"), "big")
                if chunk_size != BLOCK_SIZE:
                    raise ValueError("旧格式 chunk_size 非法")
                _validate_block_layout(total_size, FILE_HEADER_V1_SIZE, block_count)
                aad_for = _v1_file_aad
            elif version == FILE_VERSION:
                chunk_size = int.from_bytes(_read_exact(fin, 4, "chunk_size"), "big")
                block_count = int.from_bytes(_read_exact(fin, 8, "block_count"), "big")
                file_id_bytes = _read_exact(fin, 16, "file_id")
                header_nonce = _read_exact(fin, NONCE_SIZE, "header_nonce")
                header_tag = _read_exact(fin, TAG_SIZE, "header_tag")
                base_header = (
                    MAGIC + bytes([FILE_VERSION]) + chunk_size.to_bytes(4, "big")
                    + block_count.to_bytes(8, "big") + file_id_bytes
                )
                try:
                    aes.decrypt(header_nonce, header_tag, base_header + b"file-header")
                except InvalidTag as exc:
                    raise ValueError("文件头认证失败") from exc
                if chunk_size != BLOCK_SIZE:
                    raise ValueError("chunk_size 非法")
                if expected_file_id and file_id_bytes.hex() != expected_file_id:
                    raise ValueError("密文 file_id 与索引不一致")
                _validate_block_layout(total_size, FILE_HEADER_V2_SIZE, block_count)
                aad_for = lambda index: _v2_block_aad(base_header, index)
            else:
                raise ValueError(f"不支持的加密文件版本：{version}")
            for block_index in range(block_count):
                nonce = _read_exact(fin, NONCE_SIZE, "block nonce")
                if block_index < block_count - 1:
                    ciphertext = _read_exact(fin, chunk_size + TAG_SIZE, "ciphertext block")
                else:
                    ciphertext = fin.read()
                    if not (TAG_SIZE < len(ciphertext) <= chunk_size + TAG_SIZE):
                        raise ValueError("最后一个密文块长度非法")
                try:
                    plaintext = aes.decrypt(nonce, ciphertext, aad_for(block_index))
                except InvalidTag as exc:
                    raise ValueError("密文认证失败") from exc
                digest.update(plaintext)
                fout.write(plaintext)
            if expected_sha256 and digest.hexdigest() != expected_sha256:
                raise ValueError("明文摘要与索引不一致")
            fout.flush()
            os.fsync(fout.fileno())
    except Exception:
        try:
            os.remove(dst_path)
        except OSError:
            pass
        raise


def _normalize_relpath(value: object, *, legacy: bool, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"索引字段 {field} 不是有效相对路径")
    if legacy:
        value = value.replace("\\", "/")
    elif "\\" in value:
        raise ValueError(f"索引字段 {field} 必须使用 / 分隔")
    if PurePosixPath(value).is_absolute() or value.startswith("/"):
        raise ValueError(f"索引包含非法绝对路径：{value}")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError(f"索引包含非法路径：{value}")
    if not legacy:
        for part in parts:
            if (
                ":" in part
                or any(ord(char) < 32 for char in part)
                or part.endswith((" ", "."))
                or _WINDOWS_RESERVED.fullmatch(part)
            ):
                raise ValueError(f"索引包含不可移植或危险的路径段：{value}")
    if posixpath.normpath(value) != value or value.startswith("../"):
        raise ValueError(f"索引包含非法路径：{value}")
    return value


def _validate_metadata(entry: dict) -> None:
    mode = entry.get("mode")
    if mode is not None and (not isinstance(mode, int) or isinstance(mode, bool) or not 0 <= mode <= 0o7777):
        raise ValueError("索引 mode 非法")
    mtime_ns = entry.get("mtime_ns")
    if mtime_ns is not None and (not isinstance(mtime_ns, int) or isinstance(mtime_ns, bool)):
        raise ValueError("索引 mtime_ns 非法")
    for field in ("uid", "gid"):
        value = entry.get(field)
        if value is not None and (not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 2**32):
            raise ValueError(f"索引 {field} 非法")
    xattrs = entry.get("xattrs")
    if xattrs is not None:
        if not isinstance(xattrs, dict):
            raise ValueError("索引 xattrs 非法")
        total = 0
        for name, encoded in xattrs.items():
            if not isinstance(name, str) or not name or "\x00" in name or not isinstance(encoded, str):
                raise ValueError("索引扩展属性非法")
            try:
                decoded = base64.b64decode(encoded, validate=True)
            except (ValueError, TypeError) as exc:
                raise ValueError("索引扩展属性编码非法") from exc
            total += len(name.encode("utf-8")) + len(decoded)
            if total > MAX_XATTR_BYTES:
                raise ValueError("索引扩展属性过大")


def _validate_entries(raw_entries: object, *, legacy: bool) -> list[dict]:
    if not isinstance(raw_entries, list) or len(raw_entries) > MAX_INDEX_ENTRIES:
        raise ValueError("索引 entries 类型或数量非法")
    entries: list[dict] = []
    orig_seen: set[str] = set()
    enc_seen: set[str] = set()
    file_ids: set[str] = set()
    for raw in raw_entries:
        if not isinstance(raw, dict) or raw.get("type") not in ("file", "dir"):
            raise ValueError("索引条目类型非法")
        entry = dict(raw)
        entry["orig"] = _normalize_relpath(raw.get("orig"), legacy=legacy, field="orig")
        entry["enc"] = _normalize_relpath(raw.get("enc"), legacy=legacy, field="enc")
        if entry["orig"] == INDEX_FILENAME or entry["orig"].startswith(INDEX_FILENAME + "/"):
            raise ValueError("索引包含保留文件名")
        if entry["orig"] in orig_seen or entry["enc"] in enc_seen:
            raise ValueError("索引包含重复路径")
        orig_seen.add(entry["orig"])
        enc_seen.add(entry["enc"])
        if not legacy and any(not _HEX32.fullmatch(part) for part in entry["enc"].split("/")):
            raise ValueError("索引密文路径格式非法")
        _validate_metadata(entry)
        if entry["type"] == "file":
            if not isinstance(entry.get("size"), int) or isinstance(entry.get("size"), bool) or entry["size"] < 0:
                raise ValueError("索引文件大小非法")
            if not isinstance(entry.get("mtime"), (int, float)) or isinstance(entry.get("mtime"), bool):
                raise ValueError("索引 mtime 非法")
            if not legacy:
                file_id = entry.get("file_id")
                digest = entry.get("sha256")
                if not isinstance(file_id, str) or not _HEX32.fullmatch(file_id):
                    raise ValueError("索引 file_id 非法")
                if file_id in file_ids:
                    raise ValueError("索引 file_id 重复")
                file_ids.add(file_id)
                if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
                    raise ValueError("索引 sha256 非法")
        entries.append(entry)
    if not legacy:
        dirs = {entry["orig"]: entry["enc"] for entry in entries if entry["type"] == "dir"}
        for entry in entries:
            orig_parent = posixpath.dirname(entry["orig"])
            enc_parent = posixpath.dirname(entry["enc"])
            if orig_parent:
                if dirs.get(orig_parent) != enc_parent:
                    raise ValueError("索引父子目录关系不闭合")
            elif enc_parent:
                raise ValueError("索引顶层对象的密文路径非法")
    return entries


def _index_v1_aad() -> bytes:
    return MAGIC + bytes([LEGACY_VERSION]) + b"index"


def write_index(
    key_material: bytes | KeyContext,
    path: str,
    entries: list[dict],
    *,
    kdf_salt: bytes | None = None,
) -> bytes:
    validated = _validate_entries(entries, legacy=False)
    data = json.dumps(
        {"magic": "SVLT", "version": INDEX_VERSION, "entries": validated},
        ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")
    if len(data) > MAX_INDEX_SIZE:
        raise ValueError("索引过大")
    kdf_salt = _validate_kdf_salt(kdf_salt or os.urandom(KDF_SALT_SIZE))
    vault_key = _derive_v3_vault_key(key_material, kdf_salt)
    base_header = (
        MAGIC + bytes([INDEX_VERSION, KDF_ID_PBKDF2_SHA256])
        + ITERATIONS.to_bytes(4, "big") + kdf_salt
    )
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(vault_key).encrypt(nonce, data, base_header + b"index")
    tmp = path + ".tmp-" + uuid.uuid4().hex
    try:
        with open(tmp, "xb") as stream:
            stream.write(base_header + nonce + ciphertext)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        _fsync_dir(os.path.dirname(path) or ".")
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    return kdf_salt


def _read_index_with_key(
    key_material: bytes | KeyContext, path: str,
) -> tuple[list[dict], bytes, int]:
    size = os.path.getsize(path)
    if size > MAX_INDEX_SIZE or size < INDEX_HEADER_V1_SIZE + TAG_SIZE:
        raise ValueError("索引大小非法")
    with open(path, "rb") as stream:
        if _read_exact(stream, 4, "index magic") != MAGIC:
            raise ValueError("不是有效的索引文件（magic 不匹配）")
        version = _read_exact(stream, 1, "index version")[0]
        if version == LEGACY_VERSION:
            nonce = _read_exact(stream, NONCE_SIZE, "index nonce")
            ciphertext = stream.read()
            vault_key = _root_key(key_material)
            aad = _index_v1_aad()
            legacy = True
            expected_version = LEGACY_VERSION
        elif version == INDEX_V2_VERSION:
            kdf_id = _read_exact(stream, 1, "kdf_id")[0]
            iterations = int.from_bytes(_read_exact(stream, 4, "iterations"), "big")
            salt = _read_exact(stream, 16, "salt")
            vault_salt = _read_exact(stream, 16, "vault_salt")
            nonce = _read_exact(stream, NONCE_SIZE, "index nonce")
            if kdf_id != KDF_ID_PBKDF2_SHA256 or iterations != ITERATIONS or salt != DEFAULT_SALT:
                raise ValueError("索引 KDF 参数不受支持")
            base_header = (
                MAGIC + bytes([INDEX_V2_VERSION, kdf_id]) + iterations.to_bytes(4, "big")
                + salt + vault_salt
            )
            vault_key = _derive_vault_key(_root_key(key_material), vault_salt)
            ciphertext = stream.read()
            aad = base_header + b"index"
            legacy = False
            expected_version = INDEX_V2_VERSION
        elif version == INDEX_VERSION:
            kdf_id = _read_exact(stream, 1, "kdf_id")[0]
            iterations = int.from_bytes(_read_exact(stream, 4, "iterations"), "big")
            kdf_salt = _read_exact(stream, KDF_SALT_SIZE, "kdf_salt")
            nonce = _read_exact(stream, NONCE_SIZE, "index nonce")
            if kdf_id != KDF_ID_PBKDF2_SHA256 or iterations != ITERATIONS:
                raise ValueError("索引 KDF 参数不受支持")
            base_header = (
                MAGIC + bytes([INDEX_VERSION, kdf_id]) + iterations.to_bytes(4, "big")
                + kdf_salt
            )
            vault_key = _derive_v3_vault_key(key_material, kdf_salt)
            ciphertext = stream.read()
            aad = base_header + b"index"
            legacy = False
            expected_version = INDEX_VERSION
        else:
            raise ValueError(f"不支持的索引版本：{version}")
    if len(ciphertext) < TAG_SIZE:
        raise ValueError("索引密文截断")
    try:
        plaintext = AESGCM(vault_key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise ValueError("密码错误或索引已损坏") from exc
    try:
        obj = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("索引 JSON 损坏") from exc
    if not isinstance(obj, dict) or obj.get("magic") != "SVLT" or obj.get("version") != expected_version:
        raise ValueError("索引内容版本或 magic 非法")
    entries = _validate_entries(obj.get("entries"), legacy=legacy)
    return entries, vault_key, version


def read_index(key_material: bytes | KeyContext, path: str) -> list[dict]:
    return _read_index_with_key(key_material, path)[0]


def _is_link_or_junction(path: str) -> bool:
    return os.path.islink(path) or bool(getattr(os.path, "isjunction", lambda _p: False)(path))


def find_encrypted_roots(root_dir: str) -> list[str]:
    root_dir = os.path.realpath(root_dir)
    index_paths: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root_dir, followlinks=False):
        dirnames[:] = [
            name for name in dirnames
            if not name.startswith(_RESERVED_PREFIXES)
            and not _is_link_or_junction(os.path.join(dirpath, name))
        ]
        if INDEX_FILENAME in filenames:
            index_paths.append(os.path.join(dirpath, INDEX_FILENAME))
            dirnames[:] = []
        # A crash after an in-place decrypt commit can leave the authenticated
        # encrypted source in a transaction backup. Include it for password
        # verification so the workspace cannot be re-initialized with a new key.
        for name in filenames:
            if not (name.startswith(".svault-txn-") and name.endswith(".json")):
                continue
            try:
                with open(os.path.join(dirpath, name), "r", encoding="utf-8") as stream:
                    txn = json.load(stream)
                backup = os.path.realpath(txn["backup"])
                if os.path.commonpath([root_dir, backup]) != root_dir:
                    continue
                backup_index = os.path.join(backup, INDEX_FILENAME)
                if os.path.isfile(backup_index):
                    index_paths.append(backup_index)
            except (OSError, ValueError, KeyError, json.JSONDecodeError):
                continue
    return sorted(set(index_paths))


def is_initialized(root_dir: str) -> bool:
    return bool(find_encrypted_roots(root_dir))


def _read_xattrs(path: str) -> dict[str, str]:
    if not hasattr(os, "listxattr"):
        return {}
    result: dict[str, str] = {}
    total = 0
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError:
        return {}
    for name in names:
        try:
            value = os.getxattr(path, name, follow_symlinks=False)
        except OSError as exc:
            raise ValueError(f"无法读取扩展属性 {path}: {name}") from exc
        total += len(name.encode("utf-8")) + len(value)
        if total > MAX_XATTR_BYTES:
            raise ValueError(f"扩展属性过大：{path}")
        result[name] = base64.b64encode(value).decode("ascii")
    return result


def _metadata(path: str, st: os.stat_result) -> dict:
    data = {"mode": stat.S_IMODE(st.st_mode), "mtime": int(st.st_mtime), "mtime_ns": st.st_mtime_ns}
    if os.name == "posix":
        data["uid"] = st.st_uid
        data["gid"] = st.st_gid
        attrs = _read_xattrs(path)
        if attrs:
            data["xattrs"] = attrs
    return data


def _scan_folder_detailed(root_dir: str) -> tuple[list[dict], list[dict]]:
    files: list[dict] = []
    dirs: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(root_dir, followlinks=False):
        for name in list(dirnames):
            full = os.path.join(dirpath, name)
            if _is_link_or_junction(full):
                raise ValueError(f"目录包含不支持的符号链接或联接点：{full}")
            if name.startswith(_RESERVED_PREFIXES):
                raise ValueError(f"目录包含保留事务名称：{full}")
        dirnames.sort()
        rel_dir = os.path.relpath(dirpath, root_dir)
        if rel_dir != ".":
            rel_posix = rel_dir.replace(os.sep, "/")
            dirs.append({"orig": rel_posix, **_metadata(dirpath, os.stat(dirpath, follow_symlinks=False))})
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            if name == INDEX_FILENAME or name.startswith(_RESERVED_PREFIXES):
                raise ValueError(f"目录包含保留文件或嵌套加密库：{full}")
            st = os.stat(full, follow_symlinks=False)
            if _is_link_or_junction(full) or stat.S_ISLNK(st.st_mode):
                raise ValueError(f"目录包含不支持的符号链接：{full}")
            if not stat.S_ISREG(st.st_mode):
                raise ValueError(f"目录包含不支持的特殊文件：{full}")
            rel = os.path.relpath(full, root_dir).replace(os.sep, "/")
            files.append({"orig": rel, "size": st.st_size, **_metadata(full, st)})
    dirs.sort(key=lambda item: (item["orig"].count("/"), item["orig"]))
    files.sort(key=lambda item: item["orig"])
    return files, dirs


def _scan_folder(root_dir: str) -> tuple[list[tuple[str, int, int]], list[str]]:
    files, dirs = _scan_folder_detailed(root_dir)
    return (
        [(item["orig"], item["size"], item["mtime"]) for item in files],
        [item["orig"] for item in dirs],
    )


def _disk_path(root: str, rel_posix: str) -> str:
    return os.path.join(root, *rel_posix.split("/"))


def _ensure_real_directory(path: str, label: str) -> str:
    absolute = os.path.abspath(path)
    if _is_link_or_junction(absolute):
        raise ValueError(f"{label}不能是符号链接或联接点：{absolute}")
    if not os.path.isdir(absolute):
        raise ValueError(f"{label}不存在：{absolute}")
    return os.path.realpath(absolute)


def _write_txn(path: str, data: dict) -> None:
    tmp = path + ".tmp-" + uuid.uuid4().hex
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        _fsync_dir(os.path.dirname(path) or ".")
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def _commit_directory(root: str, stage: str, operation: str, verify) -> None:
    parent = os.path.dirname(root)
    txid = uuid.uuid4().hex
    backup = os.path.join(parent, ".svault-backup-" + txid)
    txn_path = os.path.join(parent, ".svault-txn-" + txid + ".json")
    txn = {"version": 1, "operation": operation, "phase": "staged", "root": root, "stage": stage, "backup": backup}
    _write_txn(txn_path, txn)
    source_moved = False
    committed = False
    try:
        os.rename(root, backup)
        source_moved = True
        _fsync_dir(parent)
        txn["phase"] = "source_moved"
        _write_txn(txn_path, txn)
        os.rename(stage, root)
        committed = True
        _fsync_dir(parent)
        txn["phase"] = "committed"
        _write_txn(txn_path, txn)
        verify(root)
        txn["phase"] = "verified"
        _write_txn(txn_path, txn)
        shutil.rmtree(backup)
        _fsync_dir(parent)
        os.remove(txn_path)
        _fsync_dir(parent)
    except Exception:
        if source_moved and not committed and not os.path.exists(root) and os.path.isdir(backup):
            try:
                os.rename(backup, root)
                _fsync_dir(parent)
                if os.path.isdir(stage):
                    shutil.rmtree(stage)
                if os.path.exists(txn_path):
                    os.remove(txn_path)
                _fsync_dir(parent)
            except Exception:
                pass
        elif not source_moved:
            try:
                if os.path.isdir(stage):
                    shutil.rmtree(stage)
                if os.path.exists(txn_path):
                    os.remove(txn_path)
            except OSError:
                pass
        raise


def recover_transactions(
    vault_root: str, key_material: bytes | KeyContext | None = None,
) -> list[str]:
    """Recover interrupted transactions.

    Without a key this only performs unambiguous rollback/cleanup. With a key,
    a committed tree is authenticated before its retained backup is removed.
    """
    vault_root = os.path.realpath(vault_root)
    recovered: list[str] = []
    for dirpath, dirnames, filenames in os.walk(vault_root, followlinks=False):
        dirnames[:] = [d for d in dirnames if not d.startswith(_RESERVED_PREFIXES)]
        for name in filenames:
            if not (name.startswith(".svault-txn-") and name.endswith(".json")):
                continue
            txn_path = os.path.join(dirpath, name)
            try:
                with open(txn_path, "r", encoding="utf-8") as stream:
                    txn = json.load(stream)
                root = os.path.realpath(txn["root"])
                stage = os.path.realpath(txn["stage"])
                backup = os.path.realpath(txn["backup"])
                if os.path.commonpath([vault_root, root]) != vault_root:
                    continue
                root_exists, stage_exists, backup_exists = map(os.path.isdir, (root, stage, backup))
                if not root_exists and backup_exists:
                    os.rename(backup, root)
                    if stage_exists:
                        shutil.rmtree(stage)
                    os.remove(txn_path)
                    recovered.append(root)
                elif root_exists and stage_exists and not backup_exists:
                    shutil.rmtree(stage)
                    os.remove(txn_path)
                    recovered.append(root)
                elif root_exists and not stage_exists and not backup_exists:
                    os.remove(txn_path)
                    recovered.append(root)
                elif root_exists and backup_exists and not stage_exists and key_material is not None:
                    operation = txn.get("operation")
                    if operation == "encrypt":
                        _verify_vault_index(key_material, root)
                    elif operation == "decrypt":
                        backup_index = os.path.join(backup, INDEX_FILENAME)
                        entries = read_index(key_material, backup_index)
                        _verify_plain_tree(root, entries)
                    else:
                        continue
                    shutil.rmtree(backup)
                    os.remove(txn_path)
                    recovered.append(root)
                _fsync_dir(dirpath)
            except (OSError, ValueError, KeyError, json.JSONDecodeError):
                continue
    return recovered


def _verify_vault_index(key_material: bytes | KeyContext, root: str) -> None:
    entries, _key, _version = _read_index_with_key(key_material, os.path.join(root, INDEX_FILENAME))
    for entry in entries:
        if entry["type"] == "file" and not os.path.isfile(_disk_path(root, entry["enc"])):
            raise ValueError("提交后的密文文件清单不完整")


def encrypt_folder(key_material: bytes | KeyContext, root_dir: str, progress=None) -> int:
    key_material = _as_key_context(key_material)
    root_dir = _ensure_real_directory(root_dir, "目录")
    if os.path.isfile(os.path.join(root_dir, INDEX_FILENAME)):
        raise ValueError("该目录已加密（已存在 .svault）")
    files, dirs = _scan_folder_detailed(root_dir)
    parent = os.path.dirname(root_dir)
    stage = tempfile.mkdtemp(prefix=".svault-stage-", dir=parent)
    kdf_salt = os.urandom(KDF_SALT_SIZE)
    vault_key = _derive_v3_vault_key(key_material, kdf_salt)
    enc_of: dict[str, str] = {}
    total = sum(item["size"] for item in files)
    done = 0
    entries: list[dict] = []
    try:
        for item in dirs:
            orig = item["orig"]
            parent_orig = posixpath.dirname(orig)
            leaf = uuid.uuid4().hex
            enc = posixpath.join(enc_of[parent_orig], leaf) if parent_orig else leaf
            enc_of[orig] = enc
            os.makedirs(_disk_path(stage, enc), exist_ok=False)
            entries.append({"type": "dir", "orig": orig, "enc": enc, **{k: v for k, v in item.items() if k != "orig"}})
        for item in files:
            orig = item["orig"]
            parent_orig = posixpath.dirname(orig)
            leaf = uuid.uuid4().hex
            enc = posixpath.join(enc_of[parent_orig], leaf) if parent_orig else leaf
            actual_id, digest = encrypt_file(
                vault_key, _disk_path(root_dir, orig), _disk_path(stage, enc), file_id=uuid.uuid4().hex,
            )
            entries.append({
                "type": "file", "orig": orig, "enc": enc, "file_id": actual_id, "sha256": digest,
                **{k: v for k, v in item.items() if k != "orig"},
            })
            done += item["size"]
            if progress:
                progress(done, total, orig)
        write_index(key_material, os.path.join(stage, INDEX_FILENAME), entries, kdf_salt=kdf_salt)
        _fsync_dir(stage)
        _verify_vault_index(key_material, stage)
        _commit_directory(root_dir, stage, "encrypt", lambda root: _verify_vault_index(key_material, root))
        return len(files)
    except Exception:
        if os.path.isdir(stage) and os.path.realpath(stage) != os.path.realpath(root_dir):
            shutil.rmtree(stage, ignore_errors=True)
        raise


def _restore_metadata(path: str, entry: dict) -> None:
    if "mode" in entry:
        try:
            os.chmod(path, int(entry["mode"]), follow_symlinks=False)
        except (NotImplementedError, TypeError):
            os.chmod(path, int(entry["mode"]))
    if os.name == "posix" and "uid" in entry and "gid" in entry:
        current = os.stat(path, follow_symlinks=False)
        if (current.st_uid, current.st_gid) != (entry["uid"], entry["gid"]):
            try:
                os.chown(path, int(entry["uid"]), int(entry["gid"]), follow_symlinks=False)
            except PermissionError as exc:
                raise ValueError(f"无法还原文件所有者：{path}") from exc
    for name, encoded in (entry.get("xattrs") or {}).items():
        try:
            os.setxattr(path, name, base64.b64decode(encoded), follow_symlinks=False)
        except OSError as exc:
            raise ValueError(f"无法还原扩展属性 {name}：{path}") from exc
    if "mtime_ns" in entry:
        try:
            os.utime(path, ns=(int(entry["mtime_ns"]), int(entry["mtime_ns"])), follow_symlinks=False)
        except (NotImplementedError, TypeError):
            os.utime(path, ns=(int(entry["mtime_ns"]), int(entry["mtime_ns"])))
    elif "mtime" in entry:
        try:
            os.utime(path, (entry["mtime"], entry["mtime"]), follow_symlinks=False)
        except (NotImplementedError, TypeError):
            os.utime(path, (entry["mtime"], entry["mtime"]))


def _verify_plain_tree(root: str, entries: list[dict]) -> None:
    for entry in entries:
        path = _disk_path(root, entry["orig"])
        if entry["type"] == "dir":
            if not os.path.isdir(path) or _is_link_or_junction(path):
                raise ValueError("提交后的目录清单不完整")
        elif not os.path.isfile(path) or os.path.getsize(path) != entry.get("size", 0):
            raise ValueError("提交后的明文文件清单不完整")


def decrypt_folder(
    key_material: bytes | KeyContext,
    root_dir: str,
    output_dir: str | None = None,
    progress=None,
) -> int:
    key_material = _as_key_context(key_material)
    root_dir = _ensure_real_directory(root_dir, "目录")
    index_path = os.path.join(root_dir, INDEX_FILENAME)
    if not os.path.isfile(index_path):
        raise ValueError(f"未找到索引文件 {INDEX_FILENAME}，该目录可能未加密")
    entries, vault_key, index_version = _read_index_with_key(key_material, index_path)
    files = [entry for entry in entries if entry["type"] == "file"]
    dirs = [entry for entry in entries if entry["type"] == "dir"]
    output = os.path.abspath(output_dir) if output_dir else root_dir
    if output != root_dir and os.path.exists(output):
        raise ValueError(f"输出目录已存在：{output}")
    parent = os.path.dirname(output)
    os.makedirs(parent, exist_ok=True)
    stage = tempfile.mkdtemp(prefix=".svault-stage-", dir=parent)
    total = sum(entry.get("size", 0) for entry in files)
    done = 0
    try:
        for entry in sorted(dirs, key=lambda item: (item["orig"].count("/"), item["orig"])):
            os.makedirs(_disk_path(stage, entry["orig"]), exist_ok=False)
        for entry in files:
            dst = _disk_path(stage, entry["orig"])
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            decrypt_file(
                vault_key, _disk_path(root_dir, entry["enc"]), dst,
                expected_file_id=entry.get("file_id") if index_version != LEGACY_VERSION else None,
                expected_sha256=entry.get("sha256") if index_version != LEGACY_VERSION else None,
            )
            _restore_metadata(dst, entry)
            done += entry.get("size", 0)
            if progress:
                progress(done, total, entry["orig"])
        for entry in sorted(dirs, key=lambda item: item["orig"].count("/"), reverse=True):
            _restore_metadata(_disk_path(stage, entry["orig"]), entry)
        _fsync_dir(stage)
        _verify_plain_tree(stage, entries)
        if output == root_dir:
            _commit_directory(root_dir, stage, "decrypt", lambda root: _verify_plain_tree(root, entries))
        else:
            os.rename(stage, output)
            _fsync_dir(parent)
        return len(files)
    except Exception:
        if os.path.isdir(stage) and os.path.realpath(stage) != os.path.realpath(output):
            shutil.rmtree(stage, ignore_errors=True)
        raise


def list_directory(key_material: bytes | KeyContext, root_dir: str, rel_path: str = "") -> list[dict]:
    root_dir = _ensure_real_directory(root_dir, "根目录")
    if rel_path:
        rel_path = _normalize_relpath(rel_path.replace(os.sep, "/"), legacy=False, field="path")
        abs_path = _disk_path(root_dir, rel_path)
    else:
        abs_path = root_dir
    if _is_link_or_junction(abs_path) or not os.path.isdir(abs_path):
        raise ValueError(f"目录不存在或不安全：{abs_path}")
    if os.path.commonpath([root_dir, os.path.realpath(abs_path)]) != root_dir:
        raise ValueError("目录路径越界")
    index_path = os.path.join(abs_path, INDEX_FILENAME)
    if os.path.isfile(index_path):
        return _build_tree_from_index(read_index(key_material, index_path))
    nodes: list[dict] = []
    for name in sorted(os.listdir(abs_path)):
        if name.startswith(_RESERVED_PREFIXES) or name == INDEX_FILENAME:
            continue
        full = os.path.join(abs_path, name)
        if _is_link_or_junction(full):
            continue
        if os.path.isdir(full):
            nodes.append({
                "name": name, "type": "dir", "encrypted": os.path.isfile(os.path.join(full, INDEX_FILENAME)),
                "size": None, "mtime": None,
            })
        elif os.path.isfile(full):
            st = os.stat(full, follow_symlinks=False)
            nodes.append({
                "name": name, "type": "file", "encrypted": False,
                "size": st.st_size, "mtime": int(st.st_mtime),
            })
    return nodes


def _build_tree_from_index(entries: list[dict]) -> list[dict]:
    tree: dict[str, dict] = {}

    def ensure_dir(parts: list[str]) -> dict:
        node = tree
        for segment in parts:
            child = node.setdefault(segment, {
                "_is_file": False, "_size": None, "_mtime": None, "_children": {},
            })
            if child.get("_is_file"):
                raise ValueError("索引中文件与目录冲突")
            node = child["_children"]
        return node

    for entry in entries:
        parts = entry["orig"].replace("\\", "/").split("/")
        if entry["type"] == "file":
            parent = ensure_dir(parts[:-1])
            if parts[-1] in parent:
                raise ValueError("索引中文件名冲突")
            parent[parts[-1]] = {
                "_is_file": True, "_size": entry.get("size"),
                "_mtime": entry.get("mtime"), "_children": {},
            }
        else:
            ensure_dir(parts)

    def to_list(node: dict[str, dict]) -> list[dict]:
        result = []
        for name in sorted(node):
            child = node[name]
            is_file = child.get("_is_file", False)
            item = {
                "name": name, "type": "file" if is_file else "dir", "encrypted": True,
                "size": child.get("_size"), "mtime": child.get("_mtime"),
            }
            if not is_file:
                item["children"] = to_list(child.get("_children", {}))
            result.append(item)
        return result
    return to_list(tree)
