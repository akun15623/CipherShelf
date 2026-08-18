import json
import os
import shutil
import tempfile
import unittest
import uuid
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import crypto

PASSWORD = "test-password-123"
KEY = crypto.derive_master_key(PASSWORD)


def make_tree(base):
    os.makedirs(os.path.join(base, "2024", "旅行"), exist_ok=True)
    os.makedirs(os.path.join(base, "2025"), exist_ok=True)
    os.makedirs(os.path.join(base, "空目录"), exist_ok=True)
    with open(os.path.join(base, "2024", "旅行", "照片.jpg"), "wb") as stream:
        stream.write(os.urandom(10_000))
    with open(os.path.join(base, "2024", "全家福.jpg"), "wb") as stream:
        stream.write("hello 全家福".encode() * 100)
    with open(os.path.join(base, "2025", "视频.bin"), "wb") as stream:
        stream.write(os.urandom(2 * 1024 * 1024 + 12_345))
    open(os.path.join(base, "空文件.txt"), "wb").close()
    with open(os.path.join(base, "根文件.txt"), "wb") as stream:
        stream.write("根目录文件".encode())


def write_raw_v2_index(path, entries):
    vault_salt = os.urandom(16)
    vault_key = crypto._derive_vault_key(KEY, vault_salt)
    base = (
        crypto.MAGIC
        + bytes([crypto.VERSION, crypto.KDF_ID_PBKDF2_SHA256])
        + crypto.ITERATIONS.to_bytes(4, "big")
        + crypto.DEFAULT_SALT
        + vault_salt
    )
    nonce = os.urandom(crypto.NONCE_SIZE)
    data = json.dumps({"magic": "SVLT", "version": crypto.VERSION, "entries": entries}).encode()
    ciphertext = AESGCM(vault_key).encrypt(nonce, data, base + b"index")
    with open(path, "wb") as stream:
        stream.write(base + nonce + ciphertext)


def write_v1_file(src, dst):
    size = os.path.getsize(src)
    count = (size + crypto.BLOCK_SIZE - 1) // crypto.BLOCK_SIZE
    aes = AESGCM(KEY)
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        fout.write(crypto.MAGIC + bytes([crypto.LEGACY_VERSION]))
        fout.write(crypto.BLOCK_SIZE.to_bytes(4, "big"))
        fout.write(count.to_bytes(4, "big"))
        for index in range(count):
            block = fin.read(crypto.BLOCK_SIZE)
            nonce = os.urandom(crypto.NONCE_SIZE)
            fout.write(nonce)
            fout.write(aes.encrypt(nonce, block, crypto._v1_file_aad(index)))


def write_v1_index(path, entries):
    nonce = os.urandom(crypto.NONCE_SIZE)
    data = json.dumps({"magic": "SVLT", "version": 1, "entries": entries}).encode()
    ciphertext = AESGCM(KEY).encrypt(nonce, data, crypto._index_v1_aad())
    with open(path, "wb") as stream:
        stream.write(crypto.MAGIC + b"\x01" + nonce + ciphertext)


class CryptoTests(unittest.TestCase):
    def test_kdf_vector_and_parameters_are_frozen(self):
        key = crypto.derive_master_key("secure-vault-test-password")
        self.assertEqual(key.hex(), "737d703b7454ea13eb5f9de1972bf9e6d154001e0415c1a04526a8490adeab06")
        with self.assertRaises(ValueError):
            crypto.derive_master_key("secure-vault-test-password", iterations=1)

    def test_file_roundtrip_and_wrong_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, enc, dec = (os.path.join(tmp, name) for name in ("src", "enc", "dec"))
            data = os.urandom(3 * 1024 * 1024 + 7)
            with open(src, "wb") as stream:
                stream.write(data)
            file_id, digest = crypto.encrypt_file(KEY, src, enc)
            crypto.decrypt_file(KEY, enc, dec, expected_file_id=file_id, expected_sha256=digest)
            with open(dec, "rb") as stream:
                self.assertEqual(stream.read(), data)
            os.remove(dec)
            with self.assertRaises(ValueError):
                crypto.decrypt_file(crypto.derive_master_key("wrong-password"), enc, dec)

    def test_authenticated_header_and_ciphertext_tamper(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, enc, out = (os.path.join(tmp, name) for name in ("src", "enc", "out"))
            with open(src, "wb") as stream:
                stream.write(os.urandom(1024))
            crypto.encrypt_file(KEY, src, enc)
            with open(enc, "r+b") as stream:
                stream.seek(9)
                stream.write((0).to_bytes(8, "big"))
            with self.assertRaises(ValueError):
                crypto.decrypt_file(KEY, enc, out)
            self.assertFalse(os.path.exists(out))

            os.remove(enc)
            crypto.encrypt_file(KEY, src, enc)
            with open(enc, "r+b") as stream:
                stream.seek(crypto.FILE_HEADER_V2_SIZE + crypto.NONCE_SIZE + 3)
                value = stream.read(1)
                stream.seek(-1, os.SEEK_CUR)
                stream.write(bytes([value[0] ^ 1]))
            with self.assertRaises(ValueError):
                crypto.decrypt_file(KEY, enc, out)

    def test_empty_file_is_authenticated(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, enc, out = (os.path.join(tmp, name) for name in ("src", "enc", "out"))
            open(src, "wb").close()
            crypto.encrypt_file(KEY, src, enc)
            with open(enc, "ab") as stream:
                stream.write(b"trailing")
            with self.assertRaises(ValueError):
                crypto.decrypt_file(KEY, enc, out)

    def test_folder_roundtrip_and_nested_encrypted_structure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "照片")
            make_tree(root)
            self.assertEqual(crypto.encrypt_folder(KEY, root), 5)
            with open(os.path.join(root, crypto.INDEX_FILENAME), "rb") as stream:
                self.assertEqual(stream.read(5), crypto.MAGIC + bytes([crypto.VERSION]))
            entries = crypto.read_index(KEY, os.path.join(root, crypto.INDEX_FILENAME))
            travel = next(entry for entry in entries if entry["orig"] == "2024/旅行")
            year = next(entry for entry in entries if entry["orig"] == "2024")
            self.assertEqual(os.path.dirname(travel["enc"]).replace("\\", "/"), year["enc"])
            self.assertEqual(crypto.decrypt_folder(KEY, root), 5)
            with open(os.path.join(root, "2024", "全家福.jpg"), "rb") as stream:
                self.assertEqual(stream.read(), "hello 全家福".encode() * 100)
            self.assertTrue(os.path.isdir(os.path.join(root, "空目录")))
            self.assertFalse(os.path.exists(os.path.join(root, crypto.INDEX_FILENAME)))

    def test_ciphertext_swap_is_rejected_without_touching_vault(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "vault")
            os.makedirs(root)
            for name, value in (("a.txt", b"A" * 32), ("b.txt", b"B" * 32)):
                with open(os.path.join(root, name), "wb") as stream:
                    stream.write(value)
            crypto.encrypt_folder(KEY, root)
            entries = crypto.read_index(KEY, os.path.join(root, crypto.INDEX_FILENAME))
            paths = {e["orig"]: crypto._disk_path(root, e["enc"]) for e in entries if e["type"] == "file"}
            swap = os.path.join(tmp, "swap")
            os.replace(paths["a.txt"], swap)
            os.replace(paths["b.txt"], paths["a.txt"])
            os.replace(swap, paths["b.txt"])
            with self.assertRaises(ValueError):
                crypto.decrypt_folder(KEY, root)
            self.assertTrue(os.path.isfile(os.path.join(root, crypto.INDEX_FILENAME)))
            self.assertFalse(os.path.exists(os.path.join(root, "a.txt")))

    def test_malicious_authenticated_index_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            index = os.path.join(tmp, crypto.INDEX_FILENAME)
            write_raw_v2_index(index, [{
                "type": "file", "orig": "../../outside", "enc": uuid.uuid4().hex,
                "file_id": uuid.uuid4().hex, "sha256": "0" * 64, "size": 1, "mtime": 0,
            }])
            with self.assertRaisesRegex(ValueError, "非法路径"):
                crypto.read_index(KEY, index)

    def test_commit_second_rename_failure_rolls_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "source")
            os.makedirs(root)
            with open(os.path.join(root, "x.txt"), "wb") as stream:
                stream.write(b"original")
            real_rename = os.rename
            calls = {"count": 0}

            def fail_second(src, dst):
                calls["count"] += 1
                if calls["count"] == 2:
                    raise OSError("simulated commit failure")
                return real_rename(src, dst)

            with patch("crypto.os.rename", side_effect=fail_second):
                with self.assertRaises(OSError):
                    crypto.encrypt_folder(KEY, root)
            with open(os.path.join(root, "x.txt"), "rb") as stream:
                self.assertEqual(stream.read(), b"original")
            self.assertFalse(any(name.startswith(".svault-backup-") for name in os.listdir(tmp)))
            self.assertFalse(any(name.startswith(".svault-txn-") for name in os.listdir(tmp)))

    def test_authenticated_recovery_cleans_committed_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "source")
            os.makedirs(root)
            with open(os.path.join(root, "x.txt"), "wb") as stream:
                stream.write(b"original")
            real_rmtree = shutil.rmtree

            def fail_backup_cleanup(path, *args, **kwargs):
                if os.path.basename(path).startswith(".svault-backup-"):
                    raise OSError("simulated cleanup failure")
                return real_rmtree(path, *args, **kwargs)

            with patch("crypto.shutil.rmtree", side_effect=fail_backup_cleanup):
                with self.assertRaises(OSError):
                    crypto.encrypt_folder(KEY, root)
            self.assertTrue(os.path.isfile(os.path.join(root, crypto.INDEX_FILENAME)))
            self.assertTrue(any(name.startswith(".svault-backup-") for name in os.listdir(tmp)))
            self.assertEqual(crypto.recover_transactions(tmp, KEY), [os.path.realpath(root)])
            self.assertFalse(any(name.startswith(".svault-backup-") for name in os.listdir(tmp)))
            self.assertFalse(any(name.startswith(".svault-txn-") for name in os.listdir(tmp)))

    def test_tree_paths_are_platform_independent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "tree")
            make_tree(root)
            crypto.encrypt_folder(KEY, root)
            nodes = crypto.list_directory(KEY, root)
            year = next(node for node in nodes if node["name"] == "2024")
            self.assertIn("旅行", {child["name"] for child in year["children"]})
            self.assertIn("全家福.jpg", {child["name"] for child in year["children"]})

    def test_symlink_is_rejected_instead_of_silently_deleted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "tree")
            outside = os.path.join(tmp, "outside")
            os.makedirs(root)
            with open(outside, "wb") as stream:
                stream.write(b"outside")
            link = os.path.join(root, "link")
            try:
                os.symlink(outside, link)
            except OSError as exc:
                self.skipTest(f"symlink unavailable: {exc}")
            with self.assertRaisesRegex(ValueError, "符号链接"):
                crypto.encrypt_folder(KEY, root)
            self.assertTrue(os.path.lexists(link))

    def test_legacy_v1_vault_can_be_decrypted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "legacy")
            os.makedirs(root)
            plain = os.path.join(tmp, "plain")
            with open(plain, "wb") as stream:
                stream.write(b"legacy-data")
            enc_name = uuid.uuid4().hex
            write_v1_file(plain, os.path.join(root, enc_name))
            write_v1_index(os.path.join(root, crypto.INDEX_FILENAME), [{
                "type": "file", "orig": "old.txt", "enc": enc_name,
                "size": 11, "mtime": 0,
            }])
            crypto.decrypt_folder(KEY, root)
            with open(os.path.join(root, "old.txt"), "rb") as stream:
                self.assertEqual(stream.read(), b"legacy-data")


if __name__ == "__main__":
    unittest.main(verbosity=2)
