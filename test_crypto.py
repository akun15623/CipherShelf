import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import crypto
from crypto import (
    derive_master_key, encrypt_file, decrypt_file,
    write_index, read_index, encrypt_folder, decrypt_folder,
    list_directory, _build_tree_from_index,
)

PWD = "test-password-123"
KEY = derive_master_key(PWD)


def _mktree(base):
    """造一个带中文名、空目录、深层嵌套、空文件的测试目录树。"""
    os.makedirs(os.path.join(base, "2024"), exist_ok=True)
    os.makedirs(os.path.join(base, "2024", "旅行"), exist_ok=True)
    os.makedirs(os.path.join(base, "2025"), exist_ok=True)
    os.makedirs(os.path.join(base, "空目录"), exist_ok=True)
    with open(os.path.join(base, "2024", "旅行", "照片.jpg"), "wb") as f:
        f.write(os.urandom(10000))
    with open(os.path.join(base, "2024", "全家福.jpg"), "wb") as f:
        f.write("hello 全家福".encode("utf-8") * 100)
    with open(os.path.join(base, "2025", "视频.bin"), "wb") as f:
        f.write(os.urandom(2 * 1024 * 1024 + 12345))  # 跨块
    with open(os.path.join(base, "空文件.txt"), "wb") as f:
        f.write(b"")  # 空文件
    with open(os.path.join(base, "根文件.txt"), "wb") as f:
        f.write("根目录文件".encode("utf-8"))


def test_roundtrip_file():
    tmp = tempfile.mkdtemp()
    src = os.path.join(tmp, "src.bin")
    enc = os.path.join(tmp, "src.enc")
    dec = os.path.join(tmp, "src.dec")
    data = os.urandom(3 * 1024 * 1024 + 7)
    with open(src, "wb") as f:
        f.write(data)
    encrypt_file(KEY, src, enc)
    decrypt_file(KEY, enc, dec)
    with open(dec, "rb") as f:
        assert f.read() == data
    shutil.rmtree(tmp)
    print("✓ 文件加解密回环（含跨块大文件）")


def test_wrong_password():
    tmp = tempfile.mkdtemp()
    src = os.path.join(tmp, "a.bin")
    enc = os.path.join(tmp, "a.enc")
    with open(src, "wb") as f:
        f.write(b"secret")
    encrypt_file(KEY, src, enc)
    wrong = derive_master_key("wrong-password")
    try:
        decrypt_file(wrong, enc, os.path.join(tmp, "dec"))
        raise AssertionError("错误密码应抛异常")
    except Exception:
        pass
    shutil.rmtree(tmp)
    print("✓ 错误密码解密被拒")


def test_tamper_detection():
    tmp = tempfile.mkdtemp()
    src = os.path.join(tmp, "a.bin")
    enc = os.path.join(tmp, "a.enc")
    data = os.urandom(1024 * 1024 + 100)
    with open(src, "wb") as f:
        f.write(data)
    encrypt_file(KEY, src, enc)
    # 翻转密文第 20 字节（在数据块内）
    with open(enc, "r+b") as f:
        f.seek(20)
        b = f.read(1)
        f.seek(20)
        f.write(bytes([b[0] ^ 0x01]))
    try:
        decrypt_file(KEY, enc, os.path.join(tmp, "dec"))
        raise AssertionError("篡改应抛认证失败")
    except Exception:
        pass
    shutil.rmtree(tmp)
    print("✓ 篡改检测（翻转 1 bit 报错）")


def test_folder_roundtrip():
    tmp = tempfile.mkdtemp()
    src_dir = os.path.join(tmp, "照片")
    _mktree(src_dir)

    # 加密
    n = encrypt_folder(KEY, src_dir)
    assert n == 5, f"应加密 5 个文件，实际 {n}"

    # 加密后：.svault 存在，无明文文件，密文是乱码名
    assert os.path.isfile(os.path.join(src_dir, ".svault"))
    for root, _dirs, files in os.walk(src_dir):
        for fn in files:
            if fn == ".svault":
                continue
            # 密文文件名应为 32 位 hex，且无 .jpg/.txt 扩展名
            assert len(fn) == 32, f"密文名长度异常：{fn}"
            assert "." not in fn, f"密文名不应有扩展名：{fn}"
    # 明文已删
    assert not os.path.exists(os.path.join(src_dir, "2024", "旅行", "照片.jpg"))

    # 解密（原地）
    n2 = decrypt_folder(KEY, src_dir)
    assert n2 == 5

    # 解密后还原
    assert os.path.exists(os.path.join(src_dir, "2024", "旅行", "照片.jpg"))
    assert os.path.exists(os.path.join(src_dir, "2024", "全家福.jpg"))
    assert os.path.exists(os.path.join(src_dir, "2025", "视频.bin"))
    assert os.path.exists(os.path.join(src_dir, "空目录"))
    assert os.path.exists(os.path.join(src_dir, "空文件.txt"))
    with open(os.path.join(src_dir, "根文件.txt"), "rb") as f:
        assert f.read() == "根目录文件".encode("utf-8")
    # 内容无损
    with open(os.path.join(src_dir, "2024", "全家福.jpg"), "rb") as f:
        assert f.read() == "hello 全家福".encode("utf-8") * 100
    # 索引已删
    assert not os.path.exists(os.path.join(src_dir, ".svault"))

    shutil.rmtree(tmp)
    print("✓ 文件夹加解密回环（中文名/空目录/空文件/深层嵌套/跨块大文件）")


def test_folder_wrong_password():
    tmp = tempfile.mkdtemp()
    src_dir = os.path.join(tmp, "d")
    _mktree(src_dir)
    encrypt_folder(KEY, src_dir)
    try:
        decrypt_folder(derive_master_key("bad"), src_dir)
        raise AssertionError("错误密码应抛异常")
    except ValueError:
        pass
    # 密文应仍在（未被破坏）
    assert os.path.isfile(os.path.join(src_dir, ".svault"))
    shutil.rmtree(tmp)
    print("✓ 文件夹错误密码被拒（索引 GCM 校验）")


def test_path_traversal():
    # 构造含 ../ 的恶意索引
    tmp = tempfile.mkdtemp()
    d = os.path.join(tmp, "evil")
    os.makedirs(d)
    write_index(KEY, os.path.join(d, ".svault"), [
        {"type": "file", "orig": "../../etc/passwd", "enc": "abc", "size": 1, "mtime": 0},
    ])
    try:
        decrypt_folder(KEY, d)
        raise AssertionError("路径穿越应被拒")
    except ValueError as e:
        assert "非法路径" in str(e)
    shutil.rmtree(tmp)
    print("✓ 路径穿越（../ 恶意索引）被拒")


def test_list_directory():
    tmp = tempfile.mkdtemp()
    src_dir = os.path.join(tmp, "照片")
    _mktree(src_dir)

    # 加密前：list 返回真实名
    nodes = list_directory(KEY, src_dir, "")
    names = {n["name"] for n in nodes}
    assert "2024" in names and "2025" in names and "空目录" in names
    assert all(not n["encrypted"] for n in nodes)

    # 加密后：list 返回原名 + encrypted=true，且结构保留
    encrypt_folder(KEY, src_dir)
    nodes = list_directory(KEY, src_dir, "")
    names = {n["name"] for n in nodes}
    assert "2024" in names and "2025" in names and "空目录" in names
    assert all(n["encrypted"] for n in nodes)
    # 2024 的 children 应含 旅行 和 全家福.jpg
    y2024 = next(n for n in nodes if n["name"] == "2024")
    child_names = {c["name"] for c in y2024["children"]}
    assert "旅行" in child_names and "全家福.jpg" in child_names

    shutil.rmtree(tmp)
    print("✓ 目录树（加密前真实名 / 加密后原名+encrypted）")


def test_same_password_same_key():
    k1 = derive_master_key("abc12345")
    k2 = derive_master_key("abc12345")
    k3 = derive_master_key("abc12346")
    assert k1 == k2
    assert k1 != k3
    print("✓ 单密钥：同密码同密钥，不同密码不同密钥")


def test_kdf_vector():
    # DESIGN.md §3.3 冻结的公开测试向量：salt/iterations 被误改立即失败
    k = derive_master_key("secure-vault-test-password")
    assert k.hex() == "737d703b7454ea13eb5f9de1972bf9e6d154001e0415c1a04526a8490adeab06", \
        f"KDF 测试向量不匹配：{k.hex()}"
    print("✓ KDF 固定测试向量（salt/iterations 冻结）")


def test_initialized():
    tmp = tempfile.mkdtemp()
    assert not crypto.is_initialized(tmp)
    assert crypto.find_encrypted_roots(tmp) == []
    src = os.path.join(tmp, "d")
    _mktree(src)
    assert not crypto.is_initialized(tmp)  # 有目录但未加密
    encrypt_folder(KEY, src)
    assert crypto.is_initialized(tmp)
    roots = crypto.find_encrypted_roots(tmp)
    assert len(roots) == 1 and roots[0].endswith(".svault")
    shutil.rmtree(tmp)
    print("✓ 初始化状态与加密根发现")


if __name__ == "__main__":
    test_kdf_vector()
    test_same_password_same_key()
    test_initialized()
    test_roundtrip_file()
    test_wrong_password()
    test_tamper_detection()
    test_folder_roundtrip()
    test_folder_wrong_password()
    test_path_traversal()
    test_list_directory()
    print("\nALL TESTS PASSED")
