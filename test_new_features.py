import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto import Vault, decrypt_chunks, decrypt_full

PWD = "unit-test-password-123"

def main():
    tmp = tempfile.mkdtemp(prefix="svtest-")
    v = Vault(tmp)
    assert not v.exists
    v.initialize(PWD)
    mk = v.unlock(PWD)
    assert mk is not None

    # 1) 多层级目录
    a = v.create_folder(mk, "A")
    b = v.create_folder(mk, "B", a)
    c = v.create_folder(mk, "C", b)
    assert v.folder_subtree_ids(mk, a) == [a, b, c], v.folder_subtree_ids(mk, a)

    # 2) ensure_folder_path（导入时镜像目录结构）
    leaf = v.ensure_folder_path(mk, ["照片", "2024", "旅行"], a)
    folders = v.list_folders(mk)
    byname = {f["name"]: f for f in folders}
    assert byname["旅行"]["parent_id"] == byname["2024"]["id"]
    assert byname["2024"]["parent_id"] == byname["照片"]["id"]
    assert byname["照片"]["parent_id"] == a

    # 3) 导入式加密：把明文文件加密进保险箱，再解密对比
    plain = os.urandom(2 * 1024 * 1024 + 12345)  # ~2MB，跨块
    src = os.path.join(tmp, "plain.bin")
    with open(src, "wb") as f:
        f.write(plain)
    fid = v.add_file(mk, src, "photo.bin", "application/octet-stream", leaf)

    # 3a) decrypt_chunks 流式解密 == decrypt_full == 原文
    path = v.get_file_path(fid)
    chunks = b"".join(decrypt_chunks(mk, fid, path))
    assert chunks == plain, "streaming decrypt mismatch"
    assert decrypt_full(mk, fid, path) == plain

    # 4) list_all_files 含 folder_id
    allf = v.list_all_files(mk)
    rec = [f for f in allf if f["id"] == fid][0]
    assert rec["folder_id"] == leaf, rec["folder_id"]
    assert rec["name"] == "photo.bin"

    # 5) 复制文件到新目录（批量复制底层）
    new_id = v.copy_file(mk, fid, c)
    assert new_id and v.get_record(new_id) is not None
    assert b"".join(decrypt_chunks(mk, new_id, v.get_file_path(new_id))) == plain

    # 6) 复制文件夹递归（含文件）
    copied = v.copy_folder(mk, a, "")  # 复制 A 整棵树到根
    assert copied is not None
    sub_ids = v.folder_subtree_ids(mk, copied)
    assert len(sub_ids) == 6, len(sub_ids)  # A/B/C + 照片/2024/旅行
    # 复制的树里应包含 2 个文件：旅行下的 photo.bin 副本 + C 下的 copy_file 副本
    allf2 = v.list_all_files(mk)
    assert len([f for f in allf2 if f["folder_id"] in sub_ids]) == 2

    # 7) 移动文件夹防循环
    assert v.move_folder(mk, a, c) is False  # A 移到自己的子孙 C
    assert v.move_folder(mk, b, "") is True  # B 移到根 OK

    print("ALL UNIT TESTS PASSED")
    shutil.rmtree(tmp)

if __name__ == "__main__":
    main()
