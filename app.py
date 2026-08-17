"""
secure-vault Web 服务（FastAPI）

安全要点：
- 密码只用于派生密钥，永不落盘、永不进日志。
- master_key 只存在内存会话里；锁定即清除。
- 上传/下载/缩略图全部走加密层，磁盘无明文。
- 支持 HTTP Range，视频/音频可拖进度条。
"""

from __future__ import annotations

import io
import os
import secrets
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, Depends, HTTPException, Request, UploadFile, File, Header, Cookie
from fastapi.responses import Response, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from crypto import Vault, plaintext_size, decrypt_range, decrypt_name, decrypt_chunks

DATA_DIR = os.environ.get("VAULT_DATA_DIR", "/data")
IMPORT_DIR = os.environ.get("VAULT_IMPORT_DIR", "/import")
AUTO_LOCK_SECONDS = int(os.environ.get("AUTO_LOCK_SECONDS", "1800"))  # 30 分钟无操作自动锁定
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "4096"))

vault = Vault(DATA_DIR)
app = FastAPI(title="Secure Vault", docs_url=None, redoc_url=None, openapi_url=None)

# 内存会话：token -> {"key": master_key, "last_active": ts}
_sessions: dict[str, dict] = {}
COOKIE_NAME = "vault_token"


# ---------------------------------------------------------------------------
# 会话辅助
# ---------------------------------------------------------------------------
def _get_key(vault_token: str | None = Cookie(default=None),
             authorization: str | None = Header(default=None)) -> bytes:
    token = vault_token or ""
    if not token and authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
    sess = _sessions.get(token)
    if not sess:
        raise HTTPException(status_code=401, detail="未解锁或会话已过期")
    # 自动锁定检查
    if AUTO_LOCK_SECONDS > 0 and (time.time() - sess["last_active"]) > AUTO_LOCK_SECONDS:
        _sessions.pop(token, None)
        raise HTTPException(status_code=401, detail="会话已自动锁定")
    sess["last_active"] = time.time()
    return sess["key"]


@app.exception_handler(Exception)
async def _unhandled(request: Request, exc: Exception):
    # 不把内部错误细节（可能含路径/密钥信息）泄露给客户端
    return JSONResponse(status_code=500, content={"detail": "服务器内部错误"})


# ---------------------------------------------------------------------------
# 静态资源（前端）
# ---------------------------------------------------------------------------
_static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")


@app.get("/")
async def index():
    return Response(content=(_static_dir / "index.html").read_bytes(), media_type="text/html")


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
@app.get("/api/status")
async def status():
    return {"initialized": vault.exists}


@app.post("/api/init")
async def init(body: dict):
    password = body.get("password", "")
    if not password:
        raise HTTPException(status_code=400, detail="密码不能为空")
    if vault.exists:
        raise HTTPException(status_code=409, detail="保险库已初始化")
    vault.initialize(password)
    return {"ok": True}


@app.post("/api/unlock")
async def unlock(body: dict, response: Response):
    password = body.get("password", "")
    if not password:
        raise HTTPException(status_code=400, detail="密码不能为空")
    key = vault.unlock(password)
    if key is None:
        raise HTTPException(status_code=401, detail="密码错误")
    token = secrets.token_urlsafe(32)
    _sessions[token] = {"key": key, "last_active": time.time()}
    response.set_cookie(
        COOKIE_NAME, token,
        httponly=True, samesite="strict",
        max_age=None,  # 会话 cookie，浏览器关闭即失效
    )
    return {"ok": True, "auto_lock_seconds": AUTO_LOCK_SECONDS}


@app.post("/api/lock")
async def lock(vault_token: str | None = Cookie(default=None), response: Response = None):
    if vault_token:
        _sessions.pop(vault_token, None)
    if response is not None:
        response.delete_cookie(COOKIE_NAME)
    return {"ok": True}


@app.get("/api/files")
async def list_files(folder_id: str = "", key: bytes = Depends(_get_key)):
    files = vault.list_files(key, folder_id)
    return {"files": files}


@app.get("/api/folders")
async def list_folders(key: bytes = Depends(_get_key)):
    return {"folders": vault.list_folders(key)}


@app.post("/api/folders")
async def create_folder(body: dict, key: bytes = Depends(_get_key)):
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="文件夹名不能为空")
    if len(name) > 64:
        raise HTTPException(status_code=400, detail="文件夹名过长")
    parent_id = body.get("parent_id") or ""
    folder_id = vault.create_folder(key, name, parent_id)
    return {"id": folder_id, "name": name}


@app.patch("/api/folders/{folder_id}")
async def rename_folder(folder_id: str, body: dict, key: bytes = Depends(_get_key)):
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="文件夹名不能为空")
    if not vault.rename_folder(key, folder_id, name):
        raise HTTPException(status_code=404, detail="文件夹不存在")
    return {"ok": True}


@app.delete("/api/folders/{folder_id}")
async def delete_folder(folder_id: str, key: bytes = Depends(_get_key)):
    if not vault.delete_folder_for_user(key, folder_id):
        raise HTTPException(status_code=404, detail="文件夹不存在")
    return {"ok": True}


@app.patch("/api/folders/{folder_id}/move")
async def move_folder(folder_id: str, body: dict, key: bytes = Depends(_get_key)):
    new_parent_id = body.get("parent_id") or ""
    if not vault.move_folder(key, folder_id, new_parent_id):
        raise HTTPException(status_code=400, detail="无法移动（目标不能是自己或自己的子目录）")
    return {"ok": True}


@app.post("/api/folders/{folder_id}/copy")
async def copy_folder(folder_id: str, body: dict, key: bytes = Depends(_get_key)):
    dst_parent_id = body.get("parent_id") or ""
    new_id = vault.copy_folder(key, folder_id, dst_parent_id)
    if new_id is None:
        raise HTTPException(status_code=404, detail="文件夹不存在")
    return {"id": new_id}


@app.patch("/api/file/{file_id}/move")
async def move_file(file_id: str, body: dict, key: bytes = Depends(_get_key)):
    folder_id = body.get("folder_id") or ""
    if not vault.move_file(key, file_id, folder_id):
        raise HTTPException(status_code=404, detail="文件不存在")
    return {"ok": True}


@app.post("/api/file/{file_id}/copy")
async def copy_file(file_id: str, body: dict, key: bytes = Depends(_get_key)):
    folder_id = body.get("folder_id") or ""
    new_id = vault.copy_file(key, file_id, folder_id)
    if new_id is None:
        raise HTTPException(status_code=404, detail="文件不存在")
    return {"id": new_id}


@app.post("/api/upload")
async def upload(
    file: UploadFile = File(...),
    folder_id: str = "",
    key: bytes = Depends(_get_key),
):
    if not file.filename:
        raise HTTPException(status_code=400, detail="缺少文件名")
    tmp_dir = os.path.join(DATA_DIR, "tmp")
    os.makedirs(tmp_dir, exist_ok=True)
    tmp_path = os.path.join(tmp_dir, uuid.uuid4().hex)
    size = 0
    max_bytes = MAX_UPLOAD_MB * 1024 * 1024
    try:
        with open(tmp_path, "wb") as f:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise HTTPException(status_code=413, detail=f"文件超过 {MAX_UPLOAD_MB}MB 上限")
                f.write(chunk)
        mime = file.content_type or ""
        if not mime or mime in ("application/octet-stream", "text/plain"):
            mime = _guess_mime(file.filename)
        file_id = vault.add_file(key, tmp_path, file.filename, mime, folder_id)
        if mime and mime.startswith("image/"):
            try:
                _make_thumbnail(key, file_id)
            except Exception:
                pass
        return {"id": file_id, "size": size}
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


def _guess_mime(name: str) -> str:
    import mimetypes
    return mimetypes.guess_type(name)[0] or "application/octet-stream"


def _make_thumbnail(key: bytes, file_id: str) -> None:
    from PIL import Image
    rec = vault.get_record(file_id)
    if not rec:
        return
    path = vault.get_file_path(file_id)
    # 只对不太大的图片做缩略图，避免解巨型图
    if rec["size"] > 50 * 1024 * 1024:
        return
    raw = decrypt_range(key, file_id, path, 0, rec["size"])
    img = Image.open(io.BytesIO(raw))
    img = img.convert("RGB")
    img.thumbnail((512, 512))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=80)
    vault.save_thumb(key, file_id, buf.getvalue())


@app.get("/api/file/{file_id}")
async def get_file(file_id: str, request: Request, key: bytes = Depends(_get_key)):
    rec = vault.get_record(file_id)
    if not rec:
        raise HTTPException(status_code=404, detail="文件不存在")
    path = vault.get_file_path(file_id)
    total = rec["size"]
    mime = _decrypt_mime(key, rec)

    range_header = request.headers.get("range")
    if range_header:
        start, end = _parse_range(range_header, total)
        if start is None:
            return Response(status_code=416, headers={"Content-Range": f"bytes */{total}"})
        length = end - start + 1
        data = decrypt_range(key, file_id, path, start, length)
        headers = {
            "Content-Range": f"bytes {start}-{end}/{total}",
            "Accept-Ranges": "bytes",
            "Content-Length": str(len(data)),
            "Content-Type": mime,
        }
        return Response(content=data, status_code=206, headers=headers)

    # 无 Range：整体返回（小文件/图片）
    data = decrypt_range(key, file_id, path, 0, total)
    return Response(
        content=data,
        media_type=mime,
        headers={"Accept-Ranges": "bytes", "Content-Length": str(len(data))},
    )


@app.get("/api/file/{file_id}/thumb")
async def get_thumb(file_id: str, key: bytes = Depends(_get_key)):
    rec = vault.get_record(file_id)
    if not rec:
        raise HTTPException(status_code=404, detail="文件不存在")
    if not vault.has_thumb(file_id):
        # 尝试现场生成
        try:
            _make_thumbnail(key, file_id)
        except Exception:
            raise HTTPException(status_code=404, detail="无缩略图")
        if not vault.has_thumb(file_id):
            raise HTTPException(status_code=404, detail="无缩略图")
    data = vault.read_thumb(key, file_id)
    return Response(content=data, media_type="image/jpeg",
                    headers={"Cache-Control": "private, max-age=3600"})


@app.delete("/api/file/{file_id}")
async def delete_file(file_id: str, key: bytes = Depends(_get_key)):
    ok = vault.delete_file(file_id)
    if not ok:
        raise HTTPException(status_code=404, detail="文件不存在")
    return {"ok": True}


def _decrypt_mime(key: bytes, rec: dict) -> str:
    from crypto import decrypt_name
    return decrypt_name(key, rec["id"], rec["mime_enc"])


def _parse_range(range_header: str, total: int):
    """解析 'bytes=start-end'，返回 (start, end) 或 (None, None)。"""
    try:
        unit, _, spec = range_header.strip().partition("=")
        if unit != "bytes":
            return None, None
        spec = spec.strip()
        if spec.startswith("-"):
            # 后缀范围：最后 N 字节
            n = int(spec[1:])
            if n <= 0:
                return None, None
            start = max(0, total - n)
            end = total - 1
        else:
            start_s, _, end_s = spec.partition("-")
            start = int(start_s)
            end = int(end_s) if end_s else total - 1
            if start >= total or start > end:
                return None, None
            end = min(end, total - 1)
        return start, end
    except (ValueError, AttributeError):
        return None, None


# ---------------------------------------------------------------------------
# 导入（把已有明文文件加密进保险箱）
# ---------------------------------------------------------------------------
def _import_items() -> list[dict]:
    """递归列出导入目录下所有文件（含相对路径）。"""
    if not os.path.isdir(IMPORT_DIR):
        return []
    items = []
    for root, _dirs, files in os.walk(IMPORT_DIR):
        for fn in files:
            full = os.path.join(root, fn)
            try:
                st = os.stat(full)
            except OSError:
                continue
            rel = os.path.relpath(full, IMPORT_DIR).replace(os.sep, "/")
            items.append({"rel": rel, "name": fn, "size": st.st_size, "mtime": int(st.st_mtime)})
    items.sort(key=lambda x: x["rel"])
    return items


@app.get("/api/import/list")
async def import_list(key: bytes = Depends(_get_key)):
    return {"root": IMPORT_DIR, "available": os.path.isdir(IMPORT_DIR), "items": _import_items()}


@app.post("/api/import")
async def import_files(body: dict, key: bytes = Depends(_get_key)):
    paths = body.get("paths") or []
    folder_id = body.get("folder_id") or ""
    delete_source = bool(body.get("delete_source"))
    if not os.path.isdir(IMPORT_DIR):
        raise HTTPException(status_code=400, detail="导入目录不可用（未挂载 VAULT_IMPORT_DIR）")
    if not paths:
        raise HTTPException(status_code=400, detail="未选择要导入的文件")
    base = os.path.realpath(IMPORT_DIR)
    ok = fail = 0
    for rel in paths:
        rel = (rel or "").replace("\\", "/").lstrip("/")
        src = os.path.realpath(os.path.join(IMPORT_DIR, rel))
        # 安全：必须仍位于导入目录内，防止路径穿越
        if not (src == base or src.startswith(base + os.sep)) or not os.path.isfile(src):
            fail += 1
            continue
        try:
            parts = [p for p in rel.split("/")[:-1] if p not in ("", ".", "..")]
            target = vault.ensure_folder_path(key, parts, folder_id) if parts else folder_id
            mime = _guess_mime(rel)
            fid = vault.add_file(key, src, os.path.basename(rel), mime, target)
            if mime.startswith("image/"):
                try:
                    _make_thumbnail(key, fid)
                except Exception:
                    pass
            if delete_source:
                try:
                    os.remove(src)
                except OSError:
                    pass
            ok += 1
        except Exception:
            fail += 1
    return {"ok": ok, "fail": fail}


# ---------------------------------------------------------------------------
# 批量操作
# ---------------------------------------------------------------------------
@app.post("/api/batch/delete")
async def batch_delete(body: dict, key: bytes = Depends(_get_key)):
    ids = body.get("ids") or []
    folder_ids = body.get("folders") or []
    removed_files = removed_folders = 0
    for fid in ids:
        if vault.delete_file(fid):
            removed_files += 1
    for foid in folder_ids:
        if vault.delete_folder_for_user(key, foid):
            removed_folders += 1
    return {"files": removed_files, "folders": removed_folders}


@app.post("/api/batch/move")
async def batch_move(body: dict, key: bytes = Depends(_get_key)):
    ids = body.get("ids") or []
    folder_ids = body.get("folders") or []
    target = body.get("target") or ""
    moved = 0
    for fid in ids:
        if vault.move_file(key, fid, target):
            moved += 1
    for foid in folder_ids:
        if vault.move_folder(key, foid, target):
            moved += 1
    return {"moved": moved}


@app.post("/api/batch/copy")
async def batch_copy(body: dict, key: bytes = Depends(_get_key)):
    ids = body.get("ids") or []
    folder_ids = body.get("folders") or []
    target = body.get("target") or ""
    copied = 0
    for fid in ids:
        if vault.copy_file(key, fid, target):
            copied += 1
    for foid in folder_ids:
        if vault.copy_folder(key, foid, target):
            copied += 1
    return {"copied": copied}


def _sanitize_arcname(name: str) -> str:
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".", "..")]
    return "/".join(parts) or "file"


@app.get("/api/batch/download")
async def batch_download(files: str = "", folders: str = "", key: bytes = Depends(_get_key)):
    import zipfile
    file_ids = [x for x in files.split(",") if x]
    folder_ids = [x for x in folders.split(",") if x]

    # 建立 文件夹 id -> 路径 映射
    fl = vault.list_folders(key)
    path_of: dict[str, str] = {}

    def fpath(fid: str) -> str:
        if fid in path_of:
            return path_of[fid]
        f = next((x for x in fl if x["id"] == fid), None)
        if not f:
            return ""
        if f["parent_id"]:
            p = fpath(f["parent_id"])
            path_of[fid] = (p + "/" + f["name"]) if p else f["name"]
        else:
            path_of[fid] = f["name"]
        return path_of[fid]

    entries: list[tuple[str, str]] = []  # (arcname, file_id)
    for fid in file_ids:
        rec = vault.get_record(fid)
        if not rec:
            continue
        entries.append((decrypt_name(key, fid, rec["name_enc"]), fid))

    if folder_ids:
        all_files = vault.list_all_files(key)
        for foid in folder_ids:
            prefix = fpath(foid)
            subtree = set(vault.folder_subtree_ids(key, foid))
            for f in all_files:
                if f["folder_id"] in subtree:
                    rel = ""
                    if f["folder_id"] != foid:
                        fp = fpath(f["folder_id"])
                        if fp.startswith(prefix):
                            rel = fp[len(prefix):].lstrip("/")
                        else:
                            rel = fp
                    arc = f"{prefix}/{rel}/{f['name']}" if rel else f"{prefix}/{f['name']}"
                    entries.append((arc, f["id"]))

    if not entries:
        raise HTTPException(status_code=404, detail="没有可下载的文件")

    tmp_dir = os.path.join(DATA_DIR, "tmp")
    os.makedirs(tmp_dir, exist_ok=True)
    tmp = os.path.join(tmp_dir, "dl-" + uuid.uuid4().hex + ".zip")
    seen: set[str] = set()
    try:
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_STORED) as zf:
            for arc, fid in entries:
                arc = _sanitize_arcname(arc)
                base, i = arc, 1
                while arc in seen:
                    stem, ext = os.path.splitext(base)
                    arc = f"{stem} ({i}){ext}"
                    i += 1
                seen.add(arc)
                path = vault.get_file_path(fid)
                with zf.open(arc, "w", force_zip64=True) as dest:
                    for chunk in decrypt_chunks(key, fid, path):
                        dest.write(chunk)
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise

    def iter_file():
        with open(tmp, "rb") as f:
            while True:
                b = f.read(1024 * 1024)
                if not b:
                    break
                yield b
        try:
            os.remove(tmp)
        except OSError:
            pass

    return StreamingResponse(
        iter_file(),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="vault-export.zip"'},
    )
