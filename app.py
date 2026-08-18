"""
secure-vault Web 服务（FastAPI，v2：文件夹就地加解密工具）

- 进入输密码 -> 派生主密钥存内存会话（锁定即清除）
- 目录树懒加载（已加密目录显示原文件名）
- 加密/解密选中的目录（后台任务 + 进度轮询）
- 密码不落盘、不进日志
"""

from __future__ import annotations

import os
import secrets
import threading
import time
import uuid

from fastapi import FastAPI, Depends, HTTPException, Request, Response, Cookie, Header
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

import crypto

VAULT_ROOT = os.environ.get("VAULT_ROOT", "/data")
PORT = int(os.environ.get("PORT", "8080"))

app = FastAPI(title="Secure Vault", docs_url=None, redoc_url=None, openapi_url=None)

# 内存会话：token -> {key: master_key, init: 创建会话时工作区是否已初始化}
_sessions: dict[str, dict] = {}
COOKIE_NAME = "svault_token"
MIN_PASSWORD_LEN = 8

# 后台任务：task_id -> {status, percent, done, total, current, error}
_tasks: dict[str, dict] = {}
_tasks_lock = threading.Lock()


# ---------------------------------------------------------------------------
# 会话辅助
# ---------------------------------------------------------------------------
def _get_key(vault_token: str | None = Cookie(default=None, alias=COOKIE_NAME)) -> bytes:
    token = vault_token or ""
    sess = _sessions.get(token)
    if not sess:
        raise HTTPException(status_code=401, detail="未解锁")
    return sess["key"]


def _check_password_strength(password: str) -> str | None:
    """返回强度错误信息，None 表示合格。"""
    if len(password) < MIN_PASSWORD_LEN:
        return f"密码至少 {MIN_PASSWORD_LEN} 位"
    return None


def _safe_path(rel: str) -> str:
    """把相对路径解析到 VAULT_ROOT 内，越界则拒绝。"""
    root = os.path.abspath(VAULT_ROOT)
    target = os.path.abspath(os.path.join(root, rel)) if rel else root
    if target != root and not target.startswith(root + os.sep):
        raise HTTPException(status_code=403, detail="路径越界")
    return target


@app.exception_handler(Exception)
async def _unhandled(request: Request, exc: Exception):
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
# 会话
# ---------------------------------------------------------------------------
@app.get("/api/status")
async def status():
    """报告工作区是否已初始化（无需会话）。未初始化时前端显示创建密码流程。"""
    return {"initialized": crypto.is_initialized(VAULT_ROOT)}


@app.post("/api/unlock")
async def unlock(body: dict, response: Response):
    password = body.get("password", "")
    if not password:
        raise HTTPException(status_code=400, detail="密码不能为空")
    confirmation = body.get("password_confirmation", "")

    initialized = crypto.is_initialized(VAULT_ROOT)

    if initialized:
        # 已初始化：单密码，派生后验证所有索引，任一失败即拒（统一提示，不泄露细节）
        key = crypto.derive_master_key(password)
        password = None
        for index_path in crypto.find_encrypted_roots(VAULT_ROOT):
            try:
                crypto.read_index(key, index_path)
            except ValueError:
                raise HTTPException(status_code=401, detail="密码错误或索引损坏")
    else:
        # 未初始化：创建密码，要求两次一致 + 满足强度；密钥只派生到内存会话，
        # 第一次成功加密并提交 .svault 时才正式建立。
        if confirmation != password:
            raise HTTPException(status_code=400, detail="两次输入的密码不一致")
        msg = _check_password_strength(password)
        if msg:
            raise HTTPException(status_code=400, detail=msg)
        key = crypto.derive_master_key(password)
        password = None

    token = secrets.token_urlsafe(32)
    _sessions[token] = {"key": key, "init": initialized}
    response.set_cookie(COOKIE_NAME, token, httponly=True, samesite="strict", max_age=86400)
    return {"ok": True, "initialized": initialized}


@app.post("/api/lock")
async def lock(vault_token: str | None = Cookie(default=None, alias=COOKIE_NAME)):
    token = vault_token or ""
    _sessions.pop(token, None)
    return {"ok": True}


# ---------------------------------------------------------------------------
# 目录树
# ---------------------------------------------------------------------------
@app.get("/api/tree")
async def tree(path: str = "", key: bytes = Depends(_get_key)):
    abs_path = _safe_path(path)
    try:
        nodes = crypto.list_directory(key, VAULT_ROOT, path)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return {"path": path, "nodes": nodes}


# ---------------------------------------------------------------------------
# 任务调度
# ---------------------------------------------------------------------------
def _run_task(task_id: str, fn, *args):
    def runner():
        try:
            fn(*args)
            with _tasks_lock:
                _tasks[task_id]["status"] = "done"
                _tasks[task_id]["percent"] = 100.0
        except Exception as e:
            with _tasks_lock:
                _tasks[task_id]["status"] = "error"
                _tasks[task_id]["error"] = str(e)

    threading.Thread(target=runner, daemon=True).start()


def _new_task() -> str:
    task_id = uuid.uuid4().hex
    _tasks[task_id] = {
        "status": "running", "percent": 0.0, "done": 0, "total": 0,
        "current": "", "error": None,
    }
    return task_id


def _invalidate_stale_init_sessions(current_token: str) -> None:
    """首次加密建立 .svault 后，失效其它尚未初始化的旧会话。

    避免两个并发会话用不同密码建立数据（DESIGN §3.3 首次使用第 4 点）。
    """
    if not crypto.is_initialized(VAULT_ROOT):
        return
    for tok in list(_sessions.keys()):
        if tok != current_token and _sessions[tok].get("init") is False:
            _sessions.pop(tok, None)


def _progress_cb(task_id: str):
    def cb(done: int, total: int, current: str):
        with _tasks_lock:
            t = _tasks[task_id]
            t["done"] = done
            t["total"] = total
            t["percent"] = (done / total * 100.0) if total else 100.0
            t["current"] = current
    return cb


# ---------------------------------------------------------------------------
# 加密 / 解密
# ---------------------------------------------------------------------------
@app.post("/api/encrypt")
async def encrypt(
    body: dict,
    key: bytes = Depends(_get_key),
    vault_token: str | None = Cookie(default=None, alias=COOKIE_NAME),
):
    paths = body.get("paths") or []
    if not paths:
        raise HTTPException(status_code=400, detail="未选择目录")
    abs_paths = [_safe_path(p) for p in paths]

    task_id = _new_task()
    cb = _progress_cb(task_id)
    token = vault_token or ""

    def work():
        for p in abs_paths:
            crypto.encrypt_folder(key, p, progress=cb)
        _invalidate_stale_init_sessions(token)

    _run_task(task_id, work)
    return {"task_id": task_id}


@app.post("/api/decrypt")
async def decrypt(body: dict, key: bytes = Depends(_get_key)):
    paths = body.get("paths") or []
    output = body.get("output") or None
    if not paths:
        raise HTTPException(status_code=400, detail="未选择目录")
    abs_paths = [_safe_path(p) for p in paths]

    task_id = _new_task()
    cb = _progress_cb(task_id)

    def work():
        for p in abs_paths:
            crypto.decrypt_folder(key, p, output_dir=output, progress=cb)

    _run_task(task_id, work)
    return {"task_id": task_id}


@app.get("/api/progress/{task_id}")
async def progress(task_id: str, key: bytes = Depends(_get_key)):
    with _tasks_lock:
        t = _tasks.get(task_id)
    if not t:
        raise HTTPException(status_code=404, detail="任务不存在")
    return {
        "status": t["status"],
        "percent": round(t["percent"], 1),
        "done": t["done"],
        "total": t["total"],
        "current": t["current"],
        "error": t["error"],
    }
