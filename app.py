"""CipherShelf FastAPI service with bounded sessions and serialized mutations."""

from __future__ import annotations

import os
import logging
import secrets
import threading
import time
import uuid
from collections import defaultdict, deque
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, StrictStr

import crypto

VAULT_ROOT = os.path.realpath(os.environ.get("VAULT_ROOT", "/data"))
PORT = int(os.environ.get("PORT", "8080"))
PRESET_PASSWORD = os.environ.get("VAULT_PASSWORD") or None
VAULT_UNCONFIGURED = os.environ.get("VAULT_UNCONFIGURED") == "1"
COOKIE_SECURE = os.environ.get("SVAULT_COOKIE_SECURE", "0") == "1"

COOKIE_NAME = "svault_token"
SESSION_IDLE_SECONDS = 30 * 60
SESSION_MAX_SECONDS = 8 * 60 * 60
MAX_TASKS = 100
MAX_PATHS_PER_REQUEST = 32
LOGIN_WINDOW_SECONDS = 5 * 60
LOGIN_MAX_FAILURES = 10
STATUS_CACHE_SECONDS = 60

app = FastAPI(title="CipherShelf", docs_url=None, redoc_url=None, openapi_url=None)

logger = logging.getLogger("ciphershelf")

_sessions: dict[str, dict] = {}
_sessions_lock = threading.Lock()
_tasks: dict[str, dict] = {}
_tasks_lock = threading.Lock()
_mutation_lock = threading.Lock()
_login_failures: dict[str, deque[float]] = defaultdict(deque)
_login_lock = threading.Lock()
_status_lock = threading.Lock()
_status_cache = {"at": 0.0, "initialized": False}


class UnlockBody(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    password: StrictStr = Field(min_length=1, max_length=1024)
    password_confirmation: StrictStr | None = Field(default=None, max_length=1024)


class PathsBody(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    paths: list[StrictStr] = Field(min_length=1, max_length=MAX_PATHS_PER_REQUEST)


class DecryptBody(PathsBody):
    output: StrictStr | None = Field(default=None, max_length=4096)


def _client_id(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _prune_login_failures(client: str, now: float) -> deque[float]:
    failures = _login_failures[client]
    while failures and now - failures[0] > LOGIN_WINDOW_SECONDS:
        failures.popleft()
    return failures


def _check_login_rate(request: Request) -> None:
    now = time.monotonic()
    with _login_lock:
        if len(_prune_login_failures(_client_id(request), now)) >= LOGIN_MAX_FAILURES:
            raise HTTPException(status_code=429, detail="登录尝试过多，请稍后再试")


def _record_login_failure(request: Request) -> None:
    with _login_lock:
        _prune_login_failures(_client_id(request), time.monotonic()).append(time.monotonic())


def _clear_login_failures(request: Request) -> None:
    with _login_lock:
        _login_failures.pop(_client_id(request), None)


def _get_request_token(
    vault_token: str | None = Cookie(default=None, alias=COOKIE_NAME),
    authorization: str | None = Header(default=None),
) -> str:
    # 优先从 Authorization: Bearer <token> 读会话（跨站 iframe 下 cookie 会被浏览器
    # 因 SameSite 策略拒存，改用 header 认证规避），其次回退到 cookie（向后兼容）。
    token = ""
    if authorization:
        scheme, separator, credentials = authorization.partition(" ")
        if separator and scheme.lower() == "bearer":
            token = credentials.strip()
    if not token:
        token = vault_token or ""
    return token


def _get_session(token: str = Depends(_get_request_token)) -> dict:
    now = time.monotonic()
    with _sessions_lock:
        session = _sessions.get(token)
        if not session:
            raise HTTPException(status_code=401, detail="未解锁")
        if now - session["last"] > SESSION_IDLE_SECONDS or now - session["created"] > SESSION_MAX_SECONDS:
            _sessions.pop(token, None)
            raise HTTPException(status_code=401, detail="会话已过期")
        session["last"] = now
        return {"token": token, "key": session["key"], "init": session["init"]}


def _check_password_strength(password: str) -> str | None:
    return crypto.password_strength_error(password)


def _is_link_or_junction(path: str) -> bool:
    return os.path.islink(path) or bool(getattr(os.path, "isjunction", lambda _p: False)(path))


def _safe_path(
    rel: str,
    *,
    allow_root: bool = True,
    must_exist: bool = True,
) -> str:
    """Resolve a POSIX-style API path under VAULT_ROOT without following links."""
    if not isinstance(rel, str) or len(rel) > 4096 or "\x00" in rel or "\\" in rel:
        raise HTTPException(status_code=400, detail="路径格式非法")
    if rel:
        pure = PurePosixPath(rel)
        if pure.is_absolute() or any(part in ("", ".", "..") for part in rel.split("/")):
            raise HTTPException(status_code=403, detail="路径越界")
        parts = rel.split("/")
    else:
        parts = []
    if not allow_root and not parts:
        raise HTTPException(status_code=400, detail="不能直接操作数据根目录")

    root = VAULT_ROOT
    target = os.path.abspath(os.path.join(root, *parts))
    try:
        if os.path.commonpath([root, target]) != root:
            raise HTTPException(status_code=403, detail="路径越界")
    except ValueError:
        raise HTTPException(status_code=403, detail="路径越界")

    current = root
    if _is_link_or_junction(current):
        raise HTTPException(status_code=403, detail="数据根目录不能是符号链接")
    for index, part in enumerate(parts):
        current = os.path.join(current, part)
        if os.path.lexists(current):
            if _is_link_or_junction(current):
                raise HTTPException(status_code=403, detail="路径包含符号链接或联接点")
        elif index < len(parts) - 1 and must_exist:
            raise HTTPException(status_code=404, detail="路径不存在")
    if must_exist and not os.path.exists(target):
        raise HTTPException(status_code=404, detail="路径不存在")
    existing = target
    while not os.path.exists(existing):
        parent = os.path.dirname(existing)
        if parent == existing:
            break
        existing = parent
    try:
        if os.path.commonpath([root, os.path.realpath(existing)]) != root:
            raise HTTPException(status_code=403, detail="路径越界")
    except ValueError:
        raise HTTPException(status_code=403, detail="路径越界")
    return target


def _validate_non_overlapping(paths: list[str]) -> None:
    normalized = sorted(set(paths), key=lambda value: (len(Path(value).parts), value))
    if len(normalized) != len(paths):
        raise HTTPException(status_code=400, detail="路径重复")
    for index, path in enumerate(normalized):
        for other in normalized[index + 1:]:
            try:
                if os.path.commonpath([path, other]) == path:
                    raise HTTPException(status_code=400, detail="所选路径不能互为父子目录")
            except ValueError:
                continue


def _same_origin(request: Request) -> bool:
    """判断请求是否同源。

    除直接同源外，兼容飞牛 fnOS 统一网关（/app/{appname}）反向代理：
    浏览器 Origin 是网关域，后端 Host 被网关改写为内网地址，二者不再相等。
    """
    origin = request.headers.get("origin")
    if not origin:
        return True
    try:
        origin_parts = urlsplit(origin)
    except ValueError:
        return False

    host = request.headers.get("host", "")

    # 1) 直接同源：Origin == Host
    if origin_parts.netloc == host:
        return True

    # 2) 反向代理：用 X-Forwarded-Host / X-Forwarded-Proto 还原浏览器视角的 Host
    fwd_host = (request.headers.get("x-forwarded-host") or "").split(",")[0].strip()
    if fwd_host:
        fwd_proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip()
        try:
            expected = fwd_host if "://" in fwd_host else f"{fwd_proto or 'http'}://{fwd_host}"
            if urlsplit(expected).netloc == origin_parts.netloc:
                return True
        except ValueError:
            pass

    # 3) 飞牛统一网关在 NAS 登录态校验通过后注入的可信同源标识
    if request.headers.get("x-trim-userid"):
        return True

    # 4) 主机名一致（忽略端口/scheme 差异，覆盖网关仅改写端口的场景）
    try:
        if origin_parts.hostname and origin_parts.hostname == urlsplit("//" + host).hostname:
            return True
    except ValueError:
        pass

    return False


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    if request.url.path.startswith("/api/") and request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        has_header = request.headers.get("x-svault-request") == "1"
        same_origin = _same_origin(request)
        if not has_header or not same_origin:
            logger.warning(
                "CSRF rejected: method=%s path=%s svault_header=%s origin=%r host=%r "
                "fwd_host=%r fwd_proto=%r trim_userid=%s",
                request.method, request.url.path, has_header,
                request.headers.get("origin"), request.headers.get("host"),
                request.headers.get("x-forwarded-host"),
                request.headers.get("x-forwarded-proto"),
                bool(request.headers.get("x-trim-userid")),
            )
            return JSONResponse(status_code=403, content={"detail": "拒绝跨站请求"})
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return response


@app.exception_handler(Exception)
async def _unhandled(_request: Request, _exc: Exception):
    return JSONResponse(status_code=500, content={"detail": "服务器内部错误"})


_static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")


@app.get("/")
async def index():
    return Response(content=(_static_dir / "index.html").read_bytes(), media_type="text/html")


@app.get("/api/status")
async def status():
    now = time.monotonic()
    with _status_lock:
        if now - _status_cache["at"] > STATUS_CACHE_SECONDS:
            if os.path.isdir(VAULT_ROOT):
                crypto.recover_transactions(VAULT_ROOT)
                _status_cache["initialized"] = crypto.is_initialized(VAULT_ROOT)
            else:
                _status_cache["initialized"] = False
            _status_cache["at"] = now
        initialized = _status_cache["initialized"]
    return {
        "initialized": initialized,
        "preset": PRESET_PASSWORD is not None,
        "configured": not VAULT_UNCONFIGURED,
    }


@app.post("/api/unlock")
async def unlock(body: UnlockBody, request: Request, response: Response):
    if VAULT_UNCONFIGURED:
        raise HTTPException(status_code=400, detail="请先在应用设置里配置数据目录")
    if _mutation_lock.locked():
        raise HTTPException(status_code=409, detail="磁盘任务正在运行，请稍后重试")
    _check_login_rate(request)
    password = body.password
    initialized = False
    try:
        if PRESET_PASSWORD is not None:
            if not secrets.compare_digest(password.encode("utf-8"), PRESET_PASSWORD.encode("utf-8")):
                raise ValueError("密码错误或索引损坏")
            key = crypto.KeyContext(crypto.derive_master_key(password))
            index_paths = crypto.find_encrypted_roots(VAULT_ROOT)
            for index_path in index_paths:
                crypto.read_index(key, index_path)
            initialized = True
        else:
            index_paths = crypto.find_encrypted_roots(VAULT_ROOT)
            initialized = bool(index_paths)
        if PRESET_PASSWORD is None and initialized:
            key = crypto.KeyContext(crypto.derive_master_key(password))
            for index_path in index_paths:
                crypto.read_index(key, index_path)
        elif PRESET_PASSWORD is None:
            if body.password_confirmation != password:
                raise HTTPException(status_code=400, detail="两次输入的密码不一致")
            message = _check_password_strength(password)
            if message:
                raise HTTPException(status_code=400, detail=message)
            key = crypto.KeyContext(crypto.derive_master_key(password))
    except HTTPException:
        _record_login_failure(request)
        raise
    except (ValueError, OSError):
        _record_login_failure(request)
        raise HTTPException(status_code=401, detail="密码错误或索引损坏")

    _clear_login_failures(request)
    # Authenticated cleanup for a commit that reached the new tree but crashed
    # before deleting its backup. This never removes a backup before verifying
    # the committed encrypted/plaintext tree with the supplied key.
    crypto.recover_transactions(VAULT_ROOT, key)
    token = secrets.token_urlsafe(32)
    now = time.monotonic()
    with _sessions_lock:
        _sessions[token] = {"key": key, "init": initialized, "created": now, "last": now}
    response.set_cookie(
        COOKIE_NAME, token, httponly=True, secure=COOKIE_SECURE, samesite="strict",
        max_age=SESSION_MAX_SECONDS, path="/api",
    )
    return {"ok": True, "initialized": initialized, "token": token}


@app.post("/api/lock")
async def lock(
    response: Response,
    token: str = Depends(_get_request_token),
):
    with _sessions_lock:
        _sessions.pop(token, None)
    response.delete_cookie(COOKIE_NAME, path="/api", secure=COOKIE_SECURE, samesite="strict")
    return {"ok": True}


@app.get("/api/tree")
async def tree(path: str = "", session: dict = Depends(_get_session)):
    _safe_path(path, allow_root=True, must_exist=True)
    try:
        nodes = crypto.list_directory(session["key"], VAULT_ROOT, path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc).replace(VAULT_ROOT, "<VAULT_ROOT>"))
    return {"path": path, "nodes": nodes}


def _cleanup_tasks(now: float) -> None:
    stale = [task_id for task_id, task in _tasks.items() if now - task["created"] > 3600 and task["status"] != "running"]
    for task_id in stale:
        _tasks.pop(task_id, None)


def _new_task(owner: str) -> str:
    with _tasks_lock:
        _cleanup_tasks(time.monotonic())
        if len(_tasks) >= MAX_TASKS:
            raise HTTPException(status_code=503, detail="任务过多，请稍后重试")
        task_id = uuid.uuid4().hex
        _tasks[task_id] = {
            "owner": owner, "created": time.monotonic(), "status": "running",
            "percent": 0.0, "done": 0, "total": 0, "current": "", "error": None,
        }
        return task_id


def _run_task(task_id: str, function) -> None:
    def runner():
        try:
            function()
            with _tasks_lock:
                _tasks[task_id]["status"] = "done"
                _tasks[task_id]["percent"] = 100.0
        except Exception as exc:
            message = str(exc).replace(VAULT_ROOT, "<VAULT_ROOT>")
            with _tasks_lock:
                _tasks[task_id]["status"] = "error"
                _tasks[task_id]["error"] = message[:1000]
        finally:
            with _status_lock:
                _status_cache["at"] = 0.0
            _mutation_lock.release()
    threading.Thread(target=runner, name=f"svault-{task_id[:8]}", daemon=True).start()


def _progress_cb(task_id: str):
    def callback(done: int, total: int, current: str):
        with _tasks_lock:
            task = _tasks[task_id]
            task["done"] = done
            task["total"] = total
            task["percent"] = (done / total * 100.0) if total else 100.0
            task["current"] = current
    return callback


def _invalidate_stale_init_sessions(current_token: str) -> None:
    if not crypto.is_initialized(VAULT_ROOT):
        return
    with _sessions_lock:
        for token in list(_sessions):
            if token != current_token and _sessions[token].get("init") is False:
                _sessions.pop(token, None)


@app.post("/api/encrypt")
async def encrypt(body: PathsBody, session: dict = Depends(_get_session)):
    abs_paths = [_safe_path(path, allow_root=False, must_exist=True) for path in body.paths]
    _validate_non_overlapping(abs_paths)
    if not _mutation_lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="已有磁盘任务正在运行")
    try:
        task_id = _new_task(session["token"])
        callback = _progress_cb(task_id)
        def work():
            for path in abs_paths:
                crypto.encrypt_folder(session["key"], path, progress=callback)
            _invalidate_stale_init_sessions(session["token"])
        _run_task(task_id, work)
        return {"task_id": task_id}
    except Exception:
        _mutation_lock.release()
        raise


@app.post("/api/decrypt")
async def decrypt(body: DecryptBody, session: dict = Depends(_get_session)):
    abs_paths = [_safe_path(path, allow_root=False, must_exist=True) for path in body.paths]
    _validate_non_overlapping(abs_paths)
    output = None
    if body.output is not None:
        if len(abs_paths) != 1:
            raise HTTPException(status_code=400, detail="指定 output 时只能解密一个目录")
        output = _safe_path(body.output, allow_root=False, must_exist=False)
        for source in abs_paths:
            try:
                common = os.path.commonpath([source, output])
            except ValueError:
                common = ""
            if common in (source, output):
                raise HTTPException(status_code=400, detail="输出目录不能与源目录重叠")
    if not _mutation_lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="已有磁盘任务正在运行")
    try:
        task_id = _new_task(session["token"])
        callback = _progress_cb(task_id)
        def work():
            for path in abs_paths:
                crypto.decrypt_folder(session["key"], path, output_dir=output, progress=callback)
        _run_task(task_id, work)
        return {"task_id": task_id}
    except Exception:
        _mutation_lock.release()
        raise


@app.get("/api/progress/{task_id}")
async def progress(task_id: str, session: dict = Depends(_get_session)):
    with _tasks_lock:
        task = _tasks.get(task_id)
        if not task or not secrets.compare_digest(task["owner"], session["token"]):
            raise HTTPException(status_code=404, detail="任务不存在")
        return {
            "status": task["status"], "percent": round(task["percent"], 1),
            "done": task["done"], "total": task["total"], "current": task["current"],
            "error": task["error"],
        }
