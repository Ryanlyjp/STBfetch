import asyncio
import hmac
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from starlette.responses import StreamingResponse

from .login_flow import Account, format_singapore_time, parse_accounts, parse_proxies, run_logins
from .secure_store import SecureStore


SCREENSHOT_DIR = Path(os.environ.get("SBEANS_SCREENSHOT_DIR", "/data/screenshots"))
STORE_PATH = Path(os.environ.get("SBEANS_STORE_PATH", "/data/secure_store.json"))
STORE = SecureStore(STORE_PATH, os.environ.get("SBEANS_ADMIN_PASSWORD", ""))
ACTIVE_LOGIN_TASKS: set[asyncio.Task] = set()
IMPORTANT_LOG_MARKERS = (
    "任务开始",
    "任务执行完成",
    "登录完成",
    "登录成功",
    "登录状态",
    "登录未成功",
    "访问 VOXI",
    "VOXI",
    "已提取",
    "代码提取",
    "下次时间",
    "下次日期",
    "优惠码库",
    "重试",
    "失败",
    "异常",
    "超时",
    "停止",
    "取消",
)

app = FastAPI(title="SBeans", docs_url=None, redoc_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8087", "http://localhost:8087"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Admin-Password"],
)


class LoginRequest(BaseModel):
    accounts: str = ""
    record_ids: list[str] = Field(default_factory=list)
    proxies: str = ""
    debug: bool = False


class RecordRequest(BaseModel):
    email: str
    password: str
    time: str


class PasswordRequest(BaseModel):
    current_password: str
    new_password: str


def require_admin(password: str | None) -> str:
    if not password or not STORE.authenticate(password):
        raise HTTPException(status_code=401, detail="面板密码错误")
    return password


def event(data: dict) -> str:
    return f"data: {json.dumps(data, ensure_ascii=False)}\n\n"


def _is_important_log(message: str) -> bool:
    text = str(message or "").strip()
    if not text:
        return False
    if text.startswith("FlareSolverr步骤："):
        return False
    if "同一 Camoufox 会话登录完成" in text:
        return False
    if text.startswith("FlareSolverr：") and "失败" not in text and "未完成" not in text:
        return False
    return any(marker in text for marker in IMPORTANT_LOG_MARKERS)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/session")
def session(x_admin_password: str | None = Header(default=None)) -> dict[str, bool]:
    require_admin(x_admin_password)
    return {"authenticated": True}


@app.get("/api/records")
def records(x_admin_password: str | None = Header(default=None)) -> dict[str, list[dict[str, str]]]:
    password = require_admin(x_admin_password)
    return {"records": STORE.list_records(password)}


@app.post("/api/records")
def add_record(payload: RecordRequest, x_admin_password: str | None = Header(default=None)) -> dict[str, dict[str, str]]:
    password = require_admin(x_admin_password)
    email = payload.email.strip()
    account_password = payload.password.strip()
    record_time = payload.time.strip()
    if not email or not account_password or not record_time:
        raise HTTPException(status_code=422, detail="账号、密码和时间都不能为空")
    return {"record": STORE.add_record(password, email, account_password, record_time)}


@app.delete("/api/records/{record_id}")
def delete_record(record_id: str, x_admin_password: str | None = Header(default=None)) -> dict[str, bool]:
    password = require_admin(x_admin_password)
    if not STORE.delete_record(password, record_id):
        raise HTTPException(status_code=404, detail="账号记录不存在")
    return {"deleted": True}


@app.post("/api/password")
def change_password(payload: PasswordRequest, x_admin_password: str | None = Header(default=None)) -> dict[str, bool]:
    password = require_admin(x_admin_password)
    if not hmac.compare_digest(payload.current_password, password):
        raise HTTPException(status_code=401, detail="当前面板密码错误")
    if not payload.new_password:
        raise HTTPException(status_code=422, detail="新密码不能为空")
    STORE.change_password(password, payload.new_password)
    return {"changed": True}


@app.get("/api/code-library")
def code_library(x_admin_password: str | None = Header(default=None)) -> dict[str, list[dict[str, object]]]:
    password = require_admin(x_admin_password)
    return {"entries": STORE.list_code_library(password)}


@app.post("/api/login-stop")
async def stop_login(x_admin_password: str | None = Header(default=None)) -> dict[str, int]:
    require_admin(x_admin_password)
    tasks = [task for task in ACTIVE_LOGIN_TASKS if not task.done()]
    for task in tasks:
        task.cancel()
    return {"stopped": len(tasks)}


def _next_code_date(codes: object) -> str:
    if not isinstance(codes, list):
        return ""
    for item in codes:
        if isinstance(item, dict) and item.get("endDate"):
            return str(item["endDate"])
    return ""


@app.post("/api/login-stream")
async def login_stream(payload: LoginRequest, x_admin_password: str | None = Header(default=None)):
    password = require_admin(x_admin_password)
    try:
        accounts = parse_accounts(payload.accounts) if payload.accounts.strip() else []
        accounts.extend(Account(email, account_password) for email, account_password in STORE.selected_accounts(password, payload.record_ids))
        if not accounts:
            raise ValueError("至少需要输入或选择一个账号")
        proxies = parse_proxies(payload.proxies)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    async def stream():
        queue: asyncio.Queue[dict] = asyncio.Queue()
        stream_started = time.monotonic()

        def runtime_log(message: str) -> None:
            if not _is_important_log(message):
                return
            timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
            elapsed = time.monotonic() - stream_started
            print(f"[sbeans] {timestamp} [+{elapsed:.3f}s] {message}", flush=True)

        async def log(message: str) -> None:
            if not _is_important_log(message):
                return
            runtime_log(message)
            await queue.put({
                "type": "log",
                "time": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "message": f"[+{time.monotonic() - stream_started:.1f}s] {message}",
            })

        async def execute() -> None:
            runtime_log("任务执行协程开始")
            try:
                results = await run_logins(accounts, proxies, SCREENSHOT_DIR, payload.debug, log)
                for result in results:
                    codes = result.get("codes")
                    next_date = _next_code_date(codes)
                    record_email = str(result.get("email") or "")
                    if result.get("login_success") is True and next_date:
                        next_date_display = format_singapore_time(next_date)
                        updated_records = STORE.update_record_time(password, record_email, next_date_display)
                        if updated_records:
                            await log(
                                f"{record_email}：账号记录时间已更新为下次时间={next_date_display}"
                            )
                    if result.get("success") is not True:
                        continue
                    if not isinstance(codes, list) or not next_date:
                        await log(f"{record_email or '账号'}：代码结果不完整，未写入优惠码库")
                        continue
                    next_date_display = format_singapore_time(next_date)
                    try:
                        STORE.add_code_library(
                            password,
                            record_email,
                            codes,
                            next_date,
                        )
                        await log(
                            f"{record_email or '账号'}：四组优惠码已归档，"
                            f"下次时间={next_date_display}"
                        )
                    except Exception as exc:
                        await log(
                            f"{result.get('email', '账号')}：优惠码库写入失败，"
                            f"异常={type(exc).__name__}: {str(exc).splitlines()[0][:160]}"
                        )
                await queue.put({"type": "result", "results": results})
                runtime_log("任务结果已放入 SSE 队列")
            except asyncio.CancelledError:
                runtime_log(f"任务执行协程被取消，已运行 {time.monotonic() - stream_started:.1f}s")
                raise
            except Exception as exc:
                runtime_log(f"任务执行异常：{type(exc).__name__}: {str(exc).splitlines()[0][:300]}")
                await queue.put({"type": "error", "message": str(exc).splitlines()[0][:300]})
            finally:
                await queue.put({"type": "done"})
                runtime_log(f"任务执行协程结束，总耗时 {time.monotonic() - stream_started:.1f}s")

        task = asyncio.create_task(execute())
        ACTIVE_LOGIN_TASKS.add(task)
        task.add_done_callback(ACTIVE_LOGIN_TASKS.discard)
        try:
            while True:
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=15)
                except TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                yield event(item)
                if item["type"] == "done":
                    break
        finally:
            ACTIVE_LOGIN_TASKS.discard(task)
            if not task.done():
                runtime_log(f"SSE 客户端断开，取消任务，已运行 {time.monotonic() - stream_started:.1f}s")
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            runtime_log(f"SSE 流结束，总耗时 {time.monotonic() - stream_started:.1f}s")

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
