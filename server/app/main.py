"""OGK-Server v2 — FastAPI app (kiến trúc đã duyệt 13/11/2026).

Phụ huynh: cookie session HttpOnly + CSRF (F5). Thiết bị: mã ghép đôi 8 ký tự,
access token 15 phút + refresh token, policy document có version + HMAC.
"""
import asyncio
import os
import sys
import time as time_mod
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import date as date_cls, datetime, time, timedelta

import pyotp
from fastapi import (Depends, FastAPI, Header, HTTPException, Query, Request,
                     Response, WebSocket, WebSocketDisconnect)
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from shared.contract import (COMMAND_TYPES, EVENT_TYPES, SYSTEM_PROCESSES,  # noqa: E402
                             is_never_blocked, normalize_domain, validate_event)

from .models import (AuditLog, Base, Child, ChildRequest, Command, Device,  # noqa: E402
                     DomainCategory, PairingCode, Parent, Policy, UsageEvent,
                     WebSession, engine, get_db, SessionLocal)
from .policy import bump_policy, get_or_create_policy, issue_policy, seed_domain_categories
from .security import (decrypt_field, encrypt_field, hash_password, hash_token,  # noqa: E402
                       new_token, verify_password)

SESSION_COOKIE = "ogk_session"
SESSION_HOURS = 12
ACCESS_MINUTES = 15
PAIRING_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
RETENTION_DAYS = 90
_DASHBOARD = os.path.join(os.path.dirname(__file__), "..", "..", "dashboard", "index.html")


# ------------------------------------------------------------------ helpers
def audit(db, parent, actor, action, ip=None, old=None, new=None, role="parent"):
    db.add(AuditLog(parent_id=parent.id if parent else None, actor=actor, role=role,
                    action=action, ip=ip, old=old, new=new))


def client_ip(request: Request):
    return request.client.host if request.client else None


_login_hits = defaultdict(deque)


def rate_limit_login(ip: str):
    now = time_mod.monotonic()
    q = _login_hits[ip or "?"]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= 60:
        raise HTTPException(429, "too many login attempts, try again later")
    q.append(now)


class WSManager:
    def __init__(self):
        self.conns: dict[int, set[WebSocket]] = {}
        self.loop = None

    async def connect(self, did, ws):
        await ws.accept()
        if self.loop is None:
            self.loop = asyncio.get_running_loop()
        self.conns.setdefault(did, set()).add(ws)

    def disconnect(self, did, ws):
        self.conns.get(did, set()).discard(ws)

    async def send(self, did, payload) -> bool:
        ok = False
        for ws in list(self.conns.get(did, [])):
            try:
                await ws.send_json(payload)
                ok = True
            except Exception:
                self.disconnect(did, ws)
        return ok

    def send_sync(self, did, payload) -> bool:
        """Gửi từ endpoint đồng bộ (threadpool): đẩy coroutine lên event loop
        chính của server. Chưa có kết nối WS nào từng mở -> bỏ qua lặng lẽ
        (agent vẫn tự phát hiện bản mới ở nhịp heartbeat 60s)."""
        loop = self.loop
        if loop is None or loop.is_closed():
            return False
        try:
            asyncio.run_coroutine_threadsafe(self.send(did, payload), loop)
            return True
        except Exception:
            return False


manager = WSManager()


def _notify_policy(device_id: int, doc) -> None:
    """Đẩy thông báo policy mới qua WS để agent áp dụng NGAY (agent đã có
    sẵn xử lý 'policy_updated' -> sync_now). WS đứt thì heartbeat 60s vẫn
    là đường dự phòng, không lỗi gì."""
    manager.send_sync(device_id, {"type": "policy_updated",
                                  "version": (doc or {}).get("version")})


def cmd_dict(c: Command):
    return {"id": c.id, "device_id": c.device_id, "type": c.type,
            "payload": c.payload or {}, "status": c.status,
            "created_by": c.created_by,
            "created_at": c.created_at.isoformat() if c.created_at else None}


def req_dict(r: ChildRequest):
    return {"id": r.id, "device_id": r.device_id, "type": r.type, "minutes": r.minutes,
            "subject": r.subject, "reason": r.reason, "status": r.status,
            "decision_note": r.decision_note,
            "created_at": r.created_at.isoformat() if r.created_at else None}


def owned_child(db, parent, child_id) -> Child:
    c = db.query(Child).filter_by(id=child_id, parent_id=parent.id).first()
    if not c:
        raise HTTPException(404, "child not found")
    return c


def owned_device(db, parent, device_id) -> Device:
    dev = db.query(Device).join(Child).filter(
        Device.id == device_id, Child.parent_id == parent.id).first()
    if not dev:
        raise HTTPException(404, "device not found")
    return dev


# ------------------------------------------------------------------ auth deps
def get_session(request: Request, db: Session = Depends(get_db)):
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        raise HTTPException(401, "not logged in")
    sess = db.query(WebSession).filter_by(token_hash=hash_token(raw)).first()
    if not sess or sess.expires_at < datetime.utcnow():
        raise HTTPException(401, "session expired")
    parent = db.get(Parent, sess.parent_id)
    if not parent:
        raise HTTPException(401, "parent not found")
    return parent, sess


def get_current_parent(pair=Depends(get_session)):
    return pair[0]


def check_csrf(request: Request, sess: WebSession):
    if request.headers.get("x-csrf-token") != sess.csrf_token:
        raise HTTPException(403, "CSRF token missing/invalid")


def get_current_device(authorization: str | None = Header(default=None),
                       db: Session = Depends(get_db)) -> Device:
    token = ""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    if not token:
        raise HTTPException(401, "missing device access token")
    dev = db.query(Device).filter_by(access_token_hash=hash_token(token), revoked=False).first()
    if not dev:
        raise HTTPException(401, "invalid device token")
    if dev.access_expires_at and dev.access_expires_at < datetime.utcnow():
        raise HTTPException(401, "access token expired")
    return dev


def cert_fingerprint():
    path = os.getenv("OGK_TLS_CERT", "")
    if not path or not os.path.exists(path):
        return None
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        data = open(path, "rb").read()
        try:
            cert = x509.load_pem_x509_certificate(data)
        except ValueError:
            from cryptography.hazmat.primitives.serialization import load_der_x509_certificate
            cert = load_der_x509_certificate(data)
        import hashlib
        return hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()
    except Exception:
        return None


def purge_old_data(db: Session) -> dict:
    cutoff = time_mod.time() - RETENTION_DAYS * 86400
    events = db.query(UsageEvent).filter(UsageEvent.ts_epoch < cutoff).delete()
    sessions = db.query(WebSession).filter(WebSession.expires_at < datetime.utcnow()).delete()
    codes = db.query(PairingCode).filter(PairingCode.expires_at < datetime.utcnow()).delete()
    db.commit()
    return {"events_deleted": events, "sessions_deleted": sessions, "codes_deleted": codes}


# ------------------------------------------------------------------ lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_domain_categories(db)
        # DEMO ONLY — đổi mật khẩu/xóa trước khi dùng thật: demo@ogk.local / Demo12345!
        if not db.query(Parent).filter_by(email="demo@ogk.local").first():
            p = Parent(email="demo@ogk.local", password_hash=hash_password("Demo12345!"))
            db.add(p)
            db.flush()
            db.add(Child(parent_id=p.id, name="Demo Child", dob=date_cls(2015, 1, 1)))
            db.commit()
        purge_old_data(db)
    finally:
        db.close()

    async def _retention_loop():
        while True:
            await asyncio.sleep(24 * 3600)
            d = SessionLocal()
            try:
                purge_old_data(d)
            except Exception:
                pass
            finally:
                d.close()

    task = asyncio.create_task(_retention_loop())
    yield
    task.cancel()


app = FastAPI(title="OpenGuard Kids Server v2", lifespan=lifespan)


@app.get("/")
def dashboard():
    if os.path.exists(_DASHBOARD):
        return FileResponse(_DASHBOARD)
    return {"service": "OpenGuard Kids Server v2"}


@app.get("/health")
def health():
    return {"ok": True}


# ------------------------------------------------------------------ schemas
class RegisterIn(BaseModel):
    email: str
    password: str = Field(min_length=10)  # F5: tối thiểu 10 ký tự
    enable_totp: bool = False


class LoginIn(BaseModel):
    email: str
    password: str
    totp: str | None = None


class ChildIn(BaseModel):
    name: str
    dob: date_cls | None = None


class PairingCodeIn(BaseModel):
    child_id: int


class RedeemIn(BaseModel):
    code: str
    device_name: str
    fingerprint: str = ""


class RefreshIn(BaseModel):
    refresh_token: str


class TimePolicyIn(BaseModel):
    quota_weekday_min: int | None = None
    quota_weekend_min: int | None = None
    schedule: list | None = None
    warn_at_min: list | None = None
    grace_sec: int | None = None
    group_budgets_min: dict | None = None


class AppRuleIn(BaseModel):
    name: str
    sha256: str | None = None
    action: str = "block"
    category: str = "khac"
    windows: list = []
    daily_cap_min: int | None = None


class WebRuleIn(BaseModel):
    domain: str
    action: str = "block"


class WebSettingsIn(BaseModel):
    category_policy: dict | None = None
    safesearch: bool | None = None
    never_block: list | None = None


class CommandIn(BaseModel):
    device_id: int
    type: str
    payload: dict = {}


class DecideIn(BaseModel):
    decision: str  # approved | rejected
    note: str | None = None


class HeartbeatIn(BaseModel):
    used_today_sec: int | None = None
    policy_version: int | None = None
    status: str | None = None


class EventsIn(BaseModel):
    events: list[dict]


class AlertIn(BaseModel):
    kind: str
    detail: dict = {}


class DeviceRequestIn(BaseModel):
    type: str  # extra_time | false_block
    minutes: int | None = None
    subject: str | None = None
    reason: str = ""


# ------------------------------------------------------------------ auth routes
@app.post("/auth/register", status_code=201)
def register(body: RegisterIn, request: Request, db: Session = Depends(get_db)):
    if "@" not in body.email:
        raise HTTPException(422, "invalid email")
    if db.query(Parent).filter_by(email=body.email).first():
        raise HTTPException(409, "email exists")
    secret = pyotp.random_base32() if body.enable_totp else None
    p = Parent(email=body.email, password_hash=hash_password(body.password),
               totp_secret_enc=encrypt_field(secret) if secret else None)
    db.add(p)
    db.flush()
    audit(db, p, p.email, "auth.register", client_ip(request))
    db.commit()
    uri = pyotp.TOTP(secret).provisioning_uri(name=p.email, issuer_name="OpenGuardKids") if secret else None
    return {"id": p.id, "email": p.email, "totp_uri": uri}


@app.post("/auth/login")
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    ip = client_ip(request)
    rate_limit_login(ip)
    p = db.query(Parent).filter_by(email=body.email).first()
    if p and p.locked_until and p.locked_until > datetime.utcnow():
        raise HTTPException(423, "account temporarily locked (too many failed attempts)")
    ok = bool(p) and verify_password(body.password, p.password_hash)
    if ok and p.totp_secret_enc:
        secret = decrypt_field(p.totp_secret_enc)
        ok = bool(body.totp) and pyotp.TOTP(secret).verify(body.totp, valid_window=1)
    if not ok:
        if p:
            p.failed_attempts = (p.failed_attempts or 0) + 1
            if p.failed_attempts >= 5:  # F5: khóa tạm 15 phút sau 5 lần sai
                p.locked_until = datetime.utcnow() + timedelta(minutes=15)
                p.failed_attempts = 0
            audit(db, p, body.email, "auth.login_failed", ip)
            db.commit()
        raise HTTPException(401, "invalid credentials")
    p.failed_attempts = 0
    p.locked_until = None
    raw = new_token()
    sess = WebSession(token_hash=hash_token(raw), parent_id=p.id, csrf_token=new_token(16),
                      ip=ip, expires_at=datetime.utcnow() + timedelta(hours=SESSION_HOURS))
    db.add(sess)
    audit(db, p, p.email, "auth.login", ip)
    db.commit()
    response.set_cookie(SESSION_COOKIE, raw, max_age=SESSION_HOURS * 3600, httponly=True,
                        samesite="lax", secure=os.getenv("OGK_SECURE_COOKIES") in ("1", "true"),
                        path="/")
    return {"id": p.id, "email": p.email, "role": p.role, "csrf_token": sess.csrf_token,
            "server_cert_fingerprint": cert_fingerprint()}


@app.post("/auth/logout")
def logout(request: Request, response: Response, pair=Depends(get_session),
           db: Session = Depends(get_db)):
    parent, sess = pair
    check_csrf(request, sess)
    db.delete(sess)  # hủy phiên phía server
    audit(db, parent, parent.email, "auth.logout", client_ip(request))
    db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@app.get("/auth/me")
def me(pair=Depends(get_session)):
    parent, sess = pair
    return {"id": parent.id, "email": parent.email, "role": parent.role,
            "csrf_token": sess.csrf_token,
            "server_cert_fingerprint": cert_fingerprint()}


# ------------------------------------------------------------------ children
@app.post("/children", status_code=201)
def create_child(body: ChildIn, request: Request, pair=Depends(get_session),
                 db: Session = Depends(get_db)):
    parent, sess = pair
    check_csrf(request, sess)
    c = Child(parent_id=parent.id, name=body.name, dob=body.dob)
    db.add(c)
    db.flush()
    audit(db, parent, parent.email, "child.create", client_ip(request), new={"name": body.name})
    db.commit()
    db.refresh(c)
    return {"id": c.id, "name": c.name, "dob": str(c.dob) if c.dob else None}


@app.get("/children")
def list_children(parent: Parent = Depends(get_current_parent), db: Session = Depends(get_db)):
    out = []
    for c in db.query(Child).filter_by(parent_id=parent.id):
        devs = [{"id": d.id, "name": d.name, "revoked": d.revoked,
                 "last_seen": d.last_seen.isoformat() if d.last_seen else None}
                for d in db.query(Device).filter_by(child_id=c.id)]
        out.append({"id": c.id, "name": c.name, "dob": str(c.dob) if c.dob else None,
                    "devices": devs})
    return out


@app.delete("/children/{child_id}/data")
async def delete_child_data(child_id: int, request: Request, pair=Depends(get_session),
                            db: Session = Depends(get_db)):
    """Nút 'Xóa toàn bộ dữ liệu của con tôi': xóa trên server + lệnh wipe_cache xuống agent."""
    parent, sess = pair
    check_csrf(request, sess)
    child = owned_child(db, parent, child_id)
    devices = db.query(Device).filter_by(child_id=child.id).all()
    ev_deleted = req_deleted = 0
    for d in devices:
        ev_deleted += db.query(UsageEvent).filter_by(device_id=d.id).delete()
        req_deleted += db.query(ChildRequest).filter_by(device_id=d.id).delete()
        cmd = Command(device_id=d.id, type="wipe_cache", payload={}, created_by=parent.email)
        db.add(cmd)
        db.flush()
        await manager.send(d.id, {"type": "command", "command": cmd_dict(cmd)})
    audit(db, parent, parent.email, "child.data_deleted", client_ip(request),
          new={"events_deleted": ev_deleted, "requests_deleted": req_deleted})
    db.commit()
    return {"events_deleted": ev_deleted, "requests_deleted": req_deleted,
            "devices_notified": len(devices)}


# ------------------------------------------------------------------ pairing
@app.post("/pairing-codes", status_code=201)
def create_pairing_code(body: PairingCodeIn, request: Request, pair=Depends(get_session),
                        db: Session = Depends(get_db)):
    parent, sess = pair
    check_csrf(request, sess)
    child = owned_child(db, parent, body.child_id)
    import secrets as _secrets
    code = "".join(_secrets.choice(PAIRING_ALPHABET) for _ in range(8))
    row = PairingCode(code_hash=hash_token(code), parent_id=parent.id, child_id=child.id,
                      expires_at=datetime.utcnow() + timedelta(minutes=10))
    db.add(row)
    audit(db, parent, parent.email, "pairing.create", client_ip(request),
          new={"child_id": child.id})
    db.commit()
    return {"code": code, "expires_in_sec": 600, "child_id": child.id}


@app.post("/pairing/redeem", status_code=201)
def redeem_pairing(body: RedeemIn, request: Request, db: Session = Depends(get_db)):
    row = db.query(PairingCode).filter_by(code_hash=hash_token(body.code.strip().upper())).first()
    if not row or row.used_at is not None:
        raise HTTPException(404, "pairing code not found or already used")
    if row.expires_at < datetime.utcnow():
        raise HTTPException(410, "pairing code expired")
    parent = db.get(Parent, row.parent_id)
    child = db.get(Child, row.child_id)
    policy_key = uuid.uuid4().hex + uuid.uuid4().hex  # khóa HMAC của policy: 64 hex = 32 byte
    access, refresh = new_token(), new_token()
    dev = Device(child_id=child.id, name=body.device_name, fingerprint=body.fingerprint,
                 access_token_hash=hash_token(access),
                 access_expires_at=datetime.utcnow() + timedelta(minutes=ACCESS_MINUTES),
                 refresh_token_hash=hash_token(refresh),
                 policy_key_enc=encrypt_field(policy_key))
    db.add(dev)
    db.flush()
    get_or_create_policy(db, dev)
    row.used_at = datetime.utcnow()
    # Điểm ghi nhận sự đồng ý của cha mẹ theo Nghị định 13/2023 (mục 2.3 của đề).
    audit(db, parent, parent.email, "consent.pairing", client_ip(request), role="parent",
          new={"device_id": dev.id, "child_id": child.id, "fingerprint": body.fingerprint})
    db.commit()
    return {"device_id": dev.id, "child_id": child.id, "child_name": child.name,
            "access_token": access, "refresh_token": refresh,
            "access_expires_in": ACCESS_MINUTES * 60, "policy_key": policy_key,
            "server_cert_fingerprint": cert_fingerprint()}


@app.post("/device/refresh")
def device_refresh(body: RefreshIn, db: Session = Depends(get_db)):
    dev = db.query(Device).filter_by(refresh_token_hash=hash_token(body.refresh_token),
                                     revoked=False).first()
    if not dev:
        raise HTTPException(401, "invalid refresh token")
    access = new_token()
    dev.access_token_hash = hash_token(access)
    dev.access_expires_at = datetime.utcnow() + timedelta(minutes=ACCESS_MINUTES)
    dev.last_seen = datetime.utcnow()
    db.commit()
    return {"access_token": access, "access_expires_in": ACCESS_MINUTES * 60}


@app.post("/devices/{device_id}/revoke")
def revoke_device(device_id: int, request: Request, pair=Depends(get_session),
                  db: Session = Depends(get_db)):
    parent, sess = pair
    check_csrf(request, sess)
    dev = owned_device(db, parent, device_id)
    dev.revoked = True
    dev.access_token_hash = None
    dev.refresh_token_hash = None
    audit(db, parent, parent.email, "device.revoke", client_ip(request),
          new={"device_id": device_id})
    db.commit()
    return {"revoked": device_id}


# ------------------------------------------------------------------ device API
@app.post("/device/heartbeat")
def heartbeat(body: HeartbeatIn, dev: Device = Depends(get_current_device),
              db: Session = Depends(get_db)):
    dev.last_seen = datetime.utcnow()
    row = get_or_create_policy(db, dev)
    cmds = db.query(Command).filter_by(device_id=dev.id, status="pending").order_by(Command.id).all()
    out = [cmd_dict(c) for c in cmds]
    for c in cmds:
        c.status = "sent"
    db.commit()
    return {"server_time": time_mod.time(), "latest_policy_version": row.version,
            "pending_commands": out}


@app.get("/device/policy")
def device_policy(dev: Device = Depends(get_current_device), db: Session = Depends(get_db)):
    dev.last_seen = datetime.utcnow()
    db.commit()
    return issue_policy(db, dev)


@app.post("/device/events", status_code=201)
def push_events(body: EventsIn, dev: Device = Depends(get_current_device),
                db: Session = Depends(get_db)):
    accepted = duplicates = 0
    for raw in body.events:
        try:
            ev = validate_event(raw)
        except ValueError as exc:
            raise HTTPException(422, f"invalid event: {exc}")
        if db.query(UsageEvent).filter_by(event_id=ev["event_id"]).first():
            duplicates += 1  # idempotency: sự kiện đã nhận rồi thì không đếm hai lần
            continue
        db.add(UsageEvent(event_id=ev["event_id"], device_id=dev.id, child_id=dev.child_id,
                          type=ev["type"], subject=ev["subject"],
                          duration_sec=ev["duration_sec"], policy_id=ev["policy_id"],
                          ts_epoch=ev["ts"]))
        accepted += 1
    dev.last_seen = datetime.utcnow()
    db.commit()
    return {"accepted": accepted, "duplicates": duplicates}


@app.post("/device/alerts", status_code=201)
def device_alert(body: AlertIn, dev: Device = Depends(get_current_device),
                 db: Session = Depends(get_db)):
    audit(db, dev.child.parent, f"device:{dev.id}", f"alert.{body.kind}", None,
          new=body.detail, role="device")
    db.commit()
    return {"ok": True}


@app.post("/device/commands/{command_id}/ack")
def command_ack(command_id: int, dev: Device = Depends(get_current_device),
                db: Session = Depends(get_db)):
    c = db.get(Command, command_id)
    if not c or c.device_id != dev.id:
        raise HTTPException(404, "command not found")
    c.status = "done"
    c.ack_at = datetime.utcnow()
    db.commit()
    return {"id": c.id, "status": c.status}


@app.post("/device/requests", status_code=201)
def device_create_request(body: DeviceRequestIn, dev: Device = Depends(get_current_device),
                          db: Session = Depends(get_db)):
    if body.type not in ("extra_time", "false_block"):
        raise HTTPException(422, "unknown request type")
    r = ChildRequest(device_id=dev.id, type=body.type, minutes=body.minutes,
                     subject=(body.subject or "")[:255] or None, reason=body.reason or "")
    db.add(r)
    db.commit()
    db.refresh(r)
    return req_dict(r)


@app.get("/device/requests")
def device_list_requests(dev: Device = Depends(get_current_device),
                         db: Session = Depends(get_db)):
    rows = (db.query(ChildRequest).filter_by(device_id=dev.id)
            .order_by(ChildRequest.id.desc()).limit(50).all())
    return [req_dict(r) for r in rows]


def _daily_report(db: Session, device_id: int, d: date_cls) -> dict:
    start = datetime.combine(d, time.min).timestamp()
    end = start + 86400
    evs = (db.query(UsageEvent)
           .filter(UsageEvent.device_id == device_id,
                   UsageEvent.ts_epoch >= start, UsageEvent.ts_epoch < end).all())
    by_app: dict[str, float] = {}
    by_domain: dict[str, int] = {}
    blocks = {"blocked_app": 0, "blocked_domain": 0}
    counts = {"quota_warning": 0, "locked": 0}
    for e in evs:
        if e.type == "app_stop" \
                and (e.subject or "").lower() not in SYSTEM_PROCESSES:
            by_app[e.subject] = by_app.get(e.subject, 0.0) + (e.duration_sec or 0)
        elif e.type == "domain_query":
            by_domain[e.subject] = by_domain.get(e.subject, 0) + 1
        elif e.type in blocks:
            blocks[e.type] += 1
        elif e.type in counts:
            counts[e.type] += 1
    top_apps = sorted(by_app.items(), key=lambda kv: -kv[1])[:10]
    top_domains = sorted(by_domain.items(), key=lambda kv: -kv[1])[:10]
    return {"device_id": device_id, "date": str(d),
            "total_app_minutes": round(sum(by_app.values()) / 60, 2),
            "top_apps": [{"app": k, "minutes": round(v / 60, 2)} for k, v in top_apps],
            "top_domains": [{"domain": k, "queries": v} for k, v in top_domains],
            "blocks": blocks, "counts": counts, "event_count": len(evs)}


@app.get("/child/summary")
def child_summary(dev: Device = Depends(get_current_device), db: Session = Depends(get_db)):
    """Màn hình của trẻ (NT5): cùng dữ liệu phụ huynh thấy, cho chính thiết bị này."""
    return _daily_report(db, dev.id, datetime.now().date())


def _mask_ip(ip):
    """Che IP trong góc nhìn của trẻ (NT5 + F4.4): trẻ đối chiếu được "thay
    đổi đến từ mạng nào" (IPv4 giữ 2 octet đầu, IPv6 giữ /32) mà không lộ
    địa chỉ đầy đủ của phụ huynh."""
    if not ip:
        return None
    if ":" in ip:
        parts = ip.split(":")
        return ":".join(parts[:2]) + "::…"
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.x.x"
    return ip


@app.get("/child/audit")
def child_audit(dev: Device = Depends(get_current_device), db: Session = Depends(get_db)):
    """Trẻ xem được nhật ký thay đổi luật của phụ huynh (NT5/F4): cả giá trị
    cũ và mới; IP đã che một phần (xem _mask_ip)."""
    rows = (db.query(AuditLog)
            .filter(AuditLog.parent_id == dev.child.parent_id,
                    AuditLog.action.like("policy.%"))
            .order_by(AuditLog.id.desc()).limit(100).all())
    more = (db.query(AuditLog)
            .filter(AuditLog.parent_id == dev.child.parent_id,
                    AuditLog.action.in_(["command.create", "request.decide", "consent.pairing"]))
            .order_by(AuditLog.id.desc()).limit(50).all())
    seen, out = set(), []
    for a in sorted(rows + more, key=lambda x: -x.id):
        if a.id in seen:
            continue
        seen.add(a.id)
        out.append({"actor": a.actor, "action": a.action, "old": a.old,
                    "new": a.new, "ip": _mask_ip(a.ip),
                    "ts": a.ts.isoformat() if a.ts else None})
    return out


# ------------------------------------------------------------------ parent: policy
@app.get("/policy/{device_id}")
def get_policy_ep(device_id: int, parent: Parent = Depends(get_current_parent),
                  db: Session = Depends(get_db)):
    dev = owned_device(db, parent, device_id)
    return issue_policy(db, dev)


def _audit_fn(db, parent, actor, action, ip, old, new):
    audit(db, parent, actor, action, ip, old, new)
    db.commit()


@app.put("/policy/{device_id}/time")
def put_time_policy(device_id: int, body: TimePolicyIn, request: Request,
                    pair=Depends(get_session), db: Session = Depends(get_db)):
    parent, sess = pair
    check_csrf(request, sess)
    dev = owned_device(db, parent, device_id)
    from shared.contract import validate_schedule
    if body.schedule is not None and not validate_schedule(body.schedule):
        raise HTTPException(422, "schedule must be a 7x48 matrix of 0/1")

    def mutate(doc):
        t = doc.setdefault("time", {})
        for k, v in body.model_dump(exclude_none=True).items():
            t[k] = v
    doc = bump_policy(db, dev, mutate, parent.email, client_ip(request), _audit_fn)
    _notify_policy(dev.id, doc)
    return doc


@app.post("/policy/{device_id}/apps", status_code=201)
def add_app_rule(device_id: int, body: AppRuleIn, request: Request,
                 pair=Depends(get_session), db: Session = Depends(get_db)):
    parent, sess = pair
    check_csrf(request, sess)
    dev = owned_device(db, parent, device_id)
    if body.action not in ("block", "allow"):
        raise HTTPException(422, "action must be block|allow")
    rule = {**body.model_dump(), "id": uuid.uuid4().hex[:8],
            "name": body.name.lower(), "set_at": datetime.utcnow().isoformat() + "Z"}

    def mutate(doc):
        doc.setdefault("apps", []).append(rule)
    doc = bump_policy(db, dev, mutate, parent.email, client_ip(request), _audit_fn)
    _notify_policy(dev.id, doc)
    return rule


@app.delete("/policy/{device_id}/apps/{rule_id}")
def delete_app_rule(device_id: int, rule_id: str, request: Request,
                    pair=Depends(get_session), db: Session = Depends(get_db)):
    parent, sess = pair
    check_csrf(request, sess)
    dev = owned_device(db, parent, device_id)

    def mutate(doc):
        doc["apps"] = [r for r in doc.get("apps", []) if r.get("id") != rule_id]
    doc = bump_policy(db, dev, mutate, parent.email, client_ip(request), _audit_fn)
    _notify_policy(dev.id, doc)
    return {"deleted": rule_id}


@app.post("/policy/{device_id}/web", status_code=201)
def add_web_rule(device_id: int, body: WebRuleIn, request: Request,
                 pair=Depends(get_session), db: Session = Depends(get_db)):
    parent, sess = pair
    check_csrf(request, sess)
    dev = owned_device(db, parent, device_id)
    dom = normalize_domain(body.domain)
    if not dom:
        raise HTTPException(422, "invalid domain")
    if body.action == "block":
        row = get_or_create_policy(db, dev)
        if is_never_blocked(dom, row.document.get("web", {}).get("never_block", [])):
            raise HTTPException(400, "domain is on the never-block list (NT6) and cannot be blocked")
    rule = {"id": uuid.uuid4().hex[:8], "domain": dom, "action": body.action,
            "set_at": datetime.utcnow().isoformat() + "Z"}

    def mutate(doc):
        doc.setdefault("web", {}).setdefault("rules", []).append(rule)
    doc = bump_policy(db, dev, mutate, parent.email, client_ip(request), _audit_fn)
    _notify_policy(dev.id, doc)
    return rule


@app.delete("/policy/{device_id}/web/{rule_id}")
def delete_web_rule(device_id: int, rule_id: str, request: Request,
                    pair=Depends(get_session), db: Session = Depends(get_db)):
    parent, sess = pair
    check_csrf(request, sess)
    dev = owned_device(db, parent, device_id)

    def mutate(doc):
        web = doc.setdefault("web", {})
        web["rules"] = [r for r in web.get("rules", []) if r.get("id") != rule_id]
    doc = bump_policy(db, dev, mutate, parent.email, client_ip(request), _audit_fn)
    _notify_policy(dev.id, doc)
    return {"deleted": rule_id}


@app.put("/policy/{device_id}/web-settings")
def put_web_settings(device_id: int, body: WebSettingsIn, request: Request,
                     pair=Depends(get_session), db: Session = Depends(get_db)):
    parent, sess = pair
    check_csrf(request, sess)
    dev = owned_device(db, parent, device_id)
    from shared.contract import DOMAIN_CATEGORIES
    if body.category_policy is not None:
        for k, v in body.category_policy.items():
            if k not in DOMAIN_CATEGORIES or v not in ("allow", "block"):
                raise HTTPException(422, f"invalid category policy entry: {k}={v}")

    def mutate(doc):
        web = doc.setdefault("web", {})
        if body.category_policy is not None:
            web.setdefault("category_policy", {}).update(body.category_policy)
        if body.safesearch is not None:
            web["safesearch"] = body.safesearch
        if body.never_block is not None:
            web["never_block"] = sorted({normalize_domain(d) for d in body.never_block if normalize_domain(d)})
    doc = bump_policy(db, dev, mutate, parent.email, client_ip(request), _audit_fn)
    _notify_policy(dev.id, doc)
    return doc


# ------------------------------------------------------------------ parent: commands/requests/reports/audit
@app.post("/commands", status_code=201)
async def create_command(body: CommandIn, request: Request, pair=Depends(get_session),
                         db: Session = Depends(get_db)):
    parent, sess = pair
    check_csrf(request, sess)
    if body.type not in COMMAND_TYPES:
        raise HTTPException(422, f"unknown command type; allowed: {COMMAND_TYPES}")
    dev = owned_device(db, parent, body.device_id)
    c = Command(device_id=dev.id, type=body.type, payload=body.payload,
                created_by=parent.email)
    db.add(c)
    db.flush()
    audit(db, parent, parent.email, "command.create", client_ip(request),
          new={"device_id": dev.id, "type": body.type})
    db.commit()
    db.refresh(c)
    sent = await manager.send(dev.id, {"type": "command", "command": cmd_dict(c)})
    if sent:
        c.status = "sent"
        db.commit()
    return {**cmd_dict(c), "ws_sent": sent}


@app.get("/requests")
def list_requests(status: str | None = None, parent: Parent = Depends(get_current_parent),
                  db: Session = Depends(get_db)):
    q = (db.query(ChildRequest).join(Device).join(Child)
         .filter(Child.parent_id == parent.id))
    if status:
        q = q.filter(ChildRequest.status == status)
    return [req_dict(r) for r in q.order_by(ChildRequest.id.desc()).limit(100)]


@app.post("/requests/{req_id}/decide")
async def decide_request(req_id: int, body: DecideIn, request: Request,
                         pair=Depends(get_session), db: Session = Depends(get_db)):
    parent, sess = pair
    check_csrf(request, sess)
    if body.decision not in ("approved", "rejected"):
        raise HTTPException(422, "decision must be approved|rejected")
    r = (db.query(ChildRequest).join(Device).join(Child)
         .filter(ChildRequest.id == req_id, Child.parent_id == parent.id).first())
    if not r:
        raise HTTPException(404, "request not found")
    if r.status != "pending":
        raise HTTPException(409, "already decided")
    r.status = body.decision
    r.decision_note = body.note
    r.decided_at = datetime.utcnow()
    followups = []
    if body.decision == "approved" and r.type == "extra_time" and r.minutes:
        c = Command(device_id=r.device_id, type="grant_extra",
                    payload={"minutes": r.minutes}, created_by=parent.email)
        db.add(c)
        db.flush()
        followups.append(cmd_dict(c))
    if body.decision == "approved" and r.type == "false_block" and r.subject:
        subj = normalize_domain(r.subject) or r.subject.lower()
        dev = db.get(Device, r.device_id)

        def mutate(doc, subj=subj):
            if "." in subj:
                doc.setdefault("web", {}).setdefault("rules", []).append(
                    {"id": uuid.uuid4().hex[:8], "domain": subj, "action": "allow",
                     "set_at": datetime.utcnow().isoformat() + "Z"})
            else:
                doc.setdefault("apps", []).append(
                    {"id": uuid.uuid4().hex[:8], "name": subj, "sha256": None,
                     "action": "allow", "category": "khac", "windows": [],
                     "daily_cap_min": None,
                     "set_at": datetime.utcnow().isoformat() + "Z"})
        doc = bump_policy(db, dev, mutate, parent.email, client_ip(request), _audit_fn)
        _notify_policy(dev.id, doc)
    audit(db, parent, parent.email, "request.decide", client_ip(request),
          new={"request_id": req_id, "decision": body.decision})
    db.commit()
    for c in followups:
        await manager.send(r.device_id, {"type": "command", "command": c})
    await manager.send(r.device_id, {"type": "request_decided", "request": req_dict(r)})
    return {**req_dict(r), "followup_commands": followups}


@app.get("/reports/{device_id}")
def report_daily(device_id: int, date: str | None = Query(default=None),
                 parent: Parent = Depends(get_current_parent), db: Session = Depends(get_db)):
    dev = owned_device(db, parent, device_id)
    d = datetime.strptime(date, "%Y-%m-%d").date() if date else datetime.now().date()
    out = _daily_report(db, dev.id, d)
    out["requests"] = [req_dict(r) for r in db.query(ChildRequest)
                       .filter_by(device_id=dev.id).order_by(ChildRequest.id.desc()).limit(20)]
    return out


@app.get("/reports/{device_id}/week")
def report_week(device_id: int, end: str | None = Query(default=None),
                parent: Parent = Depends(get_current_parent), db: Session = Depends(get_db)):
    dev = owned_device(db, parent, device_id)
    end_d = datetime.strptime(end, "%Y-%m-%d").date() if end else datetime.now().date()
    days = []
    for i in range(6, -1, -1):
        d = end_d - timedelta(days=i)
        rep = _daily_report(db, dev.id, d)
        days.append({"date": str(d), "total_app_minutes": rep["total_app_minutes"],
                     "blocks": rep["blocks"]})
    return {"device_id": dev.id, "days": days}


@app.get("/audit")
def list_audit(parent: Parent = Depends(get_current_parent), db: Session = Depends(get_db)):
    q = db.query(AuditLog)
    if parent.role != "admin":
        q = q.filter(AuditLog.parent_id == parent.id)  # không lộ log của phụ huynh khác
    rows = q.order_by(AuditLog.id.desc()).limit(200).all()
    return [{"id": a.id, "actor": a.actor, "role": a.role, "action": a.action, "ip": a.ip,
             "old": a.old, "new": a.new, "ts": a.ts.isoformat() if a.ts else None}
            for a in rows]


@app.get("/domains")
def list_domains(q: str = "", category: str | None = None,
                 parent: Parent = Depends(get_current_parent), db: Session = Depends(get_db)):
    query = db.query(DomainCategory)
    if category:
        query = query.filter_by(category=category)
    if q:
        query = query.filter(DomainCategory.domain.like(f"%{q.lower()}%"))
    rows = query.order_by(DomainCategory.domain).limit(500).all()
    return [{"domain": r.domain, "category": r.category, "note": r.note} for r in rows]


@app.get("/admin/overview")
def admin_overview(parent: Parent = Depends(get_current_parent), db: Session = Depends(get_db)):
    if parent.role != "admin":
        raise HTTPException(403, "admin only")
    return {"parents": db.query(Parent).count(), "children": db.query(Child).count(),
            "devices": db.query(Device).count(), "events": db.query(UsageEvent).count()}


# ------------------------------------------------------------------ websocket
@app.websocket("/ws/device")
async def ws_device(ws: WebSocket, token: str = ""):
    db = SessionLocal()
    try:
        dev = db.query(Device).filter_by(access_token_hash=hash_token(token),
                                         revoked=False).first()
    finally:
        db.close()
    if not dev:
        await ws.close(code=4401)
        return
    did = dev.id
    await manager.connect(did, ws)
    db = SessionLocal()
    try:
        d = db.get(Device, did)
        if d:
            d.last_seen = datetime.utcnow()
            db.commit()
        while True:
            msg = await ws.receive_json()
            if msg.get("type") == "ping":
                await ws.send_json({"type": "pong"})
            elif msg.get("type") == "ack" and msg.get("command_id"):
                c = db.get(Command, int(msg["command_id"]))
                if c and c.device_id == did:
                    c.status = "done"
                    c.ack_at = datetime.utcnow()
                    db.commit()
    except WebSocketDisconnect:
        pass
    finally:
        db.close()
        manager.disconnect(did, ws)
