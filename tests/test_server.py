# OpenGuard Kids v2 — bộ test server (vòng 1: unit + contract + API).
# Chạy: .venv/bin/python -m pytest tests/ -v
import time
import uuid

import pyotp
from fastapi.testclient import TestClient

from app.main import app, purge_old_data
from app.models import PairingCode, SessionLocal
from shared.contract import verify_policy

PW = "Test12345!"


class ParentSession:
    """Một phụ huynh với TestClient riêng (cookie tách biệt) + CSRF tự động."""

    def __init__(self, email=None, password=PW, totp=False):
        self.client = TestClient(app)
        self.email = email or f"parent-{uuid.uuid4().hex[:10]}@example.com"
        self.password = password
        r = self.client.post("/auth/register",
                             json={"email": self.email, "password": password,
                                   "enable_totp": totp})
        assert r.status_code == 201, r.text
        self.totp_uri = r.json().get("totp_uri")
        self.csrf = None

    def login(self, password=None, totp_code=None):
        body = {"email": self.email, "password": password or self.password}
        if totp_code:
            body["totp"] = totp_code
        r = self.client.post("/auth/login", json=body)
        if r.status_code == 200:
            self.csrf = r.json()["csrf_token"]
        return r

    def login_ok(self):
        r = self.login()
        assert r.status_code == 200, r.text
        return r

    def _h(self, csrf=True):
        return {"X-CSRF-Token": self.csrf} if csrf and self.csrf else {}

    def post(self, url, json=None, csrf=True):
        return self.client.post(url, json=json or {}, headers=self._h(csrf))

    def put(self, url, json=None, csrf=True):
        return self.client.put(url, json=json or {}, headers=self._h(csrf))

    def delete(self, url, csrf=True):
        return self.client.delete(url, headers=self._h(csrf))

    def get(self, url):
        return self.client.get(url)

    def add_child(self, name="Be An"):
        r = self.post("/children", {"name": name, "dob": "2017-05-01"})
        assert r.status_code == 201, r.text
        return r.json()

    def pair_device(self, child_id, name="May cua be"):
        r = self.post("/pairing-codes", {"child_id": child_id})
        assert r.status_code == 201, r.text
        code = r.json()["code"]
        assert len(code) == 8
        c = TestClient(app)
        r = c.post("/pairing/redeem", json={"code": code, "device_name": name,
                                            "fingerprint": "fp-test-123"})
        assert r.status_code == 201, r.text
        return r.json()


def dev_headers(dev, token_key="access_token"):
    return {"Authorization": f"Bearer {dev[token_key]}"}


def enrolled_parent():
    p = ParentSession()
    p.login_ok()
    child = p.add_child()
    dev = p.pair_device(child["id"])
    return p, child, dev


def push_events(dev, events):
    c = TestClient(app)
    return c.post("/device/events", json={"events": events}, headers=dev_headers(dev))


def ev(type_, subject="", duration=0, ts=None, policy_id=1):
    return {"event_id": uuid.uuid4().hex, "ts": ts or time.time(), "type": type_,
            "subject": subject, "duration_sec": duration, "policy_id": policy_id}


# ----------------------------------------------------------------------
def test_password_min_length_and_csrf():
    c = TestClient(app)
    r = c.post("/auth/register", json={"email": f"x-{uuid.uuid4().hex[:6]}@e.com",
                                       "password": "Short123!"})  # 9 ký tự
    assert r.status_code == 422, r.text
    p = ParentSession()
    p.login_ok()
    r = p.post("/children", {"name": "Be"}, csrf=False)
    assert r.status_code == 403, r.text  # thiếu CSRF -> chặn
    r = p.post("/children", {"name": "Be"})
    assert r.status_code == 201, r.text


def test_logout_revokes_session():
    p = ParentSession()
    p.login_ok()
    assert p.get("/auth/me").status_code == 200
    r = p.post("/auth/logout")
    assert r.status_code == 200, r.text
    assert p.get("/auth/me").status_code == 401  # phiên đã hủy phía server


def test_login_lockout_after_5_failures():
    p = ParentSession()
    for _ in range(5):
        r = p.login(password="WrongPass123")
        assert r.status_code == 401, r.text
    r = p.login()  # đúng mật khẩu nhưng tài khoản đang khóa tạm
    assert r.status_code == 423, r.text


def test_totp_flow():
    p = ParentSession(totp=True)
    assert p.totp_uri and "secret=" in p.totp_uri
    secret = p.totp_uri.split("secret=")[1].split("&")[0]
    r = p.login()
    assert r.status_code == 401  # thiếu TOTP
    r = p.login(totp_code=pyotp.TOTP(secret).now())
    assert r.status_code == 200, r.text


def test_pairing_flow_and_signed_policy():
    p, child, dev = enrolled_parent()
    assert dev["child_id"] == child["id"] and len(dev["policy_key"]) == 64
    c = TestClient(app)
    r = c.post("/device/heartbeat", json={"policy_version": 0}, headers=dev_headers(dev))
    assert r.status_code == 200 and r.json()["latest_policy_version"] == 1, r.text
    r = c.post("/device/heartbeat", json={})
    assert r.status_code == 401
    r = c.get("/device/policy", headers=dev_headers(dev))
    doc = r.json()
    assert verify_policy(doc, dev["policy_key"]), "policy phải ký đúng HMAC"
    assert doc["time"]["quota_weekday_min"] == 90
    blocked = set(doc["web"]["blocked_domains"])
    assert "facebook.com" in blocked          # mang_xa_hoi: block theo mặc định 6-11
    assert "youtube.com" in blocked           # bản chính YouTube xếp mang_xa_hoi (không dành cho <13)
    assert "youtubekids.com" not in blocked   # YouTube Kids mới thuộc giai_tri: allow
    assert not any(d.endswith(".gov.vn") for d in blocked)  # NT6
    assert "hcmus.edu.vn" not in blocked
    # mã ghép đôi dùng lại -> 404
    codes = [pc for pc in _pairing_rows(p)]
    r = c.post("/pairing/redeem", json={"code": codes[0], "device_name": "x",
                                        "fingerprint": "y"})
    assert r.status_code == 404, r.text


def _pairing_rows(_parent):
    db = SessionLocal()
    try:
        return [r.code_hash for r in db.query(PairingCode).all()]
    finally:
        db.close()


def test_policy_update_bumps_version_audit_and_idor():
    p, child, dev = enrolled_parent()
    did = dev["device_id"]
    r = p.put(f"/policy/{did}/time", {"quota_weekday_min": 3})
    assert r.status_code == 200, r.text
    doc = r.json()
    assert doc["version"] == 2 and doc["time"]["quota_weekday_min"] == 3
    assert verify_policy(doc, dev["policy_key"])
    r = p.get("/audit")
    rows = [a for a in r.json() if a["action"] == "policy.update"]
    assert rows and rows[0]["old"]["time"]["quota_weekday_min"] == 90
    assert rows[0]["new"]["time"]["quota_weekday_min"] == 3
    assert rows[0]["ip"]
    # IDOR: phụ huynh khác không xem/sửa được, audit không lộ chéo
    q = ParentSession()
    q.login_ok()
    assert q.get(f"/policy/{did}").status_code == 404
    assert q.put(f"/policy/{did}/time", {"quota_weekday_min": 1}).status_code == 404
    assert all(a["action"] != "policy.update" for a in q.get("/audit").json())


def test_never_block_cannot_be_blocked():
    p, child, dev = enrolled_parent()
    did = dev["device_id"]
    r = p.post(f"/policy/{did}/web", {"domain": "moet.gov.vn", "action": "block"})
    assert r.status_code == 400, r.text  # .gov.vn miễn chặn vĩnh viễn
    r = p.post(f"/policy/{did}/web", {"domain": "abc.edu.vn", "action": "block"})
    assert r.status_code == 400, r.text  # .edu.vn (cổng trường học) miễn chặn cứng
    r = p.post(f"/policy/{did}/web", {"domain": "tongdai111.vn", "action": "block"})
    assert r.status_code == 400, r.text  # Tổng đài 111: miền .vn, miễn chặn đích danh
    r = p.put(f"/policy/{did}/web-settings", {"never_block": ["truongbe.edu.vn"]})
    assert r.status_code == 200, r.text
    r = p.post(f"/policy/{did}/web", {"domain": "portal.truongbe.edu.vn", "action": "block"})
    assert r.status_code == 400, r.text  # cổng trường đã khai báo -> miễn chặn


def test_access_token_expiry_enforced():
    from datetime import datetime, timedelta

    from app.models import Device, SessionLocal
    p, child, dev = enrolled_parent()
    c = TestClient(app)
    h = dev_headers(dev)
    assert c.get("/child/summary", headers=h).status_code == 200  # còn hạn -> 200
    db = SessionLocal()
    row = db.query(Device).filter_by(id=dev["device_id"]).first()
    delta = (row.access_expires_at - datetime.utcnow()).total_seconds()
    assert 895 <= delta <= 905, delta  # hạn = now + 15 phút, sai số <= 5s
    row.access_expires_at = datetime.utcnow() - timedelta(seconds=1)
    db.commit()
    db.close()
    assert c.get("/child/summary", headers=h).status_code == 401  # hết hạn -> 401


def test_child_audit_has_old_and_masked_ip():
    from app.main import _mask_ip
    assert _mask_ip("113.161.20.5") == "113.161.x.x"
    assert _mask_ip("2001:db8:aaaa:bbbb::1").startswith("2001:db8:")
    assert _mask_ip(None) is None
    p, child, dev = enrolled_parent()
    did = dev["device_id"]
    r = p.put(f"/policy/{did}/time", {"quota_weekday_min": 111})
    assert r.status_code == 200, r.text
    c = TestClient(app)
    rows = c.get("/child/audit", headers=dev_headers(dev)).json()
    upd = [a for a in rows if a["action"] == "policy.update"]
    assert upd, rows
    assert "old" in upd[0] and upd[0]["new"] is not None and "ip" in upd[0]


def test_refresh_rotation_and_revoke():
    p, child, dev = enrolled_parent()
    c = TestClient(app)
    r = c.post("/device/refresh", json={"refresh_token": dev["refresh_token"]})
    assert r.status_code == 200, r.text
    new_access = r.json()["access_token"]
    r = c.post("/device/heartbeat", json={}, headers={"Authorization": f"Bearer {new_access}"})
    assert r.status_code == 200
    r = c.post("/device/heartbeat", json={}, headers=dev_headers(dev))  # access cũ đã bị thay
    assert r.status_code == 401
    dev2 = {**dev, "access_token": new_access}
    r = p.post(f"/devices/{dev['device_id']}/revoke")
    assert r.status_code == 200, r.text
    r = c.post("/device/heartbeat", json={}, headers=dev_headers(dev2))
    assert r.status_code == 401
    r = c.post("/device/refresh", json={"refresh_token": dev["refresh_token"]})
    assert r.status_code == 401


def test_events_schema_dedupe_and_subject_normalization():
    p, child, dev = enrolled_parent()
    events = [ev("app_stop", "game.exe", 1800), ev("domain_query", "www.youtube.com")]
    r = push_events(dev, events)
    assert r.status_code == 201 and r.json() == {"accepted": 2, "duplicates": 0}, r.text
    r = push_events(dev, events)  # gửi lại nguyên lô (mất phản hồi) -> không đếm trùng
    assert r.json() == {"accepted": 0, "duplicates": 2}, r.text
    bad = ev("app_stop", "x.exe", 1)
    bad["url"] = "http://example.com/full"  # trường ngoài lược đồ F3
    r = push_events(dev, [bad])
    assert r.status_code == 422, r.text
    bad2 = ev("keylog", "x", 0)
    r = push_events(dev, [bad2])
    assert r.status_code == 422, r.text
    rep = p.get(f"/reports/{dev['device_id']}").json()
    assert rep["top_domains"][0] == {"domain": "youtube.com", "queries": 1}


def test_reports_daily_and_week():
    p, child, dev = enrolled_parent()
    now = time.time()
    events = [ev("app_stop", "game.exe", 1800, now), ev("app_stop", "word.exe", 600, now),
              ev("domain_query", "youtube.com", 0, now), ev("domain_query", "youtube.com", 0, now),
              ev("domain_query", "facebook.com", 0, now),
              ev("blocked_app", "game.exe", 0, now), ev("blocked_app", "game.exe", 0, now),
              ev("blocked_domain", "facebook.com", 0, now)]
    assert push_events(dev, events).status_code == 201
    rep = p.get(f"/reports/{dev['device_id']}").json()
    assert rep["total_app_minutes"] == 40, rep
    assert rep["top_apps"][0] == {"app": "game.exe", "minutes": 30.0}
    assert rep["top_domains"][0] == {"domain": "youtube.com", "queries": 2}
    assert rep["blocks"] == {"blocked_app": 2, "blocked_domain": 1}
    week = p.get(f"/reports/{dev['device_id']}/week").json()
    assert len(week["days"]) == 7 and week["days"][-1]["total_app_minutes"] == 40


def test_child_week_matches_parent_week(tmp_path):
    """NT5: báo cáo phía TRẺ (agent tự tính từ kho sự kiện cục bộ bằng
    _week_summary) phải khớp báo cáo phía PHỤ HUYNH (server) trên cùng một
    dữ liệu — số lần chặn trong ngày, top ứng dụng và tổng phút ứng dụng.
    (Phần "đã dùng/hạn mức" phía trẻ lấy từ bộ đếm quota của chính máy —
    cũng là số server nhận qua heartbeat.)"""
    p, child, dev = enrolled_parent()
    now = time.time()
    raw = [("app_stop", "game.exe", 1800), ("app_stop", "word.exe", 600),
           ("blocked_app", "game.exe", 0), ("blocked_app", "game.exe", 0),
           ("blocked_domain", "facebook.com", 0)]
    assert push_events(dev, [ev(t, s, d, now) for t, s, d in raw]).status_code == 201
    rep = p.get(f"/reports/{dev['device_id']}").json()
    week = p.get(f"/reports/{dev['device_id']}/week").json()

    from agent.local_store import LocalStore
    from agent.policy import PolicyManager
    from agent.timekeeper import TimeKeeper
    import agent.service as svc
    from shared.contract import default_policy_document
    store = LocalStore(str(tmp_path / "agent.db"))
    for t, s, d in raw:
        store.queue_event(t, s, d, ts=now)
    pm = PolicyManager(store, "")
    pm._doc = default_policy_document(1, 1)
    mine = svc._week_summary(store, TimeKeeper(store, pm))
    my_today = mine["days"][-1]
    assert my_today["blocks"] == rep["blocks"] == {"blocked_app": 2, "blocked_domain": 1}
    assert mine["top_apps"][0] == rep["top_apps"][0] == {"app": "game.exe", "minutes": 30.0}
    assert sum(a["minutes"] for a in mine["top_apps"]) == 40
    assert sum(d["total_app_minutes"] for d in week["days"]) == 40


def test_commands_via_heartbeat_and_ack():
    p, child, dev = enrolled_parent()
    r = p.post("/commands", {"device_id": dev["device_id"], "type": "lock_now"})
    assert r.status_code == 201 and r.json()["status"] == "pending", r.text
    cmd_id = r.json()["id"]
    c = TestClient(app)
    r = c.post("/device/heartbeat", json={}, headers=dev_headers(dev))
    pending = r.json()["pending_commands"]
    assert [x["id"] for x in pending] == [cmd_id]
    r = c.post("/device/heartbeat", json={}, headers=dev_headers(dev))
    assert r.json()["pending_commands"] == []  # đã sent, không phát lại
    r = c.post(f"/device/commands/{cmd_id}/ack", headers=dev_headers(dev))
    assert r.json()["status"] == "done"


def test_child_requests_extra_time_and_false_block():
    p, child, dev = enrolled_parent()
    c = TestClient(app)
    r = c.post("/device/requests", json={"type": "extra_time", "minutes": 15,
                                         "reason": "con sap xong bai"}, headers=dev_headers(dev))
    assert r.status_code == 201, r.text
    req_id = r.json()["id"]
    rows = p.get("/requests?status=pending").json()
    assert any(x["id"] == req_id for x in rows)
    r = p.post(f"/requests/{req_id}/decide", {"decision": "approved"})
    assert r.status_code == 200 and r.json()["status"] == "approved", r.text
    assert r.json()["followup_commands"] and \
        r.json()["followup_commands"][0]["type"] == "grant_extra"
    rows = c.get("/device/requests", headers=dev_headers(dev)).json()
    assert rows[0]["status"] == "approved"  # trẻ nhận được phản hồi (NT3)
    # báo chặn nhầm -> duyệt -> server tự thêm luật allow
    r = c.post("/device/requests", json={"type": "false_block", "subject": "hocmai.vn",
                                         "reason": "trang hoc bai"}, headers=dev_headers(dev))
    req2 = r.json()["id"]
    r = p.post(f"/requests/{req2}/decide", {"decision": "approved"})
    assert r.status_code == 200, r.text
    doc = p.get(f"/policy/{dev['device_id']}").json()
    assert any(x["domain"] == "hocmai.vn" and x["action"] == "allow"
               for x in doc["web"]["rules"])
    assert "hocmai.vn" not in doc["web"]["blocked_domains"]


def test_delete_child_data_wipes_server_and_notifies_agent():
    p, child, dev = enrolled_parent()
    assert push_events(dev, [ev("app_stop", "game.exe", 300)]).status_code == 201
    r = p.delete(f"/children/{child['id']}/data")
    assert r.status_code == 200 and r.json()["events_deleted"] == 1, r.text
    rep = p.get(f"/reports/{dev['device_id']}").json()
    assert rep["event_count"] == 0
    c = TestClient(app)
    hb = c.post("/device/heartbeat", json={}, headers=dev_headers(dev)).json()
    assert any(x["type"] == "wipe_cache" for x in hb["pending_commands"])


def test_child_view_summary_and_audit():
    p, child, dev = enrolled_parent()
    p.put(f"/policy/{dev['device_id']}/time", {"quota_weekday_min": 45})
    assert push_events(dev, [ev("app_stop", "word.exe", 900)]).status_code == 201
    c = TestClient(app)
    s = c.get("/child/summary", headers=dev_headers(dev)).json()
    assert s["total_app_minutes"] == 15, s
    a = c.get("/child/audit", headers=dev_headers(dev)).json()
    assert any(x["action"] == "policy.update" for x in a), a


def test_retention_purge_90_days():
    p, child, dev = enrolled_parent()
    old_ts = time.time() - 100 * 86400
    assert push_events(dev, [ev("app_stop", "old.exe", 60, old_ts),
                             ev("app_stop", "new.exe", 60)]).status_code == 201
    db = SessionLocal()
    try:
        out = purge_old_data(db)
    finally:
        db.close()
    assert out["events_deleted"] >= 1
    rep = p.get(f"/reports/{dev['device_id']}").json()
    assert rep["total_app_minutes"] == 1  # chỉ còn sự kiện hôm nay


def test_domain_catalog_seeded():
    p = ParentSession()
    p.login_ok()
    rows = p.get("/domains").json()
    assert len(rows) >= 200, len(rows)
    edu = p.get("/domains?category=giao_duc").json()
    assert len(edu) >= 60


def test_admin_overview_forbidden_for_plain_parent():
    p = ParentSession()
    p.login_ok()
    assert p.get("/admin/overview").status_code == 403


def test_login_rate_limit():
    c = TestClient(app)
    codes = set()
    for i in range(65):
        r = c.post("/auth/login", json={"email": f"nobody-{i}@example.com",
                                        "password": "Whatever123"})
        codes.add(r.status_code)
    assert 429 in codes, codes
