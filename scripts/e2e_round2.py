"""VÒNG 2 — Kiểm thử tích hợp đầu-cuối: server thật (uvicorn) + agent thật
(console runtime) trên cùng máy Linux; phần Windows (Service/LockWorkStation/
tray icon) được thay bằng các điểm kiểm chứng tương đương và ghi rõ.

Chạy:  .venv/bin/python scripts/e2e_round2.py
"""
import base64
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

TMP = tempfile.mkdtemp(prefix="ogk-e2e-")
AGENT_HOME = os.path.join(TMP, "programdata")
os.environ["ProgramData"] = AGENT_HOME
MASTER = base64.b64encode(b"E" * 32).decode()

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail if not ok else ''}")


def wait_health(port, https=False, timeout=20):
    import requests
    url = f"{'https' if https else 'http'}://127.0.0.1:{port}/health"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if requests.get(url, timeout=2, verify=False).status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.3)
    return False


def start_server(port, db_path, extra_env=None, tls=None):
    env = {**os.environ, "OGK_DB_PATH": db_path, "OGK_MASTER_KEY": MASTER,
           "PYTHONPATH": ROOT}
    if extra_env:
        env.update(extra_env)
    # Dùng chính interpreter đang chạy script này (đúng trên mọi OS: Windows là
    # .venv\Scripts\python.exe, Linux/macOS là .venv/bin/python) — bản cũ ghi
    # cứng đường dẫn Unix ".venv/bin/python" nên Windows báo WinError 2.
    cmd = [sys.executable, "-m", "uvicorn",
           "app.main:app", "--host", "127.0.0.1", "--port", str(port)]
    if tls:
        cmd += ["--ssl-keyfile", tls[0], "--ssl-certfile", tls[1]]
    proc = subprocess.Popen(cmd, cwd=os.path.join(ROOT, "server"), env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert wait_health(port, https=bool(tls)), f"server :{port} did not start"
    return proc


class Parent:
    def __init__(self, base):
        import requests
        self.s = requests.Session()
        self.base = base
        self.csrf = None

    def call(self, method, path, body=None, csrf=True):
        headers = {"X-CSRF-Token": self.csrf} if csrf and self.csrf else {}
        r = self.s.request(method, self.base + path, json=body, headers=headers,
                           verify=False)
        return r

    def register_login(self, email, password="Parent12345"):
        r = self.call("POST", "/auth/register", {"email": email, "password": password},
                      csrf=False)
        assert r.status_code == 201, r.text
        r = self.call("POST", "/auth/login", {"email": email, "password": password},
                      csrf=False)
        assert r.status_code == 200, r.text
        self.csrf = r.json()["csrf_token"]
        return r.json()


def main():
    import requests

    # ---------------------------------------------------------- pha HTTP
    db1 = os.path.join(TMP, "ogk1.db")
    server = start_server(8123, db1)
    base = "http://127.0.0.1:8123"
    try:
        parent = Parent(base)
        login = parent.register_login("phuhuynh@example.com")
        check("Đăng ký + đăng nhập phụ huynh (cookie + CSRF)", bool(parent.csrf))
        r = parent.call("POST", "/children", {"name": "Be An", "dob": "2017-05-01"})
        child = r.json()
        r = parent.call("POST", "/pairing-codes", {"child_id": child["id"]})
        code = r.json()["code"]
        check("Tạo mã ghép đôi 8 ký tự", len(code) == 8)

        env = {**os.environ, "ProgramData": AGENT_HOME, "PYTHONPATH": ROOT}
        proc = subprocess.run(
            [sys.executable, "-m", "agent.enroll",
             "--server", base, "--code", code, "--device-name", "May phong be"],
            env=env, capture_output=True, text=True)
        check("enroll.py ghép đôi bằng mã (không dùng mật khẩu phụ huynh)",
              proc.returncode == 0, proc.stderr[-300:])

        from agent.service import build_runtime  # noqa: E402
        fatal = {"fired": False}
        rt = build_runtime(on_fatal=lambda: fatal.update(fired=True))
        ctl, pm, store, hub = rt["controller"], rt["pm"], rt["store"], rt["hub"]
        device_id = rt["config"]["device_id"]

        out = ctl.sync_now()
        check("Heartbeat + nhận policy v1, chữ ký HMAC hợp lệ",
              out.get("online") and pm.version() == 1, str(out))

        r = parent.call("PUT", f"/policy/{device_id}/time", {"quota_weekday_min": 3})
        check("Phụ huynh đổi quota -> policy v2", r.status_code == 200 and r.json()["version"] == 2)
        ctl.sync_now()
        check("Agent tự áp policy v2 sau heartbeat (<= 60s theo chu kỳ)",
              pm.version() == 2 and pm.time_cfg()["quota_weekday_min"] == 3)

        store.queue_event("app_stop", "game.exe", 600, pm.version())
        store.queue_event("domain_query", "youtube.com", 0, pm.version())
        ctl.sync_now()
        rep = parent.call("GET", f"/reports/{device_id}").json()
        check("Sự kiện lên server, báo cáo có số liệu",
              rep["total_app_minutes"] == 10 and rep["top_domains"][0]["domain"] == "youtube.com",
              json.dumps(rep)[:200])
        with store._lock:
            store._conn.execute("UPDATE events SET sent = 0")
            store._conn.commit()
        ctl.sync_now()  # mô phỏng mất phản hồi -> gửi lại
        rep2 = parent.call("GET", f"/reports/{device_id}").json()
        check("Gửi lại sự kiện không bị đếm trùng (idempotency)",
              rep2["total_app_minutes"] == 10 and rep2["event_count"] == rep["event_count"])

        # --- lệnh khẩn qua WebSocket: đo độ trễ
        rt["ipc"].start()
        rt["listener"].start()
        stop_drain = threading.Event()

        def drainer():
            while not stop_drain.is_set():
                ctl._drain_commands()
                time.sleep(0.05)
        threading.Thread(target=drainer, daemon=True).start()
        hub.drain()
        t0 = time.time()
        r = parent.call("POST", "/commands", {"device_id": device_id, "type": "lock_now"})
        assert r.status_code == 201, r.text
        cmd_id = r.json()["id"]
        got = None
        while time.time() - t0 < 5:
            for note in hub.drain():
                if note.get("kind") == "locked":
                    got = note
                    break
            if got:
                break
            time.sleep(0.05)
        latency = time.time() - t0
        print(f"  latency_ms lock_now = {latency * 1000:.0f}")
        check("Lệnh khóa khẩn qua WebSocket đến agent < 5 giây",
              got is not None and latency < 5, f"latency={latency:.2f}s got={got}")
        time.sleep(0.5)  # chờ ack REST
        conn = sqlite3.connect(db1)
        row = conn.execute("SELECT status FROM commands WHERE id = ?", (cmd_id,)).fetchone()
        conn.close()
        check("Agent ack lệnh -> server ghi done", row and row[0] == "done", str(row))

        # --- đo trễ mở khóa + cộng giờ: đo tới khi agent ÁP XONG lệnh (không
        # chỉ nhận lệnh) — trạng thái keeper phải thay đổi thật.
        t0 = time.time()
        r = parent.call("POST", "/commands", {"device_id": device_id, "type": "unlock"})
        assert r.status_code == 201, r.text
        applied = False
        while time.time() - t0 < 5:
            if ctl.keeper.override_left() > 0:
                applied = True
                break
            time.sleep(0.05)
        latency = time.time() - t0
        print(f"  latency_ms unlock = {latency * 1000:.0f}")
        check("Lệnh mở khóa qua WebSocket: agent áp xong < 5 giây",
              applied and latency < 5, f"latency={latency:.2f}s")

        extra_before = ctl.keeper.extra_today()
        t0 = time.time()
        r = parent.call("POST", "/commands", {"device_id": device_id,
                                              "type": "grant_extra",
                                              "payload": {"minutes": 15}})
        assert r.status_code == 201, r.text
        applied = False
        while time.time() - t0 < 5:
            if ctl.keeper.extra_today() >= extra_before + 900:
                applied = True
                break
            time.sleep(0.05)
        latency = time.time() - t0
        print(f"  latency_ms grant_extra = {latency * 1000:.0f}")
        check("Lệnh cộng giờ qua WebSocket: agent áp xong (+900s) < 5 giây",
              applied and latency < 5, f"latency={latency:.2f}s")
        stop_drain.set()
        rt["listener"].stop()

        ctl._on_alert("clock_tamper", {"skew_seconds": -10800})
        rows = parent.call("GET", "/audit").json()
        check("Cảnh báo chỉnh giờ lên audit của phụ huynh",
              any(a["action"] == "alert.clock_tamper" for a in rows))

        # --- IPC cho tray
        from agent.ipc import IPCClient
        ipc = IPCClient(rt["config"]["ipc_token"])
        st = ipc.call("get_status")
        check("IPC get_status (tray đọc qua service)", st["policy_version"] == 2, json.dumps(st)[:150])
        res = ipc.call("send_request", type="extra_time", minutes=20, reason="sap xong bai")
        reqs = parent.call("GET", "/requests?status=pending").json()
        check("IPC send_request -> phụ huynh thấy yêu cầu xin thêm giờ",
              res.get("sent") and any(q["minutes"] == 20 for q in reqs), str(res))
        ipc.call("tray_ready", icon_ok=False)
        time.sleep(0.5)
        check("Tray không hiện được icon -> service nhận lệnh tự dừng (F5)", fatal["fired"])
        rt["ipc"].stop()

        # --- mất mạng: đệm sự kiện, có mạng lại: đồng bộ đúng 1 lần
        server.terminate()
        server.wait(timeout=10)
        store.queue_event("app_stop", "word.exe", 300, pm.version())
        out = ctl.sync_now()
        queued = len(store.pop_queued_events(10))
        check("Mất mạng: sync thất bại êm, sự kiện vẫn nằm trong hàng đợi",
              not out.get("online") and queued >= 1)
        server = start_server(8123, db1)
        ctl.sync_now()
        rep3 = parent.call("GET", f"/reports/{device_id}").json()
        check("Có mạng lại: sự kiện đệm được đồng bộ, tổng 15 phút",
              rep3["total_app_minutes"] == 15, json.dumps(rep3)[:200])

        # --- xóa toàn bộ dữ liệu
        r = parent.call("DELETE", f"/children/{child['id']}/data")
        n_deleted = r.json()["events_deleted"]
        ctl.sync_now()  # nhận lệnh wipe_cache qua heartbeat
        remaining = len(store.pop_queued_events(100)) + len(store.day_events(0, 4102444800))
        rep4 = parent.call("GET", f"/reports/{device_id}").json()
        check("Xóa toàn bộ dữ liệu: server sạch + agent wipe bộ đệm",
              n_deleted >= 3 and rep4["event_count"] == 0 and remaining == 0,
              f"deleted={n_deleted} local_remaining={remaining}")

        # --- dashboard
        html = requests.get(base + "/", timeout=5).text
        check("Dashboard phục vụ tại / và không dùng localStorage",
              "OpenGuard Kids" in html and "localStorage" not in html)
    finally:
        try:
            server.terminate()
        except Exception:
            pass

    # ---------------------------------------------------------- pha TLS + ghim chứng chỉ
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime as _dt
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_dt.datetime.utcnow() - _dt.timedelta(days=1))
            .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                                        x509.IPAddress(__import__("ipaddress").IPv4Address("127.0.0.1"))]),
                           critical=False)
            .sign(key, hashes.SHA256()))
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption())
    cert_path, key_path = os.path.join(TMP, "cert.pem"), os.path.join(TMP, "key.pem")
    open(cert_path, "wb").write(cert_pem)
    open(key_path, "wb").write(key_pem)
    import hashlib
    fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()

    db2 = os.path.join(TMP, "ogk2.db")
    server2 = start_server(8124, db2, extra_env={"OGK_TLS_CERT": cert_path},
                           tls=(key_path, cert_path))
    base2 = "https://127.0.0.1:8124"
    try:
        parent2 = Parent(base2)
        login2 = parent2.register_login("tls@example.com")
        check("Server TLS: login trả server_cert_fingerprint khớp chứng chỉ",
              login2.get("server_cert_fingerprint") == fingerprint,
              str(login2.get("server_cert_fingerprint")))
        r = parent2.call("POST", "/children", {"name": "Be TLS"})
        child2 = r.json()
        code2 = parent2.call("POST", "/pairing-codes", {"child_id": child2["id"]}).json()["code"]

        from agent.client import ServerClient, redeem_pairing
        data = redeem_pairing(base2, code2, "May TLS", cert_fingerprint=fingerprint)
        check("Ghép đôi qua HTTPS với fingerprint đúng", data["device_id"] > 0)
        good = ServerClient(base2, data["access_token"], data["refresh_token"],
                            cert_fingerprint=fingerprint)
        check("Agent ghim chứng chỉ đúng -> heartbeat OK",
              good.heartbeat({}) is not None)
        bad = ServerClient(base2, data["access_token"], data["refresh_token"],
                           cert_fingerprint="00" * 32)
        try:
            bad.heartbeat({})
            check("Agent ghim chứng chỉ sai -> từ chối kết nối", False, "no SSLError")
        except Exception as exc:
            check("Agent ghim chứng chỉ sai -> từ chối kết nối",
                  "pinning mismatch" in str(exc) or "SSLError" in type(exc).__name__, str(exc))
    finally:
        server2.terminate()

    failed = [r for r in RESULTS if not r[1]]
    print(f"\n==== VÒNG 2: {len(RESULTS) - len(failed)}/{len(RESULTS)} PASS ====")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
