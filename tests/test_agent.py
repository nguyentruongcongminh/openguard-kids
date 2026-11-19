# OpenGuard Kids v2 — test agent (vòng 1): timekeeper, policy, controller, DNS, IPC.
import os
import socket
import struct
import subprocess
import threading
import time

import pytest

from agent.controller import AgentController, in_windows, sha256_of_file
from agent.dns_proxy import DnsProxy, build_nxdomain, encode_qname, parse_qname  # noqa: F401
from agent.ipc import IPCClient, IPCServer
from agent.local_store import LocalStore
from agent.policy import PolicyManager
from agent.timekeeper import TimeKeeper
from shared.contract import default_policy_document, sign_policy

KEY = "cd" * 32


class FakeClock:
    def __init__(self, wall_ts):
        self.wall = wall_ts
        self.mono = 1000.0

    def advance(self, sec):
        self.wall += sec
        self.mono += sec


def make_pm(tmp_path, mutate=None):
    store = LocalStore(tmp_path / "agent.db")
    pm = PolicyManager(store, KEY)
    doc = default_policy_document(1, 1)
    if mutate:
        mutate(doc)
    doc["signature"] = sign_policy(doc, KEY)
    assert pm.update(doc)
    return store, pm


def make_keeper(store, pm, clock, **kw):
    events, warnings, locks, alerts = [], [], [], []
    keeper = TimeKeeper(
        store, pm,
        on_warning=lambda rem, stage: warnings.append((rem, stage)),
        on_lock=lambda reason: locks.append(reason),
        on_event=lambda t, s, d: events.append((t, s, d)),
        on_alert=lambda k, det: alerts.append((k, det)),
        mono_fn=lambda: clock.mono, wall_fn=lambda: clock.wall,
        is_locked_fn=kw.get("is_locked_fn", lambda: False),
        idle_fn=kw.get("idle_fn", lambda: 0.0))
    return keeper, events, warnings, locks, alerts


# ---------------------------------------------------------------- timekeeper
def test_quota_warnings_grace_and_lock(tmp_path):
    # Thứ 2 10:00, quota 3 phút (tiêu chí nghiệm thu F1 của đề)
    from datetime import datetime
    clock = FakeClock(datetime(2026, 11, 16, 10, 0).timestamp())
    store, pm = make_pm(tmp_path, lambda d: d["time"].update(
        {"quota_weekday_min": 3, "warn_at_min": [10, 5, 1], "grace_sec": 60}))
    keeper, events, warnings, locks, _ = make_keeper(store, pm, clock)
    keeper.tick(0)
    for _ in range(119):  # dùng 119 giây
        clock.advance(1)
        keeper.tick()
    stages = [s for _, s in warnings]
    assert 5 in stages and 10 in stages
    clock.advance(1)  # tròn 120s -> còn 60s
    keeper.tick()
    assert 1 in [s for _, s in warnings]
    for _ in range(60):  # hết quota -> vào ân hạn
        clock.advance(1)
        keeper.tick()
    assert (0, 0) in warnings or any(s == 0 for _, s in warnings)
    assert not locks  # đang ân hạn, chưa khóa
    for _ in range(61):  # hết ân hạn 60s -> khóa
        clock.advance(1)
        keeper.tick()
    assert locks == ["quota"]
    assert any(t == "locked" for t, _, _ in events)
    assert any(t == "quota_warning" for t, _, _ in events)


def test_idle_and_locked_time_not_counted(tmp_path):
    from datetime import datetime
    clock = FakeClock(datetime(2026, 11, 16, 10, 0).timestamp())
    store, pm = make_pm(tmp_path)
    keeper, *_ = make_keeper(store, pm, clock, idle_fn=lambda: 400.0)
    keeper.tick(0)
    for _ in range(30):
        clock.advance(1)
        keeper.tick()
    assert keeper.used_today() == 0  # idle >= 5 phút: không đếm
    keeper2, *_ = make_keeper(store, pm, clock, is_locked_fn=lambda: True)
    keeper2.tick(0)
    for _ in range(30):
        clock.advance(1)
        keeper2.tick()
    assert keeper2.used_today() == 0  # máy khóa: không đếm


def test_weekend_quota_and_schedule_lock(tmp_path):
    from datetime import datetime
    # Thứ 7 23:30 — ngoài lịch mặc định (06:00-21:00) -> khóa theo lịch
    clock = FakeClock(datetime(2026, 11, 14, 23, 30).timestamp())
    store, pm = make_pm(tmp_path)
    keeper, events, warnings, locks, _ = make_keeper(store, pm, clock)
    assert keeper.status()["limit_min"] == 150  # quota cuối tuần
    keeper.tick(0)
    assert locks == ["schedule"]


def test_clock_tamper_detected_and_day_never_goes_back(tmp_path):
    from datetime import datetime
    clock = FakeClock(datetime(2026, 11, 16, 23, 50).timestamp())  # Thứ 2 23:50
    store, pm = make_pm(tmp_path)
    keeper, events, warnings, locks, alerts = make_keeper(store, pm, clock)
    keeper.tick(0)
    clock.advance(1200)  # qua nửa đêm -> Thứ 3 00:10 (ngày mới hợp lệ)
    keeper.tick()
    day_after = keeper.effective_date()
    assert day_after.isoformat() == "2026-11-17"
    keeper.store.kv_set(keeper._key("used_seconds", day_after), 600)
    # kẻ gian lùi đồng hồ hệ thống 3 giờ về Thứ 2 21:10
    clock.wall -= 3 * 3600
    clock.mono += 1
    keeper.tick()
    assert any(k == "clock_tamper" for k, _ in alerts), alerts
    assert keeper.effective_date() == day_after  # ngày không đi lùi
    # quota không được "hoàn": chỉ cộng đúng 1 giây trôi thật (monotonic),
    # tuyệt đối không trừ lại 3 giờ đã lùi đồng hồ.
    assert keeper.used_today() == 601


def test_extra_time_and_break(tmp_path):
    from datetime import datetime
    clock = FakeClock(datetime(2026, 11, 16, 10, 0).timestamp())
    store, pm = make_pm(tmp_path, lambda d: d["time"].update({"quota_weekday_min": 30}))
    keeper, events, *_ = make_keeper(store, pm, clock)
    keeper.tick(0)
    keeper.add_extra(15)
    assert keeper.remaining_seconds() == 45 * 60
    assert any(t == "override_granted" for t, _, _ in events)
    keeper.apply_break(15)
    for _ in range(10):
        clock.advance(1)
        keeper.tick()
    assert keeper.used_today() == 0  # đang nghỉ: không đếm


# ---------------------------------------------------------------- policy manager
def test_policy_manager_signature_version_and_web_decisions(tmp_path):
    store = LocalStore(tmp_path / "a.db")
    pm = PolicyManager(store, KEY)
    doc = default_policy_document(1, 1)
    doc["web"]["blocked_domains"] = ["facebook.com", "bet365.com"]
    doc["web"]["rules"] = [{"domain": "youtube.com", "action": "block"},
                           {"domain": "facebook.com", "action": "allow"}]
    doc["web"]["never_block"] = ["truongbe.edu.vn"]
    doc["signature"] = sign_policy(doc, KEY)
    assert pm.update(doc)
    assert pm.web_decision("www.facebook.com") == "allow"      # allow tường minh thắng
    assert pm.web_decision("m.facebook.com") == "allow"
    assert pm.web_decision("bet365.com") == "block"
    assert pm.web_decision("sub.bet365.com") == "block"        # chặn cả miền con
    assert pm.web_decision("youtube.com") == "block"           # luật block tường minh
    assert pm.web_decision("moet.gov.vn") == "allow"           # NT6: .gov.vn miễn chặn
    assert pm.web_decision("portal.truongbe.edu.vn") == "allow"
    assert pm.web_decision("example.com") == "allow"
    # bản cũ hơn -> từ chối
    assert not pm.update(doc)
    # sửa nội dung nhưng giữ chữ ký cũ -> từ chối
    doc2 = default_policy_document(1, 1)
    doc2["version"] = 99
    doc2["signature"] = doc["signature"]
    assert not pm.update(doc2)
    assert pm.version() == 1


# ---------------------------------------------------------------- controller logic
def test_hash_matching_survives_rename(tmp_path):
    import hashlib
    content = b"fake-notepad-binary-content"
    original = tmp_path / "notepad.exe"
    renamed = tmp_path / "game.exe"
    other = tmp_path / "other.exe"
    original.write_bytes(content)
    renamed.write_bytes(content)
    other.write_bytes(b"different content")
    digest = hashlib.sha256(content).hexdigest()
    store, pm = make_pm(tmp_path, lambda d: d.update(
        {"apps": [{"name": "notepad.exe", "sha256": digest, "action": "block",
                   "category": "khac", "windows": [], "daily_cap_min": None}]}))
    ctl = AgentController(store, pm, client=None)
    # đổi tên thành game.exe vẫn bị nhận diện đúng theo hash (tiêu chí F2 của đề)
    assert ctl._rule_for("game.exe", str(renamed)) is not None
    assert ctl._rule_for("notepad.exe", str(original)) is not None
    assert ctl._rule_for("game.exe", str(other)) is None
    assert sha256_of_file(str(renamed), {}) == digest


def test_in_windows():
    from datetime import datetime
    wins = [{"from": "07:00", "to": "20:00"}]
    assert in_windows(wins, datetime(2026, 1, 1, 10, 0))
    assert not in_windows(wins, datetime(2026, 1, 1, 21, 0))
    assert in_windows([], datetime(2026, 1, 1, 23, 0))
    night = [{"from": "22:00", "to": "06:00"}]
    assert in_windows(night, datetime(2026, 1, 1, 23, 30))
    assert in_windows(night, datetime(2026, 1, 1, 5, 0))
    assert not in_windows(night, datetime(2026, 1, 1, 12, 0))


def test_group_budget_blocks_process(tmp_path):
    fakebin = tmp_path / "game.exe"
    # Cần 1 chương trình thật chạy ~60s để giả làm game.exe: /bin/sleep trên
    # Linux/macOS; trên Windows dùng PING.EXE của hệ thống (ping 60 lần ~59s).
    if os.name == "nt":
        src = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "PING.EXE")
        run_args = ["-n", "60", "127.0.0.1"]
    else:
        src = "/bin/sleep"
        run_args = ["60"]
    with open(src, "rb") as f:
        fakebin.write_bytes(f.read())
    fakebin.chmod(0o755)
    store, pm = make_pm(tmp_path, lambda d: (
        d["time"].update({"group_budgets_min": {"hoc_tap": None, "giai_tri": None,
                                                "game": 0, "khac": None}}),
        d.update({"apps": [{"name": "game.exe", "sha256": None, "action": "allow",
                            "category": "game", "windows": [], "daily_cap_min": None}]})))
    notes = []
    ctl = AgentController(store, pm, client=None, on_notify=notes.append)
    proc = subprocess.Popen([str(fakebin)] + run_args)
    try:
        time.sleep(0.3)
        ctl._scan_processes(5.0)
        time.sleep(0.3)
        assert proc.poll() is not None, "tiến trình thuộc nhóm hết ngân sách phải bị dừng"
        assert any(n.get("kind") == "blocked_app" for n in notes)
    finally:
        if proc.poll() is None:
            proc.kill()


def test_session_events_duration(tmp_path):
    store, pm = make_pm(tmp_path)
    ctl = AgentController(store, pm, client=None)
    ctl._sessions["/bin/sleep"] = {"name": "sleep", "start": time.monotonic() - 125,
                                   "last_seen": time.monotonic(), "missed": 1}
    ctl._scan_processes(5.0)  # sleep thật (nếu có) khác exe path; phiên giả bị đóng
    ctl._scan_processes(5.0)
    # Lấy nhiều sự kiện: máy thật có >50 tiến trình, mỗi tiến trình sinh 1 sự
    # kiện app_start xếp trước app_stop của phiên giả — lấy 50 là bị cắt mất.
    evs = store.pop_queued_events(5000)
    stops = [e for e in evs if e["type"] == "app_stop" and e["subject"] == "sleep"]
    assert stops and 100 <= stops[0]["duration_sec"] <= 140, evs


# ---------------------------------------------------------------- DNS proxy
# Lưu ý môi trường: sandbox của máy ảo chặn syscall sendto (UDP) nên test chạy ở
# tầng xử lý gói của proxy với upstream giả (monkeypatch forward) — đúng phần
# logic ra quyết định/xây đáp án; phần socket thật kiểm chứng trên máy Windows.
import agent.dns_proxy as dns_mod


def _fake_forward(query_packet, upstream=("8.8.8.8", 53), timeout=3):
    _, qtype, qend = parse_qname(query_packet)
    tid, _flags = struct.unpack_from("!HH", query_packet, 0)
    qclass = struct.unpack_from("!H", query_packet, qend - 2)[0]
    if qtype == 1:
        answer = struct.pack("!HHHIH", 0xC00C, 1, qclass, 60, 4) + bytes([93, 184, 216, 34])
        return struct.pack("!HHHHHH", tid, 0x8180, 1, 1, 0, 0) + query_packet[12:qend] + answer
    return struct.pack("!HHHHHH", tid, 0x8180, 1, 0, 0, 0) + query_packet[12:qend]


class FakeSock:
    def __init__(self):
        self.sent = []

    def sendto(self, data, addr):
        self.sent.append(data)


def dns_query(domain, qtype=1):
    tid = 0x1234
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    return header + encode_qname(domain) + struct.pack("!HH", qtype, 1)


@pytest.fixture()
def dns_setup(tmp_path, monkeypatch):
    monkeypatch.setattr(dns_mod, "forward", _fake_forward)
    store, pm = make_pm(tmp_path, lambda d: (
        d["web"].update({"blocked_domains": ["facebook.com", "bet365.com"],
                         "safesearch": True, "rules": [], "never_block": []})))
    events = []
    proxy = DnsProxy(pm, bind=("127.0.0.1", 0),
                     upstream=("127.0.0.1", 53535),
                     on_event=lambda t, s: events.append((t, s)))
    return proxy, events


def ask(proxy):
    sock = FakeSock()
    return lambda packet: (proxy._handle(sock, packet, ("127.0.0.1", 5000)),
                           sock.sent[-1])[1]


def test_dns_block_and_subdomain(dns_setup):
    proxy, events = dns_setup
    q = ask(proxy)
    resp = q(dns_query("facebook.com"))
    assert struct.unpack_from("!H", resp, 2)[0] & 0xF == 3  # NXDOMAIN
    resp = q(dns_query("www.facebook.com"))
    assert struct.unpack_from("!H", resp, 2)[0] & 0xF == 3
    assert any(t == "blocked_domain" for t, _ in events)


def test_dns_forward_allowed_and_never_block(dns_setup):
    proxy, events = dns_setup
    q = ask(proxy)
    resp = q(dns_query("example.com"))
    assert struct.unpack_from("!H", resp, 2)[0] & 0xF == 0
    assert b"\x5d\xb8\xd8\x22" in resp  # 93.184.216.34 từ upstream giả
    resp = q(dns_query("moet.gov.vn"))  # NT6: không bao giờ bị chặn
    assert struct.unpack_from("!H", resp, 2)[0] & 0xF == 0
    assert any(t == "domain_query" for t, _ in events)


def test_dns_safesearch_cname(dns_setup):
    proxy, _events = dns_setup
    q = ask(proxy)
    resp = q(dns_query("www.google.com"))
    _, _, qend = parse_qname(resp)
    rtype = struct.unpack_from("!H", resp, qend + 2)[0]
    assert rtype == 5, "phải có bản ghi CNAME sang forcesafesearch"
    assert b"forcesafesearch" in resp


# ---------------------------------------------------------------- IPC
def test_ipc_roundtrip(tmp_path):
    server = IPCServer("tok123", {"echo": lambda p: {"got": p.get("x")}})
    server.start()
    try:
        client = IPCClient("tok123")
        assert client.call("echo", x=42) == {"got": 42}
        bad = IPCClient("sai-token")
        with pytest.raises(RuntimeError):
            bad.call("echo", x=1)
    finally:
        server.stop()
