# OpenGuard Kids v2 — test agent (vòng 1): timekeeper, policy, controller, DNS, IPC.
import json
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


def test_stale_fail_open_time_locks(tmp_path):
    # KT5: offline > 7 ngày -> không khóa theo quota/lịch nữa, vẫn đếm giờ.
    from datetime import datetime
    clock = FakeClock(datetime(2026, 11, 16, 10, 0).timestamp())  # Thứ 2 10:00
    store, pm = make_pm(tmp_path / "q", lambda d: d["time"].update(
        {"quota_weekday_min": 3, "quota_weekend_min": 3, "grace_sec": 0}))
    keeper, _e, _w, locks, _a = make_keeper(store, pm, clock)
    day = keeper.effective_date()
    store.kv_set(keeper._key("used_seconds", day), 9999)  # đã vượt quota
    keeper.tick(0)
    assert locks == ["quota"]  # chưa stale: khóa bình thường

    store2, pm2 = make_pm(tmp_path / "s", lambda d: d["time"].update(
        {"quota_weekday_min": 3, "quota_weekend_min": 3, "grace_sec": 0}))
    keeper2, _e, _w, locks2, _a = make_keeper(store2, pm2, clock)
    day2 = keeper2.effective_date()
    store2.kv_set(keeper2._key("used_seconds", day2), 9999)
    store2.kv_set("offline_elapsed_sec", 8 * 86400)
    assert keeper2.policy_stale()
    keeper2.tick(0)
    clock.advance(30)
    keeper2.tick()
    assert locks2 == []  # stale: không khóa quota...
    assert keeper2.used_today() == 9999 + 30  # ...nhưng vẫn đếm giờ

    # Lịch: 23:00 ngoài khung 06:00-21:00 — stale thì không khóa lịch.
    clock3 = FakeClock(datetime(2026, 11, 16, 23, 0).timestamp())
    store3, pm3 = make_pm(tmp_path / "t")
    keeper3, _e, _w, locks3, _a = make_keeper(store3, pm3, clock3)
    keeper3.tick(0)
    assert locks3 == ["schedule"]
    store4, pm4 = make_pm(tmp_path / "u")
    keeper4, _e, _w, locks4, _a = make_keeper(store4, pm4, clock3)
    store4.kv_set("offline_elapsed_sec", 8 * 86400)
    keeper4.tick(0)
    assert locks4 == []


def test_stale_keeps_web_and_app_blocks(tmp_path):
    # KT5 (bổ sung theo review 2): stale chỉ mở khóa THỜI GIAN — chặn web
    # theo nhóm/luật/DoH và chặn ứng dụng theo luật vẫn nguyên hiệu lực.
    store, pm = make_pm(tmp_path, lambda d: (
        d["web"].update({"blocked_domains": ["facebook.com"],
                         "rules": [{"domain": "game-vui.com", "action": "block"}],
                         "never_block": [], "safesearch": True}),
        d.update({"apps": [{"name": "game.exe", "sha256": None,
                            "action": "block", "category": "game",
                            "windows": [], "daily_cap_min": None}]})))
    from agent.timekeeper import TimeKeeper
    keeper = TimeKeeper(store, pm)
    store.kv_set("offline_elapsed_sec", 8 * 86400)
    assert keeper.policy_stale()
    assert pm.web_decision("facebook.com") == "block"            # theo nhóm
    assert pm.web_decision_detail("game-vui.com") == ("block", "rule_block")
    assert pm.web_decision_detail("dns.google") == ("block", "doh_endpoint")
    ctl = AgentController(store, pm, client=None)
    assert ctl._rule_for("game.exe", "game.exe") is not None     # luật chặn app


def test_stale_exit_over_quota_grace_before_lock(tmp_path):
    # Ra khỏi stale (sync lại được) khi đã vượt quota: vào ân hạn trước,
    # hết ân hạn mới khóa — không khóa đột ngột (review 2, FP:214).
    from datetime import datetime
    clock = FakeClock(datetime(2026, 11, 16, 10, 0).timestamp())
    store, pm = make_pm(tmp_path, lambda d: d["time"].update(
        {"quota_weekday_min": 3, "quota_weekend_min": 3, "grace_sec": 60}))
    keeper, _e, _w, locks, _a = make_keeper(store, pm, clock)
    day = keeper.effective_date()
    store.kv_set(keeper._key("used_seconds", day), 9999)  # đã vượt quota
    store.kv_set("offline_elapsed_sec", 8 * 86400)
    keeper.tick(0)
    assert locks == []                       # đang stale: không khóa
    keeper.reset_offline()                   # sync thành công -> hết stale
    keeper.tick()
    assert locks == []                       # ân hạn 60s: chưa khóa ngay
    clock.advance(61)
    keeper.tick()
    assert locks == ["quota"]                # hết ân hạn mới khóa


def test_offline_accumulation_rules(tmp_path):
    from datetime import datetime
    clock = FakeClock(datetime(2026, 11, 16, 10, 0).timestamp())
    store, pm = make_pm(tmp_path)
    keeper, _e, _w, _l, _a = make_keeper(store, pm, clock)
    # Máy nâng cấp chưa có khóa: không stale, bộ đếm bắt đầu từ 0.
    assert keeper.offline_seconds() == 0 and not keeper.policy_stale()
    keeper.tick(0)
    # Chỉnh đồng hồ tường +8 ngày nhưng monotonic chỉ trôi 60s -> KHÔNG stale.
    clock.wall += 8 * 86400
    clock.mono += 60
    keeper.tick()
    assert keeper.offline_seconds() < 120 and not keeper.policy_stale()
    # 6 ngày thật -> chưa stale; reset -> 0.
    store.kv_set("offline_elapsed_sec", 6 * 86400)
    assert not keeper.policy_stale()
    keeper.reset_offline()
    assert keeper.offline_seconds() == 0
    assert keeper.status()["policy_stale"] is False

    # Qua reboot: keeper mới trên cùng store cộng khoảng giờ tường từ tick cuối.
    # (Mô phỏng máy tắt từ 16/11: ghi lại mốc tick cuối về trước cú nhảy giờ.)
    store.kv_set("last_tick_wall", datetime(2026, 11, 16, 10, 0).timestamp())
    clock_b = FakeClock(datetime(2026, 11, 19, 10, 0).timestamp())  # +3 ngày
    keeper_b, _e, _w, _l, _a = make_keeper(store, pm, clock_b)
    keeper_b.tick(0)
    assert abs(keeper_b.offline_seconds() - 3 * 86400) < 120


def test_controller_stale_transition_alerts_once(tmp_path):
    store, pm = make_pm(tmp_path)
    notes = []
    ctl = AgentController(store, pm, client=None, on_notify=notes.append)
    store.kv_set("offline_elapsed_sec", 8 * 86400)
    ctl._check_stale_transition()
    ctl._check_stale_transition()  # lần hai: không báo lại
    assert len(notes) == 1 and "hơn 7 ngày" in notes[0]["text"]
    pending = json.loads(store.kv_get("pending_alerts", "[]"))
    assert [a["kind"] for a in pending] == ["policy_stale"]  # offline -> xếp hàng
    store.kv_set("offline_elapsed_sec", 0)
    ctl._check_stale_transition()
    assert len(notes) == 2
    pending = json.loads(store.kv_get("pending_alerts", "[]"))
    assert pending[-1]["kind"] == "policy_fresh"


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


def test_doh_blocked_by_default_and_never_block_hard_rules(tmp_path):
    # Chưa có policy nào (mới cài): DoH vẫn bị chặn, NT6 vẫn mở.
    store = LocalStore(tmp_path / "a.db")
    pm = PolicyManager(store, KEY)
    assert pm.web_decision_detail("dns.google") == ("block", "doh_endpoint")
    assert pm.web_decision_detail("chrome.cloudflare-dns.com") == ("block", "doh_endpoint")
    assert pm.web_decision_detail("one.one.one.one") == ("block", "doh_endpoint")
    assert pm.web_decision_detail("use-application-dns.net") == ("block", "doh_endpoint")
    assert pm.web_decision_detail("moet.gov.vn") == ("allow", "never_block")
    assert pm.web_decision_detail("tongdai111.vn") == ("allow", "never_block")
    assert pm.web_decision_detail("example.com") == ("allow", "default")

    # Có policy: luật allow đích danh của phụ huynh thắng DoH; luật block
    # đích danh không áp được lên .edu.vn / tongdai111.vn (NT6 cứng).
    doc = default_policy_document(1, 1)
    doc["web"]["rules"] = [{"domain": "dns.google", "action": "allow"},
                           {"domain": "abc.edu.vn", "action": "block"},
                           {"domain": "tongdai111.vn", "action": "block"}]
    doc["signature"] = sign_policy(doc, KEY)
    assert pm.update(doc)
    assert pm.web_decision_detail("dns.google") == ("allow", "rule_allow")
    assert pm.web_decision_detail("abc.edu.vn") == ("allow", "never_block")
    assert pm.web_decision_detail("portal.abc.edu.vn") == ("allow", "never_block")
    assert pm.web_decision_detail("tongdai111.vn") == ("allow", "never_block")
    # Nhóm chua_phan_loai để allow cũng KHÔNG mở DoH (chỉ luật đích danh mới mở).
    assert pm.web_decision_detail("dns.quad9.net") == ("block", "doh_endpoint")


def test_doh_constant_matches_classification_notes():
    # Hằng số DOH_ENDPOINTS phải khớp các dòng ghi chú DoH trong bảng phân loại
    # (trừ miền canary của Firefox — không nằm trong bảng phân loại).
    import csv
    import os
    path = os.path.join(os.path.dirname(__file__), "..", "server", "data",
                        "domain_categories.csv")
    noted = {r["domain"] for r in csv.DictReader(open(path, encoding="utf-8"))
             if "DoH" in (r.get("note") or "")}
    from shared.contract import DOH_ENDPOINTS
    assert noted == set(DOH_ENDPOINTS) - {"use-application-dns.net"}, noted


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


def test_group_budget_opens_when_stale(tmp_path):
    # KT5: ngân sách nhóm cũng là khóa THỜI GIAN -> mở khi stale (chặn app
    # theo luật đích danh thì không — xem test_stale_keeps_web_and_app_blocks).
    fakebin = tmp_path / "game.exe"
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
    store.kv_set("offline_elapsed_sec", 8 * 86400)  # đang stale
    ctl = AgentController(store, pm, client=None)
    assert ctl.keeper.policy_stale()
    proc = subprocess.Popen([str(fakebin)] + run_args)
    try:
        time.sleep(0.3)
        ctl._scan_processes(5.0)
        time.sleep(0.3)
        assert proc.poll() is None, "stale: ngân sách nhóm phải MỞ, không dừng tiến trình"
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


def _cname_target(resp):
    _, _, qend = parse_qname(resp)
    rtype = struct.unpack_from("!H", resp, qend + 2)[0]
    return rtype


def test_dns_safesearch_google_vn_and_youtube_restrict(dns_setup):
    proxy, _events = dns_setup
    q = ask(proxy)
    for name in ("google.com.vn", "www.google.com.vn"):
        resp = q(dns_query(name))
        assert _cname_target(resp) == 5 and b"forcesafesearch" in resp, name
    for name in ("www.youtube.com", "m.youtube.com", "youtubei.googleapis.com",
                 "youtube.googleapis.com", "www.youtube-nocookie.com"):
        resp = q(dns_query(name))
        assert _cname_target(resp) == 5 and b"restrict" in resp, name
    # Miền con lạ không bị ánh xạ (tra cứu đúng tên, không theo hậu tố).
    resp = q(dns_query("xyz.google.com.vn"))
    assert struct.unpack_from("!H", resp, 2)[0] & 0xF == 0
    assert b"\x5d\xb8\xd8\x22" in resp  # đi thẳng upstream giả


def _aaaa_answer_response(query_packet, addr6):
    name, qtype, qend = parse_qname(query_packet)
    tid, _flags = struct.unpack_from("!HH", query_packet, 0)
    qclass = struct.unpack_from("!H", query_packet, qend - 2)[0]
    answer = struct.pack("!HHHIH", 0xC00C, 28, qclass, 60, 16) + \
        socket.inet_pton(socket.AF_INET6, addr6)
    return struct.pack("!HHHHHH", tid, 0x8180, 1, 1, 0, 0) + \
        query_packet[12:qend] + answer


def test_dns_safesearch_aaaa_also_mapped(tmp_path, monkeypatch):
    # Review 2 (F2.5): thiếu AAAA thì máy IPv6 đi thẳng tới Google/YouTube
    # thật và vượt SafeSearch — cả A (1) lẫn AAAA (28) đều phải có CNAME.
    def fwd(query_packet, upstream=("8.8.8.8", 53), timeout=3):
        name, qtype, _qend = parse_qname(query_packet)
        if qtype == 28 and name in ("forcesafesearch.google.com",
                                    "restrict.youtube.com"):
            return _aaaa_answer_response(query_packet, "2001:4860:4860::8888")
        return _fake_forward(query_packet, upstream, timeout)

    monkeypatch.setattr(dns_mod, "forward", fwd)
    store, pm = make_pm(tmp_path, lambda d: (
        d["web"].update({"blocked_domains": [], "safesearch": True,
                         "rules": [], "never_block": []})))
    proxy = DnsProxy(pm, bind=("127.0.0.1", 0), upstream=("127.0.0.1", 53535),
                     on_event=lambda t, s: None)
    q = ask(proxy)
    resp = q(dns_query("www.google.com.vn", qtype=28))
    assert _cname_target(resp) == 5 and b"forcesafesearch" in resp
    resp = q(dns_query("www.youtube.com", qtype=28))
    assert _cname_target(resp) == 5 and b"restrict" in resp


def test_dns_safesearch_aaaa_no_upstream_record_gives_nodata(tmp_path, monkeypatch):
    # Upstream có AAAA THẬT của miền gốc nhưng không có AAAA của máy chủ
    # SafeSearch: proxy phải trả NODATA rỗng, TUYỆT ĐỐI không chuyển tiếp
    # truy vấn gốc (chuyển tiếp = lộ địa chỉ thật = vượt SafeSearch).
    def fwd(query_packet, upstream=("8.8.8.8", 53), timeout=3):
        name, qtype, _qend = parse_qname(query_packet)
        if qtype == 28 and name not in ("forcesafesearch.google.com",
                                        "restrict.youtube.com"):
            return _aaaa_answer_response(query_packet, "2001:db8::1")
        return _fake_forward(query_packet, upstream, timeout)

    monkeypatch.setattr(dns_mod, "forward", fwd)
    store, pm = make_pm(tmp_path, lambda d: (
        d["web"].update({"blocked_domains": [], "safesearch": True,
                         "rules": [], "never_block": []})))
    proxy = DnsProxy(pm, bind=("127.0.0.1", 0), upstream=("127.0.0.1", 53535),
                     on_event=lambda t, s: None)
    q = ask(proxy)
    resp = q(dns_query("www.google.com.vn", qtype=28))
    assert struct.unpack_from("!H", resp, 6)[0] == 0       # ancount = 0 (NODATA)
    assert b"\x20\x01\x0d\xb8" not in resp                 # không lộ AAAA thật


def test_dns_safesearch_upstream_silent_gives_servfail(tmp_path, monkeypatch):
    # Upstream câm lặng (forward trả SERVFAIL cho probe): proxy phải trả
    # SERVFAIL (rcode 2), KHÔNG trả NODATA — tránh cache phủ định của
    # Windows làm Google/YouTube mất vài phút sau một lần chập mạng.
    def fwd(query_packet, upstream=("8.8.8.8", 53), timeout=3):
        name, _qt, _qe = parse_qname(query_packet)
        if name in ("forcesafesearch.google.com", "restrict.youtube.com"):
            return dns_mod._servfail(query_packet)
        return _fake_forward(query_packet, upstream, timeout)

    monkeypatch.setattr(dns_mod, "forward", fwd)
    store, pm = make_pm(tmp_path, lambda d: (
        d["web"].update({"blocked_domains": [], "safesearch": True,
                         "rules": [], "never_block": []})))
    proxy = DnsProxy(pm, bind=("127.0.0.1", 0), upstream=("127.0.0.1", 53535),
                     on_event=lambda t, s: None)
    q = ask(proxy)
    resp = q(dns_query("www.google.com.vn"))
    assert struct.unpack_from("!H", resp, 2)[0] & 0xF == 2  # SERVFAIL


def test_dns_youtube_blocked_by_default_beats_safesearch(tmp_path, monkeypatch):
    # YouTube thuộc nhóm bị chặn theo chính sách mặc định -> NXDOMAIN thắng
    # SafeSearch (kiểm chặn chạy trước); chỉ khi phụ huynh cho phép mới restrict.
    monkeypatch.setattr(dns_mod, "forward", _fake_forward)
    store, pm = make_pm(tmp_path, lambda d: (
        d["web"].update({"blocked_domains": ["youtube.com"],
                         "safesearch": True, "rules": [], "never_block": []})))
    proxy = DnsProxy(pm, bind=("127.0.0.1", 0), upstream=("127.0.0.1", 53535),
                     on_event=lambda t, s: None)
    q = ask(proxy)
    resp = q(dns_query("www.youtube.com"))
    assert struct.unpack_from("!H", resp, 2)[0] & 0xF == 3  # NXDOMAIN


def test_dns_safesearch_off_no_mapping(tmp_path, monkeypatch):
    monkeypatch.setattr(dns_mod, "forward", _fake_forward)
    store, pm = make_pm(tmp_path, lambda d: (
        d["web"].update({"blocked_domains": [], "safesearch": False,
                         "rules": [], "never_block": []})))
    proxy = DnsProxy(pm, bind=("127.0.0.1", 0), upstream=("127.0.0.1", 53535),
                     on_event=lambda t, s: None)
    q = ask(proxy)
    resp = q(dns_query("www.google.com.vn"))
    assert b"forcesafesearch" not in resp
    assert b"\x5d\xb8\xd8\x22" in resp


def test_handle_dns_event_notifies_with_reason(tmp_path):
    store, pm = make_pm(tmp_path, lambda d: d["web"].update({
        "blocked_domains": ["facebook.com"],
        "rules": [{"domain": "game-vui.com", "action": "block"}],
        "never_block": [], "safesearch": True}))
    notes = []
    ctl = AgentController(store, pm, client=None, on_notify=notes.append)

    ctl.handle_dns_event("blocked_domain", "www.facebook.com")
    assert len(notes) == 1
    n = notes[0]
    assert n["kind"] == "blocked_domain" and n["subject"] == "facebook.com"
    assert "nhóm nội dung phụ huynh chọn chặn" in n["text"]
    assert "chính sách phiên bản" in n["text"] and "Báo chặn nhầm" in n["text"]

    # Chống spam: cùng subject trong 60s -> không toast nữa (sự kiện vẫn ghi).
    ctl.handle_dns_event("blocked_domain", "facebook.com")
    assert len(notes) == 1
    # Subject khác nhưng chưa qua 10s toàn cục -> cũng chưa toast.
    ctl.handle_dns_event("blocked_domain", "game-vui.com")
    assert len(notes) == 1
    # Giả lập thời gian đã trôi (tua ngược mốc throttle) -> toast lại được.
    ctl._web_notified.clear()
    ctl._last_web_notify = 0.0
    ctl.handle_dns_event("blocked_domain", "game-vui.com")
    assert len(notes) == 2 and "luật chặn riêng" in notes[1]["text"]
    ctl._web_notified.clear()
    ctl._last_web_notify = 0.0
    ctl.handle_dns_event("blocked_domain", "dns.google")
    assert len(notes) == 3 and "DNS bảo mật (DoH)" in notes[2]["text"]

    evs = store.pop_queued_events(50)
    blocked = [e for e in evs if e["type"] == "blocked_domain"]
    assert {e["subject"] for e in blocked} == {"facebook.com", "game-vui.com", "dns.google"}


def test_handle_dns_event_notify_error_never_breaks(tmp_path):
    store, pm = make_pm(tmp_path, lambda d: d["web"].update({
        "blocked_domains": ["facebook.com"], "rules": [], "never_block": []}))
    ctl = AgentController(store, pm, client=None,
                          on_notify=lambda n: (_ for _ in ()).throw(RuntimeError("boom")))
    ctl.handle_dns_event("blocked_domain", "facebook.com")  # không được ném lỗi
    evs = store.pop_queued_events(50)
    assert any(e["type"] == "blocked_domain" for e in evs)


def test_tray_info_roundtrip_no_secrets(tmp_path, monkeypatch):
    import agent.config as cfgmod
    monkeypatch.setattr(cfgmod, "TRAY_DIR", tmp_path / "tray")
    monkeypatch.setattr(cfgmod, "TRAY_INFO_PATH", tmp_path / "tray" / "tray.json")
    # Chưa có file -> mặc định chưa ghép đôi, không ném lỗi.
    assert cfgmod.load_tray_info() == {"port": 0, "ipc_token": "",
                                       "paired": False, "child_name": ""}
    info = cfgmod.write_tray_info(54321, "tok-ipc", True, "Bé")
    assert cfgmod.load_tray_info() == info
    raw = (tmp_path / "tray" / "tray.json").read_text(encoding="utf-8")
    assert set(json.loads(raw)) == {"port", "ipc_token", "paired", "child_name"}
    for secret in ("refresh_token", "access_token", "policy_key"):
        assert secret not in raw


def test_ipc_client_via_custom_info_path(tmp_path):
    server = IPCServer("tok123", {"echo": lambda p: {"got": p.get("x")}})
    server.start()
    try:
        info_path = tmp_path / "tray.json"
        info_path.write_text(json.dumps({"port": server.port}), encoding="utf-8")
        client = IPCClient("tok123", info_path=info_path)
        assert client.call("echo", x=7) == {"got": 7}
    finally:
        server.stop()


def _fake_watchdog_runtime(state_over=None, on_fatal=None, session=True,
                           alert_ok=True, store=None):
    alerts = []

    class FakeClient:
        def send_alert(self, kind, detail):
            alerts.append(kind)
            return alert_ok

    now = 100_000.0
    state = {"fatal": False, "session_since": now - 300,
             "last_ipc_at": now, "last_watchdog_at": now - 5,
             "stopping": False}
    state.update(state_over or {})
    rt = {"state": state, "client": FakeClient(), "on_fatal": on_fatal,
          "session_active_fn": lambda: session, "store": store, "now": now}
    return rt, alerts


def test_tray_watchdog_fires_when_tray_silent():
    import agent.service as svc
    fired = []
    rt, alerts = _fake_watchdog_runtime(on_fatal=lambda: fired.append(1))
    rt["state"]["last_ipc_at"] = rt["now"] - (svc.TRAY_LOST_AFTER_SEC + 1)
    assert svc._tray_watchdog_check(rt, now=rt["now"]) is True
    assert rt["state"]["fatal"] and alerts == ["tray_lost"] and fired


def test_tray_watchdog_fires_when_tray_never_appears():
    # Phiên đăng nhập đã chạy 300s mà tray chưa từng gọi IPC (bị tắt
    # autostart / crash / lỗi ACL) -> vẫn fatal: không cần "ready lần đầu".
    import agent.service as svc
    rt, alerts = _fake_watchdog_runtime({"last_ipc_at": 0.0})
    assert svc._tray_watchdog_check(rt, now=rt["now"]) is True
    assert alerts == ["tray_lost"]


def test_tray_watchdog_quiet_cases():
    import agent.service as svc
    # tray vừa gọi IPC -> yên
    rt, _ = _fake_watchdog_runtime()
    assert svc._tray_watchdog_check(rt, now=rt["now"]) is False
    # không có phiên đăng nhập (đã đăng xuất) -> yên dù IPC rất cũ,
    # và mốc phiên được xóa để phiên sau tính ân hạn lại từ đầu
    rt, _ = _fake_watchdog_runtime({"last_ipc_at": 0.0}, session=False)
    assert svc._tray_watchdog_check(rt, now=rt["now"]) is False
    assert rt["state"]["session_since"] is None
    # đầu phiên: mới thấy phiên 10s (< ân hạn 90s), tray chưa kịp lên -> yên
    rt, _ = _fake_watchdog_runtime(
        {"session_since": 100_000.0 - 10, "last_ipc_at": 0.0})
    assert svc._tray_watchdog_check(rt, now=rt["now"]) is False
    # máy vừa ngủ dậy: vòng kiểm trễ 1 giờ -> bỏ qua + làm mới mốc IPC
    rt, _ = _fake_watchdog_runtime(
        {"last_watchdog_at": 100_000.0 - 3600, "last_ipc_at": 100_000.0 - 3600})
    assert svc._tray_watchdog_check(rt, now=rt["now"]) is False
    assert rt["state"]["last_ipc_at"] == rt["now"]


def test_tray_lost_alert_queued_when_send_fails(tmp_path):
    # Server không nhận (send_alert False) -> alert phải vào hàng bền
    # pending_alerts để xả ở lần sync sau, không được mất (review 2 §3.2).
    import agent.service as svc
    store, _pm = make_pm(tmp_path)
    rt, _alerts = _fake_watchdog_runtime(alert_ok=False, store=store)
    rt["state"]["last_ipc_at"] = rt["now"] - (svc.TRAY_LOST_AFTER_SEC + 1)
    assert svc._tray_watchdog_check(rt, now=rt["now"]) is True
    queued = json.loads(store.kv_get("pending_alerts", "[]"))
    assert [q["kind"] for q in queued] == ["tray_lost"]


def test_child_session_active_uses_wts_user(monkeypatch):
    # C2: tín hiệu phiên là WTSActive + ĐÚNG tài khoản trẻ, không phải
    # explorer.exe của bất kỳ ai (chích win32ts giả để kiểm trên Linux).
    import sys
    import types
    import agent.service as svc
    fake = types.ModuleType("win32ts")
    fake.WTS_CURRENT_SERVER_HANDLE = 0
    fake.WTSActive = 0
    fake.WTSUserName = 5
    users = {1: "QuanTri", 2: "be"}
    fake.WTSQuerySessionInformation = lambda h, sid, kind: users[sid]
    fake.WTSEnumerateSessions = lambda h: [
        {"SessionId": 1, "State": 0},   # admin đang đăng nhập
        {"SessionId": 2, "State": 4},   # trẻ nhưng phiên đã ngắt (disconnected)
    ]
    monkeypatch.setitem(sys.modules, "win32ts", fake)
    assert svc._child_session_active("be") is False       # phiên trẻ không Active
    assert svc._child_session_active("quantri") is True   # đúng user + Active
    fake.WTSEnumerateSessions = lambda h: [{"SessionId": 2, "State": 0}]
    assert svc._child_session_active("be") is True
    assert svc._child_session_active("") is True          # chưa cấu hình: phiên nào cũng tính
    assert svc._child_session_active(None) is True


def test_watchdog_first_sighting_and_post_sleep_fatal():
    # Hai ca gợi ý ở review 3: (1) lần đầu thấy phiên chỉ đặt mốc, không
    # fatal; (2) sau lượt bỏ qua vì ngủ dậy, tray vẫn im > 60s -> fatal.
    import agent.service as svc
    rt, _ = _fake_watchdog_runtime({"session_since": None, "last_ipc_at": 0.0})
    assert svc._tray_watchdog_check(rt, now=rt["now"]) is False
    assert rt["state"]["session_since"] == rt["now"]
    rt, alerts = _fake_watchdog_runtime(
        {"last_watchdog_at": 100_000.0 - 3600, "last_ipc_at": 100_000.0 - 3600})
    assert svc._tray_watchdog_check(rt, now=rt["now"]) is False   # lượt ngủ dậy: bỏ qua
    # Vòng kiểm thật chạy mỗi 5s: sau khi mốc IPC được làm mới lúc thức,
    # im lặng tích lũy lại từ đầu — quá 60s nữa thì phải fatal.
    fired_at = None
    for step in range(5, 80, 5):
        if svc._tray_watchdog_check(rt, now=rt["now"] + step):
            fired_at = step
            break
    assert fired_at == 65
    assert alerts == ["tray_lost"]


def test_only_session_pulse_counts_as_heartbeat(tmp_path):
    # NÊN SỬA review 3: lệnh IPC thường (get_status...) không làm mới mốc
    # nhịp sống; chỉ session_pulse mới tính — script cầm token không thể
    # giả nhịp của tray bằng lệnh khác.
    import agent.service as svc
    from agent.ipc import IPCClient
    rt = svc.build_runtime()
    rt["ipc"].start()
    try:
        info = tmp_path / "info.json"
        info.write_text(json.dumps({"port": rt["ipc"].port}), encoding="utf-8")
        client = IPCClient(rt["config"]["ipc_token"], info_path=info)
        assert rt["state"]["last_ipc_at"] == 0.0
        client.call("get_status")
        assert rt["state"]["last_ipc_at"] == 0.0
        client.call("session_pulse", idle_sec=0, locked=False)
        assert rt["state"]["last_ipc_at"] > 0.0
    finally:
        rt["ipc"].stop()


def test_run_console_exits_zero_on_fatal(monkeypatch):
    import agent.service as svc
    captured = {}

    def fake_build(on_fatal=None):
        captured["on_fatal"] = on_fatal
        return {"state": {}}

    monkeypatch.setattr(svc, "build_runtime", fake_build)
    monkeypatch.setattr(svc, "_start_components",
                        lambda rt: captured["on_fatal"]())
    monkeypatch.setattr(svc, "_stop_components",
                        lambda rt: (_ for _ in ()).throw(RuntimeError("stop lỗi")))
    t0 = time.monotonic()
    assert svc.run_console() == 0  # lỗi khi dừng cũng không thành mã khác 0
    assert time.monotonic() - t0 < 3


def test_console_process_exits_zero_on_fatal(tmp_path):
    """Tiến trình con THẬT chạy run_console(): kích fatal qua IPC
    tray_ready(icon_ok=False) -> tiến trình thoát mã 0 (review 2 §3.3:
    "trả 0" phải là "tiến trình đã thoát thật", kể cả khi dừng lỗi)."""
    import subprocess
    import sys
    from pathlib import Path
    env = dict(os.environ)
    env["ProgramData"] = str(tmp_path)
    driver = (
        "import json, threading, time, sys\n"
        "from agent import service as svc\n"
        "from agent.config import TRAY_INFO_PATH\n"
        "from agent.ipc import IPCClient\n"
        "def poke():\n"
        "    for _ in range(150):\n"
        "        try:\n"
        "            info = json.loads(TRAY_INFO_PATH.read_text(encoding='utf-8'))\n"
        "            IPCClient(info['ipc_token'], info_path=TRAY_INFO_PATH)"
        ".call('tray_ready', icon_ok=False)\n"
        "            return\n"
        "        except Exception:\n"
        "            time.sleep(0.1)\n"
        "threading.Thread(target=poke, daemon=True).start()\n"
        "sys.exit(svc.run_console())\n"
    )
    t0 = time.monotonic()
    proc = subprocess.run(
        [sys.executable, "-c", driver], env=env, capture_output=True,
        text=True, timeout=60,
        cwd=str(Path(__file__).resolve().parent.parent))
    elapsed = time.monotonic() - t0
    assert proc.returncode == 0, proc.stderr[-800:]
    assert elapsed < 30, f"thoát quá chậm: {elapsed:.1f}s"


def test_tls_context_factory_sets_floor():
    """Sàn TLS 1.2 nằm trong chính context do factory tạo (assert trực tiếp,
    không phụ thuộc hành vi mặc định của OpenSSL — review 2, F5.3)."""
    import importlib.util
    import ssl as ssl_mod
    from pathlib import Path
    path = Path(__file__).resolve().parent.parent / "scripts" / "run_server.py"
    spec = importlib.util.spec_from_file_location("ogk_run_server", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    def default_factory():
        return ssl_mod.SSLContext(ssl_mod.PROTOCOL_TLS_SERVER)

    ctx = mod._tls12_context_factory(None, default_factory)
    assert ctx.minimum_version == ssl_mod.TLSVersion.TLSv1_2


def test_heartbeat_locks_immediately_and_counts_pulses():
    # C1: note "locked" phải gọi khóa NGAY trong nhịp (không chờ UI);
    # hai note locked -> khóa hai lần; nhịp vẫn đủ số pulse.
    from agent.tray import Heartbeat
    pulses, locks, shown = [], [], []
    notes = [[{"kind": "locked", "text": "a"}, {"kind": "locked", "text": "b"}],
             [{"kind": "warning", "text": "c"}]]
    hb = Heartbeat(pulse_fn=lambda: pulses.append(1),
                   fetch_fn=lambda: notes.pop(0) if notes else [],
                   lock_fn=lambda: locks.append(1),
                   display_fn=shown.append,
                   alive_fn=lambda: True)
    assert hb.step() is True
    assert locks == [1, 1]              # khóa ngay trong nhịp, chưa cần hiển thị
    hb.flush_display()
    assert len(shown) == 2
    assert hb.step() is True
    hb.flush_display()
    assert len(pulses) == 2 and len(shown) == 3


def test_heartbeat_ui_blocking_does_not_stop_pulses():
    # C1/N1: display_fn CHẶN THẬT 2 giây mỗi note (ở luồng dispatch) —
    # nhịp pulse và khóa máy ở luồng nhịp vẫn phải chạy đều.
    import threading as _th
    from agent.tray import Heartbeat
    pulses, locks = [], []

    def slow_display(note):
        time.sleep(2)

    hb = Heartbeat(pulse_fn=lambda: pulses.append(1),
                   fetch_fn=lambda: [{"kind": "locked", "text": "x"}],
                   lock_fn=lambda: locks.append(1),
                   display_fn=slow_display,
                   alive_fn=lambda: True, interval=0.02)
    stop = _th.Event()
    t = _th.Thread(target=hb.run, args=(stop,), daemon=True)
    t.start()
    time.sleep(1.0)
    stop.set()
    t.join(2)
    assert len(pulses) >= 30, f"nhịp bị đứt: {len(pulses)} pulse"
    assert len(locks) >= 30, f"khóa bị trễ: {len(locks)} lần"


def test_heartbeat_stops_when_icon_dead():
    # Biểu tượng chết -> ngừng nhịp để watchdog của service phát hiện.
    from agent.tray import Heartbeat
    pulses = []
    hb = Heartbeat(pulse_fn=lambda: pulses.append(1),
                   fetch_fn=lambda: [], lock_fn=lambda: None,
                   display_fn=lambda n: None, alive_fn=lambda: False)
    assert hb.step() is False and pulses == []


def test_wait_for_icon_tolerates_slow_start():
    # N2: pystray đặt _thread muộn vài nhịp — _wait_for_icon phải CHỜ,
    # không kết luận chết ngay; icon không bao giờ lên thì trả False.
    import threading as _th
    from agent.tray import _wait_for_icon

    class FakeIcon:
        _thread = None

    icon = FakeIcon()

    def appear():
        time.sleep(0.25)
        icon._thread = _th.Thread(target=lambda: time.sleep(2), daemon=True)
        icon._thread.start()

    _th.Thread(target=appear, daemon=True).start()
    assert _wait_for_icon(icon, timeout=2.0, interval=0.05) is True
    assert _wait_for_icon(FakeIcon(), timeout=0.3, interval=0.05) is False


def test_week_summary_and_tray_lines(tmp_path):
    import agent.service as svc
    from agent.timekeeper import TimeKeeper
    from agent.tray import audit_lines, week_lines
    store, pm = make_pm(tmp_path)
    keeper = TimeKeeper(store, pm)
    today = keeper.effective_date()
    store.kv_set(keeper._key("used_seconds", today), 3600)
    store.queue_event("app_stop", "game.exe", 1800, 1)
    wk = svc._week_summary(store, keeper)
    assert len(wk["days"]) == 7
    assert wk["days"][-1]["date"] == today.isoformat()
    assert wk["days"][-1]["used_min"] == 60.0 and wk["total_used_min"] == 60.0
    assert wk["top_apps"] == [{"app": "game.exe", "minutes": 30.0}]
    lines = week_lines(wk)
    assert any("Tổng cả tuần" in ln for ln in lines)
    rows = [{"ts": "2026-11-26T10:00:00", "actor": "bo@example.com",
             "action": "policy.update", "old": {"quota_weekday_min": 90},
             "new": {"quota_weekday_min": 111}, "ip": "113.161.x.x"}]
    line = audit_lines(rows)[0]
    assert "quota_weekday_min: 90 → 111" in line and "113.161.x.x" in line


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
