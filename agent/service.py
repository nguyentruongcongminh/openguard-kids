"""OGK-Agent — Windows Service v2 + điểm chạy console (dev/test).

Nối dây đúng theo kiến trúc v2: LocalStore -> PolicyManager -> ServerClient ->
AgentController (timekeeper + kiểm soát ứng dụng) + DnsProxy + WSListener +
IPCServer phục vụ Tray UI. Mọi sự kiện/thông báo cho trẻ đi qua NotificationHub.
"""
import json
import os
import queue
import sys
import threading
import time
import traceback
from datetime import datetime, time as dtime, timedelta

# Chạy dạng file trực tiếp (python agent\service.py) thì thư mục gốc dự án
# KHÔNG có sẵn trong sys.path -> "from agent.xxx import" lỗi No module named
# 'agent'. Thêm gốc dự án TRƯỚC mọi import agent/shared (bản cũ thêm ở giữa
# file, sau khối import agent, nên không cứu được khối đó).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil
    _HAS_WIN32 = True
except Exception:
    _HAS_WIN32 = False

try:
    from agent.client import ServerClient, WSListener
    from agent.config import CONFIG_DIR, load_config, save_config, write_tray_info
    from agent.controller import AgentController
    from agent.dns_proxy import DnsProxy
    from agent.ipc import IPCServer
    from agent.local_store import LocalStore
    from agent.policy import PolicyManager
    from agent.timekeeper import idle_seconds, is_locked
except ImportError:
    from client import ServerClient, WSListener
    from config import CONFIG_DIR, load_config, save_config, write_tray_info
    from controller import AgentController
    from dns_proxy import DnsProxy
    from ipc import IPCServer
    from local_store import LocalStore
    from policy import PolicyManager
    from timekeeper import idle_seconds, is_locked

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from shared.contract import SYSTEM_PROCESSES  # noqa: E402


class NotificationHub:
    """Hàng đợi thông báo cho trẻ — Tray lấy qua IPC (get_notifications)."""

    def __init__(self, maxlen: int = 20):
        self._items: list[dict] = []
        self._lock = threading.Lock()
        self._maxlen = maxlen

    def push(self, note: dict) -> None:
        with self._lock:
            self._items.append({**note, "at": time.time()})
            self._items = self._items[-self._maxlen:]

    def drain(self) -> list[dict]:
        with self._lock:
            items, self._items = self._items, []
            return items


def build_runtime(on_fatal=None):
    cfg = load_config()
    store = LocalStore()
    pm = PolicyManager(store, cfg.get("policy_key", ""))

    def _on_tokens(access, refresh, expires_at):
        save_config({"access_token": access, "refresh_token": refresh,
                     "access_expires_at": expires_at})

    client = ServerClient(cfg.get("server_url", ""), cfg.get("access_token", ""),
                          cfg.get("refresh_token", ""), cfg.get("cert_fingerprint", ""),
                          on_tokens=_on_tokens)
    client.access_expires_at = float(cfg.get("access_expires_at") or 0)
    hub = NotificationHub()
    command_queue = queue.Queue()

    # Trang thai phien dang nhap do Tray bao qua IPC (session_pulse). Service
    # chay o session 0 nen tu do idle/lock se mu voi phien cua tre (idle cua
    # session 0 tang vo han -> keeper ngung dem sau 300s - loi that tren may
    # tre 17/11/2026). Probe: co pulse moi (<= 90s) thi tin Tray; qua han thi
    # lui ve ham cuc bo (hanh vi cu, khong te hon).
    state = {"tray_icon_ok": None, "fatal": False,
             "session": {"idle": None, "locked": None, "at": 0.0},
             # Watchdog tray (F5.8, luật vòng sửa 3): session_since = mốc
             # monotonic từ khi phiên đăng nhập hiện tại được thấy liên tục
             # (None = đang không có phiên); last_watchdog_at để nhận biết
             # máy vừa ngủ dậy (vòng kiểm bị trễ bất thường).
             "session_since": None, "last_ipc_at": 0.0,
             "last_watchdog_at": 0.0, "stopping": False}

    def _probe_idle():
        s = state["session"]
        if s["idle"] is not None and time.time() - s["at"] <= 90:
            return s["idle"]
        return idle_seconds()

    def _probe_locked():
        s = state["session"]
        if s["locked"] is not None and time.time() - s["at"] <= 90:
            return s["locked"]
        return is_locked()

    controller = AgentController(store, pm, client, command_queue, on_notify=hub.push,
                                 idle_fn=_probe_idle, is_locked_fn=_probe_locked)

    try:
        dns = DnsProxy(pm, bind=("127.0.0.1", 53),
                       upstream=(cfg.get("upstream_dns") or "8.8.8.8", 53),
                       on_event=lambda t, s: controller.handle_dns_event(t, s))
    except Exception:
        dns = None
    # Ban IPv6 tren ::1 - bat buoc khi mang co IPv6 (router cap DNS fe80::1):
    # thieu no la trinh duyet phan giai qua router, thoat khoi loc web.
    try:
        dns6 = DnsProxy(pm, bind=("::1", 53),
                        upstream=(cfg.get("upstream_dns") or "8.8.8.8", 53),
                        on_event=lambda t, s: controller.handle_dns_event(t, s))
    except Exception:
        dns6 = None

    def ipc_status(_params):
        st = controller.keeper.status()
        st["connected"] = bool(client.access_token)
        st["tray_icon_ok"] = state["tray_icon_ok"]
        return st

    def ipc_today(_params):
        day = controller.keeper.effective_date()
        by_app, by_domain, blocks = _aggregate_day_events(store, day)
        st = controller.keeper.status()
        return {**st,
                "top_apps": [{"app": k, "minutes": round(v / 60, 1)}
                             for k, v in sorted(by_app.items(), key=lambda kv: -kv[1])[:10]],
                "top_domains": [{"domain": k, "queries": v}
                                for k, v in sorted(by_domain.items(), key=lambda kv: -kv[1])[:10]],
                "blocks": blocks}

    def ipc_week(_params):
        return _week_summary(store, controller.keeper)

    def ipc_notifications(_params):
        return hub.drain()

    def ipc_send_request(params):
        type_ = params.get("type")
        if type_ not in ("extra_time", "false_block"):
            raise ValueError("unknown request type")
        minutes = params.get("minutes")
        subject = params.get("subject")
        reason = params.get("reason", "")
        resp = None
        try:
            resp = client.send_request(type_, minutes, subject, reason)
        except Exception:
            resp = None
        if resp is not None:
            return {"sent": True, "request": resp}
        raw = store.kv_get("pending_requests", "[]")
        pending = json.loads(raw) if isinstance(raw, str) else []
        pending.append({"type": type_, "minutes": minutes, "subject": subject,
                        "reason": reason})
        store.kv_set("pending_requests", json.dumps(pending[-10:]))
        return {"sent": False, "queued": True}

    def ipc_my_requests(_params):
        try:
            rows = client.my_requests()
            store.kv_set("requests_cache", json.dumps(rows))
            return rows
        except Exception:
            raw = store.kv_get("requests_cache", "[]")
            return json.loads(raw) if isinstance(raw, str) else []

    def ipc_audit(_params):
        try:
            rows = client.child_audit()
            store.kv_set("audit_cache", json.dumps(rows))
            return rows
        except Exception:
            raw = store.kv_get("audit_cache", "[]")
            return json.loads(raw) if isinstance(raw, str) else []

    def ipc_tray_ready(params):
        ok = bool(params.get("icon_ok"))
        state["tray_icon_ok"] = ok
        if ok:
            state["last_ipc_at"] = time.monotonic()
        if not ok:
            # F5 chống lạm dụng: không hiển thị được biểu tượng -> agent tự dừng.
            state["fatal"] = True
            _alert_durable(client, store, "tray_icon_failed", {})
            if on_fatal is not None:
                threading.Thread(target=on_fatal, daemon=True).start()
        return {"acknowledged": True}

    def ipc_session_pulse(params):
        # Tray (phien cua tre) bao idle/lock that moi ~3s; probe cua keeper
        # doc tu state["session"] - xem _probe_idle/_probe_locked o tren.
        try:
            idle_val = float(params.get("idle_sec"))
        except (TypeError, ValueError):
            idle_val = None
        state["session"] = {"idle": idle_val,
                            "locked": (None if params.get("locked") is None
                                       else bool(params.get("locked"))),
                            "at": time.time()}
        return {"acknowledged": True}

    def _touch(fn):
        # Chỉ session_pulse mới tính là NHỊP SỐNG của tray: nếu mọi lệnh
        # IPC đều làm mới mốc, một script cầm ipc_token (đọc được trong
        # tray.json) có thể kill tray rồi gọi get_status mãi để watchdog
        # không bao giờ phát hiện mất tray (review 3, NÊN SỬA).
        def wrapped(params):
            state["last_ipc_at"] = time.monotonic()
            return fn(params)
        return wrapped

    ipc = IPCServer(cfg.get("ipc_token", ""), {
        "get_status": ipc_status,
        "get_today": ipc_today,
        "get_week": ipc_week,
        "get_notifications": ipc_notifications,
        "send_request": ipc_send_request,
        "get_requests": ipc_my_requests,
        "get_audit": ipc_audit,
        "tray_ready": ipc_tray_ready,
        "session_pulse": _touch(ipc_session_pulse),
    })

    listener = WSListener(cfg.get("server_url", ""),
                          token_provider=lambda: client.access_token,
                          command_queue=command_queue,
                          cert_fingerprint=cfg.get("cert_fingerprint", ""))

    hub.push({"kind": "agent_started",
              "text": "OpenGuard Kids đang chạy — đồng hành cùng con hôm nay."})
    return {"config": cfg, "store": store, "pm": pm, "client": client, "hub": hub,
            "command_queue": command_queue, "controller": controller, "dns": dns,
            "dns6": dns6,
            "ipc": ipc, "listener": listener, "state": state,
            "on_fatal": on_fatal,
            "session_active_fn": lambda: _child_session_active(
                cfg.get("child_windows_user"))}


TRAY_LOST_AFTER_SEC = 60   # tray gọi IPC mỗi ~3s; quá 60s im lặng = tray đã chết
SESSION_GRACE_SEC = 90     # ân hạn đầu phiên đăng nhập cho tray kịp khởi động
WATCHDOG_PERIOD_SEC = 5


def _session_active() -> bool:
    """Có phiên đăng nhập tương tác hay không — nhận biết qua explorer.exe
    (mỗi phiên người dùng có đúng một tiến trình shell này; service ở
    session 0 vẫn liệt kê được tiến trình các phiên khác qua psutil).
    Chỉ là đường DỰ PHÒNG khi không dùng được WTS (xem _child_session_active)."""
    try:
        import psutil
        for proc in psutil.process_iter(["name"]):
            if (proc.info.get("name") or "").lower() == "explorer.exe":
                return True
    except Exception:
        pass
    return False


def _child_session_active(child_user) -> bool:
    """Phiên đăng nhập của TÀI KHOẢN TRẺ còn hoạt động hay không (WTS).

    Dùng trạng thái phiên của Windows (WTSEnumerateSessions: phiên
    WTSActive + đúng tên user cài đặt ghi trong config child_windows_user)
    thay cho explorer.exe — review 3, CHẶN C2:
    - Trẻ kill explorer.exe KHÔNG đổi trạng thái phiên WTS -> hết đường
      tắt minh bạch mà agent vẫn chạy.
    - Phiên của tài khoản khác (admin lúc cài đặt, phụ huynh) không bị
      tính nhầm -> agent không dừng oan khi trẻ chưa đăng nhập.
    Chưa cấu hình child_windows_user: phiên WTSActive của BẤT KỲ user nào
    cũng tính (vẫn chặn được kill-explorer; installer nên luôn ghi user).
    Không có pywin32 (môi trường kiểm thử Linux): lùi về explorer.exe,
    còn test thật luôn chích session_active_fn giả."""
    try:
        import win32ts
        handle = win32ts.WTS_CURRENT_SERVER_HANDLE
        for s in win32ts.WTSEnumerateSessions(handle):
            if s["State"] != win32ts.WTSActive:
                continue
            if not child_user:
                return True
            try:
                user = win32ts.WTSQuerySessionInformation(
                    handle, s["SessionId"], win32ts.WTSUserName) or ""
            except Exception:
                continue
            if user.lower() == str(child_user).lower():
                return True
        return False
    except Exception:
        if sys.platform == "win32" and not getattr(
                _child_session_active, "_fallback_warned", False):
            # Trên Windows mà không nạp được win32ts thì cơ chế WTS tắt
            # lặng lẽ và đường dò explorer (yếu hơn, chính là lỗ C2) được
            # dùng thay — phải để lại dấu vết trong log service để bài
            # kiểm tay trên Windows phát hiện được.
            _child_session_active._fallback_warned = True
            print("[OGK] CANH BAO: khong nap duoc win32ts - watchdog lui "
                  "ve cach do explorer.exe (kem chinh xac hon).",
                  file=sys.stderr, flush=True)
        return _session_active()


def _alert_durable(client, store, kind: str, detail: dict | None = None) -> None:
    """Gửi alert ngay nếu server nhận; không được thì xếp hàng bền
    pending_alerts trong SQLite — controller xả hàng ở lần sync thành công
    kế tiếp, kể cả ở lần chạy sau (send_alert trả False khi mất mạng chứ
    không ném lỗi, nên phải kiểm giá trị trả về)."""
    try:
        if client is not None and client.send_alert(kind, detail or {}):
            return
    except Exception:
        pass
    try:
        raw = store.kv_get("pending_alerts", "[]")
        alerts = json.loads(raw) if isinstance(raw, str) else []
        alerts.append({"kind": kind, "detail": detail or {}, "ts": time.time()})
        store.kv_set("pending_alerts", json.dumps(alerts[-20:]))
    except Exception:
        pass


def _tray_watchdog_check(runtime, now=None) -> bool:
    """Một lượt kiểm watchdog tray (luật vòng sửa 3). Trả True nếu vừa kích fatal.

    - Không có phiên của TÀI KHOẢN TRẺ (tín hiệu WTS, xem
      _child_session_active): KHÔNG bao giờ fatal — đăng xuất không làm
      agent dừng; agent chờ phiên kế tiếp. Đây là cơ chế thay tray_bye
      (đã bỏ: bất kỳ tiến trình nào của trẻ cũng gọi được tray_bye bằng
      ipc_token đọc được trong tray.json -> lỗ NT1) và thay tín hiệu
      explorer.exe cũ (trẻ kill explorer là lách được — CHẶN C2).
    - Có phiên: ân hạn SESSION_GRACE_SEC đầu phiên cho tray kịp lên; sau
      đó quá TRAY_LOST_AFTER_SEC không có IPC từ tray -> gửi alert
      tray_lost (bền) RỒI mới on_fatal. Không còn điều kiện "đã ready lần
      nào chưa": tray không lên trong một phiên đang hoạt động (bị kill,
      crash, tắt autostart, lỗi ACL) đều là mất minh bạch (F5.8/NT1).
    - Máy vừa ngủ dậy: vòng kiểm bị trễ > 3 chu kỳ -> bỏ qua lượt này và
      làm mới mốc IPC (tray cũng vừa ngủ, chưa kịp gọi lại) — tránh dừng
      oan mỗi lần gập/mở laptop.
    """
    state = runtime["state"]
    now = time.monotonic() if now is None else now
    last_check = state.get("last_watchdog_at", 0.0)
    state["last_watchdog_at"] = now
    if last_check and now - last_check > 3 * WATCHDOG_PERIOD_SEC:
        state["last_ipc_at"] = now
        return False
    if state.get("fatal"):
        return False
    active_fn = runtime.get("session_active_fn") or _session_active
    try:
        active = bool(active_fn())
    except Exception:
        active = False
    if not active:
        state["session_since"] = None
        return False
    if state.get("session_since") is None:
        state["session_since"] = now
        return False
    if now - state["session_since"] < SESSION_GRACE_SEC:
        return False
    if now - state.get("last_ipc_at", 0.0) <= TRAY_LOST_AFTER_SEC:
        return False
    state["fatal"] = True
    _alert_durable(runtime["client"], runtime["store"], "tray_lost", {})
    callback = runtime.get("on_fatal")
    if callback is not None:
        try:
            callback()
        except Exception:
            pass
    return True


def _aggregate_day_events(store, day) -> tuple:
    """Gom sự kiện một ngày: (phút theo ứng dụng, lượt theo miền, số lần chặn).
    Tiến trình hệ thống bị loại như ở báo cáo ngày (cùng một quy tắc lọc)."""
    start = datetime.combine(day, dtime.min).timestamp()
    events = store.day_events(start, start + 86400)
    by_app: dict[str, float] = {}
    by_domain: dict[str, int] = {}
    blocks = {"blocked_app": 0, "blocked_domain": 0}
    for e in events:
        if e["type"] == "app_stop" \
                and (e["subject"] or "").lower() not in SYSTEM_PROCESSES:
            by_app[e["subject"]] = by_app.get(e["subject"], 0.0) + (e["duration_sec"] or 0)
        elif e["type"] == "domain_query":
            by_domain[e["subject"]] = by_domain.get(e["subject"], 0) + 1
        elif e["type"] in blocks:
            blocks[e["type"]] += 1
    return by_app, by_domain, blocks


def _week_summary(store, keeper) -> dict:
    """Báo cáo tuần cho trẻ (NT5): 7 ngày gần nhất gồm hôm nay — ngày, phút
    đã dùng/hạn mức, số lần chặn; tổng tuần và top ứng dụng của tuần. Cùng
    nguồn số liệu với báo cáo ngày nên trẻ và phụ huynh thấy khớp nhau."""
    today = keeper.effective_date()
    days = []
    total_used = 0.0
    week_apps: dict[str, float] = {}
    for back in range(6, -1, -1):
        day = today - timedelta(days=back)
        by_app, _by_domain, blocks = _aggregate_day_events(store, day)
        used = keeper.used_today(day)
        total_used += used
        for name, sec in by_app.items():
            week_apps[name] = week_apps.get(name, 0.0) + sec
        days.append({"date": day.isoformat(),
                     "used_min": round(used / 60, 1),
                     "limit_min": round(keeper.limit_seconds(day) / 60, 1),
                     "blocks": blocks})
    return {"days": days,
            "total_used_min": round(total_used / 60, 1),
            "top_apps": [{"app": k, "minutes": round(v / 60, 1)}
                         for k, v in sorted(week_apps.items(),
                                            key=lambda kv: -kv[1])[:5]]}


def _tray_watchdog(runtime):
    state = runtime["state"]
    while not state.get("stopping"):
        time.sleep(WATCHDOG_PERIOD_SEC)
        try:
            _tray_watchdog_check(runtime)
        except Exception:
            pass


def _start_components(runtime):
    threading.Thread(target=_tray_watchdog, args=(runtime,), daemon=True,
                     name="OGK-TrayWatchdog").start()
    runtime["ipc"].start()
    # Ghi tray.json (thư mục con Users được đọc): tray lấy cổng + token IPC
    # từ đây thay vì đọc config.json chứa bí mật thiết bị (F5.7).
    try:
        cfg = runtime["config"]
        write_tray_info(runtime["ipc"].port, cfg.get("ipc_token", ""),
                        bool(cfg.get("access_token")), cfg.get("child_name", ""))
    except Exception:
        pass
    runtime["controller"].start()
    runtime["listener"].start()
    if runtime.get("dns") is not None:
        try:
            runtime["dns"].start()
        except Exception as exc:
            try:
                runtime["client"].send_alert("dns_bind_failed", {"error": str(exc)})
            except Exception:
                pass
    if runtime.get("dns6") is not None:
        try:
            runtime["dns6"].start()
        except Exception as exc:
            try:
                runtime["client"].send_alert("dns6_bind_failed", {"error": str(exc)})
            except Exception:
                pass
    try:
        runtime["controller"].sync_now()
    except Exception:
        pass


def _stop_components(runtime):
    try:
        runtime["state"]["stopping"] = True
    except Exception:
        pass
    try:
        from agent.config import TRAY_INFO_PATH
    except ImportError:
        from config import TRAY_INFO_PATH
    try:
        TRAY_INFO_PATH.unlink(missing_ok=True)  # cổng trong file đã cũ sau khi dừng
    except OSError:
        pass
    for key in ("listener", "dns", "dns6", "controller", "ipc"):
        component = runtime.get(key)
        if component is not None:
            try:
                component.stop()
            except Exception:
                pass


def run_console():
    # Đường chạy thật trên máy trẻ (WinSW boc che do --console nay). Khi tray
    # bao khong hien duoc bieu tuong, on_fatal chi set event: vong lap chinh
    # thoat, finally dung cac thanh phan, tien trinh tra ma 0 — WinSW bao
    # SERVICE_STOPPED nen SCM khong ap onfailure/restart (thoat khac 0 moi bi
    # coi la crash va restart sau 5/15/60s). KHONG dung sys.exit trong thread
    # cua on_fatal (chi ket thuc thread do) va khong dung os._exit (bo don dep).
    stop_event = threading.Event()
    runtime = build_runtime(on_fatal=stop_event.set)
    try:
        _start_components(runtime)
        print("OpenGuard Kids Agent (console) running. Ctrl+C to stop.")
        while not stop_event.wait(1):
            pass
    except KeyboardInterrupt:
        pass
    finally:
        try:
            _stop_components(runtime)
        except Exception:
            pass  # loi khi dung cung khong duoc bien ma thoat thanh khac 0
    return 0


def _service_log(message: str) -> None:
    """Ghi dau vet cua service ra file ProgramData\\OpenGuardKids\\service.log.

    Event Log cua Windows khong dang tin lam nguon loi duy nhat: tren may tre
    (17/11/2026) nguon ghi cua service khong ton tai, loi khoi dong bi nuot
    mat khong dau vet (service dung ngay, ma thoat 0). File log nay la kenh
    chan doan chinh; moi loi o day deu bi nuot de khong lam chet service.
    """
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(CONFIG_DIR / "service.log", "a", encoding="utf-8") as fh:
            fh.write(f"[{stamp}] {message}\n")
    except Exception:
        pass


def _event_log(kind, code, inserts) -> None:
    """servicemanager.LogMsg co the vang loi neu nguon Event Log chua duoc
    dang ky; khong bao gio de no lam chet SvcDoRun."""
    try:
        servicemanager.LogMsg(kind, code, inserts)
    except Exception:
        pass


if _HAS_WIN32:
    class OpenGuardKidsAgent(win32serviceutil.ServiceFramework):
        _svc_name_ = "OpenGuardKidsAgent"
        _svc_display_name_ = "OpenGuard Kids Agent"
        _svc_description_ = (
            "Dịch vụ OpenGuard Kids: áp dụng giới hạn thời gian và quy tắc sử dụng "
            "do phụ huynh cấu hình trên máy của trẻ. Luôn hiển thị công khai qua "
            "biểu tượng khay hệ thống; không giám sát lén.")

        def __init__(self, args):
            super().__init__(args)
            self.hStopEvent = win32event.CreateEvent(None, 0, 0, None)
            self.runtime = None

        def _stop_runtime(self):
            if self.runtime is not None:
                runtime, self.runtime = self.runtime, None
                _stop_components(runtime)

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.hStopEvent)
            self._stop_runtime()

        def SvcDoRun(self):
            _service_log("SvcDoRun: bat dau")
            _event_log(servicemanager.EVENTLOG_INFORMATION_TYPE,
                       servicemanager.PYS_SERVICE_STARTED,
                       (self._svc_name_, ""))
            try:
                self.runtime = build_runtime(on_fatal=self.SvcStop)
                _service_log("SvcDoRun: da dung runtime")
                _start_components(self.runtime)
                _service_log("SvcDoRun: da khoi dong cac thanh phan")
                self.ReportServiceStatus(win32service.SERVICE_RUNNING)
                _service_log("SvcDoRun: da bao RUNNING, cho tin hieu dung")
                win32event.WaitForSingleObject(self.hStopEvent, win32event.INFINITE)
                _service_log("SvcDoRun: nhan tin hieu dung")
            except Exception:
                detail = traceback.format_exc()
                _service_log("SvcDoRun LOI:\n" + detail)
                try:
                    servicemanager.LogErrorMsg(
                        "OpenGuardKidsAgent failed: " + detail.strip().splitlines()[-1])
                except Exception:
                    pass
            finally:
                self._stop_runtime()
                _service_log("SvcDoRun: ket thuc")
                _event_log(servicemanager.EVENTLOG_INFORMATION_TYPE,
                           servicemanager.PYS_SERVICE_STOPPED,
                           (self._svc_name_, ""))


def _utf8_stdio():
    # Windows: stdout/stderr theo codepage (cp1252/cp1258) — in tiếng Việt ra
    # pipe/log sẽ văng UnicodeEncodeError. Ép UTF-8 như các entry point khác.
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


if __name__ == "__main__":
    _utf8_stdio()
    if "--console" in sys.argv or not _HAS_WIN32:
        run_console()
    else:
        win32serviceutil.HandleCommandLine(OpenGuardKidsAgent)
