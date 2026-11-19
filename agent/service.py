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
from datetime import datetime, time as dtime

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
    from agent.config import CONFIG_DIR, load_config, save_config
    from agent.controller import AgentController
    from agent.dns_proxy import DnsProxy
    from agent.ipc import IPCServer
    from agent.local_store import LocalStore
    from agent.policy import PolicyManager
    from agent.timekeeper import idle_seconds, is_locked
except ImportError:
    from client import ServerClient, WSListener
    from config import CONFIG_DIR, load_config, save_config
    from controller import AgentController
    from dns_proxy import DnsProxy
    from ipc import IPCServer
    from local_store import LocalStore
    from policy import PolicyManager
    from timekeeper import idle_seconds, is_locked

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from shared.contract import SYSTEM_PROCESSES, subject_domain  # noqa: E402


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
             "session": {"idle": None, "locked": None, "at": 0.0}}

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
                       on_event=lambda t, s: controller._emit(t, subject_domain(s)))
    except Exception:
        dns = None
    # Ban IPv6 tren ::1 - bat buoc khi mang co IPv6 (router cap DNS fe80::1):
    # thieu no la trinh duyet phan giai qua router, thoat khoi loc web.
    try:
        dns6 = DnsProxy(pm, bind=("::1", 53),
                        upstream=(cfg.get("upstream_dns") or "8.8.8.8", 53),
                        on_event=lambda t, s: controller._emit(t, subject_domain(s)))
    except Exception:
        dns6 = None

    def ipc_status(_params):
        st = controller.keeper.status()
        st["connected"] = bool(client.access_token)
        st["tray_icon_ok"] = state["tray_icon_ok"]
        return st

    def ipc_today(_params):
        day = controller.keeper.effective_date()
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
        st = controller.keeper.status()
        return {**st,
                "top_apps": [{"app": k, "minutes": round(v / 60, 1)}
                             for k, v in sorted(by_app.items(), key=lambda kv: -kv[1])[:10]],
                "top_domains": [{"domain": k, "queries": v}
                                for k, v in sorted(by_domain.items(), key=lambda kv: -kv[1])[:10]],
                "blocks": blocks}

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
        if not ok:
            # F5 chống lạm dụng: không hiển thị được biểu tượng -> agent tự dừng.
            state["fatal"] = True
            try:
                client.send_alert("tray_icon_failed", {})
            except Exception:
                pass
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
                            "locked": bool(params.get("locked")),
                            "at": time.time()}
        return {"acknowledged": True}

    ipc = IPCServer(cfg.get("ipc_token", ""), {
        "get_status": ipc_status,
        "get_today": ipc_today,
        "get_notifications": ipc_notifications,
        "send_request": ipc_send_request,
        "get_requests": ipc_my_requests,
        "get_audit": ipc_audit,
        "tray_ready": ipc_tray_ready,
        "session_pulse": ipc_session_pulse,
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
            "ipc": ipc, "listener": listener, "state": state}


def _start_components(runtime):
    runtime["ipc"].start()
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
    for key in ("listener", "dns", "dns6", "controller", "ipc"):
        component = runtime.get(key)
        if component is not None:
            try:
                component.stop()
            except Exception:
                pass


def run_console():
    runtime = build_runtime()
    try:
        _start_components(runtime)
        print("OpenGuard Kids Agent (console) running. Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        _stop_components(runtime)


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
