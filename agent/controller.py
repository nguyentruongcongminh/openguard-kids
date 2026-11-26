"""OGK-Agent — AgentController v2: vòng lặp điều phối của agent.

- Mỗi 1s: timekeeper.tick() (quota/lịch/cảnh báo/khóa).
- Mỗi 5s: quét tiến trình — theo dõi phiên ứng dụng (app_start/app_stop có
  duration cho báo cáo), thực thi luật chặn theo SHA-256 trước, tên sau,
  khung giờ, hạn mức theo ứng dụng và ngân sách theo nhóm.
- Mỗi 60s: heartbeat + đồng bộ policy/sự kiện/lệnh (kênh dự phòng cho WS).
"""
import hashlib
import json
import os
import queue
import threading
import time
from datetime import datetime

import psutil

try:
    from agent.timekeeper import TimeKeeper
except ImportError:
    # Fallback khi controller được nạp như module độc lập (chạy file trực
    # tiếp): import tương đối ".timekeeper" sẽ lỗi "attempted relative
    # import with no known parent package" — phải dùng import phẳng.
    from timekeeper import TimeKeeper

from shared.contract import SYSTEM_PROCESSES, subject_domain

WHITELIST = {
    "system", "registry", "csrss.exe", "winlogon.exe", "wininit.exe",
    "services.exe", "lsass.exe", "explorer.exe", "python.exe",
    "pythonw.exe", "ogk_tray.exe", "svchost.exe", "smss.exe", "fontdrvhost.exe",
    "dwm.exe", "ctfmon.exe", "searchhost.exe", "shellexperiencehost.exe",
    "startmenuexperiencehost.exe", "textinputhost.exe", "runtimebroker.exe",
}


def sha256_of_file(path: str, cache: dict) -> str | None:
    try:
        st = os.stat(path)
    except OSError:
        return None
    key = (st.st_mtime_ns, st.st_size)
    hit = cache.get(path)
    if hit and hit[0] == key:
        return hit[1]
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 256), b""):
                h.update(chunk)
        digest = h.hexdigest()
    except OSError:
        return None
    cache[path] = (key, digest)
    return digest


def _minutes_of(value) -> int | None:
    try:
        h, m = str(value).strip().split(":")
        return int(h) * 60 + int(m)
    except Exception:
        return None


def in_windows(windows, when: datetime) -> bool:
    if not windows:
        return True
    current = when.hour * 60 + when.minute
    for w in windows:
        if not isinstance(w, dict):
            continue
        start, end = _minutes_of(w.get("from")), _minutes_of(w.get("to"))
        if start is None or end is None:
            continue
        if start <= end:
            if start <= current <= end:
                return True
        elif current >= start or current <= end:
            return True
    return False


class AgentController:
    def __init__(self, store, pm, client=None, command_queue=None, on_notify=None,
                 idle_fn=None, is_locked_fn=None):
        self.store = store
        self.pm = pm
        self.client = client
        self.command_queue = command_queue if command_queue is not None else queue.Queue()
        self.on_notify = on_notify or (lambda note: None)
        # idle_fn/is_locked_fn: nguon do trang thai phien dang nhap. Khi chay
        # duoi Windows Service (session 0), GetLastInputInfo/OpenInputDesktop
        # chi thay phien 0 -> idle tang vo han -> keeper ngung dem sau 300s
        # (loi that tren may tre 17/11/2026). service.py truyen vao cac ham
        # probe doc so lieu Tray (o dung phien cua tre) bao qua IPC; khong
        # truyen thi dung ham cuc bo nhu cu (che do console).
        self.keeper = TimeKeeper(
            store, pm,
            on_warning=self._on_warning,
            on_lock=self._on_lock,
            on_event=self._emit,
            on_alert=self._on_alert,
            idle_fn=idle_fn,
            is_locked_fn=is_locked_fn,
        )
        self._stop = threading.Event()
        self._thread = None
        self._hash_cache: dict = {}
        self._sessions: dict = {}       # exe -> {name, start, last_seen, missed, category}
        self._last_scan = 0.0
        self._last_sync = 0.0
        self._last_error = 0.0
        self._block_notified: dict = {}  # key -> mono ts (chống spam thông báo)
        self._was_stale = False          # trạng thái stale KT5 của lượt kiểm trước
        self._web_notified: dict = {}    # subject_domain -> mono ts (toast chặn web)
        self._last_web_notify = 0.0      # mono ts của toast chặn web gần nhất

    # ------------------------------------------------------------ vòng đời
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="AgentController")
        self._thread.start()

    def stop(self):
        self._stop.set()
        thread = self._thread
        if thread and thread is not threading.current_thread():
            thread.join(timeout=10)
        self._flush_sessions()

    # ------------------------------------------------------------ callbacks
    def _emit(self, type_: str, subject: str = "", duration: float = 0) -> None:
        # Tiến trình hệ thống chạy nền (vd smartscreen.exe) không phải "ứng
        # dụng con đã dùng" — không ghi vào báo cáo sử dụng.
        if type_ in ("app_start", "app_stop") \
                and (subject or "").lower() in SYSTEM_PROCESSES:
            return
        try:
            self.store.queue_event(type_, subject, duration, self.pm.version())
        except Exception:
            pass

    # ------------------------------------------------------------ sự kiện DNS
    def handle_dns_event(self, type_: str, subject: str = "") -> None:
        """Điểm vào duy nhất cho sự kiện từ DNS proxy (cả v4 lẫn v6).

        Ghi sự kiện như cũ (subject rút về tên miền cấp hai); riêng
        blocked_domain thì kèm thông báo GIẢI THÍCH xuống tray (NT4): trình
        duyệt chỉ hiện lỗi DNS chung chung, không có lời giải thích là trẻ
        tưởng mạng hỏng. Chống spam ở tầng controller (dùng chung cho cả hai
        proxy): mỗi subject tối đa 1 toast/60s và tối thiểu 10s giữa hai
        toast bất kỳ. Lỗi ở bước thông báo không bao giờ được làm hỏng DNS.
        """
        subj = subject_domain(subject)
        self._emit(type_, subj)
        if type_ != "blocked_domain" or not subj:
            return
        try:
            now = time.monotonic()
            if now - self._web_notified.get(subj, -1e18) < 60:
                return
            if now - self._last_web_notify < 10:
                return
            self._web_notified[subj] = now
            self._last_web_notify = now
            _decision, reason = self.pm.web_decision_detail(subject)
            if reason == "rule_block":
                why = "phụ huynh đã đặt luật chặn riêng cho trang này"
            elif reason == "doh_endpoint":
                why = ("đây là dịch vụ DNS bảo mật (DoH) — trình duyệt dùng nó "
                       "sẽ đi vòng qua bộ lọc của OpenGuard Kids")
            else:
                why = "trang thuộc nhóm nội dung phụ huynh chọn chặn"
            text = (f"Trang {subj} bị chặn vì {why}. "
                    f"Luật do phụ huynh đặt (chính sách phiên bản {self.pm.version()}). "
                    "Nếu con cho rằng bị chặn nhầm, hãy bấm nút 'Báo chặn nhầm' "
                    "trong cửa sổ OpenGuard Kids ở khay hệ thống để xin phụ huynh xem lại.")
            self.on_notify({"kind": "blocked_domain", "subject": subj, "text": text})
        except Exception:
            pass

    def _on_warning(self, remaining_sec: int, stage: int) -> None:
        if stage == 0:
            text = ("Đã hết giờ hôm nay — con có 1 phút ân hạn để lưu bài, "
                    "máy sẽ khóa ngay sau đó.")
        else:
            text = f"Còn {stage} phút nữa là hết giờ hôm nay — nhớ lưu bài nhé!"
        self.on_notify({"kind": "warning", "stage": stage, "text": text})

    def _on_lock(self, reason: str) -> None:
        try:
            import ctypes
            ctypes.windll.user32.LockWorkStation()
        except Exception:
            pass  # không phải Windows / không có phiên đồ họa — trạng thái đã ghi nhận
        texts = {"quota": "Đã hết thời gian sử dụng hôm nay.",
                 "schedule": "Ngoài khung giờ được phép sử dụng máy.",
                 "remote": "Phụ huynh vừa khóa máy từ xa."}
        self.on_notify({"kind": "locked", "reason": reason,
                        "text": texts.get(reason, "Máy đã bị khóa.")})

    def _on_alert(self, kind: str, detail: dict) -> None:
        # send_alert trả False khi mất mạng (không ném lỗi): chỉ coi là đã
        # gửi khi trả True, còn lại xếp hàng bền để xả ở lần sync sau.
        if self.client is not None:
            try:
                if self.client.send_alert(kind, detail):
                    return
            except Exception:
                pass
        try:  # offline: giữ lại trong hàng đợi cục bộ để gửi sau qua events? -> kv
            raw = self.store.kv_get("pending_alerts", "[]")
            alerts = json.loads(raw) if isinstance(raw, str) else []
            alerts.append({"kind": kind, "detail": detail, "ts": time.time()})
            self.store.kv_set("pending_alerts", json.dumps(alerts[-20:]))
        except Exception:
            pass

    def _check_stale_transition(self) -> None:
        """Vào/ra trạng thái stale (KT5): báo phụ huynh qua kênh alert và báo
        trẻ qua tray, đúng một lần mỗi chiều chuyển."""
        stale = self.keeper.policy_stale()
        if stale == self._was_stale:
            return
        self._was_stale = stale
        days = round(self.keeper.offline_seconds() / 86400, 1)
        if stale:
            self._on_alert("policy_stale", {"offline_days": days})
            self.on_notify({"kind": "info", "text": (
                f"Máy đã mất kết nối với máy chủ của bố mẹ hơn 7 ngày "
                f"({days} ngày). Giới hạn giờ và lịch tạm mở cho con dùng, "
                "nhưng các trang web và ứng dụng bị chặn vẫn bị chặn như cũ. "
                "Con nói bố mẹ kiểm tra kết nối giúp nhé.")})
        else:
            self._on_alert("policy_fresh", {"offline_days": days})
            self.on_notify({"kind": "info", "text": (
                "Máy đã kết nối lại với máy chủ của bố mẹ — giới hạn giờ và "
                "lịch hoạt động bình thường trở lại.")})

    # ------------------------------------------------------------ vòng lặp
    def _loop(self):
        while not self._stop.is_set():
            try:
                self.keeper.tick()
            except Exception:
                pass
            try:
                self._check_stale_transition()
            except Exception:
                pass
            now = time.monotonic()
            if now - self._last_scan >= 5:
                dt_scan = now - self._last_scan if self._last_scan else 5.0
                self._last_scan = now
                try:
                    self._scan_processes(min(dt_scan, 30.0))
                except Exception:
                    pass
            try:
                self._drain_commands()
            except Exception:
                pass
            if now - self._last_sync >= 60:
                self._last_sync = now
                try:
                    self.sync_now()
                except Exception:
                    pass
            self._stop.wait(1)

    # ------------------------------------------------------------ tiến trình
    @staticmethod
    def _is_system_account(username) -> bool:
        """Tiến trình của SYSTEM/LOCAL SERVICE/NETWORK SERVICE là dịch vụ nền
        của Windows/antivirus — không phải "ứng dụng trẻ đã dùng": không ghi
        phiên, không tính ngân sách nhóm cho chúng. (Trên máy trẻ thật
        17/11/2026, WUDFHost/LsaIso/ekrn/Intel/NVIDIA... hiện 43 phút trong
        báo cáo vì chạy từ lúc mở máy.)"""
        u = str(username or "").lower()
        return u == "system" or u.endswith(
            ("\\system", "\\local service", "\\network service"))

    def _rule_for(self, name: str, exe: str):
        """Khớp luật: theo SHA-256 trước (chống đổi tên file), theo tên sau."""
        rules = self.pm.app_rules()
        digest = None
        for rule in rules:
            if rule.get("sha256"):
                if digest is None:
                    digest = sha256_of_file(exe, self._hash_cache)
                if digest and digest.lower() == str(rule["sha256"]).lower():
                    return rule
        lname = (name or "").lower()
        for rule in rules:
            if not rule.get("sha256") and str(rule.get("name", "")).lower() == lname:
                return rule
        return None

    def _scan_processes(self, dt_scan: float) -> None:
        now_mono = time.monotonic()
        when = self.keeper.trusted_now()
        day = self.keeper.effective_date().isoformat()
        present = {}
        for proc in psutil.process_iter(["pid", "name", "exe", "username"]):
            try:
                info = proc.info or {}
                name = str(info.get("name") or "")
                exe = str(info.get("exe") or "")
            except Exception:
                continue
            if not exe or name.lower() in WHITELIST:
                continue
            if self._is_system_account(info.get("username")):
                continue
            present.setdefault(exe, {"name": name, "pids": []})["pids"].append(proc.pid)

        # mở/đóng phiên
        for exe, info in present.items():
            if exe not in self._sessions:
                self._sessions[exe] = {"name": info["name"], "start": now_mono,
                                       "last_seen": now_mono, "missed": 0}
                self._emit("app_start", info["name"])
            else:
                self._sessions[exe]["last_seen"] = now_mono
                self._sessions[exe]["missed"] = 0
        for exe in list(self._sessions):
            if exe not in present:
                sess = self._sessions[exe]
                sess["missed"] += 1
                if sess["missed"] >= 2:
                    duration = sess["last_seen"] - sess["start"]
                    if duration >= 3:
                        self._emit("app_stop", sess["name"], round(duration, 1))
                    del self._sessions[exe]

        # ngân sách theo nhóm + hạn mức theo ứng dụng (tích lũy theo phiên đang chạy)
        budgets = self.pm.group_budgets()
        cat_active: dict[str, list] = {}
        for exe, info in present.items():
            rule = self._rule_for(info["name"], exe)
            category = (rule or {}).get("category") or "khac"
            cat_active.setdefault(category, []).append((exe, info, rule))
            if rule is not None:
                key = f"app_used_{info['name'].lower()}_{day}"
                self.store.kv_set(key, float(self.store.kv_get(key, 0) or 0) + dt_scan)
        for category, members in cat_active.items():
            key = f"cat_used_{category}_{day}"
            used = float(self.store.kv_get(key, 0) or 0) + dt_scan
            self.store.kv_set(key, used)
            budget = budgets.get(category)
            # KT5: khi stale, ngân sách nhóm (phần thời gian) cũng fail-open
            # như quota/lịch; luật chặn app đích danh vẫn thi hành ở dưới.
            if budget is not None and used > float(budget) * 60 \
                    and not self.keeper.policy_stale():
                for exe, info, _rule in members:
                    self._block(exe, info, "category_cap",
                                f"Nhóm '{category}' đã hết ngân sách {budget} phút hôm nay")

        # luật theo ứng dụng
        for exe, info in present.items():
            rule = self._rule_for(info["name"], exe)
            if rule is None:
                continue
            name = info["name"]
            if rule.get("action") == "block":
                self._block(exe, info, "block_rule",
                            "Ứng dụng nằm trong danh sách chặn của phụ huynh")
            elif not in_windows(rule.get("windows") or [], when):
                wins = ", ".join(f"{w.get('from')}–{w.get('to')}" for w in rule.get("windows", []))
                self._block(exe, info, "outside_window",
                            f"Ngoài khung giờ được phép ({wins})")
            elif rule.get("daily_cap_min") is not None:
                used = float(self.store.kv_get(f"app_used_{name.lower()}_{day}", 0) or 0)
                if used > float(rule["daily_cap_min"]) * 60:
                    self._block(exe, info, "daily_cap",
                                f"Đã dùng hết {rule['daily_cap_min']} phút cho ứng dụng này hôm nay")

    def _block(self, exe: str, info: dict, reason_kind: str, detail: str) -> None:
        name = info["name"]
        for pid in info.get("pids", []):
            try:
                psutil.Process(pid).terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        self._sessions.pop(exe, None)
        self._emit("blocked_app", name)
        spam_key = f"{name}:{reason_kind}"
        now = time.monotonic()
        if now - self._block_notified.get(spam_key, -1e18) > 300:
            self._block_notified[spam_key] = now
            self.on_notify({
                "kind": "blocked_app", "subject": name,
                "text": (f"Ứng dụng {name} đã bị chặn. Lý do: {detail}. "
                         f"Luật do phụ huynh đặt (chính sách phiên bản {self.pm.version()}). "
                         "Nếu con nghĩ bị chặn nhầm, hãy bấm 'Báo chặn nhầm' trong cửa sổ OpenGuard Kids."),
            })

    def _flush_sessions(self) -> None:
        now_mono = time.monotonic()
        for exe, sess in list(self._sessions.items()):
            duration = sess["last_seen"] - sess["start"]
            if duration >= 3:
                self._emit("app_stop", sess["name"], round(duration, 1))
        self._sessions.clear()

    # ------------------------------------------------------------ lệnh
    def _drain_commands(self) -> None:
        while True:
            try:
                msg = self.command_queue.get_nowait()
            except queue.Empty:
                return
            if isinstance(msg, dict) and msg.get("type") == "command":
                self.execute_command(msg.get("command") or {})
            elif isinstance(msg, dict) and msg.get("type") == "request_decided":
                req = msg.get("request") or {}
                verdict = "được đồng ý" if req.get("status") == "approved" else "bị từ chối"
                self.on_notify({"kind": "request_decided",
                                "text": f"Yêu cầu của con {verdict}. {req.get('decision_note') or ''}"})
            elif isinstance(msg, dict) and msg.get("type") == "policy_updated":
                try:
                    self.sync_now()
                except Exception:
                    pass
            elif isinstance(msg, dict) and ("type" in msg or "command" in msg):
                self.execute_command(msg)

    def execute_command(self, cmd: dict) -> None:
        if not isinstance(cmd, dict):
            return
        ctype = cmd.get("type") or cmd.get("command")
        payload = cmd.get("payload") if isinstance(cmd.get("payload"), dict) else {}
        keeper = self.keeper
        if ctype == "lock_now":
            keeper.lock_now()
        elif ctype == "unlock":
            keeper.unlock()
        elif ctype == "grant_extra":
            keeper.add_extra(payload.get("minutes", 15))
            self.on_notify({"kind": "info",
                            "text": f"Phụ huynh vừa cộng thêm {payload.get('minutes', 15)} phút cho con."})
        elif ctype == "break_15":
            keeper.apply_break(15)
        elif ctype == "pause_today":
            keeper.apply_pause_today()
        elif ctype == "wipe_cache":
            self.store.wipe()
            self.pm.reload_from_store()
        else:
            return
        if cmd.get("id") and self.client is not None:
            try:
                self.client.ack_command(int(cmd["id"]))
            except Exception:
                pass

    # ------------------------------------------------------------ đồng bộ
    def sync_now(self) -> dict:
        result = {"online": False}
        if self.client is None:
            return result
        # cảnh báo hệ thống đang chờ (vd chỉnh giờ khi mất mạng) — chỉ xóa
        # những cảnh báo đã gửi THẬT (send_alert trả True), giữ lại phần lỗi
        try:
            raw = self.store.kv_get("pending_alerts", "[]")
            pending = json.loads(raw) if isinstance(raw, str) else []
            remaining = []
            for item in pending:
                sent = False
                try:
                    sent = bool(self.client.send_alert(
                        item.get("kind", "alert"), item.get("detail", {})))
                except Exception:
                    sent = False
                if not sent:
                    remaining.append(item)
            if pending:
                self.store.kv_set("pending_alerts", json.dumps(remaining[-20:]))
        except Exception:
            pass
        status = self.keeper.status()
        resp = self.client.heartbeat({
            "used_today_sec": int(status["used_min"] * 60),
            "policy_version": self.pm.version(),
            "status": "locked" if status["remaining_min"] <= 0 else "active",
        })
        if not isinstance(resp, dict):
            return result
        result["online"] = True
        self.keeper.reset_offline()  # đồng bộ thành công -> xóa bộ đếm KT5
        if resp.get("server_time"):
            self.keeper.set_server_anchor(float(resp["server_time"]))
        for cmd in resp.get("pending_commands", []) or []:
            self.execute_command(cmd)
        if int(resp.get("latest_policy_version", 0)) > self.pm.version():
            doc = self.client.fetch_policy()
            if doc is not None and not self.pm.update(doc):
                self._on_alert("policy_rejected", {"offered_version": doc.get("version")})
        events = self.store.pop_queued_events(100)
        if events:
            out = self.client.upload_events(events)
            if out is not None:
                self.store.mark_events_sent([e["event_id"] for e in events])
                result["events_sent"] = len(events)
        # yêu cầu của trẻ gửi lúc mất mạng
        try:
            raw = self.store.kv_get("pending_requests", "[]")
            pending_reqs = json.loads(raw) if isinstance(raw, str) else []
            remaining = []
            for item in pending_reqs:
                if not self.client.send_request(item.get("type"), item.get("minutes"),
                                                item.get("subject"), item.get("reason", "")):
                    remaining.append(item)
            self.store.kv_set("pending_requests", json.dumps(remaining))
        except Exception:
            pass
        self.store.purge_old_events(90)
        return result
