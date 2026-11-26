"""OGK-Agent — TimeKeeper v2 (F1): quota theo ngày thường/cuối tuần, lịch tuần
7x48, đếm thời gian thực (trừ khóa máy/idle >= 5 phút), cảnh báo 10/5/1 phút,
ân hạn 60 giây, chống chỉnh đồng hồ hệ thống.

Thời gian "đáng tin" (trusted) = mốc giờ server gần nhất + độ trôi monotonic;
nếu chưa có mốc server thì dùng giờ hệ thống nhưng NGÀY HIỆU LỰC KHÔNG BAO GIỜ
ĐI LÙI — lùi đồng hồ không làm quota tăng trở lại.
"""
from __future__ import annotations

import ctypes
import time
from datetime import date, datetime
from typing import Callable

try:
    import win32api
except Exception:
    win32api = None

__all__ = ["idle_seconds", "is_locked", "TimeKeeper"]


class _LastInputInfo(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_ulong)]


def idle_seconds() -> float:
    try:
        if win32api is not None:
            elapsed = (int(win32api.GetTickCount()) - int(win32api.GetLastInputInfo())) & 0xFFFFFFFF
            return elapsed / 1000.0
    except Exception:
        pass
    try:
        info = _LastInputInfo()
        info.cbSize = ctypes.sizeof(info)
        if not ctypes.windll.user32.GetLastInputInfo(ctypes.byref(info)):
            return 0.0
        elapsed = (int(ctypes.windll.kernel32.GetTickCount()) - int(info.dwTime)) & 0xFFFFFFFF
        return elapsed / 1000.0
    except Exception:
        return 0.0


def is_locked() -> bool:
    try:
        import win32service

        desktop = win32service.OpenInputDesktop(0, False, 0x0001)
        try:
            name = win32service.GetUserObjectInformation(desktop, win32service.UOI_NAME)
        finally:
            try:
                win32service.CloseDesktop(desktop)
            except Exception:
                pass
        return isinstance(name, str) and name.lower() != "default"
    except Exception:
        return False


def _f(value, default=0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


class TimeKeeper:
    def __init__(self, store, policy_manager,
                 on_warning: Callable[[int, int], None] | None = None,
                 on_lock: Callable[[str], None] | None = None,
                 on_event: Callable[[str, str, float], None] | None = None,
                 on_alert: Callable[[str, dict], None] | None = None,
                 mono_fn=None, wall_fn=None, is_locked_fn=None, idle_fn=None):
        self.store = store
        self.pm = policy_manager
        self.on_warning = on_warning
        self.on_lock = on_lock
        self.on_event = on_event
        self.on_alert = on_alert
        self._mono = mono_fn or time.monotonic
        self._wall = wall_fn or time.time
        self._is_locked = is_locked_fn or is_locked
        self._idle = idle_fn or idle_seconds
        self._last_mono = None
        self._last_wall = None
        self._last_lock_mono = -1e18
        self._last_alert_mono = -1e18
        self._grace_start_mono = None

    # ------------------------------------------------------------ thời gian đáng tin
    def set_server_anchor(self, server_ts: float) -> None:
        self.store.kv_set("anchor_server_ts", float(server_ts))
        self.store.kv_set("anchor_mono", self._mono())

    def trusted_epoch(self) -> float:
        anchor_ts = self.store.kv_get("anchor_server_ts")
        anchor_mono = self.store.kv_get("anchor_mono")
        if anchor_ts is not None and anchor_mono is not None:
            return _f(anchor_ts) + (self._mono() - _f(anchor_mono))
        return self._wall()

    def trusted_now(self) -> datetime:
        return datetime.fromtimestamp(self.trusted_epoch())

    def effective_date(self) -> date:
        today = self.trusted_now().date()
        last_seen = self.store.kv_get("last_seen_date")
        if last_seen:
            try:
                last = date.fromisoformat(str(last_seen))
                if today < last:
                    return last  # ngày không đi lùi (chống chỉnh giờ)
            except ValueError:
                pass
        if not last_seen or str(today) != str(last_seen):
            self.store.kv_set("last_seen_date", today.isoformat())
        return today

    # ------------------------------------------------------------ mất kết nối (KT5)
    STALE_AFTER_SEC = 7 * 86400  # mốc 7 ngày theo quyết định KT5 (tài liệu kiến trúc §3.1)

    def offline_seconds(self) -> float:
        """Tổng thời gian chưa đồng bộ thành công, cộng dồn chống chỉnh giờ."""
        return _f(self.store.kv_get("offline_elapsed_sec", 0))

    def policy_stale(self) -> bool:
        return self.offline_seconds() > self.STALE_AFTER_SEC

    def reset_offline(self) -> None:
        self.store.kv_set("offline_elapsed_sec", 0.0)

    def _accumulate_offline(self, mono_now: float, wall_now: float) -> None:
        """Cộng dồn thời gian mất kết nối — phải chạy TRƯỚC khi _last_* bị ghi đè.

        - Trong phiên chạy: cộng min(Δgiờ tường, Δmonotonic) mỗi tick, nên
          chỉnh đồng hồ tiến +8 ngày lúc máy đang chạy cũng chỉ cộng theo
          thời gian monotonic thật (không lách được mốc 7 ngày).
        - Qua reboot: cộng khoảng giờ tường kể từ tick cuối đã lưu (nếu >= 0).
        - Máy nâng cấp chưa có khóa này: bắt đầu từ 0, không stale oan.
        Đặt lại 0 khi đồng bộ thành công (controller gọi reset_offline).
        """
        elapsed = _f(self.store.kv_get("offline_elapsed_sec", 0))
        if self._last_mono is not None and self._last_wall is not None:
            elapsed += min(max(wall_now - self._last_wall, 0.0),
                           max(mono_now - self._last_mono, 0.0))
        else:
            last_wall = self.store.kv_get("last_tick_wall")
            if last_wall is not None:
                gap = wall_now - _f(last_wall)
                if gap > 0:
                    elapsed += gap
        self.store.kv_set("offline_elapsed_sec", elapsed)
        self.store.kv_set("last_tick_wall", wall_now)

    # ------------------------------------------------------------ trạng thái
    def _key(self, prefix: str, day: date) -> str:
        return f"{prefix}_{day.isoformat()}"

    def used_today(self, day: date | None = None) -> float:
        day = day or self.effective_date()
        return _f(self.store.kv_get(self._key("used_seconds", day), 0))

    def extra_today(self, day: date | None = None) -> float:
        day = day or self.effective_date()
        return _f(self.store.kv_get(self._key("extra_seconds", day), 0))

    def limit_seconds(self, day: date | None = None) -> float:
        day = day or self.effective_date()
        return self.pm.quota_minutes_for(day) * 60 + self.extra_today(day)

    def remaining_seconds(self, day: date | None = None) -> float:
        day = day or self.effective_date()
        return self.limit_seconds(day) - self.used_today(day)

    def is_paused(self, day: date | None = None) -> bool:
        day = day or self.effective_date()
        return str(self.store.kv_get("paused_date", "") or "") == day.isoformat()

    def break_left(self) -> float:
        return max(0.0, _f(self.store.kv_get("break_until", 0)) - self.trusted_epoch())

    def override_left(self) -> float:
        return max(0.0, _f(self.store.kv_get("override_until", 0)) - self.trusted_epoch())

    def status(self) -> dict:
        day = self.effective_date()
        used = self.used_today(day)
        limit = self.limit_seconds(day)
        return {
            "date": day.isoformat(),
            "used_min": round(used / 60, 1),
            "limit_min": round(limit / 60, 1),
            "extra_min": round(self.extra_today(day) / 60, 1),
            "remaining_min": round(max(0.0, limit - used) / 60, 1),
            "paused_today": self.is_paused(day),
            "break_left_sec": int(self.break_left()),
            "policy_version": self.pm.version(),
            "offline_days": round(self.offline_seconds() / 86400, 1),
            "policy_stale": self.policy_stale(),
        }

    # ------------------------------------------------------------ sự kiện phụ
    def _emit(self, type_: str, subject: str = "", duration: float = 0) -> None:
        if self.on_event:
            try:
                self.on_event(type_, subject, duration)
            except Exception:
                pass

    def _warn(self, remaining: float, stage: int) -> None:
        if self.on_warning:
            try:
                self.on_warning(int(max(0, remaining)), int(stage))
            except Exception:
                pass

    def _do_lock(self, reason: str) -> bool:
        now = self._mono()
        if now - self._last_lock_mono < 60:
            return False
        self._last_lock_mono = now
        self._emit("locked", reason)
        if self.on_lock:
            try:
                self.on_lock(reason)
            except Exception:
                pass
        return True

    # ------------------------------------------------------------ tick chính
    def tick(self, dt: float | None = None) -> list[str]:
        fired: list[str] = []
        mono_now = self._mono()
        wall_now = self._wall()
        if dt is None:
            dt = 0.0 if self._last_mono is None else max(0.0, mono_now - self._last_mono)
        # --- chống chỉnh đồng hồ: so độ trôi tường vs monotonic
        if self._last_mono is not None and self._last_wall is not None:
            mono_delta = mono_now - self._last_mono
            wall_delta = wall_now - self._last_wall
            if mono_delta <= 300:  # bỏ qua tick ngay sau khi máy ngủ/thức
                skew = wall_delta - mono_delta
                if skew < -120 or skew > 3600:
                    if mono_now - self._last_alert_mono > 600:
                        self._last_alert_mono = mono_now
                        if self.on_alert:
                            try:
                                self.on_alert("clock_tamper", {
                                    "skew_seconds": round(skew),
                                    "wall_now": wall_now})
                            except Exception:
                                pass
                        fired.append("clock_tamper")
        self._accumulate_offline(mono_now, wall_now)
        self._last_mono = mono_now
        self._last_wall = wall_now

        if self.is_paused() or self.break_left() > 0:
            return fired
        day = self.effective_date()

        # --- đếm thời gian sử dụng thực
        if dt > 0 and not self._is_locked() and self._idle() < 300:
            total = self.used_today(day) + dt
            self.store.kv_set(self._key("used_seconds", day), total)

        if self.override_left() > 0:
            return fired

        # --- KT5: mất kết nối quá 7 ngày -> fail-open PHẦN THỜI GIAN: không
        # khóa theo lịch/quota nữa (tránh khóa trẻ khỏi máy học tập vô thời
        # hạn vì lỗi hạ tầng) nhưng vẫn ĐẾM giờ như thường; chặn web (nhóm,
        # đích danh, DoH, SafeSearch) và luật chặn app vẫn giữ — các đường đó
        # không đi qua tick này. Thoát stale thì cảnh báo/ân hạn chạy lại.
        if self.policy_stale():
            return fired

        # --- lịch tuần 7x48: ngoài khung giờ cho phép -> khóa ngay
        from shared.contract import schedule_allows
        schedule = self.pm.time_cfg().get("schedule")
        if schedule is not None and not schedule_allows(schedule, self.trusted_now()):
            if self._do_lock("schedule"):
                fired.append("locked_schedule")
            return fired

        # --- quota + cảnh báo 10/5/1 + ân hạn
        remaining = self.remaining_seconds(day)
        t = self.pm.time_cfg()
        stages = sorted((int(s) for s in t.get("warn_at_min", [10, 5, 1])), reverse=True)
        for stage in stages:
            key = self._key(f"warned_{stage}", day)
            if remaining <= stage * 60 and not self.store.kv_get(key):
                self.store.kv_set(key, "1")
                self._warn(stage * 60 if remaining > stage * 60 - 60 else remaining, stage)
                self._emit("quota_warning", f"{stage}m")
                fired.append(f"warning_{stage}")
        if remaining <= 0:
            grace = float(t.get("grace_sec", 60) or 0)
            if grace > 0 and self._grace_start_mono is None:
                self._grace_start_mono = mono_now
                self._warn(0, 0)  # stage 0 = đang trong ân hạn
                fired.append("grace_start")
            elif grace <= 0 or mono_now - self._grace_start_mono >= grace:
                if self._do_lock("quota"):
                    fired.append("locked_quota")
        else:
            self._grace_start_mono = None
        return fired

    # ------------------------------------------------------------ lệnh từ phụ huynh
    def add_extra(self, minutes) -> None:
        day = self.effective_date()
        key = self._key("extra_seconds", day)
        self.store.kv_set(key, self.extra_today(day) + int(_f(minutes) * 60))
        self._grace_start_mono = None
        self._emit("override_granted", f"+{int(_f(minutes))}m")

    def apply_break(self, minutes: float = 15) -> None:
        self.store.kv_set("break_until", self.trusted_epoch() + minutes * 60)

    def apply_pause_today(self) -> None:
        self.store.kv_set("paused_date", self.effective_date().isoformat())

    def unlock(self) -> None:
        self.store.kv_set("override_until", self.trusted_epoch() + 15 * 60)
        self._grace_start_mono = None

    def lock_now(self) -> None:
        self._last_lock_mono = -1e18  # bỏ qua throttle cho lệnh khẩn
        self._do_lock("remote")
