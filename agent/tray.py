"""OGK-Agent — Tray UI v2 dành cho trẻ (NT1/NT3/NT5).

- Biểu tượng khay hệ thống (pystray) LUÔN hiển thị khi agent chạy; nếu không
  tạo được biểu tượng, tray báo service qua IPC và thoát — service tự dừng
  (yêu cầu chống lạm dụng F5, không có chế độ ẩn).
- Mọi dữ liệu đi qua IPC tới service (không tự gọi server, không ghi DB).
- Cửa sổ: thời gian còn lại, "Hôm nay em đã dùng gì", Xin thêm giờ,
  Báo chặn nhầm, Nhật ký thay đổi luật của phụ huynh.
"""
import json
import queue
import sys
import threading
import time
import traceback
from pathlib import Path

try:
    from .client import ServerClient  # noqa: F401  (giữ tương thích import cũ)
    from .config import TRAY_INFO_PATH, load_tray_info
    from .ipc import IPCClient
except ImportError:
    from config import TRAY_INFO_PATH, load_tray_info
    from ipc import IPCClient

# Do idle/lock cua DUNG phien dang nhap nay de bao cho service qua IPC
# (session_pulse): service o session 0 khong thay duoc phien cua tre.
# Khong import duoc thi bo qua pulse - service tu lui ve cach do cuc bo.
try:
    try:
        from .timekeeper import idle_seconds, is_locked
    except ImportError:
        from timekeeper import idle_seconds, is_locked
except Exception:
    idle_seconds = None
    is_locked = None


# ------------------------------------------------------------------ helpers (thuần, có test)
def fmt_minutes(minutes) -> str:
    try:
        m = int(float(minutes))
    except (TypeError, ValueError):
        m = 0
    m = max(0, m)
    hours, mins = divmod(m, 60)
    return f"{hours} giờ {mins} phút" if hours else f"{mins} phút"


def status_line(status: dict) -> str:
    if status.get("paused_today"):
        return "Hôm nay phụ huynh đã tạm dừng giới hạn giờ."
    if status.get("break_left_sec", 0) > 0:
        return f"Đang trong giờ nghỉ, còn {fmt_minutes(status['break_left_sec'] / 60)}."
    # Hien thi nhat quan: cat le tung so rieng le lam da-dung + con-lai khong
    # bang han muc (vd dung 13.6/20 -> "13" va "6"). Tinh so con lai tu hai
    # so nguyen da hien thi de tong luc nao cung khop (13 + 7 = 20).
    try:
        used_i = int(float(status.get("used_min", 0) or 0))
    except (TypeError, ValueError):
        used_i = 0
    try:
        limit_i = int(float(status.get("limit_min", 0) or 0))
    except (TypeError, ValueError):
        limit_i = 0
    rem_i = max(0, limit_i - used_i)
    return (f"Hôm nay con đã dùng {fmt_minutes(used_i)} / "
            f"{fmt_minutes(limit_i)}. "
            f"Còn lại: {fmt_minutes(rem_i)}.")


def today_lines(today: dict) -> list[str]:
    lines = [status_line(today),
             f"Số lần ứng dụng bị chặn: {today.get('blocks', {}).get('blocked_app', 0)}",
             f"Số lần trang web bị chặn: {today.get('blocks', {}).get('blocked_domain', 0)}"]
    if today.get("top_apps"):
        lines.append("Ứng dụng dùng nhiều nhất:")
        for item in today["top_apps"]:
            lines.append(f"  • {item['app']}: {fmt_minutes(item['minutes'])}")
    if today.get("top_domains"):
        lines.append("Trang web vào nhiều nhất:")
        for item in today["top_domains"]:
            lines.append(f"  • {item['domain']}: {item['queries']} lần")
    lines.append("Bố mẹ và con đều nhìn thấy cùng báo cáo này.")
    return lines


def week_lines(week: dict) -> list[str]:
    """Báo cáo tuần cho trẻ (NT5): từng ngày đã dùng/hạn mức + tổng tuần +
    top ứng dụng — cùng nguồn số liệu với báo cáo ngày và báo cáo phụ huynh."""
    from datetime import date as _date
    names = ["Thứ 2", "Thứ 3", "Thứ 4", "Thứ 5", "Thứ 6", "Thứ 7", "Chủ nhật"]
    lines = []
    for d in (week or {}).get("days", []):
        try:
            label = names[_date.fromisoformat(d["date"]).weekday()]
        except Exception:
            label = d.get("date", "")
        lines.append(f"{label} {d.get('date', '')}: đã dùng "
                     f"{fmt_minutes(d.get('used_min', 0))} / "
                     f"hạn mức {fmt_minutes(d.get('limit_min', 0))}")
    lines.append(f"Tổng cả tuần: {fmt_minutes((week or {}).get('total_used_min', 0))}")
    if (week or {}).get("top_apps"):
        lines.append("Ứng dụng dùng nhiều nhất tuần:")
        for item in week["top_apps"]:
            lines.append(f"  • {item['app']}: {fmt_minutes(item['minutes'])}")
    lines.append("Bố mẹ và con đều nhìn thấy cùng báo cáo này.")
    return lines


def _change_summary(old, new) -> str:
    """Tóm tắt thay đổi cũ -> mới cho nhật ký của trẻ (NT5): tối đa 3 khóa."""
    if isinstance(old, dict) and isinstance(new, dict):
        parts = []
        for k in sorted(set(old) | set(new)):
            if old.get(k) != new.get(k):
                parts.append(f"{k}: {old.get(k)} → {new.get(k)}")
        return "; ".join(parts[:3])
    return ""


def audit_lines(rows: list) -> list[str]:
    labels = {"policy.update": "thay đổi chính sách", "command.create": "gửi lệnh từ xa",
              "request.decide": "phản hồi yêu cầu của con", "consent.pairing": "ghép đôi thiết bị"}
    out = []
    for r in rows or []:
        when = str(r.get("ts") or "")[:16].replace("T", " ")
        what = labels.get(r.get("action"), r.get("action"))
        line = f"{when} — {r.get('actor', '')} đã {what}."
        summary = _change_summary(r.get("old"), r.get("new"))
        if summary:
            line += f" ({summary})"
        if r.get("ip"):
            line += f" [từ {r['ip']}]"
        out.append(line)
    return out or ["Chưa có thay đổi nào."]


# ------------------------------------------------------------------ lõi giao tiếp IPC
class TrayCore:
    def __init__(self, cfg):
        self.cfg = cfg
        self.ipc = IPCClient(cfg.get("ipc_token", ""), info_path=TRAY_INFO_PATH)

    def call(self, method, **params):
        return self.ipc.call(method, **params)

    def status(self):
        return self.call("get_status")

    def today(self):
        return self.call("get_today")

    def week(self):
        return self.call("get_week")

    def notifications(self):
        return self.call("get_notifications") or []

    def send_extra_time(self, minutes, reason=""):
        return self.call("send_request", type="extra_time", minutes=int(minutes),
                         reason=reason)

    def send_false_block(self, subject, reason=""):
        return self.call("send_request", type="false_block", subject=subject,
                         reason=reason)

    def audit(self):
        return self.call("get_audit") or []

    def tray_ready(self, icon_ok: bool):
        try:
            return self.call("tray_ready", icon_ok=bool(icon_ok))
        except Exception:
            return None

    def session_pulse(self, idle_sec, locked):
        try:
            return self.call("session_pulse", idle_sec=idle_sec, locked=locked)
        except Exception:
            return None


def _lock_workstation() -> None:
    """Khóa phiên của trẻ từ chính phiên đó (service ở session 0 gọi
    LockWorkStation sẽ không khóa được phiên của trẻ)."""
    try:
        import ctypes
        ctypes.windll.user32.LockWorkStation()
    except Exception:
        pass


class Heartbeat:
    """Nhịp sống của tray — chạy trên LUỒNG RIÊNG, tách hẳn khỏi UI
    (review 3, CHẶN C1).

    Trước đây nhịp session_pulse nằm trong poll() của mainloop Tk, mà
    show_note lại mở hộp thoại MODAL chờ trẻ bấm OK: hộp thoại mở quá 60s
    là đứt nhịp, watchdog tưởng tray chết và dừng agent oan; note "locked"
    đến trong lúc hộp thoại khác đang mở cũng không khóa được máy.

    Thiết kế mới:
    - pulse_fn(): gửi session_pulse mỗi interval (đo idle/lock tại chỗ).
    - fetch_fn(): lấy thông báo mới từ service.
    - lock_fn(): khóa máy NGAY trong luồng này khi gặp note "locked" —
      không chờ UI; hộp thoại "Máy bị khóa" hiện sau cũng được.
    - display_fn(note): hiển thị thông báo. step() KHÔNG gọi trực tiếp:
      note được đẩy vào hàng đợi nội bộ, một luồng dispatch riêng gọi
      display_fn — nên display_fn có chặn bao lâu (hộp thoại chờ trẻ,
      Tk bận) cũng không làm đứt nhịp (review 4, N1).
    - alive_fn(): biểu tượng khay còn sống không; chết -> ngừng nhịp để
      watchdog của service phát hiện tray mất (F5.8).
    """

    def __init__(self, pulse_fn, fetch_fn, lock_fn, display_fn, alive_fn,
                 interval: float = 3.0):
        self._pulse = pulse_fn
        self._fetch = fetch_fn
        self._lock = lock_fn
        self._display = display_fn
        self._alive = alive_fn
        self.interval = interval
        self._display_queue: queue.Queue = queue.Queue()

    def step(self) -> bool:
        """Một nhịp. Trả False khi biểu tượng đã chết (ngừng hẳn)."""
        try:
            if not self._alive():
                return False
        except Exception:
            return False
        try:
            self._pulse()
        except Exception:
            pass
        try:
            notes = self._fetch() or []
        except Exception:
            notes = []
        for note in notes:
            if (note or {}).get("kind") == "locked":
                try:
                    self._lock()
                except Exception:
                    pass
            self._display_queue.put(note)
        return True

    def flush_display(self) -> None:
        """Đẩy hết note đang chờ sang display_fn (gọi từ luồng dispatch;
        test gọi trực tiếp để kiểm đồng bộ)."""
        while True:
            try:
                note = self._display_queue.get_nowait()
            except queue.Empty:
                return
            try:
                self._display(note)
            except Exception:
                pass

    def _dispatch(self, stop_event) -> None:
        while not stop_event.is_set():
            self.flush_display()
            stop_event.wait(0.05)

    def run(self, stop_event) -> None:
        threading.Thread(target=self._dispatch, args=(stop_event,),
                         daemon=True, name="OGK-TrayDisplay").start()
        while not stop_event.is_set():
            if not self.step():
                break
            stop_event.wait(self.interval)


def _icon_alive(icon) -> bool:
    """Biểu tượng khay còn sống không — qua luồng riêng của pystray.
    pystray chỉ đặt _thread SAU khi tạo xong cửa sổ khay, nên lúc mới
    khởi động _thread có thể chưa có: hàm này trả False và nơi gọi phải
    CHỜ (xem _wait_for_icon), không được kết luận icon chết ngay —
    kết luận vội là heartbeat ngừng vĩnh viễn và agent dừng oan (N2)."""
    try:
        thread = getattr(icon, "_thread", None)
        return bool(thread is not None and thread.is_alive())
    except Exception:
        return False


def _wait_for_icon(icon, timeout: float = 10.0, interval: float = 0.1) -> bool:
    """Chờ biểu tượng khay sẵn sàng (tối đa timeout giây). Máy chậm lúc
    đăng nhập có thể cần vài giây; quá hạn mà chưa lên thì coi là lỗi
    thật (tray_ready(False) -> agent tự dừng theo F5.8)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _icon_alive(icon):
            return True
        time.sleep(interval)
    return _icon_alive(icon)


def _make_icon_image():
    from PIL import Image, ImageDraw
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([4, 4, 60, 60], radius=14, fill=(37, 99, 235, 255))
    d.ellipse([18, 14, 46, 42], outline=(255, 255, 255, 255), width=3)
    d.line([32, 28, 32, 20], fill=(255, 255, 255, 255), width=3)
    d.line([32, 28, 39, 32], fill=(255, 255, 255, 255), width=3)
    d.ellipse([24, 46, 40, 54], fill=(52, 211, 153, 255))
    return img


# ------------------------------------------------------------------ giao diện
def run_tray() -> int:
    cfg = load_tray_info()
    core = TrayCore(cfg)
    child_name = cfg.get("child_name") or "bạn nhỏ"

    if not cfg.get("paired"):
        import tkinter as tk
        from tkinter import ttk
        root = tk.Tk()
        root.title("OpenGuard Kids — Người Bạn Đồng Hành")
        ttk.Label(root, text="Máy chưa được ghép đôi — hãy chạy enroll.py với mã do "
                             "phụ huynh tạo trên dashboard.", padding=24).pack()
        root.mainloop()
        return 0

    try:
        import pystray
    except Exception:
        core.tray_ready(False)
        print("Không tạo được biểu tượng khay (thiếu pystray) — đã báo service.",
              file=sys.stderr)
        return 1

    import tkinter as tk
    from tkinter import ttk

    root = tk.Tk()
    root.withdraw()
    root.title("OpenGuard Kids")
    actions: queue.Queue = queue.Queue()
    last_block_subject = {"value": ""}

    def window(title, build):
        win = tk.Toplevel(root)
        win.title(title)
        win.minsize(430, 320)
        build(win)
        win.lift()
        return win

    note_windows: dict = {}

    def show_message(title, text, key=None):
        """Thông báo KHÔNG chặn (non-modal): cửa sổ thường + nút Đóng.
        Tuyệt đối không dùng messagebox ở tray — hộp thoại modal chờ bấm
        OK từng làm đứt nhịp sống của tray (CHẶN C1, review 3).
        Cùng một key thì TÁI DÙNG cửa sổ đang mở (chỉ cập nhật nội dung):
        note "locked" lặp mỗi 60s mà mỗi lần mở một cửa sổ mới thì sau
        một giờ khóa máy có ~60 cửa sổ chồng nhau (gợi ý G2, review 4)."""
        key = key or title
        existing = note_windows.get(key)
        if existing is not None:
            win, label = existing
            try:
                if win.winfo_exists():
                    label.config(text=text)
                    win.lift()
                    return win
            except Exception:
                pass

        def build(win):
            label = ttk.Label(win, text=text, padding=(16, 14), wraplength=400,
                              justify="left")
            label.pack(anchor="w")
            ttk.Button(win, text="Đã hiểu", command=win.destroy).pack(
                anchor="e", padx=14, pady=(0, 12))
            note_windows[key] = (win, label)
        win = window(title, build)
        win.minsize(380, 140)
        return win

    def show_status():
        def build(win):
            try:
                st = core.status()
                text = status_line(st)
                remain = fmt_minutes(st.get("remaining_min", 0))
            except Exception:
                text, remain = "Chưa kết nối được với dịch vụ OpenGuard Kids.", "—"
            ttk.Label(win, text=f"Xin chào, {child_name}", font=("Segoe UI", 14, "bold"),
                      padding=(16, 12, 16, 0)).pack(anchor="w")
            ttk.Label(win, text="Thời gian còn lại hôm nay:", padding=(16, 8, 16, 0)).pack(anchor="w")
            ttk.Label(win, text=remain, font=("Segoe UI", 30, "bold"),
                      padding=(16, 0, 16, 4)).pack(anchor="w")
            ttk.Label(win, text=text, padding=(16, 0, 16, 16), wraplength=400).pack(anchor="w")
        window("OpenGuard Kids — Thời gian còn lại", build)

    def show_today():
        def build(win):
            try:
                lines = today_lines(core.today())
            except Exception:
                lines = ["Chưa kết nối được với dịch vụ OpenGuard Kids."]
            for line in lines:
                ttk.Label(win, text=line, padding=(16, 3), wraplength=420,
                          justify="left").pack(anchor="w")
        window("Hôm nay em đã dùng gì", build)

    def show_week():
        def build(win):
            try:
                lines = week_lines(core.week())
            except Exception:
                lines = ["Chưa kết nối được với dịch vụ OpenGuard Kids."]
            for line in lines:
                ttk.Label(win, text=line, padding=(16, 3), wraplength=420,
                          justify="left").pack(anchor="w")
        window("Tuần này em đã dùng gì", build)

    def ask_extra():
        def build(win):
            minutes_var = tk.StringVar(value="15")
            ttk.Label(win, text="Số phút xin thêm:", padding=(14, 12, 14, 4)).grid(row=0, column=0, sticky="w")
            tk.OptionMenu(win, minutes_var, "15", "30", "45", "60").grid(row=0, column=1, sticky="ew", padx=10)
            ttk.Label(win, text="Lý do:", padding=(14, 6)).grid(row=1, column=0, sticky="w")
            entry = ttk.Entry(win, width=32)
            entry.grid(row=1, column=1, sticky="ew", padx=10)

            def send():
                try:
                    res = core.send_extra_time(int(minutes_var.get()), entry.get().strip())
                    msg = ("Đã gửi yêu cầu đến bố mẹ." if res and res.get("sent")
                           else "Chưa có mạng — yêu cầu đã lưu, sẽ tự gửi khi có mạng.")
                except Exception:
                    msg = "Chưa gửi được — dịch vụ agent chưa chạy?"
                win.destroy()
                show_message("Xin thêm giờ", msg)
            ttk.Button(win, text="Gửi yêu cầu", command=send).grid(
                row=2, column=0, columnspan=2, sticky="ew", padx=14, pady=12)
        window("Xin thêm giờ", build)

    def report_block():
        def build(win):
            ttk.Label(win, text="Ứng dụng/trang bị chặn:", padding=(14, 12, 14, 4)).grid(row=0, column=0, sticky="w")
            entry_subject = ttk.Entry(win, width=32)
            entry_subject.insert(0, last_block_subject["value"])
            entry_subject.grid(row=0, column=1, sticky="ew", padx=10)
            ttk.Label(win, text="Lý do con nghĩ chặn nhầm:", padding=(14, 6)).grid(row=1, column=0, sticky="w")
            entry_reason = ttk.Entry(win, width=32)
            entry_reason.grid(row=1, column=1, sticky="ew", padx=10)

            def send():
                subject = entry_subject.get().strip()
                if not subject:
                    show_message("Báo chặn nhầm", "Con hãy nhập tên ứng dụng hoặc trang web.")
                    return
                try:
                    res = core.send_false_block(subject, entry_reason.get().strip())
                    msg = ("Đã gửi báo cáo đến bố mẹ." if res and res.get("sent")
                           else "Chưa có mạng — báo cáo đã lưu, sẽ tự gửi khi có mạng.")
                except Exception:
                    msg = "Chưa gửi được — dịch vụ agent chưa chạy?"
                win.destroy()
                show_message("Báo chặn nhầm", msg)
            ttk.Button(win, text="Gửi báo cáo", command=send).grid(
                row=2, column=0, columnspan=2, sticky="ew", padx=14, pady=12)
        window("Con nghĩ bị chặn nhầm", build)

    def show_audit():
        def build(win):
            try:
                lines = audit_lines(core.audit())
            except Exception:
                lines = ["Chưa kết nối được với dịch vụ OpenGuard Kids."]
            for line in lines[:30]:
                ttk.Label(win, text=line, padding=(16, 3), wraplength=440,
                          justify="left").pack(anchor="w")
        window("Nhật ký thay đổi luật của phụ huynh", build)

    def show_note(note):
        # CHỈ hiển thị — việc khóa máy khi note "locked" đã do luồng
        # Heartbeat làm ngay khi nhận note (không chờ UI). Hộp thoại ở
        # đây là cửa sổ thường, không chặn mainloop và không chặn nhịp.
        kind = note.get("kind")
        if note.get("subject"):
            last_block_subject["value"] = note["subject"]
        titles = {"warning": "Sắp hết giờ", "blocked_app": "Ứng dụng bị chặn",
                  "blocked_domain": "Trang web bị chặn", "locked": "Máy bị khóa",
                  "agent_started": "OpenGuard Kids", "request_decided": "Phản hồi từ bố mẹ",
                  "info": "OpenGuard Kids"}
        try:
            icon.notify(note.get("text", ""), titles.get(kind, "OpenGuard Kids"))
        except Exception:
            pass
        if kind in ("warning", "blocked_app", "locked"):
            show_message(titles.get(kind, "OpenGuard Kids"), note.get("text", ""),
                         key=kind)

    def poll():
        # Mainloop chỉ còn việc nhẹ: thực thi thao tác từ menu khay.
        # Nhịp session_pulse + nhận thông báo đã chuyển sang luồng
        # Heartbeat riêng (CHẶN C1) — poll không bao giờ được chặn lâu.
        while True:
            try:
                action = actions.get_nowait()
            except queue.Empty:
                break
            try:
                action()
            except Exception:
                # Một thao tác lỗi (mở cửa sổ, gọi IPC...) không được giết
                # vòng poll: mất poll là mất cửa sổ cảnh báo + menu khay
                # cho cả phiên (gợi ý G-a, review 5).
                traceback.print_exc()
        root.after(500, poll)

    menu = pystray.Menu(
        pystray.MenuItem("Thời gian còn lại", lambda: actions.put(show_status), default=True),
        pystray.MenuItem("Hôm nay em đã dùng gì", lambda: actions.put(show_today)),
        pystray.MenuItem("Tuần này em đã dùng gì", lambda: actions.put(show_week)),
        pystray.MenuItem("Xin thêm giờ", lambda: actions.put(ask_extra)),
        pystray.MenuItem("Báo chặn nhầm", lambda: actions.put(report_block)),
        pystray.MenuItem("Nhật ký thay đổi luật", lambda: actions.put(show_audit)),
    )
    icon = pystray.Icon("openguard-kids", _make_icon_image(),
                        "OpenGuard Kids — Người Bạn Đồng Hành", menu)
    try:
        threading.Thread(target=icon.run, daemon=True, name="OGK-TrayIcon").start()
        if not _wait_for_icon(icon, timeout=10.0):
            raise RuntimeError("icon thread died")
    except Exception as exc:
        core.tray_ready(False)
        print(f"Không hiển thị được biểu tượng khay: {exc} — đã báo service.", file=sys.stderr)
        return 1
    core.tray_ready(True)

    def _pulse():
        if idle_seconds is not None and is_locked is not None:
            core.session_pulse(idle_seconds(), is_locked())
        else:
            # Không đo được cảm biến phiên (môi trường lạ): vẫn gửi pulse
            # rỗng để giữ nhịp; service tự lùi về cách dò cục bộ.
            core.session_pulse(None, None)

    stop_event = threading.Event()
    heartbeat = Heartbeat(
        pulse_fn=_pulse,
        fetch_fn=core.notifications,
        lock_fn=_lock_workstation,
        # Chỉ đẩy vào hàng đợi thao tác của luồng UI (queue.Queue sẵn có,
        # poll() xả mỗi 500ms): luồng nhịp TUYỆT ĐỐI không gọi Tk trực
        # tiếp — root.after từ luồng khác có thể chờ luồng chính (N1).
        display_fn=lambda note: actions.put(lambda n=note: show_note(n)),
        alive_fn=lambda: _icon_alive(icon))
    threading.Thread(target=heartbeat.run, args=(stop_event,), daemon=True,
                     name="OGK-TrayHeartbeat").start()
    root.after(500, poll)
    root.mainloop()
    stop_event.set()
    # Không còn "lời chào" tray_bye (lỗ NT1: ai có ipc_token cũng giả được).
    # Agent tự biết phiên của trẻ qua trạng thái WTS: đăng xuất -> không
    # fatal, chờ phiên kế tiếp; tray biến mất GIỮA phiên -> watchdog dừng.
    try:
        icon.stop()
    except Exception:
        pass
    return 0


def _utf8_stdio():
    # Windows: stdout/stderr theo codepage (cp1252/cp1258) — in tiếng Việt ra
    # pipe/log sẽ văng UnicodeEncodeError. Ép UTF-8 như các entry point khác.
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def main():
    _utf8_stdio()
    sys.exit(run_tray())


if __name__ == "__main__":
    main()
