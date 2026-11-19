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
from pathlib import Path

try:
    from .client import ServerClient  # noqa: F401  (giữ tương thích import cũ)
    from .config import load_config
    from .ipc import IPCClient
except ImportError:
    from config import load_config
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


def audit_lines(rows: list) -> list[str]:
    labels = {"policy.update": "thay đổi chính sách", "command.create": "gửi lệnh từ xa",
              "request.decide": "phản hồi yêu cầu của con", "consent.pairing": "ghép đôi thiết bị"}
    out = []
    for r in rows or []:
        when = str(r.get("ts") or "")[:16].replace("T", " ")
        what = labels.get(r.get("action"), r.get("action"))
        out.append(f"{when} — {r.get('actor', '')} đã {what}.")
    return out or ["Chưa có thay đổi nào."]


# ------------------------------------------------------------------ lõi giao tiếp IPC
class TrayCore:
    def __init__(self, cfg):
        self.cfg = cfg
        self.ipc = IPCClient(cfg.get("ipc_token", ""))

    def call(self, method, **params):
        return self.ipc.call(method, **params)

    def status(self):
        return self.call("get_status")

    def today(self):
        return self.call("get_today")

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
            return self.call("session_pulse", idle_sec=idle_sec,
                             locked=bool(locked))
        except Exception:
            return None


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
    cfg = load_config()
    core = TrayCore(cfg)
    child_name = cfg.get("child_name") or "bạn nhỏ"

    if not cfg.get("access_token"):
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
    from tkinter import messagebox, ttk

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
                messagebox.showinfo("Xin thêm giờ", msg)
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
                    messagebox.showwarning("Báo chặn nhầm", "Con hãy nhập tên ứng dụng hoặc trang web.")
                    return
                try:
                    res = core.send_false_block(subject, entry_reason.get().strip())
                    msg = ("Đã gửi báo cáo đến bố mẹ." if res and res.get("sent")
                           else "Chưa có mạng — báo cáo đã lưu, sẽ tự gửi khi có mạng.")
                except Exception:
                    msg = "Chưa gửi được — dịch vụ agent chưa chạy?"
                win.destroy()
                messagebox.showinfo("Báo chặn nhầm", msg)
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
        kind = note.get("kind")
        if kind == "locked":
            # Service o session 0 goi LockWorkStation se khong khoa duoc
            # phien cua tre; Tray dang o dung phien do nen khoa thay ngay
            # khi nhan thong bao khoa (quota/lich/tu xa deu qua duong nay).
            try:
                import ctypes
                ctypes.windll.user32.LockWorkStation()
            except Exception:
                pass
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
            messagebox.showwarning(titles.get(kind, "OpenGuard Kids"), note.get("text", ""))

    def poll():
        while True:
            try:
                action = actions.get_nowait()
            except queue.Empty:
                break
            action()
        if idle_seconds is not None and is_locked is not None:
            try:
                core.session_pulse(idle_seconds(), is_locked())
            except Exception:
                pass
        try:
            for note in core.notifications():
                show_note(note)
        except Exception:
            pass
        root.after(3000, poll)

    menu = pystray.Menu(
        pystray.MenuItem("Thời gian còn lại", lambda: actions.put(show_status), default=True),
        pystray.MenuItem("Hôm nay em đã dùng gì", lambda: actions.put(show_today)),
        pystray.MenuItem("Xin thêm giờ", lambda: actions.put(ask_extra)),
        pystray.MenuItem("Báo chặn nhầm", lambda: actions.put(report_block)),
        pystray.MenuItem("Nhật ký thay đổi luật", lambda: actions.put(show_audit)),
    )
    icon = pystray.Icon("openguard-kids", _make_icon_image(),
                        "OpenGuard Kids — Người Bạn Đồng Hành", menu)
    try:
        threading.Thread(target=icon.run, daemon=True, name="OGK-TrayIcon").start()
        time.sleep(0.5)
        if not icon._thread.is_alive() if hasattr(icon, "_thread") else False:
            raise RuntimeError("icon thread died")
    except Exception as exc:
        core.tray_ready(False)
        print(f"Không hiển thị được biểu tượng khay: {exc} — đã báo service.", file=sys.stderr)
        return 1
    core.tray_ready(True)
    root.after(1000, poll)
    root.mainloop()
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
