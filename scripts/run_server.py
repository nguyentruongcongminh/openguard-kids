"""Chạy OGK-Server — dùng thay lệnh uvicorn trực tiếp.

Mục đích: làm sạch console trên Windows mà không đổi hành vi chạy/tắt của
uvicorn.

Vấn đề gốc: trên Windows uvicorn chạy trên ProactorEventLoop; mỗi khi trình
duyệt ngắt kết nối đột ngột, loop in ra traceback "Exception in callback
_ProactorBasePipeTransport._call_connection_lost()" kèm ConnectionResetError
[WinError 10054]. Vô hại (request vẫn 200) nhưng rối mắt.

Hai cách sửa đã thử và KHÔNG dùng:
- set_event_loop_policy(WindowsSelectorEventLoopPolicy): vô hiệu — uvicorn
  0.54 gán cứng ProactorEventLoop trong factory riêng, không đọc policy.
- Tự chạy server trên SelectorEventLoop: hết traceback nhưng Ctrl+C bị
  "treo" ở bước chờ đóng kết nối — SelectorEventLoop trên Windows xử lý
  tín hiệu Ctrl+C kém, lệnh force-quit của uvicorn không tới được
  (đã gặp trên máy Windows thật 16/11/2026).

Cách dùng ở bản này: chạy uvicorn.run(...) nguyên bản (Ctrl+C tắt như
thường) + gắn một bộ lọc vào logger "asyncio" để chỉ nuốt đúng loại
traceback vô hại nói trên (đúng callback _call_connection_lost + đúng
ConnectionResetError); mọi lỗi asyncio khác vẫn in bình thường.

Launcher tự chdir vào thư mục server/ (nơi chứa ogk.db khi chạy tay) và mặc
định trỏ chứng chỉ vào certs/ ở gốc dự án, nên dữ liệu cũ giữ nguyên dù gọi
từ thư mục nào.

Chạy (từ thư mục gốc dự án, sau khi đã đặt OGK_MASTER_KEY + OGK_TLS_CERT):
    .venv\\Scripts\\python scripts\\run_server.py
Tuỳ chọn: --host, --port, --ssl-keyfile, --ssl-certfile.
"""
import argparse
import logging
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class ProactorResetFilter(logging.Filter):
    """Nuốt đúng traceback Proactor/WinError 10054 của asyncio trên Windows."""

    def filter(self, record):
        if record.exc_info and record.exc_info[0] is not None:
            if issubclass(record.exc_info[0], ConnectionResetError):
                if "_call_connection_lost" in record.getMessage():
                    return False
        return True


def _utf8_stdio():
    # Windows: stdout/stderr theo codepage (cp1252/cp1258) — ép UTF-8 như các
    # entry point khác để log tiếng Việt không văng UnicodeEncodeError.
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def main():
    _utf8_stdio()
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--ssl-keyfile",
                    default=os.path.join(ROOT, "certs", "server-key.pem"))
    ap.add_argument("--ssl-certfile",
                    default=os.path.join(ROOT, "certs", "server-cert.pem"))
    args = ap.parse_args()

    # Gắn bộ lọc TRƯỚC khi uvicorn tạo loop: traceback kia được
    # default_exception_handler của asyncio ghi qua logger "asyncio".
    logging.getLogger("asyncio").addFilter(ProactorResetFilter())

    server_dir = os.path.join(ROOT, "server")
    sys.path.insert(0, server_dir)
    os.chdir(server_dir)  # ogk.db mặc định nằm cạnh app như khi chạy uvicorn tay

    import uvicorn
    uvicorn.run("app.main:app", host=args.host, port=args.port,
                ssl_keyfile=args.ssl_keyfile, ssl_certfile=args.ssl_certfile)


if __name__ == "__main__":
    main()
