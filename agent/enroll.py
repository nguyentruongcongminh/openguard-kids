"""Đăng ký thiết bị OpenGuard Kids bằng MÃ GHÉP ĐÔI 8 ký tự (mục 2.3 của đề).

Phụ huynh tạo mã trên dashboard (hạn 10 phút) -> chạy lệnh này trên máy trẻ:
    python agent/enroll.py --server https://<ip-server>:8000 --code ABCD2345 --device-name "May phong be"
Token chỉ lưu vào config.json trong ProgramData, không in ra màn hình.
"""

import argparse
import sys

try:
    from agent.client import device_fingerprint, redeem_pairing
    from agent.config import save_config
except ImportError:
    from client import device_fingerprint, redeem_pairing
    from config import save_config


def _utf8_stdio():
    # Windows: stdout/stderr theo codepage hệ thống (cp1252/cp1258) — in tiếng
    # Việt ra pipe/log sẽ văng UnicodeEncodeError (đã gặp trên máy Windows thật
    # ở dòng "Ghép đôi thành công."). Ép UTF-8, ký tự lạ thay bằng '?'.
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def main() -> int:
    _utf8_stdio()
    parser = argparse.ArgumentParser(description="Ghép đôi thiết bị OpenGuard Kids")
    parser.add_argument("--server", required=True, help="URL server, vd: https://192.168.1.10:8000")
    parser.add_argument("--code", required=True, help="Mã ghép đôi 8 ký tự từ dashboard phụ huynh")
    parser.add_argument("--device-name", required=True, help="Tên thiết bị, vd: May phong be")
    parser.add_argument("--cert-fingerprint", default="",
                        help="SHA-256 chứng chỉ server (phụ huynh đọc trên dashboard) — "
                             "agent sẽ ghim chứng chỉ này; bỏ trống = tin lần đầu (TOFU)")
    args = parser.parse_args()

    server = args.server.rstrip("/")
    try:
        data = redeem_pairing(server, args.code, args.device_name, device_fingerprint(),
                              cert_fingerprint=args.cert_fingerprint)
    except Exception as exc:
        print(f"Ghép đôi thất bại: {exc}", file=sys.stderr)
        print("Kiểm tra: mã còn hạn 10 phút và chưa dùng? Địa chỉ server đúng chưa?",
              file=sys.stderr)
        return 1

    save_config({
        "server_url": server,
        "device_id": data["device_id"],
        "child_id": data["child_id"],
        "child_name": data.get("child_name") or "",
        "access_token": data["access_token"],
        "refresh_token": data["refresh_token"],
        "policy_key": data["policy_key"],
        "cert_fingerprint": args.cert_fingerprint or data.get("server_cert_fingerprint") or "",
    })
    print("Ghép đôi thành công.")
    print(f"device_id: {data['device_id']}")
    if data.get("child_name"):
        print(f"child_name: {data['child_name']}")
    print("Token và khóa chính sách đã lưu vào config.json (không hiển thị).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
