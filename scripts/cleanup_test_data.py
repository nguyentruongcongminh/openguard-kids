"""Dọn dữ liệu thử nghiệm OpenGuard Kids trên server (chạy 1 lần, có hỏi
xác nhận trước khi xóa):

- Xóa hẳn một thiết bị thử theo id (--device N) cùng toàn bộ dữ liệu phụ
  thuộc của nó: sự kiện sử dụng, lệnh, yêu cầu của trẻ, policy.
- Xóa "Demo Child" (--demo-child): trẻ mẫu được seed kèm tài khoản demo,
  chỉ xóa khi nó CHƯA có thiết bị nào. Xóa xong không tự mọc lại (seed chỉ
  chạy khi tài khoản demo được tạo lần đầu).

KHÔNG đụng vào tài khoản phụ huynh, trẻ thật, hay nhật ký kiểm toán.
Chạy khi server ĐANG DỪNG. Mặc định trỏ vào server/ogk.db của dự án;
đặt biến môi trường OGK_DB_PATH để trỏ file khác.
"""
import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.environ.setdefault("OGK_DB_PATH", str(ROOT / "server" / "ogk.db"))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "server"))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def main() -> int:
    ap = argparse.ArgumentParser(description="Dọn dữ liệu thử nghiệm OGK")
    ap.add_argument("--device", type=int, action="append", default=[],
                    help="id thiết bị cần xóa hẳn (lặp lại được)")
    ap.add_argument("--demo-child", action="store_true",
                    help="xóa trẻ mẫu 'Demo Child' (khi chưa có thiết bị)")
    args = ap.parse_args()
    if not args.device and not args.demo_child:
        ap.error("chưa chọn gì để xóa: dùng --device N và/hoặc --demo-child")

    from app.models import (Child, ChildRequest, Command, Device, PairingCode,
                            Policy, SessionLocal, UsageEvent)
    db = SessionLocal()
    plan = []
    try:
        for did in args.device:
            dev = db.get(Device, did)
            if dev is None:
                print(f"! Thiết bị id={did} không tồn tại — bỏ qua.")
                continue
            counts = {
                "sự kiện": db.query(UsageEvent).filter_by(device_id=did).count(),
                "lệnh": db.query(Command).filter_by(device_id=did).count(),
                "yêu cầu": db.query(ChildRequest).filter_by(device_id=did).count(),
                "policy": db.query(Policy).filter_by(device_id=did).count(),
            }
            plan.append(("device", dev, counts))
        demo = None
        if args.demo_child:
            demo = db.query(Child).filter_by(name="Demo Child").first()
            if demo is None:
                print("! Không thấy 'Demo Child' — bỏ qua.")
            elif db.query(Device).filter_by(child_id=demo.id).count():
                print("! 'Demo Child' đang có thiết bị — KHÔNG xóa, hủy phần này.")
                demo = None
            else:
                codes = db.query(PairingCode).filter_by(child_id=demo.id).count()
                plan.append(("child", demo, {"mã ghép đôi": codes}))
        if not plan:
            print("Không có gì để xóa.")
            return 0
        print("SẼ XÓA HẲN (không khôi phục được):")
        for kind, obj, counts in plan:
            label = (f"thiết bị '{obj.name}' (id={obj.id})" if kind == "device"
                     else f"trẻ mẫu '{obj.name}' (id={obj.id})")
            detail = ", ".join(f"{v} {k}" for k, v in counts.items())
            print(f"  - {label}: {detail}")
        if input("Gõ y để xóa: ").strip().lower() != "y":
            print("Đã hủy, chưa xóa gì.")
            return 0
        for kind, obj, _counts in plan:
            if kind == "device":
                db.query(UsageEvent).filter_by(device_id=obj.id).delete()
                db.query(ChildRequest).filter_by(device_id=obj.id).delete()
                db.query(Command).filter_by(device_id=obj.id).delete()
                db.query(Policy).filter_by(device_id=obj.id).delete()
                db.delete(obj)
                print(f"Đã xóa thiết bị id={obj.id}.")
            else:
                db.query(PairingCode).filter_by(child_id=obj.id).delete()
                db.delete(obj)
                print(f"Đã xóa trẻ mẫu id={obj.id}.")
        db.commit()
        print("Dọn dẹp xong.")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
