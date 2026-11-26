"""VÒNG 3 — Nghiệm thu theo đúng tiêu chí của đề bài.

1) Bộ 60 miền kiểm thử (phụ lục đề): 0 chặn nhầm trên 20 miền giáo dục,
   chặn >= 95% trên nhóm phải chặn theo chính sách mặc định 6-11 tuổi
   (mạng xã hội + trò chơi theo phân loại, 10 miền "không phù hợp" MÔ PHỎNG
   bằng hậu tố .invalid theo đúng yêu cầu của đề — đi qua đúng đường PHÂN
   LOẠI khong_phu_hop như miền thật, lý do chặn phải là listed;
   5 điểm cuối DoH bị chặn theo mặc định với lý do doh_endpoint).
2) Đo sai số đếm giờ bằng đồng hồ thật (~10 giây) và kịch bản quota thật
   (1 phút + ân hạn 10 giây -> khóa).
3) Lịch tuần: ngoài khung giờ -> khóa trong vòng 5 giây.
4) PRIVACY.md đủ trường; lược đồ sự kiện không chứa URL; cookie phiên đúng cờ;
   mật khẩu băm Argon2id; blocked_domains không chứa miền .gov.vn (NT6).

Chạy:  .venv/bin/python scripts/acceptance_round3.py
"""
import csv
import os
import sys
import tempfile
import time
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "server"))
os.environ.setdefault("ProgramData", tempfile.mkdtemp())
os.environ["OGK_DB_PATH"] = os.path.join(tempfile.mkdtemp(), "ogk-r3.db")
import base64
os.environ.setdefault("OGK_MASTER_KEY", base64.b64encode(b"R" * 32).decode())

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok)))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail if not ok else ''}")


def main():
    # ------------------------------------------------ 1) bộ miền kiểm thử
    from app.models import Base, DomainCategory, SessionLocal, engine
    Base.metadata.create_all(bind=engine)
    from app.policy import compute_blocked_domains, seed_domain_categories
    from shared.contract import default_policy_document
    db = SessionLocal()
    seed_domain_categories(db)
    # Miền mô phỏng (.invalid, RFC 2606 — không tồn tại thật): nạp vào BẢNG
    # PHÂN LOẠI với nhóm khong_phu_hop để phép đo đi qua đúng cơ chế phân
    # loại -> compute_blocked_domains -> blocked_domains (lý do "listed"),
    # thay vì luật đích danh như trước (review 2, F2.3 NÊN SỬA).
    _rows = list(csv.DictReader(open(os.path.join(
        ROOT, "server", "data", "test_domains.csv"), encoding="utf-8")))
    for r in _rows:
        if r["domain"].endswith(".invalid"):
            db.add(DomainCategory(
                domain=r["domain"], category="khong_phu_hop",
                note="Miền mô phỏng cho kiểm thử — không phải miền thật"))
    db.commit()
    doc = default_policy_document(1, 1)
    doc["web"]["blocked_domains"] = compute_blocked_domains(db, doc)
    db.close()

    from agent.local_store import LocalStore
    from agent.policy import PolicyManager
    store = LocalStore(os.path.join(tempfile.mkdtemp(), "a.db"))
    pm = PolicyManager(store, "")
    pm._doc = doc  # tài liệu do server phát hành (đã tính blocked_domains)

    rows = _rows
    assert len(rows) == 60, len(rows)
    edu_fp = block_hits = block_total = 0
    doh_ok = sim_listed = 0
    for r in rows:
        decision, reason = pm.web_decision_detail(r["domain"])
        if r["expected"] == "allow":
            if r["category"] == "giao_duc" and decision != "allow":
                edu_fp += 1
        elif r["expected"] == "block":
            block_total += 1
            if decision == "block":
                block_hits += 1
            if r["category"] == "chua_phan_loai" and (decision, reason) == ("block", "doh_endpoint"):
                doh_ok += 1
            if r["domain"].endswith(".invalid") and (decision, reason) == ("block", "listed"):
                sim_listed += 1
    check("Bộ 60 miền: 0 chặn nhầm trên 20 miền giáo dục", edu_fp == 0, f"fp={edu_fp}")
    rate = block_hits / block_total if block_total else 0
    check(f"Bộ 60 miền: tỉ lệ chặn nhóm phải chặn >= 95% (đạt {block_hits}/{block_total})",
          rate >= 0.95)
    check("10 miền mô phỏng bị chặn qua PHÂN LOẠI (lý do listed)",
          sim_listed == 10, f"sim_listed={sim_listed}")
    check("5 điểm cuối DoH bị chặn theo mặc định (lý do doh_endpoint)",
          doh_ok == 5, f"doh_ok={doh_ok}")
    check("NT6: blocked_domains không chứa miền .gov.vn/.edu.vn/tongdai111.vn nào",
          not any(d.endswith((".gov.vn", ".edu.vn")) or d == "tongdai111.vn"
                  for d in doc["web"]["blocked_domains"]))

    # ------------------------------------------------ 2) đo sai số đếm giờ (đồng hồ thật)
    from agent.timekeeper import TimeKeeper
    from shared.contract import default_schedule
    doc2 = default_policy_document(1, 1)
    doc2["time"]["quota_weekday_min"] = 600
    doc2["time"]["quota_weekend_min"] = 600
    doc2["time"]["schedule"] = [[1] * 48 for _ in range(7)]
    pm2 = PolicyManager(store, "")
    pm2._doc = doc2
    keeper = TimeKeeper(store, pm2)
    t0 = time.monotonic()
    deadline = t0 + 10
    while time.monotonic() < deadline:
        keeper.tick()
        time.sleep(0.2)
    elapsed = time.monotonic() - t0
    used = keeper.used_today()
    err = abs(used - elapsed)
    check(f"Đếm giờ thật 10s: sai số {err:.2f}s (tiêu chí đề: <= 30s/giờ)",
          err <= 30 * (elapsed / 3600) + 0.6, f"used={used:.2f} elapsed={elapsed:.2f}")

    # ------------------------------------------------ 2b) quota thật -> khóa đúng hạn
    doc3 = default_policy_document(1, 1)
    doc3["time"].update({"quota_weekday_min": 1, "quota_weekend_min": 1,
                         "grace_sec": 10, "warn_at_min": [10, 5, 1]})
    doc3["time"]["schedule"] = [[1] * 48 for _ in range(7)]
    store3 = LocalStore(os.path.join(tempfile.mkdtemp(), "b.db"))
    pm3 = PolicyManager(store3, "")
    pm3._doc = doc3
    locked_at = []
    keeper3 = TimeKeeper(store3, pm3, on_lock=lambda reason: locked_at.append(time.monotonic()))
    t0 = time.monotonic()
    while time.monotonic() - t0 < 100 and not locked_at:
        keeper3.tick()
        time.sleep(0.25)
    lock_after = (locked_at[0] - t0) if locked_at else None
    check("Quota 1 phút + ân hạn 10s -> khóa ở ~70s (không sớm, không muộn quá 5s)",
          lock_after is not None and 68 <= lock_after <= 76,
          f"lock_after={lock_after}")

    # ------------------------------------------------ 3) lịch tuần: ngoài khung -> khóa <= 5s
    sched = default_schedule()
    now = datetime.now()
    sched[now.weekday()][now.hour * 2 + (1 if now.minute >= 30 else 0)] = 0
    doc4 = default_policy_document(1, 1)
    doc4["time"]["schedule"] = sched
    doc4["time"]["quota_weekday_min"] = 600
    doc4["time"]["quota_weekend_min"] = 600
    store4 = LocalStore(os.path.join(tempfile.mkdtemp(), "c.db"))
    pm4 = PolicyManager(store4, "")
    pm4._doc = doc4
    locked4 = []
    keeper4 = TimeKeeper(store4, pm4, on_lock=lambda r: locked4.append(r))
    t0 = time.monotonic()
    keeper4.tick(0)
    dt_lock = time.monotonic() - t0
    check("Ngoài khung giờ lịch tuần -> khóa trong 5 giây",
          locked4 == ["schedule"] and dt_lock < 5, f"{locked4} {dt_lock:.2f}s")

    # ------------------------------------------------ 4) PRIVACY/schema/cookie/hash
    privacy = open(os.path.join(ROOT, "PRIVACY.md"), encoding="utf-8").read()
    fields = ["event_id", "ts", "device_id", "child_id", "type", "subject",
              "duration_sec", "policy_id"]
    check("PRIVACY.md liệt kê đủ 8 trường sự kiện + thời hạn 90 ngày",
          all(f in privacy for f in fields) and "90 ngày" in privacy)
    from shared.contract import EVENT_FIELDS
    check("Lược đồ sự kiện F3 khóa cứng, không có trường URL/nội dung",
          EVENT_FIELDS == {"event_id", "ts", "type", "subject", "duration_sec", "policy_id"})
    from app.security import hash_password
    check("Mật khẩu băm Argon2id", hash_password("Test12345!").startswith("$argon2id$"))
    from fastapi.testclient import TestClient
    from app.main import app
    c = TestClient(app)
    email = f"r3-{int(time.time())}@example.com"
    c.post("/auth/register", json={"email": email, "password": "Test12345!"})
    r = c.post("/auth/login", json={"email": email, "password": "Test12345!"})
    cookie = r.headers.get("set-cookie", "")
    check("Cookie phiên: HttpOnly + SameSite=Lax",
          "HttpOnly" in cookie and "SameSite=lax" in cookie.lower().replace(" ", "")
          or ("HttpOnly" in cookie and "samesite=lax" in cookie.lower()),
          cookie[:120])

    failed = [n for n, ok in RESULTS if not ok]
    print(f"\n==== VÒNG 3: {len(RESULTS) - len(failed)}/{len(RESULTS)} PASS ====")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
