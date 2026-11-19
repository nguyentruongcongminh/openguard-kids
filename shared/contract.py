"""OpenGuard Kids — hợp đồng dữ liệu dùng chung server/agent (nguồn sự thật duy nhất).

Mọi JSON trao đổi giữa OGK-Server và OGK-Agent đều định nghĩa tại đây:
- Tài liệu chính sách (policy document) có phiên bản + chữ ký HMAC.
- Lược đồ sự kiện khóa cứng theo mục F3 của đề.
- Lịch tuần 7x48, phân loại miền, danh sách miễn chặn vĩnh viễn (NT6).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import datetime

# ---------------------------------------------------------------- hằng số
DOMAIN_CATEGORIES = (
    "giao_duc",        # giáo dục
    "giai_tri",        # giải trí phù hợp lứa tuổi
    "mang_xa_hoi",     # mạng xã hội
    "tro_choi",        # trò chơi trực tuyến
    "khong_phu_hop",   # không phù hợp lứa tuổi
    "chua_phan_loai",  # chưa phân loại
)
# Chính sách mặc định cho trẻ 6-11 tuổi (theo đề).
DEFAULT_CATEGORY_POLICY = {
    "giao_duc": "allow",
    "giai_tri": "allow",
    "mang_xa_hoi": "block",
    "tro_choi": "block",
    "khong_phu_hop": "block",
    "chua_phan_loai": "allow",
}
APP_CATEGORIES = ("hoc_tap", "giai_tri", "game", "khac")

# Tập type sự kiện khóa cứng — mục F3 của đề, không thêm bớt.
EVENT_TYPES = (
    "app_start", "app_stop", "domain_query", "blocked_app", "blocked_domain",
    "quota_warning", "locked", "unlock_request", "override_granted",
)
EVENT_FIELDS = {"event_id", "ts", "type", "subject", "duration_sec", "policy_id"}

COMMAND_TYPES = (
    "lock_now", "unlock", "grant_extra", "break_15", "pause_today", "wipe_cache",
)

# Miễn chặn vĩnh viễn (NT6): dịch vụ nhà nước (.gov.vn — gồm cổng Tổng đài
# bảo vệ trẻ em 111 và thông tin khẩn cấp) không bao giờ bị chặn, bất kể luật.
NEVER_BLOCK_SUFFIXES = (".gov.vn",)
_GOV_APEX = {"gov.vn"}

_MULTI_LABEL_SUFFIXES = (
    "edu.vn", "com.vn", "net.vn", "org.vn", "gov.vn", "co.uk", "com.au",
)

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")


# ---------------------------------------------------------------- miền
def normalize_domain(domain: object) -> str:
    d = str(domain or "").strip().lower()
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/")[0].split(":")[0].strip(".")
    return d[4:] if d.startswith("www.") else d


def is_valid_domain(domain: object) -> bool:
    return bool(_DOMAIN_RE.match(normalize_domain(domain)))


def subject_domain(domain: object) -> str:
    """Tên miền cấp hai dùng cho trường subject (không lưu URL đầy đủ)."""
    d = normalize_domain(domain)
    if not d:
        return ""
    labels = d.split(".")
    if len(labels) <= 2:
        return d
    tail2 = ".".join(labels[-2:])
    if tail2 in _MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return tail2


def domain_matches(host: str, rule_domain: str) -> bool:
    """host thuộc rule_domain hoặc là miền con của nó."""
    h, r = normalize_domain(host), normalize_domain(rule_domain)
    return bool(h and r) and (h == r or h.endswith("." + r))


def is_never_blocked(domain: object, never_block_list=()) -> bool:
    d = normalize_domain(domain)
    if not d:
        return False
    if d in _GOV_APEX or any(d == s.lstrip(".") or d.endswith(s) for s in NEVER_BLOCK_SUFFIXES):
        return True
    return any(domain_matches(d, item) for item in (never_block_list or ()))


# ---------------------------------------------------------------- lịch tuần
def default_schedule() -> list[list[int]]:
    """7 ngày (0=Thứ 2) x 48 ô 30 phút; mặc định được dùng 06:00-21:00."""
    rows = []
    for _ in range(7):
        row = [0] * 48
        for slot in range(12, 42):  # 06:00 -> 21:00
            row[slot] = 1
        rows.append(row)
    return rows


def validate_schedule(schedule) -> bool:
    return (
        isinstance(schedule, list) and len(schedule) == 7
        and all(isinstance(r, list) and len(r) == 48 and all(v in (0, 1) for v in r)
                for r in schedule)
    )


def schedule_allows(schedule, when: datetime) -> bool:
    if not validate_schedule(schedule):
        return True  # lịch hỏng -> không khóa oan trẻ
    slot = when.hour * 2 + (1 if when.minute >= 30 else 0)
    return schedule[when.weekday()][slot] == 1


# ---------------------------------------------------------------- policy
def default_policy_document(device_id: int, child_id: int) -> dict:
    return {
        "device_id": int(device_id),
        "child_id": int(child_id),
        "version": 1,
        "issued_at": None,
        "time": {
            "quota_weekday_min": 90,
            "quota_weekend_min": 150,
            "schedule": default_schedule(),
            "warn_at_min": [10, 5, 1],
            "grace_sec": 60,
            "group_budgets_min": {"hoc_tap": None, "giai_tri": 60, "game": 45, "khac": None},
        },
        "apps": [],
        "web": {
            "rules": [],
            "category_policy": dict(DEFAULT_CATEGORY_POLICY),
            "blocked_domains": [],
            "safesearch": True,
            "never_block": [],
        },
        "signature": "",
    }


def canonical_policy(doc: dict) -> bytes:
    body = {k: v for k, v in doc.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_policy(doc: dict, key_hex: str) -> str:
    return hmac.new(bytes.fromhex(key_hex), canonical_policy(doc), hashlib.sha256).hexdigest()


def verify_policy(doc: dict, key_hex: str) -> bool:
    if not isinstance(doc, dict) or not doc.get("signature"):
        return False
    try:
        return hmac.compare_digest(sign_policy(doc, key_hex), str(doc["signature"]))
    except Exception:
        return False


# ---------------------------------------------------------------- sự kiện
def validate_event(ev: object) -> dict:
    """Kiểm tra một sự kiện theo lược đồ F3; trả bản đã chuẩn hóa hoặc raise ValueError."""
    if not isinstance(ev, dict):
        raise ValueError("event must be an object")
    extra = set(ev) - EVENT_FIELDS
    if extra:
        raise ValueError(f"event has fields outside the F3 schema: {sorted(extra)}")
    missing = EVENT_FIELDS - set(ev)
    if missing:
        raise ValueError(f"event missing fields: {sorted(missing)}")
    if ev["type"] not in EVENT_TYPES:
        raise ValueError(f"unknown event type: {ev['type']!r}")
    if not isinstance(ev["event_id"], str) or not ev["event_id"]:
        raise ValueError("event_id must be a non-empty string")
    ts = ev["ts"]
    if not isinstance(ts, (int, float)) or isinstance(ts, bool) or ts <= 0:
        raise ValueError("ts must be a positive epoch number")
    duration = ev["duration_sec"]
    if not isinstance(duration, (int, float)) or isinstance(duration, bool) or duration < 0:
        raise ValueError("duration_sec must be a non-negative number")
    if not isinstance(ev["policy_id"], int) or isinstance(ev["policy_id"], bool):
        raise ValueError("policy_id must be an int (policy version)")
    subject = str(ev["subject"] or "")
    if ev["type"] in ("domain_query", "blocked_domain"):
        subject = subject_domain(subject)  # chỉ tên miền cấp hai, không URL
    return {
        "event_id": ev["event_id"], "ts": float(ts), "type": ev["type"],
        "subject": subject[:255], "duration_sec": float(duration),
        "policy_id": int(ev["policy_id"]),
    }


# Tiến trình hệ thống Windows chạy nền — KHÔNG tính là "ứng dụng con đã dùng"
# trong báo cáo (agent không ghi sự kiện app_start/app_stop cho chúng; báo cáo
# ở agent và server cũng bỏ qua khi tổng hợp). Chỉ ảnh hưởng BÁO CÁO — logic
# chặn ứng dụng dùng danh sách riêng, không đổi.
SYSTEM_PROCESSES = frozenset({
    "system", "registry", "csrss.exe", "winlogon.exe", "wininit.exe",
    "services.exe", "lsass.exe", "explorer.exe", "python.exe", "pythonw.exe",
    "ogk_tray.exe", "svchost.exe", "smss.exe", "fontdrvhost.exe", "dwm.exe",
    "ctfmon.exe", "searchhost.exe", "shellexperiencehost.exe",
    "startmenuexperiencehost.exe", "textinputhost.exe", "runtimebroker.exe",
    "smartscreen.exe", "msmpeng.exe", "searchindexer.exe", "conhost.exe",
    "taskhostw.exe", "dllhost.exe", "spoolsv.exe",
    # Bo sung 17/11/2026 tu may tre that (Dell): cac dich vu nen bi ghi vao
    # bao cao "ung dung da dung 43 phut" - chay tu luc mo may, khong phai
    # tre dung. Lop chinh la loc theo tai khoan SYSTEM trong controller;
    # danh sach ten nay la lop du phong.
    "wudfhost.exe", "lsaiso.exe", "ekrn.exe", "intelcphdcpsvc.exe",
    "presentationfontcache.exe", "intelcphecisvc.exe",
    "nvdisplay.container.exe", "wavessvc64.exe", "memcompression",
    # Dot 2 (10:24 cung ngay): nhom dich vu nen tiep theo noi len bao cao
    # sau khi dot 1 bi loc khoi luc doc - van la du lieu cu ghi truoc ban sua.
    "wscript.exe", "igfxcuiservice.exe", "wmiprvse.exe",
    "rtkaudioservice64.exe", "mpdefendercoreservice.exe", "ensserver.exe",
    "esif_uf.exe", "evteng.exe", "jhi_service.exe", "sqlwriter.exe",
    # Dot 3 (10:40 cung ngay): tien ich vo/nen chay trong PHIÊN cua tre
    # (khong thuoc tai khoan SYSTEM nen lop loc tai khoan khong bat duoc):
    # WebView2 cua Edge, moi gioi OOBE, Search, Realtek GUI, Intel Graphics,
    # ESET GUI proxy, shell infrastructure host. msedge.exe (trinh duyet
    # that) GIU LAI trong bao cao vi do la ung dung tre dung that.
    "msedgewebview2.exe", "useroobebroker.exe", "searchapp.exe",
    "ravbg64.exe", "rtkngui64.exe", "dptf_helper.exe", "sihost.exe",
    "eguiproxy.exe", "igfxem.exe",
})
