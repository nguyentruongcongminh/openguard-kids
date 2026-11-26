"""Phát hành policy document: tính blocked_domains, tăng version, ký HMAC."""
import csv
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from shared.contract import (DOH_ENDPOINTS, default_policy_document,  # noqa: E402
                             domain_matches, is_never_blocked, normalize_domain,
                             sign_policy)

from .models import DomainCategory, Policy
from .security import decrypt_field

_DATA = os.path.join(os.path.dirname(__file__), "..", "data", "domain_categories.csv")


def seed_domain_categories(db) -> int:
    """Nạp bảng phân loại miền từ CSV nếu bảng đang trống. Trả số dòng đã nạp."""
    if db.query(DomainCategory).count() > 0:
        return 0
    if not os.path.exists(_DATA):
        return 0
    n = 0
    with open(_DATA, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            db.add(DomainCategory(domain=normalize_domain(row["domain"]),
                                  category=row["category"].strip(),
                                  note=(row.get("note") or "").strip()))
            n += 1
    db.commit()
    return n


def category_map(db) -> dict:
    return {r.domain: r.category for r in db.query(DomainCategory).all()}


def compute_blocked_domains(db, doc: dict) -> list:
    """Miền bị chặn hiệu lực = (miền thuộc nhóm bị block + luật block tường minh)
    − luật allow tường minh − danh sách miễn chặn vĩnh viễn (NT6)."""
    web = doc.get("web", {})
    cat_policy = web.get("category_policy", {})
    blocked = {d for d, c in category_map(db).items() if cat_policy.get(c) == "block"}
    # Điểm cuối DoH: chặn theo mặc định bất kể chính sách nhóm (F2.3) — trình
    # duyệt dùng DoH là vượt toàn bộ lọc DNS. Luật allow tường minh của phụ
    # huynh vẫn thắng (được trừ ở vòng lọc bên dưới, như mọi miền khác).
    blocked |= set(DOH_ENDPOINTS)
    allows = []
    for rule in web.get("rules", []):
        dom = normalize_domain(rule.get("domain"))
        if not dom:
            continue
        if rule.get("action") == "block":
            blocked.add(dom)
        elif rule.get("action") == "allow":
            allows.append(dom)
    never = web.get("never_block", [])
    out = []
    for dom in blocked:
        if any(domain_matches(dom, a) for a in allows):
            continue
        if is_never_blocked(dom, never):
            continue
        out.append(dom)
    return sorted(out)


def get_or_create_policy(db, device) -> Policy:
    row = db.query(Policy).filter_by(device_id=device.id).first()
    if row is None:
        doc = default_policy_document(device.id, device.child_id)
        doc.pop("signature", None)
        row = Policy(device_id=device.id, version=doc["version"], document=doc)
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def device_policy_key(db, device) -> str:
    return decrypt_field(device.policy_key_enc)


def issue_policy(db, device) -> dict:
    """Trả policy document đầy đủ (đã tính blocked_domains + ký) cho agent."""
    row = get_or_create_policy(db, device)
    doc = dict(row.document)
    doc["device_id"] = device.id
    doc["child_id"] = device.child_id
    doc["version"] = row.version
    doc["issued_at"] = datetime.utcnow().isoformat() + "Z"
    doc["web"] = dict(doc.get("web", {}))
    doc["web"]["blocked_domains"] = compute_blocked_domains(db, doc)
    doc["signature"] = sign_policy(doc, device_policy_key(db, device))
    return doc


def bump_policy(db, device, mutate, actor: str, ip, audit_fn) -> dict:
    """Áp một thay đổi lên policy: sửa document, tăng version, ghi audit cũ→mới."""
    import copy
    row = get_or_create_policy(db, device)
    old = copy.deepcopy(row.document)
    doc = copy.deepcopy(row.document)
    mutate(doc)
    doc.pop("signature", None)
    row.document = doc
    row.version += 1
    row.updated_at = datetime.utcnow()
    db.commit()
    audit_fn(db, device.child.parent, actor, "policy.update", ip, old, doc)
    return issue_policy(db, device)
