"""OGK-Agent — PolicyManager: điểm truy cập policy DUY NHẤT của agent.

Mọi module (timekeeper, controller, dns_proxy, tray qua IPC) đều đọc policy
qua đây — chấm dứt lỗi mỗi module đọc một khóa khác nhau ở bản cũ.
Policy chỉ được áp dụng khi chữ ký HMAC đúng và version mới hơn bản hiện tại.
"""
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from shared.contract import (domain_matches, is_doh_endpoint,  # noqa: E402
                             is_never_blocked, normalize_domain, verify_policy)


class PolicyManager:
    def __init__(self, store, policy_key: str = ""):
        self.store = store
        self.policy_key = policy_key or ""
        self._doc = store.get_policy()

    # ------------------------------------------------------------- nạp/cập nhật
    def current(self) -> dict | None:
        return self._doc

    def version(self) -> int:
        return int(self._doc.get("version", 0)) if self._doc else 0

    def update(self, doc) -> bool:
        """Nhận policy document mới; True nếu đã áp dụng."""
        if not isinstance(doc, dict):
            return False
        if self.policy_key and not verify_policy(doc, self.policy_key):
            return False  # policy bị sửa đổi -> từ chối (F4)
        if int(doc.get("version", 0)) <= self.version():
            return False  # bản cũ hơn/không mới hơn
        self._doc = doc
        self.store.save_policy(doc)
        return True

    def reload_from_store(self) -> None:
        self._doc = self.store.get_policy()

    # ------------------------------------------------------------- thời gian
    def time_cfg(self) -> dict:
        return (self._doc or {}).get("time", {}) if self._doc else {}

    def quota_minutes_for(self, day: date) -> int:
        t = self.time_cfg()
        if day.weekday() >= 5:
            return int(t.get("quota_weekend_min", 150))
        return int(t.get("quota_weekday_min", 90))

    def group_budgets(self) -> dict:
        return self.time_cfg().get("group_budgets_min", {}) or {}

    # ------------------------------------------------------------- ứng dụng
    def app_rules(self) -> list:
        return list((self._doc or {}).get("apps", []) or [])

    # ------------------------------------------------------------- web
    def web_cfg(self) -> dict:
        return (self._doc or {}).get("web", {}) if self._doc else {}

    def never_block_list(self) -> list:
        return list(self.web_cfg().get("never_block", []) or [])

    def is_never_blocked(self, domain) -> bool:
        return is_never_blocked(domain, self.never_block_list())

    def web_decision(self, domain) -> str:
        return self.web_decision_detail(domain)[0]

    def web_decision_detail(self, domain) -> tuple:
        """(decision, reason) — thứ tự: miễn chặn NT6 > allow tường minh >
        block tường minh > điểm cuối DoH (chặn mặc định, F2.3) > danh sách
        blocked_domains (đã tính từ phân loại). reason thuộc:
        never_block | rule_allow | rule_block | doh_endpoint | listed | default.
        Kiểm DoH chạy cả khi chưa có policy (mới cài, chưa ghép đôi xong)."""
        d = normalize_domain(domain)
        if not d:
            return ("allow", "default")
        if self.is_never_blocked(d):
            return ("allow", "never_block")
        web = self.web_cfg()
        for rule in web.get("rules", []) or []:
            if domain_matches(d, rule.get("domain", "")):
                if rule.get("action") == "allow":
                    return ("allow", "rule_allow")
        for rule in web.get("rules", []) or []:
            if domain_matches(d, rule.get("domain", "")):
                if rule.get("action") == "block":
                    return ("block", "rule_block")
        if is_doh_endpoint(d):
            return ("block", "doh_endpoint")
        for blocked in web.get("blocked_domains", []) or []:
            if domain_matches(d, blocked):
                return ("block", "listed")
        return ("allow", "default")

    def safesearch_on(self) -> bool:
        return bool(self.web_cfg().get("safesearch", False))
