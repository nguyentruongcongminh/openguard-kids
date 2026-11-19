"""OGK-Agent — kho dữ liệu cục bộ v2 (SQLite trong ProgramData).

- policy_cache: bản sao policy document gần nhất (áp dụng khi mất mạng).
- events: sự kiện đúng lược đồ F3, có cờ sent; gửi thành công vẫn GIỮ lại làm
  lịch sử cho màn hình của trẻ (xóa khi quá 90 ngày) — sửa lỗi bản cũ xóa ngay
  khiến số liệu phía trẻ tụt về 0.
- kv_state: bộ đếm thời gian, ngân sách nhóm, trạng thái cảnh báo...
"""
import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path

try:
    from .config import CONFIG_DIR
except ImportError:
    from config import CONFIG_DIR

DB_PATH = CONFIG_DIR / "agent.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS policy_cache (
    key TEXT PRIMARY KEY,
    "json" TEXT NOT NULL,
    synced_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    type TEXT NOT NULL,
    subject TEXT NOT NULL DEFAULT '',
    duration_sec REAL NOT NULL DEFAULT 0,
    policy_id INTEGER NOT NULL DEFAULT 0,
    sent INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS kv_state (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""

__all__ = ["DB_PATH", "LocalStore"]


class LocalStore:
    def __init__(self, db_path: str | Path | None = None):
        self.db_path = Path(db_path) if db_path else DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---------------------------------------------------------- policy
    def save_policy(self, policy: dict) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                'INSERT INTO policy_cache(key, "json", synced_at) VALUES(?, ?, ?)'
                ' ON CONFLICT(key) DO UPDATE SET "json"=excluded."json", synced_at=excluded.synced_at',
                ("current", json.dumps(policy, ensure_ascii=False), time.time()))

    def get_policy(self) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                'SELECT "json" FROM policy_cache WHERE key = ?', ("current",)).fetchone()
        if row is None:
            return None
        try:
            data = json.loads(row["json"])
        except ValueError:
            return None
        return data if isinstance(data, dict) else None

    def policy_synced_at(self) -> float:
        with self._lock:
            row = self._conn.execute(
                "SELECT synced_at FROM policy_cache WHERE key = 'current'").fetchone()
        return float(row["synced_at"]) if row else 0.0

    # ---------------------------------------------------------- events
    def queue_event(self, type: str, subject: str = "", duration_sec: float = 0,
                    policy_id: int = 0, ts: float | None = None) -> str:
        event_id = uuid.uuid4().hex
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO events(event_id, ts, type, subject, duration_sec, policy_id, sent)"
                " VALUES(?, ?, ?, ?, ?, ?, 0)",
                (event_id, float(ts if ts is not None else time.time()), str(type),
                 str(subject or "")[:255], float(duration_sec or 0), int(policy_id or 0)))
        return event_id

    def pop_queued_events(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT event_id, ts, type, subject, duration_sec, policy_id FROM events"
                " WHERE sent = 0 ORDER BY ts ASC LIMIT ?", (max(1, int(limit)),)).fetchall()
        return [{"event_id": r["event_id"], "ts": r["ts"], "type": r["type"],
                 "subject": r["subject"], "duration_sec": r["duration_sec"],
                 "policy_id": r["policy_id"]} for r in rows]

    def mark_events_sent(self, event_ids) -> None:
        ids = [str(i) for i in (event_ids or [])]
        if not ids:
            return
        placeholders = ",".join("?" for _ in ids)
        with self._lock, self._conn:
            self._conn.execute(
                f"UPDATE events SET sent = 1 WHERE event_id IN ({placeholders})", ids)

    def purge_old_events(self, days: int = 90) -> int:
        cutoff = time.time() - days * 86400
        with self._lock, self._conn:
            cur = self._conn.execute(
                "DELETE FROM events WHERE sent = 1 AND ts < ?", (cutoff,))
            return cur.rowcount

    def day_events(self, day_start_epoch: float, day_end_epoch: float) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT type, subject, duration_sec FROM events WHERE ts >= ? AND ts < ?",
                (day_start_epoch, day_end_epoch)).fetchall()
        return [dict(r) for r in rows]

    def count_events(self, type: str, since_epoch: float = 0) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM events WHERE type = ? AND ts >= ?",
                (type, since_epoch)).fetchone()
        return int(row["n"]) if row else 0

    # ---------------------------------------------------------- kv
    def kv_get(self, key: str, default=None):
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM kv_state WHERE key = ?", (str(key),)).fetchone()
        return row["value"] if row is not None else default

    def kv_set(self, key: str, value) -> None:
        if value is None:
            text = ""
        elif isinstance(value, str):
            text = value
        elif isinstance(value, (dict, list)):
            text = json.dumps(value, ensure_ascii=False)
        else:
            text = str(value)
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO kv_state(key, value) VALUES(?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(key), text))

    # ---------------------------------------------------------- wipe
    def wipe(self) -> None:
        """Lệnh wipe_cache: xóa dữ liệu sử dụng cục bộ (giữ cấu hình + kv hệ thống tối thiểu)."""
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM events")
            self._conn.execute("DELETE FROM policy_cache")
            self._conn.execute(
                "DELETE FROM kv_state WHERE key LIKE 'used_seconds_%'"
                " OR key LIKE 'app_used_%' OR key LIKE 'cat_used_%'"
                " OR key LIKE 'extra_seconds_%' OR key LIKE 'warned_%'")
