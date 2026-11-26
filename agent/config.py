import json
import os
import uuid
from pathlib import Path

CONFIG_DIR = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "OpenGuardKids"
CONFIG_PATH = CONFIG_DIR / "config.json"
# Thư mục con dành riêng cho tray: chỉ chứa tray.json (cổng IPC, token IPC,
# trạng thái ghép đôi, tên trẻ) — KHÔNG có bí mật thiết bị. ACL của thư mục
# cha chỉ cho SYSTEM/Administrators; thư mục này cấp thêm Users quyền đọc để
# tray (chạy bằng tài khoản trẻ) kết nối được IPC mà không đọc được
# config.json / cơ sở dữ liệu (F5.7).
TRAY_DIR = CONFIG_DIR / "tray"
TRAY_INFO_PATH = TRAY_DIR / "tray.json"

DEFAULT_CONFIG = {
    "server_url": "http://127.0.0.1:8000",
    "device_id": "",
    "child_id": "",
    "child_name": "",
    "access_token": "",
    "refresh_token": "",
    "access_expires_at": 0,
    "policy_key": "",
    "cert_fingerprint": "",
    "ipc_token": "",
    "upstream_dns": "8.8.8.8",
}

__all__ = ["CONFIG_DIR", "CONFIG_PATH", "DEFAULT_CONFIG", "load_config",
           "save_config", "TRAY_DIR", "TRAY_INFO_PATH", "write_tray_info",
           "load_tray_info"]


def write_tray_info(port, ipc_token, paired, child_name) -> dict:
    """Service (SYSTEM) ghi tray.json cho tray đọc. Chỉ 4 khóa tối thiểu tray
    cần; tuyệt đối không đưa refresh_token/access_token/policy_key vào đây."""
    TRAY_DIR.mkdir(parents=True, exist_ok=True)
    info = {"port": int(port), "ipc_token": ipc_token or "",
            "paired": bool(paired), "child_name": child_name or ""}
    TRAY_INFO_PATH.write_text(json.dumps(info, ensure_ascii=False),
                              encoding="utf-8")
    return info


def load_tray_info() -> dict:
    """Tray đọc tray.json — CHỈ đọc, không bao giờ ghi: tài khoản trẻ không
    có quyền ghi vào thư mục dữ liệu (trước đây load_config() tự ghi lại
    config.json khi thiếu khóa -> sẽ PermissionError dưới ACL mới)."""
    try:
        data = json.loads(TRAY_INFO_PATH.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {"port": int(data.get("port") or 0),
                    "ipc_token": data.get("ipc_token") or "",
                    "paired": bool(data.get("paired")),
                    "child_name": data.get("child_name") or ""}
    except (OSError, ValueError):
        pass
    return {"port": 0, "ipc_token": "", "paired": False, "child_name": ""}


def save_config(config: dict | None = None, **updates) -> dict:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    current: dict = {}
    if CONFIG_PATH.exists():
        try:
            data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                current = data
        except (OSError, ValueError):
            current = {}
    cfg = {**DEFAULT_CONFIG, **current, **(config or {}), **updates}
    if not cfg.get("ipc_token"):
        cfg["ipc_token"] = uuid.uuid4().hex
    if cfg.get("server_url"):
        cfg["server_url"] = str(cfg["server_url"]).rstrip("/")
    tmp_path = CONFIG_PATH.with_name("config.json.tmp")
    tmp_path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp_path.replace(CONFIG_PATH)
    return cfg


def load_config() -> dict:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not CONFIG_PATH.exists():
        return save_config()
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("config root must be an object")
    except (OSError, ValueError):
        try:
            CONFIG_PATH.replace(Path(f"{CONFIG_PATH}.bak"))
        except OSError:
            pass
        return save_config()
    cfg = {**DEFAULT_CONFIG, **data}
    if isinstance(cfg.get("server_url"), str):
        cfg["server_url"] = cfg["server_url"].rstrip("/")
    return save_config(cfg) if cfg != data else cfg
