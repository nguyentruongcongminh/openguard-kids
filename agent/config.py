import json
import os
import uuid
from pathlib import Path

CONFIG_DIR = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "OpenGuardKids"
CONFIG_PATH = CONFIG_DIR / "config.json"

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

__all__ = ["CONFIG_DIR", "CONFIG_PATH", "DEFAULT_CONFIG", "load_config", "save_config"]


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
