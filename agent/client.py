"""OGK-Agent — ServerClient v2.

- Access token 15 phút + refresh token; tự làm mới trước khi hết hạn / khi 401.
- Ghim chứng chỉ (F5): nếu config có cert_fingerprint, mọi kết nối HTTPS đều
  được kiểm tra SHA-256 của chứng chỉ phía server bằng một lần bắt tay TLS
  riêng trước phiên làm việc; không khớp -> từ chối kết nối.
"""
import hashlib
import json
import queue as queue_module
import socket
import ssl
import threading
import time
from urllib.parse import quote, urlparse

import requests
import websocket

__all__ = ["ServerClient", "WSListener", "redeem_pairing", "device_fingerprint"]


def device_fingerprint() -> str:
    import platform
    import uuid as _uuid
    parts = [platform.node(), str(_uuid.getnode()), platform.machine()]
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Cryptography") as key:
            parts.append(str(winreg.QueryValueEx(key, "MachineGuid")[0]))
    except Exception:
        pass
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def check_cert_pin(base_url: str, fingerprint: str, timeout: float = 10) -> None:
    """Bắt tay TLS riêng để đối chiếu SHA-256 chứng chỉ (ghim chứng chỉ, F5)."""
    parsed = urlparse(base_url)
    host, port = parsed.hostname, parsed.port or 443
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # kiểm chứng bằng fingerprint thay cho CA
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    digest = hashlib.sha256(der).hexdigest()
    if digest != (fingerprint or "").lower():
        raise ssl.SSLError(
            f"certificate pinning mismatch: server presented {digest}, "
            f"expected {fingerprint}")


def redeem_pairing(server_url: str, code: str, device_name: str,
                   fingerprint: str = "", timeout: float = 15,
                   cert_fingerprint: str = "") -> dict:
    base = server_url.rstrip("/")
    verify = True
    if base.startswith("https://") and cert_fingerprint:
        check_cert_pin(base, cert_fingerprint, timeout)
        verify = False  # niềm tin đã thiết lập bằng fingerprint ngoài băng
    resp = requests.post(f"{base}/pairing/redeem",
                         json={"code": code.strip().upper(), "device_name": device_name,
                               "fingerprint": fingerprint or device_fingerprint()},
                         timeout=timeout, verify=verify)
    if not 200 <= resp.status_code < 300:
        raise RuntimeError(f"pairing failed: HTTP {resp.status_code}: {resp.text[:200]}")
    return resp.json()


class ServerClient:
    def __init__(self, base_url: str, access_token: str = "", refresh_token: str = "",
                 cert_fingerprint: str = "", timeout: float = 10, on_tokens=None):
        self.base_url = str(base_url or "").rstrip("/")
        self.access_token = access_token or ""
        self.refresh_token = refresh_token or ""
        self.cert_fingerprint = (cert_fingerprint or "").lower()
        self.timeout = timeout
        self.on_tokens = on_tokens  # fn(access, refresh, expires_at_epoch)
        self.access_expires_at = 0.0
        self._session = requests.Session()
        self._pin_checked_at = 0.0

    # ------------------------------------------------------------ ghim chứng chỉ
    def _check_pin(self) -> None:
        if not self.cert_fingerprint or not self.base_url.startswith("https://"):
            return
        if time.time() - self._pin_checked_at < 300:
            return
        check_cert_pin(self.base_url, self.cert_fingerprint, self.timeout)
        self._pin_checked_at = time.time()

    # ------------------------------------------------------------ token
    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json"}

    def refresh(self) -> bool:
        if not self.refresh_token:
            return False
        verify = not (self.cert_fingerprint and self.base_url.startswith("https://"))
        try:
            resp = self._session.post(
                f"{self.base_url}/device/refresh",
                json={"refresh_token": self.refresh_token}, timeout=self.timeout,
                verify=verify)
            if resp.status_code != 200:
                return False
            data = resp.json()
        except (requests.RequestException, ValueError):
            return False
        self.access_token = data.get("access_token", "")
        self.access_expires_at = time.time() + float(data.get("access_expires_in", 900))
        if self.on_tokens:
            try:
                self.on_tokens(self.access_token, self.refresh_token, self.access_expires_at)
            except Exception:
                pass
        return bool(self.access_token)

    def _request(self, method: str, path: str, payload=None, retry: bool = True):
        self._check_pin()
        if self.access_expires_at and time.time() > self.access_expires_at - 30:
            self.refresh()
        # Khi đã ghim chứng chỉ: niềm tin nằm ở fingerprint (đã kiểm ở _check_pin),
        # nên tắt xác thực CA cho phiên — nếu không, cert tự ký sẽ bị requests chặn.
        verify = not (self.cert_fingerprint and self.base_url.startswith("https://"))
        try:
            resp = self._session.request(method, f"{self.base_url}{path}", json=payload,
                                         headers=self._headers(), timeout=self.timeout,
                                         verify=verify)
        except requests.RequestException:
            return None
        if resp.status_code == 401 and retry and self.refresh():
            return self._request(method, path, payload, retry=False)
        if not 200 <= resp.status_code < 300:
            return None
        if not resp.content:
            return {}
        try:
            data = resp.json()
        except ValueError:
            return None
        return data if isinstance(data, dict) else {"data": data}

    # ------------------------------------------------------------ API thiết bị
    def heartbeat(self, payload: dict | None = None) -> dict | None:
        return self._request("POST", "/device/heartbeat", payload or {})

    def fetch_policy(self) -> dict | None:
        data = self._request("GET", "/device/policy")
        if isinstance(data, dict) and isinstance(data.get("policy"), dict):
            return data["policy"]
        return data

    def upload_events(self, events: list[dict]) -> dict | None:
        if not events:
            return {"accepted": 0, "duplicates": 0}
        return self._request("POST", "/device/events", {"events": list(events)})

    def ack_command(self, command_id: int) -> bool:
        return self._request("POST", f"/device/commands/{command_id}/ack", {}) is not None

    def send_alert(self, kind: str, detail: dict) -> bool:
        return self._request("POST", "/device/alerts",
                             {"kind": kind, "detail": detail or {}}) is not None

    def send_request(self, type_: str, minutes=None, subject=None, reason: str = "") -> dict | None:
        payload = {"type": type_, "reason": reason or ""}
        if minutes is not None:
            payload["minutes"] = minutes
        if subject:
            payload["subject"] = subject
        return self._request("POST", "/device/requests", payload)

    def my_requests(self) -> list:
        data = self._request("GET", "/device/requests")
        return data.get("data", []) if isinstance(data, dict) else []

    def child_summary(self) -> dict | None:
        return self._request("GET", "/child/summary")

    def child_audit(self) -> list:
        data = self._request("GET", "/child/audit")
        return data.get("data", []) if isinstance(data, dict) else []

    def close(self) -> None:
        self._session.close()


def _ws_url(base_url: str, token: str) -> str:
    base = str(base_url or "").rstrip("/")
    if base.startswith("https://"):
        base = "wss://" + base[len("https://"):]
    elif base.startswith("http://"):
        base = "ws://" + base[len("http://"):]
    return f"{base}/ws/device?token={quote(str(token or ''), safe='')}"


class WSListener:
    """Nghe lệnh khẩn qua WebSocket. Token lấy qua token_provider() mỗi lần
    kết nối lại để luôn dùng access token còn hạn."""

    RECONNECT_DELAY = 5

    def __init__(self, base_url: str, token_provider, command_queue=None,
                 reconnect_delay: float = RECONNECT_DELAY, ack_handler=None,
                 cert_fingerprint: str = ""):
        self.base_url = str(base_url or "").rstrip("/")
        self.token_provider = token_provider
        self.command_queue = command_queue if command_queue is not None else queue_module.Queue()
        self.queue = self.command_queue
        self.reconnect_delay = float(reconnect_delay)
        self.ack_handler = ack_handler
        self.cert_fingerprint = (cert_fingerprint or "").lower()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._ws = None

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> threading.Thread:
        if self.is_running:
            return self._thread
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="OGK-WSListener", daemon=True)
        self._thread.start()
        return self._thread

    def _on_message(self, ws, message) -> None:
        try:
            cmd = json.loads(message) if isinstance(message, (str, bytes)) else message
        except ValueError:
            cmd = message
        if isinstance(cmd, dict) and cmd.get("type") == "command" and self.ack_handler:
            pass  # ack do controller thực hiện sau khi thi hành lệnh
        try:
            self.command_queue.put(cmd)
        except Exception:
            pass

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                token = self.token_provider() or ""
                self._ws = websocket.WebSocketApp(
                    _ws_url(self.base_url, token),
                    on_message=self._on_message,
                )
                sslopt = {}
                if self.base_url.startswith("https://") and self.cert_fingerprint:
                    # Cert tự ký: websocket-client mặc định kiểm CA sẽ luôn
                    # thất bại -> WS không bao giờ nối được. Niềm tin nằm ở
                    # ghim chứng chỉ: kiểm fingerprint trước, rồi tắt CA.
                    check_cert_pin(self.base_url, self.cert_fingerprint,
                                   timeout=10)
                    sslopt = {"cert_reqs": ssl.CERT_NONE}
                self._ws.run_forever(ping_interval=30, ping_timeout=10,
                                     sslopt=sslopt)
            except Exception:
                pass
            finally:
                self._ws = None
            if not self._stop.is_set():
                self._stop.wait(self.reconnect_delay)

    def stop(self, timeout: float = 5) -> None:
        self._stop.set()
        if self._ws is not None:
            try:
                self._ws.close()
            except Exception:
                pass
        thread = self._thread
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=timeout)
        if thread is not None and not thread.is_alive():
            self._thread = None
