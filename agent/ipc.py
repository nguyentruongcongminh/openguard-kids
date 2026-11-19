"""OGK-Agent — IPC giữa Windows Service (SYSTEM) và Tray UI (quyền user).

Kênh: HTTP-like JSON-lines trên 127.0.0.1 + token cục bộ (phương án đề cho
phép tại mục 2.2: "named pipe hoặc HTTP 127.0.0.1 có token cục bộ").
Service ghi {port} vào ProgramData/OpenGuardKids/ipc.json; token nằm trong
config.json — cả hai đều trong thư mục ACL chỉ SYSTEM/Administrators ghi,
tray chỉ đọc để kết nối.
"""
import json
import socket
import threading

try:
    from .config import CONFIG_DIR
except ImportError:
    from config import CONFIG_DIR

IPC_INFO_PATH = CONFIG_DIR / "ipc.json"
MAX_LINE = 1024 * 1024


class IPCServer:
    def __init__(self, token: str, handlers: dict):
        self.token = token
        self.handlers = handlers
        self._sock = None
        self._thread = None
        self._stop = threading.Event()
        self.port = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen(8)
        sock.settimeout(0.5)
        self.port = sock.getsockname()[1]
        self._sock = sock
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        IPC_INFO_PATH.write_text(json.dumps({"port": self.port}), encoding="utf-8")
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, args=(sock,),
                                        daemon=True, name="OGK-IPC")
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        try:
            IPC_INFO_PATH.unlink(missing_ok=True)
        except OSError:
            pass

    def _serve(self, sock):
        while not self._stop.is_set():
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            conn.settimeout(5)
            buf = b""
            while b"\n" not in buf and len(buf) <= MAX_LINE:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
            line = buf.split(b"\n", 1)[0]
            req = json.loads(line.decode("utf-8")) if line else {}
            if req.get("token") != self.token:
                resp = {"ok": False, "error": "invalid local token"}
            else:
                handler = self.handlers.get(req.get("method", ""))
                if handler is None:
                    resp = {"ok": False, "error": "unknown method"}
                else:
                    try:
                        resp = {"ok": True, "result": handler(req.get("params") or {})}
                    except Exception as exc:
                        resp = {"ok": False, "error": str(exc)}
            conn.sendall((json.dumps(resp, ensure_ascii=False) + "\n").encode("utf-8"))
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


class IPCClient:
    def __init__(self, token: str, info_path=IPC_INFO_PATH, timeout: float = 5):
        self.token = token
        self.info_path = info_path
        self.timeout = timeout

    def _port(self) -> int:
        data = json.loads(self.info_path.read_text(encoding="utf-8"))
        return int(data["port"])

    def call(self, method: str, **params):
        req = {"token": self.token, "method": method, "params": params}
        with socket.create_connection(("127.0.0.1", self._port()),
                                      timeout=self.timeout) as sock:
            sock.sendall((json.dumps(req, ensure_ascii=False) + "\n").encode("utf-8"))
            buf = b""
            while b"\n" not in buf:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
        resp = json.loads(buf.split(b"\n", 1)[0].decode("utf-8"))
        if not resp.get("ok"):
            raise RuntimeError(resp.get("error", "ipc error"))
        return resp.get("result")
