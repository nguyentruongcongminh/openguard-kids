"""OGK-Agent — DNS proxy v2: lọc web tại 127.0.0.1:53 theo policy document.

- Quyết định chặn qua PolicyManager (miễn chặn NT6 thắng mọi luật).
- SafeSearch: ánh xạ truy vấn A/AAAA của các công cụ tìm kiếm sang máy chủ
  forcesafesearch bằng bản ghi CNAME (kiểm chứng được bằng nslookup).
- Sự kiện domain_query (chỉ tên miền cấp hai, gom theo 5 phút) và
  blocked_domain theo đúng lược đồ F3.
"""
import socket
import struct
import threading
import time

SAFESEARCH_MAP = {
    "google.com": "forcesafesearch.google.com",
    "www.google.com": "forcesafesearch.google.com",
    "bing.com": "strict.bing.com",
    "www.bing.com": "strict.bing.com",
    "duckduckgo.com": "safe.duckduckgo.com",
    "www.duckduckgo.com": "safe.duckduckgo.com",
}


def _norm(domain):
    d = str(domain or "").strip().lower().rstrip(".")
    return d[2:] if d.startswith("*.") else d


def parse_qname(packet):
    if len(packet) < 12:
        raise ValueError("short DNS packet")
    labels, offset, qend, jumps = [], 12, None, 0
    while True:
        if offset >= len(packet):
            raise ValueError("truncated qname")
        size = packet[offset]
        if size == 0:
            offset += 1
            if qend is None:
                qend = offset
            break
        if size & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated pointer")
            if qend is None:
                qend = offset + 2
            jumps += 1
            if jumps > 5:
                raise ValueError("compression loop")
            offset = ((size & 0x3F) << 8) | packet[offset + 1]
            continue
        if size & 0xC0:
            raise ValueError("bad label")
        offset += 1
        if offset + size > len(packet):
            raise ValueError("truncated label")
        labels.append(packet[offset:offset + size].decode("utf-8", "replace"))
        offset += size
        if sum(len(x) for x in labels) + len(labels) > 255:
            raise ValueError("qname too long")
    if qend is None or qend + 4 > len(packet):
        raise ValueError("truncated question")
    qtype = struct.unpack_from("!H", packet, qend)[0]
    return ".".join(labels).lower(), qtype, qend + 4


def encode_qname(domain):
    out = b""
    for label in _norm(domain).split("."):
        raw = label.encode("utf-8")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _response(query, rcode, answer=b"", ancount=0):
    if len(query) < 12:
        raise ValueError("short DNS packet")
    tid, flags = struct.unpack_from("!HH", query, 0)
    try:
        _, _, qend = parse_qname(query)
        question, qdcount = query[12:qend], 1
    except Exception:
        question, qdcount = b"", 0
    resp_flags = 0x8080 | (flags & 0x7800) | (flags & 0x0100) | (rcode & 0x0F)
    header = struct.pack("!HHHHHH", tid, resp_flags, qdcount, ancount, 0, 0)
    return header + question + answer


def build_nxdomain(query_packet):
    return _response(query_packet, 3)


def _servfail(query_packet):
    try:
        return _response(query_packet, 2)
    except Exception:
        tid = struct.unpack_from("!H", query_packet, 0)[0] if len(query_packet) >= 2 else 0
        return struct.pack("!HHHHHH", tid, 0x8082, 0, 0, 0, 0)


def forward(query_packet, upstream=("8.8.8.8", 53), timeout=3):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(query_packet, upstream)
            data, _ = sock.recvfrom(4096)
            return data
    except Exception:
        return _servfail(query_packet)


def build_safesearch_response(query_packet, upstream=("8.8.8.8", 53), timeout=3):
    """Trả CNAME sang máy chủ SafeSearch + bản ghi A/AAAA của máy chủ đó."""
    domain, qtype, qend = parse_qname(query_packet)
    target = SAFESEARCH_MAP.get(_norm(domain))
    if target is None or qtype not in (1, 28):
        return None
    tid = struct.unpack_from("!H", query_packet, 0)[0]
    qclass = struct.unpack_from("!H", query_packet, qend - 2)[0]
    probe = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) \
        + encode_qname(target) + struct.pack("!HH", qtype, qclass)
    raw = forward(probe, upstream, timeout)
    if len(raw) < 12:
        return None
    try:
        _, _, uqend = parse_qname(raw)
        ancount = struct.unpack_from("!H", raw, 6)[0]
    except Exception:
        return None
    # chép các bản ghi trả lời A/AAAA của upstream (tên trỏ về question của upstream,
    # giữ nguyên vì rdata mới là phần quan trọng; tên được thay bằng con trỏ 0xC00C
    # trỏ tới question trong gói trả lời của ta khi cần — ở đây ta dựng lại từng RR
    # với tên = con trỏ về question gốc).
    answers = b""
    offset = uqend
    copied = 0
    for _ in range(ancount):
        if offset + 2 > len(raw):
            break
        # tên: con trỏ 2 byte hoặc dãy nhãn kết thúc bằng 0
        if raw[offset] & 0xC0 == 0xC0:
            name_end = offset + 2
        else:
            name_end = offset
            while name_end < len(raw) and raw[name_end] != 0:
                name_end += raw[name_end] + 1
            name_end += 1
        if name_end + 10 > len(raw):
            break
        rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", raw, name_end)
        rdata = raw[name_end + 10: name_end + 10 + rdlen]
        if len(rdata) != rdlen:
            break
        offset = name_end + 10 + rdlen
        if rtype != qtype:
            continue
        answers += struct.pack("!HHHIH", 0xC00C, rtype, rclass, ttl, rdlen) + rdata
        copied += 1
    if not copied:
        return None
    cname_rdata = encode_qname(target)
    cname = struct.pack("!HHHIH", 0xC00C, 5, qclass, 300, len(cname_rdata)) + cname_rdata
    return _response(query_packet, 0, cname + answers, copied + 1)


class DnsProxy:
    def __init__(self, pm, bind=("127.0.0.1", 53), upstream=("8.8.8.8", 53),
                 on_event=None):
        self.pm = pm
        self.bind = bind
        self.upstream = upstream
        self.on_event = on_event  # fn(type, subject)
        self._sock = None
        self._thread = None
        self._stop = threading.Event()
        self._log_at: dict = {}

    def start(self):
        if self._thread is not None and self._thread.is_alive():
            return
        # Nghe ca IPv6 (::1): neu router cap DNS IPv6 (vd fe80::1) ma agent
        # chi nghe IPv4 127.0.0.1 thi Windows se phan giai thang qua router,
        # vong qua toan bo loc web (loi that tren may tre 17/11/2026).
        family = socket.AF_INET6 if ":" in str(self.bind[0]) else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(self.bind)
        except Exception:
            sock.close()
            raise
        sock.settimeout(0.5)
        self._sock = sock
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, args=(sock,), daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        sock, self._sock = self._sock, None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

    def decide(self, domain: str) -> str:
        return self.pm.web_decision(domain)

    def _serve(self, sock):
        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._handle(sock, data, addr)
            except Exception:
                continue

    def _handle(self, sock, data, addr):
        try:
            domain, qtype, _ = parse_qname(data)
        except Exception:
            self._send(sock, forward(data, self.upstream), addr)
            return
        if self.decide(domain) == "block":
            self._send(sock, build_nxdomain(data), addr)
            self._emit_throttled("blocked_domain", domain, 60)
            return
        # Truy van nguoc (PTR) khong phai "trang web tre vao" - khong ghi
        # vao bao cao (may tre that 17/11: in-addr.arpa loat len bao cao).
        if domain not in ("in-addr.arpa", "ip6.arpa") and not domain.endswith(
                (".in-addr.arpa", ".ip6.arpa")):
            self._emit_throttled("domain_query", domain, 300)
        if qtype in (1, 28) and self.pm.safesearch_on() and _norm(domain) in SAFESEARCH_MAP:
            resp = build_safesearch_response(data, self.upstream)
            if resp is not None:
                self._send(sock, resp, addr)
                return
        self._send(sock, forward(data, self.upstream), addr)

    def _emit_throttled(self, type_: str, domain: str, window: float) -> None:
        if self.on_event is None:
            return
        key = (type_, _norm(domain))
        now = time.monotonic()
        if now - self._log_at.get(key, -1e18) < window:
            return
        self._log_at[key] = now
        try:
            self.on_event(type_, domain)
        except Exception:
            pass

    @staticmethod
    def _send(sock, data, addr):
        if data:
            try:
                sock.sendto(data, addr)
            except OSError:
                pass

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()
