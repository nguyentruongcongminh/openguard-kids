"""Tạo chứng chỉ TLS tự ký cho OGK-Server trong môi trường phòng lab.

Chạy:  .venv/bin/python scripts/make_cert.py [--out certs] [--host 192.168.1.10]
In ra SHA-256 fingerprint — phụ huynh đối chiếu trên dashboard và nhập vào
enroll.py --cert-fingerprint để agent ghim chứng chỉ.
"""
import argparse
import datetime as dt
import hashlib
import ipaddress
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _utf8_stdio():
    # Windows: stdout theo codepage (cp1252/cp1258) — in tiếng Việt ra pipe/log
    # sẽ văng UnicodeEncodeError. Ép UTF-8 như các entry point khác.
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def main():
    _utf8_stdio()
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="certs")
    ap.add_argument("--host", action="append", default=[],
                    help="IP hoặc hostname của server (có thể lặp lại)")
    args = ap.parse_args()

    names = [x509.DNSName("localhost"),
             x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]
    for h in args.host:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(h)))
        except ValueError:
            names.append(x509.DNSName(h))

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OpenGuard Kids Server")])
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime.utcnow() - dt.timedelta(days=1))
            .not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .sign(key, hashes.SHA256()))

    os.makedirs(args.out, exist_ok=True)
    cert_path = os.path.join(args.out, "server-cert.pem")
    key_path = os.path.join(args.out, "server-key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    fingerprint = hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    print(f"cert: {cert_path}")
    print(f"key : {key_path}")
    print(f"SHA-256 fingerprint: {fingerprint}")
    print("Đặt OGK_TLS_CERT=<đường dẫn cert> khi chạy server để dashboard hiển thị "
          "fingerprint này cho phụ huynh đối chiếu.")


if __name__ == "__main__":
    main()
