"""OGK-Server — mô hình dữ liệu v2 (khớp kiến trúc đã duyệt 13/11/2026)."""
import os
from datetime import datetime

from sqlalchemy import (JSON, Boolean, Column, Date, DateTime, Float, ForeignKey,
                        Integer, String, create_engine, event)
from sqlalchemy.orm import DeclarativeBase, relationship, sessionmaker

DB_PATH = os.getenv("OGK_DB_PATH", "ogk.db")
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})


@event.listens_for(engine, "connect")
def _sqlite_pragmas(dbapi_conn, _record):
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")       # SQLite WAL theo mục 2.2 của đề
    cur.execute("PRAGMA foreign_keys=ON")
    cur.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class Parent(Base):
    __tablename__ = "parents"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)          # Argon2id
    totp_secret_enc = Column(String, nullable=True)         # AES-GCM, None = chưa bật 2FA
    role = Column(String, default="parent", nullable=False)  # parent | admin
    failed_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    children = relationship("Child", back_populates="parent", cascade="all, delete-orphan")


class WebSession(Base):
    """Phiên đăng nhập phụ huynh lưu phía server (đăng xuất = xóa dòng)."""
    __tablename__ = "web_sessions"
    id = Column(Integer, primary_key=True)
    token_hash = Column(String, unique=True, index=True, nullable=False)
    parent_id = Column(ForeignKey("parents.id"), nullable=False, index=True)
    csrf_token = Column(String, nullable=False)
    ip = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)


class Child(Base):
    __tablename__ = "children"
    id = Column(Integer, primary_key=True)
    parent_id = Column(ForeignKey("parents.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    dob = Column(Date, nullable=True)
    parent = relationship("Parent", back_populates="children")
    devices = relationship("Device", back_populates="child", cascade="all, delete-orphan")


class PairingCode(Base):
    """Mã ghép đôi 8 ký tự, hạn 10 phút, dùng 1 lần (mục 2.3 của đề)."""
    __tablename__ = "pairing_codes"
    id = Column(Integer, primary_key=True)
    code_hash = Column(String, unique=True, index=True, nullable=False)
    parent_id = Column(ForeignKey("parents.id"), nullable=False)
    child_id = Column(ForeignKey("children.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)


class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True)
    child_id = Column(ForeignKey("children.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    fingerprint = Column(String, nullable=True)
    access_token_hash = Column(String, unique=True, index=True, nullable=True)
    access_expires_at = Column(DateTime, nullable=True)
    refresh_token_hash = Column(String, unique=True, index=True, nullable=True)
    policy_key_enc = Column(String, nullable=False)  # AES-GCM(khóa HMAC của policy)
    enrolled_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, nullable=True)
    revoked = Column(Boolean, default=False)
    child = relationship("Child", back_populates="devices")


class Policy(Base):
    """Phần có thể chỉnh sửa của policy document; version/signature tính khi phát hành."""
    __tablename__ = "policies"
    id = Column(Integer, primary_key=True)
    device_id = Column(ForeignKey("devices.id"), unique=True, nullable=False, index=True)
    version = Column(Integer, default=1, nullable=False)
    document = Column(JSON, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class UsageEvent(Base):
    """Lược đồ khóa cứng F3: ts, device_id, child_id, type, subject, duration_sec, policy_id."""
    __tablename__ = "usage_events"
    id = Column(Integer, primary_key=True)
    event_id = Column(String, unique=True, index=True, nullable=False)  # idempotency key
    device_id = Column(ForeignKey("devices.id"), nullable=False, index=True)
    child_id = Column(ForeignKey("children.id"), nullable=False, index=True)
    type = Column(String, nullable=False)
    subject = Column(String, default="")
    duration_sec = Column(Float, default=0)
    policy_id = Column(Integer, nullable=False)  # = policy version lúc xảy ra sự kiện
    ts_epoch = Column(Float, nullable=False, index=True)
    received_at = Column(DateTime, default=datetime.utcnow)


class Command(Base):
    __tablename__ = "commands"
    id = Column(Integer, primary_key=True)
    device_id = Column(ForeignKey("devices.id"), nullable=False, index=True)
    type = Column(String, nullable=False)  # lock_now|unlock|grant_extra|break_15|pause_today|wipe_cache
    payload = Column(JSON, default=dict)
    status = Column(String, default="pending")  # pending|sent|done
    created_by = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    ack_at = Column(DateTime, nullable=True)


class ChildRequest(Base):
    """Yêu cầu của trẻ (NT3): xin thêm giờ hoặc báo chặn nhầm — luôn có phản hồi."""
    __tablename__ = "child_requests"
    id = Column(Integer, primary_key=True)
    device_id = Column(ForeignKey("devices.id"), nullable=False, index=True)
    type = Column(String, nullable=False)  # extra_time | false_block
    minutes = Column(Integer, nullable=True)
    subject = Column(String, nullable=True)  # app/miền bị chặn nhầm
    reason = Column(String, default="")
    status = Column(String, default="pending")  # pending|approved|rejected
    decision_note = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    decided_at = Column(DateTime, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    parent_id = Column(ForeignKey("parents.id"), nullable=True, index=True)  # phạm vi sở hữu
    actor = Column(String, nullable=False)
    role = Column(String, default="parent")
    action = Column(String, nullable=False)
    ip = Column(String, nullable=True)
    old = Column(JSON, nullable=True)
    new = Column(JSON, nullable=True)
    ts = Column(DateTime, default=datetime.utcnow, index=True)


class DomainCategory(Base):
    __tablename__ = "domain_categories"
    id = Column(Integer, primary_key=True)
    domain = Column(String, unique=True, index=True, nullable=False)
    category = Column(String, nullable=False)
    note = Column(String, default="")
