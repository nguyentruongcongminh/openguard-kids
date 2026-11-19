import base64
import os
import sys
import tempfile

_ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(_ROOT, "server"))
sys.path.insert(0, _ROOT)

os.environ.setdefault("OGK_DB_PATH", os.path.join(tempfile.mkdtemp(), "ogk-test.db"))
os.environ.setdefault("OGK_MASTER_KEY", base64.b64encode(b"T" * 32).decode())
os.environ.setdefault("ProgramData", tempfile.mkdtemp())

from app.models import Base, SessionLocal, engine  # noqa: E402

Base.metadata.create_all(bind=engine)

from app.policy import seed_domain_categories  # noqa: E402

_db = SessionLocal()
try:
    seed_domain_categories(_db)
finally:
    _db.close()
