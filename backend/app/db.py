from datetime import datetime, timezone
from sqlalchemy import create_engine, String, Integer, ForeignKey, DateTime, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from .config import DATABASE_URL

is_sqlite = DATABASE_URL.startswith("sqlite")
connect_args = {"check_same_thread": False} if is_sqlite else {}
pool_kwargs = {} if is_sqlite else {"pool_size": 10, "max_overflow": 20, "pool_recycle": 1800}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
    **pool_kwargs
)
SessionLocal = sessionmaker(bind=engine, autoflush=False)

class Base(DeclarativeBase): pass

def now(): return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    kind: Mapped[str] = mapped_column(String(10))
    target: Mapped[str] = mapped_column(Text)
    score: Mapped[int] = mapped_column(Integer)
    category: Mapped[str] = mapped_column(String(20))
    mode: Mapped[str] = mapped_column(String(60))
    details_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def init_db(): Base.metadata.create_all(engine)

class QuizAttempt(Base):
    __tablename__ = "quiz_attempts"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    score: Mapped[int] = mapped_column(Integer)
    total: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class SystemScan(Base):
    __tablename__ = "system_scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    scan_type: Mapped[str] = mapped_column(String(20))  # quick, full, custom
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued, running, paused, completed, cancelled, failed
    target_path: Mapped[str] = mapped_column(Text, default="")
    files_examined: Mapped[int] = mapped_column(Integer, default=0)
    files_skipped: Mapped[int] = mapped_column(Integer, default=0)
    errors_count: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    progress_pct: Mapped[int] = mapped_column(Integer, default=0)
    current_file: Mapped[str] = mapped_column(Text, default="")
    engine_status: Mapped[str] = mapped_column(String(100), default="")
    duration_seconds: Mapped[float] = mapped_column(default=0.0)
    details_json: Mapped[str] = mapped_column(Text, default="{}")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class SystemScanFinding(Base):
    __tablename__ = "system_scan_findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("system_scans.id"), index=True)
    file_path: Mapped[str] = mapped_column(Text)
    file_name: Mapped[str] = mapped_column(String(255))
    file_hash: Mapped[str] = mapped_column(String(64), default="")
    finding_type: Mapped[str] = mapped_column(String(50))  # malware, suspicious_pe, startup_persistence, double_extension, misconfig
    detection_source: Mapped[str] = mapped_column(String(60))  # Microsoft Defender, Signature Database, CyberShield Heuristic
    severity: Mapped[str] = mapped_column(String(20))  # Critical, High, Medium, Low, Informational
    malware_name: Mapped[str] = mapped_column(String(120), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    recommended_action: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20), default="active")  # active, quarantined, ignored
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
