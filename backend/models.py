import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, ForeignKey, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from database import Base
import enum

class UserRole(str, enum.Enum):
    student = "student"
    teacher = "teacher"
    admin   = "admin"

class AccessResult(str, enum.Enum):
    allowed = "allowed"
    denied  = "denied"

def new_uuid() -> str:
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[UserRole] = mapped_column(SAEnum(UserRole), nullable=False, default=UserRole.student)
    totp_secret: Mapped[str | None] = mapped_column(String, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    files: Mapped[list["File"]] = relationship("File", back_populates="uploader")
    audit_logs: Mapped[list["AuditLog"]] = relationship("AuditLog", back_populates="user")


class File(Base):
    __tablename__ = "files"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    filename: Mapped[str] = mapped_column(String, nullable=False)
    filepath: Mapped[str] = mapped_column(String, nullable=False)
    sha256_hash: Mapped[str] = mapped_column(String, nullable=False)
    uploader_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), nullable=False)
    required_role: Mapped[UserRole] = mapped_column(SAEnum(UserRole), default=UserRole.student)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    uploader: Mapped["User"] = relationship("User", back_populates="files")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    user_id: Mapped[str | None] = mapped_column(String, ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String, nullable=False)
    resource: Mapped[str] = mapped_column(String, nullable=False)
    ip_address: Mapped[str] = mapped_column(String, nullable=True)
    result: Mapped[AccessResult] = mapped_column(SAEnum(AccessResult), nullable=False)
    detail: Mapped[str | None] = mapped_column(String, nullable=True)
    sensitivity: Mapped[str | None] = mapped_column(String, nullable=True)  # LOW/MEDIUM/HIGH/CRITICAL
    zone: Mapped[str | None] = mapped_column(String, nullable=True)          # upload/access/auth
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    user: Mapped["User | None"] = relationship("User", back_populates="audit_logs")


class AnomalyEvent(Base):
    __tablename__ = "anomaly_events"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    ip: Mapped[str] = mapped_column(String, nullable=False)
    user_id: Mapped[str | None] = mapped_column(String, nullable=True)
    path: Mapped[str] = mapped_column(String, nullable=False)
    score: Mapped[float] = mapped_column(nullable=False)
    sensitivity: Mapped[str | None] = mapped_column(String, nullable=True)
    result: Mapped[str | None] = mapped_column(String, nullable=True)   # allowed/denied
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class InvitationToken(Base):
    __tablename__ = "invitation_tokens"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    token: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    created_by: Mapped[str] = mapped_column(String, ForeignKey("users.id"), nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    used_by: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

