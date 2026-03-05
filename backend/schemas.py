from datetime import datetime
from pydantic import BaseModel, EmailStr, ConfigDict
from models import UserRole

# --- Auth ---
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    role: UserRole = UserRole.student
    invite_token: str | None = None   # required when role == admin

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class LoginResponse(BaseModel):
    requires_2fa: bool
    temp_token: str

class Verify2FARequest(BaseModel):
    temp_token: str
    totp_code: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class Setup2FAResponse(BaseModel):
    provisioning_uri: str
    qr_code_base64: str

# --- User ---
class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: str
    role: UserRole
    totp_enabled: bool
    created_at: datetime

# --- Files ---
class FileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    filename: str
    sha256_hash: str
    uploader_id: str
    required_role: UserRole
    uploaded_at: datetime

# --- Audit ---
class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    user_id: str | None
    action: str
    resource: str
    ip_address: str | None
    result: str
    detail: str | None
    sensitivity: str | None
    zone: str | None
    timestamp: datetime

# --- Anomaly ---
class AnomalyEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    ip: str
    user_id: str | None
    path: str
    score: float
    sensitivity: str | None
    result: str | None
    timestamp: datetime

# --- Invite ---
class InviteTokenOut(BaseModel):
    token: str
