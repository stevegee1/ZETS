from datetime import datetime, timedelta
from typing import Optional
import pyotp, qrcode, io, base64, bcrypt
from jose import jwt, JWTError
from config import JWT_SECRET, JWT_ALGORITHM, JWT_EXPIRY_MINUTES

# ── Password ─────────────────────────────────────────────────────────────────
def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

# ── JWT ───────────────────────────────────────────────────────────────────────
def create_token(data: dict, expires_minutes: Optional[int] = None) -> str:
    payload = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes or JWT_EXPIRY_MINUTES)
    payload["exp"] = expire
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError:
        return {}

# ── TOTP ──────────────────────────────────────────────────────────────────────
def generate_totp_secret() -> str:
    return pyotp.random_base32()

def get_totp_uri(secret: str, email: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name="ZETS Platform")

def verify_totp(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)

def make_qr_base64(uri: str) -> str:
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode()
    return f"data:image/png;base64,{b64}"
