from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from database import get_db
from models import User, UserRole, AuditLog, AccessResult, InvitationToken
from schemas import (
    RegisterRequest, LoginRequest, LoginResponse,
    Verify2FARequest, TokenResponse, Setup2FAResponse, UserOut, InviteTokenOut,
)
from auth.utils import (
    hash_password, verify_password, create_token, decode_token,
    generate_totp_secret, get_totp_uri, verify_totp, make_qr_base64,
)
from auth.dependencies import get_current_user, get_current_user_any_token

router = APIRouter(prefix="/auth", tags=["auth"])

def _get_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"

# ─────────────────────────────────────────────────────────────
# POST /auth/register
# ─────────────────────────────────────────────────────────────
@router.post("/register", response_model=UserOut, status_code=201)
async def register(body: RegisterRequest, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    # Admin registrations require a valid invitation token
    if body.role == UserRole.admin:
        if not body.invite_token:
            raise HTTPException(status_code=403, detail="An invitation token is required to register as admin")
        inv_res = await db.execute(
            select(InvitationToken).where(InvitationToken.token == body.invite_token)
        )
        inv = inv_res.scalar_one_or_none()
        if not inv or inv.used:
            raise HTTPException(status_code=403, detail="Invalid or already-used invitation token")

    secret = generate_totp_secret()
    user = User(
        email=body.email,
        password_hash=hash_password(body.password),
        role=body.role,
        totp_secret=secret,
        totp_enabled=False,
    )
    db.add(user)
    await db.flush()   # get user.id before committing

    # Mark invite token as used
    if body.role == UserRole.admin and body.invite_token:
        inv.used = True
        inv.used_by = user.id
        db.add(inv)

    await db.commit()
    await db.refresh(user)
    return user

# ─────────────────────────────────────────────────────────────
# POST /auth/invite  →  admin generates a one-time invite token
# ─────────────────────────────────────────────────────────────
@router.post("/invite", response_model=InviteTokenOut)
async def create_invite(current_user: User = Depends(get_current_user),
                        db: AsyncSession = Depends(get_db)):
    if current_user.role != UserRole.admin:
        raise HTTPException(status_code=403, detail="Only admins can generate invitation tokens")
    import uuid
    inv = InvitationToken(
        token=str(uuid.uuid4()),
        created_by=current_user.id,
    )
    db.add(inv)
    await db.commit()
    return InviteTokenOut(token=inv.token)



# ─────────────────────────────────────────────────────────────
# POST /auth/login  →  step 1: credentials
# ─────────────────────────────────────────────────────────────
@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()

    ip = _get_ip(request)

    if not user or not verify_password(body.password, user.password_hash):
        log = AuditLog(
            user_id=user.id if user else None,
            action="LOGIN_FAILED",
            resource="/auth/login",
            ip_address=ip,
            result=AccessResult.denied,
            detail="Bad credentials",
        )
        db.add(log)
        await db.commit()
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # Issue a short-lived temp token (5 min) for the 2FA step
    temp_token = create_token(
        {"sub": user.id, "type": "temp", "role": user.role},
        expires_minutes=5,
    )

    log = AuditLog(
        user_id=user.id,
        action="LOGIN_STEP1",
        resource="/auth/login",
        ip_address=ip,
        result=AccessResult.allowed,
        detail="Credentials verified, awaiting 2FA",
    )
    db.add(log)
    await db.commit()

    return LoginResponse(requires_2fa=True, temp_token=temp_token)

# ─────────────────────────────────────────────────────────────
# POST /auth/verify-2fa  →  step 2: validate TOTP
# ─────────────────────────────────────────────────────────────
@router.post("/verify-2fa", response_model=TokenResponse)
async def verify_2fa(body: Verify2FARequest, request: Request, db: AsyncSession = Depends(get_db)):
    payload = decode_token(body.temp_token)
    user_id = payload.get("sub")
    token_type = payload.get("type")
    ip = _get_ip(request)

    if not user_id or token_type != "temp":
        raise HTTPException(status_code=401, detail="Invalid or expired temporary token")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.totp_secret:
        raise HTTPException(status_code=401, detail="User not found")

    if not verify_totp(user.totp_secret, body.totp_code):
        log = AuditLog(
            user_id=user.id,
            action="2FA_FAILED",
            resource="/auth/verify-2fa",
            ip_address=ip,
            result=AccessResult.denied,
            detail="Invalid TOTP code",
        )
        db.add(log)
        await db.commit()
        raise HTTPException(status_code=401, detail="Invalid 2FA code")

    # Enable 2FA if first time
    if not user.totp_enabled:
        user.totp_enabled = True
        db.add(user)

    # Issue full access token
    access_token = create_token({"sub": user.id, "type": "access", "role": user.role})

    log = AuditLog(
        user_id=user.id,
        action="LOGIN_SUCCESS",
        resource="/auth/verify-2fa",
        ip_address=ip,
        result=AccessResult.allowed,
        detail="2FA verified, access granted",
    )
    db.add(log)
    await db.commit()

    return TokenResponse(access_token=access_token)

# ─────────────────────────────────────────────────────────────
# GET /auth/setup-2fa  →  return QR code for authenticator app
# ─────────────────────────────────────────────────────────────
@router.get("/setup-2fa", response_model=Setup2FAResponse)
async def setup_2fa(current_user: User = Depends(get_current_user_any_token)):
    """
    Called right after registration. Returns a TOTP provisioning URI
    and a base64 QR code for scanning with Google Authenticator / Authy.
    Uses the temp token so the user can call this before full 2FA is complete.
    """
    if not current_user.totp_secret:
        raise HTTPException(status_code=400, detail="No TOTP secret found")

    uri = get_totp_uri(current_user.totp_secret, current_user.email)
    qr = make_qr_base64(uri)
    return Setup2FAResponse(provisioning_uri=uri, qr_code_base64=qr)

# ─────────────────────────────────────────────────────────────
# GET /auth/me  →  current user info
# ─────────────────────────────────────────────────────────────
@router.get("/me", response_model=UserOut)
async def me(current_user: User = Depends(get_current_user)):
    return current_user
