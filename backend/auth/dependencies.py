from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from database import get_db
from models import User
from auth.utils import decode_token

bearer_scheme = HTTPBearer()

async def _get_user_by_token(token: str, db: AsyncSession, allowed_types: tuple) -> User:
    payload = decode_token(token)
    user_id: str | None = payload.get("sub")
    token_type: str | None = payload.get("type")

    if not user_id or token_type not in allowed_types:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Requires a full access token."""
    return await _get_user_by_token(credentials.credentials, db, ("access",))

async def get_current_user_any_token(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Accepts both temp and access tokens (used for /auth/setup-2fa)."""
    return await _get_user_by_token(credentials.credentials, db, ("temp", "access"))

