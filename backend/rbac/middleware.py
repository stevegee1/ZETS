from functools import wraps
from typing import Callable
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from database import get_db
from models import User, UserRole, AuditLog, AccessResult
from auth.dependencies import get_current_user

def require_role(*roles: UserRole) -> Callable:
    """
    FastAPI dependency factory.
    Usage: Depends(require_role(UserRole.teacher, UserRole.admin))
    Raises 403 and writes an AuditLog entry if the user's role is not in `roles`.
    """
    async def checker(
        request: Request,
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> User:
        resource = str(request.url.path)
        ip = request.client.host if request.client else "unknown"

        if current_user.role not in roles:
            log = AuditLog(
                user_id=current_user.id,
                action="ACCESS_DENIED",
                resource=resource,
                ip_address=ip,
                result=AccessResult.denied,
                detail=f"Role '{current_user.role}' not in required {[r.value for r in roles]}",
            )
            db.add(log)
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: requires role {[r.value for r in roles]}",
            )

        # Log allowed access
        log = AuditLog(
            user_id=current_user.id,
            action="ACCESS_GRANTED",
            resource=resource,
            ip_address=ip,
            result=AccessResult.allowed,
        )
        db.add(log)
        await db.commit()
        return current_user

    return checker
