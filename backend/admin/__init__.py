from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional
from database import get_db
from models import User, AuditLog, UserRole
from schemas import AuditLogOut, UserOut
from rbac.middleware import require_role
from monitoring.alerts import get_recent_alerts

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/users", response_model=list[UserOut])
async def list_users(
    current_user: User = Depends(require_role(UserRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User))
    return result.scalars().all()


@router.get("/audit-logs", response_model=list[AuditLogOut])
async def list_audit_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    result_filter: Optional[str] = Query(None, alias="result"),
    action_filter: Optional[str] = Query(None, alias="action"),
    zone_filter: Optional[str] = Query(None, alias="zone"),
    current_user: User = Depends(require_role(UserRole.teacher, UserRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    """
    Paginated audit log query. Supports optional filters:
    - result=allowed|denied
    - action=LOGIN_FAILED|FILE_DOWNLOAD|INTEGRITY_VIOLATION|…
    - zone=upload|access|auth
    """
    query = select(AuditLog).order_by(AuditLog.timestamp.desc())

    if result_filter:
        query = query.where(AuditLog.result == result_filter)
    if action_filter:
        query = query.where(AuditLog.action == action_filter)
    if zone_filter:
        query = query.where(AuditLog.zone == zone_filter)

    query = query.offset(skip).limit(limit)
    db_result = await db.execute(query)
    return db_result.scalars().all()


@router.get("/alerts")
async def list_alerts(
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    """Return recent security alerts fired by the monitoring engine."""
    return get_recent_alerts(limit=limit)
