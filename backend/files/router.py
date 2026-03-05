import hashlib, os, uuid
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from database import get_db
from models import User, UserRole, File as FileModel, AuditLog, AccessResult
from schemas import FileOut
from auth.dependencies import get_current_user
from rbac.middleware import require_role
from config import UPLOAD_DIR
from monitoring.alerts import record_integrity_violation

router = APIRouter(prefix="/files", tags=["files"])

def _get_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _sha256_file(path: str) -> str:
    """Compute SHA-256 of a file on disk without loading it all into memory."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

# ─────────────────────────────────────────────────────────────
# POST /files/upload  →  teacher only
# ─────────────────────────────────────────────────────────────
@router.post("/upload", response_model=FileOut, status_code=201)
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    required_role: str = "student",
    current_user: User = Depends(require_role(UserRole.teacher, UserRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    content = await file.read()
    file_hash = _sha256(content)

    unique_name = f"{uuid.uuid4()}_{file.filename}"
    dest = os.path.join(UPLOAD_DIR, unique_name)
    with open(dest, "wb") as f:
        f.write(content)

    try:
        req_role = UserRole(required_role)
    except ValueError:
        req_role = UserRole.student

    db_file = FileModel(
        filename=file.filename,
        filepath=dest,
        sha256_hash=file_hash,
        uploader_id=current_user.id,
        required_role=req_role,
    )
    db.add(db_file)
    await db.commit()
    await db.refresh(db_file)
    return db_file

# ─────────────────────────────────────────────────────────────
# GET /files/  →  list files
# ─────────────────────────────────────────────────────────────
@router.get("/", response_model=list[FileOut])
async def list_files(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if current_user.role in (UserRole.teacher, UserRole.admin):
        result = await db.execute(select(FileModel))
    else:
        result = await db.execute(
            select(FileModel).where(FileModel.required_role == UserRole.student)
        )
    return result.scalars().all()

# ─────────────────────────────────────────────────────────────
# GET /files/{file_id}/download  →  role-gated download + integrity check
# ─────────────────────────────────────────────────────────────
@router.get("/{file_id}/download")
async def download_file(
    file_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(FileModel).where(FileModel.id == file_id))
    db_file = result.scalar_one_or_none()
    ip = _get_ip(request)

    if not db_file:
        raise HTTPException(status_code=404, detail="File not found")

    # Role gate
    role_order = {UserRole.student: 0, UserRole.teacher: 1, UserRole.admin: 2}
    if role_order.get(current_user.role, 0) < role_order.get(db_file.required_role, 0):
        log = AuditLog(
            user_id=current_user.id,
            action="FILE_DOWNLOAD_DENIED",
            resource=f"/files/{file_id}/download",
            ip_address=ip,
            result=AccessResult.denied,
            detail=f"File requires {db_file.required_role}, user is {current_user.role}",
            sensitivity="MEDIUM",
            zone="access",
        )
        db.add(log)
        await db.commit()
        raise HTTPException(status_code=403, detail="Insufficient role to access this file")

    # ── Hash integrity check ──────────────────────────────────
    if not os.path.exists(db_file.filepath):
        raise HTTPException(status_code=404, detail="File missing on disk")

    actual_hash = _sha256_file(db_file.filepath)
    if actual_hash != db_file.sha256_hash:
        # Log integrity violation
        violation_log = AuditLog(
            user_id=current_user.id,
            action="INTEGRITY_VIOLATION",
            resource=f"/files/{file_id}/download",
            ip_address=ip,
            result=AccessResult.denied,
            detail=f"Hash mismatch: stored={db_file.sha256_hash[:16]}… actual={actual_hash[:16]}…",
            sensitivity="HIGH",
            zone="access",
        )
        db.add(violation_log)
        await db.commit()

        # Fire alert
        record_integrity_violation(ip=ip, file_id=file_id, user_id=current_user.id)

        raise HTTPException(
            status_code=409,
            detail={
                "error": "INTEGRITY_VIOLATION",
                "message": "File has been tampered with. Download blocked.",
                "stored_hash": db_file.sha256_hash,
                "actual_hash": actual_hash,
            },
        )
    # ─────────────────────────────────────────────────────────

    log = AuditLog(
        user_id=current_user.id,
        action="FILE_DOWNLOAD",
        resource=f"/files/{file_id}/download",
        ip_address=ip,
        result=AccessResult.allowed,
        sensitivity="MEDIUM",
        zone="access",
    )
    db.add(log)
    await db.commit()

    return FileResponse(db_file.filepath, filename=db_file.filename)

# ─────────────────────────────────────────────────────────────
# GET /files/{file_id}/verify  →  teacher/admin integrity check
# ─────────────────────────────────────────────────────────────
@router.get("/{file_id}/verify")
async def verify_file(
    file_id: str,
    request: Request,
    current_user: User = Depends(require_role(UserRole.teacher, UserRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(FileModel).where(FileModel.id == file_id))
    db_file = result.scalar_one_or_none()
    if not db_file:
        raise HTTPException(status_code=404, detail="File not found")

    if not os.path.exists(db_file.filepath):
        return {"file_id": file_id, "valid": False, "reason": "File missing on disk"}

    actual_hash = _sha256_file(db_file.filepath)
    valid = actual_hash == db_file.sha256_hash

    return {
        "file_id": file_id,
        "filename": db_file.filename,
        "valid": valid,
        "stored_hash": db_file.sha256_hash,
        "actual_hash": actual_hash,
    }
