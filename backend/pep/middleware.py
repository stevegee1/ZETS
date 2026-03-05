from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from jose import jwt, JWTError
from config import JWT_SECRET, JWT_ALGORITHM
from pdp.engine import decide
from zones.registry import get_zone_name
from monitoring.logger import get_logger
from monitoring.alerts import record_deny, record_privilege_escalation

log = get_logger("zets.pep")

# Paths that bypass PEP entirely (Starlette internals / docs)
_BYPASS_PREFIXES = ("/docs", "/redoc", "/openapi.json", "/favicon.ico")


class PEPMiddleware(BaseHTTPMiddleware):
    """
    Policy Enforcement Point.
    Intercepts every HTTP request, calls the PDP, and either passes the
    request through or returns a 403 before any route handler runs.
    On DENY, also persists an AuditLog entry to the database.
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        method = request.method

        # Let CORS preflight pass through — OPTIONS has no auth token
        if method == "OPTIONS" or any(path.startswith(p) for p in _BYPASS_PREFIXES):
            return await call_next(request)

        identity = _extract_identity(request)
        ip = request.client.host if request.client else "unknown"
        uid = identity.get("user_id") if identity else None

        result = decide(identity, path, method, ip=ip, user_id=uid)
        sensitivity = result["sensitivity"]
        zone_name = get_zone_name(path)

        if result["decision"] == "DENY":
            if sensitivity == "CRITICAL" and identity:
                record_privilege_escalation(
                    ip=ip,
                    user_id=identity.get("user_id"),
                    role=identity.get("role", "unknown"),
                    path=path,
                    sensitivity=sensitivity,
                )

            record_deny(
                ip=ip,
                path=path,
                user_id=identity.get("user_id") if identity else None,
                reason=result["reason"],
                sensitivity=sensitivity,
            )

            await _write_deny_log(
                user_id=identity.get("user_id") if identity else None,
                resource=path,
                ip=ip,
                reason=result["reason"],
                sensitivity=sensitivity,
                zone=zone_name,
            )

            log.warning("PEP DENY", extra={
                "ip": ip, "path": path, "method": method,
                "reason": result["reason"], "sensitivity": sensitivity,
                "zone": zone_name,
                "user_id": identity.get("user_id") if identity else None,
            })

            return JSONResponse(
                status_code=403,
                content={
                    "detail": "Access denied by policy enforcement point",
                    "reason": result["reason"],
                    "sensitivity": sensitivity,
                },
                headers={"X-PEP-Decision": "DENY"},
            )

        log.info("PEP ALLOW", extra={
            "ip": ip, "path": path, "method": method,
            "sensitivity": sensitivity, "zone": zone_name,
            "user_id": identity.get("user_id") if identity else None,
        })

        response = await call_next(request)
        response.headers["X-PEP-Decision"] = "ALLOW"
        response.headers["X-PEP-Sensitivity"] = sensitivity
        if zone_name:
            response.headers["X-PEP-Zone"] = zone_name
        return response


def _extract_identity(request: Request) -> dict | None:
    """Return {user_id, role, token_type} from a Bearer JWT, or None."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header[len("Bearer "):]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return {
            "user_id": payload.get("sub"),
            "role": payload.get("role", "student"),
            "token_type": payload.get("type", "access"),
        }
    except JWTError:
        return None


async def _write_deny_log(user_id, resource, ip, reason, sensitivity, zone):
    """Persist a PEP-level DENY to the AuditLog table."""
    try:
        from database import AsyncSessionLocal
        from models import AuditLog, AccessResult
        async with AsyncSessionLocal() as db:
            audit = AuditLog(
                user_id=user_id,
                action="PEP_DENY",
                resource=resource,
                ip_address=ip,
                result=AccessResult.denied,
                detail=reason,
                sensitivity=sensitivity,
                zone=zone,
            )
            db.add(audit)
            await db.commit()
    except Exception as e:
        log.warning(f"Failed to write PEP deny audit log: {e}")
