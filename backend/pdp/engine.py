import re
from typing import Optional
from pdp.policies import RESOURCE_POLICIES, SENSITIVITY_RANK, ROLE_RANK


def _match_policy(path: str) -> tuple[str, Optional[str]]:
    """Return (sensitivity, min_role) for the given path. Defaults to HIGH/student if no match."""
    for pattern, sensitivity, min_role in RESOURCE_POLICIES:
        if re.search(pattern, path):
            return sensitivity, min_role
    return "HIGH", "student"  # safe default


def decide(
    identity: Optional[dict],
    path: str,
    method: str,
    ip: str = "unknown",
    user_id: Optional[str] = None,
) -> dict:
    """
    Evaluate an access request.

    Args:
        identity: dict {user_id, role, token_type} or None
        path:     URL path
        method:   HTTP method
        ip:       client IP address (for anomaly scoring)
        user_id:  resolved user UUID (for anomaly scoring)

    Returns:
        {"decision", "reason", "sensitivity", "min_role", "anomaly_score"}
    """
    sensitivity, min_role = _match_policy(path)

    # Unauthenticated request
    if identity is None:
        if min_role is None:
            return _allow(sensitivity, min_role, "Public endpoint, no auth required")
        return _deny(sensitivity, min_role, "Unauthenticated request to protected resource")

    role = identity.get("role", "student")
    token_type = identity.get("token_type", "access")

    # Temp tokens can only hit LOW sensitivity endpoints
    if token_type == "temp" and SENSITIVITY_RANK.get(sensitivity, 0) >= SENSITIVITY_RANK["MEDIUM"]:
        return _deny(sensitivity, min_role,
                     f"Temporary token cannot access {sensitivity} sensitivity resources")

    # No role requirement — any authenticated user passes
    if min_role is None:
        return _allow(sensitivity, min_role, "No role requirement for this resource")

    # Check role rank
    user_rank = ROLE_RANK.get(role, 0)
    required_rank = ROLE_RANK.get(min_role, 0)

    if user_rank < required_rank:
        return _deny(sensitivity, min_role,
                     f"Role '{role}' (rank {user_rank}) below required '{min_role}' (rank {required_rank})")

    # ── Anomaly gate (runs only after role check passes) ─────────
    try:
        from anomaly.engine import anomaly_engine, DENY_THRESHOLD, ALERT_THRESHOLD
        from monitoring.alerts import record_anomaly

        score = anomaly_engine.score_request(
            ip=ip,
            user_id=user_id,
            path=path,
            result="allowed",   # tentative — role check passed
            sensitivity=sensitivity,
        )

        if score >= DENY_THRESHOLD:
            record_anomaly(ip=ip, user_id=user_id, score=score, path=path)
            result = _deny(sensitivity, min_role, f"Anomaly score {score:.2f} exceeds threshold")
            result["anomaly_score"] = score
            return result

        if score >= ALERT_THRESHOLD:
            record_anomaly(ip=ip, user_id=user_id, score=score, path=path)

    except Exception:
        score = 0.0   # never block on engine failure
    else:
        pass

    result = _allow(sensitivity, min_role, f"Role '{role}' satisfies requirement '{min_role}'")
    try:
        result["anomaly_score"] = score
    except UnboundLocalError:
        result["anomaly_score"] = 0.0
    return result


def _allow(sensitivity: str, min_role: Optional[str], reason: str) -> dict:
    return {"decision": "ALLOW", "reason": reason, "sensitivity": sensitivity, "min_role": min_role, "anomaly_score": 0.0}


def _deny(sensitivity: str, min_role: Optional[str], reason: str) -> dict:
    return {"decision": "DENY", "reason": reason, "sensitivity": sensitivity, "min_role": min_role, "anomaly_score": 0.0}


