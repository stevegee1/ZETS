from collections import defaultdict, deque
from datetime import datetime, timezone
from threading import Lock
from typing import Optional

# ──────────────────────────────────────────────────────────────
# In-memory alert store (survives only while server is running)
# ──────────────────────────────────────────────────────────────
_lock = Lock()

# Recent alerts: deque of alert dicts (max 500 entries)
_alerts: deque = deque(maxlen=500)

# Per-IP deny counter for brute force detection: {ip: [(timestamp, path), ...]}
_deny_window: dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

BRUTE_FORCE_THRESHOLD = 5   # >5 denials
BRUTE_FORCE_WINDOW_SECS = 60  # within 60 seconds


# ──────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────

def record_deny(ip: str, path: str, user_id: Optional[str], reason: str, sensitivity: str):
    """Called by PEP on every DENY. Checks brute-force threshold."""
    now = datetime.now(timezone.utc)

    with _lock:
        window = _deny_window[ip]
        window.append(now)

        # Count events inside the sliding window
        cutoff = now.timestamp() - BRUTE_FORCE_WINDOW_SECS
        recent = [ts for ts in window if ts.timestamp() > cutoff]
        _deny_window[ip] = deque(recent, maxlen=100)

        if len(recent) > BRUTE_FORCE_THRESHOLD:
            _fire_alert("BRUTE_FORCE", ip=ip, user_id=user_id,
                        detail=f"{len(recent)} denied requests in {BRUTE_FORCE_WINDOW_SECS}s",
                        path=path)


def record_integrity_violation(ip: str, file_id: str, user_id: Optional[str]):
    """Called when a downloaded file fails hash verification."""
    with _lock:
        _fire_alert("INTEGRITY_VIOLATION", ip=ip, user_id=user_id,
                    detail=f"File {file_id} hash mismatch on disk",
                    path=f"/files/{file_id}/download")


def record_privilege_escalation(ip: str, user_id: Optional[str], role: str,
                                path: str, sensitivity: str):
    """Called when a low-privilege user hits a CRITICAL zone."""
    with _lock:
        _fire_alert("PRIVILEGE_ESCALATION", ip=ip, user_id=user_id,
                    detail=f"Role '{role}' attempted to access {sensitivity} resource",
                    path=path)


def record_anomaly(ip: str, user_id: Optional[str], score: float, path: str):
    """Called by PEP/PDP when anomaly score exceeds alert threshold."""
    with _lock:
        _fire_alert(
            "ANOMALY_DETECTED",
            ip=ip,
            user_id=user_id,
            detail=f"Anomaly score {score:.2f} on {path}",
            path=path,
        )


def get_recent_alerts(limit: int = 50) -> list[dict]:
    """Return the most recent alerts (newest first)."""
    with _lock:
        return list(reversed(list(_alerts)))[:limit]


# ──────────────────────────────────────────────────────────────
# Internal
# ──────────────────────────────────────────────────────────────

def _fire_alert(alert_type: str, *, ip: str, user_id: Optional[str],
                detail: str, path: str):
    """Append an alert. Must be called with _lock held."""
    alert = {
        "type": alert_type,
        "ip": ip,
        "user_id": user_id,
        "path": path,
        "detail": detail,
        "fired_at": datetime.now(timezone.utc).isoformat(),
    }
    _alerts.append(alert)
