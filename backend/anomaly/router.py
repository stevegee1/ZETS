from fastapi import APIRouter, Depends, HTTPException
from anomaly.engine import anomaly_engine
from auth.dependencies import get_current_user
from models import User

router = APIRouter(prefix="/admin/anomalies", tags=["anomalies"])


def _require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return current_user


@router.get("")
async def get_anomaly_scores(_: User = Depends(_require_admin)):
    """Return current anomaly score per IP, highest first."""
    return anomaly_engine.get_scores()


@router.get("/timeline")
async def get_anomaly_timeline(limit: int = 100, _: User = Depends(_require_admin)):
    """Return the most recent N scored events."""
    return anomaly_engine.get_timeline(limit=min(limit, 500))


@router.post("/retrain")
async def retrain(_: User = Depends(_require_admin)):
    """Manually trigger IsolationForest retraining."""
    result = anomaly_engine.retrain()
    return result
