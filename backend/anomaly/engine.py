"""
Anomaly Detection Engine — Milestone 3
IsolationForest scorer with per-IP rolling window, rule-based fallback,
DB persistence, and startup history reload.
"""
from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from threading import Lock, Thread
from typing import Optional

import numpy as np
from sklearn.ensemble import IsolationForest

# ── Constants ─────────────────────────────────────────────────────────────────

SENSITIVITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
WINDOW_SECS      = 60
MIN_SAMPLES      = 30
RETRAIN_EVERY    = 50
MAX_BUFFER       = 2000
ALERT_THRESHOLD  = 0.75
DENY_THRESHOLD   = 0.85


# ── Feature extraction ────────────────────────────────────────────────────────

def _hour_encode(dt: datetime) -> tuple[float, float]:
    h = dt.hour + dt.minute / 60
    return math.sin(2 * math.pi * h / 24), math.cos(2 * math.pi * h / 24)


def _build_features(window_events: list[dict], sensitivity: str, now: float) -> list[float]:
    cutoff = now - WINDOW_SECS
    recent = [e for e in window_events if e["ts"] > cutoff]
    req_rate  = len(recent) / WINDOW_SECS
    denied    = [e for e in recent if e["result"] == "denied"]
    deny_rate = len(denied) / max(len(recent), 1)
    sens_rank = SENSITIVITY_RANK.get(sensitivity, 1) / 3.0
    now_dt    = datetime.fromtimestamp(now, tz=timezone.utc)
    h_sin, h_cos = _hour_encode(now_dt)
    return [req_rate, deny_rate, sens_rank, h_sin, h_cos]


# ── Engine ────────────────────────────────────────────────────────────────────

class AnomalyEngine:
    def __init__(self) -> None:
        self._lock       = Lock()
        self._ip_window: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._train_buf: deque = deque(maxlen=MAX_BUFFER)
        self._history: deque = deque(maxlen=500)
        self._latest_scores: dict[str, dict] = {}
        self._model: Optional[IsolationForest] = None
        self._trained_on = 0
        self._events_since_retrain = 0

    # ── Public API ────────────────────────────────────────────────────────────

    def score_request(
        self,
        ip: str,
        user_id: Optional[str],
        path: str,
        result: str,
        sensitivity: str,
    ) -> float:
        """Record event and return anomaly score 0.0–1.0."""
        now = time.time()
        event = {"ts": now, "result": result, "sensitivity": sensitivity}

        with self._lock:
            self._ip_window[ip].append(event)
            features = _build_features(list(self._ip_window[ip]), sensitivity, now)
            self._train_buf.append(features)
            self._events_since_retrain += 1
            score = self._score_features(features)
            if self._events_since_retrain >= RETRAIN_EVERY:
                self._events_since_retrain = 0
                Thread(target=self._retrain, daemon=True).start()

        entry = {
            "ip": ip,
            "user_id": user_id,
            "path": path,
            "sensitivity": sensitivity,
            "result": result,
            "score": round(score, 4),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with self._lock:
            self._history.append(entry)
            self._latest_scores[ip] = {
                "ip": ip,
                "user_id": user_id,
                "score": round(score, 4),
                "updated_at": entry["timestamp"],
            }

        # Persist to DB in a background thread (non-blocking)
        self._persist_async(ip, user_id, path, score, sensitivity, result)
        return score

    def retrain(self) -> dict:
        n = self._retrain()
        return {"status": "ok", "trained_on": n}

    def get_scores(self) -> list[dict]:
        with self._lock:
            return sorted(self._latest_scores.values(), key=lambda x: x["score"], reverse=True)

    def get_timeline(self, limit: int = 100) -> list[dict]:
        with self._lock:
            return list(reversed(list(self._history)))[:limit]

    async def load_history(self, db_session) -> None:
        """
        Called at startup. Loads the last 500 anomaly events from the DB
        into the in-memory history deque so the timeline survives restarts.
        """
        try:
            from sqlalchemy import select, desc
            from models import AnomalyEvent
            result = await db_session.execute(
                select(AnomalyEvent).order_by(desc(AnomalyEvent.timestamp)).limit(500)
            )
            rows = result.scalars().all()
            with self._lock:
                for row in reversed(rows):
                    entry = {
                        "ip": row.ip,
                        "user_id": row.user_id,
                        "path": row.path,
                        "sensitivity": row.sensitivity,
                        "result": row.result,
                        "score": row.score,
                        "timestamp": row.timestamp.isoformat() if row.timestamp else "",
                    }
                    self._history.append(entry)
                    prev = self._latest_scores.get(row.ip)
                    if not prev or row.score >= prev["score"]:
                        self._latest_scores[row.ip] = {
                            "ip": row.ip,
                            "user_id": row.user_id,
                            "score": row.score,
                            "updated_at": entry["timestamp"],
                        }
        except Exception as exc:
            print(f"[anomaly] Could not load history from DB: {exc}")

    # ── Internal ──────────────────────────────────────────────────────────────

    def _score_features(self, features: list[float]) -> float:
        if self._model is not None:
            X = np.array([features])
            raw = float(self._model.decision_function(X)[0])
            return round(1.0 - min(max((raw + 0.5), 0.0), 1.0), 4)
        req_rate, deny_rate, sens_rank, _, _ = features
        return round(min(deny_rate * 0.6 + sens_rank * 0.3 + min(req_rate, 5) / 5 * 0.1, 1.0), 4)

    def _retrain(self) -> int:
        with self._lock:
            buf = list(self._train_buf)
        if len(buf) < MIN_SAMPLES:
            return len(buf)
        model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42, n_jobs=-1)
        model.fit(np.array(buf))
        with self._lock:
            self._model = model
            self._trained_on = len(buf)
        return len(buf)

    def _persist_async(self, ip: str, user_id: Optional[str], path: str,
                       score: float, sensitivity: str, result: str) -> None:
        def _write():
            import asyncio
            try:
                asyncio.run(_async_write(ip, user_id, path, score, sensitivity, result))
            except Exception:
                pass
        Thread(target=_write, daemon=True).start()


# ── DB write helper (runs in a new event loop on a background thread) ─────────

async def _async_write(ip: str, user_id: Optional[str], path: str,
                       score: float, sensitivity: str, result: str) -> None:
    from database import AsyncSessionLocal
    from models import AnomalyEvent
    async with AsyncSessionLocal() as session:
        session.add(AnomalyEvent(
            ip=ip, user_id=user_id, path=path,
            score=score, sensitivity=sensitivity, result=result,
        ))
        await session.commit()


# Module-level singleton
anomaly_engine = AnomalyEngine()
