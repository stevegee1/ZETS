"""
Milestone 3 Tests — AI Anomaly Detection Engine
"""
import pytest, pytest_asyncio, io, os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_zets.db"
os.environ["JWT_SECRET"]   = "test-secret"

from httpx import AsyncClient, ASGITransport
from main import app
from database import engine, AsyncSessionLocal
from models import Base

# ── Fixtures ──────────────────────────────────────────────────

@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c

async def register_and_login(client, email, password, role):
    import pyotp
    reg_body = {"email": email, "password": password, "role": role}
    if role == "admin":
        import uuid
        from models import InvitationToken
        token_val = str(uuid.uuid4())
        async with AsyncSessionLocal() as s:
            s.add(InvitationToken(token=token_val, created_by="00000000-0000-0000-0000-000000000000"))
            await s.commit()
        reg_body["invite_token"] = token_val
    r = await client.post("/auth/register", json=reg_body)
    assert r.status_code == 201, r.json()
    r2 = await client.post("/auth/login", json={"email": email, "password": password})
    temp_token = r2.json()["temp_token"]
    r3 = await client.get("/auth/setup-2fa", headers={"Authorization": f"Bearer {temp_token}"})
    uri = r3.json()["provisioning_uri"]
    secret = uri.split("secret=")[1].split("&")[0]
    code = pyotp.TOTP(secret).now()
    r4 = await client.post("/auth/verify-2fa", json={"temp_token": temp_token, "totp_code": code})
    assert r4.status_code == 200, r4.json()
    return r4.json()["access_token"]


# ── 1. Engine unit tests ───────────────────────────────────────

def test_anomaly_engine_returns_float_in_range():
    """Score should always be 0.0–1.0."""
    from anomaly.engine import AnomalyEngine
    eng = AnomalyEngine()
    score = eng.score_request(
        ip="1.2.3.4", user_id=None,
        path="/files/", result="allowed", sensitivity="HIGH",
    )
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0


def test_anomaly_engine_high_denial_raises_score():
    """Many denials on a sensitive resource should push score up."""
    from anomaly.engine import AnomalyEngine
    eng = AnomalyEngine()
    # Simulate 20 denied CRITICAL requests
    for _ in range(20):
        score = eng.score_request(
            ip="5.5.5.5", user_id=None,
            path="/admin/anything", result="denied", sensitivity="CRITICAL",
        )
    # Rule-based: denial_rate=1.0, sens_rank=1.0 → score is high
    assert score > 0.5


def test_anomaly_engine_retrain():
    """Retrain should work even if model is not yet fitted."""
    from anomaly.engine import AnomalyEngine
    eng = AnomalyEngine()
    result = eng.retrain()
    assert "status" in result
    # Fewer than MIN_SAMPLES — retrain returns sample count
    assert result["trained_on"] >= 0


def test_anomaly_engine_retrain_with_samples():
    """Full retrain with MIN_SAMPLES events should succeed."""
    from anomaly.engine import AnomalyEngine, MIN_SAMPLES
    eng = AnomalyEngine()
    for i in range(MIN_SAMPLES + 5):
        eng.score_request(ip=f"10.0.0.{i % 255}", user_id=None,
                          path="/files/", result="allowed", sensitivity="LOW")
    result = eng.retrain()
    assert result["trained_on"] >= MIN_SAMPLES


def test_anomaly_engine_get_scores():
    from anomaly.engine import AnomalyEngine
    eng = AnomalyEngine()
    eng.score_request(ip="7.7.7.7", user_id="u1", path="/files/", result="allowed", sensitivity="LOW")
    scores = eng.get_scores()
    assert any(s["ip"] == "7.7.7.7" for s in scores)


def test_anomaly_engine_timeline():
    from anomaly.engine import AnomalyEngine
    eng = AnomalyEngine()
    eng.score_request(ip="8.8.8.8", user_id=None, path="/admin/", result="denied", sensitivity="HIGH")
    timeline = eng.get_timeline()
    assert len(timeline) >= 1
    assert "score" in timeline[0]


# ── 2. PDP anomaly integration ─────────────────────────────────

def test_pdp_decide_returns_anomaly_score():
    from pdp.engine import decide
    identity = {"user_id": "u1", "role": "teacher", "token_type": "access"}
    result = decide(identity, "/files/", "GET", ip="9.9.9.9")
    assert "anomaly_score" in result
    assert isinstance(result["anomaly_score"], float)


# ── 3. API endpoints ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_anomaly_scores_admin_only(client):
    admin_token = await register_and_login(client, "admin@test.com", "pass", "admin")
    student_token = await register_and_login(client, "stu@test.com", "pass", "student")

    r_admin = await client.get("/admin/anomalies", headers={"Authorization": f"Bearer {admin_token}"})
    assert r_admin.status_code == 200
    assert isinstance(r_admin.json(), list)

    r_stu = await client.get("/admin/anomalies", headers={"Authorization": f"Bearer {student_token}"})
    assert r_stu.status_code == 403


@pytest.mark.asyncio
async def test_anomaly_timeline_endpoint(client):
    admin_token = await register_and_login(client, "admin@test.com", "pass", "admin")
    r = await client.get("/admin/anomalies/timeline?limit=10",
                         headers={"Authorization": f"Bearer {admin_token}"})
    assert r.status_code == 200
    assert isinstance(r.json(), list)


@pytest.mark.asyncio
async def test_anomaly_retrain_endpoint(client):
    admin_token = await register_and_login(client, "admin@test.com", "pass", "admin")
    r = await client.post("/admin/anomalies/retrain",
                          headers={"Authorization": f"Bearer {admin_token}"})
    assert r.status_code == 200
    body = r.json()
    assert "status" in body


@pytest.mark.asyncio
async def test_anomaly_scores_appear_after_requests(client):
    """Making requests should populate the anomaly scores endpoint."""
    admin_token = await register_and_login(client, "admin@test.com", "pass", "admin")
    teacher_token = await register_and_login(client, "teacher@test.com", "pass", "teacher")

    # Make several file list requests
    for _ in range(3):
        await client.get("/files/", headers={"Authorization": f"Bearer {teacher_token}"})

    r = await client.get("/admin/anomalies", headers={"Authorization": f"Bearer {admin_token}"})
    assert r.status_code == 200
    # Scores should have populated
    scores = r.json()
    assert len(scores) >= 1
