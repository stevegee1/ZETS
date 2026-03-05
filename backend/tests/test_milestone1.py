import pytest, pytest_asyncio
from httpx import AsyncClient, ASGITransport
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_zets.db"
os.environ["JWT_SECRET"] = "test-secret"

from main import app
from database import init_db, engine
from models import Base

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

# ── helpers ──────────────────────────────────────────────────

async def register_and_setup(client, email, password, role):
    """Register user and return (user_data, access_token)."""
    r = await client.post("/auth/register", json={"email": email, "password": password, "role": role})
    assert r.status_code == 201
    user = r.json()

    # Login step 1
    r2 = await client.post("/auth/login", json={"email": email, "password": password})
    assert r2.status_code == 200
    temp_token = r2.json()["temp_token"]

    # Get TOTP secret from setup endpoint (needs temp_token treated as access for setup)
    # For tests we use pyotp directly via the temp token payload
    import pyotp
    from auth.utils import decode_token
    payload = decode_token(temp_token)
    # Fetch user secret directly via setup-2fa using temp token as Bearer
    r3 = await client.get("/auth/setup-2fa", headers={"Authorization": f"Bearer {temp_token}"})
    uri = r3.json()["provisioning_uri"]
    secret = uri.split("secret=")[1].split("&")[0]
    code = pyotp.TOTP(secret).now()

    # Verify 2FA
    r4 = await client.post("/auth/verify-2fa", json={"temp_token": temp_token, "totp_code": code})
    assert r4.status_code == 200, r4.json()
    access_token = r4.json()["access_token"]

    return user, access_token

# ── tests ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_register(client):
    r = await client.post("/auth/register", json={
        "email": "student@test.com", "password": "pass123", "role": "student"
    })
    assert r.status_code == 201
    assert r.json()["role"] == "student"

@pytest.mark.asyncio
async def test_duplicate_register(client):
    await client.post("/auth/register", json={"email": "dup@test.com", "password": "pass", "role": "student"})
    r = await client.post("/auth/register", json={"email": "dup@test.com", "password": "pass", "role": "student"})
    assert r.status_code == 400

@pytest.mark.asyncio
async def test_login_bad_password(client):
    await client.post("/auth/register", json={"email": "u@test.com", "password": "correct", "role": "student"})
    r = await client.post("/auth/login", json={"email": "u@test.com", "password": "wrong"})
    assert r.status_code == 401

@pytest.mark.asyncio
async def test_full_2fa_flow(client):
    """Register → login → setup 2FA → verify → receive access token."""
    _, token = await register_and_setup(client, "teacher@test.com", "pass123", "teacher")
    assert token

@pytest.mark.asyncio
async def test_rbac_student_cannot_upload(client):
    _, student_token = await register_and_setup(client, "student@test.com", "pass", "student")
    import io
    r = await client.post(
        "/files/upload",
        files={"file": ("test.txt", io.BytesIO(b"hello world"), "text/plain")},
        headers={"Authorization": f"Bearer {student_token}"},
    )
    assert r.status_code == 403

@pytest.mark.asyncio
async def test_rbac_teacher_can_upload(client):
    _, teacher_token = await register_and_setup(client, "teacher@test.com", "pass", "teacher")
    import io
    r = await client.post(
        "/files/upload",
        files={"file": ("lesson.pdf", io.BytesIO(b"lesson content"), "application/pdf")},
        headers={"Authorization": f"Bearer {teacher_token}"},
    )
    assert r.status_code == 201
    data = r.json()
    assert data["filename"] == "lesson.pdf"
    assert len(data["sha256_hash"]) == 64

@pytest.mark.asyncio
async def test_audit_log_on_deny(client):
    _, student_token = await register_and_setup(client, "student@test.com", "pass", "student")
    _, teacher_token = await register_and_setup(client, "teacher@test.com", "pass", "teacher")

    import io
    await client.post(
        "/files/upload",
        files={"file": ("doc.txt", io.BytesIO(b"secret"), "text/plain")},
        headers={"Authorization": f"Bearer {teacher_token}"},
    )

    # Student tries to upload — should be denied
    await client.post(
        "/files/upload",
        files={"file": ("hack.txt", io.BytesIO(b"hax"), "text/plain")},
        headers={"Authorization": f"Bearer {student_token}"},
    )

    # Teacher can see audit logs
    r = await client.get("/admin/audit-logs", headers={"Authorization": f"Bearer {teacher_token}"})
    assert r.status_code == 200
    logs = r.json()
    denied = [l for l in logs if l["result"] == "denied"]
    assert len(denied) >= 1
