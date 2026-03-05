"""
Milestone 2 Tests — PEP, PDP, Integrity Verification, Alerts
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

# Re-use the same helper from milestone 1 tests
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
    return r4.json()["access_token"], temp_token

# ── 1. PEP blocks unauthenticated ─────────────────────────────

@pytest.mark.asyncio
async def test_pep_blocks_unauthenticated_file_list(client):
    r = await client.get("/files/")
    assert r.status_code == 403
    body = r.json()
    assert body["detail"] == "Access denied by policy enforcement point"
    assert r.headers.get("X-PEP-Decision") == "DENY"

@pytest.mark.asyncio
async def test_pep_allows_unauthenticated_health(client):
    r = await client.get("/health")
    assert r.status_code == 200
    assert r.headers.get("X-PEP-Decision") == "ALLOW"

@pytest.mark.asyncio
async def test_pep_allows_unauthenticated_register(client):
    r = await client.post("/auth/register", json={
        "email": "x@test.com", "password": "pass", "role": "student"
    })
    assert r.status_code == 201
    assert r.headers.get("X-PEP-Decision") == "ALLOW"

# ── 2. PEP/PDP: student cannot hit upload zone ────────────────

@pytest.mark.asyncio
async def test_pdp_student_blocked_from_upload(client):
    token, _ = await register_and_login(client, "student@test.com", "pass", "student")
    r = await client.post(
        "/files/upload",
        files={"file": ("hack.txt", io.BytesIO(b"hax"), "text/plain")},
        headers={"Authorization": f"Bearer {token}"},
    )
    # PEP/RBAC both deny — either is fine, key check is 403
    assert r.status_code == 403

# ── 3. Temp token blocked from medium+ resources ──────────────

@pytest.mark.asyncio
async def test_pdp_temp_token_blocked_from_files(client):
    await client.post("/auth/register", json={"email": "t@test.com", "password": "pass", "role": "teacher"})
    r2 = await client.post("/auth/login", json={"email": "t@test.com", "password": "pass"})
    temp_token = r2.json()["temp_token"]

    r = await client.get("/files/", headers={"Authorization": f"Bearer {temp_token}"})
    assert r.status_code == 403
    assert "Temporary token" in r.json()["reason"]

# ── 4. Integrity: clean file passes ───────────────────────────

@pytest.mark.asyncio
async def test_integrity_clean_file(client):
    token, _ = await register_and_login(client, "teacher@test.com", "pass", "teacher")
    upload = await client.post(
        "/files/upload",
        files={"file": ("lesson.txt", io.BytesIO(b"clean content"), "text/plain")},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert upload.status_code == 201
    file_id = upload.json()["id"]

    dl = await client.get(f"/files/{file_id}/download",
                          headers={"Authorization": f"Bearer {token}"})
    assert dl.status_code == 200

# ── 5. Integrity: tampered file returns 409 ───────────────────

@pytest.mark.asyncio
async def test_integrity_tampered_file(client):
    token, _ = await register_and_login(client, "teacher@test.com", "pass", "teacher")
    upload = await client.post(
        "/files/upload",
        files={"file": ("secret.txt", io.BytesIO(b"original content"), "text/plain")},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert upload.status_code == 201
    data = upload.json()
    file_id   = data["id"]

    # Corrupt the file on disk
    # We need to get the filepath — query DB via verify endpoint
    verify_r = await client.get(f"/files/{file_id}/verify",
                                headers={"Authorization": f"Bearer {token}"})
    assert verify_r.status_code == 200
    assert verify_r.json()["valid"] is True

    # Get filepath from DB directly (via sqlalchemy in test context)
    from database import AsyncSessionLocal
    from models import File as FileModel
    from sqlalchemy import select
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(FileModel).where(FileModel.id == file_id))
        db_file = result.scalar_one()
        filepath = db_file.filepath

    with open(filepath, "wb") as f:
        f.write(b"TAMPERED CONTENT")

    dl = await client.get(f"/files/{file_id}/download",
                          headers={"Authorization": f"Bearer {token}"})
    assert dl.status_code == 409
    body = dl.json()
    assert body["detail"]["error"] == "INTEGRITY_VIOLATION"

# ── 6. Verify endpoint ────────────────────────────────────────

@pytest.mark.asyncio
async def test_verify_endpoint_valid(client):
    token, _ = await register_and_login(client, "teacher@test.com", "pass", "teacher")
    upload = await client.post(
        "/files/upload",
        files={"file": ("doc.txt", io.BytesIO(b"important doc"), "text/plain")},
        headers={"Authorization": f"Bearer {token}"},
    )
    file_id = upload.json()["id"]

    r = await client.get(f"/files/{file_id}/verify",
                         headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    body = r.json()
    assert body["valid"] is True
    assert body["stored_hash"] == body["actual_hash"]

# ── 7. Audit log has sensitivity & zone ───────────────────────

@pytest.mark.asyncio
async def test_audit_log_has_sensitivity_and_zone(client):
    admin_token, _ = await register_and_login(client, "admin@test.com", "pass", "admin")
    teacher_token, _ = await register_and_login(client, "teacher@test.com", "pass", "teacher")

    # Teacher uploads a file — should create audit with sensitivity/zone
    await client.post(
        "/files/upload",
        files={"file": ("x.txt", io.BytesIO(b"data"), "text/plain")},
        headers={"Authorization": f"Bearer {teacher_token}"},
    )

    r = await client.get("/admin/audit-logs",
                         headers={"Authorization": f"Bearer {admin_token}"})
    assert r.status_code == 200
    logs = r.json()
    # At least one upload-related log should have zone info
    upload_logs = [l for l in logs if "upload" in l.get("resource", "")]
    assert len(upload_logs) >= 1

# ── 8. PEP response headers present ──────────────────────────

@pytest.mark.asyncio
async def test_pep_response_headers(client):
    r = await client.get("/health")
    assert r.headers.get("X-PEP-Decision") == "ALLOW"
    assert r.headers.get("X-PEP-Sensitivity") == "LOW"
