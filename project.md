# ZETS — Zero-Trust Educational Storage Platform

**Module**: Advanced Secure Systems
**Date**: February 2026
**Stack**: FastAPI · SQLite · Next.js 14 · scikit-learn

---

## 1. Project Overview

ZETS is a proof-of-concept secure file storage and access management platform built on **Zero Trust Architecture (ZTA)** principles. It demonstrates how a university environment can enforce fine-grained access control, continuous verification, and behavioural anomaly detection across a web application — with no implicit trust granted to any user, device, or network location.

The system is composed of a **Python/FastAPI backend** and a **Next.js frontend**, structured across three progressive milestones.

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Browser (Next.js 14)                                           │
│  /login  /register  /dashboard  /admin  /admin/alerts           │
│  /admin/anomalies                                               │
└───────────────────┬─────────────────────────────────────────────┘
                    │ HTTPS (JWT Bearer)
┌───────────────────▼─────────────────────────────────────────────┐
│  FastAPI Backend                                                │
│                                                                 │
│   ┌──────────┐  ┌─────────────────────────────────────────┐    │
│   │  CORS    │  │  PEP Middleware (every request)         │    │
│   │Middleware│  │  ├─ decode JWT → identity               │    │
│   └──────────┘  │  ├─ call PDP → decision                 │    │
│                 │  ├─ call Anomaly Engine → score          │    │
│                 │  └─ ALLOW / DENY + log to audit_logs    │    │
│                 └──────────────┬──────────────────────────┘    │
│                                │                                │
│        ┌───────────────────────┼──────────────────────────┐    │
│        │                       │                          │    │
│   ┌────▼─────┐  ┌──────────────▼──────┐  ┌───────────────▼┐   │
│   │  Auth    │  │  Files              │  │  Admin         │   │
│   │  Router  │  │  Router             │  │  Router        │   │
│   │ /auth/*  │  │ /files/*            │  │ /admin/*       │   │
│   └──────────┘  └─────────────────────┘  └────────────────┘   │
│                                                                 │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │  SQLite Database (zets.db)                              │  │
│   │  tables: users · files · audit_logs · anomaly_events   │  │
│   └─────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Milestones

### Milestone 1 — Authentication & RBAC

| Feature | Detail |
|---------|--------|
| User registration | Email + password (bcrypt), roles: `student`, `teacher`, `admin` |
| Two-factor authentication | TOTP via Google Authenticator/Authy (`pyotp`). Enforced on every login |
| JWT tokens | Short-lived **temp token** (pre-2FA) and full **access token** (post-2FA) |
| Role-Based Access Control | Three tiers: `student < teacher < admin` |
| File upload | Teachers/admin only; SHA-256 hash computed and stored at upload time |
| File download | Any authenticated user; integrity verified on download |
| Audit logging | Every access decision written to `audit_logs` table |

### Milestone 2 — Zero Trust Enforcement (PEP/PDP)

| Feature | Detail |
|---------|--------|
| Policy Decision Point (PDP) | `pdp/engine.py` — evaluates `(identity, path, method)` against a policy registry |
| Policy Enforcement Point (PEP) | ASGI middleware (`pep/middleware.py`) wrapping every request before routing |
| Sensitivity classification | Endpoints classified `LOW / MEDIUM / HIGH / CRITICAL` |
| Micro-segmentation zones | Requests tagged by zone (`auth`, `upload`, `access`, `admin`) |
| File integrity verification | `GET /files/{id}/verify` re-computes SHA-256 and compares to stored hash |
| Security alerts | In-memory alert store: `BRUTE_FORCE`, `INTEGRITY_VIOLATION`, `PRIVILEGE_ESCALATION` |
| Admin UI | Audit log viewer with filters; Security Alerts page (auto-refreshes every 10 s) |

### Milestone 3 — AI Anomaly Detection Engine

| Feature | Detail |
|---------|--------|
| Anomaly engine | `anomaly/engine.py` — scikit-learn `IsolationForest` on a per-IP rolling feature window |
| Feature vector | `[request_rate_1min, denial_rate_1min, sensitivity_rank, hour_sin, hour_cos]` |
| Fallback scoring | Rule-based heuristic until ≥ 30 samples are collected |
| PDP integration | Score computed after role check; score ≥ 0.85 → hard `DENY`; score ≥ 0.75 → alert |
| Alert type | `ANOMALY_DETECTED` added to the alert store and surfaced in the Alerts UI |
| Auto-retraining | Model refits in a background thread every 50 new events |
| Admin endpoints | `GET /admin/anomalies` · `GET /admin/anomalies/timeline` · `POST /admin/anomalies/retrain` |
| Anomaly dashboard | `/admin/anomalies` — live table of IP scores and scored event history |

---

## 4. Security Design Decisions

### Zero Trust Principles Applied
- **Verify explicitly**: Every request carries a JWT and is re-verified by the PEP on every call — no session state is trusted.
- **Least-privilege access**: Endpoints are classified by sensitivity and the PDP enforces minimum required role.
- **Assume breach**: The anomaly engine continuously scores behaviour; high scores trigger denial even for otherwise-valid tokens.

### Two-Factor Authentication
All logins require a TOTP code (RFC 6238). The login flow uses a short-lived `temp` JWT that can only reach `/auth/setup-2fa` and `/auth/verify-2fa` — it is rejected by the PDP for all other endpoints.

### File Integrity
SHA-256 hashes are computed at upload and stored in the database. Downloads are verified server-side; a mismatch fires an `INTEGRITY_VIOLATION` alert.

### Audit Trail
Every PEP decision (ALLOW or DENY) is written to `audit_logs` with: `user_id`, `action`, `resource`, `result`, `sensitivity`, `zone`, `ip_address`, `timestamp`. Admins and teachers can query this log with filters.

---

## 5. API Reference (Key Endpoints)

| Method | Path | Role | Description |
|--------|------|------|-------------|
| POST | `/auth/register` | Public | Create account |
| POST | `/auth/login` | Public | Credentials → temp token |
| GET | `/auth/setup-2fa` | Temp token | Generate TOTP QR code |
| POST | `/auth/verify-2fa` | Temp token | Verify TOTP → access token |
| POST | `/files/upload` | Teacher+ | Upload file (hash stored) |
| GET | `/files/` | Student+ | List accessible files |
| GET | `/files/{id}/download` | Student+ | Download + verify integrity |
| GET | `/admin/audit-logs` | Teacher+ | Query audit log |
| GET | `/admin/alerts` | Teacher+ | Security alerts |
| GET | `/admin/anomalies` | Admin | Current anomaly scores |
| GET | `/admin/anomalies/timeline` | Admin | Scored event history |
| POST | `/admin/anomalies/retrain` | Admin | Retrain IsolationForest |

---

## 6. Technology Stack

| Layer | Technology |
|-------|-----------|
| Backend framework | FastAPI 0.111 |
| Database ORM | SQLAlchemy 2.0 (async) |
| Database | SQLite (development); PostgreSQL-ready via `asyncpg` |
| Authentication | `python-jose` (JWT), `passlib` (bcrypt), `pyotp` (TOTP) |
| Anomaly detection | scikit-learn 1.8 (`IsolationForest`), numpy 2.4 |
| Frontend framework | Next.js 14 (App Router) |
| HTTP client | axios |
| Testing | pytest, pytest-asyncio, httpx |

---

## 7. Running the Project

### Backend
```bash
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
# API available at http://localhost:8000
```

### Frontend
```bash
cd frontend
npm install
npm run dev
# UI available at http://localhost:3000
```

### Tests
```bash
cd backend && source venv/bin/activate
pytest tests/test_milestone1.py -v   # Auth, RBAC, files
pytest tests/test_milestone2.py -v   # PEP/PDP, integrity, audit
pytest tests/test_milestone3.py -v   # Anomaly engine, API, PDP integration
```

---

## 8. Known Limitations (Pre-Production)

- SQLite is unsuitable for concurrent production writes — replace with PostgreSQL
- Anomaly scores and alerts are in-memory — lost on server restart
- Admin role is self-selectable at registration — production should use invitation tokens
- File storage is local disk — should migrate to object storage (S3/GCS)
- No HTTPS — requires TLS termination via reverse proxy (nginx/Caddy) before deployment
