# MedFlow EMR — Telehealth Extension Integration Guide

## What Was Added

The `telehealth.py` module extends MedFlow EMR with:

1. **Video Visits (Daily.co)** — Provider creates a HIPAA-compliant Daily.co room per appointment; patient receives a time-limited join link via their portal
2. **Patient Self-Scheduling** — Public API endpoints for the website to offer patient-facing scheduling without EMR login
3. **Patient Intake Forms** — Public intake form endpoint creates a pending patient record with HIPAA/telehealth consent capture
4. **503A Compounding Orders** — Extended prescription model with clinical necessity documentation (required for AKS/FDA compliance)
5. **MSO State Licensing Check** — Calls the MSO Dashboard API to verify provider has active license in patient's state before visit begins

## Integration Steps

### Step 1 — Add `is_compounded` columns to the database

```bash
# In your Railway PostgreSQL console or via psql:
ALTER TABLE prescriptions ADD COLUMN IF NOT EXISTS is_compounded BOOLEAN DEFAULT FALSE;
ALTER TABLE prescriptions ADD COLUMN IF NOT EXISTS compounding_clinic_necessity TEXT DEFAULT '';
ALTER TABLE prescriptions ADD COLUMN IF NOT EXISTS compounding_reason_allergy BOOLEAN DEFAULT FALSE;
ALTER TABLE prescriptions ADD COLUMN IF NOT EXISTS compounding_reason_unavailable BOOLEAN DEFAULT FALSE;
ALTER TABLE prescriptions ADD COLUMN IF NOT EXISTS compounding_reason_dose BOOLEAN DEFAULT FALSE;
```

### Step 2 — Add environment variables

Copy the variables from `.env.telehealth.example` into your Railway environment settings:
- `DAILY_API_KEY` (obtain from Daily.co dashboard)
- `DAILY_DOMAIN` (your Daily.co subdomain)
- `MSO_DASHBOARD_URL` (Railway URL of your MSO backend)
- `MSO_DASHBOARD_API_KEY`
- `WEBSITE_ORIGIN` (your website URL for CORS)

### Step 3 — Register the telehealth router in main.py

Add the following lines to `main.py` near the bottom, after the existing route registrations:

```python
# Telehealth extension (add after existing routes)
from telehealth import router as telehealth_router
app.include_router(telehealth_router, prefix="/telehealth", tags=["telehealth"])

# Allow website origin for public endpoints
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("WEBSITE_ORIGIN", "")],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)
```

### Step 4 — Install additional dependency

```bash
pip install httpx --break-system-packages
```
(httpx is already in requirements.txt in the existing MedFlow — verify it's present)

### Step 5 — Set up Daily.co BAA

Before going live with any patient visits:
1. Log in to your Daily.co account
2. Go to Settings → Privacy & Compliance
3. Enable HIPAA mode and execute the Business Associate Agreement
4. This is a non-negotiable HIPAA requirement

## New API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /telehealth/visit/create-room | Provider JWT | Create Daily.co room for appointment |
| GET | /telehealth/visit/{id}/patient-link | Provider JWT | Get patient join link |
| GET | /telehealth/visit/{id}/portal-join | Patient portal JWT | Patient join URL |
| GET | /telehealth/public/providers | None | List active providers (for website) |
| GET | /telehealth/public/availability | None | Get available slots for a provider |
| POST | /telehealth/public/self-schedule | None | Patient self-book appointment |
| POST | /telehealth/public/intake | None | Submit patient intake form |
| POST | /telehealth/compounding/order | Provider JWT | Create 503A compounding prescription |
| GET | /telehealth/compliance/provider-state-check | Provider JWT | Verify provider state license |

## HIPAA Notes

- Daily.co room names are random UUIDs — never contain patient-identifying information
- Patient tokens expire after 2 hours; provider tokens after 12 hours
- All telehealth events are logged to the `hipaa_audit_log` table
- The 503A compounding order endpoint enforces clinical necessity documentation
- Patient intake consent (HIPAA + telehealth) is captured with timestamp and IP address
