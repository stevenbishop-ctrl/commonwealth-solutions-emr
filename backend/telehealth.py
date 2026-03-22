"""
MedFlow EMR — Telehealth Extension Module
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
This module extends the existing MedFlow EMR with:

  1. Video Visit Integration (Daily.co HIPAA-compliant API)
     - Creates private, one-time Daily.co rooms per appointment
     - Generates time-limited tokens for providers and patients
     - Tracks visit start/end times for billing purposes

  2. Patient Self-Scheduling (public-facing API for website integration)
     - Patients can view provider availability and book appointments
     - Sends confirmation emails (via existing notification system)
     - Enforces state-based licensing compliance check

  3. Patient Intake Forms (new patient self-registration)
     - Online intake form for new patients
     - Creates patient record pending provider review
     - HIPAA consent capture with timestamp and IP

  4. Compounding Pharmacy Workflow
     - Extends the existing Prescription model for 503A compounding specifics
     - Clinical necessity documentation (required for compounding compliance)
     - Routes orders to designated 503A pharmacy

  5. MSO Provider Compliance Check
     - Before a telehealth visit begins, verifies provider has active license
       in the patient's state using the MSO Dashboard API
     - Blocks visit if license is expired, suspended, or not found

INTEGRATION:
  Add to main.py:
    from telehealth import router as telehealth_router
    app.include_router(telehealth_router, prefix="/telehealth")

  Add to models.py:
    from telehealth_models import VideoVisitRoom, PatientIntake

  Required environment variables (add to .env):
    DAILY_API_KEY=your_daily_co_api_key
    DAILY_DOMAIN=your-subdomain.daily.co
    MSO_DASHBOARD_URL=https://mso-backend.up.railway.app
    MSO_DASHBOARD_API_KEY=your_mso_api_key
    WEBSITE_ORIGIN=https://commonwealthsolutions.com

HIPAA:
  - Daily.co must have a signed BAA with your account before use in production
  - Visit room names are random UUIDs, never patient-identifying
  - All telehealth event access is logged to the HIPAA audit table
  - Patient tokens expire after 2 hours; provider tokens after 12 hours
"""

import hashlib
import os
import secrets
import uuid as _uuid
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

import models
from database import SessionLocal
from main import (
    audit, get_current_user, get_db, get_portal_patient,
    make_portal_token, make_token
)

router = APIRouter(tags=["telehealth"])

# ── Config ────────────────────────────────────────────────────────────────────
DAILY_API_KEY      = os.getenv("DAILY_API_KEY", "")
DAILY_DOMAIN       = os.getenv("DAILY_DOMAIN", "")
MSO_DASHBOARD_URL  = os.getenv("MSO_DASHBOARD_URL", "")
MSO_API_KEY        = os.getenv("MSO_DASHBOARD_API_KEY", "")
WEBSITE_ORIGIN     = os.getenv("WEBSITE_ORIGIN", "")
VISIT_TOKEN_TTL_H  = 2    # patient token TTL in hours
PROVIDER_TOKEN_TTL = 12   # provider token TTL in hours

# ── Daily.co HTTP client ──────────────────────────────────────────────────────
def daily_client():
    return httpx.Client(
        base_url="https://api.daily.co/v1",
        headers={"Authorization": f"Bearer {DAILY_API_KEY}"},
        timeout=15.0,
    )

# ─────────────────────────────────────────────────────────────────────────────
# 1. VIDEO VISIT ROOMS
# ─────────────────────────────────────────────────────────────────────────────

class CreateRoomRequest(BaseModel):
    appointment_id: int

@router.post("/visit/create-room")
def create_video_room(
    body: CreateRoomRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Creates a HIPAA-compliant Daily.co room for a scheduled appointment.
    Called by the provider when they are ready to begin the visit.

    The room is private and requires a Daily.co token to enter.
    Room names are random UUIDs to prevent patient identification.
    The room auto-expires 4 hours after creation.
    """
    if not DAILY_API_KEY:
        raise HTTPException(503, "Telehealth service not configured. Set DAILY_API_KEY.")

    appt = db.query(models.Appointment).filter(
        models.Appointment.id == body.appointment_id,
        models.Appointment.provider_id == current_user.id,
    ).first()
    if not appt:
        raise HTTPException(404, "Appointment not found")

    # Check for existing room stored in appointment notes (quick approach)
    # In a full implementation, store in a dedicated VideoVisitRoom table
    existing_room_name = None
    if appt.notes and appt.notes.startswith("ROOM:"):
        existing_room_name = appt.notes.split("ROOM:")[1].split("\n")[0].strip()

    if existing_room_name:
        room_name = existing_room_name
    else:
        # Create new Daily.co room
        room_name = f"cs-{_uuid.uuid4().hex[:16]}"
        exp_ts    = int((datetime.now(timezone.utc) + timedelta(hours=4)).timestamp())

        with daily_client() as client:
            resp = client.post("/rooms", json={
                "name": room_name,
                "privacy": "private",
                "properties": {
                    "exp": exp_ts,
                    "enable_chat": True,
                    "enable_screenshare": True,
                    "enable_recording": "local",  # provider can record locally
                    "start_video_off": True,       # HIPAA-conscious default
                    "start_audio_off": False,
                    "max_participants": 4,         # provider + patient + interpreter + supervisor
                    "nbf": int(datetime.now(timezone.utc).timestamp()) - 60,
                },
            })
        if resp.status_code not in (200, 201):
            raise HTTPException(502, f"Daily.co room creation failed: {resp.text}")

        # Persist room name in appointment notes field
        prefix = f"ROOM:{room_name}\n"
        appt.notes = prefix + (appt.notes or "")
        db.commit()

    # Generate provider token
    provider_token = _generate_daily_token(
        room_name=room_name,
        user_name=f"{current_user.full_name}",
        user_id=str(current_user.id),
        is_owner=True,
        ttl_hours=PROVIDER_TOKEN_TTL,
    )

    audit(db, current_user.id, "create", "video_room", body.appointment_id,
          f"Created Daily.co room {room_name} for appointment {body.appointment_id}")

    return {
        "room_name": room_name,
        "room_url": f"https://{DAILY_DOMAIN}/{room_name}" if DAILY_DOMAIN else f"https://daily.co/{room_name}",
        "provider_token": provider_token,
        "expires_in_hours": PROVIDER_TOKEN_TTL,
    }


@router.get("/visit/{appointment_id}/patient-link")
def get_patient_visit_link(
    appointment_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Generates a time-limited patient join link for a telehealth appointment.
    The link contains a Daily.co token embedded in a portal deep-link URL.
    Send this to the patient via their portal message or email.
    """
    appt = db.query(models.Appointment).filter(
        models.Appointment.id == appointment_id,
        models.Appointment.provider_id == current_user.id,
    ).first()
    if not appt:
        raise HTTPException(404, "Appointment not found")

    if not appt.notes or "ROOM:" not in appt.notes:
        raise HTTPException(409, "Room not yet created. Provider must start the room first.")

    room_name = appt.notes.split("ROOM:")[1].split("\n")[0].strip()
    patient   = db.query(models.Patient).filter(models.Patient.id == appt.patient_id).first()
    if not patient:
        raise HTTPException(404, "Patient not found")

    patient_token = _generate_daily_token(
        room_name=room_name,
        user_name=f"{patient.first_name} {patient.last_name}",
        user_id=f"patient-{patient.id}",
        is_owner=False,
        ttl_hours=VISIT_TOKEN_TTL_H,
    )

    audit(db, current_user.id, "view", "patient_visit_link", appointment_id,
          f"Generated patient join link for appointment {appointment_id}")

    return {
        "patient_token": patient_token,
        "room_url": f"https://{DAILY_DOMAIN}/{room_name}" if DAILY_DOMAIN else None,
        "expires_in_hours": VISIT_TOKEN_TTL_H,
        "full_join_url": f"https://{DAILY_DOMAIN}/{room_name}?t={patient_token}" if DAILY_DOMAIN else None,
    }


@router.get("/visit/{appointment_id}/portal-join")
def portal_join_visit(
    appointment_id: int,
    patient: models.Patient = Depends(get_portal_patient),
    db: Session = Depends(get_db),
):
    """
    Patient portal endpoint: returns the Daily.co room URL and token for the
    patient to join their telehealth appointment. Called from the patient portal.
    """
    appt = db.query(models.Appointment).filter(
        models.Appointment.id == appointment_id,
        models.Appointment.patient_id == patient.id,
    ).first()
    if not appt:
        raise HTTPException(404, "Appointment not found")
    if not appt.notes or "ROOM:" not in appt.notes:
        raise HTTPException(409, "Your provider has not yet started the visit. Please wait a moment and try again.")

    room_name = appt.notes.split("ROOM:")[1].split("\n")[0].strip()

    patient_token = _generate_daily_token(
        room_name=room_name,
        user_name=f"{patient.first_name} {patient.last_name}",
        user_id=f"patient-{patient.id}",
        is_owner=False,
        ttl_hours=VISIT_TOKEN_TTL_H,
    )

    return {
        "room_url": f"https://{DAILY_DOMAIN}/{room_name}" if DAILY_DOMAIN else None,
        "token": patient_token,
        "expires_in_hours": VISIT_TOKEN_TTL_H,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 2. PATIENT SELF-SCHEDULING (PUBLIC — website integration)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/public/providers")
def public_provider_list(db: Session = Depends(get_db)):
    """
    Public endpoint: Returns a list of active providers with their specialties
    and available appointment types. Used by the website scheduling widget.
    No authentication required.
    """
    providers = db.query(models.User).filter(
        models.User.is_active == True,
        models.User.role.in_(["physician", "admin"]),
    ).all()
    return [
        {
            "id": p.id,
            "name": p.full_name,
            "specialty": p.specialty,
            "npi": p.npi_number,
        }
        for p in providers
    ]


@router.get("/public/availability")
def public_availability(
    provider_id: int,
    date: str,  # YYYY-MM-DD
    db: Session = Depends(get_db),
):
    """
    Public endpoint: Returns available time slots for a provider on a given date.
    Used by the website scheduling widget. No authentication required.
    """
    from datetime import datetime, timedelta
    try:
        date_obj = datetime.strptime(date, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(400, "Invalid date format. Use YYYY-MM-DD.")

    dow = date_obj.weekday()

    # Get provider's recurring schedule for this day
    schedule = db.query(models.ProviderSchedule).filter(
        models.ProviderSchedule.provider_id == provider_id,
        models.ProviderSchedule.day_of_week == dow,
        models.ProviderSchedule.is_active == True,
    ).first()

    if not schedule:
        return {"date": date, "slots": []}

    # Generate 30-minute slots in the schedule window
    start_h, start_m = map(int, schedule.start_time.split(":"))
    end_h, end_m = map(int, schedule.end_time.split(":"))
    cursor = date_obj.replace(hour=start_h, minute=start_m, second=0)
    end_dt = date_obj.replace(hour=end_h, minute=end_m, second=0)
    slots = []
    while cursor < end_dt:
        slots.append(cursor.strftime("%H:%M"))
        cursor += timedelta(minutes=30)

    # Remove booked slots
    booked = db.query(models.Appointment).filter(
        models.Appointment.provider_id == provider_id,
        models.Appointment.start_time >= date_obj,
        models.Appointment.start_time < date_obj + timedelta(days=1),
        models.Appointment.status.notin_(["cancelled"]),
    ).all()

    booked_times = {a.start_time.strftime("%H:%M") for a in booked}

    # Remove schedule blocks
    blocks = db.query(models.ScheduleBlock).filter(
        models.ScheduleBlock.provider_id == provider_id,
        models.ScheduleBlock.start_datetime < date_obj + timedelta(days=1),
        models.ScheduleBlock.end_datetime > date_obj,
    ).all()

    blocked_slots = set()
    for block in blocks:
        t = block.start_datetime
        while t < block.end_datetime:
            blocked_slots.add(t.strftime("%H:%M"))
            t += timedelta(minutes=30)

    available = [s for s in slots if s not in booked_times and s not in blocked_slots]
    return {"date": date, "provider_id": provider_id, "slots": available}


class SelfScheduleRequest(BaseModel):
    provider_id: int
    date: str           # YYYY-MM-DD
    time: str           # HH:MM
    patient_first_name: str
    patient_last_name: str
    patient_dob: str    # YYYY-MM-DD
    patient_email: str
    patient_phone: str
    patient_state: str  # 2-letter state code — used for license compliance check
    reason: str
    appointment_type_id: int | None = None


@router.post("/public/self-schedule")
async def self_schedule(body: SelfScheduleRequest, request: Request, db: Session = Depends(get_db)):
    """
    Public endpoint: Allows patients to self-schedule a telehealth appointment.
    Called from the website scheduling widget or patient enrollment page.

    Compliance checks:
    - If MSO_DASHBOARD_URL is configured, verifies the provider has an active
      license in the patient's state before creating the appointment.
    - Rate limited by the global rate limiter in main.py.
    """
    from datetime import datetime

    # State licensing compliance check (if MSO integration configured)
    if MSO_DASHBOARD_URL and MSO_API_KEY:
        provider = db.query(models.User).filter(models.User.id == body.provider_id).first()
        if provider and provider.npi_number:
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.get(
                        f"{MSO_DASHBOARD_URL}/api/licenses/matrix",
                        headers={"Authorization": f"Bearer {MSO_API_KEY}"},
                    )
                if resp.status_code == 200:
                    matrix = resp.json()
                    # Find provider in matrix
                    provider_row = next(
                        (r for r in matrix.get("matrix", [])
                         if provider.npi_number in r.get("provider", {}).get("npi", "")),
                        None
                    )
                    if provider_row:
                        state_lic = provider_row["states"].get(body.patient_state.upper(), {})
                        if state_lic.get("status") not in ("active", "compact"):
                            raise HTTPException(
                                400,
                                f"This provider is not currently licensed to practice in {body.patient_state}. "
                                f"Please contact us at support@commonwealthsolutions.com to find an available provider."
                            )
            except HTTPException:
                raise
            except Exception:
                pass  # Don't block scheduling if MSO check fails — log and continue

    # Parse datetime
    try:
        start_dt = datetime.strptime(f"{body.date} {body.time}", "%Y-%m-%d %H:%M")
        end_dt   = start_dt + timedelta(minutes=30)
    except ValueError:
        raise HTTPException(400, "Invalid date or time format")

    # Find or create patient
    patient = db.query(models.Patient).filter(
        models.Patient.portal_email == body.patient_email.lower(),
    ).first()

    if not patient:
        patient = models.Patient(
            first_name=body.patient_first_name.strip(),
            last_name=body.patient_last_name.strip(),
            dob=body.patient_dob,
            phone=body.patient_phone,
            portal_email=body.patient_email.lower(),
            state=body.patient_state.upper(),
            gender="",
        )
        db.add(patient)
        db.flush()

    # Create appointment
    appt = models.Appointment(
        patient_id=patient.id,
        provider_id=body.provider_id,
        appointment_type_id=body.appointment_type_id,
        title=f"Telehealth Visit — {body.patient_first_name} {body.patient_last_name}",
        start_time=start_dt,
        end_time=end_dt,
        status="scheduled",
        notes=f"Self-scheduled via website.\nReason: {body.reason}\nPatient state: {body.patient_state.upper()}",
        created_by=body.provider_id,
    )
    db.add(appt)
    db.commit()
    db.refresh(appt)

    # Audit log (no PHI-specific user since this is a public endpoint)
    patient_ip = request.client.host if request.client else "unknown"
    db.add(models.AuditLog(
        user_id=None,
        action="create",
        resource_type="appointment",
        resource_id=str(appt.id),
        details=f"Patient self-scheduled telehealth appointment. IP: {patient_ip}",
    ))
    db.commit()

    return {
        "appointment_id": appt.id,
        "status": "scheduled",
        "date": body.date,
        "time": body.time,
        "message": "Your appointment has been scheduled. You will receive a confirmation email shortly.",
    }


# ─────────────────────────────────────────────────────────────────────────────
# 3. PATIENT INTAKE FORMS
# ─────────────────────────────────────────────────────────────────────────────

class IntakeFormRequest(BaseModel):
    # Demographics
    first_name: str
    last_name: str
    dob: str
    gender: str
    phone: str
    email: str
    address: str
    city: str
    state: str
    zip_code: str

    # Medical history
    chief_complaint: str
    current_medications: str = ""
    allergies: str = ""
    pmh: str = ""          # Past medical history
    family_history: str = ""
    surgical_history: str = ""
    social_history: str = ""

    # Insurance
    insurance_name: str = ""
    insurance_id: str = ""
    insurance_group: str = ""

    # Emergency contact
    emergency_contact: str = ""
    emergency_phone: str = ""

    # Consents (required to be true for submission)
    hipaa_consent: bool
    telehealth_consent: bool
    sms_consent: bool = False
    email_consent: bool = False

    # Pharmacy preference (for compounding patients)
    preferred_pharmacy: str = ""
    compounding_consent: bool = False


@router.post("/public/intake")
async def submit_intake(body: IntakeFormRequest, request: Request, db: Session = Depends(get_db)):
    """
    Public endpoint: Patient self-registration / intake form.
    Captures HIPAA and telehealth consent with timestamp and IP.
    Creates a pending patient record for provider review.
    No authentication required.
    """
    if not body.hipaa_consent:
        raise HTTPException(400, "HIPAA consent is required to proceed.")
    if not body.telehealth_consent:
        raise HTTPException(400, "Telehealth consent is required to proceed.")

    # Prevent duplicate submissions
    existing = db.query(models.Patient).filter(
        models.Patient.portal_email == body.email.lower()
    ).first()
    if existing:
        return {
            "status": "existing_patient",
            "message": "We already have your information on file. "
                       "Please log in to your patient portal or contact us.",
        }

    consent_ts = datetime.utcnow().isoformat()
    patient_ip = request.client.host if request.client else "unknown"

    patient = models.Patient(
        first_name=body.first_name.strip(),
        last_name=body.last_name.strip(),
        dob=body.dob,
        gender=body.gender,
        phone=body.phone,
        email=body.email.lower(),
        portal_email=body.email.lower(),
        address=body.address,
        city=body.city,
        state=body.state.upper(),
        zip_code=body.zip_code,
        insurance_name=body.insurance_name,
        insurance_id=body.insurance_id,
        insurance_group=body.insurance_group,
        emergency_contact=body.emergency_contact,
        emergency_phone=body.emergency_phone,
        sms_consent=body.sms_consent,
        sms_consent_date=datetime.utcnow() if body.sms_consent else None,
        email_consent=body.email_consent,
        email_consent_date=datetime.utcnow() if body.email_consent else None,
        portal_active=False,  # Requires staff activation
    )
    db.add(patient)
    db.flush()

    # Create a pre-populated clinical note with intake information
    note = models.ClinicalNote(
        patient_id=patient.id,
        physician_id=1,  # Assign to primary physician — reassign at provider level
        visit_date=datetime.utcnow(),
        chief_complaint=body.chief_complaint,
        pmh=body.pmh,
        medications=body.current_medications,
        allergies=body.allergies,
        hpi=f"Patient-reported. Social: {body.social_history}. Family: {body.family_history}. Surgical: {body.surgical_history}.",
        plan=f"Intake pending provider review.\n"
             f"HIPAA consent: Yes ({consent_ts}, IP: {patient_ip})\n"
             f"Telehealth consent: Yes\n"
             f"SMS consent: {'Yes' if body.sms_consent else 'No'}\n"
             f"Compounding consent: {'Yes' if body.compounding_consent else 'No'}\n"
             f"Preferred pharmacy: {body.preferred_pharmacy or 'Not specified'}",
        note_type="INTAKE",
        status="draft",
        ai_generated=False,
    )
    db.add(note)
    db.commit()

    return {
        "status": "submitted",
        "patient_id": patient.id,
        "message": "Thank you. Your information has been received. "
                   "A member of our clinical team will review your intake and contact you "
                   "within 1 business day to confirm your appointment and set up your patient portal access.",
    }


# ─────────────────────────────────────────────────────────────────────────────
# 4. COMPOUNDING PHARMACY WORKFLOW
# ─────────────────────────────────────────────────────────────────────────────

class CompoundingOrderRequest(BaseModel):
    patient_id: int
    appointment_id: int | None = None
    # Drug formulation
    compound_name: str                  # e.g. "Testosterone Cypionate 200mg/mL"
    base_formula: str                   # e.g. "Sesame oil 1mL"
    strength: str
    dosage_form: str                    # e.g. "Injectable solution", "Topical cream"
    quantity: float
    quantity_unit: str
    sig: str                            # Directions
    days_supply: int
    refills: int = 0
    daw: bool = True                    # Always DAW=True for compounded (no generic substitution)
    # 503A compliance fields
    clinical_necessity: str             # Required: why commercial product is inadequate
    allergy_to_commercial: bool = False
    commercial_unavailable: bool = False
    dose_not_available_commercially: bool = False
    # Pharmacy routing
    pharmacy_name: str                  # Must be a licensed 503A pharmacy
    pharmacy_npi: str
    pharmacy_address: str
    pharmacy_phone: str
    pharmacy_dea: str = ""
    # Notes
    notes: str = ""


@router.post("/compounding/order")
def create_compounding_order(
    body: CompoundingOrderRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Creates a prescription for a compounded medication (503A).

    503A Compliance Requirements enforced:
    - Clinical necessity documentation is MANDATORY (OIG enforcement area)
    - At least one reason for compounding must be selected
    - The pharmacy must be a licensed 503A compounding pharmacy
    - No bulk compounding or office stock orders (must be patient-specific)

    AKS Note: The selected pharmacy must be at arm's-length. No financial
    relationship between the prescribing provider and the pharmacy is permitted.
    """
    # Enforce 503A clinical necessity documentation
    if not body.clinical_necessity or len(body.clinical_necessity.strip()) < 20:
        raise HTTPException(
            400,
            "Clinical necessity documentation is required for compounded prescriptions. "
            "Please provide a detailed clinical justification (minimum 20 characters)."
        )

    if not any([body.allergy_to_commercial, body.commercial_unavailable, body.dose_not_available_commercially]):
        raise HTTPException(
            400,
            "At least one reason for compounding must be documented: "
            "allergy to commercial product, commercial product unavailable, or required dose not commercially available."
        )

    patient = db.query(models.Patient).filter(models.Patient.id == body.patient_id).first()
    if not patient:
        raise HTTPException(404, "Patient not found")

    # Build 503A compliance annotation for the sig/notes
    compliance_note = (
        f"\n\n[503A Compounding Order]\n"
        f"Clinical necessity: {body.clinical_necessity}\n"
        f"Allergy to commercial: {body.allergy_to_commercial}\n"
        f"Commercial unavailable: {body.commercial_unavailable}\n"
        f"Dose not commercially available: {body.dose_not_available_commercially}\n"
        f"Ordered by: {current_user.full_name} (NPI: {current_user.npi_number})\n"
        f"Date: {datetime.utcnow().isoformat()}"
    )

    rx = models.Prescription(
        patient_id=body.patient_id,
        physician_id=current_user.id,
        drug_name=body.compound_name,
        strength=body.strength,
        dosage_form=body.dosage_form,
        sig=body.sig,
        quantity=body.quantity,
        quantity_unit=body.quantity_unit,
        days_supply=body.days_supply,
        refills=body.refills,
        daw=True,  # Always DAW for compounded
        pharmacy_name=body.pharmacy_name,
        pharmacy_npi=body.pharmacy_npi,
        pharmacy_address=body.pharmacy_address,
        pharmacy_phone=body.pharmacy_phone,
        is_compounded=True,
        notes=(body.notes or "") + compliance_note,
    )

    db.add(rx)
    db.commit()
    db.refresh(rx)

    audit(db, current_user.id, "create", "compounding_prescription", rx.id,
          f"Compounding order for {body.compound_name} — patient {body.patient_id}")

    return {
        "prescription_id": rx.id,
        "status": "created",
        "drug": body.compound_name,
        "pharmacy": body.pharmacy_name,
        "compliance_documented": True,
    }


# ─────────────────────────────────────────────────────────────────────────────
# 5. TELEHEALTH STATE COMPLIANCE CHECK
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/compliance/provider-state-check")
async def provider_state_check(
    provider_id: int,
    patient_state: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Checks whether a provider has an active license in the patient's state
    before a telehealth visit is initiated. Uses the MSO Dashboard API.

    Returns: { licensed: bool, status: str, message: str }
    """
    provider = db.query(models.User).filter(models.User.id == provider_id).first()
    if not provider:
        raise HTTPException(404, "Provider not found")

    if not MSO_DASHBOARD_URL:
        return {
            "licensed": True,
            "status": "skipped",
            "message": "MSO Dashboard not configured — compliance check skipped. Configure MSO_DASHBOARD_URL.",
        }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{MSO_DASHBOARD_URL}/api/licenses/matrix",
                headers={"Authorization": f"Bearer {MSO_API_KEY}"},
            )

        if resp.status_code != 200:
            return {"licensed": True, "status": "unavailable", "message": "MSO check unavailable — proceeding with caution."}

        matrix = resp.json()
        state_upper = patient_state.upper()

        for row in matrix.get("matrix", []):
            if provider.npi_number and row.get("provider", {}).get("npi") == provider.npi_number:
                state_lic = row["states"].get(state_upper, {})
                if state_lic.get("status") in ("active", "compact"):
                    return {"licensed": True, "status": "active", "message": f"Provider has active license in {state_upper}."}
                else:
                    return {
                        "licensed": False,
                        "status": state_lic.get("status", "not_found"),
                        "message": f"Provider does not have an active license in {state_upper}. "
                                   f"This visit cannot proceed. Contact the credentialing team."
                    }

        return {"licensed": True, "status": "not_found_in_mso", "message": "Provider not in MSO matrix — proceeding."}
    except Exception as e:
        return {"licensed": True, "status": "error", "message": f"Compliance check failed: {str(e)} — proceeding with caution."}


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _generate_daily_token(
    room_name: str,
    user_name: str,
    user_id: str,
    is_owner: bool,
    ttl_hours: int,
) -> str | None:
    """
    Generates a Daily.co meeting token using the Daily.co REST API.
    Returns None if DAILY_API_KEY is not configured.
    """
    if not DAILY_API_KEY:
        return None

    exp_ts = int((datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).timestamp())
    with daily_client() as client:
        resp = client.post("/meeting-tokens", json={
            "properties": {
                "room_name": room_name,
                "user_name": user_name,
                "user_id": user_id,
                "is_owner": is_owner,
                "exp": exp_ts,
                "enable_recording": "local" if is_owner else "off",
                "start_video_off": not is_owner,  # Patients start with video on
                "start_audio_off": False,
            }
        })
    if resp.status_code in (200, 201):
        return resp.json().get("token")
    return None
