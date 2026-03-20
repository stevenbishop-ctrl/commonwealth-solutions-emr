from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey
from database import Base
from datetime import datetime


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String)
    password_hash = Column(String)
    full_name = Column(String)
    npi_number = Column(String, default="")
    specialty = Column(String, default="")
    role = Column(String, default="physician")  # admin, physician, staff
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Patient(Base):
    __tablename__ = "patients"
    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String)
    last_name = Column(String)
    dob = Column(String)
    gender = Column(String)
    ssn_last4 = Column(String, default="")
    phone = Column(String, default="")
    email = Column(String, default="")
    address = Column(String, default="")
    city = Column(String, default="")
    state = Column(String, default="")
    zip_code = Column(String, default="")
    insurance_name = Column(String, default="")
    insurance_id = Column(String, default="")
    insurance_group = Column(String, default="")
    emergency_contact = Column(String, default="")
    emergency_phone = Column(String, default="")
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ClinicalNote(Base):
    __tablename__ = "clinical_notes"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("patients.id"))
    physician_id = Column(Integer, ForeignKey("users.id"))
    visit_date = Column(DateTime)
    chief_complaint = Column(Text, default="")
    hpi = Column(Text, default="")
    pmh = Column(Text, default="")
    medications = Column(Text, default="")
    allergies = Column(Text, default="")
    ros = Column(Text, default="")
    physical_exam = Column(Text, default="")
    assessment = Column(Text, default="")
    plan = Column(Text, default="")
    icd10_codes = Column(Text, default="[]")   # JSON string
    cpt_codes = Column(Text, default="[]")     # JSON string
    note_type = Column(String, default="SOAP")
    ai_generated = Column(Boolean, default=False)
    status = Column(String, default="draft")   # draft, signed, amended
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)


class LabOrder(Base):
    __tablename__ = "lab_orders"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("patients.id"))
    physician_id = Column(Integer, ForeignKey("users.id"))
    tests = Column(Text, default="[]")            # JSON array of test names (legacy display)
    test_objects = Column(Text, nullable=True)    # JSON array of {name, code, category, specimen}
    clinical_indication = Column(Text, default="")
    priority = Column(String, default="routine")  # routine, stat, asap
    facility = Column(String, default="LabCorp")
    status = Column(String, default="pending")    # pending, transmitted, resulted
    icd10_codes = Column(Text, default="[]")      # JSON
    notes = Column(Text, default="")
    transmitted_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    # LabCorp Beacon API fields
    labcorp_order_id  = Column(String, nullable=True)   # LabCorp's returned order ID
    labcorp_accession = Column(String, nullable=True)   # Lab accession # assigned at receipt
    labcorp_status    = Column(String, nullable=True)   # LabCorp's own status string
    result_received_at = Column(DateTime, nullable=True)
    result_data       = Column(Text, nullable=True)     # JSON array of observations
    result_pdf        = Column(Text, nullable=True)     # Base64-encoded result PDF


class ImagingOrder(Base):
    __tablename__ = "imaging_orders"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("patients.id"))
    physician_id = Column(Integer, ForeignKey("users.id"))
    study_type = Column(String, default="")
    body_part = Column(String, default="")
    clinical_indication = Column(Text, default="")
    priority = Column(String, default="routine")
    facility = Column(String, default="")
    fax_number = Column(String, default="")
    icd10_codes = Column(Text, default="[]")
    notes = Column(Text, default="")
    fax_status = Column(String, default="pending")  # pending, sent, failed
    fax_sent_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class FaxLog(Base):
    __tablename__ = "fax_logs"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("patients.id"), nullable=True)
    physician_id = Column(Integer, ForeignKey("users.id"))
    direction = Column(String, default="sent")    # sent, received
    from_number = Column(String, default="")
    to_number = Column(String, default="")
    subject = Column(String, default="")
    pages = Column(Integer, default=1)
    status = Column(String, default="pending")    # pending, queued, sending, delivered, failed, received
    telnyx_fax_id = Column(String, nullable=True) # Telnyx fax ID for status polling
    file_path = Column(String, default="")
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)


class Membership(Base):
    __tablename__ = "memberships"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("patients.id"))
    plan_name = Column(String)
    price_monthly = Column(Float, default=0.0)
    start_date = Column(DateTime)
    end_date = Column(DateTime, nullable=True)
    status = Column(String, default="active")   # active, cancelled, expired
    stripe_customer_id = Column(String, default="")
    stripe_subscription_id = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)


class Payment(Base):
    __tablename__ = "payments"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("patients.id"))
    amount = Column(Float, default=0.0)
    description = Column(String, default="")
    payment_method = Column(String, default="card")
    status = Column(String, default="pending")  # pending, completed, failed, refunded
    stripe_payment_intent_id = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)


class CryptoPayment(Base):
    __tablename__ = "crypto_payments"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("patients.id"))
    amount_usd = Column(Float)                   # amount in USD
    currency = Column(String)                    # BTC, USDC, USDT
    network = Column(String)                     # bitcoin, solana
    address = Column(String, default="")         # receiving wallet address
    reference = Column(String, default="")       # unique 6-char ref code (Solana memo)
    crypto_amount = Column(Float, nullable=True) # amount in crypto (BTC only)
    btcpay_invoice_id = Column(String, default="")
    btcpay_invoice_url = Column(String, default="")
    tx_signature = Column(String, default="")    # Solana tx signature or BTC txid
    status = Column(String, default="pending")   # pending, confirmed, expired, failed
    description = Column(String, default="")
    expires_at = Column(DateTime, nullable=True)
    confirmed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class PatientMedication(Base):
    __tablename__ = "patient_medications"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("patients.id"), nullable=False)
    name = Column(String, nullable=False)
    dosage = Column(String, default="")
    frequency = Column(String, default="")
    route = Column(String, default="oral")
    start_date = Column(String, default="")
    end_date = Column(String, default="")
    prescriber = Column(String, default="")
    indication = Column(String, default="")
    is_active = Column(Boolean, default=True)
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)


class PatientHistoryEntry(Base):
    __tablename__ = "patient_history"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("patients.id"), nullable=False)
    entry_type = Column(String, nullable=False)  # problem|allergy|surgical|family|social|immunization
    description = Column(String, nullable=False)
    detail = Column(String, default="")   # reaction/severity for allergies, relationship for family hx
    onset_date = Column(String, default="")
    status = Column(String, default="active")  # active|resolved|inactive
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)


class AppointmentType(Base):
    __tablename__ = "appointment_types"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    duration_minutes = Column(Integer, default=30)
    color = Column(String, default="#2563eb")
    description = Column(String, default="")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Appointment(Base):
    __tablename__ = "appointments"
    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("patients.id"), nullable=True)
    provider_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    appointment_type_id = Column(Integer, ForeignKey("appointment_types.id"), nullable=True)
    title = Column(String, nullable=False)
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=False)
    status = Column(String, default="scheduled")  # scheduled|confirmed|completed|cancelled|no_show
    notes = Column(Text, default="")
    color = Column(String, nullable=True)
    reminder_sent = Column(Boolean, default=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)


class ProviderSchedule(Base):
    """Weekly recurring availability for a provider."""
    __tablename__ = "provider_schedules"
    id = Column(Integer, primary_key=True, index=True)
    provider_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    day_of_week = Column(Integer, nullable=False)  # 0=Mon … 6=Sun
    start_time = Column(String, default="09:00")   # "HH:MM" local time
    end_time = Column(String, default="17:00")
    is_active = Column(Boolean, default=True)


class ScheduleBlock(Base):
    """One-off blocked time (vacation, meeting, etc.)."""
    __tablename__ = "schedule_blocks"
    id = Column(Integer, primary_key=True, index=True)
    provider_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    start_datetime = Column(DateTime, nullable=False)
    end_datetime = Column(DateTime, nullable=False)
    reason = Column(String, default="Blocked")
    created_at = Column(DateTime, default=datetime.utcnow)


class Prescription(Base):
    __tablename__ = "prescriptions"
    id               = Column(Integer, primary_key=True, index=True)
    patient_id       = Column(Integer, ForeignKey("patients.id"), nullable=False)
    physician_id     = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Drug
    drug_name        = Column(String, nullable=False)
    rxcui            = Column(String, default="")        # RxNorm concept ID
    ndc              = Column(String, default="")        # NDC code
    strength         = Column(String, default="")        # e.g. "10 mg"
    dosage_form      = Column(String, default="")        # tablet, capsule, liquid…
    sig              = Column(Text, default="")          # directions / sig line
    quantity         = Column(Float, default=30)
    quantity_unit    = Column(String, default="tablet(s)")
    days_supply      = Column(Integer, default=30)
    refills          = Column(Integer, default=0)
    daw              = Column(Boolean, default=False)    # Dispense as Written

    # Controlled substance
    dea_schedule     = Column(String, nullable=True)     # II | III | IV | V | None
    is_controlled    = Column(Boolean, default=False)
    epcs_verified    = Column(Boolean, default=False)    # EPCS two-factor completed

    # Pharmacy
    pharmacy_name    = Column(String, default="")
    pharmacy_npi     = Column(String, default="")
    pharmacy_address = Column(String, default="")
    pharmacy_phone   = Column(String, default="")
    pharmacy_fax     = Column(String, default="")

    # Diagnosis link
    icd10_codes      = Column(Text, default="[]")        # JSON

    # Status
    status           = Column(String, default="draft")   # draft|signed|transmitted|filled|cancelled
    signed_at        = Column(DateTime, nullable=True)
    transmitted_at   = Column(DateTime, nullable=True)
    filled_at        = Column(DateTime, nullable=True)

    # E-prescribing platform fields (adapter-ready)
    eprescribe_platform  = Column(String, nullable=True)  # dosespot|drfirst|surescripts
    eprescribe_rx_id     = Column(String, nullable=True)  # Platform's prescription reference
    eprescribe_status    = Column(String, nullable=True)  # Platform's status string
    eprescribe_response  = Column(Text, nullable=True)    # Raw JSON response from platform

    # Telnyx fax fields
    fax_pdf_token    = Column(String, nullable=True)      # UUID token for public PDF URL
    fax_pdf_data     = Column(Text, nullable=True)        # base64-encoded PDF for Telnyx to fetch
    fax_id           = Column(String, nullable=True)      # Telnyx fax ID
    fax_status       = Column(String, nullable=True)      # queued|sending|delivered|failed
    fax_sent_at      = Column(DateTime, nullable=True)

    notes            = Column(Text, default="")
    created_at       = Column(DateTime, default=datetime.utcnow)
    updated_at       = Column(DateTime, default=datetime.utcnow)


class SavedPharmacy(Base):
    """Pharmacies saved by the practice for quick selection."""
    __tablename__ = "saved_pharmacies"
    id       = Column(Integer, primary_key=True, index=True)
    name     = Column(String, nullable=False)
    npi      = Column(String, default="")
    address  = Column(String, default="")
    city     = Column(String, default="")
    state    = Column(String, default="")
    zip_code = Column(String, default="")
    phone    = Column(String, default="")
    fax      = Column(String, default="")
    chain    = Column(String, default="")   # CVS | Walgreens | Walmart | etc.
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class MembershipPlan(Base):
    """Membership plan templates — Valiant, Valiant Premier, Young Valiant."""
    __tablename__ = "membership_plans"
    id              = Column(Integer, primary_key=True, index=True)
    name            = Column(String, nullable=False)          # "Valiant", "Valiant Premier", "Young Valiant"
    slug            = Column(String, nullable=False, unique=True)  # "valiant", "valiant-premier", "young-valiant"
    description     = Column(Text, default="")
    price_monthly   = Column(Float, default=0.0)              # Monthly fee (placeholder until set)
    price_annual    = Column(Float, nullable=True)            # Optional annual price
    enrollment_fee  = Column(Float, default=0.0)              # One-time enrollment fee
    features        = Column(Text, default="[]")              # JSON array of feature strings
    age_min         = Column(Integer, nullable=True)          # Minimum age (Young Valiant: 0)
    age_max         = Column(Integer, nullable=True)          # Maximum age (Young Valiant: 17)
    color           = Column(String, default="#1e3a5f")       # Brand color for UI
    badge           = Column(String, nullable=True)           # "Most Popular", "Best Value", etc.
    is_active       = Column(Boolean, default=True)
    square_plan_id  = Column(String, default="")              # Square subscription plan variation ID
    zaprite_plan_id = Column(String, default="")              # Zaprite plan ID
    sort_order      = Column(Integer, default=0)
    created_at      = Column(DateTime, default=datetime.utcnow)
    updated_at      = Column(DateTime, default=datetime.utcnow)


class EnrollmentApplication(Base):
    """Patient self-enrollment applications submitted via the public /enroll page."""
    __tablename__ = "enrollment_applications"
    id                   = Column(Integer, primary_key=True, index=True)
    enrollment_token     = Column(String, unique=True, nullable=False)  # UUID for tracking
    plan_id              = Column(Integer, ForeignKey("membership_plans.id"), nullable=True)
    plan_name            = Column(String, default="")        # Denormalized for display
    status               = Column(String, default="pending") # pending|payment_pending|active|rejected|cancelled

    # Demographics
    first_name           = Column(String, default="")
    last_name            = Column(String, default="")
    dob                  = Column(String, default="")
    gender               = Column(String, default="")
    email                = Column(String, default="")
    phone                = Column(String, default="")
    address              = Column(String, default="")
    city                 = Column(String, default="")
    state                = Column(String, default="")
    zip_code             = Column(String, default="")

    # Emergency contact
    emergency_name       = Column(String, default="")
    emergency_phone      = Column(String, default="")
    emergency_relation   = Column(String, default="")

    # Insurance (for referrals — not billed by practice)
    insurance_name       = Column(String, default="")
    insurance_id         = Column(String, default="")

    # Medical history (JSON)
    allergies            = Column(Text, default="[]")
    medications          = Column(Text, default="[]")
    conditions           = Column(Text, default="[]")

    # Signed consents (JSON array: [{type, version, signed_at, ip, signature}])
    consents             = Column(Text, default="[]")

    # Payment
    payment_provider     = Column(String, default="")        # square | zaprite
    payment_status       = Column(String, default="pending") # pending|completed|failed
    payment_reference    = Column(String, default="")        # Square order ID / Zaprite checkout ID
    payment_amount       = Column(Float, default=0.0)

    # Linked patient (set by staff after approval)
    patient_id           = Column(Integer, ForeignKey("patients.id"), nullable=True)
    reviewed_by          = Column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at          = Column(DateTime, nullable=True)
    review_notes         = Column(Text, default="")

    ip_address           = Column(String, default="")
    user_agent           = Column(String, default="")
    created_at           = Column(DateTime, default=datetime.utcnow)
    updated_at           = Column(DateTime, default=datetime.utcnow)


class PatientConsent(Base):
    """Individual consent records — one row per consent type per patient/enrollment."""
    __tablename__ = "patient_consents"
    id               = Column(Integer, primary_key=True, index=True)
    patient_id       = Column(Integer, ForeignKey("patients.id"), nullable=True)
    enrollment_id    = Column(Integer, ForeignKey("enrollment_applications.id"), nullable=True)
    consent_type     = Column(String, nullable=False)  # hipaa|telehealth|communication|membership
    document_version = Column(String, default="1.0")
    signed_at        = Column(DateTime, nullable=False)
    ip_address       = Column(String, default="")
    user_agent       = Column(String, default="")
    signature_text   = Column(String, default="")      # Typed full name as e-signature
    consented        = Column(Boolean, default=True)
    created_at       = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String)
    resource_type = Column(String)
    resource_id = Column(String)
    ip_address = Column(String, default="")
    details = Column(Text, default="")
    timestamp = Column(DateTime, default=datetime.utcnow)
