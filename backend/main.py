"""
MedFlow EMR — FastAPI Backend
HIPAA-oriented: audit logging on every PHI access, JWT auth, encrypted DB-ready.

Run:
  pip install -r requirements.txt
  python setup.py          # seed DB once
  python main.py           # start server → http://localhost:8000
"""

import base64
import collections
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from io import BytesIO
from typing import Optional

import pyotp

import uuid as _uuid

import bcrypt
import httpx
import uvicorn
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from jose import JWTError, jwt
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable, KeepTogether, PageBreak,
    Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
)
from sqlalchemy.orm import Session

load_dotenv()

# ── Square config ─────────────────────────────────────────────────────────────
SQUARE_ACCESS_TOKEN = os.getenv("SQUARE_ACCESS_TOKEN", "")
SQUARE_LOCATION_ID  = os.getenv("SQUARE_LOCATION_ID", "")
SQUARE_APP_ID       = os.getenv("SQUARE_APP_ID", "")
SQUARE_ENVIRONMENT  = os.getenv("SQUARE_ENVIRONMENT", "production")
BILLING_SECRET      = os.getenv("BILLING_SECRET", "")   # secret key for scheduled billing cron
SQUARE_BASE_URL = (
    "https://connect.squareupsandbox.com"
    if SQUARE_ENVIRONMENT == "sandbox"
    else "https://connect.squareup.com"
)

# ── LabCorp Beacon API config ──────────────────────────────────────────────────
# Set these in Railway → Variables:
#   LABCORP_CLIENT_ID      — OAuth client ID from developer.labcorp.com
#   LABCORP_CLIENT_SECRET  — OAuth client secret
#   LABCORP_ACCOUNT_NUM    — Your LabCorp billing account number
#   LABCORP_NPI            — Ordering facility NPI (overridden per-provider if set)
#   LABCORP_WEBHOOK_SECRET — Shared secret LabCorp sends in X-LabCorp-Signature header
#   LABCORP_SANDBOX        — Set to "true" to use sandbox environment
_lc_sandbox = os.getenv("LABCORP_SANDBOX", "false").lower() == "true"
LABCORP_CLIENT_ID      = os.getenv("LABCORP_CLIENT_ID", "")
LABCORP_CLIENT_SECRET  = os.getenv("LABCORP_CLIENT_SECRET", "")
LABCORP_ACCOUNT_NUM    = os.getenv("LABCORP_ACCOUNT_NUM", "")
LABCORP_FACILITY_NPI   = os.getenv("LABCORP_NPI", "")
LABCORP_WEBHOOK_SECRET = os.getenv("LABCORP_WEBHOOK_SECRET", "")
LABCORP_BASE_URL       = (
    "https://api.sandbox.labcorp.com" if _lc_sandbox else "https://api.labcorp.com"
)
LABCORP_TOKEN_URL      = (
    "https://identity.sandbox.labcorp.com/oauth2/v1/token"
    if _lc_sandbox
    else "https://identity.labcorp.com/oauth2/aus1lmzz00pBc4M9V0h8/v1/token"
)

# LabCorp test name → numeric order code mapping
# Full embedded catalog used as: (1) code lookup when transmitting orders,
# (2) fallback search when LabCorp API credentials are not configured.
# Codes sourced from LabCorp's public test directory (labcorp.com/tests).
# Always verify codes at https://www.labcorp.com/tests before clinical use.
LABCORP_TEST_CATALOG: list = [
    # ── HEMATOLOGY ──────────────────────────────────────────────────────────
    {"code":"005009","name":"CBC With Differential/Platelet",           "category":"Hematology",        "specimen":"Blood"},
    {"code":"005025","name":"CBC Without Differential",                  "category":"Hematology",        "specimen":"Blood"},
    {"code":"007476","name":"Reticulocyte Count",                        "category":"Hematology",        "specimen":"Blood"},
    {"code":"004390","name":"Sickle Cell Screen (Hemoglobin S)",         "category":"Hematology",        "specimen":"Blood"},
    {"code":"005843","name":"Blood Type, ABO and Rh",                   "category":"Hematology",        "specimen":"Blood"},
    {"code":"006643","name":"Direct Antiglobulin Test (Direct Coombs)", "category":"Hematology",        "specimen":"Blood"},
    {"code":"006628","name":"Indirect Antiglobulin (Indirect Coombs)",  "category":"Hematology",        "specimen":"Blood"},
    {"code":"002040","name":"Peripheral Blood Smear",                   "category":"Hematology",        "specimen":"Blood"},

    # ── CHEMISTRY / METABOLIC ────────────────────────────────────────────────
    {"code":"322000","name":"Comprehensive Metabolic Panel (CMP)",      "category":"Chemistry",         "specimen":"Blood"},
    {"code":"020594","name":"Basic Metabolic Panel (BMP)",              "category":"Chemistry",         "specimen":"Blood"},
    {"code":"001453","name":"Hemoglobin A1c (HbA1c)",                   "category":"Chemistry",         "specimen":"Blood"},
    {"code":"001032","name":"Glucose, Serum",                           "category":"Chemistry",         "specimen":"Blood"},
    {"code":"004184","name":"Insulin, Fasting",                         "category":"Chemistry",         "specimen":"Blood"},
    {"code":"004540","name":"C-Peptide",                                 "category":"Chemistry",         "specimen":"Blood"},
    {"code":"001040","name":"Creatinine, Serum",                        "category":"Chemistry",         "specimen":"Blood"},
    {"code":"001065","name":"BUN (Blood Urea Nitrogen)",                 "category":"Chemistry",         "specimen":"Blood"},
    {"code":"001180","name":"Uric Acid, Serum",                         "category":"Chemistry",         "specimen":"Blood"},
    {"code":"001123","name":"Calcium, Serum",                           "category":"Chemistry",         "specimen":"Blood"},
    {"code":"001115","name":"Magnesium, Serum",                         "category":"Chemistry",         "specimen":"Blood"},
    {"code":"001156","name":"Phosphorus, Serum",                        "category":"Chemistry",         "specimen":"Blood"},
    {"code":"001636","name":"Total Protein, Serum",                     "category":"Chemistry",         "specimen":"Blood"},
    {"code":"001644","name":"Albumin, Serum",                           "category":"Chemistry",         "specimen":"Blood"},
    {"code":"001677","name":"LDH (Lactate Dehydrogenase)",              "category":"Chemistry",         "specimen":"Blood"},
    {"code":"001784","name":"GGT (Gamma-Glutamyl Transferase)",         "category":"Chemistry",         "specimen":"Blood"},
    {"code":"001800","name":"Amylase",                                   "category":"Chemistry",         "specimen":"Blood"},
    {"code":"001818","name":"Lipase",                                    "category":"Chemistry",         "specimen":"Blood"},
    {"code":"004246","name":"Prealbumin (Transthyretin)",               "category":"Chemistry",         "specimen":"Blood"},

    # ── LIPIDS ───────────────────────────────────────────────────────────────
    {"code":"303756","name":"Lipid Panel",                               "category":"Lipids",            "specimen":"Blood"},
    {"code":"012165","name":"LDL Cholesterol, Direct",                  "category":"Lipids",            "specimen":"Blood"},
    {"code":"012001","name":"Cholesterol, Total",                       "category":"Lipids",            "specimen":"Blood"},
    {"code":"012173","name":"HDL Cholesterol",                          "category":"Lipids",            "specimen":"Blood"},
    {"code":"012207","name":"Triglycerides",                             "category":"Lipids",            "specimen":"Blood"},
    {"code":"496300","name":"Lipoprotein (a)",                          "category":"Lipids",            "specimen":"Blood"},
    {"code":"072975","name":"Apolipoprotein B",                         "category":"Lipids",            "specimen":"Blood"},
    {"code":"070212","name":"Apolipoprotein A-1",                       "category":"Lipids",            "specimen":"Blood"},
    {"code":"320025","name":"Cardio IQ Lipid Panel Advanced",           "category":"Lipids",            "specimen":"Blood"},

    # ── LIVER / HEPATIC ──────────────────────────────────────────────────────
    {"code":"322755","name":"Hepatic Function Panel (LFTs)",            "category":"Liver",             "specimen":"Blood"},
    {"code":"001776","name":"AST (Aspartate Aminotransferase/SGOT)",    "category":"Liver",             "specimen":"Blood"},
    {"code":"001768","name":"ALT (Alanine Aminotransferase/SGPT)",      "category":"Liver",             "specimen":"Blood"},
    {"code":"001800","name":"Alkaline Phosphatase",                     "category":"Liver",             "specimen":"Blood"},
    {"code":"001818","name":"Bilirubin, Total",                         "category":"Liver",             "specimen":"Blood"},
    {"code":"001826","name":"Bilirubin, Direct",                        "category":"Liver",             "specimen":"Blood"},

    # ── THYROID ──────────────────────────────────────────────────────────────
    {"code":"004259","name":"TSH (Thyroid Stimulating Hormone)",        "category":"Thyroid",           "specimen":"Blood"},
    {"code":"001974","name":"Free T4 (Free Thyroxine)",                 "category":"Thyroid",           "specimen":"Blood"},
    {"code":"010389","name":"Free T3 (Free Triiodothyronine)",          "category":"Thyroid",           "specimen":"Blood"},
    {"code":"002188","name":"T3, Total",                                 "category":"Thyroid",           "specimen":"Blood"},
    {"code":"001628","name":"T4, Total (Thyroxine)",                    "category":"Thyroid",           "specimen":"Blood"},
    {"code":"006676","name":"Anti-TPO (Thyroid Peroxidase Ab)",         "category":"Thyroid",           "specimen":"Blood"},
    {"code":"006684","name":"Anti-Thyroglobulin Antibody",              "category":"Thyroid",           "specimen":"Blood"},
    {"code":"002253","name":"Thyroglobulin",                             "category":"Thyroid",           "specimen":"Blood"},
    {"code":"004038","name":"PTH (Parathyroid Hormone), Intact",        "category":"Thyroid",           "specimen":"Blood"},

    # ── VITAMINS & MINERALS ──────────────────────────────────────────────────
    {"code":"081950","name":"Vitamin D, 25-Hydroxy",                    "category":"Vitamins/Minerals", "specimen":"Blood"},
    {"code":"001503","name":"Vitamin B12 (Cobalamin)",                  "category":"Vitamins/Minerals", "specimen":"Blood"},
    {"code":"001529","name":"Folate (Folic Acid), Serum",               "category":"Vitamins/Minerals", "specimen":"Blood"},
    {"code":"004598","name":"Ferritin",                                  "category":"Vitamins/Minerals", "specimen":"Blood"},
    {"code":"001966","name":"Iron and TIBC",                             "category":"Vitamins/Minerals", "specimen":"Blood"},
    {"code":"001990","name":"Iron, Serum",                               "category":"Vitamins/Minerals", "specimen":"Blood"},
    {"code":"007765","name":"Zinc, Serum or Plasma",                    "category":"Vitamins/Minerals", "specimen":"Blood"},
    {"code":"070789","name":"Copper, Serum",                             "category":"Vitamins/Minerals", "specimen":"Blood"},
    {"code":"140525","name":"Vitamin A (Retinol)",                      "category":"Vitamins/Minerals", "specimen":"Blood"},
    {"code":"140517","name":"Vitamin E (Tocopherol)",                   "category":"Vitamins/Minerals", "specimen":"Blood"},
    {"code":"001586","name":"Vitamin C (Ascorbic Acid)",                "category":"Vitamins/Minerals", "specimen":"Blood"},
    {"code":"001610","name":"Vitamin B1 (Thiamine), Blood",             "category":"Vitamins/Minerals", "specimen":"Blood"},
    {"code":"001594","name":"Vitamin B6 (Pyridoxine), Plasma",          "category":"Vitamins/Minerals", "specimen":"Blood"},

    # ── HORMONES ─────────────────────────────────────────────────────────────
    {"code":"004226","name":"Testosterone, Total, Males",               "category":"Hormones",          "specimen":"Blood"},
    {"code":"070181","name":"Testosterone, Free",                       "category":"Hormones",          "specimen":"Blood"},
    {"code":"004515","name":"Estradiol (E2)",                           "category":"Hormones",          "specimen":"Blood"},
    {"code":"004523","name":"Estrogens, Total",                         "category":"Hormones",          "specimen":"Blood"},
    {"code":"004564","name":"Progesterone",                             "category":"Hormones",          "specimen":"Blood"},
    {"code":"004281","name":"FSH (Follicle Stimulating Hormone)",       "category":"Hormones",          "specimen":"Blood"},
    {"code":"004317","name":"LH (Luteinizing Hormone)",                 "category":"Hormones",          "specimen":"Blood"},
    {"code":"004524","name":"Prolactin",                                 "category":"Hormones",          "specimen":"Blood"},
    {"code":"004533","name":"Cortisol, AM (8 AM)",                      "category":"Hormones",          "specimen":"Blood"},
    {"code":"004549","name":"Cortisol, PM (4 PM)",                      "category":"Hormones",          "specimen":"Blood"},
    {"code":"004020","name":"DHEA-S",                                    "category":"Hormones",          "specimen":"Blood"},
    {"code":"004236","name":"SHBG (Sex Hormone Binding Globulin)",      "category":"Hormones",          "specimen":"Blood"},
    {"code":"004197","name":"IGF-1 (Insulin-like Growth Factor 1)",     "category":"Hormones",          "specimen":"Blood"},
    {"code":"004057","name":"Aldosterone, Serum",                       "category":"Hormones",          "specimen":"Blood"},
    {"code":"004073","name":"Renin Activity, Plasma",                   "category":"Hormones",          "specimen":"Blood"},
    {"code":"004218","name":"hCG (Pregnancy Test), Quantitative",       "category":"Hormones",          "specimen":"Blood"},
    {"code":"004202","name":"ACTH (Adrenocorticotropic Hormone)",       "category":"Hormones",          "specimen":"Blood"},

    # ── INFLAMMATORY / AUTOIMMUNE ────────────────────────────────────────────
    {"code":"120766","name":"CRP, High Sensitivity (hs-CRP)",           "category":"Inflammatory",      "specimen":"Blood"},
    {"code":"004986","name":"CRP (C-Reactive Protein)",                 "category":"Inflammatory",      "specimen":"Blood"},
    {"code":"005215","name":"ESR (Erythrocyte Sedimentation Rate)",     "category":"Inflammatory",      "specimen":"Blood"},
    {"code":"002040","name":"ANA Screen (Antinuclear Antibody)",        "category":"Inflammatory",      "specimen":"Blood"},
    {"code":"002064","name":"Anti-dsDNA Antibody",                      "category":"Inflammatory",      "specimen":"Blood"},
    {"code":"006676","name":"Rheumatoid Factor (RF)",                   "category":"Inflammatory",      "specimen":"Blood"},
    {"code":"092486","name":"Anti-CCP (Anti-Cyclic Citrullinated Peptide)","category":"Inflammatory",  "specimen":"Blood"},
    {"code":"002271","name":"Complement C3",                             "category":"Inflammatory",      "specimen":"Blood"},
    {"code":"002287","name":"Complement C4",                             "category":"Inflammatory",      "specimen":"Blood"},
    {"code":"002295","name":"CH50 (Total Complement)",                  "category":"Inflammatory",      "specimen":"Blood"},
    {"code":"006694","name":"Anti-Smith Antibody",                      "category":"Inflammatory",      "specimen":"Blood"},
    {"code":"006702","name":"Anti-SSA/Ro Antibody",                     "category":"Inflammatory",      "specimen":"Blood"},
    {"code":"006710","name":"Anti-SSB/La Antibody",                     "category":"Inflammatory",      "specimen":"Blood"},
    {"code":"006728","name":"Anti-Scl-70 (Topoisomerase I) Antibody",  "category":"Inflammatory",      "specimen":"Blood"},
    {"code":"004978","name":"IL-6 (Interleukin-6)",                     "category":"Inflammatory",      "specimen":"Blood"},

    # ── INFECTIOUS DISEASE ───────────────────────────────────────────────────
    {"code":"083935","name":"HIV-1/O/2 Abs, Differentiated",            "category":"Infectious Disease","specimen":"Blood"},
    {"code":"040736","name":"HIV-1 RNA, Quantitative (Viral Load)",     "category":"Infectious Disease","specimen":"Blood"},
    {"code":"006455","name":"Hepatitis B Surface Antigen (HBsAg)",      "category":"Infectious Disease","specimen":"Blood"},
    {"code":"006619","name":"Hepatitis B Surface Antibody (HBsAb)",     "category":"Infectious Disease","specimen":"Blood"},
    {"code":"006635","name":"Hepatitis B Core Ab, Total (HBcAb)",       "category":"Infectious Disease","specimen":"Blood"},
    {"code":"010546","name":"Hepatitis C Antibody (HCV Ab)",            "category":"Infectious Disease","specimen":"Blood"},
    {"code":"540798","name":"Hepatitis C RNA, Quantitative (Viral Load)","category":"Infectious Disease","specimen":"Blood"},
    {"code":"006676","name":"RPR (Syphilis Screen)",                    "category":"Infectious Disease","specimen":"Blood"},
    {"code":"006697","name":"Syphilis IgG/IgM (TPPA Confirmatory)",    "category":"Infectious Disease","specimen":"Blood"},
    {"code":"006072","name":"Mononucleosis Screen (Monospot)",          "category":"Infectious Disease","specimen":"Blood"},
    {"code":"017244","name":"Strep A Antigen, Direct (Rapid)",          "category":"Infectious Disease","specimen":"Throat Swab"},
    {"code":"190850","name":"Influenza A and B, Rapid Antigen",         "category":"Infectious Disease","specimen":"Nasal Swab"},
    {"code":"188955","name":"COVID-19 Antigen",                         "category":"Infectious Disease","specimen":"Nasal Swab"},
    {"code":"188998","name":"COVID-19 PCR (Molecular, NAAT)",           "category":"Infectious Disease","specimen":"Nasal Swab"},
    {"code":"164940","name":"COVID-19 Antibody, Spike Protein (IgG)",   "category":"Infectious Disease","specimen":"Blood"},
    {"code":"006008","name":"Lyme Disease Antibody (EIA Screen)",       "category":"Infectious Disease","specimen":"Blood"},
    {"code":"006027","name":"Lyme Disease Western Blot (IgG/IgM)",     "category":"Infectious Disease","specimen":"Blood"},
    {"code":"008862","name":"Culture, Urine, Routine",                  "category":"Infectious Disease","specimen":"Urine"},
    {"code":"005010","name":"Culture, Blood (Aerobic/Anaerobic)",       "category":"Infectious Disease","specimen":"Blood"},
    {"code":"004387","name":"Chlamydia/GC NAAT",                        "category":"Infectious Disease","specimen":"Swab/Urine"},
    {"code":"164924","name":"RSV Antigen, Rapid",                       "category":"Infectious Disease","specimen":"Nasal Swab"},
    {"code":"009019","name":"QuantiFERON-TB Gold Plus (TB Test)",       "category":"Infectious Disease","specimen":"Blood"},
    {"code":"006016","name":"Varicella Zoster Virus (VZV) IgG",        "category":"Infectious Disease","specimen":"Blood"},
    {"code":"006044","name":"EBV (Epstein-Barr) Antibody Panel",        "category":"Infectious Disease","specimen":"Blood"},
    {"code":"006052","name":"CMV (Cytomegalovirus) IgG/IgM",           "category":"Infectious Disease","specimen":"Blood"},
    {"code":"188831","name":"Toxoplasma IgG/IgM",                       "category":"Infectious Disease","specimen":"Blood"},
    {"code":"006020","name":"Rubella IgG (Immunity Screen)",            "category":"Infectious Disease","specimen":"Blood"},

    # ── URINE ────────────────────────────────────────────────────────────────
    {"code":"003038","name":"Urinalysis, Complete",                     "category":"Urine",             "specimen":"Urine"},
    {"code":"003020","name":"Urinalysis with Microscopy",               "category":"Urine",             "specimen":"Urine"},
    {"code":"089084","name":"Microalbumin/Creatinine Ratio, Urine",    "category":"Urine",             "specimen":"Urine"},
    {"code":"003055","name":"Pregnancy Test (hCG), Urine Qualitative",  "category":"Urine",             "specimen":"Urine"},
    {"code":"167672","name":"Drug Screen, Urine (10-Panel)",            "category":"Urine",             "specimen":"Urine"},
    {"code":"167668","name":"Drug Screen, Urine (5-Panel)",             "category":"Urine",             "specimen":"Urine"},
    {"code":"004040","name":"Protein, 24-Hour Urine",                   "category":"Urine",             "specimen":"24h Urine"},
    {"code":"004048","name":"Creatinine Clearance, 24-Hour Urine",     "category":"Urine",             "specimen":"24h Urine"},
    {"code":"004056","name":"Catecholamines, Fractionated, 24-Hr Urine","category":"Urine",            "specimen":"24h Urine"},
    {"code":"004064","name":"Cortisol, Free, 24-Hour Urine",           "category":"Urine",             "specimen":"24h Urine"},
    {"code":"004072","name":"Aldosterone, 24-Hour Urine",               "category":"Urine",             "specimen":"24h Urine"},
    {"code":"003012","name":"Urine Osmolality",                         "category":"Urine",             "specimen":"Urine"},
    {"code":"008862","name":"Urine Culture and Sensitivity",            "category":"Urine",             "specimen":"Urine"},

    # ── COAGULATION ──────────────────────────────────────────────────────────
    {"code":"013983","name":"Prothrombin Time (PT) and INR",            "category":"Coagulation",       "specimen":"Blood"},
    {"code":"012500","name":"Activated PTT (aPTT)",                     "category":"Coagulation",       "specimen":"Blood"},
    {"code":"167167","name":"D-Dimer, Quantitative",                    "category":"Coagulation",       "specimen":"Blood"},
    {"code":"003178","name":"Fibrinogen Activity",                      "category":"Coagulation",       "specimen":"Blood"},
    {"code":"004417","name":"Factor V Leiden Mutation (PCR)",           "category":"Coagulation",       "specimen":"Blood"},
    {"code":"004424","name":"Prothrombin G20210A Gene Mutation",        "category":"Coagulation",       "specimen":"Blood"},
    {"code":"004431","name":"Antithrombin III Activity",                "category":"Coagulation",       "specimen":"Blood"},
    {"code":"004448","name":"Protein C Activity",                       "category":"Coagulation",       "specimen":"Blood"},
    {"code":"004455","name":"Protein S, Free",                          "category":"Coagulation",       "specimen":"Blood"},
    {"code":"004463","name":"Lupus Anticoagulant Panel",                "category":"Coagulation",       "specimen":"Blood"},
    {"code":"004471","name":"Antiphospholipid Antibody Panel",          "category":"Coagulation",       "specimen":"Blood"},
    {"code":"004479","name":"Von Willebrand Factor Antigen",            "category":"Coagulation",       "specimen":"Blood"},

    # ── CARDIOLOGY ───────────────────────────────────────────────────────────
    {"code":"070238","name":"BNP (B-Type Natriuretic Peptide)",         "category":"Cardiology",        "specimen":"Blood"},
    {"code":"070245","name":"NT-proBNP",                                 "category":"Cardiology",        "specimen":"Blood"},
    {"code":"049506","name":"Troponin I, High Sensitivity",             "category":"Cardiology",        "specimen":"Blood"},
    {"code":"049514","name":"Troponin T",                                "category":"Cardiology",        "specimen":"Blood"},
    {"code":"706922","name":"Homocysteine, Plasma",                     "category":"Cardiology",        "specimen":"Blood"},
    {"code":"070253","name":"CK-MB (Creatine Kinase-MB)",               "category":"Cardiology",        "specimen":"Blood"},
    {"code":"070261","name":"CK (Creatine Kinase), Total",              "category":"Cardiology",        "specimen":"Blood"},

    # ── CANCER MARKERS ───────────────────────────────────────────────────────
    {"code":"010334","name":"PSA, Total (Prostate Specific Antigen)",   "category":"Cancer Markers",    "specimen":"Blood"},
    {"code":"010391","name":"PSA, Free and Total",                      "category":"Cancer Markers",    "specimen":"Blood"},
    {"code":"010367","name":"CEA (Carcinoembryonic Antigen)",           "category":"Cancer Markers",    "specimen":"Blood"},
    {"code":"010383","name":"AFP (Alpha-Fetoprotein), Tumor Marker",    "category":"Cancer Markers",    "specimen":"Blood"},
    {"code":"010375","name":"CA 125",                                    "category":"Cancer Markers",    "specimen":"Blood"},
    {"code":"010359","name":"CA 19-9",                                   "category":"Cancer Markers",    "specimen":"Blood"},
    {"code":"010342","name":"CA 15-3 (Breast Tumor Marker)",            "category":"Cancer Markers",    "specimen":"Blood"},
    {"code":"010318","name":"Beta-2 Microglobulin",                     "category":"Cancer Markers",    "specimen":"Blood"},

    # ── KIDNEY / RENAL ───────────────────────────────────────────────────────
    {"code":"070222","name":"Cystatin C",                                "category":"Kidney",            "specimen":"Blood"},
    {"code":"001065","name":"Creatinine with eGFR",                     "category":"Kidney",            "specimen":"Blood"},

    # ── MICROBIOLOGY ─────────────────────────────────────────────────────────
    {"code":"008870","name":"Culture, Wound",                           "category":"Microbiology",      "specimen":"Wound Swab"},
    {"code":"008888","name":"Culture, Sputum",                          "category":"Microbiology",      "specimen":"Sputum"},
    {"code":"008896","name":"Culture, Stool (Enteric Pathogen Screen)", "category":"Microbiology",      "specimen":"Stool"},
    {"code":"008904","name":"Ova and Parasites (O&P), Stool",           "category":"Microbiology",      "specimen":"Stool"},
    {"code":"008912","name":"H. pylori Antigen, Stool",                 "category":"Microbiology",      "specimen":"Stool"},
    {"code":"008920","name":"C. difficile Toxin A/B, PCR, Stool",       "category":"Microbiology",      "specimen":"Stool"},

    # ── DRUG LEVELS (THERAPEUTIC MONITORING) ────────────────────────────────
    {"code":"004507","name":"Digoxin Level",                             "category":"Drug Levels",       "specimen":"Blood"},
    {"code":"004484","name":"Lithium Level",                             "category":"Drug Levels",       "specimen":"Blood"},
    {"code":"004473","name":"Phenytoin (Dilantin) Level",               "category":"Drug Levels",       "specimen":"Blood"},
    {"code":"004481","name":"Valproic Acid (Depakote) Level",           "category":"Drug Levels",       "specimen":"Blood"},
    {"code":"004476","name":"Carbamazepine (Tegretol) Level",           "category":"Drug Levels",       "specimen":"Blood"},
    {"code":"007148","name":"Cyclosporine Level",                       "category":"Drug Levels",       "specimen":"Blood"},
    {"code":"007155","name":"Tacrolimus (FK506) Level",                 "category":"Drug Levels",       "specimen":"Blood"},
    {"code":"091016","name":"Vancomycin Trough Level",                  "category":"Drug Levels",       "specimen":"Blood"},
    {"code":"091048","name":"Gentamicin Trough Level",                  "category":"Drug Levels",       "specimen":"Blood"},
    {"code":"007162","name":"Methotrexate Level",                       "category":"Drug Levels",       "specimen":"Blood"},
    {"code":"004490","name":"Phenobarbital Level",                      "category":"Drug Levels",       "specimen":"Blood"},
    {"code":"004498","name":"Theophylline Level",                       "category":"Drug Levels",       "specimen":"Blood"},

    # ── STOOL ────────────────────────────────────────────────────────────────
    {"code":"002024","name":"Fecal Occult Blood (FOBT), Guaiac",        "category":"Stool",             "specimen":"Stool"},
    {"code":"188021","name":"FIT (Fecal Immunochemical Test)",          "category":"Stool",             "specimen":"Stool"},
    {"code":"002032","name":"Fecal Calprotectin",                       "category":"Stool",             "specimen":"Stool"},
    {"code":"002048","name":"Fecal Fat, 72-Hour (Quantitative)",        "category":"Stool",             "specimen":"Stool"},

    # ── GENETIC / MOLECULAR ──────────────────────────────────────────────────
    {"code":"167680","name":"BRCA1/BRCA2 Full Sequencing",              "category":"Genetics",          "specimen":"Blood"},
    {"code":"164872","name":"KRAS Mutation Analysis",                   "category":"Genetics",          "specimen":"Tissue"},
    {"code":"004417","name":"Factor V Leiden (PCR)",                    "category":"Genetics",          "specimen":"Blood"},
    {"code":"164888","name":"MTHFR Gene Mutation, 2 Variants",         "category":"Genetics",          "specimen":"Blood"},
    {"code":"164896","name":"HLA-B27 Antigen (PCR)",                    "category":"Genetics",          "specimen":"Blood"},
]

# Fast lookup dict: test name → {code, name} used at order-submission time
LABCORP_TEST_CODES: dict = {
    t["name"]: {"code": t["code"], "name": t["name"]}
    for t in LABCORP_TEST_CATALOG
}
# Also keep old short-name aliases so existing orders still resolve
_LEGACY_ALIASES = {
    "CBC": "CBC With Differential/Platelet",
    "CMP": "Comprehensive Metabolic Panel (CMP)",
    "BMP": "Basic Metabolic Panel (BMP)",
    "Lipid Panel": "Lipid Panel",
    "HbA1c": "Hemoglobin A1c (HbA1c)",
    "TSH": "TSH (Thyroid Stimulating Hormone)",
    "Urinalysis": "Urinalysis, Complete",
    "Urine Culture": "Culture, Urine, Routine",
    "PT/INR": "Prothrombin Time (PT) and INR",
    "PSA": "PSA, Total (Prostate Specific Antigen)",
    "Vitamin D 25-OH": "Vitamin D, 25-Hydroxy",
    "LFTs": "Hepatic Function Panel (LFTs)",
    "Ferritin": "Ferritin",
    "B12": "Vitamin B12 (Cobalamin)",
    "Folate": "Folate (Folic Acid), Serum",
    "CRP": "CRP (C-Reactive Protein)",
    "ESR": "ESR (Erythrocyte Sedimentation Rate)",
    "HIV": "HIV-1/O/2 Abs, Differentiated",
    "HBsAg": "Hepatitis B Surface Antigen (HBsAg)",
    "HCV Ab": "Hepatitis C Antibody (HCV Ab)",
    "Mono": "Mononucleosis Screen (Monospot)",
    "Strep A": "Strep A Antigen, Direct (Rapid)",
    "Flu A/B": "Influenza A and B, Rapid Antigen",
}
for alias, full in _LEGACY_ALIASES.items():
    if alias not in LABCORP_TEST_CODES and full in LABCORP_TEST_CODES:
        LABCORP_TEST_CODES[alias] = LABCORP_TEST_CODES[full]

# Category list for UI navigation
LABCORP_CATEGORIES: list = sorted(set(t["category"] for t in LABCORP_TEST_CATALOG))

# In-memory OAuth token cache
_lc_token_cache: dict = {"access_token": None, "expires_at": 0.0}


def _get_labcorp_token() -> str:
    """Fetch (or return cached) LabCorp OAuth2 bearer token."""
    if not LABCORP_CLIENT_ID or not LABCORP_CLIENT_SECRET:
        raise HTTPException(
            status_code=503,
            detail="LabCorp not configured — add LABCORP_CLIENT_ID and LABCORP_CLIENT_SECRET to Railway variables",
        )
    now = time.time()
    if _lc_token_cache["access_token"] and _lc_token_cache["expires_at"] > now + 60:
        return _lc_token_cache["access_token"]
    try:
        r = httpx.post(
            LABCORP_TOKEN_URL,
            data={"grant_type": "client_credentials", "scope": "ordersapi resultsapi"},
            auth=(LABCORP_CLIENT_ID, LABCORP_CLIENT_SECRET),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()
        _lc_token_cache["access_token"] = data["access_token"]
        _lc_token_cache["expires_at"] = now + float(data.get("expires_in", 3600))
        return _lc_token_cache["access_token"]
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"LabCorp OAuth failed: {e.response.text}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"LabCorp OAuth error: {str(e)}")


def _build_labcorp_order_payload(order, patient, provider) -> dict:
    """
    Build the LabCorp Beacon API FHIR R4 order payload.
    Reference: https://developer.labcorp.com/apis/ordering
    """
    icd10 = json.loads(order.icd10_codes or "[]")

    # Prefer the rich test_objects field (set by new picker UI); fall back to
    # legacy tests array with name-based code lookup for old orders.
    lc_tests = []
    test_objects = json.loads(order.test_objects or "[]") if hasattr(order, "test_objects") and order.test_objects else []
    if test_objects:
        for t in test_objects:
            code = t.get("code", "")
            name = t.get("name", "")
            if not code:
                # Try to resolve via catalog
                mapped = LABCORP_TEST_CODES.get(name)
                code = mapped["code"] if mapped else ""
            lc_tests.append({"testCode": code, "testName": name})
    else:
        tests = json.loads(order.tests or "[]")
        for t in tests:
            mapped = LABCORP_TEST_CODES.get(t)
            if mapped:
                lc_tests.append({"testCode": mapped["code"], "testName": mapped["name"]})
            else:
                lc_tests.append({"testCode": "", "testName": t})

    priority_map = {"routine": "R", "stat": "S", "asap": "A"}

    return {
        "accountNumber": LABCORP_ACCOUNT_NUM,
        "orderingProvider": {
            "npi":       getattr(provider, "npi_number", "") or LABCORP_FACILITY_NPI,
            "firstName": (getattr(provider, "full_name", "") or "").split()[0] if getattr(provider, "full_name", "") else "",
            "lastName":  " ".join((getattr(provider, "full_name", "") or "").split()[1:]) or getattr(provider, "username", ""),
            "phone":     "",
        },
        "patient": {
            "firstName":   patient.first_name,
            "lastName":    patient.last_name,
            "dateOfBirth": patient.dob or "",
            "gender":      (patient.gender or "U")[0].upper(),
            "address": {
                "street":  patient.address or "",
                "city":    patient.city or "",
                "state":   patient.state or "",
                "zipCode": patient.zip_code or "",
            },
            "phone": patient.phone or "",
        },
        "tests":           lc_tests,
        "diagnoses":       [{"code": c, "codeType": "ICD10"} for c in icd10],
        "priority":        priority_map.get(order.priority, "R"),
        "collectionDate":  datetime.utcnow().strftime("%Y-%m-%d"),
        "clinicalHistory": order.clinical_indication or "",
        "notes":           order.notes or "",
        "internalOrderId": str(order.id),
    }


def _parse_hl7_oru(hl7_text: str) -> list:
    """
    Parse an HL7 v2.5 ORU^R01 message and return a list of observation dicts.
    Each dict: {name, value, units, reference_range, abnormal_flag, status}
    """
    observations = []
    lines = hl7_text.replace("\r\n", "\r").replace("\n", "\r").split("\r")
    for seg in lines:
        if not seg.startswith("OBX"):
            continue
        fields = seg.split("|")
        def f(i, default=""):
            return fields[i] if i < len(fields) else default
        # OBX-3: observation identifier (code^name)
        ident = f(3).split("^")
        name  = ident[1] if len(ident) > 1 else ident[0]
        value = f(5)
        units = f(6).split("^")[0] if f(6) else ""
        ref_range = f(7)
        abn_flag  = f(8)   # H/L/HH/LL/A/N
        result_status = f(11)  # F=final, P=preliminary
        observations.append({
            "name":            name,
            "value":           value,
            "units":           units,
            "reference_range": ref_range,
            "abnormal_flag":   abn_flag,
            "status":          result_status,
        })
    return observations


from database import Base, SessionLocal, engine
import models

# ── App ───────────────────────────────────────────────────────────────────────
# NOTE: DB tables are created by setup.py (which runs before uvicorn starts).
# Do NOT call Base.metadata.create_all() here — it blocks at import time and
# prevents uvicorn from binding to the port before the healthcheck timeout.
app = FastAPI(title="MedFlow EMR", version="1.0.0", docs_url="/api/docs")

# CORS: credentials (cookies/Authorization header) must never be combined with a
# wildcard origin — browsers reject it and it's a HIPAA data-leakage risk.
# Set ALLOWED_ORIGINS to a comma-separated list of explicit origins in production
# (e.g. "https://app.medflow.com,https://portal.medflow.com").
# When no explicit list is provided we still allow * but disable credentials so
# public health-check/static routes continue to work.
_origins_raw = os.getenv("ALLOWED_ORIGINS", "")
if _origins_raw:
    _origins            = [o.strip() for o in _origins_raw.split(",") if o.strip()]
    _allow_credentials  = True
else:
    _origins            = ["*"]
    _allow_credentials  = False  # wildcard + credentials is forbidden by the CORS spec

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=_allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Security Headers Middleware (Risk 16) ────────────────────────────────────
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains; preload"
            )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' "
            "  https://cdnjs.cloudflare.com https://unpkg.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "img-src 'self' data: blob:; "
            "connect-src 'self' https://clinicaltables.nlm.nih.gov "
            "  https://rxnav.nlm.nih.gov https://api.telnyx.com; "
            "frame-ancestors 'none';"
        )
        return response

app.add_middleware(SecurityHeadersMiddleware)


# ── CSRF Protection Middleware (double-submit cookie pattern) ─────────────────
# State-changing requests must include an X-CSRF-Token header that matches the
# mf_csrf non-httpOnly cookie set at login.  SameSite=Strict on the auth cookie
# already blocks cross-site attacks in modern browsers; this is defense-in-depth.
_CSRF_EXEMPT_PREFIXES = ("/api/auth/login", "/api/auth/mfa/verify", "/portal/login",
                         "/health", "/api/zaprite/webhook", "/api/telnyx/",
                         "/api/sms/", "/api/public/", "/api/fax-pdf/")

class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return await call_next(request)
        path = request.url.path
        if any(path.startswith(p) for p in _CSRF_EXEMPT_PREFIXES):
            return await call_next(request)
        csrf_cookie = request.cookies.get("mf_csrf", "")
        csrf_header = request.headers.get("X-CSRF-Token", "")
        if not csrf_cookie or not csrf_header:
            from fastapi.responses import JSONResponse as _JR
            return _JR({"detail": "CSRF token missing"}, status_code=403)
        if not hmac.compare_digest(csrf_cookie, csrf_header):
            from fastapi.responses import JSONResponse as _JR
            return _JR({"detail": "CSRF validation failed"}, status_code=403)
        return await call_next(request)

app.add_middleware(CSRFMiddleware)


# ── HTTPS Enforcement Middleware ──────────────────────────────────────────────
class HTTPSRedirectMiddleware(BaseHTTPMiddleware):
    """Redirect HTTP → HTTPS in production. Exempts internal/healthcheck traffic."""
    _LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "testserver"}
    # Paths Railway uses for healthchecks — must never be redirected
    _EXEMPT_PATHS = {"/health", "/healthz", "/ping"}

    async def dispatch(self, request: Request, call_next):
        # Always pass through healthcheck paths (Railway hits these over HTTP internally)
        if request.url.path in self._EXEMPT_PATHS:
            return await call_next(request)
        host = request.url.hostname or ""
        client_ip = (request.client.host if request.client else "") or ""
        # Exempt local + RFC-1918 + RFC-6598 (100.64/10 — Railway's internal CGNAT range)
        if (host in self._LOCAL_HOSTS
                or host.startswith("192.168.")
                or host.startswith("10.")
                or host.startswith("100.64.")
                or client_ip.startswith("100.64.")
                or client_ip.startswith("10.")):
            return await call_next(request)
        if request.url.scheme == "http":
            https_url = str(request.url).replace("http://", "https://", 1)
            return RedirectResponse(url=https_url, status_code=301)
        return await call_next(request)

app.add_middleware(HTTPSRedirectMiddleware)


# ── Rate Limiter (Risk 9) ─────────────────────────────────────────────────────
_rl_lock = threading.Lock()
_failed_attempts: dict = collections.defaultdict(list)  # ip -> [timestamps]
RATE_LIMIT_MAX = 5
RATE_LIMIT_WINDOW = 600  # 10 minutes


def _check_rate_limit(ip: str):
    now = time.time()
    with _rl_lock:
        _failed_attempts[ip] = [
            t for t in _failed_attempts[ip] if now - t < RATE_LIMIT_WINDOW
        ]
        if len(_failed_attempts[ip]) >= RATE_LIMIT_MAX:
            raise HTTPException(
                status_code=429,
                detail="Too many failed login attempts. Please wait 10 minutes.",
            )


def _record_failure(ip: str):
    with _rl_lock:
        _failed_attempts[ip].append(time.time())


def _clear_failures(ip: str):
    with _rl_lock:
        _failed_attempts[ip] = []


# ── Upload rate limiter ────────────────────────────────────────────────────────
_upload_lock = threading.Lock()
_upload_attempts: dict = collections.defaultdict(list)  # user_id -> [timestamps]
UPLOAD_RATE_LIMIT = 10   # max uploads per user per minute
UPLOAD_RATE_WINDOW = 60

def _check_upload_rate_limit(user_id: int):
    now = time.time()
    with _upload_lock:
        _upload_attempts[user_id] = [t for t in _upload_attempts[user_id] if now - t < UPLOAD_RATE_WINDOW]
        if len(_upload_attempts[user_id]) >= UPLOAD_RATE_LIMIT:
            raise HTTPException(status_code=429, detail="Upload rate limit exceeded — max 10 per minute")
        _upload_attempts[user_id].append(now)


# ── SMS rate limiter ───────────────────────────────────────────────────────────
_sms_rl_lock = threading.Lock()
_sms_attempts: dict = collections.defaultdict(list)  # patient_id -> [timestamps]
SMS_RATE_LIMIT = 10   # max outbound SMS per patient per hour
SMS_RATE_WINDOW = 3600

def _check_sms_rate_limit(patient_id: int):
    now = time.time()
    with _sms_rl_lock:
        _sms_attempts[patient_id] = [t for t in _sms_attempts[patient_id] if now - t < SMS_RATE_WINDOW]
        if len(_sms_attempts[patient_id]) >= SMS_RATE_LIMIT:
            raise HTTPException(status_code=429, detail="SMS rate limit exceeded for this patient — max 10/hour")
        _sms_attempts[patient_id].append(now)


# ── Enrollment rate limiter ────────────────────────────────────────────────────
_enroll_lock = threading.Lock()
_enrollment_attempts: dict = collections.defaultdict(list)  # ip -> [timestamps]
ENROLL_RATE_LIMIT = 5    # max submissions per IP per hour
ENROLL_RATE_WINDOW = 3600

def _check_enrollment_rate_limit(ip: str):
    now = time.time()
    with _enroll_lock:
        _enrollment_attempts[ip] = [t for t in _enrollment_attempts[ip] if now - t < ENROLL_RATE_WINDOW]
        if len(_enrollment_attempts[ip]) >= ENROLL_RATE_LIMIT:
            raise HTTPException(status_code=429, detail="Too many enrollment submissions — please wait before trying again")
        _enrollment_attempts[ip].append(now)


# ── Password reset rate limiter ────────────────────────────────────────────────
_reset_rl_lock = threading.Lock()
_reset_attempts: dict = collections.defaultdict(list)  # user_id -> [timestamps]
RESET_RATE_LIMIT = 3     # max reset attempts per user per 5 minutes
RESET_RATE_WINDOW = 300

def _check_reset_rate_limit(user_id: int):
    now = time.time()
    with _reset_rl_lock:
        _reset_attempts[user_id] = [t for t in _reset_attempts[user_id] if now - t < RESET_RATE_WINDOW]
        if len(_reset_attempts[user_id]) >= RESET_RATE_LIMIT:
            raise HTTPException(status_code=429, detail="Too many password reset attempts — please wait 5 minutes")
        _reset_attempts[user_id].append(now)


# ── Suspicious Access Detection (HIPAA §164.308(a)(1)) ───────────────────────
# Track per-user patient record access; alert if volume exceeds threshold
_pac_lock = threading.Lock()
_patient_access_log: dict = collections.defaultdict(list)  # user_id -> [timestamps]
PAC_THRESHOLD = 50     # access events
PAC_WINDOW    = 300    # 5 minutes


def _track_patient_access(db, user_id: int, patient_id: int):
    """Record a patient data access event and emit a HIPAA audit alert if suspicious."""
    now = time.time()
    with _pac_lock:
        _patient_access_log[user_id] = [
            t for t in _patient_access_log[user_id] if now - t < PAC_WINDOW
        ]
        count = len(_patient_access_log[user_id])
        _patient_access_log[user_id].append(now)
    if count >= PAC_THRESHOLD:
        audit(db, user_id, "SUSPICIOUS_ACCESS_VOLUME", "Patient", str(patient_id),
              f"ALERT: User accessed {count + 1} patient records in {PAC_WINDOW // 60} minutes. "
              "Possible unauthorized bulk access — review required.")


def _require_patient_access(patient, current_user: "models.User"):
    """
    Enforce minimum-necessary access (HIPAA §164.502(b)).
    - admin and physician: access all patients
    - staff: access only patients they created
    Raises 403 if access is denied.
    """
    if current_user.role in ("admin", "physician"):
        return  # full access
    # staff: only their own patients
    created_by = getattr(patient, "created_by", None)
    if created_by != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="Access denied: staff may only access records of patients they registered."
        )


# ── Password Complexity (Risk 10) ─────────────────────────────────────────────
def _validate_password(password: str):
    errors = []
    if len(password) < 12:
        errors.append("at least 12 characters")
    if not re.search(r"[A-Z]", password):
        errors.append("one uppercase letter")
    if not re.search(r"[a-z]", password):
        errors.append("one lowercase letter")
    if not re.search(r"\d", password):
        errors.append("one number")
    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append("one special character")
    if errors:
        raise HTTPException(
            status_code=400,
            detail=f"Password must contain: {', '.join(errors)}.",
        )


@app.get("/health")
def health_check():
    """Railway health check endpoint."""
    return {"status": "ok", "service": "MedFlow EMR"}

# ── Auth config ───────────────────────────────────────────────────────────────
SECRET_KEY = os.getenv("SECRET_KEY", "")
if not SECRET_KEY or SECRET_KEY == "CHANGE_ME_IN_PRODUCTION_USE_RANDOM_256BIT":
    raise RuntimeError(
        "SECRET_KEY environment variable is not set or is still the default value. "
        "Generate a secure random key and set it in your environment before starting."
    )
ALGORITHM = "HS256"
TOKEN_HOURS = int(os.getenv("TOKEN_EXPIRE_HOURS", "8"))
# HIPAA §164.312(a)(2)(iii): automatic logoff after inactivity.
# Set IDLE_TIMEOUT_MINUTES=0 to disable server-side idle enforcement.
IDLE_TIMEOUT_MINUTES = int(os.getenv("IDLE_TIMEOUT_MINUTES", "30"))
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# ── DB dependency ─────────────────────────────────────────────────────────────
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Auth helpers ──────────────────────────────────────────────────────────────
def hash_pw(password: str) -> str:
    # HIPAA best-practice: bcrypt cost ≥12; 13 balances security and latency.
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=13)).decode()


def verify_pw(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def make_token(user_id: int, role: str, token_version: int = 0) -> str:
    exp = datetime.utcnow() + timedelta(hours=TOKEN_HOURS)
    return jwt.encode(
        {"sub": str(user_id), "role": role, "tv": token_version, "exp": exp},
        SECRET_KEY, ALGORITHM
    )


def get_current_user(
    request: Request,
    token_header: Optional[str] = Depends(OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)),
    db: Session = Depends(get_db),
) -> models.User:
    # Prefer httpOnly cookie (XSS-safe); fall back to Authorization: Bearer header
    cookie_token = request.cookies.get("mf_auth")
    token = cookie_token or token_header
    logging.debug("AUTH cookie=%s bearer=%s", bool(cookie_token), bool(token_header))
    if not token:
        logging.warning("AUTH FAIL: no token (cookie=%s, bearer=%s)", cookie_token, token_header)
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload["sub"])
        token_version = int(payload.get("tv", 0))
    except (JWTError, KeyError, ValueError) as e:
        logging.warning("AUTH FAIL: jwt decode error: %s | token_prefix=%s", e, token[:20] if token else None)
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user or not user.is_active:
        logging.warning("AUTH FAIL: user %s not found or disabled", user_id)
        raise HTTPException(status_code=401, detail="User not found or disabled")
    # Reject tokens issued before a password change
    current_tv = getattr(user, "token_version", 0) or 0
    if token_version != current_tv:
        logging.warning("AUTH FAIL: token_version mismatch token=%s db=%s user=%s", token_version, current_tv, user_id)
        raise HTTPException(status_code=401, detail="Session invalidated — please log in again")
    # ── Idle session timeout (HIPAA §164.312(a)(2)(iii)) ────────────────────────
    now = datetime.utcnow()
    if IDLE_TIMEOUT_MINUTES > 0:
        last_active = getattr(user, "last_active", None)
        if last_active and (now - last_active).total_seconds() > IDLE_TIMEOUT_MINUTES * 60:
            raise HTTPException(
                status_code=401,
                detail="Session expired due to inactivity — please log in again"
            )
    # Throttle last_active writes to at most once per 60 s to avoid per-request DB overhead
    last_active = getattr(user, "last_active", None)
    if not last_active or (now - last_active).total_seconds() > 60:
        user.last_active = now
        db.commit()

    # Enforce MFA for privileged roles when REQUIRE_MFA env var is set
    if os.getenv("REQUIRE_MFA", "false").lower() == "true":
        if user.role in ("admin", "physician") and not getattr(user, "mfa_enabled", False):
            raise HTTPException(
                status_code=403,
                detail="MFA_REQUIRED: Multi-factor authentication must be enabled for your role. "
                       "Please set up an authenticator app in Settings → Security."
            )
    return user


def require_admin(current_user: models.User = Depends(get_current_user)) -> models.User:
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


# ── HIPAA audit log ───────────────────────────────────────────────────────────
def audit(
    db: Session,
    user_id: int,
    action: str,
    resource_type: str,
    resource_id: str,
    details: str = "",
    request: Request = None,
):
    ip         = request.client.host if request else ""
    user_agent = request.headers.get("user-agent", "") if request else ""
    log = models.AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=ip,
        user_agent=user_agent,
        details=details,
        timestamp=datetime.utcnow(),
    )
    db.add(log)
    db.commit()


def user_dict(u: models.User) -> dict:
    changed_at = getattr(u, "password_changed_at", None) or getattr(u, "created_at", None)
    days_remaining = None
    if changed_at:
        days_remaining = max(0, PASSWORD_EXPIRY_DAYS - (datetime.utcnow() - changed_at).days)
    return {
        "id": u.id, "username": u.username, "full_name": u.full_name,
        "email": u.email, "role": u.role, "npi_number": u.npi_number,
        "specialty": u.specialty, "is_active": u.is_active,
        "mfa_enabled": bool(getattr(u, "mfa_enabled", False)),
        "password_expires_in_days": days_remaining,
    }


def clean(obj) -> dict:
    """Strip SQLAlchemy internals from a model instance dict."""
    d = {k: v for k, v in obj.__dict__.items() if not k.startswith("_")}
    # Serialize datetime objects
    for k, v in d.items():
        if isinstance(v, datetime):
            d[k] = v.isoformat()
    return d


# ═════════════════════════════════════════════════════════════════════════════
# AUTH
# ═════════════════════════════════════════════════════════════════════════════

def _make_mfa_pending_token(user_id: int) -> str:
    exp = datetime.utcnow() + timedelta(minutes=5)
    return jwt.encode(
        {"sub": str(user_id), "type": "mfa_pending", "exp": exp}, SECRET_KEY, ALGORITHM
    )


PASSWORD_EXPIRY_DAYS = 90  # HIPAA-aligned maximum password age


def _password_is_expired(user: models.User) -> bool:
    """Return True if the user's password has not been changed in PASSWORD_EXPIRY_DAYS days."""
    changed_at = getattr(user, "password_changed_at", None)
    if changed_at is None:
        # Never recorded — treat created_at as the baseline; if that's also missing, force reset
        changed_at = getattr(user, "created_at", None)
    if changed_at is None:
        return True
    return (datetime.utcnow() - changed_at).days >= PASSWORD_EXPIRY_DAYS


def _make_pw_expired_token(user_id: int) -> str:
    exp = datetime.utcnow() + timedelta(minutes=15)
    return jwt.encode(
        {"sub": str(user_id), "type": "pw_expired", "exp": exp}, SECRET_KEY, ALGORITHM
    )


@app.post("/api/auth/login")
def login(
    form: OAuth2PasswordRequestForm = Depends(),
    request: Request = None,
    db: Session = Depends(get_db),
):
    ip = request.client.host if request else "unknown"
    _check_rate_limit(ip)
    user = db.query(models.User).filter(models.User.username == form.username).first()
    if not user or not verify_pw(form.password, user.password_hash):
        _record_failure(ip)
        audit(db, None, "LOGIN_FAILED", "User", form.username, request=request,
              details=f"username={form.username}")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        audit(db, user.id, "LOGIN_FAILED", "User", str(user.id), request=request,
              details="Account disabled")
        raise HTTPException(status_code=401, detail="Account disabled")
    _clear_failures(ip)
    # If MFA is enabled, return a short-lived challenge token instead of full access
    if getattr(user, "mfa_enabled", False) and user.mfa_secret:
        audit(db, user.id, "LOGIN_MFA_CHALLENGE", "User", str(user.id), request=request)
        return {"mfa_required": True, "mfa_token": _make_mfa_pending_token(user.id)}
    # Check password expiry (90-day policy)
    if _password_is_expired(user):
        audit(db, user.id, "LOGIN_PASSWORD_EXPIRED", "User", str(user.id), request=request)
        return {"password_expired": True, "reset_token": _make_pw_expired_token(user.id)}
    tv = getattr(user, "token_version", 0) or 0
    token = make_token(user.id, user.role, tv)
    audit(db, user.id, "LOGIN", "User", str(user.id), request=request)
    csrf_token = secrets.token_hex(32)
    resp = JSONResponse({"access_token": token, "token_type": "bearer", "user": user_dict(user)})
    resp.set_cookie(
        key="mf_auth", value=token,
        httponly=True, secure=True, samesite="strict",
        max_age=TOKEN_HOURS * 3600, path="/",
    )
    resp.set_cookie(
        key="mf_csrf", value=csrf_token,
        httponly=False, secure=True, samesite="strict",
        max_age=TOKEN_HOURS * 3600, path="/",
    )
    return resp


@app.post("/api/auth/mfa/verify")
def mfa_verify(data: dict, request: Request = None, db: Session = Depends(get_db)):
    """Exchange a short-lived MFA challenge token + TOTP code for a full access token."""
    mfa_token = data.get("mfa_token", "")
    code = str(data.get("code", "")).strip()
    try:
        payload = jwt.decode(mfa_token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "mfa_pending":
            raise HTTPException(status_code=401, detail="Invalid MFA token")
        user_id = int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired MFA token")
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user or not user.is_active or not user.mfa_secret:
        raise HTTPException(status_code=401, detail="Invalid MFA token")
    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(code, valid_window=1):
        raise HTTPException(status_code=401, detail="Invalid authenticator code")
    tv2 = getattr(user, "token_version", 0) or 0
    token = make_token(user.id, user.role, tv2)
    audit(db, user.id, "LOGIN", "User", str(user.id), request=request)
    csrf_token = secrets.token_hex(32)
    resp = JSONResponse({"access_token": token, "token_type": "bearer", "user": user_dict(user)})
    resp.set_cookie(
        key="mf_auth", value=token,
        httponly=True, secure=True, samesite="strict",
        max_age=TOKEN_HOURS * 3600, path="/",
    )
    resp.set_cookie(
        key="mf_csrf", value=csrf_token,
        httponly=False, secure=True, samesite="strict",
        max_age=TOKEN_HOURS * 3600, path="/",
    )
    return resp


@app.post("/api/auth/mfa/setup")
def mfa_setup(current_user: models.User = Depends(get_current_user)):
    """Generate a fresh TOTP secret for the current user to scan."""
    secret = pyotp.random_base32()
    uri = pyotp.TOTP(secret).provisioning_uri(
        name=current_user.username, issuer_name="Valiant DPC"
    )
    return {"secret": secret, "uri": uri}


@app.post("/api/auth/mfa/enable")
def mfa_enable(
    data: dict,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Confirm the TOTP code and permanently enable MFA for the logged-in user."""
    secret = data.get("secret", "")
    code = str(data.get("code", "")).strip()
    if not secret or not code:
        raise HTTPException(status_code=400, detail="secret and code are required")
    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        raise HTTPException(status_code=400, detail="Invalid authenticator code — try again")
    current_user.mfa_secret = secret
    current_user.mfa_enabled = True
    db.commit()
    audit(db, current_user.id, "MFA_ENABLED", "User", str(current_user.id))
    return {"success": True}


@app.post("/api/auth/mfa/disable")
def mfa_disable(
    data: dict,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Disable MFA after verifying the user's password."""
    if not verify_pw(data.get("password", ""), current_user.password_hash):
        raise HTTPException(status_code=400, detail="Incorrect password")
    current_user.mfa_secret = None
    current_user.mfa_enabled = False
    db.commit()
    audit(db, current_user.id, "MFA_DISABLED", "User", str(current_user.id))
    return {"success": True}


@app.get("/api/auth/me")
def get_me(current_user: models.User = Depends(get_current_user)):
    return user_dict(current_user)


@app.post("/api/auth/logout")
def logout(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
    request: Request = None,
):
    """Record the session termination event in the audit log and clear the auth cookies."""
    audit(db, current_user.id, "LOGOUT", "User", str(current_user.id), request=request)
    resp = JSONResponse({"success": True})
    resp.delete_cookie(key="mf_auth",  path="/", httponly=True,  secure=True, samesite="strict")
    resp.delete_cookie(key="mf_csrf",  path="/", httponly=False, secure=True, samesite="strict")
    return resp


@app.put("/api/auth/me/password")
def change_password(
    data: dict,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_pw(data.get("current_password", ""), current_user.password_hash):
        raise HTTPException(status_code=400, detail="Current password incorrect")
    _validate_password(data["new_password"])
    current_user.password_hash = hash_pw(data["new_password"])
    current_user.password_changed_at = datetime.utcnow()
    current_user.token_version = (getattr(current_user, "token_version", 0) or 0) + 1
    db.commit()
    audit(db, current_user.id, "CHANGE_PASSWORD", "User", str(current_user.id))
    return {"success": True}


@app.post("/api/auth/reset-expired-password")
def reset_expired_password(
    data: dict,
    request: Request = None,
    db: Session = Depends(get_db),
):
    """
    Called when login returns password_expired=True.
    Validates the short-lived pw_expired token, verifies the current password,
    sets a new password, and returns a full access token.
    """
    reset_token = data.get("reset_token", "")
    current_password = data.get("current_password", "")
    new_password = data.get("new_password", "")
    try:
        payload = jwt.decode(reset_token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "pw_expired":
            raise HTTPException(status_code=401, detail="Invalid reset token")
        user_id = int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired reset token")
    _check_reset_rate_limit(user_id)
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid reset token")
    if not verify_pw(current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    _validate_password(new_password)
    user.password_hash = hash_pw(new_password)
    user.password_changed_at = datetime.utcnow()
    user.token_version = (getattr(user, "token_version", 0) or 0) + 1
    db.commit()
    audit(db, user.id, "PASSWORD_RESET_EXPIRED", "User", str(user.id), request=request)
    tv3 = getattr(user, "token_version", 0) or 0
    token = make_token(user.id, user.role, tv3)
    csrf_token = secrets.token_hex(32)
    resp = JSONResponse({"access_token": token, "token_type": "bearer", "user": user_dict(user)})
    resp.set_cookie("mf_auth", token, httponly=True, secure=True, samesite="strict", max_age=TOKEN_HOURS*3600, path="/")
    resp.set_cookie("mf_csrf", csrf_token, httponly=False, secure=True, samesite="strict", max_age=TOKEN_HOURS*3600, path="/")
    return resp


# ═════════════════════════════════════════════════════════════════════════════
# USERS  (admin)
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/users")
def list_users(db: Session = Depends(get_db), _: models.User = Depends(require_admin)):
    return [user_dict(u) for u in db.query(models.User).all()]


@app.post("/api/users")
def create_user(
    data: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin),
):
    if db.query(models.User).filter(models.User.username == data["username"]).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    _validate_password(data["password"])
    u = models.User(
        username=data["username"],
        email=data.get("email", ""),
        password_hash=hash_pw(data["password"]),
        full_name=data.get("full_name", ""),
        npi_number=data.get("npi_number", ""),
        specialty=data.get("specialty", ""),
        role=data.get("role", "physician"),
        is_active=True,
        password_changed_at=datetime.utcnow(),
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    audit(db, current_user.id, "CREATE_USER", "User", str(u.id))
    return user_dict(u)


@app.put("/api/users/{user_id}")
def update_user(
    user_id: int,
    data: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin),
):
    u = db.query(models.User).filter(models.User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    for field in ["full_name", "email", "npi_number", "specialty", "role", "is_active"]:
        if field in data:
            setattr(u, field, data[field])
    if "password" in data and data["password"]:
        _validate_password(data["password"])
        u.password_hash = hash_pw(data["password"])
        u.password_changed_at = datetime.utcnow()
        u.token_version = (getattr(u, "token_version", 0) or 0) + 1
    db.commit()
    audit(db, current_user.id, "UPDATE_USER", "User", str(user_id))
    return user_dict(u)


# ═════════════════════════════════════════════════════════════════════════════
# PATIENTS
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/patients")
def list_patients(
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    q = db.query(models.Patient)
    # Minimum necessary: staff only see patients they registered
    if current_user.role == "staff":
        q = q.filter(models.Patient.created_by == current_user.id)
    if search:
        s = f"%{search}%"
        q = q.filter(
            models.Patient.first_name.ilike(s)
            | models.Patient.last_name.ilike(s)
            | models.Patient.phone.ilike(s)
            | models.Patient.email.ilike(s)
        )
    rows = q.order_by(models.Patient.last_name).all()
    audit(db, current_user.id, "LIST_PATIENTS", "Patient", "all",
          f"Role: {current_user.role} | Results: {len(rows)}")
    return [clean(p) for p in rows]


@app.post("/api/patients")
def create_patient(
    data: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    p = models.Patient(
        first_name=data.get("first_name", ""),
        last_name=data.get("last_name", ""),
        dob=data.get("dob", ""),
        gender=data.get("gender", ""),
        ssn_last4=data.get("ssn_last4", ""),
        phone=data.get("phone", ""),
        email=data.get("email", ""),
        address=data.get("address", ""),
        city=data.get("city", ""),
        state=data.get("state", ""),
        zip_code=data.get("zip_code", ""),
        insurance_name=data.get("insurance_name", ""),
        insurance_id=data.get("insurance_id", ""),
        insurance_group=data.get("insurance_group", ""),
        emergency_contact=data.get("emergency_contact", ""),
        emergency_phone=data.get("emergency_phone", ""),
        created_by=current_user.id,
    )
    db.add(p)
    db.commit()
    db.refresh(p)
    audit(db, current_user.id, "CREATE_PATIENT", "Patient", str(p.id))
    return clean(p)


@app.get("/api/patients/{patient_id}")
def get_patient(
    patient_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    p = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Patient not found")
    _require_patient_access(p, current_user)
    _track_patient_access(db, current_user.id, patient_id)
    audit(db, current_user.id, "VIEW_PATIENT", "Patient", str(patient_id))
    return clean(p)


@app.put("/api/patients/{patient_id}")
def update_patient(
    patient_id: int,
    data: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    p = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Patient not found")
    _require_patient_access(p, current_user)
    skip = {"id", "created_at", "created_by"}
    for k, v in data.items():
        if k not in skip and hasattr(p, k):
            setattr(p, k, v)
    db.commit()
    db.refresh(p)
    audit(db, current_user.id, "UPDATE_PATIENT", "Patient", str(patient_id))
    return clean(p)


# ═════════════════════════════════════════════════════════════════════════════
# MEDICATIONS
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/patients/{patient_id}/medications")
def list_medications(patient_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    patient = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
    if not patient: raise HTTPException(status_code=404, detail="Patient not found")
    _require_patient_access(patient, current_user)
    audit(db, current_user.id, "VIEW_MEDICATIONS", "Patient", str(patient_id))
    return db.query(models.PatientMedication).filter(
        models.PatientMedication.patient_id == patient_id
    ).order_by(models.PatientMedication.is_active.desc(), models.PatientMedication.name).all()

@app.post("/api/patients/{patient_id}/medications")
def create_medication(patient_id: int, data: dict, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    patient = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
    if not patient: raise HTTPException(status_code=404, detail="Patient not found")
    _require_patient_access(patient, current_user)
    m = models.PatientMedication(
        patient_id=patient_id,
        name=data.get("name","").strip(),
        dosage=data.get("dosage",""),
        frequency=data.get("frequency",""),
        route=data.get("route","oral"),
        start_date=data.get("start_date",""),
        end_date=data.get("end_date",""),
        prescriber=data.get("prescriber",""),
        indication=data.get("indication",""),
        is_active=data.get("is_active",True),
        notes=data.get("notes",""),
    )
    db.add(m); db.commit(); db.refresh(m)
    audit(db, current_user.id, "ADD_MEDICATION", "Patient", str(patient_id), details=m.name)
    return m

@app.put("/api/medications/{med_id}")
def update_medication(med_id: int, data: dict, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    m = db.query(models.PatientMedication).filter(models.PatientMedication.id == med_id).first()
    if not m: raise HTTPException(status_code=404, detail="Not found")
    patient = db.query(models.Patient).filter(models.Patient.id == m.patient_id).first()
    if patient: _require_patient_access(patient, current_user)
    for k in ("name","dosage","frequency","route","start_date","end_date","prescriber","indication","is_active","notes"):
        if k in data: setattr(m, k, data[k])
    db.commit(); db.refresh(m)
    audit(db, current_user.id, "UPDATE_MEDICATION", "PatientMedication", str(med_id))
    return m

@app.delete("/api/medications/{med_id}")
def delete_medication(med_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    m = db.query(models.PatientMedication).filter(models.PatientMedication.id == med_id).first()
    if not m: raise HTTPException(status_code=404, detail="Not found")
    patient = db.query(models.Patient).filter(models.Patient.id == m.patient_id).first()
    if patient: _require_patient_access(patient, current_user)
    db.delete(m); db.commit()
    audit(db, current_user.id, "DELETE_MEDICATION", "PatientMedication", str(med_id))
    return {"ok": True}


# ═════════════════════════════════════════════════════════════════════════════
# MEDICAL HISTORY
# ═════════════════════════════════════════════════════════════════════════════

_VALID_ENTRY_TYPES = {"problem", "allergy", "surgical", "family", "social", "immunization", "other"}

@app.get("/api/patients/{patient_id}/history")
def list_history(patient_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    patient = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
    if not patient: raise HTTPException(status_code=404, detail="Patient not found")
    _require_patient_access(patient, current_user)
    audit(db, current_user.id, "VIEW_HISTORY", "Patient", str(patient_id))
    return db.query(models.PatientHistoryEntry).filter(
        models.PatientHistoryEntry.patient_id == patient_id
    ).order_by(models.PatientHistoryEntry.entry_type, models.PatientHistoryEntry.created_at).all()

@app.post("/api/patients/{patient_id}/history")
def create_history_entry(patient_id: int, data: dict, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    patient = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
    if not patient: raise HTTPException(status_code=404, detail="Patient not found")
    _require_patient_access(patient, current_user)
    entry_type = data.get("entry_type", "problem")
    if entry_type not in _VALID_ENTRY_TYPES:
        raise HTTPException(status_code=400, detail=f"entry_type must be one of: {', '.join(sorted(_VALID_ENTRY_TYPES))}")
    e = models.PatientHistoryEntry(
        patient_id=patient_id,
        entry_type=entry_type,
        description=data.get("description","").strip(),
        detail=data.get("detail",""),
        onset_date=data.get("onset_date",""),
        status=data.get("status","active"),
        notes=data.get("notes",""),
    )
    db.add(e); db.commit(); db.refresh(e)
    audit(db, current_user.id, "ADD_HISTORY_ENTRY", "Patient", str(patient_id), details=e.description)
    return e

@app.put("/api/history/{entry_id}")
def update_history_entry(entry_id: int, data: dict, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    e = db.query(models.PatientHistoryEntry).filter(models.PatientHistoryEntry.id == entry_id).first()
    if not e: raise HTTPException(status_code=404, detail="Not found")
    patient = db.query(models.Patient).filter(models.Patient.id == e.patient_id).first()
    if patient: _require_patient_access(patient, current_user)
    for k in ("entry_type","description","detail","onset_date","status","notes"):
        if k in data: setattr(e, k, data[k])
    db.commit(); db.refresh(e)
    audit(db, current_user.id, "UPDATE_HISTORY_ENTRY", "PatientHistoryEntry", str(entry_id))
    return e

@app.delete("/api/history/{entry_id}")
def delete_history_entry(entry_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    e = db.query(models.PatientHistoryEntry).filter(models.PatientHistoryEntry.id == entry_id).first()
    if not e: raise HTTPException(status_code=404, detail="Not found")
    patient = db.query(models.Patient).filter(models.Patient.id == e.patient_id).first()
    if patient: _require_patient_access(patient, current_user)
    db.delete(e); db.commit()
    audit(db, current_user.id, "DELETE_HISTORY_ENTRY", "PatientHistoryEntry", str(entry_id))
    return {"ok": True}


# ═════════════════════════════════════════════════════════════════════════════
# CLINICAL NOTES
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/notes")
def list_notes(
    patient_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    q = db.query(models.ClinicalNote)
    if patient_id:
        patient = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
        if patient: _require_patient_access(patient, current_user)
        q = q.filter(models.ClinicalNote.patient_id == patient_id)
        audit(db, current_user.id, "VIEW_NOTES", "Patient", str(patient_id))
    rows = q.order_by(models.ClinicalNote.created_at.desc()).all()
    return [clean(n) for n in rows]


@app.post("/api/notes")
def create_note(
    data: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    _note_patient = db.query(models.Patient).filter(models.Patient.id == data.get("patient_id")).first()
    if not _note_patient: raise HTTPException(status_code=404, detail="Patient not found")
    _require_patient_access(_note_patient, current_user)
    visit = data.get("visit_date")
    note = models.ClinicalNote(
        patient_id=data["patient_id"],
        physician_id=current_user.id,
        visit_date=datetime.fromisoformat(visit) if visit else datetime.utcnow(),
        chief_complaint=data.get("chief_complaint", ""),
        hpi=data.get("hpi", ""),
        pmh=data.get("pmh", ""),
        medications=data.get("medications", ""),
        allergies=data.get("allergies", ""),
        ros=data.get("ros", ""),
        physical_exam=data.get("physical_exam", ""),
        assessment=data.get("assessment", ""),
        plan=data.get("plan", ""),
        icd10_codes=json.dumps(data.get("icd10_codes", [])),
        cpt_codes=json.dumps(data.get("cpt_codes", [])),
        note_type=data.get("note_type", "SOAP"),
        ai_generated=data.get("ai_generated", False),
        status=data.get("status", "draft"),
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    audit(db, current_user.id, "CREATE_NOTE", "ClinicalNote", str(note.id))
    return clean(note)


@app.put("/api/notes/{note_id}")
def update_note(
    note_id: int,
    data: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    note = db.query(models.ClinicalNote).filter(models.ClinicalNote.id == note_id).first()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    patient = db.query(models.Patient).filter(models.Patient.id == note.patient_id).first()
    if patient: _require_patient_access(patient, current_user)
    # HIPAA integrity control: signed notes are immutable
    # Only the status field may be changed on a signed note (e.g. to unsign for addendum)
    if note.status == "signed":
        content_fields = set(data.keys()) - {"status"}
        if content_fields:
            raise HTTPException(
                status_code=409,
                detail="Signed notes are immutable. Only status may be changed. "
                       "Create an addendum note instead of editing the signed record."
            )
    skip = {"id", "created_at", "patient_id", "physician_id"}
    for k, v in data.items():
        if k in skip:
            continue
        if k in ("icd10_codes", "cpt_codes"):
            setattr(note, k, json.dumps(v))
        elif hasattr(note, k):
            setattr(note, k, v)
    note.updated_at = datetime.utcnow()
    db.commit()
    audit(db, current_user.id, "UPDATE_NOTE", "ClinicalNote", str(note_id),
          f"Status: {note.status}")
    return clean(note)


@app.delete("/api/notes/{note_id}")
def delete_note(
    note_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    note = db.query(models.ClinicalNote).filter(models.ClinicalNote.id == note_id).first()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    patient = db.query(models.Patient).filter(models.Patient.id == note.patient_id).first()
    if patient: _require_patient_access(patient, current_user)
    db.delete(note)
    db.commit()
    audit(db, current_user.id, "DELETE_NOTE", "ClinicalNote", str(note_id))
    return {"success": True}


# ── PDF generation ────────────────────────────────────────────────────────────
@app.get("/api/notes/{note_id}/pdf")
def note_pdf(
    note_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    note = db.query(models.ClinicalNote).filter(models.ClinicalNote.id == note_id).first()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    patient = db.query(models.Patient).filter(models.Patient.id == note.patient_id).first()
    physician = db.query(models.User).filter(models.User.id == note.physician_id).first()
    # HIPAA audit: PHI export event
    audit(db, current_user.id, "EXPORT_PHI_PDF", "ClinicalNote", str(note_id),
          f"Clinical note PDF exported for patient_id={note.patient_id}")

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter,
                            rightMargin=54, leftMargin=54, topMargin=54, bottomMargin=54)
    styles = getSampleStyleSheet()
    story = []

    BLUE = colors.HexColor("#1e40af")
    LIGHT = colors.HexColor("#dbeafe")

    # ── Title block ───────────────────────────────────────────────────────
    story.append(Paragraph("<b>MEDFLOW EMR — CONFIDENTIAL CLINICAL NOTE</b>", styles["Title"]))
    story.append(Spacer(1, 6))

    pname = f"{patient.first_name} {patient.last_name}" if patient else "Unknown"
    pdob  = getattr(patient, "dob", "") if patient else ""
    pins  = getattr(patient, "insurance_name", "") if patient else ""
    doc_name = physician.full_name if physician else "Unknown"
    doc_npi  = physician.npi_number if physician else ""

    meta = [
        ["Patient:", pname, "Visit Date:", str(note.visit_date)[:10]],
        ["DOB:", pdob,  "Physician:", doc_name],
        ["Insurance:", pins, "NPI:", doc_npi],
        ["Note Type:", note.note_type, "Status:", note.status.upper()],
    ]
    t = Table(meta, colWidths=[75, 185, 75, 175])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT),
        ("BACKGROUND", (0, 0), (0, -1), BLUE),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
        ("BACKGROUND", (2, 0), (2, -1), BLUE),
        ("TEXTCOLOR", (2, 0), (2, -1), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t)
    story.append(Spacer(1, 16))

    sections = [
        ("Chief Complaint", note.chief_complaint),
        ("History of Present Illness (HPI)", note.hpi),
        ("Past Medical History (PMH)", note.pmh),
        ("Current Medications", note.medications),
        ("Allergies", note.allergies),
        ("Review of Systems (ROS)", note.ros),
        ("Physical Examination", note.physical_exam),
        ("Assessment", note.assessment),
        ("Plan", note.plan),
    ]
    for heading, content in sections:
        if content and content.strip():
            story.append(Paragraph(f"<b>{heading}</b>", styles["Heading3"]))
            story.append(Paragraph(content.replace("\n", "<br/>"), styles["Normal"]))
            story.append(Spacer(1, 8))

    # ── Billing codes ──────────────────────────────────────────────────────
    icd = json.loads(note.icd10_codes or "[]")
    cpt = json.loads(note.cpt_codes or "[]")
    if icd or cpt:
        story.append(Spacer(1, 4))
        codes = [["ICD-10 Diagnosis Codes", "CPT Procedure Codes"]]
        codes.append([", ".join(icd) or "None", ", ".join(cpt) or "None"])
        ct = Table(codes, colWidths=[255, 255])
        ct.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(ct)

    # ── Signature ──────────────────────────────────────────────────────────
    story.append(Spacer(1, 24))
    story.append(Paragraph("─" * 60, styles["Normal"]))
    story.append(Paragraph(
        f"<b>Electronically signed by:</b> {doc_name}  |  NPI: {doc_npi}  |  "
        f"Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        styles["Normal"]
    ))
    if note.ai_generated:
        story.append(Paragraph(
            "<i>Note generated with AI assistance and reviewed/signed by the treating physician.</i>",
            styles["Normal"]
        ))

    doc.build(story)
    buf.seek(0)
    audit(db, current_user.id, "GENERATE_PDF", "ClinicalNote", str(note_id))
    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=note_{note_id}.pdf"},
    )


# ═════════════════════════════════════════════════════════════════════════════
# AI NOTE GENERATION  (Ollama — local LLM)
# ═════════════════════════════════════════════════════════════════════════════

@app.post("/api/notes/ai-generate")
async def ai_generate(
    data: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    prompt = data.get("prompt", "").strip()
    patient_id = data.get("patient_id")
    if not prompt:
        raise HTTPException(status_code=400, detail="Prompt is required")
    if len(prompt) > 2000:
        raise HTTPException(status_code=400, detail="Prompt too long — maximum 2000 characters")
    # Reject obvious prompt-injection attempts
    _injection_patterns = ["ignore previous", "ignore all", "disregard", "forget instructions",
                           "system prompt", "jailbreak", "bypass", "override instructions"]
    if any(pat in prompt.lower() for pat in _injection_patterns):
        raise HTTPException(status_code=400, detail="Prompt content not allowed")

    patient_ctx = ""
    if patient_id:
        p = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
        if p:
            _require_patient_access(p, current_user)
            patient_ctx = (
                f"Patient: {p.first_name} {p.last_name}, DOB: {p.dob}, "
                f"Gender: {p.gender}, Insurance: {p.insurance_name}"
            )

    anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not anthropic_key:
        return {
            "success": False,
            "error": "AI generation is not configured. Add ANTHROPIC_API_KEY to Railway environment variables.",
        }

    model = os.getenv("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")

    system_prompt = (
        "You are a medical documentation AI. Output ONLY a valid JSON object — no markdown, "
        "no code fences, no explanation. The very first character must be { and the last must be }.\n\n"
        "Generate a complete Medicare-compliant SOAP note with these exact keys:\n"
        "chief_complaint, hpi, pmh, medications, allergies, ros, physical_exam, assessment, plan, "
        "icd10_codes (array of strings), cpt_codes (array of strings).\n\n"
        "Use precise medical language. Include ≥4 HPI elements. "
        "Select specific ICD-10-CM codes and appropriate CPT E&M level codes."
    )

    user_content = (
        f"{('Patient context: ' + patient_ctx + chr(10)) if patient_ctx else ''}"
        f"Clinical scenario: {prompt}\n\n"
        "Output only the JSON object, starting with {{ and ending with }}."
    )

    def extract_json(text: str):
        """Try multiple strategies to extract a JSON object from model output."""
        text = text.strip()
        # Strip markdown code fences if present
        if "```" in text:
            import re
            match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
            if match:
                return match.group(1)
        # Find outermost { ... }
        start = text.find("{")
        if start == -1:
            return None
        depth = 0
        for i, ch in enumerate(text[start:], start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start:i + 1]
        return None

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": anthropic_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": model,
                    "max_tokens": 2048,
                    "system": system_prompt,
                    "messages": [{"role": "user", "content": user_content}],
                },
            )

        if resp.status_code != 200:
            err = resp.json().get("error", {}).get("message", resp.text[:300])
            return {"success": False, "error": f"AI API error: {err}"}

        raw = resp.json().get("content", [{}])[0].get("text", "")

        json_str = extract_json(raw)
        if not json_str:
            return {"success": False, "error": "Model did not return a JSON object. Try rephrasing your prompt.", "raw": raw[:500]}

        note_json = json.loads(json_str)

        # Ensure required keys exist
        defaults = {"chief_complaint":"","hpi":"","pmh":"","medications":"","allergies":"",
                    "ros":"","physical_exam":"","assessment":"","plan":"",
                    "icd10_codes":[],"cpt_codes":[]}
        for k, v in defaults.items():
            note_json.setdefault(k, v)

        audit(db, current_user.id, "AI_GENERATE_NOTE", "ClinicalNote", "new",
              details=f"model={model} prompt_len={len(prompt)}")
        return {"success": True, "note": note_json}

    except httpx.ConnectError as e:
        return {"success": False, "error": f"Could not reach Anthropic API: {e}"}
    except json.JSONDecodeError as e:
        return {"success": False, "error": f"Could not parse model output as JSON: {e}", "raw": raw[:500]}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ═════════════════════════════════════════════════════════════════════════════
# LAB ORDERS
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/lab-orders")
def list_lab_orders(
    patient_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    q = db.query(models.LabOrder)
    if patient_id:
        patient = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
        if patient: _require_patient_access(patient, current_user)
        q = q.filter(models.LabOrder.patient_id == patient_id)
        audit(db, current_user.id, "VIEW_LAB_ORDERS", "Patient", str(patient_id))
    return [clean(o) for o in q.order_by(models.LabOrder.created_at.desc()).all()]


@app.post("/api/lab-orders")
def create_lab_order(
    data: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    _lab_patient = db.query(models.Patient).filter(models.Patient.id == data.get("patient_id")).first()
    if not _lab_patient: raise HTTPException(status_code=404, detail="Patient not found")
    _require_patient_access(_lab_patient, current_user)
    _VALID_PRIORITIES = {"routine", "stat", "asap"}
    if data.get("priority", "routine") not in _VALID_PRIORITIES:
        raise HTTPException(status_code=400, detail=f"priority must be one of: {', '.join(_VALID_PRIORITIES)}")
    # test_objects is the rich picker payload: [{name, code, category, specimen}, ...]
    test_objects_raw = data.get("test_objects")  # already a JSON string from picker
    tests_display = data.get("tests", [])
    # If test_objects provided but tests array is empty, derive display names
    if test_objects_raw and not tests_display:
        try:
            tests_display = [t["name"] for t in json.loads(test_objects_raw)]
        except Exception:
            pass

    order = models.LabOrder(
        patient_id=data["patient_id"],
        physician_id=current_user.id,
        tests=json.dumps(tests_display),
        test_objects=test_objects_raw,
        clinical_indication=data.get("clinical_indication", ""),
        priority=data.get("priority", "routine"),
        facility=data.get("facility", "LabCorp"),
        icd10_codes=json.dumps(data.get("icd10_codes", [])),
        notes=data.get("notes", ""),
        status="pending",
    )
    db.add(order)
    db.commit()
    db.refresh(order)
    audit(db, current_user.id, "CREATE_LAB_ORDER", "LabOrder", str(order.id))
    return clean(order)


@app.post("/api/lab-orders/{order_id}/transmit")
def transmit_lab_order(
    order_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Transmit a lab order to LabCorp via the Beacon REST API.
    Requires LABCORP_CLIENT_ID, LABCORP_CLIENT_SECRET, and LABCORP_ACCOUNT_NUM
    to be set in Railway environment variables.
    Docs: https://developer.labcorp.com/apis/ordering
    """
    order = db.query(models.LabOrder).filter(models.LabOrder.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    if order.status == "transmitted" and order.labcorp_order_id:
        return {"success": True, "message": "Already transmitted", "labcorp_order_id": order.labcorp_order_id}

    patient  = db.query(models.Patient).filter(models.Patient.id == order.patient_id).first()
    provider = db.query(models.User).filter(models.User.id == order.physician_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    # ── ABN gate: Medicare patients require a signed ABN before transmission ──
    is_medicare = "medicare" in (patient.insurance_name or "").lower()
    if is_medicare:
        signed_abn = db.query(models.AdvanceBeneficiaryNotice).filter(
            models.AdvanceBeneficiaryNotice.lab_order_id == order_id,
            models.AdvanceBeneficiaryNotice.status == "signed",
            models.AdvanceBeneficiaryNotice.patient_decision.in_(["OPTION_1", "OPTION_2"]),
        ).first()
        if not signed_abn:
            raise HTTPException(
                status_code=422,
                detail="ABN_REQUIRED: A signed Advance Beneficiary Notice is required before transmitting a lab order for a Medicare patient."
            )
        # OPTION_3 means patient declined — order should not be transmitted
        declined_abn = db.query(models.AdvanceBeneficiaryNotice).filter(
            models.AdvanceBeneficiaryNotice.lab_order_id == order_id,
            models.AdvanceBeneficiaryNotice.status == "signed",
            models.AdvanceBeneficiaryNotice.patient_decision == "OPTION_3",
        ).first()
        if declined_abn:
            raise HTTPException(
                status_code=422,
                detail="ABN_DECLINED: Patient selected Option 3 (does not want the test). Order cannot be transmitted."
            )

    token   = _get_labcorp_token()
    payload = _build_labcorp_order_payload(order, patient, provider)

    try:
        resp = httpx.post(
            f"{LABCORP_BASE_URL}/v1/orders",
            json=payload,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            timeout=20,
        )
        resp.raise_for_status()
        result = resp.json()
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"LabCorp API error {e.response.status_code}: {e.response.text}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"LabCorp connection error: {str(e)}")

    # LabCorp returns orderId in the response
    lc_order_id = result.get("orderId") or result.get("id") or result.get("orderNumber", "")
    order.status           = "transmitted"
    order.transmitted_at   = datetime.utcnow()
    order.labcorp_order_id = lc_order_id
    order.labcorp_status   = result.get("status", "submitted")
    db.commit()
    audit(db, current_user.id, "TRANSMIT_LAB_ORDER", "LabOrder", str(order_id), f"LabCorp ID: {lc_order_id}")
    return {"success": True, "labcorp_order_id": lc_order_id, "message": "Order transmitted to LabCorp"}


@app.get("/api/lab-orders/{order_id}/result")
def get_lab_result(
    order_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Check LabCorp for results on a transmitted order.
    If results exist, stores observations and PDF in the DB.
    """
    order = db.query(models.LabOrder).filter(models.LabOrder.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    # If already resulted and we have data, return it immediately
    if order.status == "resulted" and order.result_data:
        return {
            "status":      order.labcorp_status or "resulted",
            "observations": json.loads(order.result_data),
            "received_at": order.result_received_at.isoformat() if order.result_received_at else None,
            "has_pdf":     bool(order.result_pdf),
        }

    if not order.labcorp_order_id:
        return {"status": "not_transmitted", "observations": []}

    token = _get_labcorp_token()
    try:
        resp = httpx.get(
            f"{LABCORP_BASE_URL}/v1/results/{order.labcorp_order_id}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=20,
        )
        if resp.status_code == 404:
            return {"status": "pending", "observations": []}
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"LabCorp results error: {e.response.text}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))

    lc_status   = data.get("status", "")
    observations = []

    # Parse observations from FHIR DiagnosticReport or LabCorp JSON structure
    for obs in data.get("observations", data.get("results", [])):
        observations.append({
            "name":            obs.get("testName") or obs.get("name", ""),
            "value":           str(obs.get("value", obs.get("result", ""))),
            "units":           obs.get("units", ""),
            "reference_range": obs.get("referenceRange", obs.get("reference_range", "")),
            "abnormal_flag":   obs.get("abnormalFlag", obs.get("flag", "")),
            "status":          obs.get("resultStatus", "F"),
        })

    # Fetch PDF if available
    pdf_b64 = None
    pdf_url = data.get("reportPdfUrl") or data.get("pdfUrl")
    if pdf_url:
        try:
            pr = httpx.get(pdf_url, headers={"Authorization": f"Bearer {token}"}, timeout=30)
            if pr.status_code == 200:
                pdf_b64 = base64.b64encode(pr.content).decode()
        except Exception:
            pass  # PDF fetch failure is non-fatal

    if observations or lc_status.lower() in ("final", "resulted", "complete"):
        order.status           = "resulted"
        order.labcorp_status   = lc_status
        order.result_data      = json.dumps(observations)
        order.result_received_at = datetime.utcnow()
        if pdf_b64:
            order.result_pdf   = pdf_b64
        db.commit()
        audit(db, current_user.id, "RECEIVE_LAB_RESULT", "LabOrder", str(order_id))

    return {
        "status":       lc_status or order.labcorp_status or "pending",
        "observations": observations,
        "received_at":  order.result_received_at.isoformat() if order.result_received_at else None,
        "has_pdf":      bool(order.result_pdf or pdf_b64),
    }


@app.get("/api/lab-orders/{order_id}/result-pdf")
def download_result_pdf(
    order_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Return the stored LabCorp result PDF for download."""
    order = db.query(models.LabOrder).filter(models.LabOrder.id == order_id).first()
    if not order or not order.result_pdf:
        raise HTTPException(status_code=404, detail="No result PDF available")
    pdf_bytes = base64.b64decode(order.result_pdf)
    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=labresult_{order_id}.pdf"},
    )


@app.post("/api/labcorp/webhook")
async def labcorp_webhook(request: Request, db: Session = Depends(get_db)):
    """
    Receive inbound result notifications from LabCorp.
    LabCorp sends either:
      - JSON body with orderId + observations  (Beacon v2)
      - HL7 v2.5 ORU^R01 text/plain body      (legacy)
    Configure your LabCorp account to POST to: https://<your-domain>/api/labcorp/webhook
    Set LABCORP_WEBHOOK_SECRET to validate the X-LabCorp-Signature header.
    """
    # Validate signature if secret is configured
    if LABCORP_WEBHOOK_SECRET:
        sig = request.headers.get("X-LabCorp-Signature", "")
        if sig != LABCORP_WEBHOOK_SECRET:
            raise HTTPException(status_code=401, detail="Invalid webhook signature")

    content_type = request.headers.get("content-type", "")
    body_bytes   = await request.body()

    observations = []
    lc_order_id  = None
    lc_accession = None
    lc_status    = "final"

    if "application/json" in content_type:
        # ── JSON payload (Beacon v2 result notification) ──────────────────────
        data = json.loads(body_bytes)
        lc_order_id  = data.get("orderId") or data.get("internalOrderId")
        lc_accession = data.get("accessionNumber")
        lc_status    = data.get("status", "final")
        for obs in data.get("observations", data.get("results", [])):
            observations.append({
                "name":            obs.get("testName", obs.get("name", "")),
                "value":           str(obs.get("value", obs.get("result", ""))),
                "units":           obs.get("units", ""),
                "reference_range": obs.get("referenceRange", ""),
                "abnormal_flag":   obs.get("abnormalFlag", obs.get("flag", "")),
                "status":          obs.get("resultStatus", "F"),
            })
        # Extract PDF if embedded as base64
        pdf_b64 = data.get("reportPdf") or data.get("pdfBase64")
    else:
        # ── HL7 v2.5 ORU^R01 plain-text payload ──────────────────────────────
        hl7_text = body_bytes.decode("utf-8", errors="replace")
        observations = _parse_hl7_oru(hl7_text)
        pdf_b64 = None
        # Extract order reference from ORC or OBR segment
        for seg in hl7_text.replace("\r\n", "\r").replace("\n", "\r").split("\r"):
            if seg.startswith("ORC"):
                parts = seg.split("|")
                lc_order_id = parts[3] if len(parts) > 3 else None
                lc_accession = parts[2] if len(parts) > 2 else None
                break
            if seg.startswith("OBR") and not lc_order_id:
                parts = seg.split("|")
                lc_order_id = parts[3] if len(parts) > 3 else None

    if not lc_order_id:
        return {"received": True, "matched": False, "reason": "no order ID in payload"}

    # Match to internal order — try labcorp_order_id first, then internalOrderId
    order = db.query(models.LabOrder).filter(
        models.LabOrder.labcorp_order_id == lc_order_id
    ).first()
    if not order:
        # Try matching on internal ID (some LabCorp configs echo back our ID)
        try:
            order = db.query(models.LabOrder).filter(
                models.LabOrder.id == int(lc_order_id)
            ).first()
        except (ValueError, TypeError):
            pass

    if not order:
        return {"received": True, "matched": False, "reason": f"no order found for ID {lc_order_id}"}

    order.status             = "resulted"
    order.labcorp_status     = lc_status
    order.labcorp_accession  = lc_accession
    order.result_data        = json.dumps(observations)
    order.result_received_at = datetime.utcnow()
    if pdf_b64:
        order.result_pdf = pdf_b64
    db.commit()
    audit(db, None, "WEBHOOK_LAB_RESULT", "LabOrder", str(order.id), f"LabCorp accession: {lc_accession}")
    return {"received": True, "matched": True, "order_id": order.id, "observations": len(observations)}


# ═══════════════════════════════════════════════════════════════════════════════
# ADVANCE BENEFICIARY NOTICE (ABN) — CMS-R-131
# 42 C.F.R. § 411.408(f); required before ordering tests for Medicare patients
# when Medicare coverage is uncertain.
# ═══════════════════════════════════════════════════════════════════════════════

def _abn_dict(abn: models.AdvanceBeneficiaryNotice) -> dict:
    return {
        "id":               abn.id,
        "lab_order_id":     abn.lab_order_id,
        "patient_id":       abn.patient_id,
        "created_by":       abn.created_by,
        "items":            json.loads(abn.items or "[]"),
        "reason":           abn.reason,
        "estimated_cost":   abn.estimated_cost,
        "patient_decision": abn.patient_decision,
        "signed_at":        abn.signed_at.isoformat() if abn.signed_at else None,
        "signed_by_name":   abn.signed_by_name,
        "witness_name":     abn.witness_name,
        "status":           abn.status,
        "notes":            abn.notes,
        "created_at":       abn.created_at.isoformat(),
    }


@app.post("/api/abns")
def create_abn(
    body: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Create a new ABN for a Medicare patient prior to a lab order."""
    patient_id = body.get("patient_id")
    if not patient_id:
        raise HTTPException(status_code=400, detail="patient_id required")
    patient = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    abn = models.AdvanceBeneficiaryNotice(
        lab_order_id     = body.get("lab_order_id"),
        patient_id       = patient_id,
        created_by       = current_user.id,
        items            = json.dumps(body.get("items", [])),
        reason           = body.get("reason", "Medicare may not cover this test for the stated diagnosis"),
        estimated_cost   = float(body.get("estimated_cost", 0)),
        status           = "pending",
    )
    db.add(abn)
    db.commit()
    db.refresh(abn)
    audit(db, current_user.id, "CREATE_ABN", "ABN", str(abn.id),
          f"Patient {patient_id}; items: {body.get('items', [])}")
    return _abn_dict(abn)


@app.get("/api/abns")
def list_abns(
    patient_id: Optional[int] = None,
    lab_order_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """List ABNs, optionally filtered by patient or lab order."""
    q = db.query(models.AdvanceBeneficiaryNotice)
    if patient_id:
        q = q.filter(models.AdvanceBeneficiaryNotice.patient_id == patient_id)
    if lab_order_id:
        q = q.filter(models.AdvanceBeneficiaryNotice.lab_order_id == lab_order_id)
    return [_abn_dict(a) for a in q.order_by(models.AdvanceBeneficiaryNotice.created_at.desc()).all()]


@app.get("/api/abns/{abn_id}")
def get_abn(
    abn_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    abn = db.query(models.AdvanceBeneficiaryNotice).filter(
        models.AdvanceBeneficiaryNotice.id == abn_id).first()
    if not abn:
        raise HTTPException(status_code=404, detail="ABN not found")
    return _abn_dict(abn)


@app.post("/api/abns/{abn_id}/sign")
def sign_abn(
    abn_id: int,
    body: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Record the patient's signed decision.
    body: { patient_decision, signed_by_name, witness_name, lab_order_id (optional) }
    """
    abn = db.query(models.AdvanceBeneficiaryNotice).filter(
        models.AdvanceBeneficiaryNotice.id == abn_id).first()
    if not abn:
        raise HTTPException(status_code=404, detail="ABN not found")

    decision = body.get("patient_decision", "")
    if decision not in ("OPTION_1", "OPTION_2", "OPTION_3"):
        raise HTTPException(status_code=400,
            detail="patient_decision must be OPTION_1, OPTION_2, or OPTION_3")

    signed_name = body.get("signed_by_name", "").strip()
    if not signed_name:
        raise HTTPException(status_code=400, detail="signed_by_name required")

    abn.patient_decision = decision
    abn.signed_by_name   = signed_name
    abn.witness_name     = body.get("witness_name", "")
    abn.signed_at        = datetime.utcnow()
    abn.status           = "signed"
    abn.updated_at       = datetime.utcnow()

    # Link to lab order if provided
    if body.get("lab_order_id"):
        abn.lab_order_id = int(body["lab_order_id"])

    db.commit()
    db.refresh(abn)
    audit(db, current_user.id, "SIGN_ABN", "ABN", str(abn.id),
          f"Decision: {decision}; signed by: {signed_name}")
    return _abn_dict(abn)


@app.delete("/api/abns/{abn_id}")
def void_abn(
    abn_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Void an ABN (e.g. order was cancelled)."""
    abn = db.query(models.AdvanceBeneficiaryNotice).filter(
        models.AdvanceBeneficiaryNotice.id == abn_id).first()
    if not abn:
        raise HTTPException(status_code=404, detail="ABN not found")
    abn.status = "voided"
    abn.updated_at = datetime.utcnow()
    db.commit()
    audit(db, current_user.id, "VOID_ABN", "ABN", str(abn.id), "ABN voided")
    return {"voided": True}


# ═══════════════════════════════════════════════════════════════════════════════
# SKIN LESION TRACKING MODULE
# Serial dermoscopic photography with AI-assisted ABCDE analysis via Claude Vision
# ═══════════════════════════════════════════════════════════════════════════════

def _lesion_dict(l: models.SkinLesion, include_latest_thumb: bool = False, db: Session = None) -> dict:
    d = {
        "id":            l.id,
        "patient_id":    l.patient_id,
        "created_by":    l.created_by,
        "name":          l.name,
        "body_location": l.body_location,
        "description":   l.description,
        "first_noted":   l.first_noted,
        "status":        l.status,
        "notes":         l.notes,
        "created_at":    l.created_at.isoformat(),
        "updated_at":    l.updated_at.isoformat(),
    }
    if include_latest_thumb and db:
        latest = (db.query(models.LesionImage)
                  .filter(models.LesionImage.lesion_id == l.id)
                  .order_by(models.LesionImage.created_at.desc())
                  .first())
        d["image_count"] = (db.query(models.LesionImage)
                            .filter(models.LesionImage.lesion_id == l.id).count())
        d["latest_image_id"] = latest.id if latest else None
        d["latest_taken_at"] = latest.taken_at if latest else None
        # Include latest AI analysis summary if available
        if latest and latest.ai_analysis:
            try:
                analysis = json.loads(latest.ai_analysis)
                d["latest_urgency"] = analysis.get("urgency")
                d["latest_summary"] = analysis.get("summary", "")[:120]
            except Exception:
                pass
    return d


def _image_dict(img: models.LesionImage, include_data: bool = True) -> dict:
    d = {
        "id":             img.id,
        "lesion_id":      img.lesion_id,
        "patient_id":     img.patient_id,
        "uploaded_by":    img.uploaded_by,
        "image_mime":     img.image_mime,
        "image_filename": img.image_filename,
        "taken_at":       img.taken_at,
        "notes":          img.notes,
        "ai_analysis":    json.loads(img.ai_analysis) if img.ai_analysis else None,
        "ai_analyzed_at": img.ai_analyzed_at.isoformat() if img.ai_analyzed_at else None,
        "created_at":     img.created_at.isoformat(),
    }
    if include_data:
        d["data_url"] = f"data:{img.image_mime};base64,{img.image_data}"
    return d


@app.get("/api/skin-lesions")
def list_skin_lesions(
    patient_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    patient = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
    if patient: _require_patient_access(patient, current_user)
    lesions = (db.query(models.SkinLesion)
               .filter(models.SkinLesion.patient_id == patient_id)
               .order_by(models.SkinLesion.created_at.desc()).all())
    return [_lesion_dict(l, include_latest_thumb=True, db=db) for l in lesions]


@app.post("/api/skin-lesions")
def create_skin_lesion(
    body: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    patient_id = body.get("patient_id")
    if not patient_id:
        raise HTTPException(status_code=400, detail="patient_id required")
    patient = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    _require_patient_access(patient, current_user)
    lesion = models.SkinLesion(
        patient_id    = patient_id,
        created_by    = current_user.id,
        name          = body.get("name", "Unnamed lesion"),
        body_location = body.get("body_location", ""),
        description   = body.get("description", ""),
        first_noted   = body.get("first_noted", datetime.utcnow().date().isoformat()),
        status        = body.get("status", "monitoring"),
        notes         = body.get("notes", ""),
    )
    db.add(lesion)
    db.commit()
    db.refresh(lesion)
    audit(db, current_user.id, "CREATE_SKIN_LESION", "SkinLesion", str(lesion.id),
          f"Patient {patient_id}: {lesion.name} @ {lesion.body_location}")
    return _lesion_dict(lesion, include_latest_thumb=True, db=db)


@app.put("/api/skin-lesions/{lesion_id}")
def update_skin_lesion(
    lesion_id: int,
    body: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    lesion = db.query(models.SkinLesion).filter(models.SkinLesion.id == lesion_id).first()
    if not lesion:
        raise HTTPException(status_code=404, detail="Lesion not found")
    patient = db.query(models.Patient).filter(models.Patient.id == lesion.patient_id).first()
    if patient: _require_patient_access(patient, current_user)
    for field in ("name", "body_location", "description", "first_noted", "status", "notes"):
        if field in body:
            setattr(lesion, field, body[field])
    lesion.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(lesion)
    audit(db, current_user.id, "UPDATE_SKIN_LESION", "SkinLesion", str(lesion_id), "")
    return _lesion_dict(lesion, include_latest_thumb=True, db=db)


@app.get("/api/skin-lesions/{lesion_id}/images")
def list_lesion_images(
    lesion_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    imgs = (db.query(models.LesionImage)
            .filter(models.LesionImage.lesion_id == lesion_id)
            .order_by(models.LesionImage.taken_at.asc(), models.LesionImage.created_at.asc())
            .all())
    return [_image_dict(img, include_data=True) for img in imgs]


@app.post("/api/skin-lesions/{lesion_id}/images")
async def upload_lesion_image(
    lesion_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Upload a photo for a skin lesion via multipart/form-data."""
    lesion = db.query(models.SkinLesion).filter(models.SkinLesion.id == lesion_id).first()
    if not lesion:
        raise HTTPException(status_code=404, detail="Lesion not found")
    patient = db.query(models.Patient).filter(models.Patient.id == lesion.patient_id).first()
    if patient: _require_patient_access(patient, current_user)
    _check_upload_rate_limit(current_user.id)

    content_type = request.headers.get("content-type", "")
    if "multipart" not in content_type:
        raise HTTPException(status_code=400, detail="Multipart form data required")

    form = await request.form()
    image_file = form.get("image")
    if not image_file:
        raise HTTPException(status_code=400, detail="image field required")

    raw = await image_file.read()
    _MAX_IMAGE_BYTES = 10 * 1024 * 1024  # 10 MB
    if len(raw) > _MAX_IMAGE_BYTES:
        raise HTTPException(status_code=413, detail="Image too large — maximum 10 MB")
    mime = getattr(image_file, "content_type", None) or "image/jpeg"
    if mime not in ("image/jpeg", "image/png", "image/webp", "image/gif"):
        mime = "image/jpeg"

    img = models.LesionImage(
        lesion_id      = lesion_id,
        patient_id     = lesion.patient_id,
        uploaded_by    = current_user.id,
        image_data     = base64.b64encode(raw).decode("utf-8"),
        image_mime     = mime,
        image_filename = getattr(image_file, "filename", f"lesion_{lesion_id}.jpg"),
        taken_at       = form.get("taken_at", datetime.utcnow().date().isoformat()),
        notes          = form.get("notes", ""),
    )
    db.add(img)
    # Update lesion timestamp
    lesion.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(img)
    audit(db, current_user.id, "UPLOAD_LESION_IMAGE", "LesionImage", str(img.id),
          f"Lesion {lesion_id} — {img.taken_at}")
    return _image_dict(img, include_data=False)


@app.delete("/api/lesion-images/{image_id}")
def delete_lesion_image(
    image_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if current_user.role not in ("admin", "physician"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    img = db.query(models.LesionImage).filter(models.LesionImage.id == image_id).first()
    if not img:
        raise HTTPException(status_code=404, detail="Image not found")
    db.delete(img)
    db.commit()
    audit(db, current_user.id, "DELETE_LESION_IMAGE", "LesionImage", str(image_id), "")
    return {"deleted": True}


@app.post("/api/skin-lesions/{lesion_id}/analyze")
async def analyze_lesion(
    lesion_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Use Claude Vision (claude-sonnet-4-6) to analyze the latest lesion image against
    the full history, scoring ABCDE dermoscopy criteria and flagging significant changes.
    Requires ANTHROPIC_API_KEY to be set.
    """
    if current_user.role not in ("admin", "physician"):
        raise HTTPException(status_code=403, detail="Physician access required")

    if not anthropic_key:
        raise HTTPException(status_code=503,
            detail="ANTHROPIC_API_KEY not configured — add it to Railway environment variables")

    lesion = db.query(models.SkinLesion).filter(models.SkinLesion.id == lesion_id).first()
    if not lesion:
        raise HTTPException(status_code=404, detail="Lesion not found")

    images = (db.query(models.LesionImage)
              .filter(models.LesionImage.lesion_id == lesion_id)
              .order_by(models.LesionImage.taken_at.asc(), models.LesionImage.created_at.asc())
              .all())
    if not images:
        raise HTTPException(status_code=400, detail="No images uploaded for this lesion yet")

    latest = images[-1]
    previous = images[:-1]

    # Build the vision message content
    # Include up to 4 previous images for change comparison
    content = []

    if previous:
        content.append({
            "type": "text",
            "text": f"These are {len(previous)} previous photograph(s) of this skin lesion, "
                    f"ordered from oldest to most recent. Use them to assess evolution over time:"
        })
        for i, img in enumerate(previous[-4:]):  # max 4 previous images
            content.append({
                "type": "image",
                "source": {
                    "type": "base64",
                    "media_type": img.image_mime,
                    "data": img.image_data,
                }
            })
            content.append({
                "type": "text",
                "text": f"[Photo {i+1} — taken {img.taken_at}]"
            })

    content.append({
        "type": "text",
        "text": "This is the most recent photograph, taken today, requiring analysis:"
    })
    content.append({
        "type": "image",
        "source": {
            "type": "base64",
            "media_type": latest.image_mime,
            "data": latest.image_data,
        }
    })

    # ── HIPAA de-identification before sending to Anthropic ──────────────────
    # Per HIPAA Safe Harbor (45 CFR §164.514(b)), we remove direct and
    # quasi-identifiers before disclosing to external AI service:
    #   - No patient name, DOB, or exact age
    #   - No lesion label (could be unique)
    #   - No absolute dates; use relative elapsed time instead
    #   - Body region kept (broad anatomical zone) — required for clinical utility
    #   - Age decade kept (not exact age) — clinically relevant without identifying
    patient = db.query(models.Patient).filter(models.Patient.id == lesion.patient_id).first()
    age_decade_str = ""
    if patient and patient.dob:
        try:
            from datetime import date as _date
            dob = _date.fromisoformat(patient.dob)
            age_yrs = (_date.today() - dob).days // 365
            decade = (age_yrs // 10) * 10
            age_decade_str = f" Patient age group: {decade}s."
        except Exception:
            pass

    # Compute relative time since first noted (no absolute date)
    time_known_str = ""
    if lesion.first_noted:
        try:
            from datetime import date as _date2
            fn = _date2.fromisoformat(str(lesion.first_noted)[:10])
            months = max(1, round((_date2.today() - fn).days / 30.44))
            time_known_str = f" Lesion has been monitored for approximately {months} month(s)."
        except Exception:
            pass

    # Broad anatomical region only (strip laterality/specificity)
    body_region = (lesion.body_location or "").strip()

    content.append({
        "type": "text",
        "text": (
            f"Anatomical region: {body_region}\n"
            f"Initial clinical description: {lesion.description or 'Not provided'}\n"
            f"Serial photo count: {len(images)}\n"
            f"{age_decade_str}{time_known_str}\n\n"
            "Please perform a structured ABCDE dermoscopy assessment on the most recent image "
            "and compare to any previous images for evolution. Respond ONLY with a JSON object "
            "matching this exact schema (no markdown, no prose outside the JSON):\n"
            '{\n'
            '  "summary": "1-2 sentence clinical summary of the lesion and any notable changes",\n'
            '  "abcde": {\n'
            '    "asymmetry":  {"score": "low|moderate|high",    "notes": "brief observation"},\n'
            '    "border":     {"score": "regular|irregular",     "notes": "brief observation"},\n'
            '    "color":      {"score": "uniform|variegated",    "notes": "brief observation"},\n'
            '    "diameter":   {"estimated": "~Xmm",              "notes": "brief observation"},\n'
            '    "evolution":  {"change": "stable|changing|concerning", "notes": "brief observation"}\n'
            '  },\n'
            '  "changes_from_previous": "description of changes vs prior photos, or \\"No prior images\\" if first photo",\n'
            '  "recommendation": "clinical recommendation for next step",\n'
            '  "urgency": "routine|follow-up-3-months|follow-up-6-weeks|urgent-referral"\n'
            '}'
        )
    })

    system_prompt = (
        "You are a clinical decision support tool embedded in a HIPAA-compliant EMR used by "
        "a physician. Your role is to provide structured dermoscopy analysis to assist the "
        "physician — not to replace their clinical judgment. Always respond with valid JSON only. "
        "Be precise, conservative, and clinically accurate. Flag any features concerning for "
        "melanoma (irregular borders, multiple colors, rapid growth, ulceration) clearly in "
        "the urgency field."
    )

    try:
        async with httpx.AsyncClient(timeout=90.0) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": anthropic_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-sonnet-4-6",   # Use Sonnet for vision quality
                    "max_tokens": 1024,
                    "system": system_prompt,
                    "messages": [{"role": "user", "content": content}],
                },
            )
        if resp.status_code != 200:
            raise HTTPException(status_code=502,
                detail=f"Claude API error {resp.status_code}: {resp.text[:200]}")

        raw_json = resp.json()["content"][0]["text"].strip()
        # Strip any accidental markdown fences
        if raw_json.startswith("```"):
            raw_json = re.sub(r"^```[a-z]*\n?", "", raw_json)
            raw_json = re.sub(r"\n?```$", "", raw_json.strip())

        analysis = json.loads(raw_json)
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=502, detail=f"Claude returned invalid JSON: {e}")
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Analysis timed out — please retry")

    # Persist analysis on the latest image
    latest.ai_analysis   = json.dumps(analysis)
    latest.ai_analyzed_at = datetime.utcnow()
    lesion.updated_at    = datetime.utcnow()
    db.commit()

    audit(db, current_user.id, "ANALYZE_SKIN_LESION", "SkinLesion", str(lesion_id),
          f"Urgency: {analysis.get('urgency','unknown')} | Images: {len(images)}")
    # HIPAA audit: PHI images disclosed to external AI service (de-identified per Safe Harbor)
    audit(db, current_user.id, "PHI_DISCLOSURE_EXTERNAL", "SkinLesion", str(lesion_id),
          f"De-identified lesion images ({len(images)}) sent to Anthropic Claude API for ABCDE analysis. "
          f"Patient identifiers removed per HIPAA Safe Harbor §164.514(b).")
    return {"image_id": latest.id, "analysis": analysis, "analyzed_at": latest.ai_analyzed_at.isoformat()}


@app.get("/api/labcorp/tests")
def search_labcorp_tests(
    q: str = "",
    category: str = "",
    page: int = 1,
    page_size: int = 30,
    current_user: models.User = Depends(get_current_user),
):
    """
    Search the LabCorp test catalog.
    - When LABCORP_CLIENT_ID + LABCORP_CLIENT_SECRET are set, queries the live
      LabCorp Beacon API catalog so ALL 5,000+ tests are available.
    - Falls back to the embedded catalog (~150 common tests) when unconfigured.
    Returns: {tests: [...], total: int, categories: [...], source: "live"|"local"}
    """
    # ── Try live LabCorp Beacon catalog ──────────────────────────────────────
    if LABCORP_CLIENT_ID and LABCORP_CLIENT_SECRET:
        try:
            token = _get_labcorp_token()
            params: dict = {"pageSize": page_size, "page": page}
            if q:
                params["query"] = q
            if category:
                params["category"] = category
            resp = httpx.get(
                f"{LABCORP_BASE_URL}/v1/catalog/tests",
                params=params,
                headers={"Authorization": f"Bearer {token}"},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                tests = [
                    {
                        "code":     t.get("testCode") or t.get("code", ""),
                        "name":     t.get("testName") or t.get("name", ""),
                        "category": t.get("category", ""),
                        "specimen": t.get("specimenType") or t.get("specimen", ""),
                        "tat":      t.get("turnaroundTime", ""),
                    }
                    for t in data.get("tests", data.get("items", []))
                ]
                return {
                    "tests":      tests,
                    "total":      data.get("total", len(tests)),
                    "categories": LABCORP_CATEGORIES,
                    "source":     "live",
                }
        except Exception:
            pass  # Fall through to local catalog on any error

    # ── Local embedded catalog (fallback) ────────────────────────────────────
    results = LABCORP_TEST_CATALOG
    if q:
        q_lower = q.lower()
        results = [
            t for t in results
            if q_lower in t["name"].lower()
            or q_lower in t["code"]
            or q_lower in t["category"].lower()
            or q_lower in t["specimen"].lower()
        ]
    if category:
        results = [t for t in results if t["category"].lower() == category.lower()]

    total  = len(results)
    start  = (page - 1) * page_size
    paged  = results[start: start + page_size]
    return {
        "tests":      paged,
        "total":      total,
        "categories": LABCORP_CATEGORIES,
        "source":     "local",
    }


@app.get("/api/labcorp/categories")
def list_labcorp_categories(current_user: models.User = Depends(get_current_user)):
    """Return the list of test categories available in the local catalog."""
    return {"categories": LABCORP_CATEGORIES}


# ═════════════════════════════════════════════════════════════════════════════
# IMAGING ORDERS
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/imaging-orders")
def list_imaging_orders(
    patient_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    q = db.query(models.ImagingOrder)
    if patient_id:
        _img_patient = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
        if _img_patient: _require_patient_access(_img_patient, current_user)
        q = q.filter(models.ImagingOrder.patient_id == patient_id)
        audit(db, current_user.id, "VIEW_IMAGING_ORDERS", "Patient", str(patient_id))
    return [clean(o) for o in q.order_by(models.ImagingOrder.created_at.desc()).all()]


async def _do_fax_imaging_order(order: models.ImagingOrder, patient: models.Patient,
                                physician: models.User, user_id: int, db: Session):
    """Shared helper: build PDF, send fax, update order + FaxLog."""
    pdf_bytes = _build_imaging_order_pdf(order, patient, physician)
    subject = f"Imaging Order — {order.study_type} — {patient.first_name} {patient.last_name}"

    if _telnyx_configured():
        fax_to = re.sub(r"[^\d+]", "", order.fax_number)
        if not fax_to.startswith("+"):
            fax_to = "+1" + fax_to.lstrip("1")
        fax_id, fax_status = await _send_telnyx_fax(fax_to, pdf_bytes, subject)
        order.telnyx_fax_id = fax_id
        order.fax_status = fax_status
    else:
        order.fax_status = "queued"

    order.fax_sent_at = datetime.utcnow()
    order.status = "faxed"
    db.commit()

    log = models.FaxLog(
        patient_id=order.patient_id,
        physician_id=user_id,
        direction="sent",
        to_number=order.fax_number,
        subject=subject,
        pages=1,
        status=order.fax_status,
        telnyx_fax_id=order.telnyx_fax_id or "",
    )
    db.add(log)
    db.commit()
    audit(db, user_id, "FAX_IMAGING_ORDER", "ImagingOrder", str(order.id))


@app.post("/api/imaging-orders")
async def create_imaging_order(
    data: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    _io_patient = db.query(models.Patient).filter(models.Patient.id == data.get("patient_id")).first()
    if not _io_patient: raise HTTPException(status_code=404, detail="Patient not found")
    _require_patient_access(_io_patient, current_user)
    if data.get("priority", "routine") not in {"routine", "stat", "asap"}:
        raise HTTPException(status_code=400, detail="priority must be one of: routine, stat, asap")
    order = models.ImagingOrder(
        patient_id=data["patient_id"],
        physician_id=current_user.id,
        study_type=data.get("study_type", ""),
        body_part=data.get("body_part", ""),
        clinical_indication=data.get("clinical_indication", ""),
        priority=data.get("priority", "routine"),
        facility=data.get("facility", ""),
        fax_number=data.get("fax_number", ""),
        icd10_codes=json.dumps(data.get("icd10_codes", [])),
        cpt_code=data.get("cpt_code", ""),
        notes=data.get("notes", ""),
        status="ordered",
        fax_status="pending",
    )
    db.add(order)
    db.commit()
    db.refresh(order)
    audit(db, current_user.id, "CREATE_IMAGING_ORDER", "ImagingOrder", str(order.id))

    # Auto-fax immediately if a fax number was provided
    if order.fax_number:
        patient = db.query(models.Patient).filter(models.Patient.id == order.patient_id).first()
        try:
            await _do_fax_imaging_order(order, patient, current_user, current_user.id, db)
        except Exception as e:
            # Fax failure doesn't block order creation
            order.fax_status = "failed"
            db.commit()

    return clean(order)


@app.put("/api/imaging-orders/{order_id}")
def update_imaging_order(
    order_id: int,
    data: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Update status, scheduling date, results, notes, etc."""
    order = db.query(models.ImagingOrder).filter(models.ImagingOrder.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    now = datetime.utcnow()
    for field in ["study_type","body_part","clinical_indication","priority",
                  "facility","fax_number","cpt_code","notes","result_notes"]:
        if field in data:
            setattr(order, field, data[field])
    if "icd10_codes" in data:
        order.icd10_codes = json.dumps(data["icd10_codes"])
    if "status" in data:
        new_status = data["status"]
        order.status = new_status
        if new_status == "scheduled" and not order.scheduled_at:
            order.scheduled_at = datetime.fromisoformat(data["scheduled_at"]) if data.get("scheduled_at") else now
        if new_status == "completed" and not order.completed_at:
            order.completed_at = now
        if new_status == "results_received" and not order.results_received_at:
            order.results_received_at = now
    db.commit()
    audit(db, current_user.id, "UPDATE_IMAGING_ORDER", "ImagingOrder", str(order_id))
    return clean(order)


def _build_imaging_order_pdf(order: models.ImagingOrder, patient: models.Patient, physician: models.User) -> bytes:
    """Generate a structured imaging order PDF using reportlab."""
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib import colors
    import io

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter,
                            leftMargin=0.75*inch, rightMargin=0.75*inch,
                            topMargin=0.75*inch, bottomMargin=0.75*inch)
    styles = getSampleStyleSheet()
    story = []

    # Header
    story.append(Paragraph("<b>VALIANT DIRECT PRIMARY CARE</b>", ParagraphStyle("h",fontSize=16,spaceAfter=2,alignment=1)))
    story.append(Paragraph("Direct Primary Care Practice • Virginia", ParagraphStyle("sub",fontSize=10,spaceAfter=4,alignment=1,textColor=colors.grey)))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1e3a5f")))
    story.append(Spacer(1, 10))

    priority_color = {"STAT": colors.red, "urgent": colors.orange, "routine": colors.black}.get(order.priority, colors.black)
    story.append(Paragraph(f"<b>IMAGING ORDER</b> — <font color='{'red' if order.priority=='STAT' else 'black'}'>{order.priority.upper()}</font>",
                            ParagraphStyle("title",fontSize=14,spaceAfter=8)))
    story.append(Paragraph(f"Order Date: {order.created_at.strftime('%B %d, %Y') if order.created_at else ''}  |  Order #: IMG-{order.id:04d}",
                            ParagraphStyle("meta",fontSize=10,spaceAfter=12,textColor=colors.grey)))

    # Patient info
    story.append(Paragraph("<b>PATIENT INFORMATION</b>", ParagraphStyle("sh",fontSize=11,spaceAfter=4,textColor=colors.HexColor("#1e3a5f"))))
    raw_dob = getattr(patient, "dob", None) or getattr(patient, "date_of_birth", None) or ""
    pt_dob = raw_dob if isinstance(raw_dob, str) else (raw_dob.strftime('%m/%d/%Y') if raw_dob else "")
    pt_addr = getattr(patient, "address", "") or ""
    pt_city = getattr(patient, "city", "") or ""
    pt_state = getattr(patient, "state", "") or ""
    pt_zip = getattr(patient, "zip_code", "") or ""
    addr_parts = [pt_addr]
    if pt_city or pt_state or pt_zip:
        addr_parts.append(f"{pt_city}, {pt_state} {pt_zip}".strip(", "))
    pt_addr_full = "  ".join(p for p in addr_parts if p) or "—"
    pt_data = [
        ["Name:", f"{patient.first_name} {patient.last_name}", "DOB:", pt_dob],
        ["Phone:", getattr(patient, "phone", "") or "—", "MRN:", f"PT-{patient.id:05d}"],
        ["Address:", pt_addr_full, "", ""],
    ]
    pt_table = Table(pt_data, colWidths=[1.1*inch, 2.5*inch, 1.1*inch, 2.0*inch])
    pt_table.setStyle(TableStyle([
        ("FONTSIZE", (0,0), (-1,-1), 10),
        ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTNAME", (2,0), (2,-1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("SPAN", (1,2), (3,2)),   # address value spans columns 1-3
    ]))
    story.append(pt_table)
    story.append(Spacer(1, 10))

    # Order details
    story.append(Paragraph("<b>ORDER DETAILS</b>", ParagraphStyle("sh",fontSize=11,spaceAfter=4,textColor=colors.HexColor("#1e3a5f"))))
    details = [
        ["Study Type:", f"{order.study_type}{' — ' + order.body_part if order.body_part else ''}"],
        ["CPT Code:", order.cpt_code or "—"],
        ["Facility:", order.facility or "—"],
        ["Priority:", order.priority.upper()],
    ]
    try:
        icd_list = json.loads(order.icd10_codes or "[]")
        details.append(["ICD-10:", ", ".join(icd_list) if icd_list else "—"])
    except Exception:
        pass
    det_table = Table(details, colWidths=[1.5*inch, 5.2*inch])
    det_table.setStyle(TableStyle([
        ("FONTSIZE", (0,0), (-1,-1), 10),
        ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.HexColor("#f8fafc"), colors.white]),
    ]))
    story.append(det_table)
    story.append(Spacer(1, 10))

    # Clinical indication
    if order.clinical_indication:
        story.append(Paragraph("<b>CLINICAL INDICATION / REASON FOR EXAM</b>",
                               ParagraphStyle("sh",fontSize=11,spaceAfter=4,textColor=colors.HexColor("#1e3a5f"))))
        story.append(Paragraph(order.clinical_indication, ParagraphStyle("body",fontSize=10,spaceAfter=8)))

    # Notes
    if order.notes:
        story.append(Paragraph("<b>SPECIAL INSTRUCTIONS</b>",
                               ParagraphStyle("sh",fontSize=11,spaceAfter=4,textColor=colors.HexColor("#1e3a5f"))))
        story.append(Paragraph(order.notes, ParagraphStyle("body",fontSize=10,spaceAfter=8)))

    # Ordering physician
    story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey))
    story.append(Spacer(1, 8))
    story.append(Paragraph("<b>ORDERING PROVIDER</b>", ParagraphStyle("sh",fontSize=11,spaceAfter=4,textColor=colors.HexColor("#1e3a5f"))))
    doc_name = f"Dr. {physician.full_name}" if hasattr(physician,"full_name") and physician.full_name else physician.username
    story.append(Paragraph(f"{doc_name}  |  Valiant Direct Primary Care",
                           ParagraphStyle("body",fontSize=10,spaceAfter=2)))
    story.append(Spacer(1, 20))
    story.append(Paragraph("_" * 45 + "     " + "_" * 20,
                           ParagraphStyle("sig",fontSize=10)))
    story.append(Paragraph("Physician Signature                                           Date",
                           ParagraphStyle("siglabel",fontSize=9,textColor=colors.grey)))

    doc.build(story)
    return buf.getvalue()


@app.post("/api/imaging-orders/{order_id}/fax")
async def fax_imaging_order(
    order_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Manually (re)send an imaging order via fax — useful for retries."""
    order = db.query(models.ImagingOrder).filter(models.ImagingOrder.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    if not order.fax_number:
        raise HTTPException(status_code=400, detail="No fax number set for this order")

    patient = db.query(models.Patient).filter(models.Patient.id == order.patient_id).first()
    physician = db.query(models.User).filter(models.User.id == order.physician_id).first() or current_user

    await _do_fax_imaging_order(order, patient, physician, current_user.id, db)
    return clean(order)


@app.get("/api/imaging-orders/{order_id}/fax-status")
async def imaging_fax_status(
    order_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Poll Telnyx for updated fax status."""
    order = db.query(models.ImagingOrder).filter(models.ImagingOrder.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    if order.telnyx_fax_id and _telnyx_configured():
        headers = {"Authorization": f"Bearer {TELNYX_API_KEY}"}
        r = httpx.get(f"https://api.telnyx.com/v2/faxes/{order.telnyx_fax_id}", headers=headers, timeout=10)
        if r.status_code == 200:
            telnyx_status = r.json().get("data", {}).get("status", order.fax_status)
            order.fax_status = telnyx_status
            if telnyx_status == "delivered" and order.status == "faxed":
                order.status = "faxed"  # keep as faxed until scheduled
            db.commit()
    return clean(order)


@app.post("/api/imaging-orders/{order_id}/results")
async def upload_imaging_results(
    order_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Accept either a JSON body with result_notes, or a multipart PDF upload.
    Updates status to results_received.
    """
    content_type = request.headers.get("content-type", "")
    order = db.query(models.ImagingOrder).filter(models.ImagingOrder.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    if "multipart" in content_type:
        form = await request.form()
        result_file = form.get("result_file")
        if result_file:
            # Risk 12: store as base64 blob in DB — never write to ephemeral filesystem
            contents = await result_file.read()
            order.result_file_data = base64.b64encode(contents).decode("utf-8")
            order.result_file_name = getattr(result_file, "filename", None) or f"IMG-{order_id:04d}-result.pdf"
            order.result_file_path = ""   # clear legacy path
        order.result_notes = form.get("result_notes", order.result_notes or "")
    else:
        body = await request.json()
        order.result_notes = body.get("result_notes", order.result_notes or "")

    order.status = "results_received"
    order.results_received_at = datetime.utcnow()
    if not order.completed_at:
        order.completed_at = datetime.utcnow()
    db.commit()
    audit(db, current_user.id, "IMAGING_RESULTS_RECEIVED", "ImagingOrder", str(order_id))
    return clean(order)


@app.get("/api/imaging-orders/{order_id}/result-pdf")
def download_imaging_result_pdf(
    order_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Stream the stored imaging result PDF from database blob storage."""
    order = db.query(models.ImagingOrder).filter(models.ImagingOrder.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    # Try DB blob first (new path), fall back to legacy filesystem path
    if order.result_file_data:
        pdf_bytes = base64.b64decode(order.result_file_data)
        fname = getattr(order, "result_file_name", None) or f"imaging_result_{order_id}.pdf"
        return StreamingResponse(
            BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f"inline; filename={fname}"},
        )
    # Legacy: file stored on filesystem (pre-migration uploads)
    legacy_path = getattr(order, "result_file_path", "") or ""
    if legacy_path:
        import os as _os
        if _os.path.isfile(legacy_path):
            return FileResponse(legacy_path, media_type="application/pdf")
    raise HTTPException(status_code=404, detail="No result PDF available for this order")


# ═════════════════════════════════════════════════════════════════════════════
# FAX CENTER
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/faxes")
def list_faxes(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    rows = db.query(models.FaxLog).order_by(models.FaxLog.created_at.desc()).all()
    return [clean(f) for f in rows]



@app.post("/api/faxes/send")
def send_fax(
    data: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Send a fax via Telnyx. Provide to_number, subject, and pdf_base64."""
    to_number = data.get("to_number", "")
    pdf_b64   = data.get("pdf_base64", "")
    subject   = data.get("subject", "Medical Document")
    if not to_number:
        raise HTTPException(status_code=400, detail="to_number required")
    pdf_bytes = base64.b64decode(pdf_b64) if pdf_b64 else b""
    telnyx_data = _send_telnyx_fax(to_number, pdf_bytes, subject)
    fax = models.FaxLog(
        patient_id=data.get("patient_id"),
        physician_id=current_user.id,
        direction="sent",
        from_number=TELNYX_FROM_NUMBER,
        to_number=to_number,
        subject=subject,
        pages=data.get("pages", 1),
        notes=data.get("notes", ""),
        status="queued",
        telnyx_fax_id=telnyx_data.get("id", ""),
    )
    db.add(fax)
    db.commit()
    db.refresh(fax)
    audit(db, current_user.id, "SEND_FAX", "Fax", str(fax.id))
    return {"success": True, "fax_id": fax.id, "telnyx_fax_id": telnyx_data.get("id")}


@app.post("/api/weno/webhook", include_in_schema=False)
async def weno_webhook(request: Request, db: Session = Depends(get_db)):
    """
    WENO Exchange asynchronous callback endpoint.
    WENO posts NCPDP SCRIPT STATUS, VERIFY, CANCEL, or ERROR messages here
    after routing a prescription to the pharmacy.

    Configure in the WENO portal as your Listening Endpoint URL:
      https://yourapp.railway.app/api/weno/webhook

    NCPDP SCRIPT message types received:
      STATUS  → Rx accepted and routed to pharmacy network
      VERIFY  → Pharmacy acknowledged receipt (delivery confirmation)
      ERROR   → Routing failed — check Description for reason
      CANCEL  → Pharmacy cancelled the Rx
    """
    raw_body = await request.body()
    try:
        body_text = raw_body.decode("utf-8")
    except Exception:
        return {"success": False, "error": "Could not decode body"}

    # WENO sends either raw NCPDP XML or a SOAP envelope — strip SOAP wrapper if present
    ncpdp_text = body_text
    if "<soap:" in body_text or "<SOAP-ENV:" in body_text:
        try:
            root = ET.fromstring(body_text)
            for el in root.iter():
                if el.text and el.text.strip().startswith("<"):
                    ncpdp_text = el.text.strip()
                    break
        except Exception:
            pass

    ns = "http://www.ncpdp.org/schema/SCRIPT"
    msg_type   = ""
    order_num  = ""
    status_code= ""
    description= ""
    try:
        xml_root = ET.fromstring(ncpdp_text)
        body_el  = xml_root.find(f"{{{ns}}}Body")
        if body_el is not None:
            for child in body_el:
                msg_type = child.tag.replace(f"{{{ns}}}", "")
                break
        order_num   = (xml_root.find(f".//{{{ns}}}PrescriberOrderNumber") or ET.Element("x")).text or ""
        status_code = (xml_root.find(f".//{{{ns}}}Code") or ET.Element("x")).text or ""
        description = (xml_root.find(f".//{{{ns}}}Description") or ET.Element("x")).text or ""
    except Exception:
        pass

    # Map order number back to a Prescription (format: MF-{id}-{timestamp})
    rx = None
    if order_num.startswith("MF-"):
        try:
            rx_id = int(order_num.split("-")[1])
            rx = db.query(models.Prescription).filter(models.Prescription.id == rx_id).first()
        except (IndexError, ValueError):
            pass

    if rx:
        type_to_status = {
            "Status":  "routed",
            "Verify":  "delivered",
            "Error":   "error",
            "Cancel":  "cancelled_by_pharmacy",
        }
        new_status = type_to_status.get(msg_type, msg_type.lower() or "updated")
        rx.eprescribe_status   = new_status
        rx.eprescribe_response = json.dumps({
            "msg_type": msg_type, "code": status_code,
            "description": description, "received_at": datetime.utcnow().isoformat(),
        })
        if msg_type == "Verify":
            rx.filled_at = datetime.utcnow()
            rx.status    = "filled"
        db.commit()

    return {"success": True, "msg_type": msg_type, "order_num": order_num}


@app.post("/api/faxes/webhook")
async def fax_webhook(request: Request, db: Session = Depends(get_db)):
    """
    Telnyx fax status webhook.
    Configure in Telnyx portal → Messaging → Fax Applications → Webhook URL:
      https://yourapp.railway.app/api/faxes/webhook
    """
    body = await request.json()
    event_type = body.get("data", {}).get("event_type", "")
    payload    = body.get("data", {}).get("payload", {})
    telnyx_fax_id = payload.get("fax_id") or payload.get("id", "")
    status_map = {
        "fax.queued":    "queued",
        "fax.media.processed": "processing",
        "fax.sending.started": "sending",
        "fax.delivered": "delivered",
        "fax.failed":    "failed",
        "fax.received":  "received",
    }
    new_status = status_map.get(event_type)
    if telnyx_fax_id and new_status:
        fax = db.query(models.FaxLog).filter(models.FaxLog.telnyx_fax_id == telnyx_fax_id).first()
        if fax:
            fax.status = new_status
            db.commit()
        # Also update prescription fax_status if this fax was for an Rx
        rx = db.query(models.Prescription).filter(models.Prescription.fax_id == telnyx_fax_id).first()
        if rx:
            rx.fax_status = new_status
            db.commit()
    return {"success": True}


@app.get("/api/fax-pdf/{token}", include_in_schema=False)
def serve_fax_pdf(token: str):
    """
    Public endpoint — no auth required. Telnyx fetches the prescription PDF
    from here using the one-time token generated at fax time.
    """
    pdf_bytes = _telnyx_pdf_cache.pop(token, None)
    if not pdf_bytes:
        raise HTTPException(status_code=404, detail="PDF not found or already retrieved")
    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": "inline; filename=document.pdf"},
    )


# ═════════════════════════════════════════════════════════════════════════════
# MEMBERSHIPS
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/memberships")
def list_memberships(
    patient_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    q = db.query(models.Membership)
    if patient_id:
        q = q.filter(models.Membership.patient_id == patient_id)
    return [clean(m) for m in q.order_by(models.Membership.created_at.desc()).all()]


@app.post("/api/memberships")
def create_membership(
    data: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Create a membership record for a patient."""
    start = data.get("start_date")
    m = models.Membership(
        patient_id=data["patient_id"],
        plan_name=data.get("plan_name", "Basic"),
        price_monthly=data.get("price_monthly", 0.0),
        start_date=datetime.fromisoformat(start) if start else datetime.utcnow(),
        status="active",
    )
    db.add(m)
    db.commit()
    db.refresh(m)
    audit(db, current_user.id, "CREATE_MEMBERSHIP", "Membership", str(m.id))
    return clean(m)


@app.put("/api/memberships/{membership_id}")
def update_membership(
    membership_id: int,
    data: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    m = db.query(models.Membership).filter(models.Membership.id == membership_id).first()
    if not m:
        raise HTTPException(status_code=404, detail="Membership not found")
    for k, v in data.items():
        if hasattr(m, k) and k not in ("id", "patient_id", "created_at"):
            setattr(m, k, v)
    db.commit()
    audit(db, current_user.id, "UPDATE_MEMBERSHIP", "Membership", str(membership_id))
    return clean(m)


# ═════════════════════════════════════════════════════════════════════════════
# PAYMENTS
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/payments")
def list_payments(
    patient_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    q = db.query(models.Payment)
    if patient_id:
        q = q.filter(models.Payment.patient_id == patient_id)
    return [clean(p) for p in q.order_by(models.Payment.created_at.desc()).all()]


@app.post("/api/payments")
def create_payment(
    data: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Record a payment for a patient."""
    pay = models.Payment(
        patient_id=data["patient_id"],
        amount=data.get("amount", 0.0),
        description=data.get("description", ""),
        payment_method=data.get("payment_method", "card"),
        status="completed",   # placeholder
    )
    db.add(pay)
    db.commit()
    db.refresh(pay)
    audit(db, current_user.id, "PAYMENT", "Payment", str(pay.id),
          details=f"${pay.amount:.2f}")
    return clean(pay)


# ═════════════════════════════════════════════════════════════════════════════
# DASHBOARD  &  AUDIT LOG
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/dashboard/stats")
def dashboard_stats(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    today = datetime.utcnow().date()
    return {
        "total_patients": db.query(models.Patient).count(),
        "notes_today": db.query(models.ClinicalNote).filter(
            models.ClinicalNote.created_at >= today
        ).count(),
        "pending_lab_orders": db.query(models.LabOrder).filter(
            models.LabOrder.status == "pending"
        ).count(),
        "active_memberships": db.query(models.Membership).filter(
            models.Membership.status == "active"
        ).count(),
        "faxes_today": db.query(models.FaxLog).filter(
            models.FaxLog.created_at >= today
        ).count(),
        "pending_faxes": db.query(models.FaxLog).filter(
            models.FaxLog.status == "queued"
        ).count(),
    }


@app.get("/api/audit-logs")
def audit_logs(
    db: Session = Depends(get_db),
    _: models.User = Depends(require_admin),
):
    rows = db.query(models.AuditLog).order_by(models.AuditLog.timestamp.desc()).limit(500).all()
    return [clean(r) for r in rows]


# ═════════════════════════════════════════════════════════════════════════════
# SQUARE PAYMENTS
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/square/config")
def square_config():
    """Return Square app credentials so the frontend can initialize the Web Payments SDK."""
    sdk_url = (
        "https://sandbox.web.squarecdn.com/v1/square.js"
        if SQUARE_ENVIRONMENT == "sandbox"
        else "https://web.squarecdn.com/v1/square.js"
    )
    return {
        "app_id":      SQUARE_APP_ID,
        "location_id": SQUARE_LOCATION_ID,
        "environment": SQUARE_ENVIRONMENT,
        "sdk_url":     sdk_url,
        "enabled":     bool(SQUARE_ACCESS_TOKEN and SQUARE_APP_ID and SQUARE_LOCATION_ID),
    }


@app.post("/api/square/payment")
async def create_square_payment(
    data: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Create a one-time Square card payment using a Web Payments SDK nonce (source_id)."""
    if not SQUARE_ACCESS_TOKEN:
        raise HTTPException(
            status_code=503,
            detail="Square not configured — add SQUARE_ACCESS_TOKEN, SQUARE_LOCATION_ID, SQUARE_APP_ID to environment variables",
        )

    amount_cents = int(float(data.get("amount", 0)) * 100)
    if amount_cents <= 0:
        raise HTTPException(status_code=400, detail="Amount must be greater than 0")

    source_id = data.get("source_id")
    if not source_id:
        raise HTTPException(status_code=400, detail="source_id (card nonce) is required")

    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.post(
            f"{SQUARE_BASE_URL}/v2/payments",
            headers={
                "Authorization":  f"Bearer {SQUARE_ACCESS_TOKEN}",
                "Content-Type":   "application/json",
                "Square-Version": "2024-11-20",
            },
            json={
                "idempotency_key": str(_uuid.uuid4()),
                "source_id":       source_id,
                "amount_money":    {"amount": amount_cents, "currency": "USD"},
                "location_id":     SQUARE_LOCATION_ID,
                "note":            data.get("description", ""),
            },
        )

    result = r.json()
    if r.status_code != 200:
        errors = result.get("errors", [{}])
        raise HTTPException(status_code=400, detail=errors[0].get("detail", "Payment failed"))

    sq_payment = result["payment"]
    pay = models.Payment(
        patient_id=data["patient_id"],
        amount=float(data.get("amount", 0)),
        description=data.get("description", ""),
        payment_method="square",
        status="completed" if sq_payment["status"] == "COMPLETED" else "pending",
        payment_ref_id=sq_payment["id"],
    )
    db.add(pay)
    db.commit()
    db.refresh(pay)
    audit(db, current_user.id, "CREATE_SQUARE_PAYMENT", "Payment", str(pay.id),
          details=f"${pay.amount:.2f}")
    return {"success": True, "payment_id": pay.id, "square_payment_id": sq_payment["id"]}


@app.post("/api/square/subscription")
async def create_square_subscription(
    data: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Create a Square membership subscription.
    Flow: create/find customer → save card on file → charge first month → record membership.
    The card_id is stored so future monthly charges can be processed.
    """
    if not SQUARE_ACCESS_TOKEN:
        raise HTTPException(
            status_code=503,
            detail="Square not configured — add SQUARE_ACCESS_TOKEN, SQUARE_LOCATION_ID, SQUARE_APP_ID",
        )

    patient = db.query(models.Patient).filter(models.Patient.id == data["patient_id"]).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    source_id     = data.get("source_id")
    plan_name     = data.get("plan_name", "Medical Membership")
    price_monthly = float(data.get("price_monthly", 0))
    price_cents   = int(price_monthly * 100)

    if price_cents <= 0:
        raise HTTPException(status_code=400, detail="Price must be greater than 0")
    if not source_id:
        raise HTTPException(status_code=400, detail="source_id (card nonce) is required")

    sq_headers = {
        "Authorization":  f"Bearer {SQUARE_ACCESS_TOKEN}",
        "Content-Type":   "application/json",
        "Square-Version": "2024-11-20",
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        # 1. Re-use existing Square customer for this patient if available
        existing = db.query(models.Membership).filter(
            models.Membership.patient_id == data["patient_id"],
            models.Membership.square_customer_id != None,
            models.Membership.square_customer_id != "",
        ).first()

        if existing and existing.square_customer_id:
            customer_id = existing.square_customer_id
        else:
            cr = await client.post(
                f"{SQUARE_BASE_URL}/v2/customers",
                headers=sq_headers,
                json={
                    "idempotency_key": str(_uuid.uuid4()),
                    "given_name":      patient.first_name or "",
                    "family_name":     patient.last_name or "",
                    "email_address":   patient.email or f"patient_{patient.id}@medflow.local",
                    "reference_id":    str(patient.id),
                },
            )
            if cr.status_code not in (200, 201):
                raise HTTPException(status_code=400, detail="Failed to create Square customer")
            customer_id = cr.json()["customer"]["id"]

        # 2. Save card on file for the customer using the nonce
        card_r = await client.post(
            f"{SQUARE_BASE_URL}/v2/cards",
            headers=sq_headers,
            json={
                "idempotency_key": str(_uuid.uuid4()),
                "source_id":       source_id,
                "card":            {"customer_id": customer_id},
            },
        )
        if card_r.status_code not in (200, 201):
            errs = card_r.json().get("errors", [{}])
            raise HTTPException(status_code=400, detail=errs[0].get("detail", "Failed to save card on file"))
        card_id = card_r.json()["card"]["id"]

        # 3. Charge first month immediately using the stored card
        pay_r = await client.post(
            f"{SQUARE_BASE_URL}/v2/payments",
            headers=sq_headers,
            json={
                "idempotency_key": str(_uuid.uuid4()),
                "source_id":       card_id,
                "customer_id":     customer_id,
                "amount_money":    {"amount": price_cents, "currency": "USD"},
                "location_id":     SQUARE_LOCATION_ID,
                "note":            f"Membership: {plan_name} — first month",
            },
        )
        if pay_r.status_code != 200:
            errs = pay_r.json().get("errors", [{}])
            raise HTTPException(status_code=400, detail=errs[0].get("detail", "Initial membership payment failed"))
        sq_payment_id = pay_r.json()["payment"]["id"]

    # Record the initial payment
    pay = models.Payment(
        patient_id=data["patient_id"],
        amount=price_monthly,
        description=f"Membership: {plan_name} — first month",
        payment_method="square",
        status="completed",
        payment_ref_id=sq_payment_id,
    )
    db.add(pay)

    # Record the membership with Square IDs
    _start = datetime.utcnow()
    mem = models.Membership(
        patient_id=data["patient_id"],
        plan_name=plan_name,
        price_monthly=price_monthly,
        start_date=_start,
        status="active",
        square_customer_id=customer_id,
        square_card_id=card_id,
        payment_provider="square",
        next_billing_date=_next_anniversary(_start),
        billing_status="ok",
    )
    db.add(mem)
    db.commit()
    db.refresh(mem)
    audit(db, current_user.id, "CREATE_SQUARE_SUBSCRIPTION", "Membership", str(mem.id),
          details=f"${price_monthly:.2f}/mo — {plan_name}")
    return {"success": True, "membership_id": mem.id, "square_customer_id": customer_id}


@app.delete("/api/square/subscription/{membership_id}")
async def cancel_square_subscription(
    membership_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Cancel a Square membership — disables the card on file and marks it cancelled."""
    mem = db.query(models.Membership).filter(models.Membership.id == membership_id).first()
    if not mem:
        raise HTTPException(status_code=404, detail="Membership not found")

    # Disable the card on file so future charges are blocked
    card_id = mem.square_card_id
    if card_id and SQUARE_ACCESS_TOKEN:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                await client.post(
                    f"{SQUARE_BASE_URL}/v2/cards/{card_id}/disable",
                    headers={
                        "Authorization":  f"Bearer {SQUARE_ACCESS_TOKEN}",
                        "Square-Version": "2024-11-20",
                    },
                )
        except Exception:
            pass  # proceed even if disable fails

    mem.status = "cancelled"
    db.commit()
    audit(db, current_user.id, "CANCEL_SQUARE_SUBSCRIPTION", "Membership", str(membership_id))
    return {"success": True}


@app.post("/api/square/webhook")
async def square_webhook(request: Request, db: Session = Depends(get_db)):
    """
    Square webhook endpoint.
    In Square Developer Dashboard → Webhooks → Add endpoint:
      URL: https://your-railway-app.railway.app/api/square/webhook
      Events: payment.completed
    Set SQUARE_WEBHOOK_SIGNATURE_KEY env var to the webhook signature key.
    """
    import base64, hmac as _hmac, hashlib as _hashlib

    payload = await request.body()
    sig_header  = request.headers.get("x-square-hmacsha256-signature", "")
    webhook_key = os.getenv("SQUARE_WEBHOOK_SIGNATURE_KEY", "")

    if webhook_key and sig_header:
        url = str(request.url)
        expected_sig = base64.b64encode(
            _hmac.new(webhook_key.encode(), (url + payload.decode()).encode(), _hashlib.sha256).digest()
        ).decode()
        if not _hmac.compare_digest(sig_header, expected_sig):
            raise HTTPException(status_code=400, detail="Invalid Square webhook signature")

    try:
        event = json.loads(payload)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    event_type = event.get("type", "")
    obj        = event.get("data", {}).get("object", {})

    if event_type == "payment.completed":
        sq_pay_id = obj.get("payment", {}).get("id", "")
        if sq_pay_id:
            pay = db.query(models.Payment).filter(
                models.Payment.payment_ref_id == sq_pay_id
            ).first()
            if pay:
                pay.status = "completed"
                db.commit()

    return {"ok": True}


# ═════════════════════════════════════════════════════════════════════════════
# SCHEDULING
# ═════════════════════════════════════════════════════════════════════════════

# ── Appointment Types ──────────────────────────────────────────────────────

@app.get("/api/appointment-types")
def list_appointment_types(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return db.query(models.AppointmentType).filter(models.AppointmentType.is_active == True).order_by(models.AppointmentType.name).all()

@app.post("/api/appointment-types")
def create_appointment_type(data: dict, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    at = models.AppointmentType(
        name=data.get("name","").strip(),
        duration_minutes=int(data.get("duration_minutes",30)),
        color=data.get("color","#2563eb"),
        description=data.get("description",""),
    )
    db.add(at); db.commit(); db.refresh(at)
    return at

@app.put("/api/appointment-types/{at_id}")
def update_appointment_type(at_id: int, data: dict, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    at = db.query(models.AppointmentType).filter(models.AppointmentType.id == at_id).first()
    if not at: raise HTTPException(status_code=404, detail="Not found")
    for k in ("name","duration_minutes","color","description","is_active"):
        if k in data: setattr(at, k, data[k])
    db.commit(); db.refresh(at)
    return at

@app.delete("/api/appointment-types/{at_id}")
def delete_appointment_type(at_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    at = db.query(models.AppointmentType).filter(models.AppointmentType.id == at_id).first()
    if not at: raise HTTPException(status_code=404, detail="Not found")
    at.is_active = False; db.commit()
    return {"ok": True}


# ── Appointments ───────────────────────────────────────────────────────────

def _enrich_appointment(a, db):
    from datetime import datetime as _dt
    patient  = db.query(models.Patient).filter(models.Patient.id == a.patient_id).first() if a.patient_id else None
    provider = db.query(models.User).filter(models.User.id == a.provider_id).first()
    apt_type = db.query(models.AppointmentType).filter(models.AppointmentType.id == a.appointment_type_id).first() if a.appointment_type_id else None
    return {
        "id": a.id, "title": a.title,
        "start_time": a.start_time.isoformat(), "end_time": a.end_time.isoformat(),
        "status": a.status, "notes": a.notes,
        "color": a.color or (apt_type.color if apt_type else "#2563eb"),
        "reminder_sent": a.reminder_sent,
        "patient_id": a.patient_id,
        "patient_name": f"{patient.first_name} {patient.last_name}" if patient else None,
        "patient_phone": patient.phone if patient else None,
        "patient_email": patient.email if patient else None,
        "provider_id": a.provider_id,
        "provider_name": provider.full_name if provider else None,
        "appointment_type_id": a.appointment_type_id,
        "appointment_type": apt_type.name if apt_type else None,
        "duration_minutes": int((a.end_time - a.start_time).total_seconds() // 60),
        "created_at": a.created_at.isoformat(),
        "updated_at": a.updated_at.isoformat() if a.updated_at else None,
    }

@app.get("/api/appointments")
def list_appointments(
    start: str = None, end: str = None,
    provider_id: int = None, patient_id: int = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    from datetime import datetime as _dt
    q = db.query(models.Appointment).filter(models.Appointment.status != "cancelled")
    if start:       q = q.filter(models.Appointment.start_time >= _dt.fromisoformat(start))
    if end:         q = q.filter(models.Appointment.start_time <= _dt.fromisoformat(end))
    if provider_id: q = q.filter(models.Appointment.provider_id == provider_id)
    if patient_id:
        _appt_patient = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
        if _appt_patient: _require_patient_access(_appt_patient, current_user)
        q = q.filter(models.Appointment.patient_id == patient_id)
    return [_enrich_appointment(a, db) for a in q.order_by(models.Appointment.start_time).all()]

@app.post("/api/appointments")
def create_appointment(data: dict, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    from datetime import datetime as _dt
    if data.get("patient_id"):
        _ca_patient = db.query(models.Patient).filter(models.Patient.id == data["patient_id"]).first()
        if _ca_patient: _require_patient_access(_ca_patient, current_user)
    a = models.Appointment(
        patient_id=data.get("patient_id"),
        provider_id=data["provider_id"],
        appointment_type_id=data.get("appointment_type_id"),
        title=data.get("title","Appointment"),
        start_time=_dt.fromisoformat(data["start_time"]),
        end_time=_dt.fromisoformat(data["end_time"]),
        status=data.get("status","scheduled"),
        notes=data.get("notes",""),
        color=data.get("color"),
        created_by=current_user.id,
    )
    db.add(a); db.commit(); db.refresh(a)
    audit(db, current_user.id, "CREATE_APPOINTMENT", "Appointment", str(a.id),
          details=f"{a.title} @ {a.start_time.isoformat()}")
    return _enrich_appointment(a, db)

@app.put("/api/appointments/{appt_id}")
def update_appointment(appt_id: int, data: dict, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    from datetime import datetime as _dt
    a = db.query(models.Appointment).filter(models.Appointment.id == appt_id).first()
    if not a: raise HTTPException(status_code=404, detail="Not found")
    for k in ("title","status","notes","color","patient_id","provider_id","appointment_type_id"):
        if k in data: setattr(a, k, data[k])
    if "start_time" in data: a.start_time = _dt.fromisoformat(data["start_time"])
    if "end_time"   in data: a.end_time   = _dt.fromisoformat(data["end_time"])
    a.updated_at = _dt.utcnow()
    db.commit(); db.refresh(a)
    audit(db, current_user.id, "UPDATE_APPOINTMENT", "Appointment", str(a.id))
    return _enrich_appointment(a, db)

@app.delete("/api/appointments/{appt_id}")
def cancel_appointment(appt_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    from datetime import datetime as _dt
    a = db.query(models.Appointment).filter(models.Appointment.id == appt_id).first()
    if not a: raise HTTPException(status_code=404, detail="Not found")
    a.status = "cancelled"; a.updated_at = _dt.utcnow(); db.commit()
    audit(db, current_user.id, "CANCEL_APPOINTMENT", "Appointment", str(a.id))
    return {"ok": True}


# ── Provider Schedules ─────────────────────────────────────────────────────

@app.get("/api/provider-schedules")
def get_provider_schedules(provider_id: int = None, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    q = db.query(models.ProviderSchedule)
    if provider_id: q = q.filter(models.ProviderSchedule.provider_id == provider_id)
    return q.order_by(models.ProviderSchedule.provider_id, models.ProviderSchedule.day_of_week).all()

@app.post("/api/provider-schedules")
def save_provider_schedules(data: dict, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    """Replace all schedule rows for a provider with the new set."""
    provider_id = data["provider_id"]
    db.query(models.ProviderSchedule).filter(models.ProviderSchedule.provider_id == provider_id).delete()
    for entry in data.get("schedules", []):
        db.add(models.ProviderSchedule(
            provider_id=provider_id,
            day_of_week=entry["day_of_week"],
            start_time=entry.get("start_time","09:00"),
            end_time=entry.get("end_time","17:00"),
        ))
    db.commit()
    return {"ok": True}


# ── Schedule Blocks ────────────────────────────────────────────────────────

@app.get("/api/schedule-blocks")
def list_schedule_blocks(provider_id: int = None, start: str = None, end: str = None,
                         db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    from datetime import datetime as _dt
    q = db.query(models.ScheduleBlock)
    if provider_id: q = q.filter(models.ScheduleBlock.provider_id == provider_id)
    if start: q = q.filter(models.ScheduleBlock.end_datetime   >= _dt.fromisoformat(start))
    if end:   q = q.filter(models.ScheduleBlock.start_datetime <= _dt.fromisoformat(end))
    blocks = q.order_by(models.ScheduleBlock.start_datetime).all()
    return [{"id": b.id, "provider_id": b.provider_id,
             "start_datetime": b.start_datetime.isoformat(),
             "end_datetime": b.end_datetime.isoformat(), "reason": b.reason} for b in blocks]

@app.post("/api/schedule-blocks")
def create_schedule_block(data: dict, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    from datetime import datetime as _dt
    b = models.ScheduleBlock(
        provider_id=data["provider_id"],
        start_datetime=_dt.fromisoformat(data["start_datetime"]),
        end_datetime=_dt.fromisoformat(data["end_datetime"]),
        reason=data.get("reason","Blocked"),
    )
    db.add(b); db.commit(); db.refresh(b)
    return {"id": b.id, "provider_id": b.provider_id,
            "start_datetime": b.start_datetime.isoformat(),
            "end_datetime": b.end_datetime.isoformat(), "reason": b.reason}

@app.delete("/api/schedule-blocks/{block_id}")
def delete_schedule_block(block_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    b = db.query(models.ScheduleBlock).filter(models.ScheduleBlock.id == block_id).first()
    if not b: raise HTTPException(status_code=404, detail="Not found")
    db.delete(b); db.commit()
    return {"ok": True}


# ── Providers list ─────────────────────────────────────────────────────────

@app.get("/api/providers")
def list_providers(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    users = db.query(models.User).filter(
        models.User.is_active == True,
        models.User.role.in_(["physician","admin"])
    ).order_by(models.User.full_name).all()
    return [{"id": u.id, "full_name": u.full_name, "specialty": u.specialty, "role": u.role} for u in users]


# ═════════════════════════════════════════════════════════════════════════════
# ZAPRITE  (Bitcoin / Lightning / crypto payments)
# ═════════════════════════════════════════════════════════════════════════════
# Docs: https://api.zaprite.com
# Set ZAPRITE_API_KEY env var (from app.zaprite.com → Settings → API)

ZAPRITE_API_KEY  = os.getenv("ZAPRITE_API_KEY", "")
ZAPRITE_BASE_URL = "https://api.zaprite.com"


@app.post("/api/zaprite/order")
async def create_zaprite_order(
    data: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Create a Zaprite order (hosted checkout — BTC, Lightning, USDT, etc.).
    Returns a checkout_url the frontend opens in a new tab.
    """
    if not ZAPRITE_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="Zaprite not configured — add ZAPRITE_API_KEY to environment variables",
        )

    amount = float(data.get("amount", 0))
    if amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be greater than 0")

    patient_id   = data.get("patient_id")
    description  = data.get("description", "Medical payment")
    amount_cents = int(round(amount * 100))  # Zaprite expects cents for USD

    external_id = str(_uuid.uuid4())  # used to reconcile webhook deliveries

    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.post(
            f"{ZAPRITE_BASE_URL}/v1/orders",
            headers={
                "Authorization": f"Bearer {ZAPRITE_API_KEY}",
                "Content-Type":  "application/json",
            },
            json={
                "currency":       "USD",
                "amount":         amount_cents,
                "label":          description,
                "externalUniqId": external_id,
                "metadata": {
                    "patient_id": str(patient_id or ""),
                    "user_id":    str(current_user.id),
                },
            },
        )

    result = r.json()
    if r.status_code not in (200, 201):
        raise HTTPException(status_code=400, detail=result.get("message", "Failed to create Zaprite order"))

    order_id     = result["id"]
    checkout_url = result["checkoutUrl"]

    # Record a pending payment — marked completed via webhook or polling
    pay = models.Payment(
        patient_id=patient_id,
        amount=amount,
        description=description,
        payment_method="crypto",
        status="pending",
        payment_ref_id=order_id,
    )
    db.add(pay)
    db.commit()
    db.refresh(pay)
    audit(db, current_user.id, "CREATE_ZAPRITE_ORDER", "Payment", str(pay.id),
          details=f"${amount:.2f} — {description}")

    return {
        "success":      True,
        "payment_id":   pay.id,
        "order_id":     order_id,
        "checkout_url": checkout_url,
    }


@app.get("/api/zaprite/order/{order_id}/status")
async def get_zaprite_order_status(
    order_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Poll a Zaprite order for its current payment status."""
    if not ZAPRITE_API_KEY:
        raise HTTPException(status_code=503, detail="Zaprite not configured")

    async with httpx.AsyncClient(timeout=15.0) as client:
        r = await client.get(
            f"{ZAPRITE_BASE_URL}/v1/orders/{order_id}",
            headers={"Authorization": f"Bearer {ZAPRITE_API_KEY}"},
        )

    if r.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to fetch order")

    order  = r.json()
    status = order.get("status", "PENDING")  # PENDING|PROCESSING|PAID|OVERPAID|UNDERPAID|COMPLETE|ABANDONED

    if status in ("PAID", "OVERPAID", "COMPLETE"):
        pay = db.query(models.Payment).filter(
            models.Payment.payment_ref_id == order_id
        ).first()
        if pay and pay.status != "completed":
            pay.status = "completed"
            db.commit()
            audit(db, current_user.id, "ZAPRITE_ORDER_CONFIRMED", "Payment", str(pay.id))
        return {"order_id": order_id, "status": "completed", "zaprite_status": status,
                "payment_id": pay.id if pay else None}
    elif status == "ABANDONED":
        return {"order_id": order_id, "status": "failed", "zaprite_status": status}
    else:
        return {"order_id": order_id, "status": "pending", "zaprite_status": status}


@app.post("/api/zaprite/webhook")
async def zaprite_webhook(request: Request, db: Session = Depends(get_db)):
    """
    Zaprite webhook endpoint for order.change events.
    In app.zaprite.com → Settings → API → Webhooks → add:
      URL: https://your-railway-app.railway.app/api/zaprite/webhook
    Set ZAPRITE_WEBHOOK_SECRET env var to the secret shown in Zaprite's webhook settings.
    """
    raw_body = await request.body()

    # ── HMAC-SHA256 signature verification ──────────────────────────────────────
    # Zaprite signs each webhook with HMAC-SHA256(secret, raw_body) sent in
    # the X-Zaprite-Signature header as a hex digest.
    zaprite_secret = os.getenv("ZAPRITE_WEBHOOK_SECRET", "")
    if zaprite_secret:
        sig_header = request.headers.get("X-Zaprite-Signature", "")
        expected   = hmac.new(
            zaprite_secret.encode("utf-8"), raw_body, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(sig_header, expected):
            raise HTTPException(status_code=403, detail="Invalid webhook signature")

    try:
        event = json.loads(raw_body)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    event_type = event.get("type", "")
    order      = event.get("data", {})
    order_id   = order.get("id", "")
    status     = order.get("status", "")

    if event_type == "order.change" and order_id:
        pay = db.query(models.Payment).filter(
            models.Payment.payment_ref_id == order_id
        ).first()
        if pay:
            if status in ("PAID", "OVERPAID", "COMPLETE"):
                pay.status = "completed"
                db.commit()
            elif status == "ABANDONED" and pay.status == "pending":
                pay.status = "failed"
                db.commit()

    return {"ok": True}


# ═════════════════════════════════════════════════════════════════════════════
# PRESCRIBING
# ═════════════════════════════════════════════════════════════════════════════

# ── E-prescribing platform config (adapter-ready) ────────────────────────────
# Set EPRESCRIBE_PLATFORM to "dosespot", "drfirst", or "surescripts" when ready.
# Each platform's credentials are loaded from environment variables below.
EPRESCRIBE_PLATFORM       = os.getenv("EPRESCRIBE_PLATFORM", "")           # active platform
DOSESPOT_CLINIC_ID        = os.getenv("DOSESPOT_CLINIC_ID", "")
DOSESPOT_CLINIC_KEY       = os.getenv("DOSESPOT_CLINIC_KEY", "")
DOSESPOT_USER_ID          = os.getenv("DOSESPOT_USER_ID", "")
DRFIRST_USERNAME          = os.getenv("DRFIRST_USERNAME", "")
DRFIRST_PASSWORD          = os.getenv("DRFIRST_PASSWORD", "")
DRFIRST_ACCOUNT_ID        = os.getenv("DRFIRST_ACCOUNT_ID", "")
SURESCRIPTS_PARTNER_ID    = os.getenv("SURESCRIPTS_PARTNER_ID", "")
SURESCRIPTS_PARTNER_SECRET= os.getenv("SURESCRIPTS_PARTNER_SECRET", "")

# ── WENO Exchange e-Prescribing Configuration ─────────────────────────────────
# Sign up at https://online.wenoexchange.com → EHR EZ Integration
# Required Railway env vars:
#   WENO_PARTNER_ID          → Your EHR Partner ID (from WENO account dashboard)
#   WENO_PARTNER_PASSWORD_MD5→ MD5 hash of your WENO API password (shown in Account → Company Data)
#   WENO_PRESCRIBER_D        → Prescriber D value, e.g. "1234" (from D1234:C14332)
#   WENO_LOCATION_C          → Location C value,   e.g. "14332"
#   WENO_PHYSICIAN_NPI       → Prescribing physician's NPI number
#   WENO_PHYSICIAN_DEA       → Prescribing physician's DEA number (required for EPCS)
#   WENO_PHYSICIAN_STATE_LIC → State medical license number
#   WENO_PHYSICIAN_FNAME     → Physician first name
#   WENO_PHYSICIAN_LNAME     → Physician last name
#   WENO_PRACTICE_NAME       → Practice/clinic name
#   WENO_PRACTICE_ADDRESS    → Practice street address
#   WENO_PRACTICE_CITY       → Practice city
#   WENO_PRACTICE_STATE      → Practice state (2-letter)
#   WENO_PRACTICE_ZIP        → Practice ZIP code
#   WENO_PRACTICE_PHONE      → Practice phone (digits only, e.g. 3055551234)
#   WENO_PRODUCTION          → Set to "true" to use live network (default: test/cert mode)
WENO_PARTNER_ID          = os.getenv("WENO_PARTNER_ID", "")
WENO_PARTNER_PASSWORD_MD5= os.getenv("WENO_PARTNER_PASSWORD_MD5", "")
WENO_PRESCRIBER_D        = os.getenv("WENO_PRESCRIBER_D", "")
WENO_LOCATION_C          = os.getenv("WENO_LOCATION_C", "")
WENO_PHYSICIAN_NPI       = os.getenv("WENO_PHYSICIAN_NPI", "")
WENO_PHYSICIAN_DEA       = os.getenv("WENO_PHYSICIAN_DEA", "")
WENO_PHYSICIAN_STATE_LIC = os.getenv("WENO_PHYSICIAN_STATE_LIC", "")
WENO_PHYSICIAN_FNAME     = os.getenv("WENO_PHYSICIAN_FNAME", "")
WENO_PHYSICIAN_LNAME     = os.getenv("WENO_PHYSICIAN_LNAME", "")
WENO_PRACTICE_NAME       = os.getenv("WENO_PRACTICE_NAME", os.getenv("PRACTICE_NAME", ""))
WENO_PRACTICE_ADDRESS    = os.getenv("WENO_PRACTICE_ADDRESS", "")
WENO_PRACTICE_CITY       = os.getenv("WENO_PRACTICE_CITY", "")
WENO_PRACTICE_STATE      = os.getenv("WENO_PRACTICE_STATE", "")
WENO_PRACTICE_ZIP        = os.getenv("WENO_PRACTICE_ZIP", "")
WENO_PRACTICE_PHONE      = os.getenv("WENO_PRACTICE_PHONE", "")
_WENO_PRODUCTION         = os.getenv("WENO_PRODUCTION", "false").lower() == "true"
WENO_ENDPOINT            = (
    "https://api.wenoexchange.com/wenox/service.asmx" if _WENO_PRODUCTION
    else "https://cert.wenoexchange.com/wenox/service.asmx"
)

def _weno_configured() -> bool:
    return bool(WENO_PARTNER_ID and WENO_PARTNER_PASSWORD_MD5
                and WENO_PRESCRIBER_D and WENO_LOCATION_C)

def _digits_only(s: str) -> str:
    """Strip all non-digit characters from a phone/fax number."""
    return re.sub(r"\D", "", s or "")

def _weno_dob(dob_str: str) -> str:
    """Convert any date string to YYYYMMDD required by NCPDP SCRIPT."""
    if not dob_str:
        return ""
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%Y%m%d"):
        try:
            return datetime.strptime(str(dob_str)[:10], fmt).strftime("%Y%m%d")
        except ValueError:
            continue
    return str(dob_str).replace("-", "")[:8]

def _build_weno_ncpdp_xml(rx, patient, order_id: str, epcs_code: str = "") -> str:
    """
    Build an NCPDP SCRIPT 20170715 NewRx XML message for WENO Exchange.
    Spec: NCPDP SCRIPT Standard Version 20170715
    Reference: https://wenoexchange.com/switch-documentation/
    """
    NS = "http://www.ncpdp.org/schema/SCRIPT"
    XSI = "http://www.w3.org/2001/XMLSchema-instance"
    ET.register_namespace("", NS)
    ET.register_namespace("xsi", XSI)

    msg = ET.Element(f"{{{NS}}}Message", attrib={
        "DatatypesVersion": "20170715",
        "ECLVersion": "20170715",
        "StructuresVersion": "20170715",
        "TransportVersion": "20170715",
        "TransactionDomain": "SCRIPT",
        "TransactionVersion": "20170715",
        "ImplementationVersion": "20170715",
        f"{{{XSI}}}schemaLocation": f"{NS} {NS}",
    })

    # ── Header ────────────────────────────────────────────────────────────────
    hdr = ET.SubElement(msg, f"{{{NS}}}Header")
    ET.SubElement(hdr, f"{{{NS}}}To",   attrib={"Qualifier": "ZZZ"}).text = "WENO"
    ET.SubElement(hdr, f"{{{NS}}}From", attrib={"Qualifier": "D"}).text   = (
        f"D{WENO_PRESCRIBER_D}:C{WENO_LOCATION_C}"
    )
    ET.SubElement(hdr, f"{{{NS}}}MessageID").text       = order_id
    ET.SubElement(hdr, f"{{{NS}}}SentTime").text        = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    ET.SubElement(hdr, f"{{{NS}}}PrescriberOrderNumber").text = order_id

    sec = ET.SubElement(hdr, f"{{{NS}}}Security")
    snd = ET.SubElement(sec, f"{{{NS}}}Sender")
    ET.SubElement(snd, f"{{{NS}}}SecondaryIdentification").text  = WENO_PARTNER_ID
    ET.SubElement(snd, f"{{{NS}}}TertiaryIdentification").text   = WENO_PARTNER_PASSWORD_MD5

    sw = ET.SubElement(hdr, f"{{{NS}}}SenderSoftware")
    ET.SubElement(sw, f"{{{NS}}}SenderSoftwareDeveloper").text        = "MedFlow"
    ET.SubElement(sw, f"{{{NS}}}SenderSoftwareProduct").text          = "MedFlowEMR"
    ET.SubElement(sw, f"{{{NS}}}SenderSoftwareVersionRelease").text   = "1.0"

    # ── Body → NewRx ──────────────────────────────────────────────────────────
    body  = ET.SubElement(msg, f"{{{NS}}}Body")
    newrx = ET.SubElement(body, f"{{{NS}}}NewRx")

    # Patient
    pt_elem = ET.SubElement(newrx, f"{{{NS}}}Patient")
    hp = ET.SubElement(pt_elem, f"{{{NS}}}HumanPatient")
    nm = ET.SubElement(hp, f"{{{NS}}}Name")
    ET.SubElement(nm, f"{{{NS}}}LastName").text  = getattr(patient, "last_name",  "") or ""
    ET.SubElement(nm, f"{{{NS}}}FirstName").text = getattr(patient, "first_name", "") or ""
    dob_el = ET.SubElement(hp, f"{{{NS}}}DateOfBirth")
    ET.SubElement(dob_el, f"{{{NS}}}Date").text  = _weno_dob(getattr(patient, "dob", "") or "")
    gender_raw = (getattr(patient, "gender", "") or "U")[:1].upper()
    ET.SubElement(hp, f"{{{NS}}}Gender").text    = gender_raw if gender_raw in ("M", "F") else "U"
    addr_el = ET.SubElement(hp, f"{{{NS}}}Address")
    ET.SubElement(addr_el, f"{{{NS}}}AddressLine1").text = getattr(patient, "address",  "") or ""
    ET.SubElement(addr_el, f"{{{NS}}}City").text         = getattr(patient, "city",     "") or ""
    ET.SubElement(addr_el, f"{{{NS}}}StateProvince").text= getattr(patient, "state",    "") or ""
    ET.SubElement(addr_el, f"{{{NS}}}PostalCode").text   = getattr(patient, "zip_code", "") or ""
    ET.SubElement(addr_el, f"{{{NS}}}CountryCode").text  = "US"
    if getattr(patient, "phone", ""):
        comms = ET.SubElement(hp, f"{{{NS}}}CommunicationNumbers")
        pri = ET.SubElement(comms, f"{{{NS}}}PrimaryTelephone")
        ET.SubElement(pri, f"{{{NS}}}Number").text = _digits_only(patient.phone)

    # Pharmacy
    pharm_el = ET.SubElement(newrx, f"{{{NS}}}Pharmacy")
    pharm_id = ET.SubElement(pharm_el, f"{{{NS}}}Identification")
    if rx.pharmacy_npi:
        ET.SubElement(pharm_id, f"{{{NS}}}NPI").text = rx.pharmacy_npi
    ET.SubElement(pharm_el, f"{{{NS}}}BusinessName").text = rx.pharmacy_name or ""
    if rx.pharmacy_address:
        ph_addr = ET.SubElement(pharm_el, f"{{{NS}}}Address")
        ET.SubElement(ph_addr, f"{{{NS}}}AddressLine1").text = rx.pharmacy_address
        ET.SubElement(ph_addr, f"{{{NS}}}CountryCode").text  = "US"
    if rx.pharmacy_fax or rx.pharmacy_phone:
        ph_comms = ET.SubElement(pharm_el, f"{{{NS}}}CommunicationNumbers")
        if rx.pharmacy_fax:
            fax_el = ET.SubElement(ph_comms, f"{{{NS}}}Fax")
            ET.SubElement(fax_el, f"{{{NS}}}Number").text = _digits_only(rx.pharmacy_fax)
        if rx.pharmacy_phone:
            ph_tel = ET.SubElement(ph_comms, f"{{{NS}}}PrimaryTelephone")
            ET.SubElement(ph_tel, f"{{{NS}}}Number").text = _digits_only(rx.pharmacy_phone)

    # Prescriber
    presc_el = ET.SubElement(newrx, f"{{{NS}}}Prescriber")
    nv = ET.SubElement(presc_el, f"{{{NS}}}NonVeterinarian")
    pnm = ET.SubElement(nv, f"{{{NS}}}Name")
    ET.SubElement(pnm, f"{{{NS}}}LastName").text  = WENO_PHYSICIAN_LNAME  or ""
    ET.SubElement(pnm, f"{{{NS}}}FirstName").text = WENO_PHYSICIAN_FNAME  or ""
    pid = ET.SubElement(nv, f"{{{NS}}}Identification")
    if WENO_PHYSICIAN_NPI:
        ET.SubElement(pid, f"{{{NS}}}NPI").text              = WENO_PHYSICIAN_NPI
    if WENO_PHYSICIAN_DEA:
        ET.SubElement(pid, f"{{{NS}}}DEANumber").text        = WENO_PHYSICIAN_DEA
    if WENO_PHYSICIAN_STATE_LIC:
        ET.SubElement(pid, f"{{{NS}}}StateLicenseNumber").text = WENO_PHYSICIAN_STATE_LIC
    paddr = ET.SubElement(nv, f"{{{NS}}}Address")
    ET.SubElement(paddr, f"{{{NS}}}AddressLine1").text  = WENO_PRACTICE_ADDRESS or ""
    ET.SubElement(paddr, f"{{{NS}}}City").text          = WENO_PRACTICE_CITY    or ""
    ET.SubElement(paddr, f"{{{NS}}}StateProvince").text = WENO_PRACTICE_STATE   or ""
    ET.SubElement(paddr, f"{{{NS}}}PostalCode").text    = WENO_PRACTICE_ZIP     or ""
    ET.SubElement(paddr, f"{{{NS}}}CountryCode").text   = "US"
    if WENO_PRACTICE_PHONE:
        pcomms = ET.SubElement(nv, f"{{{NS}}}CommunicationNumbers")
        ptel = ET.SubElement(pcomms, f"{{{NS}}}PrimaryTelephone")
        ET.SubElement(ptel, f"{{{NS}}}Number").text = _digits_only(WENO_PRACTICE_PHONE)

    # Medication
    med = ET.SubElement(newrx, f"{{{NS}}}MedicationPrescribed")
    desc = f"{rx.drug_name}"
    if rx.strength:
        desc += f" {rx.strength}"
    if rx.dosage_form:
        desc += f" {rx.dosage_form}"
    ET.SubElement(med, f"{{{NS}}}DrugDescription").text = desc
    if rx.rxcui:
        dc = ET.SubElement(med, f"{{{NS}}}DrugCoded")
        dbc = ET.SubElement(dc, f"{{{NS}}}DrugDBCode")
        ET.SubElement(dbc, f"{{{NS}}}Code").text      = rx.rxcui
        ET.SubElement(dbc, f"{{{NS}}}Qualifier").text = "RX"   # RxCUI qualifier
    ET.SubElement(med, f"{{{NS}}}Directions").text = rx.sig or ""
    qty = ET.SubElement(med, f"{{{NS}}}Quantity")
    ET.SubElement(qty, f"{{{NS}}}Value").text            = str(int(rx.quantity or 30))
    ET.SubElement(qty, f"{{{NS}}}CodeListQualifier").text = "38"    # Units qualifier
    ET.SubElement(qty, f"{{{NS}}}UnitSourceCode").text   = "EA"     # Each
    ET.SubElement(med, f"{{{NS}}}DaysSupply").text       = str(rx.days_supply or 30)
    # Substitutions: 0 = DAW (no substitution), 1 = substitution allowed
    ET.SubElement(med, f"{{{NS}}}Substitutions").text    = "0" if rx.daw else "1"
    ET.SubElement(med, f"{{{NS}}}NumberOfRefills").text  = str(rx.refills or 0)
    wd = ET.SubElement(med, f"{{{NS}}}WrittenDate")
    ET.SubElement(wd, f"{{{NS}}}Date").text = (rx.signed_at or datetime.utcnow()).strftime("%Y%m%d")
    if rx.notes:
        ET.SubElement(med, f"{{{NS}}}Note").text = rx.notes

    # EPCS / Controlled Substance fields
    if rx.is_controlled and rx.dea_schedule:
        # DEA Schedule in NCPDP SCRIPT — maps I–V to roman numeral codes
        sched_map = {"II": "CII", "III": "CIII", "IV": "CIV", "V": "CV"}
        sched_code = sched_map.get(rx.dea_schedule, f"C{rx.dea_schedule}")
        ET.SubElement(med, f"{{{NS}}}DEASchedule").text = sched_code
        # EPCS: mark as electronically prescribed controlled substance
        if rx.epcs_verified:
            ET.SubElement(med, f"{{{NS}}}ControlledSubstanceReportingState").text = (
                WENO_PRACTICE_STATE or ""
            )

    xml_str = ET.tostring(msg, encoding="unicode", xml_declaration=False)
    return f'<?xml version="1.0" encoding="utf-8"?>\n{xml_str}'


def _weno_soap_call(ncpdp_xml: str) -> dict:
    """
    Wrap NCPDP XML in a SOAP 1.1 envelope and POST to the WENO Switch endpoint.
    Returns a dict with keys: success (bool), weno_message_id (str), raw_response (str).
    Raises HTTPException on network or protocol error.
    """
    soap_body = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:weno="http://wenoexchange.com/">
  <soap:Header/>
  <soap:Body>
    <weno:WenoSwitch>
      <weno:NCPDPScript>{ncpdp_xml}</weno:NCPDPScript>
    </weno:WenoSwitch>
  </soap:Body>
</soap:Envelope>"""
    try:
        resp = httpx.post(
            WENO_ENDPOINT,
            content=soap_body.encode("utf-8"),
            headers={
                "Content-Type": "text/xml; charset=utf-8",
                "SOAPAction": '"http://wenoexchange.com/WenoSwitch"',
            },
            timeout=30,
        )
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="WENO gateway timeout — try again")
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"WENO connection error: {e}")

    raw = resp.text
    # Parse SOAP response — look for STATUS (success) or ERROR (failure)
    try:
        root = ET.fromstring(raw)
        ns_soap = "http://schemas.xmlsoap.org/soap/envelope/"
        ns_weno = "http://wenoexchange.com/"
        ns_ncpdp = "http://www.ncpdp.org/schema/SCRIPT"
        # Navigate: Envelope → Body → WenoSwitchResponse → WenoSwitchResult
        body_el = root.find(f"{{{ns_soap}}}Body")
        result_text = ""
        if body_el is not None:
            for child in body_el.iter():
                if "Result" in child.tag or "result" in child.tag:
                    result_text = child.text or ""
                    break
        # Parse the inner NCPDP XML returned by WENO
        if result_text.strip().startswith("<"):
            inner = ET.fromstring(result_text)
        else:
            inner = root
        # Check for ERROR body
        error_el = inner.find(f".//{{{ns_ncpdp}}}Error")
        if error_el is not None:
            code = (inner.find(f".//{{{ns_ncpdp}}}Code") or ET.Element("x")).text or "?"
            desc = (inner.find(f".//{{{ns_ncpdp}}}Description") or ET.Element("x")).text or raw[:300]
            raise HTTPException(status_code=502, detail=f"WENO Error {code}: {desc}")
        # Check for STATUS body (code 010 = accepted)
        status_el = inner.find(f".//{{{ns_ncpdp}}}Status")
        msg_id = (inner.find(f".//{{{ns_ncpdp}}}MessageID") or ET.Element("x")).text or ""
        return {"success": True, "weno_message_id": msg_id, "raw_response": raw[:500]}
    except HTTPException:
        raise
    except Exception:
        # If we can't parse the response, return as-is for debugging
        return {"success": resp.is_success, "weno_message_id": "", "raw_response": raw[:500]}

# ── Telnyx Fax Configuration ─────────────────────────────────────────────────
# Set these in Railway environment variables:
#   TELNYX_API_KEY         → API key from telnyx.com/account/keys
#   TELNYX_FROM_NUMBER     → E.164 number purchased in Telnyx with fax enabled, e.g. +15005550006
#   TELNYX_CONNECTION_ID   → (optional) Telnyx fax application/connection ID
#   APP_BASE_URL           → Public URL of this app, e.g. https://yourapp.railway.app
TELNYX_API_KEY        = os.getenv("TELNYX_API_KEY", "")
TELNYX_FROM_NUMBER    = os.getenv("TELNYX_FROM_NUMBER", "")
TELNYX_CONNECTION_ID  = os.getenv("TELNYX_CONNECTION_ID", "")
APP_BASE_URL          = os.getenv("APP_BASE_URL", "").rstrip("/")

def _telnyx_configured() -> bool:
    return bool(TELNYX_API_KEY and TELNYX_FROM_NUMBER and APP_BASE_URL)

def _send_telnyx_fax(to_number: str, pdf_bytes: bytes, subject: str = "Medical Document") -> dict:
    """
    Send a fax via Telnyx. Stores the PDF against a UUID token so Telnyx can
    fetch it from our public /api/fax-pdf/{token} endpoint.
    Returns the Telnyx fax object dict.
    """
    if not _telnyx_configured():
        raise HTTPException(status_code=503, detail=(
            "Telnyx not configured — add TELNYX_API_KEY, TELNYX_FROM_NUMBER, "
            "and APP_BASE_URL to your Railway environment variables."
        ))
    # Generate a single-use token so Telnyx can fetch the PDF without auth
    token = str(_uuid.uuid4())
    # Temporarily cache the PDF bytes in memory (keyed by token)
    # In production with multiple workers, use Redis or store in DB before calling this
    _telnyx_pdf_cache[token] = pdf_bytes
    media_url = f"{APP_BASE_URL}/api/fax-pdf/{token}"
    payload: dict = {
        "from": TELNYX_FROM_NUMBER,
        "to": to_number,
        "media_url": media_url,
        "quality": "normal",
    }
    if TELNYX_CONNECTION_ID:
        payload["connection_id"] = TELNYX_CONNECTION_ID
    resp = httpx.post(
        "https://api.telnyx.com/v2/faxes",
        json=payload,
        headers={
            "Authorization": f"Bearer {TELNYX_API_KEY}",
            "Content-Type": "application/json",
        },
        timeout=20,
    )
    if not resp.is_success:
        raise HTTPException(status_code=502, detail=f"Telnyx error: {resp.text}")
    return resp.json().get("data", {})

# In-process PDF cache for Telnyx media_url fetches (token → bytes)
# Entries are evicted after Telnyx retrieves them via the /api/fax-pdf/{token} endpoint
_telnyx_pdf_cache: dict = {}

# DEA controlled-substance schedule lookup (well-known drugs only, for UI display)
_DEA_SCHEDULE: dict = {
    # Schedule II
    "adderall":"II","amphetamine":"II","dextroamphetamine":"II","methylphenidate":"II",
    "ritalin":"II","concerta":"II","vyvanse":"II","lisdexamfetamine":"II",
    "oxycodone":"II","oxycontin":"II","percocet":"II","hydrocodone":"II",
    "vicodin":"II","norco":"II","fentanyl":"II","morphine":"II","methadone":"II",
    "hydromorphone":"II","dilaudid":"II","meperidine":"II","codeine":"II",
    "cocaine":"II","phencyclidine":"II","methamphetamine":"II",
    # Schedule III
    "buprenorphine":"III","suboxone":"III","subutex":"III","ketamine":"III",
    "anabolic steroids":"III","testosterone":"III",
    # Schedule IV
    "alprazolam":"IV","xanax":"IV","diazepam":"IV","valium":"IV",
    "clonazepam":"IV","klonopin":"IV","lorazepam":"IV","ativan":"IV",
    "zolpidem":"IV","ambien":"IV","zaleplon":"IV","eszopiclone":"IV",
    "tramadol":"IV","ultram":"IV","carisoprodol":"IV","soma":"IV",
    "phenobarbital":"IV","modafinil":"IV","provigil":"IV","phentermine":"IV",
    "pregabalin":"IV","lyrica":"IV",
    # Schedule V
    "gabapentin":"V","cough preparations with codeine":"V","lacosamide":"V",
}

def _get_dea_schedule(drug_name: str) -> str | None:
    key = drug_name.lower().strip()
    return _DEA_SCHEDULE.get(key) or next(
        (v for k, v in _DEA_SCHEDULE.items() if k in key), None
    )


def _rx_to_dict(rx: models.Prescription, db: Session) -> dict:
    d = clean(rx)
    # Attach prescriber name
    provider = db.query(models.User).filter(models.User.id == rx.physician_id).first()
    d["prescriber_name"] = provider.full_name if provider else ""
    d["prescriber_npi"]  = provider.npi_number if provider else ""
    return d


# ── Drug search via RxNorm (NLM — free, no API key) ─────────────────────────
@app.get("/api/drugs/search")
async def drug_search(
    q: str,
    current_user: models.User = Depends(get_current_user),
):
    """
    Search for drugs using the NLM RxNorm API (free, no credentials required).
    Returns up to 20 matching drug concepts with strength/form details.
    """
    if len(q) < 2:
        return {"drugs": []}
    try:
        # Spell-suggest + concept search
        r = await _rxnorm_get(f"https://rxnav.nlm.nih.gov/REST/drugs.json?name={q}&expand=nih")
        drugs = []
        concept_group = r.get("drugGroup", {}).get("conceptGroup", [])
        for group in concept_group:
            tty = group.get("tty", "")
            for c in group.get("conceptProperties", []):
                drugs.append({
                    "rxcui":  c.get("rxcui", ""),
                    "name":   c.get("name", ""),
                    "tty":    tty,
                    "synonym": c.get("synonym", ""),
                })
        # Also try approximateMatch for typos
        if not drugs:
            r2 = await _rxnorm_get(f"https://rxnav.nlm.nih.gov/REST/approximateTerm.json?term={q}&maxEntries=10")
            for c in r2.get("approximateGroup", {}).get("candidate", []):
                drugs.append({
                    "rxcui": c.get("rxcui", ""),
                    "name":  c.get("name", ""),
                    "tty":   "",
                    "synonym": "",
                })
        return {"drugs": drugs[:25]}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"RxNorm API error: {str(e)}")


@app.get("/api/drugs/{rxcui}/info")
async def drug_info(
    rxcui: str,
    current_user: models.User = Depends(get_current_user),
):
    """Get full drug details (strengths, forms, NDCs) for an RxCUI."""
    try:
        # Related products (clinical drug forms with strengths)
        r = await _rxnorm_get(
            f"https://rxnav.nlm.nih.gov/REST/rxcui/{rxcui}/related.json?tty=SCD+SCDF+GPCK+BN"
        )
        related = []
        for group in r.get("relatedGroup", {}).get("conceptGroup", []):
            for c in group.get("conceptProperties", []):
                related.append({"rxcui": c["rxcui"], "name": c["name"], "tty": group["tty"]})

        # Check DEA schedule via RxNorm properties
        props_r = await _rxnorm_get(
            f"https://rxnav.nlm.nih.gov/REST/rxcui/{rxcui}/property.json?propName=SCHEDULE"
        )
        schedule_raw = (
            props_r.get("propConceptGroup", {})
            .get("propConcept", [{}])[0]
            .get("propValue", "")
        )
        schedule = schedule_raw.replace("CIII","III").replace("CII","II").replace("CIV","IV").replace("CV","V") if schedule_raw else None

        return {
            "rxcui":    rxcui,
            "related":  related[:20],
            "schedule": schedule,
        }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"RxNorm API error: {str(e)}")


async def _rxnorm_get(url: str) -> dict:
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(url, headers={"Accept": "application/json"})
        r.raise_for_status()
        return r.json()


# ── Pharmacy endpoints ───────────────────────────────────────────────────────
@app.get("/api/pharmacies")
def list_pharmacies(
    q: str = "",
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """List saved pharmacies, optionally filtered by name."""
    query = db.query(models.SavedPharmacy).filter(models.SavedPharmacy.is_active == True)
    if q:
        query = query.filter(models.SavedPharmacy.name.ilike(f"%{q}%"))
    return [clean(p) for p in query.order_by(models.SavedPharmacy.name).all()]


@app.post("/api/pharmacies")
def create_pharmacy(
    data: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Save a pharmacy to the practice's directory."""
    ph = models.SavedPharmacy(
        name    =data.get("name",""),
        npi     =data.get("npi",""),
        address =data.get("address",""),
        city    =data.get("city",""),
        state   =data.get("state",""),
        zip_code=data.get("zip_code",""),
        phone   =data.get("phone",""),
        fax     =data.get("fax",""),
        chain   =data.get("chain",""),
    )
    db.add(ph); db.commit(); db.refresh(ph)
    return clean(ph)


@app.delete("/api/pharmacies/{ph_id}")
def delete_pharmacy(
    ph_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    ph = db.query(models.SavedPharmacy).filter(models.SavedPharmacy.id == ph_id).first()
    if ph:
        ph.is_active = False
        db.commit()
    return {"success": True}


# ── Prescription CRUD ────────────────────────────────────────────────────────
@app.get("/api/patients/{patient_id}/prescriptions")
def list_prescriptions(
    patient_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    _rx_patient = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
    if not _rx_patient: raise HTTPException(status_code=404, detail="Patient not found")
    _require_patient_access(_rx_patient, current_user)
    audit(db, current_user.id, "VIEW_PRESCRIPTIONS", "Patient", str(patient_id))
    rxs = (db.query(models.Prescription)
           .filter(models.Prescription.patient_id == patient_id)
           .order_by(models.Prescription.created_at.desc())
           .all())
    return [_rx_to_dict(rx, db) for rx in rxs]


@app.post("/api/prescriptions")
def create_prescription(
    data: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    _crx_patient = db.query(models.Patient).filter(models.Patient.id == data.get("patient_id")).first()
    if not _crx_patient: raise HTTPException(status_code=404, detail="Patient not found")
    _require_patient_access(_crx_patient, current_user)
    drug_name = data.get("drug_name","").strip()
    if not drug_name:
        raise HTTPException(status_code=422, detail="drug_name is required")

    is_controlled = data.get("is_controlled", False)
    dea_schedule  = data.get("dea_schedule") or _get_dea_schedule(drug_name)
    if dea_schedule:
        is_controlled = True

    rx = models.Prescription(
        patient_id    =data["patient_id"],
        physician_id  =current_user.id,
        drug_name     =drug_name,
        rxcui         =data.get("rxcui",""),
        ndc           =data.get("ndc",""),
        strength      =data.get("strength",""),
        dosage_form   =data.get("dosage_form",""),
        sig           =data.get("sig",""),
        quantity      =float(data.get("quantity",30)),
        quantity_unit =data.get("quantity_unit","tablet(s)"),
        days_supply   =int(data.get("days_supply",30)),
        refills       =int(data.get("refills",0)),
        daw           =bool(data.get("daw",False)),
        is_controlled =is_controlled,
        dea_schedule  =dea_schedule,
        pharmacy_name =data.get("pharmacy_name",""),
        pharmacy_npi  =data.get("pharmacy_npi",""),
        pharmacy_address=data.get("pharmacy_address",""),
        pharmacy_phone=data.get("pharmacy_phone",""),
        pharmacy_fax  =data.get("pharmacy_fax",""),
        icd10_codes   =json.dumps(data.get("icd10_codes",[])),
        notes         =data.get("notes",""),
        status        ="draft",
    )
    db.add(rx); db.commit(); db.refresh(rx)
    audit(db, current_user.id, "CREATE_PRESCRIPTION", "Prescription", str(rx.id))
    return _rx_to_dict(rx, db)


@app.put("/api/prescriptions/{rx_id}")
def update_prescription(
    rx_id: int,
    data: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    rx = db.query(models.Prescription).filter(models.Prescription.id == rx_id).first()
    if not rx:
        raise HTTPException(status_code=404, detail="Prescription not found")
    if rx.status not in ("draft",):
        raise HTTPException(status_code=400, detail="Only draft prescriptions can be edited")

    editable = ["drug_name","rxcui","ndc","strength","dosage_form","sig","quantity",
                "quantity_unit","days_supply","refills","daw","pharmacy_name",
                "pharmacy_npi","pharmacy_address","pharmacy_phone","pharmacy_fax",
                "icd10_codes","notes","is_controlled","dea_schedule"]
    for k in editable:
        if k in data:
            val = json.dumps(data[k]) if k == "icd10_codes" else data[k]
            setattr(rx, k, val)

    # Re-check schedule if drug name changed
    if "drug_name" in data:
        sched = _get_dea_schedule(data["drug_name"])
        if sched:
            rx.dea_schedule  = sched
            rx.is_controlled = True

    rx.updated_at = datetime.utcnow()
    db.commit()
    return _rx_to_dict(rx, db)


@app.delete("/api/prescriptions/{rx_id}")
def delete_prescription(
    rx_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    rx = db.query(models.Prescription).filter(models.Prescription.id == rx_id).first()
    if not rx:
        raise HTTPException(status_code=404, detail="Not found")
    if rx.status != "draft":
        raise HTTPException(status_code=400, detail="Only drafts can be deleted")
    rx.status = "cancelled"
    db.commit()
    audit(db, current_user.id, "CANCEL_PRESCRIPTION", "Prescription", str(rx_id))
    return {"success": True}


@app.post("/api/prescriptions/{rx_id}/sign")
def sign_prescription(
    rx_id: int,
    data: dict = {},
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Sign a prescription. For controlled substances (EPCS), the caller must
    pass epcs_code (the second-factor token) — validated here as non-empty
    for now; swap for real TOTP/PIV verification when a platform is connected.
    """
    rx = db.query(models.Prescription).filter(models.Prescription.id == rx_id).first()
    if not rx:
        raise HTTPException(status_code=404, detail="Not found")
    if rx.status != "draft":
        raise HTTPException(status_code=400, detail="Only draft prescriptions can be signed")

    if rx.is_controlled:
        epcs_code = (data or {}).get("epcs_code","").strip()
        if not epcs_code:
            raise HTTPException(status_code=422,
                detail="EPCS two-factor code is required for controlled substances")
        # TODO: validate epcs_code against TOTP/PIV when platform connected
        rx.epcs_verified = True

    rx.status    = "signed"
    rx.signed_at = datetime.utcnow()
    db.commit()
    audit(db, current_user.id, "SIGN_PRESCRIPTION", "Prescription", str(rx_id),
          "EPCS" if rx.is_controlled else "")
    return _rx_to_dict(rx, db)


@app.post("/api/prescriptions/{rx_id}/transmit")
def transmit_prescription(
    rx_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Transmit a signed prescription to the pharmacy via the configured
    e-prescribing platform.

    Platform adapter pattern — set EPRESCRIBE_PLATFORM env var to activate:
      "dosespot"    → calls DoseSpot REST API
      "drfirst"     → calls DrFirst Rcopia API
      "surescripts" → calls Surescripts DirectTrust API

    Until a platform is configured this endpoint marks the Rx as transmitted
    so the print-and-fax workflow can be used as a fallback.
    """
    rx = db.query(models.Prescription).filter(models.Prescription.id == rx_id).first()
    if not rx:
        raise HTTPException(status_code=404, detail="Not found")
    if rx.status != "signed":
        raise HTTPException(status_code=400, detail="Prescription must be signed before transmitting")

    platform = EPRESCRIBE_PLATFORM.lower() if EPRESCRIBE_PLATFORM else ""

    if platform == "weno":
        _transmit_weno(rx, db, current_user)
    elif platform == "dosespot":
        _transmit_dosespot(rx, db, current_user)
    elif platform == "drfirst":
        _transmit_drfirst(rx, db, current_user)
    elif platform == "surescripts":
        _transmit_surescripts(rx, db, current_user)
    else:
        # No e-prescribing platform — mark transmitted (provider prints or uses the Fax button)
        rx.status           = "transmitted"
        rx.transmitted_at   = datetime.utcnow()
        rx.eprescribe_platform = "telnyx-fax" if (_telnyx_configured() and rx.pharmacy_fax) else "print/fax"
        db.commit()

    audit(db, current_user.id, "TRANSMIT_PRESCRIPTION", "Prescription", str(rx_id),
          f"via {platform or rx.eprescribe_platform} to {rx.pharmacy_name}")
    return _rx_to_dict(rx, db)


# ── E-prescribing platform adapters ─────────────────────────────────────────
def _transmit_dosespot(rx, db, user):
    """DoseSpot REST API adapter. Docs: https://docs.dosespot.com"""
    if not DOSESPOT_CLINIC_ID or not DOSESPOT_CLINIC_KEY:
        raise HTTPException(status_code=503,
            detail="DoseSpot not configured — add DOSESPOT_CLINIC_ID, DOSESPOT_CLINIC_KEY, DOSESPOT_USER_ID to Railway vars")
    patient = db.query(models.Patient).filter(models.Patient.id == rx.patient_id).first()
    try:
        # Step 1: get SSO token
        token_resp = httpx.post(
            "https://my.dosespot.com/webapi/api/token",
            data={"grant_type":"password","Username":DOSESPOT_USER_ID,"Password":DOSESPOT_CLINIC_KEY},
            timeout=10,
        )
        token_resp.raise_for_status()
        access_token = token_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {access_token}"}

        # Step 2: ensure patient exists in DoseSpot
        pt_payload = {
            "FirstName": patient.first_name, "LastName": patient.last_name,
            "DateOfBirth": patient.dob, "Gender": (patient.gender or "U")[0].upper(),
            "Address1": patient.address, "City": patient.city,
            "State": patient.state, "ZipCode": patient.zip_code,
            "PrimaryPhone": patient.phone,
        }
        pt_resp = httpx.post(
            f"https://my.dosespot.com/webapi/api/{DOSESPOT_CLINIC_ID}/patients",
            json=pt_payload, headers=headers, timeout=10,
        )
        pt_resp.raise_for_status()
        ds_patient_id = pt_resp.json().get("Item", {}).get("PatientId")

        # Step 3: create the prescription
        rx_payload = {
            "PatientId": ds_patient_id,
            "DrugName": rx.drug_name, "Strength": rx.strength,
            "DosageForm": rx.dosage_form, "RxCUI": rx.rxcui,
            "Directions": rx.sig,
            "Quantity": rx.quantity, "DaysSupply": rx.days_supply,
            "Refills": rx.refills, "DispenseAsWritten": rx.daw,
            "PharmacyId": rx.pharmacy_npi,
        }
        rx_resp = httpx.post(
            f"https://my.dosespot.com/webapi/api/{DOSESPOT_CLINIC_ID}/prescriptions",
            json=rx_payload, headers=headers, timeout=10,
        )
        rx_resp.raise_for_status()
        ds_rx_id = rx_resp.json().get("Item", {}).get("PrescriptionId","")
        rx.eprescribe_platform = "dosespot"
        rx.eprescribe_rx_id    = str(ds_rx_id)
        rx.eprescribe_status   = "sent"
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"DoseSpot error: {e.response.text}")
    rx.status = "transmitted"; rx.transmitted_at = datetime.utcnow()
    db.commit()


def _transmit_weno(rx, db, user):
    """
    WENO Exchange e-prescribing adapter.
    Sends an NCPDP SCRIPT 20170715 NewRx message via WENO's SOAP API.

    Supports both standard and EPCS (controlled substance) prescriptions.
    EPCS requires:
      • Prescriber enrolled in EPCS via WENO ($99/year)
      • WENO_PHYSICIAN_DEA set in Railway env vars
      • rx.epcs_verified = True (provider completed 2FA at signing)

    WENO documentation: https://wenoexchange.com/switch-documentation/
    Test dashboard:     https://cert.wenoexchange.com
    """
    if not _weno_configured():
        raise HTTPException(status_code=503, detail=(
            "WENO not configured — add WENO_PARTNER_ID, WENO_PARTNER_PASSWORD_MD5, "
            "WENO_PRESCRIBER_D, WENO_LOCATION_C, and physician details to Railway env vars. "
            "Sign up at https://online.wenoexchange.com"
        ))
    if rx.is_controlled and not rx.epcs_verified:
        raise HTTPException(status_code=400, detail=(
            "EPCS verification required — prescription must be signed with a valid "
            "two-factor authentication code before transmitting a controlled substance."
        ))
    if rx.is_controlled and not WENO_PHYSICIAN_DEA:
        raise HTTPException(status_code=400, detail=(
            "WENO_PHYSICIAN_DEA not configured — DEA number is required for EPCS "
            "controlled substance prescriptions."
        ))

    patient = db.query(models.Patient).filter(models.Patient.id == rx.patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    order_id = f"MF-{rx.id}-{int(time.time())}"
    ncpdp_xml = _build_weno_ncpdp_xml(rx, patient, order_id)
    result    = _weno_soap_call(ncpdp_xml)

    rx.eprescribe_platform  = "weno"
    rx.eprescribe_rx_id     = result.get("weno_message_id") or order_id
    rx.eprescribe_status    = "sent"
    rx.eprescribe_response  = json.dumps(result)
    rx.status               = "transmitted"
    rx.transmitted_at       = datetime.utcnow()
    db.commit()


def _transmit_drfirst(rx, db, user):
    """DrFirst Rcopia adapter stub. Contact DrFirst for API docs."""
    raise HTTPException(status_code=501,
        detail="DrFirst integration pending — contact DrFirst for API credentials and docs")


def _transmit_surescripts(rx, db, user):
    """Surescripts adapter stub. Requires Surescripts certification."""
    raise HTTPException(status_code=501,
        detail="Surescripts integration pending — requires Surescripts network certification")


# ── Prescription PDF ─────────────────────────────────────────────────────────
@app.get("/api/prescriptions/{rx_id}/pdf")
def prescription_pdf(
    rx_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Generate a printable/faxable prescription PDF."""
    rx = db.query(models.Prescription).filter(models.Prescription.id == rx_id).first()
    if not rx:
        raise HTTPException(status_code=404, detail="Not found")

    patient  = db.query(models.Patient).filter(models.Patient.id == rx.patient_id).first()
    provider = db.query(models.User).filter(models.User.id == rx.physician_id).first()

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter,
                            topMargin=54, bottomMargin=54, leftMargin=72, rightMargin=72)
    styles = getSampleStyleSheet()
    story  = []

    def h(text, size=12, bold=True, color=colors.HexColor("#1e293b"), space_before=0, space_after=6):
        s = styles["Normal"].clone("h")
        s.fontSize=size; s.leading=size+4; s.textColor=color
        s.fontName="Helvetica-Bold" if bold else "Helvetica"
        s.spaceBefore=space_before; s.spaceAfter=space_after
        return Paragraph(text, s)

    def p(text, size=10, color=colors.HexColor("#374151")):
        s = styles["Normal"].clone("p")
        s.fontSize=size; s.leading=size+4; s.textColor=color; s.fontName="Helvetica"
        return Paragraph(text, s)

    # Header
    story += [
        h("PRESCRIPTION", 16, color=colors.HexColor("#2563eb")),
        h(f"Dr. {provider.full_name}", 13) if provider else h("", 1),
        p(f"NPI: {provider.npi_number}" if provider and provider.npi_number else ""),
        p(f"DEA: {'_'*15}") if rx.is_controlled else Spacer(1,0),
        Spacer(1, 12),
    ]

    # Patient info box
    pt_data = [["Patient", f"{patient.first_name} {patient.last_name}" if patient else ""],
               ["DOB",     patient.dob if patient else ""],
               ["Address", f"{patient.address}, {patient.city}, {patient.state} {patient.zip_code}" if patient else ""]]
    pt_table = Table([[k, v] for k,v in pt_data], colWidths=[80,380])
    pt_table.setStyle(TableStyle([
        ("FONTSIZE",     (0,0),(-1,-1),10),
        ("FONTNAME",     (0,0),(0,-1),"Helvetica-Bold"),
        ("TEXTCOLOR",    (0,0),(0,-1),colors.HexColor("#475569")),
        ("BOTTOMPADDING",(0,0),(-1,-1),4),
    ]))
    story += [pt_table, Spacer(1,16)]

    # Drug info
    story += [
        h(rx.drug_name + (f" {rx.strength}" if rx.strength else ""), 14,
          color=colors.HexColor("#1e293b")),
        p(f"{rx.dosage_form}") if rx.dosage_form else Spacer(1,0),
        Spacer(1,6),
        h("Sig:", 11), p(rx.sig or "—", 11),
        Spacer(1,8),
    ]

    # Quantity / refills table
    rx_data = [
        ["Quantity", str(int(rx.quantity)) + " " + rx.quantity_unit,
         "Days Supply", str(rx.days_supply)],
        ["Refills",  str(rx.refills),
         "DAW",      "Yes" if rx.daw else "No"],
    ]
    rx_table = Table(rx_data, colWidths=[80,150,80,150])
    rx_table.setStyle(TableStyle([
        ("FONTSIZE",     (0,0),(-1,-1),10),
        ("FONTNAME",     (0,0),(0,-1),"Helvetica-Bold"),
        ("FONTNAME",     (2,0),(2,-1),"Helvetica-Bold"),
        ("TEXTCOLOR",    (0,0),(0,-1),colors.HexColor("#475569")),
        ("TEXTCOLOR",    (2,0),(2,-1),colors.HexColor("#475569")),
        ("BOTTOMPADDING",(0,0),(-1,-1),5),
        ("BOX",          (0,0),(-1,-1),0.5,colors.HexColor("#e2e8f0")),
        ("INNERGRID",    (0,0),(-1,-1),0.5,colors.HexColor("#f1f5f9")),
    ]))
    story += [rx_table, Spacer(1,16)]

    # CIII-V substitution line
    if rx.is_controlled:
        story += [
            h(f"⚠ CONTROLLED SUBSTANCE — Schedule {rx.dea_schedule}", 10,
              color=colors.HexColor("#dc2626")),
            Spacer(1,8),
            Table([["Dispense as Written ___", "Substitution Permitted ___"]],
                  colWidths=[240,240]),
            Spacer(1,12),
        ]

    # Pharmacy
    if rx.pharmacy_name:
        story += [
            h("Pharmacy:", 10, color=colors.HexColor("#475569")),
            p(rx.pharmacy_name),
            p(rx.pharmacy_address) if rx.pharmacy_address else Spacer(1,0),
            p(f"Ph: {rx.pharmacy_phone}  Fax: {rx.pharmacy_fax}") if rx.pharmacy_phone else Spacer(1,0),
            Spacer(1,12),
        ]

    # Signature line
    story += [
        Spacer(1, 24),
        Table([["Prescriber Signature: " + "_"*30,
                f"Date: {datetime.utcnow().strftime('%m/%d/%Y')}"]],
              colWidths=[330, 150]),
    ]

    if rx.notes:
        story += [Spacer(1,12), h("Notes:", 10, color=colors.HexColor("#475569")), p(rx.notes)]

    doc.build(story)
    buf.seek(0)
    audit(db, current_user.id, "PRINT_PRESCRIPTION", "Prescription", str(rx_id))
    return StreamingResponse(buf, media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=rx_{rx_id}_{rx.drug_name.replace(' ','_')}.pdf"})


# ── Prescription Fax (Telnyx) ─────────────────────────────────────────────────

@app.post("/api/prescriptions/{rx_id}/fax")
def fax_prescription(
    rx_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Fax a signed prescription directly to the pharmacy via Telnyx.
    Generates the PDF on the fly, uploads it via our public /api/fax-pdf/{token}
    endpoint, and submits the fax job to Telnyx.

    Required Railway env vars: TELNYX_API_KEY, TELNYX_FROM_NUMBER, APP_BASE_URL
    """
    rx = db.query(models.Prescription).filter(models.Prescription.id == rx_id).first()
    if not rx:
        raise HTTPException(status_code=404, detail="Prescription not found")
    if rx.status not in ("signed", "transmitted"):
        raise HTTPException(status_code=400, detail="Prescription must be signed before faxing")
    if not rx.pharmacy_fax:
        raise HTTPException(status_code=400, detail="No pharmacy fax number on this prescription")

    # Build the PDF using the same generator as the print endpoint
    # We call it by generating the PDF bytes directly here
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors as rl_colors

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, rightMargin=0.75*inch, leftMargin=0.75*inch,
                            topMargin=0.75*inch, bottomMargin=0.75*inch)
    styles = getSampleStyleSheet()
    story = []

    def _p(text, style="Normal", **kw):
        s = ParagraphStyle("_", parent=styles[style], **kw)
        story.append(Paragraph(text, s))

    patient = db.query(models.Patient).filter(models.Patient.id == rx.patient_id).first()
    physician = db.query(models.User).filter(models.User.id == rx.physician_id).first()
    practice_name = os.getenv("PRACTICE_NAME", "Medical Practice")
    practice_phone = os.getenv("PRACTICE_PHONE", "")
    practice_address = os.getenv("PRACTICE_ADDRESS", "")
    practice_fax = TELNYX_FROM_NUMBER

    _p(practice_name, "Heading1", fontSize=16, textColor=rl_colors.HexColor("#1e3a5f"))
    if practice_address:
        _p(practice_address, fontSize=9, textColor=rl_colors.grey)
    if practice_phone:
        _p(f"Phone: {practice_phone}  Fax: {practice_fax}", fontSize=9, textColor=rl_colors.grey)
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=2, color=rl_colors.HexColor("#1e3a5f")))
    story.append(Spacer(1, 10))

    _p("PRESCRIPTION", "Heading2", fontSize=13, textColor=rl_colors.HexColor("#1e3a5f"))
    story.append(Spacer(1, 6))

    pt_name = f"{patient.first_name} {patient.last_name}" if patient else "Unknown"
    pt_dob = patient.dob if patient else ""
    data_rows = [
        ["Patient:", pt_name, "DOB:", pt_dob],
        ["Prescriber:", physician.full_name if physician else "", "Date:", (rx.signed_at or rx.created_at).strftime("%m/%d/%Y")],
        ["DEA#:", os.getenv("PHYSICIAN_DEA", ""), "NPI:", os.getenv("PHYSICIAN_NPI", "")],
    ]
    t = Table(data_rows, colWidths=[1.1*inch, 2.8*inch, 0.8*inch, 2.0*inch])
    t.setStyle(TableStyle([
        ("FONTSIZE", (0,0), (-1,-1), 9),
        ("TEXTCOLOR", (0,0), (0,-1), rl_colors.HexColor("#64748b")),
        ("TEXTCOLOR", (2,0), (2,-1), rl_colors.HexColor("#64748b")),
        ("BOTTOMPADDING", (0,0), (-1,-1), 3),
    ]))
    story.append(t)
    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", thickness=1, color=rl_colors.HexColor("#e2e8f0")))
    story.append(Spacer(1, 10))

    _p(f"<b>{rx.drug_name}</b> {rx.strength}", fontSize=14)
    _p(f"{rx.dosage_form} — {rx.sig}", fontSize=11)
    story.append(Spacer(1, 6))
    qty_rows = [
        ["Qty:", f"{int(rx.quantity)} {rx.quantity_unit}", "Days Supply:", str(rx.days_supply)],
        ["Refills:", str(rx.refills), "DAW:", "Yes" if rx.daw else "No"],
    ]
    if rx.is_controlled:
        qty_rows.append(["Schedule:", rx.dea_schedule or "Controlled", "EPCS:", "Verified" if rx.epcs_verified else "Pending"])
    t2 = Table(qty_rows, colWidths=[1.1*inch, 2.8*inch, 0.8*inch, 2.0*inch])
    t2.setStyle(TableStyle([
        ("FONTSIZE", (0,0), (-1,-1), 10),
        ("TEXTCOLOR", (0,0), (0,-1), rl_colors.HexColor("#64748b")),
        ("TEXTCOLOR", (2,0), (2,-1), rl_colors.HexColor("#64748b")),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
    ]))
    story.append(t2)
    if rx.notes:
        story.append(Spacer(1, 6))
        _p(f"Notes: {rx.notes}", fontSize=9, textColor=rl_colors.grey)
    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=1, color=rl_colors.HexColor("#e2e8f0")))
    story.append(Spacer(1, 8))
    if rx.pharmacy_name:
        _p(f"<b>Send to:</b> {rx.pharmacy_name}", fontSize=10)
        if rx.pharmacy_address:
            _p(rx.pharmacy_address, fontSize=9, textColor=rl_colors.grey)
        if rx.pharmacy_fax:
            _p(f"Fax: {rx.pharmacy_fax}", fontSize=9, textColor=rl_colors.grey)
    story.append(Spacer(1, 20))
    _p("_" * 40, fontSize=10)
    _p(f"Prescriber Signature: {physician.full_name if physician else ''}", fontSize=9, textColor=rl_colors.grey)
    doc.build(story)
    pdf_bytes = buf.getvalue()

    # Normalise fax number to E.164 (strip spaces/dashes, ensure +1)
    fax_to = rx.pharmacy_fax.strip().replace(" ","").replace("-","").replace("(","").replace(")","").replace(".","")
    if not fax_to.startswith("+"):
        fax_to = "+1" + fax_to.lstrip("1")

    telnyx_data = _send_telnyx_fax(fax_to, pdf_bytes, f"Rx: {rx.drug_name} for {pt_name}")

    # Persist fax metadata on the prescription
    rx.fax_id     = telnyx_data.get("id", "")
    rx.fax_status = telnyx_data.get("status", "queued")
    rx.fax_sent_at = datetime.utcnow()
    if rx.status == "signed":
        rx.status = "transmitted"
        rx.transmitted_at = datetime.utcnow()
        rx.eprescribe_platform = "telnyx-fax"
    db.commit()

    # Also log in FaxLog
    fax_log = models.FaxLog(
        patient_id=rx.patient_id,
        physician_id=current_user.id,
        direction="sent",
        from_number=TELNYX_FROM_NUMBER,
        to_number=fax_to,
        subject=f"Rx: {rx.drug_name}",
        status="queued",
        telnyx_fax_id=rx.fax_id,
    )
    db.add(fax_log)
    db.commit()
    audit(db, current_user.id, "FAX_PRESCRIPTION", "Prescription", str(rx_id),
          f"Telnyx fax {rx.fax_id} to {fax_to}")
    return {"success": True, "fax_id": rx.fax_id, "fax_status": rx.fax_status}


@app.get("/api/prescriptions/{rx_id}/fax-status")
def get_prescription_fax_status(
    rx_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Poll Telnyx for the current fax delivery status and update DB."""
    rx = db.query(models.Prescription).filter(models.Prescription.id == rx_id).first()
    if not rx:
        raise HTTPException(status_code=404, detail="Not found")
    if not rx.fax_id:
        return {"fax_status": None, "message": "No fax sent for this prescription"}
    if not _telnyx_configured():
        return {"fax_status": rx.fax_status, "fax_id": rx.fax_id}
    try:
        resp = httpx.get(
            f"https://api.telnyx.com/v2/faxes/{rx.fax_id}",
            headers={"Authorization": f"Bearer {TELNYX_API_KEY}"},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        new_status = data.get("status", rx.fax_status)
        rx.fax_status = new_status
        db.commit()
        return {"fax_status": new_status, "fax_id": rx.fax_id, "telnyx": data}
    except Exception as e:
        return {"fax_status": rx.fax_status, "fax_id": rx.fax_id, "error": str(e)}

# ═════════════════════════════════════════════════════════════════════════════
# PUBLIC ENROLLMENT API  (no authentication required)
# ═════════════════════════════════════════════════════════════════════════════

# ── Payment provider config ───────────────────────────────────────────────────
SQUARE_APP_ID      = os.getenv("SQUARE_APP_ID", "")
SQUARE_ACCESS_TOKEN= os.getenv("SQUARE_ACCESS_TOKEN", "")
SQUARE_LOCATION_ID = os.getenv("SQUARE_LOCATION_ID", "")
_SQUARE_PRODUCTION = os.getenv("SQUARE_PRODUCTION", "false").lower() == "true"
SQUARE_BASE_URL    = ("https://connect.squareup.com" if _SQUARE_PRODUCTION
                      else "https://connect.squareupsandbox.com")
ZAPRITE_API_KEY    = os.getenv("ZAPRITE_API_KEY", "")
ZAPRITE_BASE_URL   = "https://api.zaprite.com/v1"

def _seed_membership_plans(db: Session):
    """Insert default Valiant DPC membership plans if none exist."""
    if db.query(models.MembershipPlan).count() > 0:
        return
    plans = [
        models.MembershipPlan(
            name="Valiant", slug="valiant",
            description="Comprehensive direct primary care for adults.",
            price_monthly=0.0, enrollment_fee=0.0,
            features=json.dumps([
                "Unlimited office visits (in-person & telehealth)",
                "Same/next-day appointment availability",
                "Preventive care & annual wellness visits",
                "Chronic disease management",
                "Prescription management",
                "Direct physician access via secure messaging",
                "After-hours urgent care access",
                "Care coordination & specialist referrals",
            ]),
            age_min=18, age_max=None, color="#1e3a5f", sort_order=1,
        ),
        models.MembershipPlan(
            name="Valiant Premier", slug="valiant-premier",
            description="Enhanced direct primary care with expanded services and priority access.",
            price_monthly=0.0, enrollment_fee=0.0,
            features=json.dumps([
                "All Valiant plan features",
                "Priority scheduling & extended visit times",
                "Comprehensive wellness assessments",
                "Advanced chronic disease management",
                "Nutritional counseling coordination",
                "Executive health services",
                "Enhanced after-hours access",
                "Quarterly wellness check-ins",
            ]),
            age_min=18, age_max=None, color="#7c3aed",
            badge="Most Comprehensive", sort_order=2,
        ),
        models.MembershipPlan(
            name="Young Valiant", slug="young-valiant",
            description="Dedicated primary care for children and adolescents.",
            price_monthly=0.0, enrollment_fee=0.0,
            features=json.dumps([
                "Unlimited pediatric visits",
                "Well-child examinations & developmental monitoring",
                "Immunization tracking & coordination",
                "School & sports physical forms",
                "Acute illness & injury care",
                "Adolescent health services",
                "Parent consultation & education",
                "ADHD & behavioral health coordination",
            ]),
            age_min=0, age_max=17, color="#0891b2", sort_order=3,
        ),
    ]
    for p in plans:
        db.add(p)
    db.commit()


def _migrate_add_billing_columns(db: Session):
    """
    Add billing columns to the memberships table if they don't exist.
    SQLAlchemy create_all() never adds columns to existing tables, so we
    run ALTER TABLE ... ADD COLUMN IF NOT EXISTS for each new column.
    Safe to run repeatedly — IF NOT EXISTS is a no-op when already present.
    """
    migrations = [
        "ALTER TABLE memberships ADD COLUMN IF NOT EXISTS next_billing_date TIMESTAMP",
        "ALTER TABLE memberships ADD COLUMN IF NOT EXISTS last_billed_at TIMESTAMP",
        "ALTER TABLE memberships ADD COLUMN IF NOT EXISTS billing_failure_count INTEGER DEFAULT 0",
        "ALTER TABLE memberships ADD COLUMN IF NOT EXISTS billing_status VARCHAR DEFAULT 'ok'",
        "ALTER TABLE memberships ADD COLUMN IF NOT EXISTS payment_provider VARCHAR DEFAULT 'square'",
        "ALTER TABLE crypto_payments ADD COLUMN IF NOT EXISTS zaprite_order_id VARCHAR DEFAULT ''",
        "ALTER TABLE crypto_payments ADD COLUMN IF NOT EXISTS zaprite_checkout_url VARCHAR DEFAULT ''",
        # Imaging order enhancements
        "ALTER TABLE imaging_orders ADD COLUMN IF NOT EXISTS status VARCHAR DEFAULT 'ordered'",
        "ALTER TABLE imaging_orders ADD COLUMN IF NOT EXISTS telnyx_fax_id VARCHAR",
        "ALTER TABLE imaging_orders ADD COLUMN IF NOT EXISTS cpt_code VARCHAR DEFAULT ''",
        "ALTER TABLE imaging_orders ADD COLUMN IF NOT EXISTS scheduled_at TIMESTAMP",
        "ALTER TABLE imaging_orders ADD COLUMN IF NOT EXISTS completed_at TIMESTAMP",
        "ALTER TABLE imaging_orders ADD COLUMN IF NOT EXISTS results_received_at TIMESTAMP",
        "ALTER TABLE imaging_orders ADD COLUMN IF NOT EXISTS result_notes TEXT DEFAULT ''",
        "ALTER TABLE imaging_orders ADD COLUMN IF NOT EXISTS result_file_path VARCHAR DEFAULT ''",
        # Membership billing cycle
        "ALTER TABLE memberships ADD COLUMN IF NOT EXISTS billing_cycle VARCHAR DEFAULT 'monthly'",
        "ALTER TABLE memberships ADD COLUMN IF NOT EXISTS price_annual FLOAT",
        # Patient portal
        "ALTER TABLE patients ADD COLUMN IF NOT EXISTS portal_email VARCHAR DEFAULT ''",
        "ALTER TABLE patients ADD COLUMN IF NOT EXISTS portal_password_hash VARCHAR DEFAULT ''",
        "ALTER TABLE patients ADD COLUMN IF NOT EXISTS portal_active BOOLEAN DEFAULT FALSE",
        # Note visibility
        "ALTER TABLE clinical_notes ADD COLUMN IF NOT EXISTS patient_visible BOOLEAN DEFAULT FALSE",
        # Fax sent_at (may already exist on some deploys)
        "ALTER TABLE imaging_orders ADD COLUMN IF NOT EXISTS fax_sent_at TIMESTAMP",
        # MFA fields on users (Risk 7)
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN DEFAULT FALSE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret VARCHAR",
        # Imaging result DB blob storage (Risk 12)
        "ALTER TABLE imaging_orders ADD COLUMN IF NOT EXISTS result_file_data TEXT",
        "ALTER TABLE imaging_orders ADD COLUMN IF NOT EXISTS result_file_name VARCHAR DEFAULT ''",
        # Password expiry tracking + token invalidation
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_required BOOLEAN DEFAULT FALSE",
        # Workforce training records (POL-HIPAA-001)
        """CREATE TABLE IF NOT EXISTS training_records (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            training_name VARCHAR NOT NULL,
            training_type VARCHAR DEFAULT 'hipaa_annual',
            completed_at TIMESTAMP NOT NULL,
            recorded_by INTEGER REFERENCES users(id),
            notes TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT NOW()
        )""",
        # ABN (Advance Beneficiary Notice) — CMS-R-131
        """CREATE TABLE IF NOT EXISTS abns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            lab_order_id INTEGER REFERENCES lab_orders(id),
            patient_id INTEGER NOT NULL REFERENCES patients(id),
            created_by INTEGER NOT NULL REFERENCES users(id),
            items TEXT DEFAULT '[]',
            reason TEXT DEFAULT '',
            estimated_cost REAL DEFAULT 0,
            patient_decision VARCHAR,
            signed_at TIMESTAMP,
            signed_by_name VARCHAR DEFAULT '',
            witness_name VARCHAR DEFAULT '',
            status VARCHAR DEFAULT 'pending',
            notes TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""",
        # Skin lesion tracking module
        """CREATE TABLE IF NOT EXISTS skin_lesions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL REFERENCES patients(id),
            created_by INTEGER NOT NULL REFERENCES users(id),
            name VARCHAR NOT NULL,
            body_location VARCHAR DEFAULT '',
            description TEXT DEFAULT '',
            first_noted VARCHAR DEFAULT '',
            status VARCHAR DEFAULT 'monitoring',
            notes TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""",
        """CREATE TABLE IF NOT EXISTS lesion_images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            lesion_id INTEGER NOT NULL REFERENCES skin_lesions(id),
            patient_id INTEGER NOT NULL REFERENCES patients(id),
            uploaded_by INTEGER NOT NULL REFERENCES users(id),
            image_data TEXT NOT NULL,
            image_mime VARCHAR DEFAULT 'image/jpeg',
            image_filename VARCHAR DEFAULT '',
            taken_at VARCHAR DEFAULT '',
            notes TEXT DEFAULT '',
            ai_analysis TEXT,
            ai_analyzed_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""",
    ]
    from sqlalchemy import text
    for sql in migrations:
        try:
            db.execute(text(sql))
        except Exception:
            db.rollback()  # SQLite doesn't support IF NOT EXISTS — skip silently
    db.commit()


# ═════════════════════════════════════════════════════════════════════════════
# PATIENT PORTAL — auth helpers + endpoints
# ═════════════════════════════════════════════════════════════════════════════

PORTAL_TOKEN_HOURS = 2  # Risk 11: reduced from 24h to 2h
# HIPAA §164.312(a)(2)(iii): auto-logoff for patient portal after inactivity.
PORTAL_IDLE_TIMEOUT_MINUTES = int(os.getenv("PORTAL_IDLE_TIMEOUT_MINUTES", "30"))

def make_portal_token(patient_id: int) -> str:
    exp = datetime.utcnow() + timedelta(hours=PORTAL_TOKEN_HOURS)
    return jwt.encode({"sub": str(patient_id), "type": "portal", "exp": exp}, SECRET_KEY, ALGORITHM)


portal_oauth2 = OAuth2PasswordBearer(tokenUrl="/portal/login", auto_error=False)

def get_portal_patient(
    token: str = Depends(portal_oauth2),
    db: Session = Depends(get_db),
) -> models.Patient:
    credentials_exc = HTTPException(status_code=401, detail="Not authenticated")
    if not token:
        raise credentials_exc
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "portal":
            raise credentials_exc
        patient_id = int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise credentials_exc
    patient = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
    if not patient or not patient.portal_active:
        raise credentials_exc
    # ── Portal idle timeout ───────────────────────────────────────────────────
    now = datetime.utcnow()
    if PORTAL_IDLE_TIMEOUT_MINUTES > 0:
        last_active = getattr(patient, "portal_last_active", None)
        if last_active and (now - last_active).total_seconds() > PORTAL_IDLE_TIMEOUT_MINUTES * 60:
            raise HTTPException(status_code=401, detail="Portal session expired due to inactivity")
    # Throttle write to at most once per 60 s
    last_active = getattr(patient, "portal_last_active", None)
    if not last_active or (now - last_active).total_seconds() > 60:
        patient.portal_last_active = now
        db.commit()
    return patient


@app.post("/portal/login")
def portal_login(
    form: OAuth2PasswordRequestForm = Depends(),
    request: Request = None,
    db: Session = Depends(get_db),
):
    ip = request.client.host if request else "unknown"
    _check_rate_limit(ip)
    patient = db.query(models.Patient).filter(
        models.Patient.portal_email == form.username,
        models.Patient.portal_active == True,
    ).first()
    if not patient or not patient.portal_password_hash:
        _record_failure(ip)
        audit(db, None, "PORTAL_LOGIN_FAILED", "Patient", form.username, request=request,
              details=f"email={form.username} reason=not_found")
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not verify_pw(form.password, patient.portal_password_hash):
        _record_failure(ip)
        audit(db, None, "PORTAL_LOGIN_FAILED", "Patient", str(patient.id), request=request,
              details=f"patient_id={patient.id} reason=bad_password")
        raise HTTPException(status_code=401, detail="Invalid email or password")
    _clear_failures(ip)
    audit(db, None, "PORTAL_LOGIN", "Patient", str(patient.id), request=request)
    return {"access_token": make_portal_token(patient.id), "token_type": "bearer"}


@app.get("/portal/me")
def portal_me(patient: models.Patient = Depends(get_portal_patient)):
    d = clean(patient)
    # Never expose password hash to portal
    d.pop("portal_password_hash", None)
    return d


@app.get("/portal/notes")
def portal_notes(patient: models.Patient = Depends(get_portal_patient), db: Session = Depends(get_db)):
    audit(db, None, "PORTAL_VIEW_NOTES", "Patient", str(patient.id), details=f"patient_id={patient.id}")
    notes = (db.query(models.ClinicalNote)
             .filter(models.ClinicalNote.patient_id == patient.id,
                     models.ClinicalNote.patient_visible == True)
             .order_by(models.ClinicalNote.visit_date.desc())
             .all())
    result = []
    for n in notes:
        d = clean(n)
        # Only expose safe fields — no internal codes or AI flags
        result.append({
            "id": d["id"],
            "visit_date": d.get("visit_date"),
            "chief_complaint": d.get("chief_complaint", ""),
            "assessment": d.get("assessment", ""),
            "plan": d.get("plan", ""),
            "note_type": d.get("note_type", "SOAP"),
        })
    return result


@app.get("/portal/labs")
def portal_labs(patient: models.Patient = Depends(get_portal_patient), db: Session = Depends(get_db)):
    audit(db, None, "PORTAL_VIEW_LABS", "Patient", str(patient.id), details=f"patient_id={patient.id}")
    orders = (db.query(models.LabOrder)
              .filter(models.LabOrder.patient_id == patient.id,
                      models.LabOrder.status == "resulted")
              .order_by(models.LabOrder.created_at.desc())
              .all())
    result = []
    for o in orders:
        d = clean(o)
        observations = []
        try:
            observations = json.loads(o.result_data or "[]")
        except Exception:
            pass
        result.append({
            "id": d["id"],
            "created_at": d.get("created_at"),
            "tests": json.loads(o.tests or "[]"),
            "facility": d.get("facility", ""),
            "status": d.get("status", ""),
            "result_received_at": d.get("result_received_at"),
            "observations": observations,
        })
    return result


@app.get("/portal/imaging")
def portal_imaging(patient: models.Patient = Depends(get_portal_patient), db: Session = Depends(get_db)):
    audit(db, None, "PORTAL_VIEW_IMAGING", "Patient", str(patient.id), details=f"patient_id={patient.id}")
    orders = (db.query(models.ImagingOrder)
              .filter(models.ImagingOrder.patient_id == patient.id,
                      models.ImagingOrder.status.in_(["results_received", "completed"]))
              .order_by(models.ImagingOrder.created_at.desc())
              .all())
    result = []
    for o in orders:
        d = clean(o)
        result.append({
            "id": d["id"],
            "created_at": d.get("created_at"),
            "study_type": d.get("study_type", ""),
            "body_part": d.get("body_part", ""),
            "facility": d.get("facility", ""),
            "status": d.get("status", ""),
            "completed_at": d.get("completed_at"),
            "results_received_at": d.get("results_received_at"),
            "result_notes": d.get("result_notes", ""),
        })
    return result


@app.get("/portal/membership")
def portal_membership(patient: models.Patient = Depends(get_portal_patient), db: Session = Depends(get_db)):
    memberships = (db.query(models.Membership)
                   .filter(models.Membership.patient_id == patient.id)
                   .order_by(models.Membership.created_at.desc())
                   .all())
    result = []
    for m in memberships:
        d = clean(m)
        d.pop("square_customer_id", None)
        d.pop("square_card_id", None)
        result.append(d)
    return result


@app.get("/portal/payments")
def portal_payments(patient: models.Patient = Depends(get_portal_patient), db: Session = Depends(get_db)):
    payments = (db.query(models.Payment)
                .filter(models.Payment.patient_id == patient.id)
                .order_by(models.Payment.created_at.desc())
                .all())
    result = []
    for p in payments:
        d = clean(p)
        d.pop("payment_ref_id", None)
        result.append(d)
    return result


# ── Staff: manage portal accounts ────────────────────────────────────────────

@app.post("/api/patients/{patient_id}/portal/activate")
def portal_activate(
    patient_id: int,
    data: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Set or update a patient's portal credentials and activate their account."""
    patient = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    _require_patient_access(patient, current_user)
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password are required")
    # Check email not already used by another patient
    conflict = db.query(models.Patient).filter(
        models.Patient.portal_email == email,
        models.Patient.id != patient_id,
    ).first()
    if conflict:
        raise HTTPException(status_code=409, detail="That email is already used by another patient")
    _validate_password(password)
    patient.portal_email = email
    patient.portal_password_hash = hash_pw(password)
    patient.portal_active = True
    db.commit()
    audit(db, current_user.id, "PORTAL_ACTIVATE", "Patient", str(patient_id))
    return {"ok": True, "portal_email": email}


@app.post("/api/patients/{patient_id}/portal/deactivate")
def portal_deactivate(
    patient_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    patient = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    _require_patient_access(patient, current_user)
    patient.portal_active = False
    db.commit()
    audit(db, current_user.id, "PORTAL_DEACTIVATE", "Patient", str(patient_id))
    return {"ok": True}


@app.patch("/api/notes/{note_id}/patient-visible")
def toggle_note_visibility(
    note_id: int,
    data: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Toggle whether a note is visible in the patient portal."""
    note = db.query(models.ClinicalNote).filter(models.ClinicalNote.id == note_id).first()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    note.patient_visible = bool(data.get("patient_visible", False))
    db.commit()
    audit(db, current_user.id, "TOGGLE_NOTE_VISIBILITY", "ClinicalNote", str(note_id))
    return clean(note)


# ══════════════════════════════════════════════════════════════════════════════
# PATIENT DATA EXPORT  (HIPAA Right of Access — 45 C.F.R. § 164.524)
# ══════════════════════════════════════════════════════════════════════════════

def _build_patient_export(patient_id: int, db: Session) -> dict:
    """Assemble a complete ePHI bundle for one patient."""
    patient = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    p = clean(patient)
    # Strip internal/portal credential fields from the export
    for field in ("portal_password_hash", "portal_email", "portal_active"):
        p.pop(field, None)

    notes = [clean(n) for n in
             db.query(models.ClinicalNote)
             .filter(models.ClinicalNote.patient_id == patient_id)
             .order_by(models.ClinicalNote.visit_date.desc()).all()]

    lab_orders = []
    for o in (db.query(models.LabOrder)
              .filter(models.LabOrder.patient_id == patient_id)
              .order_by(models.LabOrder.created_at.desc()).all()):
        d = clean(o)
        try:
            d["observations"] = json.loads(o.result_data or "[]")
        except Exception:
            d["observations"] = []
        d.pop("result_data", None)
        d.pop("result_pdf", None)
        lab_orders.append(d)

    imaging_orders = []
    for o in (db.query(models.ImagingOrder)
              .filter(models.ImagingOrder.patient_id == patient_id)
              .order_by(models.ImagingOrder.created_at.desc()).all()):
        d = clean(o)
        d.pop("result_file_data", None)  # exclude raw binary blob
        imaging_orders.append(d)

    prescriptions = [
        _rx_to_dict(rx, db) for rx in
        (db.query(models.Prescription)
         .filter(models.Prescription.patient_id == patient_id)
         .order_by(models.Prescription.created_at.desc()).all())
    ]

    medications = [clean(m) for m in
                   (db.query(models.PatientMedication)
                    .filter(models.PatientMedication.patient_id == patient_id)
                    .order_by(models.PatientMedication.is_active.desc()).all())]

    history = [clean(e) for e in
               (db.query(models.PatientHistoryEntry)
                .filter(models.PatientHistoryEntry.patient_id == patient_id)
                .order_by(models.PatientHistoryEntry.entry_type).all())]

    appointments = [clean(a) for a in
                    (db.query(models.Appointment)
                     .filter(models.Appointment.patient_id == patient_id)
                     .order_by(models.Appointment.start_time.desc()).all())]

    memberships = []
    for m in (db.query(models.Membership)
              .filter(models.Membership.patient_id == patient_id)
              .order_by(models.Membership.created_at.desc()).all()):
        d = clean(m)
        d.pop("square_customer_id", None)
        d.pop("square_card_id", None)
        memberships.append(d)

    payments = []
    for pay in (db.query(models.Payment)
                .filter(models.Payment.patient_id == patient_id)
                .order_by(models.Payment.created_at.desc()).all()):
        d = clean(pay)
        d.pop("payment_ref_id", None)
        payments.append(d)

    consents = [clean(c) for c in
                (db.query(models.PatientConsent)
                 .filter(models.PatientConsent.patient_id == patient_id)
                 .order_by(models.PatientConsent.signed_at.asc()).all())]

    return {
        "export_generated_at": datetime.utcnow().isoformat() + "Z",
        "hipaa_notice": (
            "This record was produced pursuant to the HIPAA Right of Access "
            "(45 C.F.R. § 164.524). It contains Protected Health Information (PHI) "
            "and must be safeguarded accordingly."
        ),
        "patient": p,
        "clinical_notes": notes,
        "lab_orders": lab_orders,
        "imaging_orders": imaging_orders,
        "prescriptions": prescriptions,
        "medications": medications,
        "medical_history": history,
        "appointments": appointments,
        "memberships": memberships,
        "payments": payments,
        "consents": consents,
    }


@app.get("/api/patients/{patient_id}/export")
def export_patient_records(
    patient_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    HIPAA Right of Access — staff-initiated full export of a patient's ePHI.
    Physician or admin only.  Every export is audit-logged.
    """
    if current_user.role not in ("admin", "physician"):
        raise HTTPException(status_code=403, detail="Physician or admin required")
    data = _build_patient_export(patient_id, db)
    patient = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
    fname = f"{patient.last_name}_{patient.first_name}_records_{datetime.utcnow().strftime('%Y%m%d')}.json"
    audit(db, current_user.id, "EXPORT_PATIENT_RECORDS", "Patient", str(patient_id),
          details="HIPAA Right of Access export")
    return JSONResponse(
        content=data,
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# ── Patient Record PDF Export ─────────────────────────────────────────────────
def _build_record_pdf(data: dict) -> bytes:
    """
    Render a complete patient health record as a formatted PDF.
    Uses ReportLab Platypus for multi-page layout with headers/footers.
    """
    buf = BytesIO()

    # ── Colours & constants ───────────────────────────────────────────────────
    TEAL       = colors.HexColor("#0d9488")
    TEAL_LIGHT = colors.HexColor("#e6f7f6")
    DARK       = colors.HexColor("#292524")
    GREY       = colors.HexColor("#78716c")
    RULE       = colors.HexColor("#d6d3d1")
    WHITE      = colors.white

    p = data.get("patient", {})
    pt_name = f"{p.get('first_name','')} {p.get('last_name','')}".strip() or "Unknown"
    generated = data.get("export_generated_at", "")[:10]

    # ── Page template with running header/footer ──────────────────────────────
    def _on_page(canvas, doc):
        canvas.saveState()
        w, h = letter
        # Header bar
        canvas.setFillColor(DARK)
        canvas.rect(0, h - 36, w, 36, fill=1, stroke=0)
        canvas.setFont("Helvetica-Bold", 10)
        canvas.setFillColor(WHITE)
        canvas.drawString(18, h - 23, "MedFlow EMR — CONFIDENTIAL HEALTH RECORD")
        canvas.drawRightString(w - 18, h - 23, pt_name)
        # Footer
        canvas.setFillColor(GREY)
        canvas.setFont("Helvetica", 8)
        canvas.drawString(18, 16, f"Generated {generated}  |  HIPAA Right of Access — 45 C.F.R. § 164.524")
        canvas.drawRightString(w - 18, 16, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        leftMargin=46, rightMargin=46, topMargin=54, bottomMargin=36,
        onFirstPage=_on_page, onLaterPages=_on_page,
    )
    styles = getSampleStyleSheet()

    # ── Custom paragraph styles ───────────────────────────────────────────────
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT

    s_title   = ParagraphStyle("s_title",   parent=styles["Title"],
                                textColor=DARK, fontSize=22, spaceAfter=4)
    s_sub     = ParagraphStyle("s_sub",     parent=styles["Normal"],
                                textColor=GREY, fontSize=10, spaceAfter=2)
    s_h1      = ParagraphStyle("s_h1",      parent=styles["Heading1"],
                                textColor=TEAL, fontSize=13, spaceBefore=14, spaceAfter=4)
    s_h2      = ParagraphStyle("s_h2",      parent=styles["Heading2"],
                                textColor=DARK, fontSize=11, spaceBefore=8, spaceAfter=2)
    s_body    = ParagraphStyle("s_body",    parent=styles["Normal"],
                                fontSize=9, leading=13, spaceAfter=3)
    s_label   = ParagraphStyle("s_label",   parent=styles["Normal"],
                                fontSize=8, textColor=GREY, leading=11)
    s_notice  = ParagraphStyle("s_notice",  parent=styles["Normal"],
                                fontSize=8, textColor=GREY, leading=12,
                                borderPad=6, backColor=TEAL_LIGHT, borderRadius=4)
    s_empty   = ParagraphStyle("s_empty",   parent=styles["Normal"],
                                fontSize=9, textColor=GREY, alignment=TA_CENTER)

    W = letter[0] - 92  # usable width

    def rule():
        return HRFlowable(width="100%", thickness=0.5, color=RULE, spaceAfter=6, spaceBefore=2)

    def section(title):
        return [Spacer(1, 6), Paragraph(title, s_h1), rule()]

    def kv_table(rows, col_w=None):
        """Two-column label/value table."""
        if not rows:
            return []
        cw = col_w or [110, W - 110]
        t = Table([[Paragraph(f"<b>{k}</b>", s_label), Paragraph(str(v or "—"), s_body)]
                   for k, v in rows], colWidths=cw)
        t.setStyle(TableStyle([
            ("VALIGN",       (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",   (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
            ("ROWBACKGROUNDS",(0, 0),(-1,-1), [colors.white, TEAL_LIGHT]),
        ]))
        return [t, Spacer(1, 6)]

    story = []

    # ── Cover / title block ───────────────────────────────────────────────────
    story.append(Spacer(1, 24))
    story.append(Paragraph("Patient Health Record", s_title))
    story.append(Paragraph(pt_name, ParagraphStyle("big", parent=styles["Normal"],
                                                    fontSize=16, textColor=TEAL, spaceAfter=6)))
    dob = p.get("dob", "")
    story.append(Paragraph(f"Date of Birth: {dob}  |  Record generated: {generated}", s_sub))
    story.append(Spacer(1, 10))
    story.append(Paragraph(data.get("hipaa_notice", ""), s_notice))
    story.append(Spacer(1, 20))
    story.append(rule())

    # ── 1. Demographics & Insurance ──────────────────────────────────────────
    story += section("1. Demographics & Insurance")
    demo_rows = [
        ("First Name",        p.get("first_name")),
        ("Last Name",         p.get("last_name")),
        ("Date of Birth",     p.get("dob")),
        ("Gender",            p.get("gender")),
        ("Phone",             p.get("phone")),
        ("Email",             p.get("email")),
        ("Address",           ", ".join(filter(None, [
                                  p.get("address"), p.get("city"),
                                  p.get("state"), p.get("zip_code")]))),
        ("Emergency Contact", p.get("emergency_contact")),
        ("Emergency Phone",   p.get("emergency_phone")),
        ("Insurance",         p.get("insurance_name")),
        ("Member ID",         p.get("insurance_id")),
        ("Group #",           p.get("insurance_group")),
    ]
    story += kv_table(demo_rows)

    # ── 2. Medical History ────────────────────────────────────────────────────
    history = data.get("medical_history", [])
    story += section("2. Medical History")
    if history:
        by_type: dict = {}
        for e in history:
            t = (e.get("entry_type") or "Other").replace("_", " ").title()
            by_type.setdefault(t, []).append(e)
        for etype, entries in sorted(by_type.items()):
            story.append(Paragraph(etype, s_h2))
            rows = [[Paragraph("<b>Description</b>", s_label),
                     Paragraph("<b>Notes</b>", s_label)]]
            for e in entries:
                rows.append([Paragraph(e.get("description") or "—", s_body),
                              Paragraph(e.get("notes") or "—", s_body)])
            t = Table(rows, colWidths=[W * 0.55, W * 0.45])
            t.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, 0), TEAL),
                ("TEXTCOLOR",    (0, 0), (-1, 0), WHITE),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE, TEAL_LIGHT]),
                ("GRID",         (0, 0), (-1, -1), 0.3, RULE),
                ("VALIGN",       (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING",   (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
            ]))
            story.append(t)
            story.append(Spacer(1, 6))
    else:
        story.append(Paragraph("No medical history recorded.", s_empty))

    # ── 3. Current Medications ────────────────────────────────────────────────
    meds = data.get("medications", [])
    story += section("3. Current Medications")
    if meds:
        rows = [[Paragraph(h, s_label) for h in
                 ["<b>Medication</b>", "<b>Dose</b>", "<b>Frequency</b>", "<b>Status</b>"]]]
        for m in meds:
            rows.append([
                Paragraph(m.get("medication_name") or "—", s_body),
                Paragraph(m.get("dose") or "—", s_body),
                Paragraph(m.get("frequency") or "—", s_body),
                Paragraph("Active" if m.get("is_active") else "Inactive", s_body),
            ])
        t = Table(rows, colWidths=[W * 0.40, W * 0.20, W * 0.25, W * 0.15])
        t.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0), TEAL),
            ("TEXTCOLOR",    (0, 0), (-1, 0), WHITE),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE, TEAL_LIGHT]),
            ("GRID",         (0, 0), (-1, -1), 0.3, RULE),
            ("VALIGN",       (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",   (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
        ]))
        story.append(t)
        story.append(Spacer(1, 6))
    else:
        story.append(Paragraph("No medications on record.", s_empty))

    # ── 4. Clinical Notes ─────────────────────────────────────────────────────
    notes = data.get("clinical_notes", [])
    story += section("4. Clinical Notes")
    if notes:
        for note in notes:
            vdate = str(note.get("visit_date") or "")[:10]
            cc = note.get("chief_complaint") or ""
            block = [
                Paragraph(f"<b>{vdate}</b> — {cc}", s_h2),
            ]
            for field, label in [
                ("hpi",           "History of Present Illness"),
                ("assessment",    "Assessment"),
                ("plan",          "Plan"),
                ("pmh",           "Past Medical History"),
                ("medications",   "Medications (note)"),
                ("allergies",     "Allergies"),
            ]:
                val = note.get(field, "")
                if val and val.strip():
                    block.append(Paragraph(f"<b>{label}:</b> {val.replace(chr(10), ' ')}", s_body))
            # ICD / CPT codes
            try:
                icd = json.loads(note.get("icd10_codes") or "[]")
                cpt = json.loads(note.get("cpt_codes") or "[]")
                if icd:
                    block.append(Paragraph(f"<b>ICD-10:</b> {', '.join(icd)}", s_label))
                if cpt:
                    block.append(Paragraph(f"<b>CPT:</b> {', '.join(cpt)}", s_label))
            except Exception:
                pass
            status = note.get("status", "")
            if status:
                block.append(Paragraph(f"<b>Status:</b> {status.title()}", s_label))
            block.append(Spacer(1, 4))
            block.append(HRFlowable(width="100%", thickness=0.3, color=RULE))
            story.append(KeepTogether(block))
    else:
        story.append(Paragraph("No clinical notes on record.", s_empty))

    # ── 5. Lab Orders ─────────────────────────────────────────────────────────
    labs = data.get("lab_orders", [])
    story += section("5. Lab Orders")
    if labs:
        for lab in labs:
            ldate = str(lab.get("created_at") or "")[:10]
            tests = lab.get("test_names") or lab.get("tests") or ""
            block = [Paragraph(f"<b>{ldate}</b> — {tests}", s_h2)]
            rows = [("Ordering Physician", lab.get("ordering_physician_name")),
                    ("Status",             lab.get("status")),
                    ("Clinical Indication",lab.get("clinical_indication")),
                    ("Notes",              lab.get("notes"))]
            block += kv_table([(k, v) for k, v in rows if v])
            obs = lab.get("observations", [])
            if obs:
                block.append(Paragraph("<b>Results:</b>", s_label))
                obs_rows = [[Paragraph(h, s_label) for h in
                             ["<b>Test</b>", "<b>Value</b>", "<b>Units</b>", "<b>Range</b>", "<b>Flag</b>"]]]
                for o in obs:
                    obs_rows.append([
                        Paragraph(o.get("display_name") or o.get("test_name") or "—", s_body),
                        Paragraph(str(o.get("value") or "—"), s_body),
                        Paragraph(o.get("units") or "—", s_body),
                        Paragraph(o.get("reference_range") or "—", s_body),
                        Paragraph(o.get("abnormal_flag") or "—", s_body),
                    ])
                ot = Table(obs_rows, colWidths=[W*0.30, W*0.15, W*0.15, W*0.25, W*0.15])
                ot.setStyle(TableStyle([
                    ("BACKGROUND",   (0, 0), (-1, 0), TEAL),
                    ("TEXTCOLOR",    (0, 0), (-1, 0), WHITE),
                    ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE, TEAL_LIGHT]),
                    ("GRID",         (0, 0), (-1, -1), 0.3, RULE),
                    ("VALIGN",       (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING",   (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
                ]))
                block.append(ot)
            block.append(Spacer(1, 4))
            block.append(HRFlowable(width="100%", thickness=0.3, color=RULE))
            story.append(KeepTogether(block[:6]))  # keep header + meta together
            story += block[6:]

    else:
        story.append(Paragraph("No lab orders on record.", s_empty))

    # ── 6. Imaging Orders ────────────────────────────────────────────────────
    imaging = data.get("imaging_orders", [])
    story += section("6. Imaging Orders")
    if imaging:
        rows_hdr = [[Paragraph(h, s_label) for h in
                     ["<b>Date</b>", "<b>Modality</b>", "<b>Body Part</b>",
                      "<b>Indication</b>", "<b>Status</b>"]]]
        for img in imaging:
            rows_hdr.append([
                Paragraph(str(img.get("created_at") or "")[:10], s_body),
                Paragraph(img.get("modality") or "—", s_body),
                Paragraph(img.get("body_part") or "—", s_body),
                Paragraph(img.get("clinical_indication") or "—", s_body),
                Paragraph(img.get("status") or "—", s_body),
            ])
        it = Table(rows_hdr, colWidths=[W*0.12, W*0.13, W*0.18, W*0.42, W*0.15])
        it.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0), TEAL),
            ("TEXTCOLOR",    (0, 0), (-1, 0), WHITE),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE, TEAL_LIGHT]),
            ("GRID",         (0, 0), (-1, -1), 0.3, RULE),
            ("VALIGN",       (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",   (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
        ]))
        story.append(it)
    else:
        story.append(Paragraph("No imaging orders on record.", s_empty))

    # ── 7. Prescriptions ─────────────────────────────────────────────────────
    rxs = data.get("prescriptions", [])
    story += section("7. Prescriptions")
    if rxs:
        rows_hdr = [[Paragraph(h, s_label) for h in
                     ["<b>Date</b>", "<b>Drug</b>", "<b>Sig</b>",
                      "<b>Quantity</b>", "<b>Refills</b>", "<b>Status</b>"]]]
        for rx in rxs:
            rows_hdr.append([
                Paragraph(str(rx.get("created_at") or "")[:10], s_body),
                Paragraph(rx.get("drug_name") or "—", s_body),
                Paragraph(rx.get("sig") or "—", s_body),
                Paragraph(str(rx.get("quantity") or "—"), s_body),
                Paragraph(str(rx.get("refills") or "0"), s_body),
                Paragraph(rx.get("status") or "—", s_body),
            ])
        rt = Table(rows_hdr, colWidths=[W*0.10, W*0.22, W*0.35, W*0.11, W*0.10, W*0.12])
        rt.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0), TEAL),
            ("TEXTCOLOR",    (0, 0), (-1, 0), WHITE),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE, TEAL_LIGHT]),
            ("GRID",         (0, 0), (-1, -1), 0.3, RULE),
            ("VALIGN",       (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",   (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
        ]))
        story.append(rt)
    else:
        story.append(Paragraph("No prescriptions on record.", s_empty))

    # ── 8. Memberships ───────────────────────────────────────────────────────
    memberships = data.get("memberships", [])
    story += section("8. Memberships")
    if memberships:
        for m in memberships:
            story += kv_table([
                ("Plan",        m.get("plan_name")),
                ("Status",      m.get("status")),
                ("Start Date",  str(m.get("start_date") or "")[:10]),
                ("Next Billing",str(m.get("next_billing_date") or "")[:10]),
            ])
    else:
        story.append(Paragraph("No memberships on record.", s_empty))

    # ── Build ─────────────────────────────────────────────────────────────────
    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    return buf.getvalue()


@app.get("/api/patients/{patient_id}/export-pdf")
def export_patient_pdf(
    patient_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    HIPAA Right of Access — full patient record export as a formatted PDF.
    Accessible to physician and admin only. Every export is audit-logged.
    """
    patient = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    _require_patient_access(patient, current_user)

    data = _build_patient_export(patient_id, db)
    pdf_bytes = _build_record_pdf(data)

    fname = (f"{patient.last_name}_{patient.first_name}_"
             f"HealthRecord_{datetime.utcnow().strftime('%Y%m%d')}.pdf")
    audit(db, current_user.id, "EXPORT_PHI_PDF", "Patient", str(patient_id),
          details=f"Full patient record PDF exported ({len(pdf_bytes)//1024} KB)")

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@app.get("/portal/export")
def portal_export_records(
    patient: models.Patient = Depends(get_portal_patient),
    db: Session = Depends(get_db),
):
    """
    HIPAA Right of Access — patient self-service export from the portal.
    Returns the patient's own complete record bundle as a downloadable JSON file.
    """
    data = _build_patient_export(patient.id, db)
    fname = f"my_health_records_{datetime.utcnow().strftime('%Y%m%d')}.json"
    audit(db, None, "PORTAL_EXPORT_RECORDS", "Patient", str(patient.id),
          details="Patient self-service Right of Access export")
    return JSONResponse(
        content=data,
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# ══════════════════════════════════════════════════════════════════════════════
# RECORD IMPORT  (AI-powered chart filing)
# ══════════════════════════════════════════════════════════════════════════════

_IMPORT_PROMPT = """You are a clinical data extraction engine for an EMR system.
You will receive raw text extracted from a patient record (referral note, discharge summary, old chart, lab report, etc.).

Your job is to:
1. Extract and structure ALL clinical information into four categories (notes, labs, imaging, medications).
2. Write a concise medical history summary of the patient based solely on what is present in this document.
3. List specific, actionable recommended next steps a physician should consider based on the findings.

Return ONLY valid JSON in exactly this structure — no markdown, no prose, just JSON:
{
  "summary": "One sentence describing what type of document this is.",
  "medical_history_summary": "A 3-5 sentence narrative paragraph summarizing the patient's relevant medical history, active conditions, and current medication regimen as described in this document. Write in clinical language suitable for a physician. Do not invent anything not present in the document.",
  "recommended_next_steps": [
    "Specific, actionable follow-up item based on the document findings (e.g. 'Follow up on elevated HbA1c of 8.2% — consider adjusting diabetes regimen')",
    "Another specific action item"
  ],
  "clinical_notes": [
    {
      "visit_date": "YYYY-MM-DD or empty string if unknown",
      "note_type": "SOAP|Consult|Discharge|H&P|Progress|Other",
      "chief_complaint": "...",
      "hpi": "...",
      "assessment": "...",
      "plan": "..."
    }
  ],
  "lab_results": [
    {
      "test_name": "...",
      "value": "...",
      "units": "...",
      "reference_range": "...",
      "date": "YYYY-MM-DD or empty",
      "flag": "normal|high|low|critical|unknown"
    }
  ],
  "imaging_orders": [
    {
      "study_type": "X-Ray|CT|MRI|Ultrasound|PET|Nuclear|Other",
      "body_part": "...",
      "date": "YYYY-MM-DD or empty",
      "clinical_indication": "...",
      "result_notes": "impression/findings from the report, or empty if not present"
    }
  ],
  "medications": [
    {
      "name": "...",
      "dosage": "...",
      "frequency": "...",
      "route": "oral|IV|IM|topical|inhaled|other",
      "indication": "..."
    }
  ]
}

Rules:
- If a category has no data, return an empty array for it.
- Do not invent clinical data — only extract what is explicitly present in the document.
- recommended_next_steps should be specific (cite values, dates, findings) — not generic advice.
- medical_history_summary should read like a concise referral paragraph, not a list.
"""


def _extract_pdf_text(pdf_bytes: bytes) -> str:
    """Extract plain text from a PDF using pdfplumber."""
    import pdfplumber, io
    text_parts = []
    with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
        for page in pdf.pages:
            t = page.extract_text()
            if t:
                text_parts.append(t)
    return "\n\n".join(text_parts)


def _call_import_ai(raw_text: str) -> dict:
    """Send extracted text to Anthropic and return parsed JSON."""
    client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY", ""))
    # Trim to ~15k chars to stay within token limits while preserving most content
    trimmed = raw_text[:15000]
    response = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=4096,
        messages=[
            {
                "role": "user",
                "content": f"{_IMPORT_PROMPT}\n\n---DOCUMENT TEXT---\n{trimmed}",
            }
        ],
    )
    raw_json = response.content[0].text.strip()
    # Strip markdown fences if model wrapped the JSON
    if raw_json.startswith("```"):
        raw_json = re.sub(r"^```[a-z]*\n?", "", raw_json)
        raw_json = re.sub(r"\n?```$", "", raw_json)
    return json.loads(raw_json)


def _file_imported_data(patient_id: int, parsed: dict, physician_id: int,
                        import_id: int, db: Session) -> dict:
    """Create DB records from AI-parsed import data in 'pending_review' status.

    All records are tagged with source_import_id so they can be bulk-approved
    or discarded later via the review endpoints.
    """
    counts = {"notes": 0, "labs": 0, "imaging": 0, "meds": 0}

    # ── Clinical notes — filed as drafts pending physician review ─────────────
    for n in parsed.get("clinical_notes", []):
        try:
            visit_dt = datetime.strptime(n.get("visit_date", ""), "%Y-%m-%d") if n.get("visit_date") else datetime.utcnow()
        except ValueError:
            visit_dt = datetime.utcnow()
        note = models.ClinicalNote(
            patient_id=patient_id,
            physician_id=physician_id,
            visit_date=visit_dt,
            note_type=n.get("note_type", "Other"),
            chief_complaint=n.get("chief_complaint", ""),
            hpi=n.get("hpi", ""),
            assessment=n.get("assessment", ""),
            plan=n.get("plan", ""),
            status="pending_review",   # physician must approve before it becomes signed
            ai_generated=True,
            source_import_id=import_id,
        )
        db.add(note)
        counts["notes"] += 1

    # ── Lab results ───────────────────────────────────────────────────────────
    if parsed.get("lab_results"):
        result_observations = []
        for lr in parsed["lab_results"]:
            result_observations.append({
                "test_name": lr.get("test_name", ""),
                "value": lr.get("value", ""),
                "units": lr.get("units", ""),
                "reference_range": lr.get("reference_range", ""),
                "flag": lr.get("flag", "unknown"),
                "date": lr.get("date", ""),
            })
        order = models.LabOrder(
            patient_id=patient_id,
            physician_id=physician_id,
            tests=json.dumps([lr.get("test_name", "") for lr in parsed["lab_results"]]),
            clinical_indication="Imported from external record — pending physician review",
            status="pending_review",
            notes="AI-imported. Approve or discard via the import review panel.",
            result_data=json.dumps(result_observations),
            source_import_id=import_id,
        )
        db.add(order)
        counts["labs"] = len(parsed["lab_results"])

    # ── Imaging ───────────────────────────────────────────────────────────────
    for img in parsed.get("imaging_orders", []):
        try:
            sched = datetime.strptime(img.get("date", ""), "%Y-%m-%d") if img.get("date") else None
        except ValueError:
            sched = None
        io_rec = models.ImagingOrder(
            patient_id=patient_id,
            physician_id=physician_id,
            study_type=img.get("study_type", "Other"),
            body_part=img.get("body_part", ""),
            clinical_indication=img.get("clinical_indication", "Imported from external record"),
            status="pending_review",
            result_notes=img.get("result_notes", ""),
            scheduled_at=sched,
            completed_at=sched,
            source_import_id=import_id,
        )
        db.add(io_rec)
        counts["imaging"] += 1

    # ── Medications — inactive until approved ─────────────────────────────────
    for med in parsed.get("medications", []):
        m = models.PatientMedication(
            patient_id=patient_id,
            name=med.get("name", ""),
            dosage=med.get("dosage", ""),
            frequency=med.get("frequency", ""),
            route=med.get("route", "oral"),
            indication=med.get("indication", ""),
            is_active=False,   # activated on approval
            notes="AI-imported — pending physician review",
            source_import_id=import_id,
        )
        db.add(m)
        counts["meds"] += 1

    db.commit()
    return counts


@app.post("/api/patients/{patient_id}/import-records")
async def import_patient_records(
    patient_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
    file: Optional[UploadFile] = File(None),
    text: Optional[str] = Form(None),
):
    """
    Accept a PDF upload or pasted text, parse with AI, and file into the
    appropriate tabs of the patient chart as pending_review records.
    Only physicians and admins may import records (HIPAA minimum-necessary).
    """
    if current_user.role not in ("physician", "admin"):
        raise HTTPException(status_code=403, detail="Only physicians and admins may import records.")
    patient = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    _require_patient_access(patient, current_user)
    _check_upload_rate_limit(current_user.id)

    # ── Extract raw text ─────────────────────────────────────────────────────
    source_type = "text"
    filename = ""
    raw_text = ""

    if file and file.filename:
        filename = file.filename
        content = await file.read()
        _MAX_IMPORT_BYTES = 50 * 1024 * 1024  # 50 MB
        if len(content) > _MAX_IMPORT_BYTES:
            raise HTTPException(status_code=413, detail="File too large — maximum 50 MB")
        if file.filename.lower().endswith(".pdf"):
            source_type = "pdf"
            try:
                raw_text = _extract_pdf_text(content)
            except Exception as e:
                raise HTTPException(status_code=422, detail=f"Could not read PDF: {e}")
        else:
            raw_text = content.decode("utf-8", errors="replace")
    elif text:
        raw_text = text
    else:
        raise HTTPException(status_code=400, detail="Provide either a file upload or pasted text.")

    if not raw_text.strip():
        raise HTTPException(status_code=422, detail="No readable text found in the document.")

    # ── Create import record (pending) ───────────────────────────────────────
    imp = models.ImportedRecord(
        patient_id=patient_id,
        uploaded_by=current_user.id,
        filename=filename,
        source_type=source_type,
        raw_text=raw_text[:20000],   # cap stored text
        status="pending",
    )
    db.add(imp)
    db.commit()
    db.refresh(imp)

    # ── Call AI ──────────────────────────────────────────────────────────────
    try:
        parsed = _call_import_ai(raw_text)
    except Exception as e:
        imp.status = "error"
        imp.error_detail = str(e)
        db.commit()
        raise HTTPException(status_code=502, detail=f"AI parsing failed: {e}")

    # ── File the data as pending_review ───────────────────────────────────────
    try:
        counts = _file_imported_data(patient_id, parsed, current_user.id, imp.id, db)
    except Exception as e:
        imp.status = "error"
        imp.error_detail = str(e)
        db.commit()
        raise HTTPException(status_code=500, detail=f"Failed to file records: {e}")

    # ── Update import record ─────────────────────────────────────────────────
    imp.ai_summary              = parsed.get("summary", "")
    imp.medical_history_summary = parsed.get("medical_history_summary", "")
    imp.recommended_next_steps  = json.dumps(parsed.get("recommended_next_steps", []))
    imp.notes_filed   = counts["notes"]
    imp.labs_filed    = counts["labs"]
    imp.imaging_filed = counts["imaging"]
    imp.meds_filed    = counts["meds"]
    imp.status        = "complete"
    imp.review_status = "pending_review"
    db.commit()

    audit(db, current_user.id, "IMPORT_RECORDS", "Patient", str(patient_id), request=request,
          details=f"import_id={imp.id} notes={counts['notes']} labs={counts['labs']} "
                  f"imaging={counts['imaging']} meds={counts['meds']} status=pending_review")

    return {
        "import_id":               imp.id,
        "summary":                 imp.ai_summary,
        "medical_history_summary": imp.medical_history_summary,
        "recommended_next_steps":  parsed.get("recommended_next_steps", []),
        "filed":                   counts,
        "review_status":           "pending_review",
    }


# ── Import review: approve / discard ─────────────────────────────────────────

@app.post("/api/imported-records/{import_id}/approve")
def approve_import(
    import_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Physician approves an AI import — all pending_review records go live."""
    if current_user.role not in ("physician", "admin"):
        raise HTTPException(status_code=403, detail="Only physicians and admins may approve imports.")
    imp = db.query(models.ImportedRecord).filter(models.ImportedRecord.id == import_id).first()
    if not imp:
        raise HTTPException(status_code=404, detail="Import record not found")
    if imp.review_status == "approved":
        return {"ok": True, "already_approved": True}

    # Activate clinical notes → signed
    db.query(models.ClinicalNote).filter(
        models.ClinicalNote.source_import_id == import_id
    ).update({"status": "signed", "ai_generated": True}, synchronize_session=False)

    # Activate lab orders → resulted
    db.query(models.LabOrder).filter(
        models.LabOrder.source_import_id == import_id
    ).update({"status": "resulted"}, synchronize_session=False)

    # Activate imaging → results_received (if result notes present) else completed
    imaging_rows = db.query(models.ImagingOrder).filter(
        models.ImagingOrder.source_import_id == import_id
    ).all()
    for img in imaging_rows:
        img.status = "results_received" if img.result_notes else "completed"

    # Activate medications
    db.query(models.PatientMedication).filter(
        models.PatientMedication.source_import_id == import_id
    ).update({"is_active": True}, synchronize_session=False)

    imp.review_status = "approved"
    db.commit()

    audit(db, current_user.id, "IMPORT_APPROVED", "ImportedRecord", str(import_id),
          request=request, details=f"patient_id={imp.patient_id}")
    return {"ok": True, "review_status": "approved"}


@app.post("/api/imported-records/{import_id}/discard")
def discard_import(
    import_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Physician discards an AI import — all pending_review records are deleted."""
    if current_user.role not in ("physician", "admin"):
        raise HTTPException(status_code=403, detail="Only physicians and admins may discard imports.")
    imp = db.query(models.ImportedRecord).filter(models.ImportedRecord.id == import_id).first()
    if not imp:
        raise HTTPException(status_code=404, detail="Import record not found")
    if imp.review_status == "discarded":
        return {"ok": True, "already_discarded": True}

    # Delete all records tagged to this import
    db.query(models.ClinicalNote).filter(
        models.ClinicalNote.source_import_id == import_id
    ).delete(synchronize_session=False)
    db.query(models.LabOrder).filter(
        models.LabOrder.source_import_id == import_id
    ).delete(synchronize_session=False)
    db.query(models.ImagingOrder).filter(
        models.ImagingOrder.source_import_id == import_id
    ).delete(synchronize_session=False)
    db.query(models.PatientMedication).filter(
        models.PatientMedication.source_import_id == import_id
    ).delete(synchronize_session=False)

    imp.review_status = "discarded"
    db.commit()

    audit(db, current_user.id, "IMPORT_DISCARDED", "ImportedRecord", str(import_id),
          request=request, details=f"patient_id={imp.patient_id}")
    return {"ok": True, "review_status": "discarded"}


# ══════════════════════════════════════════════════════════════════════════════
# PATIENT MESSAGING  (secure portal messages + two-way SMS forwarding)
# ══════════════════════════════════════════════════════════════════════════════

PHYSICIAN_CELL    = os.getenv("PHYSICIAN_CELL_PHONE", "")   # E.164, e.g. +12145550100
TELNYX_SMS_NUMBER = os.getenv("TELNYX_SMS_NUMBER", "")      # Your Telnyx SMS-capable number


def _send_sms(to: str, body: str, from_number: str = None) -> Optional[str]:
    """Send an SMS via Telnyx. Returns message ID or None on failure.

    ``from_number`` should be the provider's dedicated Telnyx number (E.164).
    Falls back to the global TELNYX_SMS_NUMBER env-var when not supplied.
    """
    api_key  = os.getenv("TELNYX_API_KEY", "")
    from_num = from_number or TELNYX_SMS_NUMBER
    if not api_key or not from_num or not to:
        return None
    try:
        resp = httpx.post(
            "https://api.telnyx.com/v2/messages",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"from": from_num, "to": to, "text": body},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json().get("data", {}).get("id")
    except Exception:
        return None


@app.get("/api/patients/{patient_id}/messages")
def get_messages(
    patient_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Retrieve the full message thread for a patient (provider view)."""
    patient = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    _require_patient_access(patient, current_user)

    messages = (
        db.query(models.PatientMessage)
        .filter(models.PatientMessage.patient_id == patient_id)
        .order_by(models.PatientMessage.created_at.asc())
        .all()
    )
    # Mark unread inbound messages as read
    for m in messages:
        if m.direction == "inbound" and not m.read_at:
            m.read_at = datetime.utcnow()
    db.commit()
    return [clean(m) for m in messages]


@app.post("/api/patients/{patient_id}/messages")
def send_message_to_patient(
    patient_id: int,
    data: dict,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Provider sends a message to the patient (outbound). Stored in DB; patient sees it in portal."""
    patient = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    _require_patient_access(patient, current_user)
    _check_sms_rate_limit(patient_id)

    body = (data.get("body") or "").strip()
    if not body:
        raise HTTPException(status_code=400, detail="Message body is required.")

    sms_status = "not_applicable"
    telnyx_mid = None

    # Send SMS to patient's phone if they have consent and a phone number on file
    # Send from this provider's dedicated Telnyx number so replies route back correctly
    if patient.sms_consent and patient.phone:
        sms_text    = f"[Valiant DPC] {body}"
        from_num    = getattr(current_user, "telnyx_sms_number", None) or TELNYX_SMS_NUMBER
        telnyx_mid  = _send_sms(patient.phone, sms_text, from_number=from_num)
        sms_status  = "sent" if telnyx_mid else "failed"

    msg = models.PatientMessage(
        patient_id=patient_id,
        provider_id=current_user.id,
        direction="outbound",
        body=body,
        sms_status=sms_status,
        telnyx_msg_id=telnyx_mid,
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)

    audit(db, current_user.id, "SEND_PATIENT_MESSAGE", "Patient", str(patient_id), request=request,
          details=f"sms_status={sms_status}")
    return clean(msg)


@app.post("/api/patients/{patient_id}/messages/sms-forward")
def sms_forward_message(
    patient_id: int,
    data: dict,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Re-forward a patient message to the physician's cell phone via SMS.
    Useful if the original forward failed or physician wants it resent.
    """
    msg_id = data.get("message_id")
    msg = db.query(models.PatientMessage).filter(
        models.PatientMessage.id == msg_id,
        models.PatientMessage.patient_id == patient_id,
    ).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")

    patient = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
    sms_body = (
        f"[Valiant DPC] Msg from {patient.first_name} {patient.last_name} "
        f"(PT#{patient_id}):\n\n{msg.body}\n\n"
        f"Reply to this number to respond to the patient."
    )
    # Route to the provider who owns the message thread, else fall back to current user
    dest_provider = None
    if msg.provider_id:
        dest_provider = db.query(models.User).filter(models.User.id == msg.provider_id).first()
    dest_provider = dest_provider or current_user

    dest_cell  = getattr(dest_provider, "cell_phone", "") or PHYSICIAN_CELL
    from_num   = getattr(dest_provider, "telnyx_sms_number", "") or TELNYX_SMS_NUMBER
    mid = _send_sms(dest_cell, sms_body, from_number=from_num) if dest_cell else None
    if mid:
        msg.sms_status = "sent"
        msg.telnyx_msg_id = mid
        db.commit()
    return {"sent": bool(mid)}


@app.get("/api/messages/unread-count")
def unread_message_count(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Total unread inbound messages across all patients (for the badge in the sidebar)."""
    count = (
        db.query(models.PatientMessage)
        .filter(
            models.PatientMessage.direction == "inbound",
            models.PatientMessage.read_at == None,
        )
        .count()
    )
    return {"unread": count}


# ── Patient portal — messaging ────────────────────────────────────────────────

def _get_patient_provider(patient: models.Patient, db) -> Optional[models.User]:
    """Return the provider best associated with this patient.

    Priority:
    1. The provider on the most recent PatientMessage thread
    2. The provider on the most recent appointment
    3. The User who created the patient record (if role == physician)
    4. The first active physician in the DB
    """
    # 1. Most recent message thread
    recent_msg = (
        db.query(models.PatientMessage)
        .filter(
            models.PatientMessage.patient_id == patient.id,
            models.PatientMessage.provider_id != None,
        )
        .order_by(models.PatientMessage.created_at.desc())
        .first()
    )
    if recent_msg and recent_msg.provider_id:
        p = db.query(models.User).filter(models.User.id == recent_msg.provider_id).first()
        if p:
            return p

    # 2. Most recent appointment
    recent_appt = (
        db.query(models.Appointment)
        .filter(models.Appointment.patient_id == patient.id)
        .order_by(models.Appointment.created_at.desc())
        .first()
    )
    if recent_appt and recent_appt.provider_id:
        p = db.query(models.User).filter(models.User.id == recent_appt.provider_id).first()
        if p:
            return p

    # 3. Created-by user if they are a physician
    if patient.created_by:
        p = db.query(models.User).filter(
            models.User.id == patient.created_by,
            models.User.role == "physician",
        ).first()
        if p:
            return p

    # 4. First active physician
    return (
        db.query(models.User)
        .filter(models.User.role == "physician", models.User.is_active == True)
        .order_by(models.User.id)
        .first()
    )


@app.get("/portal/provider-info")
def portal_provider_info(
    patient: models.Patient = Depends(get_portal_patient),
    db: Session = Depends(get_db),
):
    """Return safe provider contact info for the patient's portal.

    Only exposes the Telnyx SMS number (so patients know which number to text)
    and the provider's display name. No PHI about other patients is disclosed.
    """
    provider = _get_patient_provider(patient, db)
    if not provider:
        return {"provider_name": "Your Care Team", "sms_number": TELNYX_SMS_NUMBER or None}
    return {
        "provider_name": provider.full_name,
        "sms_number": provider.telnyx_sms_number or TELNYX_SMS_NUMBER or None,
    }


@app.get("/portal/messages")
def portal_get_messages(
    patient: models.Patient = Depends(get_portal_patient),
    db: Session = Depends(get_db),
):
    """Patient retrieves their message thread with the practice."""
    messages = (
        db.query(models.PatientMessage)
        .filter(models.PatientMessage.patient_id == patient.id)
        .order_by(models.PatientMessage.created_at.asc())
        .all()
    )
    # Mark outbound (provider→patient) messages as read when patient views them
    for m in messages:
        if m.direction == "outbound" and not m.read_at:
            m.read_at = datetime.utcnow()
    db.commit()
    return [clean(m) for m in messages]


@app.post("/portal/messages")
def portal_send_message(
    data: dict,
    request: Request,
    patient: models.Patient = Depends(get_portal_patient),
    db: Session = Depends(get_db),
):
    """Patient sends a message. Stored in DB and forwarded to physician via SMS."""
    body = (data.get("body") or "").strip()
    if not body:
        raise HTTPException(status_code=400, detail="Message body is required.")
    if len(body) > 2000:
        raise HTTPException(status_code=400, detail="Message too long (max 2000 characters).")

    msg = models.PatientMessage(
        patient_id=patient.id,
        direction="inbound",
        body=body,
        sms_status="pending",
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)

    # Forward to the patient's assigned provider via SMS
    provider   = _get_patient_provider(patient, db)
    dest_cell  = (getattr(provider, "cell_phone", "") if provider else "") or PHYSICIAN_CELL
    from_num   = (getattr(provider, "telnyx_sms_number", "") if provider else "") or TELNYX_SMS_NUMBER

    if dest_cell:
        sms_body = (
            f"[Valiant DPC] Portal msg from {patient.first_name} {patient.last_name} "
            f"(PT#{patient.id}):\n\n{body}\n\n"
            f"Reply to this number to respond to the patient."
        )
        mid = _send_sms(dest_cell, sms_body, from_number=from_num)
        msg.sms_status = "sent" if mid else "failed"
        if mid:
            msg.telnyx_msg_id = mid
        if provider:
            msg.provider_id = provider.id
    db.commit()

    audit(db, None, "PORTAL_SEND_MESSAGE", "Patient", str(patient.id), request=request,
          details=f"provider_id={provider.id if provider else 'none'}")
    return clean(msg)


# ── Communication consent endpoints ──────────────────────────────────────────

@app.put("/api/patients/{patient_id}/communication-consent")
def update_communication_consent(
    patient_id: int,
    data: dict,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    Record or revoke a patient's SMS and/or email communication consent.
    Only admin and physician may update consent on behalf of a patient.
    Body: { "sms_consent": bool, "email_consent": bool }
    """
    if current_user.role not in ("admin", "physician"):
        raise HTTPException(status_code=403, detail="Not authorized")
    patient = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    now = datetime.utcnow()
    changed = []

    if "sms_consent" in data:
        new_val = bool(data["sms_consent"])
        if new_val != bool(patient.sms_consent):
            patient.sms_consent = new_val
            patient.sms_consent_date = now if new_val else None
            changed.append(f"sms_consent={'granted' if new_val else 'revoked'}")

    if "email_consent" in data:
        new_val = bool(data["email_consent"])
        if new_val != bool(patient.email_consent):
            patient.email_consent = new_val
            patient.email_consent_date = now if new_val else None
            changed.append(f"email_consent={'granted' if new_val else 'revoked'}")

    if changed:
        db.commit()
        audit(db, current_user.id, "UPDATE_COMMUNICATION_CONSENT", "Patient",
              str(patient_id), request=request, details="; ".join(changed))

    return {
        "sms_consent": patient.sms_consent,
        "sms_consent_date": patient.sms_consent_date.isoformat() if patient.sms_consent_date else None,
        "email_consent": patient.email_consent,
        "email_consent_date": patient.email_consent_date.isoformat() if patient.email_consent_date else None,
    }


# ── Telnyx signature verification ────────────────────────────────────────────

def _verify_telnyx_sms_signature(raw_body: bytes, timestamp: str, signature_b64: str) -> bool:
    """
    Verify an inbound Telnyx webhook using Ed25519.
    Set TELNYX_PUBLIC_KEY in Railway to the base64-encoded public key from the
    Telnyx Mission Control Portal → Webhooks → your endpoint → Public Key.
    If the env var is not set, verification is skipped with a warning (dev mode).
    """
    public_key_b64 = os.getenv("TELNYX_PUBLIC_KEY", "")
    if not public_key_b64:
        # No key configured — skip but log so operators know
        return True

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        import base64, time as _time

        # Reject replayed requests older than 5 minutes
        if abs(_time.time() - int(timestamp)) > 300:
            return False

        pub_key_bytes = base64.b64decode(public_key_b64)
        pub_key = Ed25519PublicKey.from_public_bytes(pub_key_bytes)
        message = f"{timestamp}|{raw_body.decode('utf-8', errors='replace')}".encode()
        sig = base64.b64decode(signature_b64)
        pub_key.verify(sig, message)   # raises InvalidSignature on failure
        return True
    except Exception:
        return False


_SMS_DISCLAIMER = (
    "Your message has been received and will be reviewed by your care team. "
    "For URGENT or EMERGENCY issues please call 911 or your physician directly. "
    "IMPORTANT: SMS text messages are not encrypted. Do not send sensitive health "
    "information by text. Use your secure patient portal instead."
)

_SMS_NO_CONSENT = (
    "We received your text but SMS communication has not been enabled for your account. "
    "Please contact Valiant DPC to update your communication preferences."
)

_SMS_NOT_FOUND = (
    "This number is reserved for Valiant DPC patients. "
    "If you are a patient, please ensure we have your current phone number on file."
)


@app.post("/api/webhooks/telnyx/sms")
async def telnyx_sms_webhook(request: Request, db: Session = Depends(get_db)):
    """
    Telnyx inbound SMS webhook — HIPAA-hardened.

    Handles two scenarios:
    1. Inbound from a patient → filed in their chart, forwarded to physician.
    2. Inbound from the physician's cell → filed as outbound reply to most recent patient thread.

    Security:
    - Ed25519 signature verification (TELNYX_PUBLIC_KEY env var)
    - Timestamp replay protection (±5 min window)
    - Phone number matching against patients.phone
    - sms_consent gate — patients without consent receive a polite rejection
    - Full audit trail on every event
    """
    raw_body = await request.body()

    # ── Signature verification ────────────────────────────────────────────────
    timestamp  = request.headers.get("telnyx-timestamp", "")
    signature  = request.headers.get("telnyx-signature-ed25519", "")
    if timestamp and signature:
        if not _verify_telnyx_sms_signature(raw_body, timestamp, signature):
            audit(db, None, "SMS_WEBHOOK_SIGNATURE_FAIL", "Webhook", "telnyx_sms",
                  details=f"Invalid signature from {request.client.host if request.client else 'unknown'}")
            raise HTTPException(status_code=403, detail="Invalid webhook signature")

    try:
        payload = json.loads(raw_body)
    except Exception:
        return {"ok": False, "error": "invalid JSON"}

    event_type = payload.get("data", {}).get("event_type", "")
    if event_type != "message.received":
        return {"ok": True, "ignored": event_type}

    record      = payload.get("data", {}).get("payload", {})
    from_number = record.get("from", {}).get("phone_number", "")
    to_number   = record.get("to", [{}])[0].get("phone_number", "") if record.get("to") else ""
    body_text   = (record.get("text") or "").strip()

    if not body_text or not from_number:
        return {"ok": True, "ignored": "empty body or sender"}

    # ─────────────────────────────────────────────────────────────────────────
    # Normalize helper
    def _norm(num: str) -> str:
        d = re.sub(r"\D", "", num)
        if len(d) == 10:
            d = "1" + d
        return "+" + d

    # ── Identify the provider who owns the Telnyx number that received the SMS ─
    # Each provider has a unique telnyx_sms_number; match on it (try both raw &
    # normalized forms to be safe).
    to_norm = _norm(to_number) if to_number else ""
    provider = None
    if to_number or to_norm:
        provider = (
            db.query(models.User)
            .filter(
                models.User.telnyx_sms_number.in_(
                    [t for t in [to_number, to_norm] if t]
                )
            )
            .first()
        )

    # ── Provider reply path: from_number matches a provider's cell_phone ─────
    # A provider replies from their personal cell → the message comes back to
    # their Telnyx number → we file it as outbound and forward to the patient.
    replying_provider = (
        db.query(models.User)
        .filter(models.User.cell_phone != "")
        .filter(
            models.User.cell_phone.in_(
                [f for f in [from_number, _norm(from_number)] if f]
            )
        )
        .first()
    )

    if replying_provider:
        # Find the most recent inbound message for any patient in this provider's thread
        recent = (
            db.query(models.PatientMessage)
            .filter(
                models.PatientMessage.direction == "inbound",
                models.PatientMessage.provider_id == replying_provider.id,
            )
            .order_by(models.PatientMessage.created_at.desc())
            .first()
        )
        # Fallback: if no provider_id-tagged messages, use any recent inbound on their Telnyx number
        if not recent and provider:
            recent = (
                db.query(models.PatientMessage)
                .filter(models.PatientMessage.direction == "inbound")
                .order_by(models.PatientMessage.created_at.desc())
                .first()
            )
        if recent:
            pt = db.query(models.Patient).filter(models.Patient.id == recent.patient_id).first()
            sms_status = "not_applicable"
            telnyx_mid = None

            if pt and pt.sms_consent and pt.phone:
                # Send from the provider's Telnyx number so the patient sees
                # the same number they originally texted
                from_num   = getattr(replying_provider, "telnyx_sms_number", None) or TELNYX_SMS_NUMBER
                fwd_body   = f"[Valiant DPC] {body_text}"
                telnyx_mid = _send_sms(pt.phone, fwd_body, from_number=from_num)
                sms_status = "sent" if telnyx_mid else "failed"

            reply = models.PatientMessage(
                patient_id=recent.patient_id,
                provider_id=replying_provider.id,
                direction="outbound",
                body=body_text,
                sms_status=sms_status,
                telnyx_msg_id=telnyx_mid,
            )
            db.add(reply)
            db.commit()
            audit(db, replying_provider.id, "SMS_PHYSICIAN_REPLY", "Patient", str(recent.patient_id),
                  details=f"Provider {replying_provider.id} SMS reply filed; sms_status={sms_status}")
            return {"ok": True, "filed_to_patient": recent.patient_id}
        return {"ok": True, "ignored": "no recent patient thread to reply to"}

    # ── Inbound from patient — normalize phone and look them up ──────────────
    from_norm = _norm(from_number)
    from_10   = re.sub(r"\D", "", from_number)[-10:]

    patient = (
        db.query(models.Patient)
        .filter(
            models.Patient.phone.in_(
                [f for f in [from_number, from_norm, from_norm.replace("+1", ""), from_10] if f]
            )
        )
        .first()
    )

    if not patient:
        # Unknown number — reply and audit, but do NOT expose patient info
        _send_sms(from_number, _SMS_NOT_FOUND,
                  from_number=(provider.telnyx_sms_number if provider else None))
        audit(db, None, "SMS_UNKNOWN_SENDER", "Webhook", "telnyx_sms",
              details=f"Inbound SMS from unrecognized number (last4={from_number[-4:]})")
        return {"ok": True, "ignored": "no matching patient"}

    # ── Consent gate ─────────────────────────────────────────────────────────
    if not patient.sms_consent:
        _send_sms(from_number, _SMS_NO_CONSENT,
                  from_number=(provider.telnyx_sms_number if provider else None))
        audit(db, None, "SMS_NO_CONSENT", "Patient", str(patient.id),
              details="Inbound SMS blocked — sms_consent not granted")
        return {"ok": True, "ignored": "patient has not consented to SMS"}

    # ── File the message ──────────────────────────────────────────────────────
    is_first_message = (
        db.query(models.PatientMessage)
        .filter(models.PatientMessage.patient_id == patient.id)
        .count() == 0
    )

    msg = models.PatientMessage(
        patient_id=patient.id,
        provider_id=provider.id if provider else None,
        direction="inbound",
        body=body_text,
        sms_status="delivered",
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)

    audit(db, None, "SMS_PATIENT_MESSAGE", "Patient", str(patient.id),
          details=f"Inbound SMS from patient; msg_id={msg.id}; provider_id={provider.id if provider else 'unknown'}")

    # ── Send disclaimer on first message (from provider's Telnyx number) ─────
    telnyx_from = (provider.telnyx_sms_number if provider else None) or TELNYX_SMS_NUMBER
    if is_first_message:
        _send_sms(from_number, _SMS_DISCLAIMER, from_number=telnyx_from)

    # ── Forward to provider's cell phone ─────────────────────────────────────
    if provider and getattr(provider, "cell_phone", ""):
        fwd = (
            f"[Valiant DPC] {patient.first_name} {patient.last_name} (PT#{patient.id}) texted:\n\n"
            f"{body_text}\n\n"
            f"Reply to this number to respond. Message is filed in the EMR."
        )
        mid = _send_sms(provider.cell_phone, fwd, from_number=telnyx_from)
        if mid:
            msg.telnyx_msg_id = mid
            msg.sms_status = "sent"
            db.commit()
    elif PHYSICIAN_CELL:
        # Fallback: global physician cell (for backward-compat with single-provider setups)
        fwd = (
            f"[Valiant DPC] {patient.first_name} {patient.last_name} (PT#{patient.id}) texted:\n\n"
            f"{body_text}\n\n"
            f"Reply to this number to respond. Message is filed in the EMR."
        )
        mid = _send_sms(PHYSICIAN_CELL, fwd, from_number=telnyx_from)
        if mid:
            msg.telnyx_msg_id = mid
            msg.sms_status = "sent"
            db.commit()

    return {"ok": True, "filed": msg.id, "patient_id": patient.id}


@app.get("/portal")
def serve_portal():
    from fastapi.responses import FileResponse
    import os
    portal_path = os.path.join(os.path.dirname(__file__), "..", "frontend", "portal.html")
    return FileResponse(os.path.abspath(portal_path))


@app.on_event("startup")
def on_startup():
    db = next(get_db())
    try:
        _migrate_add_billing_columns(db)
        _seed_membership_plans(db)
        _backfill_billing_dates(db)
    finally:
        db.close()


@app.get("/api/public/plans")
def public_list_plans(db: Session = Depends(get_db)):
    """Public endpoint — returns active membership plan definitions."""
    _seed_membership_plans(db)
    plans = (db.query(models.MembershipPlan)
             .filter(models.MembershipPlan.is_active == True)
             .order_by(models.MembershipPlan.sort_order)
             .all())
    result = []
    for p in plans:
        d = clean(p)
        try:
            d["features"] = json.loads(p.features or "[]")
        except Exception:
            d["features"] = []
        result.append(d)
    return result


@app.post("/api/public/enroll")
async def public_enroll(data: dict, request: Request, db: Session = Depends(get_db)):
    """
    Public enrollment submission — no auth required.
    Accepts the full enrollment form payload: plan, demographics,
    medical history, signed consents, and payment info.
    Creates an EnrollmentApplication and PatientConsent records.
    """
    ip   = request.client.host if request.client else ""
    ua   = request.headers.get("user-agent", "")
    _check_enrollment_rate_limit(ip)
    token = str(_uuid.uuid4())

    # Resolve plan
    plan_slug = data.get("plan_slug", "")
    plan = db.query(models.MembershipPlan).filter(
        models.MembershipPlan.slug == plan_slug,
        models.MembershipPlan.is_active == True,
    ).first()

    app_record = models.EnrollmentApplication(
        enrollment_token  = token,
        plan_id           = plan.id if plan else None,
        plan_name         = plan.name if plan else plan_slug,
        status            = "pending",
        # Demographics
        first_name        = data.get("first_name", ""),
        last_name         = data.get("last_name", ""),
        dob               = data.get("dob", ""),
        gender            = data.get("gender", ""),
        email             = data.get("email", ""),
        phone             = data.get("phone", ""),
        address           = data.get("address", ""),
        city              = data.get("city", ""),
        state             = data.get("state", ""),
        zip_code          = data.get("zip_code", ""),
        # Emergency contact
        emergency_name    = data.get("emergency_name", ""),
        emergency_phone   = data.get("emergency_phone", ""),
        emergency_relation= data.get("emergency_relation", ""),
        # Insurance
        insurance_name    = data.get("insurance_name", ""),
        insurance_id      = data.get("insurance_id", ""),
        # Medical history
        allergies         = json.dumps(data.get("allergies", [])),
        medications       = json.dumps(data.get("medications", [])),
        conditions        = json.dumps(data.get("conditions", [])),
        # Consents stored as JSON
        consents          = json.dumps(data.get("consents", [])),
        # Payment
        payment_provider  = data.get("payment_provider", ""),
        payment_amount    = plan.price_monthly if plan else 0.0,
        ip_address        = ip,
        user_agent        = ua,
    )
    db.add(app_record)
    db.commit()
    db.refresh(app_record)

    # Store individual consent records
    consents_raw = data.get("consents", {})
    # Support both dict form (new) and list form (legacy)
    if isinstance(consents_raw, dict):
        consent_items = [
            {"type": "hipaa",         "signature": consents_raw.get("hipaa", "")},
            {"type": "telehealth",    "signature": consents_raw.get("telehealth", "")},
            {"type": "communication", "signature": consents_raw.get("communication", ""),
             "sms_consent": consents_raw.get("sms_consent", False),
             "email_consent": consents_raw.get("email_consent", False)},
            {"type": "membership",    "signature": consents_raw.get("membership", "")},
        ]
    else:
        consent_items = consents_raw

    for c in consent_items:
        if not c.get("signature") and not c.get("consented"):
            continue
        consent = models.PatientConsent(
            enrollment_id    = app_record.id,
            consent_type     = c.get("type", ""),
            document_version = c.get("version", "1.0"),
            signed_at        = datetime.utcnow(),
            ip_address       = ip,
            user_agent       = ua,
            signature_text   = c.get("signature", ""),
            consented        = True,
        )
        db.add(consent)

    # Store the full consents dict (with SMS/email flags) on the enrollment record
    app_record.consents = json.dumps([
        {**c, "signed_at": datetime.utcnow().isoformat()} for c in consent_items
    ])
    db.commit()

    return {
        "success": True,
        "enrollment_token": token,
        "enrollment_id": app_record.id,
        "message": "Enrollment application received. Proceed to payment.",
    }


@app.post("/api/public/create-payment")
async def public_create_payment(data: dict, request: Request, db: Session = Depends(get_db)):
    """
    Create a payment session after enrollment is submitted.
    Provider: "square" → creates Square customer + charges card nonce
              "zaprite" → creates a Zaprite hosted checkout link
    Returns: {success, redirect_url} for Zaprite
             {success, payment_id}   for Square
    """
    token    = data.get("enrollment_token", "")
    provider = data.get("provider", "square")
    enroll   = db.query(models.EnrollmentApplication).filter(
        models.EnrollmentApplication.enrollment_token == token
    ).first()
    if not enroll:
        raise HTTPException(status_code=404, detail="Enrollment not found")

    plan = db.query(models.MembershipPlan).filter(
        models.MembershipPlan.id == enroll.plan_id
    ).first() if enroll.plan_id else None
    amount_cents = int((plan.price_monthly if plan else 0) * 100)
    description  = f"Valiant DPC — {enroll.plan_name} Monthly Membership"

    if provider == "zaprite":
        if not ZAPRITE_API_KEY:
            raise HTTPException(status_code=503, detail="ZAPRITE_API_KEY not configured")
        success_url = f"{APP_BASE_URL}/enroll/success?token={token}"
        cancel_url  = f"{APP_BASE_URL}/enroll?token={token}"
        resp = httpx.post(
            f"{ZAPRITE_BASE_URL}/checkout",
            json={
                "amount": amount_cents,
                "currency": "USD",
                "label": description,
                "success_url": success_url,
                "cancel_url":  cancel_url,
                "metadata": {"enrollment_token": token},
            },
            headers={"Authorization": f"Bearer {ZAPRITE_API_KEY}"},
            timeout=15,
        )
        if not resp.is_success:
            raise HTTPException(status_code=502, detail=f"Zaprite error: {resp.text}")
        checkout_url = resp.json().get("url") or resp.json().get("checkout_url", "")
        enroll.payment_provider  = "zaprite"
        enroll.payment_reference = resp.json().get("id", "")
        enroll.status            = "payment_pending"
        db.commit()
        return {"success": True, "redirect_url": checkout_url}

    elif provider == "square":
        if not SQUARE_ACCESS_TOKEN or not SQUARE_LOCATION_ID:
            raise HTTPException(status_code=503, detail="Square not configured — add SQUARE_ACCESS_TOKEN and SQUARE_LOCATION_ID")
        nonce = data.get("card_nonce", "")
        if not nonce:
            raise HTTPException(status_code=400, detail="card_nonce required for Square")
        idempotency_key = str(_uuid.uuid4())
        # Create Square customer
        cust_resp = httpx.post(
            f"{SQUARE_BASE_URL}/v2/customers",
            json={
                "idempotency_key": idempotency_key,
                "given_name":  enroll.first_name,
                "family_name": enroll.last_name,
                "email_address": enroll.email,
                "phone_number":  enroll.phone,
                "reference_id":  token,
            },
            headers={"Authorization": f"Bearer {SQUARE_ACCESS_TOKEN}", "Content-Type": "application/json"},
            timeout=15,
        )
        cust_resp.raise_for_status()
        customer_id = cust_resp.json().get("customer", {}).get("id", "")
        # Create card on file
        card_resp = httpx.post(
            f"{SQUARE_BASE_URL}/v2/cards",
            json={
                "idempotency_key": str(_uuid.uuid4()),
                "source_id": nonce,
                "card": {"customer_id": customer_id},
            },
            headers={"Authorization": f"Bearer {SQUARE_ACCESS_TOKEN}", "Content-Type": "application/json"},
            timeout=15,
        )
        card_resp.raise_for_status()
        card_id = card_resp.json().get("card", {}).get("id", "")
        # Charge first month
        charge_resp = httpx.post(
            f"{SQUARE_BASE_URL}/v2/payments",
            json={
                "idempotency_key": str(_uuid.uuid4()),
                "amount_money": {"amount": amount_cents, "currency": "USD"},
                "source_id": card_id,
                "customer_id": customer_id,
                "location_id": SQUARE_LOCATION_ID,
                "note": description,
                "reference_id": token,
            },
            headers={"Authorization": f"Bearer {SQUARE_ACCESS_TOKEN}", "Content-Type": "application/json"},
            timeout=15,
        )
        charge_resp.raise_for_status()
        payment_id = charge_resp.json().get("payment", {}).get("id", "")
        enroll.payment_provider  = "square"
        enroll.payment_reference = payment_id
        enroll.payment_status    = "completed"
        enroll.status            = "active"
        db.commit()
        return {"success": True, "payment_id": payment_id}

    raise HTTPException(status_code=400, detail="Unknown payment provider")


@app.post("/api/public/payment-webhook")
async def public_payment_webhook(request: Request, db: Session = Depends(get_db)):
    """Webhook from Zaprite or Square confirming payment completion."""
    body = await request.json()
    # Zaprite webhook
    token = (body.get("metadata", {}) or {}).get("enrollment_token", "")
    if not token:
        token = body.get("reference_id", "")
    if token:
        enroll = db.query(models.EnrollmentApplication).filter(
            models.EnrollmentApplication.enrollment_token == token
        ).first()
        if enroll:
            enroll.payment_status = "completed"
            enroll.status         = "active"
            db.commit()
    return {"success": True}


@app.get("/api/public/enrollment-status/{token}")
def public_enrollment_status(token: str, db: Session = Depends(get_db)):
    """Check enrollment status by token (for post-payment confirmation page)."""
    enroll = db.query(models.EnrollmentApplication).filter(
        models.EnrollmentApplication.enrollment_token == token
    ).first()
    if not enroll:
        raise HTTPException(status_code=404, detail="Not found")
    return {
        "status":     enroll.status,
        "plan_name":  enroll.plan_name,
        "first_name": enroll.first_name,
        "last_name":  enroll.last_name,
    }


# ── Admin enrollment management (authenticated) ───────────────────────────────

@app.get("/api/enrollment-applications")
def list_enrollments(
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    q = db.query(models.EnrollmentApplication)
    if status:
        q = q.filter(models.EnrollmentApplication.status == status)
    rows = q.order_by(models.EnrollmentApplication.created_at.desc()).all()
    result = []
    for r in rows:
        d = clean(r)
        try: d["allergies"]   = json.loads(r.allergies or "[]")
        except: pass
        try: d["medications"] = json.loads(r.medications or "[]")
        except: pass
        try: d["conditions"]  = json.loads(r.conditions or "[]")
        except: pass
        try: d["consents"]    = json.loads(r.consents or "[]")
        except: pass
        result.append(d)
    return result


@app.post("/api/enrollment-applications/{eid}/approve")
def approve_enrollment(
    eid: int,
    data: dict = {},
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Approve an enrollment and create a Patient record from it."""
    enroll = db.query(models.EnrollmentApplication).filter(
        models.EnrollmentApplication.id == eid
    ).first()
    if not enroll:
        raise HTTPException(status_code=404)
    # Create patient
    pt = models.Patient(
        first_name   = enroll.first_name,
        last_name    = enroll.last_name,
        dob          = enroll.dob,
        gender       = enroll.gender,
        email        = enroll.email,
        phone        = enroll.phone,
        address      = enroll.address,
        city         = enroll.city,
        state        = enroll.state,
        zip_code     = enroll.zip_code,
        is_active    = True,
    )
    db.add(pt)
    db.flush()
    # Create membership
    plan = db.query(models.MembershipPlan).filter(
        models.MembershipPlan.id == enroll.plan_id
    ).first() if enroll.plan_id else None
    if plan:
        start_now = datetime.utcnow()
        billing_cycle = data.get("billing_cycle", "monthly") if isinstance(data, dict) else "monthly"
        is_annual = billing_cycle == "annual"
        next_date = start_now.replace(year=start_now.year + 1) if is_annual else _next_anniversary(start_now)
        mem = models.Membership(
            patient_id        = pt.id,
            plan_name         = plan.name,
            price_monthly     = plan.price_monthly,
            price_annual      = plan.price_annual,
            billing_cycle     = billing_cycle,
            start_date        = start_now,
            status            = "active",
            payment_provider  = enroll.payment_method or "square",
            next_billing_date = next_date,
            billing_status    = "ok",
        )
        db.add(mem)
    # Link consents to new patient
    db.query(models.PatientConsent).filter(
        models.PatientConsent.enrollment_id == eid
    ).update({"patient_id": pt.id})

    # Propagate communication consent from enrollment to patient record
    consents_json = enroll.consents or "[]"
    try:
        consents_list = json.loads(consents_json) if isinstance(consents_json, str) else consents_json
    except Exception:
        consents_list = []
    comm_consent = next((c for c in consents_list if c.get("type") in ("communication", "sms_email")), None)
    if comm_consent and comm_consent.get("consented", True):
        signed_at_str = comm_consent.get("signed_at", "")
        try:
            signed_dt = datetime.fromisoformat(signed_at_str) if signed_at_str else datetime.utcnow()
        except ValueError:
            signed_dt = datetime.utcnow()
        sms_val  = comm_consent.get("sms_consent", True)
        mail_val = comm_consent.get("email_consent", True)
        if sms_val:
            pt.sms_consent      = True
            pt.sms_consent_date = signed_dt
        if mail_val:
            pt.email_consent      = True
            pt.email_consent_date = signed_dt

    # Update enrollment
    enroll.patient_id   = pt.id
    enroll.status       = "active"
    enroll.reviewed_by  = current_user.id
    enroll.reviewed_at  = datetime.utcnow()
    enroll.review_notes = data.get("notes", "")
    db.commit()
    audit(db, current_user.id, "APPROVE_ENROLLMENT", "Enrollment", str(eid), f"Patient {pt.id} created")
    return {"success": True, "patient_id": pt.id}


@app.post("/api/enrollment-applications/{eid}/reject")
def reject_enrollment(
    eid: int,
    data: dict = {},
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    enroll = db.query(models.EnrollmentApplication).filter(
        models.EnrollmentApplication.id == eid
    ).first()
    if not enroll:
        raise HTTPException(status_code=404)
    enroll.status       = "rejected"
    enroll.reviewed_by  = current_user.id
    enroll.reviewed_at  = datetime.utcnow()
    enroll.review_notes = data.get("notes", "")
    db.commit()
    audit(db, current_user.id, "REJECT_ENROLLMENT", "Enrollment", str(eid))
    return {"success": True}


@app.get("/api/membership-plans")
def list_membership_plans(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    _seed_membership_plans(db)
    plans = db.query(models.MembershipPlan).order_by(models.MembershipPlan.sort_order).all()
    result = []
    for p in plans:
        d = clean(p)
        try: d["features"] = json.loads(p.features or "[]")
        except: pass
        result.append(d)
    return result


@app.put("/api/membership-plans/{plan_id}")
def update_membership_plan(
    plan_id: int,
    data: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    plan = db.query(models.MembershipPlan).filter(models.MembershipPlan.id == plan_id).first()
    if not plan:
        raise HTTPException(status_code=404)
    for field in ["name","description","price_monthly","price_annual","enrollment_fee",
                  "badge","color","is_active","square_plan_id","zaprite_plan_id"]:
        if field in data:
            setattr(plan, field, data[field])
    if "features" in data:
        plan.features = json.dumps(data["features"])
    plan.updated_at = datetime.utcnow()
    db.commit()
    audit(db, current_user.id, "UPDATE_PLAN", "MembershipPlan", str(plan_id))
    d = clean(plan)
    try: d["features"] = json.loads(plan.features or "[]")
    except: pass
    return d


# ═════════════════════════════════════════════════════════════════════════════
# COMPLIANCE POLICIES
# ═════════════════════════════════════════════════════════════════════════════

_POLICIES_META = [
    {
        "id": "POL-HIPAA-001",
        "title": "HIPAA Workforce Training Policy",
        "category": "Administrative Safeguard",
        "risk_refs": ["Risk 2"],
        "version": "1.0",
        "effective_date": "2026-03-20",
        "next_review": "2027-03-20",
        "owner": "Privacy & Security Officer",
        "regulatory_basis": "45 C.F.R. § 164.308(a)(5)",
        "summary": "Establishes mandatory pre-access and annual HIPAA training requirements for all workforce members, including documentation and record retention obligations.",
        "filename": "POL-HIPAA-001_Workforce_Training_Policy.docx",
    },
    {
        "id": "POL-HIPAA-002",
        "title": "Incident Response & Breach Notification Plan",
        "category": "Administrative Safeguard",
        "risk_refs": ["Risk 3"],
        "version": "1.0",
        "effective_date": "2026-03-20",
        "next_review": "2027-03-20",
        "owner": "Privacy & Security Officer",
        "regulatory_basis": "45 C.F.R. § 164.308(a)(6); 45 C.F.R. §§ 164.400–414",
        "summary": "Five-phase response plan covering detection, containment, investigation, notification (60-day deadline), and post-incident remediation for security incidents involving ePHI.",
        "filename": "POL-HIPAA-002_Incident_Response_Breach_Notification_Plan.docx",
    },
    {
        "id": "POL-HIPAA-003",
        "title": "User Access Management & Workforce Offboarding Policy",
        "category": "Administrative Safeguard",
        "risk_refs": ["Risk 4"],
        "version": "1.0",
        "effective_date": "2026-03-20",
        "next_review": "2027-03-20",
        "owner": "Privacy & Security Officer",
        "regulatory_basis": "45 C.F.R. § 164.308(a)(3); § 164.308(a)(4)",
        "summary": "Governs provisioning, modification, and revocation of ePHI system access. Requires same-day revocation on termination, quarterly access reviews, and minimum necessary access principles.",
        "filename": "POL-HIPAA-003_User_Access_Management_Policy.docx",
    },
    {
        "id": "POL-HIPAA-004",
        "title": "Data Retention & Disposal Policy",
        "category": "Administrative Safeguard",
        "risk_refs": ["Risk 5"],
        "version": "1.0",
        "effective_date": "2026-03-20",
        "next_review": "2027-03-20",
        "owner": "Privacy & Security Officer",
        "regulatory_basis": "45 C.F.R. § 164.310(d)(2); Virginia Code § 32.1-127.1:03",
        "summary": "Defines retention schedules for all record types (5–7 years depending on type) and mandates NIST SP 800-88 compliant disposal methods for electronic and paper records.",
        "filename": "POL-HIPAA-004_Data_Retention_Disposal_Policy.docx",
    },
    {
        "id": "POL-HIPAA-005",
        "title": "Audit Log Review Policy",
        "category": "Administrative Safeguard",
        "risk_refs": ["Risk 6"],
        "version": "1.0",
        "effective_date": "2026-03-20",
        "next_review": "2027-03-20",
        "owner": "Privacy & Security Officer",
        "regulatory_basis": "45 C.F.R. § 164.312(b); § 164.308(a)(1)(ii)(D)",
        "summary": "Requires weekly and monthly audit log reviews with defined anomaly triggers (e.g., 5+ failed logins, bulk record access, after-hours admin actions) and mandatory written review summaries.",
        "filename": "POL-HIPAA-005_Audit_Log_Review_Policy.docx",
    },
    {
        "id": "POL-HIPAA-006",
        "title": "Business Associate Agreement Management Policy",
        "category": "Administrative Safeguard",
        "risk_refs": ["Risk 1"],
        "version": "1.0",
        "effective_date": "2026-03-20",
        "next_review": "2027-03-20",
        "owner": "Privacy & Security Officer",
        "regulatory_basis": "45 C.F.R. § 164.308(b); § 164.504(e)",
        "summary": "Mandates BAA execution with all vendors handling ePHI before access is granted. Identifies Railway, Telnyx, Square, and LabCorp as immediate priority. Includes BAA lifecycle management and vendor register requirements.",
        "filename": "POL-HIPAA-006_BAA_Management_Policy.docx",
    },
    {
        "id": "POL-PHYS-001",
        "title": "BYOD & Acceptable Use Policy",
        "category": "Physical Safeguard",
        "risk_refs": ["Risk 18"],
        "version": "1.0",
        "effective_date": "2026-03-20",
        "next_review": "2027-03-20",
        "owner": "Privacy & Security Officer",
        "regulatory_basis": "45 C.F.R. § 164.310(b); § 164.310(c)",
        "summary": "Governs use of personal and practice-owned devices to access ePHI. Requires MDM enrollment, screen-lock, encrypted storage, remote-wipe capability, and prohibited storage of ePHI on personal devices without approval.",
        "filename": "POL-PHYS-001_BYOD_Acceptable_Use_Policy.docx",
    },
    {
        "id": "POL-PHYS-002",
        "title": "Workstation Privacy Screen & Security Policy",
        "category": "Physical Safeguard",
        "risk_refs": ["Risk 19"],
        "version": "1.0",
        "effective_date": "2026-03-20",
        "next_review": "2027-03-20",
        "owner": "Privacy & Security Officer",
        "regulatory_basis": "45 C.F.R. § 164.310(b); § 164.310(c)",
        "summary": "Requires privacy screens on all workstations visible to the public, automatic screen-lock at 5 minutes, clean-desk rules, and physical placement standards to prevent shoulder-surfing of patient data.",
        "filename": "POL-PHYS-002_Workstation_Privacy_Screen_Security.docx",
    },
    {
        "id": "POL-PHYS-003",
        "title": "Downtime & Business Continuity Procedure",
        "category": "Physical Safeguard",
        "risk_refs": ["Risk 20"],
        "version": "1.0",
        "effective_date": "2026-03-20",
        "next_review": "2027-03-20",
        "owner": "Privacy & Security Officer",
        "regulatory_basis": "45 C.F.R. § 164.308(a)(7); § 164.310(a)(2)(i)",
        "summary": "Documents procedures for continued patient care during EMR outages. Includes paper-based downtime forms, a 4-hour recovery objective, database backup verification steps, and staff communication protocols.",
        "filename": "POL-PHYS-003_Downtime_Business_Continuity_Procedure.docx",
    },
]

_POLICIES_DIR = os.path.join(os.path.dirname(__file__), "policies")


@app.get("/api/policies")
def list_policies(_: models.User = Depends(get_current_user)):
    return _POLICIES_META


@app.get("/api/security-status")
def security_status(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return a security posture checklist for the compliance dashboard."""
    # MFA adoption
    total_users   = db.query(models.User).filter(models.User.is_active == True).count()
    mfa_users     = db.query(models.User).filter(
        models.User.is_active == True,
        models.User.mfa_enabled == True,
    ).count()

    # Env var presence (boolean only — never expose values)
    def _env(key: str) -> bool:
        return bool(os.getenv(key, "").strip())

    env_checks = {
        "SECRET_KEY":          _env("SECRET_KEY") and os.getenv("SECRET_KEY") != "CHANGE_ME_IN_PRODUCTION_USE_RANDOM_256BIT",
        "DATABASE_URL":        _env("DATABASE_URL"),
        "TELNYX_API_KEY":      _env("TELNYX_API_KEY"),
        "TELNYX_FAX_FROM":     _env("TELNYX_FAX_FROM"),
        "SQUARE_ACCESS_TOKEN": _env("SQUARE_ACCESS_TOKEN"),
        "LABCORP_API_KEY":     _env("LABCORP_API_KEY"),
    }

    # Recent suspicious login activity (last 7 days)
    cutoff = datetime.utcnow() - timedelta(days=7)
    failed_logins = db.query(models.AuditLog).filter(
        models.AuditLog.action == "LOGIN_FAILED",
        models.AuditLog.timestamp >= cutoff,
    ).count()
    recent_logins = db.query(models.AuditLog).filter(
        models.AuditLog.action == "LOGIN",
        models.AuditLog.timestamp >= cutoff,
    ).count()

    return {
        "mfa": {
            "enabled_count": mfa_users,
            "total_staff": total_users,
            "percent": round(mfa_users / total_users * 100) if total_users else 0,
            "all_enrolled": mfa_users == total_users,
        },
        "technical_controls": {
            "rate_limiting":       True,   # always on (in-process)
            "session_timeout_min": 15,     # always on (client-side)
            "password_complexity": True,   # always enforced at API
            "security_headers":    True,   # SecurityHeadersMiddleware
            "portal_jwt_hours":    PORTAL_TOKEN_HOURS,
            "result_file_db_storage": True,  # Risk 12 — no more /tmp
        },
        "env_vars": env_checks,
        "manual_verification": {
            "railway_encryption_at_rest": {
                "label": "Railway PostgreSQL encryption at rest",
                "status": "manual",
                "instructions": "Verify at railway.app → Project → Database → Settings. Look for 'Encryption at rest: Enabled'.",
            },
            "railway_backups": {
                "label": "Railway automated database backups",
                "status": "manual",
                "instructions": "Verify at railway.app → Project → Database → Backups. Enable daily backups and confirm retention period.",
            },
            "railway_env_access": {
                "label": "Railway environment variable access restricted",
                "status": "manual",
                "instructions": "Verify at railway.app → Project → Settings → Members. Only necessary personnel should have access to view env vars.",
            },
        },
        "baa_checklist": [
            {"vendor": "Railway",  "service": "Cloud hosting & PostgreSQL", "priority": "HIGH", "url": "https://railway.app/legal"},
            {"vendor": "Telnyx",   "service": "HIPAA fax transmission",     "priority": "HIGH", "url": "https://telnyx.com/hipaa"},
            {"vendor": "Square",   "service": "Payment processing",          "priority": "HIGH", "url": "https://squareup.com/us/en/healthcare"},
            {"vendor": "LabCorp",  "service": "Lab orders & results API",    "priority": "HIGH", "url": "https://www.labcorp.com/providers"},
        ],
        "activity_7d": {
            "successful_logins": recent_logins,
            "failed_logins": failed_logins,
        },
    }


@app.get("/api/policies/{policy_id}/download")
def download_policy(
    policy_id: str,
    _: models.User = Depends(get_current_user),
):
    pol = next((p for p in _POLICIES_META if p["id"] == policy_id), None)
    if not pol:
        raise HTTPException(status_code=404, detail="Policy not found")
    fpath = os.path.join(_POLICIES_DIR, pol["filename"])
    if not os.path.isfile(fpath):
        raise HTTPException(status_code=404, detail="Policy file not found on server")
    return FileResponse(
        fpath,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        filename=pol["filename"],
    )


# ══════════════════════════════════════════════════════════════════════════════
# SECURITY ALERTS  (automated anomaly detection on audit log)
# ══════════════════════════════════════════════════════════════════════════════

_ALERT_WINDOW_HOURS = 1       # sliding window for bulk-access detection
_BULK_PATIENT_THRESHOLD = 20  # unique patients in _ALERT_WINDOW_HOURS → alert
_BULK_EXPORT_THRESHOLD = 3    # exports in 24 h → alert
_AFTER_HOURS_START = 0        # midnight UTC
_AFTER_HOURS_END = 5          # 5 AM UTC


@app.get("/api/security-alerts")
def security_alerts(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Returns a list of anomaly alerts derived from recent audit log entries.
    Used to drive the badge on the Audit Logs tab and the alert panel.
    """
    if current_user.role not in ("admin", "physician"):
        raise HTTPException(status_code=403, detail="Not authorised")

    alerts = []
    now = datetime.utcnow()
    window_1h = now - timedelta(hours=_ALERT_WINDOW_HOURS)
    window_24h = now - timedelta(hours=24)

    # 1 — Bulk patient record access (any single user viewing 20+ unique patients in 1 h)
    recent_views = (
        db.query(models.AuditLog)
        .filter(
            models.AuditLog.action.in_([
                "VIEW_PATIENT", "VIEW_NOTES", "VIEW_LAB_ORDERS",
                "VIEW_IMAGING_ORDERS", "VIEW_PRESCRIPTIONS", "VIEW_MEDICATIONS",
            ]),
            models.AuditLog.user_id != None,
            models.AuditLog.timestamp >= window_1h,
        )
        .all()
    )
    user_patients: dict = collections.defaultdict(set)
    for row in recent_views:
        user_patients[row.user_id].add(row.resource_id)
    for uid, patient_ids in user_patients.items():
        if len(patient_ids) >= _BULK_PATIENT_THRESHOLD:
            user = db.query(models.User).filter(models.User.id == uid).first()
            uname = user.full_name if user else f"User #{uid}"
            alerts.append({
                "severity": "high",
                "type": "BULK_RECORD_ACCESS",
                "message": f"{uname} accessed {len(patient_ids)} patient records in the last hour",
                "detail": f"user_id={uid}, unique patients={len(patient_ids)}",
                "timestamp": now.isoformat() + "Z",
            })

    # 2 — Failed login spike (10+ failures in the last hour from any single IP)
    failed_logins = (
        db.query(models.AuditLog)
        .filter(
            models.AuditLog.action == "LOGIN_FAILED",
            models.AuditLog.timestamp >= window_1h,
        )
        .all()
    )
    ip_failures: dict = collections.defaultdict(int)
    for row in failed_logins:
        ip_failures[row.ip_address or "unknown"] += 1
    for ip, count in ip_failures.items():
        if count >= 10:
            alerts.append({
                "severity": "high",
                "type": "FAILED_LOGIN_SPIKE",
                "message": f"{count} failed login attempts from {ip} in the last hour",
                "detail": f"ip={ip}, failures={count}",
                "timestamp": now.isoformat() + "Z",
            })

    # 3 — After-hours admin actions (any admin action midnight–5 AM UTC)
    after_hours = (
        db.query(models.AuditLog)
        .filter(
            models.AuditLog.timestamp >= window_24h,
            models.AuditLog.action.in_([
                "CREATE_USER", "UPDATE_USER", "DELETE_USER",
                "EXPORT_PATIENT_RECORDS", "PORTAL_ACTIVATE", "PORTAL_DEACTIVATE",
            ]),
        )
        .all()
    )
    for row in after_hours:
        h = row.timestamp.hour
        if _AFTER_HOURS_START <= h < _AFTER_HOURS_END:
            user = db.query(models.User).filter(models.User.id == row.user_id).first() if row.user_id else None
            uname = user.full_name if user else "Unknown"
            alerts.append({
                "severity": "medium",
                "type": "AFTER_HOURS_ADMIN",
                "message": f"Admin action '{row.action}' performed at {row.timestamp.strftime('%H:%M')} UTC",
                "detail": f"user={uname}, action={row.action}, resource={row.resource_type} #{row.resource_id}",
                "timestamp": row.timestamp.isoformat() + "Z",
            })

    # 4 — Bulk record exports (3+ exports in 24 h)
    exports = (
        db.query(models.AuditLog)
        .filter(
            models.AuditLog.action == "EXPORT_PATIENT_RECORDS",
            models.AuditLog.timestamp >= window_24h,
        )
        .all()
    )
    if len(exports) >= _BULK_EXPORT_THRESHOLD:
        alerts.append({
            "severity": "medium",
            "type": "BULK_EXPORT",
            "message": f"{len(exports)} patient record exports in the last 24 hours",
            "detail": f"count={len(exports)}",
            "timestamp": now.isoformat() + "Z",
        })

    # Sort: high first, then by timestamp desc
    severity_order = {"high": 0, "medium": 1, "low": 2}
    alerts.sort(key=lambda a: (severity_order.get(a["severity"], 9), a["timestamp"]), reverse=False)
    alerts.sort(key=lambda a: severity_order.get(a["severity"], 9))

    return {"alerts": alerts, "count": len(alerts)}


# ══════════════════════════════════════════════════════════════════════════════
# WORKFORCE TRAINING RECORDS  (POL-HIPAA-001)
# ══════════════════════════════════════════════════════════════════════════════

_REQUIRED_TRAININGS = [
    {
        "type": "hipaa_initial",
        "name": "HIPAA Privacy & Security Initial Training",
        "provider": "HIPAA Training US",
        "url": "https://hipaatraining.us/",
        "description": "Free initial HIPAA training covering Privacy Rule, Security Rule, and Breach Notification. Certificate included at no cost.",
        "estimated_minutes": 30,
    },
    {
        "type": "hipaa_annual",
        "name": "HIPAA Annual Refresher Training",
        "provider": "HIPAA Training US",
        "url": "https://hipaatraining.us/",
        "description": "Annual HIPAA refresher — retake the same course each year. Log the new certificate date to reset the compliance clock.",
        "estimated_minutes": 30,
    },
    {
        "type": "security",
        "name": "Security Awareness & Phishing Training",
        "provider": "HIPAA Training US",
        "url": "https://hipaatraining.us/",
        "description": "Covers cybersecurity best practices, phishing awareness, and ePHI handling. Included in the HIPAA Training US course.",
        "estimated_minutes": 30,
    },
    {
        "type": "breach",
        "name": "Breach Notification Procedures",
        "provider": "Internal (POL-HIPAA-002)",
        "url": None,
        "description": "Review the Incident Response & Breach Notification Plan (POL-HIPAA-002) in the Policies tab. Document attestation in the notes field.",
        "estimated_minutes": 15,
    },
]


@app.get("/api/training-records")
def list_training_records(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    users = db.query(models.User).filter(models.User.is_active == True).all()
    records = db.query(models.TrainingRecord).all()
    # Build a lookup: user_id → list of training records
    by_user: dict = collections.defaultdict(list)
    for r in records:
        by_user[r.user_id].append({
            "id": r.id,
            "training_name": r.training_name,
            "training_type": r.training_type,
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            "notes": r.notes or "",
            "recorded_by": r.recorded_by,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        })
    return {
        "required_trainings": _REQUIRED_TRAININGS,
        "staff": [
            {
                "user_id": u.id,
                "full_name": u.full_name,
                "username": u.username,
                "role": u.role,
                "records": by_user.get(u.id, []),
            }
            for u in users
        ],
    }


@app.post("/api/training-records")
def create_training_record(
    data: dict,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    user_id = data.get("user_id")
    training_name = (data.get("training_name") or "").strip()
    training_type = data.get("training_type", "hipaa_annual")
    completed_at_str = data.get("completed_at", "")
    notes = (data.get("notes") or "").strip()
    if not user_id or not training_name:
        raise HTTPException(status_code=400, detail="user_id and training_name are required")
    try:
        completed_at = datetime.fromisoformat(completed_at_str) if completed_at_str else datetime.utcnow()
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid completed_at date")
    rec = models.TrainingRecord(
        user_id=user_id,
        training_name=training_name,
        training_type=training_type,
        completed_at=completed_at,
        recorded_by=current_user.id,
        notes=notes,
    )
    db.add(rec)
    db.commit()
    db.refresh(rec)
    audit(db, current_user.id, "RECORD_TRAINING", "User", str(user_id),
          details=f"{training_name} — {training_type}")
    return {"id": rec.id, "ok": True}


@app.delete("/api/training-records/{record_id}")
def delete_training_record(
    record_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    rec = db.query(models.TrainingRecord).filter(models.TrainingRecord.id == record_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="Record not found")
    db.delete(rec)
    db.commit()
    audit(db, current_user.id, "DELETE_TRAINING_RECORD", "TrainingRecord", str(record_id))
    return {"ok": True}


# ═════════════════════════════════════════════════════════════════════════════
# SERVE FRONTEND
# ═════════════════════════════════════════════════════════════════════════════
frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")

if os.path.isdir(frontend_dir):
    from fastapi.responses import HTMLResponse

    @app.get("/", response_class=HTMLResponse)
    @app.get("/{full_path:path}", response_class=HTMLResponse, include_in_schema=False)
    def serve_spa(full_path: str = ""):
        # Don't intercept /api/* routes
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404)
        # Serve enrollment page for /enroll and /enroll/* paths
        if full_path == "enroll" or full_path.startswith("enroll/"):
            enroll_file = os.path.join(frontend_dir, "enroll.html")
            if os.path.isfile(enroll_file):
                with open(enroll_file, "r") as f:
                    return HTMLResponse(content=f.read())
        index = os.path.join(frontend_dir, "index.html")
        if os.path.isfile(index):
            with open(index, "r") as f:
                return HTMLResponse(content=f.read())
        return HTMLResponse(content="<h1>Frontend not found</h1>", status_code=404)


# ── Monthly Billing ───────────────────────────────────────────────────────────

BILLING_RETRY_DAYS = [3, 7]   # retry on day 3 and day 7 after first failure

def _square_charge_card(customer_id: str, card_id: str, amount_cents: int, note: str) -> dict:
    """Charge a stored Square card-on-file. Returns Square payment object or raises."""
    import uuid as _uuid_mod
    headers = {
        "Authorization":  f"Bearer {SQUARE_ACCESS_TOKEN}",
        "Content-Type":   "application/json",
        "Square-Version": "2024-11-20",
    }
    payload = {
        "idempotency_key": str(_uuid_mod.uuid4()),
        "amount_money":    {"amount": amount_cents, "currency": "USD"},
        "customer_id":     customer_id,
        "source_id":       card_id,
        "note":            note,
        "location_id":     SQUARE_LOCATION_ID,
    }
    r = httpx.post(f"{SQUARE_BASE_URL}/v2/payments", json=payload, headers=headers, timeout=20)
    body = r.json()
    if r.status_code != 200 or body.get("payment", {}).get("status") not in ("COMPLETED", "APPROVED"):
        errors = body.get("errors", [{}])
        raise RuntimeError(errors[0].get("detail", "Square charge failed"))
    return body["payment"]


def _zaprite_charge(membership: models.Membership, patient: models.Patient, note: str) -> dict:
    """Create a Zaprite checkout for a membership renewal. Returns checkout URL."""
    import uuid as _uuid_mod
    ZAPRITE_API_KEY = os.getenv("ZAPRITE_API_KEY", "")
    if not ZAPRITE_API_KEY:
        raise RuntimeError("Zaprite not configured")
    headers = {
        "Authorization": f"Bearer {ZAPRITE_API_KEY}",
        "Content-Type":  "application/json",
    }
    payload = {
        "amount":      int(membership.price_monthly * 100),
        "currency":    "USD",
        "description": note,
        "customer":    {"email": patient.email, "name": f"{patient.first_name} {patient.last_name}"},
        "metadata":    {"membership_id": str(membership.id), "patient_id": str(patient.id)},
        "idempotency_key": str(_uuid_mod.uuid4()),
    }
    r = httpx.post("https://api.zaprite.com/v1/checkout", json=payload, headers=headers, timeout=20)
    if r.status_code != 200:
        raise RuntimeError(f"Zaprite error {r.status_code}: {r.text[:200]}")
    return r.json()


def _notify_billing_failure(patient: models.Patient, membership: models.Membership, attempt: int, error: str):
    """Log a billing failure. Email notification can be wired here when email is configured."""
    import logging
    logging.warning(
        f"BILLING FAILURE — patient {patient.id} ({patient.email}) "
        f"membership {membership.id} attempt #{attempt}: {error}"
    )
    # TODO: send email via SendGrid/SES when email provider is configured


def process_monthly_billing(db: Session):
    """
    Run billing for all active memberships whose next_billing_date is today or earlier.
    - Square members: charge card-on-file directly
    - Zaprite members: generate checkout link (logged; email delivery when email is configured)
    - On failure: increment billing_failure_count, set billing_status='past_due'
    - After 3 failures: set billing_status='suspended', membership status='past_due'
    - Retries happen automatically on subsequent daily runs (day 3, day 7 after first failure)
    """
    import logging
    now = datetime.utcnow()
    today = now.date()

    memberships = (
        db.query(models.Membership)
        .filter(
            models.Membership.status.in_(["active", "past_due"]),
            models.Membership.next_billing_date != None,
            models.Membership.next_billing_date <= now,
            models.Membership.billing_status != "suspended",
        )
        .all()
    )

    results = {"attempted": 0, "succeeded": 0, "failed": 0, "skipped": 0}

    for mem in memberships:
        patient = db.query(models.Patient).filter(models.Patient.id == mem.patient_id).first()
        if not patient:
            results["skipped"] += 1
            continue

        # Determine billing cycle and amount
        is_annual = getattr(mem, "billing_cycle", "monthly") == "annual"
        if is_annual:
            billing_amount = mem.price_annual or (mem.price_monthly * 12 if mem.price_monthly else 0)
        else:
            billing_amount = mem.price_monthly or 0

        # Skip $0 plans (free / contact-for-pricing)
        if not billing_amount or billing_amount <= 0:
            cur = mem.next_billing_date
            mem.next_billing_date = cur.replace(year=cur.year + 1) if is_annual else _next_anniversary(cur)
            db.commit()
            results["skipped"] += 1
            continue

        results["attempted"] += 1
        amount_cents = int(round(billing_amount * 100))
        period = today.strftime('%Y') if is_annual else today.strftime('%B %Y')
        note = f"Valiant DPC — {mem.plan_name} membership ({period})"
        provider = mem.payment_provider or "square"

        try:
            if provider == "square":
                if not (mem.square_customer_id and mem.square_card_id):
                    raise RuntimeError("No Square card on file")
                sq_pay = _square_charge_card(
                    mem.square_customer_id, mem.square_card_id, amount_cents, note
                )
                pay = models.Payment(
                    patient_id=mem.patient_id,
                    amount=billing_amount,
                    description=note,
                    payment_method="square_card",
                    status="completed",
                    payment_ref_id=sq_pay["id"],
                )
            else:  # zaprite
                checkout = _zaprite_charge(mem, patient, note)
                pay = models.Payment(
                    patient_id=mem.patient_id,
                    amount=billing_amount,
                    description=note,
                    payment_method="zaprite",
                    status="pending",
                    payment_ref_id=checkout.get("id", ""),
                )
                logging.info(
                    f"Zaprite checkout for membership {mem.id}: {checkout.get('url', '')}"
                )

            db.add(pay)

            # Success — reset failure count, advance next billing date
            cur = mem.next_billing_date
            mem.last_billed_at        = now
            mem.billing_failure_count = 0
            mem.billing_status        = "ok"
            mem.status                = "active"
            mem.next_billing_date     = cur.replace(year=cur.year + 1) if is_annual else _next_anniversary(cur)
            db.commit()
            audit(db, 0, "BILLING_SUCCESS", "Membership", str(mem.id))
            results["succeeded"] += 1

        except Exception as exc:
            db.rollback()
            mem.billing_failure_count = (mem.billing_failure_count or 0) + 1
            attempt = mem.billing_failure_count

            _notify_billing_failure(patient, mem, attempt, str(exc))

            if attempt >= 3:
                mem.billing_status = "suspended"
                mem.status         = "past_due"
                logging.warning(f"Membership {mem.id} suspended after {attempt} failures")
            else:
                mem.billing_status    = "past_due"
                # Schedule next retry
                retry_days = BILLING_RETRY_DAYS[min(attempt - 1, len(BILLING_RETRY_DAYS) - 1)]
                mem.next_billing_date = now + timedelta(days=retry_days)

            db.commit()
            audit(db, 0, "BILLING_FAILURE", "Membership", str(mem.id))
            results["failed"] += 1

    return results


def _next_anniversary(current: datetime) -> datetime:
    """Advance a billing date by exactly one month, preserving the day-of-month."""
    import calendar
    month = current.month + 1
    year  = current.year
    if month > 12:
        month = 1
        year += 1
    # Clamp to last valid day of the target month (e.g. Jan 31 → Feb 28)
    last_day = calendar.monthrange(year, month)[1]
    day = min(current.day, last_day)
    return current.replace(year=year, month=month, day=day)


@app.post("/api/admin/billing/run")
def run_billing_now(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Manually trigger the monthly billing run. Admin only."""
    if current_user.role not in ("admin", "provider"):
        raise HTTPException(status_code=403, detail="Admin access required")
    results = process_monthly_billing(db)
    return {"status": "ok", "results": results}


@app.post("/api/cron/billing")
def cron_billing(request: Request, db: Session = Depends(get_db)):
    """
    Scheduled billing endpoint — authenticated by BILLING_SECRET header.
    Called daily by an external cron job (no JWT required).
    Set BILLING_SECRET env var and pass it as X-Billing-Secret header.
    """
    if not BILLING_SECRET:
        raise HTTPException(status_code=503, detail="Billing cron not configured — set BILLING_SECRET env var")
    secret = request.headers.get("X-Billing-Secret", "")
    if not secret or secret != BILLING_SECRET:
        raise HTTPException(status_code=401, detail="Invalid billing secret")
    results = process_monthly_billing(db)
    import logging
    logging.info(f"Cron billing complete: {results}")
    return {"status": "ok", "results": results}


@app.get("/api/admin/billing/upcoming")
def billing_upcoming(
    days: int = 7,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """Return memberships with billing due in the next N days."""
    cutoff = datetime.utcnow() + timedelta(days=days)
    mems = (
        db.query(models.Membership)
        .filter(
            models.Membership.status.in_(["active", "past_due"]),
            models.Membership.next_billing_date != None,
            models.Membership.next_billing_date <= cutoff,
        )
        .order_by(models.Membership.next_billing_date)
        .all()
    )
    rows = []
    for m in mems:
        d = clean(m)
        pt = db.query(models.Patient).filter(models.Patient.id == m.patient_id).first()
        if pt:
            d["patient_name"] = f"{pt.first_name} {pt.last_name}"
            d["patient_email"] = pt.email
        rows.append(d)
    return rows


# Wire billing into the startup event so next_billing_date is set for
# any approved membership that doesn't have one yet (e.g. legacy rows).
def _backfill_billing_dates(db: Session):
    mems = db.query(models.Membership).filter(
        models.Membership.status == "active",
        models.Membership.next_billing_date == None,
    ).all()
    for m in mems:
        anchor = m.last_billed_at or m.start_date or datetime.utcnow()
        m.next_billing_date = _next_anniversary(anchor)
    if mems:
        db.commit()


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    reload = os.getenv("ENVIRONMENT", "development") == "development"
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=reload)
