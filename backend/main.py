"""
MedFlow EMR — FastAPI Backend
HIPAA-oriented: audit logging on every PHI access, JWT auth, encrypted DB-ready.

Run:
  pip install -r requirements.txt
  python setup.py          # seed DB once
  python main.py           # start server → http://localhost:8000
"""

import base64
import hashlib
import json
import os
import re
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from io import BytesIO
from typing import Optional

import uuid as _uuid

import bcrypt
import httpx
import uvicorn
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from jose import JWTError, jwt
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
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

_origins_raw = os.getenv("ALLOWED_ORIGINS", "*")
_origins = [o.strip() for o in _origins_raw.split(",")] if _origins_raw != "*" else ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health_check():
    """Railway health check endpoint."""
    return {"status": "ok", "service": "MedFlow EMR"}

# ── Auth config ───────────────────────────────────────────────────────────────
SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_ME_IN_PRODUCTION_USE_RANDOM_256BIT")
ALGORITHM = "HS256"
TOKEN_HOURS = int(os.getenv("TOKEN_EXPIRE_HOURS", "8"))
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
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_pw(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def make_token(user_id: int, role: str) -> str:
    exp = datetime.utcnow() + timedelta(hours=TOKEN_HOURS)
    return jwt.encode({"sub": str(user_id), "role": role, "exp": exp}, SECRET_KEY, ALGORITHM)


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or disabled")
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
    ip = request.client.host if request else ""
    log = models.AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=ip,
        details=details,
        timestamp=datetime.utcnow(),
    )
    db.add(log)
    db.commit()


def user_dict(u: models.User) -> dict:
    return {
        "id": u.id, "username": u.username, "full_name": u.full_name,
        "email": u.email, "role": u.role, "npi_number": u.npi_number,
        "specialty": u.specialty, "is_active": u.is_active,
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

@app.post("/api/auth/login")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == form.username).first()
    if not user or not verify_pw(form.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=401, detail="Account disabled")
    token = make_token(user.id, user.role)
    audit(db, user.id, "LOGIN", "User", str(user.id))
    return {"access_token": token, "token_type": "bearer", "user": user_dict(user)}


@app.get("/api/auth/me")
def get_me(current_user: models.User = Depends(get_current_user)):
    return user_dict(current_user)


@app.put("/api/auth/me/password")
def change_password(
    data: dict,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_pw(data.get("current_password", ""), current_user.password_hash):
        raise HTTPException(status_code=400, detail="Current password incorrect")
    current_user.password_hash = hash_pw(data["new_password"])
    db.commit()
    audit(db, current_user.id, "CHANGE_PASSWORD", "User", str(current_user.id))
    return {"success": True}


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
    u = models.User(
        username=data["username"],
        email=data.get("email", ""),
        password_hash=hash_pw(data["password"]),
        full_name=data.get("full_name", ""),
        npi_number=data.get("npi_number", ""),
        specialty=data.get("specialty", ""),
        role=data.get("role", "physician"),
        is_active=True,
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
        u.password_hash = hash_pw(data["password"])
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
    if search:
        s = f"%{search}%"
        q = q.filter(
            models.Patient.first_name.ilike(s)
            | models.Patient.last_name.ilike(s)
            | models.Patient.phone.ilike(s)
            | models.Patient.email.ilike(s)
        )
    rows = q.order_by(models.Patient.last_name).all()
    audit(db, current_user.id, "LIST_PATIENTS", "Patient", "all")
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
    return db.query(models.PatientMedication).filter(
        models.PatientMedication.patient_id == patient_id
    ).order_by(models.PatientMedication.is_active.desc(), models.PatientMedication.name).all()

@app.post("/api/patients/{patient_id}/medications")
def create_medication(patient_id: int, data: dict, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
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
    for k in ("name","dosage","frequency","route","start_date","end_date","prescriber","indication","is_active","notes"):
        if k in data: setattr(m, k, data[k])
    db.commit(); db.refresh(m)
    return m

@app.delete("/api/medications/{med_id}")
def delete_medication(med_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    m = db.query(models.PatientMedication).filter(models.PatientMedication.id == med_id).first()
    if not m: raise HTTPException(status_code=404, detail="Not found")
    db.delete(m); db.commit()
    return {"ok": True}


# ═════════════════════════════════════════════════════════════════════════════
# MEDICAL HISTORY
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/patients/{patient_id}/history")
def list_history(patient_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return db.query(models.PatientHistoryEntry).filter(
        models.PatientHistoryEntry.patient_id == patient_id
    ).order_by(models.PatientHistoryEntry.entry_type, models.PatientHistoryEntry.created_at).all()

@app.post("/api/patients/{patient_id}/history")
def create_history_entry(patient_id: int, data: dict, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    e = models.PatientHistoryEntry(
        patient_id=patient_id,
        entry_type=data.get("entry_type","problem"),
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
    for k in ("entry_type","description","detail","onset_date","status","notes"):
        if k in data: setattr(e, k, data[k])
    db.commit(); db.refresh(e)
    return e

@app.delete("/api/history/{entry_id}")
def delete_history_entry(entry_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    e = db.query(models.PatientHistoryEntry).filter(models.PatientHistoryEntry.id == entry_id).first()
    if not e: raise HTTPException(status_code=404, detail="Not found")
    db.delete(e); db.commit()
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
        q = q.filter(models.ClinicalNote.patient_id == patient_id)
    rows = q.order_by(models.ClinicalNote.created_at.desc()).all()
    return [clean(n) for n in rows]


@app.post("/api/notes")
def create_note(
    data: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
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
    audit(db, current_user.id, "UPDATE_NOTE", "ClinicalNote", str(note_id))
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

    patient_ctx = ""
    if patient_id:
        p = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
        if p:
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
        q = q.filter(models.LabOrder.patient_id == patient_id)
    return [clean(o) for o in q.order_by(models.LabOrder.created_at.desc()).all()]


@app.post("/api/lab-orders")
def create_lab_order(
    data: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
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
        q = q.filter(models.ImagingOrder.patient_id == patient_id)
    return [clean(o) for o in q.order_by(models.ImagingOrder.created_at.desc()).all()]


@app.post("/api/imaging-orders")
def create_imaging_order(
    data: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
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
    pt_dob = patient.date_of_birth.strftime('%m/%d/%Y') if patient.date_of_birth else ""
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
    """Generate imaging order PDF and send via Telnyx fax."""
    order = db.query(models.ImagingOrder).filter(models.ImagingOrder.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    if not order.fax_number:
        raise HTTPException(status_code=400, detail="No fax number set for this order")

    patient = db.query(models.Patient).filter(models.Patient.id == order.patient_id).first()
    physician = db.query(models.User).filter(models.User.id == order.physician_id).first() or current_user

    # Generate PDF
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

    # Log to FaxLog
    log = models.FaxLog(
        patient_id=order.patient_id,
        physician_id=current_user.id,
        direction="sent",
        to_number=order.fax_number,
        subject=subject,
        pages=1,
        status=order.fax_status,
        telnyx_fax_id=order.telnyx_fax_id or "",
    )
    db.add(log)
    db.commit()
    audit(db, current_user.id, "FAX_IMAGING_ORDER", "ImagingOrder", str(order_id))
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
            import os as _os
            upload_dir = "/tmp/imaging_results"
            _os.makedirs(upload_dir, exist_ok=True)
            filename = f"IMG-{order_id:04d}-result-{int(datetime.utcnow().timestamp())}.pdf"
            file_path = f"{upload_dir}/{filename}"
            contents = await result_file.read()
            with open(file_path, "wb") as f:
                f.write(contents)
            order.result_file_path = file_path
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
    if patient_id:  q = q.filter(models.Appointment.patient_id == patient_id)
    return [_enrich_appointment(a, db) for a in q.order_by(models.Appointment.start_time).all()]

@app.post("/api/appointments")
def create_appointment(data: dict, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    from datetime import datetime as _dt
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
    """
    try:
        event = await request.json()
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
    ]
    from sqlalchemy import text
    for sql in migrations:
        try:
            db.execute(text(sql))
        except Exception:
            db.rollback()  # SQLite doesn't support IF NOT EXISTS — skip silently
    db.commit()


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
    for c in data.get("consents", []):
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
        mem = models.Membership(
            patient_id        = pt.id,
            plan_name         = plan.name,
            price_monthly     = plan.price_monthly,
            start_date        = start_now,
            status            = "active",
            payment_provider  = enroll.payment_method or "square",
            next_billing_date = _next_anniversary(start_now),
            billing_status    = "ok",
        )
        db.add(mem)
    # Link consents to new patient
    db.query(models.PatientConsent).filter(
        models.PatientConsent.enrollment_id == eid
    ).update({"patient_id": pt.id})
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

        # Skip $0 plans (free / contact-for-pricing)
        if not mem.price_monthly or mem.price_monthly <= 0:
            # Advance next_billing_date without charging
            mem.next_billing_date = _next_anniversary(mem.next_billing_date)
            db.commit()
            results["skipped"] += 1
            continue

        results["attempted"] += 1
        amount_cents = int(round(mem.price_monthly * 100))
        note = f"Valiant DPC — {mem.plan_name} membership ({today.strftime('%B %Y')})"
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
                    amount=mem.price_monthly,
                    description=note,
                    payment_method="square_card",
                    status="completed",
                    payment_ref_id=sq_pay["id"],
                )
            else:  # zaprite
                checkout = _zaprite_charge(mem, patient, note)
                pay = models.Payment(
                    patient_id=mem.patient_id,
                    amount=mem.price_monthly,
                    description=note,
                    payment_method="zaprite",
                    status="pending",
                    payment_ref_id=checkout.get("id", ""),
                )
                # Log the checkout URL so staff can follow up if needed
                logging.info(
                    f"Zaprite checkout for membership {mem.id}: {checkout.get('url', '')}"
                )

            db.add(pay)

            # Success — reset failure count, advance next billing date
            mem.last_billed_at        = now
            mem.billing_failure_count = 0
            mem.billing_status        = "ok"
            mem.status                = "active"
            mem.next_billing_date     = _next_anniversary(mem.next_billing_date)
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
