#!/usr/bin/env python3
"""
Railway startup wrapper.
Runs DB setup as a subprocess (with timeout), then exec's into uvicorn.
Using os.execvp means uvicorn becomes PID 1's direct child with no
shell layer between them — Railway sees it as the main process.
"""
import os
import subprocess
import sys

print("=== MedFlow EMR starting up ===", flush=True)

# ── 1. DB setup ────────────────────────────────────────────────────────────
print("=== Running setup.py (timeout 30s) ===", flush=True)
try:
    result = subprocess.run(
        [sys.executable, "-u", "setup.py"],
        timeout=30,          # kill if SQLAlchemy hangs
        capture_output=False # let stdout/stderr pass through to Railway logs
    )
    print(f"=== setup.py exited with code {result.returncode} ===", flush=True)
except subprocess.TimeoutExpired:
    print("=== setup.py timed out after 30s — continuing to uvicorn ===", flush=True)
except Exception as exc:
    print(f"=== setup.py error: {exc} — continuing to uvicorn ===", flush=True)

# ── 2. Start uvicorn (replaces this process — no extra shell layer) ────────
port = int(os.getenv("PORT", "8000"))
print(f"=== Handing off to uvicorn on port {port} ===", flush=True)
sys.stdout.flush()

os.execvp(sys.executable, [
    sys.executable, "-m", "uvicorn", "main:app",
    "--host", "0.0.0.0",
    "--port", str(port),
    "--log-level", "info",
])
