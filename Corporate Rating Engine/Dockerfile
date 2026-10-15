# corp-rating — Corporate Rating Engine (Flask backend + static web app).
# Serves the rating UI + /api/* (ingest, map, quotes). The /api/map Claude path
# runs through the veilguard pii-proxy (redact -> Claude -> rehydrate), so this
# container holds NO Anthropic key and no raw assessment text leaves the VM
# un-redacted. Sibling of the SME Rating Engine backend.
FROM python:3.12-slim

WORKDIR /app

# PyMuPDF / python-docx / openpyxl ship manylinux wheels — no apt build deps needed.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5003
# app:app is the module-level Flask app; init_db() runs on import (the `else` branch).
# --timeout 180: /api/map runs a redact -> Claude -> scorecard round-trip via the proxy.
CMD ["gunicorn", "--bind", "0.0.0.0:5003", "--workers", "2", "--timeout", "180", "app:app"]
