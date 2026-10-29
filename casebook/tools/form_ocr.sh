#!/usr/bin/env bash
# Read a proposal / risk form through the live Corporate Rating Engine ingest (text layer + parallel
# page OCR via the stack's audited /v1/ocr shim). One call per form instead of reading pages by hand.
# Usage: bash casebook/tools/form_ocr.sh <form.pdf|.png|.jpg|.docx|.xlsx> [out.json]
# Prints pages, OCR seconds, unread pages and notes; full result (text, blocks) goes to out.json.
set -euo pipefail
cd /work
SRC="$1"
OUT="${2:-${SRC%.*}.ingest.json}"
SSH="bash .secrets/ssh/prod.sh"
ID=$(date +%s%N)
NAME=$(basename "$SRC" | tr -c 'A-Za-z0-9._\n-' '_')
TMP="/tmp/fo_${ID}_${NAME}"
cat "$SRC" | $SSH "cat > $TMP"
T0=$(date +%s.%N)
$SSH "curl -s -m 300 -H 'x-user-id: ${OCR_USER_ID:-$(cat .secrets/casebook_ocr_user)}' -F 'file=@$TMP;filename=$NAME' http://127.0.0.1:8003/api/ingest; rm -f $TMP" > "$OUT"
T1=$(date +%s.%N)
python3 - "$OUT" "$T0" "$T1" <<'EOF'
import json, sys
r = json.load(open(sys.argv[1]))
wall = float(sys.argv[3]) - float(sys.argv[2])
print("ok=%s pages=%s chars=%s ocr_read=%s unread=%s ocr_s=%s wall_s=%.1f" % (
    r.get("ok"), r.get("pages"), r.get("chars"), len(r.get("ocr_read_pages") or []),
    r.get("ocr_pages"), r.get("ocr_seconds", "n/a"), wall))
for n in (r.get("notes") or [])[:4]:
    print(" -", n[:200])
if r.get("error"):
    print("error:", r["error"])
EOF
echo "saved $OUT"
