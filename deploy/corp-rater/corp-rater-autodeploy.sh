#!/usr/bin/env bash
# corp-rater-autodeploy: deploy an APPROVED commit of the corporate rater to the live server.
#
# Runs every 5 minutes from corp-rater-autodeploy.timer. It deploys only when:
#   - the newest successful run of the "Corporate rater" GitHub workflow on master is newer than
#     the one last deployed, and
#   - that run carries an "approved" review for the corp-rater-production environment from an
#     allowed reviewer (so a missing or unprotected environment can never deploy on its own).
# Then it backs up the app, copies the rater folder from that exact commit, installs Python
# dependencies if requirements.txt changed, restarts the service and health-checks it.
# A failed health check restores the backup and restarts again.
#
# Installed at /usr/local/sbin/corp-rater-autodeploy. Log: journalctl -u corp-rater-autodeploy
# Status: /var/lib/corp-rater-deploy/status   Manual run: sudo systemctl start corp-rater-autodeploy
set -euo pipefail

REPO="brafter12345-cmyk/PSQ"
WORKFLOW="corp-rater.yml"
ENVIRONMENT="corp-rater-production"
APPROVERS="brafter12345-cmyk"          # space-separated GitHub logins allowed to approve
SUBDIR="Corporate Rating Engine"
APP="/opt/corp-rating/app"
VENV="/opt/corp-rating/venv"
SERVICE="corp-rating.service"
HEALTH="http://127.0.0.1:8003/"
STATE="/var/lib/corp-rater-deploy"
BACKUPS="/root/backups/corp-rating"
KEEP_BACKUPS=20

mkdir -p "$STATE" "$BACKUPS"
exec 9>"$STATE/lock"
flock -n 9 || exit 0

log() { echo "$*"; echo "$(date -u +%FT%TZ) $*" >> "$STATE/history.log"; }
status() { echo "$(date -u +%FT%TZ) $*" > "$STATE/status"; }
api() { curl -fsS --max-time 30 -H "Accept: application/vnd.github+json" "https://api.github.com/repos/$REPO/$1"; }

last_run=$(cat "$STATE/deployed_run" 2>/dev/null || echo 0)
failed_run=$(cat "$STATE/failed_run" 2>/dev/null || echo 0)

# Newest successful run on master.
runs_json=$(api "actions/workflows/$WORKFLOW/runs?branch=master&status=success&per_page=1" 2>/dev/null || echo '{}')
read -r run_id sha < <(printf '%s' "$runs_json" | python3 -c '
import sys, json
try:
    r = json.load(sys.stdin).get("workflow_runs") or []
except Exception:
    r = []
print(r[0]["id"], r[0]["head_sha"]) if r else print(0, "-")') || { run_id=0; sha=-; }

if [ "$run_id" = 0 ] || [ "$run_id" -le "$last_run" ] || [ "$run_id" = "$failed_run" ]; then
  exit 0
fi

# The run must carry an approval from an allowed reviewer for the production environment.
approver=$( (api "actions/runs/$run_id/approvals" 2>/dev/null || echo '[]') | APPROVERS="$APPROVERS" ENVIRONMENT="$ENVIRONMENT" python3 -c '
import sys, json, os
allowed = os.environ["APPROVERS"].split()
env = os.environ["ENVIRONMENT"]
for a in json.load(sys.stdin):
    envs = [e.get("name") for e in a.get("environments", [])]
    login = (a.get("user") or {}).get("login")
    if a.get("state") == "approved" and env in envs and login in allowed:
        print(login); break
')
if [ -z "$approver" ]; then
  log "SKIP run $run_id (${sha:0:7}): succeeded without an approval from $APPROVERS. Not deployed."
  status "skipped ${sha:0:7}: no approval on run $run_id"
  echo "$run_id" > "$STATE/failed_run"
  exit 0
fi

log "DEPLOY run $run_id commit ${sha:0:7}, approved by $approver"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL --max-time 120 "https://codeload.github.com/$REPO/tar.gz/$sha" -o "$tmp/src.tgz"
tar xzf "$tmp/src.tgz" -C "$tmp"
src=$(find "$tmp" -mindepth 2 -maxdepth 2 -type d -name "$SUBDIR" | head -1)
if [ -z "$src" ] || [ ! -f "$src/app.py" ] || [ ! -f "$src/corporate-engine.js" ]; then
  log "FAIL ${sha:0:7}: rater folder not found in the commit. Nothing changed."
  status "failed ${sha:0:7}: source incomplete"
  echo "$run_id" > "$STATE/failed_run"
  exit 1
fi

ts=$(date -u +%Y%m%dT%H%M%SZ)
backup="$BACKUPS/app-$ts-before-${sha:0:7}.tgz"
tar czf "$backup" --exclude=app/quote_pdfs --exclude=app/ingest_uploads --exclude=app/__pycache__ \
  -C /opt/corp-rating app
log "backup $backup"

req_changed=0
cmp -s "$src/requirements.txt" "$APP/requirements.txt" || req_changed=1

rollback() {
  log "ROLLBACK ${sha:0:7}: $1. Restoring $backup"
  tar xzf "$backup" -C /opt/corp-rating
  [ "$req_changed" = 1 ] && "$VENV/bin/pip" install -q -r "$APP/requirements.txt" || true
  systemctl restart "$SERVICE"
  status "rolled back ${sha:0:7}: $1 (backup $backup)"
  echo "$run_id" > "$STATE/failed_run"
  exit 1
}

# Copy the tracked rater files; runtime folders stay untouched.
(cd "$src" && find . -type f ! -path "./quote_pdfs/*" ! -path "./ingest_uploads/*" \
   ! -path "*/__pycache__/*" ! -path "./.pytest_cache/*" -print0) > "$tmp/files"
(cd "$src" && tar cf - --null -T "$tmp/files") | tar xf - -C "$APP" --no-same-owner
(cd "$APP" && xargs -0 chown root:corprating < "$tmp/files" && xargs -0 chmod 644 < "$tmp/files")
find "$APP" -mindepth 1 -maxdepth 1 -type d ! -name quote_pdfs ! -name ingest_uploads \
  -exec chown root:corprating {} + -exec chmod 755 {} +

if [ "$req_changed" = 1 ]; then
  log "requirements.txt changed, installing into the venv"
  "$VENV/bin/pip" install -q -r "$APP/requirements.txt" || rollback "pip install failed"
fi

systemctl restart "$SERVICE"
ok=0
for i in 1 2 3 4 5 6; do
  sleep 5
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$HEALTH" || true)
  if systemctl is-active --quiet "$SERVICE" && [ "$code" = 200 ]; then ok=1; break; fi
done
[ "$ok" = 1 ] || rollback "health check failed (http $code)"

echo "$run_id" > "$STATE/deployed_run"
echo "$sha" > "$STATE/deployed_sha"
log "LIVE ${sha:0:7} (run $run_id, approved by $approver)"
status "live ${sha:0:7} (run $run_id, approved by $approver, backup $backup)"

# Keep the newest backups only.
ls -1t "$BACKUPS"/app-*.tgz 2>/dev/null | tail -n +$((KEEP_BACKUPS + 1)) | xargs -r rm -f
