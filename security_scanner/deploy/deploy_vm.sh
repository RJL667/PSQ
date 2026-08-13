#!/usr/bin/env bash
# Phishield CyberRisk Scanner — VM deploy (idempotent).
#
# Provisions a DEDICATED Postgres container + Python venv + systemd service for the
# scanner on an Ubuntu VM. Safe to re-run: it preserves .env, secrets.env, and the
# Postgres volume, and never touches anything else on the box (e.g. the Veilguard stack).
#
# SOURCE OF TRUTH = brafter (origin) master.
#   The VM is TARBALL-deployed: /opt/phishield-scanner is NOT a git checkout and does
#   NOT pull from GitHub. So "the VM is sourced from brafter" is a CONVENTION, not infra:
#     1. land changes on local `master`, then push to brafter FIRST, then RJL:
#          git push                  # -> brafter (origin/master), which is master's upstream
#          git push rjl667 master    # -> RJL (secondary mirror)
#     2. build the deploy tarball FROM local `master` (== brafter origin/master) so what
#        ships to the VM is EXACTLY what is on brafter. Never deploy an unpushed or
#        feature branch — that would put code on the VM that is not on brafter.
#
# Usage (from the repo root, on `master`, AFTER the two pushes above):
#   tar -czf /tmp/scanner_deploy.tar.gz --exclude=.git --exclude='*/node_modules' \
#       --exclude='*/__pycache__' --exclude='*.pyc' --exclude=scans.db --exclude=.env \
#       -C <repo-root> security_scanner
#   gcloud compute scp /tmp/scanner_deploy.tar.gz security_scanner/deploy/deploy_vm.sh \
#       <vm>:/tmp/ --zone=<zone>
#   # CRLF-normalise the script (Windows checkout) on the VM, then run it:
#   gcloud compute ssh <vm> --zone=<zone> \
#       --command="tr -d '\r' < /tmp/deploy_vm.sh > /tmp/deploy_vm_unix.sh; bash /tmp/deploy_vm_unix.sh"
#   # Verify VM == brafter by sha256 (tar preserves mtimes, so do NOT trust mtime):
#   #   sha256sum /opt/phishield-scanner/security_scanner/scanner.py  (compare to local `master`)
#
# See security_scanner/docs/DEPLOYMENT.md for the full runbook (if present).
set -euo pipefail

# --- knobs (override via env) ------------------------------------------------
APP_ROOT=${APP_ROOT:-/opt/phishield-scanner}
PORT=${PORT:-8001}
PG_PORT=${PG_PORT:-5544}
PG_DB=${PG_DB:-phishield_scanner}
PG_USER=${PG_USER:-phishield}
PG_CONTAINER=${PG_CONTAINER:-phishield-scanner-pg}
PG_VOLUME=${PG_VOLUME:-phishield_scanner_pgdata}
TARBALL=${TARBALL:-/tmp/scanner_deploy.tar.gz}
# -----------------------------------------------------------------------------
APP_DIR="$APP_ROOT/security_scanner"

echo "== [1/7] unpack code to $APP_ROOT =="
sudo mkdir -p "$APP_ROOT"; sudo chown "$USER:$USER" "$APP_ROOT"
# Server-owned secrets must NEVER arrive from the tarball. The documented build
# command excludes them, but that is a convention a hand-rolled `tar -czf ...
# security_scanner/` silently breaks -- and did, on 2026-07-27: a developer .env
# rode along and replaced the VM's, taking a VM-only GOOGLE_API_KEY with it. The
# running process kept serving from memory, so nothing looked wrong until the
# next restart. Excluding at EXTRACT time makes the mistake unrepresentable,
# whoever builds the tarball and however carelessly.
if tar -tzf "$TARBALL" | grep -qE '(^|/)security_scanner/(\.env|secrets\.env)'; then
  echo "   !! WARNING: tarball contains a .env / secrets.env -- IGNORING it."
  echo "   !! Rebuild with --exclude=.env (see the Usage header) to silence this."
fi
# Server-owned RUNTIME state, excluded for the same reason as .env: it is written
# by the running app and a dev machine's copy must never replace it. gitignore
# does NOT protect a tarball -- a local test run recreates the file and `tar`
# happily includes it -- so the guarantee has to live here, at extract time.
#   scans/_objstore        generated PDFs + one-time export blobs
#   _dehashed_balance_history.jsonl  append-only credit-spend log; a tarball copy
#                          would overwrite the server's real history
#   _dehashed_balance.json cached credit balance; a stale copy would rewind the
#                          displayed count and trigger a needless paid refresh
tar -xzf "$TARBALL" -C "$APP_ROOT" \
    --exclude='security_scanner/.env' \
    --exclude='security_scanner/.env.*' \
    --exclude='security_scanner/secrets.env' \
    --exclude='security_scanner/scans/_dehashed_balance.json' \
    --exclude='security_scanner/scans/_dehashed_balance_history.jsonl' \
    --exclude='security_scanner/scans/_objstore' \
    --exclude='security_scanner/scans/_objstore/*'   # -> $APP_ROOT/security_scanner
echo "   code at $APP_DIR"

echo "== [2/7] secrets (generate once, reuse after) =="
if [ ! -f "$APP_ROOT/secrets.env" ]; then
  printf 'PG_PW=%s\nSECRET_KEY=%s\n' "$(openssl rand -hex 24)" "$(openssl rand -hex 32)" \
    > "$APP_ROOT/secrets.env"
  chmod 600 "$APP_ROOT/secrets.env"
  echo "   generated new secrets.env"
else
  echo "   reusing existing secrets.env"
fi
# shellcheck disable=SC1091
source "$APP_ROOT/secrets.env"

echo "== [3/7] dedicated Postgres container =="
if ! sudo docker ps -a --format '{{.Names}}' | grep -qx "$PG_CONTAINER"; then
  sudo docker run -d --name "$PG_CONTAINER" --restart unless-stopped \
    -e POSTGRES_USER="$PG_USER" -e POSTGRES_PASSWORD="$PG_PW" -e POSTGRES_DB="$PG_DB" \
    -v "$PG_VOLUME":/var/lib/postgresql/data -p 127.0.0.1:"$PG_PORT":5432 \
    postgres:16-alpine
  echo "   created $PG_CONTAINER on 127.0.0.1:$PG_PORT"
else
  sudo docker start "$PG_CONTAINER" >/dev/null 2>&1 || true
  echo "   $PG_CONTAINER already present"
fi
echo "   waiting for postgres..."
for i in $(seq 1 30); do
  sudo docker exec "$PG_CONTAINER" pg_isready -U "$PG_USER" -d "$PG_DB" >/dev/null 2>&1 \
    && { echo "   postgres ready"; break; }
  sleep 2; [ "$i" = 30 ] && { echo "   ERROR: postgres not ready"; exit 1; }
done

echo "== [4/7] .env (preserve if present; scaffold placeholder on first run) =="
if [ ! -f "$APP_DIR/.env" ]; then
  cat > "$APP_DIR/.env" <<ENVEOF
# Phishield CyberRisk Scanner — production env. FILL IN API KEYS (all optional; the
# scanner runs without them at reduced coverage). See .env example in the repo root docs.
VIRUSTOTAL_API_KEY=
SECURITYTRAILS_API_KEY=
SHODAN_API_KEY=
HIBP_API_KEY=
DEHASHED_EMAIL=
DEHASHED_API_KEY=
PORT=$PORT
DB_PATH=scans.db
MAX_CONCURRENT_SCANS=5
SECRET_KEY=$SECRET_KEY
DATABASE_URL=postgresql://$PG_USER:$PG_PW@localhost:$PG_PORT/$PG_DB
ENVEOF
  chmod 600 "$APP_DIR/.env"
  echo "   scaffolded $APP_DIR/.env  >>> FILL IN API KEYS <<<"
else
  echo "   preserving existing $APP_DIR/.env"
fi

echo "== [5/7] python venv + deps =="
cd "$APP_DIR"
[ -d .venv ] || python3 -m venv .venv
./.venv/bin/pip install --quiet --upgrade pip
echo "   installing requirements..."
./.venv/bin/pip install --quiet -r requirements.txt
# age binary for credential_export (optional feature)
mkdir -p bin
if [ ! -x bin/age ]; then
  curl -sSL https://github.com/FiloSottile/age/releases/download/v1.2.1/age-v1.2.1-linux-amd64.tar.gz \
    | tar -xz -C /tmp && cp /tmp/age/age bin/age && chmod +x bin/age && echo "   installed age"
fi

echo "== [6/7] apply DB migrations (idempotent) =="
set -a; source "$APP_DIR/.env"; set +a
./.venv/bin/python -c "import scanner_db; scanner_db.init_schema(); print('   migrations: ok')"

echo "== [7/7] systemd service =="
sudo tee /etc/systemd/system/phishield-scanner.service >/dev/null <<UNITEOF
[Unit]
Description=Phishield CyberRisk Scanner (Flask/gunicorn)
After=network.target docker.service
Wants=docker.service

[Service]
Type=simple
User=$USER
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/.venv/bin/gunicorn app:app --bind 127.0.0.1:$PORT --workers 1 --threads 16 --timeout 1200
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNITEOF
sudo systemctl daemon-reload
sudo systemctl enable phishield-scanner >/dev/null 2>&1 || true
sudo systemctl restart phishield-scanner
sleep 4
echo "   service: $(systemctl is-active phishield-scanner)"

echo "== health check =="
sleep 2
curl -fsS "http://127.0.0.1:$PORT/health" -o /dev/null -w "   /health -> HTTP %{http_code}\n" \
  || echo "   /health probe failed — check: sudo journalctl -u phishield-scanner -n 50"

# The probe above uses the SAME $PORT this script just baked into the unit, so it
# proves self-consistency, not reachability. On 2026-07-27 a stray PORT=5001 (a
# dev value, from a .env that should never have reached the VM) rebound gunicorn
# to 5001; this probe cheerfully passed against 5001 while Caddy kept proxying
# 8001 and the public scanner 502'd for nine minutes. So also verify the URL a
# broker actually hits. Set PUBLIC_HEALTH_URL='' to skip (e.g. first-run boxes
# with no DNS/edge yet).
PUBLIC_HEALTH_URL=${PUBLIC_HEALTH_URL-https://veilguard.phishield.com/scanner/health}
if [ -n "$PUBLIC_HEALTH_URL" ]; then
  echo "== public reachability =="
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 25 "$PUBLIC_HEALTH_URL" || echo 000)
  if [ "$code" = "200" ]; then
    echo "   $PUBLIC_HEALTH_URL -> HTTP 200"
  else
    echo "   !! PUBLIC ENDPOINT NOT SERVING: $PUBLIC_HEALTH_URL -> HTTP $code"
    echo "   !! gunicorn is bound to :$PORT (from PORT in $APP_DIR/.env)."
    echo "   !! If Caddy proxies a different port, the site is DOWN despite the"
    echo "   !! local probe passing. Check PORT in .env, then: sudo systemctl cat"
    echo "   !! phishield-scanner | grep -- --bind"
    exit 1
  fi
fi
echo "DONE.  Caddy edge is wired separately (see deploy/caddy_patch.py / docs/DEPLOYMENT.md)."
