#!/usr/bin/env bash
# DEV/DEMO ONLY: Bring up full stack (ipremember + Authelia + Nginx + whoami),
# run gofmt/tests, build images, log into Authelia, and exercise the protected route.
# Not for production use.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

log() { echo "TEST: $*"; }

ENV_FILE="$ROOT/.env"
CERT_SCRIPT="$ROOT/scripts/gen-selfsigned.sh"
COOKIE_JAR=$(mktemp)
if [ ! -f "$ENV_FILE" ]; then
  echo "Missing .env; run scripts/dev-stack.sh first to generate one."
  exit 1
fi
SHARED_SECRET_VALUE=$(grep '^SHARED_SECRET=' "$ENV_FILE" | head -n1 | cut -d= -f2-)
if [ -z "$SHARED_SECRET_VALUE" ]; then
  echo "Missing SHARED_SECRET in .env"
  exit 1
fi

log "Generating self-signed cert if needed"
"$CERT_SCRIPT"

# Run gofmt/tests in a Go container (keeps host clean).
log "Running gofmt + tests..."
docker run --rm -v "$ROOT":/src -w /src golang:1.22-alpine sh -c "apk add --no-cache git curl >/dev/null && gofmt -w main.go main_test.go && go test ./..."

log "Stopping any existing stack..."
docker compose -f docker-compose.authelia.yml down --remove-orphans >/dev/null 2>&1 || true

log "Building and starting full stack..."
docker compose -f docker-compose.authelia.yml up -d --build

log "Waiting for services..."
wait_for() {
  local url="$1"
  local resolve="${2:-}"
  local retries=30
  until curl -k -s -o /dev/null $resolve "$url"; do
    retries=$((retries-1))
    if [ "$retries" -le 0 ]; then
      echo "Service not ready: $url"
      exit 1
    fi
    sleep 1
  done
}
wait_for "http://localhost:8080/healthz"
wait_for "https://auth.localtest.me:9091/api/health" "--resolve auth.localtest.me:9091:127.0.0.1"
wait_for "https://app.localtest.me:8443/healthz" "--resolve app.localtest.me:8443:127.0.0.1"

expect_http() {
  local expected="$1"
  local desc="$2"
  shift 2
  echo "$desc (expect $expected)..."
  local code
  code=$(curl -k -s -o /dev/null -w "%{http_code}" "$@")
  if [ "$code" != "$expected" ]; then
    echo "FAIL: $desc (got $code, expected $expected)"
    exit 1
  fi
  echo "PASS: $desc ($code)"
}

log "Initial request via Nginx/ipremember (should be blocked with 401)"
expect_http 401 "Unauthenticated app request" --resolve app.localtest.me:8443:127.0.0.1 https://app.localtest.me:8443/

LOGIN_PAYLOAD='{"username":"naomi.roci","password":"filip","keepMeLoggedIn":true,"targetURL":"https://app.localtest.me:8443/"}'
LOGIN_OUT=$(mktemp)
log "Logging in to Authelia (first factor, expect 200 JSON)..."
login_code=$(curl -k -s -o "$LOGIN_OUT" -w "%{http_code}" -c "$COOKIE_JAR" -X POST -H "Content-Type: application/json" --data "$LOGIN_PAYLOAD" --resolve auth.localtest.me:9091:127.0.0.1 https://auth.localtest.me:9091/api/firstfactor)
if [ "$login_code" != "200" ]; then
  echo "FAIL: Authelia login returned $login_code"
  echo "Response:"
  cat "$LOGIN_OUT"
  exit 1
fi
echo "PASS: Authelia login ($login_code)"

expect_http 200 "App request with Authelia session cookie (should register IP)" -b "$COOKIE_JAR" -c "$COOKIE_JAR" --resolve app.localtest.me:8443:127.0.0.1 https://app.localtest.me:8443/

log "Follow-up request without Authelia cookie (should be allowed via ipremember entry)"
expect_http 200 "App request without session after ipremember registration" --resolve app.localtest.me:8443:127.0.0.1 https://app.localtest.me:8443/

log "Calling /remember directly to ensure cookie is set on client"
REMEMBER_CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" -c "$COOKIE_JAR" -H "Authorization: Bearer $SHARED_SECRET_VALUE" -H "X-User: naomi.roci" http://localhost:8080/remember)
if [ "$REMEMBER_CODE" != "204" ]; then
  echo "FAIL: /remember returned $REMEMBER_CODE"
  exit 1
fi

log "Status from ipremember without cookie (expect allowed:true, user empty):"
STATUS_JSON=$(curl -s http://localhost:8080/status)
echo "TEST: $STATUS_JSON"
python3 - "$STATUS_JSON" <<'PY'
import json
import sys

raw = sys.argv[1]
try:
    data = json.loads(raw)
except Exception as exc:
    print(f"Failed to parse /status response: {exc}")
    sys.exit(1)

if not data.get("allowed"):
    print(f"FAIL: /status.allowed expected true, got: {data}")
    sys.exit(1)

ttl = data.get("ttlSeconds")
if ttl is None or ttl <= 0:
    print(f"FAIL: ttlSeconds expected > 0, got: {ttl}")
    sys.exit(1)

if data.get("user"):
    print(f"FAIL: expected user to be empty without cookie, got: {data['user']}")
    sys.exit(1)

print(f"PASS: /status allowed=true ttlSeconds={ttl} user(empty)")
PY

log "Status from ipremember with cookie (expect allowed:true and user present):"
COOKIE_VAL=$(awk '$6=="ipremember"{print $7}' "$COOKIE_JAR" | tail -n1)
if [ -z "$COOKIE_VAL" ]; then
  echo "FAIL: could not extract ipremember cookie from jar"
  exit 1
fi
STATUS_JSON_COOKIE=$(curl -s -H "Cookie: ipremember=$COOKIE_VAL" http://localhost:8080/status)
echo "TEST: $STATUS_JSON_COOKIE"
python3 - "$STATUS_JSON_COOKIE" <<'PY'
import json
import sys

raw = sys.argv[1]
try:
    data = json.loads(raw)
except Exception as exc:
    print(f"Failed to parse /status response (cookie): {exc}")
    sys.exit(1)

if not data.get("allowed"):
    print(f"FAIL: /status (cookie) allowed expected true, got: {data}")
    sys.exit(1)

ttl = data.get("ttlSeconds")
if ttl is None or ttl <= 0:
    print(f"FAIL: (cookie) ttlSeconds expected > 0, got: {ttl}")
    sys.exit(1)

user = data.get("user", "")
if not user:
    print(f"FAIL: expected user to be present with cookie, got empty")
    sys.exit(1)

print(f"PASS: /status (cookie) allowed=true ttlSeconds={ttl} user={user}")
PY

log "To stop: docker compose -f docker-compose.authelia.yml down"
