#!/usr/bin/env bash
# DEV/DEMO ONLY: Bring up full stack (ipremember + Authelia + Nginx + whoami),
# run gofmt/tests, build images, log into Authelia, and exercise the protected route.
# Not for production use.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

info() { echo "$*"; }
test_step() { echo "TEST: $*"; }

ENV_FILE="$ROOT/.env"
CERT_SCRIPT="$ROOT/scripts/gen-selfsigned.sh"
COOKIE_JAR=$(mktemp)
LOGIN_OUT=$(mktemp)
STACK_UP=0

clear_allowlist() {
  if [ -z "${SHARED_SECRET_VALUE:-}" ]; then
    echo "000"
    return 0
  fi
  curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $SHARED_SECRET_VALUE" -X POST http://localhost:8080/admin/clear
}

cleanup() {
  rm -f "$COOKIE_JAR" "$LOGIN_OUT"
  if [ "$STACK_UP" -eq 1 ]; then
    info "Clearing allowlist after run..."
    exit_clear=$(clear_allowlist || true)
    if [ "${exit_clear:-000}" != "204" ]; then
      info "Allowlist clear on exit returned ${exit_clear:-000} (ignored)"
    fi
    info "Stack is still running for manual testing."
    info "Stop it later with: docker compose -f docker-compose.authelia.yml down --remove-orphans"
  fi
}
trap cleanup EXIT

if [ ! -f "$ENV_FILE" ]; then
  echo "Missing .env; run scripts/dev-stack.sh first to generate one."
  exit 1
fi
SHARED_SECRET_VALUE=$(grep '^SHARED_SECRET=' "$ENV_FILE" | head -n1 | cut -d= -f2-)
if [ -z "$SHARED_SECRET_VALUE" ]; then
  echo "Missing SHARED_SECRET in .env"
  exit 1
fi

info "Generating self-signed cert if needed"
"$CERT_SCRIPT"

# Run gofmt/tests in a Go container (keeps host clean).
info "Running gofmt + tests..."
docker run --rm -v "$ROOT":/src -w /src golang:1.22-alpine sh -c "apk add --no-cache curl >/dev/null && gofmt -w *.go && go test ./..."

info "Stopping any existing stack..."
docker compose -f docker-compose.authelia.yml down --remove-orphans >/dev/null 2>&1 || true

info "Building and starting full stack..."
docker compose -f docker-compose.authelia.yml up -d --build
STACK_UP=1

info "Waiting for services..."
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

info "Clearing any residual allowlist state before tests"
clear_code=$(clear_allowlist)
if [ "$clear_code" != "204" ]; then
  echo "FAIL: admin clear returned $clear_code (expected 204); check SHARED_SECRET"
  exit 1
fi

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

extract_ttl() {
  python3 - "$1" <<'PY'
import json
import sys

raw = sys.argv[1]
data = json.loads(raw)
print(int(data.get("ttlSeconds", 0)))
PY
}

expect_redirect() {
  local desc="$1"
  local match="$2"
  shift 2
  local headers
  headers=$(mktemp)
  local code
  code=$(curl -k -s -D "$headers" -o /dev/null -w "%{http_code}" "$@")
  if [ "$code" != "302" ]; then
    echo "FAIL: $desc (got $code, expected 302)"
    cat "$headers"
    rm -f "$headers"
    exit 1
  fi
  local location
  location=$(awk 'tolower($1)=="location:" {print $2}' "$headers" | tail -n1 | tr -d '\r')
  rm -f "$headers"
  if [ -z "$location" ] || [[ "$location" != *"$match"* ]]; then
    echo "FAIL: $desc (302 but Location missing/unexpected: ${location:-<none>})"
    exit 1
  fi
  echo "PASS: $desc (302 -> $location)"
}

test_step "Initial request via Nginx/ipremember (should redirect to Authelia portal)"
expect_redirect "Unauthenticated app request" "https://auth.localtest.me:9091" --resolve app.localtest.me:8443:127.0.0.1 https://app.localtest.me:8443/

LOGIN_PAYLOAD='{"username":"naomi.roci","password":"filip","keepMeLoggedIn":true,"targetURL":"https://app.localtest.me:8443/"}'
test_step "Logging in to Authelia (first factor, expect 200 JSON)"
login_code=$(curl -k -s -o "$LOGIN_OUT" -w "%{http_code}" -c "$COOKIE_JAR" -X POST -H "Content-Type: application/json" --data "$LOGIN_PAYLOAD" --resolve auth.localtest.me:9091:127.0.0.1 https://auth.localtest.me:9091/api/firstfactor)
if [ "$login_code" != "200" ]; then
  echo "FAIL: Authelia login returned $login_code"
  echo "Response:"
  cat "$LOGIN_OUT"
  exit 1
fi
echo "PASS: Authelia login ($login_code)"

expect_http 200 "App request with Authelia session cookie (should register IP)" -b "$COOKIE_JAR" -c "$COOKIE_JAR" --resolve app.localtest.me:8443:127.0.0.1 https://app.localtest.me:8443/

test_step "Follow-up request without Authelia cookie (should be allowed via ipremember entry)"
expect_http 200 "App request without session after ipremember registration" --resolve app.localtest.me:8443:127.0.0.1 https://app.localtest.me:8443/
test_step "New incognito request without ipremember cookie (should still bypass but must not refresh TTL)"
STATUS_JSON_PRE=$(curl -s http://localhost:8080/status)
ttl_before=$(extract_ttl "$STATUS_JSON_PRE")
if [ "$ttl_before" -le 0 ]; then
  echo "FAIL: ttlSeconds missing/invalid before incognito check"
  exit 1
fi
expect_http 200 "Incognito request without cookie (should rely on IP allowlist only)" --resolve app.localtest.me:8443:127.0.0.1 https://app.localtest.me:8443/
STATUS_JSON_POST=$(curl -s http://localhost:8080/status)
ttl_after=$(extract_ttl "$STATUS_JSON_POST")
if [ "$ttl_after" -le 0 ]; then
  echo "FAIL: ttlSeconds missing/invalid after incognito check"
  exit 1
fi
if [ "$ttl_after" -gt $((ttl_before + 2)) ]; then
  echo "FAIL: TTL unexpectedly increased after incognito request (before=$ttl_before after=$ttl_after)"
  exit 1
fi
echo "PASS: Incognito request succeeded without refreshing TTL (before=$ttl_before after=$ttl_after)"

test_step "Checking /status quickly (without cookie) to ensure allowed=true"
STATUS_JSON_QUICK=$(curl -s http://localhost:8080/status)
python3 - "$STATUS_JSON_QUICK" <<'PY'
import json
import sys

raw = sys.argv[1]
try:
    data = json.loads(raw)
except Exception as exc:
    print(f"Failed to parse /status response: {exc}")
    sys.exit(1)

if not data.get("allowed"):
    print(f"FAIL: /status.allowed expected true after Authelia login, got: {data}")
    sys.exit(1)
print(f"PASS: quick /status allowed={data.get('allowed')} ttlSeconds={data.get('ttlSeconds')}")
PY

test_step "Calling /remember directly to ensure cookie is set on client"
REMEMBER_CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" -c "$COOKIE_JAR" -H "Authorization: Bearer $SHARED_SECRET_VALUE" -H "X-User: naomi.roci" http://localhost:8080/remember)
if [ "$REMEMBER_CODE" != "204" ]; then
  echo "FAIL: /remember returned $REMEMBER_CODE"
  exit 1
fi

test_step "Status from ipremember without cookie (expect allowed:true, user empty)"
STATUS_JSON=$(curl -s http://localhost:8080/status)
echo "Status response: $STATUS_JSON"
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

test_step "Status from ipremember with cookie (expect allowed:true and user present)"
COOKIE_VAL=$(awk '$6=="ipremember"{print $7}' "$COOKIE_JAR" | tail -n1)
if [ -z "$COOKIE_VAL" ]; then
  echo "FAIL: could not extract ipremember cookie from jar"
  exit 1
fi
STATUS_JSON_COOKIE=$(curl -s -H "Cookie: ipremember=$COOKIE_VAL" http://localhost:8080/status)
echo "Status response (cookie): $STATUS_JSON_COOKIE"
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
