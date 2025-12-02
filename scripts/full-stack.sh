#!/usr/bin/env bash
# DEV/DEMO ONLY: Bring up full stack (ipremember + Authelia + Nginx + whoami),
# run gofmt/tests, build images, log into Authelia, and exercise the protected route.
# Not for production use.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ENV_FILE="$ROOT/.env"
CERT_SCRIPT="$ROOT/scripts/gen-selfsigned.sh"
if [ ! -f "$ENV_FILE" ]; then
  echo "Missing .env; run scripts/dev-stack.sh first to generate one."
  exit 1
fi

"$CERT_SCRIPT"

# Run gofmt/tests in a Go container (keeps host clean).
echo "Running gofmt + tests..."
docker run --rm -v "$ROOT":/src -w /src golang:1.22-alpine sh -c "apk add --no-cache git >/dev/null && gofmt -w main.go main_test.go && go test ./..."

echo "Stopping any existing stack..."
docker compose -f docker-compose.authelia.yml down --remove-orphans >/dev/null 2>&1 || true

echo "Building and starting full stack..."
docker compose -f docker-compose.authelia.yml up -d --build

echo "Waiting for services..."
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

echo "Initial request (should be 401) via Nginx -> ipremember -> Authelia"
curl -k -s -o /dev/null -w "HTTP %{http_code}\\n" --resolve app.localtest.me:8443:127.0.0.1 https://app.localtest.me:8443/

COOKIE_JAR=$(mktemp)
LOGIN_PAYLOAD='{"username":"naomi.roci","password":"filip","keepMeLoggedIn":true,"targetURL":"https://app.localtest.me:8443/"}'

echo "Logging in to Authelia (first factor)..."
curl -k -s -o /tmp/authelia_login.json -c "$COOKIE_JAR" -X POST -H "Content-Type: application/json" --data "$LOGIN_PAYLOAD" --resolve auth.localtest.me:9091:127.0.0.1 https://auth.localtest.me:9091/api/firstfactor || true

echo "Request with Authelia session cookie (should register IP and return 200)"
curl -k -s -o /dev/null -w "HTTP %{http_code}\\n" -b "$COOKIE_JAR" --resolve app.localtest.me:8443:127.0.0.1 https://app.localtest.me:8443/

echo "Follow-up request without session cookie (should be allowed via ipremember IP entry)"
curl -k -s -o /dev/null -w "HTTP %{http_code}\\n" --resolve app.localtest.me:8443:127.0.0.1 https://app.localtest.me:8443/

echo "Status from ipremember:"
curl -s http://localhost:8080/status && echo

echo "To stop: docker compose -f docker-compose.authelia.yml down"
