#!/usr/bin/env bash
# DEV-ONLY helper. Builds the image, ensures .env exists, runs gofmt/tests in a Go container,
# starts the lightweight dev stack (ipremember + curl helper), and exercises the basic workflow.
# Not for production use.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ENV_FILE="$ROOT/.env"
if [ ! -f "$ENV_FILE" ]; then
  echo "Creating .env from config.example.env"
  cp config.example.env "$ENV_FILE"
  # Generate a fresh SHARED_SECRET for dev/demo.
  NEW_SECRET=$(python3 - <<'PY'
import secrets
print(secrets.token_hex(16))
PY
)
  # replace SHARED_SECRET line
  tmp=$(mktemp)
  sed "s/^SHARED_SECRET=.*/SHARED_SECRET=${NEW_SECRET}/" "$ENV_FILE" > "$tmp"
  mv "$tmp" "$ENV_FILE"
  echo "Generated SHARED_SECRET=${NEW_SECRET}"
fi

echo "Using env file at $ENV_FILE"

# Build image (dev/demo only).
echo "Building ipremember image..."
docker compose -f docker-compose.dev.yml build ipremember

# Run gofmt/tests in a Go container to keep host clean.
echo "Running gofmt + tests in golang:1.22 container..."
docker run --rm -v "$ROOT":/src -w /src golang:1.22-alpine sh -c "apk add --no-cache curl >/dev/null && gofmt -w *.go && go test ./..."

# Start the minimal dev stack (ipremember + curl helper).
echo "Starting dev stack (ipremember + curl helper)..."
docker compose -f docker-compose.dev.yml up -d ipremember curl

echo "Waiting for ipremember to be ready..."
sleep 2

# Check expected 401 before registration.
echo "Workflow check: expect 401 before registration"
docker compose -f docker-compose.dev.yml exec curl sh -c 'curl -s -o /dev/null -w "HTTP %{http_code}\\n" http://ipremember:8080/auth'

# Register caller IP via remember endpoint with bearer token.
echo "Registering IP via /remember (should be 204)"
docker compose -f docker-compose.dev.yml exec curl sh -c 'curl -s -o /dev/null -w "HTTP %{http_code}\\n" -XPOST -H "Authorization: Bearer $SHARED_SECRET" http://ipremember:8080/remember'

# Now IP should be allowed.
echo "Workflow check: expect 204 after registration"
docker compose -f docker-compose.dev.yml exec curl sh -c 'curl -s -o /dev/null -w "HTTP %{http_code}\\n" http://ipremember:8080/auth'

# Show current status JSON.
echo "Status payload from /status:"
docker compose -f docker-compose.dev.yml exec curl sh -c 'curl -s http://ipremember:8080/status'
echo

echo "To stop the stack: docker compose -f docker-compose.dev.yml down"
