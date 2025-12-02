#!/usr/bin/env bash
# DEV/DEMO ONLY: Generate self-signed cert with SANs for app/auth hosts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="$ROOT/certs"
CERT="$CERT_DIR/selfsigned.crt"
KEY="$CERT_DIR/selfsigned.key"

mkdir -p "$CERT_DIR"

if [ -f "$CERT" ] && [ -f "$KEY" ]; then
  exit 0
fi

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -subj "/C=US/ST=NA/L=Dev/O=AutheliaIPRememberMe/CN=app.localtest.me" \
  -addext "subjectAltName=DNS:app.localtest.me,DNS:auth.localtest.me" \
  -keyout "$KEY" -out "$CERT"
