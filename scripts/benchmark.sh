#!/usr/bin/env sh
# Benchmark auth path with and without ipremember using only curl timings.
# Defaults hit health endpoints so the stack doesn’t need an active login.
# Env:
#   REQUESTS (default 1500)        - number of requests per target (aim ~15-30s on this box)
#   DIRECT_URL (default http://localhost:9091/api/health) - Authelia health
#   IPREMEMBER_URL (default http://localhost:8080/healthz) - ipremember health; set both to HTTPS if desired
#   CERT_FILE (default certs/selfsigned.crt) - passed to curl for TLS if you switch to HTTPS
#   AUTO_START=0/1 (default 0)     - start docker-compose.authelia.yml if services are down (off by default)
#   CURL_TIMEOUT (default 5)       - per-request timeout in seconds
#   USE_DOCKER_CURL=0/1 (default 0) - run curl inside a fresh container instead of host curl
# Output: medians/stdevs and a percent comparison; exits on failures (no stubs).

set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

REQUESTS=${REQUESTS:-1500}
DIRECT_URL=${DIRECT_URL:-http://localhost:9091/api/health}
IPREMEMBER_URL=${IPREMEMBER_URL:-https://localhost:8443/healthz}
CERT_FILE=${CERT_FILE:-"$ROOT/certs/selfsigned.crt"}
AUTO_START=${AUTO_START:-0}
CURL_TIMEOUT=${CURL_TIMEOUT:-5}
USE_DOCKER_CURL=${USE_DOCKER_CURL:-0}
CURL_IMAGE=${CURL_IMAGE:-curlimages/curl:8.4.0}
RESOLVES=${RESOLVES:-}

# Load .env if present for convenience
if [ -f ".env" ]; then
  set -a
  . "./.env"
  set +a
fi

check_url() {
  url="$1"
  if command -v curl >/dev/null 2>&1; then
    code=$(curl -k -s -o /dev/null -w "%{http_code}" "$url") || return 1
    [ "$code" -ge 200 ] && [ "$code" -lt 500 ]
  else
    return 0
  fi
}

pick_url() {
  preferred="$1"; shift
  for u in "$@"; do
    if check_url "$u"; then
      echo "$u"
      return 0
    fi
  done
  echo "$preferred"
  return 0
}

summarize_file() {
  file="$1"; label="$2"
  sorted=$(mktemp)
  sort -n "$file" >"$sorted"
  awk -v label="$label" '
    NR==1 {min=$1}
    { vals[NR]=$1; sum+=$1; sumsq+=$1*$1; max=$1 }
    END {
      if (NR==0) { print label ": no data"; exit 1 }
      n=NR
      if (n%2==1) med=vals[(n+1)/2]; else med=(vals[n/2]+vals[n/2+1])/2
      mean=sum/n; stdev=sqrt(sumsq/n - mean*mean)
      printf "%s: count=%d median=%.2fms avg=%.2fms stdev=%.2fms min=%.2fms max=%.2fms\n",
        label, n, med*1000, mean*1000, stdev*1000, min*1000, max*1000
    }
  ' "$sorted"
  rm -f "$sorted"
}

run_stub() {
  :
}

measure() {
  label="$1"; url="$2"
  ca_opt="-k"
  tmp=$(mktemp)
  ok=1
  progress_every=$((REQUESTS/50))
  if [ "$progress_every" -lt 1 ]; then progress_every=1; fi
  >&2 printf "Running %s (%s requests)\n" "$label" "$REQUESTS"
  idx=0
  for _ in $(seq 1 "$REQUESTS"); do
    t=$(run_curl "$ca_opt" "$url") || ok=0
    echo "$t" >>"$tmp"
    idx=$((idx+1))
    if [ $((idx % progress_every)) -eq 0 ] || [ "$idx" -eq "$REQUESTS" ]; then >&2 printf "."; fi
  done
  >&2 printf "\n"
  if [ "$ok" -ne 1 ]; then
    rm -f "$tmp"
    return 1
  fi
  summarize_file "$tmp" "$label"
  rm -f "$tmp"
  return 0
}

# Run curl either on host or in a modern curl container.
run_curl() {
  ca_opt="$1"; url="$2"
  resolve_args=""
  IFS_save="$IFS"
  IFS=','; set -- $RESOLVES; IFS="$IFS_save"
  for entry in "$@"; do
    [ -n "$entry" ] && resolve_args="$resolve_args --resolve $entry"
  done
  if [ "$USE_DOCKER_CURL" -eq 1 ]; then
    mount_cert=""
    if [ -f "$CERT_FILE" ]; then
      mount_cert="-v $CERT_FILE:/cert.pem:ro -e CURL_CA_BUNDLE=/cert.pem"
    fi
    docker run --rm --network host $mount_cert "$CURL_IMAGE" sh -c "curl -f -s -o /dev/null -w '%{time_total}' -m '$CURL_TIMEOUT' $resolve_args $ca_opt '$url'" || return 1
  else
    curl -f -s -o /dev/null -w '%{time_total}' -m "$CURL_TIMEOUT" $resolve_args $ca_opt "$url" || return 1
  fi
}

# Main flow
direct_url=$(pick_url "$DIRECT_URL" "$DIRECT_URL" http://localhost:9091/api/health https://localhost:9091/api/health http://127.0.0.1:9091/api/health https://127.0.0.1:9091/api/health)
ip_url=$(pick_url "$IPREMEMBER_URL" "$IPREMEMBER_URL" https://localhost:8443/healthz https://127.0.0.1:8443/healthz http://localhost:8080/healthz http://127.0.0.1:8080/healthz)

echo "DIRECT_URL: $direct_url"
echo "IPREMEMBER_URL: $ip_url"
echo "Settings: requests=$REQUESTS timeout=${CURL_TIMEOUT}s use_docker_curl=$USE_DOCKER_CURL"
start_ts=$(date +%s)

direct_out="" ip_out=""
direct_ok=1
ip_ok=1
if ! check_url "$direct_url"; then direct_ok=0; fi
if ! check_url "$ip_url"; then ip_ok=0; fi

if [ "$direct_ok" -eq 0 ]; then
  echo "DIRECT_URL unreachable ($direct_url); start the stack or override the URL."
  exit 1
else
  direct_out=$(measure "DIRECT" "$direct_url" 2>/dev/null || echo "")
  if [ -z "$direct_out" ]; then
    echo "DIRECT measurement failed; exiting."
    exit 1
  fi
fi

if [ "$ip_ok" -eq 0 ]; then
  echo "IPREMEMBER_URL unreachable ($ip_url); start the stack or override the URL."
  exit 1
else
  ip_out=$(measure "IPREMEMBER" "$ip_url" 2>/dev/null || echo "")
  if [ -z "$ip_out" ]; then
    echo "IPREMEMBER measurement failed; exiting."
    exit 1
  fi
fi

echo "$direct_out"
echo "$ip_out"

if [ "${direct_url%%://*}" != "${ip_url%%://*}" ]; then
  echo "Note: Schemes differ (direct=${direct_url%%://*}, ipremember=${ip_url%%://*}); set DIRECT_URL/IPREMEMBER_URL for apples-to-apples."
fi

# Compare medians and stdevs if both real measurements succeeded
if echo "$direct_out" | grep -q "median=" && echo "$ip_out" | grep -q "median="; then
  d_med=$(echo "$direct_out" | awk -F'median=' '{print $2}' | awk '{print $1}' | sed 's/ms//')
  i_med=$(echo "$ip_out" | awk -F'median=' '{print $2}' | awk '{print $1}' | sed 's/ms//')
  d_std=$(echo "$direct_out" | awk -F'stdev=' '{print $2}' | awk '{print $1}' | sed 's/ms//')
  i_std=$(echo "$ip_out" | awk -F'stdev=' '{print $2}' | awk '{print $1}' | sed 's/ms//')
  if [ -n "$d_med" ] && [ -n "$i_med" ]; then
    faster=$(awk -v d="$d_med" -v i="$i_med" 'BEGIN { if (d>0) printf "%.1f", ((d-i)/d)*100; else print "" }')
    echo "Comparison: ipremember median ${i_med}ms (stdev ${i_std}ms) vs direct median ${d_med}ms (stdev ${d_std}ms) => ~${faster}% faster"
  fi
fi

end_ts=$(date +%s)
elapsed=$((end_ts - start_ts))
echo "Benchmark elapsed: ${elapsed}s"
