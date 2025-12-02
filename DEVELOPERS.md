Developers
==========

Readme vs this doc
------------------
The README covers the user-facing story (what/why/how, quick demos, endpoints). This file is the engineering companion: request flow, security assumptions, data model, config nuances, test/bench/stack notes, and the PR checklist. Keep it in sync with README when behavior changes.

Request flow (technical)
------------------------
- `/auth`: checks in-memory allowlist; if allowed, 204. If `AUTHELIA_URL` is set and verification is enabled, calls Authelia `/api/authz/auth-request` with incoming cookies/headers; on success registers the IP (evicting oldest per user if over limit), sets cookie, returns 204.
- `/remember`: bearer-only; registers caller IP/user, issues cookie binding IP/user/expiry (evict oldest per user if over limit).
- Cookie (`ipremember`): HMAC-SHA256 using `SHARED_SECRET`, contains IP|user|expiry. `/status` returns `user` only when a valid cookie for that IP is present; otherwise `user` is blank even if allowed.
- `/user`: cookie-required; lists that user’s IPs and allows extend for those IPs only.
- Admin endpoints: bearer-only; list/clear allowlist; UI is just a thin HTML shell calling the APIs.

Data model & limits
-------------------
- In-memory map: IP -> {user, expiresAt, lastSeen}; no disk writes.
- Per-user cap: when `MAX_IPS_PER_USER` is exceeded, evict the oldest IP for that user and insert the new one.
- Background cleanup prunes expired entries.

Config notes
------------
- Core env: `SHARED_SECRET`, `ALLOW_DURATION_HOURS`, `MAX_IPS_PER_USER`, `LISTEN_ADDR`, `LOG_LEVEL`.
- Authelia options: `AUTHELIA_URL`, `AUTHELIA_INSECURE_SKIP_VERIFY`, `AUTHELIA_VERIFY`, `AUTHELIA_ALLOW_HEADER_TOGGLE`, `AUTHELIA_TOGGLE_HEADER`, `AUTHELIA_TIMEOUT_SECONDS`.
- Security: proxy must control/clean `X-Forwarded-For`; header-based Authelia toggle should be set/stripped by the proxy only.

Testing & scripts
-----------------
Scripts should manage Docker bring-up/tear-down themselves; avoid manual docker compose unless debugging.
- CI runs gofmt checks and `go test ./...` on pushes/PRs before publishing images.
- Unit tests (container-only; do not run host `go`): `./scripts/dev-stack.sh` (fast path) or `docker run --rm -v "$PWD":/src -w /src golang:1.22-alpine sh -c "apk add --no-cache git curl >/dev/null && go test ./..."`.
- Dev stack: `./scripts/dev-stack.sh` (build, tests, compose.dev up, workflow smoke).
- Full stack: `./scripts/full-stack.sh` (build, tests, compose.authelia up, 401→login→200 flow, cookie/no-cookie `/status` checks).
- Benchmark: `./scripts/benchmark.sh` (curl-based, defaults to ~1,500 requests, auto-starts/stops the full stack if needed, progress + median/stddev + percent comparison, exits on failure). On this machine expect ~15–40s wall clock.
- Admin UI: `/admin/ui` uses bearer token to list/clear allowlist; `/user` endpoints are cookie-scoped for per-user view/extend.

Packaging / images
------------------
- CI (`.github/workflows/ci.yml`) publishes multi-arch (amd64 + arm64) images to `ghcr.io/circuitguy/iprememberme` with ref-based tags (`latest`, tags, SHA). GHCR should show the repo README; if metadata regresses to `unknown/unknown`, rebuild via buildx.

PR/agents checklist
-------------------
- Keep README and DEVELOPERS aligned when behavior/config changes.
- Run gofmt + go test ./... in a Go container (stack scripts already do this); avoid running host `go`.
- Ensure gofmt + go test ./... pass (stack scripts also run tests).
- Prefer the stack scripts for local validation; update docs/examples when changing flows/config.
- Update docs when endpoints/config/tests/benchmarks change.
- Remember cookie/user rules in tests: `/status` user is blank without the valid cookie; present with it.
