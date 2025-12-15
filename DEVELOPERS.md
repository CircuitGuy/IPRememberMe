Developers
==========

Readme vs this doc
------------------
The README covers the user-facing story (what/why/how, quick demos, endpoints). This file is the engineering companion: request flow, security assumptions, data model, config nuances, test/bench/stack notes, and the PR checklist. Keep it in sync with README when behavior changes.

Request flow (technical)
------------------------
- `/auth`: checks in-memory allowlist; if allowed, 204. If `AUTHELIA_URL` is set and verification is enabled, calls Authelia `/api/authz/auth-request` with incoming cookies/headers; on success registers the IP (evicting oldest per user if over limit), sets cookie, returns 204.
- `/remember`: bearer-only; registers caller IP/user, issues cookie binding IP/user/expiry (evict oldest per user if over limit).
- Cookie (`ipremember`): HMAC-SHA256 using `SHARED_SECRET`, contains IP|user|expiry. `/status` returns `user` only when a valid cookie for that IP is present; otherwise `user` is blank even if allowed. Demo note: cookie is `Secure` + host-only on `app.localtest.me`, so hitting `http://localhost:8080/user` in a browser 401s; use curl with `Cookie: ipremember=<value>` or set `COOKIE_DOMAIN=localtest.me` for the demo only if you want browser access to `/user`.
- `/user`: cookie-required; lists that user’s IPs and allows extend for those IPs only.
- Admin endpoints: bearer-only; list (GET) and clear (POST-only) allowlist; UI is just a thin HTML shell calling the APIs.
- Requests with multi-hop `X-Forwarded-For` are rejected (400) to avoid spoof chains; proxy should set a single client IP and strip user-supplied XFF.

Code organization
-----------------
- `main.go`: bootstraps config/logging, registers routes, starts the HTTP server.
- `config.go`: env parsing + defaults for every knob (Authelia, TTLs, logging, etc.).
- `store.go`: in-memory allowlist (insert/refresh/evict/list/clear) and associated struct.
- `server.go`: HTTP handlers, middleware, and cookie helpers (`/auth`, `/remember`, `/status`, `/user`, `/admin/*`).
- `authelia_client.go`: Authelia verification toggle + client that calls `/api/authz/auth-request`.
- `token.go`: cookie token signing/parsing helpers + `clientIP` / `cookieDomainFromRequest`.

Data model & limits
-------------------
- In-memory map: IP -> {user, expiresAt, lastSeen}; no disk writes.
- Per-user cap: when `MAX_IPS_PER_USER` is exceeded, evict the oldest IP for that user and insert the new one.
- Background cleanup prunes expired entries.
- Geo/ISP: best-effort lookup via ip-api.com (https://ip-api.com) for public IPs; cached for several hours and skipped entirely for private/reserved addresses. Surfaced on `/status`, `/user`, `/admin/list`, and `/admin/ui`.

Config notes
------------
- Core env: `SHARED_SECRET`, `ALLOW_DURATION_HOURS`, `MAX_IPS_PER_USER`, `LISTEN_ADDR`, `LOG_LEVEL`.
- `COOKIE_DOMAIN` (optional): explicit cookie domain; when unset cookies are host-only to avoid trusting unvalidated Host/forwarded host headers.
- Authelia options: `AUTHELIA_URL`, `AUTHELIA_INSECURE_SKIP_VERIFY`, `AUTHELIA_VERIFY`, `AUTHELIA_ALLOW_HEADER_TOGGLE`, `AUTHELIA_TOGGLE_HEADER`, `AUTHELIA_TIMEOUT_SECONDS`.
- Security: proxy must control/clean `X-Forwarded-For`; header-based Authelia toggle should be set/stripped by the proxy only.

Testing & scripts
-----------------
Scripts should manage Docker bring-up/tear-down themselves; avoid manual docker compose unless debugging.
- CI runs gofmt checks and `go test ./...` on pushes/PRs before publishing images.
- Unit tests (container-only; do not run host `go`): `./scripts/dev-stack.sh` (fast path) or `docker run --rm -v "$PWD":/src -w /src golang:1.22-alpine sh -c "apk add --no-cache git curl >/dev/null && go test ./..."`.
- Dev stack: `./scripts/dev-stack.sh` (build, tests, compose.dev up, workflow smoke).
- Full stack: `./scripts/full-stack.sh` (build, tests, compose.authelia up, 401→login→200 flow, cookie/no-cookie `/status` checks, blocks incognito/no-cookie access).
- Benchmark: `./scripts/benchmark.sh` (curl-based, defaults to ~1,500 requests, auto-starts/stops the full stack if needed, progress + median/stddev + percent comparison, exits on failure). On this machine expect ~15–40s wall clock. Run via the script; no local Go/Docker setup beyond what the script spins up.
- Admin UI: `/admin/ui` uses bearer token to list/clear allowlist; `/user` endpoints are cookie-scoped for per-user view/extend.

Packaging / images
------------------
- CI (`.github/workflows/ci.yml`) publishes multi-arch (amd64 + arm64) images to `ghcr.io/circuitguy/iprememberme` with ref-based tags (`latest`, tags, SHA). GHCR should show the repo README; if metadata regresses to `unknown/unknown`, rebuild via buildx.
- PR builds publish preview images to `ghcr.io/circuitguy/iprememberme-preview` tagged `pr-<number>` and `pr-<number>-<sha>` so the main package stays clean.
- Release tags (e.g., `v0.2.0`) produce matching image tags on the main package.

Versioning & releases
---------------------
- Version is tracked in `VERSION`; bump it when changing behavior/config. CI enforces a version bump when code/config changes.
- Release tags (e.g., `v0.2.0`) publish matching image tags to GHCR; preview images are published per PR.

PR/agents checklist
-------------------
- Keep README and DEVELOPERS aligned when behavior/config changes.
- Run gofmt + go test ./... in a Go container (stack scripts already do this); avoid running host `go`.
- Ensure gofmt + go test ./... pass (stack scripts also run tests).
- Prefer the stack scripts for local validation; update docs/examples when changing flows/config.
- Update docs when endpoints/config/tests/benchmarks change.
- Remember cookie/user rules in tests: `/status` user is blank without the valid cookie; present with it.
