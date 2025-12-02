## Authelia-IPRememberMe Agent Notes

### Purpose

- Lightweight sidecar between proxy (e.g., Nginx Proxy Manager) and protected apps.
- Lets one Authelia-authenticated client mark the current IP as trusted for a configurable window (default 24h); other devices on that IP bypass Authelia.
- Provides status page for the calling IP, cap on stored IPs, admin/user ability to clear allowlist, and good logs.

### Proposed Flow

1) Proxy checks this service first (auth_request).  
2) If IP is already trusted (not expired), service returns 204 and proxy forwards to app with no Authelia challenge.  
3) If not trusted, proxy falls back to Authelia forward-auth. On success, proxy makes a background subrequest to this service `/remember` to record the IP and sets a signed cookie.  
4) Any request with a valid cookie refreshes the expiry for that IP.  
5) Users can hit `/` to see remaining time for their IP; admins can clear IPs via authenticated endpoints.

### Security/Assumptions (brief)

- All mutating endpoints require `Authorization: Bearer <SHARED_SECRET>`.
- Proxy must strip/override `X-Forwarded-For` to prevent spoofing.
- Cookie `ipremember` signed with HMAC-SHA256 using `SHARED_SECRET`; binds IP+user+expiry.
- All allowlist state is in memory; logs to stdout; no disk writes (keeps deployments simple and protects wear-limited media).
- `/status` only returns `user` when a valid cookie for the caller IP is present; IP-only callers get allowed/TTL without the user. `/user` endpoints are cookie-scoped.

### Agent workflow / best practices

- Run gofmt + unit tests inside the Go container (use `./scripts/dev-stack.sh` or `./scripts/full-stack.sh`; do not run `go` on the host).
- Prefer the stack scripts for local workflows; they already format, test, build, and smoke-check flows.
- Keep README and DEVELOPERS in sync whenever behavior/config/testing changes; update both when touching endpoints or scripts.
- Keep docs/test notes aligned with reality (configs, demo users, TTLs, cookie behavior); add/adjust examples when changing flows.
- Stack scripts (dev/full/benchmark) should bring Docker up/down automatically; if they don’t, fix the script instead of relying on manual docker invocations.

### Sanity checks (for PRs/local)

- gofmt + go test ./... (in container via the scripts above)
- `./scripts/dev-stack.sh` (401 → remember → 204, `/status`).
- `./scripts/full-stack.sh` (401 → login → 200, `/status` allowed:true).
- Admin UI reachable at `/admin/ui` with bearer token; list/clear works.
- Benchmark (when run): 10k auth requests with/without sidecar; report median/stddev.

### Current status

- Go service with per-user IP cap (evicts oldest when exceeding limit), Authelia verification fallback, admin UI (`/admin/ui`), `/user` view/extend endpoints.
- Dev/full-stack scripts with self-signed certs (app/auth SANs).
- Demo users: `holden.roci` / `race horse battery staple`; `naomi.roci` / `filip`.
- CI runs gofmt/tests and publishes multi-arch GHCR images (`ghcr.io/circuitguy/iprememberme`) with README-linked metadata.
- Build/test: `docker run --rm -v "$PWD":/src -w /src golang:1.22-alpine sh -c "apk add --no-cache git >/dev/null && go test ./..."; docker build -t ipremember:dev .`.
- Unit tests: token round-trip/bad sig; per-user limit (refresh allowed; cross-user allowed).
