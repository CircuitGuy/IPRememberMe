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

### Endpoints

- `GET /healthz` — liveness.
- `GET /` — HTML for “this IP” with hours remaining and limit info.
- `GET /status` — JSON for current IP (allowed, expiresAt, ttlSeconds, ip, user).
- `GET /auth` — proxy check; 204 if IP allowed (or Authelia session verified), 401 otherwise.
- `POST /remember` — requires shared secret header; registers current IP + user; issues signed cookie.
- `POST /admin/clear` — requires shared secret; clears all or target IP.
- `GET /admin/list` — requires shared secret; returns current allowlist.
- `GET /admin/ui` — minimal HTML admin UI; uses bearer token to list/clear IPs.

### Configuration (env)

- `SHARED_SECRET` (required): bearer token for admin/remember endpoints and cookie signing.
- `ALLOW_DURATION_HOURS` (default 24).
- `MAX_IPS_PER_USER` (default 3): distinct IPs allowed per user; currently rejects beyond limit (see TODO to evict oldest).
- `LISTEN_ADDR` (default `:8080`).
- `LOG_LEVEL` (default `info`).
- `AUTHELIA_URL` / `AUTHELIA_INSECURE_SKIP_VERIFY`: optional Authelia auth-request verification in `/auth`.

### Data Model

- In-memory map keyed by IP -> { user, expiresAt, lastSeen }.  
- Max entries enforced per user; currently rejects when the user exceeds `MAX_IPS_PER_USER`.  
- Background cleanup ticker removes expired entries.

### Logging

- Structured log per request: method, path, status, ip, user, ttl.
- Startup logs config values (non-secret).

### Security/Assumptions

- All mutating endpoints require `Authorization: Bearer <SHARED_SECRET>`.
- Cookie `ipremember` signed with HMAC-SHA256 using `SHARED_SECRET`; contains IP and expiry.
- Proxy must strip/override `X-Forwarded-For` to prevent spoofing.

### Proxy Integration Sketch (Nginx)

```
location / {
  auth_request /ipremember-check;
  error_page 401 = @authelia;
  proxy_pass http://app;
}

location = /ipremember-check {
  internal;
  proxy_pass http://ipremember:8080/auth;
}

location @authelia {
  internal;
  auth_request /authelia;  # your existing Authelia forward-auth
  auth_request_set $auth_status $upstream_status;
  if ($auth_status = 200) {
    proxy_set_header Authorization "Bearer ${IPREMEMBER_SECRET}";
    proxy_pass http://ipremember:8080/remember;
    break;
  }
  return 401;
}
```

### Current status

- Go service implemented with per-user IP cap, Authelia verification fallback, admin UI (`/admin/ui`), and structured logging.
- Dev and full-stack scripts in place; self-signed cert with SANs for app/auth hosts.
- Default demo user: `holden.roci` / `racehorse`; avoid using admin accounts.
- Build/test commands: `docker run --rm -v "$PWD":/src -w /src golang:1.22-alpine sh -c "apk add --no-cache git >/dev/null && go test ./..."`; binary build: `docker run --rm -v "$PWD":/src -w /src golang:1.22-alpine go build -o ipremember`; image: `docker build -t ipremember:dev .`.
- Tests: token round-trip/bad signature, store per-user limit (refresh allowed), per-user limit across users.

### Next Steps / TODO

- Change per-user cap behavior: when exceeding `MAX_IPS_PER_USER`, evict oldest IP for that user instead of rejecting the new IP. Update tests/README accordingly.
- Performance check: script a benchmark (wrk/hey/docker) to send 10k parallel auth requests without the sidecar vs. with ipremember in front; report median and standard deviation latencies for both.
- Add automated curl/asserts in `scripts/full-stack.sh` to fail fast if `/status` is not allowed:true.
- Optional: allow toggling Authelia verification via header/env per deployment, and tune timeouts.
- Add CI (GitHub Actions) to run gofmt/go test and possibly lint on PRs.
- Build and publish container image via GitHub Container Registry; wire README badges and sample `docker pull ghcr.io/<owner>/ipremember:latest`.
- Think about and add some security tests. In particular make sure the /status with the user is only given to the cookied user. The time remaining (only) should be given to anybody allowed by IP.
- Add a simple user webpage that lets them see their current and previous IPs and extend the timer (even if not on that IP). Make sure it's cookied user only, add that to security unit tests.
- Make sure all logging and stored IPs are in memory only; not on the disk. Make disk-touching minimal. State that in the readme and agents.md as a security feature and to prevent wear-out on simple devices like SD card Raspberry Pis.
