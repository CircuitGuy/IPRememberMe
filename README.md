Authelia-IPRememberMe
=====================

What this is
------------

Lightweight Go service (Dockerized) that sits between your proxy (e.g., Nginx Proxy Manager) and Authelia-protected apps. After one successful Authelia login on an IP, the service marks that IP as trusted for a configurable window (default 24h). While trusted, any device on that IP can skip Authelia challenges for the protected apps. Each touch refreshes the timer. A small status page shows the remaining time for “this IP” so apps like HomeAssistant or Jellyfin can surface a banner.

Why it exists
-------------

- HomeAssistant mobile app and Jellyfin on constrained clients don’t handle repeated Authelia redirects well.
- You want to log in once (per network), then let other devices on that IP pass through for a while.
- You still want visibility, limits, and the ability to clear the allowlist quickly.
- IP-trust warning: Whitelisting “this IP” is a convenience. On shared IPs (NAT/VPN/carrier), you may be trusting more than one device. Keep TTLs sensible and clear the list when in doubt.

How it works (high level)
-------------------------

1. Proxy calls `/auth` first. If the IP is already trusted and not expired, it returns 204 and the request proceeds without Authelia.
2. If the IP is not trusted, the proxy falls back to your normal Authelia forward-auth. On success, it makes a short subrequest to `/remember` (with the shared secret) to register the IP and set a signed cookie.
3. Any request carrying the signed cookie and correct IP refreshes the expiry.
4. `/` and `/status` show “this IP” remaining time; admin endpoints allow clearing the list.

Configuration (env)
-------------------

- `SHARED_SECRET` (required): bearer token for admin/remember endpoints and cookie signing.
- `ALLOW_DURATION_HOURS` (default `24`): TTL for each IP.
- `MAX_IPS_PER_USER` (default `3`): cap on distinct IPs per user; new additions beyond this are rejected with 409.
- `LISTEN_ADDR` (default `:8080`): listen address.
- `LOG_LEVEL` (default `info`): `debug|info|warn|error`.
- `AUTHELIA_URL` (optional): if set, `/auth` will fall back to Authelia’s `/api/authz/auth-request` using the incoming cookies/headers and auto-register the IP on success.
- `AUTHELIA_INSECURE_SKIP_VERIFY` (default `false`): allow self-signed TLS when talking to Authelia.

Endpoints
---------

- `GET /healthz` — liveness probe.
- `GET /` — minimal HTML page showing remaining time for this IP.
- `GET /status` — JSON: `{ allowed, expiresAt, ttlSeconds, ip, user }`.
- `GET /auth` — proxy check; 204 if IP allowed, else 401.
- `POST /remember` — register current IP/user; requires `Authorization: Bearer <SHARED_SECRET>`. Accepts optional `X-User` header for audit. Issues/refreshes cookie.
- `POST /admin/clear` — clear all or a specific IP (`ip` form value). Requires bearer token.
- `GET /admin/list` — list current allowlist. Requires bearer token.
- `GET /admin/ui` — minimal HTML admin UI; still requires bearer token for actions.

Banner example (HomeAssistant/Jellyfin)
---------------------------------------

The status page returns JSON at `/status`. A simple fetch with CSS overlay can show remaining hours. Example snippet (JS + CSS):

```js
async function renderBanner() {
  try {
    const res = await fetch('/status', { credentials: 'include' });
    if (!res.ok) return;
    const data = await res.json();
    if (!data.allowed) return;
    const hours = (data.ttlSeconds / 3600).toFixed(1);
    const banner = document.createElement('div');
    banner.className = 'ip-remember-banner';
    banner.textContent = `This IP (~${hours}h remaining)`;
    document.body.prepend(banner);
  } catch (_) {}
}
renderBanner();
```

```css
.ip-remember-banner {
  background: linear-gradient(120deg, #0a6cff, #42c6ff);
  color: #fff;
  font: 600 14px/1.4 "Segoe UI", system-ui, sans-serif;
  padding: 10px 14px;
  text-align: center;
  box-shadow: 0 4px 12px rgba(0,0,0,0.15);
}
```

Docker (compose example)
------------------------

A fuller compose (ipremember only):
```yaml
services:
  ipremember:
    image: ghcr.io/your/ipremember:latest
    ports:
      - "8080:8080"
    environment:
      SHARED_SECRET: changeme
      ALLOW_DURATION_HOURS: 24
      MAX_IPS_PER_USER: 3
      LOG_LEVEL: info
```

Local dev stack (WSL-friendly)
------------------------------
- Run `./scripts/dev-stack.sh`.
- The script copies `config.example.env` to `.env` (generating `SHARED_SECRET` if missing), builds the image, runs `gofmt` + `go test ./...` inside `golang:1.22-alpine`, brings up `docker-compose.dev.yml` (ipremember + curl helper), and exercises the workflow (401 before remember, 204 after, then shows `/status`).
- Stop the stack with `docker compose -f docker-compose.dev.yml down`.
- Full-stack (with Authelia + Nginx + whoami): `./scripts/full-stack.sh` generates a self-signed cert (stored in `certs/`), builds, runs tests, brings up `docker-compose.authelia.yml`, performs Authelia login, and verifies 401 → login → 200 → bypass flow over HTTPS (`https://app.localtest.me:8443`, self-signed; curl uses `-k`).

Planned behavior and constraints
--------------------------------

- Timer refreshes on any request carrying a valid cookie whose IP matches.
- Expired entries are cleaned in the background.
- When `MAX_IPS_PER_USER` is exceeded for a user, new registrations for that user fail (409) until cleared.
- Logs include method, path, status, ip, user, and TTL where applicable.
- Demo/local note: The provided docker-compose uses the Docker bridge, so requests appear as the bridge gateway IP (e.g., 172.18.0.1). It does not automatically allow your LAN IPs in this mode; in real deployments, ensure the proxy forwards the real client IP (or run host networking) so LAN IPs are recognized.

Unit tests & quick demo
-----------------------
- Unit tests (no host Go needed): `docker run --rm -v "$PWD":/src -w /src golang:1.22-alpine sh -c "apk add --no-cache git >/dev/null && go test ./..."`.
- Build binary: `docker run --rm -v "$PWD":/src -w /src golang:1.22-alpine go build -o ipremember`.
- Build image: `docker build -t ipremember:dev .`.
- Dev stack (ipremember only): `./scripts/dev-stack.sh`, then hit `http://localhost:8080/status` (or `/`/`/auth`); stop with `docker compose -f docker-compose.dev.yml down`.
- Full stack (Authelia+Nginx+whoami+ipremember): `./scripts/full-stack.sh`; then:
  - App via Nginx: `https://localhost:8443/` (self-signed; accept warning). Preferred hostname: `https://app.localtest.me:8443/` with curl `-k`.
  - ipremember direct: `http://localhost:8080/status`.
  - Authelia health: `https://localhost:9091/api/health` (`-k` because of self-signed).
  - Reminder: In this demo, the client IP appears as the Docker bridge gateway. For real LAN/IP-based allowlisting, deploy behind a proxy that forwards the actual client IP or run with host networking.
- To re-auth in Chrome: clear site data for `localtest.me` (Settings → Privacy & Security → Cookies and site data → See all cookies → search `localtest.me` → remove). This also clears the ipremember cookie so new sessions/users take effect.
- Admin UI: `https://app.localtest.me:8443/admin/ui` (supply `Authorization: Bearer <SHARED_SECRET>` in the UI input to list/clear IPs).

Hosts (if localtest.me doesn’t resolve for you)
-----------------------------------------------
- Some DNS resolvers block or rewrite loopback wildcards. If `app.localtest.me` doesn’t resolve or returns IPv6-only (::1), pin it to IPv4 loopback:
  - Windows (PowerShell as admin): `$hosts = $env:SystemRoot+'\System32\drivers\etc\hosts'; $lines = Get-Content $hosts | Where-Object {$_ -notmatch 'localtest\.me'}; $lines + @('127.0.0.1 localtest.me','127.0.0.1 app.localtest.me','127.0.0.1 auth.localtest.me') | Set-Content -Path $hosts -Encoding ascii; ipconfig /flushdns`
  - Linux: `printf '127.0.0.1 localtest.me\n127.0.0.1 app.localtest.me\n127.0.0.1 auth.localtest.me\n' | sudo tee -a /etc/hosts`
- After editing hosts:
  - Windows: command above flushes DNS; restart the browser if it cached DNS.
  - Linux: many browsers cache DNS; restart the browser or the nscd/systemd-resolved service if in use.
- Use `ping -4 app.localtest.me` or curl to confirm it hits 127.0.0.1. Run hosts edits with admin/root rights so writes succeed.

Step-by-step demo (full stack)
------------------------------
1) Run `./scripts/full-stack.sh` (builds, tests, starts Authelia+Nginx+whoami+ipremember with self-signed certs).
2) In a browser, go to `https://auth.localtest.me:9091/?rd=https://app.localtest.me:8443/` (accept cert warning).
3) Log in with `holden.roci` / `race horse battery staple` (demo user; see `authelia/users.yml`). You’ll be redirected to `https://app.localtest.me:8443/`. Scripted login in `scripts/full-stack.sh` uses `naomi.roci` / `filip` as another crew user.
4) Nginx asks ipremember `/auth`; ipremember calls Authelia to verify your session, registers your IP, and returns 204. The whoami app now loads.
5) Future requests from this IP go straight through. Check `http://app.localtest.me:8080/status` — it should show `allowed:true` with TTL.
6) Stop the stack with `docker compose -f docker-compose.authelia.yml down`.
