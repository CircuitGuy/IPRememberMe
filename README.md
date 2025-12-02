Authelia-IPRememberMe
=====================
[![CI](https://github.com/CircuitGuy/IPRememberMe/actions/workflows/ci.yml/badge.svg)](https://github.com/CircuitGuy/IPRememberMe/actions/workflows/ci.yml)
[![Container](https://img.shields.io/badge/ghcr.io-circuitguy%2Fiprememberme-blue?logo=docker)](https://ghcr.io/circuitguy/iprememberme)

What this is
------------

Lightweight sidecar that sits between your proxy (e.g., Nginx Proxy Manager) and Authelia-protected apps. After one successful Authelia login on an IP, the service marks that IP as trusted for a configurable window (default 24h). While trusted, any device on that IP can skip Authelia challenges for the protected apps. Each touch refreshes the timer. A status page and a user page keep visibility and control simple. When `MAX_IPS_PER_USER` is exceeded, the oldest IP for that user is evicted and replaced by the new one.

Why it exists
-------------

- HomeAssistant mobile app and Jellyfin on constrained clients don’t handle repeated Authelia redirects well.
- You want to log in once (per network), then let other devices on that IP pass through for a while.
- You still want visibility, limits, and the ability to clear/expire IPs quickly.
- IP-trust warning: Whitelisting “this IP” is a convenience. On shared IPs (NAT/VPN/carrier), you may be trusting more than one device. Keep TTLs sensible and clear the list when in doubt.
- Compared to exposing app logins directly, this narrows the attack surface to a bounded set of trusted IPs while keeping user friction low. Example: phone authenticates and adds the IP; Chromecast rides that trust without handling Authelia itself.

How it works (high level)
-------------------------

1. Proxy calls `/auth` first. If the IP is already trusted and not expired, it returns 204 and the request proceeds without Authelia.
2. If the IP is not trusted, the proxy falls back to your normal Authelia forward-auth. On success, it makes a short subrequest to `/remember` (with the shared secret) to register the IP and set a signed cookie.
3. Any request carrying the signed cookie and correct IP refreshes the expiry.
4. `/` and `/status` show “this IP” remaining time; admin endpoints allow clearing the list; `/user` shows and extends a user’s IPs when a valid cookie is present.

Configuration (env)
-------------------

- `SHARED_SECRET` (required): bearer token for admin/remember endpoints and cookie signing.
- `ALLOW_DURATION_HOURS` (default `24`): TTL for each IP.
- `MAX_IPS_PER_USER` (default `3`): cap on distinct IPs per user; new additions evict the oldest IP for that user.
- `LISTEN_ADDR` (default `:8080`): listen address.
- `LOG_LEVEL` (default `info`): `debug|info|warn|error`.
- `AUTHELIA_URL` (optional): if set, `/auth` will fall back to Authelia’s `/api/authz/auth-request` using the incoming cookies/headers and auto-register the IP on success.
- `AUTHELIA_INSECURE_SKIP_VERIFY` (default `false`): allow self-signed TLS when talking to Authelia.
- `AUTHELIA_VERIFY`, `AUTHELIA_ALLOW_HEADER_TOGGLE`, `AUTHELIA_TOGGLE_HEADER`, `AUTHELIA_TIMEOUT_SECONDS`: control Authelia verification and timeouts.

Endpoints
---------

- `GET /healthz` — liveness probe.
- `GET /` — minimal HTML page showing remaining time for this IP.
- `GET /status` — JSON: `{ allowed, expiresAt, ttlSeconds, ip, user }` (user returned only when a valid cookie is present).
- `GET /auth` — proxy check; 204 if IP allowed, else 401 (or Authelia-verified if configured).
- `POST /remember` — register current IP/user; requires `Authorization: Bearer <SHARED_SECRET>`. Accepts optional `X-User` header for audit. Issues/refreshes cookie.
- `POST /admin/clear` — clear all or a specific IP (`ip` form value). Requires bearer token.
- `GET /admin/list` — list current allowlist. Requires bearer token.
- `GET /admin/ui` — minimal HTML admin UI; still requires bearer token for actions.
- `GET /user` — cookie-required user page or JSON showing that user’s trusted IPs and TTLs.
- `POST /user/extend` — cookie-required; refreshes TTL for an existing IP owned by the cookie user.

Banner example (HomeAssistant/Jellyfin)
---------------------------------------

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

Docker (compose example)
------------------------

```yaml
services:
  ipremember:
    image: ghcr.io/circuitguy/iprememberme:latest
    ports:
      - "8080:8080"
    environment:
      SHARED_SECRET: changeme
      ALLOW_DURATION_HOURS: 24
      MAX_IPS_PER_USER: 3
      LOG_LEVEL: info
```

Quick demos
-----------
- Dev stack (ipremember only): `./scripts/dev-stack.sh` then hit `http://localhost:8080/status` (or `/`/`/auth`); stop with `docker compose -f docker-compose.dev.yml down`.
- Full stack (Authelia + Nginx + whoami + ipremember): `./scripts/full-stack.sh` (self-signed certs). ipremember direct: `http://localhost:8080/status`. App via Nginx: `https://app.localtest.me:8443/` (`-k` for curl).
- Benchmark: `./scripts/benchmark.sh` (curl-based; defaults to HTTPS health checks on Authelia and ipremember, prints median/stddev comparison and elapsed time ~15–40s). Fails if targets are unreachable (no stubs).

Images & install
----------------
- CI publishes a multi-arch (amd64 + arm64) image to `ghcr.io/circuitguy/iprememberme` with tags for `latest`, default-branch heads, tags, and SHAs. If GitHub Packages ever shows `unknown/unknown`, rebuild with buildx to refresh metadata.
- GitHub Packages links back to this README for setup/env/compose examples; use the stack scripts for local runs and CI-built tags for deployments.

Step-by-step demo (full stack)
------------------------------
1) Run `./scripts/full-stack.sh` (builds, tests, starts Authelia+Nginx+whoami+ipremember with self-signed certs).
2) In a browser, go to `https://auth.localtest.me:9091/?rd=https://app.localtest.me:8443/` (accept cert warning).
3) Log in with `holden.roci` / `race horse battery staple` (demo user; see `authelia/users.yml`). You’ll be redirected to `https://app.localtest.me:8443/`. Scripted login in `scripts/full-stack.sh` uses `naomi.roci` / `filip` as another crew user.
4) Nginx asks ipremember `/auth`; ipremember calls Authelia to verify your session, registers your IP, and returns 204. The whoami app now loads.
5) Future requests from this IP go straight through. Check `https://app.localtest.me:8443/user` while the cookie is valid to see/extend your IPs, or hit `https://app.localtest.me:8443/status` to view TTL (user omitted without a cookie).
6) Stop the stack with `docker compose -f docker-compose.authelia.yml down`.

Hosts (if localtest.me doesn’t resolve for you)
-----------------------------------------------
- Some DNS resolvers block or rewrite loopback wildcards. If `app.localtest.me` doesn’t resolve or returns IPv6-only (::1), pin it to IPv4 loopback:
  - Windows (PowerShell as admin): `$hosts = $env:SystemRoot+'\System32\drivers\etc\hosts'; $lines = Get-Content $hosts | Where-Object {$_ -notmatch 'localtest\.me'}; $lines + @('127.0.0.1 localtest.me','127.0.0.1 app.localtest.me','127.0.0.1 auth.localtest.me') | Set-Content -Path $hosts -Encoding ascii; ipconfig /flushdns`
  - Linux: `printf '127.0.0.1 localtest.me\n127.0.0.1 app.localtest.me\n127.0.0.1 auth.localtest.me\n' | sudo tee -a /etc/hosts`
- After editing hosts:
  - Windows: command above flushes DNS; restart the browser if it cached DNS.
  - Linux: many browsers cache DNS; restart the browser or the nscd/systemd-resolved service if in use.
- Use `ping -4 app.localtest.me` or curl to confirm it hits 127.0.0.1. Run hosts edits with admin/root rights so writes succeed.

More docs
---------
See `DEVELOPERS.md` for deeper configuration, code flow, banners, compose examples, and test commands.
