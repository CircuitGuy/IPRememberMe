Authelia-IPRememberMe
=====================
[![CI](https://github.com/CircuitGuy/IPRememberMe/actions/workflows/ci.yml/badge.svg)](https://github.com/CircuitGuy/IPRememberMe/actions/workflows/ci.yml)
[![Container](https://img.shields.io/badge/ghcr.io-circuitguy%2Fiprememberme-blue?logo=docker)](https://ghcr.io/circuitguy/iprememberme)

What this is
------------

Lightweight sidecar that sits between your proxy (e.g., Nginx Proxy Manager) and Authelia-protected apps. After one successful Authelia login on an IP, the service marks that IP as trusted for a configurable window (default 24h). While trusted, any device on that IP can skip Authelia challenges for the protected apps. **Each touch refreshes the timer only when the signed cookie is present (cookie binds IP+user); plain IP hits do not refresh TTL.** A status page and a user page keep visibility and control simple. When `MAX_IPS_PER_USER` is exceeded, the oldest IP for that user is evicted and replaced by the new one.

Why it exists
-------------

- You want Authelia to serve as the bouncer for your publicly-exposed services without presenting a global login screen, but the clients aren't designed for that (HomeAssistant mobile app and Jellyfin on constrained clients don't handle Authelia)

Example: You use your cell phone to access a Jellyfin webpage (and authenticate through Authelia). This app adds the IP to the whitelist server-side. Now you can use your cell phone to cast to a device on that network; Chromecast rides that trust without seeing the Authelia bouncer.

Warning: IP-trust warning: Whitelisting “this IP” is a convenience. On shared IPs (NAT/VPN/carrier), you may be trusting more than one device. Keep TTLs sensible and clear the list when in doubt. Any services exposed should have their own authorization/trust system. This project is designed to be more secure than directly exposing app logins by adding a sensible protection layer.

How it works (high level)
-------------------------

1. Proxy calls `/auth` first. If the IP is already trusted and not expired, it returns 204 and the request proceeds without Authelia.
2. If the IP is not trusted, the proxy falls back to your normal Authelia forward-auth. On success, it makes a short subrequest to `/remember` (with the shared secret) to register the IP and set a signed cookie.
3. Any request carrying the signed cookie and correct IP refreshes the expiry; requests without the cookie do not refresh TTL. I.e. so the HomeAssistant or Jellyfin or similar clients can continue running for a number of hours or days, but will eventually hit the Authelia bouncer unless there is a user logging in from the web portal on that IP.
4. Clearing the allowlist (e.g., via `/admin/clear` or rerunning the demo script) removes trust immediately and invalidates cookie refresh. Even if a browser still has the `ipremember` cookie, it cannot recreate an entry once cleared; a fresh Authelia login is required.

Step-by-step demo (clone this repo and run the app as a self-contained demo)
------------------------------
Stack frontmatter (what’s running)
- `https://app.localtest.me:8443/` — app behind Nginx. Nginx calls ipremember first (`/auth`), then Authelia if needed, then proxies to the demo app (whoami). Only auth traffic flows through the sidecar; management endpoints are not exposed here.
- `https://auth.localtest.me:9091/` — Authelia UI/API (self-signed cert).
- ipremember sidecar — tracks trusted IPs, issues cookies, exposes `/status`, `/user`, and admin endpoints; reached directly on `http://localhost:8080` (not via the app host).

1) Run `./scripts/full-stack.sh` (builds, tests, starts Authelia+Nginx+whoami+ipremember with self-signed certs).
2) In a browser, visit `https://app.localtest.me:8443/`. The proxy responds with a 302 redirect to the Authelia portal at `https://auth.localtest.me:9091/?rd=https://app.localtest.me:8443/` (accept the cert warning). This mirrors a production Authelia flow where unauthorized users land on the login screen automatically.
3) Log in with `holden.roci` / `racehorse battery staple` (demo user; see `authelia/users.yml`). After login you’re bounced back to `https://app.localtest.me:8443/`. Scripted login in `scripts/full-stack.sh` uses `naomi.roci` / `filip` as another crew user.
4) Nginx asks ipremember `/auth`; ipremember calls Authelia to verify your session, registers your IP, and returns 204. The whoami app now loads.
5) Future requests from this IP go straight through. Hit `http://localhost:8080/status` to confirm `allowed:true` and see the remaining `ttlSeconds`. The `/user` page requires the `ipremember` cookie; in the demo that cookie is `Secure` + host-only for `app.localtest.me`, so a browser will **not** send it to `http://localhost:8080/user` and you’ll see 401. Either (a) grab the `ipremember` cookie from devtools and call `curl -H "Cookie: ipremember=<value>" http://localhost:8080/user?format=json` or (b) set `COOKIE_DOMAIN=localtest.me` in `.env` (demo-only) so the browser sends the cookie to localhost.
6) Stop the stack with `docker compose -f docker-compose.authelia.yml down`.
7) Debug pages: ipremember status/user/admin are at `http://localhost:8080/status`, `/user`, `/admin/ui` (bearer token required for admin). Authelia UI is at `https://auth.localtest.me:9091/`.

Hosts (if localtest.me doesn’t resolve for you)
-----------------------------------------------
- Some DNS resolvers block or rewrite loopback wildcards. If `app.localtest.me` doesn’t resolve or returns IPv6-only (::1), pin it to IPv4 loopback:
  - Windows (PowerShell as admin): `$hosts = $env:SystemRoot+'\System32\drivers\etc\hosts'; $lines = Get-Content $hosts | Where-Object {$_ -notmatch 'localtest\.me'}; $lines + @('127.0.0.1 localtest.me','127.0.0.1 app.localtest.me','127.0.0.1 auth.localtest.me') | Set-Content -Path $hosts -Encoding ascii; ipconfig /flushdns`
  - Linux: `printf '127.0.0.1 localtest.me\n127.0.0.1 app.localtest.me\n127.0.0.1 auth.localtest.me\n' | sudo tee -a /etc/hosts`
- After editing hosts:
  - Windows: command above flushes DNS; restart the browser if it cached DNS.
  - Linux: many browsers cache DNS; restart the browser or the nscd/systemd-resolved service if in use.
- Use `ping -4 app.localtest.me` or curl to confirm it hits 127.0.0.1. Run hosts edits with admin/root rights so writes succeed.

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
- `COOKIE_DOMAIN` (optional): explicitly sets the cookie domain. When unset, cookies are host-only (no Domain attribute) to avoid trusting unvalidated Host headers. Set it only when you need the cookie across subdomains you control (e.g., app.example.com and api.example.com).

Managing sessions / TTLs
------------------------
- For your own sessions, visit `/user` (or `/user?format=json`) while the cookie is valid to see your current IPs, TTLs, and last-seen timestamps; extend entries, or clear the auth cookie.
- User/admin pages include a cached city/region/country + ISP lookup for each IP (powered by ip-api.com). Private/reserved IPs skip external lookups to avoid leaking LAN details. Geolocation data by https://ip-api.com.
- To check whether the current IP is trusted and its remaining TTL, hit `/status` (user is only returned when the cookie is present for security to avoid leaking any important info to untrusted clients).
- Clearing entries via `/admin/clear` immediately removes trust even if clients still carry the cookie; the next request will redirect through Authelia before ipremember repopulates the entry.
- Admins can use `/admin/ui` with the bearer token to list and clear any IPs.

Endpoints (both root and `/ipremember/`-prefixed aliases)
---------------------------------------------------------

- `GET /healthz` — liveness probe.
- `GET /` — minimal HTML page showing remaining time and geo/ISP for this IP.
- `GET /status` (alias: `/ipremember/status`) — JSON: `{ allowed, expiresAt, ttlSeconds, ip, user, geo }` (user returned only when a valid cookie is present).
- `GET /auth` (alias: `/ipremember/auth`) — proxy check; 204 if IP allowed, else 401 (or Authelia-verified if configured).
- `POST /remember` (alias: `/ipremember/remember`) — register current IP/user; requires `Authorization: Bearer <SHARED_SECRET>`. Accepts optional `X-User` header for audit. Issues/refreshes cookie.
- `POST /admin/clear` (alias: `/ipremember/admin/clear`) — clear all or a specific IP (`ip` form value). Requires bearer token.
- `GET /admin/list` (alias: `/ipremember/admin/list`) — list current allowlist (includes geo/ISP summaries). Requires bearer token.
- `GET /admin/ui` (alias: `/ipremember/admin/ui`) — minimal HTML admin UI with per-IP geo/ISP; still requires bearer token for actions.
- `GET /user` (alias: `/ipremember/user`) — cookie-required user page or JSON showing that user’s trusted IPs, TTLs, and geo/ISP summaries.
- `POST /user/extend` (alias: `/ipremember/user/extend`) — cookie-required; refreshes TTL for an existing IP owned by the cookie user.
- `POST /user/clear-cookie` (alias: `/ipremember/user/clear-cookie`) — clears the `ipremember` cookie on the caller (does not alter the allowlist entry).
- Admin endpoints (bearer: `Authorization: Bearer $SHARED_SECRET`):
  - `GET /admin/list` — JSON map of IPs and their user/expiry/lastSeen.
  - `POST /admin/clear` — clear all or a specific IP via `ip=<addr>` (query or form).
  - `GET /admin/ui` — simple HTML that lists IPs and allows clear actions (enter the bearer token in the UI). Reachable directly (`http://localhost:8080/admin/ui`); not proxied through the demo app host.

Production setup (Nginx Proxy Manager: app.example.com / auth.example.com)
--------------------------------------------------------------------------
Hosted URLs
- `app.example.com` — your protected app(s) behind the proxy; proxy calls iprememberme `/auth` first.
- `auth.example.com` — Authelia UI/API (exposed as normal).
- `iprememberme` — sidecar service; recommended to keep internal. If you need client-visible status, proxy a path on `app.example.com` (e.g., `/ipremember/status`) to iprememberme instead of exposing a separate hostname.

1. Deploy iprememberme alongside your proxy and Authelia. Set `SHARED_SECRET` in iprememberme **and** in the proxy env (so it can call `/remember` and admin endpoints). If you want iprememberme to verify sessions via Authelia on `/auth`, set `AUTHELIA_URL=https://auth.example.com`.
2. In Nginx/NPM, add an `auth_request` to `http://iprememberme:8080/auth` before forwarding to your app. For NPM custom locations, proxy `/auth` to iprememberme and honor 204/401.
3. On successful Authelia login, have the proxy issue a subrequest to `http://iprememberme:8080/remember` with `Authorization: Bearer $SHARED_SECRET` (and optionally `X-User` for audit). This registers the IP and sets the cookie on the client.
4. Ensure the proxy owns `X-Forwarded-For` so clients cannot spoof IPs.
5. Keep management endpoints sidecar-only (do not expose via the app host); access them directly (e.g., `http://iprememberme:8080/admin/list`).
6. Cookie refresh requires the signed cookie; incognito or another browser on the same IP will not refresh TTL or see the user.
7. (Optional) Add a LAN bypass in your proxy config if you want trusted subnets to skip Authelia entirely. Use cautiously; only allow ranges you truly trust.
8. iprememberme rejects requests with multi-hop `X-Forwarded-For`; the proxy should send a single client IP and strip user-supplied headers. Cookies are host-only unless `COOKIE_DOMAIN` is set; avoid exposing the service directly to untrusted clients to prevent Host header games. For the provided `auth.localtest.me` / `app.localtest.me` demo, leave `COOKIE_DOMAIN` unset (host-only) since the cookie is issued on `app.localtest.me`.

- Set `SHARED_SECRET` as an environment variable on the NPM container so you can reference it.
- Update the `set $auth_portal ...` line in the snippet below to match your Authelia portal (e.g., `https://auth.example.com`) so unauthorized users are redirected there.
- In the proxy host for `app.example.com`, open Custom Nginx Configuration and paste (adjust service names/ports if different). Optional: add a proxied status path `/ipremember/status` that forwards internally to iprememberme if you need the banner.
Nginx Proxy Manager Config:
```
set $ipremember http://iprememberme:8080;
set $auth_portal https://auth.example.com;  # Authelia portal URL (used for redirects)

location = /ipremember-auth {
  internal;
  proxy_pass $ipremember/auth;
  proxy_pass_request_body off;
  proxy_set_header Content-Length "";
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_set_header X-Forwarded-Host $host;
  proxy_set_header X-Forwarded-URI $request_uri;
  proxy_set_header X-Original-Method $request_method;
  proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
}

location = /ipremember-remember {
  internal;
  proxy_pass $ipremember/remember;
  proxy_pass_request_body off;
  proxy_set_header Content-Length "";
  proxy_set_header Authorization "Bearer $SHARED_SECRET";
  proxy_set_header X-User $remote_user;
}

# Optional: proxy status to iprememberme without exposing a new host
location = /ipremember/status {
  internal;
  proxy_pass $ipremember/ipremember/status;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_set_header X-Forwarded-Host $host;
  proxy_set_header X-Forwarded-URI $request_uri;
  proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
}

location @authelia_portal {
  return 302 $auth_portal/?rd=$scheme://$host$request_uri;
}

# Main location with auth + Set-Cookie (and optional LAN bypass)
location / {
  satisfy any;
  allow 192.168.0.0/16;
  allow 10.0.0.0/8;
  deny all; # only reached if auth_request fails

  proxy_pass http://app-upstream.example.internal:8080; # adjust to your app
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_set_header X-Forwarded-Host $host;
  proxy_set_header X-Forwarded-URI $request_uri;

  proxy_intercept_errors on;
  error_page 401 = @authelia_portal;
  auth_request /ipremember-auth;
  auth_request_set $ipremember_cookie $upstream_http_set_cookie;
  add_header Set-Cookie $ipremember_cookie always;
}

```

- Point the app upstream to your backend as usual (replace `app-upstream.example.internal:8080`).
- Authelia stays at `auth.example.com` with your existing forward-auth/access list; ipremember only needs the `auth_request` + `/remember` hook with the shared secret.
- Authelia should be reachable at `https://auth.example.com` (or your chosen hostname). Set `AUTHELIA_URL` to that value (e.g., `AUTHELIA_URL=https://auth.example.com`) in iprememberme if you want iprememberme to verify sessions via Authelia on `/auth`. If Authelia uses a self-signed cert, set `AUTHELIA_INSECURE_SKIP_VERIFY=true`.

Use a `.env` with shared settings, e.g.:
```
# Required
SHARED_SECRET=change-me
AUTHELIA_URL=https://auth.example.com
# Service behavior
ALLOW_DURATION_HOURS=24
MAX_IPS_PER_USER=3
LOG_LEVEL=info
AUTHELIA_TIMEOUT_SECONDS=5
AUTHELIA_VERIFY=true
AUTHELIA_INSECURE_SKIP_VERIFY=false
LISTEN_ADDR=:8080
COOKIE_DOMAIN=
# Optional: publish iprememberme to host; leave unset to keep internal-only
IPREMEMBER_HOST_PORT=8080
# TZ for services (NPM/Authelia)
TZ=UTC
```
Then the Docker-Compose:
```yaml
services:
  iprememberme:
    image: ghcr.io/circuitguy/iprememberme:latest
    env_file:
      - .env  # contains SHARED_SECRET, AUTHELIA_URL, TZ
    environment:
      SHARED_SECRET: ${SHARED_SECRET}
      AUTHELIA_URL: ${AUTHELIA_URL:-}
      AUTHELIA_INSECURE_SKIP_VERIFY: "${AUTHELIA_INSECURE_SKIP_VERIFY:-false}"
      AUTHELIA_VERIFY: "${AUTHELIA_VERIFY:-true}"
      AUTHELIA_TIMEOUT_SECONDS: ${AUTHELIA_TIMEOUT_SECONDS:-5}
      ALLOW_DURATION_HOURS: ${ALLOW_DURATION_HOURS:-24}
      MAX_IPS_PER_USER: ${MAX_IPS_PER_USER:-3}
      LOG_LEVEL: ${LOG_LEVEL:-info}
      LISTEN_ADDR: ${LISTEN_ADDR:-:8080}
    ports:
      - "${IPREMEMBER_HOST_PORT:-}:8080"  # optional: publish iprememberme; leave blank to keep internal-only
    networks: [web]

  nginx-proxy-manager:
    image: jc21/nginx-proxy-manager:latest
    depends_on: [iprememberme]
    environment:
      SHARED_SECRET: ${SHARED_SECRET}
      TZ: ${TZ:-UTC}
    volumes:
      - npm-data:/data
      - npm-ssl:/etc/letsencrypt
    ports:
      - "80:80"
      - "443:443"
    networks: [web]

  authelia:
    image: authelia/authelia:latest
    environment:
      TZ: UTC
    volumes:
      - ./authelia:/config
    networks: [web]

  # app: #Replace with your app
  #  image: ...

networks:
  web:
    driver: bridge  # default; switch to host if you need host networking

volumes:
  npm-data:
  npm-ssl:
```

Client banner example (status proxied via app host)
---------------------------------------------------
If you expose iprememberme status via the app host (e.g., proxy `/ipremember/status` on `app.example.com` to the internal iprememberme `/ipremember/status`), point clients there:

```js
async function renderBanner() {
  try {
    const res = await fetch('https://app.example.com/ipremember/status', { credentials: 'include' });
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

More docs
---------
See [DEVELOPERS.md](DEVELOPERS.md) for deeper configuration, code flow, and test commands.
