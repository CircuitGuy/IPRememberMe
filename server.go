package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"
)

// server ties together configuration, the in-memory store, and HTTP handlers.
type server struct {
	cfg    config
	store  *store
	logger *slog.Logger
	secret []byte
	client *http.Client
}

func newServer(cfg config, store *store, logger *slog.Logger) *server {
	return &server{
		cfg:    cfg,
		store:  store,
		logger: logger,
		secret: []byte(cfg.SharedSecret),
		client: &http.Client{
			Timeout: cfg.AutheliaTimeout,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: cfg.InsecureTLS,
				},
			},
		},
	}
}

// registerRoutes wires all HTTP handlers, including the prefixed aliases the proxy can use.
func (s *server) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/auth", s.handleAuth)
	mux.HandleFunc("/remember", s.handleRemember)
	mux.HandleFunc("/admin/clear", s.handleAdminClear)
	mux.HandleFunc("/admin/list", s.handleAdminList)
	mux.HandleFunc("/admin/ui", s.handleAdminUI)
	mux.HandleFunc("/user/clear-cookie", s.handleUserClearCookie)
	mux.HandleFunc("/user", s.handleUser)
	mux.HandleFunc("/user/extend", s.handleUserExtend)

	// Prefixed aliases avoid collisions when iprememberme shares a host with other apps.
	mux.HandleFunc("/ipremember/status", s.handleStatus)
	mux.HandleFunc("/ipremember/auth", s.handleAuth)
	mux.HandleFunc("/ipremember/remember", s.handleRemember)
	mux.HandleFunc("/ipremember/admin/clear", s.handleAdminClear)
	mux.HandleFunc("/ipremember/admin/list", s.handleAdminList)
	mux.HandleFunc("/ipremember/admin/ui", s.handleAdminUI)
	mux.HandleFunc("/ipremember/user/clear-cookie", s.handleUserClearCookie)
	mux.HandleFunc("/ipremember/user", s.handleUser)
	mux.HandleFunc("/ipremember/user/extend", s.handleUserExtend)
}

func (s *server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// handleRoot renders a very small HTML view showing trust status for the caller IP.
func (s *server) handleRoot(w http.ResponseWriter, r *http.Request) {
	ip, ok := s.requireClientIP(w, r)
	if !ok {
		return
	}
	now := time.Now()
	_, cookieValid := s.maybeRefreshFromCookie(w, r, ip, now)
	e, ok := s.store.allowed(ip, now)
	ttl := time.Duration(0)
	if ok {
		ttl = time.Until(e.ExpiresAt)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if !ok {
		fmt.Fprintf(w, "<html><body><h2>Authelia IP Remember</h2><p>IP %s is <strong>not</strong> trusted.</p></body></html>", ip)
		return
	}
	if cookieValid {
		fmt.Fprintf(w, "<html><body><h2>Authelia IP Remember</h2><p>IP %s is trusted for approximately %.1f hours.</p><p>User: %s</p><p>Expires at: %s</p></body></html>", ip, ttl.Hours(), e.User, e.ExpiresAt.Format(time.RFC1123))
		return
	}
	fmt.Fprintf(w, "<html><body><h2>Authelia IP Remember</h2><p>IP %s is trusted for approximately %.1f hours.</p><p>Expires at: %s</p></body></html>", ip, ttl.Hours(), e.ExpiresAt.Format(time.RFC1123))
}

// handleStatus returns JSON describing trust state for the caller IP.
func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ip, ok := s.requireClientIP(w, r)
	if !ok {
		return
	}
	now := time.Now()
	_, cookieValid := s.maybeRefreshFromCookie(w, r, ip, now)
	e, ok := s.store.allowed(ip, now)
	resp := map[string]interface{}{
		"ip":        ip,
		"allowed":   ok,
		"user":      "",
		"expiresAt": nil,
		"ttlSeconds": func() int64 {
			if !ok {
				return 0
			}
			return int64(time.Until(e.ExpiresAt).Seconds())
		}(),
	}
	if ok {
		if cookieValid {
			resp["user"] = e.User
		}
		resp["expiresAt"] = e.ExpiresAt
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleAuth is the endpoint the proxy uses via auth_request.
// It returns 204 when an IP is trusted, optionally falls back to Authelia verification, and 401 otherwise.
func (s *server) handleAuth(w http.ResponseWriter, r *http.Request) {
	ip, ok := s.requireClientIP(w, r)
	if !ok {
		return
	}
	now := time.Now()
	_, _ = s.maybeRefreshFromCookie(w, r, ip, now)
	if _, ok := s.store.allowed(ip, now); ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if s.autheliaEnabled(r) {
		if user, ok := s.verifyWithAuthelia(r); ok {
			e, err := s.store.upsert(ip, user.user, now)
			if err == nil {
				s.setCookie(w, r, ip, e.User, e.ExpiresAt)
				w.WriteHeader(http.StatusNoContent)
				return
			}
			s.logger.Warn("authelia verified but failed to upsert", "err", err)
		}
	}

	w.WriteHeader(http.StatusUnauthorized)
}

// handleRemember registers the caller IP after a successful Authelia login.
func (s *server) handleRemember(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ip, ok := s.requireClientIP(w, r)
	if !ok {
		return
	}
	user := r.Header.Get("X-User")
	if user == "" {
		user = r.FormValue("user")
		if user == "" {
			user = "unknown"
		}
	}
	now := time.Now()
	e, err := s.store.upsert(ip, user, now)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.setCookie(w, r, ip, e.User, e.ExpiresAt)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleAdminClear(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	target := r.URL.Query().Get("ip")
	removed := s.store.clear(target)
	w.Header().Set("Content-Type", "application/json")
	if target == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if removed == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleAdminList(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	now := time.Now()
	list := s.store.list(now)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func (s *server) handleAdminUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `
<!DOCTYPE html>
<html>
<head>
  <title>IP Remember Admin</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    input, button { padding: 6px 8px; margin: 4px 0; }
    table { border-collapse: collapse; width: 100%; margin-top: 12px; }
    th, td { border: 1px solid #ccc; padding: 6px; text-align: left; }
  </style>
  <script>
    async function loadList() {
      const token = document.getElementById('token').value.trim();
      if (!token) { alert('Enter bearer token'); return; }
      const res = await fetch('/admin/list', { headers: { Authorization: 'Bearer ' + token }});
      if (!res.ok) { alert('List failed: ' + res.status); return; }
      const data = await res.json();
      const tbody = document.querySelector('#list tbody');
      tbody.innerHTML = '';
      Object.entries(data).forEach(([ip, entry]) => {
        const tr = document.createElement('tr');
        tr.innerHTML = '<td>'+ip+'</td><td>'+entry.user+'</td><td>'+entry.expiresAt+'</td>';
        const btn = document.createElement('button');
        btn.textContent = 'Clear';
        btn.onclick = () => clearIP(ip);
        const td = document.createElement('td');
        td.appendChild(btn);
        tr.appendChild(td);
        tbody.appendChild(tr);
      });
    }
    async function clearIP(ip) {
      const token = document.getElementById('token').value.trim();
      const res = await fetch('/admin/clear?ip='+encodeURIComponent(ip), { method: 'POST', headers: { Authorization: 'Bearer ' + token }});
      if (!res.ok) { alert('Clear failed: ' + res.status); return; }
      loadList();
    }
    async function clearAll() {
      const token = document.getElementById('token').value.trim();
      const res = await fetch('/admin/clear', { method: 'POST', headers: { Authorization: 'Bearer ' + token }});
      if (!res.ok) { alert('Clear failed: ' + res.status); return; }
      loadList();
    }
  </script>
</head>
<body>
  <h2>IP Remember Admin</h2>
  <label>Bearer token: <input id="token" type="password" placeholder="SHARED_SECRET"></label>
  <button onclick="loadList()">Refresh</button>
  <button onclick="clearAll()">Clear All</button>
  <table id="list">
    <thead><tr><th>IP</th><th>User</th><th>Expires</th><th>Actions</th></tr></thead>
    <tbody></tbody>
  </table>
</body>
</html>
`)
}

// handleUser serves the HTML + JSON page where end users can inspect/extend their trusted IPs.
func (s *server) handleUser(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	user, ok := s.cookieUser(w, r, now)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	currentIP, ok := s.requireClientIP(w, r)
	if !ok {
		return
	}
	raw := s.store.listByUser(now, user)
	type userEntry struct {
		IP        string    `json:"ip"`
		ExpiresAt time.Time `json:"expiresAt"`
		LastSeen  time.Time `json:"lastSeen"`
		TTL       int64     `json:"ttlSeconds"`
	}
	list := make([]userEntry, 0, len(raw))
	var currentTTL int64
	var currentExpires time.Time
	for ip, e := range raw {
		if ip == currentIP {
			currentTTL = int64(time.Until(e.ExpiresAt).Seconds())
			currentExpires = e.ExpiresAt
		}
		list = append(list, userEntry{
			IP:        ip,
			ExpiresAt: e.ExpiresAt,
			LastSeen:  e.LastSeen,
			TTL:       int64(time.Until(e.ExpiresAt).Seconds()),
		})
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].LastSeen.After(list[j].LastSeen)
	})
	if currentTTL < 0 {
		currentTTL = 0
	}

	escUser := html.EscapeString(user)
	escIP := html.EscapeString(currentIP)

	if strings.Contains(r.Header.Get("Accept"), "application/json") || r.URL.Query().Get("format") == "json" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"user":    user,
			"entries": list,
		})
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head>
  <title>IP Remember - User</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    table { border-collapse: collapse; width: 100%; margin-top: 12px; }
    th, td { border: 1px solid #ccc; padding: 6px; text-align: left; }
    button { padding: 6px 10px; }
    .status { margin-top: 10px; font-weight: 600; }
    .summary { margin: 10px 0; padding: 10px; border: 1px solid #ddd; background: #f8f8f8; }
  </style>
  <script>
    async function clearCookie() {
      const res = await fetch('/user/clear-cookie', { method: 'POST' });
      const status = document.getElementById('status');
      if (!res.ok) {
        status.textContent = 'Failed to clear cookie: ' + res.status;
        status.style.color = '#b00020';
        return;
      }
      status.textContent = 'Auth cookie cleared. Reloading...';
      status.style.color = '#0a6';
      setTimeout(() => window.location.reload(), 400);
    }
    async function extend(ip) {
      const res = await fetch('/user/extend', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'ip=' + encodeURIComponent(ip)
      });
      const status = document.getElementById('status');
      if (!res.ok) {
        status.textContent = 'Extend failed for ' + ip + ': ' + res.status;
        status.style.color = '#b00020';
        return;
      }
      const data = await res.json();
      status.textContent = 'Extended ' + ip + ' (ttlSeconds=' + data.ttlSeconds + ')';
      status.style.color = '#0a6';
      setTimeout(() => window.location.reload(), 500);
    }
  </script>
</head>
<body>
  <h2>Your trusted IPs</h2>
  <p>Cookie user: `+escUser+`</p>
  <div class="summary">
    <p>Current IP: `+escIP+`</p>
    <p>TTL: `+fmt.Sprintf("%ds", currentTTL)+` `+func() string {
		if currentTTL <= 0 {
			return "(not registered yet)"
		}
		return fmt.Sprintf("(expires %s)", currentExpires.Format(time.RFC1123))
	}()+`</p>
    <button onclick="clearCookie()">Clear auth cookie</button>
  </div>
  <table>
    <thead><tr><th>IP</th><th>TTL (s)</th><th>Expires</th><th>Last seen</th><th>Extend</th></tr></thead>
    <tbody>`)
	for _, e := range list {
		escIP := html.EscapeString(e.IP)
		fmt.Fprintf(w, "<tr><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td><button onclick=\"extend('%s')\">Extend</button></td></tr>",
			escIP, e.TTL, e.ExpiresAt.Format(time.RFC1123), e.LastSeen.Format(time.RFC1123), escIP)
	}
	fmt.Fprint(w, `</tbody>
  </table>
  <div id="status" class="status"></div>
</body>
</html>`)
}

func (s *server) handleUserExtend(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	user, ok := s.cookieUser(w, r, now)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := r.FormValue("ip")
	if ip == "" {
		http.Error(w, "ip required", http.StatusBadRequest)
		return
	}
	if _, ok := s.requireClientIP(w, r); !ok {
		return
	}
	entries := s.store.listByUser(now, user)
	if _, exists := entries[ip]; !exists {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	e, err := s.store.upsert(ip, user, now)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ip":         ip,
		"expiresAt":  e.ExpiresAt,
		"ttlSeconds": int64(time.Until(e.ExpiresAt).Seconds()),
	})
}

func (s *server) handleUserClearCookie(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) authorized(r *http.Request) bool {
	if s.cfg.SharedSecret == "" {
		return false
	}
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(h), "bearer ") {
		if strings.TrimSpace(h[7:]) == s.cfg.SharedSecret {
			return true
		}
	}
	return false
}

func (s *server) requireClientIP(w http.ResponseWriter, r *http.Request) (string, bool) {
	ip, ok := clientIP(r)
	if !ok {
		http.Error(w, "invalid X-Forwarded-For; must be single hop and set by the proxy", http.StatusBadRequest)
		return "", false
	}
	return ip, true
}

func (s *server) maybeRefreshFromCookie(w http.ResponseWriter, r *http.Request, ip string, now time.Time) (entry, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return entry{}, false
	}
	token, err := parseToken(s.secret, c.Value)
	if err != nil {
		return entry{}, false
	}
	if token.IP != ip {
		return entry{}, false
	}
	e, ok := s.store.refresh(ip, token.User, now)
	if !ok {
		return entry{}, false
	}
	s.setCookie(w, r, ip, e.User, e.ExpiresAt)
	return e, true
}

func (s *server) setCookie(w http.ResponseWriter, r *http.Request, ip, user string, expires time.Time) {
	v := signToken(s.secret, ip, user, expires)
	domain := s.cfg.CookieDomain
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    v,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
		Domain:   domain,
	})
}

func (s *server) cookieUser(w http.ResponseWriter, r *http.Request, now time.Time) (string, bool) {
	ip, ok := s.requireClientIP(w, r)
	if !ok {
		return "", false
	}
	e, ok := s.maybeRefreshFromCookie(w, r, ip, now)
	if !ok {
		return "", false
	}
	return e.User, true
}

// logging adds basic structured logs for every request.
func (s *server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ip, ok := clientIP(r)
		if !ok {
			http.Error(w, "invalid X-Forwarded-For; must be single hop", http.StatusBadRequest)
			return
		}
		lrw := &loggingResponseWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(lrw, r)
		s.logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", lrw.status,
			"ip", ip,
			"duration", time.Since(start).String(),
		)
	})
}

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.status = code
	lrw.ResponseWriter.WriteHeader(code)
}
