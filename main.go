// Package main implements a lightweight IP remember/bypass service for Authelia setups.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const cookieName = "ipremember"

type config struct {
	SharedSecret  string
	Duration      time.Duration
	MaxIPsPerUser int
	ListenAddr    string
	LogLevel      slog.Level
	AutheliaURL   string
	InsecureTLS   bool
}

type entry struct {
	User      string    `json:"user"`
	ExpiresAt time.Time `json:"expiresAt"`
	LastSeen  time.Time `json:"lastSeen"`
}

type store struct {
	mu         sync.Mutex
	entries    map[string]entry
	duration   time.Duration
	maxPerUser int
}

var errLimit = errors.New("ip limit reached")

func newStore(duration time.Duration, maxPerUser int) *store {
	return &store{
		entries:    make(map[string]entry),
		duration:   duration,
		maxPerUser: maxPerUser,
	}
}

func (s *store) pruneLocked(now time.Time) {
	for ip, e := range s.entries {
		if now.After(e.ExpiresAt) {
			delete(s.entries, ip)
		}
	}
}

func (s *store) allowed(ip string, now time.Time) (entry, bool) {
	// Fast check for an IP; removes expired entries first.
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	e, ok := s.entries[ip]
	return e, ok
}

func (s *store) upsert(ip, user string, now time.Time) (entry, error) {
	// Registers or refreshes an IP entry; enforces the max capacity on new IPs.
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)

	if existing, exists := s.entries[ip]; exists {
		// Refresh existing IP regardless of count.
		existing.ExpiresAt = now.Add(s.duration)
		existing.LastSeen = now
		existing.User = user
		s.entries[ip] = existing
		return existing, nil
	}

	// Count existing IPs for this user before adding.
	count := 0
	for _, e := range s.entries {
		if e.User == user {
			count++
		}
	}
	if count >= s.maxPerUser {
		return entry{}, errLimit
	}
	e := entry{
		User:      user,
		ExpiresAt: now.Add(s.duration),
		LastSeen:  now,
	}
	s.entries[ip] = e
	return e, nil
}

func (s *store) clear(ip string) int {
	// Clears either a single IP or all entries.
	s.mu.Lock()
	defer s.mu.Unlock()
	if ip == "" {
		count := len(s.entries)
		s.entries = make(map[string]entry)
		return count
	}
	if _, ok := s.entries[ip]; ok {
		delete(s.entries, ip)
		return 1
	}
	return 0
}

func (s *store) list(now time.Time) map[string]entry {
	// Returns a snapshot copy of the allowlist with expired entries removed.
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	out := make(map[string]entry, len(s.entries))
	for k, v := range s.entries {
		out[k] = v
	}
	return out
}

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
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: cfg.InsecureTLS,
				},
			},
		},
	}
}

func main() {
	cfg := loadConfig()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	s := newServer(cfg, newStore(cfg.Duration, cfg.MaxIPsPerUser), logger)

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/auth", s.handleAuth)
	mux.HandleFunc("/remember", s.handleRemember)
	mux.HandleFunc("/admin/clear", s.handleAdminClear)
	mux.HandleFunc("/admin/list", s.handleAdminList)
	mux.HandleFunc("/admin/ui", s.handleAdminUI)

	logger.Info("starting server", "addr", cfg.ListenAddr, "duration", cfg.Duration.String(), "maxIPsPerUser", cfg.MaxIPsPerUser)
	if err := http.ListenAndServe(cfg.ListenAddr, s.logging(mux)); err != nil {
		logger.Error("server exited", "err", err)
		os.Exit(1)
	}
}

func loadConfig() config {
	durationHours := getenvInt("ALLOW_DURATION_HOURS", 24)
	maxIPsPerUser := getenvInt("MAX_IPS_PER_USER", 3)
	level := slog.LevelInfo
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	return config{
		SharedSecret:  os.Getenv("SHARED_SECRET"),
		Duration:      time.Duration(durationHours) * time.Hour,
		MaxIPsPerUser: maxIPsPerUser,
		ListenAddr:    getenv("LISTEN_ADDR", ":8080"),
		LogLevel:      level,
		AutheliaURL:   os.Getenv("AUTHELIA_URL"),
		InsecureTLS:   getenvBool("AUTHELIA_INSECURE_SKIP_VERIFY", false),
	}
}

func (s *server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *server) handleRoot(w http.ResponseWriter, r *http.Request) {
	// Minimal HTML page showing whether the caller IP is trusted and for how long.
	ip := clientIP(r)
	now := time.Now()
	s.maybeRefreshFromCookie(w, r, ip, now)
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
	fmt.Fprintf(w, "<html><body><h2>Authelia IP Remember</h2><p>IP %s is trusted for approximately %.1f hours.</p><p>User: %s</p><p>Expires at: %s</p></body></html>", ip, ttl.Hours(), e.User, e.ExpiresAt.Format(time.RFC1123))
}

func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	// JSON status for the caller IP; attempts a refresh if cookie is present.
	ip := clientIP(r)
	now := time.Now()
	s.maybeRefreshFromCookie(w, r, ip, now)
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
		resp["user"] = e.User
		resp["expiresAt"] = e.ExpiresAt
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *server) handleAuth(w http.ResponseWriter, r *http.Request) {
	// Endpoint intended for proxy auth_request checks. Returns 204 when allowed.
	ip := clientIP(r)
	now := time.Now()
	s.maybeRefreshFromCookie(w, r, ip, now)
	if _, ok := s.store.allowed(ip, now); ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// If not yet allowed, try Authelia verification when configured.
	if s.cfg.AutheliaURL != "" {
		if user, ok := s.verifyWithAuthelia(r); ok {
			e, err := s.store.upsert(ip, user.user, now)
			if err == nil {
				s.setCookie(w, ip, e.User, e.ExpiresAt)
				w.WriteHeader(http.StatusNoContent)
				return
			}
			s.logger.Warn("authelia verified but failed to upsert", "err", err)
		}
	}

	w.WriteHeader(http.StatusUnauthorized)
}

func (s *server) handleRemember(w http.ResponseWriter, r *http.Request) {
	// Registers the caller IP after successful Authelia; requires shared secret.
	if !s.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ip := clientIP(r)
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
		if errors.Is(err, errLimit) {
			http.Error(w, "max ip limit reached", http.StatusConflict)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.setCookie(w, ip, e.User, e.ExpiresAt)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleAdminClear(w http.ResponseWriter, r *http.Request) {
	// Admin endpoint to clear all or a specific IP; protected by shared secret.
	if !s.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	target := r.URL.Query().Get("ip")
	removed := s.store.clear(target)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"removed": removed})
}

func (s *server) handleAdminList(w http.ResponseWriter, r *http.Request) {
	// Admin endpoint returning the current allowlist; protected by shared secret.
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
	// Lightweight HTML UI to view and clear allowlist. Actual API calls still require the bearer token.
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

func (s *server) authorized(r *http.Request) bool {
	// Simple bearer check using the shared secret; avoids work when unset.
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

func (s *server) maybeRefreshFromCookie(w http.ResponseWriter, r *http.Request, ip string, now time.Time) {
	// If a valid signed cookie is present for this IP, refresh the entry and cookie.
	c, err := r.Cookie(cookieName)
	if err != nil {
		return
	}
	token, err := parseToken(s.secret, c.Value)
	if err != nil {
		return
	}
	if token.IP != ip {
		return
	}
	e, err := s.store.upsert(ip, token.User, now)
	if err != nil {
		return
	}
	s.setCookie(w, ip, e.User, e.ExpiresAt)
}

func (s *server) setCookie(w http.ResponseWriter, ip, user string, expires time.Time) {
	// Issues an HttpOnly, secure cookie binding the IP/user/expiry.
	v := signToken(s.secret, ip, user, expires)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    v,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	})
}

type token struct {
	IP     string
	User   string
	Expiry time.Time
}

func signToken(secret []byte, ip, user string, exp time.Time) string {
	// Compact token: v1|ip|expUnix|base64(user)|hex(hmac).
	data := strings.Join([]string{
		ip,
		strconv.FormatInt(exp.Unix(), 10),
		base64.RawURLEncoding.EncodeToString([]byte(user)),
	}, "|")
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(data))
	sig := hex.EncodeToString(mac.Sum(nil))
	return strings.Join([]string{"v1", data, sig}, "|")
}

func parseToken(secret []byte, raw string) (token, error) {
	// Validates and parses a token; rejects bad signatures or expired tokens.
	parts := strings.Split(raw, "|")
	if len(parts) != 5 || parts[0] != "v1" {
		return token{}, errors.New("invalid token format")
	}
	data := strings.Join(parts[1:4], "|")
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(data))
	if !hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(parts[4])) {
		return token{}, errors.New("signature mismatch")
	}
	expUnix, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return token{}, errors.New("invalid expiry")
	}
	userBytes, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return token{}, errors.New("invalid user encoding")
	}
	exp := time.Unix(expUnix, 0)
	if time.Now().After(exp) {
		return token{}, errors.New("token expired")
	}
	return token{IP: parts[1], User: string(userBytes), Expiry: exp}, nil
}

func clientIP(r *http.Request) string {
	// Trusts the first X-Forwarded-For entry if present; otherwise remote addr.
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		if comma := strings.Index(xf, ","); comma != -1 {
			return strings.TrimSpace(xf[:comma])
		}
		return strings.TrimSpace(xf)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

type autheliaResult struct {
	user string
}

func (s *server) verifyWithAuthelia(r *http.Request) (autheliaResult, bool) {
	if s.cfg.AutheliaURL == "" {
		return autheliaResult{}, false
	}

	u, err := url.Parse(s.cfg.AutheliaURL)
	if err != nil {
		s.logger.Warn("invalid authelia url", "err", err)
		return autheliaResult{}, false
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/api/authz/auth-request"

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		s.logger.Warn("failed to build authelia request", "err", err)
		return autheliaResult{}, false
	}

	origURL := r.Header.Get("X-Original-URL")
	if origURL == "" {
		origURL = fmt.Sprintf("%s://%s%s", schemeFromRequest(r), r.Host, r.RequestURI)
	}
	req.Header.Set("X-Original-URL", origURL)
	req.Header.Set("X-Original-Method", r.Header.Get("X-Original-Method"))
	if req.Header.Get("X-Original-Method") == "" {
		req.Header.Set("X-Original-Method", r.Method)
	}
	req.Header.Set("X-Forwarded-Proto", r.Header.Get("X-Forwarded-Proto"))
	req.Header.Set("X-Forwarded-Host", r.Header.Get("X-Forwarded-Host"))
	req.Header.Set("X-Forwarded-URI", r.Header.Get("X-Forwarded-URI"))

	if c := r.Header.Get("Cookie"); c != "" {
		req.Header.Set("Cookie", c)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		s.logger.Debug("authelia verify failed", "err", err)
		return autheliaResult{}, false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		user := resp.Header.Get("Remote-User")
		if user == "" {
			user = "authelia"
		}
		return autheliaResult{user: user}, true
	}
	s.logger.Debug("authelia denied", "status", resp.StatusCode)
	return autheliaResult{}, false
}

func schemeFromRequest(r *http.Request) string {
	if r.Header.Get("X-Forwarded-Proto") != "" {
		return r.Header.Get("X-Forwarded-Proto")
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func getenv(key, def string) string {
	val := os.Getenv(key)
	if val == "" {
		return def
	}
	return val
}

func getenvBool(key string, def bool) bool {
	val := strings.ToLower(os.Getenv(key))
	if val == "" {
		return def
	}
	return val == "1" || val == "true" || val == "yes" || val == "on"
}

func getenvInt(key string, def int) int {
	val := os.Getenv(key)
	if val == "" {
		return def
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return def
	}
	return n
}

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.status = code
	lrw.ResponseWriter.WriteHeader(code)
}

func (s *server) logging(next http.Handler) http.Handler {
	// Middleware for structured request logging.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ip := clientIP(r)
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
