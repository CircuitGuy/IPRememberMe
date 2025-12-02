package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTokenRoundTrip(t *testing.T) {
	// Happy path: token signs and parses back.
	secret := []byte("test-secret")
	exp := time.Now().Add(2 * time.Hour)
	raw := signToken(secret, "1.2.3.4", "alice", exp)
	token, err := parseToken(secret, raw)
	if err != nil {
		t.Fatalf("parseToken failed: %v", err)
	}
	if token.IP != "1.2.3.4" || token.User != "alice" {
		t.Fatalf("unexpected token values: %+v", token)
	}
}

func TestTokenRejectsBadSignature(t *testing.T) {
	// Corrupted token should fail signature validation.
	secret := []byte("secret")
	exp := time.Now().Add(time.Hour)
	raw := signToken(secret, "1.2.3.4", "bob", exp)
	raw += "corrupt"
	if _, err := parseToken(secret, raw); err == nil {
		t.Fatalf("expected signature error")
	}
}

func TestStoreEvictsOldestAtLimit(t *testing.T) {
	// With max 1 per user, adding a second IP evicts the oldest instead of erroring.
	s := newStore(time.Hour, 1)
	now := time.Now()
	if _, err := s.upsert("1.1.1.1", "a", now); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if _, err := s.upsert("2.2.2.2", "a", now.Add(10*time.Minute)); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if _, ok := s.allowed("1.1.1.1", now.Add(20*time.Minute)); ok {
		t.Fatalf("expected oldest IP to be evicted")
	}
	if _, ok := s.allowed("2.2.2.2", now.Add(20*time.Minute)); !ok {
		t.Fatalf("expected newest IP to remain")
	}
	// Different user still allowed independently.
	if _, err := s.upsert("3.3.3.3", "b", now); err != nil {
		t.Fatalf("unexpected err for other user: %v", err)
	}
}

func TestStoreEvictsOldestByLastSeen(t *testing.T) {
	s := newStore(time.Hour, 2)
	start := time.Now()
	if _, err := s.upsert("1.1.1.1", "alice", start); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if _, err := s.upsert("2.2.2.2", "alice", start.Add(5*time.Minute)); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	// Refresh first IP to bump its LastSeen.
	if _, err := s.upsert("1.1.1.1", "alice", start.Add(10*time.Minute)); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	// Add third; should evict 2.2.2.2 (oldest LastSeen) not 1.1.1.1.
	if _, err := s.upsert("3.3.3.3", "alice", start.Add(15*time.Minute)); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if _, ok := s.allowed("2.2.2.2", start.Add(20*time.Minute)); ok {
		t.Fatalf("expected middle IP to be evicted")
	}
	if _, ok := s.allowed("1.1.1.1", start.Add(20*time.Minute)); !ok {
		t.Fatalf("expected refreshed IP to remain")
	}
	if _, ok := s.allowed("3.3.3.3", start.Add(20*time.Minute)); !ok {
		t.Fatalf("expected new IP to be present")
	}
}

func TestAutheliaEnabledToggle(t *testing.T) {
	s := &server{
		cfg: config{
			AutheliaURL:          "http://auth",
			AutheliaVerify:       true,
			AutheliaAllowHeader:  true,
			AutheliaToggleHeader: "X-Toggle",
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if !s.autheliaEnabled(req) {
		t.Fatalf("expected authelia enabled by default")
	}
	req.Header.Set("X-Toggle", "off")
	if s.autheliaEnabled(req) {
		t.Fatalf("expected authelia disabled via header")
	}
	req.Header.Set("X-Toggle", "on")
	if !s.autheliaEnabled(req) {
		t.Fatalf("expected authelia enabled via header override")
	}

	// When disabled globally, header can re-enable.
	s.cfg.AutheliaVerify = false
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	if s.autheliaEnabled(req2) {
		t.Fatalf("expected disabled when verify=false and no header")
	}
	req2.Header.Set("X-Toggle", "on")
	if !s.autheliaEnabled(req2) {
		t.Fatalf("expected header to enable authelia when globally off")
	}
}

func newTestServer(t *testing.T) *server {
	t.Helper()
	cfg := config{
		SharedSecret:    "secret",
		Duration:        time.Hour,
		MaxIPsPerUser:   3,
		AutheliaTimeout: 5 * time.Second,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
	return newServer(cfg, newStore(cfg.Duration, cfg.MaxIPsPerUser), logger)
}

func TestStatusHidesUserWithoutCookie(t *testing.T) {
	s := newTestServer(t)
	now := time.Now()
	if _, err := s.store.upsert("1.2.3.4", "alice", now); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rr := httptest.NewRecorder()
	s.handleStatus(rr, req)

	var resp struct {
		Allowed   bool        `json:"allowed"`
		User      string      `json:"user"`
		ExpiresAt interface{} `json:"expiresAt"`
		TTL       int64       `json:"ttlSeconds"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if !resp.Allowed {
		t.Fatalf("expected allowed true")
	}
	if resp.User != "" {
		t.Fatalf("expected user to be hidden without cookie, got %q", resp.User)
	}
	if resp.TTL <= 0 {
		t.Fatalf("expected ttlSeconds > 0")
	}
}

func TestStatusShowsUserWithCookie(t *testing.T) {
	s := newTestServer(t)
	now := time.Now()
	entry, err := s.store.upsert("1.2.3.4", "alice", now)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	token := signToken([]byte(s.cfg.SharedSecret), "1.2.3.4", "alice", entry.ExpiresAt)

	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.RemoteAddr = "1.2.3.4:9999"
	req.Header.Set("Cookie", cookieName+"="+token)
	rr := httptest.NewRecorder()
	s.handleStatus(rr, req)

	var resp struct {
		Allowed bool   `json:"allowed"`
		User    string `json:"user"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if !resp.Allowed {
		t.Fatalf("expected allowed true")
	}
	if resp.User != "alice" {
		t.Fatalf("expected user to be returned with cookie, got %q", resp.User)
	}
}

func TestUserPageRequiresCookie(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/user", nil)
	req.RemoteAddr = "1.1.1.1:1234"
	rr := httptest.NewRecorder()
	s.handleUser(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestUserPageJsonWithCookie(t *testing.T) {
	s := newTestServer(t)
	now := time.Now()
	if _, err := s.store.upsert("1.1.1.1", "alice", now); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if _, err := s.store.upsert("2.2.2.2", "alice", now.Add(-10*time.Minute)); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	token := signToken([]byte(s.cfg.SharedSecret), "1.1.1.1", "alice", now.Add(time.Hour))

	req := httptest.NewRequest(http.MethodGet, "/user", nil)
	req.RemoteAddr = "1.1.1.1:9999"
	req.Header.Set("Cookie", cookieName+"="+token)
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	s.handleUser(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp struct {
		User    string `json:"user"`
		Entries []struct {
			IP        string `json:"ip"`
			TTL       int64  `json:"ttlSeconds"`
			ExpiresAt string `json:"expiresAt"`
		} `json:"entries"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if resp.User != "alice" {
		t.Fatalf("expected user alice, got %s", resp.User)
	}
	if len(resp.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(resp.Entries))
	}
	for _, e := range resp.Entries {
		if e.TTL <= 0 {
			t.Fatalf("expected ttlSeconds > 0 for %s", e.IP)
		}
	}
}

func TestUserExtendRefreshesTTL(t *testing.T) {
	s := newTestServer(t)
	start := time.Now()
	if _, err := s.store.upsert("1.1.1.1", "alice", start); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if _, err := s.store.upsert("2.2.2.2", "alice", start.Add(-30*time.Minute)); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	beforeEntry, ok := s.store.allowed("2.2.2.2", time.Now())
	if !ok {
		t.Fatalf("expected IP present")
	}
	beforeTTL := time.Until(beforeEntry.ExpiresAt)

	token := signToken([]byte(s.cfg.SharedSecret), "1.1.1.1", "alice", start.Add(time.Hour))
	form := url.Values{"ip": {"2.2.2.2"}}
	req := httptest.NewRequest(http.MethodPost, "/user/extend", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", cookieName+"="+token)
	req.RemoteAddr = "1.1.1.1:9999"
	rr := httptest.NewRecorder()
	s.handleUserExtend(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	afterEntry, ok := s.store.allowed("2.2.2.2", time.Now())
	if !ok {
		t.Fatalf("expected IP present after extend")
	}
	afterTTL := time.Until(afterEntry.ExpiresAt)
	if afterTTL <= beforeTTL {
		t.Fatalf("expected ttl to increase, before=%s after=%s", beforeTTL, afterTTL)
	}
}

func TestSetCookieUsesForwardedHost(t *testing.T) {
	s := newTestServer(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/dummy", nil)
	req.Host = "app.localtest.me:8443"
	req.Header.Set("X-Forwarded-Host", "app.localtest.me:8443")
	s.setCookie(rr, req, "1.1.1.1", "alice", time.Now().Add(time.Hour))
	var found *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == cookieName {
			found = c
			break
		}
	}
	if found == nil {
		t.Fatalf("expected cookie to be set")
	}
	if found.Domain != "app.localtest.me" {
		t.Fatalf("expected domain app.localtest.me, got %q", found.Domain)
	}
}

func TestUserRequiresCookieEvenWhenAllowedIP(t *testing.T) {
	s := newTestServer(t)
	now := time.Now()
	if _, err := s.store.upsert("1.1.1.1", "alice", now); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/user", nil)
	req.RemoteAddr = "1.1.1.1:1234"
	req.Host = "app.localtest.me:8443"
	req.Header.Set("X-Forwarded-For", "1.1.1.1")
	rr := httptest.NewRecorder()
	s.handleUser(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without cookie, got %d", rr.Code)
	}
}

func TestUserClearCookie(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/user/clear-cookie", nil)
	rr := httptest.NewRecorder()
	s.handleUserClearCookie(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
	found := false
	for _, c := range rr.Result().Cookies() {
		if c.Name == cookieName {
			found = true
			if c.MaxAge != -1 {
				t.Fatalf("expected MaxAge -1, got %d", c.MaxAge)
			}
			if !c.Expires.Before(time.Now().Add(1 * time.Second)) {
				t.Fatalf("expected expired cookie, got %s", c.Expires)
			}
		}
	}
	if !found {
		t.Fatalf("expected ipremember cookie to be cleared")
	}
}

func TestAdminEndpointsAuthorized(t *testing.T) {
	s := newTestServer(t)
	// Seed entries
	now := time.Now()
	if _, err := s.store.upsert("1.2.3.4", "alice", now); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if _, err := s.store.upsert("5.6.7.8", "bob", now); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	// Unauthorized list
	req := httptest.NewRequest(http.MethodGet, "/admin/list", nil)
	rr := httptest.NewRecorder()
	s.handleAdminList(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing bearer, got %d", rr.Code)
	}

	// Authorized list
	reqAuth := httptest.NewRequest(http.MethodGet, "/admin/list", nil)
	reqAuth.Header.Set("Authorization", "Bearer "+s.cfg.SharedSecret)
	rrAuth := httptest.NewRecorder()
	s.handleAdminList(rrAuth, reqAuth)
	if rrAuth.Code != http.StatusOK {
		t.Fatalf("expected 200 for authorized list, got %d", rrAuth.Code)
	}
	var listed map[string]entry
	if err := json.NewDecoder(rrAuth.Body).Decode(&listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(listed))
	}

	// Authorized clear single IP
	reqClear := httptest.NewRequest(http.MethodPost, "/admin/clear?ip=1.2.3.4", nil)
	reqClear.Header.Set("Authorization", "Bearer "+s.cfg.SharedSecret)
	rrClear := httptest.NewRecorder()
	s.handleAdminClear(rrClear, reqClear)
	if rrClear.Code != http.StatusNoContent {
		t.Fatalf("expected 204 clearing single IP, got %d", rrClear.Code)
	}
	if _, ok := s.store.allowed("1.2.3.4", time.Now()); ok {
		t.Fatalf("expected IP to be cleared")
	}

	// Clear all (authorized)
	reqClearAll := httptest.NewRequest(http.MethodPost, "/admin/clear", nil)
	reqClearAll.Header.Set("Authorization", "Bearer "+s.cfg.SharedSecret)
	rrClearAll := httptest.NewRecorder()
	s.handleAdminClear(rrClearAll, reqClearAll)
	if rrClearAll.Code != http.StatusNoContent {
		t.Fatalf("expected 204 clearing all, got %d", rrClearAll.Code)
	}
	if _, ok := s.store.allowed("5.6.7.8", time.Now()); ok {
		t.Fatalf("expected all IPs cleared")
	}

	// Unauthorized clear should fail
	reqClearBad := httptest.NewRequest(http.MethodPost, "/admin/clear", nil)
	rrClearBad := httptest.NewRecorder()
	s.handleAdminClear(rrClearBad, reqClearBad)
	if rrClearBad.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthorized clear, got %d", rrClearBad.Code)
	}
}

func TestBenchmarkScriptRuns(t *testing.T) {
	// Spin up a tiny HTTP server that always 200s so the benchmark script
	// has a reachable target without relying on external services.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	script := filepath.Join("scripts", "benchmark.sh")

	cmd := exec.Command(script)
	cmd.Env = append(cmd.Env,
		"DIRECT_URL="+srv.URL,
		"IPREMEMBER_URL="+srv.URL,
		"REQUESTS=3",
		"AUTO_START=0",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("benchmark script failed: %v\noutput:\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "DIRECT:") || !strings.Contains(string(out), "IPREMEMBER:") {
		t.Fatalf("expected benchmark output labels, got:\n%s", string(out))
	}
}
