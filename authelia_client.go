package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// autheliaResult captures the minimal data ipremember needs from Authelia on success.
type autheliaResult struct {
	user string
}

// autheliaEnabled returns true when the server should call Authelia for verification.
// Deployments can toggle verification via config or a per-request header.
func (s *server) autheliaEnabled(r *http.Request) bool {
	if s.cfg.AutheliaURL == "" {
		return false
	}
	enabled := s.cfg.AutheliaVerify
	if s.cfg.AutheliaAllowHeader {
		hv := strings.ToLower(strings.TrimSpace(r.Header.Get(s.cfg.AutheliaToggleHeader)))
		switch hv {
		case "on", "true", "1", "yes":
			enabled = true
		case "off", "false", "0", "no", "skip", "disabled":
			enabled = false
		}
	}
	return enabled
}

// verifyWithAuthelia forwards the caller’s cookies/headers to Authelia’s authz endpoint.
// When Authelia OKs the request, the user string is returned so ipremember can persist it.
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
	if ip, ok := clientIP(r); ok {
		req.Header.Set("X-Forwarded-For", ip)
	}

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
