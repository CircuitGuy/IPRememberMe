package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const cookieName = "ipremember"

// token is the signed payload stored in the ipremember cookie.
type token struct {
	IP     string
	User   string
	Expiry time.Time
}

// signToken binds the IP/user/expiry with an HMAC so tampered cookies are rejected.
func signToken(secret []byte, ip, user string, exp time.Time) string {
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

// parseToken validates signature/expiry and returns the decoded payload.
func parseToken(secret []byte, raw string) (token, error) {
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

func clientIP(r *http.Request) (string, bool) {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		if strings.Contains(xf, ",") {
			return "", false
		}
		ip := strings.TrimSpace(xf)
		if ip != "" {
			return ip, true
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host, true
	}
	return r.RemoteAddr, true
}

func cookieDomainFromRequest(r *http.Request) string {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	if host == "" {
		return ""
	}
	if strings.Contains(host, ":") {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	return host
}
