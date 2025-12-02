package main

import (
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

func TestStoreLimit(t *testing.T) {
	// Enforce MAX_IPS_PER_USER but allow refresh for existing IP.
	s := newStore(time.Hour, 1)
	now := time.Now()
	if _, err := s.upsert("1.1.1.1", "a", now); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	// Second IP for same user should fail at limit 1.
	if _, err := s.upsert("2.2.2.2", "a", now); err == nil {
		t.Fatalf("expected limit error for same user")
	}
	// Existing IP can be refreshed even when at limit.
	if _, err := s.upsert("1.1.1.1", "a", now.Add(10*time.Minute)); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	// Different user still allowed.
	if _, err := s.upsert("2.2.2.2", "b", now); err != nil {
		t.Fatalf("unexpected err for other user: %v", err)
	}
}

func TestStoreLimitPerUser(t *testing.T) {
	s := newStore(time.Hour, 2)
	now := time.Now()
	if _, err := s.upsert("1.1.1.1", "alice", now); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if _, err := s.upsert("2.2.2.2", "alice", now); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if _, err := s.upsert("3.3.3.3", "alice", now); err == nil {
		t.Fatalf("expected limit error for same user")
	}
	// Different user can still register.
	if _, err := s.upsert("4.4.4.4", "bob", now); err != nil {
		t.Fatalf("unexpected err for other user: %v", err)
	}
}
