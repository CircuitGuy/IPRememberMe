package main

import (
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

func TestGeoResolverSkipsPrivateWithoutFetch(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
	resolver := newGeoResolver(logger)
	calls := 0
	resolver.fetch = func(_ *http.Client, ip string) (geoInfo, bool) {
		calls++
		return geoInfo{City: "Test City", Country: "TC", ISP: "ISP"}, true
	}
	info := resolver.Lookup("192.168.1.10")
	if calls != 0 {
		t.Fatalf("expected fetch not to run for private IP, got %d", calls)
	}
	if !strings.Contains(strings.ToLower(info.Summary), "private") {
		t.Fatalf("expected private summary, got %q", info.Summary)
	}
}

func TestGeoResolverCachesLookups(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
	resolver := newGeoResolver(logger)
	calls := 0
	resolver.fetch = func(_ *http.Client, ip string) (geoInfo, bool) {
		calls++
		return geoInfo{City: "Austin", Country: "USA", ISP: "Test ISP"}, true
	}
	first := resolver.Lookup("8.8.8.8")
	second := resolver.Lookup("8.8.8.8")
	if calls != 1 {
		t.Fatalf("expected single fetch call with caching, got %d", calls)
	}
	if first.Summary == "" || second.Summary != first.Summary {
		t.Fatalf("expected cached summary to match, first=%q second=%q", first.Summary, second.Summary)
	}
}
