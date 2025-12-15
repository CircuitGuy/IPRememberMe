package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// geoInfo captures a best-effort location/ISP lookup for an IP address.
type geoInfo struct {
	Summary string `json:"summary"`
	City    string `json:"city,omitempty"`
	Region  string `json:"region,omitempty"`
	Country string `json:"country,omitempty"`
	ISP     string `json:"isp,omitempty"`
	Note    string `json:"note,omitempty"`
	Source  string `json:"source,omitempty"`
}

type geoResolver struct {
	mu     sync.Mutex
	cache  map[string]geoCacheEntry
	ttl    time.Duration
	client *http.Client
	fetch  func(*http.Client, string) (geoInfo, bool)
	logger *slog.Logger
}

type geoCacheEntry struct {
	info    geoInfo
	fetched time.Time
}

func newGeoResolver(logger *slog.Logger) *geoResolver {
	return &geoResolver{
		cache:  make(map[string]geoCacheEntry),
		ttl:    6 * time.Hour,
		client: &http.Client{Timeout: 4 * time.Second},
		fetch:  fetchGeoFromIPAPI,
		logger: logger,
	}
}

// Lookup returns cached geo info when available, skips lookups for private/reserved IPs,
// and falls back gracefully when the remote service cannot be reached.
func (g *geoResolver) Lookup(ip string) geoInfo {
	now := time.Now()
	// Avoid leaking private/reserved addresses to the external service.
	if ip == "" {
		return geoInfo{Summary: "IP unavailable", Note: "IP unavailable"}
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return geoInfo{Summary: "Invalid IP", Note: "Invalid IP"}
	}
	if parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() || parsed.IsUnspecified() {
		return geoInfo{Summary: "Private/reserved IP (lookup skipped)", Note: "Private/reserved IP (lookup skipped)"}
	}

	if cached, ok := g.cached(ip, now); ok {
		return cached
	}

	info, ok := g.fetch(g.client, ip)
	if info.Source == "" {
		info.Source = "ip-api.com"
	}
	info = summarizeGeo(info)
	g.store(ip, info, now)
	if !ok && g.logger != nil {
		g.logger.Debug("geo lookup failed", "ip", ip, "summary", info.Summary)
	}
	return info
}

func (g *geoResolver) cached(ip string, now time.Time) (geoInfo, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	entry, ok := g.cache[ip]
	if !ok {
		return geoInfo{}, false
	}
	if now.Sub(entry.fetched) > g.ttl {
		return geoInfo{}, false
	}
	return entry.info, true
}

func (g *geoResolver) store(ip string, info geoInfo, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cache[ip] = geoCacheEntry{info: info, fetched: now}
}

func summarizeGeo(info geoInfo) geoInfo {
	if info.Summary != "" {
		return info
	}
	locationParts := make([]string, 0, 3)
	if info.City != "" {
		locationParts = append(locationParts, info.City)
	}
	if info.Region != "" {
		locationParts = append(locationParts, info.Region)
	}
	if info.Country != "" {
		locationParts = append(locationParts, info.Country)
	}
	location := strings.Join(locationParts, ", ")
	switch {
	case location != "" && info.ISP != "":
		info.Summary = fmt.Sprintf("%s (%s)", location, info.ISP)
	case location != "":
		info.Summary = location
	case info.ISP != "":
		info.Summary = info.ISP
	case info.Note != "":
		info.Summary = info.Note
	default:
		info.Summary = "Unknown"
	}
	return info
}

func fetchGeoFromIPAPI(client *http.Client, ip string) (geoInfo, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	endpoint := fmt.Sprintf("https://ip-api.com/json/%s?fields=status,message,country,regionName,city,isp", url.PathEscape(ip))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return geoInfo{Summary: "Geo lookup unavailable", Note: "request build failed"}, false
	}
	req.Header.Set("User-Agent", "iprememberme/geo")
	resp, err := client.Do(req)
	if err != nil {
		return geoInfo{Summary: "Geo lookup unavailable", Note: "request failed"}, false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return geoInfo{Summary: "Geo lookup unavailable", Note: fmt.Sprintf("status %d", resp.StatusCode)}, false
	}

	var body struct {
		Status  string `json:"status"`
		Message string `json:"message"`
		Country string `json:"country"`
		Region  string `json:"regionName"`
		City    string `json:"city"`
		ISP     string `json:"isp"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return geoInfo{Summary: "Geo lookup unavailable", Note: "decode failed"}, false
	}
	if strings.ToLower(body.Status) != "success" {
		msg := body.Message
		if msg == "" {
			msg = "Geo lookup unavailable"
		}
		return geoInfo{Summary: msg, Note: msg}, false
	}
	info := geoInfo{
		Country: body.Country,
		Region:  body.Region,
		City:    body.City,
		ISP:     body.ISP,
		Source:  "ip-api.com",
	}
	return summarizeGeo(info), true
}
