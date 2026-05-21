package guardian

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestEventBlacklistedIPBlocked(t *testing.T) {
	dir := t.TempDir()
	s, err := LoadState(filepath.Join(dir, "cfg.json"), filepath.Join(dir, "log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	s.RegisterEventRoutes(mux)

	payload := map[string]any{
		"name":      "blacklistedIpBlocked",
		"timestamp": 0,
		"uuid":      "abc",
		"data": map[string]any{
			"ip":            "1.2.3.4",
			"comment":       "manual",
			"requested_url": "/foo",
			"hostname":      "x.test",
			"user_agent":    "curl",
			"method":        "GET",
		},
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, SubscriptionPath+"/blacklistedIpBlocked", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	entries := s.LogPage(0, 0)
	if len(entries) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Source != "zoraxy" || e.Reason != "zoraxy-blacklist" || e.IP != "1.2.3.4" || e.Host != "x.test" {
		t.Errorf("unexpected log entry: %+v", e)
	}
}

func TestEventGetRejected(t *testing.T) {
	dir := t.TempDir()
	s, err := LoadState(filepath.Join(dir, "cfg.json"), filepath.Join(dir, "log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	s.RegisterEventRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, SubscriptionPath+"/anything", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET should be 405, got %d", rr.Code)
	}
}
