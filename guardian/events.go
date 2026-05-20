package guardian

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"example.com/guardian/mod/zoraxy_plugin/events"
)

const SubscriptionPath = "/zoraxy_event"

// EventDescriptors lists the Zoraxy events Guardian wants to receive. The
// map values are descriptions Zoraxy shows in its plugin-info UI.
var EventDescriptors = map[string]string{
	string(events.EventBlacklistedIPBlocked): "Mirror Zoraxy's own blocklist hits into Guardian's block log.",
	string(events.EventBlacklistToggled):     "Track when an upstream blacklist toggle changes.",
}

// RegisterEventRoutes wires the subscription endpoint into mux. Zoraxy POSTs
// to <SubscriptionPath>/<event_name>; we strip the prefix, parse the body
// with the events SDK, and dispatch.
func (s *Store) RegisterEventRoutes(mux *http.ServeMux) {
	if mux == nil {
		mux = http.DefaultServeMux
	}
	mux.HandleFunc(SubscriptionPath+"/", s.handleEvent)
}

func (s *Store) handleEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var ev events.Event
	if err := events.ParseEvent(raw, &ev); err != nil {
		// Unknown events still get logged generically so we can debug.
		s.logUnknownEvent(r, raw)
		w.WriteHeader(http.StatusOK)
		return
	}

	switch ev.Name {
	case events.EventBlacklistedIPBlocked:
		if p, ok := ev.Data.(*events.BlacklistedIPBlockedEvent); ok {
			s.LogEntry(BlockLogEntry{
				Time:       time.Unix(ev.Timestamp, 0).UTC(),
				Source:     "zoraxy",
				IP:         p.IP,
				Host:       p.Hostname,
				Method:     p.Method,
				RequestURI: p.RequestedURL,
				UserAgent:  p.UserAgent,
				Reason:     "zoraxy-blacklist",
				Status:     http.StatusForbidden,
			})
		}
	case events.EventBlacklistToggled:
		if p, ok := ev.Data.(*events.BlacklistToggledEvent); ok {
			payload, _ := json.Marshal(p)
			s.LogEntry(BlockLogEntry{
				Source: "zoraxy",
				Reason: "blacklist-toggled",
				Status: 0,
				Host:   string(payload),
			})
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Store) logUnknownEvent(r *http.Request, body []byte) {
	name := r.Header.Get("X-Zoraxy-Event-Type")
	if name == "" {
		name = strings.TrimPrefix(r.URL.Path, SubscriptionPath+"/")
	}
	s.LogEntry(BlockLogEntry{
		Source: "zoraxy",
		Reason: "event:" + name,
		Host:   truncate(string(body), 200),
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
