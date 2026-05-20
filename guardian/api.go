package guardian

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	plugin "example.com/guardian/mod/zoraxy_plugin"
)

type API struct {
	store *Store
}

func NewAPI(s *Store) *API { return &API{store: s} }

func (a *API) RegisterRoutes(ui *plugin.PluginUiRouter, mux *http.ServeMux) {
	ui.HandleFunc("/api/config", a.handleConfig, mux)
	ui.HandleFunc("/api/blocklog", a.handleBlockLog, mux)
	ui.HandleFunc("/api/blocklog/stream", a.handleBlockLogStream, mux)
	ui.HandleFunc("/api/tempbans", a.handleTempBans, mux)
	ui.HandleFunc("/api/tempbans/clear", a.handleTempBansClear, mux)
}

func (a *API) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, a.store.Snapshot())
	case http.MethodPost:
		var cfg Config
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := a.store.Update(cfg); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *API) handleBlockLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	offset := atoiDefault(r.URL.Query().Get("offset"), 0)
	limit := atoiDefault(r.URL.Query().Get("limit"), 0) // 0 = all
	entries := a.store.LogPage(offset, limit)
	writeJSON(w, http.StatusOK, map[string]any{
		"total":   a.store.LogTotal(),
		"offset":  offset,
		"limit":   limit,
		"entries": entries,
	})
}

// handleBlockLogStream is an SSE endpoint. On open, it pushes a snapshot of
// the most recent N entries (newest first) then streams future entries as
// they arrive. Keepalive comment every 25s.
func (a *API) handleBlockLogStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // hint to upstream proxies
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ctx := r.Context()
	ch := a.store.Broadcaster().Subscribe()
	defer a.store.Broadcaster().Unsubscribe(ch)

	keepalive := time.NewTicker(25 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-keepalive.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		case e, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(e)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: block\ndata: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (a *API) handleTempBans(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bans := a.store.TempBansSnapshot()
	type entry struct {
		IP      string `json:"ip"`
		Expires string `json:"expires"`
	}
	out := make([]entry, 0, len(bans))
	for ip, exp := range bans {
		out = append(out, entry{IP: ip, Expires: exp.UTC().Format(time.RFC3339)})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) handleTempBansClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "missing ip query param", http.StatusBadRequest)
		return
	}
	a.store.ClearTempBan(ip)
	writeJSON(w, http.StatusOK, map[string]string{"status": "cleared", "ip": ip})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func atoiDefault(s string, d int) int {
	if s == "" {
		return d
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return d
	}
	return n
}
