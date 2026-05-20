package guardian

import (
	"encoding/json"
	"net"
	"os"
	"regexp"
	"sync"
	"time"

	plugin "example.com/guardian/mod/zoraxy_plugin"
)

// ScopedEntry pairs a rule value (IP/CIDR or regex) with an optional set of
// host glob patterns. An empty Hosts slice means the entry applies to all
// hosts proxied through this plugin.
type ScopedEntry struct {
	Value string   `json:"value"`
	Hosts []string `json:"hosts,omitempty"`
}

type Config struct {
	IPAllowlist []ScopedEntry `json:"ip_allowlist"`
	IPBlocklist []ScopedEntry `json:"ip_blocklist"`
	UABlocklist []ScopedEntry `json:"ua_blocklist"`
	WAFRules    []WAFRule     `json:"waf_rules"`
	RateLimit   RateLimit     `json:"rate_limit"`
	TrustXFF    bool          `json:"trust_xff"`
}

type WAFRule struct {
	Name    string   `json:"name"`
	Pattern string   `json:"pattern"`
	Enabled bool     `json:"enabled"`
	Hosts   []string `json:"hosts,omitempty"`
}

type RateLimit struct {
	Enabled           bool `json:"enabled"`
	RequestsPerMinute int  `json:"requests_per_minute"`
	Burst             int  `json:"burst"`
}

type BlockLogEntry struct {
	Time       time.Time `json:"time"`
	Source     string    `json:"source"` // "guardian" or "zoraxy"
	IP         string    `json:"ip"`
	Host       string    `json:"host"`
	Method     string    `json:"method"`
	RequestURI string    `json:"request_uri"`
	UserAgent  string    `json:"user_agent"`
	Reason     string    `json:"reason"`
	Status     int       `json:"status"`
}

type compiledIPRule struct {
	Net   *net.IPNet
	Hosts []string
}

type compiledRegexRule struct {
	RE    *regexp.Regexp
	Hosts []string
}

type Store struct {
	configPath string
	logPath    string

	mu           sync.RWMutex
	cfg          Config
	allowRules   []compiledIPRule
	blockRules   []compiledIPRule
	uaRules      []compiledRegexRule
	wafRules     []compiledRegexRule
	wafRuleNames []string
	limiter      *rateLimiter
	log          *blockLog

	pendingMu sync.Mutex
	pending   map[string]Decision
}

type Decision struct {
	Block  bool
	Reason string
	Status int
}

func LoadState(configPath, logPath string) (*Store, error) {
	s := &Store{
		configPath: configPath,
		logPath:    logPath,
		pending:    make(map[string]Decision),
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		s.cfg = defaultConfig()
	} else {
		if err := json.Unmarshal(data, &s.cfg); err != nil {
			return nil, err
		}
	}
	s.compile()
	log, err := openBlockLog(logPath, maxBlockLog)
	if err != nil {
		return nil, err
	}
	s.log = log
	return s, nil
}

func defaultConfig() Config {
	return Config{
		IPAllowlist: []ScopedEntry{},
		IPBlocklist: []ScopedEntry{},
		UABlocklist: []ScopedEntry{
			{Value: `(?i)sqlmap`},
			{Value: `(?i)nikto`},
			{Value: `(?i)nmap`},
			{Value: `(?i)masscan`},
			{Value: `(?i)acunetix`},
			{Value: `(?i)nessus`},
		},
		WAFRules: []WAFRule{
			{Name: "sqli-union", Pattern: `(?i)union[\s/*]+select`, Enabled: true},
			{Name: "sqli-comment", Pattern: `(?i)(--|#|/\*).*(\bor\b|\band\b)`, Enabled: true},
			{Name: "xss-script", Pattern: `(?i)<script\b`, Enabled: true},
			{Name: "xss-javascript-uri", Pattern: `(?i)javascript:`, Enabled: true},
			{Name: "xss-onevent", Pattern: `(?i)\bon\w+\s*=`, Enabled: true},
			{Name: "path-traversal", Pattern: `(\.\./|\.\.\\)`, Enabled: true},
			{Name: "null-byte", Pattern: `%00`, Enabled: true},
		},
		RateLimit: RateLimit{
			Enabled:           false,
			RequestsPerMinute: 120,
			Burst:             30,
		},
		TrustXFF: true,
	}
}

func (s *Store) compile() {
	s.allowRules = compileIPRules(s.cfg.IPAllowlist)
	s.blockRules = compileIPRules(s.cfg.IPBlocklist)
	s.uaRules = compileRegexRules(s.cfg.UABlocklist)

	s.wafRules = make([]compiledRegexRule, 0, len(s.cfg.WAFRules))
	s.wafRuleNames = make([]string, 0, len(s.cfg.WAFRules))
	for _, r := range s.cfg.WAFRules {
		if !r.Enabled {
			continue
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			continue
		}
		s.wafRules = append(s.wafRules, compiledRegexRule{RE: re, Hosts: r.Hosts})
		s.wafRuleNames = append(s.wafRuleNames, r.Name)
	}

	if s.cfg.RateLimit.Enabled {
		s.limiter = newRateLimiter(s.cfg.RateLimit.RequestsPerMinute, s.cfg.RateLimit.Burst)
	} else {
		s.limiter = nil
	}
}

func compileIPRules(entries []ScopedEntry) []compiledIPRule {
	out := make([]compiledIPRule, 0, len(entries))
	for _, e := range entries {
		var ipnet *net.IPNet
		if _, n, err := net.ParseCIDR(e.Value); err == nil {
			ipnet = n
		} else if ip := net.ParseIP(e.Value); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		} else {
			continue
		}
		out = append(out, compiledIPRule{Net: ipnet, Hosts: e.Hosts})
	}
	return out
}

func compileRegexRules(entries []ScopedEntry) []compiledRegexRule {
	out := make([]compiledRegexRule, 0, len(entries))
	for _, e := range entries {
		re, err := regexp.Compile(e.Value)
		if err != nil {
			continue
		}
		out = append(out, compiledRegexRule{RE: re, Hosts: e.Hosts})
	}
	return out
}

func (s *Store) Snapshot() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cfg := s.cfg
	cfg.IPAllowlist = append([]ScopedEntry{}, s.cfg.IPAllowlist...)
	cfg.IPBlocklist = append([]ScopedEntry{}, s.cfg.IPBlocklist...)
	cfg.UABlocklist = append([]ScopedEntry{}, s.cfg.UABlocklist...)
	cfg.WAFRules = append([]WAFRule{}, s.cfg.WAFRules...)
	return cfg
}

func (s *Store) Update(cfg Config) error {
	s.mu.Lock()
	s.cfg = cfg
	s.compile()
	s.mu.Unlock()
	return s.Save()
}

func (s *Store) Save() error {
	s.mu.RLock()
	data, err := json.MarshalIndent(s.cfg, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	return os.WriteFile(s.configPath, data, 0o644)
}

func (s *Store) RecordDecision(uuid string, d Decision) {
	if uuid == "" {
		return
	}
	s.pendingMu.Lock()
	s.pending[uuid] = d
	s.pendingMu.Unlock()
}

func (s *Store) TakeDecision(uuid string) (Decision, bool) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	d, ok := s.pending[uuid]
	if ok {
		delete(s.pending, uuid)
	}
	return d, ok
}

func (s *Store) LogBlock(req *plugin.DynamicSniffForwardRequest, d Decision) {
	s.mu.RLock()
	trust := s.cfg.TrustXFF
	s.mu.RUnlock()

	entry := BlockLogEntry{
		Time:       time.Now().UTC(),
		Source:     "guardian",
		IP:         clientIP(req, trust),
		Host:       req.Host,
		Method:     req.Method,
		RequestURI: req.RequestURI,
		UserAgent:  firstHeader(req.Header, "User-Agent"),
		Reason:     d.Reason,
		Status:     d.Status,
	}
	s.log.Append(entry)
}

func (s *Store) LogEntry(entry BlockLogEntry) {
	if entry.Time.IsZero() {
		entry.Time = time.Now().UTC()
	}
	s.log.Append(entry)
}

func (s *Store) Log() []BlockLogEntry {
	return s.log.Snapshot()
}
