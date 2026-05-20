package guardian

import (
	"net"
	"net/http"
	"strings"
	"time"

	plugin "example.com/guardian/mod/zoraxy_plugin"
)

// Evaluate applies the rules in order and returns a Decision.
//
// Order:
//
//  1. Temp ban (set by honeypot or auto-ban escalation)
//  2. IP blocklist
//  3. Host-header blocklist
//  4. Honeypot path match (installs a temp ban as a side-effect)
//  5. IP allowlist (only enforced on hosts where an allow rule applies)
//  6. UA blocklist (with optional ExceptPaths)
//  7. WAF rules
//  8. Rate limit
//
// After any block (other than temp-ban itself, which is already promoted),
// the IP gets a strike towards auto-ban escalation.
func (s *Store) Evaluate(req *plugin.DynamicSniffForwardRequest) Decision {
	s.mu.RLock()
	host := req.Host
	trust := s.cfg.TrustXFF
	honeypotEnabled := s.cfg.Honeypot.Enabled
	honeypotBanSecs := s.cfg.Honeypot.BanSeconds
	allowRules := s.allowRules
	blockRules := s.blockRules
	uaRules := s.uaRules
	hostBlockRules := s.hostBlockRules
	wafRules := s.wafRules
	wafNames := s.wafRuleNames
	honeypotRules := s.honeypotRules
	limiter := s.limiter
	s.mu.RUnlock()

	ip := clientIP(req, trust)
	parsedIP := net.ParseIP(ip)

	// 1. Temp ban
	if banned, _ := s.IsTempBanned(ip); banned {
		return Decision{Block: true, Reason: "temp-ban", Status: http.StatusForbidden}
	}

	// 2. IP blocklist
	if parsedIP != nil {
		for _, r := range blockRules {
			if !HostMatches(host, r.Hosts) {
				continue
			}
			if r.Net.Contains(parsedIP) {
				s.RecordStrike(ip)
				return Decision{Block: true, Reason: "ip-blocklist", Status: http.StatusForbidden}
			}
		}
	}

	// 3. Host-header blocklist
	for _, r := range hostBlockRules {
		if !HostMatches(host, r.Hosts) {
			continue
		}
		if r.RE.MatchString(host) {
			s.RecordStrike(ip)
			return Decision{Block: true, Reason: "host-blocklist", Status: http.StatusForbidden}
		}
	}

	// 4. Honeypot path match — install temp ban as a side-effect
	if honeypotEnabled {
		for _, r := range honeypotRules {
			if !HostMatches(host, r.Hosts) {
				continue
			}
			if r.RE.MatchString(req.RequestURI) {
				dur := time.Duration(honeypotBanSecs) * time.Second
				s.AddTempBan(ip, dur)
				return Decision{Block: true, Reason: "honeypot", Status: http.StatusForbidden}
			}
		}
	}

	// 5. Allowlist (only enforced if at least one allow rule applies to this host)
	allowHostScoped := make([]compiledIPRule, 0, len(allowRules))
	for _, r := range allowRules {
		if HostMatches(host, r.Hosts) {
			allowHostScoped = append(allowHostScoped, r)
		}
	}
	if len(allowHostScoped) > 0 {
		if parsedIP == nil {
			s.RecordStrike(ip)
			return Decision{Block: true, Reason: "not-allowlisted", Status: http.StatusForbidden}
		}
		allowed := false
		for _, r := range allowHostScoped {
			if r.Net.Contains(parsedIP) {
				allowed = true
				break
			}
		}
		if !allowed {
			s.RecordStrike(ip)
			return Decision{Block: true, Reason: "not-allowlisted", Status: http.StatusForbidden}
		}
	}

	// 6. UA blocklist (with ExceptPaths)
	ua := firstHeader(req.Header, "User-Agent")
	for _, r := range uaRules {
		if !HostMatches(host, r.Hosts) {
			continue
		}
		if pathExempt(req.RequestURI, r.ExceptPaths) {
			continue
		}
		if r.RE.MatchString(ua) {
			s.RecordStrike(ip)
			return Decision{Block: true, Reason: "ua-blocklist", Status: http.StatusForbidden}
		}
	}

	// 7. WAF rules
	if hit := wafCheck(req, host, wafRules, wafNames); hit != "" {
		s.RecordStrike(ip)
		return Decision{Block: true, Reason: "waf-" + hit, Status: http.StatusForbidden}
	}

	// 8. Rate limit
	if limiter != nil && parsedIP != nil {
		if !limiter.allow(parsedIP.String()) {
			s.RecordStrike(ip)
			return Decision{Block: true, Reason: "rate-limit", Status: http.StatusTooManyRequests}
		}
	}

	return Decision{Block: false}
}

// pathExempt returns true if requestURI contains any of the literal except
// paths as a substring. Used by UA rules to skip when the request is going
// to (say) /robots.txt.
func pathExempt(requestURI string, exceptPaths []string) bool {
	if len(exceptPaths) == 0 {
		return false
	}
	uri := strings.ToLower(requestURI)
	for _, p := range exceptPaths {
		if p == "" {
			continue
		}
		if strings.Contains(uri, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func wafCheck(req *plugin.DynamicSniffForwardRequest, host string, rules []compiledRegexRule, names []string) string {
	target := req.RequestURI + " " + req.URL
	for k, vs := range req.Header {
		if strings.EqualFold(k, "cookie") || strings.EqualFold(k, "referer") {
			target += " " + strings.Join(vs, " ")
		}
	}
	for i, r := range rules {
		if !HostMatches(host, r.Hosts) {
			continue
		}
		if r.RE.MatchString(target) {
			return names[i]
		}
	}
	return ""
}

func clientIP(req *plugin.DynamicSniffForwardRequest, trustXFF bool) string {
	if trustXFF {
		if xff := firstHeader(req.Header, "X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[0])
		}
		if xri := firstHeader(req.Header, "X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

func firstHeader(h map[string][]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}
