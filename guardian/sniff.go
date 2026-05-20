package guardian

import (
	"net"
	"net/http"
	"strings"

	plugin "example.com/guardian/mod/zoraxy_plugin"
)

// Evaluate applies the rules in order and returns a Decision.
// Order: blocklist > allowlist > UA > WAF > rate limit. All rules are
// filtered by host scope first.
func (s *Store) Evaluate(req *plugin.DynamicSniffForwardRequest) Decision {
	s.mu.RLock()
	defer s.mu.RUnlock()

	host := req.Host
	ip := clientIP(req, s.cfg.TrustXFF)
	parsedIP := net.ParseIP(ip)

	if parsedIP != nil {
		for _, r := range s.blockRules {
			if !HostMatches(host, r.Hosts) {
				continue
			}
			if r.Net.Contains(parsedIP) {
				return Decision{Block: true, Reason: "ip-blocklist", Status: http.StatusForbidden}
			}
		}
	}

	// Allowlist: only enforce if at least one allow rule applies to this host.
	allowHostScoped := make([]compiledIPRule, 0, len(s.allowRules))
	for _, r := range s.allowRules {
		if HostMatches(host, r.Hosts) {
			allowHostScoped = append(allowHostScoped, r)
		}
	}
	if len(allowHostScoped) > 0 {
		if parsedIP == nil {
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
			return Decision{Block: true, Reason: "not-allowlisted", Status: http.StatusForbidden}
		}
	}

	ua := firstHeader(req.Header, "User-Agent")
	for _, r := range s.uaRules {
		if !HostMatches(host, r.Hosts) {
			continue
		}
		if r.RE.MatchString(ua) {
			return Decision{Block: true, Reason: "ua-blocklist", Status: http.StatusForbidden}
		}
	}

	if hit := s.wafCheckLocked(req, host); hit != "" {
		return Decision{Block: true, Reason: "waf-" + hit, Status: http.StatusForbidden}
	}

	if s.limiter != nil && parsedIP != nil {
		if !s.limiter.allow(parsedIP.String()) {
			return Decision{Block: true, Reason: "rate-limit", Status: http.StatusTooManyRequests}
		}
	}

	return Decision{Block: false}
}

func (s *Store) wafCheckLocked(req *plugin.DynamicSniffForwardRequest, host string) string {
	target := req.RequestURI + " " + req.URL
	for k, vs := range req.Header {
		if strings.EqualFold(k, "cookie") || strings.EqualFold(k, "referer") {
			target += " " + strings.Join(vs, " ")
		}
	}
	for i, r := range s.wafRules {
		if !HostMatches(host, r.Hosts) {
			continue
		}
		if r.RE.MatchString(target) {
			return s.wafRuleNames[i]
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
