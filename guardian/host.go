package guardian

import (
	"regexp"
	"strings"
)

// HostMatches returns true if host matches any pattern in patterns.
// An empty or nil patterns slice matches every host (rule is global).
// Patterns use simple glob syntax with `*` as wildcard for any chars
// except `.` (so `*.example.com` matches `foo.example.com` but not
// `foo.bar.example.com`). `**.example.com` would match any subdomain depth.
func HostMatches(host string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	for _, p := range patterns {
		if matchOne(host, strings.ToLower(strings.TrimSpace(p))) {
			return true
		}
	}
	return false
}

func matchOne(host, pattern string) bool {
	if pattern == "" || pattern == "*" || pattern == "**" {
		return true
	}
	if !strings.ContainsAny(pattern, "*?") {
		return host == pattern
	}
	re := globToRegex(pattern)
	matched, err := regexp.MatchString(re, host)
	if err != nil {
		return false
	}
	return matched
}

func globToRegex(p string) string {
	var b strings.Builder
	b.WriteString("^")
	i := 0
	for i < len(p) {
		c := p[i]
		switch c {
		case '*':
			// "**" -> match anything including dots
			if i+1 < len(p) && p[i+1] == '*' {
				b.WriteString(".*")
				i += 2
				continue
			}
			b.WriteString("[^.]*")
		case '?':
			b.WriteString("[^.]")
		case '.', '+', '(', ')', '|', '^', '$', '{', '}', '[', ']', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
		i++
	}
	b.WriteString("$")
	return b.String()
}
