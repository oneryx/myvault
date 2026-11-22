// Package uri reads login URIs the way Bitwarden's URI match rules do:
// their host name and registrable domain.
package uri

import (
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Parse parses s as a URL, assuming http:// when it has no scheme, the
// way Bitwarden's URL helpers do.
func Parse(s string) *url.URL {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if !strings.Contains(s, "://") {
		if !strings.Contains(s, ".") {
			return nil
		}
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return nil
	}
	return u
}

// Hostname is a URI's host name in lowercase, or "".
func Hostname(s string) string {
	s = strings.TrimSpace(s)
	for _, p := range []string{"data:", "about:", "file:"} {
		if strings.HasPrefix(s, p) {
			return ""
		}
	}
	u := Parse(s)
	if u == nil {
		return ""
	}
	h := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if a, err := idna.ToASCII(h); err == nil {
		h = a
	}
	return h
}

// Domain is the registrable domain of a URI (its public suffix plus one
// label), the host itself for localhost and IP addresses, or "".
func Domain(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "data:") || strings.HasPrefix(s, "about:") {
		return ""
	}
	h := Hostname(s)
	if h == "" {
		return ""
	}
	if h == "localhost" || net.ParseIP(strings.Trim(h, "[]")) != nil {
		return h
	}
	d, err := publicsuffix.EffectiveTLDPlusOne(h)
	if err != nil {
		return ""
	}
	return d
}
