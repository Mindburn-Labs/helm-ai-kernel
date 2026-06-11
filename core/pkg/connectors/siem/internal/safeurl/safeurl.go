package safeurl

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// RequireHTTPS rejects non-TLS collector URLs unless explicitly allowed for local tests.
func RequireHTTPS(rawURL, component string, allowInsecureHTTP bool) error {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return fmt.Errorf("%s: invalid URL: %w", component, err)
	}
	if strings.EqualFold(parsed.Scheme, "https") {
		return nil
	}
	if allowInsecureHTTP && strings.EqualFold(parsed.Scheme, "http") && isLocalHost(parsed.Hostname()) {
		return nil
	}
	return fmt.Errorf("%s: collector URL must use https; insecure HTTP is only allowed for explicit local tests", component)
}

func isLocalHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
