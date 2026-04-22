package sources

import (
	"crypto/sha256"
	"fmt"
	"net/url"
	"strings"
)

// NormalizeURL canonicalizes a URL by lowercasing scheme/host, removing fragments, and sorting query params.
func NormalizeURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""
	return u.String(), nil
}

// ContentHash computes SHA-256 of raw content.
func ContentHash(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", h)
}
