package admission

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// CheckOwnerOrigins validates exact browser origins configured by the gateway
// operator. An empty list uses https://<credential rp_id>. Subdomains and ports
// are never inferred; local HTTP needs an explicit loopback origin.
func CheckOwnerOrigins(origins []string) error {
	for _, origin := range origins {
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" || u.Opaque != "" || u.User != nil || u.Path != "" || u.RawPath != "" ||
			u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(origin, "*#\\") ||
			u.Host != strings.ToLower(u.Host) || u.String() != origin {
			return fmt.Errorf("owner origin %q must be an exact origin without credentials, wildcard, path, query or fragment", origin)
		}
		host := u.Hostname()
		ip := net.ParseIP(host)
		loopback := host == "localhost" || ip != nil && ip.IsLoopback()
		if u.Scheme != "https" && (u.Scheme != "http" || !loopback) {
			return fmt.Errorf("owner origin %q needs HTTPS; HTTP is only allowed for an explicit loopback origin", origin)
		}
		if port := u.Port(); port != "" {
			n, err := strconv.Atoi(port)
			if err != nil || n < 1 || n > 65535 || port != strconv.Itoa(n) {
				return fmt.Errorf("owner origin %q has an invalid port", origin)
			}
		} else if strings.HasSuffix(u.Host, ":") {
			return fmt.Errorf("owner origin %q has an empty port", origin)
		}
	}
	return nil
}
