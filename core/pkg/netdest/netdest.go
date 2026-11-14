// Package netdest resolves the network endpoint a URL or host names, in the
// one form an egress allowlist is compared against. The shell scanner uses it
// to read destinations out of commands and the workstation policy uses it to
// compare them, so the two cannot disagree about which host a string means.
package netdest

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// Undetermined is the target of a network effect whose destinations could not
// all be named. It is not a destination: Parse rejects it, so no allowlist
// entry can match it.
const Undetermined = "<undetermined>"

// Destination is one network endpoint in the form an egress allowlist is
// compared against.
type Destination struct {
	Scheme string // lower case
	Host   string // CanonicalHost form
	Port   string // decimal, empty when the scheme's default applies or none is known
}

// String renders the canonical scheme://host[:port] form. Parse maps it back
// to the same Destination.
func (d Destination) String() string {
	host := d.Host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if d.Port == "" {
		return d.Scheme + "://" + host
	}
	return d.Scheme + "://" + host + ":" + d.Port
}

// DefaultPort is the port a scheme implies, or empty. It lets https://host
// and https://host:443 name one destination.
func DefaultPort(scheme string) string {
	return defaultPorts[scheme]
}

var defaultPorts = map[string]string{
	"ftp":    "21",
	"ftps":   "990",
	"http":   "80",
	"https":  "443",
	"rsync":  "873",
	"scp":    "22",
	"sftp":   "22",
	"ssh":    "22",
	"telnet": "23",
	"ws":     "80",
	"wss":    "443",
}

// Parse resolves a URL, or a bare host[:port] taken as https, to the endpoint
// a client would connect to. The host is the one after any userinfo. It fails
// on anything that is not one concrete endpoint, and on spellings that URL
// parsers are known to read differently, so a caller that treats an error as
// "not allowed" cannot be talked into the wrong host.
func Parse(target string) (Destination, error) {
	return ParseWithScheme(target, "https")
}

// ParseWithScheme is Parse for a client that assumes defaultScheme, rather
// than https, when the target names none.
func ParseWithScheme(target, defaultScheme string) (Destination, error) {
	if target == "" {
		return Destination{}, errors.New("destination is empty")
	}
	for _, r := range target {
		if r <= ' ' || r == 0x7f || r == '\\' {
			return Destination{}, fmt.Errorf("destination contains %q", r)
		}
	}
	raw := target
	if !HasScheme(raw) {
		// "http:/host" is a URL to curl and a host named "http" to a strict
		// parser, so a scheme followed by one slash has no single meaning.
		if colon := strings.IndexByte(raw, ':'); colon > 0 && strings.HasPrefix(raw[colon+1:], "/") && !strings.ContainsAny(raw[:colon], "@[./") {
			return Destination{}, errors.New("destination has a malformed scheme separator")
		}
		// A bare IPv6 address has colons that a URL parser would read as a port.
		if addr, err := netip.ParseAddr(raw); err == nil && addr.Is6() {
			raw = "[" + raw + "]"
		}
		raw = defaultScheme + "://" + raw
	}
	if err := checkAuthorityBoundary(raw); err != nil {
		return Destination{}, err
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return Destination{}, fmt.Errorf("destination is not a URL: %w", err)
	}
	if parsed.Opaque != "" || parsed.Host == "" {
		return Destination{}, errors.New("destination names no host")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "" || scheme == "file" {
		return Destination{}, fmt.Errorf("scheme %q names no network host", scheme)
	}
	host, err := CanonicalHost(parsed.Hostname())
	if err != nil {
		return Destination{}, err
	}
	port := parsed.Port()
	if port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return Destination{}, fmt.Errorf("port %q is out of range", port)
		}
		port = strconv.Itoa(number)
		if port == defaultPorts[scheme] {
			port = ""
		}
	}
	return Destination{Scheme: scheme, Host: host, Port: port}, nil
}

// HasScheme reports whether value starts with scheme://. A "://" later in the
// text, such as a URL carried in a query string, does not count.
func HasScheme(value string) bool {
	separator := strings.Index(value, "://")
	if separator <= 0 {
		return false
	}
	for i := 0; i < separator; i++ {
		c := value[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return true
}

// checkAuthorityBoundary rejects a URL whose authority ends at "?" or "#" and
// is followed by an "@". RFC 3986 parsers stop the host at that character;
// others have taken the text after the "@" as the host instead.
func checkAuthorityBoundary(raw string) error {
	rest := raw[strings.Index(raw, "://")+3:]
	end := strings.IndexAny(rest, "/?#")
	if end < 0 || rest[end] == '/' {
		return nil
	}
	if strings.Contains(rest[end:], "@") {
		return errors.New(`destination has an "@" after the end of its authority`)
	}
	return nil
}

// hostProfile maps a Unicode host the way IDNA lookup does. Domain-name
// strictness is applied by validHostLabel so that an underscore, which
// resolvers accept, is not an error here.
var hostProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.CheckJoiners(true),
	idna.StrictDomainName(false),
	idna.Transitional(false),
)

// CanonicalHost returns the one spelling of a host that every equal host
// shares: an IP address in its shortest form, or a lower-case ASCII domain
// name without a trailing dot. Allowlist entries and command targets both go
// through it, so they cannot disagree about case, punycode, brackets or a
// trailing dot.
func CanonicalHost(host string) (string, error) {
	if host == "" {
		return "", errors.New("host is empty")
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return "", errors.New("host is a zoned address")
		}
		return addr.Unmap().String(), nil
	}
	if strings.Contains(host, ":") {
		return "", fmt.Errorf("host %q is not an IP address", host)
	}
	for _, r := range host {
		switch r {
		// IDNA 2003 and IDNA 2008 map these to different names, so the client
		// that makes the connection may not agree with this function.
		case 'ß', 'ς', '‌', '‍':
			return "", fmt.Errorf("host contains %q, which IDNA versions map differently", r)
		}
	}
	ascii, err := hostProfile.ToASCII(host)
	if err != nil {
		return "", fmt.Errorf("host %q is not a domain name: %w", host, err)
	}
	ascii = strings.ToLower(strings.TrimSuffix(ascii, "."))
	if ascii == "" || len(ascii) > 253 {
		return "", fmt.Errorf("host %q is not a domain name", host)
	}
	labels := strings.Split(ascii, ".")
	for _, label := range labels {
		if !validHostLabel(label) {
			return "", fmt.Errorf("host %q is not a domain name", host)
		}
	}
	// A name whose last label is a number is read as an IPv4 address by
	// inet_aton-style clients (2130706433, 0x7f.1, 127.1). It was not a
	// canonical address above, so it has no single meaning.
	if last := labels[len(labels)-1]; numericLabel(last) {
		return "", fmt.Errorf("host %q is an ambiguous numeric address", host)
	}
	return ascii, nil
}

func validHostLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_':
		case c == '-' && i > 0 && i < len(label)-1:
		default:
			return false
		}
	}
	return true
}

func numericLabel(label string) bool {
	if strings.HasPrefix(label, "0x") {
		return true
	}
	for i := 0; i < len(label); i++ {
		if label[i] < '0' || label[i] > '9' {
			return false
		}
	}
	return true
}
