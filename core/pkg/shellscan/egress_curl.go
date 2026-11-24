package shellscan

import (
	"net/netip"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/netdest"
)

var curlSpec = cliSpec{
	negatable: true,
	short: map[byte]string{
		'E': "cert", 'K': "config", 'C': "continue-at", 'b': "cookie", 'c': "cookie-jar",
		'd': "data", 'D': "dump-header", 'F': "form", 'P': "ftp-port", 'H': "header",
		'm': "max-time", 'o': "output", 'U': "proxy-user", 'Q': "quote", 'r': "range",
		'e': "referer", 'X': "request", 'Y': "speed-limit", 'y': "speed-time",
		't': "telnet-option", 'z': "time-cond", 'T': "upload-file", 'u': "user",
		'A': "user-agent", 'w': "write-out", 'x': "proxy",
		'a': "append", 'q': "disable", 'f': "fail", 'G': "get", 'g': "globoff", 'h': "help",
		'I': "head", '0': "http1.0", 'i': "include", 'k': "insecure", '4': "ipv4", '6': "ipv6",
		'j': "junk-session-cookies", 'l': "list-only", 'L': "location", 'M': "manual",
		'n': "netrc", ':': "next", 'N': "no-buffer", 'Z': "parallel", '#': "progress-bar",
		'p': "proxytunnel", 'J': "remote-header-name", 'O': "remote-name", 'R': "remote-time",
		'S': "show-error", 's': "silent", '2': "sslv2", '3': "sslv3", '1': "tlsv1",
		'B': "use-ascii", 'v': "verbose", 'V': "version",
	},
	value: withRoles(names(`
		aws-sigv4 cacert capath cert cert-type ciphers connect-timeout continue-at cookie
		cookie-jar create-file-mode crlfile curves data data-ascii data-binary data-raw
		data-urlencode delegation dns-interface dns-ipv4-addr dns-ipv6-addr dump-header
		egd-file engine etag-compare etag-save expect100-timeout form form-string ftp-account
		ftp-alternative-to-user ftp-method ftp-ssl-ccc-mode happy-eyeballs-timeout-ms
		haproxy-clientip header hostpubmd5 hostpubsha256 interface json keepalive-time
		key key-type krb libcurl limit-rate local-port login-options mail-auth mail-from
		mail-rcpt max-filesize max-redirs max-time netrc-file noproxy oauth2-bearer output
		output-dir parallel-max pass pinnedpubkey proto proto-redir proxy-cacert proxy-capath
		proxy-cert proxy-cert-type proxy-ciphers proxy-crlfile proxy-header proxy-key
		proxy-key-type proxy-pass proxy-pinnedpubkey proxy-service-name proxy-tls13-ciphers
		proxy-tlsauthtype proxy-tlspassword proxy-tlsuser proxy-user pubkey quote random-file
		range rate referer request request-target retry retry-delay retry-max-time
		sasl-authzid service-name socks5-gssapi-service speed-limit speed-time stderr
		telnet-option tftp-blksize time-cond tls-max tls13-ciphers tlsauthtype tlspassword
		tlsuser trace trace-ascii trace-config upload-file url-query user user-agent write-out
	`), map[string]optRole{
		"url": roleURL, "doh-url": roleURL, "ipfs-gateway": roleURL,
		"proxy": roleProxy, "preproxy": roleProxy, "proxy1.0": roleProxy,
		"socks4": roleProxy, "socks4a": roleProxy, "socks5": roleProxy, "socks5-hostname": roleProxy,
		"connect-to": roleConnectTo, "resolve": roleResolve,
		"config": roleOpaque, "unix-socket": roleOpaque, "abstract-unix-socket": roleOpaque,
		"dns-servers": roleOpaque, "alt-svc": roleOpaque, "hsts": roleOpaque, "ftp-port": roleOpaque,
		"proto-default": roleOpaque, "variable": roleOpaque, "engine": roleOpaque,
	}),
	flag: withRoles(names(`
		anyauth append basic ca-native cert-status compressed compressed-ssh create-dirs crlf
		digest disable disable-eprt disable-epsv disallow-username-in-url doh-cert-status
		doh-insecure fail fail-early fail-with-body false-start form-escape ftp-create-dirs
		ftp-pasv ftp-pret ftp-skip-pasv-ip ftp-ssl-ccc ftp-ssl-control get globoff
		haproxy-protocol head help http0.9 http1.0 http1.1 http2 http2-prior-knowledge http3
		http3-only ignore-content-length include insecure ipv4 ipv6 junk-session-cookies
		list-only mail-rcpt-allowfails manual negotiate netrc netrc-optional next no-alpn
		no-buffer no-clobber no-keepalive no-npn no-progress-meter no-sessionid ntlm ntlm-wb
		parallel parallel-immediate path-as-is post301 post302 post303 progress-bar
		proxy-anyauth proxy-basic proxy-ca-native proxy-digest proxy-http2 proxy-insecure
		proxy-negotiate proxy-ntlm proxy-ssl-allow-beast proxy-ssl-auto-client-cert
		proxy-tlsv1 proxytunnel raw remote-header-name remote-name remote-name-all remote-time
		remove-on-error retry-all-errors retry-connrefused sasl-ir show-error silent
		socks5-basic socks5-gssapi socks5-gssapi-nec ssl ssl-allow-beast ssl-auto-client-cert
		ssl-no-revoke ssl-reqd ssl-revoke-best-effort sslv2 sslv3 styled-output
		suppress-connect-headers tcp-fastopen tcp-nodelay tftp-no-options tlsv1 tlsv1.0
		tlsv1.1 tlsv1.2 tlsv1.3 tr-encoding trace-ids trace-time use-ascii verbose version
		xattr
	`), map[string]optRole{
		"location": roleOpaque, "location-trusted": roleOpaque, "metalink": roleOpaque,
		"no-ftp-skip-pasv-ip": roleOpaque,
	}),
}

// curlProxySchemes is the protocol curl speaks to a proxy named without one.
var curlProxySchemes = map[string]string{
	"proxy": "http", "preproxy": "http", "proxy1.0": "http",
	"socks4": "socks4", "socks4a": "socks4a", "socks5": "socks5", "socks5-hostname": "socks5h",
}

// curlOutputUsesGlob reports a "#" followed by a digit, which curl replaces
// in an output name with the text a URL glob matched.
func curlOutputUsesGlob(value string) bool {
	for index := 0; index+1 < len(value); index++ {
		if value[index] == '#' && value[index+1] >= '0' && value[index+1] <= '9' {
			return true
		}
	}
	return false
}

// curlURLGlob reports glob syntax in a URL: "{" or "[" anywhere but in a
// bracketed IPv6 host, which curl does not expand.
func curlURLGlob(raw string) bool {
	authority, rest, _ := strings.Cut(urlAfterScheme(raw), "/")
	if open := strings.IndexByte(authority, '['); open >= 0 {
		if end := strings.IndexByte(authority[open:], ']'); end > 0 {
			authority = authority[:open] + authority[open+end+1:]
		}
	}
	return strings.ContainsAny(authority, "{[") || strings.ContainsAny(rest, "{[")
}

func curlEgress(tokens []string) egressScan {
	var scan egressScan
	var urls, connectTo, resolve []string
	remoteName, uploadGlob := false, false
	// --globoff applies to one transfer; with --next it is not known which.
	globoff, transfers := false, 1
	walkCLI(curlSpec, tokens, cliVisitor{
		operand: func(token string) { urls = append(urls, token) },
		invalid: scan.refuse,
		option: func(name string, role optRole, value string) {
			if name == "form" {
				if _, ok := curlFormPaths(value); !ok {
					scan.refuse("curl form has unsupported file syntax")
				}
			}
			if name == "data-urlencode" || name == "url-query" {
				// Curl and the platform each read a backslash in this file
				// name their own way; the spelling stays unsupported.
				if strings.Contains(curlEncodedFilePath(name, value), `\`) {
					scan.refuse("curl encoded input has an unsupported file path")
				}
			}
			if name == "globoff" {
				globoff = true
			}
			if name == "next" {
				transfers++
			}
			if name == "upload-file" && strings.ContainsAny(value, "{[") {
				// Curl expands {a,b} and [1-3] in an upload name into
				// several files, which are not each checked here.
				uploadGlob = true
			}
			if name == "output" && curlOutputUsesGlob(value) {
				scan.refuse("--output builds the file name from a URL glob")
			}
			if name == "remote-name" || name == "remote-name-all" {
				remoteName = true
			}
			if name == "write-out" && strings.HasPrefix(value, "@") {
				// The format can send output to any file ("%output{name}"),
				// and here it is read at run time.
				scan.refuse("--write-out reads its format, which can name output files, from a file")
			}
			switch role {
			case roleURL:
				if name == "url" {
					urls = append(urls, value)
					return
				}
				scan.addTarget(value, "https", "--"+name)
			case roleProxy:
				if value != "" {
					scan.addTarget(value, curlProxySchemes[name], "--"+name)
				}
			case roleConnectTo:
				connectTo = append(connectTo, value)
			case roleResolve:
				resolve = append(resolve, value)
			case roleOpaque:
				scan.refuse(opaqueReason("curl", name))
			}
		},
	})
	globbing := !globoff || transfers > 1
	if uploadGlob && globbing {
		scan.refuse("--upload-file with a glob names files that are not each checked")
	}
	for _, raw := range urls {
		if remoteName && globbing && curlURLGlob(raw) {
			scan.refuse("--remote-name with a URL glob writes files that are not each checked")
		}
		if strings.HasPrefix(strings.ToLower(raw), "file:") {
			if _, ok := localFileURLPath(raw); !ok {
				scan.refuse("file URL has an unsupported local path")
			}
			if globbing && curlURLGlob(raw) {
				// Curl expands {a,b} and [1-3] into several local files,
				// which are not each checked here.
				scan.refuse("file URL with a glob names files that are not each checked")
			}
			continue // a local file, reported as a read by the secret rules
		}
		defaultScheme := ""
		if !netdest.HasScheme(raw) {
			defaultScheme = curlGuessedScheme(raw)
		}
		scan.addTarget(raw, defaultScheme, "a URL")
	}
	scheme := ""
	for _, destination := range scan.destinations {
		if scheme == "" {
			scheme = destination.Scheme
		} else if scheme != destination.Scheme && (len(connectTo) > 0 || len(resolve) > 0) {
			// Remappings keep the protocol of the request they affect. This
			// scanner does not model transfer groups or the shared DNS cache;
			// choosing one protocol could allow a connection under the wrong
			// rule. Split mixed-protocol remappings into separate commands.
			scan.refuse("mixed-protocol curl remappings are undetermined; use separate commands")
			return scan
		}
	}
	if scheme == "" {
		scheme = "https"
	}
	// The redirected connection speaks the protocol of the URL it replaces.
	for _, value := range connectTo {
		fields := splitColonFields(value)
		if len(fields) != 4 {
			scan.refuse("--connect-to value is malformed")
			continue
		}
		host, port := fields[2], fields[3]
		if host == "" {
			host = fields[0]
		}
		if port == "" {
			port = fields[1]
		}
		if host == "" || port == "" {
			scan.refuse("--connect-to inherits a host or port from a wildcard match")
			continue
		}
		scan.addHost(scheme, host, port, "--connect-to")
	}
	for _, value := range resolve {
		if strings.HasPrefix(value, "-") {
			continue // removes an earlier entry
		}
		fields := splitColonFields(strings.TrimPrefix(value, "+"))
		if len(fields) < 3 {
			scan.refuse("--resolve value is malformed")
			continue
		}
		// An unbracketed IPv6 address was split on its own colons.
		for _, address := range strings.Split(strings.Join(fields[2:], ":"), ",") {
			if _, err := netip.ParseAddr(strings.Trim(address, "[]")); err != nil {
				scan.refuse("--resolve value is malformed")
				continue
			}
			scan.addHost(scheme, address, fields[1], "--resolve")
		}
	}
	return scan
}

// curlGuessedScheme is the protocol curl assumes for a URL without one: it
// guesses from the first label of the host and falls back to HTTP.
func curlGuessedScheme(raw string) string {
	host := raw
	if end := strings.IndexAny(host, "/?#"); end >= 0 {
		host = host[:end]
	}
	host = strings.ToLower(host[strings.LastIndex(host, "@")+1:])
	for _, scheme := range []string{"ftp", "dict", "ldap", "imap", "smtp", "pop3"} {
		if strings.HasPrefix(host, scheme+".") {
			return scheme
		}
	}
	return "http"
}
