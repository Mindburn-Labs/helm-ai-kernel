package shellscan

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/netdest"
)

// This file resolves where a network command connects. The rule is the same
// for every tool: each destination the arguments name is reported, an option
// that moves the connection adds the place it moves to, and anything that
// leaves the set open (an unknown option, a value read from a file, a client
// that follows redirects) makes the whole command undetermined. Nothing here
// guesses: an unparsed argument is never skipped as harmless.

// optRole says what an option's value means for where a command connects.
type optRole uint8

const (
	rolePlain     optRole = iota // no effect on the destination
	roleURL                      // a URL the tool connects to
	roleProxy                    // [scheme://]host[:port] the connection goes through
	roleConnectTo                // curl HOST1:PORT1:HOST2:PORT2
	roleResolve                  // curl HOST:PORT:ADDR[,ADDR]
	rolePort                     // port of the destination operand
	roleJump                     // ssh jump hosts
	roleSSHOption                // ssh -o Key=Value
	roleConfig                   // git name=value configuration
	roleOpaque                   // leaves the destination set unknowable
)

// cliSpec describes one tool's command line well enough to tell options from
// operands. An option missing from it is reported as unknown rather than
// assumed to take no value, because a wrong guess would hide an operand.
type cliSpec struct {
	short map[byte]string    // short letter -> option name
	value map[string]optRole // options that take a value
	flag  map[string]optRole // options that take none
	// optional lists options whose value is only ever attached
	// (--name[=value]); the next token is never consumed for them.
	optional map[string]optRole
	words    map[string]string // whole tokens that are options (wget -nv)
	// equals accepts --name=value; negatable accepts --no-name for a flag.
	equals, negatable bool
	// operandsEnd, when positive, is the operand at which option parsing
	// stops: 1 for a client that reads no option after its first operand, 2
	// for ssh, which keeps reading options after the host and stops at the
	// first word of the remote command. Zero reads options everywhere.
	operandsEnd int
}

type cliVisitor struct {
	option  func(name string, role optRole, value string)
	operand func(token string)
	// invalid reports a token that cannot be placed: an unknown option or an
	// option whose value is missing.
	invalid func(reason string)
}

func walkCLI(spec cliSpec, tokens []string, visit cliVisitor) {
	operandsOnly := false
	operands := 0
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		if operandsOnly || token == "" || token == "-" || !strings.HasPrefix(token, "-") {
			visit.operand(token)
			operands++
			operandsOnly = operandsOnly || spec.operandsEnd > 0 && operands >= spec.operandsEnd
			continue
		}
		if token == "--" {
			operandsOnly = true
			continue
		}
		if name, ok := spec.words[token]; ok {
			visit.option(name, spec.flag[name], "")
			continue
		}
		if strings.HasPrefix(token, "--") {
			name, value, attached := strings.Cut(token[2:], "=")
			if role, ok := spec.optional[name]; ok {
				visit.option(name, role, value)
				continue
			}
			if role, ok := spec.value[name]; ok {
				if attached && !spec.equals {
					visit.invalid("option --" + name + " does not take =value")
					continue
				}
				if !attached {
					if i+1 >= len(tokens) {
						visit.invalid("--" + name + " has no value")
						continue
					}
					i++
					value = tokens[i]
				}
				visit.option(name, role, value)
				continue
			}
			role, ok := spec.flag[name]
			if !ok && spec.negatable {
				role, ok = spec.flag[strings.TrimPrefix(name, "no-")]
				// Destination-changing negations must be explicit flag entries
				// above, such as curl --no-ftp-skip-pasv-ip.
				role = rolePlain
			}
			if !ok || attached {
				visit.invalid("option --" + name + " is not recognized")
				continue
			}
			visit.option(name, role, "")
			continue
		}
		cluster := token[1:]
		for j := 0; j < len(cluster); j++ {
			name, ok := spec.short[cluster[j]]
			if !ok {
				visit.invalid("option -" + cluster[j:j+1] + " is not recognized")
				break
			}
			role, takesValue := spec.value[name]
			if !takesValue {
				visit.option(name, spec.flag[name], "")
				continue
			}
			value := cluster[j+1:]
			if value == "" {
				if i+1 >= len(tokens) {
					visit.invalid(optionLabel(name) + " has no value")
					break
				}
				i++
				value = tokens[i]
			}
			visit.option(name, role, value)
			break
		}
	}
}

func optionLabel(name string) string {
	if len(name) == 1 {
		return "-" + name
	}
	return "--" + name
}

// egressScan is what one command's arguments say about where it connects.
type egressScan struct {
	destinations []netdest.Destination
	// seen holds the destinations already added, so a command that names
	// many costs time in proportion to their number, not its square.
	seen map[netdest.Destination]bool
	// undetermined says why the destinations are not all known. Once set, the
	// command as a whole is undetermined whatever else was resolved.
	undetermined string
}

func (s *egressScan) add(destination netdest.Destination) {
	if s.seen[destination] {
		return
	}
	if s.seen == nil {
		s.seen = map[netdest.Destination]bool{}
	}
	s.seen[destination] = true
	s.destinations = append(s.destinations, destination)
}

func (s *egressScan) refuse(reason string) {
	if s.undetermined == "" {
		s.undetermined = reason
	}
}

// addTarget parses one destination, or marks the scan undetermined when it is
// not one concrete endpoint.
func (s *egressScan) addTarget(raw, defaultScheme, what string) (netdest.Destination, bool) {
	destination, err := netdest.ParseWithScheme(raw, defaultScheme)
	if err != nil {
		s.refuse(what + " could not be parsed")
		return netdest.Destination{}, false
	}
	s.add(destination)
	return destination, true
}

// addHost adds scheme://host[:port] built from separate parts.
func (s *egressScan) addHost(scheme, host, port, what string) {
	canonical, err := netdest.CanonicalHost(host)
	if err != nil {
		s.refuse(what + " could not be parsed")
		return
	}
	if port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			s.refuse(what + " could not be parsed")
			return
		}
		port = strconv.Itoa(number)
		if port == netdest.DefaultPort(scheme) {
			port = ""
		}
	}
	s.add(netdest.Destination{Scheme: scheme, Host: canonical, Port: port})
}

func names(list string) map[string]optRole {
	out := map[string]optRole{}
	for _, name := range strings.Fields(list) {
		out[name] = rolePlain
	}
	return out
}

func withRoles(base map[string]optRole, roles map[string]optRole) map[string]optRole {
	for name, role := range roles {
		base[name] = role
	}
	return base
}

// letters builds single-letter options whose name is the letter itself.
func letters(valueLetters, flagLetters string) (short map[byte]string, value, flag map[string]optRole) {
	short, value, flag = map[byte]string{}, map[string]optRole{}, map[string]optRole{}
	for i := 0; i < len(valueLetters); i++ {
		short[valueLetters[i]] = valueLetters[i : i+1]
		value[valueLetters[i:i+1]] = rolePlain
	}
	for i := 0; i < len(flagLetters); i++ {
		short[flagLetters[i]] = flagLetters[i : i+1]
		flag[flagLetters[i:i+1]] = rolePlain
	}
	return short, value, flag
}

// opaqueReasons explains, per tool and option, why the option leaves the
// destination set open. An opaque option without an entry gets a generic
// sentence.
var opaqueReasons = map[string]string{
	"curl config":               "--config reads destinations from a file",
	"curl location":             "--location follows redirects to hosts the command line does not name",
	"curl location-trusted":     "--location-trusted follows redirects to hosts the command line does not name",
	"curl metalink":             "--metalink takes mirrors from a file",
	"curl unix-socket":          "--unix-socket connects through a local socket",
	"curl abstract-unix-socket": "--abstract-unix-socket connects through a local socket",
	"curl dns-servers":          "--dns-servers sends lookups to other resolvers",
	"curl alt-svc":              "--alt-svc lets a cache file redirect the connection",
	"curl no-ftp-skip-pasv-ip":  "--no-ftp-skip-pasv-ip accepts a server-selected data destination",
	"curl ftp-port":             "--ftp-port opens a connection back from the server",
	"curl proto-default":        "--proto-default changes the protocol of every URL",
	"curl variable":             "--variable builds arguments at run time",
	"wget execute":              "--execute runs a wgetrc command that can set a proxy",
	"wget input-file":           "--input-file reads URLs from a file",
	"wget config":               "--config reads settings from a file",
	"wget span-hosts":           "--span-hosts follows links to other hosts",
	"wget input-metalink":       "--input-metalink takes mirrors from a file",
	"wget metalink-over-http":   "--metalink-over-http takes mirrors from the server",
	"wget dns-servers":          "--dns-servers sends lookups to other resolvers",
	"ssh F":                     "-F reads hosts from a configuration file",
	"ssh S":                     "-S reuses a control connection to whatever host opened it",
	"ssh O":                     "-O drives a control connection to whatever host opened it",
	"scp F":                     "-F reads hosts from a configuration file",
	"scp S":                     "-S replaces the program that makes the connection",
	"sftp F":                    "-F reads hosts from a configuration file",
	"sftp S":                    "-S replaces the program that makes the connection",
	"sftp D":                    "-D replaces the connection with a local command",
	"nc l":                      "-l listens for inbound connections",
	"nc U":                      "-U connects through a local socket",
}

func opaqueReason(tool, name string) string {
	if reason, ok := opaqueReasons[tool+" "+name]; ok {
		return reason
	}
	return optionLabel(name) + " leaves the destination open"
}

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
		haproxy-clientip header hostpubmd5 hostpubsha256 hsts interface json keepalive-time
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
		"dns-servers": roleOpaque, "alt-svc": roleOpaque, "ftp-port": roleOpaque,
		"proto-default": roleOpaque, "variable": roleOpaque,
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

func curlEgress(tokens []string) egressScan {
	var scan egressScan
	var urls, connectTo, resolve []string
	walkCLI(curlSpec, tokens, cliVisitor{
		operand: func(token string) { urls = append(urls, token) },
		invalid: scan.refuse,
		option: func(name string, role optRole, value string) {
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
	for _, raw := range urls {
		if strings.HasPrefix(strings.ToLower(raw), "file:") {
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

// splitColonFields splits on the colons that are not inside an IPv6 bracket.
func splitColonFields(value string) []string {
	var fields []string
	start, depth := 0, 0
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		case ':':
			if depth == 0 {
				fields = append(fields, value[start:i])
				start = i + 1
			}
		}
	}
	return append(fields, value[start:])
}

var wgetSpec = cliSpec{
	equals: true,
	short: map[byte]string{
		'e': "execute", 'o': "output-file", 'a': "append-output", 'i': "input-file", 'B': "base",
		't': "tries", 'O': "output-document", 'T': "timeout", 'w': "wait", 'Q': "quota",
		'P': "directory-prefix", 'U': "user-agent", 'l': "level", 'A': "accept", 'R': "reject",
		'D': "domains", 'I': "include-directories", 'X': "exclude-directories",
		'V': "version", 'h': "help", 'b': "background", 'q': "quiet", 'v': "verbose",
		'd': "debug", 'F': "force-html", 'c': "continue", 'N': "timestamping",
		'S': "server-response", '4': "inet4-only", '6': "inet6-only", 'x': "force-directories",
		'E': "adjust-extension", 'r': "recursive", 'k': "convert-links", 'K': "backup-converted",
		'm': "mirror", 'p': "page-requisites", 'H': "span-hosts", 'L': "relative",
	},
	words: map[string]string{
		"-nv": "no-verbose", "-nc": "no-clobber", "-nd": "no-directories",
		"-nH": "no-host-directories", "-np": "no-parent",
	},
	value: withRoles(names(`
		output-file append-output report-speed base rejected-log tries retry-on-http-error
		output-document start-pos progress timeout dns-timeout connect-timeout read-timeout
		wait waitretry quota bind-address limit-rate restrict-file-names prefer-family user
		password use-askpass local-encoding remote-encoding directory-prefix cut-dirs
		http-user http-password default-page header compression max-redirect proxy-user
		proxy-password referer user-agent load-cookies save-cookies post-data post-file
		method body-data body-file secure-protocol certificate certificate-type private-key
		private-key-type ca-certificate ca-directory crl-file pinnedpubkey random-file ciphers
		hsts-file ftp-user ftp-password warc-file warc-header warc-max-size warc-dedup
		warc-tempdir level backups accept reject accept-regex reject-regex regex-type domains
		exclude-domains follow-tags ignore-tags include-directories exclude-directories
	`), map[string]optRole{
		"execute": roleOpaque, "input-file": roleOpaque, "config": roleOpaque,
		"input-metalink": roleOpaque, "dns-servers": roleOpaque,
	}),
	flag: withRoles(names(`
		version help background quiet verbose no-verbose debug force-html no-config
		retry-connrefused retry-on-host-error no-clobber no-netrc continue show-progress
		timestamping no-if-modified-since no-use-server-timestamps server-response spider
		random-wait no-proxy no-dns-cache ignore-case inet4-only inet6-only ask-password
		no-iri unlink xattr no-directories force-directories no-host-directories
		protocol-directories no-cache adjust-extension ignore-length save-headers
		no-http-keep-alive no-cookies keep-session-cookies content-disposition
		content-on-error auth-no-challenge https-only no-check-certificate no-hsts
		no-remove-listing no-glob no-passive-ftp preserve-permissions retr-symlinks
		ftps-implicit ftps-resume-ssl ftps-clear-data-connection ftps-fallback-to-ftp
		warc-cdx no-warc-compression no-warc-digests no-warc-keep-log recursive delete-after
		convert-links convert-file-only backup-converted mirror page-requisites
		strict-comments follow-ftp relative trust-server-names no-parent
	`), map[string]optRole{
		"span-hosts": roleOpaque, "metalink-over-http": roleOpaque,
	}),
}

func wgetEgress(tokens []string) egressScan {
	var scan egressScan
	var urls []string
	redirects := true
	walkCLI(wgetSpec, tokens, cliVisitor{
		operand: func(token string) { urls = append(urls, token) },
		invalid: scan.refuse,
		option: func(name string, role optRole, value string) {
			if role == roleOpaque {
				scan.refuse(opaqueReason("wget", name))
			}
			if name == "max-redirect" {
				redirects = strings.TrimSpace(value) != "0"
			}
		},
	})
	for _, raw := range urls {
		defaultScheme := ""
		if !netdest.HasScheme(raw) {
			defaultScheme = "http"
		}
		scan.addTarget(raw, defaultScheme, "a URL")
	}
	if len(urls) > 0 && redirects {
		scan.refuse("wget follows redirects to hosts the command line does not name; pass --max-redirect=0")
	}
	return scan
}

func sshFamilySpec(valueLetters, flagLetters string, roles map[string]optRole, operandsEnd int) cliSpec {
	short, value, flag := letters(valueLetters, flagLetters)
	for name, role := range roles {
		if _, ok := value[name]; ok {
			value[name] = role
		}
	}
	return cliSpec{short: short, value: value, flag: flag, operandsEnd: operandsEnd}
}

var (
	sshSpec = sshFamilySpec("BbcDEeFIiJLlmOoPpQRSWw", "46AaCfGgKkMNnqsTtVvXxYy", map[string]optRole{
		"p": rolePort, "J": roleJump, "o": roleSSHOption, "F": roleOpaque, "S": roleOpaque, "O": roleOpaque,
		// ssh takes its host, then goes back to reading options, and treats
		// the next operand as the start of the remote command (ssh.c parses
		// the remaining arguments again after the host). An option written
		// after the host is therefore an option, not part of the command.
	}, 2)
	scpSpec = sshFamilySpec("cDFiJloPSX", "346ABCOpqRrsTv", map[string]optRole{
		"P": rolePort, "J": roleJump, "o": roleSSHOption, "F": roleOpaque, "S": roleOpaque,
	}, 0)
	sftpSpec = sshFamilySpec("BbcDFiJloPRSsX", "46AaCfNpqrv", map[string]optRole{
		"P": rolePort, "J": roleJump, "o": roleSSHOption, "F": roleOpaque, "S": roleOpaque, "D": roleOpaque,
	}, 0)
)

// sshConnection collects the options the OpenSSH clients share.
type sshConnection struct {
	scan     *egressScan
	tool     string
	port     string
	hostName string // -o HostName, which replaces the host that was typed
	offline  bool   // the invocation prints something and exits
	// operands counts the operands seen so far, for the clients where an
	// option after an operand is read by some builds and not by others.
	operands int
}

// optionAfterOperand refuses an scp or sftp option written after an operand.
// Whether the client reads it as an option depends on the getopt it was built
// with, so the destination it yields is not known from the text.
func (c *sshConnection) optionAfterOperand(name string, role optRole) bool {
	if c.operands == 0 || role == rolePlain {
		return false
	}
	c.scan.refuse(optionLabel(name) + " after an operand is read differently by different builds of " + c.tool)
	return true
}

func (c *sshConnection) option(name string, role optRole, value string) {
	switch role {
	case rolePort:
		c.setPort(value)
	case roleJump:
		c.jump(value)
	case roleSSHOption:
		c.configOption(value)
	case roleOpaque:
		c.scan.refuse(opaqueReason(c.tool, name))
	}
	if c.tool == "ssh" && (name == "V" || name == "G" || name == "Q") {
		c.offline = true
	}
}

// sshOpaqueOptions are -o keys that run a program or move the connection in a
// way the command line does not show.
var sshOpaqueOptions = map[string]bool{
	"proxycommand": true, "knownhostscommand": true, "localcommand": true,
	"controlpath": true, "controlmaster": true, "canonicalizehostname": true,
	"canonicaldomains": true, "canonicalizepermittedcnames": true, "proxyusefdpass": true,
}

// sshPlainOptions are -o keys that leave the host ssh connects to, and the
// program it connects with, as the command line shows them. A key in neither
// table makes the destination undetermined: a key that is not known here is
// not assumed to be harmless.
var sshPlainOptions = names(`
	addkeystoagent addressfamily batchmode bindaddress bindinterface
	casignaturealgorithms certificatefile checkhostip ciphers clearallforwardings
	compression connectionattempts connecttimeout controlpersist dynamicforward
	escapechar exitonforwardfailure fingerprinthash forkafterauthentication
	forwardagent forwardx11 forwardx11timeout forwardx11trusted gatewayports
	globalknownhostsfile gssapiauthentication gssapidelegatecredentials
	hashknownhosts hostbasedauthentication hostkeyalgorithms hostkeyalias
	identitiesonly identityagent identityfile ipqos kbdinteractiveauthentication
	kexalgorithms localforward loglevel logverbose macs
	nohostauthenticationforlocalhost numberofpasswordprompts
	passwordauthentication preferredauthentications pubkeyacceptedalgorithms
	pubkeyauthentication rekeylimit remoteforward requesttty requiredrsasize
	sendenv serveralivecountmax serveraliveinterval sessiontype setenv stdinnull
	stricthostkeychecking tcpkeepalive updatehostkeys user userknownhostsfile
	verifyhostkeydns visualhostkey`)

func (c *sshConnection) configOption(option string) {
	// ssh reads a configuration line here: it skips leading blanks and one
	// "=", ends the key at "=", a space or a tab, and skips the separator
	// before the value. So "-o=Key=Value" and "-o 'Key<TAB>Value'" set Key.
	option = strings.TrimLeft(option, " \t")
	option = strings.TrimLeft(strings.TrimPrefix(option, "="), " \t")
	original, value := option, ""
	if end := strings.IndexAny(option, "= \t"); end >= 0 {
		original, value = option[:end], strings.TrimLeft(option[end:], "= \t")
	}
	key := strings.ToLower(original)
	value = strings.TrimSpace(value)
	switch {
	case key == "hostname":
		// OpenSSH keeps the first HostName, even across repeated -o flags.
		if c.hostName != "" {
			return
		}
		// %h and the other tokens are expanded by ssh, not here.
		if strings.Contains(value, "%") {
			c.scan.refuse("-o HostName is built from a token")
			return
		}
		c.hostName = value
	case key == "port":
		c.setPort(value)
	case key == "proxyjump":
		c.jump(value)
	case sshOpaqueOptions[key]:
		if !strings.EqualFold(value, "none") && !strings.EqualFold(value, "no") {
			c.scan.refuse("-o " + original + " moves the connection")
		}
	default:
		if _, plain := sshPlainOptions[key]; !plain {
			c.scan.refuse("-o " + original + " is not an option whose effect on the connection is known")
		}
	}
}

func (c *sshConnection) setPort(value string) {
	// The clients forward -p/-P and -o Port differently. Refuse conflicts
	// rather than issue a receipt for a port a client may ignore.
	if c.port != "" && c.port != value {
		c.scan.refuse("conflicting port options")
		return
	}
	c.port = value
}

func (c *sshConnection) urlDestination(raw, what string) {
	if c.hostName != "" || c.port != "" {
		c.scan.refuse("a URL combined with HostName or port options has an unresolved destination")
		return
	}
	c.scan.addTarget(raw, "", what)
}

func (c *sshConnection) jump(value string) {
	if strings.EqualFold(value, "none") {
		return
	}
	for _, hop := range strings.Split(value, ",") {
		c.destination(hop, "", "a jump host")
	}
}

// destination adds [user@]host[:port] or an ssh:// URL. port, when set,
// applies to a host written without one.
func (c *sshConnection) destination(raw, port, what string) {
	if netdest.HasScheme(raw) {
		c.scan.addTarget(raw, "", what)
		return
	}
	host := raw[strings.LastIndex(raw, "@")+1:]
	if fields := splitColonFields(host); len(fields) == 2 {
		host, port = fields[0], fields[1]
	}
	c.scan.addHost("ssh", host, port, what)
}

func (c *sshConnection) final(host string) {
	if c.hostName != "" {
		host = c.hostName
	}
	c.scan.addHost("ssh", host, c.port, "the host")
}

func sshEgress(tokens []string) egressScan {
	var scan egressScan
	connection := sshConnection{scan: &scan, tool: "ssh"}
	var host string
	seen := false
	walkCLI(sshSpec, tokens, cliVisitor{
		invalid: scan.refuse,
		option:  connection.option,
		operand: func(token string) {
			if !seen {
				host, seen = token, true
			}
		},
	})
	if connection.offline || !seen {
		return egressScan{}
	}
	if netdest.HasScheme(host) {
		connection.urlDestination(host, "the host")
		return scan
	}
	connection.final(host[strings.LastIndex(host, "@")+1:])
	return scan
}

func sftpEgress(tokens []string) egressScan {
	var scan egressScan
	connection := sshConnection{scan: &scan, tool: "sftp"}
	var destination string
	seen := false
	walkCLI(sftpSpec, tokens, cliVisitor{
		invalid: scan.refuse,
		option: func(name string, role optRole, value string) {
			if !connection.optionAfterOperand(name, role) {
				connection.option(name, role, value)
			}
		},
		operand: func(token string) {
			connection.operands++
			if !seen {
				destination, seen = token, true
			}
		},
	})
	if !seen {
		return egressScan{}
	}
	if netdest.HasScheme(destination) {
		connection.urlDestination(destination, "the host")
		return scan
	}
	// sftp takes host[:path]; a name without a colon is still a host.
	host, _, ok := remoteSpec(destination)
	if !ok {
		host = destination[strings.LastIndex(destination, "@")+1:]
	}
	connection.final(host)
	return scan
}

func scpEgress(tokens []string) egressScan {
	var scan egressScan
	connection := sshConnection{scan: &scan, tool: "scp"}
	var operands []string
	walkCLI(scpSpec, tokens, cliVisitor{
		invalid: scan.refuse,
		option: func(name string, role optRole, value string) {
			if !connection.optionAfterOperand(name, role) {
				connection.option(name, role, value)
			}
		},
		operand: func(token string) {
			connection.operands++
			operands = append(operands, token)
		},
	})
	for _, operand := range operands {
		if netdest.HasScheme(operand) {
			connection.urlDestination(operand, "a remote")
			continue
		}
		if host, _, ok := remoteSpec(operand); ok {
			connection.final(host)
		}
	}
	return scan
}

// remoteSpec splits the [user@]host:path form that scp, rsync and git share.
// A path is remote when a colon comes before any slash; an IPv6 host is
// written in brackets. C:\ and C:/ are Windows drive paths.
func remoteSpec(value string) (host, rest string, ok bool) {
	if value == "" || strings.HasPrefix(value, ":") || strings.HasPrefix(value, "-") {
		return "", "", false
	}
	depth := 0
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		case '/', '\\':
			if depth == 0 {
				return "", "", false
			}
		case ':':
			if depth > 0 {
				continue
			}
			host, rest = value[:i], value[i+1:]
			if len(host) == 1 && (strings.HasPrefix(rest, `\`) || strings.HasPrefix(rest, "/")) {
				return "", "", false
			}
			return host[strings.LastIndex(host, "@")+1:], rest, true
		}
	}
	return "", "", false
}

func rsyncEgress(tokens []string) egressScan {
	var scan egressScan
	port := ""
	endOptions := false
	var operands []string
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		if !endOptions && token == "--" {
			endOptions = true
			continue
		}
		if endOptions || !strings.HasPrefix(token, "-") || token == "-" {
			operands = append(operands, token)
			continue
		}
		name, value, attached := strings.Cut(token, "=")
		switch {
		case name == "--rsh" || !strings.HasPrefix(token, "--") && strings.Contains(token, "e"):
			scan.refuse("the remote shell option replaces the program that makes the connection")
		case name == "--daemon":
			scan.refuse("--daemon listens for inbound connections")
		case name == "--port":
			if !attached && i+1 < len(tokens) {
				i++
				value = tokens[i]
			}
			port = value
		}
	}
	for _, operand := range operands {
		if netdest.HasScheme(operand) {
			if !strings.HasPrefix(strings.ToLower(operand), "file:") {
				scan.addTarget(operand, "", "a remote")
			}
			continue
		}
		host, rest, ok := remoteSpec(operand)
		if !ok {
			continue
		}
		// host::module talks to an rsync daemon; host:path runs over ssh.
		if strings.HasPrefix(rest, ":") {
			scan.addHost("rsync", host, port, "a remote")
			continue
		}
		scan.addHost("ssh", host, "", "a remote")
	}
	return scan
}

var netcatSpec = func() cliSpec {
	short, value, flag := letters("IiMmOPpqsTVWwXx", "46bCDdFhklNnrStUuvZz")
	value["x"] = roleProxy
	flag["l"], flag["U"] = roleOpaque, roleOpaque
	return cliSpec{short: short, value: value, flag: flag}
}()

func netcatEgress(tokens []string) egressScan {
	var scan egressScan
	scheme, proxy := "tcp", ""
	var operands []string
	walkCLI(netcatSpec, tokens, cliVisitor{
		invalid: scan.refuse,
		operand: func(token string) { operands = append(operands, token) },
		option: func(name string, role optRole, value string) {
			switch {
			case role == roleOpaque:
				scan.refuse(opaqueReason("nc", name))
			case role == roleProxy:
				proxy = value
			case name == "u":
				scheme = "udp"
			}
		},
	})
	if proxy != "" {
		scan.addTarget(proxy, "tcp", "-x")
	}
	if len(operands) == 0 {
		return scan
	}
	if len(operands) == 1 {
		scan.addHost(scheme, operands[0], "", "the host")
		return scan
	}
	for _, port := range operands[1:] {
		if _, err := strconv.Atoi(port); err != nil {
			port = "" // a range or a service name: the host is what is decided
		}
		scan.addHost(scheme, operands[0], port, "the host")
	}
	return scan
}

var telnetSpec = func() cliSpec {
	short, value, flag := letters("XbeklnS", "468EKLacdfrxF")
	return cliSpec{short: short, value: value, flag: flag}
}()

func telnetEgress(tokens []string) egressScan {
	var scan egressScan
	var operands []string
	walkCLI(telnetSpec, tokens, cliVisitor{
		invalid: scan.refuse,
		option:  func(string, optRole, string) {},
		operand: func(token string) { operands = append(operands, token) },
	})
	switch len(operands) {
	case 0:
	case 1:
		scan.addHost("tcp", operands[0], "23", "the host")
	default:
		scan.addHost("tcp", operands[0], operands[1], "the host")
	}
	return scan
}

// opensslClientFlags and opensslClientValues are the s_client and s_time
// options that leave the peer as -connect, -host and -port name it. An option
// in neither table makes the destination undetermined: several of the others
// fetch from an address (-crl_download, a store URI) or load code (-engine,
// -provider), and a table that skipped what it did not know would pass them.
var opensslClientFlags = names(`
	4 6 quiet brief showcerts crlf ign_eof no_ign_eof state debug msg prexit
	tls1 tls1_1 tls1_2 tls1_3 dtls dtls1 dtls1_2 no_ssl3 no_tls1 no_tls1_1
	no_tls1_2 no_tls1_3 reconnect status tlsextdebug nocommands
	verify_return_error verify_quiet no_ticket comp no_comp bugs nbio
	noservername trace security_debug security_debug_verbose partial_chain
	no_check_time x509_strict enable_pha legacy_renegotiation no_renegotiation
	legacy_server_connect no_legacy_server_connect fallback_scsv serverpref
	new reuse`)

var opensslClientValues = names(`
	servername verify verify_depth verify_hostname verify_ip verify_email
	verify_name cert key cert_chain certform keyform pass cafile capath
	chaincafile cipher ciphersuites sigalgs client_sigalgs curves groups alpn
	nextprotoneg starttls xmpphost name sess_in sess_out psk psk_identity
	keylogfile msgfile bind maxfraglen max_send_frag split_send_frag mtu
	min_protocol max_protocol proxy_user proxy_pass attime purpose time www
	keymatexport keymatexportlen`)

// opensslEgress covers s_client and s_time, the openssl subcommands that open
// a client connection. The peer is the value of -connect, of -host with
// -port, or an operand written as host:port; -proxy is a second destination.
// openssl accepts -name, --name and name=value spellings of every option.
func opensslEgress(tokens []string) egressScan {
	var scan egressScan
	host, port := "", ""
	connected := false
	for i := 1; i < len(tokens); i++ {
		token := tokens[i]
		if !strings.HasPrefix(token, "-") || token == "-" {
			// OpenSSL 3 takes the peer as an operand.
			scan.addTarget(token, "tcp", "the host")
			connected = true
			continue
		}
		name, value, attached := strings.Cut(strings.TrimLeft(token, "-"), "=")
		name = strings.ToLower(name)
		next := func() (string, bool) {
			if attached {
				return value, true
			}
			if i+1 >= len(tokens) {
				scan.refuse(token + " has no value")
				return "", false
			}
			i++
			return tokens[i], true
		}
		switch {
		case name == "help":
			return egressScan{}
		case name == "connect" || name == "proxy":
			if target, ok := next(); ok {
				scan.addTarget(target, "tcp", "-"+name)
				connected = connected || name == "connect"
			}
		case name == "host":
			host, _ = next()
		case name == "port":
			port, _ = next()
		case name == "unix":
			scan.refuse("-unix connects through a local socket")
		default:
			if _, flag := opensslClientFlags[name]; flag && !attached {
				continue
			}
			if _, takesValue := opensslClientValues[name]; !takesValue {
				scan.refuse("openssl option " + token + " is not one whose effect on the connection is known")
				continue
			}
			// A file option also accepts a store URI, which openssl fetches.
			if argument, ok := next(); ok && netdest.HasScheme(argument) {
				scan.refuse(token + " names an address openssl loads from")
			}
		}
	}
	switch {
	case connected:
		// -connect wins over -host and -port when both are given.
	case host != "" || port != "":
		if host == "" {
			host = "localhost"
		}
		if port == "" {
			port = "4433"
		}
		scan.addHost("tcp", host, port, "-host")
	default:
		// Without a peer the client dials its built-in default address.
		scan.addHost("tcp", "localhost", "4433", "the default address")
	}
	return scan
}

// opensslFetchEgress covers the other openssl subcommands. They read keys and
// certificates from files, but ocsp and cmp talk to a responder, and any of
// them loads an argument written as a URL from that address.
func opensslFetchEgress(tokens []string) (egressScan, bool) {
	var scan egressScan
	if len(tokens) == 0 {
		return scan, false
	}
	sub := tokens[0]
	for i := 1; i < len(tokens); i++ {
		name, value, attached := strings.Cut(strings.ToLower(strings.TrimLeft(tokens[i], "-")), "=")
		isOption := strings.HasPrefix(tokens[i], "-")
		switch {
		case isOption && (sub == "ocsp" && name == "host" || sub == "cmp" && (name == "server" || name == "proxy")):
			if !attached && i+1 < len(tokens) {
				i++
				value = tokens[i]
			}
			scan.addTarget(value, "http", "-"+name)
		case isOption && sub == "cmp" && name == "config":
			scan.refuse("cmp reads its server from a configuration file")
		case netdest.HasScheme(tokens[i]) && !strings.HasPrefix(strings.ToLower(tokens[i]), "file:"):
			scan.addTarget(tokens[i], "", "a URL")
		case attached && netdest.HasScheme(value) && !strings.HasPrefix(value, "file:"):
			scan.addTarget(tokens[i][strings.Index(tokens[i], "=")+1:], "", "a URL")
		}
	}
	return scan, len(scan.destinations) > 0 || scan.undetermined != ""
}

// egressResolvers are the tools whose destinations are read from their
// arguments.
var egressResolvers = map[string]func([]string) egressScan{
	"curl":    curlEgress,
	"wget":    wgetEgress,
	"ssh":     sshEgress,
	"scp":     scpEgress,
	"sftp":    sftpEgress,
	"rsync":   rsyncEgress,
	"nc":      netcatEgress,
	"ncat":    netcatEgress,
	"netcat":  netcatEgress,
	"telnet":  telnetEgress,
	"openssl": opensslEgress,
}

// unparsedNetworkTools open connections, but their destinations are not read
// here: they take them from scripts, peers, mirrors or an address syntax of
// their own. They are always undetermined.
var unparsedNetworkTools = map[string]string{
	"aria2c": "aria2c follows redirects, mirrors and peers",
	"ftp":    "ftp opens hosts from commands it reads at run time",
	"lftp":   "lftp opens hosts from commands it reads at run time",
	"socat":  "socat addresses are not parsed",
	"http":   "http (HTTPie) arguments are not parsed",
	"https":  "https (HTTPie) arguments are not parsed",
	"httpie": "httpie arguments are not parsed",
	// These run another command with its connections sent through a proxy.
	"proxychains":  "proxychains routes the command through a proxy",
	"proxychains4": "proxychains4 routes the command through a proxy",
	"torsocks":     "torsocks routes the command through a proxy",
	"torify":       "torify routes the command through a proxy",
	"tsocks":       "tsocks routes the command through a proxy",
}

// egressTool reports whether name is a program this file resolves or refuses
// as a network client.
func egressTool(name string) bool {
	return name == "git" || egressResolvers[name] != nil || unparsedNetworkTools[name] != ""
}

// dynamicToken stands in for an argument computed at run time where a
// resolver needs to know which argument it was. No parser accepts it.
const dynamicToken = "\x00dynamic"

// commandEgress reports where one command connects. network is false for a
// command that opens no connection. overrides are the connection variables
// the command line sets.
func commandEgress(command Command, overrides []envOverride) (scan egressScan, network bool) {
	tokens := command.Tokens
	if len(tokens) > 0 {
		tokens = tokens[1:]
	}
	switch {
	case command.Name == "git":
		// git tells a computed refspec from a computed address, so it gets the
		// arguments with the computed ones marked instead of a blanket refusal.
		marked := append([]string(nil), tokens...)
		for i := range marked {
			if i+1 < len(command.dynamic) && command.dynamic[i+1] {
				marked[i] = dynamicToken
			}
		}
		var configured bool
		scan, network, configured = gitEgress(marked)
		// A configured remote is operator configuration, unless the command
		// line also sets a variable that moves the connection.
		return scan, network && !(configured && len(overrides) == 0)
	case command.Name == "openssl" && (len(tokens) == 0 || tokens[0] != "s_client" && tokens[0] != "s_time"):
		// Digests, encodings and key handling open no connection, unless an
		// argument is an address to load from or a responder to ask.
		scan, network = opensslFetchEgress(tokens)
		if !network {
			return egressScan{}, false
		}
	case egressResolvers[command.Name] != nil:
		scan = egressResolvers[command.Name](tokens)
		network = len(scan.destinations) > 0 || scan.undetermined != "" || command.Dynamic && hasOperand(tokens)
	case unparsedNetworkTools[command.Name] != "":
		if !hasOperand(tokens) && !command.Dynamic {
			return egressScan{}, false // --help, --version: nothing connects
		}
		return egressScan{undetermined: unparsedNetworkTools[command.Name]}, true
	}
	if network && command.Dynamic {
		// The resolved part of a computed argument says nothing about the rest.
		scan = egressScan{undetermined: "an argument is computed at run time"}
	}
	return scan, network
}

func hasOperand(tokens []string) bool {
	for _, token := range tokens {
		if token != "" && (token == "-" || !strings.HasPrefix(token, "-")) {
			return true
		}
	}
	return false
}

// envOverride is a variable the command line sets for the programs it runs.
type envOverride struct {
	name    string
	value   string
	dynamic bool
}

// proxyVariables name a proxy every HTTP-speaking client honours.
var proxyVariables = map[string]bool{
	"http_proxy": true, "https_proxy": true, "all_proxy": true, "ftp_proxy": true, "rsync_proxy": true,
}

// connectionVariables change the program or the configuration a client
// connects with, so the destination is no longer what the arguments say.
var connectionVariables = map[string]bool{
	"home": true, "xdg_config_home": true, "curl_home": true, "wgetrc": true,
	"git_ssh": true, "git_ssh_command": true, "git_proxy_command": true,
	"git_config": true, "git_config_global": true, "git_config_system": true,
	"git_config_count": true, "git_config_parameters": true, "git_exec_path": true,
	"rsync_rsh": true, "rsync_connect_prog": true,
	"ld_preload": true, "dyld_insert_libraries": true,
}

// shellStartupVariables name a file a shell runs before its command, so a
// command run with one set first does what that file says. Shells read them
// in upper case only.
var shellStartupVariables = map[string]bool{"BASH_ENV": true, "ENV": true}

// tracksVariable reports whether an assignment to name matters for egress.
func tracksVariable(name string) bool {
	lower := strings.ToLower(name)
	return proxyVariables[lower] || connectionVariables[lower] || shellStartupVariables[name]
}

func applyEnvOverrides(scan *egressScan, overrides []envOverride) {
	for _, override := range overrides {
		name := strings.ToLower(override.name)
		switch {
		case override.name == "":
			// The name itself is computed, so it may be any of the variables
			// a client reads.
			scan.refuse("a variable is set under a name computed at run time")
		case shellStartupVariables[override.name]:
			scan.refuse(override.name + " makes a shell run another file first")
		case connectionVariables[name]:
			scan.refuse(override.name + " changes how the client connects")
		case !proxyVariables[name]:
		case override.dynamic:
			scan.refuse(override.name + " is computed at run time")
		case override.value != "":
			scan.addTarget(override.value, "http", override.name)
		}
	}
}

// networkFacts turns one command's scan into effect facts: one per
// destination, or a single undetermined fact.
func networkFacts(command Command, overrides []envOverride) []EffectFact {
	scan, network := commandEgress(command, overrides)
	if !network {
		return nil
	}
	applyEnvOverrides(&scan, overrides)
	return scan.facts(command.Name)
}

func (s egressScan) facts(via string) []EffectFact {
	if s.undetermined != "" {
		return []EffectFact{{
			Class:  "network",
			Action: "network_egress",
			Target: netdest.Undetermined,
			Reason: "network egress via " + via + ": destination could not be determined (" + s.undetermined + ")",
		}}
	}
	facts := make([]EffectFact, 0, len(s.destinations))
	for _, destination := range s.destinations {
		facts = append(facts, EffectFact{
			Class:  "network",
			Action: "network_egress",
			Target: destination.String(),
			Reason: "network egress via " + via,
		})
	}
	return facts
}

// deviceSocketEgress resolves a bash /dev/tcp/host/port or /dev/udp/host/port
// redirect target, which opens a socket without running any program.
func deviceSocketEgress(target wordTok) (egressScan, bool) {
	var scheme string
	switch {
	case strings.HasPrefix(target.text, "/dev/tcp/"):
		scheme = "tcp"
	case strings.HasPrefix(target.text, "/dev/udp/"):
		scheme = "udp"
	default:
		return egressScan{}, false
	}
	var scan egressScan
	parts := strings.Split(target.text[len("/dev/tcp/"):], "/")
	switch {
	case target.dynamic || target.glob:
		scan.refuse("the socket address is computed at run time")
	case len(parts) != 2:
		scan.refuse("the socket address could not be parsed")
	default:
		scan.addHost(scheme, parts[0], parts[1], "the socket address")
	}
	return scan, true
}
