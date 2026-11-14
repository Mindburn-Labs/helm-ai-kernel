package shellscan

import (
	"strings"
	"testing"
)

// The classifier reads a client's command line the way the client does. Each
// case here is a spelling the client accepts and that an earlier version of
// the tables read differently, so the destination it named was not the one
// the client connects to.
func TestClassifyReadsClientOptionsWhereverTheClientDoes(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    []string
	}{
		// ssh goes back to reading options after its host (ssh.c parses the
		// rest of the arguments again), so these set HostName and Port.
		{"ssh option after host", "ssh allowed.example -o HostName=other.example", []string{"ssh://other.example"}},
		{"ssh option after user@host", "ssh git@allowed.example -o HostName=other.example", []string{"ssh://other.example"}},
		{"ssh options between host and command", "ssh allowed.example -p 2222 -o HostName=other.example uptime", []string{"ssh://other.example:2222"}},
		{"ssh jump after host", "ssh allowed.example -J other.example", []string{"ssh://allowed.example", "ssh://other.example"}},
		// The remote command starts at the second operand; its words are not
		// options of ssh.
		{"ssh remote command arguments", "ssh allowed.example ls -o HostName=other.example", []string{"ssh://allowed.example"}},
		// ssh skips one "=" before the key and ends the key at "=", a space or
		// a tab.
		{"ssh -o=Key=Value", "ssh -o=HostName=other.example allowed.example", []string{"ssh://other.example"}},
		{"ssh -o key and tab", "ssh -o 'HostName\tother.example' allowed.example", []string{"ssh://other.example"}},
		{"ssh -o key and space", "ssh -o 'HostName other.example' allowed.example", []string{"ssh://other.example"}},
		// OpenSSH's first HostName wins, including across the host operand.
		{"ssh first HostName denied", "ssh -o HostName=other.example -o HostName=allowed.example allowed.example", []string{"ssh://other.example"}},
		{"ssh first HostName allowed", "ssh -o HostName=allowed.example -o HostName=other.example allowed.example", []string{"ssh://allowed.example"}},
		{"ssh repeated HostName after host", "ssh -o HostName=other.example allowed.example -o HostName=allowed.example", []string{"ssh://other.example"}},
		{"scp repeated HostName", "scp -o HostName=other.example -o HostName=allowed.example ./a allowed.example:/tmp/", []string{"ssh://other.example"}},
		{"sftp repeated HostName", "sftp -o HostName=other.example -o HostName=allowed.example allowed.example", []string{"ssh://other.example"}},
		{"ssh plain option keeps host", "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 allowed.example", []string{"ssh://allowed.example"}},
		{"scp -o=Key=Value", "scp -o=HostName=other.example ./a allowed.example:/tmp/", []string{"ssh://other.example"}},

		// openssl takes the peer as -connect, as -host with -port, or as an
		// operand, and spells every option -name, --name or name=value.
		{"openssl operand peer", "openssl s_client other.example:443", []string{"tcp://other.example:443"}},
		{"openssl -host and -port", "openssl s_client -host other.example -port 443", []string{"tcp://other.example:443"}},
		{"openssl -connect=value", "openssl s_client -connect=other.example:443", []string{"tcp://other.example:443"}},
		{"openssl --connect", "openssl s_client --connect other.example:443", []string{"tcp://other.example:443"}},
		{"openssl -connect wins over -host", "openssl s_client -connect allowed.example:443 -host other.example -port 443", []string{"tcp://allowed.example:443"}},
		{"openssl plain options", "openssl s_client -connect allowed.example:443 -servername allowed.example -showcerts -quiet", []string{"tcp://allowed.example:443"}},
		{"openssl ocsp responder", "openssl ocsp -issuer ca.pem -cert c.pem -url http://other.example/ocsp", []string{"http://other.example"}},
		{"openssl loads a URL", "openssl x509 -in https://other.example/c.pem -noout", []string{"https://other.example"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := Classify(tc.command)
			if got := networkTargets(res); !sameTargets(got, tc.want) {
				t.Fatalf("Classify(%q) network targets = %q, want %q (facts %+v)", tc.command, got, tc.want, res.EffectFacts)
			}
		})
	}
}

// What a client's table does not know makes the destination undetermined. It
// is never skipped as harmless and never turns the command into one with no
// network decision.
func TestClassifyRefusesWhatAClientTableDoesNotKnow(t *testing.T) {
	cases := []struct {
		name    string
		command string
		reason  string
	}{
		{"ssh unknown -o key", "ssh -o PKCS11Provider=/tmp/p.so allowed.example", "PKCS11Provider"},
		{"ssh conflicting config ports", "ssh -o Port=2222 -o Port=22 allowed.example", "conflicting port"},
		{"ssh conflicting flags", "ssh -p 2222 -p 22 allowed.example", "conflicting port"},
		{"ssh conflicting mixed ports", "ssh -o Port=2222 -p 22 allowed.example", "conflicting port"},
		{"scp conflicting ports", "scp -o Port=2222 -P 22 ./a allowed.example:/tmp/", "conflicting port"},
		{"sftp conflicting ports", "sftp -o Port=2222 -P 22 allowed.example", "conflicting port"},
		{"ssh URL and HostName", "ssh -o HostName=other.example ssh://allowed.example", "URL"},
		{"ssh URL and port", "ssh -p 2222 ssh://allowed.example", "URL"},
		{"scp URL and HostName", "scp -o HostName=other.example ./a scp://allowed.example/x", "URL"},
		{"sftp URL and HostName", "sftp -o HostName=other.example sftp://allowed.example/x", "URL"},
		{"ssh unknown -o key after host", "ssh allowed.example -o SecurityKeyProvider=/tmp/p.so", "SecurityKeyProvider"},
		{"ssh proxy command after host", "ssh allowed.example -o ProxyCommand='nc other.example 22'", "ProxyCommand"},
		{"scp option after operand", "scp ./a allowed.example:/tmp/ -o HostName=other.example", "after an operand"},
		{"sftp option after host", "sftp allowed.example -o HostName=other.example", "after an operand"},

		{"openssl unknown option", "openssl s_client -connect allowed.example:443 -crl_download", "-crl_download"},
		{"openssl engine", "openssl s_client -connect allowed.example:443 -engine /tmp/e.so", "-engine"},
		{"openssl provider", "openssl s_client -connect allowed.example:443 -provider-path /tmp -provider p", "-provider-path"},
		{"openssl store URI", "openssl s_client -connect allowed.example:443 -CAfile http://other.example/ca.pem", "loads from"},
		{"openssl cert URI", "openssl s_client -connect allowed.example:443 -cert https://other.example/c.pem", "loads from"},

		// git keeps the last value of a repeated key.
		{"git redirects turned back on", "git -c http.followRedirects=false -c http.followRedirects=true clone https://allowed.example/o/r.git", "redirect"},
		{"git redirects on in another case", "git -c http.followRedirects=false -c HTTP.FollowRedirects=initial clone https://allowed.example/o/r.git", "redirect"},
		{"git redirects on for one URL", "git -c http.followRedirects=false -c http.https://allowed.example/.followRedirects=true clone https://allowed.example/o/r.git", "redirect"},
		{"git redirects key without a value", "git -c http.followRedirects=false -c http.followRedirects clone https://allowed.example/o/r.git", "redirect"},
		// An option the table does not know hides where the subcommand is.
		{"git unknown global option", "git --frobnicate HEAD push origin main", "--frobnicate"},
		{"git exec path", "git --exec-path=/tmp/x push origin main", "--exec-path"},
		{"git ssh command", "git -c core.sshCommand=/tmp/x push origin main", "core.sshcommand"},
		{"git bundle URI", "git -c fetch.bundleURI=https://other.example/b fetch origin", "fetch.bundleuri"},
		{"git credential helper", "git -c credential.helper=/tmp/x fetch origin", "credential.helper"},
		// git config stores an address the next push uses by name.
		{"git config --file", "git config --file .git/config remote.origin.url https://other.example/r.git", ""},
		{"git config -f", "git config -f .git/config url.https://other.example/.insteadOf https://allowed.example/", "url."},
		{"git config --type before key", "git config --type path core.sshCommand /tmp/x", "core.sshcommand"},
		{"git config --comment before key", "git config --comment note remote.origin.pushurl other.example:r.git", ""},

		// A quoted assignment word still assigns.
		{"quoted export", `export "HTTPS_PROXY=http://other.example:8080"; curl https://allowed.example/`, ""},
		{"quoted declare -x", `declare -x 'https_proxy=http://other.example:8080'; curl https://allowed.example/`, ""},
		{"export of a computed name", `export "$NAME=http://other.example:8080"; curl https://allowed.example/`, "name computed"},
		{"quoted export of a computed proxy", `export "HTTPS_PROXY=$P"; curl https://allowed.example/`, "run time"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := Classify(tc.command)
			got := networkTargets(res)
			if tc.reason == "" {
				// The other host is a named destination, or the command is
				// undetermined; either way an allowlist of the first host
				// cannot approve it.
				if sameTargets(got, []string{"https://allowed.example"}) || len(got) == 0 {
					t.Fatalf("Classify(%q) network targets = %q, want the second destination named or the command undetermined", tc.command, got)
				}
				return
			}
			if !sameTargets(got, []string{undetermined}) {
				t.Fatalf("Classify(%q) network targets = %q, want only %q (facts %+v)", tc.command, got, undetermined, res.EffectFacts)
			}
			var reason string
			for _, fact := range res.EffectFacts {
				if fact.Class == "network" {
					reason = fact.Reason
				}
			}
			if !strings.Contains(reason, tc.reason) {
				t.Fatalf("Classify(%q) reason = %q, want it to mention %q", tc.command, reason, tc.reason)
			}
		})
	}
}

// The stricter tables leave everyday commands as they were: none of these
// names a destination or becomes undetermined.
func TestClassifyStricterTablesLeaveEverydayCommandsAlone(t *testing.T) {
	for _, command := range []string{
		"git status",
		"git push origin main",
		"git pull --rebase",
		"git fetch --all --prune",
		`git commit -m "see https://other.example/issue/1"`,
		"git config user.name agent",
		"git config --get remote.origin.url",
		"git config --global core.editor vim",
		"git --no-pager log --oneline -5",
		"git -C ../other status",
		"ssh -V",
		"openssl version",
		"openssl x509 -in cert.pem -noout -text",
		"openssl dgst -sha256 file.bin",
		"openssl s_client -help",
		"export PATH=/usr/local/bin:$PATH",
		`export "EDITOR=vim"`,
		"echo https://other.example/",
		"grep -r curl .",
	} {
		if res := Classify(command); len(networkTargets(res)) != 0 {
			t.Errorf("Classify(%q) network targets = %q, want none", command, networkTargets(res))
		}
	}
}
