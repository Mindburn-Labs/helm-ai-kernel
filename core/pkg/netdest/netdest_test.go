package netdest

import "testing"

func TestParseResolvesTheHostAClientConnectsTo(t *testing.T) {
	cases := []struct {
		target string
		want   string
	}{
		{"https://example.com", "https://example.com"},
		{"https://example.com/path?q=1#frag", "https://example.com"},
		{"HTTPS://Example.COM./", "https://example.com"},
		{"https://example.com:443", "https://example.com"},
		{"https://example.com:0443", "https://example.com"},
		{"https://example.com:8443", "https://example.com:8443"},
		{"http://example.com:80/", "http://example.com"},
		{"http://example.com:443/", "http://example.com:443"},
		{"example.com", "https://example.com"},
		{"example.com:8080/x", "https://example.com:8080"},
		{"example.com/?next=https://other.example/", "https://example.com"},
		{"user@example.com", "https://example.com"},
		// name:secret@host is userinfo whatever the name looks like.
		{"mailto:user@example.com", "https://example.com"},
		{"https://user:pass@example.com/", "https://example.com"},
		{"https://allowed.example@other.example/", "https://other.example"},
		{"https://allowed.example:443@other.example:8443/", "https://other.example:8443"},
		{"https://a@b@other.example/", "https://other.example"},
		{"ssh://git@example.com:22/repo.git", "ssh://example.com"},
		{"ssh://example.com:2222", "ssh://example.com:2222"},
		{"tcp://example.com:443", "tcp://example.com:443"},
		{"https://[2001:DB8::1]/", "https://[2001:db8::1]"},
		{"https://[2001:0db8:0000:0000:0000:0000:0000:0001]:8443", "https://[2001:db8::1]:8443"},
		{"2001:db8::1", "https://[2001:db8::1]"},
		{"[2001:db8::1]:8443", "https://[2001:db8::1]:8443"},
		{"https://[::ffff:192.0.2.1]/", "https://192.0.2.1"},
		{"192.0.2.1:8080", "https://192.0.2.1:8080"},
		{"https://bücher.example/", "https://xn--bcher-kva.example"},
		{"https://BÜCHER.example/", "https://xn--bcher-kva.example"},
		{"https://xn--bcher-kva.example/", "https://xn--bcher-kva.example"},
		{"https://ｅｘａｍｐｌｅ.com/", "https://example.com"},
		{"https://example。com/", "https://example.com"},
		{"https://my_service.internal:8080/", "https://my_service.internal:8080"},
		{"https://localhost/", "https://localhost"},
	}
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			got, err := Parse(tc.target)
			if err != nil {
				t.Fatalf("Parse(%q) error = %v, want %s", tc.target, err, tc.want)
			}
			if got.String() != tc.want {
				t.Fatalf("Parse(%q) = %s, want %s", tc.target, got, tc.want)
			}
			// The canonical form is a fixed point: a receipt that carries it
			// names the same endpoint when it is read back.
			again, err := Parse(got.String())
			if err != nil || again != got {
				t.Fatalf("Parse(%q) = %+v, %v; want %+v", got.String(), again, err, got)
			}
		})
	}
}

func TestParseRefusesWhatIsNotOneEndpoint(t *testing.T) {
	for _, target := range []string{
		"",
		Undetermined,
		" ",
		"https://",
		"https:///example.com/",
		"https://example.com other.example",
		"https://example.com\t",
		"https://example.com\n.other.example",
		`https://example.com\@other.example/`,
		`https://other.example\.example.com/`,
		"https://other.example#@example.com/",
		"https://other.example?@example.com/",
		"https://example%2ecom/",
		"https://exa%6dple.com/",
		"https://{a,b}.example/",
		"https://[1-3].example/",
		"https://*.example.com/",
		"https://$HOST/",
		"https://exam ple.com/",
		"https://example.com:99999/",
		"https://example.com:0/",
		"https://example.com:abc/",
		"https://example.com:-1/",
		"https://[fe80::1%25en0]/",
		"https://[::1/",
		"http://2130706433/",
		"http://0x7f.0.0.1/",
		"http://0x7f000001/",
		"http://127.1/",
		"http://017700000001/",
		"http://127.0.0.1./",
		"https://faß.example/",
		"https://example.‍com/",
		"https://-bad.example/",
		"https://bad-.example/",
		"https://a..example/",
		"https://.example.com/",
		"http:/example.com/",
		"http:example.com",
		"file:///etc/passwd",
		"javascript:alert(1)",
		"https://" + string(make([]byte, 300)),
	} {
		if got, err := Parse(target); err == nil {
			t.Errorf("Parse(%q) = %s, want an error", target, got)
		}
	}
}

func TestParseWithSchemeAppliesTheClientDefault(t *testing.T) {
	got, err := ParseWithScheme("example.com/x", "http")
	if err != nil || got.String() != "http://example.com" {
		t.Fatalf("ParseWithScheme(http) = %s, %v", got, err)
	}
	got, err = ParseWithScheme("https://example.com/x", "http")
	if err != nil || got.String() != "https://example.com" {
		t.Fatalf("an explicit scheme must win: %s, %v", got, err)
	}
	got, err = ParseWithScheme("proxy.example:1080", "socks5")
	if err != nil || got.String() != "socks5://proxy.example:1080" {
		t.Fatalf("ParseWithScheme(socks5) = %s, %v", got, err)
	}
}

// Spellings of one host share a canonical form, so an allowlist entry and a
// command target cannot differ by presentation.
func TestCanonicalHostAgreesAcrossSpellings(t *testing.T) {
	groups := [][]string{
		{"example.com", "EXAMPLE.com", "example.com.", "Example.Com."},
		{"xn--bcher-kva.example", "bücher.example", "BÜCHER.EXAMPLE", "bücher.example."},
		{"2001:db8::1", "[2001:db8::1]", "2001:DB8:0:0:0:0:0:1", "[2001:0db8::0001]"},
		{"192.0.2.1", "::ffff:192.0.2.1", "[::ffff:192.0.2.1]"},
	}
	for _, group := range groups {
		want, err := CanonicalHost(group[0])
		if err != nil || want != group[0] {
			t.Fatalf("CanonicalHost(%q) = %q, %v; want it unchanged", group[0], want, err)
		}
		for _, spelling := range group[1:] {
			if got, err := CanonicalHost(spelling); err != nil || got != want {
				t.Errorf("CanonicalHost(%q) = %q, %v; want %q", spelling, got, err, want)
			}
		}
	}
	for _, host := range []string{"", "*", "*.example.com", "a b", "example.com:443", "https://example.com", "example.com/path", "fe80::1%en0", "1.2.3", "0x7f.1", "faß.example", "a..b"} {
		if got, err := CanonicalHost(host); err == nil {
			t.Errorf("CanonicalHost(%q) = %q, want an error", host, got)
		}
	}
}

func TestHasScheme(t *testing.T) {
	for value, want := range map[string]bool{
		"https://example.com":          true,
		"git+ssh://example.com":        true,
		"example.com":                  false,
		"example.com/?u=https://other": false,
		"://example.com":               false,
		"1http://example.com":          false,
		"ext::ssh://example.com":       false,
	} {
		if got := HasScheme(value); got != want {
			t.Errorf("HasScheme(%q) = %v, want %v", value, got, want)
		}
	}
}
