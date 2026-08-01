package main

import "testing"

func TestDisplayVersion(t *testing.T) {
	original := version
	t.Cleanup(func() { version = original })

	for _, test := range []struct {
		name  string
		input string
		want  string
	}{
		{name: "development fallback", input: "", want: "v0.0.0-dev"},
		{name: "release version", input: "0.8.0", want: "v0.8.0"},
		{name: "already prefixed release version", input: "v0.8.0", want: "v0.8.0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			version = test.input
			if got := displayVersion(); got != test.want {
				t.Fatalf("displayVersion() = %q, want %q", got, test.want)
			}
		})
	}
}
