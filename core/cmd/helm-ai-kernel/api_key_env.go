package main

import (
	"fmt"
	"io"
)

// mindburnAPIKeyFromEnv avoids sharing another vendor's environment namespace.
// The legacy lookup is retained for compatibility and never logs its value.
func mindburnAPIKeyFromEnv(getenv func(string) string, stderr io.Writer) string {
	if key := getenv("MINDBURN_HELM_API_KEY"); key != "" {
		return key
	}
	key := getenv("HELM_API_KEY")
	if key != "" {
		_, _ = fmt.Fprintln(stderr, "warning: HELM_API_KEY is deprecated; use MINDBURN_HELM_API_KEY for Mindburn HELM")
	}
	return key
}
