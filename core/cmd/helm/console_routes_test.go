package main

import "testing"

func TestConsoleReservedPathsDoNotFallThroughToSPA(t *testing.T) {
	reserved := []string{
		"/api/v1/unknown",
		"/v1/chat/completions",
		"/mcp",
		"/mcp/v1/capabilities",
		"/.well-known/oauth-protected-resource/mcp",
		"/healthz",
		"/version",
	}
	for _, path := range reserved {
		if !isReservedConsolePath(path) {
			t.Fatalf("%s should be reserved", path)
		}
	}
}

func TestConsoleApplicationRoutesFallThroughToSPA(t *testing.T) {
	appRoutes := []string{"/", "/command", "/receipts/rcpt_123", "/settings"}
	for _, path := range appRoutes {
		if isReservedConsolePath(path) {
			t.Fatalf("%s should be handled by console SPA", path)
		}
	}
}
