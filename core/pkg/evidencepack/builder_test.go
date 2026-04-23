package evidencepack_test

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/evidencepack"
)

func newTestBuilder() *evidencepack.Builder {
	return evidencepack.NewBuilder("pack-1", "actor-1", "intent-1", "sha256:policy").
		WithCreatedAt(time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC))
}

func TestAddNetworkLog(t *testing.T) {
	b := newTestBuilder()
	if err := b.AddNetworkLog("egress", []byte("10.0.0.1:443 ALLOW\n")); err != nil {
		t.Fatal(err)
	}

	manifest, content, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}

	// Verify entry exists under network/ prefix.
	if _, ok := content["network/egress.log"]; !ok {
		t.Fatal("expected network/egress.log in content map")
	}

	found := false
	for _, e := range manifest.Entries {
		if e.Path == "network/egress.log" {
			found = true
			if e.ContentHash == "" {
				t.Fatal("expected non-empty hash")
			}
		}
	}
	if !found {
		t.Fatal("expected network/egress.log in manifest entries")
	}
}

func TestAddNetworkLog_Empty(t *testing.T) {
	b := newTestBuilder()
	if err := b.AddNetworkLog("empty", []byte{}); err == nil {
		t.Fatal("expected error for empty log")
	}
}

func TestAddSecretAccessLog(t *testing.T) {
	b := newTestBuilder()
	events := []map[string]string{
		{"action": "issue", "token_id": "tok-1"},
		{"action": "revoke", "token_id": "tok-1"},
	}
	if err := b.AddSecretAccessLog("token-lifecycle", events); err != nil {
		t.Fatal(err)
	}

	_, content, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := content["secrets/token-lifecycle.json"]; !ok {
		t.Fatal("expected secrets/token-lifecycle.json")
	}
}

func TestAddPortExposure(t *testing.T) {
	b := newTestBuilder()
	event := contracts.PortExposureEvent{
		Port:      8080,
		Protocol:  "tcp",
		Direction: "inbound",
		StartedAt: time.Now(),
	}
	if err := b.AddPortExposure("port-8080", event); err != nil {
		t.Fatal(err)
	}

	_, content, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := content["ports/port-8080.json"]; !ok {
		t.Fatal("expected ports/port-8080.json")
	}
}

func TestAddGitDiff(t *testing.T) {
	b := newTestBuilder()
	diff := []byte("diff --git a/file.go b/file.go\n--- a/file.go\n+++ b/file.go\n@@ -1 +1 @@\n-old\n+new\n")
	if err := b.AddGitDiff("workspace", diff); err != nil {
		t.Fatal(err)
	}

	manifest, content, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := content["diffs/workspace.diff"]; !ok {
		t.Fatal("expected diffs/workspace.diff")
	}

	found := false
	for _, e := range manifest.Entries {
		if e.Path == "diffs/workspace.diff" {
			found = true
			if e.ContentType != "text/x-diff" {
				t.Fatalf("expected text/x-diff, got %s", e.ContentType)
			}
		}
	}
	if !found {
		t.Fatal("expected diffs/workspace.diff in manifest")
	}
}

func TestAddGitDiff_Empty(t *testing.T) {
	b := newTestBuilder()
	if err := b.AddGitDiff("empty", []byte{}); err == nil {
		t.Fatal("expected error for empty diff")
	}
}

func TestAddReplayManifest(t *testing.T) {
	b := newTestBuilder()
	manifest := map[string]any{
		"manifest_id": "replay-1",
		"run_id":      "run-1",
		"mode":        "dry",
	}
	if err := b.AddReplayManifest("run-1", manifest); err != nil {
		t.Fatal(err)
	}

	_, content, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := content["replay/run-1.json"]; !ok {
		t.Fatal("expected replay/run-1.json")
	}
}

func TestAllNewEntryTypes_InSinglePack(t *testing.T) {
	b := newTestBuilder()

	// Add one of each new entry type.
	_ = b.AddNetworkLog("net", []byte("log data"))
	_ = b.AddSecretAccessLog("sec", map[string]string{"action": "issue"})
	_ = b.AddPortExposure("port", map[string]int{"port": 3000})
	_ = b.AddGitDiff("diff", []byte("diff content"))
	_ = b.AddReplayManifest("replay", map[string]string{"mode": "dry"})

	manifest, content, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}

	// 5 new entries + manifest.json = 6 total in content map.
	// But manifest.json is added by Build() itself.
	expectedPaths := []string{
		"network/net.log",
		"secrets/sec.json",
		"ports/port.json",
		"diffs/diff.diff",
		"replay/replay.json",
	}
	for _, path := range expectedPaths {
		if _, ok := content[path]; !ok {
			t.Fatalf("missing content entry: %s", path)
		}
	}

	if len(manifest.Entries) != 5 {
		t.Fatalf("expected 5 manifest entries, got %d", len(manifest.Entries))
	}

	if manifest.ManifestHash == "" {
		t.Fatal("expected non-empty manifest hash")
	}
}
