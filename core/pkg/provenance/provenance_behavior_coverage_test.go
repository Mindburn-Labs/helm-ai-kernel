package provenance

import (
	"strings"
	"testing"
)

func TestBuilder_EnvelopeID(t *testing.T) {
	b := NewBuilder()
	env := b.Build()
	if !strings.HasPrefix(env.EnvelopeID, "env-") {
		t.Fatalf("envelope ID should start with env-, got %s", env.EnvelopeID)
	}
}

func TestBuilder_VersionSet(t *testing.T) {
	b := NewBuilder()
	env := b.Build()
	if env.Version != Version {
		t.Fatalf("expected version %s, got %s", Version, env.Version)
	}
}

func TestBuilder_ContentHashDeterministic(t *testing.T) {
	b1 := NewBuilder()
	b1.AddSystemPrompt("hello")
	e1 := b1.Build()

	b2 := NewBuilder()
	b2.AddSystemPrompt("hello")
	e2 := b2.Build()

	if e1.ContentHash != e2.ContentHash {
		t.Fatalf("same content should produce same hash: %s vs %s", e1.ContentHash, e2.ContentHash)
	}
}

func TestBuilder_ContentHashDiffers(t *testing.T) {
	b1 := NewBuilder()
	b1.AddSystemPrompt("alpha")
	e1 := b1.Build()

	b2 := NewBuilder()
	b2.AddSystemPrompt("beta")
	e2 := b2.Build()

	if e1.ContentHash == e2.ContentHash {
		t.Fatal("different content should produce different hash")
	}
}

func TestBuilder_WebContentUntrusted(t *testing.T) {
	b := NewBuilder()
	seg := b.AddWebContent("page content", "https://example.com")
	if seg.TrustLevel != TrustLevelUntrusted {
		t.Fatalf("web content should be untrusted, got %s", seg.TrustLevel)
	}
	if seg.Metadata.SourceURI != "https://example.com" {
		t.Fatalf("expected source URI, got %s", seg.Metadata.SourceURI)
	}
}

func TestBuilder_TransformQuote(t *testing.T) {
	b := NewBuilder()
	seg := &Segment{Content: "line1\nline2"}
	result := b.applyTransform(seg, TransformQuote)
	if !strings.HasPrefix(result.Content, "> line1") {
		t.Fatalf("expected quoted lines, got %s", result.Content)
	}
}

func TestBuilder_TransformEscape(t *testing.T) {
	b := NewBuilder()
	seg := &Segment{Content: "<script>alert(1)</script>"}
	result := b.applyTransform(seg, TransformEscape)
	if strings.Contains(result.Content, "<script>") {
		t.Fatal("angle brackets should be escaped")
	}
	if !strings.Contains(result.Content, "&lt;script&gt;") {
		t.Fatalf("expected escaped content, got %s", result.Content)
	}
}

func TestEnvelope_NoInjectionOnCleanContent(t *testing.T) {
	b := NewBuilder()
	b.AddSystemPrompt("Be helpful.")
	b.AddUserInput("What time is it?", "u1")
	env := b.Build()
	if env.HasInjectionIndicators() {
		t.Fatal("clean content should not trigger injection indicators")
	}
	if env.MaxInjectionConfidence() != 0.0 {
		t.Fatalf("expected 0 confidence, got %f", env.MaxInjectionConfidence())
	}
}

func TestBuilder_FirewallBlockAction(t *testing.T) {
	b := NewBuilder()
	b.SetFirewallPolicy(&FirewallPolicy{
		PolicyID: "fw1",
		Rules:    []FirewallRule{{RuleID: "r1", TrustLevel: TrustLevelUntrusted, Action: "block"}},
	})
	seg := b.AddToolOutput("sensitive data", "tool-x")
	if seg.Content != "[BLOCKED BY FIREWALL]" {
		t.Fatalf("expected blocked content, got %q", seg.Content)
	}
}

func TestBuilder_SegmentIDUnique(t *testing.T) {
	b := NewBuilder()
	s1 := b.AddSystemPrompt("a")
	s2 := b.AddSystemPrompt("b")
	if s1.SegmentID == s2.SegmentID {
		t.Fatal("segment IDs should be unique")
	}
}
