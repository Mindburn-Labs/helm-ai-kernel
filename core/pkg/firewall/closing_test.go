package firewall

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// ── Helpers ─────────────────────────────────────────────────────────

type closingStubDispatcher struct{ called int }

func (s *closingStubDispatcher) Dispatch(_ context.Context, _ string, _ map[string]any) (any, error) {
	s.called++
	return "ok", nil
}

func closingFixedClock() time.Time {
	return time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)
}

// ── 1. CheckEgress with 10+ domains ─────────────────────────────────

func TestClosing_CheckEgress_AllowedDomains(t *testing.T) {
	domains := []string{"api.helm.dev", "auth.helm.dev", "data.helm.dev", "cdn.helm.dev", "status.helm.dev"}
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: domains})
	for _, d := range domains {
		t.Run("allowed/"+d, func(t *testing.T) {
			dec := ec.CheckEgress(d, "https", 100)
			if !dec.Allowed {
				t.Fatalf("expected allowed for %s", d)
			}
		})
	}
}

func TestClosing_CheckEgress_DeniedDomains(t *testing.T) {
	denied := []string{"evil.com", "malware.net", "phish.org", "bad.io", "hack.dev"}
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"safe.com"}, DeniedDomains: denied})
	for _, d := range denied {
		t.Run("denied/"+d, func(t *testing.T) {
			dec := ec.CheckEgress(d, "https", 100)
			if dec.Allowed {
				t.Fatalf("expected denied for %s", d)
			}
			if dec.ReasonCode != "DATA_EGRESS_BLOCKED" {
				t.Fatalf("reason = %s, want DATA_EGRESS_BLOCKED", dec.ReasonCode)
			}
		})
	}
}

func TestClosing_CheckEgress_UnlistedDomains(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"known.com"}})
	unlisted := []string{"unknown.com", "random.io", "new.dev", "other.net", "test.org"}
	for _, d := range unlisted {
		t.Run("unlisted/"+d, func(t *testing.T) {
			dec := ec.CheckEgress(d, "https", 100)
			if dec.Allowed {
				t.Fatalf("expected fail-closed deny for unlisted %s", d)
			}
		})
	}
}

func TestClosing_CheckEgress_CaseInsensitive(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"api.helm.dev"}})
	variants := []string{"API.HELM.DEV", "Api.Helm.Dev", "api.HELM.dev"}
	for _, v := range variants {
		t.Run(v, func(t *testing.T) {
			dec := ec.CheckEgress(v, "https", 100)
			if !dec.Allowed {
				t.Fatalf("expected case-insensitive match for %s", v)
			}
		})
	}
}

func TestClosing_CheckEgress_DenyTakesPrecedence(t *testing.T) {
	// Domain appears in both allowed and denied — denied should win
	shared := []string{"dual1.com", "dual2.com", "dual3.com"}
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: shared, DeniedDomains: shared})
	for _, d := range shared {
		t.Run(d, func(t *testing.T) {
			dec := ec.CheckEgress(d, "https", 100)
			if dec.Allowed {
				t.Fatal("deny should take precedence over allow")
			}
		})
	}
}

// ── 2. CIDR matching ────────────────────────────────────────────────

func TestClosing_CIDR_AllowedRanges(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}})
	cases := map[string]string{
		"10.0.0.1":     "10.0.0.0/8",
		"10.255.255.1": "10.0.0.0/8",
		"172.16.0.1":   "172.16.0.0/12",
		"172.31.255.1": "172.16.0.0/12",
		"192.168.1.1":  "192.168.0.0/16",
	}
	for ip, cidr := range cases {
		t.Run(ip+"_in_"+cidr, func(t *testing.T) {
			dec := ec.CheckEgress(ip, "https", 100)
			if !dec.Allowed {
				t.Fatalf("expected %s allowed in %s", ip, cidr)
			}
		})
	}
}

func TestClosing_CIDR_DeniedOutOfRange(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"10.0.0.0/24"}})
	ips := []string{"10.0.1.1", "10.0.2.1", "192.168.0.1", "8.8.8.8"}
	for _, ip := range ips {
		t.Run("outside/"+ip, func(t *testing.T) {
			dec := ec.CheckEgress(ip, "https", 100)
			if dec.Allowed {
				t.Fatalf("expected %s denied (outside CIDR)", ip)
			}
		})
	}
}

func TestClosing_CIDR_MultipleCIDRs(t *testing.T) {
	cidrs := []string{"10.0.0.0/24", "10.1.0.0/24", "10.2.0.0/24", "10.3.0.0/24"}
	ec := NewEgressChecker(&EgressPolicy{AllowedCIDRs: cidrs})
	for i, cidr := range cidrs {
		ip := fmt.Sprintf("10.%d.0.50", i)
		t.Run(ip+"_in_"+cidr, func(t *testing.T) {
			dec := ec.CheckEgress(ip, "https", 100)
			if !dec.Allowed {
				t.Fatalf("expected %s allowed in %s", ip, cidr)
			}
		})
	}
}

func TestClosing_CIDR_IPv6(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"fd00::/8"}})
	cases := map[string]bool{
		"fd00::1":  true,
		"fd12::99": true,
		"fe80::1":  false,
		"::1":      false,
	}
	for ip, want := range cases {
		t.Run(ip, func(t *testing.T) {
			dec := ec.CheckEgress(ip, "https", 100)
			if dec.Allowed != want {
				t.Fatalf("ip=%s allowed=%v want=%v", ip, dec.Allowed, want)
			}
		})
	}
}

// ── 3. Protocol filtering ──────────────────────────────────────────

func TestClosing_Protocol_AllowedProtocols(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{
		AllowedDomains:   []string{"api.helm.dev"},
		AllowedProtocols: []string{"https", "grpc"},
	})
	protos := []string{"https", "grpc"}
	for _, p := range protos {
		t.Run("allowed/"+p, func(t *testing.T) {
			dec := ec.CheckEgress("api.helm.dev", p, 100)
			if !dec.Allowed {
				t.Fatalf("expected protocol %s allowed", p)
			}
		})
	}
}

func TestClosing_Protocol_DeniedProtocols(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{
		AllowedDomains:   []string{"api.helm.dev"},
		AllowedProtocols: []string{"https"},
	})
	blocked := []string{"http", "ftp", "ssh", "grpc", "ws"}
	for _, p := range blocked {
		t.Run("blocked/"+p, func(t *testing.T) {
			dec := ec.CheckEgress("api.helm.dev", p, 100)
			if dec.Allowed {
				t.Fatalf("expected protocol %s blocked", p)
			}
		})
	}
}

func TestClosing_Protocol_CaseInsensitive(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{
		AllowedDomains:   []string{"api.helm.dev"},
		AllowedProtocols: []string{"https"},
	})
	variants := []string{"HTTPS", "Https", "hTTpS"}
	for _, v := range variants {
		t.Run(v, func(t *testing.T) {
			dec := ec.CheckEgress("api.helm.dev", v, 100)
			if !dec.Allowed {
				t.Fatalf("expected case-insensitive protocol match for %s", v)
			}
		})
	}
}

func TestClosing_Protocol_NoRestriction(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"api.helm.dev"}})
	protos := []string{"https", "http", "ftp", "ssh", "grpc"}
	for _, p := range protos {
		t.Run("unrestricted/"+p, func(t *testing.T) {
			dec := ec.CheckEgress("api.helm.dev", p, 100)
			if !dec.Allowed {
				t.Fatalf("expected all protocols allowed when no restriction: %s", p)
			}
		})
	}
}

// ── 4. Payload limits at boundary values ────────────────────────────

func TestClosing_Payload_ExactLimit(t *testing.T) {
	limits := []int64{1024, 4096, 65536, 1048576, 10485760}
	for _, limit := range limits {
		t.Run(fmt.Sprintf("limit_%d", limit), func(t *testing.T) {
			ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"a.com"}, MaxPayloadBytes: limit})
			dec := ec.CheckEgress("a.com", "https", limit)
			if !dec.Allowed {
				t.Fatal("expected allowed at exact limit")
			}
		})
	}
}

func TestClosing_Payload_OneBeyondLimit(t *testing.T) {
	limits := []int64{1024, 4096, 65536, 1048576}
	for _, limit := range limits {
		t.Run(fmt.Sprintf("limit_%d_plus1", limit), func(t *testing.T) {
			ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"a.com"}, MaxPayloadBytes: limit})
			dec := ec.CheckEgress("a.com", "https", limit+1)
			if dec.Allowed {
				t.Fatal("expected denied one beyond limit")
			}
		})
	}
}

func TestClosing_Payload_OneBelowLimit(t *testing.T) {
	limits := []int64{1024, 4096, 65536}
	for _, limit := range limits {
		t.Run(fmt.Sprintf("limit_%d_minus1", limit), func(t *testing.T) {
			ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"a.com"}, MaxPayloadBytes: limit})
			dec := ec.CheckEgress("a.com", "https", limit-1)
			if !dec.Allowed {
				t.Fatal("expected allowed one below limit")
			}
		})
	}
}

func TestClosing_Payload_ZeroMeansUnlimited(t *testing.T) {
	sizes := []int64{0, 1, 1024, 1048576, 1073741824}
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"a.com"}, MaxPayloadBytes: 0})
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("size_%d", sz), func(t *testing.T) {
			dec := ec.CheckEgress("a.com", "https", sz)
			if !dec.Allowed {
				t.Fatalf("expected unlimited when MaxPayloadBytes=0, payload=%d", sz)
			}
		})
	}
}

func TestClosing_Payload_ZeroPayload(t *testing.T) {
	limits := []int64{0, 1, 100, 1024}
	for _, limit := range limits {
		t.Run(fmt.Sprintf("limit_%d_zero_payload", limit), func(t *testing.T) {
			ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"a.com"}, MaxPayloadBytes: limit})
			dec := ec.CheckEgress("a.com", "https", 0)
			if !dec.Allowed {
				t.Fatal("zero-byte payload should always be allowed")
			}
		})
	}
}

// ── 5. PolicyFirewall with multiple tools ───────────────────────────

func TestClosing_Firewall_AllowedTools(t *testing.T) {
	tools := []string{"read_file", "write_file", "list_dir", "search", "execute"}
	stub := &closingStubDispatcher{}
	fw := NewPolicyFirewall(stub)
	for _, tool := range tools {
		_ = fw.AllowTool(tool, "")
	}
	bundle := PolicyInputBundle{ActorID: "u1", Role: "admin", SessionID: "s1"}
	for _, tool := range tools {
		t.Run("allowed/"+tool, func(t *testing.T) {
			_, err := fw.CallTool(context.Background(), bundle, tool, nil)
			if err != nil {
				t.Fatalf("expected allowed: %v", err)
			}
		})
	}
}

func TestClosing_Firewall_BlockedTools(t *testing.T) {
	stub := &closingStubDispatcher{}
	fw := NewPolicyFirewall(stub)
	_ = fw.AllowTool("read_file", "")
	blocked := []string{"delete_file", "shell_exec", "drop_table", "rm_rf", "chmod"}
	bundle := PolicyInputBundle{ActorID: "u1", Role: "admin", SessionID: "s1"}
	for _, tool := range blocked {
		t.Run("blocked/"+tool, func(t *testing.T) {
			_, err := fw.CallTool(context.Background(), bundle, tool, nil)
			if err == nil {
				t.Fatalf("expected blocked for %s", tool)
			}
			if !strings.Contains(err.Error(), "not in allowlist") {
				t.Fatalf("wrong error: %v", err)
			}
		})
	}
}

func TestClosing_Firewall_EmptyAllowlistBlocksAll(t *testing.T) {
	stub := &closingStubDispatcher{}
	fw := NewPolicyFirewall(stub)
	tools := []string{"a", "b", "c", "d", "e"}
	bundle := PolicyInputBundle{ActorID: "u1", Role: "admin", SessionID: "s1"}
	for _, tool := range tools {
		t.Run("blocked/"+tool, func(t *testing.T) {
			_, err := fw.CallTool(context.Background(), bundle, tool, nil)
			if err == nil {
				t.Fatal("empty allowlist should block all tools")
			}
		})
	}
}

func TestClosing_Firewall_NilDispatcher(t *testing.T) {
	fw := NewPolicyFirewall(nil)
	_ = fw.AllowTool("test", "")
	bundle := PolicyInputBundle{ActorID: "u1", Role: "admin", SessionID: "s1"}
	tools := []string{"test"}
	for _, tool := range tools {
		t.Run(tool, func(t *testing.T) {
			_, err := fw.CallTool(context.Background(), bundle, tool, nil)
			if err == nil || !strings.Contains(err.Error(), "fail-closed") {
				t.Fatalf("expected fail-closed error, got: %v", err)
			}
		})
	}
}

// ── 6. Schema validation ────────────────────────────────────────────

func TestClosing_Schema_ValidParams(t *testing.T) {
	schema := `{
		"type": "object",
		"properties": {
			"path": {"type": "string"},
			"mode": {"type": "integer"}
		},
		"required": ["path"]
	}`
	stub := &closingStubDispatcher{}
	fw := NewPolicyFirewall(stub)
	if err := fw.AllowTool("file_op", schema); err != nil {
		t.Fatal(err)
	}
	bundle := PolicyInputBundle{ActorID: "u1", Role: "admin", SessionID: "s1"}
	cases := []map[string]any{
		{"path": "/tmp/a"},
		{"path": "/tmp/b", "mode": 0644},
		{"path": "/home/test"},
	}
	for i, params := range cases {
		t.Run(fmt.Sprintf("valid_%d", i), func(t *testing.T) {
			_, err := fw.CallTool(context.Background(), bundle, "file_op", params)
			if err != nil {
				t.Fatalf("expected valid: %v", err)
			}
		})
	}
}

func TestClosing_Schema_InvalidParams(t *testing.T) {
	schema := `{
		"type": "object",
		"properties": {
			"path": {"type": "string"}
		},
		"required": ["path"]
	}`
	stub := &closingStubDispatcher{}
	fw := NewPolicyFirewall(stub)
	if err := fw.AllowTool("file_op", schema); err != nil {
		t.Fatal(err)
	}
	bundle := PolicyInputBundle{ActorID: "u1", Role: "admin", SessionID: "s1"}
	cases := []struct {
		name   string
		params map[string]any
	}{
		{"missing_required", map[string]any{"mode": 0644}},
		{"wrong_type", map[string]any{"path": 123}},
		{"empty_map", map[string]any{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := fw.CallTool(context.Background(), bundle, "file_op", tc.params)
			if err == nil {
				t.Fatal("expected schema validation error")
			}
			if !strings.Contains(err.Error(), "schema validation failed") {
				t.Fatalf("wrong error: %v", err)
			}
		})
	}
}

func TestClosing_Schema_NilParams(t *testing.T) {
	schema := `{"type": "object", "properties": {"x": {"type": "string"}}}`
	stub := &closingStubDispatcher{}
	fw := NewPolicyFirewall(stub)
	if err := fw.AllowTool("tool_x", schema); err != nil {
		t.Fatal(err)
	}
	bundle := PolicyInputBundle{ActorID: "u1", Role: "admin", SessionID: "s1"}
	t.Run("nil_params", func(t *testing.T) {
		_, err := fw.CallTool(context.Background(), bundle, "tool_x", nil)
		if err == nil || !strings.Contains(err.Error(), "missing parameters") {
			t.Fatalf("expected missing parameters error: %v", err)
		}
	})
}

func TestClosing_Schema_MultipleSchemaTypes(t *testing.T) {
	schemas := map[string]string{
		"str_tool":  `{"type": "object", "properties": {"val": {"type": "string"}}, "required": ["val"]}`,
		"int_tool":  `{"type": "object", "properties": {"val": {"type": "integer"}}, "required": ["val"]}`,
		"bool_tool": `{"type": "object", "properties": {"val": {"type": "boolean"}}, "required": ["val"]}`,
	}
	validParams := map[string]map[string]any{
		"str_tool":  {"val": "hello"},
		"int_tool":  {"val": 42},
		"bool_tool": {"val": true},
	}
	stub := &closingStubDispatcher{}
	fw := NewPolicyFirewall(stub)
	for name, s := range schemas {
		if err := fw.AllowTool(name, s); err != nil {
			t.Fatal(err)
		}
	}
	bundle := PolicyInputBundle{ActorID: "u1", Role: "admin", SessionID: "s1"}
	for name, params := range validParams {
		t.Run("type_match/"+name, func(t *testing.T) {
			_, err := fw.CallTool(context.Background(), bundle, name, params)
			if err != nil {
				t.Fatalf("expected valid: %v", err)
			}
		})
	}
}

// ── 7. EgressChecker nil policy ─────────────────────────────────────

func TestClosing_NilPolicy_DenyAll(t *testing.T) {
	ec := NewEgressChecker(nil)
	targets := []string{"google.com", "1.1.1.1", "internal.net", "api.dev", "test.io"}
	for _, d := range targets {
		t.Run("nil_deny/"+d, func(t *testing.T) {
			dec := ec.CheckEgress(d, "https", 100)
			if dec.Allowed {
				t.Fatalf("nil policy should deny all: %s", d)
			}
		})
	}
}

// ── 8. Stats tracking ──────────────────────────────────────────────

func TestClosing_Stats_IncrementOnCheck(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"ok.com"}})
	domains := []string{"ok.com", "bad.com", "ok.com", "bad.com", "ok.com"}
	for i, d := range domains {
		t.Run(fmt.Sprintf("check_%d_%s", i, d), func(t *testing.T) {
			ec.CheckEgress(d, "https", 10)
			total, _, _ := ec.Stats()
			if total == 0 {
				t.Fatal("total checks should be > 0")
			}
		})
	}
}

func TestClosing_Stats_AllowedVsDenied(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"good.com"}})
	allowDomains := []string{"good.com", "good.com", "good.com"}
	denyDomains := []string{"bad.com", "evil.com"}
	for _, d := range allowDomains {
		ec.CheckEgress(d, "https", 10)
	}
	for _, d := range denyDomains {
		ec.CheckEgress(d, "https", 10)
	}
	total, allowed, denied := ec.Stats()
	t.Run("total", func(t *testing.T) {
		if total != 5 {
			t.Fatalf("total = %d, want 5", total)
		}
	})
	t.Run("allowed", func(t *testing.T) {
		if allowed != 3 {
			t.Fatalf("allowed = %d, want 3", allowed)
		}
	})
	t.Run("denied", func(t *testing.T) {
		if denied != 2 {
			t.Fatalf("denied = %d, want 2", denied)
		}
	})
}

// ── 9. EgressDecision fields ────────────────────────────────────────

func TestClosing_Decision_FieldsPopulated(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"api.dev"}}).
		WithClock(fixedClock)
	cases := []struct {
		dest     string
		payload  int64
		wantAllow bool
	}{
		{"api.dev", 100, true},
		{"api.dev", 200, true},
		{"other.dev", 100, false},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s_%d", tc.dest, tc.payload), func(t *testing.T) {
			dec := ec.CheckEgress(tc.dest, "https", tc.payload)
			if dec.Destination != tc.dest {
				t.Fatalf("destination = %s, want %s", dec.Destination, tc.dest)
			}
			if dec.PayloadBytes != tc.payload {
				t.Fatalf("payload = %d, want %d", dec.PayloadBytes, tc.payload)
			}
			if dec.Allowed != tc.wantAllow {
				t.Fatalf("allowed = %v, want %v", dec.Allowed, tc.wantAllow)
			}
			if dec.CheckedAt.IsZero() {
				t.Fatal("CheckedAt should not be zero")
			}
		})
	}
}

func TestClosing_Decision_TimestampDeterministic(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"a.com"}}).WithClock(closingFixedClock)
	domains := []string{"a.com", "b.com", "c.com"}
	for _, d := range domains {
		t.Run(d, func(t *testing.T) {
			dec := ec.CheckEgress(d, "https", 1)
			if !dec.CheckedAt.Equal(closingFixedClock()) {
				t.Fatalf("timestamp not deterministic: %v", dec.CheckedAt)
			}
		})
	}
}

// ── 10. Stringer ────────────────────────────────────────────────────

func TestClosing_Stringer_Format(t *testing.T) {
	policies := []struct {
		name   string
		policy *EgressPolicy
	}{
		{"empty", &EgressPolicy{}},
		{"domains_only", &EgressPolicy{AllowedDomains: []string{"a.com", "b.com"}}},
		{"cidrs_only", &EgressPolicy{AllowedCIDRs: []string{"10.0.0.0/8"}}},
		{"full", &EgressPolicy{
			AllowedDomains: []string{"a.com"}, DeniedDomains: []string{"b.com"},
			AllowedCIDRs: []string{"10.0.0.0/8"}, AllowedProtocols: []string{"https"},
		}},
	}
	for _, tc := range policies {
		t.Run(tc.name, func(t *testing.T) {
			ec := NewEgressChecker(tc.policy)
			s := ec.String()
			if !strings.HasPrefix(s, "EgressChecker{") {
				t.Fatalf("unexpected format: %s", s)
			}
		})
	}
}

// ── 11. Mixed domain + CIDR ─────────────────────────────────────────

func TestClosing_MixedDomainCIDR_BothWork(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{
		AllowedDomains: []string{"api.helm.dev"},
		AllowedCIDRs:   []string{"10.0.0.0/8"},
	})
	cases := map[string]bool{
		"api.helm.dev": true,
		"10.0.0.1":     true,
		"other.com":    false,
		"192.168.0.1":  false,
	}
	for dest, want := range cases {
		t.Run(dest, func(t *testing.T) {
			dec := ec.CheckEgress(dest, "https", 100)
			if dec.Allowed != want {
				t.Fatalf("dest=%s allowed=%v want=%v", dest, dec.Allowed, want)
			}
		})
	}
}

// ── 12. Schema compile errors ───────────────────────────────────────

func TestClosing_Schema_CompileErrors(t *testing.T) {
	stub := &closingStubDispatcher{}
	fw := NewPolicyFirewall(stub)
	badSchemas := []struct {
		name   string
		schema string
	}{
		{"not_json", "this is not json"},
		{"invalid_type", `{"type": "bogus"}`},
		{"broken_ref", `{"$ref": "nonexistent://path"}`},
	}
	for _, tc := range badSchemas {
		t.Run(tc.name, func(t *testing.T) {
			err := fw.AllowTool("bad_"+tc.name, tc.schema)
			if err == nil {
				t.Fatal("expected schema compile error")
			}
		})
	}
}

// ── 13. Schema empty string means no validation ─────────────────────

func TestClosing_Schema_EmptyMeansNoValidation(t *testing.T) {
	stub := &closingStubDispatcher{}
	fw := NewPolicyFirewall(stub)
	_ = fw.AllowTool("flexible", "")
	bundle := PolicyInputBundle{ActorID: "u1", Role: "admin", SessionID: "s1"}
	params := []map[string]any{
		nil,
		{"any": "thing"},
		{"nested": map[string]any{"deep": true}},
	}
	for i, p := range params {
		t.Run(fmt.Sprintf("any_params_%d", i), func(t *testing.T) {
			_, err := fw.CallTool(context.Background(), bundle, "flexible", p)
			if err != nil {
				t.Fatalf("expected no validation: %v", err)
			}
		})
	}
}

// ── 14. PolicyInputBundle variations ────────────────────────────────

func TestClosing_Bundle_DifferentRoles(t *testing.T) {
	stub := &closingStubDispatcher{}
	fw := NewPolicyFirewall(stub)
	_ = fw.AllowTool("action", "")
	roles := []string{"admin", "user", "service", "auditor", "readonly"}
	for _, role := range roles {
		t.Run("role/"+role, func(t *testing.T) {
			bundle := PolicyInputBundle{ActorID: "u1", Role: role, SessionID: "s1"}
			_, err := fw.CallTool(context.Background(), bundle, "action", nil)
			if err != nil {
				t.Fatalf("unexpected error for role %s: %v", role, err)
			}
		})
	}
}

func TestClosing_Bundle_DifferentActors(t *testing.T) {
	stub := &closingStubDispatcher{}
	fw := NewPolicyFirewall(stub)
	_ = fw.AllowTool("action", "")
	actors := []string{"user:1", "user:2", "service:agent", "bot:cron"}
	for _, actor := range actors {
		t.Run("actor/"+actor, func(t *testing.T) {
			bundle := PolicyInputBundle{ActorID: actor, Role: "admin", SessionID: "s1"}
			_, err := fw.CallTool(context.Background(), bundle, "action", nil)
			if err != nil {
				t.Fatalf("unexpected error for actor %s: %v", actor, err)
			}
		})
	}
}

// ── 15. Egress with combined restrictions ───────────────────────────

func TestClosing_Combined_ProtocolAndPayload(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{
		AllowedDomains:   []string{"api.dev"},
		AllowedProtocols: []string{"https"},
		MaxPayloadBytes:  1024,
	})
	cases := []struct {
		proto   string
		payload int64
		want    bool
	}{
		{"https", 100, true},
		{"https", 1024, true},
		{"https", 1025, false},
		{"http", 100, false},
		{"grpc", 500, false},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s_%d", tc.proto, tc.payload), func(t *testing.T) {
			dec := ec.CheckEgress("api.dev", tc.proto, tc.payload)
			if dec.Allowed != tc.want {
				t.Fatalf("proto=%s payload=%d allowed=%v want=%v", tc.proto, tc.payload, dec.Allowed, tc.want)
			}
		})
	}
}

// ── 16. Multiple tool schemas ───────────────────────────────────────

func TestClosing_MultiSchema_IndependentValidation(t *testing.T) {
	stub := &closingStubDispatcher{}
	fw := NewPolicyFirewall(stub)
	_ = fw.AllowTool("tool_a", `{"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}`)
	_ = fw.AllowTool("tool_b", `{"type": "object", "properties": {"count": {"type": "integer"}}, "required": ["count"]}`)
	bundle := PolicyInputBundle{ActorID: "u1", Role: "admin", SessionID: "s1"}

	cases := []struct {
		tool   string
		params map[string]any
		ok     bool
	}{
		{"tool_a", map[string]any{"name": "test"}, true},
		{"tool_a", map[string]any{"count": 1}, false},
		{"tool_b", map[string]any{"count": 1}, true},
		{"tool_b", map[string]any{"name": "test"}, false},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s_%v", tc.tool, tc.ok), func(t *testing.T) {
			_, err := fw.CallTool(context.Background(), bundle, tc.tool, tc.params)
			if tc.ok && err != nil {
				t.Fatalf("expected ok: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

// ── 17. Empty EgressPolicy ──────────────────────────────────────────

func TestClosing_EmptyPolicy_DenyAllDomains(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{})
	domains := []string{"a.com", "b.com", "c.com", "d.com"}
	for _, d := range domains {
		t.Run(d, func(t *testing.T) {
			dec := ec.CheckEgress(d, "https", 100)
			if dec.Allowed {
				t.Fatal("empty policy should deny all")
			}
		})
	}
}

// ── 18. CIDR boundary IPs ──────────────────────────────────────────

func TestClosing_CIDR_BoundaryIPs(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"10.0.0.0/24"}})
	cases := map[string]bool{
		"10.0.0.0":   true,
		"10.0.0.255": true,
		"10.0.0.128": true,
		"10.0.1.0":   false,
		"9.255.255.255": false,
	}
	for ip, want := range cases {
		t.Run(ip, func(t *testing.T) {
			dec := ec.CheckEgress(ip, "https", 1)
			if dec.Allowed != want {
				t.Fatalf("ip=%s allowed=%v want=%v", ip, dec.Allowed, want)
			}
		})
	}
}

// ── 19. Firewall dispatcher call count ──────────────────────────────

func TestClosing_Dispatcher_CalledOnAllow(t *testing.T) {
	stub := &closingStubDispatcher{}
	fw := NewPolicyFirewall(stub)
	tools := []string{"t1", "t2", "t3"}
	for _, tool := range tools {
		_ = fw.AllowTool(tool, "")
	}
	bundle := PolicyInputBundle{ActorID: "u1", Role: "admin", SessionID: "s1"}
	for _, tool := range tools {
		t.Run(tool, func(t *testing.T) {
			_, err := fw.CallTool(context.Background(), bundle, tool, nil)
			if err != nil {
				t.Fatal(err)
			}
			if stub.called == 0 {
				t.Fatal("dispatcher should have been called")
			}
		})
	}
}

// ── 20. Egress with wildcards (no wildcard support) ─────────────────

func TestClosing_Egress_NoWildcardSupport(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"*.helm.dev"}})
	// Wildcard is stored literally, so exact subdomain won't match
	domains := []string{"api.helm.dev", "auth.helm.dev", "cdn.helm.dev"}
	for _, d := range domains {
		t.Run(d, func(t *testing.T) {
			dec := ec.CheckEgress(d, "https", 100)
			if dec.Allowed {
				t.Fatal("wildcard stored literally should not match subdomains")
			}
		})
	}
}

// ── 21-25. Additional payload edge cases ────────────────────────────

func TestClosing_Payload_NegativeSize(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"a.com"}, MaxPayloadBytes: 100})
	sizes := []int64{-1, -100, -1000}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("neg_%d", sz), func(t *testing.T) {
			dec := ec.CheckEgress("a.com", "https", sz)
			if !dec.Allowed {
				t.Fatalf("negative payload size %d should pass (less than limit)", sz)
			}
		})
	}
}

func TestClosing_Payload_LargeValues(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"a.com"}, MaxPayloadBytes: 1 << 30})
	sizes := []int64{1 << 20, 1 << 25, 1 << 29, 1 << 30}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("size_%d", sz), func(t *testing.T) {
			dec := ec.CheckEgress("a.com", "https", sz)
			if !dec.Allowed {
				t.Fatalf("size %d should be within 1GiB limit", sz)
			}
		})
	}
}

func TestClosing_Payload_ExceedLargeLimit(t *testing.T) {
	limit := int64(1 << 30)
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"a.com"}, MaxPayloadBytes: limit})
	over := []int64{limit + 1, limit + 1000, limit * 2}
	for _, sz := range over {
		t.Run(fmt.Sprintf("over_%d", sz), func(t *testing.T) {
			dec := ec.CheckEgress("a.com", "https", sz)
			if dec.Allowed {
				t.Fatal("should deny over limit")
			}
		})
	}
}

// ── 26-30. Schema edge cases ────────────────────────────────────────

func TestClosing_Schema_NumberTypes(t *testing.T) {
	schema := `{"type": "object", "properties": {"val": {"type": "number"}}, "required": ["val"]}`
	stub := &closingStubDispatcher{}
	fw := NewPolicyFirewall(stub)
	_ = fw.AllowTool("num_tool", schema)
	bundle := PolicyInputBundle{ActorID: "u1", Role: "admin", SessionID: "s1"}
	vals := []any{0, 1, -1, 3.14, 1000000}
	for i, v := range vals {
		t.Run(fmt.Sprintf("num_%d", i), func(t *testing.T) {
			_, err := fw.CallTool(context.Background(), bundle, "num_tool", map[string]any{"val": v})
			if err != nil {
				t.Fatalf("expected valid number: %v", err)
			}
		})
	}
}

func TestClosing_Schema_ArrayType(t *testing.T) {
	schema := `{"type": "object", "properties": {"items": {"type": "array", "items": {"type": "string"}}}, "required": ["items"]}`
	stub := &closingStubDispatcher{}
	fw := NewPolicyFirewall(stub)
	_ = fw.AllowTool("arr_tool", schema)
	bundle := PolicyInputBundle{ActorID: "u1", Role: "admin", SessionID: "s1"}
	// JSON schema validator requires []any, not []string — runtime JSON decoding produces []any.
	arrays := [][]any{{"a"}, {"a", "b"}, {"x", "y", "z"}}
	for i, arr := range arrays {
		t.Run(fmt.Sprintf("arr_%d", i), func(t *testing.T) {
			_, err := fw.CallTool(context.Background(), bundle, "arr_tool", map[string]any{"items": arr})
			if err != nil {
				t.Fatalf("expected valid array: %v", err)
			}
		})
	}
}

func TestClosing_Schema_NestedObject(t *testing.T) {
	schema := `{
		"type": "object",
		"properties": {
			"config": {
				"type": "object",
				"properties": {"key": {"type": "string"}},
				"required": ["key"]
			}
		},
		"required": ["config"]
	}`
	stub := &closingStubDispatcher{}
	fw := NewPolicyFirewall(stub)
	_ = fw.AllowTool("nested", schema)
	bundle := PolicyInputBundle{ActorID: "u1", Role: "admin", SessionID: "s1"}
	configs := []map[string]any{
		{"config": map[string]any{"key": "val1"}},
		{"config": map[string]any{"key": "val2"}},
		{"config": map[string]any{"key": "val3"}},
	}
	for i, c := range configs {
		t.Run(fmt.Sprintf("nested_%d", i), func(t *testing.T) {
			_, err := fw.CallTool(context.Background(), bundle, "nested", c)
			if err != nil {
				t.Fatalf("expected valid nested: %v", err)
			}
		})
	}
}

func TestClosing_Schema_EnumValidation(t *testing.T) {
	schema := `{"type": "object", "properties": {"status": {"type": "string", "enum": ["active", "paused", "stopped"]}}, "required": ["status"]}`
	stub := &closingStubDispatcher{}
	fw := NewPolicyFirewall(stub)
	_ = fw.AllowTool("enum_tool", schema)
	bundle := PolicyInputBundle{ActorID: "u1", Role: "admin", SessionID: "s1"}
	valid := []string{"active", "paused", "stopped"}
	for _, v := range valid {
		t.Run("valid/"+v, func(t *testing.T) {
			_, err := fw.CallTool(context.Background(), bundle, "enum_tool", map[string]any{"status": v})
			if err != nil {
				t.Fatalf("expected valid enum: %v", err)
			}
		})
	}
	invalid := []string{"running", "deleted", "unknown"}
	for _, v := range invalid {
		t.Run("invalid/"+v, func(t *testing.T) {
			_, err := fw.CallTool(context.Background(), bundle, "enum_tool", map[string]any{"status": v})
			if err == nil {
				t.Fatal("expected invalid enum error")
			}
		})
	}
}

func TestClosing_Schema_MinMaxLength(t *testing.T) {
	schema := `{"type": "object", "properties": {"name": {"type": "string", "minLength": 2, "maxLength": 10}}, "required": ["name"]}`
	stub := &closingStubDispatcher{}
	fw := NewPolicyFirewall(stub)
	_ = fw.AllowTool("len_tool", schema)
	bundle := PolicyInputBundle{ActorID: "u1", Role: "admin", SessionID: "s1"}
	cases := []struct {
		val  string
		ok   bool
	}{
		{"ab", true},
		{"abcdefghij", true},
		{"abc", true},
		{"a", false},
		{"abcdefghijk", false},
	}
	for _, tc := range cases {
		t.Run("len/"+tc.val, func(t *testing.T) {
			_, err := fw.CallTool(context.Background(), bundle, "len_tool", map[string]any{"name": tc.val})
			if tc.ok && err != nil {
				t.Fatalf("expected valid: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

// ── 31-35. Egress edge cases ────────────────────────────────────────

func TestClosing_Egress_EmptyDestination(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{""}})
	protos := []string{"https", "http", "grpc"}
	for _, p := range protos {
		t.Run("empty_dest/"+p, func(t *testing.T) {
			dec := ec.CheckEgress("", p, 0)
			// Empty string is in allowed set
			if !dec.Allowed {
				t.Fatal("empty string in allowlist should match empty destination")
			}
		})
	}
}

func TestClosing_Egress_EmptyProtocol(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{
		AllowedDomains:   []string{"a.com"},
		AllowedProtocols: []string{"https"},
	})
	t.Run("empty_protocol_blocked", func(t *testing.T) {
		dec := ec.CheckEgress("a.com", "", 0)
		if dec.Allowed {
			t.Fatal("empty protocol should not match 'https'")
		}
	})
	t.Run("empty_protocol_no_restriction", func(t *testing.T) {
		ec2 := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"a.com"}})
		dec := ec2.CheckEgress("a.com", "", 0)
		if !dec.Allowed {
			t.Fatal("empty protocol should be allowed when no protocol restriction")
		}
	})
}

func TestClosing_Egress_SpecialCharDomains(t *testing.T) {
	special := []string{"xn--nxasmq6b.com", "test-hyphen.dev", "under_score.io"}
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: special})
	for _, d := range special {
		t.Run(d, func(t *testing.T) {
			dec := ec.CheckEgress(d, "https", 0)
			if !dec.Allowed {
				t.Fatalf("special domain %s should be allowed", d)
			}
		})
	}
}

func TestClosing_Egress_IPv4MappedIPv6(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"10.0.0.0/8"}})
	ips := []string{"::ffff:10.0.0.1", "::ffff:10.1.2.3"}
	for _, ip := range ips {
		t.Run(ip, func(t *testing.T) {
			dec := ec.CheckEgress(ip, "https", 0)
			// net.ParseIP handles IPv4-mapped IPv6 — should match 10.0.0.0/8
			if !dec.Allowed {
				t.Fatalf("IPv4-mapped IPv6 %s should match 10.0.0.0/8", ip)
			}
		})
	}
}

// ── 36-40. Multiple sequential operations ───────────────────────────

func TestClosing_Sequential_MultipleChecksAccumulate(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"a.com"}})
	counts := []int{1, 5, 10, 20, 50}
	for _, n := range counts {
		t.Run(fmt.Sprintf("after_%d_checks", n), func(t *testing.T) {
			fresh := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"a.com"}})
			for i := 0; i < n; i++ {
				fresh.CheckEgress("a.com", "https", 1)
			}
			total, _, _ := fresh.Stats()
			if total != int64(n) {
				t.Fatalf("total = %d, want %d", total, n)
			}
		})
	}
	_ = ec // suppress unused
}

func TestClosing_Firewall_ToolOverwrite(t *testing.T) {
	stub := &closingStubDispatcher{}
	fw := NewPolicyFirewall(stub)
	// Add then re-add with schema
	_ = fw.AllowTool("morph", "")
	schema := `{"type": "object", "properties": {"x": {"type": "string"}}, "required": ["x"]}`
	_ = fw.AllowTool("morph", schema)
	bundle := PolicyInputBundle{ActorID: "u1", Role: "admin", SessionID: "s1"}
	t.Run("overwritten_valid", func(t *testing.T) {
		_, err := fw.CallTool(context.Background(), bundle, "morph", map[string]any{"x": "hello"})
		if err != nil {
			t.Fatalf("expected valid after overwrite: %v", err)
		}
	})
	t.Run("overwritten_invalid", func(t *testing.T) {
		_, err := fw.CallTool(context.Background(), bundle, "morph", map[string]any{"y": 1})
		if err == nil {
			t.Fatal("expected schema validation error after overwrite")
		}
	})
}

func TestClosing_Firewall_ContextCancellation(t *testing.T) {
	stub := &closingStubDispatcher{}
	fw := NewPolicyFirewall(stub)
	_ = fw.AllowTool("op", "")
	bundle := PolicyInputBundle{ActorID: "u1", Role: "admin", SessionID: "s1"}
	ctxs := []string{"bg", "cancel_before", "cancel_after"}
	for _, name := range ctxs {
		t.Run(name, func(t *testing.T) {
			var ctx context.Context
			switch name {
			case "bg":
				ctx = context.Background()
			default:
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(context.Background())
				if name == "cancel_before" {
					cancel()
				} else {
					defer cancel()
				}
			}
			// Firewall itself doesn't check context cancellation — it passes through
			_, err := fw.CallTool(ctx, bundle, "op", nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// ── 41-45. CIDR edge cases ──────────────────────────────────────────

func TestClosing_CIDR_SingleHost(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"10.0.0.5/32"}})
	cases := map[string]bool{
		"10.0.0.5": true,
		"10.0.0.4": false,
		"10.0.0.6": false,
	}
	for ip, want := range cases {
		t.Run(ip, func(t *testing.T) {
			dec := ec.CheckEgress(ip, "https", 0)
			if dec.Allowed != want {
				t.Fatalf("ip=%s allowed=%v want=%v", ip, dec.Allowed, want)
			}
		})
	}
}

func TestClosing_CIDR_InvalidCIDRIgnored(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"not-a-cidr", "also-bad"}})
	ips := []string{"10.0.0.1", "192.168.0.1", "8.8.8.8"}
	for _, ip := range ips {
		t.Run(ip, func(t *testing.T) {
			dec := ec.CheckEgress(ip, "https", 0)
			if dec.Allowed {
				t.Fatal("invalid CIDRs should result in deny-all for IPs")
			}
		})
	}
}

func TestClosing_CIDR_LoopbackRange(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedCIDRs: []string{"127.0.0.0/8"}})
	ips := []string{"127.0.0.1", "127.0.0.2", "127.255.255.255"}
	for _, ip := range ips {
		t.Run(ip, func(t *testing.T) {
			dec := ec.CheckEgress(ip, "https", 0)
			if !dec.Allowed {
				t.Fatalf("loopback %s should be allowed in 127.0.0.0/8", ip)
			}
		})
	}
}

// ── 46-50. Firewall additional cases ────────────────────────────────

func TestClosing_Firewall_MultipleSessionIDs(t *testing.T) {
	stub := &closingStubDispatcher{}
	fw := NewPolicyFirewall(stub)
	_ = fw.AllowTool("action", "")
	sessions := []string{"sess-1", "sess-2", "sess-3", "sess-uuid-abc", ""}
	for _, s := range sessions {
		t.Run("session/"+s, func(t *testing.T) {
			bundle := PolicyInputBundle{ActorID: "u1", Role: "admin", SessionID: s}
			_, err := fw.CallTool(context.Background(), bundle, "action", nil)
			if err != nil {
				t.Fatalf("unexpected error for session %s: %v", s, err)
			}
		})
	}
}

func TestClosing_Firewall_ToolNameCaseSensitive(t *testing.T) {
	stub := &closingStubDispatcher{}
	fw := NewPolicyFirewall(stub)
	_ = fw.AllowTool("ReadFile", "")
	bundle := PolicyInputBundle{ActorID: "u1", Role: "admin", SessionID: "s1"}
	variants := []struct {
		name string
		ok   bool
	}{
		{"ReadFile", true},
		{"readfile", false},
		{"READFILE", false},
		{"readFile", false},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			_, err := fw.CallTool(context.Background(), bundle, v.name, nil)
			if v.ok && err != nil {
				t.Fatalf("expected ok: %v", err)
			}
			if !v.ok && err == nil {
				t.Fatal("tool names should be case-sensitive")
			}
		})
	}
}

func TestClosing_Firewall_DispatcherResult(t *testing.T) {
	stub := &closingStubDispatcher{}
	fw := NewPolicyFirewall(stub)
	_ = fw.AllowTool("op", "")
	bundle := PolicyInputBundle{ActorID: "u1", Role: "admin", SessionID: "s1"}
	calls := []int{1, 2, 3}
	for _, n := range calls {
		t.Run(fmt.Sprintf("call_%d", n), func(t *testing.T) {
			result, err := fw.CallTool(context.Background(), bundle, "op", nil)
			if err != nil {
				t.Fatal(err)
			}
			if result != "ok" {
				t.Fatalf("result = %v, want ok", result)
			}
		})
	}
}

func TestClosing_Egress_ReasonCodeConsistency(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"good.com"}})
	denied := []string{"bad1.com", "bad2.com", "bad3.com"}
	for _, d := range denied {
		t.Run(d, func(t *testing.T) {
			dec := ec.CheckEgress(d, "https", 0)
			if dec.ReasonCode != "DATA_EGRESS_BLOCKED" {
				t.Fatalf("reason = %s, want DATA_EGRESS_BLOCKED", dec.ReasonCode)
			}
		})
	}
}

func TestClosing_Egress_AllowedReasonEmpty(t *testing.T) {
	ec := NewEgressChecker(&EgressPolicy{AllowedDomains: []string{"ok1.com", "ok2.com", "ok3.com"}})
	for _, d := range []string{"ok1.com", "ok2.com", "ok3.com"} {
		t.Run(d, func(t *testing.T) {
			dec := ec.CheckEgress(d, "https", 0)
			if dec.ReasonCode != "" {
				t.Fatalf("allowed decision should have empty reason, got %s", dec.ReasonCode)
			}
		})
	}
}
