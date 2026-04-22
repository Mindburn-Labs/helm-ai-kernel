package a2a

import (
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 1-5: Feature enum coverage
// ---------------------------------------------------------------------------

func TestClosing_Feature_AllValues(t *testing.T) {
	features := []struct {
		f    Feature
		name string
	}{
		{FeatureMeteringReceipts, "METERING_RECEIPTS"},
		{FeatureDisputeReplay, "DISPUTE_REPLAY"},
		{FeatureProofGraphSync, "PROOFGRAPH_SYNC"},
		{FeatureEvidenceExport, "EVIDENCE_EXPORT"},
		{FeaturePolicyNegotiation, "POLICY_NEGOTIATION"},
		{FeatureAgentPayments, "AGENT_PAYMENTS"},
		{FeatureIATPAuth, "IATP_AUTH"},
		{FeaturePeerVouching, "PEER_VOUCHING"},
		{FeatureTrustPropagation, "TRUST_PROPAGATION"},
	}
	for _, tc := range features {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.f) != tc.name {
				t.Fatalf("got %q", tc.f)
			}
		})
	}
}

func TestClosing_Feature_Count(t *testing.T) {
	t.Run("nine_features", func(t *testing.T) {
		all := []Feature{FeatureMeteringReceipts, FeatureDisputeReplay, FeatureProofGraphSync, FeatureEvidenceExport, FeaturePolicyNegotiation, FeatureAgentPayments, FeatureIATPAuth, FeaturePeerVouching, FeatureTrustPropagation}
		if len(all) != 9 {
			t.Fatalf("got %d", len(all))
		}
	})
	t.Run("all_distinct", func(t *testing.T) {
		seen := make(map[Feature]bool)
		all := []Feature{FeatureMeteringReceipts, FeatureDisputeReplay, FeatureProofGraphSync, FeatureEvidenceExport, FeaturePolicyNegotiation, FeatureAgentPayments, FeatureIATPAuth, FeaturePeerVouching, FeatureTrustPropagation}
		for _, f := range all {
			if seen[f] {
				t.Fatalf("duplicate feature: %s", f)
			}
			seen[f] = true
		}
	})
	t.Run("all_nonempty", func(t *testing.T) {
		all := []Feature{FeatureMeteringReceipts, FeatureDisputeReplay, FeatureProofGraphSync, FeatureEvidenceExport, FeaturePolicyNegotiation, FeatureAgentPayments, FeatureIATPAuth, FeaturePeerVouching, FeatureTrustPropagation}
		for _, f := range all {
			if string(f) == "" {
				t.Fatal("feature should not be empty")
			}
		}
	})
}

func TestClosing_Feature_Categories(t *testing.T) {
	t.Run("trust_features", func(t *testing.T) {
		trustFeatures := []Feature{FeatureIATPAuth, FeaturePeerVouching, FeatureTrustPropagation}
		for _, f := range trustFeatures {
			if string(f) == "" {
				t.Fatalf("trust feature %s should be non-empty", f)
			}
		}
	})
	t.Run("evidence_features", func(t *testing.T) {
		evidenceFeatures := []Feature{FeatureEvidenceExport, FeatureProofGraphSync, FeatureMeteringReceipts}
		for _, f := range evidenceFeatures {
			if string(f) == "" {
				t.Fatalf("evidence feature %s should be non-empty", f)
			}
		}
	})
	t.Run("governance_features", func(t *testing.T) {
		govFeatures := []Feature{FeaturePolicyNegotiation, FeatureDisputeReplay}
		for _, f := range govFeatures {
			if string(f) == "" {
				t.Fatalf("governance feature %s should be non-empty", f)
			}
		}
	})
}

func TestClosing_Feature_PaymentsFeature(t *testing.T) {
	t.Run("value", func(t *testing.T) {
		if FeatureAgentPayments != "AGENT_PAYMENTS" {
			t.Fatalf("got %q", FeatureAgentPayments)
		}
	})
	t.Run("distinct_from_others", func(t *testing.T) {
		others := []Feature{FeatureMeteringReceipts, FeatureDisputeReplay, FeatureProofGraphSync}
		for _, o := range others {
			if FeatureAgentPayments == o {
				t.Fatalf("should be distinct from %s", o)
			}
		}
	})
	t.Run("is_string_type", func(t *testing.T) {
		var s string = string(FeatureAgentPayments)
		if s == "" {
			t.Fatal("should cast to non-empty string")
		}
	})
}

func TestClosing_Feature_IATPAuth(t *testing.T) {
	t.Run("value", func(t *testing.T) {
		if FeatureIATPAuth != "IATP_AUTH" {
			t.Fatalf("got %q", FeatureIATPAuth)
		}
	})
	t.Run("part_of_trust_set", func(t *testing.T) {
		if FeatureIATPAuth == FeatureAgentPayments {
			t.Fatal("IATP_AUTH should not equal AGENT_PAYMENTS")
		}
	})
	t.Run("nonempty", func(t *testing.T) {
		if string(FeatureIATPAuth) == "" {
			t.Fatal("should be non-empty")
		}
	})
}

// ---------------------------------------------------------------------------
// 6-10: DenyReason coverage
// ---------------------------------------------------------------------------

func TestClosing_DenyReason_AllValues(t *testing.T) {
	reasons := []struct {
		r    DenyReason
		name string
	}{
		{DenyVersionIncompatible, "VERSION_INCOMPATIBLE"},
		{DenyFeatureMissing, "FEATURE_MISSING"},
		{DenyPolicyViolation, "POLICY_VIOLATION"},
		{DenySignatureInvalid, "SIGNATURE_INVALID"},
		{DenyAgentNotTrusted, "AGENT_NOT_TRUSTED"},
		{DenyChallengeFailure, "CHALLENGE_FAILURE"},
		{DenyVouchRevoked, "VOUCH_REVOKED"},
	}
	for _, tc := range reasons {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.r) != tc.name {
				t.Fatalf("got %q", tc.r)
			}
		})
	}
}

func TestClosing_DenyReason_Count(t *testing.T) {
	t.Run("seven_reasons", func(t *testing.T) {
		all := []DenyReason{DenyVersionIncompatible, DenyFeatureMissing, DenyPolicyViolation, DenySignatureInvalid, DenyAgentNotTrusted, DenyChallengeFailure, DenyVouchRevoked}
		if len(all) != 7 {
			t.Fatalf("got %d", len(all))
		}
	})
	t.Run("all_distinct", func(t *testing.T) {
		seen := make(map[DenyReason]bool)
		all := []DenyReason{DenyVersionIncompatible, DenyFeatureMissing, DenyPolicyViolation, DenySignatureInvalid, DenyAgentNotTrusted, DenyChallengeFailure, DenyVouchRevoked}
		for _, r := range all {
			if seen[r] {
				t.Fatalf("duplicate: %s", r)
			}
			seen[r] = true
		}
	})
	t.Run("all_nonempty", func(t *testing.T) {
		all := []DenyReason{DenyVersionIncompatible, DenyFeatureMissing, DenyPolicyViolation, DenySignatureInvalid, DenyAgentNotTrusted, DenyChallengeFailure, DenyVouchRevoked}
		for _, r := range all {
			if string(r) == "" {
				t.Fatal("reason should not be empty")
			}
		}
	})
}

func TestClosing_DenyReason_SecurityReasons(t *testing.T) {
	securityReasons := []DenyReason{DenySignatureInvalid, DenyChallengeFailure, DenyAgentNotTrusted}
	for _, r := range securityReasons {
		t.Run(string(r), func(t *testing.T) {
			if string(r) == "" {
				t.Fatal("should not be empty")
			}
		})
	}
}

func TestClosing_DenyReason_ProtocolReasons(t *testing.T) {
	protocolReasons := []DenyReason{DenyVersionIncompatible, DenyFeatureMissing}
	for _, r := range protocolReasons {
		t.Run(string(r), func(t *testing.T) {
			if string(r) == "" {
				t.Fatal("should not be empty")
			}
		})
	}
}

func TestClosing_DenyReason_VouchRevoked(t *testing.T) {
	t.Run("value", func(t *testing.T) {
		if DenyVouchRevoked != "VOUCH_REVOKED" {
			t.Fatalf("got %q", DenyVouchRevoked)
		}
	})
	t.Run("distinct", func(t *testing.T) {
		if DenyVouchRevoked == DenyPolicyViolation {
			t.Fatal("should be distinct")
		}
	})
	t.Run("string_cast", func(t *testing.T) {
		s := string(DenyVouchRevoked)
		if s != "VOUCH_REVOKED" {
			t.Fatalf("got %q", s)
		}
	})
}

// ---------------------------------------------------------------------------
// 11-17: IATP states
// ---------------------------------------------------------------------------

func TestClosing_IATPSessionStatus_Values(t *testing.T) {
	statuses := []struct {
		s    IATPSessionStatus
		name string
	}{
		{IATPPending, "PENDING"},
		{IATPAuthenticated, "AUTHENTICATED"},
		{IATPFailed, "FAILED"},
	}
	for _, tc := range statuses {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.s) != tc.name {
				t.Fatalf("got %q", tc.s)
			}
		})
	}
}

func TestClosing_IATPSession_Fields(t *testing.T) {
	session := IATPSession{
		SessionID:   "sess-1",
		LocalAgent:  "local",
		RemoteAgent: "remote",
		Status:      IATPAuthenticated,
		TrustScore:  500,
	}
	t.Run("session_id", func(t *testing.T) {
		if session.SessionID != "sess-1" {
			t.Fatalf("got %q", session.SessionID)
		}
	})
	t.Run("status", func(t *testing.T) {
		if session.Status != IATPAuthenticated {
			t.Fatalf("got %q", session.Status)
		}
	})
	t.Run("trust_score", func(t *testing.T) {
		if session.TrustScore != 500 {
			t.Fatalf("got %d", session.TrustScore)
		}
	})
}

func TestClosing_ChallengeRequest_Fields(t *testing.T) {
	req := ChallengeRequest{
		ChallengeID:     "ch-1",
		ChallengerAgent: "agent-A",
		Nonce:           "deadbeef",
		TTL:             200 * time.Millisecond,
	}
	t.Run("challenge_id", func(t *testing.T) {
		if req.ChallengeID != "ch-1" {
			t.Fatalf("got %q", req.ChallengeID)
		}
	})
	t.Run("ttl", func(t *testing.T) {
		if req.TTL != 200*time.Millisecond {
			t.Fatalf("got %v", req.TTL)
		}
	})
	t.Run("nonce", func(t *testing.T) {
		if req.Nonce == "" {
			t.Fatal("nonce should not be empty")
		}
	})
}

func TestClosing_ChallengeResponse_Fields(t *testing.T) {
	resp := ChallengeResponse{
		ChallengeID:    "ch-1",
		ResponderAgent: "agent-B",
		SignedNonce:     "signed",
		PublicKey:       "pubkey",
	}
	t.Run("responder", func(t *testing.T) {
		if resp.ResponderAgent != "agent-B" {
			t.Fatalf("got %q", resp.ResponderAgent)
		}
	})
	t.Run("signed_nonce", func(t *testing.T) {
		if resp.SignedNonce == "" {
			t.Fatal("signed nonce should not be empty")
		}
	})
	t.Run("public_key", func(t *testing.T) {
		if resp.PublicKey == "" {
			t.Fatal("public key should not be empty")
		}
	})
}

func TestClosing_SchemaVersion_String(t *testing.T) {
	v := SchemaVersion{Major: 1, Minor: 2, Patch: 3}
	t.Run("format", func(t *testing.T) {
		if v.String() != "1.2.3" {
			t.Fatalf("got %q", v.String())
		}
	})
	t.Run("current_version", func(t *testing.T) {
		if CurrentVersion.Major != 1 || CurrentVersion.Minor != 0 || CurrentVersion.Patch != 0 {
			t.Fatalf("got %s", CurrentVersion.String())
		}
	})
	t.Run("zero_version", func(t *testing.T) {
		z := SchemaVersion{}
		if z.String() != "0.0.0" {
			t.Fatalf("got %q", z.String())
		}
	})
}

func TestClosing_PolicyAction_Values(t *testing.T) {
	t.Run("allow", func(t *testing.T) {
		if PolicyAllow != "ALLOW" {
			t.Fatalf("got %q", PolicyAllow)
		}
	})
	t.Run("deny", func(t *testing.T) {
		if PolicyDeny != "DENY" {
			t.Fatalf("got %q", PolicyDeny)
		}
	})
	t.Run("distinct", func(t *testing.T) {
		if PolicyAllow == PolicyDeny {
			t.Fatal("should be distinct")
		}
	})
}

func TestClosing_AuthMethod_Values(t *testing.T) {
	methods := []struct {
		m    AuthMethod
		name string
	}{
		{AuthMethodIATP, "IATP"},
		{AuthMethodAPIKey, "API_KEY"},
		{AuthMethodOAuth2, "OAUTH2"},
		{AuthMethodMTLS, "MTLS"},
	}
	for _, tc := range methods {
		t.Run(tc.name, func(t *testing.T) {
			if string(tc.m) != tc.name {
				t.Fatalf("got %q", tc.m)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 18-25: Vouch ops
// ---------------------------------------------------------------------------

func TestClosing_VouchRecord_Fields(t *testing.T) {
	rec := VouchRecord{
		VouchID: "v1", Voucher: "a", Vouchee: "b",
		Scope: []string{"read", "write"}, Stake: 50, MaxExposure: 50,
	}
	t.Run("vouch_id", func(t *testing.T) {
		if rec.VouchID != "v1" {
			t.Fatalf("got %q", rec.VouchID)
		}
	})
	t.Run("stake", func(t *testing.T) {
		if rec.Stake != 50 {
			t.Fatalf("got %d", rec.Stake)
		}
	})
	t.Run("scope_count", func(t *testing.T) {
		if len(rec.Scope) != 2 {
			t.Fatalf("got %d", len(rec.Scope))
		}
	})
	t.Run("not_revoked", func(t *testing.T) {
		if rec.Revoked {
			t.Fatal("should not be revoked")
		}
	})
}

func TestClosing_SlashResult_Fields(t *testing.T) {
	sr := SlashResult{VouchID: "v1", VoucherPenalty: 50, VoucheePenalty: 25, Reason: "violation"}
	t.Run("vouch_id", func(t *testing.T) {
		if sr.VouchID != "v1" {
			t.Fatalf("got %q", sr.VouchID)
		}
	})
	t.Run("voucher_penalty", func(t *testing.T) {
		if sr.VoucherPenalty != 50 {
			t.Fatalf("got %d", sr.VoucherPenalty)
		}
	})
	t.Run("reason", func(t *testing.T) {
		if sr.Reason != "violation" {
			t.Fatalf("got %q", sr.Reason)
		}
	})
}

func TestClosing_Envelope_Fields(t *testing.T) {
	env := Envelope{
		EnvelopeID:    "e1",
		SchemaVersion: CurrentVersion,
		OriginAgentID: "origin",
		TargetAgentID: "target",
		PayloadHash:   "sha256:abc",
	}
	t.Run("envelope_id", func(t *testing.T) {
		if env.EnvelopeID != "e1" {
			t.Fatalf("got %q", env.EnvelopeID)
		}
	})
	t.Run("schema_version", func(t *testing.T) {
		if env.SchemaVersion.Major != 1 {
			t.Fatalf("got %d", env.SchemaVersion.Major)
		}
	})
	t.Run("agents", func(t *testing.T) {
		if env.OriginAgentID == "" || env.TargetAgentID == "" {
			t.Fatal("agents should be set")
		}
	})
}

func TestClosing_ComputeEnvelopeHash(t *testing.T) {
	env := &Envelope{
		EnvelopeID:    "e1",
		SchemaVersion: CurrentVersion,
		OriginAgentID: "origin",
		TargetAgentID: "target",
		PayloadHash:   "sha256:abc",
	}
	t.Run("has_sha256_prefix", func(t *testing.T) {
		h := ComputeEnvelopeHash(env)
		if len(h) < 7 || h[:7] != "sha256:" {
			t.Fatalf("expected sha256: prefix, got %q", h)
		}
	})
	t.Run("deterministic", func(t *testing.T) {
		h1 := ComputeEnvelopeHash(env)
		h2 := ComputeEnvelopeHash(env)
		if h1 != h2 {
			t.Fatal("should be deterministic")
		}
	})
	t.Run("different_env_different_hash", func(t *testing.T) {
		env2 := &Envelope{EnvelopeID: "e2", SchemaVersion: CurrentVersion, OriginAgentID: "other", TargetAgentID: "target", PayloadHash: "sha256:def"}
		h1 := ComputeEnvelopeHash(env)
		h2 := ComputeEnvelopeHash(env2)
		if h1 == h2 {
			t.Fatal("different envelopes should have different hashes")
		}
	})
}

func TestClosing_SignEnvelope(t *testing.T) {
	env := &Envelope{
		EnvelopeID:    "e1",
		SchemaVersion: CurrentVersion,
		OriginAgentID: "origin",
		TargetAgentID: "target",
		PayloadHash:   "sha256:abc",
	}
	SignEnvelope(env, "key-1", "ed25519", "origin")
	t.Run("signature_set", func(t *testing.T) {
		if env.Signature.Value == "" {
			t.Fatal("signature value should be set")
		}
	})
	t.Run("key_id", func(t *testing.T) {
		if env.Signature.KeyID != "key-1" {
			t.Fatalf("got %q", env.Signature.KeyID)
		}
	})
	t.Run("algorithm", func(t *testing.T) {
		if env.Signature.Algorithm != "ed25519" {
			t.Fatalf("got %q", env.Signature.Algorithm)
		}
	})
	t.Run("agent_id", func(t *testing.T) {
		if env.Signature.AgentID != "origin" {
			t.Fatalf("got %q", env.Signature.AgentID)
		}
	})
}

func TestClosing_NegotiationResult_Fields(t *testing.T) {
	nr := NegotiationResult{
		Accepted:       true,
		AgreedFeatures: []Feature{FeatureMeteringReceipts, FeatureEvidenceExport},
		AgreedVersion:  &CurrentVersion,
		ReceiptID:      "r1",
	}
	t.Run("accepted", func(t *testing.T) {
		if !nr.Accepted {
			t.Fatal("should be accepted")
		}
	})
	t.Run("agreed_features", func(t *testing.T) {
		if len(nr.AgreedFeatures) != 2 {
			t.Fatalf("got %d", len(nr.AgreedFeatures))
		}
	})
	t.Run("receipt_id", func(t *testing.T) {
		if nr.ReceiptID != "r1" {
			t.Fatalf("got %q", nr.ReceiptID)
		}
	})
}

func TestClosing_PolicyRule_Fields(t *testing.T) {
	rule := PolicyRule{
		RuleID:          "r1",
		OriginAgent:     "*",
		TargetAgent:     "agent-B",
		AllowedFeatures: []Feature{FeatureMeteringReceipts},
		Action:          PolicyAllow,
	}
	t.Run("rule_id", func(t *testing.T) {
		if rule.RuleID != "r1" {
			t.Fatalf("got %q", rule.RuleID)
		}
	})
	t.Run("wildcard_origin", func(t *testing.T) {
		if rule.OriginAgent != "*" {
			t.Fatalf("got %q", rule.OriginAgent)
		}
	})
	t.Run("action", func(t *testing.T) {
		if rule.Action != PolicyAllow {
			t.Fatalf("got %q", rule.Action)
		}
	})
}

// ---------------------------------------------------------------------------
// 26-33: Propagation configs
// ---------------------------------------------------------------------------

func TestClosing_DefaultPropagationConfig(t *testing.T) {
	cfg := DefaultPropagationConfig()
	t.Run("decay_0.7", func(t *testing.T) {
		if cfg.DecayPerHop != 0.7 {
			t.Fatalf("got %f", cfg.DecayPerHop)
		}
	})
	t.Run("max_hops_3", func(t *testing.T) {
		if cfg.MaxHops != 3 {
			t.Fatalf("got %d", cfg.MaxHops)
		}
	})
	t.Run("min_score_400", func(t *testing.T) {
		if cfg.MinScore != 400 {
			t.Fatalf("got %d", cfg.MinScore)
		}
	})
}

func TestClosing_PropagationConfig_CustomValues(t *testing.T) {
	cfg := PropagationConfig{DecayPerHop: 0.5, MaxHops: 5, MinScore: 200}
	t.Run("custom_decay", func(t *testing.T) {
		if cfg.DecayPerHop != 0.5 {
			t.Fatalf("got %f", cfg.DecayPerHop)
		}
	})
	t.Run("custom_hops", func(t *testing.T) {
		if cfg.MaxHops != 5 {
			t.Fatalf("got %d", cfg.MaxHops)
		}
	})
	t.Run("custom_min_score", func(t *testing.T) {
		if cfg.MinScore != 200 {
			t.Fatalf("got %d", cfg.MinScore)
		}
	})
}

func TestClosing_TrustPath_Fields(t *testing.T) {
	path := TrustPath{
		Hops:        []string{"A", "B", "C"},
		HopScores:   []int{800, 700, 600},
		FinalScore:  420,
		DecayFactor: 0.7,
	}
	t.Run("hop_count", func(t *testing.T) {
		if len(path.Hops) != 3 {
			t.Fatalf("got %d", len(path.Hops))
		}
	})
	t.Run("final_score", func(t *testing.T) {
		if path.FinalScore != 420 {
			t.Fatalf("got %d", path.FinalScore)
		}
	})
	t.Run("decay_factor", func(t *testing.T) {
		if path.DecayFactor != 0.7 {
			t.Fatalf("got %f", path.DecayFactor)
		}
	})
}

// ---------------------------------------------------------------------------
// 34-40: AgentCard / AgentRegistry
// ---------------------------------------------------------------------------

func TestClosing_ValidateAgentCard(t *testing.T) {
	validCard := &AgentCard{
		AgentID:           "agent-1",
		Endpoint:          "https://example.com",
		SupportedVersions: []SchemaVersion{CurrentVersion},
		Skills:            []AgentSkill{{ID: "s1", Name: "Skill One"}},
	}
	t.Run("valid_card", func(t *testing.T) {
		if err := ValidateAgentCard(validCard); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("nil_card", func(t *testing.T) {
		if err := ValidateAgentCard(nil); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("empty_agent_id", func(t *testing.T) {
		c := *validCard
		c.AgentID = ""
		if err := ValidateAgentCard(&c); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("no_endpoint", func(t *testing.T) {
		c := *validCard
		c.Endpoint = ""
		if err := ValidateAgentCard(&c); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("no_skills", func(t *testing.T) {
		c := *validCard
		c.Skills = nil
		if err := ValidateAgentCard(&c); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestClosing_ComputeCardHash(t *testing.T) {
	card := &AgentCard{
		AgentID:           "agent-1",
		Name:              "Test Agent",
		Endpoint:          "https://example.com",
		SupportedVersions: []SchemaVersion{CurrentVersion},
		Skills:            []AgentSkill{{ID: "s1", Name: "Skill"}},
	}
	t.Run("has_sha256_prefix", func(t *testing.T) {
		h := ComputeCardHash(card)
		if len(h) < 7 || h[:7] != "sha256:" {
			t.Fatalf("expected sha256: prefix, got %q", h)
		}
	})
	t.Run("deterministic", func(t *testing.T) {
		h1 := ComputeCardHash(card)
		h2 := ComputeCardHash(card)
		if h1 != h2 {
			t.Fatal("should be deterministic")
		}
	})
	t.Run("different_cards_different_hash", func(t *testing.T) {
		card2 := &AgentCard{AgentID: "agent-2", Name: "Other", Endpoint: "https://other.com", SupportedVersions: []SchemaVersion{CurrentVersion}, Skills: []AgentSkill{{ID: "s2", Name: "S2"}}}
		h1 := ComputeCardHash(card)
		h2 := ComputeCardHash(card2)
		if h1 == h2 {
			t.Fatal("different cards should have different hashes")
		}
	})
}

func TestClosing_AgentRegistry_RegisterLookup(t *testing.T) {
	reg := NewAgentRegistry()
	card := &AgentCard{AgentID: "a1", Endpoint: "https://a1.com", SupportedVersions: []SchemaVersion{CurrentVersion}, Skills: []AgentSkill{{ID: "s1", Name: "S1"}}}
	t.Run("register", func(t *testing.T) {
		err := reg.Register(card)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("lookup", func(t *testing.T) {
		found, ok := reg.Lookup("a1")
		if !ok || found == nil {
			t.Fatal("should find card")
		}
	})
	t.Run("lookup_missing", func(t *testing.T) {
		_, ok := reg.Lookup("missing")
		if ok {
			t.Fatal("should not find")
		}
	})
	t.Run("content_hash_set", func(t *testing.T) {
		found, _ := reg.Lookup("a1")
		if found.ContentHash == "" {
			t.Fatal("content hash should be set")
		}
	})
}

func TestClosing_AgentRegistry_Deregister(t *testing.T) {
	reg := NewAgentRegistry()
	card := &AgentCard{AgentID: "a1", Endpoint: "https://a1.com", SupportedVersions: []SchemaVersion{CurrentVersion}, Skills: []AgentSkill{{ID: "s1", Name: "S1"}}}
	reg.Register(card)
	t.Run("deregister_exists", func(t *testing.T) {
		ok := reg.Deregister("a1")
		if !ok {
			t.Fatal("should return true for existing agent")
		}
	})
	t.Run("deregister_nonexistent", func(t *testing.T) {
		ok := reg.Deregister("missing")
		if ok {
			t.Fatal("should return false")
		}
	})
	t.Run("lookup_after_deregister", func(t *testing.T) {
		_, ok := reg.Lookup("a1")
		if ok {
			t.Fatal("should not find after deregister")
		}
	})
}

func TestClosing_AgentRegistry_ListAgents(t *testing.T) {
	reg := NewAgentRegistry()
	reg.Register(&AgentCard{AgentID: "a1", Endpoint: "https://a1.com", SupportedVersions: []SchemaVersion{CurrentVersion}, Skills: []AgentSkill{{ID: "s1", Name: "S1"}}})
	reg.Register(&AgentCard{AgentID: "a2", Endpoint: "https://a2.com", SupportedVersions: []SchemaVersion{CurrentVersion}, Skills: []AgentSkill{{ID: "s2", Name: "S2"}}})
	t.Run("two_agents", func(t *testing.T) {
		ids := reg.ListAgents()
		if len(ids) != 2 {
			t.Fatalf("got %d", len(ids))
		}
	})
	t.Run("empty_registry", func(t *testing.T) {
		empty := NewAgentRegistry()
		if len(empty.ListAgents()) != 0 {
			t.Fatal("should be empty")
		}
	})
	t.Run("after_deregister", func(t *testing.T) {
		reg.Deregister("a1")
		ids := reg.ListAgents()
		if len(ids) != 1 {
			t.Fatalf("got %d", len(ids))
		}
	})
}

func TestClosing_AgentRegistry_FindBySkill(t *testing.T) {
	reg := NewAgentRegistry()
	reg.Register(&AgentCard{AgentID: "a1", Endpoint: "https://a1.com", SupportedVersions: []SchemaVersion{CurrentVersion}, Skills: []AgentSkill{{ID: "search", Name: "Search"}}})
	reg.Register(&AgentCard{AgentID: "a2", Endpoint: "https://a2.com", SupportedVersions: []SchemaVersion{CurrentVersion}, Skills: []AgentSkill{{ID: "translate", Name: "Translate"}}})
	t.Run("find_search", func(t *testing.T) {
		cards := reg.FindBySkill("search")
		if len(cards) != 1 {
			t.Fatalf("got %d", len(cards))
		}
	})
	t.Run("find_none", func(t *testing.T) {
		cards := reg.FindBySkill("nonexistent")
		if len(cards) != 0 {
			t.Fatalf("got %d", len(cards))
		}
	})
	t.Run("find_translate", func(t *testing.T) {
		cards := reg.FindBySkill("translate")
		if len(cards) != 1 {
			t.Fatalf("got %d", len(cards))
		}
	})
}

func TestClosing_AgentRegistry_FindByFeature(t *testing.T) {
	reg := NewAgentRegistry()
	reg.Register(&AgentCard{AgentID: "a1", Endpoint: "https://a1.com", SupportedVersions: []SchemaVersion{CurrentVersion}, Skills: []AgentSkill{{ID: "s1", Name: "S1"}}, Features: []Feature{FeatureIATPAuth, FeatureEvidenceExport}})
	reg.Register(&AgentCard{AgentID: "a2", Endpoint: "https://a2.com", SupportedVersions: []SchemaVersion{CurrentVersion}, Skills: []AgentSkill{{ID: "s2", Name: "S2"}}, Features: []Feature{FeatureIATPAuth}})
	t.Run("find_iatp", func(t *testing.T) {
		cards := reg.FindByFeature(FeatureIATPAuth)
		if len(cards) != 2 {
			t.Fatalf("got %d", len(cards))
		}
	})
	t.Run("find_evidence", func(t *testing.T) {
		cards := reg.FindByFeature(FeatureEvidenceExport)
		if len(cards) != 1 {
			t.Fatalf("got %d", len(cards))
		}
	})
	t.Run("find_none", func(t *testing.T) {
		cards := reg.FindByFeature(FeatureAgentPayments)
		if len(cards) != 0 {
			t.Fatalf("got %d", len(cards))
		}
	})
}

// ---------------------------------------------------------------------------
// 41-50: AgentRegistry validation, TrustedKey, and misc
// ---------------------------------------------------------------------------

func TestClosing_AgentRegistry_InvalidCard(t *testing.T) {
	reg := NewAgentRegistry()
	t.Run("nil_card", func(t *testing.T) {
		err := reg.Register(nil)
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("empty_id", func(t *testing.T) {
		err := reg.Register(&AgentCard{Endpoint: "https://x.com", SupportedVersions: []SchemaVersion{CurrentVersion}, Skills: []AgentSkill{{ID: "s", Name: "S"}}})
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("empty_skills", func(t *testing.T) {
		err := reg.Register(&AgentCard{AgentID: "a", Endpoint: "https://x.com", SupportedVersions: []SchemaVersion{CurrentVersion}})
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestClosing_TrustedKey_Fields(t *testing.T) {
	key := TrustedKey{KeyID: "k1", AgentID: "a1", Algorithm: "ed25519", PublicKey: "base64key", Active: true}
	t.Run("key_id", func(t *testing.T) {
		if key.KeyID != "k1" {
			t.Fatalf("got %q", key.KeyID)
		}
	})
	t.Run("active", func(t *testing.T) {
		if !key.Active {
			t.Fatal("should be active")
		}
	})
	t.Run("algorithm", func(t *testing.T) {
		if key.Algorithm != "ed25519" {
			t.Fatalf("got %q", key.Algorithm)
		}
	})
}

func TestClosing_Signature_Fields(t *testing.T) {
	sig := Signature{KeyID: "k1", Algorithm: "ed25519", Value: "sigvalue", AgentID: "a1"}
	t.Run("key_id", func(t *testing.T) {
		if sig.KeyID != "k1" {
			t.Fatalf("got %q", sig.KeyID)
		}
	})
	t.Run("value", func(t *testing.T) {
		if sig.Value != "sigvalue" {
			t.Fatalf("got %q", sig.Value)
		}
	})
	t.Run("agent_id", func(t *testing.T) {
		if sig.AgentID != "a1" {
			t.Fatalf("got %q", sig.AgentID)
		}
	})
}

func TestClosing_AgentSkill_Validation(t *testing.T) {
	t.Run("valid_skill", func(t *testing.T) {
		card := &AgentCard{AgentID: "a", Endpoint: "https://x.com", SupportedVersions: []SchemaVersion{CurrentVersion}, Skills: []AgentSkill{{ID: "s1", Name: "S1"}}}
		if err := ValidateAgentCard(card); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("empty_skill_id", func(t *testing.T) {
		card := &AgentCard{AgentID: "a", Endpoint: "https://x.com", SupportedVersions: []SchemaVersion{CurrentVersion}, Skills: []AgentSkill{{Name: "S1"}}}
		if err := ValidateAgentCard(card); err == nil {
			t.Fatal("expected error for empty skill ID")
		}
	})
	t.Run("empty_skill_name", func(t *testing.T) {
		card := &AgentCard{AgentID: "a", Endpoint: "https://x.com", SupportedVersions: []SchemaVersion{CurrentVersion}, Skills: []AgentSkill{{ID: "s1"}}}
		if err := ValidateAgentCard(card); err == nil {
			t.Fatal("expected error for empty skill name")
		}
	})
}

func TestClosing_AgentSkill_IOMode(t *testing.T) {
	skill := AgentSkill{ID: "s1", Name: "Test", InputModes: []string{"text", "file"}, OutputModes: []string{"structured"}}
	t.Run("input_modes", func(t *testing.T) {
		if len(skill.InputModes) != 2 {
			t.Fatalf("got %d", len(skill.InputModes))
		}
	})
	t.Run("output_modes", func(t *testing.T) {
		if len(skill.OutputModes) != 1 {
			t.Fatalf("got %d", len(skill.OutputModes))
		}
	})
	t.Run("empty_modes_ok", func(t *testing.T) {
		s := AgentSkill{ID: "s2", Name: "Minimal"}
		if s.InputModes != nil {
			t.Fatal("nil modes should be ok")
		}
	})
}

func TestClosing_AgentRegistry_UpdateCard(t *testing.T) {
	reg := NewAgentRegistry()
	card1 := &AgentCard{AgentID: "a1", Name: "V1", Endpoint: "https://a1.com", SupportedVersions: []SchemaVersion{CurrentVersion}, Skills: []AgentSkill{{ID: "s1", Name: "S1"}}}
	reg.Register(card1)
	card2 := &AgentCard{AgentID: "a1", Name: "V2", Endpoint: "https://a1-new.com", SupportedVersions: []SchemaVersion{CurrentVersion}, Skills: []AgentSkill{{ID: "s1", Name: "S1 Updated"}}}
	reg.Register(card2)
	t.Run("updated", func(t *testing.T) {
		found, _ := reg.Lookup("a1")
		if found.Name != "V2" {
			t.Fatalf("got %q", found.Name)
		}
	})
	t.Run("count_unchanged", func(t *testing.T) {
		if len(reg.ListAgents()) != 1 {
			t.Fatalf("got %d", len(reg.ListAgents()))
		}
	})
	t.Run("new_hash", func(t *testing.T) {
		found, _ := reg.Lookup("a1")
		if found.ContentHash == "" {
			t.Fatal("hash should be set")
		}
	})
}

func TestClosing_Envelope_Expiry(t *testing.T) {
	now := time.Now()
	env := Envelope{
		EnvelopeID: "e1",
		CreatedAt:  now,
		ExpiresAt:  now.Add(5 * time.Minute),
	}
	t.Run("not_expired", func(t *testing.T) {
		if time.Now().After(env.ExpiresAt) {
			t.Fatal("should not be expired")
		}
	})
	t.Run("has_lifetime", func(t *testing.T) {
		lifetime := env.ExpiresAt.Sub(env.CreatedAt)
		if lifetime != 5*time.Minute {
			t.Fatalf("got %v", lifetime)
		}
	})
	t.Run("created_before_expires", func(t *testing.T) {
		if !env.CreatedAt.Before(env.ExpiresAt) {
			t.Fatal("created_at should be before expires_at")
		}
	})
}

func TestClosing_AgentCard_Timestamps(t *testing.T) {
	now := time.Now()
	card := AgentCard{
		AgentID:   "a1",
		CreatedAt: now,
		UpdatedAt: now,
	}
	t.Run("created_at", func(t *testing.T) {
		if card.CreatedAt.IsZero() {
			t.Fatal("should be set")
		}
	})
	t.Run("updated_at", func(t *testing.T) {
		if card.UpdatedAt.IsZero() {
			t.Fatal("should be set")
		}
	})
	t.Run("same_time", func(t *testing.T) {
		if !card.CreatedAt.Equal(card.UpdatedAt) {
			t.Fatal("should be equal on creation")
		}
	})
}
