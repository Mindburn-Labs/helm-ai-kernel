package capability

import (
	"strings"
	"testing"
	"time"

	kcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func testRegistry(t *testing.T) *Registry {
	t.Helper()
	reg, err := LoadDir("testdata/valid")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	return reg
}

func testAuthority(t *testing.T, clock func() time.Time) (*TokenAuthority, *TokenVerifier) {
	t.Helper()
	signer, err := kcrypto.NewEd25519Signer("capability-token-test")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	reg := testRegistry(t)
	store := NewInMemoryTokenStore()
	authority := NewTokenAuthority(signer, reg, store, clock)
	verifier := NewTokenVerifier(authority.PubKeyHex(), reg, store, clock)
	return authority, verifier
}

func mintReq(taskID string) MintRequest {
	return MintRequest{
		TaskID:       taskID,
		Subject:      TokenSubject{AgentID: "agent-1"},
		CapabilityID: "helm.cap.gui.gelab.tap",
	}
}

func TestToken_MintVerifyRoundtrip(t *testing.T) {
	authority, verifier := testAuthority(t, nil)
	token, err := authority.Mint(mintReq("task-1"))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if token.Status != TokenStatusActive || token.Signature == "" {
		t.Fatalf("minted token malformed: %+v", token)
	}
	stored, err := verifier.Verify(VerifyRequest{Presented: token, TaskID: "task-1"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if stored.TokenID != token.TokenID {
		t.Fatalf("token mismatch: %s vs %s", stored.TokenID, token.TokenID)
	}
}

func TestToken_MaxUsesExhaustion(t *testing.T) {
	authority, verifier := testAuthority(t, nil)
	req := mintReq("task-1")
	req.MaxUses = 1
	token, err := authority.Mint(req)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := verifier.Verify(VerifyRequest{Presented: token, TaskID: "task-1"}); err != nil {
		t.Fatalf("first use should succeed: %v", err)
	}
	_, err = verifier.Verify(VerifyRequest{Presented: token, TaskID: "task-1"})
	assertReject(t, err, TokenStatusUsedUp)
}

func TestToken_Expired(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	authority, verifier := testAuthority(t, clock)
	req := mintReq("task-1")
	req.TTL = time.Minute
	token, err := authority.Mint(req)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	now = now.Add(2 * time.Minute) // advance past expiry
	_, err = verifier.Verify(VerifyRequest{Presented: token, TaskID: "task-1"})
	assertReject(t, err, TokenStatusExpired)
}

func TestToken_TaskMismatch(t *testing.T) {
	authority, verifier := testAuthority(t, nil)
	token, err := authority.Mint(mintReq("task-A"))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	_, err = verifier.Verify(VerifyRequest{Presented: token, TaskID: "task-B"})
	assertReject(t, err, TokenRejectTaskMismatch)
}

func TestToken_BadSignature(t *testing.T) {
	authority, verifier := testAuthority(t, nil)
	token, err := authority.Mint(mintReq("task-1"))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	tampered := *token
	tampered.TaskID = "task-forged" // breaks the signed payload
	_, err = verifier.Verify(VerifyRequest{Presented: &tampered, TaskID: "task-forged"})
	assertReject(t, err, TokenRejectBadSignature)
}

func TestToken_Revoked(t *testing.T) {
	authority, verifier := testAuthority(t, nil)
	token, err := authority.Mint(mintReq("task-1"))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if err := authority.Store().Revoke(token.TokenID, "rcpt_revoke_1"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	_, err = verifier.Verify(VerifyRequest{Presented: token, TaskID: "task-1"})
	assertReject(t, err, TokenStatusRevoked)
}

func TestToken_MintUnknownCapabilityFails(t *testing.T) {
	authority, _ := testAuthority(t, nil)
	req := mintReq("task-1")
	req.CapabilityID = "helm.cap.does.not.exist"
	if _, err := authority.Mint(req); err == nil {
		t.Fatal("minting against unregistered capability must fail closed")
	}
}

func TestToken_ArgsDigestConstraint(t *testing.T) {
	authority, verifier := testAuthority(t, nil)
	goodArgs := map[string]interface{}{"device_id": "dev-1", "x": float64(512), "y": float64(300)}
	digest, err := HashArgs(goodArgs)
	if err != nil {
		t.Fatalf("HashArgs: %v", err)
	}
	req := mintReq("task-1")
	req.MaxUses = 2
	req.Constraints.ArgsDigest = digest
	token, err := authority.Mint(req)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := verifier.Verify(VerifyRequest{Presented: token, TaskID: "task-1", Args: goodArgs}); err != nil {
		t.Fatalf("matching args should verify: %v", err)
	}
	badArgs := map[string]interface{}{"device_id": "dev-1", "x": float64(1), "y": float64(1)}
	_, err = verifier.Verify(VerifyRequest{Presented: token, TaskID: "task-1", Args: badArgs})
	assertReject(t, err, TokenRejectArgsDigest)
}

func TestToken_BoundaryCeiling(t *testing.T) {
	authority, verifier := testAuthority(t, nil)
	req := mintReq("task-1") // tap manifest: device_boundary
	req.Constraints.DataBoundaryCeiling = "local_only"
	token, err := authority.Mint(req)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	_, err = verifier.Verify(VerifyRequest{Presented: token, TaskID: "task-1"})
	assertReject(t, err, TokenRejectBoundaryCeiling)
}

func TestToken_ValidateShape(t *testing.T) {
	authority, _ := testAuthority(t, nil)
	base, err := authority.Mint(mintReq("task-1"))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*Token)
	}{
		{"bad schema", func(tk *Token) { tk.SchemaVersion = "v0" }},
		{"bad token id", func(tk *Token) { tk.TokenID = "nope" }},
		{"missing task", func(tk *Token) { tk.TaskID = "" }},
		{"missing agent", func(tk *Token) { tk.Subject.AgentID = "" }},
		{"missing hash", func(tk *Token) { tk.CapabilityRef.ManifestHash = "" }},
		{"zero times", func(tk *Token) { tk.Grant.ExpiresAt = time.Time{} }},
		{"bad ceiling", func(tk *Token) { tk.Grant.Constraints.DataBoundaryCeiling = "moon" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tk := *base
			tc.mutate(&tk)
			if err := tk.ValidateShape(); err == nil {
				t.Fatal("expected shape validation error")
			}
		})
	}
}

func TestDecodeToken(t *testing.T) {
	authority, _ := testAuthority(t, nil)
	token, err := authority.Mint(mintReq("task-1"))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	asJSON := `{"schema_version":"` + TokenSchemaVersion + `","token_id":"` + token.TokenID + `"}`
	decoded, err := DecodeToken(asJSON)
	if err != nil {
		t.Fatalf("DecodeToken string: %v", err)
	}
	if decoded.TokenID != token.TokenID {
		t.Fatal("string decode mismatch")
	}
	asMap := map[string]interface{}{"token_id": token.TokenID, "schema_version": TokenSchemaVersion}
	decoded, err = DecodeToken(asMap)
	if err != nil {
		t.Fatalf("DecodeToken map: %v", err)
	}
	if decoded.TokenID != token.TokenID {
		t.Fatal("map decode mismatch")
	}
	if _, err := DecodeToken(42); err == nil {
		t.Fatal("unsupported type must fail")
	}
}

func assertReject(t *testing.T, err error, want interface{}) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected rejection %v, got nil error", want)
	}
	te, ok := err.(*TokenError)
	if !ok {
		t.Fatalf("expected *TokenError, got %T: %v", err, err)
	}
	wantStr := ""
	switch w := want.(type) {
	case string:
		wantStr = w
	case TokenStatus:
		wantStr = string(w)
	}
	if te.Reason != wantStr && !strings.Contains(te.Reason, wantStr) {
		t.Fatalf("reject reason %q, want %q", te.Reason, wantStr)
	}
}
