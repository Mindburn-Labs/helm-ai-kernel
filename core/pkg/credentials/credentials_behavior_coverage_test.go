package credentials

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newTestStore(t *testing.T) (*Store, *sql.DB) {
	t.Helper()
	s, db, _ := newKMSStore(t)
	return s, db
}

func TestSaveAndRetrieveCredential(t *testing.T) {
	s, db := newTestStore(t)
	defer db.Close()
	ctx := context.Background()
	s.SaveCredential(ctx, &Credential{ID: "c1", OperatorID: "op1", Provider: ProviderAnthropic, TokenType: TokenTypeApiKey, AccessToken: "key123"})
	cred, err := s.GetCredential(ctx, "op1", ProviderAnthropic)
	if err != nil || cred == nil || cred.AccessToken != "key123" {
		t.Fatalf("retrieval failed: %v, cred=%v", err, cred)
	}
}

func TestGetCredentialNotFound(t *testing.T) {
	s, db := newTestStore(t)
	defer db.Close()
	cred, err := s.GetCredential(context.Background(), "missing", ProviderGoogle)
	if err != nil || cred != nil {
		t.Fatalf("expected nil, got err=%v cred=%v", err, cred)
	}
}

func TestDeleteCredentialRemoves(t *testing.T) {
	s, db := newTestStore(t)
	defer db.Close()
	ctx := context.Background()
	s.SaveCredential(ctx, &Credential{ID: "d1", OperatorID: "op2", Provider: ProviderOpenAI, TokenType: TokenTypeApiKey, AccessToken: "k"})
	s.DeleteCredential(ctx, "op2", ProviderOpenAI)
	cred, _ := s.GetCredential(ctx, "op2", ProviderOpenAI)
	if cred != nil {
		t.Fatal("expected nil after delete")
	}
}

func TestNeedsRefreshNilCredential(t *testing.T) {
	var c *Credential
	if c.NeedsRefresh() {
		t.Fatal("nil credential should not need refresh")
	}
}

func TestNeedsRefreshNoExpiry(t *testing.T) {
	c := &Credential{}
	if c.NeedsRefresh() {
		t.Fatal("no expiry should not need refresh")
	}
}

func TestNeedsRefreshFarFuture(t *testing.T) {
	exp := time.Now().Add(24 * time.Hour)
	c := &Credential{ExpiresAt: &exp}
	if c.NeedsRefresh() {
		t.Fatal("far future should not need refresh")
	}
}

func TestNeedsRefreshImminent(t *testing.T) {
	exp := time.Now().Add(2 * time.Minute)
	c := &Credential{ExpiresAt: &exp}
	if !c.NeedsRefresh() {
		t.Fatal("imminent expiry should need refresh")
	}
}

func TestRotationManagerIssue(t *testing.T) {
	m := NewRotationManager(RotationPolicy{MaxAge: time.Hour})
	c := m.Issue("t1", "svc")
	if c.State != CredentialActive || c.RotationGen != 1 {
		t.Fatalf("bad issue state=%s gen=%d", c.State, c.RotationGen)
	}
}

func TestRotationManagerRotateIncrements(t *testing.T) {
	m := NewRotationManager(RotationPolicy{MaxAge: time.Hour})
	old := m.Issue("t1", "svc")
	nc, _ := m.Rotate(old.CredentialID)
	if nc.RotationGen != 2 {
		t.Fatalf("expected gen 2, got %d", nc.RotationGen)
	}
}

func TestRotationManagerRevokeInvalidates(t *testing.T) {
	m := NewRotationManager(RotationPolicy{MaxAge: time.Hour})
	c := m.Issue("t1", "svc")
	m.Revoke(c.CredentialID)
	if m.IsValid(c.CredentialID) {
		t.Fatal("revoked credential should not be valid")
	}
}

func TestRotationManagerGetNotFound(t *testing.T) {
	m := NewRotationManager(RotationPolicy{MaxAge: time.Hour})
	_, err := m.Get("missing")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRotationManagerIsValidMissing(t *testing.T) {
	m := NewRotationManager(RotationPolicy{MaxAge: time.Hour})
	if m.IsValid("nope") {
		t.Fatal("missing credential should not be valid")
	}
}
