package capability

import (
	"strings"
	"testing"
)

func mintReq(taskID string) MintRequest {
	return MintRequest{
		TaskID:       taskID,
		Subject:      TokenSubject{AgentID: "agent-1"},
		CapabilityID: "helm.cap.gui.gelab.tap",
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
