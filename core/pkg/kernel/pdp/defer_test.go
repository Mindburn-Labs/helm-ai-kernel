package pdp

import (
	"testing"
	"time"
)

func TestValidateDEFERResponse(t *testing.T) {
	tests := []struct {
		name    string
		resp    PDPResponse
		wantErr bool
	}{
		{
			name: "Valid DEFER",
			resp: PDPResponse{
				Decision:        "DEFER",
				DeferReasonCode: "reason",
				RequiredFacts:   []FactRef{{FactID: "fact1"}},
				TimeoutPolicy:   &TimeoutPolicy{PolicyID: "policy1"},
				RequeryRule:     &RequeryRule{Mode: "EXACT_REUSE"},
			},
			wantErr: false,
		},
		{
			name: "Missing Reason",
			resp: PDPResponse{
				Decision:      "DEFER",
				RequiredFacts: []FactRef{{FactID: "fact1"}},
				TimeoutPolicy: &TimeoutPolicy{PolicyID: "policy1"},
				RequeryRule:   &RequeryRule{Mode: "EXACT_REUSE"},
			},
			wantErr: true,
		},
		{
			name: "Missing Required Facts",
			resp: PDPResponse{
				Decision:        "DEFER",
				DeferReasonCode: "reason",
				RequiredFacts:   []FactRef{},
				TimeoutPolicy:   &TimeoutPolicy{PolicyID: "policy1"},
				RequeryRule:     &RequeryRule{Mode: "EXACT_REUSE"},
			},
			wantErr: true,
		},
		{
			name: "Missing Timeout Policy",
			resp: PDPResponse{
				Decision:        "DEFER",
				DeferReasonCode: "reason",
				RequiredFacts:   []FactRef{{FactID: "fact1"}},
				RequeryRule:     &RequeryRule{Mode: "EXACT_REUSE"},
			},
			wantErr: true,
		},
		{
			name: "Missing Requery Rule",
			resp: PDPResponse{
				Decision:        "DEFER",
				DeferReasonCode: "reason",
				RequiredFacts:   []FactRef{{FactID: "fact1"}},
				TimeoutPolicy:   &TimeoutPolicy{PolicyID: "policy1"},
			},
			wantErr: true,
		},
		{
			name: "Valid ALLOW (Ignored)",
			resp: PDPResponse{
				Decision: "ALLOW",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateDEFERResponse(tt.resp); (err != nil) != tt.wantErr {
				t.Errorf("ValidateDEFERResponse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCheckTimeout(t *testing.T) {
	baseTime := time.Date(2023, 1, 1, 10, 0, 0, 0, time.UTC)
	state := ObligationState{EnteredAt: baseTime}
	policy := TimeoutPolicy{TimeoutDurationMs: 60000} // 1 minute

	tests := []struct {
		name            string
		now             time.Time
		wantExpired     bool
		wantRemainingMs int64
	}{
		{
			name:            "Before Timeout",
			now:             baseTime.Add(30 * time.Second),
			wantExpired:     false,
			wantRemainingMs: 30000,
		},
		{
			name:            "At Timeout (Exact)",
			now:             baseTime.Add(60 * time.Second),
			wantExpired:     false, // After(deadline) checks strictly greater
			wantRemainingMs: 0,
		},
		{
			name:            "After Timeout",
			now:             baseTime.Add(61 * time.Second),
			wantExpired:     true,
			wantRemainingMs: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckTimeout(state, policy, tt.now)
			if got.Expired != tt.wantExpired {
				t.Errorf("CheckTimeout() expired = %v, want %v", got.Expired, tt.wantExpired)
			}
			if !got.Expired && got.RemainingMs != tt.wantRemainingMs {
				t.Errorf("CheckTimeout() remainingMs = %v, want %v", got.RemainingMs, tt.wantRemainingMs)
			}
		})
	}
}
