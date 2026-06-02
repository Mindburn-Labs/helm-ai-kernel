package governance

import "testing"

func TestEdgeAssistantShouldAllow(t *testing.T) {
	tests := []struct {
		name       string
		assistant  EdgeAssistant
		effectType string
		riskLevel  string
		want       bool
	}{
		{
			name:       "full mode defers to complete pdp",
			assistant:  EdgeAssistant{Config: EdgeConfig{Mode: EdgeFull}},
			effectType: "any",
			riskLevel:  "CRITICAL",
			want:       true,
		},
		{
			name: "reduced mode allows configured effect",
			assistant: EdgeAssistant{Config: EdgeConfig{
				Mode:           EdgeReduced,
				AllowedEffects: []string{"DATA_READ"},
			}},
			effectType: "DATA_READ",
			riskLevel:  "LOW",
			want:       true,
		},
		{
			name: "reduced mode denies unconfigured effect",
			assistant: EdgeAssistant{Config: EdgeConfig{
				Mode:           EdgeReduced,
				AllowedEffects: []string{"DATA_READ"},
			}},
			effectType: "DATA_WRITE",
			riskLevel:  "LOW",
			want:       false,
		},
		{
			name: "fallback deny all fails closed",
			assistant: EdgeAssistant{
				Config:   EdgeConfig{Mode: EdgeFallback},
				Fallback: FallbackPolicy{Strategy: FallbackDenyAll},
			},
			effectType: "DATA_READ",
			riskLevel:  "LOW",
			want:       false,
		},
		{
			name: "fallback ring fence allows matching low risk effect",
			assistant: EdgeAssistant{
				Config: EdgeConfig{Mode: EdgeFallback},
				Fallback: FallbackPolicy{
					Strategy:   FallbackRingFence,
					AllowRules: []FallbackRule{{EffectType: "DATA_READ", MaxRisk: "MEDIUM"}},
				},
			},
			effectType: "DATA_READ",
			riskLevel:  "LOW",
			want:       true,
		},
		{
			name: "fallback ring fence denies excessive risk",
			assistant: EdgeAssistant{
				Config: EdgeConfig{Mode: EdgeFallback},
				Fallback: FallbackPolicy{
					Strategy:   FallbackRingFence,
					AllowRules: []FallbackRule{{EffectType: "DATA_READ", MaxRisk: "LOW"}},
				},
			},
			effectType: "DATA_READ",
			riskLevel:  "HIGH",
			want:       false,
		},
		{
			name: "offline cached allow uses configured effects",
			assistant: EdgeAssistant{
				Config: EdgeConfig{
					Mode:           EdgeOffline,
					AllowedEffects: []string{"LOCAL_EXPLAIN"},
				},
				Fallback: FallbackPolicy{Strategy: FallbackCachedAllow},
			},
			effectType: "LOCAL_EXPLAIN",
			riskLevel:  "LOW",
			want:       true,
		},
		{
			name: "offline cached allow denies unconfigured effect",
			assistant: EdgeAssistant{
				Config: EdgeConfig{
					Mode:           EdgeOffline,
					AllowedEffects: []string{"LOCAL_EXPLAIN"},
				},
				Fallback: FallbackPolicy{Strategy: FallbackCachedAllow},
			},
			effectType: "REMOTE_WRITE",
			riskLevel:  "LOW",
			want:       false,
		},
		{
			name:       "unknown mode fails closed",
			assistant:  EdgeAssistant{Config: EdgeConfig{Mode: "UNKNOWN"}},
			effectType: "DATA_READ",
			riskLevel:  "LOW",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.assistant.ShouldAllow(tt.effectType, tt.riskLevel); got != tt.want {
				t.Fatalf("ShouldAllow()=%t want %t", got, tt.want)
			}
		})
	}
}

func TestIsRiskAtOrBelow(t *testing.T) {
	if !isRiskAtOrBelow("MEDIUM", "HIGH") {
		t.Fatal("MEDIUM should be at or below HIGH")
	}
	if isRiskAtOrBelow("CRITICAL", "HIGH") {
		t.Fatal("CRITICAL should exceed HIGH")
	}
	if isRiskAtOrBelow("UNKNOWN", "LOW") {
		t.Fatal("unknown actual risk should deny")
	}
	if isRiskAtOrBelow("LOW", "UNKNOWN") {
		t.Fatal("unknown max risk should deny")
	}
}
