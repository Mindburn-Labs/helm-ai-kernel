package session

import (
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
)

func TestRuntimeSecretsTokenBrokerDoesNotProjectRawProviderKey(t *testing.T) {
	t.Setenv("OPENROUTER_API_KEY", "sk-raw-provider")
	compiled := plan.LaunchPlan{
		ModelGatewayEnv:  []string{"OPENROUTER_API_KEY"},
		ModelGatewayMode: "token_broker",
	}

	secrets := runtimeSecrets(compiled, ExecuteOptions{
		RuntimeSecretEnv: map[string]string{
			"HELM_MODEL_GATEWAY_TOKEN": "broker-token",
			"HELM_MODEL_GATEWAY_URL":   "https://gateway.example",
		},
	})

	if _, leaked := secrets["OPENROUTER_API_KEY"]; leaked {
		t.Fatalf("token broker projected raw provider key: %#v", secrets)
	}
	if secrets["HELM_MODEL_GATEWAY_TOKEN"] != "broker-token" {
		t.Fatalf("broker token missing: %#v", secrets)
	}
	if secrets["HELM_MODEL_GATEWAY_URL"] != "https://gateway.example" {
		t.Fatalf("broker URL missing: %#v", secrets)
	}
}
