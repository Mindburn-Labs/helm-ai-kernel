package observability

import (
	"os"
	"testing"
)

// TestServiceNameFromEnv pins the two directions that matter: OTEL_SERVICE_NAME
// wins when set, and the historical default survives when it is not. Before
// HELM-495 the name was a constant, so spans landed under
// "helm-sovereign-os" no matter what the deployment called itself and a backend
// query for the deployment name found nothing.
func TestServiceNameFromEnv(t *testing.T) {
	cases := []struct {
		name string
		set  bool
		env  string
		want string
	}{
		{name: "unset keeps the historical default", set: false, want: DefaultServiceName},
		{name: "empty keeps the historical default", set: true, env: "", want: DefaultServiceName},
		{name: "blank keeps the historical default", set: true, env: "   ", want: DefaultServiceName},
		{name: "set overrides", set: true, env: "helm-ai-kernel", want: "helm-ai-kernel"},
		{name: "set is trimmed", set: true, env: "  helm-ai-kernel\n", want: "helm-ai-kernel"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv("OTEL_SERVICE_NAME", tc.env)
			} else {
				// t.Setenv restores on cleanup; clear so an ambient value in
				// the developer's shell cannot make this case vacuous.
				t.Setenv("OTEL_SERVICE_NAME", "")
				if err := unsetServiceNameEnv(); err != nil {
					t.Fatalf("unset OTEL_SERVICE_NAME: %v", err)
				}
			}
			if got := ServiceNameFromEnv(); got != tc.want {
				t.Errorf("ServiceNameFromEnv() = %q, want %q", got, tc.want)
			}
			if got := DefaultConfig().ServiceName; got != tc.want {
				t.Errorf("DefaultConfig().ServiceName = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDefaultConfigSamplesEverything(t *testing.T) {
	if got := DefaultConfig().SampleRate; got != 1.0 {
		t.Errorf("DefaultConfig().SampleRate = %v, want 1.0 — a lower default silently drops spans", got)
	}
}

// unsetServiceNameEnv removes the variable entirely (t.Setenv can only set it
// to the empty string). t.Setenv above has already registered the restore.
func unsetServiceNameEnv() error {
	return os.Unsetenv("OTEL_SERVICE_NAME")
}
