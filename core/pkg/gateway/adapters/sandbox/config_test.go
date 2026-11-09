package sandbox

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfigAcceptsAWellFormedFileAndRefusesTheRest(t *testing.T) {
	good := `{"providers":[
	  {"provider":"e2b","key_file":"/run/helm/e2b","api_url":"https://api.e2b.dev","template_id":"base","default_timeout_seconds":120},
	  {"provider":"daytona","key_file":"/run/helm/daytona","base_url":"https://daytona.example"},
	  {"provider":"opensandbox","key_file":"/run/helm/os","base_url":"https://os.example","tls_required":true,"egress_strict_mode":true},
	  {"provider":"docker","docker_bin":"docker"},
	  {"provider":"claude-managed-agents","key_file":"/run/helm/cma","managed_agents":{"worker_id":"w1"}}]}`
	c, err := ParseConfig([]byte(good))
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"e2b": "/run/helm/e2b", "daytona": "/run/helm/daytona", "opensandbox": "/run/helm/os", "claude-managed-agents": "/run/helm/cma"}, c.KeyFiles(),
		"Docker has no key file: it takes no credential")

	for name, raw := range map[string]string{
		"empty":                     ``,
		"no providers":              `{"providers":[]}`,
		"unknown field":             `{"providers":[{"provider":"docker","privileged":true}]}`,
		"unknown provider":          `{"providers":[{"provider":"modal","key_file":"/k"}]}`,
		"duplicate":                 `{"providers":[{"provider":"docker"},{"provider":"docker"}]}`,
		"trailing value":            `{"providers":[{"provider":"docker"}]} {}`,
		"docker with a key":         `{"providers":[{"provider":"docker","key_file":"/k"}]}`,
		"e2b without a key file":    `{"providers":[{"provider":"e2b"}]}`,
		"e2b with daytona settings": `{"providers":[{"provider":"e2b","key_file":"/k","base_url":"https://x"}]}`,
		"daytona without a url":     `{"providers":[{"provider":"daytona","key_file":"/k"}]}`,
		"opensandbox with e2b":      `{"providers":[{"provider":"opensandbox","key_file":"/k","base_url":"https://x","template_id":"t"}]}`,
		"claude without agents":     `{"providers":[{"provider":"claude-managed-agents","key_file":"/k"}]}`,
		"a key in the file":         `{"providers":[{"provider":"e2b","key_file":"/k","api_key":"sk-live"}]}`,
		"oversized":                 `{"providers":[{"provider":"docker","docker_bin":"` + strings.Repeat("a", MaxConfigBytes) + `"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseConfig([]byte(raw))
			assert.Error(t, err)
		})
	}
}
