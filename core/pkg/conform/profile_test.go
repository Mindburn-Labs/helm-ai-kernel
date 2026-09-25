package conform

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// HELM-756: only the release profile remains, and it requires G0 alone.
func TestProfiles_OnlyReleaseProfileRemains(t *testing.T) {
	p := Profiles()
	require.Len(t, p, 1)
	require.Contains(t, p, ProfileSMB)
	require.Equal(t, []string{"G0"}, GatesForProfile(ProfileSMB))
}

func TestProfiles_RetiredProfilesAreUnknown(t *testing.T) {
	for _, id := range []ProfileID{ProfileCore, "ENTERPRISE", "L3", "REGULATED_FINANCE", "REGULATED_HEALTH", "AGENTIC_WEB_ROUTER"} {
		require.Nil(t, GatesForProfile(id), "profile %s must be retired", id)
	}
}

func TestProfiles_UnknownProfile(t *testing.T) {
	require.Nil(t, GatesForProfile("NONEXISTENT"))
}
