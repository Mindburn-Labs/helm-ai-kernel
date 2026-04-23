package conform

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProfiles_AllDefined(t *testing.T) {
	p := Profiles()
	require.NotEmpty(t, p)
	require.Contains(t, p, ProfileSMB)
	require.Contains(t, p, ProfileCore)
	require.Contains(t, p, ProfileEnterprise)
	require.Contains(t, p, ProfileRegulatedFinance)
	require.Contains(t, p, ProfileRegulatedHealth)
	require.Contains(t, p, ProfileAgenticWebRouter)
}

func TestProfiles_SMBProfile(t *testing.T) {
	gates := GatesForProfile(ProfileSMB)
	require.NotNil(t, gates)
	require.Contains(t, gates, "G0")
	require.Contains(t, gates, "G1")
	require.Contains(t, gates, "GX_ENVELOPE")
	// SMB does not require GX_TENANT
	for _, g := range gates {
		require.NotEqual(t, "GX_TENANT", g, "SMB should not require GX_TENANT")
	}
}

func TestProfiles_CoreGates(t *testing.T) {
	gates := GatesForProfile(ProfileCore)
	require.NotNil(t, gates)
	require.Contains(t, gates, "G0")
	require.Contains(t, gates, "G1")
	require.Contains(t, gates, "G2")
	require.Contains(t, gates, "G3")
	require.Contains(t, gates, "GX_ENVELOPE")
}

func TestProfiles_EnterpriseInheritsCore(t *testing.T) {
	p := Profiles()
	enterprise := p[ProfileEnterprise]
	require.NotNil(t, enterprise)
	require.Equal(t, ProfileCore, enterprise.Inherits)
	require.Contains(t, enterprise.RequiredGates, "GX_TENANT")
	require.Contains(t, enterprise.RequiredGates, "GX_ENVELOPE")
	require.Contains(t, enterprise.RequiredGates, "G4")
	require.Contains(t, enterprise.RequiredGates, "G9")
}

func TestProfiles_UnknownProfile(t *testing.T) {
	gates := GatesForProfile("NONEXISTENT")
	require.Nil(t, gates)
}

func TestProfiles_ComplianceIsProfileScoped(t *testing.T) {
	// SMB has fewer gates than CORE
	smb := GatesForProfile(ProfileSMB)
	core := GatesForProfile(ProfileCore)
	require.Less(t, len(smb), len(core), "SMB should have fewer gates than CORE")
}
