package tooling

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validDescriptor() *ToolDescriptor {
	return &ToolDescriptor{
		ToolID: "send-email", Version: "1.0.0", Endpoint: "https://api.example.com/send",
		AuthMethodClass: "oauth2", InputSchemaHash: "in-hash", OutputSchemaHash: "out-hash",
	}
}

func TestValidateSuccess(t *testing.T) {
	assert.NoError(t, validDescriptor().Validate())
}

func TestValidateMissingEndpoint(t *testing.T) {
	d := validDescriptor()
	d.Endpoint = ""
	assert.ErrorContains(t, d.Validate(), "endpoint")
}

func TestValidateMissingInputSchemaHash(t *testing.T) {
	d := validDescriptor()
	d.InputSchemaHash = ""
	assert.ErrorContains(t, d.Validate(), "input_schema_hash")
}

func TestValidateMissingOutputSchemaHash(t *testing.T) {
	d := validDescriptor()
	d.OutputSchemaHash = ""
	assert.ErrorContains(t, d.Validate(), "output_schema_hash")
}

func TestFingerprintLength(t *testing.T) {
	assert.Len(t, validDescriptor().Fingerprint(), 64)
}

func TestFingerprintDeterministic(t *testing.T) {
	d := validDescriptor()
	assert.Equal(t, d.Fingerprint(), d.Fingerprint())
}

func TestFingerprintChangesOnVersionBump(t *testing.T) {
	d1 := validDescriptor()
	d2 := validDescriptor()
	d2.Version = "2.0.0"
	assert.NotEqual(t, d1.Fingerprint(), d2.Fingerprint())
}

func TestHasChangedFalseForIdentical(t *testing.T) {
	assert.False(t, validDescriptor().HasChanged(validDescriptor()))
}

func TestHasChangedTrueForDifferentEndpoint(t *testing.T) {
	d2 := validDescriptor()
	d2.Endpoint = "https://other.example.com"
	assert.True(t, validDescriptor().HasChanged(d2))
}

func TestRegistryRegisterAndGet(t *testing.T) {
	reg := NewToolRegistry()
	require.NoError(t, reg.Register(validDescriptor()))
	tool, ok := reg.Get("send-email")
	assert.True(t, ok)
	assert.Equal(t, "1.0.0", tool.Version)
}

func TestRegistryGetMissing(t *testing.T) {
	_, ok := NewToolRegistry().Get("nonexistent")
	assert.False(t, ok)
}

func TestRegistryRegisterInvalid(t *testing.T) {
	assert.Error(t, NewToolRegistry().Register(&ToolDescriptor{}))
}

func TestRegistryListSorted(t *testing.T) {
	reg := NewToolRegistry()
	for _, id := range []string{"z-tool", "a-tool", "m-tool"} {
		d := validDescriptor()
		d.ToolID = id
		require.NoError(t, reg.Register(d))
	}
	assert.Equal(t, []string{"a-tool", "m-tool", "z-tool"}, reg.List())
}

func TestRegistryGetFingerprint(t *testing.T) {
	reg := NewToolRegistry()
	require.NoError(t, reg.Register(validDescriptor()))
	fp, ok := reg.GetFingerprint("send-email")
	assert.True(t, ok)
	assert.Len(t, fp, 64)
}

func TestRegistryGetFingerprintMissing(t *testing.T) {
	_, ok := NewToolRegistry().GetFingerprint("nope")
	assert.False(t, ok)
}

func TestChangeDetectorFirstCheckNotChanged(t *testing.T) {
	det := NewToolChangeDetector()
	changed, _ := det.CheckForChange(validDescriptor())
	assert.False(t, changed)
}

func TestChangeDetectorDetectsChange(t *testing.T) {
	det := NewToolChangeDetector()
	det.CheckForChange(validDescriptor())
	d2 := validDescriptor()
	d2.Version = "2.0.0"
	changed, msg := det.CheckForChange(d2)
	assert.True(t, changed)
	assert.Contains(t, msg, "send-email")
}

func TestGateExecutionBlocksAfterChange(t *testing.T) {
	det := NewToolChangeDetector()
	det.CheckForChange(validDescriptor())
	d2 := validDescriptor()
	d2.Version = "2.0.0"
	det.CheckForChange(d2)
	err := det.GateExecution(d2)
	require.Error(t, err)
	var ce *ToolChangeError
	assert.True(t, errors.As(err, &ce))
	assert.Equal(t, "send-email", ce.ToolID)
}

func TestGateExecutionAllowsAfterReevaluation(t *testing.T) {
	det := NewToolChangeDetector()
	det.CheckForChange(validDescriptor())
	d2 := validDescriptor()
	d2.Version = "2.0.0"
	det.CheckForChange(d2)
	det.MarkReevaluated(d2)
	assert.NoError(t, det.GateExecution(d2))
}
