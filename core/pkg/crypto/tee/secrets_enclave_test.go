package tee

import (
	"context"
	"strings"
	"testing"
)

func TestSovereignKMSVault_SealAndUnseal(t *testing.T) {
	ctx := context.Background()
	platform := PlatformMock
	measurement := []byte("stabilized_mock_measurement_bytes")

	vault, err := NewSovereignKMSVault(platform, measurement)
	if err != nil {
		t.Fatalf("Failed to initialize vault: %v", err)
	}

	secretPlain := []byte("SovereignSecretsHoldStrong123!")

	// 1. Success case: seal and unseal
	sealed, err := vault.SealSecret(ctx, secretPlain)
	if err != nil {
		t.Fatalf("SealSecret failed: %v", err)
	}

	if sealed.Platform != platform {
		t.Errorf("SealedSecret Platform = %s, want %s", sealed.Platform, platform)
	}

	unsealed, err := vault.UnsealSecret(ctx, sealed)
	if err != nil {
		t.Fatalf("UnsealSecret failed: %v", err)
	}

	if string(unsealed) != string(secretPlain) {
		t.Errorf("Decrypted plain = %q, want %q", string(unsealed), string(secretPlain))
	}

	// 2. Failure case: Platform mismatch
	badPlatformVault, err := NewSovereignKMSVault(PlatformNitro, measurement)
	if err != nil {
		t.Fatalf("Failed to create Nitro vault: %v", err)
	}
	_, err = badPlatformVault.UnsealSecret(ctx, sealed)
	if err == nil {
		t.Error("Expected error unsealing with different TEE platform, got nil")
	}

	// 3. Failure case: Measurement mismatch
	badMeasurement := []byte("completely_different_measurement")
	badMeasurementVault, err := NewSovereignKMSVault(platform, badMeasurement)
	if err != nil {
		t.Fatalf("Failed to create vault with different measurement: %v", err)
	}
	_, err = badMeasurementVault.UnsealSecret(ctx, sealed)
	if err == nil {
		t.Error("Expected error unsealing with unauthorized enclave measurement, got nil")
	}

	// 4. Failure case: Ciphertext tampering
	sealed.Ciphertext[0] ^= 0xFF
	_, err = vault.UnsealSecret(ctx, sealed)
	if err == nil {
		t.Error("Expected error decrypting tampered ciphertext, got nil")
	}
}

func TestSecretProxyFilter_InjectAndScrub(t *testing.T) {
	ctx := context.Background()
	vault, err := NewSovereignKMSVault(PlatformMock, nil)
	if err != nil {
		t.Fatalf("Failed to initialize vault: %v", err)
	}

	apiKeySecret := []byte("x-api-key-sovereign-super-secure")
	sealedAPIKey, err := vault.SealSecret(ctx, apiKeySecret)
	if err != nil {
		t.Fatalf("SealSecret failed: %v", err)
	}

	filter := NewSecretProxyFilter(vault)
	err = filter.RegisterSecret(ctx, "openai_api_key", sealedAPIKey)
	if err != nil {
		t.Fatalf("RegisterSecret failed: %v", err)
	}

	// 1. Verify InjectHeaders
	headers := map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Bearer HELM_SECRET{openai_api_key}",
	}

	injected, err := filter.InjectHeaders(ctx, headers)
	if err != nil {
		t.Fatalf("InjectHeaders failed: %v", err)
	}

	expectedAuth := "Bearer x-api-key-sovereign-super-secure"
	if injected["Authorization"] != expectedAuth {
		t.Errorf("Injected header = %q, want %q", injected["Authorization"], expectedAuth)
	}
	if injected["Content-Type"] != "application/json" {
		t.Errorf("Unrelated header mutated: %q", injected["Content-Type"])
	}

	// 2. Verify FilterLogs (Log Scrubbing)
	rawLog := "2026-05-21T12:00:00Z INFO Dispatching outbound request with Bearer x-api-key-sovereign-super-secure to api.openai.com"
	scrubbedLog := filter.FilterLogs(rawLog)

	if strings.Contains(scrubbedLog, string(apiKeySecret)) {
		t.Errorf("Scrubbed log still contains raw API key: %q", scrubbedLog)
	}

	expectedScrubbedLog := "2026-05-21T12:00:00Z INFO Dispatching outbound request with Bearer [REDACTED_HELM_SECRET{openai_api_key}] to api.openai.com"
	if scrubbedLog != expectedScrubbedLog {
		t.Errorf("Scrubbed log = %q, want %q", scrubbedLog, expectedScrubbedLog)
	}
}

func TestSovereignKMSVault_RandMeasurement(t *testing.T) {
	vault, err := NewSovereignKMSVault(PlatformMock, nil)
	if err != nil {
		t.Fatalf("NewSovereignKMSVault with nil measurement failed: %v", err)
	}
	if len(vault.measurement) != 32 {
		t.Errorf("Expected auto-generated measurement size 32, got %d", len(vault.measurement))
	}
}
