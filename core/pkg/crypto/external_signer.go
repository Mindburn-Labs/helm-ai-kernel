package crypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// ExternalSignRequest is sent to a command-backed signer on stdin.
type ExternalSignRequest struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id,omitempty"`
	Payload   string `json:"payload"`
}

// ExternalSignResponse is read from a command-backed signer on stdout.
type ExternalSignResponse struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

// CommandSigner delegates signing to an external command. Private key material
// never enters the HELM process.
type CommandSigner struct {
	Command   string
	KeyID     string
	Algorithm string
}

func (s CommandSigner) Sign(ctx context.Context, payload []byte) (ExternalSignResponse, error) {
	if strings.TrimSpace(s.Command) == "" {
		return ExternalSignResponse{}, fmt.Errorf("external signer command is required")
	}
	algorithm := strings.TrimSpace(s.Algorithm)
	if algorithm == "" {
		algorithm = "ed25519"
	}
	req := ExternalSignRequest{
		Algorithm: algorithm,
		KeyID:     strings.TrimSpace(s.KeyID),
		Payload:   base64.StdEncoding.EncodeToString(payload),
	}
	in, err := json.Marshal(req)
	if err != nil {
		return ExternalSignResponse{}, err
	}

	cmd := exec.CommandContext(ctx, "sh", "-c", s.Command)
	cmd.Stdin = bytes.NewReader(append(in, '\n'))
	out, err := cmd.Output()
	if err != nil {
		return ExternalSignResponse{}, fmt.Errorf("external signer command failed: %w", err)
	}

	var resp ExternalSignResponse
	if err := json.Unmarshal(bytes.TrimSpace(out), &resp); err != nil {
		return ExternalSignResponse{}, fmt.Errorf("parse external signer response: %w", err)
	}
	if resp.Algorithm == "" {
		resp.Algorithm = algorithm
	}
	if resp.KeyID == "" {
		resp.KeyID = req.KeyID
	}
	if resp.KeyID == "" {
		return ExternalSignResponse{}, fmt.Errorf("external signer response key_id is required")
	}
	if resp.Signature == "" {
		return ExternalSignResponse{}, fmt.Errorf("external signer response signature is required")
	}
	if _, err := DecodeSignature(resp.Signature); err != nil {
		return ExternalSignResponse{}, err
	}
	return resp, nil
}

// DecodeSignature accepts hex first, then base64. External signer responses
// should prefer hex for human auditability.
func DecodeSignature(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("signature is required")
	}
	if decoded, err := hex.DecodeString(value); err == nil {
		return decoded, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("signature must be hex or base64: %w", err)
	}
	return decoded, nil
}
