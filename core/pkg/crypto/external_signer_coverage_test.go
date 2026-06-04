package crypto

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

func TestCommandSignerCoversSuccessDefaultsAndErrors(t *testing.T) {
	ctx := context.Background()
	resp, err := CommandSigner{
		Command: "printf '{\"signature\":\"0a0b\"}'",
		KeyID:   "request-key",
	}.Sign(ctx, []byte("payload"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if resp.Algorithm != "ed25519" || resp.KeyID != "request-key" || resp.Signature != "0a0b" {
		t.Fatalf("response defaults not applied: %+v", resp)
	}

	resp, err = CommandSigner{
		Command:   "printf '{\"algorithm\":\"mldsa65\",\"key_id\":\"response-key\",\"signature\":\"Cg==\"}'",
		Algorithm: "mldsa65",
	}.Sign(ctx, []byte("payload"))
	if err != nil {
		t.Fatalf("base64 Sign: %v", err)
	}
	if resp.Algorithm != "mldsa65" || resp.KeyID != "response-key" {
		t.Fatalf("explicit response fields not preserved: %+v", resp)
	}

	for name, tc := range map[string]struct {
		signer CommandSigner
		want   string
	}{
		"missing command": {
			signer: CommandSigner{},
			want:   "command is required",
		},
		"command failure": {
			signer: CommandSigner{Command: "exit 7", KeyID: "key"},
			want:   "command failed",
		},
		"invalid json": {
			signer: CommandSigner{Command: "printf not-json", KeyID: "key"},
			want:   "parse external signer response",
		},
		"missing key": {
			signer: CommandSigner{Command: "printf '{\"signature\":\"0a\"}'"},
			want:   "key_id is required",
		},
		"missing signature": {
			signer: CommandSigner{Command: "printf '{\"key_id\":\"key\"}'"},
			want:   "signature is required",
		},
		"bad signature": {
			signer: CommandSigner{Command: "printf '{\"key_id\":\"key\",\"signature\":\"not-valid\"}'"},
			want:   "signature must be hex or base64",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := tc.signer.Sign(ctx, []byte("payload")); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Sign error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestDecodeSignatureAcceptsHexAndBase64(t *testing.T) {
	hexSig, err := DecodeSignature(" 0a0b ")
	if err != nil {
		t.Fatalf("hex DecodeSignature: %v", err)
	}
	if len(hexSig) != 2 || hexSig[0] != 0x0a || hexSig[1] != 0x0b {
		t.Fatalf("hex decoded bytes = %x", hexSig)
	}
	base64Sig, err := DecodeSignature(base64.StdEncoding.EncodeToString([]byte("sig")))
	if err != nil {
		t.Fatalf("base64 DecodeSignature: %v", err)
	}
	if string(base64Sig) != "sig" {
		t.Fatalf("base64 decoded bytes = %q", base64Sig)
	}
	if _, err := DecodeSignature(""); err == nil || !strings.Contains(err.Error(), "signature is required") {
		t.Fatalf("empty signature error = %v", err)
	}
	if _, err := DecodeSignature("not-valid"); err == nil || !strings.Contains(err.Error(), "signature must be hex or base64") {
		t.Fatalf("invalid signature error = %v", err)
	}
}
