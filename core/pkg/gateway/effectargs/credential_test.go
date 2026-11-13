package effectargs

// Passkeys of human principals (helm-tracker#334): what the gateway accepts as
// a credential it can verify with, and the optional credentials member of a
// provision plan's principal.
//
// quantum_posture: generates classical P-256, P-384 and Ed25519 test keys; no
// post-quantum claim.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func spki(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestCheckCredentialAcceptsOnlyKeysTheGatewayVerifies(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	es := Credential{ID: []byte{1, 2}, Alg: AlgES256, PublicKeySPKI: spki(t, &p256.PublicKey), RPID: "app.example.com"}
	ed := Credential{ID: []byte{3}, Alg: AlgEdDSA, PublicKeySPKI: spki(t, edPub), RPID: "localhost"}
	for _, ok := range []Credential{es, ed} {
		if err := CheckCredential(ok); err != nil {
			t.Errorf("%d: %v", ok.Alg, err)
		}
	}
	for name, bad := range map[string]func(Credential) Credential{
		"no id":                   func(c Credential) Credential { c.ID = nil; return c },
		"a long id":               func(c Credential) Credential { c.ID = make([]byte, MaxCredentialIDBytes+1); return c },
		"another algorithm":       func(c Credential) Credential { c.Alg = -257; return c },
		"an Ed25519 key as ES256": func(c Credential) Credential { c.PublicKeySPKI = spki(t, edPub); return c },
		"a P-384 key":             func(c Credential) Credential { c.PublicKeySPKI = spki(t, &p384.PublicKey); return c },
		"a key that is not DER":   func(c Credential) Credential { c.PublicKeySPKI = []byte("not der"); return c },
		"no relying party":        func(c Credential) Credential { c.RPID = ""; return c },
		"an upper-case rp_id":     func(c Credential) Credential { c.RPID = "App.Example.com"; return c },
		"an origin as rp_id":      func(c Credential) Credential { c.RPID = "https://app.example.com"; return c },
	} {
		if err := CheckCredential(bad(es)); err == nil {
			t.Errorf("%s passed", name)
		}
	}
	if err := CheckCredential(Credential{ID: []byte{1}, Alg: AlgEdDSA, PublicKeySPKI: spki(t, &p256.PublicKey), RPID: "x.example"}); err == nil {
		t.Error("a P-256 key as EdDSA passed")
	}
}

func TestPlanCredentialsAreAHumansPasskeys(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cred := map[string]any{"credential_id": base64.RawURLEncoding.EncodeToString([]byte("cred-1")), "alg": -7,
		"public_key_spki": base64.RawURLEncoding.EncodeToString(spki(t, &p256.PublicKey)), "rp_id": "app.example.com"}
	plan := func(schema string, principal map[string]any) []byte {
		doc := map[string]any{"schema": schema, "org_ref": "org:acme", "version_ref": "v1", "stage": "constrained-live",
			"base_plan_digest": "", "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2026-01-02T00:00:00Z",
			"effect_types": []any{map[string]any{"effect_type": "ops.read", "risk_class": "low"}},
			"principals":   []any{map[string]any{"id": "org:acme", "kind": "service"}, principal},
			"mandates": []any{map[string]any{"node": "org:acme", "holder": "org:acme", "parent": nil,
				"terms": map[string]any{"effect_types": []string{"ops.read"}, "targets": nil}}}}
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	human := func(creds ...any) map[string]any {
		return map[string]any{"id": "usr_r", "kind": "human", "external_subject": map[string]any{"system": "helm-control-plane", "id": "usr_r"}, "credentials": creds}
	}
	p, err := ParsePlan(AuthorityProvision, plan(AuthorityProvision, human(cred)))
	if err != nil || len(p.Principals[1].Credentials) != 1 || string(p.Principals[1].Credentials[0].ID) != "cred-1" || p.Principals[1].Credentials[0].Alg != AlgES256 {
		t.Fatalf("plan = %+v, %v", p, err)
	}
	with := func(key string, v any) map[string]any {
		c := map[string]any{}
		for k, x := range cred {
			c[k] = x
		}
		c[key] = v
		return c
	}
	for name, raw := range map[string][]byte{
		"a narrowing plan":       plan(AuthorityNarrow, human(cred)),
		"a service":              plan(AuthorityProvision, map[string]any{"id": "svc:x", "kind": "service", "credentials": []any{cred}}),
		"no credential":          plan(AuthorityProvision, human()),
		"a credential id twice":  plan(AuthorityProvision, human(cred, cred)),
		"padded base64":          plan(AuthorityProvision, human(with("credential_id", base64.URLEncoding.EncodeToString([]byte("c"))))),
		"another algorithm":      plan(AuthorityProvision, human(with("alg", -257))),
		"an algorithm as a text": plan(AuthorityProvision, human(with("alg", "-7"))),
		"an unknown member":      plan(AuthorityProvision, human(with("transports", "usb"))),
		"a bad key":              plan(AuthorityProvision, human(with("public_key_spki", "AAAA"))),
	} {
		schema := AuthorityProvision
		if name == "a narrowing plan" {
			schema = AuthorityNarrow
		}
		if _, err := ParsePlan(schema, raw); err == nil {
			t.Errorf("%s parsed", name)
		}
	}
}
