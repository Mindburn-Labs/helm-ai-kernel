package pgscram

// quantum_posture: exercises the classical SCRAM-SHA-256 exchange; no
// post-quantum claim.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"

	"github.com/lib/pq/scram"
)

// serverExchange plays PostgreSQL's side of a SCRAM-SHA-256 login from the
// stored verifier alone, against lib/pq's client (the gateway's own driver),
// and reports whether the client's proof verifies.
func serverExchange(t *testing.T, verifier, password string) bool {
	t.Helper()
	parts := strings.Split(strings.TrimPrefix(verifier, "SCRAM-SHA-256$"), "$")
	iterSalt := strings.SplitN(parts[0], ":", 2)
	keys := strings.SplitN(parts[1], ":", 2)
	storedKey, err := base64.StdEncoding.DecodeString(keys[0])
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := base64.StdEncoding.DecodeString(keys[1])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strconv.Atoi(iterSalt[0]); err != nil {
		t.Fatal(err)
	}

	client := scram.NewClient(sha256.New, "", password)
	client.Step(nil)
	clientFirst := string(client.Out())
	clientFirstBare := strings.TrimPrefix(clientFirst, "n,,")
	clientNonce := strings.TrimPrefix(clientFirstBare[strings.Index(clientFirstBare, "r="):], "r=")
	serverFirst := "r=" + clientNonce + "servernonce,s=" + iterSalt[1] + ",i=" + iterSalt[0]
	// Step reports false while the exchange continues without error.
	if client.Step([]byte(serverFirst)) || client.Err() != nil {
		t.Fatalf("client refused the server-first message: %v", client.Err())
	}
	clientFinal := string(client.Out())
	proofAt := strings.LastIndex(clientFinal, ",p=")
	proof, err := base64.StdEncoding.DecodeString(clientFinal[proofAt+3:])
	if err != nil {
		t.Fatal(err)
	}
	authMessage := clientFirstBare + "," + serverFirst + "," + clientFinal[:proofAt]
	clientSignature := mac(storedKey, authMessage)
	clientKey := make([]byte, len(proof))
	for i := range proof {
		clientKey[i] = proof[i] ^ clientSignature[i]
	}
	recomputed := sha256.Sum256(clientKey)
	if !hmac.Equal(recomputed[:], storedKey) {
		return false
	}
	// The client checks the server signature in turn.
	serverFinal := "v=" + base64.StdEncoding.EncodeToString(mac(serverKey, authMessage))
	if !client.Step([]byte(serverFinal)) || client.Err() != nil {
		t.Fatalf("client refused the server signature: %v", client.Err())
	}
	return true
}

func TestVerifierAuthenticatesItsPasswordOnly(t *testing.T) {
	password := "Gateway-probe_" + strings.Repeat("x9", 8) + " ~!"
	verifier, err := New(password)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(verifier, "SCRAM-SHA-256$4096:") || strings.Contains(verifier, password) {
		t.Fatalf("verifier %q is not a PostgreSQL SCRAM-SHA-256 verifier", verifier)
	}
	if !serverExchange(t, verifier, password) {
		t.Fatal("the verifier does not authenticate its own password")
	}
	if serverExchange(t, verifier, password+"x") {
		t.Fatal("the verifier authenticates a different password")
	}
}

func TestVerifierIsSaltedAndDeterministicPerSalt(t *testing.T) {
	a, err := New("same-password")
	if err != nil {
		t.Fatal(err)
	}
	b, err := New("same-password")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two verifiers of one password share a salt")
	}
	salt := bytes.Repeat([]byte{7}, SaltLen)
	c, _ := Verifier("same-password", salt, Iterations)
	d, _ := Verifier("same-password", salt, Iterations)
	if c != d {
		t.Fatal("a fixed salt gave two verifiers")
	}
}

func TestVerifierRefusesWhatSASLprepWouldChange(t *testing.T) {
	for _, password := range []string{"", "tab\there", "newline\n", "café", strings.Repeat("a", MaxPasswordLen+1)} {
		if _, err := New(password); err == nil {
			t.Fatalf("New(%q) accepted a password it cannot derive exactly", password)
		}
	}
}
