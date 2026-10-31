// quantum_posture: test-only classical verifier oracle; no signing material.
// Explicitly run by the WASM test driver; testdata is not a shipped command.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
)

func main() {
	if len(os.Args) != 2 {
		panic("usage: native_corpus corpus.json")
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var corpus struct {
		Documents  map[string]string `json:"documents"`
		TrustRoots map[string]string `json:"trust_roots"`
		Cases      []struct {
			Name, Document string
			TrustRoot      string `json:"trust_root"`
			Expected       receiptverify.Verdict
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		panic(err)
	}
	if len(corpus.Cases) == 0 {
		panic("empty corpus")
	}
	results := make(map[string]receiptverify.DocumentResult)
	for _, c := range corpus.Cases {
		doc, ok := corpus.Documents[c.Document]
		if !ok {
			panic("missing document")
		}
		root, ok := corpus.TrustRoots[c.TrustRoot]
		if !ok {
			panic("missing trust input")
		}
		result := receiptverify.VerifyJSON([]byte(doc), []byte(root))
		if result.Verdict != c.Expected {
			panic(fmt.Sprintf("%s: got %s, want %s", c.Name, result.Verdict, c.Expected))
		}
		results[c.Name] = result
	}
	if err := json.NewEncoder(os.Stdout).Encode(results); err != nil {
		panic(err)
	}
}
