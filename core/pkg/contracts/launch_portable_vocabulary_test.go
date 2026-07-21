// quantum_posture: this test verifies public vocabulary synchronization only;
// it does not exercise or claim cryptographic protection.
package contracts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLaunchPortableCommercialVocabularyMatchesBlueprintSchema(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "protocols", "json-schemas", "effects", "launch", "launch_blueprint.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Definitions struct {
			PortableCurrency struct {
				Enum []string `json:"enum"`
			} `json:"portable_currency"`
			PortableJurisdiction struct {
				Enum []string `json:"enum"`
			} `json:"portable_jurisdiction"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}

	assertLaunchPortableVocabularyMatches(t, "currency", launchPortableCurrencies, document.Definitions.PortableCurrency.Enum)
	assertLaunchPortableVocabularyMatches(t, "jurisdiction", launchPortableJurisdictions, document.Definitions.PortableJurisdiction.Enum)
}

func assertLaunchPortableVocabularyMatches(t *testing.T, name string, runtime map[string]struct{}, schema []string) {
	t.Helper()
	declared := launchPortableTokenSet(strings.Join(schema, " "))
	if len(declared) != len(schema) {
		t.Fatalf("launch portable %s schema contains duplicate tokens", name)
	}
	if len(runtime) != len(declared) {
		t.Fatalf("launch portable %s vocabulary size drifted: runtime=%d schema=%d", name, len(runtime), len(declared))
	}
	for token := range runtime {
		if _, ok := declared[token]; !ok {
			t.Fatalf("launch portable %s token %q exists in runtime but not schema", name, token)
		}
	}
	for token := range declared {
		if _, ok := runtime[token]; !ok {
			t.Fatalf("launch portable %s token %q exists in schema but not runtime", name, token)
		}
	}
}
