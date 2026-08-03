// Command semantic-model-gen builds the deterministic quantized subword model
// embedded by core/pkg/threatscan. The artifact contains no executable code.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

const dimensions = 6

type lexeme struct {
	Token  string
	Vector [dimensions]int
}

type model struct {
	Version     string            `json:"version"`
	Dimensions  int               `json:"dimensions"`
	ThresholdBP int               `json:"threshold_bp"`
	MaxTokens   int               `json:"max_tokens"`
	Embeddings  map[string][]int8 `json:"embeddings"`
	Centroids   []centroid        `json:"centroids"`
}

type centroid struct {
	Class  string `json:"class"`
	Vector []int8 `json:"vector"`
}

var lexicon = []lexeme{
	// Instruction and authority override.
	{"ignore", [dimensions]int{110, 10, 20, 25, 20, 0}},
	{"disregard", [dimensions]int{115, 10, 15, 20, 20, 0}},
	{"forget", [dimensions]int{100, 15, 10, 15, 15, 0}},
	{"override", [dimensions]int{115, 20, 20, 35, 25, 0}},
	{"abandon", [dimensions]int{100, 15, 15, 20, 20, 0}},
	{"aside", [dimensions]int{85, 15, 10, 15, 10, 0}},
	{"leave", [dimensions]int{80, 10, 10, 15, 10, 0}},
	{"behind", [dimensions]int{70, 10, 10, 15, 10, 0}},
	{"put", [dimensions]int{55, 10, 10, 10, 5, 0}},
	{"previous", [dimensions]int{75, 10, 5, 10, 5, 0}},
	{"prior", [dimensions]int{70, 10, 5, 10, 5, 0}},
	{"initial", [dimensions]int{65, 10, 5, 10, 5, 0}},
	{"outset", [dimensions]int{70, 10, 5, 10, 5, 0}},
	{"original", [dimensions]int{65, 10, 5, 10, 5, 0}},
	{"earlier", [dimensions]int{65, 10, 5, 10, 5, 0}},
	{"started", [dimensions]int{55, 10, 5, 10, 5, 0}},
	{"instructions", [dimensions]int{75, 15, 10, 15, 10, 0}},
	{"guidance", [dimensions]int{75, 15, 10, 15, 10, 0}},
	{"directives", [dimensions]int{75, 15, 10, 15, 10, 0}},
	{"directions", [dimensions]int{75, 15, 10, 15, 10, 0}},
	{"rules", [dimensions]int{55, 10, 5, 25, 5, 0}},

	// Objective replacement.
	{"instead", [dimensions]int{15, 100, 20, 15, 15, 0}},
	{"replace", [dimensions]int{25, 100, 20, 15, 15, 0}},
	{"substitute", [dimensions]int{20, 95, 15, 15, 15, 0}},
	{"treat", [dimensions]int{15, 80, 20, 10, 10, 0}},
	{"real", [dimensions]int{10, 70, 10, 10, 5, 0}},
	{"actual", [dimensions]int{10, 70, 10, 10, 5, 0}},
	{"new", [dimensions]int{10, 65, 10, 10, 5, 0}},
	{"objective", [dimensions]int{10, 90, 20, 10, 10, 0}},
	{"goal", [dimensions]int{10, 85, 20, 10, 10, 0}},
	{"mission", [dimensions]int{10, 85, 20, 10, 10, 0}},
	{"priority", [dimensions]int{10, 75, 15, 15, 10, 0}},
	{"message", [dimensions]int{10, 55, 15, 10, 10, 0}},

	// Imperative execution.
	{"proceed", [dimensions]int{10, 25, 105, 25, 20, 0}},
	{"execute", [dimensions]int{10, 20, 110, 25, 25, 0}},
	{"follow", [dimensions]int{10, 30, 95, 15, 15, 0}},
	{"comply", [dimensions]int{10, 25, 100, 20, 20, 0}},
	{"perform", [dimensions]int{10, 20, 90, 15, 15, 0}},
	{"carry", [dimensions]int{10, 20, 85, 15, 15, 0}},
	{"immediately", [dimensions]int{10, 15, 90, 30, 25, 0}},
	{"now", [dimensions]int{5, 25, 75, 20, 10, 0}},

	// Approval and safeguard bypass.
	{"approval", [dimensions]int{15, 10, 20, 110, 25, 0}},
	{"approvals", [dimensions]int{15, 10, 20, 110, 25, 0}},
	{"permission", [dimensions]int{15, 10, 20, 105, 25, 0}},
	{"permissions", [dimensions]int{15, 10, 20, 105, 25, 0}},
	{"authorization", [dimensions]int{15, 10, 20, 105, 25, 0}},
	{"authorize", [dimensions]int{15, 10, 20, 100, 25, 0}},
	{"review", [dimensions]int{10, 5, 10, 85, 10, 0}},
	{"oversight", [dimensions]int{10, 5, 10, 95, 20, 0}},
	{"safeguards", [dimensions]int{20, 5, 10, 105, 30, 0}},
	{"restrictions", [dimensions]int{20, 5, 10, 100, 25, 0}},
	{"without", [dimensions]int{15, 10, 20, 80, 15, 0}},
	{"skip", [dimensions]int{20, 10, 35, 95, 20, 0}},
	{"bypass", [dimensions]int{25, 10, 30, 115, 35, 0}},
	{"usual", [dimensions]int{10, 10, 10, 60, 5, 0}},

	// Explicit hostile framing.
	{"jailbreak", [dimensions]int{40, 25, 35, 90, 120, 0}},
	{"secretly", [dimensions]int{15, 10, 30, 65, 95, 0}},
	{"hidden", [dimensions]int{15, 10, 20, 45, 80, 0}},

	// Benign security-discussion framing. This dimension points away from the
	// threat centroid and bounds common documentation/test false positives.
	{"scanner", [dimensions]int{0, 0, 0, 0, 0, 120}},
	{"detector", [dimensions]int{0, 0, 0, 0, 0, 115}},
	{"detect", [dimensions]int{0, 0, 0, 0, 0, 100}},
	{"detection", [dimensions]int{0, 0, 0, 0, 0, 110}},
	{"example", [dimensions]int{0, 0, 0, 0, 0, 95}},
	{"examples", [dimensions]int{0, 0, 0, 0, 0, 95}},
	{"document", [dimensions]int{0, 0, 0, 0, 0, 105}},
	{"documentation", [dimensions]int{0, 0, 0, 0, 0, 110}},
	{"describe", [dimensions]int{0, 0, 0, 0, 0, 95}},
	{"discuss", [dimensions]int{0, 0, 0, 0, 0, 100}},
	{"attackers", [dimensions]int{0, 0, 0, 0, 0, 105}},
	{"quoted", [dimensions]int{0, 0, 0, 0, 0, 100}},
	{"fixture", [dimensions]int{0, 0, 0, 0, 0, 105}},
	{"test", [dimensions]int{0, 0, 0, 0, 0, 80}},
	{"after", [dimensions]int{0, 0, 0, 0, 0, 95}},
	{"before", [dimensions]int{0, 0, 0, 0, 0, 85}},
	{"only", [dimensions]int{0, 0, 0, 0, 0, 90}},
	{"wait", [dimensions]int{0, 0, 0, 0, 0, 100}},
	{"pause", [dimensions]int{0, 0, 0, 0, 0, 95}},
	{"established", [dimensions]int{0, 0, 0, 0, 0, 110}},
	{"request", [dimensions]int{0, 0, 0, 0, 0, 80}},
	{"reviewer", [dimensions]int{0, 0, 0, 0, 0, 100}},
	{"approved", [dimensions]int{0, 0, 0, 0, 0, 110}},
	{"obtain", [dimensions]int{0, 0, 0, 0, 0, 100}},
	{"remain", [dimensions]int{0, 0, 0, 0, 0, 100}},
	{"authoritative", [dimensions]int{0, 0, 0, 0, 0, 115}},
	{"until", [dimensions]int{0, 0, 0, 0, 0, 100}},
	{"active", [dimensions]int{0, 0, 0, 0, 0, 90}},
	{"must", [dimensions]int{0, 0, 0, 0, 0, 75}},
	{"cannot", [dimensions]int{0, 0, 0, 0, 0, 100}},
	{"confirmed", [dimensions]int{0, 0, 0, 0, 0, 105}},
	{"succeeds", [dimensions]int{0, 0, 0, 0, 0, 100}},
	{"recorded", [dimensions]int{0, 0, 0, 0, 0, 95}},
	{"pending", [dimensions]int{0, 0, 0, 0, 0, 105}},
	{"workflow", [dimensions]int{0, 0, 0, 0, 0, 95}},
	{"process", [dimensions]int{0, 0, 0, 0, 0, 90}},
	{"completes", [dimensions]int{0, 0, 0, 0, 0, 100}},
	{"careful", [dimensions]int{0, 0, 0, 0, 0, 90}},
}

func main() {
	outPath := flag.String("out", "semantic_model.json", "model artifact output")
	hashOutPath := flag.String("hash-out", "semantic_model_hash_generated.go", "Go hash constant output")
	flag.Parse()

	artifact := buildModel()
	encoded, err := json.Marshal(artifact)
	if err != nil {
		fatal(err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(*outPath, encoded, 0o644); err != nil {
		fatal(err)
	}
	sum := sha256.Sum256(encoded)
	hash := "sha256:" + hex.EncodeToString(sum[:])
	hashSource := fmt.Sprintf("// Code generated by semantic-model-gen; DO NOT EDIT.\n\npackage threatscan\n\nconst embeddedSemanticModelHash = %q\n", hash)
	if err := os.WriteFile(*hashOutPath, []byte(hashSource), 0o644); err != nil {
		fatal(err)
	}
}

func buildModel() model {
	accumulated := make(map[string][dimensions]int)
	for _, item := range lexicon {
		accumulate := func(subword string) {
			vector := accumulated[subword]
			for i, value := range item.Vector {
				vector[i] += value
			}
			accumulated[subword] = vector
		}
		token := strings.ToLower(item.Token)
		forEachPrefixSubword(token, accumulate)
		if item.Vector[dimensions-1] == 0 {
			// The OOV fallback recovers perturbed threat lexemes. Benign framing
			// remains prefix-only so common trigrams cannot inject negative noise.
			forEachCharTrigram(token, accumulate)
		}
	}

	keys := make([]string, 0, len(accumulated))
	for key := range accumulated {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	embeddings := make(map[string][]int8, len(keys))
	for _, key := range keys {
		vector := accumulated[key]
		quantized := make([]int8, dimensions)
		for i, value := range vector {
			quantized[i] = clampInt8(value)
		}
		embeddings[key] = quantized
	}

	return model{
		Version:     "helm-semantic-threat-v1",
		Dimensions:  dimensions,
		ThresholdBP: 6400,
		MaxTokens:   256,
		Embeddings:  embeddings,
		Centroids: []centroid{{
			Class:  "PROMPT_INJECTION_PATTERN",
			Vector: []int8{95, 85, 80, 90, 45, -90},
		}},
	}
}

func forEachPrefixSubword(token string, yield func(string)) {
	bounded := []rune("^" + token + "$")
	for size := 5; size <= 8 && size <= len(bounded); size++ {
		yield("p:" + string(bounded[:size]))
	}
}

func forEachCharTrigram(token string, yield func(string)) {
	bounded := []rune("^" + token + "$")
	for start := 0; start+3 <= len(bounded); start++ {
		yield("g:" + string(bounded[start:start+3]))
	}
}

func clampInt8(value int) int8 {
	if value > 127 {
		return 127
	}
	if value < -127 {
		return -127
	}
	return int8(value)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
