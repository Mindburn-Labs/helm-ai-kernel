package modelgw

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The routes file that docs/architecture/model-gateway.md shows is one the
// gateway accepts, so the note cannot drift from the parser it describes.
func TestTheDocumentedRoutesFileParses(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "docs", "architecture", "model-gateway.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, after, ok := strings.Cut(string(raw), "```json\n")
	if !ok {
		t.Fatal("the note shows no routes file")
	}
	block, _, ok := strings.Cut(after, "```")
	if !ok {
		t.Fatal("the note's routes file is not closed")
	}
	cfg, err := ParseConfig([]byte(block))
	if err != nil {
		t.Fatalf("the documented routes file does not parse: %v", err)
	}
	if _, ok := cfg.Resolve("anthropic-messages", "claude-sonnet-5-5"); !ok {
		t.Error("the documented route does not resolve by its provider's model id")
	}
	if _, ok := cfg.Resolve("anthropic-messages", "anthropic/claude-sonnet-5-5"); !ok {
		t.Error("the documented route does not resolve by its id")
	}
}
