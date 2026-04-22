package context

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/store"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/store/ledger"
)

type Assembler struct {
	ledger   ledger.Ledger
	memory   store.VectorStore
	embedder store.Embedder
}

func NewAssembler(ledger ledger.Ledger, mem store.VectorStore, emb store.Embedder) *Assembler {
	return &Assembler{
		ledger:   ledger,
		memory:   mem,
		embedder: emb,
	}
}

// Assemble builds the prompt context for the LLM.
func (a *Assembler) Assemble(ctx context.Context, activeObligationID string) (string, error) {
	var sb strings.Builder

	// 1. System Identity
	sb.WriteString("You are the HELM Kernel, an autonomous operating system.\n")
	sb.WriteString("Your goal is to fulfill obligations safely.\n\n")

	// 2. Active Context
	if activeObligationID != "" {
		obl, err := a.ledger.Get(ctx, activeObligationID)
		if err == nil {
			_, _ = fmt.Fprintf(&sb, "ACTIVE OBLIGATION: %s\n", obl.Intent)

			// RAG: Find relevant past obligations/decisions
			if a.embedder != nil && a.memory != nil {
				vec, embedErr := a.embedder.Embed(ctx, obl.Intent)
				if embedErr != nil {
					slog.Warn("assembler: embedding failed, skipping RAG context",
						"obligation_id", activeObligationID,
						"error", embedErr,
					)
				} else {
					results, searchErr := a.memory.Search(ctx, vec, 3)
					if searchErr != nil {
						slog.Warn("assembler: vector search failed, skipping RAG context",
							"obligation_id", activeObligationID,
							"error", searchErr,
						)
					} else if len(results) > 0 {
						sb.WriteString("\nRELEVANT EXPERIENCE:\n")
						for _, r := range results {
							_, _ = fmt.Fprintf(&sb, "- %s\n", r.Text)
						}
					}
				}
			}

			_, _ = fmt.Fprintf(&sb, "\nID: %s\n", obl.ID)
			_, _ = fmt.Fprintf(&sb, "Status: %s\n\n", obl.State)
		}
	}

	// 3. Global Directives
	sb.WriteString("RULES:\n")
	sb.WriteString("1. Always use Planner for complex tasks.\n")
	sb.WriteString("2. Never hallucinate tools.\n")
	sb.WriteString("3. If unsure, search existing ledger.\n")

	return sb.String(), nil
}
