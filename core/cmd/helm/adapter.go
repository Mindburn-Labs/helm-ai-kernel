package main

import (
	"context"
	"fmt"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/store"
)

// EmbedderAdapter adapts store.Embedder to llm.Embedder
type EmbedderAdapter struct {
	StoreEmbedder store.Embedder
}

func (a *EmbedderAdapter) Embed(ctx context.Context, text string) ([]float32, error) {
	result, err := a.StoreEmbedder.Embed(ctx, text)
	if err != nil {
		return nil, fmt.Errorf("embed failed: %w", err)
	}
	return result, nil
}
