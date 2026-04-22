package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Embedding represents a vector.
type Embedding []float32

// Embedder interface for getting vectors from text.
type Embedder interface {
	Embed(ctx context.Context, text string) (Embedding, error)
}

// VectorStore interface for storing/searching vectors.
type VectorStore interface {
	Store(ctx context.Context, id string, text string, vector Embedding, metadata map[string]string) error
	Search(ctx context.Context, vector Embedding, limit int) ([]SearchResult, error)
}

type SearchResult struct {
	ID       string
	Text     string
	Score    float32
	Metadata map[string]string
}

// OpenAIEmbedder uses OpenAI API to generate embeddings.
type OpenAIEmbedder struct {
	apiKey string
	client *http.Client
}

func NewOpenAIEmbedder(apiKey string) *OpenAIEmbedder {
	return &OpenAIEmbedder{
		apiKey: apiKey,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (e *OpenAIEmbedder) Embed(ctx context.Context, text string) (Embedding, error) {
	if e.apiKey == "" {
		return nil, errors.New("missing openai api key")
	}

	reqBody := map[string]interface{}{
		"input": text,
		"model": "text-embedding-3-small",
	}
	jsonBody, _ := json.Marshal(reqBody)

	req, _ := http.NewRequestWithContext(ctx, "POST", "https://api.openai.com/v1/embeddings", bytes.NewBuffer(jsonBody))
	req.Header.Set("Authorization", "Bearer "+e.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("openai api error: %d", resp.StatusCode)
	}

	var result struct {
		Data []struct {
			Embedding []float32 `json:"embedding"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if len(result.Data) == 0 {
		return nil, errors.New("no embedding returned")
	}

	return result.Data[0].Embedding, nil
}

// PGVectorStore implementation using pgvector extension.
type PGVectorStore struct {
	db *sql.DB
}

func NewPGVectorStore(db *sql.DB) *PGVectorStore {
	return &PGVectorStore{db: db}
}

func (p *PGVectorStore) Store(ctx context.Context, id string, text string, vector Embedding, metadata map[string]string) error {
	// Requires: CREATE EXTENSION vector; CREATE TABLE items (id text, embedding vector(1536), text, metadata jsonb);
	metaBytes, _ := json.Marshal(metadata)

	// Format vector as string "[1.0, 2.0, ...]" for pgvector
	vecStr := fmt.Sprintf("[%s]", strings.Trim(strings.Join(strings.Fields(fmt.Sprint(vector)), ","), "[]"))
	// Note: fmt.Sprint([]float32) prints "[1 2 3]". strings.Fields splits by space. Join by comma.
	// Actually there is a library for this, but simplistic approach:

	query := `
		INSERT INTO embeddings (id, vector, text, metadata) 
		VALUES ($1, $2::vector, $3, $4)
		ON CONFLICT (id) DO UPDATE SET vector = $2::vector, text = $3, metadata = $4
	`
	_, err := p.db.ExecContext(ctx, query, id, vecStr, text, metaBytes)
	return err
}

func (p *PGVectorStore) Search(ctx context.Context, vector Embedding, limit int) ([]SearchResult, error) {
	// Format vector
	vecStr := fmt.Sprintf("[%s]", strings.Trim(strings.Join(strings.Fields(fmt.Sprint(vector)), ","), "[]"))

	query := `
		SELECT id, text, metadata, 1 - (vector <=> $1::vector) as score 
		FROM embeddings 
		ORDER BY vector <=> $1::vector 
		LIMIT $2
	`
	rows, err := p.db.QueryContext(ctx, query, vecStr, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	//nolint:prealloc // result count unknown from SQL query
	var results []SearchResult
	for rows.Next() {
		var r SearchResult
		var metaBytes []byte
		if err := rows.Scan(&r.ID, &r.Text, &metaBytes, &r.Score); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(metaBytes, &r.Metadata)
		results = append(results, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

// MemoryEmbedder (formerly Mock) for testing.
type MemoryEmbedder struct{}

func (m *MemoryEmbedder) Embed(ctx context.Context, text string) (Embedding, error) {
	return make(Embedding, 1536), nil
}
