package siwc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"unicode"
)

// Catalogs include sizeable provider instructions that we intentionally discard.
// Keep their bound separate from the smaller OAuth credential responses.
const maxModelCatalogBytes = 2 << 20

// Model is provider catalog metadata, not a grant to use that model. The
// model gateway must still intersect the selection with the seat's mandate.
type Model struct {
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
}

// Models reads the selected local account's current catalog. It makes no
// inference call and never falls back to a bundled catalog or another account.
// HTTP consumers must resolve CP Connection ownership before calling it.
func (s *Store) Models(ctx context.Context, c *Client, ref Reference) ([]Model, error) {
	token, err := s.AccessToken(ctx, c, ref)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.modelsURL, nil)
	if err != nil {
		return nil, ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	response, err := c.http.Do(req)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer func() { _ = response.Body.Close() }()
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return nil, ErrReauthorize
	case http.StatusForbidden:
		return nil, ErrPermission
	default:
		return nil, ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxModelCatalogBytes+1))
	if err != nil || len(body) > maxModelCatalogBytes {
		return nil, ErrUnavailable
	}
	var catalog struct {
		Models []struct {
			Model
			Visibility string `json:"visibility"`
		} `json:"models"`
	}
	if json.Unmarshal(body, &catalog) != nil || catalog.Models == nil || len(catalog.Models) > 256 {
		return nil, ErrUnavailable
	}
	models := make([]Model, 0, len(catalog.Models))
	seen := make(map[string]bool)
	for _, model := range catalog.Models {
		if model.Visibility != "list" {
			continue
		}
		if !catalogText(model.Slug, 255) || strings.ContainsAny(model.Slug, " \t\r\n") ||
			!catalogText(model.DisplayName, 256) || seen[model.Slug] {
			return nil, ErrUnavailable
		}
		seen[model.Slug] = true
		models = append(models, model.Model)
	}
	// A logout or account switch while the catalog was in flight invalidates
	// this result. Do not show the previous registration's choices afterwards.
	unlock, err := s.lock(ctx, ref.ID)
	if err != nil {
		return nil, err
	}
	defer unlock()
	current, err := s.load(ref.ID)
	if err != nil {
		return nil, err
	}
	if current.Generation != ref.Generation || current.HostID != ref.HostID || !current.SignedIn || !current.PlanUse {
		return nil, ErrChanged
	}
	return models, nil
}

func catalogText(value string, limit int) bool {
	return value != "" && len(value) <= limit && strings.TrimSpace(value) == value &&
		strings.IndexFunc(value, unicode.IsControl) == -1
}
