package modelgw

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/server"
)

// models answers GET /v1/models: the routes the caller's mandates let it use,
// each by the model id a request can name. One document serves both SDKs: the
// OpenAI shape ({"object": "list", "data": [{"id", "object", "created",
// "owned_by"}]}) and Anthropic's ({"data": [{"type": "model", "id",
// "display_name", "created_at"}], "has_more", "first_id", "last_id"}) share no
// field names, and both SDKs ignore fields they do not know.
func (h *handler) models(w http.ResponseWriter, r *http.Request) {
	api := effectargs.APIOpenAIChat
	if r.Header.Get("Anthropic-Version") != "" || r.Header.Get("X-Api-Key") != "" {
		api = effectargs.APIAnthropicMessages
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeAPIError(w, api, refuse(http.StatusMethodNotAllowed, kindInvalidRequest, "method_not_allowed", "use GET"))
		return
	}
	id, aerr := h.authenticate(r, api, server.ScopePropose, server.ScopeRead)
	if aerr != nil {
		writeAPIError(w, api, aerr)
		return
	}
	grants, err := h.g.Ledger.ModelGrants(r.Context(), callerOf(id), effectargs.ModelInference)
	if err != nil {
		writeAPIError(w, api, h.ledgerError(r.Context(), "grants", err, ""))
		return
	}
	if aerr := h.checkPrincipal(grants); aerr != nil {
		writeAPIError(w, api, aerr)
		return
	}
	seen := map[string]bool{}
	var ids []string
	for _, route := range h.g.Config.Routes() {
		if !grants.Allows(route.ID) {
			continue
		}
		for _, name := range []string{route.Model, route.ID} {
			if !seen[name] {
				seen[name] = true
				ids = append(ids, name)
			}
		}
	}
	sort.Strings(ids)
	type entry struct {
		ID          string `json:"id"`
		Object      string `json:"object"`
		Created     int64  `json:"created"`
		OwnedBy     string `json:"owned_by"`
		Type        string `json:"type"`
		DisplayName string `json:"display_name"`
		CreatedAt   string `json:"created_at"`
	}
	data := make([]entry, 0, len(ids))
	epoch := time.Unix(0, 0).UTC().Format(time.RFC3339)
	for _, id := range ids {
		data = append(data, entry{ID: id, Object: "model", OwnedBy: "helm", Type: "model", DisplayName: id, CreatedAt: epoch})
	}
	doc := map[string]any{"object": "list", "data": data, "has_more": false, "first_id": nil, "last_id": nil}
	if len(ids) > 0 {
		doc["first_id"], doc["last_id"] = ids[0], ids[len(ids)-1]
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(doc)
}
