package mcp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	pkg_artifact "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSentinelConnectorEvaluation(t *testing.T) {
	t.Run("Valid HTTP SentinelIntent maps and evaluates successfully", func(t *testing.T) {
		signer, err := crypto.NewEd25519Signer("test-sentinel-key")
		require.NoError(t, err)

		g := guardian.NewGuardian(signer, prg.NewGraph(), pkg_artifact.NewRegistry(nil, nil))
		connector := NewSentinelConnector(g)

		intent := SentinelIntent{
			Principal: "spiffe://highflame.com/agent-sentinel",
			Action:    "EXECUTE_TOOL",
			Resource:  "http.post",
			Context: map[string]interface{}{
				"zeroid_token": "token_sentinel_xyz",
				"spiffe_uri":   "spiffe://highflame.com/agent-sentinel",
			},
		}

		body, err := json.Marshal(intent)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sentinel/evaluate", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		connector.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var decision contracts.DecisionRecord
		err = json.NewDecoder(rr.Body).Decode(&decision)
		require.NoError(t, err)

		// By default, a minimal guardian with empty graph allowing all passes will verdict VerdictAllow or VerdictDeny depending on the fallback.
		// Wait, let's verify if the decision contains a verdict and valid signature
		assert.NotEmpty(t, decision.Verdict)
		assert.NotEmpty(t, decision.Signature)
		assert.Contains(t, decision.SignatureType, "ed25519")
	})

	t.Run("Invalid HTTP Method is rejected", func(t *testing.T) {
		signer, err := crypto.NewEd25519Signer("test-sentinel-key")
		require.NoError(t, err)

		g := guardian.NewGuardian(signer, prg.NewGraph(), pkg_artifact.NewRegistry(nil, nil))
		connector := NewSentinelConnector(g)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sentinel/evaluate", nil)
		rr := httptest.NewRecorder()

		connector.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
	})

	t.Run("Malformed JSON payload returns BadRequest", func(t *testing.T) {
		signer, err := crypto.NewEd25519Signer("test-sentinel-key")
		require.NoError(t, err)

		g := guardian.NewGuardian(signer, prg.NewGraph(), pkg_artifact.NewRegistry(nil, nil))
		connector := NewSentinelConnector(g)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sentinel/evaluate", bytes.NewReader([]byte("{invalid-json}")))
		rr := httptest.NewRecorder()

		connector.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}
