//! HELM SDK — Rust client for the HELM kernel API.
//! Minimal deps: reqwest + serde.

use reqwest::{
    blocking::Client,
    header::{HeaderMap, HeaderValue, AUTHORIZATION},
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub mod client;
pub mod canonical;
pub mod types_gen;
pub use types_gen::*;

// ── Proto-generated types (available when compiled with `--features codegen`) ──
#[cfg(feature = "codegen")]
pub mod generated {
    pub mod kernel {
        include!("generated/helm.kernel.v1.rs");
    }
    pub mod authority {
        include!("generated/helm.authority.v1.rs");
    }
    pub mod effects {
        include!("generated/helm.effects.v1.rs");
    }
    pub mod intervention {
        include!("generated/helm.intervention.v1.rs");
    }
    pub mod truth {
        include!("generated/helm.truth.v1.rs");
    }
}

/// Error returned by HELM API calls.
#[derive(Debug)]
pub struct HelmApiError {
    pub status: u16,
    pub message: String,
    pub reason_code: ReasonCode,
}

/// Authenticated scope bound to a governed decision evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluationScope {
    pub tenant_id: String,
    pub principal_id: String,
    pub session_id: String,
    pub workspace_id: Option<String>,
}

impl EvaluationScope {
    pub fn new(
        tenant_id: impl Into<String>,
        principal_id: impl Into<String>,
        session_id: impl Into<String>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            principal_id: principal_id.into(),
            session_id: session_id.into(),
            workspace_id: None,
        }
    }

    pub fn with_workspace_id(mut self, workspace_id: impl Into<String>) -> Self {
        self.workspace_id = Some(workspace_id.into());
        self
    }
}

/// A signed decision and the receipt metadata returned by the evaluator.
#[derive(Clone, Debug)]
pub struct EvaluationResult {
    pub decision: DecisionRecord,
    pub receipt_id: String,
    pub replayed: bool,
}

impl std::fmt::Display for HelmApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HELM API {}: {} ({:?})",
            self.status, self.message, self.reason_code
        )
    }
}

impl std::error::Error for HelmApiError {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvidenceEnvelopeExportRequest {
    pub manifest_id: String,
    pub envelope: String,
    pub native_evidence_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub experimental: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvidenceEnvelopeManifest {
    pub manifest_id: String,
    pub envelope: String,
    pub native_evidence_hash: String,
    pub native_authority: bool,
    pub created_at: String,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub statement_hash: Option<String>,
    #[serde(default)]
    pub payload_type: Option<String>,
    #[serde(default)]
    pub payload_hash: Option<String>,
    #[serde(default)]
    pub experimental: bool,
    #[serde(default)]
    pub manifest_hash: Option<String>,
}

pub type EvidenceEnvelopePayload = serde_json::Value;
pub type ApprovalWebAuthnChallenge = serde_json::Value;
pub type ApprovalWebAuthnAssertion = serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NegativeBoundaryVector {
    pub id: String,
    pub category: String,
    pub trigger: String,
    pub expected_verdict: String,
    pub expected_reason_code: String,
    pub must_emit_receipt: bool,
    pub must_not_dispatch: bool,
    #[serde(default)]
    pub must_bind_evidence: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpRegistryDiscoverRequest {
    pub server_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_names: Vec<String>,
    #[serde(default = "default_mcp_risk")]
    pub risk: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

fn default_mcp_risk() -> String {
    "unknown".to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpRegistryApprovalRequest {
    pub server_id: String,
    pub approver_id: String,
    pub approval_receipt_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpQuarantineRecord {
    pub server_id: String,
    pub risk: String,
    pub state: String,
    pub discovered_at: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub tool_names: Vec<String>,
    #[serde(default)]
    pub approved_at: Option<String>,
    #[serde(default)]
    pub approved_by: Option<String>,
    #[serde(default)]
    pub approval_receipt_id: Option<String>,
    #[serde(default)]
    pub revoked_at: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SandboxBackendProfile {
    pub name: String,
    pub kind: String,
    pub runtime: String,
    pub hosted: bool,
    pub deny_network_by_default: bool,
    pub native_isolation: bool,
    #[serde(default)]
    pub experimental: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SandboxGrant {
    pub grant_id: String,
    pub runtime: String,
    pub profile: String,
    pub env: serde_json::Value,
    pub network: serde_json::Value,
    pub declared_at: String,
    #[serde(default)]
    pub runtime_version: Option<String>,
    #[serde(default)]
    pub image_digest: Option<String>,
    #[serde(default)]
    pub template_digest: Option<String>,
    #[serde(default)]
    pub filesystem_preopens: Vec<serde_json::Value>,
    #[serde(default)]
    pub limits: Option<serde_json::Value>,
    #[serde(default)]
    pub policy_epoch: Option<String>,
    #[serde(default)]
    pub grant_hash: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SandboxGrantInspection {
    Profiles(Vec<SandboxBackendProfile>),
    Grant(SandboxGrant),
}

/// Typed client for the HELM kernel API.
pub struct HelmClient {
    base_url: String,
    client: Client,
    evaluation_client: Client,
    api_key: Option<String>,
    tenant_id: Option<String>,
    principal_id: Option<String>,
    session_id: Option<String>,
    workspace_id: Option<String>,
}

impl HelmClient {
    /// Create a new client.
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: Self::configured_client(None, None, None, None, None),
            // Deliberately has no default identity or workspace headers. The
            // typed evaluator binds its complete scope explicitly per call.
            evaluation_client: Self::configured_client(None, None, None, None, None),
            api_key: None,
            tenant_id: None,
            principal_id: None,
            session_id: None,
            workspace_id: None,
        }
    }

    /// Attach a bearer key for protected runtime routes.
    pub fn with_api_key(mut self, api_key: impl Into<String>) -> Self {
        self.api_key = Some(api_key.into());
        self.rebuild_client();
        self
    }

    /// Attach tenant and principal headers for protected runtime routes.
    pub fn with_identity(
        mut self,
        tenant_id: impl Into<String>,
        principal_id: impl Into<String>,
    ) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self.principal_id = Some(principal_id.into());
        self.rebuild_client();
        self
    }

    /// Attach a session header for governed chat calls.
    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self.rebuild_client();
        self
    }

    /// Attach an optional workspace header for workspace-scoped routes.
    pub fn with_workspace_id(mut self, workspace_id: impl Into<String>) -> Self {
        self.workspace_id = Some(workspace_id.into());
        self.rebuild_client();
        self
    }

    fn configured_client(
        api_key: Option<&str>,
        tenant_id: Option<&str>,
        principal_id: Option<&str>,
        session_id: Option<&str>,
        workspace_id: Option<&str>,
    ) -> Client {
        let mut headers = HeaderMap::new();
        if let Some(api_key) = api_key.filter(|value| !value.trim().is_empty()) {
            if let Ok(value) = HeaderValue::from_str(&format!("Bearer {api_key}")) {
                headers.insert(AUTHORIZATION, value);
            }
        }
        for (name, value) in [
            ("X-Helm-Tenant-ID", tenant_id),
            ("X-Helm-Principal-ID", principal_id),
            ("X-Helm-Session-ID", session_id),
            ("X-Helm-Workspace-ID", workspace_id),
        ] {
            if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
                if let Ok(value) = HeaderValue::from_str(value) {
                    headers.insert(name, value);
                }
            }
        }
        Client::builder()
            .timeout(Duration::from_secs(30))
            .default_headers(headers)
            .build()
            .expect("failed to build HTTP client")
    }

    fn rebuild_client(&mut self) {
        self.client = Self::configured_client(
            self.api_key.as_deref(),
            self.tenant_id.as_deref(),
            self.principal_id.as_deref(),
            self.session_id.as_deref(),
            self.workspace_id.as_deref(),
        );
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn check(
        &self,
        resp: reqwest::blocking::Response,
    ) -> Result<reqwest::blocking::Response, HelmApiError> {
        if resp.status().is_success() {
            return Ok(resp);
        }
        let status = resp.status().as_u16();
        match resp.json::<HelmError>() {
            Ok(e) => Err(HelmApiError {
                status,
                message: e.error.message,
                reason_code: e.error.reason_code,
            }),
            Err(_) => Err(HelmApiError {
                status,
                message: "unknown error".into(),
                reason_code: ReasonCode::ErrorInternal,
            }),
        }
    }

    fn get_value(&self, path: &str) -> Result<serde_json::Value, HelmApiError> {
        let resp = self
            .client
            .get(self.url(path))
            .send()
            .map_err(|e| HelmApiError {
                status: 0,
                message: e.to_string(),
                reason_code: ReasonCode::ErrorInternal,
            })?;
        let resp = self.check(resp)?;
        resp.json().map_err(|e| HelmApiError {
            status: 0,
            message: e.to_string(),
            reason_code: ReasonCode::ErrorInternal,
        })
    }

    fn post_value<T: Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<serde_json::Value, HelmApiError> {
        let resp = self
            .client
            .post(self.url(path))
            .json(body)
            .send()
            .map_err(|e| HelmApiError {
                status: 0,
                message: e.to_string(),
                reason_code: ReasonCode::ErrorInternal,
            })?;
        let resp = self.check(resp)?;
        resp.json().map_err(|e| HelmApiError {
            status: 0,
            message: e.to_string(),
            reason_code: ReasonCode::ErrorInternal,
        })
    }

    fn put_value<T: Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<serde_json::Value, HelmApiError> {
        let resp = self
            .client
            .put(self.url(path))
            .json(body)
            .send()
            .map_err(|e| HelmApiError {
                status: 0,
                message: e.to_string(),
                reason_code: ReasonCode::ErrorInternal,
            })?;
        let resp = self.check(resp)?;
        resp.json().map_err(|e| HelmApiError {
            status: 0,
            message: e.to_string(),
            reason_code: ReasonCode::ErrorInternal,
        })
    }

    pub fn get_boundary_status(&self) -> Result<serde_json::Value, HelmApiError> {
        self.get_value("/api/v1/boundary/status")
    }

    pub fn list_boundary_capabilities(&self) -> Result<serde_json::Value, HelmApiError> {
        self.get_value("/api/v1/boundary/capabilities")
    }

    pub fn list_boundary_records(&self) -> Result<serde_json::Value, HelmApiError> {
        self.get_value("/api/v1/boundary/records")
    }

    pub fn get_boundary_record(&self, record_id: &str) -> Result<serde_json::Value, HelmApiError> {
        self.get_value(&format!(
            "/api/v1/boundary/records/{}",
            encode_query(record_id)
        ))
    }

    pub fn verify_boundary_record(
        &self,
        record_id: &str,
    ) -> Result<serde_json::Value, HelmApiError> {
        self.post_value(
            &format!(
                "/api/v1/boundary/records/{}/verify",
                encode_query(record_id)
            ),
            &serde_json::json!({}),
        )
    }

    pub fn list_boundary_checkpoints(&self) -> Result<serde_json::Value, HelmApiError> {
        self.get_value("/api/v1/boundary/checkpoints")
    }

    pub fn create_boundary_checkpoint(&self) -> Result<serde_json::Value, HelmApiError> {
        self.post_value("/api/v1/boundary/checkpoints", &serde_json::json!({}))
    }

    pub fn verify_boundary_checkpoint(
        &self,
        checkpoint_id: &str,
    ) -> Result<serde_json::Value, HelmApiError> {
        self.post_value(
            &format!(
                "/api/v1/boundary/checkpoints/{}/verify",
                encode_query(checkpoint_id)
            ),
            &serde_json::json!({}),
        )
    }

    /// POST /v1/chat/completions
    pub fn chat_completions(
        &self,
        req: &ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse, HelmApiError> {
        self.validate_chat_scope()?;
        let resp = self
            .client
            .post(self.url("/v1/chat/completions"))
            .json(req)
            .send()
            .map_err(|e| HelmApiError {
                status: 0,
                message: e.to_string(),
                reason_code: ReasonCode::ErrorInternal,
            })?;
        let resp = self.check(resp)?;
        resp.json().map_err(|e| HelmApiError {
            status: 0,
            message: e.to_string(),
            reason_code: ReasonCode::ErrorInternal,
        })
    }

    fn validate_chat_scope(&self) -> Result<(), HelmApiError> {
        let invalid = |message: &str| HelmApiError {
            status: 0,
            message: message.to_string(),
            reason_code: ReasonCode::ErrorInternal,
        };
        if self
            .api_key
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err(invalid("api_key is required for governed chat"));
        }
        if self
            .tenant_id
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err(invalid("tenant_id is required for governed chat"));
        }
        if self
            .principal_id
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err(invalid("principal_id is required for governed chat"));
        }
        if self
            .session_id
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err(invalid("session_id is required for governed chat"));
        }
        Ok(())
    }

    /// Source-compatibility shim for the retired generic evaluator.
    ///
    /// Deprecated: use `evaluate_decision_with_scope` for the public evaluator contract.
    #[deprecated(note = "use evaluate_decision_with_scope for the public evaluator contract")]
    pub fn evaluate_decision<T: Serialize>(
        &self,
        _req: &T,
    ) -> Result<serde_json::Value, HelmApiError> {
        Err(HelmApiError {
            status: 0,
            message: "evaluate_decision is retired; use evaluate_decision_with_scope with EvaluationScope".to_string(),
            reason_code: ReasonCode::ErrorInternal,
        })
    }

    /// POST /api/v1/evaluate using the public authenticated evaluator contract.
    pub fn evaluate_decision_with_scope(
        &self,
        req: &DecisionRequest,
        scope: &EvaluationScope,
        idempotency_key: Option<&str>,
    ) -> Result<EvaluationResult, HelmApiError> {
        self.validate_evaluation_scope(scope)?;
        let mut body = serde_json::Map::new();
        body.insert(
            "action".to_string(),
            serde_json::Value::String(req.action.clone()),
        );
        body.insert(
            "resource".to_string(),
            serde_json::Value::String(req.resource.clone()),
        );
        if let Some(context) = &req.context {
            body.insert(
                "context".to_string(),
                serde_json::to_value(context).map_err(|e| HelmApiError {
                    status: 0,
                    message: e.to_string(),
                    reason_code: ReasonCode::ErrorInternal,
                })?,
            );
        }
        if let Some(session_history) = &req.session_history {
            body.insert(
                "session_history".to_string(),
                serde_json::to_value(session_history).map_err(|e| HelmApiError {
                    status: 0,
                    message: e.to_string(),
                    reason_code: ReasonCode::ErrorInternal,
                })?,
            );
        }

        let api_key = self.api_key.as_deref().expect("validated API key").trim();
        let mut request = self
            .evaluation_client
            .post(self.url("/api/v1/evaluate"))
            .bearer_auth(api_key)
            .header("X-Helm-Tenant-ID", scope.tenant_id.trim())
            .header("X-Helm-Principal-ID", scope.principal_id.trim())
            .header("X-Helm-Session-ID", scope.session_id.trim())
            .json(&body);
        if let Some(workspace_id) = scope
            .workspace_id
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            request = request.header("X-Helm-Workspace-ID", workspace_id.trim());
        }
        if let Some(key) = idempotency_key.filter(|value| !value.trim().is_empty()) {
            request = request.header("Idempotency-Key", key.trim());
        }
        let response = request.send().map_err(|e| HelmApiError {
            status: 0,
            message: e.to_string(),
            reason_code: ReasonCode::ErrorInternal,
        })?;
        let response = self.check(response)?;
        let receipt_id = response
            .headers()
            .get("X-Helm-Receipt-ID")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| HelmApiError {
                status: 0,
                message: "evaluator response missing required X-Helm-Receipt-ID".to_string(),
                reason_code: ReasonCode::ErrorInternal,
            })?
            .to_string();
        let replayed = response
            .headers()
            .get("X-Helm-Idempotency-Replayed")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("true"));
        let decision = response.json().map_err(|e| HelmApiError {
            status: 0,
            message: e.to_string(),
            reason_code: ReasonCode::ErrorInternal,
        })?;
        Ok(EvaluationResult {
            decision,
            receipt_id,
            replayed,
        })
    }

    fn validate_evaluation_scope(&self, scope: &EvaluationScope) -> Result<(), HelmApiError> {
        let invalid = |message: &str| HelmApiError {
            status: 0,
            message: message.to_string(),
            reason_code: ReasonCode::ErrorInternal,
        };
        if self
            .api_key
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err(invalid(
                "api_key is required for scoped decision evaluation",
            ));
        }
        if scope.tenant_id.trim().is_empty() {
            return Err(invalid(
                "tenant_id is required for scoped decision evaluation",
            ));
        }
        if scope.principal_id.trim().is_empty() {
            return Err(invalid(
                "principal_id is required for scoped decision evaluation",
            ));
        }
        if scope.session_id.trim().is_empty() {
            return Err(invalid(
                "session_id is required for scoped decision evaluation",
            ));
        }
        if scope
            .workspace_id
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(invalid("workspace_id must be non-empty when provided"));
        }
        Ok(())
    }

    /// POST /api/v1/kernel/approve
    pub fn approve_intent(&self, req: &ApprovalRequest) -> Result<Receipt, HelmApiError> {
        let resp = self
            .client
            .post(self.url("/api/v1/kernel/approve"))
            .json(req)
            .send()
            .map_err(|e| HelmApiError {
                status: 0,
                message: e.to_string(),
                reason_code: ReasonCode::ErrorInternal,
            })?;
        let resp = self.check(resp)?;
        resp.json().map_err(|e| HelmApiError {
            status: 0,
            message: e.to_string(),
            reason_code: ReasonCode::ErrorInternal,
        })
    }

    /// GET /api/v1/proofgraph/sessions
    pub fn list_sessions(&self) -> Result<Vec<Session>, HelmApiError> {
        let resp = self
            .client
            .get(self.url("/api/v1/proofgraph/sessions"))
            .send()
            .map_err(|e| HelmApiError {
                status: 0,
                message: e.to_string(),
                reason_code: ReasonCode::ErrorInternal,
            })?;
        let resp = self.check(resp)?;
        resp.json().map_err(|e| HelmApiError {
            status: 0,
            message: e.to_string(),
            reason_code: ReasonCode::ErrorInternal,
        })
    }

    /// GET /api/v1/proofgraph/sessions/{id}/receipts
    pub fn get_receipts(&self, session_id: &str) -> Result<Vec<Receipt>, HelmApiError> {
        let resp = self
            .client
            .get(self.url(&format!(
                "/api/v1/proofgraph/sessions/{}/receipts",
                session_id
            )))
            .send()
            .map_err(|e| HelmApiError {
                status: 0,
                message: e.to_string(),
                reason_code: ReasonCode::ErrorInternal,
            })?;
        let resp = self.check(resp)?;
        resp.json().map_err(|e| HelmApiError {
            status: 0,
            message: e.to_string(),
            reason_code: ReasonCode::ErrorInternal,
        })
    }

    /// POST /api/v1/evidence/export — returns raw bytes
    pub fn export_evidence(&self, session_id: Option<&str>) -> Result<Vec<u8>, HelmApiError> {
        let body = serde_json::json!({
            "session_id": session_id,
            "format": "tar.gz"
        });
        let resp = self
            .client
            .post(self.url("/api/v1/evidence/export"))
            .json(&body)
            .send()
            .map_err(|e| HelmApiError {
                status: 0,
                message: e.to_string(),
                reason_code: ReasonCode::ErrorInternal,
            })?;
        let resp = self.check(resp)?;
        resp.bytes().map(|b| b.to_vec()).map_err(|e| HelmApiError {
            status: 0,
            message: e.to_string(),
            reason_code: ReasonCode::ErrorInternal,
        })
    }

    /// POST /api/v1/evidence/verify
    pub fn verify_evidence(&self, bundle: &[u8]) -> Result<VerificationResult, HelmApiError> {
        let form = reqwest::blocking::multipart::Form::new().part(
            "bundle",
            reqwest::blocking::multipart::Part::bytes(bundle.to_vec())
                .file_name("pack.tar.gz")
                .mime_str("application/octet-stream")
                .unwrap(),
        );
        let resp = self
            .client
            .post(self.url("/api/v1/evidence/verify"))
            .multipart(form)
            .send()
            .map_err(|e| HelmApiError {
                status: 0,
                message: e.to_string(),
                reason_code: ReasonCode::ErrorInternal,
            })?;
        let resp = self.check(resp)?;
        resp.json().map_err(|e| HelmApiError {
            status: 0,
            message: e.to_string(),
            reason_code: ReasonCode::ErrorInternal,
        })
    }

    /// POST /api/v1/replay/verify
    pub fn replay_verify(&self, bundle: &[u8]) -> Result<VerificationResult, HelmApiError> {
        let form = reqwest::blocking::multipart::Form::new().part(
            "bundle",
            reqwest::blocking::multipart::Part::bytes(bundle.to_vec())
                .file_name("pack.tar.gz")
                .mime_str("application/octet-stream")
                .unwrap(),
        );
        let resp = self
            .client
            .post(self.url("/api/v1/replay/verify"))
            .multipart(form)
            .send()
            .map_err(|e| HelmApiError {
                status: 0,
                message: e.to_string(),
                reason_code: ReasonCode::ErrorInternal,
            })?;
        let resp = self.check(resp)?;
        resp.json().map_err(|e| HelmApiError {
            status: 0,
            message: e.to_string(),
            reason_code: ReasonCode::ErrorInternal,
        })
    }

    /// POST /api/v1/evidence/envelopes
    pub fn create_evidence_envelope_manifest(
        &self,
        req: &EvidenceEnvelopeExportRequest,
    ) -> Result<EvidenceEnvelopeManifest, HelmApiError> {
        let resp = self
            .client
            .post(self.url("/api/v1/evidence/envelopes"))
            .json(req)
            .send()
            .map_err(|e| HelmApiError {
                status: 0,
                message: e.to_string(),
                reason_code: ReasonCode::ErrorInternal,
            })?;
        let resp = self.check(resp)?;
        resp.json().map_err(|e| HelmApiError {
            status: 0,
            message: e.to_string(),
            reason_code: ReasonCode::ErrorInternal,
        })
    }

    pub fn list_evidence_envelope_manifests(&self) -> Result<serde_json::Value, HelmApiError> {
        self.get_value("/api/v1/evidence/envelopes")
    }

    pub fn get_evidence_envelope_manifest(
        &self,
        manifest_id: &str,
    ) -> Result<serde_json::Value, HelmApiError> {
        self.get_value(&format!(
            "/api/v1/evidence/envelopes/{}",
            encode_query(manifest_id)
        ))
    }

    pub fn get_evidence_envelope_payload(
        &self,
        manifest_id: &str,
    ) -> Result<EvidenceEnvelopePayload, HelmApiError> {
        self.get_value(&format!(
            "/api/v1/evidence/envelopes/{}/payload",
            encode_query(manifest_id)
        ))
    }

    pub fn verify_evidence_envelope_manifest(
        &self,
        manifest_id: &str,
    ) -> Result<serde_json::Value, HelmApiError> {
        self.post_value(
            &format!(
                "/api/v1/evidence/envelopes/{}/verify",
                encode_query(manifest_id)
            ),
            &serde_json::json!({}),
        )
    }

    /// GET /api/v1/proofgraph/receipts/{hash}
    pub fn get_receipt(&self, receipt_hash: &str) -> Result<Receipt, HelmApiError> {
        let resp = self
            .client
            .get(self.url(&format!("/api/v1/proofgraph/receipts/{}", receipt_hash)))
            .send()
            .map_err(|e| HelmApiError {
                status: 0,
                message: e.to_string(),
                reason_code: ReasonCode::ErrorInternal,
            })?;
        let resp = self.check(resp)?;
        resp.json().map_err(|e| HelmApiError {
            status: 0,
            message: e.to_string(),
            reason_code: ReasonCode::ErrorInternal,
        })
    }

    /// POST /api/v1/conformance/run
    pub fn conformance_run(
        &self,
        req: &ConformanceRequest,
    ) -> Result<ConformanceResult, HelmApiError> {
        let resp = self
            .client
            .post(self.url("/api/v1/conformance/run"))
            .json(req)
            .send()
            .map_err(|e| HelmApiError {
                status: 0,
                message: e.to_string(),
                reason_code: ReasonCode::ErrorInternal,
            })?;
        let resp = self.check(resp)?;
        resp.json().map_err(|e| HelmApiError {
            status: 0,
            message: e.to_string(),
            reason_code: ReasonCode::ErrorInternal,
        })
    }

    /// GET /api/v1/conformance/reports/{id}
    pub fn get_conformance_report(
        &self,
        report_id: &str,
    ) -> Result<ConformanceResult, HelmApiError> {
        let resp = self
            .client
            .get(self.url(&format!("/api/v1/conformance/reports/{}", report_id)))
            .send()
            .map_err(|e| HelmApiError {
                status: 0,
                message: e.to_string(),
                reason_code: ReasonCode::ErrorInternal,
            })?;
        let resp = self.check(resp)?;
        resp.json().map_err(|e| HelmApiError {
            status: 0,
            message: e.to_string(),
            reason_code: ReasonCode::ErrorInternal,
        })
    }

    /// GET /api/v1/conformance/negative
    pub fn list_negative_conformance_vectors(
        &self,
    ) -> Result<Vec<NegativeBoundaryVector>, HelmApiError> {
        let resp = self
            .client
            .get(self.url("/api/v1/conformance/negative"))
            .send()
            .map_err(|e| HelmApiError {
                status: 0,
                message: e.to_string(),
                reason_code: ReasonCode::ErrorInternal,
            })?;
        let resp = self.check(resp)?;
        resp.json().map_err(|e| HelmApiError {
            status: 0,
            message: e.to_string(),
            reason_code: ReasonCode::ErrorInternal,
        })
    }

    pub fn list_conformance_reports(&self) -> Result<serde_json::Value, HelmApiError> {
        self.get_value("/api/v1/conformance/reports")
    }

    pub fn list_conformance_vectors(&self) -> Result<serde_json::Value, HelmApiError> {
        self.get_value("/api/v1/conformance/vectors")
    }

    /// GET /api/v1/mcp/registry
    pub fn list_mcp_registry(&self) -> Result<Vec<McpQuarantineRecord>, HelmApiError> {
        let resp = self
            .client
            .get(self.url("/api/v1/mcp/registry"))
            .send()
            .map_err(|e| HelmApiError {
                status: 0,
                message: e.to_string(),
                reason_code: ReasonCode::ErrorInternal,
            })?;
        let resp = self.check(resp)?;
        resp.json().map_err(|e| HelmApiError {
            status: 0,
            message: e.to_string(),
            reason_code: ReasonCode::ErrorInternal,
        })
    }

    /// POST /api/v1/mcp/registry
    pub fn discover_mcp_server(
        &self,
        req: &McpRegistryDiscoverRequest,
    ) -> Result<McpQuarantineRecord, HelmApiError> {
        let resp = self
            .client
            .post(self.url("/api/v1/mcp/registry"))
            .json(req)
            .send()
            .map_err(|e| HelmApiError {
                status: 0,
                message: e.to_string(),
                reason_code: ReasonCode::ErrorInternal,
            })?;
        let resp = self.check(resp)?;
        resp.json().map_err(|e| HelmApiError {
            status: 0,
            message: e.to_string(),
            reason_code: ReasonCode::ErrorInternal,
        })
    }

    /// POST /api/v1/mcp/registry/approve
    pub fn approve_mcp_server(
        &self,
        req: &McpRegistryApprovalRequest,
    ) -> Result<McpQuarantineRecord, HelmApiError> {
        let resp = self
            .client
            .post(self.url("/api/v1/mcp/registry/approve"))
            .json(req)
            .send()
            .map_err(|e| HelmApiError {
                status: 0,
                message: e.to_string(),
                reason_code: ReasonCode::ErrorInternal,
            })?;
        let resp = self.check(resp)?;
        resp.json().map_err(|e| HelmApiError {
            status: 0,
            message: e.to_string(),
            reason_code: ReasonCode::ErrorInternal,
        })
    }

    pub fn get_mcp_registry_record(
        &self,
        server_id: &str,
    ) -> Result<McpQuarantineRecord, HelmApiError> {
        let resp = self
            .client
            .get(self.url(&format!("/api/v1/mcp/registry/{}", encode_query(server_id))))
            .send()
            .map_err(|e| HelmApiError {
                status: 0,
                message: e.to_string(),
                reason_code: ReasonCode::ErrorInternal,
            })?;
        let resp = self.check(resp)?;
        resp.json().map_err(|e| HelmApiError {
            status: 0,
            message: e.to_string(),
            reason_code: ReasonCode::ErrorInternal,
        })
    }

    pub fn approve_mcp_registry_record(
        &self,
        server_id: &str,
        req: &McpRegistryApprovalRequest,
    ) -> Result<McpQuarantineRecord, HelmApiError> {
        let resp = self
            .client
            .post(self.url(&format!(
                "/api/v1/mcp/registry/{}/approve",
                encode_query(server_id)
            )))
            .json(req)
            .send()
            .map_err(|e| HelmApiError {
                status: 0,
                message: e.to_string(),
                reason_code: ReasonCode::ErrorInternal,
            })?;
        let resp = self.check(resp)?;
        resp.json().map_err(|e| HelmApiError {
            status: 0,
            message: e.to_string(),
            reason_code: ReasonCode::ErrorInternal,
        })
    }

    pub fn revoke_mcp_registry_record(
        &self,
        server_id: &str,
        reason: Option<&str>,
    ) -> Result<McpQuarantineRecord, HelmApiError> {
        let body = serde_json::json!({ "reason": reason.unwrap_or("") });
        let resp = self
            .client
            .post(self.url(&format!(
                "/api/v1/mcp/registry/{}/revoke",
                encode_query(server_id)
            )))
            .json(&body)
            .send()
            .map_err(|e| HelmApiError {
                status: 0,
                message: e.to_string(),
                reason_code: ReasonCode::ErrorInternal,
            })?;
        let resp = self.check(resp)?;
        resp.json().map_err(|e| HelmApiError {
            status: 0,
            message: e.to_string(),
            reason_code: ReasonCode::ErrorInternal,
        })
    }

    pub fn scan_mcp_server<T: Serialize>(
        &self,
        req: &T,
    ) -> Result<serde_json::Value, HelmApiError> {
        self.post_value("/api/v1/mcp/scan", req)
    }

    pub fn list_mcp_auth_profiles(&self) -> Result<serde_json::Value, HelmApiError> {
        self.get_value("/api/v1/mcp/auth-profiles")
    }

    pub fn put_mcp_auth_profile<T: Serialize>(
        &self,
        profile_id: &str,
        profile: &T,
    ) -> Result<serde_json::Value, HelmApiError> {
        self.put_value(
            &format!("/api/v1/mcp/auth-profiles/{}", encode_query(profile_id)),
            profile,
        )
    }

    pub fn authorize_mcp_call<T: Serialize>(
        &self,
        req: &T,
    ) -> Result<serde_json::Value, HelmApiError> {
        self.post_value("/api/v1/mcp/authorize-call", req)
    }

    /// GET /api/v1/sandbox/grants/inspect
    pub fn inspect_sandbox_grants(
        &self,
        runtime: Option<&str>,
        profile: Option<&str>,
        policy_epoch: Option<&str>,
    ) -> Result<SandboxGrantInspection, HelmApiError> {
        let mut path = "/api/v1/sandbox/grants/inspect".to_string();
        let mut params = Vec::new();
        if let Some(runtime) = runtime {
            params.push(format!("runtime={}", encode_query(runtime)));
        }
        if let Some(profile) = profile {
            params.push(format!("profile={}", encode_query(profile)));
        }
        if let Some(policy_epoch) = policy_epoch {
            params.push(format!("policy_epoch={}", encode_query(policy_epoch)));
        }
        if !params.is_empty() {
            path.push('?');
            path.push_str(&params.join("&"));
        }
        let resp = self
            .client
            .get(self.url(&path))
            .send()
            .map_err(|e| HelmApiError {
                status: 0,
                message: e.to_string(),
                reason_code: ReasonCode::ErrorInternal,
            })?;
        let resp = self.check(resp)?;
        resp.json().map_err(|e| HelmApiError {
            status: 0,
            message: e.to_string(),
            reason_code: ReasonCode::ErrorInternal,
        })
    }

    pub fn list_sandbox_profiles(&self) -> Result<serde_json::Value, HelmApiError> {
        self.get_value("/api/v1/sandbox/profiles")
    }

    pub fn list_sandbox_grants(&self) -> Result<serde_json::Value, HelmApiError> {
        self.get_value("/api/v1/sandbox/grants")
    }

    pub fn create_sandbox_grant<T: Serialize>(
        &self,
        req: &T,
    ) -> Result<serde_json::Value, HelmApiError> {
        self.post_value("/api/v1/sandbox/grants", req)
    }

    pub fn get_sandbox_grant(&self, grant_id: &str) -> Result<serde_json::Value, HelmApiError> {
        self.get_value(&format!(
            "/api/v1/sandbox/grants/{}",
            encode_query(grant_id)
        ))
    }

    pub fn verify_sandbox_grant(&self, grant_id: &str) -> Result<serde_json::Value, HelmApiError> {
        self.post_value(
            &format!("/api/v1/sandbox/grants/{}/verify", encode_query(grant_id)),
            &serde_json::json!({}),
        )
    }

    pub fn preflight_sandbox_grant<T: Serialize>(
        &self,
        req: &T,
    ) -> Result<serde_json::Value, HelmApiError> {
        self.post_value("/api/v1/sandbox/preflight", req)
    }

    pub fn list_agent_identities(&self) -> Result<serde_json::Value, HelmApiError> {
        self.get_value("/api/v1/identity/agents")
    }

    pub fn get_authz_health(&self) -> Result<serde_json::Value, HelmApiError> {
        self.get_value("/api/v1/authz/health")
    }

    pub fn check_authz<T: Serialize>(&self, req: &T) -> Result<serde_json::Value, HelmApiError> {
        self.post_value("/api/v1/authz/check", req)
    }

    pub fn list_authz_snapshots(&self) -> Result<serde_json::Value, HelmApiError> {
        self.get_value("/api/v1/authz/snapshots")
    }

    pub fn get_authz_snapshot(&self, snapshot_id: &str) -> Result<serde_json::Value, HelmApiError> {
        self.get_value(&format!(
            "/api/v1/authz/snapshots/{}",
            encode_query(snapshot_id)
        ))
    }

    pub fn list_approval_ceremonies(&self) -> Result<serde_json::Value, HelmApiError> {
        self.get_value("/api/v1/approvals")
    }

    pub fn create_approval_ceremony<T: Serialize>(
        &self,
        req: &T,
    ) -> Result<serde_json::Value, HelmApiError> {
        self.post_value("/api/v1/approvals", req)
    }

    pub fn transition_approval_ceremony<T: Serialize>(
        &self,
        approval_id: &str,
        action: &str,
        req: &T,
    ) -> Result<serde_json::Value, HelmApiError> {
        self.post_value(
            &format!(
                "/api/v1/approvals/{}/{}",
                encode_query(approval_id),
                encode_query(action)
            ),
            req,
        )
    }

    pub fn create_approval_webauthn_challenge<T: Serialize>(
        &self,
        approval_id: &str,
        req: &T,
    ) -> Result<ApprovalWebAuthnChallenge, HelmApiError> {
        self.post_value(
            &format!(
                "/api/v1/approvals/{}/webauthn/challenge",
                encode_query(approval_id)
            ),
            req,
        )
    }

    pub fn assert_approval_webauthn_challenge<T: Serialize>(
        &self,
        approval_id: &str,
        req: &T,
    ) -> Result<serde_json::Value, HelmApiError> {
        self.post_value(
            &format!(
                "/api/v1/approvals/{}/webauthn/assert",
                encode_query(approval_id)
            ),
            req,
        )
    }

    pub fn list_budget_ceilings(&self) -> Result<serde_json::Value, HelmApiError> {
        self.get_value("/api/v1/budgets")
    }

    pub fn put_budget_ceiling<T: Serialize>(
        &self,
        budget_id: &str,
        req: &T,
    ) -> Result<serde_json::Value, HelmApiError> {
        self.put_value(&format!("/api/v1/budgets/{}", encode_query(budget_id)), req)
    }

    pub fn get_coexistence_capabilities(&self) -> Result<serde_json::Value, HelmApiError> {
        self.get_value("/api/v1/coexistence/capabilities")
    }

    pub fn get_telemetry_otel_config(&self) -> Result<serde_json::Value, HelmApiError> {
        self.get_value("/api/v1/telemetry/otel/config")
    }

    pub fn export_telemetry<T: Serialize>(
        &self,
        req: &T,
    ) -> Result<serde_json::Value, HelmApiError> {
        self.post_value("/api/v1/telemetry/export", req)
    }

    /// GET /healthz
    pub fn health(&self) -> Result<serde_json::Value, HelmApiError> {
        let resp = self
            .client
            .get(self.url("/healthz"))
            .send()
            .map_err(|e| HelmApiError {
                status: 0,
                message: e.to_string(),
                reason_code: ReasonCode::ErrorInternal,
            })?;
        let resp = self.check(resp)?;
        resp.json().map_err(|e| HelmApiError {
            status: 0,
            message: e.to_string(),
            reason_code: ReasonCode::ErrorInternal,
        })
    }

    /// GET /version
    pub fn version(&self) -> Result<VersionInfo, HelmApiError> {
        let resp = self
            .client
            .get(self.url("/version"))
            .send()
            .map_err(|e| HelmApiError {
                status: 0,
                message: e.to_string(),
                reason_code: ReasonCode::ErrorInternal,
            })?;
        let resp = self.check(resp)?;
        resp.json().map_err(|e| HelmApiError {
            status: 0,
            message: e.to_string(),
            reason_code: ReasonCode::ErrorInternal,
        })
    }
}

fn encode_query(value: &str) -> String {
    value
        .bytes()
        .flat_map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                vec![b as char]
            }
            _ => format!("%{b:02X}").chars().collect(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn test_client_creation() {
        let _client = HelmClient::new("http://localhost:8080");
    }

    #[test]
    fn identity_configuration_binds_protected_route_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = Vec::new();
            let mut chunk = [0_u8; 1024];
            while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut chunk).unwrap();
                assert_ne!(read, 0, "client closed before sending headers");
                bytes.extend_from_slice(&chunk[..read]);
            }
            let response = r#"{"status":"ready"}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            )
            .unwrap();
            String::from_utf8(bytes).unwrap()
        });

        HelmClient::new(&format!("http://{address}"))
            .with_api_key("token")
            .with_identity("tenant-a", "principal-a")
            .with_session_id("session-a")
            .with_workspace_id("workspace-a")
            .get_boundary_status()
            .unwrap();
        let request = server.join().unwrap().to_ascii_lowercase();
        assert!(request.starts_with("get /api/v1/boundary/status "));
        assert!(request.contains("authorization: bearer token"));
        assert!(request.contains("x-helm-tenant-id: tenant-a"));
        assert!(request.contains("x-helm-principal-id: principal-a"));
        assert!(request.contains("x-helm-session-id: session-a"));
        assert!(request.contains("x-helm-workspace-id: workspace-a"));
    }

    #[test]
    fn test_reason_code_serde() {
        let code = ReasonCode::DenyToolNotFound;
        let json = serde_json::to_string(&code).unwrap();
        assert_eq!(json, "\"DENY_TOOL_NOT_FOUND\"");
    }

    #[test]
    fn test_execution_boundary_types_serde() {
        let req = EvidenceEnvelopeExportRequest {
            manifest_id: "env1".to_string(),
            envelope: "dsse".to_string(),
            native_evidence_hash: "sha256:native".to_string(),
            subject: None,
            experimental: false,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("native_evidence_hash"));

        let manifest: EvidenceEnvelopeManifest = serde_json::from_str(
            r#"{"manifest_id":"env1","envelope":"dsse","native_evidence_hash":"sha256:native","native_authority":false,"created_at":"2026-05-05T00:00:00Z","payload_type":"application/vnd.dsse+json","payload_hash":"sha256:payload","manifest_hash":"sha256:manifest"}"#,
        )
        .unwrap();
        assert_eq!(manifest.payload_hash.as_deref(), Some("sha256:payload"));

        let record: McpQuarantineRecord = serde_json::from_str(
            r#"{"server_id":"mcp1","risk":"high","state":"quarantined","discovered_at":"2026-05-05T00:00:00Z"}"#,
        )
        .unwrap();
        assert_eq!(record.server_id, "mcp1");

        let grant: SandboxGrant = serde_json::from_str(
            r#"{"grant_id":"grant1","runtime":"wazero","profile":"deny-default","env":{"mode":"deny-all"},"network":{"mode":"deny-all"},"declared_at":"2026-05-05T00:00:00Z"}"#,
        )
        .unwrap();
        assert_eq!(grant.grant_id, "grant1");
    }

    #[test]
    fn test_boundary_status_default_is_fail_closed() {
        let status = BoundaryStatus::default();
        assert_eq!(status.status, BoundaryStatusStatus::Degraded);
        assert_eq!(
            status.receipt_signer,
            BoundaryStatusReceiptSigner::Unavailable
        );
        assert_eq!(
            status.receipt_store,
            BoundaryStatusReceiptStore::Unavailable
        );

        let json = serde_json::to_value(status).unwrap();
        assert_eq!(json["status"], "degraded");
        assert_eq!(json["receipt_signer"], "unavailable");
        assert_eq!(json["receipt_store"], "unavailable");
    }

    #[test]
    fn scoped_evaluation_binds_headers_and_canonical_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut bytes = Vec::new();
                let mut chunk = [0_u8; 1024];
                loop {
                    let read = stream.read(&mut chunk).unwrap();
                    assert_ne!(read, 0, "client closed before sending a complete request");
                    bytes.extend_from_slice(&chunk[..read]);
                    let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n")
                    else {
                        continue;
                    };
                    let headers = std::str::from_utf8(&bytes[..header_end]).unwrap();
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            line.strip_prefix("content-length: ")
                                .or_else(|| line.strip_prefix("Content-Length: "))
                        })
                        .and_then(|value| value.parse::<usize>().ok())
                        .unwrap_or_default();
                    if bytes.len() >= header_end + 4 + content_length {
                        break;
                    }
                }
                let response = r#"{"id":"decision-1","tenant_id":"tenant-a","session_id":"session-a"}"#;
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-Helm-Receipt-ID: rcpt-decision-1\r\nX-Helm-Idempotency-Replayed: true\r\nConnection: close\r\n\r\n{}",
                    response.len(),
                    response
                )
                .unwrap();
                requests.push(String::from_utf8(bytes).unwrap());
            }
            requests
        });

        let mut request = DecisionRequest::new("read_ticket".to_string(), "ticket:1".to_string());
        request.context = Some(HashMap::from([(
            "priority".to_string(),
            serde_json::Value::String("low".to_string()),
        )]));
        let client = HelmClient::new(&format!("http://{address}"))
            .with_api_key("token")
            .with_identity("tenant-default", "principal-default")
            .with_workspace_id("workspace-default");
        let scope = EvaluationScope::new("tenant-a", "principal-a", "session-a")
            .with_workspace_id("workspace-a");

        let result = client
            .evaluate_decision_with_scope(&request, &scope, Some("request-1"))
            .unwrap();
        client
            .evaluate_decision_with_scope(
                &DecisionRequest::new("read_ticket".to_string(), "ticket:2".to_string()),
                &EvaluationScope::new("tenant-a", "principal-a", "session-a"),
                None,
            )
            .unwrap();
        let raw_requests = server.join().unwrap();
        let raw_request = &raw_requests[0];
        let headers = raw_request.to_ascii_lowercase();
        let body = raw_request.split("\r\n\r\n").nth(1).unwrap();
        assert!(headers.starts_with("post /api/v1/evaluate "));
        assert!(headers.contains("authorization: bearer token"));
        assert!(headers.contains("x-helm-tenant-id: tenant-a"));
        assert!(headers.contains("x-helm-principal-id: principal-a"));
        assert!(headers.contains("x-helm-session-id: session-a"));
        assert!(headers.contains("x-helm-workspace-id: workspace-a"));
        assert!(headers.contains("idempotency-key: request-1"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(body).unwrap(),
            serde_json::json!({"action":"read_ticket","resource":"ticket:1","context":{"priority":"low"}})
        );
        assert_eq!(result.decision.id.as_deref(), Some("decision-1"));
        assert_eq!(result.receipt_id, "rcpt-decision-1");
        assert!(result.replayed);
        assert!(
            !raw_requests[1]
                .to_ascii_lowercase()
                .contains("x-helm-workspace-id:"),
            "scoped evaluation inherited a client workspace: {}",
            raw_requests[1]
        );
    }

    #[test]
    fn scoped_evaluation_rejects_missing_bindings_locally() {
        let request = DecisionRequest::new("read_ticket".to_string(), "ticket:1".to_string());
        let missing_key = HelmClient::new("http://127.0.0.1:1")
            .evaluate_decision_with_scope(
                &request,
                &EvaluationScope::new("tenant-a", "principal-a", "session-a"),
                None,
            )
            .unwrap_err();
        assert_eq!(missing_key.status, 0);
        assert!(missing_key.message.contains("api_key is required"));

        let missing_session = HelmClient::new("http://127.0.0.1:1")
            .with_api_key("token")
            .evaluate_decision_with_scope(
                &request,
                &EvaluationScope::new("tenant-a", "principal-a", ""),
                None,
            )
            .unwrap_err();
        assert_eq!(missing_session.status, 0);
        assert!(missing_session.message.contains("session_id is required"));
    }

    #[test]
    fn governed_chat_rejects_missing_session_locally() {
        let request = ChatCompletionRequest::new("test".to_string(), vec![]);
        let error = HelmClient::new("http://127.0.0.1:1")
            .with_api_key("token")
            .with_identity("tenant-a", "principal-a")
            .chat_completions(&request)
            .unwrap_err();
        assert!(error.message.contains("session_id is required"));
    }

    #[test]
    #[allow(deprecated)]
    fn generic_evaluation_is_retired_locally() {
        let error = HelmClient::new("http://127.0.0.1:1")
            .evaluate_decision(&serde_json::json!({"principal": "spoofed"}))
            .unwrap_err();
        assert!(error.message.contains("evaluate_decision is retired"));
    }

    #[test]
    fn scoped_evaluation_rejects_missing_receipt_id() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut chunk = [0_u8; 1024];
            let _ = stream.read(&mut chunk).unwrap();
            let response = r#"{"id":"decision-3"}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            )
            .unwrap();
        });
        let error = HelmClient::new(&format!("http://{address}"))
            .with_api_key("token")
            .evaluate_decision_with_scope(
                &DecisionRequest::new("read_ticket".to_string(), "ticket:3".to_string()),
                &EvaluationScope::new("tenant-a", "principal-a", "session-a"),
                None,
            )
            .unwrap_err();
        server.join().unwrap();
        assert!(error.message.contains("missing required X-Helm-Receipt-ID"));
    }
}
