//! HELM SDK — Rust client for the HELM kernel API.
//! Minimal deps: reqwest + serde.

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub mod client;
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
}

impl HelmClient {
    /// Create a new client.
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("failed to build HTTP client"),
        }
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

    /// POST /api/v1/evaluate
    pub fn evaluate_decision<T: Serialize>(
        &self,
        req: &T,
    ) -> Result<serde_json::Value, HelmApiError> {
        self.post_value("/api/v1/evaluate", req)
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

    #[test]
    fn test_client_creation() {
        let _client = HelmClient::new("http://localhost:8080");
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
}
