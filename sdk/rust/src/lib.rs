//! HELM SDK — Rust client for the HELM kernel API.
//! Minimal deps: reqwest + serde.

use reqwest::blocking::Client;
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
        resp.bytes()
            .map(|b| b.to_vec())
            .map_err(|e| HelmApiError {
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

    /// GET /api/v1/proofgraph/receipts/{hash}
    pub fn get_receipt(&self, receipt_hash: &str) -> Result<Receipt, HelmApiError> {
        let resp = self
            .client
            .get(self.url(&format!(
                "/api/v1/proofgraph/receipts/{}",
                receipt_hash
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
            .get(self.url(&format!(
                "/api/v1/conformance/reports/{}",
                report_id
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
}
