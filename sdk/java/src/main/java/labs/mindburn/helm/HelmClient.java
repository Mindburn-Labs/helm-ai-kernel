package labs.mindburn.helm;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import labs.mindburn.helm.TypesGen.*;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Typed Java client for the HELM kernel API.
 * Uses java.net.http (JDK 11+) and Gson. Zero framework deps.
 */
public class HelmClient {
    private final String baseUrl;
    private final HttpClient httpClient;
    private final Gson gson;
    private final String apiKey;

    public HelmClient(String baseUrl) {
        this(baseUrl, null);
    }

    public HelmClient(String baseUrl, String apiKey) {
        this.baseUrl = baseUrl.replaceAll("/$", "");
        this.apiKey = apiKey;
        this.gson = new Gson();
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30))
                .build();
    }

    /** Thrown when the HELM API returns a non-2xx response. */
    public static class HelmApiException extends RuntimeException {
        public final int status;
        public final String reasonCode;

        public HelmApiException(int status, String message, String reasonCode) {
            super(message);
            this.status = status;
            this.reasonCode = reasonCode;
        }
    }

    public static class EvidenceEnvelopeExportRequest {
        public String manifest_id;
        public String envelope;
        public String native_evidence_hash;
        public String subject;
        public boolean experimental;
    }

    public static class EvidenceEnvelopeManifest {
        public String manifest_id;
        public String envelope;
        public String native_evidence_hash;
        public boolean native_authority;
        public String subject;
        public String statement_hash;
        public boolean experimental;
        public String created_at;
        public String manifest_hash;
    }

    public static class NegativeBoundaryVector {
        public String id;
        public String category;
        public String trigger;
        public String expected_verdict;
        public String expected_reason_code;
        public boolean must_emit_receipt;
        public boolean must_not_dispatch;
        public List<String> must_bind_evidence;
    }

    public static class MCPRegistryDiscoverRequest {
        public String server_id;
        public String name;
        public String transport;
        public String endpoint;
        public List<String> tool_names;
        public String risk;
        public String reason;
    }

    public static class MCPRegistryApprovalRequest {
        public String server_id;
        public String approver_id;
        public String approval_receipt_id;
        public String reason;
    }

    public static class MCPQuarantineRecord {
        public String server_id;
        public String name;
        public String transport;
        public String endpoint;
        public List<String> tool_names;
        public String risk;
        public String state;
        public String discovered_at;
        public String approved_at;
        public String approved_by;
        public String approval_receipt_id;
        public String revoked_at;
        public String expires_at;
        public String reason;
    }

    public static class SandboxBackendProfile {
        public String name;
        public String kind;
        public String runtime;
        public boolean hosted;
        public boolean deny_network_by_default;
        public boolean native_isolation;
        public boolean experimental;
    }

    public static class SandboxGrant {
        public String grant_id;
        public String runtime;
        public String runtime_version;
        public String profile;
        public String image_digest;
        public String template_digest;
        public List<java.util.Map<String, Object>> filesystem_preopens;
        public java.util.Map<String, Object> env;
        public java.util.Map<String, Object> network;
        public java.util.Map<String, Object> limits;
        public String declared_at;
        public String policy_epoch;
        public String grant_hash;
    }

    private HttpRequest.Builder req(String method, String path) {
        HttpRequest.Builder b = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + path))
                .timeout(Duration.ofSeconds(30))
                .header("Content-Type", "application/json");
        if (apiKey != null && !apiKey.isEmpty()) {
            b.header("Authorization", "Bearer " + apiKey);
        }
        return b;
    }

    private <T> T send(HttpRequest request, Class<T> type) {
        try {
            HttpResponse<String> resp = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() >= 400) {
                HelmError err = gson.fromJson(resp.body(), HelmError.class);
                throw new HelmApiException(
                        resp.statusCode(),
                        err != null && err.getError() != null ? err.getError().getMessage() : resp.body(),
                        err != null && err.getError() != null ? String.valueOf(err.getError().getReasonCode()) : "ERROR_INTERNAL");
            }
            return gson.fromJson(resp.body(), type);
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException("HELM API request failed", e);
        }
    }

    private <T> T sendList(HttpRequest request, TypeToken<T> typeToken) {
        try {
            HttpResponse<String> resp = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() >= 400) {
                HelmError err = gson.fromJson(resp.body(), HelmError.class);
                throw new HelmApiException(
                        resp.statusCode(),
                        err != null && err.getError() != null ? err.getError().getMessage() : resp.body(),
                        err != null && err.getError() != null ? String.valueOf(err.getError().getReasonCode()) : "ERROR_INTERNAL");
            }
            return gson.fromJson(resp.body(), typeToken.getType());
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException("HELM API request failed", e);
        }
    }

    /** POST /v1/chat/completions */
    public ChatCompletionResponse chatCompletions(ChatCompletionRequest req) {
        HttpRequest r = req("POST", "/v1/chat/completions")
                .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(req)))
                .build();
        return send(r, ChatCompletionResponse.class);
    }

    /** POST /api/v1/kernel/approve */
    public Receipt approveIntent(ApprovalRequest req) {
        HttpRequest r = this.req("POST", "/api/v1/kernel/approve")
                .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(req)))
                .build();
        return send(r, Receipt.class);
    }

    /** GET /api/v1/proofgraph/sessions */
    public List<Session> listSessions() {
        HttpRequest r = req("GET", "/api/v1/proofgraph/sessions")
                .GET().build();
        return sendList(r, new TypeToken<List<Session>>() {
        });
    }

    /** GET /api/v1/proofgraph/sessions/{id}/receipts */
    public List<Receipt> getReceipts(String sessionId) {
        HttpRequest r = req("GET", "/api/v1/proofgraph/sessions/" + sessionId + "/receipts")
                .GET().build();
        return sendList(r, new TypeToken<List<Receipt>>() {
        });
    }

    /** GET /api/v1/proofgraph/receipts/{hash} */
    public Receipt getReceipt(String receiptHash) {
        HttpRequest r = req("GET", "/api/v1/proofgraph/receipts/" + receiptHash)
                .GET().build();
        return send(r, Receipt.class);
    }

    /** POST /api/v1/evidence/export — returns raw bytes */
    public byte[] exportEvidence(String sessionId) {
        String body = gson.toJson(new java.util.HashMap<String, String>() {{
            put("session_id", sessionId);
            put("format", "tar.gz");
        }});
        HttpRequest r = req("POST", "/api/v1/evidence/export")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        try {
            HttpResponse<byte[]> resp = httpClient.send(r, HttpResponse.BodyHandlers.ofByteArray());
            if (resp.statusCode() >= 400) {
                HelmError err = gson.fromJson(new String(resp.body()), HelmError.class);
                throw new HelmApiException(
                        resp.statusCode(),
                        err != null && err.getError() != null ? err.getError().getMessage() : "export failed",
                        err != null && err.getError() != null ? String.valueOf(err.getError().getReasonCode()) : "ERROR_INTERNAL");
            }
            return resp.body();
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException("HELM API request failed", e);
        }
    }

    /** POST /api/v1/evidence/verify */
    public VerificationResult verifyEvidence(byte[] bundle) {
        // Send as JSON with base64-encoded bundle for simplicity
        String body = gson.toJson(java.util.Map.of("bundle_b64",
                java.util.Base64.getEncoder().encodeToString(bundle)));
        HttpRequest r = req("POST", "/api/v1/evidence/verify")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        return send(r, VerificationResult.class);
    }

    /** POST /api/v1/replay/verify */
    public VerificationResult replayVerify(byte[] bundle) {
        String body = gson.toJson(java.util.Map.of("bundle_b64",
                java.util.Base64.getEncoder().encodeToString(bundle)));
        HttpRequest r = req("POST", "/api/v1/replay/verify")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        return send(r, VerificationResult.class);
    }

    /** POST /api/v1/evidence/envelopes */
    public EvidenceEnvelopeManifest createEvidenceEnvelopeManifest(EvidenceEnvelopeExportRequest req) {
        HttpRequest r = this.req("POST", "/api/v1/evidence/envelopes")
                .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(req)))
                .build();
        return send(r, EvidenceEnvelopeManifest.class);
    }

    /** POST /api/v1/conformance/run */
    public ConformanceResult conformanceRun(ConformanceRequest req) {
        HttpRequest r = this.req("POST", "/api/v1/conformance/run")
                .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(req)))
                .build();
        return send(r, ConformanceResult.class);
    }

    /** GET /api/v1/conformance/reports/{id} */
    public ConformanceResult getConformanceReport(String reportId) {
        HttpRequest r = req("GET", "/api/v1/conformance/reports/" + reportId)
                .GET().build();
        return send(r, ConformanceResult.class);
    }

    /** GET /api/v1/conformance/negative */
    public List<NegativeBoundaryVector> listNegativeConformanceVectors() {
        HttpRequest r = req("GET", "/api/v1/conformance/negative")
                .GET().build();
        return sendList(r, new TypeToken<List<NegativeBoundaryVector>>() {
        });
    }

    /** GET /api/v1/mcp/registry */
    public List<MCPQuarantineRecord> listMcpRegistry() {
        HttpRequest r = req("GET", "/api/v1/mcp/registry")
                .GET().build();
        return sendList(r, new TypeToken<List<MCPQuarantineRecord>>() {
        });
    }

    /** POST /api/v1/mcp/registry */
    public MCPQuarantineRecord discoverMcpServer(MCPRegistryDiscoverRequest req) {
        HttpRequest r = this.req("POST", "/api/v1/mcp/registry")
                .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(req)))
                .build();
        return send(r, MCPQuarantineRecord.class);
    }

    /** POST /api/v1/mcp/registry/approve */
    public MCPQuarantineRecord approveMcpServer(MCPRegistryApprovalRequest req) {
        HttpRequest r = this.req("POST", "/api/v1/mcp/registry/approve")
                .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(req)))
                .build();
        return send(r, MCPQuarantineRecord.class);
    }

    /** GET /api/v1/sandbox/grants/inspect without a runtime lists backend profiles. */
    public List<SandboxBackendProfile> listSandboxBackendProfiles() {
        HttpRequest r = req("GET", "/api/v1/sandbox/grants/inspect")
                .GET().build();
        return sendList(r, new TypeToken<List<SandboxBackendProfile>>() {
        });
    }

    /** GET /api/v1/sandbox/grants/inspect with runtime returns a sealed grant. */
    public SandboxGrant inspectSandboxGrant(String runtime, String profile, String policyEpoch) {
        ArrayList<String> params = new ArrayList<>();
        params.add("runtime=" + encode(runtime));
        if (profile != null && !profile.isEmpty()) {
            params.add("profile=" + encode(profile));
        }
        if (policyEpoch != null && !policyEpoch.isEmpty()) {
            params.add("policy_epoch=" + encode(policyEpoch));
        }
        HttpRequest r = req("GET", "/api/v1/sandbox/grants/inspect?" + String.join("&", params))
                .GET().build();
        return send(r, SandboxGrant.class);
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    /** GET /healthz */
    public String health() {
        HttpRequest r = req("GET", "/healthz").GET().build();
        return send(r, String.class);
    }

    /** GET /version */
    public VersionInfo version() {
        HttpRequest r = req("GET", "/version").GET().build();
        return send(r, VersionInfo.class);
    }
}
