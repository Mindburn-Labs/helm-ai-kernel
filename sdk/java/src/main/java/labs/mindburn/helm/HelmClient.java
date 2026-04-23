package labs.mindburn.helm;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import labs.mindburn.helm.TypesGen.*;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
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
