package labs.mindburn.helm;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.DeserializationFeature;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Functional tests for the HELM Java SDK.
 * These test client construction, request building, serialization,
 * and error handling without requiring a live server.
 */
public class HelmClientTest {
    private static final ObjectMapper mapper = new ObjectMapper()
        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    @Test
    @DisplayName("Client construction with base URL")
    void testClientConstruction() {
        HelmClient client = new HelmClient("http://localhost:8080");
        assertNotNull(client);
    }

    @Test
    @DisplayName("Client construction with API key")
    void testClientConstructionWithApiKey() {
        HelmClient client = new HelmClient("http://localhost:8080", "test-api-key");
        assertNotNull(client);
    }

    @Test
    @DisplayName("Client strips trailing slash from base URL")
    void testTrailingSlashNormalization() {
        HelmClient client = new HelmClient("http://localhost:8080/");
        assertNotNull(client);
    }

    @Test
    @DisplayName("TypesGen: ChatCompletionRequest serialization")
    void testChatCompletionRequestSerialization() throws Exception {
        TypesGen.ChatCompletionRequest req = new TypesGen.ChatCompletionRequest();
        req.setModel("gpt-4");
        TypesGen.ChatCompletionRequestMessagesInner msg = new TypesGen.ChatCompletionRequestMessagesInner();
        msg.setRole(TypesGen.ChatCompletionRequestMessagesInner.RoleEnum.USER);
        msg.setContent("Hello");
        req.setMessages(java.util.List.of(msg));

        String json = mapper.writeValueAsString(req);
        assertNotNull(json);
        assertTrue(json.contains("\"model\":\"gpt-4\""));
    }

    @Test
    @DisplayName("TypesGen: Receipt deserialization")
    void testReceiptDeserialization() throws Exception {
        String json = "{\"receipt_id\":\"rcpt-123\",\"decision_id\":\"dec-456\",\"status\":\"APPROVED\",\"blob_hash\":\"sha256:abc\"}";
        TypesGen.Receipt receipt = mapper.readValue(json, TypesGen.Receipt.class);
        assertEquals("rcpt-123", receipt.getReceiptId());
        assertEquals("dec-456", receipt.getDecisionId());
        assertNotNull(receipt.getStatus());
        assertEquals("sha256:abc", receipt.getBlobHash());
    }

    @Test
    @DisplayName("TypesGen: ApprovalRequest roundtrip")
    void testApprovalRequestRoundtrip() throws Exception {
        TypesGen.ApprovalRequest req = new TypesGen.ApprovalRequest();
        req.setIntentHash("intent-789");
        req.setSignatureB64("sig-ed25519-abc");

        String json = mapper.writeValueAsString(req);
        TypesGen.ApprovalRequest deserialized = mapper.readValue(json, TypesGen.ApprovalRequest.class);
        assertEquals("intent-789", deserialized.getIntentHash());
        assertEquals("sig-ed25519-abc", deserialized.getSignatureB64());
    }

    @Test
    @DisplayName("TypesGen: ConformanceRequest serialization")
    void testConformanceRequestSerialization() throws Exception {
        TypesGen.ConformanceRequest req = new TypesGen.ConformanceRequest();
        req.setLevel(TypesGen.ConformanceRequest.LevelEnum.L2);
        req.setProfile("production");

        String json = mapper.writeValueAsString(req);
        assertNotNull(json);
        assertTrue(json.contains("\"profile\":\"production\""));
    }

    @Test
    @DisplayName("HelmApiException preserves status and reason code")
    void testHelmApiException() {
        HelmClient.HelmApiException ex = new HelmClient.HelmApiException(
            403, "Access denied by policy", "POLICY_DENIED"
        );
        assertEquals(403, ex.status);
        assertEquals("POLICY_DENIED", ex.reasonCode);
        assertEquals("Access denied by policy", ex.getMessage());
    }

    @Test
    @DisplayName("TypesGen: HelmError deserialization")
    void testHelmErrorDeserialization() throws Exception {
        String json = "{\"error\":{\"message\":\"Tool not found\",\"reason_code\":\"DENY_TOOL_NOT_FOUND\"}}";
        TypesGen.HelmError err = mapper.readValue(json, TypesGen.HelmError.class);
        assertNotNull(err.getError());
        assertEquals("Tool not found", err.getError().getMessage());
    }

    @Test
    @DisplayName("TypesGen: VersionInfo deserialization")
    void testVersionInfoDeserialization() throws Exception {
        String json = "{\"version\":\"0.1.0\",\"commit\":\"abc123\",\"build_time\":\"2026-02-17T00:00:00Z\"}";
        TypesGen.VersionInfo info = mapper.readValue(json, TypesGen.VersionInfo.class);
        assertEquals("0.1.0", info.getVersion());
        assertEquals("abc123", info.getCommit());
        assertEquals("2026-02-17T00:00:00Z", info.getBuildTime());
    }

    @Test
    @DisplayName("TypesGen: VerificationResult deserialization")
    void testVerificationResultDeserialization() throws Exception {
        String json = "{\"verdict\":\"PASS\"}";
        TypesGen.VerificationResult result = mapper.readValue(json, TypesGen.VerificationResult.class);
        assertNotNull(result.getVerdict());
    }

    @Test
    @DisplayName("Execution boundary SDK types serialize")
    void testExecutionBoundaryTypesSerialize() throws Exception {
        HelmClient.EvidenceEnvelopeExportRequest envelope = new HelmClient.EvidenceEnvelopeExportRequest();
        envelope.manifest_id = "env1";
        envelope.envelope = "dsse";
        envelope.native_evidence_hash = "sha256:native";
        assertTrue(mapper.writeValueAsString(envelope).contains("native_evidence_hash"));

        HelmClient.EvidenceEnvelopeManifest manifest = mapper.readValue(
            "{\"manifest_id\":\"env1\",\"envelope\":\"dsse\",\"native_evidence_hash\":\"sha256:native\",\"native_authority\":false,\"created_at\":\"2026-05-05T00:00:00Z\",\"payload_type\":\"application/vnd.dsse+json\",\"payload_hash\":\"sha256:payload\"}",
            HelmClient.EvidenceEnvelopeManifest.class
        );
        assertEquals("sha256:payload", manifest.payload_hash);

        HelmClient.ApprovalWebAuthnAssertion assertion = new HelmClient.ApprovalWebAuthnAssertion();
        assertion.challenge_id = "challenge-1";
        assertion.actor = "user:alice";
        assertion.assertion = "signed-client-data";
        assertTrue(mapper.writeValueAsString(assertion).contains("challenge_id"));

        HelmClient.MCPRegistryDiscoverRequest discover = new HelmClient.MCPRegistryDiscoverRequest();
        discover.server_id = "mcp1";
        discover.risk = "high";
        assertTrue(mapper.writeValueAsString(discover).contains("server_id"));

        HelmClient.SandboxGrant grant = mapper.readValue(
            "{\"grant_id\":\"grant1\",\"runtime\":\"wazero\",\"profile\":\"deny-default\",\"declared_at\":\"2026-05-05T00:00:00Z\"}",
            HelmClient.SandboxGrant.class
        );
        assertEquals("grant1", grant.grant_id);
    }

    @Test
    @DisplayName("Scoped decision evaluation binds headers and canonical body")
    void testEvaluateDecisionWithScope() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        AtomicReference<String> method = new AtomicReference<>();
        AtomicReference<String> body = new AtomicReference<>();
        AtomicReference<Map<String, String>> headers = new AtomicReference<>();
        AtomicReference<Map<String, String>> genericHeaders = new AtomicReference<>();
        server.createContext("/api/v1/boundary/status", exchange -> {
            genericHeaders.set(Map.of(
                "authorization", exchange.getRequestHeaders().getFirst("Authorization"),
                "tenant", exchange.getRequestHeaders().getFirst("X-Helm-Tenant-ID"),
                "principal", exchange.getRequestHeaders().getFirst("X-Helm-Principal-ID"),
                "workspace", exchange.getRequestHeaders().getFirst("X-Helm-Workspace-ID")
            ));
            byte[] response = "{}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });
        server.createContext("/api/v1/evaluate", exchange -> {
            method.set(exchange.getRequestMethod());
            body.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            headers.set(Map.of(
                "authorization", exchange.getRequestHeaders().getFirst("Authorization"),
                "tenant", exchange.getRequestHeaders().getFirst("X-Helm-Tenant-ID"),
                "principal", exchange.getRequestHeaders().getFirst("X-Helm-Principal-ID"),
                "session", exchange.getRequestHeaders().getFirst("X-Helm-Session-ID"),
                "workspace", exchange.getRequestHeaders().getFirst("X-Helm-Workspace-ID"),
                "idempotency", exchange.getRequestHeaders().getFirst("Idempotency-Key")
            ));
            byte[] response = "{\"id\":\"decision-1\",\"tenant_id\":\"tenant-a\",\"session_id\":\"session-a\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.getResponseHeaders().set("X-Helm-Receipt-ID", "rcpt-decision-1");
            exchange.getResponseHeaders().set("X-Helm-Idempotency-Replayed", "true");
            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });
        server.start();
        try {
            TypesGen.DecisionRequest request = new TypesGen.DecisionRequest();
            request.setAction("read_ticket");
            request.setResource("ticket:1");
            request.setContext(Map.of("priority", "low"));
            request.putAdditionalProperty("principal", "spoofed-principal");
            TypesGen.SessionAction history = new TypesGen.SessionAction()
                .action("read_history")
                .resource("ticket:0")
                .verdict(TypesGen.SessionAction.VerdictEnum.ALLOW)
                .timestamp(1L);
            history.put("principal", "spoofed-history-principal");
            request.setSessionHistory(List.of(history));
            HelmClient client = new HelmClient(
                "http://127.0.0.1:" + server.getAddress().getPort(),
                "token",
                "tenant-default",
                "principal-default",
                "workspace-default"
            );
            client.getBoundaryStatus();

            HelmClient.EvaluationResult result = client.evaluateDecisionWithScope(
                request,
                new HelmClient.EvaluationScope("tenant-a", "principal-a", "session-a", "workspace-a"),
                "request-1"
            );

            assertEquals("POST", method.get());
            assertEquals("Bearer token", genericHeaders.get().get("authorization"));
            assertEquals("tenant-default", genericHeaders.get().get("tenant"));
            assertEquals("principal-default", genericHeaders.get().get("principal"));
            assertEquals("workspace-default", genericHeaders.get().get("workspace"));
            assertEquals("Bearer token", headers.get().get("authorization"));
            assertEquals("tenant-a", headers.get().get("tenant"));
            assertEquals("principal-a", headers.get().get("principal"));
            assertEquals("session-a", headers.get().get("session"));
            assertEquals("workspace-a", headers.get().get("workspace"));
            assertEquals("request-1", headers.get().get("idempotency"));
            JsonNode requestBody = mapper.readTree(body.get());
            assertFalse(requestBody.has("principal"));
            assertEquals("read_history", requestBody.path("session_history").get(0).path("action").asText());
            assertFalse(requestBody.path("session_history").get(0).has("principal"));
            assertEquals("decision-1", result.decision.getId());
            assertEquals("rcpt-decision-1", result.receiptId);
            assertTrue(result.replayed);
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("Scoped decision evaluation rejects missing bindings locally")
    void testEvaluateDecisionWithScopeRejectsMissingBindings() {
        TypesGen.DecisionRequest request = new TypesGen.DecisionRequest();
        request.setAction("read_ticket");
        request.setResource("ticket:1");
        assertThrows(IllegalArgumentException.class, () ->
            new HelmClient("http://127.0.0.1:1").evaluateDecisionWithScope(
                request,
                new HelmClient.EvaluationScope("tenant-a", "principal-a", "session-a")
            )
        );
        assertThrows(IllegalArgumentException.class, () ->
            new HelmClient("http://127.0.0.1:1", "token").evaluateDecisionWithScope(
                request,
                new HelmClient.EvaluationScope("tenant-a", "principal-a", "")
            )
        );
    }

    @Test
    @DisplayName("Retired generic evaluation fails locally")
    void testEvaluateDecisionIsRetiredLocally() {
        assertThrows(UnsupportedOperationException.class, () ->
            new HelmClient("http://127.0.0.1:1").evaluateDecision(Map.of("principal", "spoofed"))
        );
    }

    @Test
    @DisplayName("Scoped evaluation does not inherit a client workspace")
    void testEvaluateDecisionWithScopeDoesNotInheritClientWorkspace() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        AtomicReference<String> workspace = new AtomicReference<>();
        server.createContext("/api/v1/evaluate", exchange -> {
            workspace.set(exchange.getRequestHeaders().getFirst("X-Helm-Workspace-ID"));
            byte[] response = "{\"id\":\"decision-2\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.getResponseHeaders().set("X-Helm-Receipt-ID", "rcpt-decision-2");
            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });
        server.start();
        try {
            TypesGen.DecisionRequest request = new TypesGen.DecisionRequest();
            request.setAction("read_ticket");
            request.setResource("ticket:2");
            new HelmClient(
                "http://127.0.0.1:" + server.getAddress().getPort(),
                "token",
                "tenant-default",
                "principal-default",
                "workspace-default"
            ).evaluateDecisionWithScope(
                request,
                new HelmClient.EvaluationScope("tenant-a", "principal-a", "session-a")
            );
            assertNull(workspace.get());
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("Scoped evaluation rejects a response without its required receipt")
    void testEvaluateDecisionWithScopeRejectsMissingReceiptID() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/v1/evaluate", exchange -> {
            byte[] response = "{\"id\":\"decision-3\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });
        server.start();
        try {
            TypesGen.DecisionRequest request = new TypesGen.DecisionRequest();
            request.setAction("read_ticket");
            request.setResource("ticket:3");
            IllegalStateException error = assertThrows(IllegalStateException.class, () ->
                new HelmClient("http://127.0.0.1:" + server.getAddress().getPort(), "token")
                    .evaluateDecisionWithScope(
                        request,
                        new HelmClient.EvaluationScope("tenant-a", "principal-a", "session-a")
                    )
            );
            assertTrue(error.getMessage().contains("missing required X-Helm-Receipt-ID"));
        } finally {
            server.stop(0);
        }
    }
}
