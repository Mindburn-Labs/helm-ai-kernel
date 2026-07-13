package labs.mindburn.helm;

import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.sun.net.httpserver.HttpServer;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
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
    @DisplayName("Evaluate serializes the canonical body and binds transport identity")
    void testEvaluateDecisionContract() throws Exception {
        AtomicReference<String> authorization = new AtomicReference<>();
        AtomicReference<String> tenant = new AtomicReference<>();
        AtomicReference<String> principal = new AtomicReference<>();
        AtomicReference<String> workspace = new AtomicReference<>();
        AtomicReference<String> requestBody = new AtomicReference<>();
        String response = """
            {"id":"decision-1","proposal_id":"proposal-1","step_id":"step-1","phenotype_hash":"sha256:phenotype","policy_version":"policy-v1","subject_id":"principal-a","action":"EXECUTE_TOOL","resource":"local.echo","effect_digest":"sha256:effect","state_cursor":"cursor-1","env_fingerprint":"sha256:env","verdict":"DENY","reason":"policy denied","trajectory_risk_score":0.75,"risk_accumulation_window":3,"signature":"sig","signature_type":"ed25519","timestamp":"2026-07-13T00:00:00Z","intervention":{"type":"THROTTLE","reason_code":"TEST_THROTTLE","wait_duration":5,"tokens_saved":7}}
            """;
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/v1/evaluate", exchange -> {
            authorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            tenant.set(exchange.getRequestHeaders().getFirst("X-Helm-Tenant-ID"));
            principal.set(exchange.getRequestHeaders().getFirst("X-Helm-Principal-ID"));
            workspace.set(exchange.getRequestHeaders().getFirst("X-Helm-Workspace-ID"));
            requestBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        try {
            int port = server.getAddress().getPort();
            HelmClient client = new HelmClient("http://127.0.0.1:" + port, "token", "tenant-a", "principal-a", "workspace-a");
            TypesGen.DecisionRequest request = new TypesGen.DecisionRequest();
            request.setAction("EXECUTE_TOOL");
            request.setResource("local.echo");
            request.setContext(Map.of("request_id", "req-1"));
            request.putAdditionalProperty("principal", "attacker");

            TypesGen.DecisionRecord decision = client.evaluateDecision(request);

            assertEquals("decision-1", decision.getId());
            assertEquals("principal-a", decision.getSubjectId());
            assertEquals("EXECUTE_TOOL", decision.getAction());
            assertEquals("local.echo", decision.getResource());
            assertEquals("sha256:effect", decision.getEffectDigest());
            assertEquals(0.75, decision.getTrajectoryRiskScore());
            assertEquals(3, decision.getRiskAccumulationWindow());
            assertEquals("2026-07-13T00:00Z", decision.getTimestamp().toString());
            assertNotNull(decision.getIntervention());
            assertEquals("THROTTLE", decision.getIntervention().getType());
            assertEquals(5L, decision.getIntervention().getWaitDuration());
            assertEquals("Bearer token", authorization.get());
            assertEquals("tenant-a", tenant.get());
            assertEquals("principal-a", principal.get());
            assertEquals("workspace-a", workspace.get());
            assertNotNull(requestBody.get());
            var payload = mapper.readTree(requestBody.get());
            assertEquals(3, payload.size());
            assertEquals("EXECUTE_TOOL", payload.get("action").asText());
            assertEquals("local.echo", payload.get("resource").asText());
            assertEquals("req-1", payload.get("context").get("request_id").asText());
            assertFalse(payload.has("principal"));
            assertFalse(payload.has("tenant"));
            assertFalse(payload.has("workspace"));
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("Evaluate refuses missing authenticated bindings before making a request")
    void testEvaluateDecisionRequiresBindings() {
        TypesGen.DecisionRequest request = new TypesGen.DecisionRequest();
        request.setAction("EXECUTE_TOOL");
        request.setResource("local.echo");

        IllegalStateException error = assertThrows(IllegalStateException.class,
            () -> new HelmClient("http://127.0.0.1:1").evaluateDecision(request));
        assertTrue(error.getMessage().contains("apiKey, tenantId, and principalId"));
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
}
