package labs.mindburn.helm;

import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Functional tests for the HELM Java SDK.
 * These test client construction, request building, serialization,
 * and error handling without requiring a live server.
 * quantum_posture: HTTP compatibility tests do not implement or assert a cryptographic primitive.
 */
public class HelmClientTest {
    private static final ObjectMapper mapper = HelmClient.createObjectMapper();

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
    @DisplayName("Authenticated client sends API key, tenant, and principal headers")
    void testAuthenticatedClientHeaders() throws Exception {
        AtomicReference<String> authorization = new AtomicReference<>();
        AtomicReference<String> tenant = new AtomicReference<>();
        AtomicReference<String> principal = new AtomicReference<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/healthz", exchange -> {
            authorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            tenant.set(exchange.getRequestHeaders().getFirst("X-Helm-Tenant-ID"));
            principal.set(exchange.getRequestHeaders().getFirst("X-Helm-Principal-ID"));
            byte[] response = "ok".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "text/plain");
            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });
        server.start();
        try {
            HelmClient client = new HelmClient(
                "http://127.0.0.1:" + server.getAddress().getPort(),
                "test-api-key",
                "tenant-a",
                "principal-a"
            );
            assertEquals("ok", client.health());
            assertEquals("Bearer test-api-key", authorization.get());
            assertEquals("tenant-a", tenant.get());
            assertEquals("principal-a", principal.get());
        } finally {
            server.stop(0);
        }
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
    @DisplayName("EvaluateDecision uses the canonical V5 request and response")
    void testEvaluateDecisionCanonicalContract() throws Exception {
        AtomicReference<String> body = new AtomicReference<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/v1/evaluate", exchange -> {
            body.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] response = "{\"allow\":true,\"verdict\":\"ALLOW\",\"receipt_id\":\"receipt-evaluate\",\"decision_id\":\"decision-evaluate\",\"decision_hash\":\"sha256:decision\",\"reason_code\":\"\",\"policy_ref\":\"helm:test\",\"lamport_clock\":1}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });
        server.start();
        try {
            HelmClient client = new HelmClient("http://127.0.0.1:" + server.getAddress().getPort());
            TypesGen.EvaluateResponse result = client.evaluateDecisionV5(new TypesGen.EvaluateRequest()
                    .tool("read_file")
                    .effectLevel("read")
                    .sessionId("session-test"));
            assertEquals("receipt-evaluate", result.getReceiptId());
            assertEquals("decision-evaluate", result.getDecisionId());
            assertTrue(body.get().contains("\"effect_level\":\"read\""));
            assertTrue(body.get().contains("\"session_id\":\"session-test\""));

            com.google.gson.JsonElement legacy = client.evaluateDecision(
                    com.google.gson.JsonParser.parseString("{\"action\":\"legacy-read\",\"resource\":\"legacy-resource\",\"context\":{\"session_id\":\"legacy-session\"}}"));
            assertEquals("receipt-evaluate", legacy.getAsJsonObject().get("receipt_id").getAsString());
            assertTrue(body.get().contains("\"action\":\"legacy-read\""));
        } finally {
            server.stop(0);
        }

        HelmClient client = new HelmClient("http://127.0.0.1:1");
        assertThrows(IllegalArgumentException.class, () -> client.evaluateDecisionV5(new TypesGen.EvaluateRequest()
                .tool("read_file")
                .effectLevel("read")
                .sessionId(" ")));
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
    @DisplayName("Typed client honors generated wire names and response getters")
    void testTypedClientJsonMapping() throws Exception {
        AtomicReference<String> body = new AtomicReference<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/chat/completions", exchange -> {
            body.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] response = ("{\"id\":\"chatcmpl-1\",\"object\":\"chat.completion\",\"created\":1784900000,"
                    + "\"model\":\"gpt-4\",\"choices\":[{\"index\":0,"
                    + "\"message\":{\"role\":\"assistant\",\"content\":\"hello back\"},"
                    + "\"finish_reason\":\"stop\"}],"
                    + "\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}")
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });
        server.start();
        try {
            HelmClient client = new HelmClient("http://127.0.0.1:" + server.getAddress().getPort());
            TypesGen.ChatCompletionResponse response = client.chatCompletions(new TypesGen.ChatCompletionRequest()
                    .model("gpt-4")
                    .messages(java.util.List.of(new TypesGen.ChatCompletionRequestMessagesInner()
                            .role(TypesGen.ChatCompletionRequestMessagesInner.RoleEnum.USER)
                            .content("hello")))
                    .maxTokens(256));

            assertTrue(body.get().contains("\"max_tokens\":256"));
            assertFalse(body.get().contains("maxTokens"));
            assertEquals("chatcmpl-1", response.getId());
            assertEquals("hello back", response.getChoices().get(0).getMessage().getContent());
            assertEquals(Integer.valueOf(5), response.getUsage().getTotalTokens());
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("Additional-properties models remain typed beans")
    void testAdditionalPropertiesModelsAreTypedBeans() throws Exception {
        TypesGen.CapabilityGraph graph = new TypesGen.CapabilityGraph()
                .capabilities(java.util.List.of("fs.read", "net.http"))
                .confidence(new java.math.BigDecimal("0.9"))
                .confidenceReason("test");
        graph.putAdditionalProperty("undeclared_extension", "kept");

        assertFalse(graph instanceof java.util.Map);
        String json = mapper.writeValueAsString(graph);
        assertTrue(json.contains("\"confidence_reason\":\"test\""));
        assertTrue(json.contains("\"undeclared_extension\":\"kept\""));
        assertFalse(json.contains("additionalProperties"));

        TypesGen.CapabilityGraph decoded = mapper.readValue(json, TypesGen.CapabilityGraph.class);
        assertEquals(java.util.List.of("fs.read", "net.http"), decoded.getCapabilities());
        assertEquals(new java.math.BigDecimal("0.9"), decoded.getConfidence());
        assertEquals("kept", decoded.getAdditionalProperty("undeclared_extension"));
    }

    @Test
    @DisplayName("Client mapper writes OffsetDateTime as ISO-8601")
    void testClientMapperWritesIsoDateTime() throws Exception {
        String json = mapper.writeValueAsString(new TypesGen.Session()
                .createdAt(OffsetDateTime.parse("2026-07-24T00:00:00Z")));
        assertTrue(json.contains("\"created_at\":\"2026-07-24T00:00:00Z\""));
    }

    @Test
    @DisplayName("Missing API reason code defaults to ERROR_INTERNAL")
    void testMissingApiReasonCode() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/v1/kernel/approve", exchange -> {
            byte[] response = "{\"error\":{\"message\":\"approval failed\"}}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(500, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });
        server.start();
        try {
            HelmClient client = new HelmClient("http://127.0.0.1:" + server.getAddress().getPort());
            HelmClient.HelmApiException exception = assertThrows(HelmClient.HelmApiException.class,
                    () -> client.approveIntent(new TypesGen.ApprovalRequest().intentHash("sha256:intent")));
            assertEquals("approval failed", exception.getMessage());
            assertEquals("ERROR_INTERNAL", exception.reasonCode);
        } finally {
            server.stop(0);
        }
    }
}
