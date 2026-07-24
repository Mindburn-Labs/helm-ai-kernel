package labs.mindburn.helm;

import labs.mindburn.helm.TypesGen.*;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Real HTTP loopback tests for the HELM Java SDK.
 *
 * A JDK {@link HttpServer} stands in for the kernel on 127.0.0.1. Each test
 * drives a typed {@link HelmClient} method, then verifies both sides of the
 * JSON mapping: the request payload carries the documented wire names, and
 * the response is decoded into typed model getters (HELM-173).
 */
public class HelmClientLoopbackTest {
    private static final ObjectMapper mapper = HelmClient.createObjectMapper();

    private static HttpServer server;
    private static String baseUrl;
    private static final Map<String, String> requestBodies = new ConcurrentHashMap<>();
    private static final AtomicBoolean failApprove = new AtomicBoolean(false);

    @BeforeAll
    static void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);

        server.createContext("/v1/chat/completions", exchange -> respond(exchange, 200,
                "{\"id\":\"chatcmpl-1\",\"object\":\"chat.completion\",\"created\":1784900000,"
                        + "\"model\":\"gpt-4\",\"choices\":[{\"index\":0,"
                        + "\"message\":{\"role\":\"assistant\",\"content\":\"hello back\"},"
                        + "\"finish_reason\":\"stop\"}],"
                        + "\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}"));

        server.createContext("/api/v1/kernel/approve", exchange -> {
            if (failApprove.get()) {
                respond(exchange, 403,
                        "{\"error\":{\"message\":\"Tool not found\",\"type\":\"permission_denied\","
                                + "\"code\":\"forbidden\",\"reason_code\":\"DENY_TOOL_NOT_FOUND\"}}");
                return;
            }
            respond(exchange, 200,
                    "{\"receipt_id\":\"rcpt-1\",\"decision_id\":\"dec-1\",\"status\":\"APPROVED\","
                            + "\"blob_hash\":\"sha256:abc\",\"principal\":\"user:alice\"}");
        });

        server.createContext("/api/v1/proofgraph/sessions", exchange -> respond(exchange, 200,
                "[{\"session_id\":\"sess-1\",\"created_at\":\"2026-07-24T00:00:00Z\","
                        + "\"receipt_count\":2,\"last_lamport_clock\":7}]"));

        server.createContext("/api/v1/conformance/run", exchange -> respond(exchange, 200,
                "{\"report_id\":\"rep-1\",\"level\":\"L2\",\"verdict\":\"PASS\",\"gates\":12,\"failed\":0}"));

        server.createContext("/api/v1/mcp/registry", exchange -> respond(exchange, 200,
                "{\"server_id\":\"mcp-1\",\"name\":\"fs-server\",\"transport\":\"stdio\","
                        + "\"endpoint\":\"npx fs-server\",\"tool_names\":[\"read_file\"],"
                        + "\"risk\":\"high\",\"state\":\"quarantined\","
                        + "\"discovered_at\":\"2026-07-24T00:00:00Z\"}"));

        server.createContext("/api/v1/sandbox/grants/inspect", exchange -> respond(exchange, 200,
                "{\"grant_id\":\"grant-1\",\"runtime\":\"wazero\",\"runtime_version\":\"1.8.0\","
                        + "\"profile\":\"deny-default\",\"policy_epoch\":\"epoch-1\","
                        + "\"grant_hash\":\"sha256:grant\"}"));

        server.createContext("/api/v1/evaluate", exchange -> respond(exchange, 200,
                "{\"decision_id\":\"dec-9\",\"verdict\":\"ALLOW\"}"));

        server.createContext("/healthz", exchange -> respond(exchange, 200, "OK"));

        server.createContext("/version", exchange -> respond(exchange, 200,
                "{\"version\":\"0.7.4\",\"commit\":\"abc123\",\"build_time\":\"2026-07-24T00:00:00Z\"}"));

        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterAll
    static void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @BeforeEach
    void resetState() {
        requestBodies.clear();
        failApprove.set(false);
    }

    private static void respond(com.sun.net.httpserver.HttpExchange exchange, int status, String body)
            throws IOException {
        if ("POST".equals(exchange.getRequestMethod()) || "PUT".equals(exchange.getRequestMethod())) {
            requestBodies.put(exchange.getRequestURI().getPath(),
                    new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
        }
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private JsonNode lastRequest(String path) throws IOException {
        String body = requestBodies.get(path);
        assertNotNull(body, "expected a captured request body for " + path);
        return mapper.readTree(body);
    }

    @Test
    @DisplayName("chatCompletions: documented request fields on the wire, typed response getters")
    void testChatCompletions() throws Exception {
        HelmClient client = new HelmClient(baseUrl);
        ChatCompletionRequest req = new ChatCompletionRequest()
                .model("gpt-4")
                .messages(List.of(new ChatCompletionRequestMessagesInner()
                        .role(ChatCompletionRequestMessagesInner.RoleEnum.USER)
                        .content("hello")))
                .maxTokens(256)
                .temperature(new java.math.BigDecimal("0.2"));

        ChatCompletionResponse resp = client.chatCompletions(req);

        JsonNode sent = lastRequest("/v1/chat/completions");
        assertEquals("gpt-4", sent.get("model").asText());
        assertTrue(sent.has("max_tokens"), "wire name must be max_tokens");
        assertFalse(sent.has("maxTokens"), "camelCase field name must not leak onto the wire");
        assertEquals(256, sent.get("max_tokens").asInt());
        assertEquals("user", sent.get("messages").get(0).get("role").asText());

        assertEquals("chatcmpl-1", resp.getId());
        assertEquals("gpt-4", resp.getModel());
        assertEquals(1, resp.getChoices().size());
        assertEquals(Integer.valueOf(0), resp.getChoices().get(0).getIndex());
        assertEquals("hello back", resp.getChoices().get(0).getMessage().getContent());
        assertEquals("stop", resp.getChoices().get(0).getFinishReason());
        assertEquals(Integer.valueOf(5), resp.getUsage().getTotalTokens());
    }

    @Test
    @DisplayName("approveIntent: snake_case request payload, typed Receipt getters")
    void testApproveIntent() throws Exception {
        HelmClient client = new HelmClient(baseUrl);
        ApprovalRequest req = new ApprovalRequest()
                .intentHash("sha256:intent")
                .signatureB64("c2ln");

        Receipt receipt = client.approveIntent(req);

        JsonNode sent = lastRequest("/api/v1/kernel/approve");
        assertEquals("sha256:intent", sent.get("intent_hash").asText());
        assertEquals("c2ln", sent.get("signature_b64").asText());

        assertEquals("rcpt-1", receipt.getReceiptId());
        assertEquals("dec-1", receipt.getDecisionId());
        assertEquals("sha256:abc", receipt.getBlobHash());
        assertNotNull(receipt.getStatus());
    }

    @Test
    @DisplayName("listSessions: typed list decode restores getters")
    void testListSessions() {
        HelmClient client = new HelmClient(baseUrl);
        List<Session> sessions = client.listSessions();

        assertEquals(1, sessions.size());
        Session s = sessions.get(0);
        assertEquals("sess-1", s.getSessionId());
        assertEquals(Integer.valueOf(2), s.getReceiptCount());
        assertEquals(Integer.valueOf(7), s.getLastLamportClock());
        assertNotNull(s.getCreatedAt());
    }

    @Test
    @DisplayName("conformanceRun: enum request value and typed ConformanceResult getters")
    void testConformanceRun() throws Exception {
        HelmClient client = new HelmClient(baseUrl);
        ConformanceRequest req = new ConformanceRequest()
                .level(ConformanceRequest.LevelEnum.L2)
                .profile("production");

        ConformanceResult result = client.conformanceRun(req);

        JsonNode sent = lastRequest("/api/v1/conformance/run");
        assertEquals("L2", sent.get("level").asText());
        assertEquals("production", sent.get("profile").asText());

        assertEquals("rep-1", result.getReportId());
        assertEquals(ConformanceResult.VerdictEnum.PASS, result.getVerdict());
        assertEquals(Integer.valueOf(12), result.getGates());
        assertEquals(Integer.valueOf(0), result.getFailed());
    }

    @Test
    @DisplayName("discoverMcpServer: documented payload and typed quarantine record")
    void testDiscoverMcpServer() throws Exception {
        HelmClient client = new HelmClient(baseUrl);
        HelmClient.MCPRegistryDiscoverRequest req = new HelmClient.MCPRegistryDiscoverRequest();
        req.server_id = "mcp-1";
        req.name = "fs-server";
        req.transport = "stdio";
        req.endpoint = "npx fs-server";
        req.tool_names = List.of("read_file");
        req.risk = "high";
        req.reason = "loopback test";

        HelmClient.MCPQuarantineRecord record = client.discoverMcpServer(req);

        JsonNode sent = lastRequest("/api/v1/mcp/registry");
        assertEquals("mcp-1", sent.get("server_id").asText());
        assertEquals("read_file", sent.get("tool_names").get(0).asText());

        assertEquals("mcp-1", record.server_id);
        assertEquals("quarantined", record.state);
        assertEquals("high", record.risk);
    }

    @Test
    @DisplayName("inspectSandboxGrant: typed grant getters after decode")
    void testInspectSandboxGrant() {
        HelmClient client = new HelmClient(baseUrl);
        HelmClient.SandboxGrant grant = client.inspectSandboxGrant("wazero", "deny-default", "epoch-1");

        assertEquals("grant-1", grant.grant_id);
        assertEquals("wazero", grant.runtime);
        assertEquals("epoch-1", grant.policy_epoch);
        assertEquals("sha256:grant", grant.grant_hash);
    }

    @Test
    @DisplayName("evaluateDecision: generated DecisionRequest serializes documented fields")
    void testEvaluateDecision() throws Exception {
        HelmClient client = new HelmClient(baseUrl);
        DecisionRequest req = new DecisionRequest()
                .principal("user:alice")
                .action("fs.write")
                .resource("workspace:/tmp/out.txt");
        req.putContextItem("agent", "loopback-test");

        client.evaluateDecision(req);

        JsonNode sent = lastRequest("/api/v1/evaluate");
        assertEquals("fs.write", sent.get("action").asText());
        assertEquals("workspace:/tmp/out.txt", sent.get("resource").asText());
        assertEquals("user:alice", sent.get("principal").asText());
        assertEquals("loopback-test", sent.get("context").get("agent").asText());
    }

    @Test
    @DisplayName("error path: HelmError reason_code decoded into HelmApiException")
    void testErrorReasonCode() {
        failApprove.set(true);
        HelmClient client = new HelmClient(baseUrl);
        ApprovalRequest req = new ApprovalRequest().intentHash("sha256:intent");

        HelmClient.HelmApiException ex = assertThrows(HelmClient.HelmApiException.class,
                () -> client.approveIntent(req));
        assertEquals(403, ex.status);
        assertEquals("Tool not found", ex.getMessage());
        assertEquals("DENY_TOOL_NOT_FOUND", ex.reasonCode);
    }

    @Test
    @DisplayName("health: plain-text body returned without JSON decoding")
    void testHealth() {
        HelmClient client = new HelmClient(baseUrl);
        assertEquals("OK", client.health());
    }

    @Test
    @DisplayName("version: typed VersionInfo getters after decode")
    void testVersion() {
        HelmClient client = new HelmClient(baseUrl);
        VersionInfo info = client.version();
        assertEquals("0.7.4", info.getVersion());
        assertEquals("abc123", info.getCommit());
    }

    @Test
    @DisplayName("additionalProperties models: declared fields serialize and typed getters restore")
    void testAdditionalPropertiesModelRoundtrip() throws Exception {
        CapabilityGraph graph = new CapabilityGraph()
                .capabilities(List.of("fs.read", "net.http"))
                .confidence(new java.math.BigDecimal("0.9"))
                .confidenceReason("loopback");
        graph.putAdditionalProperty("undeclared_extension", "kept");

        String json = mapper.writeValueAsString(graph);
        JsonNode node = mapper.readTree(json);
        assertEquals("fs.read", node.get("capabilities").get(0).asText());
        assertEquals("loopback", node.get("confidence_reason").asText());
        assertEquals("kept", node.get("undeclared_extension").asText());
        assertFalse(node.has("additionalProperties"),
                "additionalProperties container must not leak as a wire field");

        CapabilityGraph decoded = mapper.readValue(json, CapabilityGraph.class);
        assertEquals(List.of("fs.read", "net.http"), decoded.getCapabilities());
        assertEquals(new java.math.BigDecimal("0.9"), decoded.getConfidence());
        assertEquals("loopback", decoded.getConfidenceReason());
        assertEquals("kept", decoded.getAdditionalProperty("undeclared_extension"));
    }
}
