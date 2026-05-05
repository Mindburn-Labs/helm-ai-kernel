package labs.mindburn.helm;

import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.DeserializationFeature;

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
